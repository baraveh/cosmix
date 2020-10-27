#include "pfcounter.h"
#include "../common/mem_allocator.h"
#include "../common/SyncUtils.h"
#include "../common/PageTable.h"
#include "../common/page_cache.h"
#include "../common/mstore_common.h"
#include "../../include/common.h"
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <vector>
#include <assert.h>
#include  <math.h>
#include <time.h>

#ifndef SDK_BUILD
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

static pthread_cond_t cv;
static pthread_mutex_t lock;

#else
extern "C" void ocall_untrusted_alloc(void** umem, size_t size);

#endif



long long g_major_faults = 0;
long long g_minor_faults = 0;
long long g_inc_ref_num = 0;
long long g_unlink_num = 0;
long long g_evictions = 0;

// Maximum number of entries we support to be evicted simultaneously
const int MAX_NUM_OF_THREADS_OPTIMIZATION = 10;

// guard against double initializations requests from users
bool g_is_initialized = 0;

// Page table (maps PFCOUNTER backing store to EPC cache and vise versa)
PageTable *g_page_table;

// base pointer to the Backing Store (BS)
uintptr_t g_base_pfcounter_bs_ptr = 0;

static struct page_cache g_pfcounter_page_cache;

// base pointer to the Page Cache (PC)
uintptr_t g_pfcounter_base_page_cache_ptr;

volatile char *volatile m_ref_count;

unsigned char *try_evict_page(item_t *pce) {
    int page_index = pce->bs_page_index;
    unsigned char *epc_page_ptr = (unsigned char *) (g_pfcounter_base_page_cache_ptr +
                                                     (pce->epc_page_index * PFCOUNTER_PAGE_SIZE));

    // if the page is dirty (was written to)
    if (m_ref_count[page_index * 2 + 1]) {
        INC_COUNTER(g_evictions);
        m_ref_count[page_index * 2 + 1] = 0;

        unsigned char* ram_page_ptr = (unsigned char*)(g_base_pfcounter_bs_ptr + page_index * PFCOUNTER_PAGE_SIZE);
        memcpy(ram_page_ptr, epc_page_ptr, PFCOUNTER_PAGE_SIZE); //copy the data from epc to ram
    }

    g_page_table->remove(page_index);
    return epc_page_ptr;
}

void *allocate_untrusted_buffer(size_t size) {
    // Note: we always allocate with extra HW PAGE to later align to hardware pages for better performance.
    //
    size_t alloc_size = size + 0x1000;
    void *bs_ptr = NULL;

#ifdef SDK_BUILD
    ocall_untrusted_alloc(&bs_ptr, alloc_size);
#elif ANJUNA_BUILD
    #warning Using alloc_untrusted system call exported by Anjuna Runtime
    int ret = syscall(346, alloc_size, &bs_ptr);
    if (ret < 0) {
        printf("Failed allocating untrusted memory (%d)\n", ret);
        return NULL;
    }
#elif GRAPHENE_BUILD
    #warning Using alloc_untrusted system call exported by a modified Graphene-SGX version
    int ret = syscall(310, alloc_size, &bs_ptr);
        if (ret < 0 || bs_ptr == NULL) {
            printf("Failed allocating untrusted memory (%d)\n", ret);
          exit(-1);
        }
#else
    // Note: workaround for SCONE. They don't have page cache,
    // so allocating annonymous memory backed by "a file" will actually be untrusted memory
    //
    int fd = _real_open("/dev/zero", O_RDWR);
    bs_ptr = mmap(0, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    _real_close(fd);

    ASSERT (bs_ptr != MAP_FAILED);
#endif
    ASSERT (bs_ptr);
    return bs_ptr;
}

int pfcounter_mstore_init(void *priv_data) {
    // Protect from double initializations
    if (g_is_initialized) {
        return -1;
    }

    const size_t num_bs_entries = PFCOUNTER_BS_SIZE / PFCOUNTER_PAGE_SIZE;
    const size_t bs_mac_size = MAC_BYTE_SIZE * num_bs_entries;
    void *bs_ptr = allocate_untrusted_buffer(PFCOUNTER_BS_SIZE + bs_mac_size);
    int rc = Untrustedmemsys5Init(NULL, bs_ptr, PFCOUNTER_BS_SIZE, MN_REQ);
    ASSERT (rc == 0);

    g_base_pfcounter_bs_ptr = (uintptr_t) bs_ptr;

    m_ref_count = (volatile char *volatile) _real_malloc(num_bs_entries * 2 * sizeof(char));
    memset((void *) m_ref_count, 0, num_bs_entries * 2 * sizeof(char));

    g_page_table = new PageTable(/*num_of_buckets=*/
            (PFCOUNTER_PAGE_CACHE_SIZE / PFCOUNTER_PAGE_SIZE) * 10,/*backing_store_size=*/
            num_bs_entries, /*page cache size=*/ (PFCOUNTER_PAGE_CACHE_SIZE / PFCOUNTER_PAGE_SIZE));

    init_page_cache(&g_pfcounter_page_cache, &g_pfcounter_base_page_cache_ptr, PFCOUNTER_PAGE_CACHE_SIZE,
                    PFCOUNTER_PAGE_SIZE);

    g_is_initialized = 1;
    return 0;

}

int pfcounter_mstore_cleanup() {
    cleanup_page_cache(&g_pfcounter_page_cache);
    g_page_table->cleanup();
    free((void *) m_ref_count);

    return 0;
}

void *pfcounter_mstore_alloc(size_t size, void *private_data) {
    return Untrustedmemsys5Malloc(size);
}

void pfcounter_mstore_free(void *ptr) {
    Untrustedmemsys5Free(ptr);
}

size_t pfcounter_mstore_alloc_size(void *ptr) {
    size_t res = Untrustedmemsys5Size(ptr);
    return res;
}

uintptr_t pfcounter_mstore_get_mpage_cache_base_ptr()
{
    return g_pfcounter_base_page_cache_ptr;
}

uintptr_t pfcounter_mstore_get_mstorage_page(uintptr_t ptr)
{
    return ptr - g_base_pfcounter_bs_ptr;
}

size_t pfcounter_mstore_get_mpage_size()
{
    return PFCOUNTER_PAGE_SIZE;
}

int pfcounter_mstore_get_mpage_bits()
{
    return PFCOUNTER_PAGE_BITS;
}

// Page fault routine - gets a pointer to the BS and returns a pointer to PFCOUNTER's cache in EPC.
void *pfcounter_mpf_handler_c(void *bs_page) {
    int bs_page_index = ((uintptr_t) bs_page - g_base_pfcounter_bs_ptr) >> PFCOUNTER_PAGE_BITS;
    int page_offset = ((uintptr_t) bs_page - g_base_pfcounter_bs_ptr) & PFCOUNTER_PAGE_OFFSET_MASK;
    char dirty = 0; // non-dirty by default

    // Increase it. It is decreased when it gets evicted from the TLB
    //
    __sync_fetch_and_add(&m_ref_count[bs_page_index * 2], 1);

    item_t *it = g_page_table->get(bs_page_index, dirty);
    bool is_minor = it != NULL;
    if (is_minor) {

        INC_COUNTER(g_minor_faults);
        uintptr_t res = g_pfcounter_base_page_cache_ptr + (it->epc_page_index * PFCOUNTER_PAGE_SIZE) + page_offset;

        return (void *) res;
    }

    INC_COUNTER(g_major_faults);
    unsigned char *free_epc_ptr = pop_free_page(&g_pfcounter_page_cache);

    // No page available, need to evict
    if (!free_epc_ptr) {

        item_t *page_to_evict = g_page_table->get_page_index_to_evict(m_ref_count);
        free_epc_ptr = try_evict_page(page_to_evict);

    }

    int free_epc_page_index = ((uintptr_t) free_epc_ptr - g_pfcounter_base_page_cache_ptr) / PFCOUNTER_PAGE_SIZE;

    // if the page isn't dirty, update from ram
    if (!(m_ref_count[bs_page_index * 2 + 1])) {
        unsigned char* ram_page_ptr = (unsigned char*)(g_base_pfcounter_bs_ptr + bs_page_index * PFCOUNTER_PAGE_SIZE);
        memcpy(free_epc_ptr, ram_page_ptr, PFCOUNTER_PAGE_SIZE); //copy the data from ram to epc
    }

    // Try add to cache, if other ptr already added while we worked on it - just return it as a minor, and return our page to the free pages pool.
    if (!g_page_table->try_add(bs_page_index, free_epc_page_index, dirty)) {
        item_t *found = g_page_table->get(bs_page_index, dirty);
        ASSERT (found != NULL); // if NULL - abort!

        push_free_page(&g_pfcounter_page_cache, free_epc_ptr);
        free_epc_ptr = (unsigned char *) (g_pfcounter_base_page_cache_ptr +
                                          (found->epc_page_index * PFCOUNTER_PAGE_SIZE));
    }

    unsigned char *res = free_epc_ptr + page_offset;

    return res;
}

void pfcounter_flush(void *ptr, size_t size) {
    unsigned char *start_page = (unsigned char *) ((uintptr_t) ptr & ~PFCOUNTER_PAGE_OFFSET_MASK);
    for (unsigned i = 0; i < size; i += PFCOUNTER_PAGE_SIZE) {
        unsigned char *curr_page = start_page + i * PFCOUNTER_PAGE_SIZE;
        int bs_page_index = ((uintptr_t) curr_page - g_base_pfcounter_bs_ptr) >> PFCOUNTER_PAGE_BITS;

        // lookup backing store page
        item_t *it = g_page_table->get(bs_page_index, 0);
        bool is_minor = it != NULL;
        if (is_minor) {
            // found it, evict
            unsigned char *epc_page_ptr = (unsigned char *) (g_pfcounter_base_page_cache_ptr +
                                                             it->epc_page_index * PFCOUNTER_PAGE_SIZE);
            memcpy(curr_page, epc_page_ptr, PFCOUNTER_PAGE_SIZE);
        }
    }
}

void pfcounter_notify_tlb_cached(void *ptr) {
    // Note: PF already increases reference count for this page, which locks the pte.
    // so no need to do anything here.
}

void pfcounter_notify_tlb_dropped(void *ptr, bool dirty) {
    int removed_page_index = ((uintptr_t) ptr - g_base_pfcounter_bs_ptr) >> PFCOUNTER_PAGE_BITS;
    __sync_fetch_and_add(&m_ref_count[removed_page_index * 2], -1);
    m_ref_count[removed_page_index * 2 + 1] |= dirty;
}