#include "pfcounter.h"
#include "../common/mem_allocator.h"
#include "../common/SyncUtils.h"
#include "../common/PageTable.h"
#include "../common/page_cache.h"
#include "../common/mstore_common.h"
#include "../../include/common.h"

ong long g_major_faults = 0;
long long g_minor_faults = 0;
long long g_inc_ref_num = 0;
long long g_unlink_num = 0;
long long g_evictions = 0;

// Maximum number of entries we support to be evicted simultaneously 
const int MAX_NUM_OF_THREADS_OPTIMIZATION = 10;

// guard against double initializations requests from users
bool g_is_initialized = 0;

// Page table (maps PFCOUNTER backing store to EPC cache and vise versa)
PageTable* g_page_table;

// base pointer to the Backing Store (BS)
uintptr_t g_base_pfcounter_bs_ptr = 0;

static struct page_cache g_pfcounter_page_cache;

// base pointer to the Page Cache (PC)
uintptr_t g_pfcounter_base_page_cache_ptr;

// base pointer to the MACs stored in the backing store
sgx_mac_t* g_mac_base_ptr;


volatile char* volatile m_ref_count;

int pfcounter_mstore_init(void* priv_data){
    // Protect from double initializations
	if (g_is_initialized)
	{
		return -1;
	}

    const size_t num_bs_entries = PFCOUNTER_BS_SIZE / PFCOUNTER_PAGE_SIZE;
	const size_t bs_mac_size = MAC_BYTE_SIZE * num_bs_entries;
	void* bs_ptr = allocate_untrusted_buffer(PFCOUNTER_BS_SIZE+bs_mac_size);
	int rc = Untrustedmemsys5Init(NULL, bs_ptr, PFCOUNTER_BS_SIZE, MN_REQ);
	ASSERT (rc == 0);

    g_base_pfcounter_bs_ptr = (uintptr_t)bs_ptr;
	g_mac_base_ptr = (sgx_mac_t*)((char*)bs_ptr + PFCOUNTER_BS_SIZE);

	m_ref_count = (volatile char* volatile)_real_malloc(num_bs_entries * 2 * sizeof(char));
	memset((void*)m_ref_count, 0, num_bs_entries * 2 * sizeof(char));

}

int pfcounter_mstore_cleanup(){
    cleanup_page_cache(&g_pfcounter_page_cache);
	g_page_table->cleanup();
	free(g_nonce_base_ptr);
	free((void*)m_ref_count);

	return 0;
}

void* pfcounter_mstore_alloc(size_t size, void* private_data);
void pfcounter_mstore_free(void* ptr);
size_t pfcounter_mstore_alloc_size(void* ptr);
size_t pfcounter_mstore_get_mpage_size();
void pfcounter_mpf_handler_d(void* ptr, void* dst, size_t s);
void pfcounter_write_back(void* ptr, void* dst, size_t s);