#ifndef _PFCOUNTER_H
#define _PFCOUNTER_H

#include "../../include/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PFCOUNTER_PAGE_CACHE_BITS
#define PFCOUNTER_PAGE_CACHE_BITS 26
#endif

#define PFCOUNTER_PAGE_CACHE_SIZE (1 << PFCOUNTER_PAGE_CACHE_BITS) // 64 MB
#define EVICT_CACHE_THRESHOLD 50

#define PFCOUNTER_BS_BITS 31
#define PFCOUNTER_BS_SIZE (1L << PFCOUNTER_BS_BITS) // 2GB

#ifndef PFCOUNTER_PAGE_BITS
#define PFCOUNTER_PAGE_BITS 12
#endif

#define PFCOUNTER_PAGE_SIZE (1 << PFCOUNTER_PAGE_BITS)
#define PFCOUNTER_PAGE_OFFSET_MASK (PFCOUNTER_PAGE_SIZE - 1)

//Callback API
void* pfcounter_mstore_alloc(size_t size, void* private_data);
void pfcounter_mstore_free(void* ptr);
size_t pfcounter_mstore_alloc_size(void* ptr);
size_t pfcounter_mstore_get_mpage_size();

int pfcounter_mstore_init(void* priv_data);
int pfcounter_mstore_cleanup();

//Cached-based mstore API
void* pfcounter_mpf_handler_c(void* bs_page);
void pfcounter_flush(void* ptr, size_t size);
void pfcounter_notify_tlb_cached(void* ptr);
void pfcounter_notify_tlb_dropped(void* ptr, bool dirty);


#ifdef __cplusplus
}
#endif
#endif