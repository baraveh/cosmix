//
// Created by baraveh on 11/5/20.
//

#ifndef COSMIX_ADDRESS_SANITIZER_H
#define COSMIX_ADDRESS_SANITIZER_H

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SCALE_BITS (3) //can adjust between 3 and 6 (inclusive bounds)
#define SCALE (1<<SCALE_BITS)
#define REDZONE_BYTES (SCALE) //must be scale aligned
#define DEBUG 0

int address_sanitizer_mstore_init(void* priv_data);

int address_sanitizer_mstore_cleanup();
    
void address_sanitizer_mpf_handler_d(void* ptr, void* dst, size_t s);

void address_sanitizer_write_back(void* ptr, void* dst, size_t s);

void* address_sanitizer_mstore_alloc(size_t size, void* private_data);

void address_sanitizer_mstore_free(void* ptr);

size_t address_sanitizer_mstore_alloc_size(void* ptr);

size_t address_sanitizer_mstore_get_mpage_size();
    
    
    
#ifdef __cplusplus
}
#endif
#endif //COSMIX_ADDRESS_SANITIZER_H
