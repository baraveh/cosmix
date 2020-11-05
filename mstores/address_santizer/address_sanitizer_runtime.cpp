//
// Created by baraveh on 11/5/20.
//

#include "address_sanitizer_runtime.h"


int address_sanitizer_mstore_init(void* priv_data);

int address_sanitizer_mstore_cleanup();

void address_sanitizer_mpf_handler_d(void* ptr, void* dst, size_t s);

void address_sanitizer_write_back(void* ptr, void* dst, size_t s);

void* address_sanitizer_mstore_alloc(size_t size, void* private_data);

void address_sanitizer_mstore_free(void* ptr);

size_t address_sanitizer_mstore_alloc_size(void* ptr);

size_t address_sanitizer_mstore_get_mpage_size();