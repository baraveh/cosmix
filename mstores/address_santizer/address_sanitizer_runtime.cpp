//
// Created by baraveh on 11/5/20.
//

#define OFFSET_32_BIT (0x20000000)
#define OFFSET_64_BIT (0x0000100000000000)

#include "address_sanitizer_runtime.h"
#include <sys/mman.h>

/* array of bytes, each byte represent an 8 byte sequence in the address space
 * for each byte in the shadow mem - 0 means that all 8 bytes of the corresponding application
memory region are addressable; k (1 ≤ k ≤ 7) means that
the first k bytes are addressible; any negative value indicates that the entire 8-byte word is unaddressable.
 */
char* g_shadow_mem = (char*) -1;

char* get_shadow_byte(void* addr){
    return (char*) ((((u_int64_t) addr)>>3) + (u_int64_t)g_shadow_mem); //(Addr>>3) + Offset
}


int address_sanitizer_mstore_init(void *priv_data) {
    if (g_shadow_mem != (void *) -1) {
        return -1;
    }
    void* offset;
    size_t mem_size = sizeof(void *) * 8;
    switch (mem_size) {
        case 32:
            offset = (void*) OFFSET_32_BIT;
            break;
        case 64:
            offset = (void*) OFFSET_64_BIT;
            break;
        default:
            offset = 0;
            break;
    }
    if(priv_data != nullptr){
        offset = priv_data;
    }
    g_shadow_mem = (char*) mmap(offset, (1<<mem_size)/8, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
    if(g_shadow_mem != (char*) offset){
        return -1;
    }
    for(int i =0; i < (1<<mem_size)/8; i++){ //Marking the shadow memory as inaccessible
        g_shadow_mem[i] = -1;
    }
    return 0;
}

int address_sanitizer_mstore_cleanup(){
    size_t mem_size = sizeof(void *) * 8;
    int res = munmap(g_shadow_mem, (1<<mem_size)/8);
    if (res == 0){
        g_shadow_mem = (char*) -1;
        return 0;
    }
    return -1;
}

void address_sanitizer_mpf_handler_d(void *ptr, void *dst, size_t s);

void address_sanitizer_write_back(void *ptr, void *dst, size_t s);

void *address_sanitizer_mstore_alloc(size_t size, void *private_data);

void address_sanitizer_mstore_free(void *ptr);

size_t address_sanitizer_mstore_alloc_size(void *ptr);

size_t address_sanitizer_mstore_get_mpage_size();