//
// Created by baraveh on 11/5/20.
//

/* Shadow memory start address as defined in the address sanitizer paper */
#define OFFSET_32_BIT (0x20000000)
#define OFFSET_64_BIT (0x0000100000000000)
#define REDZONE_BYTES (8) //must be 8 divisible


#include "address_sanitizer_runtime.h"
#include <sys/mman.h>
#include <sys/resource.h>

/* array of bytes, each byte represent an 8 byte sequence in the address space
 * for each byte in the shadow mem - 0 means that all 8 bytes of the corresponding application
memory region are unaddressable; k (1 ≤ k ≤ 8) means that
the first k bytes are addressible; any negative value indicates that the entire 8-byte word is unaddressable.
Slight modification from the address sanitizer paper - instead of 0 for 8-addressable I used 8 and 0 means unallocated
 */
char* g_shadow_mem;
unsigned long long g_shadow_mem_size = 0;

char* get_shadow_byte(void* addr){
    return (char*) ((((unsigned long long) addr)>>3) + (unsigned long long)g_shadow_mem); //(Addr>>3) + Offset
}

int round_up_to_eight_divisible(int num){
    if(num%8 == 0){
        return num;
    }
    return num + (8-(num%8));
}

void mark_as_redzone(void* red_zone_ptr){
    for(int eight_byte_chunk = 0; eight_byte_chunk < REDZONE_BYTES/8; eight_byte_chunk++){
        char* shadow_byte = get_shadow_byte(((char*)red_zone_ptr)+8*eight_byte_chunk);
        *shadow_byte = -1;
    }
}

void mark_as_allocated(void* ptr, size_t size){
    for(int eight_byte_chunk = 0; eight_byte_chunk < size/8; eight_byte_chunk++){
        char* shadow_byte = get_shadow_byte((((char*)ptr)+8*eight_byte_chunk));
        *shadow_byte = 8;
    }
    if(size%8 > 0){ //size isn't divisible by eight, need to mark the shadow mem for the last k (1 ≤ k ≤ 7) bytes
        char* shadow_byte = get_shadow_byte((((char*)ptr)+(size-(size%8))));
        *shadow_byte = size%8;
    }
}


int address_sanitizer_mstore_init(void *priv_data) {
    if (g_shadow_mem_size != 0) {
        return -1;
    }
    void* offset;
    struct rlimit mem_limit;
    if(getrlimit(RLIMIT_AS, &mem_limit) != 0){
        return -1;
    }
    g_shadow_mem_size = (mem_limit.rlim_max)/8;
    size_t os_bits = sizeof(void *) * 8;
    switch (os_bits) {
        case 32:
            offset = (void*) OFFSET_32_BIT;
            break;
        case 64:
            offset = (void*) OFFSET_64_BIT;
            break;
        default:
            offset = (void*) 0;
            break;
    }
    if(priv_data != nullptr){
        offset = priv_data;
    }
    g_shadow_mem = (char*) mmap(offset, g_shadow_mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
    if(g_shadow_mem != (char*) offset){
        return -1;
    }
    return 0;
}

int address_sanitizer_mstore_cleanup(){
    int res = munmap(g_shadow_mem, g_shadow_mem_size);
    if (res == 0){
        g_shadow_mem_size = 0;
        return 0;
    }
    return -1;
}

void address_sanitizer_mpf_handler_d(void *ptr, void *dst, size_t s);

void address_sanitizer_write_back(void *ptr, void *dst, size_t s);

void *address_sanitizer_mstore_alloc(size_t size, void *private_data){
    char* ptr = (char*) malloc(round_up_to_eight_divisible(size) + 2*REDZONE_BYTES);
    if(ptr == nullptr){
        return nullptr;
    }
    char* start_redzone = ptr;
    mark_as_redzone(start_redzone);
    char* actual_ptr = ptr + REDZONE_BYTES;
    mark_as_allocated(ptr, size);
    char* end_redzone = actual_ptr + round_up_to_eight_divisible(size);
    mark_as_redzone(end_redzone);
    return actual_ptr;
}

void address_sanitizer_mstore_free(void *ptr){

}

size_t address_sanitizer_mstore_alloc_size(void *ptr);

size_t address_sanitizer_mstore_get_mpage_size();