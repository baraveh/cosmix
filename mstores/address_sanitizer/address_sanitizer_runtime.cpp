//
// Created by baraveh on 11/5/20.
//

/* Shadow memory start address as defined in the address sanitizer paper */
#define OFFSET_32_BIT (0x20000000)
#define OFFSET_64_BIT (0x0000100000000000)
#define REDZONE_BYTES (8) //must be 8 aligned


#include "address_sanitizer_runtime.h"
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

/* array of bytes, each byte represent an 8 byte sequence in the address space
 * for each byte in the shadow mem - 0 means that all 8 bytes of the corresponding application
memory region are unaddressable; k (1 ≤ k ≤ 8) means that
the first k bytes are addressible; any negative value indicates that the entire 8-byte word is unaddressable.
Slight modification from the address sanitizer paper - instead of 0 for 8-addressable I used 8 and 0 means unallocated
 */
typedef char byte;
byte* g_shadow_mem;
unsigned long g_shadow_mem_size = 0;

unsigned long round_up_to_eight_aligned(unsigned long);
byte* get_shadow_byte(void* addr);
void assert_access(void* ptr, size_t s);
void mark_as_redzone(void* red_zone_ptr);
void mark_as_allocated(void* ptr, size_t size);
void mark_as_freed(void* ptr, size_t size);

unsigned long round_up_to_eight_aligned(unsigned long num){
    if(num%8 == 0){
        return num;
    }
    return num + (8-(num%8));
}

byte* get_shadow_byte(void* addr){
    return (byte*) ((((unsigned long) addr)>>3) + (unsigned long)g_shadow_mem); //(Addr>>3) + Offset
}

bool is_allowed(void* ptr, size_t size){
    size_t remaining_bytes = size;
    byte* curr_byte = (byte*)ptr;
    byte* curr_shadow_byte;

    // if pointer is not 8-aligned, special handling of the first byte
    if((u_int64_t)curr_byte % 8){
        curr_shadow_byte = get_shadow_byte(curr_byte);
        if (*curr_shadow_byte != 8){
            return false;
        }
        remaining_bytes -= (8- ((u_int64_t)curr_byte % 8));
        curr_byte = (char*) round_up_to_eight_aligned((u_int64_t) curr_byte);
    }

    while(remaining_bytes > 0){
        curr_shadow_byte = get_shadow_byte(curr_byte);
        if(remaining_bytes < 8){
            //the last byte, and size is not 8 aligned
            return (*curr_shadow_byte >= remaining_bytes);
        }
        // size is at least 8 bytes, so curr shadow byte needs to allow for 8 bytes
        if (*curr_shadow_byte != 8){
            return false;
        }
        remaining_bytes -= 8;
        curr_byte += 8;
    }
    return true;
}

void assert_access(void* ptr, size_t s){
    if(!is_allowed(ptr, s)){
        std::cerr << "Access out of bounds" << std::endl;
        exit(3);
    }
}

void mark_as_redzone(void* red_zone_ptr){
    for(int eight_byte_chunk = 0; eight_byte_chunk < REDZONE_BYTES/8; eight_byte_chunk++){
        byte* shadow_byte = get_shadow_byte(((byte*)red_zone_ptr)+8*eight_byte_chunk);
        *shadow_byte = -1;
    }
}

void mark_as_allocated(void* ptr, size_t size){
    for(int eight_byte_chunk = 0; eight_byte_chunk < size/8; eight_byte_chunk++){
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+8*eight_byte_chunk));
        *shadow_byte = 8;
    }
    if(size%8 > 0){ //size isn't divisible by eight, need to mark the shadow mem for the last k (1 ≤ k ≤ 7) bytes
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+(size-(size%8))));
        *shadow_byte = size%8;
    }
}

void mark_as_freed(void* ptr, size_t size){
    for(int eight_byte_chunk = 0; eight_byte_chunk < size/8; eight_byte_chunk++){
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+8*eight_byte_chunk));
        *shadow_byte = 0;
    }
    if(size%8 > 0){ //size isn't divisible by eight, need to mark the shadow mem for the last k (1 ≤ k ≤ 7) bytes
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+(size-(size%8))));
        *shadow_byte = 0;
    }
}


int address_sanitizer_mstore_init(void *priv_data) {
    if (g_shadow_mem_size != 0) {
        return -1;
    }
    void* offset;
    struct rlimit mem_limit;
    if(getrlimit(RLIMIT_AS, &mem_limit) != 0){
        return -errno;
    }
    g_shadow_mem_size = (mem_limit.rlim_max)>>3;
    printf("memory size is %lu bytes, g_shadow_mem_size is %lu bytes\n", mem_limit.rlim_max, g_shadow_mem_size);
    /* size_t os_bits = sizeof(void *) * 8;
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
    } */
    g_shadow_mem = (byte*) mmap(0, g_shadow_mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(g_shadow_mem == MAP_FAILED){
        return -errno;
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

void address_sanitizer_mpf_handler_d(void *ptr, void *dst, size_t s){
    address_sanitizer_write_back(ptr, dst, s);
}

void address_sanitizer_write_back(void *ptr, void *dst, size_t s){
    assert_access(ptr, s);
    assert_access(dst, s);
    memcpy(dst, ptr, s);
}

void *address_sanitizer_mstore_alloc(size_t size, void *private_data){
    byte* ptr = (byte*) malloc(round_up_to_eight_aligned(size) + 2*REDZONE_BYTES);
    if(ptr == nullptr){
        return nullptr;
    }
    byte* start_redzone = ptr;
    mark_as_redzone(start_redzone);
    byte* actual_ptr = ptr + REDZONE_BYTES;
    mark_as_allocated(ptr, size);
    byte* end_redzone = actual_ptr + round_up_to_eight_aligned(size);
    mark_as_redzone(end_redzone);
    return actual_ptr;
}

void address_sanitizer_mstore_free(void *ptr){
    byte* start_redzone = ((byte*)ptr) - REDZONE_BYTES;
    mark_as_freed(start_redzone, 2*REDZONE_BYTES + round_up_to_eight_aligned(address_sanitizer_mstore_alloc_size(ptr)));
    free(start_redzone);
}

size_t address_sanitizer_mstore_alloc_size(void *ptr){
    byte* curr_shadow_byte_ptr = get_shadow_byte(ptr);
    size_t alloc_size = 0;
    while(*(curr_shadow_byte_ptr) > 0){
        alloc_size += *(curr_shadow_byte_ptr);
        curr_shadow_byte_ptr = get_shadow_byte((byte*)ptr + alloc_size);
    }
    return alloc_size;
}

size_t address_sanitizer_mstore_get_mpage_size(){
    return sysconf(_SC_PAGESIZE);
}