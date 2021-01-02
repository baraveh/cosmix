//
// Created by baraveh on 11/5/20.
//


#define SCALE_BITS (3)
#define SCALE (1<<SCALE_BITS)
#define REDZONE_BYTES (SCALE) //must be scale aligned
#define MEMORY_SIZE (1<<30)
#define DEBUG 1
#define debug_print(fmt, ...) \
            do { if (DEBUG) {fprintf(stderr, "***Debug*** - "); fprintf(stderr, fmt, __VA_ARGS__);} } while (0)

#include "address_sanitizer_runtime.h"
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <errno.h>
#include <utility>

/* array of bytes, each byte represent an <scale> byte sequence in the address space
 * for each byte in the shadow mem - 0 means that all 8 bytes of the corresponding application
memory region are unaddressable; k (1 ≤ k ≤ SCALE) means that
the first k bytes are addressible; any negative value indicates that the entire 8-byte word is unaddressable.
Slight modification from the address sanitizer paper - instead of 0 for 8-addressable I used 8 and 0 means unallocated
 */
typedef char byte;
byte* g_shadow_mem;
unsigned long g_shadow_mem_size = 0;

unsigned long round_up_to_scale_aligned(unsigned long);
byte* get_shadow_byte(void* addr);
void assert_access(void* ptr, size_t s);
void mark_as_redzone(void* red_zone_ptr);
void mark_as_allocated(void* ptr, size_t size);
void mark_as_freed(void* ptr, size_t size);

unsigned long round_up_to_scale_aligned(unsigned long num){
    if(num%SCALE == 0){
        return num;
    }
    return num + (SCALE-(num%SCALE));
}

byte* get_shadow_byte(void* addr){
    unsigned long long address = (unsigned long long) addr;
    return &(g_shadow_mem[(unsigned long long) address/SCALE]); //(Addr>>SCALE) + Offset
}

std::pair<bool, byte*> is_allowed(void* ptr, long size){
    if(size == 0){
        return std::pair<bool, byte*>(true, 0);
    }
    debug_print("checking permissions for address range %p - %p\n", ptr, (byte*) ptr + size);
    byte* curr_byte = (byte*)ptr;
    byte* curr_shadow_byte;

    // special handling of the first sequence in case ptr isn't scale aligned
    if((unsigned long long)curr_byte % SCALE){
        long sequence_bytes = size + (((unsigned long long)curr_byte % SCALE));
        curr_shadow_byte = get_shadow_byte(curr_byte);
        if(sequence_bytes < SCALE){
            // the entire access is wholly contained in one sequence
            debug_print("address range %p - %p: shadow byte is %d\n", curr_byte, curr_byte + size, *(curr_shadow_byte));
            return std::pair<bool, byte*>((*(curr_shadow_byte)) >= sequence_bytes, curr_byte);
        }
        debug_print("address range %p - %p: shadow byte is %d\n", curr_byte, curr_byte + SCALE, *(curr_shadow_byte));
        if(*(curr_shadow_byte) != SCALE){
            return std::pair<bool, byte*>(false , curr_byte);
        }
    }

    for(curr_byte = (byte*) round_up_to_scale_aligned((uintptr_t) curr_byte); curr_byte < (((byte*)ptr) + size); curr_byte += SCALE){
        curr_shadow_byte = get_shadow_byte(curr_byte);
        if((((byte*)ptr) + size) - curr_byte < SCALE){
            //last sequence, and ptr + size isn't scale aligned
            debug_print("address range %p - %p: shadow byte is %d\n", curr_byte, (((byte*)ptr) + size), *(curr_shadow_byte));
            return std::pair<bool, byte*>(*(curr_shadow_byte) >= (((byte*)ptr) + size) - curr_byte , curr_byte);
        }
        debug_print("address range %p - %p: shadow byte is %d\n", curr_byte, curr_byte + SCALE, *(curr_shadow_byte));
        if(*(curr_shadow_byte) != SCALE){
            return std::pair<bool, byte*>(false , curr_byte);
        }
    }
    return std::pair<bool, byte*>(true, 0);
}

void assert_access(void* ptr, size_t s){
    std::pair<bool, byte*> result = is_allowed(ptr, (long)s);
    if(!result.first){
        printf("***Address Sanitizer*** - Illegal access in address %p\n", result.second);
        exit(3);
    }
}

void mark_as_redzone(void* red_zone_ptr){
    debug_print("marking %d bytes as redzone, starting from address %p\n", REDZONE_BYTES, red_zone_ptr);
    for(int scale_byte_chunk = 0; scale_byte_chunk < REDZONE_BYTES/SCALE; scale_byte_chunk++){
        debug_print("marking %p as redzone\n", (byte*)red_zone_ptr+SCALE*scale_byte_chunk);
        byte* shadow_byte = get_shadow_byte((byte*)red_zone_ptr+SCALE*scale_byte_chunk);
        *shadow_byte = -1;
    }
}

void mark_as_allocated(void* ptr, size_t size){
    debug_print("marking %lu bytes as allocated, starting from address %p\n", size, ptr);
    for(int scale_byte_chunk = 0; scale_byte_chunk < size/SCALE; scale_byte_chunk++){
        debug_print("marking %p as allocated\n", (((byte*)ptr)+SCALE*scale_byte_chunk));
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+SCALE*scale_byte_chunk));
        *shadow_byte = SCALE;
    }
    if(size%SCALE > 0){ //size isn't divisible by scale, need to mark the shadow mem for the last k (1 ≤ k ≤ SCALE - 1) bytes
        debug_print("marking %p as allocated\n", (((byte*)ptr)+(size-(size%SCALE))));
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+(size-(size%SCALE))));
        *shadow_byte = size%SCALE;
    }
}

void mark_as_freed(void* ptr, size_t size){
    debug_print("marking %lu bytes as freed, starting from address %p\n", size, ptr);
    for(int scale_byte_chunk = 0; scale_byte_chunk < size/SCALE; scale_byte_chunk++){
        debug_print("marking %p as freed\n", (((byte*)ptr)+SCALE*scale_byte_chunk));
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+SCALE*scale_byte_chunk));
        *shadow_byte = 0;
    }
    if(size%SCALE > 0){ //size isn't divisible by eight, need to mark the shadow mem for the last k (1 ≤ k ≤ SCALE - 1) bytes
        debug_print("marking %p as freed\n", (((byte*)ptr)+(size-(size%SCALE))));
        byte* shadow_byte = get_shadow_byte((((byte*)ptr)+(size-(size%SCALE))));
        *shadow_byte = 0;
    }
}


int address_sanitizer_mstore_init(void *priv_data) {
    if (g_shadow_mem_size != 0) {
        return -1;
    }
    struct rlimit mem_limit;
    if(getrlimit(RLIMIT_AS, &mem_limit) != 0){
        return -errno;
    }
    mem_limit.rlim_cur = MEMORY_SIZE;
    mem_limit.rlim_max = MEMORY_SIZE;
    if(setrlimit(RLIMIT_AS, &mem_limit) != 0){
        return -errno;
    }
    g_shadow_mem_size = (mem_limit.rlim_cur)/SCALE;
    g_shadow_mem = (byte*) mmap((void*) (MEMORY_SIZE - g_shadow_mem_size), g_shadow_mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(g_shadow_mem == MAP_FAILED){
        debug_print("memory size is %lu, shadow mem size is %lu\n", mem_limit.rlim_cur, g_shadow_mem_size);
        debug_print("mmap failed with %d - %s\n", errno, strerror(errno));
        return -errno;
    }
    debug_print("address sanitizer is initialized, shadow mem starts at %p and ends at %p\n", g_shadow_mem, g_shadow_mem + g_shadow_mem_size);
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
    debug_print("page fault - copying %zu bytes from %p to %p\n", s, ptr, dst);
    assert_access(ptr, s);
    //memcpy(dst, ptr, s);
}

void address_sanitizer_write_back(void *ptr, void *dst, size_t s){
    debug_print("write back size of %zu bytes from %p to %p\n", s, ptr, dst);
    assert_access(ptr, s);
    //memcpy(dst, ptr, s);
}

void *address_sanitizer_mstore_alloc(size_t size, void *private_data){
    debug_print("allocating %lu bytes, + %d redzone bytes\n", round_up_to_scale_aligned(size), 2*REDZONE_BYTES);
    byte* ptr = (byte*) malloc(round_up_to_scale_aligned(size) + 2*REDZONE_BYTES);
    if(ptr == nullptr){
        return nullptr;
    }
    byte* start_redzone = ptr;

    mark_as_redzone(start_redzone);

    byte* actual_ptr = ptr + REDZONE_BYTES;

    mark_as_allocated(actual_ptr, size);

    byte* end_redzone = actual_ptr + round_up_to_scale_aligned(size);

    mark_as_redzone(end_redzone);
    return actual_ptr;
}

void address_sanitizer_mstore_free(void *ptr){
    byte* start_redzone = ((byte*)ptr) - REDZONE_BYTES;
    mark_as_freed(start_redzone, 2*REDZONE_BYTES + round_up_to_scale_aligned(address_sanitizer_mstore_alloc_size(ptr)));
    free(start_redzone);
}

size_t address_sanitizer_mstore_alloc_size(void *ptr){
    debug_print("getting alloc size of pointer %p\n", ptr);
    byte* curr_byte = (byte*) ptr;
    byte* curr_shadow_byte = get_shadow_byte(curr_byte);
    size_t alloc_size = 0;
    if ((uintptr_t)(curr_byte) % SCALE){
        if(*curr_shadow_byte != SCALE){
            return 0;
        }
        alloc_size += SCALE - ((uintptr_t)(curr_byte) % SCALE);
        curr_byte = (byte*) round_up_to_scale_aligned((uintptr_t) curr_byte);
        curr_shadow_byte = get_shadow_byte(curr_byte);
    }
    while(*(curr_shadow_byte) > 0){
        alloc_size += *(curr_shadow_byte);
        curr_byte += SCALE;
        curr_shadow_byte = (byte*) get_shadow_byte(curr_byte);
    }
    return alloc_size;
}

size_t address_sanitizer_mstore_get_mpage_size(){
    //return sysconf(_SC_PAGESIZE);
    return 1;
}
