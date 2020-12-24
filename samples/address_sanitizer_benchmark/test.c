#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>

extern void* __cosmix_address_sanitizer_annotation(void* ptr);
void legal_heap_accesses();
void left_heap_overflow();
void right_heap_overflow();
void heap_access_after_free();
void legal_stack_accesses();
void left_stack_overflow();
void right_stack_overflow();
void access_char_array_at(size_t i, const char*);

struct test{
    char name[64];
    void (*fun_ptr)();
} tests_arr[] = {
        {"Legal Heap Access", legal_heap_accesses},
        {"Left Heap Overflow", left_heap_overflow},
        {"Right Heap Overflow", right_heap_overflow},
        {"Heap Access After Free", heap_access_after_free},
        {"Legal Stack Access", legal_stack_accesses},
        {"Left Stack Overflow", left_stack_overflow},
        {"Right Stack Overflow", right_stack_overflow}
};


void legal_heap_accesses(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    x[7] = 'a';
    x[0] = 'b';
    x[3] = 'c';
    free(x);
    char* y = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*13));
    for(int i = 0; i < 13; i++){
        y[i] = 'a';
    }
    int* z = (int*)__cosmix_address_sanitizer_annotation(malloc(sizeof(int)*13));
    z[12] = 1;
    z[11] = 1;
    z[0] = 1;
    free(z);
    free(y);
    exit(0);
}

void left_heap_overflow(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    x[-1] = 'a'; //should exit here
    assert(0);
}

void right_heap_overflow(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    x[10] = 'a'; //should exit here
    assert(0);
}

void heap_access_after_free(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    free(x);
    x[1] = 'a'; //should exit here
    assert(0);
}

void legal_stack_accesses(){
    volatile char x[26] __attribute__((annotate("address_sanitizer")));
    x[0] = 'a';
    x[1] = 'b';
    x[2] = 'c';
    x[25] = 'z';
    volatile char y[8] __attribute__((annotate("address_sanitizer")));
    for(int i = 0; i < 8; i++){
        y[i] = 'a';
    }
    volatile int z[8] __attribute__((annotate("address_sanitizer")));
    for(int i = 0; i < 8; i ++){
        z[i] = i;
    }
    exit(0);
}

void left_stack_overflow(){
    volatile char x[1] __attribute__((annotate("address_sanitizer")));
    x[0] = 'a';
    access_char_array_at(-1, x);
    assert(0);
}

void right_stack_overflow(){
    volatile char x[1] __attribute__((annotate("address_sanitizer")));
    x[0] = 'a';
    access_char_array_at(2, x);
    assert(0);
}

/** When in doubt - change debug flag to 1 in address sanitizer runtime and check prints **/
int main(){
    for(int i = 0; i < sizeof(tests_arr) / sizeof(struct test); i++){
        pid_t pid = fork();
        if(pid == 0){
            printf("Starting %s Test\n", tests_arr[i].name);
            tests_arr[i].fun_ptr();
        }
        else{
            int status;
            waitpid(pid, &status, 0);
            printf("%s Test Finished\n", tests_arr[i].name);
        }
    }
}

void access_char_array_at(size_t i, const char* a){
    a[i] = 'e';
}