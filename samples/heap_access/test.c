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

struct test{
    char name[64];
    void (*fun_ptr)();
} tests_arr[] = {
        {"Legal Heap Access", legal_heap_accesses},
        {"Left Heap Overflow", left_heap_overflow},
        {"Right Heap Overflow", right_heap_overflow},
        {"Heap Access After Free", heap_access_after_free}
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
    printf("Legal Heap Access - Passed\n");
    exit(0);
}

void left_heap_overflow(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    printf("Left Heap Overflow - Allocated 8 bytes from address %p\n",x);
    printf("Left Heap Overflow - Trying to illegally access %p\n",(x - 1));
    x[-1] = 'a'; //should exit here
    assert(false);
}

void right_heap_overflow(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    printf("Right Heap Overflow - Allocated 8 bytes from address %p\n", x);
    printf("Right Heap Overflow - Trying to illegally access %p\n", (x + 10));
    x[10] = 'a'; //should exit here
    assert(false);
}

void heap_access_after_free(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    printf("Access After Free - Allocated 8 bytes from address %p\n", x);
    free(x);
    printf("Access After Free - Freed 8 bytes from address %p\n", x);
    printf("Access After Free - Trying to illegally access %p\n", (x + 1));
    x[1] = 'a'; //should exit here
    assert(false);
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