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

extern void* __cosmix_address_sanitizer_annotation(void* ptr);
void legal_heap_accesses();
void left_heap_overflow();
void right_heap_overflow();
void access_after_free();

struct test{
    char name[64];
    void (*fun_ptr)();
} tests_arr[] = {
        {"Legal Heap Access", legal_heap_accesses},
        {"Left Heap Overflow", left_heap_overflow},
        {"Right Heap Overflow", right_heap_overflow},
        {"Access After Free", access_after_free}
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
    exit(1);
}

void left_heap_overflow(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    x[-1] = 'a'; //should exit here
    free(x);
    exit(0);
}

void right_heap_overflow(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    x[10] = 'a'; //should exit here
    free(x);
    exit(0);
}

void access_after_free(){
    char* x = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    free(x);
    x[1] = 'a';
    exit(0);
}

/** test pass <==> exit code = 1 **/
int main(){
    for(int i = 0; i < sizeof(tests_arr) / sizeof(struct test); i++){
        pid_t pid = fork();
        if(pid == 0){
            tests_arr[i].fun_ptr();
        }
        else{
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(stat) && WEXITSTATUS(stat) == 1){
                printf("%s Test Passed", tests_arr[i].name);
            }
            else{
                printf("%s Test Failed", tests_arr[i].name);
            }
        }
    }
}