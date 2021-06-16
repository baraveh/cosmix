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

void demo();

struct test{
    char name[32];
    void (*fun_ptr)();
} tests_arr[] = {
        {"Demo", demo}
};


void demo(){
    char* user_buffer = (char*)__cosmix_address_sanitizer_annotation(malloc(sizeof(char)*8));
    printf("Welcome to ASan's demo, please enter an input to my 8 byte array!\n");
    scanf("%s",user_buffer);
    printf("You entered: %s\n", user_buffer);
    printf("Have a nice day!\n");
}


/** Change debug flag to 1 in address sanitizer runtime and check prints **/
int main(){
    while(1){
        demo();
    }
}