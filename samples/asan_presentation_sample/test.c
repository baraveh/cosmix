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
    volatile char secret_password[8] __attribute__((annotate("address_sanitizer"))) = "1234567";
    volatile char user_buffer[8] __attribute__((annotate("address_sanitizer")));
    printf("Welcome to ASan's demo, please enter an input to my 8 byte array!");
    scanf("%s",user_buffer);
    printf("Have a nice day!")
    exit();
}


/** Change debug flag to 1 in address sanitizer runtime and check prints **/
int main(){
    while(true){
        printf("Starting Demo\n"); 
        pid_t pid = fork();
        if(pid == 0){
            tests_arr[0].fun_ptr();
        }
        else{
            int status;
            waitpid(pid, &status, 0);
            printf("Process Finished with Exit Code %d\n",WEXITSTATUS(status));
        }
    }
}