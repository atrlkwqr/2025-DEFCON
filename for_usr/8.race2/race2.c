// gcc -o race2 race2.c -no-pie -lpthread
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

typedef struct {
    int flag;
    void *ptr;
    void (*func)();
} heap; 

heap HEAP[0x10];

void win() {
    execve("/bin/bash", NULL, NULL);
}

void print() {
    puts("Hello?");
}

void *set_flag(void *arg) {
    while(1) {
        for(int i = 0; i < 0x10; ++i) {
            if(HEAP[i].ptr) {
                HEAP[i].flag = 1;
            }
            if(HEAP[i].func == win){
                return NULL;
            }
        }
    }
}

void alloc() {
    int idx = 0;

    puts("idx?");
    scanf("%d%*c", &idx);
    
    if(0 > idx || idx >= 0x10) {
        puts("no...");
        return;
    }

    HEAP[idx].ptr = (void*)malloc(0x8);
    HEAP[idx].func = print;
}

void delete() {
    int idx = 0;
    
    puts("idx?");
    scanf("%d%*c", &idx);
    
    if(0 > idx || idx >= 0x10) {
        puts("no...");
        return;
    }

    if(HEAP[idx].ptr != NULL) {
        HEAP[idx].flag = 0;
        free(HEAP[idx].ptr);
        HEAP[idx].ptr = NULL;
        HEAP[idx].func = NULL;
        printf("HEAP[%d] is freed :)\n", idx);
    } else {
        puts("no...");
    }
}

int main () {
    char c;

    pthread_t thd;

    pthread_create(&thd, NULL, set_flag, NULL);

    while(1) {
        puts("1. alloc");
        puts("2. free");
        puts("3. hello");
        puts("4. try hack");
        scanf("%c%*c", &c);

        switch(c) {
            case '1':
                alloc();
                break;
            case '2':
                delete();
                break;
            case '3':
                for(int i = 0; i < 0x10; ++i) {
                    if (HEAP[i].func == win) pthread_join(thd, NULL);
                    if (HEAP[i].func) HEAP[i].func();
                }
                break;
            case '4':
                for(int i = 0; i < 0x10; ++i) {
                    if(HEAP[i].ptr == NULL && HEAP[i].flag == 1) {
                        puts("How to do that??");
                        HEAP[i].func = win;
                    }
                }
                break;
        }
    }
}