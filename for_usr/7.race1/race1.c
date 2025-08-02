// gcc -o race1 race1.c -no-pie
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>

int fd;
signed long *shm;

void init() {
    fd = shmget(1337, 0x8, 0x3b6);

    if(fd == -1) {
        exit(-1);
    } 

    shm = shmat(fd, 0, 0);
}

int flag = 0;

int main () {
    init();

    while(1) {
        char c;
        
        puts("1. set value");
        puts("2. read value");
        puts("3. try hack");
        puts("4. check hack");

        scanf("%c%*c", &c);

        switch (c) {
            case '1':
                scanf("%ld%*c", shm);
                break;
            case '2':
                printf("%ld\n", *shm);
                break;
            case '3':
                scanf("%ld%*c", shm);
                if (*shm < 0) {
                    puts("let's check? (y/n)");
                    scanf("%c%*c", &c);
                    if(c == 'y') {
                        if (*shm == 0x1337) {
                            puts("gratz!");
                            flag = 1;
                        } else {
                            puts("Fail...");
                        }
                    }
                } else {
                    puts("try harder");
                }
                break;
            case '4':
                if (flag) {
                    execve("/bin/bash", NULL, NULL);
                } else {
                    puts("no...");
                }
                break;
        }
    }
}