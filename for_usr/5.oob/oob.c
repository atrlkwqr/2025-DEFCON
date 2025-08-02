// gcc -o oob oob.c -no-pie
#include <stdio.h>
#include <stdlib.h>

void gift() {
    execve("/bin/bash", NULL, NULL);
}

int main () {

    long array[0x20];

    for(int i = 0; i < 0x20; ++i) array[i] = i*0x31337;

    while (1) {
        char c;
        int idx = 0;

        puts("0. exit");
        puts("1. read");
        puts("2. write");
        puts("3. echo");
        
        scanf("%c%*c", &c);
        if (c == '0') break;
        switch(c) {
            case '1':
                scanf("%d%*c", &idx);
                if (idx < 0 || 0x20 <= idx) {
                    puts("no..");
                } else {
                    printf("%d: %ld\n", idx, array[idx]);
                }
                break;
            case '2':
                scanf("%d%*c", &idx);
                if (idx < 0 && 0x20 <= idx) {
                    puts("no..");
                } else {
                    scanf("%ld%*c", &array[idx]);
                }
                break;
            case '3': 
                scanf("%d%*c", &idx);
                if (idx < 0 || 0x20 <= idx) {
                    puts("no..");
                } else {
                    puts((char*)array[idx]);
                }
        }
    }
}