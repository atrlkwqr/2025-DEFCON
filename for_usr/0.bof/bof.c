// gcc -o bof bof.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char name[0x10];
    char address[0x10];
    char contents[40];
} Info;

void setup() {
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void win() {
    execve("/bin/bash", NULL, NULL);
}

int main () {
    Info info; 

    setup();

    puts("Mail service.");
    puts("==========name==========");
    printf("> "); scanf("%15s%*c", info.name);
    puts("=========address========");
    printf("> "); scanf("%32s%*c", info.address);
    puts("========contents========");
    printf("> "); read(0, info.contents, 0x40);
    puts("Sent. :)");
}