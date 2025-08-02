// gcc -o integer_bug integer_bug.c -no-pie

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int hdr1;
    int hdr2;
    char hdr3[0x20];
} header;

typedef struct {
    header hdr;
    char data[];
} datas;

typedef struct {
    void (*ptr)();
} test_struct;

void print() {
    puts("Test successfully worked");
}

void win() {
    execve("/bin/bash", NULL, NULL);
}

int main () {
    short hdr_size = sizeof(header);
    short data_size;

    datas *mem;
    test_struct *test;
    
    puts("data size?");
    scanf("%hd%*c", &data_size);

    mem = (datas*)malloc(data_size + hdr_size);
    test = (test_struct*)malloc(sizeof(test_struct));

    test->ptr = print;

    puts("hdr1");
    scanf("%d%*c", &mem->hdr.hdr1);
    puts("hdr2");
    scanf("%d%*c", &mem->hdr.hdr2);
    puts("hdr3");
    read(0, mem->hdr.hdr3, 0x20);

    test->ptr();
}