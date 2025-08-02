// gcc -o uaf uaf.c -no-pie
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    void (*ptr)();
    char name[0x10];
} man;

typedef struct {
    char name[0x10];
    void (*ptr)();
} woman;

void man_introduce() {
    puts("Hi, I'm man");
}

void woman_introduce() {
    puts("Hi, I'm woman");
}

void ironman_introduce() {
    puts("Hi, I'm iron man");
    execve("/bin/bash", NULL, NULL);
}

int main () {
    man *p1;
    woman *p2;

    p1 = (man*)malloc(sizeof(man));
    p2 = (woman*)malloc(sizeof(woman));

    p1->ptr = man_introduce;
    p2->ptr = woman_introduce;

    while (2) {
        char c;
        puts("1. introduce man");
        puts("2. introduce woman ");
        puts("3. info of man");
        puts("4. info of woman ");
        puts("5. bye man");
        puts("6. bye woman");
        puts("7. hi man");
        puts("8. hi woman");
        scanf("%c%*c", &c);
        switch(c) {
            case '1':
                p1->ptr();
                break;
            case '2':
                p2->ptr();
                break;
            case '3':
                read(0, p1->name, 0xf);
                break;
            case '4':
                read(0, p2->name, 0xf);
                break;
            case '5':
                free(p1);
                break;
            case '6':
                free(p2);
                break;
            case '7':
                p1 = (man*)malloc(sizeof(man));
                p1->ptr = man_introduce;
                break;
            case '8':
                p2 = (woman*)malloc(sizeof(woman));
                p2->ptr = woman_introduce;
                break;
        }    
    }
}