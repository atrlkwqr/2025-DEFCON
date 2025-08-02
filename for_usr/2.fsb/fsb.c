// gcc -o fsb fsb.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char TOP_SECRET[] = "TOP SECRET IS HERE :)";
int PRIVATE_KEY = 0xdeadbeef; 

int main () {
    char command[0x200];
    memset(command, '\0', 0x200);

    puts("What is your command?");
    read(0, command, 0x200);

    printf(command);

    if(PRIVATE_KEY == 0xcafebabe) {
        execve("/bin/bash", NULL, NULL);
    } else {
        puts("I hope to protect my top secret... :)");
    }
}