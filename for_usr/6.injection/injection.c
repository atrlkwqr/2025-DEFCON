// gcc -o injection injection.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main () {
    char command[0x80] = { '\0', };
    
    strcpy(command, "ping -c 4 '");

    puts("Command?");
    read(0, &command[strlen(command)], 0x1f);

    if (command[strlen(command)-1] == '\n') {
        command[strlen(command)-1] = '\0';
    }
    
    command[strlen(command)] = '\'';
    
    printf("your command: %s\n", command);
    system(command);
}