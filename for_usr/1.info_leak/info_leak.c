// gcc -o info_leak info_leak.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <string.h>

void save_secret() {
    char top_secret[0x100];
    char buffer[0x100];

    strcpy(top_secret, "TOOOOOOOP_SECRET!!!!!");
    strcpy(buffer, "SUCCESSFULLY SAVED");
    puts(buffer);
}

void normal_func() {
    char buffer[0x200];
    
    memset(buffer, '\0', 0x100);
    read(0, buffer, 0x1ff);
    puts(buffer);
}

int main() {
    save_secret();
    normal_func();
}