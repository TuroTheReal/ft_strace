#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("Hello from 32-bit!\n");
    printf("PID: %d\n", getpid());

    write(1, "Test write\n", 11);
    getpid();
    getuid();

    return 0;
}

// gcc -m32 -o test_32 test_32.c