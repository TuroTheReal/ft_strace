#include <stdio.h>

int main() {
    printf("Hello from %zu-bit program!\n", sizeof(void*) * 8);
    return 0;
}