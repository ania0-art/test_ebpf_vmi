#include <stdio.h>
#include <stdint.h>

int main(void)
{
    long ret;
    asm volatile (
        "int $0x80"
        : "=a"(ret)         // 返回值在 eax
        : "0"(20)           // i386 __NR_getpid = 20，放到同一个 eax
        : "memory", "cc"
    );

    printf("int80 getpid returned: %ld\n", ret);
    return 0;
}
