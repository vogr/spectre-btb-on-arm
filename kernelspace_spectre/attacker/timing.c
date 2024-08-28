#include "timing.h"


void full_fence(void)
{
    asm volatile(
        "dsb sy\n\t"
        "isb\n\t"
        :
        :
        :
    );
}


uint64_t time_access(void const * a)
{
    // memory access is fenced
    uint64_t t;
    asm volatile(
        "dsb sy\n\t"
        "isb\n\t"
        "mrs x1, cntvct_el0\n\t"
        "dsb sy\n\t"
        "ldrb w0, [%1]\n\t"
        "dsb sy\n\t"
        "isb\n\t"
        "mrs x2, cntvct_el0\n\t"
        "sub %0, x2, x1\n\t"
        : "=r"(t)
        : "r"((uint64_t)a)
        : "x1", "x2"
    );
    return t;
}



