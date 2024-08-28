#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "libcall.h"

#include "timing.h"

/*

    Disable ASLR:
        echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

    Run with
        LD_LIBRARY_PATH="../libcall:$LD_LIBRARY_PATH" taskset -c 61 ./victim
        
        # (change address of indirect_call and libcall_data in attacker)
        
        LD_LIBRARY_PATH="../libcall:$LD_LIBRARY_PATH" taskset -c 89 ./attacker_ca
    
    (victim on processor 89, attacker on processor 61)

    Find siblings with
         cat /sys/devices/system/cpu/cpu5/topology/thread_siblings_list
*/


//#define TEST_ATTACKER_FUNCTION
#ifdef TEST_ATTACKER_FUNCTION
void gadget(void);
#endif


int f(void)
{
    return 10;
}

void flush(void * a)
{
    asm volatile(
        "dc civac, %0\n\t"
        :
        : "r" ((uint64_t)a)
        : "memory"
    );
}



int main(int argc, char ** argv)
{
    void ** f_ptr = mmap(
        NULL,
        128, // one cacheline size
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
#ifdef TEST_ATTACKER_FUNCTION
        f_ptr[0] = &gadget;
#else
        f_ptr[0] = &f;
#endif

    do
    {
        printf("Press a key to run f...\n");
        getc(stdin);

        asm volatile(
            "ldr x15, [%0]\n\t"
            :
            : "r"(&libcall_data[20 * 128])
            : "x15"
        );

        
        //printf("gadget %" PRIu64 "\n", time_access(&gadget));
        //printf("indirect call %" PRIu64 "\n", time_access(&indirect_call));
        

        asm volatile("mov x21, #42\n\t":::);
        flush(f_ptr);
        indirect_call(f_ptr);

    } while(1);
}