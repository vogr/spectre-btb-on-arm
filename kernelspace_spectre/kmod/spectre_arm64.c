#include <linux/module.h>
#include <linux/proc_fs.h>
#include <asm/memory.h>
#include <linux/fs.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include "../kmod_uapi/kmod_spectre_arm64.h"


typedef void (*func_ptr)(void);


static struct proc_dir_entry *procfs_file;
static struct synth_gadget_desc desc = {};


#define str(s) #s
#define xstr(s) str(s)

#define NOP_STR(n) \
    ".rept " xstr(n) "\n\t"\
    "nop\n\t"\
    ".endr\n\t"



/* Function that the victim wants to call by indirect call.
   Implementation does not matter. */
void spec_dummy(void);
asm(
    ".align 0x10\n\t"
    "spec_dummy:\n\t"
    "ret\n\t"
);

/* Indirect call to fp. Register x0 contains a secret, and
   x1 the address of a F+R buffer.
   The kernel module will call this function with fp=spec_dummy.
   The goal of the attack is to have the CPU mispredict the destination
   of this call and execute spec_gadget instead. */
void spec_src(u64 s, u64 rb, func_ptr const * fp);
asm(
    ".align 0x10\n\t"
    "spec_src:\n\t"
    "stp     x29, x30, [sp, #-32]!\n\t"
    "mov     x29, sp\n\t"
    "dc civac, x2\n\t" // flush to_dummy_ptr
    "dsb sy\n\tisb\n\t" // full fence 
    //NOP_STR(0x40)
    "ldr x2, [x2]\n\t"
    "blr x2\n\t"
    "ldp     x29, x30, [sp], #32\n\t"
    "ret\n\t"
);

/* In kernel gadget. Leaks the value of x0 into
   the F+R buffer present in x1.*/
void spec_gadget(void);
asm(
    ".align 0x10\n\t"
    "spec_gadget:\n\t"
    "and x0, x0, #0xff\n\t"
    "lsl x0, x0, #7\n\t"
    "ldr x0, [x1, x0]\n\t"
    "mov x0, #0\n\t"
    "gadget_loop:\n\t"
    "add x0, x0, #1\n\t"
    "cmp x0, #0x1000\n\t"
    "b.le gadget_loop\n\t"
    "ret\n\t"
);

static const func_ptr to_dummy_ptr[1]={&spec_dummy};

static long handle_ioctl(struct file *filp, unsigned int request, unsigned long argp) {
    unsigned long reload_buf;
    if (request == REQ_GADGET_DESC) {
        /* Return the location of spec_src and of spec_gadget so that the userspace attacker
           can train an indirect call (colliding with spec_src) to predict to spec_gadget */
        if (copy_to_user((void *)argp, &desc, sizeof(struct synth_gadget_desc)) != 0) {
            return -EFAULT;
        }
    }
    if (request == REQ_SPEC) {
        /* Victim code: attempt to run spec_dummy through an indirect call in spec_src.
           Pass the address of the F+R buffer provided by the attacker. The gadget will
           attempt to leak the secret in the F+R buffer.
         */
        if (copy_from_user(&reload_buf, (void *)argp, 8) != 0) {
            return -EFAULT;
        }

#define SECRET_VALUE 0x8
        pr_info("run indirect call in kernel...\n");
        spec_src(SECRET_VALUE, reload_buf, to_dummy_ptr);
        asm("finish:");
    }
    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = handle_ioctl,
    .open = nonseekable_open,
    .llseek = no_llseek,
};

static void mod_spectre_exit(void) {
    proc_remove(procfs_file);
}

static int mod_spectre_init(void) {
    desc.kbr_gadget = ((u64)&spec_gadget);
    desc.kbr_src = ((u64)&spec_src);
    pr_info("kbr_src %lx\n", desc.kbr_src);
    pr_info("kbr_gadget %lx\n", desc.kbr_gadget);
    procfs_file = proc_create(PROC_SPECTRE_ARM64, 0, NULL, &fops);
    return 0;
}

module_init(mod_spectre_init);
module_exit(mod_spectre_exit);

MODULE_LICENSE("GPL");
