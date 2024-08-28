# Spectre-BTB on ARM

## Presentation

This repository contains five Spectre-BTB attacks for ARM CPUs, ranging from a simple one in which a process attacking itself in userspace, to a complex one in which a userspace attacker leaks kernel secret!

All these attacks rely on (mis-)training the Branch Target Buffer (BTB). When encountering an indirect call (i.e., to a function pointer, `(*f)()`), the CPU attempts to predict the destination of the call. An attacker can abuse this by training the CPU to speculatively execute arbitrarily-chosen code (the "gadget"). In particular, the attacker can use a gadget that leaks a secret to a side channel: here we use a Flush+Reload buffer side channel.

## Environment

This code was tested on a [ThunderX2 CN9975](https://en.wikichip.org/wiki/cavium/thunderx2/cn9975). This microprocessor follows the ARMv8.1 ISA.

## Contributions

Extending the knowledge from [transient.fail](https://transient.fail), this repository proves that in addition to in-place Spectre-BTB attacks, out-of-place attacks also affect ARM CPUs. This is even true when the victim is a kernel module!

## Context and disclosure

This attack was developped in December 2023 as part of a student project for the Hardware Security class at ETH Zürich, with guidance from researchers of the [COMSEC group](https://comsec.ethz.ch/).

[Cavium](https://en.wikipedia.org/wiki/Cavium), the manufacturer of the CPU shown to be vulnerable, was acquired in 2018, just after the release of the ThunderX2 CN9975. The new owners were apparently not interested in the disclosure. I obtained confirmation from COMSEC that I was free to publish this code.

In any case, the value of this attack lies in the proof that strong Spectre-BTB attacks are possible on some ARM CPUs, rather than in its impact on the affected CPU. This particular CPU was sold for a short duration and is therefore unlikely to be in wide use anywhere.

## Notations

Following the notations from [[1]](https://arxiv.org/abs/1811.05441), we will distinguish between two main types of attacks:

1. Spectre-BTB-SA: the attacker and the victim code run in the same address-space.
2. Spectre-BTB-CA: the attacker and the victim code run in two different address spaces.

For each attack type, we will distinguish between:

1. In-place training (IP): the attacker can call arbitrary functions at the victim call-site during training.
2. Out-of-place training (OOP): the attacker cannot use the victin call-site, they must set-up a call-site that conflicts in the BTB with the victim call-site instead.


## Repository structure

`userspace_spectre` contains the code for the attacks:

- SA-IP and SA-OOP: in `attacker`, executable `attacker_sa`.
    + The two attacks are run one after the other.
- CA-IP and CA-OOP:
    + The victim code is the  executable `victim` in `victim_ca`.
    + The attacker code is the executable `attacker_ca` in `attacker`. 
    + There is some common code: in `libcall`, the library `libcall.so`.

Note: `libcall.so` contains the location of the indirect call (used both by the attacker and the victim) in the case of the CA-IP attack. For this implementation of the CA-OOP attack, the gadget is also placed in the common code; however the kernelspace attack will lift this requirement.

`kernelspace_spectre` contains the code for the last attack:

- CA-OOP with a victim in the kernel.
    + The victim is the kernel module in `kmod`.
    + The attacker is the (userspace, but root) executable in `attacker`.
    + (The root user is used to translate virtual addresses to physical addresses, it shouldn't matter for the attack itself)
    + `kmod_uapi` contains some structures used by the userspace program to request some layout.
    information to the kernel. A real attack would use another vector to leak this information.

### Caveat

We've tested all of the attacks and can affirm that they work, EXCEPT the userspace CA-OOP attack: after losing access to the hardware, we were not able to test whether this implementation worked. Considering that the *stronger* CA-OOP attack against the kernel works, it should be possible to adapt it so that it works too.


## Description of the kernel-side Spectre-BTB

Interestingly, it turns out that it is possible to train the BTB to mispredict to an address *in the kernel* even in userspace. 

0. Setup a Flush+Reload buffer in userspace, pass its address to the kernel.
    + (CHEAT) Here we let the kernel access the F+R buffer through its direct map, after translating the userspace virtual address to a physical address.
1. Get the address `victim_call_addr` of the victim indirect call. This address is in kernel-space.
    + (CHEAT) Here we simply get it through an `ioctl`.
2. Setup an indirect call at the address `attacker_call_addr = victim_call_addr & 0xff..f` (keeping the 48 lower bits). This address is in userspace.
    + In practice, this is done by `memcpy`-ing a function at this position on the heap, and marking it executable.
3. Get the address `gadget_addr` of the in-kernel gadget.
    + (CHEAT) Here we simply get it through an `ioctl`.
4. Set-up a signal handler: we will repeatedly try to make an indirect call to `gadget_addr`; because this is an address in kernelspace this will raise a segfault. The signal handler will simply restore the execution to the instruction right after the faulting indirect call (in the instruction sequence at `attacker_call_addr`).
5. Training! Repeatedly pass `gadget_addr` to the code at `attacker_call_addr`.
    + This causes a segfault caught by our signal handler, which resumes execution.
6. Victim. Have the kernel execute the code at  `victim_call_addr`.
    + The CPU mispredicts the destination of the indirect call and speculatively executes the code at `gadget_addr`.
    + This leaks a secret into the F+R buffer.
7. The attacker reloads the F+R buffer and obtains the secret.

## Demo of `kernelspace_spectre`

In this demo, the secret value in the kernel is `8`, and it is stored in the register `x21`. The gadget will make the 8-th slot of the F+R buffer hot, and this will be detected by the attacker.

With the kernel module loaded:

```console
$ time sudo ./attacker 
fr_buf_va=1337000000, fr_buf_pa=9fab600000, fr_buf_kva=ffff009f2b600000
&kernel_indirect_call=0xffff80000957b000  &kernel_gadget=0xffff80000958b000
attacker_page at 0x80000957b000, &indirect_call_reloc=0x80000957b000
low atimes:
low atimes:
low atimes:
low atimes:
low atimes:
low atimes:
low atimes:
low atimes:
low atimes:8(12) 
MISPREDICT   access_time=12

real    0m2.788s
user    0m0.142s
sys     0m2.591s
```

`low atime` means that the access time for this entry in the F+R buffer is below a given threshold (here: 28 cycles). After repeatedly probing the F+R buffer, the attacker detects that it takes only 12 cycles to access the 8-th entry in the F+R buffer.

From start to finish, this attack executed in less than 3 seconds!

## Bibiliography

[1] *[
A Systematic Evaluation of Transient Execution Attacks and Defenses
](https://arxiv.org/abs/1811.05441)*, Claudio Canella, Jo Van Bulck, Michael Schwarz, Moritz Lipp, Benjamin von Berg, Philipp Ortner, Frank Piessens, Dmitry Evtyushkin, Daniel Gruss

