/*
 * Adapted from musl crt startup code (MIT licensed). Darwin uses Mach-O symbol
 * spelling and ncc selects this entry with -Wl,-e,_n00b_start. The selected
 * entry receives argc/argv/envp in the C argument registers.
 */

    .text
    .globl _n00b_start
    .p2align 4, 0x90
_n00b_start:
    xorl %ebp, %ebp
    andq $-16, %rsp
    callq _n00b_crt_main
    ud2
