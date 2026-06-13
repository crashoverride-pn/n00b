/*
 * Adapted from musl crt startup code (MIT licensed). Darwin uses Mach-O symbol
 * spelling and ncc selects this entry with -Wl,-e,_n00b_start. The selected
 * entry receives argc/argv/envp in x0/x1/x2.
 */

    .text
    .globl _n00b_start
    .p2align 2
_n00b_start:
    mov x29, xzr
    mov x30, xzr
    bl _n00b_crt_main
    brk #0
