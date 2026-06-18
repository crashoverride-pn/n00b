/*
 * Adapted from musl crt startup code (MIT licensed). See the project license
 * notes for musl attribution. This stub owns only the platform argument capture
 * and transfer to n00b_crt_main; runtime initialization is generated C.
 */

    .text
    .globl n00b_start
    .type n00b_start,%function
n00b_start:
    mov x29, xzr
    mov x30, xzr

    ldr x0, [sp]
    add x1, sp, #8
    add x2, x1, x0, lsl #3
    add x2, x2, #8

    bl n00b_crt_main
    brk #0

    .size n00b_start, .-n00b_start
    .section .note.GNU-stack,"",@progbits
