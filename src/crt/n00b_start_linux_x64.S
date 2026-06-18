/*
 * Adapted from musl crt startup code (MIT licensed). See the project license
 * notes for musl attribution. This stub owns only the platform argument capture
 * and transfer to n00b_crt_main; runtime initialization is generated C.
 */

    .text
    .globl n00b_start
    .type n00b_start,@function
n00b_start:
    xorl %ebp, %ebp

    movq (%rsp), %rdi
    leaq 8(%rsp), %rsi
    leaq 16(%rsp,%rdi,8), %rdx

    andq $-16, %rsp
    call n00b_crt_main
    ud2

    .size n00b_start, .-n00b_start
    .section .note.GNU-stack,"",@progbits
