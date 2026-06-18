/*
 * Windows PE x64 startup. The loader does not pass argc/argv/envp; this stub
 * preserves ABI stack alignment/shadow space and delegates argument acquisition
 * to n00b_crt_windows_main.
 */

    .text
    .globl n00b_start
    .def n00b_start;
    .scl 2;
    .type 32;
    .endef
n00b_start:
    xorq %rbp, %rbp
    subq $40, %rsp
    call n00b_crt_windows_main
    ud2
