/*
 * Windows PE ARM64 startup. The loader does not pass argc/argv/envp; this stub
 * delegates argument acquisition to n00b_crt_windows_main.
 */

    .text
    .globl n00b_start
    .def n00b_start;
    .scl 2;
    .type 32;
    .endef
n00b_start:
    mov x29, xzr
    mov x30, xzr
    bl n00b_crt_windows_main
    brk #0
