# Debugger substrate: hardware watchpoints + breakpoints.
#
# Platform-neutral surface + slot registry, plus the per-OS debug-register
# backend. The Linux backend and software breakpoints land in later phases.

n00b_debug_src = files(
    'debug.c',
    'watchpoint.c',
    'breakpoint.c',
    'registry.c',
)

if host_machine.system() == 'darwin'
    n00b_debug_src += files('platform/darwin.c')
elif host_machine.system() == 'linux'
    n00b_debug_src += files('platform/linux.c')
elif host_machine.system() == 'windows'
    n00b_debug_src += files('platform/windows.c')
endif
