# Sources for the n00b core: allocators, GC, threading primitives,
# strings core, type registry, sha256, etc.

n00b_crt_host_stub_file = []
n00b_crt_host_stub_src  = []

if target_os == 'darwin'
    if target_arch == 'aarch64' or target_arch == 'arm64'
        n00b_crt_host_stub_file = files('../crt/n00b_start_macos_arm64.S')
    elif target_arch == 'x86_64'
        n00b_crt_host_stub_file = files('../crt/n00b_start_macos_x64.S')
    endif
elif target_os == 'linux'
    if target_arch == 'aarch64' or target_arch == 'arm64'
        n00b_crt_host_stub_file = files('../crt/n00b_start_linux_arm64.S')
    elif target_arch == 'x86_64'
        n00b_crt_host_stub_file = files('../crt/n00b_start_linux_x64.S')
    endif
elif target_os == 'windows'
    if target_arch == 'aarch64' or target_arch == 'arm64'
        n00b_crt_host_stub_file = files('../crt/n00b_start_windows_arm64.S')
    elif target_arch == 'x86_64'
        n00b_crt_host_stub_file = files('../crt/n00b_start_windows_x64.S')
    endif
endif

if n00b_crt_host_stub_file.length() > 0
    n00b_crt_asm = find_program('clang', required: true)
    n00b_crt_host_stub_src += custom_target('n00b_crt_host_stub_obj',
        input: n00b_crt_host_stub_file,
        output: 'n00b_crt_host_stub.o',
        command: [n00b_crt_asm, '-c', '@INPUT@', '-o', '@OUTPUT@'],
    )
endif

n00b_core_src = files(
    'exit.c',
    'init.c',
    '../crt/n00b_crt.c',
    'env.c',
    'thread.c',
    'callstack.c',
    'crash.c',
    'crash_capture.c',
    'signals.c',
    'mmaps.c',
    'static_objects.c',
    'static_image.c',
    'alloc.c',
    'alloc_interpose.c',
    'arena.c',
    'pool.c',
    'memory_info.c',
    'hash.c',
    'stw.c',
    'gc.c',
    'gc_map.c',
    'gc_type_map.c',
    'buffer.c',
    'file_map.c',
    'file.c',
    'data_lock.c',
    'string.c',
    'lock_accounting.c',
    'mutex.c',
    'rwlock.c',
    'spinlock.c',
    'condition.c',
    'time.c',
    'type_registry.c',
    'builtin_types.c',
    'sha256.c',
    'sha512.c',  # SHA-384 + SHA-512 (FIPS 180-4) — needed by RS384/RS512 JWS.
    'std_streams.c',
) + n00b_crt_host_stub_src

if target_os == 'windows'
    n00b_core_src += files('../crt/n00b_crt_windows.c')
endif
