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
elif target_os == 'windows' and not link_args.contains('--ncc-system-entry')
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

# Built WITHOUT -fsanitize=thread when -Duse_n00b_tsan is on, as their own
# static_library. Two reasons. The allocator, the mmap tree and the callstack
# pool sit underneath the detector's own shadow allocation, and the collector
# reads other threads' stacks and registers by design, so instrumenting it
# reports its contract as a race. Instrumenting them is also where most of the
# slowdown comes from: n00b_gc_stack_push runs on every GC-framed call.
#
# This exists as a separate target rather than as .tsan_ignore entries because
# ncc does not forward -fsanitize-ignorelist to clang, so that file has no
# effect. See src/tsan/README.md.
n00b_core_uninstrumented_src = files(
    'thread.c',
    'callstack.c',
    'mmaps.c',
    'alloc.c',
    'alloc_interpose.c',
    'arena.c',
    'pool.c',
    'stw.c',
    'gc.c',
    'gc_baked.c',
    'gc_map.c',
    'gc_type_map.c',
)

n00b_core_src = files(
    'exit.c',
    'init.c',
    '../crt/n00b_crt.c',
    '../crt/n00b_crt_comptime_shim.c',
    'env.c',
    'crash.c',
    'crash_capture.c',
    'signals.c',
    'static_objects.c',
    'codegen_abi_guard.c',
    'static_init_runtime.c',
    'static_image.c',
    'memory_info.c',
    'hash.c',
    'transient_map.c',
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
    'crc32.c',   # IEEE 802.3 / zlib CRC-32 (D-039) — SPLIT carrier slice pre-check.
    'sha512.c',  # SHA-384 + SHA-512 (FIPS 180-4) — needed by RS384/RS512 JWS.
    'std_streams.c',
)

if target_os == 'windows' and not link_args.contains('--ncc-system-entry')
    n00b_core_src += files('../crt/n00b_crt_windows.c')
endif
