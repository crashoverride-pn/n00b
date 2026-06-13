# Conduit pub/sub system — core API plus platform-conditional IO
# backends and the Windows-specific subprocess implementation.
#
# This subdir adds to the top-level `deps` variable (Linux liburing,
# Windows ws2_32/synchronization/advapi32) — meson's subdir() inlines
# this file into the parent scope so those modifications are visible
# to the rest of the build.

n00b_conduit_src = files(
    'conduit.c',
    'subscription.c',
    'thread_lifecycle.c',
    'service.c',
    # IO core
    'io.c',
    # Managed FDs
    'fd_managed.c',
    'fd_writer.c',
    'local.c',
    'socket.c',
    'socket_udp.c',   # UDP datagram conduit (used by QUIC stack).
    'file.c',
    'timer.c',
    'user_event.c',
    'signal.c',
    'proc_lifecycle.c',
    'file_change.c',
    # Pipeline / transforms
    'xform.c',
    'xform_linebuf.c',
    'xform_ansi_strip.c',
    'xform_render.c',
    'xform_hexdump.c',
    'xform_json.c',
    'xform_http.c',
    'xform_marshal.c',
    # Print API
    'print.c',
)

n00b_conduit_link_whole_libs = []

# Platform-conditional IO backends.
if target_os != 'windows'
    n00b_conduit_src += files(
        'io_poll.c',
        'subproc.c',
    )
endif

if target_os == 'darwin' or target_os in ['freebsd', 'openbsd', 'netbsd']
    n00b_conduit_src += files('io_kqueue.c')
endif

if target_os == 'linux'
    n00b_conduit_src += files('io_epoll.c')
    liburing_dep = dependency('liburing', required: false)
    if liburing_dep.found()
        n00b_conduit_src += files('io_uring.c')
        deps += liburing_dep
    endif
endif

if target_os == 'darwin'
    conduit_xpc_objc_args = [
        '-Wextra',
        '-g',
        '-fno-omit-frame-pointer',
        '-fPIC',
        '-std=c23',
        '-fobjc-arc',
        '-isysroot', macos_sdk,
        '-DN00B_HOST_OS=' + host_machine.system(),
        '-DN00B_HOST_CPU=' + host_machine.cpu_family(),
    ]
    if conf_dev_mode
        conduit_xpc_objc_args += '-DN00B_DEV'
    endif
    if conf_debug
        conduit_xpc_objc_args += '-DN00B_DEBUG'
    endif

    n00b_conduit_link_whole_libs += static_library(
        'n00b_conduit_xpc_darwin',
        ['local_xpc_darwin.m'],
        include_directories: incdir,
        dependencies: deps,
        objc_args: conduit_xpc_objc_args,
        link_args: link_args,
    )
endif

if target_os == 'windows'
    n00b_conduit_src += files(
        'io_wsa.c',
        'local_windows.c',
        'subproc_windows.c',
    )
    winsock_dep = cc.find_library('ws2_32', required: true)
    sync_dep    = cc.find_library('synchronization', required: true)
    advapi_dep  = cc.find_library('advapi32', required: true)
    deps += [winsock_dep, sync_dep, advapi_dep]
endif
