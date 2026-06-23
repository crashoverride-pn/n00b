# Virtual filesystem — pluggable backends, in-memory + local frontends,
# plus platform-conditional NFS/FUSE frontends.

n00b_vfs_src = files(
    'types.c',
    'backend.c',
    'backend_memory.c',
    'backend_local.c',
    'backend_s3.c',
    'hooks.c',
    'vfs.c',
    'cache.c',
    'frontend.c',
)

# NFSv3 frontend is portable userspace (POSIX sockets + pthread); enabled on
# Linux and macOS (both have a built-in kernel NFS client to mount it).
if target_os == 'linux' or target_os == 'darwin'
    n00b_vfs_src += files('frontend_nfs.c')
endif

if target_os == 'darwin'
    fuse_dep_opt = dependency('fuse', required: false)
    if fuse_dep_opt.found()
        n00b_vfs_src += files('frontend_fuse.c')
        deps += fuse_dep_opt
        exe_c_args += ['-DN00B_HAVE_FUSE=1']
    endif
endif
