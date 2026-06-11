// PoC: prove no-extract execute-from-memory on macOS via the n00b VFS NFS
// frontend. Serves a real (signed) binary out of the in-memory VFS backend over
// a loopback NFSv3 server, mounts it with the OS's built-in NFS client, and
// fork+execv's the served path. Nothing is written to disk.
//
// Must run as root (mounting requires privilege on macOS). Usage:
//   sudo nfs-exec-poc [/path/to/binary]   (default: /bin/echo)
//
// Throwaway de-risk tool: uses libc for mount/exec/mkdir (no n00b wrappers for
// those), n00b for everything else.

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "conduit/print.h"
#include "text/strings/format.h"
#include "compiler/objfile/bstream.h"
#include "vfs/vfs.h"
#include "vfs/backend_memory.h"
#include "vfs/frontend_nfs.h"
#include "vfs/types.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>

extern char **environ;

#define POC_PORT  20049
#define POC_MNT   "/tmp/n00b_nfs_poc_mnt"
#define POC_VPATH "/prog"
#define POC_EXEC  POC_MNT POC_VPATH

// Spawn argv[0] with the given argv, wait, and return its exit code (or <0).
static int
run_cmd(char *const cmd_argv[])
{
    pid_t pid    = 0;
    int   status = 0;

    int rc = posix_spawn(&pid, cmd_argv[0], nullptr, nullptr, cmd_argv, environ);

    if (rc != 0) {
        return -1;
    }
    if (waitpid(pid, &status, 0) < 0) {
        return -2;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return -3;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_string_t *payload = (argc > 1)
                                 ? n00b_string_from_cstr(argv[1])
                                 : r"/bin/echo";

    n00b_printf("nfs-exec-poc: serving «#» from in-memory VFS over loopback "
                "NFS, then exec'ing it (no disk extraction)",
                payload);

    if (geteuid() != 0) {
        n00b_eprintf("nfs-exec-poc: must run as root to mount; re-run with sudo");
        n00b_shutdown();
        return 2;
    }

    // 1. Read the real binary's bytes (binary-safe).
    auto sr = n00b_bstream_from_file(payload->data);

    if (n00b_result_is_err(sr)) {
        n00b_eprintf("nfs-exec-poc: cannot read «#»", payload);
        n00b_shutdown();
        return 1;
    }

    n00b_buffer_t *bytes = n00b_result_get(sr)->buf;

    // 2. Build a VFS with an in-memory backend mounted at "/".
    n00b_vfs_t         *vfs     = n00b_result_get(n00b_vfs_new());
    n00b_vfs_backend_t *backend = n00b_result_get(n00b_vfs_backend_memory_new());

    if (n00b_result_is_err(n00b_vfs_mount(vfs, r"/", backend, 0))) {
        n00b_eprintf("nfs-exec-poc: vfs mount failed");
        n00b_shutdown();
        return 1;
    }

    // Ensure the export root exists as a directory: the NFS client GETATTRs /
    // LOOKUPs the mount root, and an in-memory backend has no implicit root.
    // (The real execute-from-bundle runtime sets this up the same way.)
    n00b_vfs_mkdir(vfs, r"/");

    // 3. Put the binary bytes at the VFS path.
    auto fh_r = n00b_vfs_open(vfs, n00b_string_from_cstr(POC_VPATH), N00B_VFS_O_W);

    if (n00b_result_is_err(fh_r)) {
        n00b_eprintf("nfs-exec-poc: vfs open failed");
        n00b_shutdown();
        return 1;
    }

    n00b_vfs_fh_t fh = n00b_result_get(fh_r);
    n00b_vfs_write(vfs, fh, bytes);
    n00b_vfs_close(vfs, fh);

    // 4. Start the loopback NFSv3 server over that VFS.
    auto fe_r = n00b_vfs_frontend_nfs_new(vfs, n00b_string_from_cstr(POC_MNT), POC_PORT);

    if (n00b_result_is_err(fe_r)) {
        n00b_eprintf("nfs-exec-poc: nfs frontend create failed");
        n00b_shutdown();
        return 1;
    }

    n00b_vfs_frontend_t *fe = n00b_result_get(fe_r);

    if (n00b_result_is_err(n00b_vfs_frontend_start(fe))) {
        n00b_eprintf("nfs-exec-poc: nfs frontend start failed (port «#» busy?)",
                     (int64_t)POC_PORT);
        n00b_shutdown();
        return 1;
    }

    // 5. Mount it with the OS NFS client.
    mkdir(POC_MNT, 0755);

    n00b_string_t *opts = n00b_cformat(
        "vers=3,tcp,port=«#»,mountport=«#»,nolocks,soft,timeo=10,retrans=2",
        (int64_t)POC_PORT,
        (int64_t)POC_PORT);

    char *mount_argv[] = {
        (char *)"/sbin/mount_nfs",
        (char *)"-o",
        opts->data,
        (char *)"localhost:/",
        (char *)POC_MNT,
        nullptr,
    };

    n00b_printf("nfs-exec-poc: mount_nfs -o «#» localhost:/ «#»", opts, n00b_string_from_cstr(POC_MNT));

    int mrc = run_cmd(mount_argv);

    if (mrc != 0) {
        n00b_eprintf("nfs-exec-poc: mount_nfs failed (rc=«#»)", (int64_t)mrc);
        n00b_vfs_frontend_stop(fe);
        n00b_shutdown();
        return 1;
    }

    n00b_printf("nfs-exec-poc: mounted; exec'ing «#» (served from memory)",
                n00b_string_from_cstr(POC_EXEC));

    // 6. fork + execv the served binary; observe it actually runs.
    int   child_status = 0;
    pid_t pid          = fork();

    if (pid == 0) {
        char *exec_argv[] = {
            (char *)POC_EXEC,
            (char *)"n00b-nfs-exec-ok",
            nullptr,
        };
        execv(POC_EXEC, exec_argv);
        _exit(127); // execv failed
    }

    waitpid(pid, &child_status, 0);

    int exit_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;

    if (exit_code == 127) {
        n00b_eprintf("nfs-exec-poc: execv of served binary FAILED");
    }
    else {
        n00b_printf("nfs-exec-poc: served binary ran, exit code = «#» «#»",
                    (int64_t)exit_code,
                    (exit_code == 0) ? r"(SUCCESS — exec-from-memory works)"
                                     : r"(ran, non-zero exit)");
    }

    // 7. Cleanup: unmount + stop the server.
    char *umount_argv[] = {(char *)"/sbin/umount", (char *)POC_MNT, nullptr};
    run_cmd(umount_argv);
    n00b_vfs_frontend_stop(fe);

    n00b_shutdown();
    return (exit_code == 0) ? 0 : 1;
}
