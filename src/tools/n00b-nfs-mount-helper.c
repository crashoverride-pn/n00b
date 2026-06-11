// n00b-nfs-mount-helper — dedicated setuid-root loopback NFS mount helper for
// the macOS execute-from-bundle NFS execution mode (WP-016, D-050 / OQ-2).
//
// This is a MINIMAL setuid-root binary: it performs ONLY the validated loopback
// NFS mount of `localhost:/` (fixed host 127.0.0.1, caller-supplied port) at the
// caller-supplied absolute mount point, and nothing else. It carries no
// entitlements (ad-hoc signing is sufficient).
//
// The ONLY OS-boundary call is the final image replacement,
// `execv("/sbin/mount_nfs", validated_argv)`: libn00b has NO wrapper for
// replacing the current process image, and `/sbin/mount_nfs` is a base-macOS
// (macOS-only) binary that performs the actual privileged mount. This is the
// §2.10 raw-syscall exemption, mirroring src/util/proc.c:1-9. Everything else
// — argv parsing, validation, diagnostics — uses n00b primitives. Argv is
// rejected (nonzero exit + diagnostic, NO mount) on any deviation from the
// fixed shape `n00b-nfs-mount-helper <tcp-port> <absolute-mount-point>`.
//
// Built/installed on macOS ONLY (Linux NFS is out of scope for WP-016).

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "adt/option.h"
#include "adt/result.h"
#include "conduit/print.h"
#include "text/strings/string_ops.h"
#include "util/parse_num.h"

#if defined(__MACH__)
#include <unistd.h>
#endif

#define HELPER_EXIT_BAD_ARGS  2
#define HELPER_EXIT_EXEC_FAIL 3

#if !defined(__MACH__)

// The helper is macOS-only. On any other platform it must never mount; build a
// stub that fails safe so an accidental non-darwin build cannot misbehave.
int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_eprintf("n00b-nfs-mount-helper: NFS mount mode is macOS-only");
    n00b_exit(HELPER_EXIT_BAD_ARGS);
    return HELPER_EXIT_BAD_ARGS;
}

#else

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    // Fixed-shape argv: <tcp-port> <absolute-mount-point>. Reject anything else
    // with a nonzero exit + diagnostic and NO mount.
    if (argc != 3) {
        n00b_eprintf("n00b-nfs-mount-helper: usage: n00b-nfs-mount-helper "
                     "<tcp-port> <absolute-mount-point>");
        n00b_exit(HELPER_EXIT_BAD_ARGS);
    }

    n00b_string_t *port_str    = n00b_string_from_cstr(argv[1]);
    n00b_string_t *mount_point = n00b_string_from_cstr(argv[2]);

    // The port must be a valid TCP port (1..65535).
    auto port_result = n00b_parse_i64_string(port_str);

    if (n00b_result_is_err(port_result)) {
        n00b_eprintf("n00b-nfs-mount-helper: port is not a number");
        n00b_exit(HELPER_EXIT_BAD_ARGS);
    }

    int64_t port = n00b_result_get(port_result);

    if (port < 1 || port > 65535) {
        n00b_eprintf("n00b-nfs-mount-helper: port out of range (1..65535)");
        n00b_exit(HELPER_EXIT_BAD_ARGS);
    }

    // The mount point must be a non-empty absolute path.
    if (mount_point->u8_bytes == 0 || mount_point->data[0] != '/') {
        n00b_eprintf("n00b-nfs-mount-helper: mount point must be an absolute "
                     "path");
        n00b_exit(HELPER_EXIT_BAD_ARGS);
    }

    // Reject any ".." path component. Defense-in-depth for a setuid-root binary:
    // without this, a caller-supplied path like "/tmp/x/../../etc" would let the
    // privileged mount land outside the intended directory. The path is already
    // absolute, so a ".." component can only appear as "/../" or a trailing
    // "/.." ("/..foo" is a normal filename and stays allowed).
    if (n00b_unicode_str_contains(mount_point, r"/../")
        || n00b_unicode_str_ends_with(mount_point, r"/..")) {
        n00b_eprintf("n00b-nfs-mount-helper: mount point must not contain a "
                     "'..' path component");
        n00b_exit(HELPER_EXIT_BAD_ARGS);
    }

    // Build the validated NFS mount options string for the loopback export.
    n00b_string_t *opts =
        n00b_unicode_str_cat(r"vers=3,tcp,port=", port_str);
    opts = n00b_unicode_str_cat(opts, r",mountport=");
    opts = n00b_unicode_str_cat(opts, port_str);
    opts = n00b_unicode_str_cat(opts, r",nolocks,soft,timeo=10,retrans=2");

    // Build the validated argv for /sbin/mount_nfs:
    //   /sbin/mount_nfs -o <opts> localhost:/ <mount_point>
    // n00b strings are NUL-terminated, so `->data` is a valid C string for
    // execv. This is the §2.10 raw OS-boundary image replacement.
    char *exec_argv[] = {
        (char *)"/sbin/mount_nfs",
        (char *)"-o",
        opts->data,
        (char *)"localhost:/",
        mount_point->data,
        nullptr,
    };

    execv("/sbin/mount_nfs", exec_argv);

    // execv only returns on failure.
    n00b_eprintf("n00b-nfs-mount-helper: execv of /sbin/mount_nfs failed");
    n00b_exit(HELPER_EXIT_EXEC_FAIL);
    return HELPER_EXIT_EXEC_FAIL;
}

#endif // __MACH__
