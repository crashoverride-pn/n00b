/*
 * exec_abi.c — plain-C ABI shim layer for the exec primitive. The ONLY file in
 * this module where `const char *` parameters and other libc-shaped APIs are
 * allowed (n00b-api-guidelines § 11). These symbols are installed as FFI targets
 * (n00b_ffi_install_simple) so embedded n00b policy programs can call them with a
 * simple scalar/pointer ABI, avoiding the `_kargs` / `n00b_result_t` struct ABI.
 *
 * The shim ALWAYS calls IN to the ncc-flavored surface (n00b_exec in
 * util/exec.h), keeping the single `exec*` image-replacement boundary there.
 * Internal libn00b code never calls these shims; the FFI runtime does.
 */

#include "n00b.h"
#include "adt/array.h"
#include "adt/result.h"
#include "core/string.h"
#include "util/exec.h"

int64_t
n00b_exec_shim(const char *cmd, const char *const *argv)
{
    if (cmd == nullptr) {
        return (int64_t)N00B_EXEC_ERR_NULL_CMD;
    }

    n00b_string_t *cmd_str = n00b_string_from_cstr(cmd);

    // The raw C argv is null-terminated (or null for no args). Convert to an
    // n00b array so the single exec boundary stays in n00b_exec.
    n00b_array_t(n00b_string_t *) *argv_arr = nullptr;

    if (argv != nullptr && argv[0] != nullptr) {
        size_t n = 0;
        while (argv[n] != nullptr) {
            n++;
        }

        argv_arr  = n00b_alloc(n00b_array_t(n00b_string_t *));
        *argv_arr = n00b_array_new(n00b_string_t *, (int64_t)n);

        for (size_t i = 0; i < n; i++) {
            n00b_array_set(*argv_arr, i, n00b_string_from_cstr(argv[i]));
        }
    }

    auto r = n00b_exec(cmd_str, .argv = argv_arr);

    // n00b_exec only returns on failure; surface its error code.
    return (int64_t)n00b_result_get_err(r);
}
