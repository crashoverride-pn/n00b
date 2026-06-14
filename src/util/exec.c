// Process-image replacement primitive (`exec`).
//
// The public API in util/exec.h is platform-neutral. The only raw OS-boundary
// surface is the `execvp`/`execve` pair inside `n00b_exec`: § 2.10 — image
// replacement has no pre-existing n00b wrapper, so this module IS that wrapper,
// mirroring the justified raw `execv` in the object-bundle exec-replace path
// (src/compiler/objfile/obj_bundle_exec_run.c) and the raw process calls in
// src/util/proc.c. On success `exec*` never returns; the surrounding result
// machinery only ever observes the failure path.

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/array.h"
#include "adt/result.h"
#include "util/exec.h"

#include <unistd.h>

n00b_result_t(bool)
n00b_exec(n00b_string_t *cmd) _kargs
{
    n00b_array_t(n00b_string_t *) *argv      = nullptr;
    n00b_array_t(n00b_string_t *) *env       = nullptr;
    n00b_allocator_t              *allocator = nullptr;
}
    // No `requires` block: a null `cmd` is a documented, body-guarded Err per
    // D-031 (a bare `requires {}` would assert nothing — in-tree convention,
    // cf. obj_bundle.c:11041).
    ensures {
        // exec-replace never returns on success; the only returned value is the
        // failure payload, so the result is always Err and result.ok is false
        // (matches the n00b_obj_bundle_exec_run exec-replace precedent).
        !result.is_ok || result.ok == false;
    }
{
    if (cmd == nullptr) {
        return n00b_result_err(bool, N00B_EXEC_ERR_NULL_CMD);
    }

    size_t argc = (argv == nullptr) ? 0 : (size_t)n00b_array_len(*argv);
    size_t envc = (env == nullptr) ? 0 : (size_t)n00b_array_len(*env);

    // Allocate BOTH raw vectors up front. These are the LAST allocations before
    // exec; after this point we only read interior `->data` pointers and call
    // exec*, so no allocation (and therefore no GC move) occurs between filling
    // the vectors and the exec call, and the interior pointers stay valid
    // (mirrors the exec-replace path in obj_bundle_exec_run.c).
    char **raw_argv = n00b_alloc_array(char *,
                                       (argc == 0 ? 1 : argc) + 1,
                                       .allocator = allocator);
    char **raw_envp = (envc == 0)
                          ? nullptr
                          : n00b_alloc_array(char *,
                                             envc + 1,
                                             .allocator = allocator);

    if (argc == 0) {
        raw_argv[0] = cmd->data;
        raw_argv[1] = nullptr;
    }
    else {
        for (size_t i = 0; i < argc; i++) {
            n00b_string_t *a = n00b_array_get(*argv, (int64_t)i);
            raw_argv[i]      = a->data;
        }
        raw_argv[argc] = nullptr;
    }

    if (raw_envp != nullptr) {
        for (size_t i = 0; i < envc; i++) {
            n00b_string_t *e = n00b_array_get(*env, (int64_t)i);
            raw_envp[i]      = e->data;
        }
        raw_envp[envc] = nullptr;
    }

    // § 2.10 raw OS boundary. execvp resolves `cmd` via PATH and inherits the
    // current environment; execve takes `cmd` as a literal path with the
    // supplied environment.
    if (raw_envp == nullptr) {
        execvp(cmd->data, raw_argv);
    }
    else {
        execve(cmd->data, raw_argv, raw_envp);
    }

    // exec* only returns on failure.
    return n00b_result_err(bool, N00B_EXEC_ERR_LAUNCH_FAILED);
}

n00b_string_t *
n00b_exec_err_str(n00b_err_t code)
{
    switch (code) {
    case 0:
        return r"ok";
    case N00B_EXEC_ERR_NULL_CMD:
        return r"exec: null command";
    case N00B_EXEC_ERR_LAUNCH_FAILED:
        return r"exec: process image replacement failed";
    default:
        return r"unknown exec error";
    }
}
