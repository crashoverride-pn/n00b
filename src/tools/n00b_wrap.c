// n00b-wrap — wrap one or more target binaries behind an EMBEDDED_N00B policy
// PROGRAM, in a single self-detecting binary (WP-017, D-051/D-052).
//
// Two modes, chosen by self-inspection (NOT by argv[0]):
//
//   * HOST mode — when this very executable already CARRIES an object bundle
//     with an EMBEDDED_N00B EXECUTION policy. It reads its own bytes, decodes the
//     bundle, and runs the embedded policy as a full n00b PROGRAM via
//     `_n00b_obj_bundle_run_wrapped`. The canonical policy (the agent-guard,
//     below) is a CONTROLLER: on allow it execs the wrapped target via the
//     `exec_target` FFI shim (exec-replace — never returns here); on deny it
//     `eprint`s a refusal and returns a nonzero verdict, which becomes this
//     process's exit code.
//
//   * BUILDER mode — when this executable carries no such bundle (the bare,
//     freshly-built `n00b-wrap`). It embeds the given target binaries plus a
//     policy program into a COPY of its own bytes, producing a new wrapped binary
//     that will self-detect as HOST when run. Usage:
//
//         n00b-wrap <target>... -o <output> [--policy <file>]
//
//     With no `--policy`, the embedded agent-guard program (below) is used: it
//     blocks an AI agent (or a shell spawned, even indirectly, by an agent) from
//     directly running the wrapped command, while letting humans and non-shell
//     tools through. The ancestry FACTS + exec EFFECT are FFI shims installed by
//     the wrap runtime (see src/util/wrap_policy.c).
//
// Replaces the retired src/tools/agent_guard.c PATH-proxy (D-051): the policy is
// now a real n00b program, not a special-purpose proxy binary.

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "conduit/print.h"
#include "slay/commander.h"
#include "util/path.h"
#include "util/proc.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"

#define WRAP_EXIT_USAGE 2
#define WRAP_EXIT_ERROR 1

// Domain error codes for the file-reading helpers (negative, errno-disjoint).
#define WRAP_ERR_OPEN    (-1) /**< open() of the path failed. */
#define WRAP_ERR_READ    (-2) /**< reading the opened file failed. */
#define WRAP_ERR_NO_SELF (-3) /**< own executable path is unresolvable. */

// The default policy PROGRAM: the agent-guard, as a n00b program run by the wrap
// runtime. It calls the FFI shims the runtime installs — `caller_is_blocked_agent()`
// (process-ancestry fact), `eprint(cstring)` (stderr message), and `exec_target()`
// (exec the wrapped binary). On ALLOW the else branch execs the target (never
// returns); on BLOCK the if branch prints the refusal and the program's trailing
// value 126 becomes the host's exit code.
//
// Shape note: the wrap runtime compiles the policy with the eval-session grammar,
// which accepts a top-level expression/statement program but NOT a `func`
// definition, and requires `if` to have an `else`. So the guard is written as a
// side-effecting if/else followed by the trailing verdict (the module's value),
// rather than as a function with `return`s.
#define WRAP_DEFAULT_POLICY_SOURCE                                            \
    "if caller_is_blocked_agent() != 0 {\n"                                   \
    "  eprint(\"Agent cannot directly run this command. "                     \
    "Prompt the user if you need more guidance.\")\n"                         \
    "} else {\n"                                                              \
    "  exec_target()\n"                                                       \
    "}\n"                                                                     \
    "126\n"

// Read a file's full contents into a fresh, independent buffer (a copy, so the
// mmap view can be released immediately). Failure is a real error, so the result
// is `n00b_result_t` (not a nullptr sentinel) per § 5.4.
static n00b_result_t(n00b_buffer_t *)
_wrap_read_file(n00b_string_t *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto open_result = n00b_file_open(path,
                                      .kind     = N00B_FILE_KIND_MMAP,
                                      .populate = true);

    if (n00b_result_is_err(open_result)) {
        return n00b_result_err(n00b_buffer_t *, WRAP_ERR_OPEN);
    }

    n00b_file_t *f      = n00b_result_get(open_result);
    auto         as_buf = n00b_file_as_buffer(f);

    if (n00b_result_is_err(as_buf)) {
        n00b_file_close(f);
        return n00b_result_err(n00b_buffer_t *, WRAP_ERR_READ);
    }

    n00b_buffer_t *view = n00b_result_get(as_buf);
    n00b_buffer_t *copy = n00b_buffer_from_bytes(view->data,
                                                 (int64_t)view->byte_len,
                                                 .allocator = allocator);

    n00b_file_close(f);
    return n00b_result_ok(n00b_buffer_t *, copy);
}

// Read this process's own executable bytes (resolve own exe path, then read it).
static n00b_result_t(n00b_buffer_t *)
_wrap_self_bytes() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto self = n00b_proc_get_info(n00b_proc_self_pid(), .allocator = allocator);

    if (n00b_result_is_err(self)) {
        return n00b_result_err(n00b_buffer_t *, WRAP_ERR_NO_SELF);
    }

    n00b_string_t *path = n00b_result_get(self)->exe_path;

    if (path == nullptr) {
        return n00b_result_err(n00b_buffer_t *, WRAP_ERR_NO_SELF);
    }

    return _wrap_read_file(path, .allocator = allocator);
}

// If this executable carries an EMBEDDED_N00B EXECUTION policy, the decoded
// bundle is present (HOST mode); its ABSENCE is the normal BUILDER-mode case (not
// an error), so this returns an option per § 5.4. Takes the self-bytes READ
// RESULT (not a nullable pointer) so an own-read failure is discriminated from a
// genuine "no carrier" absence rather than conflated into a single null value.
static n00b_option_t(n00b_obj_bundle_t *)
_wrap_self_carried_bundle(n00b_result_t(n00b_buffer_t *) self_result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (n00b_result_is_err(self_result)) {
        // Own bytes unreadable — there is no carrier to detect (the builder
        // path reports the read failure to the user).
        return n00b_option_none(n00b_obj_bundle_t *);
    }

    n00b_buffer_t *self_bytes = n00b_result_get(self_result);

    auto read = n00b_obj_bundle_read(self_bytes, .allocator = allocator);

    if (n00b_result_is_err(read)) {
        return n00b_option_none(n00b_obj_bundle_t *);
    }

    n00b_obj_bundle_t *bundle = n00b_result_get(read);

    if (_n00b_obj_bundle_embedded_policy_source_for_scope(
            bundle,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
            .allocator = allocator)
        == nullptr) {
        return n00b_option_none(n00b_obj_bundle_t *);
    }

    return n00b_option_set(n00b_obj_bundle_t *, bundle);
}

// HOST mode: run the carried policy program. A controller policy execs the target
// internally (never returns); a returning (gate / deny) policy yields its int64
// verdict, which becomes the exit code.
static int
_wrap_run_host(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto r = _n00b_obj_bundle_run_wrapped(bundle, .allocator = allocator);

    if (n00b_result_is_err(r)) {
        n00b_eprintf("n00b-wrap: policy execution failed (code «#»)",
                     (int64_t)n00b_result_get_err(r));
        return WRAP_EXIT_ERROR;
    }

    return (int)n00b_result_get(r);
}

// The n00b-wrap command-line interface, built on slay/commander (the project's
// CLI framework — same as n00b-attest / wax) rather than hand-rolled argv
// parsing. Root-level flags + a 1-or-more `<target>` positional; commander
// supplies `--help` handling and flag/positional validation. n00b-wrap has no
// subcommands (the bare invocation IS the builder), so everything is registered
// at the root (empty command name).
static n00b_cmdr_t *
build_wrap_cmdr(void)
{
    n00b_cmdr_t *c = n00b_cmdr_new();
    n00b_cmdr_set_name(c, r"n00b-wrap");

    n00b_cmdr_add_flag(c, n00b_string_empty(), r"--help",
                       N00B_CMDR_TYPE_BOOL, false, r"Show this help message");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--help", r"-h");

    n00b_cmdr_add_flag(c, n00b_string_empty(), r"--output",
                       N00B_CMDR_TYPE_WORD, true,
                       r"Path to write the wrapped binary (required)");
    n00b_cmdr_add_flag_alias(c, n00b_string_empty(), r"--output", r"-o");

    n00b_cmdr_add_flag(c, n00b_string_empty(), r"--policy",
                       N00B_CMDR_TYPE_WORD, true,
                       r"Policy program source file (default: built-in agent-guard)");

    n00b_cmdr_add_positional(c, n00b_string_empty(), r"target",
                             N00B_CMDR_TYPE_WORD, 1, -1);

    return c;
}

static void
wrap_usage(void)
{
    n00b_eprintf("usage: n00b-wrap <target>... -o <output> [--policy <file>]");
    n00b_eprintf("  Wrap one or more target binaries behind an embedded n00b");
    n00b_eprintf("  policy program (default: the agent-guard). The output is a");
    n00b_eprintf("  self-detecting binary that runs the policy when executed.");
    n00b_eprintf("  -o, --output <path>   where to write the wrapped binary");
    n00b_eprintf("  --policy <file>       policy program source (optional)");
    n00b_eprintf("  -h, --help            show this help");
}

// BUILDER mode: read the targets + flags from the parsed commander result, then
// embed the targets + policy into a copy of this binary at the output path.
static int
_wrap_run_builder(n00b_buffer_t      *self_bytes,
                  n00b_cmdr_result_t *r) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (self_bytes == nullptr) {
        n00b_eprintf("n00b-wrap: cannot read own executable bytes");
        return WRAP_EXIT_ERROR;
    }

    n00b_string_t *output_path = n00b_cmdr_flag_present(r, r"--output")
                                     ? n00b_cmdr_flag_str(r, r"--output")
                                     : nullptr;

    if (output_path == nullptr) {
        n00b_eprintf("n00b-wrap: -o/--output <path> is required");
        wrap_usage();
        return WRAP_EXIT_USAGE;
    }

    n00b_string_t *policy_file = n00b_cmdr_flag_present(r, r"--policy")
                                     ? n00b_cmdr_flag_str(r, r"--policy")
                                     : nullptr;

    n00b_list_t(n00b_string_t *) targets =
        n00b_list_new(n00b_string_t *, .allocator = allocator);
    int32_t target_count = n00b_cmdr_arg_count(r);

    for (int32_t i = 0; i < target_count; i++) {
        n00b_list_push(targets, n00b_cmdr_arg_str(r, i));
    }

    if (n00b_list_len(targets) == 0) {
        n00b_eprintf("n00b-wrap: at least one <target> is required");
        wrap_usage();
        return WRAP_EXIT_USAGE;
    }

    // wrap persists with reject-existing semantics; give a clear message rather
    // than a generic wrap failure when the destination is already present.
    if (n00b_path_exists(output_path)) {
        n00b_eprintf("n00b-wrap: output «#» already exists", output_path);
        return WRAP_EXIT_ERROR;
    }

    n00b_string_t *policy_source;

    if (policy_file != nullptr) {
        auto src_result = _wrap_read_file(policy_file, .allocator = allocator);

        if (n00b_result_is_err(src_result)) {
            n00b_eprintf("n00b-wrap: cannot read policy file «#»", policy_file);
            return WRAP_EXIT_ERROR;
        }
        n00b_buffer_t *src = n00b_result_get(src_result);
        policy_source      = n00b_string_from_raw(src->data,
                                             (int64_t)src->byte_len,
                                             .allocator = allocator);
    }
    else {
        policy_source = n00b_string_from_cstr(WRAP_DEFAULT_POLICY_SOURCE,
                                              .allocator = allocator);
    }

    auto wrapped = n00b_obj_bundle_wrap(self_bytes,
                                        &targets,
                                        policy_source,
                                        output_path,
                                        .allocator = allocator);

    if (n00b_result_is_err(wrapped)) {
        // The wrap error is a structured payload (not a plain integer code), so
        // it is not unwrapped here; report a generic failure.
        n00b_eprintf("n00b-wrap: wrap failed");
        return WRAP_EXIT_ERROR;
    }

    n00b_eprintf("n00b-wrap: wrote «#»", output_path);
    return 0;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    auto self_result = _wrap_self_bytes();
    auto carried     = _wrap_self_carried_bundle(self_result);

    int rc;
    if (n00b_option_is_set(carried)) {
        // HOST mode: a carrier-bearing binary runs its embedded policy and does
        // not parse command-line flags (argv passthrough to the target is a
        // future enhancement, not in this MVP).
        rc = _wrap_run_host(n00b_option_get(carried));
    }
    else {
        // BUILDER mode. self_bytes is the carrier host; a failed self-read is
        // surfaced by the builder's own null guard.
        n00b_buffer_t *self_bytes = n00b_result_is_ok(self_result)
                                        ? n00b_result_get(self_result)
                                        : nullptr;

        n00b_cmdr_t *cmdr = build_wrap_cmdr();

        // Bare invocation (no args) → help, like the n00b / n00b-attest tools.
        if (argc <= 1) {
            wrap_usage();
            rc = 0;
        }
        else {
            n00b_cmdr_result_t *r = n00b_cmdr_parse(cmdr,
                                                    argc - 1,
                                                    (const char **)&argv[1]);

            if (r == nullptr || !r->ok) {
                int32_t nerr = (r == nullptr) ? 0 : n00b_cmdr_error_count(r);
                for (int32_t i = 0; i < nerr; i++) {
                    n00b_eprintf("n00b-wrap: «#»", n00b_cmdr_error_get(r, i));
                }
                wrap_usage();
                rc = WRAP_EXIT_USAGE;
            }
            else if (n00b_cmdr_flag_present(r, r"--help")) {
                wrap_usage();
                rc = 0;
            }
            else {
                rc = _wrap_run_builder(self_bytes, r);
            }
        }
    }

    n00b_shutdown(.runtime = &rt);
    return rc;
}
