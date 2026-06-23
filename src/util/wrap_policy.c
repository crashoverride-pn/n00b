/*
 * wrap_policy.c — plain-C FFI shims + verdict core for EMBEDDED_N00B wrap
 * policies (WP-017, D-052). § 11 plain-C ABI shim layer: this is a file where
 * `const char *` FFI parameters and libc-shaped APIs are allowed, because these
 * symbols are installed as FFI targets (n00b_ffi_install_simple) that embedded
 * n00b policy programs call with a simple scalar/pointer ABI.
 *
 * The ancestry-classification logic here is ported from the retired
 * src/tools/agent_guard.c PATH-proxy (D-051): the same agent/shell matching, now
 * reachable from a full n00b PROGRAM policy rather than baked into a standalone
 * proxy binary. The pure verdict (n00b_wrap_ancestry_is_blocked) is factored out
 * so it can be unit-tested with injected ancestry chains (a real agent ancestor
 * is not reproducible in the test harness).
 */

#include "n00b.h"
#include "core/env.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/array.h"
#include "adt/result.h"
#include "adt/option.h"
#include "conduit/print.h"
#include "text/strings/string_ops.h"
#include "util/proc.h"
#include "util/wrap_policy.h"

// Comma-separated env list, or `defaults` when the var is unset/empty.
static n00b_array_t(n00b_string_t *)
wrap_parse_set(n00b_string_t *env_name, n00b_string_t *defaults)
{
    n00b_string_t *v   = n00b_getenv(env_name);
    n00b_string_t *src = (v != nullptr && v->codepoints > 0) ? v : defaults;

    return n00b_unicode_str_split(src, r",");
}

static bool
wrap_set_contains(n00b_array_t(n00b_string_t *) *set, n00b_string_t *name)
{
    if (name == nullptr) {
        return false;
    }

    int64_t n = (int64_t)n00b_array_len(*set);

    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *tok = n00b_array_get(*set, i);

        if (tok->codepoints == 0) {
            continue;
        }
        if (n00b_unicode_str_eq(tok, name)) {
            return true;
        }
    }

    return false;
}

// An ancestor matches a set if its kernel process name OR its executable
// basename is in the set.
static bool
wrap_name_match(n00b_array_t(n00b_string_t *) *set, n00b_proc_info_t *info)
{
    return wrap_set_contains(set, info->proc_name)
        || wrap_set_contains(set, info->exe_name);
}

// Agents are matched more liberally than shells: by process/exe name, OR by a
// path COMPONENT of the executable (so a version-named binary under a stable
// `.../claude/...` directory still matches). Component matching (not substring)
// avoids false positives like `/home/notclaude/...`.
static bool
wrap_agent_match(n00b_array_t(n00b_string_t *) *agents, n00b_proc_info_t *info)
{
    if (wrap_name_match(agents, info)) {
        return true;
    }

    if (info->exe_path == nullptr) {
        return false;
    }

    n00b_array_t(n00b_string_t *) segs =
        n00b_unicode_str_split(info->exe_path, r"/");
    int64_t n = (int64_t)n00b_array_len(segs);

    for (int64_t i = 0; i < n; i++) {
        if (wrap_set_contains(agents, n00b_array_get(segs, i))) {
            return true;
        }
    }

    return false;
}

bool
n00b_wrap_ancestry_is_blocked(n00b_list_t(n00b_proc_info_t *) *chain,
                              n00b_array_t(n00b_string_t *)    *agents,
                              n00b_array_t(n00b_string_t *)    *shells)
{
    if (chain == nullptr) {
        return false;
    }

    int64_t len = (int64_t)n00b_list_len(*chain);

    // index 0 is the process itself; classify ancestors from index 1 upward.
    for (int64_t i = 1; i < len; i++) {
        n00b_proc_info_t *info = n00b_list_get(*chain, i);

        if (wrap_agent_match(agents, info)) {
            return true; // an agent reached through shells-only — block
        }
        if (wrap_name_match(shells, info)) {
            continue; // a shell — keep climbing
        }

        return false; // a non-shell ancestor breaks the chain — allow
    }

    return false; // reached the top with no agent — allow
}

int64_t
n00b_caller_is_blocked_agent(void)
{
    n00b_array_t(n00b_string_t *) agents =
        wrap_parse_set(r"N00B_WRAP_AGENTS",
                       n00b_string_from_cstr(N00B_WRAP_DEFAULT_AGENTS));
    n00b_array_t(n00b_string_t *) shells =
        wrap_parse_set(r"N00B_WRAP_SHELLS",
                       n00b_string_from_cstr(N00B_WRAP_DEFAULT_SHELLS));

    auto anc = n00b_proc_ancestry(n00b_proc_self_pid());

    if (n00b_result_is_err(anc)) {
        return 0; // fail-open: don't block when ancestry is undeterminable
    }

    n00b_list_t(n00b_proc_info_t *) *chain = n00b_result_get(anc);

    return n00b_wrap_ancestry_is_blocked(chain, &agents, &shells) ? 1 : 0;
}

int64_t
n00b_policy_eprint_shim(const char *msg)
{
    if (msg != nullptr) {
        n00b_eprintf("«#»", n00b_string_from_cstr(msg));
    }

    return 0;
}
