// n00b-agent-guard — a wrap that blocks an AGENT (or a shell spawned by an
// agent, even indirectly, as long as every process in between is also a shell)
// from directly running a wrapped command, while letting humans and non-shell
// tools (jj, build systems, ...) through.
//
// Built on the cross-platform n00b_proc_* ancestry primitive (util/proc.h):
// the policy and exec are platform-neutral; only proc.c differs per OS.
//
// Two invocation modes, chosen by argv[0]'s basename:
//   * "n00b-agent-guard"  -> REPORT mode: print the ancestry + verdict and exit
//                            (0 = would allow, 126 = would block). No exec.
//   * anything else (a shim, e.g. symlinked as "git") -> GUARD mode: on ALLOW,
//                            exec the real tool; on BLOCK, print the message and
//                            exit 126.
//
// Real-tool resolution (GUARD mode): N00B_GUARD_TARGET if it names a path;
// otherwise the invoked name is looked up on PATH, skipping this binary itself
// (so a "git" shim finds the next "git", and jj's own git calls are untouched).

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/env.h"
#include "adt/result.h"
#include "adt/list.h"
#include "adt/array.h"
#include "adt/option.h"
#include "conduit/print.h"
#include "text/strings/string_ops.h"
#include "text/strings/format.h"
#include "util/path.h"
#include "util/proc.h"

#include <unistd.h>   // execv, access, X_OK
#include <sys/stat.h> // stat — device+inode identity for skip-self

#define GUARD_SELF_NAME      r"n00b-agent-guard"
#define GUARD_EXIT_BLOCKED   126
#define GUARD_EXIT_NO_TARGET 127

#define GUARD_DEFAULT_AGENTS  r"claude"
#define GUARD_DEFAULT_SHELLS  r"sh,bash,zsh,dash,ksh,fish,tcsh,csh"
#define GUARD_DEFAULT_MESSAGE \
    r"Agent cannot directly run this command. Prompt the user if you need more guidance."

typedef enum {
    GUARD_ALLOW,
    GUARD_BLOCK,
} guard_verdict_t;

// Last path component, without touching the filesystem (so a bare "git" stays
// "git" and "/usr/bin/git" becomes "git").
static n00b_string_t *
guard_basename(n00b_string_t *path)
{
    auto pos = n00b_unicode_str_find(path, r"/", .reverse = true);

    if (!n00b_option_is_set(pos)) {
        return path;
    }

    int32_t idx = n00b_option_get(pos);

    return n00b_unicode_str_slice(path, idx + 1, (int32_t)path->codepoints);
}

// Comma-separated env list, or `defaults` when unset/empty.
static n00b_array_t(n00b_string_t *)
guard_parse_set(n00b_string_t *env_name, n00b_string_t *defaults)
{
    n00b_string_t *v   = n00b_getenv(env_name);
    n00b_string_t *src = (v != nullptr && v->codepoints > 0) ? v : defaults;

    return n00b_unicode_str_split(src, r",");
}

static bool
guard_set_contains(n00b_array_t(n00b_string_t *) *set, n00b_string_t *name)
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

// An ancestor matches a set if either its kernel process name or its
// executable basename is in the set. The process name is usually the right
// signal (e.g. a launcher whose binary is version-named but whose comm is
// stable); the exe basename is a useful fallback.
static bool
guard_match(n00b_array_t(n00b_string_t *) *set, n00b_proc_info_t *info)
{
    return guard_set_contains(set, info->proc_name)
        || guard_set_contains(set, info->exe_name);
}

// Agents are matched more liberally than shells: by process/exe name, OR by a
// path COMPONENT of the executable. The latter is essential because some
// launchers ship a version-named binary under a stable directory — e.g. Claude
// Code lives at `.../share/claude/versions/<version>`, so the binary's name is
// the version but the path contains a `claude` component. Component matching
// (not substring) avoids false positives like `/home/notclaude/...`.
static bool
guard_agent_match(n00b_array_t(n00b_string_t *) *agents, n00b_proc_info_t *info)
{
    if (guard_match(agents, info)) {
        return true;
    }

    if (info->exe_path == nullptr) {
        return false;
    }

    n00b_array_t(n00b_string_t *) segs =
        n00b_unicode_str_split(info->exe_path, r"/");
    int64_t n = (int64_t)n00b_array_len(segs);

    for (int64_t i = 0; i < n; i++) {
        if (guard_set_contains(agents, n00b_array_get(segs, i))) {
            return true;
        }
    }

    return false;
}

// Walk the parent chain (skipping self): the first agent ancestor reached
// through shells-only blocks; any non-shell ancestor (or the top of the tree)
// allows. Fail-open if ancestry can't be determined.
static guard_verdict_t
guard_evaluate(n00b_array_t(n00b_string_t *) *agents,
               n00b_array_t(n00b_string_t *) *shells,
               bool                           explain)
{
    auto anc = n00b_proc_ancestry(n00b_proc_self_pid());

    if (n00b_result_is_err(anc)) {
        if (explain) {
            n00b_eprintf("n00b-agent-guard: ancestry lookup failed: «#»",
                         n00b_proc_err_str(n00b_result_get_err(anc)));
        }
        return GUARD_ALLOW; // fail-open: don't block when we can't tell
    }

    n00b_list_t(n00b_proc_info_t *) *chain = n00b_result_get(anc);
    int64_t                          len   = (int64_t)n00b_list_len(*chain);

    guard_verdict_t verdict = GUARD_ALLOW;

    // index 0 is self; classify ancestors from index 1 upward.
    for (int64_t i = 1; i < len; i++) {
        n00b_proc_info_t *info = n00b_list_get(*chain, i);

        if (guard_agent_match(agents, info)) {
            verdict = GUARD_BLOCK;
            break;
        }
        if (guard_match(shells, info)) {
            continue; // a shell — keep climbing
        }

        verdict = GUARD_ALLOW; // a non-shell ancestor breaks the chain
        break;
    }

    if (explain) {
        n00b_eprintf("n00b-agent-guard: ancestry (child → ancestor):");

        for (int64_t i = 0; i < len; i++) {
            n00b_proc_info_t *info = n00b_list_get(*chain, i);

            n00b_string_t *nm = info->proc_name;
            if (nm == nullptr) {
                nm = info->exe_name;
            }
            if (nm == nullptr) {
                nm = r"(unknown)";
            }

            n00b_string_t *tag;
            if (i == 0) {
                tag = r"self";
            }
            else if (guard_agent_match(agents, info)) {
                tag = r"AGENT";
            }
            else if (guard_match(shells, info)) {
                tag = r"shell";
            }
            else {
                tag = r"other";
            }

            n00b_eprintf("  [«#»] pid «#»  «#»  («#»)",
                         (int64_t)i,
                         (int64_t)info->pid,
                         nm,
                         tag);
        }

        n00b_eprintf("n00b-agent-guard: verdict = «#»",
                     (verdict == GUARD_BLOCK) ? r"BLOCK" : r"ALLOW");
    }

    return verdict;
}

// True if both paths name the same file (same device + inode). stat() follows
// symlinks, so this is symlink-proof — the right way to recognize "this is me"
// when the shim is a symlink to the guard binary (path-string comparison fails
// because n00b_resolve_path normalizes but does not follow symlinks).
static bool
guard_same_file(n00b_string_t *a, n00b_string_t *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }

    struct stat sa = {};
    struct stat sb = {};

    if (stat(a->data, &sa) != 0 || stat(b->data, &sb) != 0) {
        return false;
    }

    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

// Find `name` on PATH, skipping any entry that is this binary, so a shim named
// like its target doesn't exec itself into an infinite loop.
static n00b_string_t *
guard_path_search_skip_self(n00b_string_t *name)
{
    auto self = n00b_proc_get_info(n00b_proc_self_pid());

    if (n00b_result_is_err(self)) {
        return nullptr;
    }

    n00b_string_t *self_path = n00b_result_get(self)->exe_path;
    n00b_string_t *path_env  = n00b_getenv(r"PATH");

    if (path_env == nullptr || path_env->codepoints == 0) {
        return nullptr;
    }

    n00b_array_t(n00b_string_t *) dirs = n00b_unicode_str_split(path_env, r":");
    int64_t                       n    = (int64_t)n00b_array_len(dirs);

    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *dir = n00b_array_get(dirs, i);

        if (dir->codepoints == 0) {
            continue; // skip empty PATH entries
        }

        n00b_string_t *cand = n00b_cformat("«#»/«#»", dir, name);

        if (access(cand->data, X_OK) != 0) {
            continue;
        }
        if (guard_same_file(cand, self_path)) {
            continue; // that's us — keep looking
        }

        return cand;
    }

    return nullptr;
}

// Resolve the real tool to exec: an explicit N00B_GUARD_TARGET path wins;
// otherwise look up `invoked_name` on PATH (skipping self).
static n00b_string_t *
guard_resolve_target(n00b_string_t *invoked_name)
{
    n00b_string_t *configured = n00b_getenv(r"N00B_GUARD_TARGET");

    if (configured != nullptr && configured->codepoints > 0) {
        bool has_slash = n00b_option_is_set(
            n00b_unicode_str_find(configured, r"/"));

        if (has_slash) {
            return configured; // explicit path
        }

        return guard_path_search_skip_self(configured);
    }

    return guard_path_search_skip_self(invoked_name);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_string_t *argv0   = n00b_string_from_cstr(argv[0]);
    n00b_string_t *invoked = guard_basename(argv0);

    bool report_mode = n00b_unicode_str_eq(invoked, GUARD_SELF_NAME);
    bool explain     = report_mode
                   || (n00b_getenv(r"N00B_GUARD_EXPLAIN") != nullptr);

    n00b_array_t(n00b_string_t *) agents =
        guard_parse_set(r"N00B_GUARD_AGENTS", GUARD_DEFAULT_AGENTS);
    n00b_array_t(n00b_string_t *) shells =
        guard_parse_set(r"N00B_GUARD_SHELLS", GUARD_DEFAULT_SHELLS);

    guard_verdict_t verdict = guard_evaluate(&agents, &shells, explain);

    // REPORT mode: never exec; the exit code reflects the verdict.
    if (report_mode) {
        n00b_shutdown();
        return (verdict == GUARD_BLOCK) ? GUARD_EXIT_BLOCKED : 0;
    }

    // GUARD mode.
    if (verdict == GUARD_BLOCK) {
        n00b_string_t *msg = n00b_getenv(r"N00B_GUARD_MESSAGE");

        if (msg == nullptr || msg->codepoints == 0) {
            msg = GUARD_DEFAULT_MESSAGE;
        }

        n00b_eprintf("«#»", msg);
        n00b_shutdown();
        return GUARD_EXIT_BLOCKED;
    }

    // ALLOW: exec the real tool in place, forwarding our argv unchanged.
    n00b_string_t *target = guard_resolve_target(invoked);

    if (target == nullptr) {
        n00b_eprintf("n00b-agent-guard: cannot find real «#» on PATH", invoked);
        n00b_shutdown();
        return GUARD_EXIT_NO_TARGET;
    }

    execv(target->data, (char *const *)argv);

    // Only reached if execv failed.
    n00b_eprintf("n00b-agent-guard: exec of «#» failed", target);
    n00b_shutdown();
    return GUARD_EXIT_NO_TARGET;
}
