/*
 * WP-001 Phase 4 — CLI driver (library entry).
 *
 * Implements `n00b_audit_run_cli`, the library-shaped CLI entry
 * declared in `include/audit/audit.h`. Wires up libn00b's
 * `slay/commander.h`-based argv parser, resolves the guidance file
 * (flag override OR discovery walk from cwd), loads guidance,
 * builds the engine, runs `check_file` on the positional target,
 * and emits terminal violations to stdout via
 * `n00b_audit_print_terminal`.
 *
 * The thin `main()` in `src/tools/n00b_audit.c` is a wrapper that
 * converts `char *argv[]` to `n00b_string_t *audit_argv[]`,
 * invokes `n00b_audit_run_cli`, and translates the result into the
 * process exit code.
 *
 * Exit-code contract (ok-branch int payload):
 *   - 0  no violations found.
 *   - 1  at least one violation.
 *   - 2  internal error (with a stderr diagnostic already emitted).
 *
 * Per project DECISIONS.md D-005, this implementation's public
 * function carries no `_kargs` block. Per D-008, null-pointer
 * guards use the `!ptr` boolean-conversion idiom.
 *
 * Capture-mechanism note. Diagnostics go through libn00b's stderr
 * topic via `n00b_eprintf` / `n00b_print(.., .fd = 2)`. The Phase
 * 4 regression test captures both fds via POSIX `pipe()` +
 * `dup2()` before invoking `n00b_audit_run_cli`; see `output.c`
 * for the W-4 capture-mechanism rationale.
 *
 * NCC.md "Rich string literals" gotcha: `r"..."` literals cannot
 * carry `«#»` substitution markers or use C-style adjacent-literal
 * concatenation. Format templates with substitutions in this file
 * are plain C strings passed to `n00b_eprintf` / `n00b_printf`.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/result.h"
#include "conduit/print.h"
#include "slay/commander.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/path.h"

#include "naudit/naudit.h"
#include "naudit/engine.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/output.h"
#include "naudit/signing_ux.h"
#include "naudit/trust_root.h"
#include "naudit/violation.h"

#include <unistd.h>

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

/*
 * Build the commander spec for the `n00b-audit` CLI:
 *   - one positional `file` (required, exactly one),
 *   - `--guidance <path>` flag (optional),
 *   - `--format <terminal|json>` flag (optional, default terminal).
 *
 * Returns a finalized commander, or nullptr on internal failure.
 */
static n00b_cmdr_t *
build_cmdr(void)
{
    n00b_cmdr_t *c = n00b_cmdr_new();
    if (!c) {
        return nullptr;
    }
    n00b_cmdr_set_name(c, r"n00b-audit");

    n00b_string_t *empty = r"";

    /*
     * Positional `file`, min=0, max=1 — exactly one target normally,
     * but `--sign <file>` / `--verify <file>` carry the file as the
     * flag's argument so no positional is needed in those modes.
     * WP-012 widens this from min=1 to min=0; the run_cli body
     * enforces "positional required" in audit mode (the default
     * path) where the validation rejects argv without a file.
     */
    n00b_cmdr_add_positional(c, empty,
                             r"file",
                             N00B_CMDR_TYPE_WORD, 0, 1);

    /* --guidance <path> */
    n00b_cmdr_add_flag(c, empty,
                       r"--guidance",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Override the discovery walk and load this guidance file."));

    /* --format <terminal|json> */
    n00b_cmdr_add_flag(c, empty,
                       r"--format",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Output format: 'terminal' (default) or 'json' (Phase 5+)."));

    /*
     * --fix (WP-007 Phase 2): when set, apply suggested rewrites
     * in-place. The boolean shape uses `N00B_CMDR_TYPE_BOOL` with
     * `takes_arg=false` — matches the slay-commander convention
     * for valueless flags.
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--fix",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Apply suggested rewrites in-place "
                           "(writes a `<file>.bak` backup first)."));

    /*
     * WP-011: `--ignore-baseline` skips the loaded
     * `audit/baseline/baseline.bnf` suppression set so the user can
     * re-surface baselined findings for selective review. Per-record
     * exemptions in `audit/exemptions/` still apply.
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--ignore-baseline",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Skip baseline suppression — re-surface "
                           "baselined findings."));

    /*
     * WP-011: `--baseline-finalize` switches the standard
     * `naudit <file>` invocation into the baseline-bootstrap path
     * (per D-X6): run the audit, capture every finding into
     * `audit/baseline/baseline.bnf`, no signature in Phase 1
     * (WP-012 wires that). `--overwrite` permits clobbering an
     * existing baseline file. Per the prompt, the surface is the
     * `baseline` conceptual subcommand; we implement it as a
     * top-level flag on the existing `naudit <file>` parse shape so
     * the commander spec stays minimal — same UX, identical
     * semantics.
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--baseline-finalize",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Run the audit and write every finding to "
                           "audit/baseline/baseline.bnf (D-X6 bootstrap)."));
    n00b_cmdr_add_flag(c, empty,
                       r"--overwrite",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Clobber an existing baseline.bnf when "
                           "--baseline-finalize is set."));

    /*
     * WP-012: signature-related flags.
     *
     * Per the prompt (item 5), sign + verify are implemented as
     * flags rather than subcommands so they follow the existing
     * `--baseline-finalize` precedent (D-024 W-4). Each flag takes
     * an argument carrying the exemption-file path.
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--sign",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Sign mode: sign the supplied exemption file "
                           "(requires --key + --signer)."));
    n00b_cmdr_add_flag(c, empty,
                       r"--verify",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Verify mode: verify the supplied exemption "
                           "file's detached signature."));
    n00b_cmdr_add_flag(c, empty,
                       r"--key",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Path to the SSH private key used for "
                           "--sign / --baseline-finalize signing."));
    n00b_cmdr_add_flag(c, empty,
                       r"--signer",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Principal identifier embedded in the "
                           "signature record (matches a roster entry)."));
    n00b_cmdr_add_flag(c, empty,
                       r"--allow-unsigned",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Warn-and-accept exemption + baseline records "
                           "that fail signature verification (default: drop)."));

    /*
     * WP-014: interactive signing ceremony flags.
     *
     * `--sign-pending` enters the interactive ceremony — walks
     * pending proposals (per the white paper § 11) one at a time.
     * Implemented as a separate flag from the WP-012 `--sign <file>`
     * because the two modes have different semantics:
     *   - `--sign <file>`     single-file non-interactive sign
     *                         (the WP-012 surface).
     *   - `--sign-pending`    interactive walk through every
     *                         `<project>/audit/exemptions/*.bnf`
     *                         lacking a `.sig`.
     *
     * `--initial-adoption` bulk-signs every pending proposal with a
     * standardized rationale + 90-day expiry. The friction the white
     * paper would have spread across the team's day-1 schedule is
     * moved to the 90-day expiration boundary.
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--sign-pending",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Interactive signing ceremony: walk pending "
                           "exemption proposals one at a time."));
    n00b_cmdr_add_flag(c, empty,
                       r"--initial-adoption",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Bulk-sign every pending proposal with the "
                           "standardized 'preexisting' rationale + 90-day "
                           "expiration. Use ONCE at project adoption."));

    /*
     * WP-015: trust-root + rule-file signature flags.
     *
     *  - `--repo-protected` (boolean): assert that the running
     *    environment is a protected CI / pre-commit context.
     *    Downgrades repo-roster + unsigned-rule-file warnings.
     *  - `--sign-rules` (path): sign `audit-rules.bnf` (or the
     *    supplied path) with `--key` + `--signer`, mirroring the
     *    WP-012 `--sign` flag pattern (DF-CC resolution).
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--repo-protected",
                       N00B_CMDR_TYPE_BOOL, false,
                       n00b_string_from_cstr(
                           "Assert that the running environment is a "
                           "protected CI / pre-commit context (downgrades "
                           "repo-roster + unsigned-rule warnings to info)."));
    n00b_cmdr_add_flag(c, empty,
                       r"--sign-rules",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Sign the supplied audit-rules.bnf path "
                           "(requires --key + --signer)."));
    /*
     * WP-017: pass-through args to `cc -E` for the preprocessor
     * pre-pass on C files. Typical usage:
     *   --cpp-args="-I /path/to/n00b/include -DFOO"
     * Required when auditing real n00b source that includes
     * project headers — without it the preprocessor fails on
     * `#include "n00b.h"`.
     */
    n00b_cmdr_add_flag(c, empty,
                       r"--cpp-args",
                       N00B_CMDR_TYPE_WORD, true,
                       n00b_string_from_cstr(
                           "Extra arguments to pass to cc -E for the "
                           "C preprocessor pre-pass (e.g. \"-I path\")."));

    n00b_cmdr_finalize(c);
    return c;
}

/*
 * Convert the n00b_string_t-shaped argv we accept on the library
 * surface into the const-char-pointer array commander expects.
 * Allocates via libn00b's GC (zero-initialized). Returns nullptr on
 * any null entry in argv (treated as a bad-args programming error).
 *
 * `argc_out` is set to argc-1 because commander conventionally
 * receives argv+1 (the program name is implicit).
 *
 * `n00b_string_t` data fields are NUL-terminated per the Phase 2
 * loader's precedent (`require_string_field` in guidance.c uses
 * `n00b_string_from_cstr` whose output is documented as
 * NUL-terminated), so passing `s->data` as `const char *` to
 * commander is safe.
 */
static const char **
build_cargv(int argc, n00b_string_t *argv[], int *argc_out)
{
    if (argc <= 0 || !argv) {
        return nullptr;
    }
    /* commander conventionally receives argv+1 (program name is
     * implicit). With argc==1 we pass 0 entries — commander will
     * then complain about the missing positional, which is the
     * correct behavior. */
    int n = argc - 1;
    if (n < 0) {
        n = 0;
    }

    const char **out = n00b_alloc_array(const char *, (size_t)(n + 1));
    for (int i = 0; i < n; i++) {
        n00b_string_t *s = argv[i + 1];
        if (!s) {
            return nullptr;
        }
        out[i] = (const char *)s->data;
    }
    out[n] = nullptr;
    *argc_out = n;
    return out;
}

/* ---------------------------------------------------------------- */
/* --fix application                                                */
/* ---------------------------------------------------------------- */

/*
 * Compute the absolute byte offset of (line, col) in `src` (both
 * 1-based). Returns -1 if the position is past EOF.
 *
 * Counts UTF-8 bytes, not code points — that matches slay's
 * `n00b_token_info_t.column` semantics (which the c_tokenizer
 * advances per byte, not per codepoint). For ASCII-only fixtures
 * the distinction is moot; for non-ASCII source the column-as-byte
 * convention is the engine's own convention and we follow it.
 */
static int64_t
line_col_to_offset(const char *src, size_t src_len,
                   int64_t line, int64_t col)
{
    if (line <= 0 || col <= 0) {
        return -1;
    }
    int64_t cur_line = 1;
    size_t  i        = 0;
    while (cur_line < line && i < src_len) {
        if (src[i] == '\n') {
            cur_line++;
        }
        i++;
    }
    if (cur_line != line) {
        return -1;
    }
    /* `col` is 1-based column on this line. Advance col-1 bytes. */
    int64_t needed = col - 1;
    int64_t advanced = 0;
    while (advanced < needed && i < src_len && src[i] != '\n') {
        i++;
        advanced++;
    }
    if (advanced != needed) {
        return -1;
    }
    return (int64_t)i;
}

/*
 * One pending splice: byte span [start, end) -> `replacement`.
 * Sort splices by `start` DESCENDING then apply so earlier offsets
 * stay valid as we mutate from end to beginning.
 */
typedef struct {
    int64_t        start;
    int64_t        end;
    n00b_string_t *replacement;
} fix_splice_t;

/*
 * Simple in-place insertion sort of a fix_splice_t array, ASCENDING
 * by `start`. n is small (per-file violation count — single digits
 * in practice), so a quadratic sort is fine and dodges any libc-qsort
 * dependency question.
 */
static void
fix_splice_sort_asc(fix_splice_t *a, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        fix_splice_t key = a[i];
        size_t       j   = i;
        while (j > 0 && a[j - 1].start > key.start) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = key;
    }
}

/*
 * Read the file at `path` into a buffered string. Returns nullptr
 * on any I/O failure. The returned buffer's `data` is GC-managed.
 */
static n00b_buffer_t *
read_whole_file(n00b_string_t *path)
{
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return nullptr;
    }
    n00b_file_t *f = n00b_result_get(fr);
    auto br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return nullptr;
    }
    /* Copy out so the lifetime is independent of the file handle. */
    return n00b_buffer_copy(n00b_result_get(br));
}

/*
 * Write `buf`'s contents to `path` (truncating). Returns true on
 * success, false on any I/O failure.
 */
static bool
write_whole_file(n00b_string_t *path, n00b_buffer_t *buf)
{
    auto fr = n00b_file_open(path, .mode = N00B_FILE_W,
                              .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(fr)) {
        return false;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    size_t       n  = buf ? (size_t)buf->byte_len : 0;
    bool         ok = true;
    if (n > 0) {
        auto wr = n00b_file_write(f, buf->data, n);
        if (n00b_result_is_err(wr)) {
            ok = false;
        }
    }
    n00b_file_close(f);
    return ok;
}

/*
 * Apply all auto-fixable rewrites in one file. Pre-conditions:
 *   - `violations_for_file` is a list of violations all carrying
 *     the same `file` path.
 *   - At least one entry has a non-null `rewrite`.
 *
 * Steps (matches phase2-plan.md § 5):
 *   1. Read the source into memory.
 *   2. Write `<file>.bak` verbatim copy.
 *   3. Compute byte spans for each violation with a rewrite.
 *      Skip (with stderr warning) any multi-line match — Phase 2
 *      only handles single-line rewrites (DF-P resolution).
 *   4. Sort by start_offset DESCENDING.
 *   5. Splice from end to beginning.
 *   6. Write the new content back to `file`.
 *
 * DF-O resolution (rewrite-application failure mode): if writing
 * `<file>.bak` fails, abort before touching the original (clean
 * fail). If the file write at step 6 fails after the .bak is on
 * disk, the .bak is left in place and the function returns false;
 * the caller emits a stderr diagnostic — the user can recover by
 * `mv <file>.bak <file>`.
 *
 * Returns true on success and writes the applied count to
 * `*applied_out`; returns false on any I/O failure.
 */
static bool
apply_fixes_in_file(n00b_string_t                          *file,
                    n00b_list_t(n00b_audit_violation_t *)  *violations_for_file,
                    int                                   *applied_out)
{
    *applied_out = 0;

    n00b_buffer_t *src = read_whole_file(file);
    if (!src) {
        return false;
    }

    /* Step 2: write <file>.bak as a verbatim copy. */
    n00b_string_t *bak_path = n00b_cformat("«#».bak", file);
    if (!write_whole_file(bak_path, src)) {
        return false;
    }

    /* Step 3: compute byte spans. */
    size_t cap_lists = (size_t)n00b_list_len(*violations_for_file);
    fix_splice_t *splices = n00b_alloc_array(fix_splice_t, cap_lists);
    size_t        nsplice = 0;

    const char *data = src->data;
    size_t      len  = (size_t)src->byte_len;

    for (size_t i = 0; i < cap_lists; i++) {
        n00b_audit_violation_t *v = n00b_list_get(*violations_for_file, i);
        if (!v || !v->rewrite) {
            continue;
        }
        /* DF-P: skip multi-line rewrites — Phase 2 doesn't handle
         * them (all auto-fixable rules in the canonical guidance
         * match single-token / single-line spans). */
        if (v->end_line != v->line) {
            n00b_eprintf(
                "n00b-audit: skipping multi-line auto-fix at «#»:«#»:«#» (not supported in Phase 2)",
                v->file, (int64_t)v->line, (int64_t)v->column);
            continue;
        }
        int64_t s = line_col_to_offset(data, len, v->line, v->column);
        int64_t e = line_col_to_offset(data, len, v->end_line, v->end_column);
        if (s < 0 || e < 0 || e < s) {
            n00b_eprintf(
                "n00b-audit: skipping auto-fix at «#»:«#»:«#» (bad span)",
                v->file, (int64_t)v->line, (int64_t)v->column);
            continue;
        }
        splices[nsplice].start       = s;
        splices[nsplice].end         = e;
        splices[nsplice].replacement = v->rewrite;
        nsplice++;
    }

    if (nsplice == 0) {
        return true;
    }

    /* Step 4: sort by start ASC. The phase2-plan describes the
     * algorithm as "sort DESC, apply end-to-start". Equivalent shape
     * (chosen here for clarity): sort ASC, then build a fresh buffer
     * left-to-right by walking the source, copying the unaffected
     * runs between splices, and substituting at each splice. End
     * result is identical. */
    fix_splice_sort_asc(splices, nsplice);

    n00b_buffer_t *out = n00b_buffer_empty();
    int64_t cursor = 0;
    for (size_t i = 0; i < nsplice; i++) {
        int64_t s = splices[i].start;
        int64_t e = splices[i].end;
        if (s < cursor) {
            /* Overlap — should not happen for Phase 2 rules. Skip. */
            continue;
        }
        if (s > cursor) {
            n00b_buffer_t *chunk = n00b_buffer_from_bytes(
                (char *)(data + cursor), s - cursor);
            n00b_buffer_concat(out, chunk);
        }
        n00b_buffer_t *repl = n00b_buffer_from_bytes(
            splices[i].replacement->data,
            (int64_t)splices[i].replacement->u8_bytes);
        n00b_buffer_concat(out, repl);
        cursor = e;
    }
    if (cursor < (int64_t)len) {
        n00b_buffer_t *tail = n00b_buffer_from_bytes(
            (char *)(data + cursor), (int64_t)len - cursor);
        n00b_buffer_concat(out, tail);
    }

    /* Step 6: write back. */
    if (!write_whole_file(file, out)) {
        return false;
    }
    *applied_out = (int)nsplice;
    return true;
}

/*
 * Group violations by file and run `apply_fixes_in_file` per group.
 * Emits the success report per the spec ("naudit: fixed N violation(s)
 * in <file> (backup: <file>.bak)") to stderr. Returns ok-0 unless an
 * I/O failure occurred (in which case the diagnostic is already
 * emitted and we return ok-2 to mirror the W-4 internal-error path).
 */
static n00b_result_t(int)
apply_fixes_dispatch(n00b_list_t(n00b_audit_violation_t *) *violations)
{
    size_t n = (size_t)n00b_list_len(*violations);
    if (n == 0) {
        return n00b_result_ok(int, 0);
    }

    /*
     * Single-target-per-invocation CLI: Phase 2's `n00b-audit
     * <file>` accepts exactly one positional, so every violation
     * shares one `file` value. Group anyway (defensive — and a
     * future multi-file invocation just works without changes).
     */
    n00b_list_t(n00b_string_t *) *files_seen =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *files_seen = n00b_list_new(n00b_string_t *);

    for (size_t i = 0; i < n; i++) {
        n00b_audit_violation_t *v = n00b_list_get(*violations, i);
        if (!v || !v->file) {
            continue;
        }
        bool   found = false;
        size_t m     = (size_t)n00b_list_len(*files_seen);
        for (size_t j = 0; j < m; j++) {
            n00b_string_t *s = n00b_list_get(*files_seen, j);
            if (s && n00b_unicode_str_eq(s, v->file)) {
                found = true;
                break;
            }
        }
        if (!found) {
            n00b_list_push(*files_seen, v->file);
        }
    }

    size_t nfiles = (size_t)n00b_list_len(*files_seen);
    for (size_t f = 0; f < nfiles; f++) {
        n00b_string_t *fpath = n00b_list_get(*files_seen, f);
        if (!fpath) {
            continue;
        }
        n00b_list_t(n00b_audit_violation_t *) *per_file =
            n00b_alloc(n00b_list_t(n00b_audit_violation_t *));
        *per_file = n00b_list_new(n00b_audit_violation_t *);
        bool any_rewrite = false;
        for (size_t i = 0; i < n; i++) {
            n00b_audit_violation_t *v = n00b_list_get(*violations, i);
            if (!v || !v->file) {
                continue;
            }
            if (!n00b_unicode_str_eq(v->file, fpath)) {
                continue;
            }
            n00b_list_push(*per_file, v);
            if (v->rewrite && v->rewrite->u8_bytes > 0) {
                any_rewrite = true;
            }
        }
        if (!any_rewrite) {
            continue;
        }
        int applied = 0;
        if (!apply_fixes_in_file(fpath, per_file, &applied)) {
            n00b_eprintf("n00b-audit: --fix failed to update «#»", fpath);
            return n00b_result_ok(int, 2);
        }
        n00b_eprintf(
            "n00b-audit: fixed «#» violation(s) in «#» (backup: «#».bak)",
            (int64_t)applied, fpath, fpath);
    }

    return n00b_result_ok(int, 0);
}

/*
 * Compose a stderr diagnostic combining a short prefix and a
 * n00b_audit_err_str describing the error code, then return ok-2.
 */
static n00b_result_t(int)
diagnose_and_fail(const char *prefix, int err_code)
{
    n00b_eprintf("n00b-audit: «#»: «#»",
                 n00b_string_from_cstr(prefix),
                 n00b_audit_err_str(err_code));
    return n00b_result_ok(int, 2);
}

/* ---------------------------------------------------------------- */
/* Public entry                                                     */
/* ---------------------------------------------------------------- */

n00b_result_t(int)
n00b_audit_run_cli(int argc, n00b_string_t *argv[])
{
    if (argc <= 0 || !argv) {
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_BAD_ARGS);
    }

    /* Build + parse the commander spec. */
    n00b_cmdr_t *c = build_cmdr();
    if (!c) {
        n00b_eprintf("n00b-audit: «#»",
                     n00b_string_from_cstr(
                         "internal error: failed to build commander spec"));
        return n00b_result_ok(int, 2);
    }

    int cargc = 0;
    const char **cargv = build_cargv(argc, argv, &cargc);
    if (!cargv) {
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_BAD_ARGS);
    }

    n00b_cmdr_result_t *parse = n00b_cmdr_parse(c, cargc, cargv);
    if (!parse || !parse->ok) {
        if (parse) {
            int32_t errn = n00b_cmdr_error_count(parse);
            for (int32_t i = 0; i < errn; i++) {
                n00b_eprintf("n00b-audit: «#»",
                             n00b_cmdr_error_get(parse, i));
            }
        }
        n00b_eprintf("n00b-audit: «#»",
                     n00b_string_from_cstr(
                         "usage: n00b-audit [--guidance <path>] [--format terminal|json] <file>"));
        if (parse) {
            n00b_cmdr_result_free(parse);
        }
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
    }

    /*
     * WP-012: detect sign / verify mode early. These short-circuit
     * the audit pipeline — no guidance load, no engine, no
     * positional required.
     */
    n00b_string_t *sign_flag      = r"--sign";
    n00b_string_t *verify_flag    = r"--verify";
    n00b_string_t *key_flag       = r"--key";
    n00b_string_t *signer_flag    = r"--signer";
    n00b_string_t *allow_uns_flag = r"--allow-unsigned";

    bool want_sign   = n00b_cmdr_flag_present(parse, sign_flag);
    bool want_verify = n00b_cmdr_flag_present(parse, verify_flag);

    if (want_sign && want_verify) {
        n00b_eprintf(
            "n00b-audit: --sign and --verify are mutually exclusive");
        n00b_cmdr_result_free(parse);
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
    }

    if (want_sign) {
        n00b_string_t *file = n00b_cmdr_flag_str(parse, sign_flag);
        n00b_string_t *key  = n00b_cmdr_flag_present(parse, key_flag)
                                  ? n00b_cmdr_flag_str(parse, key_flag)
                                  : nullptr;
        n00b_string_t *signer = n00b_cmdr_flag_present(parse, signer_flag)
                                    ? n00b_cmdr_flag_str(parse, signer_flag)
                                    : nullptr;
        if (!file || file->u8_bytes == 0
            || !key || key->u8_bytes == 0
            || !signer || signer->u8_bytes == 0) {
            n00b_eprintf(
                "n00b-audit: --sign requires --key <path> and --signer <id>");
            n00b_cmdr_result_free(parse);
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
        }
        auto sr = n00b_audit_exemption_sign(file, key, signer);
        n00b_cmdr_result_free(parse);
        if (n00b_result_is_err(sr)) {
            n00b_eprintf("n00b-audit: --sign failed: «#»",
                         n00b_audit_err_str(n00b_result_get_err(sr)));
            return n00b_result_ok(int, 2);
        }
        n00b_eprintf("n00b-audit: signed «#» (-> «#».sig)", file, file);
        return n00b_result_ok(int, 0);
    }

    if (want_verify) {
        n00b_string_t *file = n00b_cmdr_flag_str(parse, verify_flag);
        if (!file || file->u8_bytes == 0) {
            n00b_eprintf(
                "n00b-audit: --verify requires an exemption file path");
            n00b_cmdr_result_free(parse);
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
        }
        /*
         * The verifier needs both the roster + the signer id; the
         * signer id is recorded in the exemption record (the
         * `@signer_id` directive). Parse just that one field via
         * the existing loader, then verify. Roster comes from the
         * guidance discovery walk so the user doesn't have to pass
         * it explicitly.
         */
        auto lr = n00b_audit_load_exemptions(file);
        if (n00b_result_is_err(lr)) {
            n00b_eprintf("n00b-audit: --verify: load failed: «#»",
                         n00b_audit_err_str(n00b_result_get_err(lr)));
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        n00b_list_t(n00b_audit_exemption_t *) *list = n00b_result_get(lr);
        if (!list || n00b_list_len(*list) < 1) {
            n00b_eprintf(
                "n00b-audit: --verify: «#» carries no exemption records",
                file);
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        n00b_audit_exemption_t *ex0 = n00b_list_get(*list, 0);
        if (!ex0 || !ex0->signer_id || ex0->signer_id->u8_bytes == 0) {
            n00b_eprintf(
                "n00b-audit: --verify: «#» has no @signer_id field",
                file);
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        /*
         * Roster path: walk parents from the file's directory
         * looking for `audit/allowed_signers`. Falls back to the
         * cwd-based guidance discovery shape used elsewhere.
         */
        n00b_string_t *cwd = n00b_get_current_directory();
        n00b_string_t *roster = nullptr;
        if (cwd) {
            n00b_string_t *candidate = n00b_path_simple_join(
                cwd,
                r"audit/allowed_signers");
            if (n00b_path_is_file(candidate)) {
                roster = candidate;
            }
        }
        if (!roster) {
            n00b_eprintf(
                "n00b-audit: --verify: no audit/allowed_signers roster found in cwd; cannot verify");
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        auto vr = n00b_audit_exemption_verify(file, roster, ex0->signer_id);
        n00b_cmdr_result_free(parse);
        if (n00b_result_is_err(vr)) {
            n00b_eprintf("n00b-audit: --verify: «#» — «#»",
                         file,
                         n00b_audit_err_str(n00b_result_get_err(vr)));
            return n00b_result_ok(int, 1);
        }
        n00b_eprintf("n00b-audit: --verify: «#» — ok", file);
        return n00b_result_ok(int, 0);
    }

    /*
     * WP-015: --sign-rules dispatch. Short-circuits the audit
     * pipeline like --sign / --verify; signs the supplied
     * audit-rules.bnf via `n00b_audit_sign_rules` (which delegates
     * to the WP-012 signing primitive).
     */
    n00b_string_t *sign_rules_flag = r"--sign-rules";
    if (n00b_cmdr_flag_present(parse, sign_rules_flag)) {
        n00b_string_t *rules_path = n00b_cmdr_flag_str(parse, sign_rules_flag);
        n00b_string_t *key = n00b_cmdr_flag_present(parse, key_flag)
                                 ? n00b_cmdr_flag_str(parse, key_flag)
                                 : nullptr;
        n00b_string_t *signer = n00b_cmdr_flag_present(parse, signer_flag)
                                    ? n00b_cmdr_flag_str(parse, signer_flag)
                                    : nullptr;
        if (!rules_path || rules_path->u8_bytes == 0
            || !key || key->u8_bytes == 0
            || !signer || signer->u8_bytes == 0) {
            n00b_eprintf(
                "n00b-audit: --sign-rules requires <path> + --key <path> + --signer <id>");
            n00b_cmdr_result_free(parse);
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
        }
        auto sr = n00b_audit_sign_rules(rules_path, key, signer);
        n00b_cmdr_result_free(parse);
        if (n00b_result_is_err(sr)) {
            n00b_eprintf("n00b-audit: --sign-rules failed: «#»",
                         n00b_audit_err_str(n00b_result_get_err(sr)));
            return n00b_result_ok(int, 2);
        }
        n00b_eprintf("n00b-audit: signed rules «#» (-> «#».sig)",
                     rules_path, rules_path);
        return n00b_result_ok(int, 0);
    }

    /*
     * WP-014: --sign-pending / --initial-adoption dispatch. Like
     * --sign / --verify, these short-circuit the audit pipeline.
     * Both modes need `--key` + `--signer` and discover the project
     * root from the guidance discovery walk (same as a normal audit
     * run). The positional `<file>` is NOT required.
     */
    n00b_string_t *sp_flag = r"--sign-pending";
    n00b_string_t *ia_flag = r"--initial-adoption";
    bool want_sign_pending     = n00b_cmdr_flag_present(parse, sp_flag);
    bool want_initial_adoption = n00b_cmdr_flag_present(parse, ia_flag);
    if (want_sign_pending && want_initial_adoption) {
        n00b_eprintf(
            "n00b-audit: --sign-pending and --initial-adoption are mutually exclusive");
        n00b_cmdr_result_free(parse);
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
    }
    if (want_sign_pending || want_initial_adoption) {
        n00b_string_t *key = n00b_cmdr_flag_present(parse, key_flag)
                                 ? n00b_cmdr_flag_str(parse, key_flag)
                                 : nullptr;
        n00b_string_t *signer = n00b_cmdr_flag_present(parse, signer_flag)
                                    ? n00b_cmdr_flag_str(parse, signer_flag)
                                    : nullptr;
        if (!key || key->u8_bytes == 0
            || !signer || signer->u8_bytes == 0) {
            n00b_eprintf(
                "n00b-audit: --sign-pending / --initial-adoption require --key <path> + --signer <id>");
            n00b_cmdr_result_free(parse);
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
        }
        /*
         * Resolve the project root: walk up from cwd looking for
         * `audit-rules.bnf`, then take that file's parent directory.
         */
        n00b_string_t *cwd = n00b_get_current_directory();
        if (!cwd) {
            n00b_eprintf("n00b-audit: cwd lookup failed");
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        auto disc = n00b_audit_find_guidance_file(cwd);
        if (n00b_result_is_err(disc)) {
            n00b_eprintf(
                "n00b-audit: could not locate audit-rules.bnf — run from inside a naudit-configured project");
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        n00b_string_t *rules_path = n00b_result_get(disc);
        /* Project root = directory containing audit-rules.bnf. */
        n00b_string_t *project_root = nullptr;
        if (rules_path) {
            int64_t n = (int64_t)rules_path->u8_bytes;
            int64_t last = -1;
            for (int64_t i = n - 1; i >= 0; i--) {
                if (rules_path->data[i] == '/') {
                    last = i;
                    break;
                }
            }
            if (last > 0) {
                project_root = n00b_string_from_raw(rules_path->data,
                                                    last);
            }
            else if (last == 0) {
                project_root = r"/";
            }
        }
        if (!project_root) {
            n00b_eprintf(
                "n00b-audit: could not derive project root from rules path");
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }

        if (want_initial_adoption) {
            /* Bulk path: 90-day expiry per the white paper § 11.3. */
            n00b_eprintf(
                "n00b-audit: --initial-adoption: bulk-signing pending proposals");
            auto br = n00b_audit_sign_initial_adoption_bulk(
                project_root, key, signer, 90);
            n00b_cmdr_result_free(parse);
            if (n00b_result_is_err(br)) {
                n00b_eprintf(
                    "n00b-audit: --initial-adoption failed: «#»",
                    n00b_audit_err_str(n00b_result_get_err(br)));
                return n00b_result_ok(int, 2);
            }
            n00b_eprintf(
                "n00b-audit: --initial-adoption: signed «#» proposal(s)",
                (int64_t)n00b_result_get(br));
            return n00b_result_ok(int, 0);
        }

        /* Interactive ceremony. */
        auto dr = n00b_audit_discover_proposals(project_root);
        if (n00b_result_is_err(dr)) {
            n00b_eprintf(
                "n00b-audit: --sign-pending: proposal discovery failed: «#»",
                n00b_audit_err_str(n00b_result_get_err(dr)));
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        n00b_list_t(n00b_string_t *) *proposals = n00b_result_get(dr);
        int64_t np = n00b_list_len(*proposals);
        if (np == 0) {
            n00b_eprintf(
                "n00b-audit: --sign-pending: no pending proposals to sign");
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 0);
        }
        n00b_eprintf(
            "n00b-audit: --sign-pending: walking «#» pending proposal(s)",
            (int64_t)np);
        n00b_naudit_input_source_t *src =
            n00b_naudit_input_from_fd(STDIN_FILENO);
        int signed_count   = 0;
        int declined_count = 0;
        for (int64_t i = 0; i < np; i++) {
            n00b_string_t *p = n00b_list_get(*proposals, i);
            if (!p) {
                continue;
            }
            auto rr = n00b_audit_sign_proposal_interactive(
                p, key, signer, src, 365);
            if (n00b_result_is_err(rr)) {
                n00b_eprintf(
                    "n00b-audit: --sign-pending: «#» failed: «#»",
                    p,
                    n00b_audit_err_str(n00b_result_get_err(rr)));
                continue;
            }
            int rc = n00b_result_get(rr);
            if (rc == 0) {
                signed_count++;
            }
            else {
                declined_count++;
            }
        }
        n00b_eprintf(
            "n00b-audit: --sign-pending: signed «#», declined «#»",
            (int64_t)signed_count, (int64_t)declined_count);
        n00b_cmdr_result_free(parse);
        return n00b_result_ok(int, 0);
    }

    /* Positional `file` is required for audit mode. */
    if (n00b_cmdr_arg_count(parse) < 1) {
        n00b_eprintf(
            "n00b-audit: missing positional <file> (use --sign / --verify for non-audit modes)");
        n00b_cmdr_result_free(parse);
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
    }
    n00b_string_t *target = n00b_cmdr_arg_str(parse, 0);
    if (!target || target->u8_bytes == 0) {
        n00b_cmdr_result_free(parse);
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
    }

    /* --format handling. terminal (default) and json are the v1
     * values; everything else is rejected. The Phase 4 stub that
     * stderr-diagnosed json + returned ok-2 has been replaced (in
     * Phase 5) by a real dispatch to `n00b_audit_print_json` below;
     * here we just validate the flag value and remember the choice. */
    n00b_string_t *fmt_flag     = r"--format";
    n00b_string_t *fmt_terminal = r"terminal";
    n00b_string_t *fmt_json     = r"json";
    n00b_string_t *fmt = nullptr;
    if (n00b_cmdr_flag_present(parse, fmt_flag)) {
        fmt = n00b_cmdr_flag_str(parse, fmt_flag);
    }
    bool want_json = false;
    if (fmt && fmt->u8_bytes > 0) {
        if (n00b_unicode_str_eq(fmt, fmt_json)) {
            want_json = true;
        }
        else if (!n00b_unicode_str_eq(fmt, fmt_terminal)) {
            n00b_eprintf("n00b-audit: unrecognized --format value: «#» (use terminal or json)",
                         fmt);
            n00b_cmdr_result_free(parse);
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_ARGS);
        }
    }

    /* Resolve the guidance file path. */
    n00b_string_t *guidance_flag = r"--guidance";
    n00b_string_t *guidance_path = nullptr;
    if (n00b_cmdr_flag_present(parse, guidance_flag)) {
        guidance_path = n00b_cmdr_flag_str(parse, guidance_flag);
    }
    if (!guidance_path || guidance_path->u8_bytes == 0) {
        n00b_string_t *cwd = n00b_get_current_directory();
        if (!cwd) {
            n00b_cmdr_result_free(parse);
            return diagnose_and_fail(
                "cwd lookup failed",
                N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
        }
        auto disc = n00b_audit_find_guidance_file(cwd);
        if (n00b_result_is_err(disc)) {
            n00b_cmdr_result_free(parse);
            return diagnose_and_fail(
                "guidance discovery",
                n00b_result_get_err(disc));
        }
        guidance_path = n00b_result_get(disc);
    }

    /* Load guidance. */
    auto gr = n00b_audit_load_guidance(guidance_path);
    if (n00b_result_is_err(gr)) {
        n00b_cmdr_result_free(parse);
        return diagnose_and_fail("load guidance",
                                 n00b_result_get_err(gr));
    }
    n00b_audit_guidance_t *guidance = n00b_result_get(gr);

    /* Build engine. */
    auto er = n00b_audit_engine_new(guidance);
    if (n00b_result_is_err(er)) {
        n00b_cmdr_result_free(parse);
        return diagnose_and_fail("engine build",
                                 n00b_result_get_err(er));
    }
    n00b_audit_engine_t *engine = n00b_result_get(er);

    /*
     * WP-011: per-invocation toggles. `--ignore-baseline` skips the
     * baseline suppression set; `--baseline-finalize` enables the
     * bootstrap path (we must also disable baseline suppression
     * during the bootstrap run itself — otherwise the findings we
     * want to baseline would already be suppressed if a baseline
     * happened to exist).
     */
    n00b_string_t *ib_flag = r"--ignore-baseline";
    n00b_string_t *bf_flag = r"--baseline-finalize";
    n00b_string_t *ow_flag = r"--overwrite";
    bool want_ignore_baseline = n00b_cmdr_flag_present(parse, ib_flag);
    bool want_baseline_final  = n00b_cmdr_flag_present(parse, bf_flag);
    bool want_overwrite       = n00b_cmdr_flag_present(parse, ow_flag);
    if (want_ignore_baseline || want_baseline_final) {
        n00b_audit_engine_set_ignore_baseline(engine, true);
    }

    /*
     * WP-012: forward the --allow-unsigned flag to the engine so
     * the signature gate downgrades verification failures from
     * "drop" to "warn-and-keep". During --baseline-finalize we
     * also allow-unsigned implicitly: there's no signature on the
     * just-created baseline yet, and the engine should not refuse
     * pre-existing exemption records when the user is bootstrapping
     * the baseline.
     */
    if (n00b_cmdr_flag_present(parse, allow_uns_flag) || want_baseline_final) {
        n00b_audit_engine_set_allow_unsigned(engine, true);
    }

    /*
     * WP-015: forward --repo-protected to the engine so the
     * trust-root checks downgrade their REPO-source and
     * unsigned-rule-file warnings from prominent to informational.
     */
    n00b_string_t *rp_flag = r"--repo-protected";
    if (n00b_cmdr_flag_present(parse, rp_flag)) {
        n00b_audit_engine_set_repo_protected(engine, true);
    }

    /*
     * WP-017: forward --cpp-args to the engine. Required when
     * auditing real n00b source that needs project headers in
     * scope for preprocessor expansion.
     */
    n00b_string_t *cpp_flag = r"--cpp-args";
    if (n00b_cmdr_flag_present(parse, cpp_flag)) {
        n00b_string_t *val = n00b_cmdr_flag_str(parse, cpp_flag);
        if (val) {
            n00b_audit_engine_set_cpp_args(engine, val);
        }
    }

    /* Check the target. */
    auto cr = n00b_audit_engine_check_file(engine, target);
    if (n00b_result_is_err(cr)) {
        n00b_cmdr_result_free(parse);
        return diagnose_and_fail("check file",
                                 n00b_result_get_err(cr));
    }
    n00b_list_t(n00b_audit_violation_t *) *violations = n00b_result_get(cr);

    /*
     * --fix dispatch (WP-007 Phase 2). When set, skip the
     * stdout-renderer and apply the rewrites in-place. Per the
     * phase2-plan.md § 5 contract, --fix exits 0; the user re-runs
     * without --fix to verify clean.
     */
    n00b_string_t *fix_flag = r"--fix";
    bool want_fix = n00b_cmdr_flag_present(parse, fix_flag);
    if (want_fix) {
        n00b_result_t(int) fr = apply_fixes_dispatch(violations);
        n00b_cmdr_result_free(parse);
        return fr;
    }

    /*
     * WP-011: --baseline-finalize dispatch. Write every current
     * finding into `<project_root>/audit/baseline/baseline.bnf` and
     * return ok-0. Per D-X6 the bulk baseline is bounded to one
     * moment (project adoption); refuse to clobber an existing file
     * without `--overwrite`.
     */
    if (want_baseline_final) {
        n00b_string_t *root = guidance->project_root;
        if (!root) {
            n00b_eprintf(
                "n00b-audit: --baseline-finalize: guidance has no project root");
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        /*
         * WP-012: if --key + --signer are present, auto-sign the
         * baseline file after writing. Without them, write the
         * baseline file unsigned and emit a stderr warning that
         * the audit verifier will refuse it absent --allow-unsigned.
         */
        n00b_string_t *bf_key = n00b_cmdr_flag_present(parse, key_flag)
                                    ? n00b_cmdr_flag_str(parse, key_flag)
                                    : nullptr;
        n00b_string_t *bf_signer = n00b_cmdr_flag_present(parse, signer_flag)
                                       ? n00b_cmdr_flag_str(parse, signer_flag)
                                       : nullptr;
        bool will_sign = bf_key && bf_key->u8_bytes > 0
                          && bf_signer && bf_signer->u8_bytes > 0;

        n00b_result_t(int) bfr = n00b_audit_finalize_baseline_signed(
            root, violations, want_overwrite,
            will_sign ? bf_key : nullptr,
            will_sign ? bf_signer : nullptr);
        if (n00b_result_is_err(bfr)) {
            int code = n00b_result_get_err(bfr);
            if (code == N00B_AUDIT_ERR_GUIDANCE_SCHEMA) {
                n00b_eprintf(
                    "n00b-audit: baseline.bnf already exists; pass --overwrite to clobber");
            }
            else {
                n00b_eprintf(
                    "n00b-audit: --baseline-finalize failed: «#»",
                    n00b_audit_err_str(code));
            }
            n00b_cmdr_result_free(parse);
            return n00b_result_ok(int, 2);
        }
        int written = n00b_result_get(bfr);
        n00b_eprintf(
            "n00b-audit: baselined «#» finding(s) to «#»/audit/baseline/baseline.bnf",
            (int64_t)written, root);
        if (will_sign) {
            n00b_eprintf(
                "n00b-audit: baseline signed (-> baseline.bnf.sig)");
        }
        else {
            n00b_eprintf(
                "n00b-audit: baseline written WITHOUT a signature; subsequent audits will refuse it absent --allow-unsigned (pass --key + --signer to auto-sign)");
        }
        n00b_cmdr_result_free(parse);
        return n00b_result_ok(int, 0);
    }

    /* Render — dispatch on `--format`. Both renderers share the
     * same return-shape contract; on err, emit a stderr diagnostic
     * and return ok-2 (the W-4 internal-error path). */
    n00b_result_t(int) pr = want_json
                                ? n00b_audit_print_json(violations, guidance)
                                : n00b_audit_print_terminal(violations, guidance);
    if (n00b_result_is_err(pr)) {
        n00b_cmdr_result_free(parse);
        return diagnose_and_fail("render", n00b_result_get_err(pr));
    }

    int exit_code = (n00b_list_len(*violations) == 0) ? 0 : 1;
    n00b_cmdr_result_free(parse);
    return n00b_result_ok(int, exit_code);
}
