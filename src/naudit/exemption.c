/*
 * WP-011 — exemption + baseline record schema, hashing, loader,
 * matcher, and baseline writer.
 *
 * # DF-Y resolution — canonicalization shapes
 *
 * Two distinct canonicalizations live in this file: one for rule BNF
 * content hashing, one for matched-region fingerprinting. Both feed
 * `n00b_hash_raw` (XXH3-128 — the same primitive backing
 * `n00b_string_t.cached_hash`; per `src/core/hash.c::n00b_string_hash`
 * + `n00b_hash_raw`) and produce a lowercase 32-character hex string.
 *
 * ## Rule BNF canonicalization
 *
 * Per the WP-011 prompt step 2, the canonical-form spec must be
 * trivial-reformat-robust but production-edit-sensitive. The
 * canonicalization:
 *
 *   1. Walk the BNF text line-by-line (split on `\n`).
 *   2. Drop lines whose first non-whitespace byte is `#` (comments).
 *   3. Trim trailing whitespace (spaces, tabs, `\r`) from each line.
 *   4. Trim leading whitespace from each line. Indentation in BNF
 *      bodies has no semantic meaning per the slay BNF loader —
 *      see `src/slay/bnf.c` strip rules — so stripping it is safe.
 *   5. Drop fully-blank lines after the trim.
 *   6. Join surviving lines with a single `\n` separator (no
 *      trailing newline).
 *
 * This makes the hash stable across:
 *   - comment-only edits inside the rule's BNF body;
 *   - leading-indent reformatting;
 *   - trailing-whitespace tweaks;
 *   - extra blank lines;
 *   - CR/LF normalization (the trim removes `\r`).
 *
 * And it changes whenever any production text byte changes
 * (token name, terminal text, rewrite template, etc.).
 *
 * ## Region fingerprint canonicalization
 *
 * Per the WP-011 prompt step 3 (and preflight risk 2), region
 * fingerprinting is the matching primitive for Phase 1; whitespace-
 * only changes inside the matched span must NOT change the
 * fingerprint, but token-text changes must. The canonicalization:
 *
 *   1. Walk byte-by-byte; normalize CR/LF endings to `\n`.
 *   2. Split on `\n`.
 *   3. Per line: strip leading + trailing whitespace; collapse
 *      internal whitespace (` `, `\t`) runs to a single space.
 *   4. Drop fully-blank lines.
 *   5. Join surviving lines with a single `\n` (no trailing
 *      newline).
 *
 * Examples (region bytes -> canonical bytes):
 *
 *   "  int *p = NULL;\n"          -> "int *p = NULL;"
 *   "  int  *p\t=\tNULL;\n  "     -> "int * p = NULL;"
 *   "int *p = NULL;\n\n\n"        -> "int *p = NULL;"
 *
 * # Exemption file format
 *
 * Per the prompt's "Decision points" + § 8 of the white paper,
 * Phase 1 supports **both** layouts via the same loader:
 *
 *   1. `audit/exemptions/<id>.bnf` — one file per record. Better
 *      merge-conflict surface (the paper's recommendation).
 *   2. `audit/baseline/baseline.bnf` — a single file with many
 *      `@exemption <id>` sections.
 *
 * The loader sees both as "one or more `@exemption` sections in a
 * single file" and returns one struct per section. Per-file or
 * multi-section is the writer's choice.
 *
 * # Tokenizer + metagrammar reuse
 *
 * The exemption file format reuses the existing `audit_rule_file`
 * tokenizer + `audit-rule-file.bnf` metagrammar. The only difference
 * from a guidance file is that exemption sections open with
 * `@exemption <id>` instead of `@rule <id>`. The tokenizer's
 * special-case for `@rule` is extended to recognize `@exemption`
 * symmetrically (both emit a RULE_MARKER token); the metagrammar's
 * `<rule_section>` shape (`<rule_marker> <meta_field>* <bnf_body>`)
 * accommodates exemption sections naturally because exemption files
 * carry no BNF productions — the empty `<bnf_body>` reduction
 * succeeds against zero `<bnf_line>` children.
 *
 * Per project DECISIONS.md D-005, this file's public functions
 * carry no `_kargs` block. Per D-008, null guards use the `!ptr`
 * idiom.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/hash.h"
#include "core/string.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/result.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/path.h"

#include "naudit/blame.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/violation.h"
#include "internal/naudit/_naudit_internal.h"

#include "audit_rule_file_grammar.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

/*
 * WP-012 — the parent process needs access to `environ` to forward
 * its environment into the ssh-keygen child via `posix_spawn`. POSIX
 * declares this in unistd.h on some systems but not all; declare it
 * here to be portable across macOS + Linux (D-001 platform matrix).
 */
extern char **environ;

/* ---------------------------------------------------------------- */
/* Hex encoding                                                     */
/* ---------------------------------------------------------------- */

/*
 * Lowercase hex-encode a 128-bit value as a 32-character
 * n00b_string_t. The byte order is the natural memory layout of the
 * `n00b_uint128_t` (the XXH3-128 result interpreted as a u128 — see
 * `n00b_xxh_convert` in `src/core/hash.c`). Order stability is
 * guaranteed by the convert routine: same input bytes -> same u128
 * pattern -> same hex digits.
 */
static n00b_string_t *
hex_encode_u128(n00b_uint128_t hv)
{
    static const char digits[] = "0123456789abcdef";
    /*
     * Treat the 128-bit value as 16 raw bytes. Reading via a typed
     * pointer to unsigned char is the standard C aliasing-safe path.
     */
    const unsigned char *bytes = (const unsigned char *)&hv;
    char                 buf[32];
    for (int i = 0; i < 16; i++) {
        buf[2 * i + 0] = digits[(bytes[i] >> 4) & 0xF];
        buf[2 * i + 1] = digits[(bytes[i] >> 0) & 0xF];
    }
    return n00b_string_from_raw(buf, 32);
}

/* ---------------------------------------------------------------- */
/* BNF canonicalization (DF-Y)                                      */
/* ---------------------------------------------------------------- */

/*
 * Trim leading whitespace (spaces, tabs) from a byte slice.
 * Returns the new start offset.
 */
static size_t
skip_leading_ws(const char *buf, size_t start, size_t end)
{
    size_t i = start;
    while (i < end && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    return i;
}

/*
 * Trim trailing whitespace + CR (spaces, tabs, `\r`) from a byte
 * slice. Returns the new end offset (exclusive).
 */
static size_t
trim_trailing_ws(const char *buf, size_t start, size_t end)
{
    while (end > start
           && (buf[end - 1] == ' ' || buf[end - 1] == '\t'
               || buf[end - 1] == '\r')) {
        end--;
    }
    return end;
}

n00b_string_t *
n00b_audit_compute_rule_content_hash(n00b_string_t *bnf_fragment)
{
    /*
     * Step 0: empty / null fragment → hash of the empty canonical
     * string. We still go through `n00b_hash_raw(nullptr, 0)`-equivalent
     * by passing a zero-length data pointer; XXH3-128 of empty input
     * is well-defined.
     */
    const char *src = (bnf_fragment && bnf_fragment->u8_bytes > 0)
                          ? bnf_fragment->data
                          : "";
    size_t      n   = (bnf_fragment && bnf_fragment->u8_bytes > 0)
                          ? bnf_fragment->u8_bytes
                          : 0;

    n00b_buffer_t *acc = n00b_buffer_empty();

    /* Walk line by line. */
    size_t i = 0;
    bool   need_sep = false;
    while (i < n) {
        /* Find end of line. */
        size_t lstart = i;
        while (i < n && src[i] != '\n') {
            i++;
        }
        size_t lend = i;
        if (i < n) {
            i++; /* skip the '\n' */
        }

        /* Trim trailing whitespace + CR. */
        lend = trim_trailing_ws(src, lstart, lend);
        /* Trim leading whitespace. */
        size_t s = skip_leading_ws(src, lstart, lend);

        /* Drop empty lines. */
        if (s >= lend) {
            continue;
        }
        /* Drop comment lines (first non-ws byte is `#`). */
        if (src[s] == '#') {
            continue;
        }

        if (need_sep) {
            n00b_buffer_t *nl = n00b_buffer_from_bytes((char *)"\n", 1);
            n00b_buffer_concat(acc, nl);
        }
        n00b_buffer_t *line = n00b_buffer_from_bytes(
            (char *)(src + s), (int64_t)(lend - s));
        n00b_buffer_concat(acc, line);
        need_sep = true;
    }

    /*
     * Hash the canonicalized bytes. Empty input: XXH3-128 of zero
     * bytes — well-defined per the xxHash spec and deterministic.
     */
    const void *data = acc->byte_len > 0 ? (const void *)acc->data
                                          : (const void *)"";
    size_t      len  = acc->byte_len > 0 ? (size_t)acc->byte_len : 0;
    n00b_uint128_t hv = n00b_hash_raw(data, len);
    return hex_encode_u128(hv);
}

/* ---------------------------------------------------------------- */
/* Region fingerprint canonicalization (DF-Y)                       */
/* ---------------------------------------------------------------- */

n00b_string_t *
n00b_audit_compute_region_fingerprint(n00b_string_t *region_bytes)
{
    const char *src = (region_bytes && region_bytes->u8_bytes > 0)
                          ? region_bytes->data
                          : "";
    size_t      n   = (region_bytes && region_bytes->u8_bytes > 0)
                          ? region_bytes->u8_bytes
                          : 0;

    n00b_buffer_t *acc = n00b_buffer_empty();

    size_t i        = 0;
    bool   need_sep = false;
    while (i < n) {
        /* Find end of line (treat \r\n and \r as line terminators too). */
        size_t lstart = i;
        while (i < n && src[i] != '\n' && src[i] != '\r') {
            i++;
        }
        size_t lend = i;
        if (i < n && src[i] == '\r') {
            i++;
            if (i < n && src[i] == '\n') {
                i++;
            }
        }
        else if (i < n && src[i] == '\n') {
            i++;
        }

        /* Trim leading + trailing whitespace. */
        size_t s = skip_leading_ws(src, lstart, lend);
        size_t e = trim_trailing_ws(src, s, lend);
        if (s >= e) {
            continue;
        }

        /*
         * Collapse runs of internal whitespace (` `, `\t`) into a
         * single space. Walk the [s, e) slice into a per-line
         * buffer.
         */
        n00b_buffer_t *lb       = n00b_buffer_empty();
        bool           prev_ws  = false;
        for (size_t j = s; j < e; j++) {
            char c = src[j];
            if (c == ' ' || c == '\t') {
                if (!prev_ws) {
                    n00b_buffer_t *sp = n00b_buffer_from_bytes(
                        (char *)" ", 1);
                    n00b_buffer_concat(lb, sp);
                    prev_ws = true;
                }
            }
            else {
                n00b_buffer_t *ch = n00b_buffer_from_bytes(
                    (char *)&src[j], 1);
                n00b_buffer_concat(lb, ch);
                prev_ws = false;
            }
        }

        if (lb->byte_len == 0) {
            continue;
        }

        if (need_sep) {
            n00b_buffer_t *nl = n00b_buffer_from_bytes((char *)"\n", 1);
            n00b_buffer_concat(acc, nl);
        }
        n00b_buffer_concat(acc, lb);
        need_sep = true;
    }

    const void *data = acc->byte_len > 0 ? (const void *)acc->data
                                          : (const void *)"";
    size_t      len  = acc->byte_len > 0 ? (size_t)acc->byte_len : 0;
    n00b_uint128_t hv = n00b_hash_raw(data, len);
    return hex_encode_u128(hv);
}

/* ---------------------------------------------------------------- */
/* Matching predicate                                               */
/* ---------------------------------------------------------------- */

/* ---------------------------------------------------------------- */
/* WP-014 — expiration enforcement helper                           */
/* ---------------------------------------------------------------- */

/*
 * Format the current UTC time as ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`.
 * Used at the top of `n00b_audit_exemption_match` to drive the
 * expiration check without modifying the WP-013 match signature
 * (which is a D-024-preserved schema function — a `now` parameter
 * on `_match` would be visible to every caller). Lexicographic
 * comparison against an exemption's `expires_at` (which may be a
 * shorter `YYYY-MM-DD` form) is well-defined: the calendar-only
 * form sorts as if the trailing instant fields were all zero, so
 * an exemption with `expires_at = "2026-01-01"` is "expired" the
 * instant the wall clock crosses `"2026-01-01T00:00:01Z"`, which
 * matches the intuitive calendar semantics.
 */
static n00b_string_t *
current_iso8601_utc(void)
{
    time_t    now = time(nullptr);
    struct tm tm_buf;
    /*
     * gmtime_r is POSIX; naudit-side may use libc primitives (the
     * libc carveout). On rare clock-failure (now == -1 on a
     * misconfigured embedded system) we return the empty string;
     * the caller's lex-compare against any sane `expires_at` then
     * returns "not expired" (empty < anything non-empty), which is
     * the safe default (don't drop exemptions on clock failure).
     */
    if (now == (time_t)-1) {
        return n00b_string_empty();
    }
    if (!gmtime_r(&now, &tm_buf)) {
        return n00b_string_empty();
    }
    /*
     * Hand-format rather than strftime: the format is fixed, the
     * fields are bounded, and we avoid locale-dependent surprises.
     * tm_year is years since 1900; tm_mon is 0-based.
     */
    int year  = tm_buf.tm_year + 1900;
    int mon   = tm_buf.tm_mon  + 1;
    int day   = tm_buf.tm_mday;
    int hour  = tm_buf.tm_hour;
    int minute = tm_buf.tm_min;
    int second = tm_buf.tm_sec;
    /* Clamp seconds: POSIX permits 60 for leap seconds; we cap at 59
     * for lexicographic monotonicity at the second boundary. */
    if (second > 59) {
        second = 59;
    }
    /*
     * Use n00b_cformat per the libn00b API surface — the «#:NNd»
     * spec syntax delegates to format_spec.c's printf-flag parser
     * (`0` flag + width digits) for zero-padded fixed-width.
     */
    return n00b_cformat(
        "«#:04d»-«#:02d»-«#:02d»T«#:02d»:«#:02d»:«#:02d»Z",
        (int64_t)year, (int64_t)mon, (int64_t)day,
        (int64_t)hour, (int64_t)minute, (int64_t)second);
}

bool
n00b_audit_exemption_is_expired(n00b_audit_exemption_t *exemption,
                                 n00b_string_t          *now_iso8601)
{
    if (!exemption || !now_iso8601 || now_iso8601->u8_bytes == 0) {
        return false;
    }
    n00b_string_t *exp = exemption->expires_at;
    if (!exp || exp->u8_bytes == 0) {
        /* No expiration field => never expires. */
        return false;
    }
    /*
     * Lexicographic byte compare. The expires_at field may be
     * `YYYY-MM-DD` or the full `YYYY-MM-DDTHH:MM:SSZ`; in both
     * cases left-to-right byte order matches chronological order
     * because ISO-8601's most-significant-field-first layout is
     * intentional. The shorter calendar form compares against the
     * longer instant form correctly because '\0' (end of string)
     * sorts as less than any byte in the longer string's tail —
     * which means an exemption with `expires_at = "2026-01-01"`
     * is treated as "expired" the moment `now_iso8601` becomes
     * `"2026-01-01T00:00:00Z"` (the calendar form's missing tail
     * is treated as the lowest possible value; the instant
     * `"2026-01-01T00:00:00Z"` then compares greater).
     *
     * For correctness, do a manual byte-by-byte compare since we
     * can't rely on libc strcmp behavior with the n00b_string_t's
     * pre-NUL-terminated buffer.
     */
    size_t la = exp->u8_bytes;
    size_t lb = now_iso8601->u8_bytes;
    size_t mn = la < lb ? la : lb;
    for (size_t i = 0; i < mn; i++) {
        unsigned char ca = (unsigned char)exp->data[i];
        unsigned char cb = (unsigned char)now_iso8601->data[i];
        if (ca < cb) {
            return true;  /* expires_at < now → expired */
        }
        if (ca > cb) {
            return false; /* expires_at > now → not expired */
        }
    }
    /* Common prefix matched; whichever is shorter sorts less. */
    if (la < lb) {
        return true;  /* expires_at is the shorter prefix => "<" => expired */
    }
    return false;     /* equal or now is shorter => not expired */
}

void
n00b_audit_exemption_blank_rationale(n00b_audit_exemption_t *exemption)
{
    if (!exemption) {
        return;
    }
    exemption->rationale = n00b_string_empty();
}

bool
n00b_audit_exemption_match(n00b_audit_exemption_t  *exemption,
                            n00b_audit_violation_t  *violation,
                            n00b_string_t           *repo_root,
                            int                      similarity_threshold)
{
    if (!exemption || !violation || !violation->rule) {
        return false;
    }
    if (!exemption->rule_id || !violation->rule->content_hash) {
        return false;
    }
    if (!exemption->region_fingerprint || !violation->region_fingerprint) {
        return false;
    }
    /*
     * WP-014 expiration enforcement — runs BEFORE the blame /
     * fingerprint check per D-026 ordering. An exemption whose
     * `expires_at` is in the past does NOT suppress, even with a
     * valid signature and a clean blame trace (white paper § 11.4:
     * "exemptions must expire and be re-reviewed").
     *
     * The current time is fetched here rather than on the public
     * surface so the WP-013 four-argument signature stays
     * unchanged (D-024 preserves the matcher signature for
     * schema-compatibility callers).
     */
    {
        n00b_string_t *now = current_iso8601_utc();
        if (n00b_audit_exemption_is_expired(exemption, now)) {
            return false;
        }
    }
    /*
     * Step 1 (always): rule identity. The content-hash equality
     * is the D-X3 dual-identity gate — exemptions never cross
     * rules, regardless of the rule's human-name churn.
     */
    if (!n00b_unicode_str_eq(exemption->rule_id,
                              violation->rule->content_hash)) {
        return false;
    }
    /*
     * Step 2: blame anchor (WP-013) — post-commit path. We derive
     * the signing commit from VCS history every time per § 5.2:
     * it is NOT stored in the exemption record. If the record's
     * `source_file` is null (loader skipped populating it) OR
     * `repo_root` is null (engine running outside a git repo) OR
     * the signing-commit lookup fails (exemption file not yet
     * committed — the pre-commit case from § 4.4), we fall back
     * to the pure-fingerprint match (WP-011 behavior) below.
     */
    if (repo_root && exemption->source_file
        && exemption->source_file->u8_bytes > 0) {
        n00b_option_t(n00b_string_t *) signing_opt =
            n00b_audit_blame_signing_commit(repo_root,
                                            exemption->source_file);
        if (n00b_option_is_set(signing_opt)) {
            n00b_string_t *signing = n00b_option_get(signing_opt);
            /*
             * Post-commit path: BOTH blame trace AND fingerprint
             * must match. The fingerprint is the cross-check per
             * § 4.4 — it catches drift that libgit2's blame
             * heuristic accepts but the developer didn't intend.
             */
            if (!n00b_unicode_str_eq(exemption->region_fingerprint,
                                     violation->region_fingerprint)) {
                return false;
            }
            return n00b_audit_blame_traces_to(
                repo_root,
                violation->file,
                violation->line,
                violation->end_line,
                signing,
                exemption->locator_line,
                exemption->locator_end_line,
                similarity_threshold);
        }
        /* fall through to fingerprint-only fallback */
    }
    /*
     * Step 2 fallback (pre-commit case, OR no-repo case): pure
     * fingerprint. White paper § 4.4 last paragraph — once the
     * exemption file is committed, the post-commit path takes
     * over and the fingerprint becomes redundant (we keep it
     * around as belt-and-suspenders).
     */
    if (!n00b_unicode_str_eq(exemption->region_fingerprint,
                              violation->region_fingerprint)) {
        return false;
    }
    return true;
}

/* ---------------------------------------------------------------- */
/* Region byte extraction                                           */
/* ---------------------------------------------------------------- */

/*
 * Compute the byte offset corresponding to a (line, col) tuple in the
 * source buffer. 1-based line and column on entry; column is treated
 * as a byte count from the line start (matches slay's
 * `n00b_token_info_t.column` semantics — same as `cli.c`'s
 * `line_col_to_offset`). Returns -1 if the position is past EOF.
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
    int64_t needed   = col - 1;
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

n00b_string_t *
n00b_audit_extract_region_bytes_from_text(n00b_string_t *src_text,
                                          int64_t        line,
                                          int64_t        column,
                                          int64_t        end_line,
                                          int64_t        end_column)
{
    if (!src_text) {
        return nullptr;
    }
    const char *src = src_text->data;
    size_t      n   = (size_t)src_text->u8_bytes;
    int64_t     s   = line_col_to_offset(src, n, line, column);
    int64_t     e   = line_col_to_offset(src, n, end_line, end_column);
    if (s < 0 || e < 0 || e < s) {
        return nullptr;
    }
    /* Return the raw span bytes; the caller canonicalizes via
     * n00b_audit_compute_region_fingerprint before hashing. */
    return n00b_string_from_raw(src + s, (int64_t)(e - s));
}

n00b_string_t *
n00b_audit_extract_region_bytes(n00b_string_t *file_path,
                                int64_t        line,
                                int64_t        column,
                                int64_t        end_line,
                                int64_t        end_column)
{
    if (!file_path) {
        return nullptr;
    }
    file_path = n00b_path_canonical(file_path);
    auto fr   = n00b_file_open(file_path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return nullptr;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return nullptr;
    }
    n00b_buffer_t *buf = n00b_result_get(br);
    n00b_string_t *src = n00b_string_from_raw(buf->data,
                                              (int64_t)buf->byte_len);
    /*
     * WP-021 / task #14: this raw-file path is correct ONLY when the
     * parse-tree coordinates were produced from the same on-disk bytes
     * (i.e. preprocessing OFF). For preprocessed languages the
     * coordinates index the reflowed post-preprocess buffer, so the
     * engine must use `..._from_text` against the parsed `src_text`
     * instead — re-reading the raw file here would slice the wrong
     * span (e.g. `int *p`→`int * p` shifts a NULL token by one column).
     */
    return n00b_audit_extract_region_bytes_from_text(src, line, column,
                                                     end_line, end_column);
}

/* ---------------------------------------------------------------- */
/* Loader — reuses the audit-rule-file tokenizer + metagrammar      */
/* ---------------------------------------------------------------- */

/*
 * Compare an n00b_string_t to a C-string literal — byte-wise; suitable
 * for the directive-name ASCII keys.
 */
static bool
str_eq_cstr(n00b_string_t *s, const char *expected)
{
    if (!s || !expected) {
        return false;
    }
    size_t elen = 0;
    while (expected[elen]) {
        elen++;
    }
    if (s->u8_bytes != elen) {
        return false;
    }
    for (size_t i = 0; i < elen; i++) {
        if (s->data[i] != expected[i]) {
            return false;
        }
    }
    return true;
}

/*
 * Parse a decimal integer string into int64_t. Returns true on
 * success. Mirrors guidance.c's `parse_int64`.
 */
static bool
parse_int64_field(n00b_string_t *s, int64_t *out)
{
    if (!s || s->u8_bytes == 0) {
        *out = 0;
        return false;
    }
    int64_t     v   = 0;
    size_t      n   = s->u8_bytes;
    const char *buf = s->data;
    size_t      i   = 0;
    bool        neg = false;
    if (buf[0] == '-') {
        neg = true;
        i   = 1;
    }
    if (i >= n) {
        return false;
    }
    for (; i < n; i++) {
        char c = buf[i];
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + (int64_t)(c - '0');
    }
    *out = neg ? -v : v;
    return true;
}

static n00b_token_info_t *
nth_token_child(n00b_parse_tree_t *node, int idx)
{
    if (!node) {
        return nullptr;
    }
    size_t n = n00b_pt_num_children(node);
    if (idx < 0 || (size_t)idx >= n) {
        return nullptr;
    }
    n00b_parse_tree_t *child = n00b_pt_get_child(node, (size_t)idx);
    if (!child) {
        return nullptr;
    }
    while (!n00b_pt_is_token(child)) {
        size_t nc = n00b_pt_num_children(child);
        if (nc != 1) {
            return nullptr;
        }
        child = n00b_pt_get_child(child, 0);
        if (!child) {
            return nullptr;
        }
    }
    return n00b_parse_node_token(child);
}

static n00b_string_t *
token_text(n00b_token_info_t *tok)
{
    if (!tok) {
        return nullptr;
    }
    if (!n00b_option_is_set(tok->value)) {
        return nullptr;
    }
    return n00b_option_get(tok->value);
}

/*
 * Assemble a meta-field value (REST + continuation lines joined by
 * `\n`). Mirrors guidance.c's `assemble_field_value` exactly; copied
 * here to keep exemption.c independent of guidance.c's static
 * helpers.
 */
static n00b_string_t *
assemble_field_value(n00b_parse_tree_t *meta_field_node)
{
    n00b_token_info_t *rest_tok = nth_token_child(meta_field_node, 1);
    n00b_string_t     *rest     = token_text(rest_tok);
    if (!rest) {
        rest = n00b_string_empty();
    }

    enum { MAX_CONT = 1024 };
    n00b_parse_tree_t *conts[MAX_CONT];
    int n_cont = n00b_pt_collect_nt_deep(meta_field_node, "continuation",
                                         conts, MAX_CONT);
    if (n_cont == 0) {
        return rest;
    }

    n00b_buffer_t *acc = n00b_buffer_empty();
    if (rest->u8_bytes > 0) {
        n00b_buffer_t *r = n00b_buffer_from_bytes(rest->data,
                                                  (int64_t)rest->u8_bytes);
        n00b_buffer_concat(acc, r);
    }
    bool need_sep = (rest->u8_bytes > 0);
    for (int i = 0; i < n_cont; i++) {
        n00b_token_info_t *line_tok = nth_token_child(conts[i], 0);
        n00b_string_t     *line     = token_text(line_tok);
        if (!line) {
            line = n00b_string_empty();
        }
        if (need_sep) {
            n00b_buffer_t *nl = n00b_buffer_from_bytes((char *)"\n", 1);
            n00b_buffer_concat(acc, nl);
        }
        n00b_buffer_t *lb = n00b_buffer_from_bytes(line->data,
                                                   (int64_t)line->u8_bytes);
        n00b_buffer_concat(acc, lb);
        need_sep = true;
    }

    return n00b_string_from_raw(acc->data, (int64_t)acc->byte_len);
}

/*
 * Walk one `<rule_section>` (which, in an exemption file, is an
 * `@exemption` section thanks to the tokenizer's symmetric marker
 * handling) and populate the exemption struct from its `<meta_field>`
 * children. Returns false on a schema error.
 */
static bool
populate_exemption(n00b_parse_tree_t      *sec,
                   n00b_audit_exemption_t *ex,
                   int                    *err_code)
{
    enum { MAX_FIELDS = 4096 };
    n00b_parse_tree_t *fields[MAX_FIELDS];
    int n = n00b_pt_collect_nt_deep(sec, "meta_field",
                                    fields, MAX_FIELDS);
    for (int i = 0; i < n; i++) {
        n00b_token_info_t *name_tok = nth_token_child(fields[i], 0);
        n00b_string_t     *name     = token_text(name_tok);
        if (!name) {
            continue;
        }
        n00b_string_t *value = assemble_field_value(fields[i]);
        if (str_eq_cstr(name, "version")) {
            int64_t v = 0;
            if (!parse_int64_field(value, &v)) {
                *err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
                return false;
            }
            ex->version = v;
            if (v != 1) {
                *err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA_VERSION;
                return false;
            }
        }
        else if (str_eq_cstr(name, "rule_id")) {
            ex->rule_id = value;
        }
        else if (str_eq_cstr(name, "rule_name")) {
            ex->rule_name = value;
        }
        else if (str_eq_cstr(name, "file_path")) {
            ex->file_path = value;
        }
        else if (str_eq_cstr(name, "locator_line")) {
            int64_t v = 0;
            (void)parse_int64_field(value, &v);
            ex->locator_line = v;
        }
        else if (str_eq_cstr(name, "locator_col")) {
            int64_t v = 0;
            (void)parse_int64_field(value, &v);
            ex->locator_col = v;
        }
        else if (str_eq_cstr(name, "locator_end_line")) {
            int64_t v = 0;
            (void)parse_int64_field(value, &v);
            ex->locator_end_line = v;
        }
        else if (str_eq_cstr(name, "locator_end_col")) {
            int64_t v = 0;
            (void)parse_int64_field(value, &v);
            ex->locator_end_col = v;
        }
        else if (str_eq_cstr(name, "region_fingerprint")) {
            ex->region_fingerprint = value;
        }
        else if (str_eq_cstr(name, "rationale")) {
            ex->rationale = value;
        }
        else if (str_eq_cstr(name, "signer_id")) {
            ex->signer_id = value;
        }
        else if (str_eq_cstr(name, "approved_at")) {
            ex->approved_at = value;
        }
        else if (str_eq_cstr(name, "expires_at")) {
            ex->expires_at = value;
        }
        /* Unknown directives tolerated silently — forward-compat. */
    }

    /*
     * Required fields per the v1 schema: `version`, `rule_id`,
     * `region_fingerprint`. Everything else is optional /
     * informational in Phase 1 (signatures + blame land in WP-012 /
     * WP-013).
     */
    if (!ex->rule_id || ex->rule_id->u8_bytes == 0
        || !ex->region_fingerprint
        || ex->region_fingerprint->u8_bytes == 0
        || ex->version != 1) {
        *err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
        return false;
    }
    return true;
}

/*
 * Build the metagrammar grammar object. Mirrors guidance.c's
 * `build_metagrammar`.
 */
static n00b_grammar_t *
build_metagrammar(void)
{
    n00b_grammar_t *g = n00b_grammar_new();
    n00b_string_t  *text =
        n00b_string_from_cstr(N00B_AUDIT_RULE_FILE_METAGRAMMAR);
    bool ok = n00b_bnf_load(text, r"file", g);
    if (!ok) {
        n00b_grammar_free(g);
        return nullptr;
    }
    return g;
}

n00b_result_t(n00b_list_t(n00b_audit_exemption_t *) *)
n00b_audit_load_exemptions(n00b_string_t *path)
{
    if (!path) {
        return n00b_result_err(
            n00b_list_t(n00b_audit_exemption_t *) *,
            N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }

    path = n00b_path_canonical(path);

    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(
            n00b_list_t(n00b_audit_exemption_t *) *,
            N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return n00b_result_err(
            n00b_list_t(n00b_audit_exemption_t *) *,
            N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }
    n00b_buffer_t *src_buf = n00b_result_get(br);

    n00b_grammar_t *meta_g = build_metagrammar();
    if (!meta_g) {
        return n00b_result_err(
            n00b_list_t(n00b_audit_exemption_t *) *,
            N00B_AUDIT_ERR_GUIDANCE_PARSE);
    }

    void *st = _n00b_audit_rule_file_scanner_state_new();
    n00b_scanner_t *sc = n00b_scanner_new(
        src_buf, _n00b_audit_rule_file_scan_cb(), meta_g,
        .state    = st,
        .reset_cb = _n00b_audit_rule_file_reset_cb());
    n00b_token_stream_t *ts = n00b_token_stream_new(sc);

    n00b_parse_result_t *pr = n00b_grammar_parse(meta_g, ts);
    if (!n00b_parse_result_ok(pr)) {
        n00b_parse_result_free(pr);
        n00b_grammar_free(meta_g);
        return n00b_result_err(
            n00b_list_t(n00b_audit_exemption_t *) *,
            N00B_AUDIT_ERR_GUIDANCE_PARSE);
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    n00b_list_t(n00b_audit_exemption_t *) *out = n00b_alloc(
        n00b_list_t(n00b_audit_exemption_t *));
    *out = n00b_list_new(n00b_audit_exemption_t *);

    enum { MAX_SECTIONS = 65536 };
    n00b_parse_tree_t *sections[MAX_SECTIONS];
    int n_sections = n00b_pt_collect_nt_deep(tree, "rule_section",
                                             sections, MAX_SECTIONS);
    for (int i = 0; i < n_sections; i++) {
        n00b_audit_exemption_t *ex = n00b_alloc(n00b_audit_exemption_t);
        ex->version            = 0;
        ex->rule_id            = nullptr;
        ex->rule_name          = nullptr;
        ex->file_path          = nullptr;
        ex->locator_line       = 0;
        ex->locator_col        = 0;
        ex->locator_end_line   = 0;
        ex->locator_end_col    = 0;
        ex->region_fingerprint = nullptr;
        ex->rationale          = nullptr;
        ex->signer_id          = nullptr;
        ex->approved_at        = nullptr;
        ex->expires_at         = nullptr;
        ex->source_file        = path;

        int err = 0;
        if (!populate_exemption(sections[i], ex, &err)) {
            n00b_parse_result_free(pr);
            n00b_grammar_free(meta_g);
            return n00b_result_err(
                n00b_list_t(n00b_audit_exemption_t *) *,
                err ? err : N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
        }
        n00b_list_push(*out, ex);
    }

    n00b_parse_result_free(pr);
    n00b_grammar_free(meta_g);
    return n00b_result_ok(n00b_list_t(n00b_audit_exemption_t *) *, out);
}

n00b_result_t(n00b_list_t(n00b_audit_exemption_t *) *)
n00b_audit_discover_exemptions(n00b_string_t *project_root)
{
    n00b_list_t(n00b_audit_exemption_t *) *out = n00b_alloc(
        n00b_list_t(n00b_audit_exemption_t *));
    *out = n00b_list_new(n00b_audit_exemption_t *);

    if (!project_root) {
        return n00b_result_ok(
            n00b_list_t(n00b_audit_exemption_t *) *, out);
    }

    project_root = n00b_path_canonical(project_root);

    n00b_string_t *ex_dir = n00b_path_simple_join(
        project_root, r"audit/exemptions");
    if (!n00b_path_is_directory(ex_dir)) {
        return n00b_result_ok(
            n00b_list_t(n00b_audit_exemption_t *) *, out);
    }

    n00b_list_t(n00b_string_t *) *entries = n00b_list_directory(
        ex_dir,
        .extension = r".bnf",
        .full_path = true);
    if (!entries) {
        return n00b_result_ok(
            n00b_list_t(n00b_audit_exemption_t *) *, out);
    }

    int64_t n = n00b_list_len(*entries);
    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *p = n00b_list_get(*entries, i);
        if (!p) {
            continue;
        }
        auto lr = n00b_audit_load_exemptions(p);
        if (n00b_result_is_err(lr)) {
            return n00b_result_err(
                n00b_list_t(n00b_audit_exemption_t *) *,
                n00b_result_get_err(lr));
        }
        n00b_list_t(n00b_audit_exemption_t *) *batch = n00b_result_get(lr);
        int64_t bn = n00b_list_len(*batch);
        for (int64_t j = 0; j < bn; j++) {
            n00b_list_push(*out, n00b_list_get(*batch, j));
        }
    }
    return n00b_result_ok(n00b_list_t(n00b_audit_exemption_t *) *, out);
}

/* ---------------------------------------------------------------- */
/* Baseline writer                                                  */
/* ---------------------------------------------------------------- */

/*
 * Create a directory at `path` (POSIX mkdir(0755)). Returns true on
 * success OR when the directory already exists. Distinct from
 * n00b's vfs surface — naudit's I/O surface is libc-direct (matches
 * `cli.c`'s pattern + `src/util/path.c::n00b_new_temp_dir`).
 */
static bool
ensure_directory(n00b_string_t *path)
{
    if (!path) {
        return false;
    }
    if (n00b_path_is_directory(path)) {
        return true;
    }
    if (mkdir(path->data, 0755) == 0) {
        return true;
    }
    return n00b_path_is_directory(path);
}

/*
 * Write a string to a file at `path`, truncating any existing content.
 * Mirrors cli.c's `write_whole_file` minus the n00b_buffer_t wrapper.
 */
static bool
write_text_file(n00b_string_t *path, n00b_string_t *content)
{
    if (!path || !content) {
        return false;
    }
    auto fr = n00b_file_open(path, .mode = N00B_FILE_W,
                              .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(fr)) {
        return false;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    bool         ok = true;
    if (content->u8_bytes > 0) {
        auto wr = n00b_file_write(f, content->data,
                                   (size_t)content->u8_bytes);
        if (n00b_result_is_err(wr)) {
            ok = false;
        }
    }
    n00b_file_close(f);
    return ok;
}

/*
 * Append a single line "@<directive> <value>\n" to the accumulator.
 * The `value` may contain newlines — the rule-file metaformat handles
 * multi-line values via continuation lines indented one space deep;
 * we serialize accordingly.
 */
static void
emit_directive(n00b_buffer_t *acc,
               const char    *directive,
               n00b_string_t *value)
{
    n00b_buffer_t *at = n00b_buffer_from_bytes((char *)"@", 1);
    n00b_buffer_concat(acc, at);
    n00b_buffer_t *dn = n00b_buffer_from_bytes((char *)directive,
                                                (int64_t)strlen(directive));
    n00b_buffer_concat(acc, dn);
    if (value && value->u8_bytes > 0) {
        n00b_buffer_t *sp = n00b_buffer_from_bytes((char *)" ", 1);
        n00b_buffer_concat(acc, sp);
        /* Single-line emission; rationale + region_fingerprint
         * are short enough that we don't need continuation lines
         * in Phase 1's baseline output. */
        n00b_buffer_t *vb = n00b_buffer_from_bytes(
            value->data, (int64_t)value->u8_bytes);
        n00b_buffer_concat(acc, vb);
    }
    n00b_buffer_t *nl = n00b_buffer_from_bytes((char *)"\n", 1);
    n00b_buffer_concat(acc, nl);
}

static void
emit_directive_int(n00b_buffer_t *acc,
                   const char    *directive,
                   int64_t        value)
{
    n00b_string_t *s = n00b_cformat("«#»", value);
    emit_directive(acc, directive, s);
}

n00b_result_t(int)
n00b_audit_finalize_baseline(
    n00b_string_t                          *project_root,
    n00b_list_t(n00b_audit_violation_t *)  *violations,
    bool                                    overwrite)
{
    /* Unsigned shape — pass nullptr signing pair through to the
     * signed variant so there's a single write path. WP-012 reuse. */
    return n00b_audit_finalize_baseline_signed(project_root, violations,
                                               overwrite, nullptr, nullptr);
}

n00b_result_t(int)
n00b_audit_finalize_baseline_signed(
    n00b_string_t                          *project_root,
    n00b_list_t(n00b_audit_violation_t *)  *violations,
    bool                                    overwrite,
    n00b_string_t                          *key_path,
    n00b_string_t                          *signer_id)
{
    if (!project_root || !violations) {
        return n00b_result_err(int,
                               N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }

    project_root = n00b_path_canonical(project_root);

    /* Ensure `<project_root>/audit/baseline/` exists. */
    n00b_string_t *audit_dir = n00b_path_simple_join(
        project_root, r"audit");
    if (!ensure_directory(audit_dir)) {
        return n00b_result_err(int,
                               N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }
    n00b_string_t *base_dir = n00b_path_simple_join(
        audit_dir, r"baseline");
    if (!ensure_directory(base_dir)) {
        return n00b_result_err(int,
                               N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }
    n00b_string_t *base_file = n00b_path_simple_join(
        base_dir, r"baseline.bnf");

    if (!overwrite && n00b_path_is_file(base_file)) {
        return n00b_result_err(int, N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
    }

    /*
     * Build the file body. Format reuses the rule-file metaformat:
     *   @schema_version 1
     *   <blank line>
     *   @exemption baseline_NNNN
     *   @version 1
     *   @rule_id <hex>
     *   ...
     */
    n00b_buffer_t *acc = n00b_buffer_empty();
    {
        n00b_buffer_t *hdr = n00b_buffer_from_bytes(
            (char *)"@schema_version 1\n\n",
            (int64_t)strlen("@schema_version 1\n\n"));
        n00b_buffer_concat(acc, hdr);
    }

    int64_t n = n00b_list_len(*violations);
    int     written = 0;
    for (int64_t i = 0; i < n; i++) {
        n00b_audit_violation_t *v = n00b_list_get(*violations, i);
        if (!v || !v->rule || !v->rule->content_hash
            || !v->region_fingerprint) {
            continue;
        }
        n00b_string_t *id = n00b_cformat("baseline_«#»", (int64_t)i);
        n00b_string_t *marker = n00b_cformat("@exemption «#»\n", id);
        n00b_buffer_t *mb = n00b_buffer_from_bytes(
            marker->data, (int64_t)marker->u8_bytes);
        n00b_buffer_concat(acc, mb);

        emit_directive_int(acc, "version", 1);
        emit_directive(acc, "rule_id", v->rule->content_hash);
        if (v->rule->id) {
            emit_directive(acc, "rule_name", v->rule->id);
        }
        if (v->file) {
            emit_directive(acc, "file_path", v->file);
        }
        emit_directive_int(acc, "locator_line", v->line);
        emit_directive_int(acc, "locator_col", v->column);
        emit_directive_int(acc, "locator_end_line", v->end_line);
        emit_directive_int(acc, "locator_end_col", v->end_column);
        emit_directive(acc, "region_fingerprint", v->region_fingerprint);
        emit_directive(acc, "rationale",
                       r"baselined at project adoption");
        /* WP-012 placeholder; current writer leaves empty value. */
        emit_directive(acc, "signer_id", n00b_string_empty());
        emit_directive(acc, "approved_at", n00b_string_empty());

        n00b_buffer_t *nl = n00b_buffer_from_bytes((char *)"\n", 1);
        n00b_buffer_concat(acc, nl);
        written++;
    }

    n00b_string_t *body = n00b_string_from_raw(acc->data,
                                                (int64_t)acc->byte_len);
    if (!write_text_file(base_file, body)) {
        return n00b_result_err(int,
                               N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }

    /*
     * WP-012 auto-sign path. When key_path + signer_id are both
     * supplied, immediately sign the freshly written baseline so
     * `<base_file>.sig` lands atomically with the data. On signing
     * failure the baseline file is left in place — the caller can
     * retry with --baseline-finalize --overwrite, or sign manually.
     */
    if (key_path && key_path->u8_bytes > 0
        && signer_id && signer_id->u8_bytes > 0) {
        auto sr = n00b_audit_exemption_sign(base_file, key_path, signer_id);
        if (n00b_result_is_err(sr)) {
            return n00b_result_err(int, n00b_result_get_err(sr));
        }
    }

    return n00b_result_ok(int, written);
}

/* ---------------------------------------------------------------- */
/* WP-012 — SSH signature primitives (sign + verify)                */
/* ---------------------------------------------------------------- */

/*
 * DF-Z resolution. We use direct `posix_spawn` + `waitpid` rather
 * than libn00b's `n00b_subproc_*` API.
 *
 * Rationale:
 *   - libn00b's subprocess primitive is an async, conduit-driven
 *     abstraction (PTY support, capture pipelines, completion
 *     events) designed for long-lived child processes integrated
 *     with the event loop. For a synchronous "spawn ssh-keygen,
 *     wait, check exit code, optionally pipe one file to stdin"
 *     the abstraction adds significant overhead — and naudit-side
 *     code is explicitly carved out of the libc-I/O ban (the ban
 *     applies to libn00b core: src/n00b/, src/slay/, src/core/;
 *     naudit-side code may use POSIX subprocess primitives per
 *     the WP-012 prompt and the WP-011 precedent in
 *     `apply_fixes_in_file`).
 *   - POSIX `posix_spawn` with file_actions is the natural primitive
 *     for the "open exemption file -> dup to STDIN -> exec
 *     ssh-keygen" pattern documented in the prompt. The shell-
 *     shorthand `< <file>` cannot be expressed via a plain argv;
 *     explicit dup is required either way.
 *   - The dependency surface stays minimal: <spawn.h>, <fcntl.h>,
 *     <sys/wait.h>, <unistd.h> — all POSIX-mandatory headers.
 *
 * Trade-off acknowledged: posix_spawn doesn't capture stderr by
 * default, so the verifier's ability to distinguish
 * UNKNOWN_SIGNER from BAD_SIGNATURE based on ssh-keygen's stderr
 * is limited. We fall back to "collapse to BAD_SIGNATURE when in
 * doubt" — the loader's stderr diagnostic remains correct
 * ("refused") and the engineering distinction is a Phase-1.5 nice
 * to have, not a security-critical signal.
 */

/*
 * Wait for a child PID and translate its termination into an
 * (exited_ok, exit_status) pair. Returns false on waitpid error.
 */
static bool
_wait_child(pid_t pid, int *exit_status_out)
{
    int   status = 0;
    pid_t done   = 0;
    do {
        done = waitpid(pid, &status, 0);
    } while (done < 0 && errno == EINTR);

    if (done != pid) {
        return false;
    }
    if (WIFEXITED(status)) {
        *exit_status_out = WEXITSTATUS(status);
        return true;
    }
    /* Killed by a signal or stopped — surface as a subprocess
     * failure with a sentinel non-zero status. */
    *exit_status_out = -1;
    return true;
}

n00b_result_t(int)
n00b_audit_exemption_sign(n00b_string_t *file_path,
                          n00b_string_t *key_path,
                          n00b_string_t *signer_id)
{
    if (!file_path || !key_path || !signer_id) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    /* Path canonicalization rule (PR #72 / WP-008 D-017): every
     * function taking a path argument auto-normalizes to an
     * absolute form before use. */
    file_path = n00b_path_canonical(file_path);
    key_path  = n00b_path_canonical(key_path);

    if (!file_path || !key_path) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    /*
     * argv layout:
     *   ssh-keygen -Y sign -f <key_path> -n naudit-exemption-v1 <file_path>
     *
     * ssh-keygen writes `<file_path>.sig` next to the input. We
     * don't pipe anything to its STDIN — the file argument is read
     * by ssh-keygen directly.
     *
     * The `(char *)` casts are required by the historical `char *const
     * argv[]` shape of posix_spawn; the strings are not modified.
     */
    char *argv[] = {
        (char *)"ssh-keygen",
        (char *)"-Y",
        (char *)"sign",
        (char *)"-f",
        (char *)key_path->data,
        (char *)"-n",
        (char *)"naudit-exemption-v1",
        (char *)file_path->data,
        nullptr,
    };
    /* Silence the `signer_id` unused warning — sign mode doesn't
     * need the principal name; ssh-keygen reads it from the key
     * file itself. Kept in the signature for API symmetry with
     * verify + so the CLI can validate the user typed it. */
    (void)signer_id;

    pid_t                    pid     = 0;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }
    int spawn_rc = posix_spawnp(&pid, "ssh-keygen", &actions, nullptr,
                                argv, environ);
    posix_spawn_file_actions_destroy(&actions);

    if (spawn_rc != 0) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    int exit_status = 0;
    if (!_wait_child(pid, &exit_status)) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }
    if (exit_status != 0) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }
    return n00b_result_ok(int, 0);
}

n00b_result_t(int)
n00b_audit_exemption_verify(n00b_string_t *file_path,
                            n00b_string_t *roster_path,
                            n00b_string_t *signer_id)
{
    if (!file_path || !roster_path || !signer_id) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    file_path   = n00b_path_canonical(file_path);
    roster_path = n00b_path_canonical(roster_path);
    if (!file_path || !roster_path) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    /*
     * Derive the .sig sibling path and require it exist. If it's
     * absent the verifier returns NO_SIGNATURE before spawning
     * ssh-keygen — same observable behavior, cheaper. The .sig path
     * goes through canonicalization implicitly via the file_path
     * already-canonical path; we just append `.sig`.
     */
    n00b_string_t *sig_path = n00b_cformat("«#».sig", file_path);

    if (!n00b_path_is_file(sig_path)) {
        return n00b_result_err(int, N00B_AUDIT_ERR_EXEMPTION_NO_SIGNATURE);
    }

    /*
     * Open the exemption file so its content can be piped to
     * ssh-keygen's STDIN. The shell-shorthand `< <file>` is NOT
     * implementable via posix_spawn; we open it parent-side and
     * dup2 to STDIN_FILENO in the child's file_actions.
     */
    int data_fd = open(file_path->data, O_RDONLY | O_CLOEXEC);
    if (data_fd < 0) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    /*
     * argv:
     *   ssh-keygen -Y verify -f <roster> -I <signer_id>
     *              -n naudit-exemption-v1 -s <sig_path>
     */
    char *argv[] = {
        (char *)"ssh-keygen",
        (char *)"-Y",
        (char *)"verify",
        (char *)"-f",
        (char *)roster_path->data,
        (char *)"-I",
        (char *)signer_id->data,
        (char *)"-n",
        (char *)"naudit-exemption-v1",
        (char *)"-s",
        (char *)sig_path->data,
        nullptr,
    };

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(data_fd);
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }
    /* Child: dup data_fd onto STDIN_FILENO, then close the original. */
    if (posix_spawn_file_actions_adddup2(&actions, data_fd, STDIN_FILENO)
        != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(data_fd);
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }
    if (posix_spawn_file_actions_addclose(&actions, data_fd) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(data_fd);
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    pid_t pid      = 0;
    int   spawn_rc = posix_spawnp(&pid, "ssh-keygen", &actions, nullptr,
                                  argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    /* Parent closes its copy regardless of spawn outcome — the child
     * (if spawned) has its own duped fd. */
    close(data_fd);

    if (spawn_rc != 0) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }

    int exit_status = 0;
    if (!_wait_child(pid, &exit_status)) {
        return n00b_result_err(int, N00B_AUDIT_ERR_SIGN_SUBPROCESS);
    }
    if (exit_status == 0) {
        return n00b_result_ok(int, 0);
    }

    /*
     * Differentiating UNKNOWN_SIGNER from BAD_SIGNATURE solely from
     * ssh-keygen's exit code is not reliably possible (OpenSSH
     * collapses many failure modes to exit 255). Per the WP-012
     * prompt's documented fallback, we collapse the two cases to
     * BAD_SIGNATURE when in doubt. A future enhancement would
     * capture ssh-keygen's stderr and pattern-match for the
     * "principal not found" string to disambiguate; for now the
     * conservative collapse keeps the security verdict correct
     * (refused) without claiming a precision we can't deliver.
     */
    return n00b_result_err(int, N00B_AUDIT_ERR_EXEMPTION_BAD_SIGNATURE);
}
