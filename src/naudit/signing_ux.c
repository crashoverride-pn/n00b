/*
 * WP-014 — interactive signing UX implementation.
 *
 * See `include/naudit/signing_ux.h` for the public surface
 * documentation. This file implements the per-item signing
 * ceremony described in the signed-exemption-records white paper
 * § 11, including the rationale-blanking property, the
 * `--initial-adoption` bulk-sign path, and the input-source
 * abstraction that makes the flow testable in-process.
 *
 * # DF-BA — input-source abstraction
 *
 * The signing ceremony reads developer input from an abstracted
 * `n00b_naudit_input_source_t`. Two implementations exist:
 *
 *   - fd-backed (production): wraps `STDIN_FILENO` (or any other
 *     fd a future caller might want); reads bytes via `read(2)`
 *     one byte at a time and buffers per line. Acceptable cost
 *     for a low-volume interactive ceremony — the developer
 *     types lines, not blocks.
 *   - buffer-backed (tests): wraps a pre-loaded `n00b_buffer_t *`
 *     carrying scripted input; advances an internal cursor on
 *     each `read_line` call. Lets the unit tests stay in-process
 *     and deterministic — no subprocess spawning, no pipe wiring.
 *
 * The public `read_line` entry point doesn't branch on the kind
 * at every byte — it dispatches once at the top, then runs the
 * appropriate loop. The flow above sees a uniform interface and
 * does not care which kind it has.
 *
 * # DF-BB — multiline rationale terminator
 *
 * Resolved as `.`-on-its-own-line (mutt-style). The blank-line
 * alternative was rejected because it silently truncates
 * multi-paragraph rationales: a developer who writes
 *
 *     This exemption covers the legacy DSP loop.
 *
 *     The vendor's SDK is not updateable until Q3; the rationale
 *     for retaining is documented in tickets X / Y / Z.
 *
 * would have their rationale chopped at the first blank line. The
 * `.`-on-its-own-line terminator is rare in human text and the
 * prompt explicitly tells the developer to use it.
 *
 * Per project DECISIONS.md D-005, this file's public functions
 * carry no `_kargs` block — naudit's public surface does not
 * expose `.allocator` keyword arguments. Per D-008, null guards
 * use the `!ptr` idiom.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "conduit/print.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/path.h"

#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/signing_ux.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ================================================================ */
/* Input-source abstraction                                          */
/* ================================================================ */

n00b_naudit_input_source_t *
n00b_naudit_input_from_fd(int fd)
{
    n00b_naudit_input_source_t *s =
        n00b_alloc(n00b_naudit_input_source_t);
    s->kind   = N00B_NAUDIT_INPUT_FROM_FD;
    s->fd     = fd;
    s->buffer = nullptr;
    s->cursor = 0;
    return s;
}

n00b_naudit_input_source_t *
n00b_naudit_input_from_buffer(n00b_buffer_t *buffer)
{
    n00b_naudit_input_source_t *s =
        n00b_alloc(n00b_naudit_input_source_t);
    s->kind   = N00B_NAUDIT_INPUT_FROM_BUFFER;
    s->fd     = -1;
    s->buffer = buffer;
    s->cursor = 0;
    return s;
}

/*
 * Read a line from a buffer-backed source: walk forward from the
 * current cursor until either `\n` is seen (consume it, return the
 * preceding bytes) or the buffer is exhausted. EOF is signaled by
 * a "none" option result.
 */
static n00b_option_t(n00b_string_t *)
read_line_from_buffer(n00b_naudit_input_source_t *src)
{
    if (!src->buffer) {
        return n00b_option_none(n00b_string_t *);
    }
    size_t total = (size_t)src->buffer->byte_len;
    if (src->cursor >= total) {
        return n00b_option_none(n00b_string_t *);
    }
    const char *data  = src->buffer->data;
    size_t      start = src->cursor;
    size_t      i     = start;
    while (i < total && data[i] != '\n') {
        i++;
    }
    /*
     * `[start, i)` is the line content; if `i < total` then data[i]
     * is the terminating `\n` and we advance past it.
     */
    size_t line_len = i - start;
    src->cursor     = (i < total) ? i + 1 : total;
    /* Strip a trailing \r so CRLF-terminated scripted input works
     * without surprises. */
    if (line_len > 0 && data[start + line_len - 1] == '\r') {
        line_len--;
    }
    n00b_string_t *line = n00b_string_from_raw(data + start,
                                                (int64_t)line_len);
    return n00b_option_set(n00b_string_t *, line);
}

/*
 * Read a line from an fd-backed source via `read(2)` one byte at a
 * time. Acceptable cost for the interactive signing ceremony — the
 * volume is human-typed, not bulk. EOF (or read error) returns
 * `none`. The trailing `\n` is consumed and not part of the result.
 */
static n00b_option_t(n00b_string_t *)
read_line_from_fd(n00b_naudit_input_source_t *src)
{
    /*
     * Reasonable per-line buffer; the rationale prompt can take
     * many lines but each line is bounded by what a human types.
     * Grow on demand by capturing into an n00b_buffer_t.
     */
    n00b_buffer_t *acc      = n00b_buffer_empty();
    bool           saw_any  = false;
    while (true) {
        char  byte = 0;
        ssize_t r  = 0;
        do {
            r = read(src->fd, &byte, 1);
        } while (r < 0 && errno == EINTR);
        if (r == 0) {
            /* EOF */
            break;
        }
        if (r < 0) {
            /* read error: treat as EOF (defensive). */
            break;
        }
        saw_any = true;
        if (byte == '\n') {
            break;
        }
        n00b_buffer_t *b1 = n00b_buffer_from_bytes(&byte, 1);
        n00b_buffer_concat(acc, b1);
    }
    if (!saw_any && acc->byte_len == 0) {
        return n00b_option_none(n00b_string_t *);
    }
    /* Strip a trailing \r for CRLF tolerance. */
    int64_t n = acc->byte_len;
    if (n > 0 && acc->data[n - 1] == '\r') {
        n--;
    }
    n00b_string_t *line = n00b_string_from_raw(acc->data, n);
    return n00b_option_set(n00b_string_t *, line);
}

n00b_option_t(n00b_string_t *)
n00b_naudit_input_read_line(n00b_naudit_input_source_t *src)
{
    if (!src) {
        return n00b_option_none(n00b_string_t *);
    }
    if (src->kind == N00B_NAUDIT_INPUT_FROM_BUFFER) {
        return read_line_from_buffer(src);
    }
    return read_line_from_fd(src);
}

/* ================================================================ */
/* ISO-8601 formatter — today + offset                              */
/* ================================================================ */

n00b_string_t *
n00b_audit_today_plus_days_iso(int days_offset)
{
    time_t now = time(nullptr);
    if (now == (time_t)-1) {
        return n00b_string_empty();
    }
    time_t target = now + ((time_t)days_offset) * 86400;
    struct tm tm_buf;
    if (!gmtime_r(&target, &tm_buf)) {
        return n00b_string_empty();
    }
    /*
     * Use n00b_cformat per the libn00b API surface — the «#:NNd»
     * spec syntax delegates to format_spec.c's printf-flag parser
     * (`0` flag + width digits) for zero-padded fixed-width.
     */
    return n00b_cformat("«#:04d»-«#:02d»-«#:02d»",
                        (int64_t)(tm_buf.tm_year + 1900),
                        (int64_t)(tm_buf.tm_mon + 1),
                        (int64_t)tm_buf.tm_mday);
}

/* ================================================================ */
/* Proposal discovery                                                */
/* ================================================================ */

/*
 * Compute the parent directory of `p`. Mirrors POSIX `dirname(3)`
 * semantics for the cases the signing flow needs:
 *   - `/a/b/c` -> `/a/b`
 *   - `/a/b/c/` -> `/a/b`
 *   - `/a` -> `/`
 *   - `/` -> `/`
 *   - empty / nullptr -> nullptr (caller treats as failure).
 *
 * The libn00b path surface ships an `n00b_path_parts` splitter but no
 * direct parent helper, so we do this manually.
 */
static n00b_string_t *
path_parent(n00b_string_t *p)
{
    if (!p || p->u8_bytes == 0) {
        return nullptr;
    }
    const char *data = p->data;
    int64_t     n    = (int64_t)p->u8_bytes;
    /* Strip trailing slashes (but keep a lone "/"). */
    while (n > 1 && data[n - 1] == '/') {
        n--;
    }
    int64_t last = -1;
    for (int64_t i = n - 1; i >= 0; i--) {
        if (data[i] == '/') {
            last = i;
            break;
        }
    }
    if (last < 0) {
        /* No slash: parent is the current dir; return nullptr to
         * signal "no upward step possible" — the caller falls back
         * to the proposal-file-relative path. */
        return nullptr;
    }
    if (last == 0) {
        /* `/foo` → `/`. */
        return r"/";
    }
    return n00b_string_from_raw(data, last);
}

/*
 * Strcmp-style comparator for n00b_string_t * pointers, used by
 * `n00b_list_sort` to alphabetize the discovered proposal paths.
 * The list-element type is `n00b_string_t *`, so qsort passes
 * `n00b_string_t **`.
 */
static int
str_ptr_cmp_asc(const void *a, const void *b)
{
    n00b_string_t *sa = *(n00b_string_t **)a;
    n00b_string_t *sb = *(n00b_string_t **)b;
    if (!sa && !sb) {
        return 0;
    }
    if (!sa) {
        return -1;
    }
    if (!sb) {
        return 1;
    }
    size_t la = sa->u8_bytes;
    size_t lb = sb->u8_bytes;
    size_t mn = la < lb ? la : lb;
    for (size_t i = 0; i < mn; i++) {
        unsigned char ca = (unsigned char)sa->data[i];
        unsigned char cb = (unsigned char)sb->data[i];
        if (ca < cb) {
            return -1;
        }
        if (ca > cb) {
            return 1;
        }
    }
    if (la < lb) {
        return -1;
    }
    if (la > lb) {
        return 1;
    }
    return 0;
}

n00b_result_t(n00b_list_t(n00b_string_t *) *)
n00b_audit_discover_proposals(n00b_string_t *project_root)
{
    n00b_list_t(n00b_string_t *) *out =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *out = n00b_list_new(n00b_string_t *);

    if (!project_root) {
        return n00b_result_err(
            n00b_list_t(n00b_string_t *) *,
            N00B_AUDIT_ERR_ENGINE_BAD_ARGS);
    }

    /* Path-canonicalization rule (auto-memory feedback_path_handling). */
    project_root = n00b_path_canonical(project_root);

    n00b_string_t *ex_dir = n00b_path_simple_join(
        project_root, r"audit/exemptions");
    if (!n00b_path_is_directory(ex_dir)) {
        /* No proposals when the directory is absent — empty list. */
        return n00b_result_ok(n00b_list_t(n00b_string_t *) *, out);
    }

    n00b_list_t(n00b_string_t *) *entries = n00b_list_directory(
        ex_dir,
        .extension = r".bnf",
        .full_path = true);
    if (!entries) {
        return n00b_result_ok(n00b_list_t(n00b_string_t *) *, out);
    }

    int64_t n = n00b_list_len(*entries);
    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *p = n00b_list_get(*entries, i);
        if (!p) {
            continue;
        }
        n00b_string_t *sig = n00b_cformat("«#».sig", p);
        if (n00b_path_is_file(sig)) {
            continue;
        }
        n00b_list_push(*out, p);
    }

    /* Deterministic order. */
    n00b_list_sort(*out, str_ptr_cmp_asc);

    return n00b_result_ok(n00b_list_t(n00b_string_t *) *, out);
}

/* ================================================================ */
/* Atomic file write (write to .tmp, then rename)                   */
/* ================================================================ */

static bool
write_text_atomic(n00b_string_t *path, n00b_string_t *content)
{
    if (!path || !content) {
        return false;
    }
    n00b_string_t *tmp = n00b_cformat("«#».tmp", path);
    auto fr = n00b_file_open(tmp, .mode = N00B_FILE_W,
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
    if (!ok) {
        unlink(tmp->data);
        return false;
    }
    /* POSIX rename(2) is atomic on same-filesystem moves. */
    if (rename(tmp->data, path->data) != 0) {
        unlink(tmp->data);
        return false;
    }
    return true;
}

/* ================================================================ */
/* Rewriting an exemption record                                     */
/* ================================================================ */

/*
 * Re-serialize an exemption record back to the `audit-rule-file.bnf`
 * format. We emit one `@directive` per non-empty field, following the
 * shape `n00b_audit_finalize_baseline` already establishes.
 */
static n00b_string_t *
serialize_exemption(n00b_audit_exemption_t *ex,
                    const char             *section_id)
{
    n00b_buffer_t *acc = n00b_buffer_empty();
    /* File header — schema_version 1, blank line, then the section. */
    {
        const char *hdr = "@schema_version 1\n\n";
        n00b_buffer_t *hb = n00b_buffer_from_bytes((char *)hdr,
                                                    (int64_t)strlen(hdr));
        n00b_buffer_concat(acc, hb);
    }
    {
        n00b_string_t *marker = n00b_cformat("@exemption «#»\n",
                                              n00b_string_from_cstr(
                                                  (char *)section_id));
        n00b_buffer_t *mb = n00b_buffer_from_bytes(
            marker->data, (int64_t)marker->u8_bytes);
        n00b_buffer_concat(acc, mb);
    }
    /* Helper macro-like emitter; keep it local for clarity. */
#define EMIT_LINE(buf, line)                                                  \
    do {                                                                      \
        const char *_p = (line);                                              \
        n00b_buffer_t *_b = n00b_buffer_from_bytes((char *)_p,                \
                                                    (int64_t)strlen(_p));     \
        n00b_buffer_concat((buf), _b);                                        \
    } while (0)

    /* Required fields. */
    EMIT_LINE(acc, "@version 1\n");
    if (ex->rule_id && ex->rule_id->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@rule_id «#»\n", ex->rule_id);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    if (ex->rule_name && ex->rule_name->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@rule_name «#»\n", ex->rule_name);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    if (ex->file_path && ex->file_path->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@file_path «#»\n", ex->file_path);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    {
        n00b_string_t *l = n00b_cformat("@locator_line «#»\n",
                                         (int64_t)ex->locator_line);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    {
        n00b_string_t *l = n00b_cformat("@locator_col «#»\n",
                                         (int64_t)ex->locator_col);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    {
        n00b_string_t *l = n00b_cformat("@locator_end_line «#»\n",
                                         (int64_t)ex->locator_end_line);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    {
        n00b_string_t *l = n00b_cformat("@locator_end_col «#»\n",
                                         (int64_t)ex->locator_end_col);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    if (ex->region_fingerprint && ex->region_fingerprint->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@region_fingerprint «#»\n",
                                         ex->region_fingerprint);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    /*
     * Rationale: may be multi-line. The rule-file metaformat
     * supports continuation lines indented one space deep. Emit the
     * first line on the @directive line; subsequent lines get a
     * leading space.
     */
    if (ex->rationale && ex->rationale->u8_bytes > 0) {
        EMIT_LINE(acc, "@rationale ");
        size_t      n   = ex->rationale->u8_bytes;
        const char *src = ex->rationale->data;
        size_t      i   = 0;
        bool        first = true;
        while (i < n) {
            size_t lstart = i;
            while (i < n && src[i] != '\n') {
                i++;
            }
            size_t lend = i;
            if (i < n) {
                i++;
            }
            if (first) {
                if (lend > lstart) {
                    n00b_buffer_t *b = n00b_buffer_from_bytes(
                        (char *)(src + lstart),
                        (int64_t)(lend - lstart));
                    n00b_buffer_concat(acc, b);
                }
                EMIT_LINE(acc, "\n");
                first = false;
            }
            else {
                /* Continuation: one leading space + the line text. */
                EMIT_LINE(acc, " ");
                if (lend > lstart) {
                    n00b_buffer_t *b = n00b_buffer_from_bytes(
                        (char *)(src + lstart),
                        (int64_t)(lend - lstart));
                    n00b_buffer_concat(acc, b);
                }
                EMIT_LINE(acc, "\n");
            }
        }
    }
    else {
        EMIT_LINE(acc, "@rationale\n");
    }
    if (ex->signer_id && ex->signer_id->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@signer_id «#»\n", ex->signer_id);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    if (ex->approved_at && ex->approved_at->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@approved_at «#»\n",
                                         ex->approved_at);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    if (ex->expires_at && ex->expires_at->u8_bytes > 0) {
        n00b_string_t *l = n00b_cformat("@expires_at «#»\n",
                                         ex->expires_at);
        n00b_buffer_t *b = n00b_buffer_from_bytes(l->data,
                                                   (int64_t)l->u8_bytes);
        n00b_buffer_concat(acc, b);
    }
    EMIT_LINE(acc, "\n");
#undef EMIT_LINE
    return n00b_string_from_raw(acc->data, (int64_t)acc->byte_len);
}

/*
 * Derive a section id from the proposal file's basename: take the
 * last path component, strip the trailing `.bnf`. The original
 * section id (e.g., `wp012_widget_loop_0001`) lived in the agent's
 * draft text but the loader doesn't currently surface it on the
 * struct; we use the filename as a stable, human-meaningful
 * substitute.
 */
static const char *
section_id_from_path(n00b_string_t *path)
{
    if (!path || path->u8_bytes == 0) {
        return "proposal";
    }
    const char *data = path->data;
    size_t      n    = path->u8_bytes;
    /* Find the last '/'. */
    size_t      slash = 0;
    bool        seen  = false;
    for (size_t i = 0; i < n; i++) {
        if (data[i] == '/') {
            slash = i + 1;
            seen  = true;
        }
    }
    if (!seen) {
        slash = 0;
    }
    /* Strip the `.bnf` suffix if present. */
    size_t end = n;
    if (end >= 4 && data[end - 4] == '.' && data[end - 3] == 'b'
        && data[end - 2] == 'n' && data[end - 1] == 'f') {
        end -= 4;
    }
    if (end <= slash) {
        return "proposal";
    }
    /* Allocate a NUL-terminated copy. */
    size_t len = end - slash;
    char *buf = n00b_alloc_array(char, len + 1);
    for (size_t i = 0; i < len; i++) {
        buf[i] = data[slash + i];
    }
    buf[len] = 0;
    return (const char *)buf;
}

/* ================================================================ */
/* Region preview (with `>` marker on exempted lines)               */
/* ================================================================ */

/*
 * Read the source file and print three lines of context above and
 * below the exempted region, marking the exempted lines with a
 * leading `>`. Out-of-range lines are silently skipped. The
 * function reads the entire file (mmap) to compute the slice; for
 * the audit ceremony's volumes (small source files; bounded
 * regions) this is acceptable.
 */
static void
print_region_preview(n00b_string_t *file_path,
                     int64_t        start_line,
                     int64_t        end_line)
{
    if (!file_path || file_path->u8_bytes == 0) {
        n00b_eprintf("  (no file path on proposal — skipping preview)");
        return;
    }
    auto fr = n00b_file_open(file_path,
                              .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        n00b_eprintf("  (could not open «#» for preview)", file_path);
        return;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        n00b_eprintf("  (could not read «#» for preview)", file_path);
        return;
    }
    n00b_buffer_t *buf = n00b_result_get(br);
    const char    *src = buf->data;
    int64_t        n   = buf->byte_len;
    int64_t        win_start = start_line - 3;
    int64_t        win_end   = end_line   + 3;
    if (win_start < 1) {
        win_start = 1;
    }
    /* Iterate line-by-line. */
    int64_t cur_line = 1;
    int64_t i        = 0;
    while (i < n && cur_line <= win_end) {
        int64_t lstart = i;
        while (i < n && src[i] != '\n') {
            i++;
        }
        int64_t lend = i;
        if (i < n) {
            i++;
        }
        if (cur_line >= win_start && cur_line <= win_end) {
            n00b_string_t *line = n00b_string_from_raw(
                src + lstart, (int64_t)(lend - lstart));
            const char *marker =
                (cur_line >= start_line && cur_line <= end_line)
                    ? "  > "
                    : "    ";
            n00b_printf("«#»«#»: «#»",
                        n00b_string_from_cstr((char *)marker),
                        (int64_t)cur_line, line);
        }
        cur_line++;
    }
}

/* ================================================================ */
/* Rule summary lookup                                               */
/* ================================================================ */

/*
 * Discover the guidance file from the proposal's project root and
 * look up the rule whose content_hash matches the exemption's
 * rule_id. Returns nullptr when the rule can't be found (the flow
 * still proceeds — we just won't have a summary to print).
 *
 * The proposal's `source_file` is the path to its own `.bnf`; we
 * walk up two parents (`audit/exemptions/X.bnf` -> `audit/X.bnf` ->
 * project_root) to find `audit-rules.bnf` and call the existing
 * `n00b_audit_load_guidance` to get the rule list.
 */
static n00b_audit_rule_t *
lookup_rule_summary(n00b_audit_exemption_t *ex)
{
    if (!ex || !ex->source_file) {
        return nullptr;
    }
    /*
     * Source file is `<root>/audit/exemptions/<id>.bnf` →
     * project_root is two parents up.
     */
    n00b_string_t *p1 = path_parent(ex->source_file);
    if (!p1) {
        return nullptr;
    }
    n00b_string_t *p2 = path_parent(p1);
    if (!p2) {
        return nullptr;
    }
    n00b_string_t *root = path_parent(p2);
    if (!root) {
        return nullptr;
    }
    n00b_string_t *rules_path = n00b_path_simple_join(
        root, r"audit-rules.bnf");
    if (!n00b_path_is_file(rules_path)) {
        return nullptr;
    }
    auto gr = n00b_audit_load_guidance(rules_path);
    if (n00b_result_is_err(gr)) {
        return nullptr;
    }
    n00b_audit_guidance_t *g = n00b_result_get(gr);
    if (!g || !g->rules) {
        return nullptr;
    }
    int64_t n = n00b_list_len(*g->rules);
    for (int64_t i = 0; i < n; i++) {
        n00b_audit_rule_t *r = n00b_list_get(*g->rules, i);
        if (!r) {
            continue;
        }
        if (!r->content_hash || !ex->rule_id) {
            continue;
        }
        if (n00b_unicode_str_eq(r->content_hash, ex->rule_id)) {
            return r;
        }
    }
    return nullptr;
}

/* ================================================================ */
/* Expiration-input parsing                                          */
/* ================================================================ */

/*
 * Parse the developer's expiration input. Accepts:
 *   - Empty string → returns the default (today + default_days).
 *   - `YYYY-MM-DD`  → returned verbatim as the expires_at value.
 *   - `Nd` / `Nm` / `Ny` (digits + unit) → today + N * unit days.
 *     Months are approximated as 30 days, years as 365 days, per
 *     the WP-014 preflight risk 3.
 * Returns nullptr on any other shape (caller re-prompts or fails).
 */
static n00b_string_t *
parse_expiration_input(n00b_string_t *raw, int default_days)
{
    if (!raw || raw->u8_bytes == 0) {
        return n00b_audit_today_plus_days_iso(default_days);
    }
    const char *data = raw->data;
    size_t      n    = raw->u8_bytes;

    /* ISO-8601 calendar form: exactly 10 chars, YYYY-MM-DD. */
    if (n == 10 && data[4] == '-' && data[7] == '-') {
        bool digits_ok = true;
        for (size_t i = 0; i < 10; i++) {
            if (i == 4 || i == 7) {
                continue;
            }
            if (data[i] < '0' || data[i] > '9') {
                digits_ok = false;
                break;
            }
        }
        if (digits_ok) {
            return raw;
        }
    }
    /* Shorthand: digits + d / m / y suffix. */
    if (n >= 2) {
        char unit = data[n - 1];
        if (unit == 'd' || unit == 'm' || unit == 'y') {
            int64_t v = 0;
            bool    ok = true;
            for (size_t i = 0; i + 1 < n; i++) {
                if (data[i] < '0' || data[i] > '9') {
                    ok = false;
                    break;
                }
                v = v * 10 + (int64_t)(data[i] - '0');
            }
            if (ok && v > 0) {
                int days = (int)v;
                if (unit == 'm') {
                    days = (int)(v * 30);
                }
                else if (unit == 'y') {
                    days = (int)(v * 365);
                }
                return n00b_audit_today_plus_days_iso(days);
            }
        }
    }
    return nullptr;
}

/* ================================================================ */
/* Interactive single-proposal sign                                  */
/* ================================================================ */

n00b_result_t(int)
n00b_audit_sign_proposal_interactive(
    n00b_string_t              *proposal_path,
    n00b_string_t              *key_path,
    n00b_string_t              *signer_id,
    n00b_naudit_input_source_t *input_source,
    int                         default_expiry_days)
{
    if (!proposal_path || !key_path || !signer_id || !input_source) {
        return n00b_result_err(int, N00B_AUDIT_ERR_ENGINE_BAD_ARGS);
    }
    proposal_path = n00b_path_canonical(proposal_path);

    /* Step 1: load the proposal. */
    auto lr = n00b_audit_load_exemptions(proposal_path);
    if (n00b_result_is_err(lr)) {
        return n00b_result_err(int, n00b_result_get_err(lr));
    }
    n00b_list_t(n00b_audit_exemption_t *) *list = n00b_result_get(lr);
    if (!list || n00b_list_len(*list) < 1) {
        return n00b_result_err(int, N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
    }
    /* Phase 1 supports one record per proposal file (the typical
     * shape the agent emits). Multi-section proposal files are
     * out of scope for WP-014 — we operate on the first record. */
    n00b_audit_exemption_t *ex = n00b_list_get(*list, 0);

    /* Step 2: look up the rule's summary text. */
    n00b_audit_rule_t *rule = lookup_rule_summary(ex);

    /* Step 3 + 4: print the rule, the locator, and the region. */
    n00b_printf("=== Proposal: «#» ===", proposal_path);
    if (rule) {
        n00b_printf("Rule:           «#»",
                    rule->id ? rule->id : r"(unnamed)");
        if (rule->title) {
            n00b_printf("Title:          «#»", rule->title);
        }
        if (rule->guidance) {
            n00b_printf("Guidance:       «#»", rule->guidance);
        }
    }
    else if (ex->rule_name) {
        n00b_printf("Rule:           «#»  (full guidance not found)",
                    ex->rule_name);
    }
    n00b_printf("Rule id (hash): «#»",
                ex->rule_id ? ex->rule_id : n00b_string_empty());
    n00b_printf("File path:      «#»",
                ex->file_path ? ex->file_path : n00b_string_empty());
    n00b_printf("Locator:        «#»:«#» .. «#»:«#»",
                (int64_t)ex->locator_line, (int64_t)ex->locator_col,
                (int64_t)ex->locator_end_line, (int64_t)ex->locator_end_col);
    n00b_printf("Fingerprint:    «#»",
                ex->region_fingerprint ? ex->region_fingerprint
                                       : n00b_string_empty());
    /*
     * Region preview: try the absolute path the record stored
     * (`file_path` is typically repo-relative at signing time —
     * see exemption.h's schema doc). If the relative path doesn't
     * resolve, try resolving it from the proposal file's
     * grandparent (the project root).
     */
    if (ex->file_path && ex->file_path->u8_bytes > 0) {
        n00b_string_t *fp = ex->file_path;
        if (!n00b_path_is_file(fp)) {
            n00b_string_t *p1 = path_parent(proposal_path);
            n00b_string_t *p2 = p1 ? path_parent(p1) : nullptr;
            n00b_string_t *root = p2 ? path_parent(p2) : nullptr;
            if (root) {
                n00b_string_t *cand = n00b_path_simple_join(root, fp);
                if (n00b_path_is_file(cand)) {
                    fp = cand;
                }
            }
        }
        n00b_printf("--- region preview ---");
        print_region_preview(fp, ex->locator_line, ex->locator_end_line);
        n00b_printf("--- end preview ---");
    }

    /* Step 5: BLANK the rationale. */
    n00b_audit_exemption_blank_rationale(ex);

    /* Step 6: prompt for new rationale (multiline, `.`-on-own-line). */
    n00b_printf(
        "Rationale (multi-line; end with a `.` on its own line):");
    n00b_buffer_t *rat_acc = n00b_buffer_empty();
    bool           rat_any = false;
    while (true) {
        n00b_option_t(n00b_string_t *) lr_opt =
            n00b_naudit_input_read_line(input_source);
        if (!n00b_option_is_set(lr_opt)) {
            /* EOF before terminator — treat as decline. */
            return n00b_result_ok(int, 1);
        }
        n00b_string_t *line = n00b_option_get(lr_opt);
        if (line->u8_bytes == 1 && line->data[0] == '.') {
            break;
        }
        if (rat_any) {
            n00b_buffer_t *nl = n00b_buffer_from_bytes((char *)"\n", 1);
            n00b_buffer_concat(rat_acc, nl);
        }
        if (line->u8_bytes > 0) {
            n00b_buffer_t *lb = n00b_buffer_from_bytes(
                line->data, (int64_t)line->u8_bytes);
            n00b_buffer_concat(rat_acc, lb);
        }
        rat_any = true;
    }
    n00b_string_t *new_rationale = n00b_string_from_raw(
        rat_acc->data, (int64_t)rat_acc->byte_len);

    /* Step 7: expiration prompt. */
    n00b_string_t *default_exp = n00b_audit_today_plus_days_iso(
        default_expiry_days);
    n00b_printf(
        "Expiration (ISO YYYY-MM-DD, Nd / Nm / Ny shorthand, or blank for default «#»):",
        default_exp);
    n00b_option_t(n00b_string_t *) eopt =
        n00b_naudit_input_read_line(input_source);
    if (!n00b_option_is_set(eopt)) {
        return n00b_result_ok(int, 1);
    }
    n00b_string_t *exp_raw = n00b_option_get(eopt);
    n00b_string_t *expires = parse_expiration_input(exp_raw,
                                                     default_expiry_days);
    if (!expires) {
        n00b_eprintf("Unrecognized expiration value «#» — declined.",
                     exp_raw);
        return n00b_result_ok(int, 1);
    }

    /* Step 8: approve / decline prompt. */
    n00b_printf("Approve? [y/N]:");
    n00b_option_t(n00b_string_t *) aopt =
        n00b_naudit_input_read_line(input_source);
    if (!n00b_option_is_set(aopt)) {
        return n00b_result_ok(int, 1);
    }
    n00b_string_t *ans = n00b_option_get(aopt);
    bool           approve = false;
    /* Trim leading + trailing whitespace via a small inline pass. */
    {
        size_t a = 0;
        size_t b = ans->u8_bytes;
        while (a < b
               && (ans->data[a] == ' ' || ans->data[a] == '\t')) {
            a++;
        }
        while (b > a
               && (ans->data[b - 1] == ' ' || ans->data[b - 1] == '\t')) {
            b--;
        }
        size_t blen = b - a;
        if (blen == 1) {
            if (ans->data[a] == 'y' || ans->data[a] == 'Y') {
                approve = true;
            }
        }
        else if (blen == 3) {
            if ((ans->data[a] == 'y' || ans->data[a] == 'Y')
                && (ans->data[a + 1] == 'e' || ans->data[a + 1] == 'E')
                && (ans->data[a + 2] == 's' || ans->data[a + 2] == 'S')) {
                approve = true;
            }
        }
    }
    if (!approve) {
        n00b_printf("Declined: «#» left unchanged.", proposal_path);
        return n00b_result_ok(int, 1);
    }

    /* Step 9a: rewrite the record with developer input + sign. */
    ex->rationale  = new_rationale;
    ex->expires_at = expires;
    ex->signer_id  = signer_id;
    n00b_string_t *today_iso = n00b_audit_today_plus_days_iso(0);
    ex->approved_at = today_iso;

    const char *sid = section_id_from_path(proposal_path);
    n00b_string_t *body = serialize_exemption(ex, sid);
    if (!write_text_atomic(proposal_path, body)) {
        n00b_eprintf("Could not rewrite «#»", proposal_path);
        return n00b_result_err(int, N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }
    auto sr = n00b_audit_exemption_sign(proposal_path, key_path, signer_id);
    if (n00b_result_is_err(sr)) {
        return n00b_result_err(int, n00b_result_get_err(sr));
    }
    n00b_eprintf("Signed «#»", proposal_path);
    return n00b_result_ok(int, 0);
}

/* ================================================================ */
/* Initial-adoption bulk-sign                                        */
/* ================================================================ */

n00b_result_t(int)
n00b_audit_sign_initial_adoption_bulk(n00b_string_t *project_root,
                                       n00b_string_t *key_path,
                                       n00b_string_t *signer_id,
                                       int            expiry_days)
{
    if (!project_root || !key_path || !signer_id) {
        return n00b_result_err(int, N00B_AUDIT_ERR_ENGINE_BAD_ARGS);
    }
    project_root = n00b_path_canonical(project_root);

    auto dr = n00b_audit_discover_proposals(project_root);
    if (n00b_result_is_err(dr)) {
        return n00b_result_err(int, n00b_result_get_err(dr));
    }
    n00b_list_t(n00b_string_t *) *proposals = n00b_result_get(dr);
    int64_t n = n00b_list_len(*proposals);
    if (n == 0) {
        return n00b_result_ok(int, 0);
    }

    n00b_string_t *expires    = n00b_audit_today_plus_days_iso(expiry_days);
    n00b_string_t *approved   = n00b_audit_today_plus_days_iso(0);
    n00b_string_t *rationale  = n00b_cformat(
        "preexisting; scheduled for review by «#»", expires);
    int signed_count = 0;
    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *p = n00b_list_get(*proposals, i);
        if (!p) {
            continue;
        }
        auto lr = n00b_audit_load_exemptions(p);
        if (n00b_result_is_err(lr)) {
            return n00b_result_err(int, n00b_result_get_err(lr));
        }
        n00b_list_t(n00b_audit_exemption_t *) *recs = n00b_result_get(lr);
        if (!recs || n00b_list_len(*recs) < 1) {
            continue;
        }
        n00b_audit_exemption_t *ex = n00b_list_get(*recs, 0);
        ex->rationale   = rationale;
        ex->expires_at  = expires;
        ex->signer_id   = signer_id;
        ex->approved_at = approved;
        const char *sid = section_id_from_path(p);
        n00b_string_t *body = serialize_exemption(ex, sid);
        if (!write_text_atomic(p, body)) {
            n00b_eprintf("initial-adoption: could not rewrite «#»", p);
            return n00b_result_err(int,
                                   N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
        }
        auto sr = n00b_audit_exemption_sign(p, key_path, signer_id);
        if (n00b_result_is_err(sr)) {
            return n00b_result_err(int, n00b_result_get_err(sr));
        }
        n00b_printf("initial-adoption: signed «#»", p);
        signed_count++;
    }
    return n00b_result_ok(int, signed_count);
}
