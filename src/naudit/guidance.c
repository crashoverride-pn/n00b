/*
 * WP-005 — guidance-file loader (rule-file format v2).
 *
 * Replaces the WP-001 Phase 2 JSON-based loader. The v2 format is a
 * slay-format `.bnf` text file carrying `@directive` metadata; the
 * loader uses libn00b's `parsers/scanner.h` + `slay/n00b_parse.h`
 * pipeline with:
 *
 *   - the custom `"audit_rule_file"` tokenizer registered by
 *     `n00b_audit_module_init` (see src/audit/rule_file_tokenizer.c);
 *   - the embedded metagrammar string
 *     `N00B_AUDIT_RULE_FILE_METAGRAMMAR` from
 *     `audit_rule_file_grammar.h` (built at configure-time from
 *     `grammars/audit-rule-file.bnf` via `scripts/embed_metagrammar.py`);
 *   - `n00b_bnf_load` to compose the metagrammar object, then
 *     `n00b_grammar_parse` to parse the rule-file token stream;
 *   - a recursive descent over the resulting parse tree to populate
 *     `n00b_audit_guidance_t` + per-rule `n00b_audit_rule_t` structs.
 *
 * Per-rule embedded BNF productions are extracted as opaque
 * `BNF_LINE` text and concatenated into the rule's `bnf_fragment`
 * field — the engine's existing `n00b_bnf_load` call (in
 * src/audit/engine.c) then merges that text into the base grammar
 * unchanged.
 *
 * File I/O surface: same `core/file.h` MMAP substrate used by the
 * Phase 2 loader; precedent
 * `subprojects/n00b/src/chalk/file_io.c::n00b_chalk_read_file`.
 *
 * Allocation: structs are allocated via `n00b_alloc(T)`. No `malloc`.
 *
 * Per project DECISIONS.md D-005, this implementation's public
 * functions carry no `_kargs` block — n00b-audit's own surface does
 * not expose `.allocator` keyword arguments.
 */

#include "n00b.h"
#include "core/file.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "adt/result.h"
#include "adt/list.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "text/strings/string_ops.h"
#include "util/path.h"

#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/languages.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/trust_root.h"
#include "internal/naudit/_naudit_internal.h"

#include "audit_rule_file_grammar.h"

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

/*
 * Compare an n00b_string_t to a C-string literal. The audit-rule
 * file's directive names are short ASCII (e.g. "schema_version") so
 * byte-wise compare is correct.
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
 * Extract the n00b_string_t * value from a token leaf, or nullptr
 * if the leaf has no payload. The token's `value` is a
 * n00b_option_t(n00b_string_t *).
 */
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
 * Get the Nth child of `node`, descending through any
 * single-child non-terminal wrapper (slay's BNF loader wraps each
 * terminal in a `$term-...` synthetic NT when the terminal appears
 * inside a production's RHS — see the dumped tree shape).
 *
 * The wrapper has exactly one child: the token leaf. We return
 * the token-leaf's `n00b_token_info_t *` if the descent ends on a
 * token; otherwise nullptr.
 */
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
    /* Descend through $term-* wrappers (each carries exactly one
     * child, the token leaf or another wrapper). */
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

/* ---------------------------------------------------------------- */
/* Multi-line value assembly                                        */
/* ---------------------------------------------------------------- */

/*
 * Given a <meta_field> node, walk its <continuation> children and
 * append each continuation's text to the value. The result is a
 * single n00b_string_t that joins REST and all continuation lines
 * with "\n" separators (only when continuations are present).
 *
 * The <meta_field> tree shape is:
 *
 *   <meta_field>
 *     DIRECTIVE      (token leaf)
 *     REST           (token leaf)
 *     NEWLINE        (token leaf)
 *     <continuation>* (children, possibly under a $$group_N wrapper)
 *
 * `n00b_pt_collect_nt_deep` flattens through `$$group_N` synthetic
 * nodes so we get all continuation children directly.
 */
static n00b_string_t *
assemble_field_value(n00b_parse_tree_t *meta_field_node)
{
    n00b_token_info_t *rest_tok = nth_token_child(meta_field_node, 1);
    n00b_string_t     *rest     = token_text(rest_tok);
    if (!rest) {
        rest = n00b_string_empty();
    }

    /* Collect <continuation> children. */
    enum { MAX_CONT = 1024 };
    n00b_parse_tree_t *conts[MAX_CONT];
    int n_cont = n00b_pt_collect_nt_deep(meta_field_node, "continuation",
                                         conts, MAX_CONT);
    if (n_cont == 0) {
        return rest;
    }

    /*
     * Build the joined string: REST + ("\n" + INDENT_LINE) per
     * continuation. If REST is empty, drop the empty prefix and
     * start with the first continuation's text.
     */
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

/* ---------------------------------------------------------------- */
/* Directive table walking                                          */
/* ---------------------------------------------------------------- */

/*
 * For a node that contains <meta_field> children (either <file_meta>
 * or <rule_section>), walk its meta_field children and call
 * `handler` once per directive. `handler` receives the directive
 * name + the assembled value + an opaque carry pointer. If
 * `handler` returns false, `walk_meta_fields` returns immediately
 * with false (the caller's signal for "schema error").
 */
typedef bool (*meta_field_handler_t)(n00b_string_t *name,
                                     n00b_string_t *value,
                                     void          *carry);

static bool
walk_meta_fields(n00b_parse_tree_t   *parent,
                 meta_field_handler_t handler,
                 void                *carry)
{
    enum { MAX_FIELDS = 4096 };
    n00b_parse_tree_t *fields[MAX_FIELDS];
    int n = n00b_pt_collect_nt_deep(parent, "meta_field",
                                    fields, MAX_FIELDS);
    for (int i = 0; i < n; i++) {
        n00b_token_info_t *name_tok = nth_token_child(fields[i], 0);
        n00b_string_t     *name     = token_text(name_tok);
        if (!name) {
            name = n00b_string_empty();
        }
        n00b_string_t *value = assemble_field_value(fields[i]);
        if (!handler(name, value, carry)) {
            return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------- */
/* File-level handler context + helpers                             */
/* ---------------------------------------------------------------- */

typedef struct {
    n00b_audit_guidance_t *g;
    int                    err_code;
    bool                   saw_schema_version;
} file_field_ctx_t;

/* ---------------------------------------------------------------- */
/* @filter_def parsing (WP-009 Phase 4)                             */
/* ---------------------------------------------------------------- */

/*
 * Lazily allocate `g->filters` as a name->filter dict on first use.
 * The field stays nullptr when the rule file declares no
 * `@filter_def` blocks.
 */
static void
ensure_filters(n00b_audit_guidance_t *g)
{
    if (g->filters) {
        return;
    }
    // Runtime-only guidance state: keep the dict object and backing arrays
    // scanned so static-grammar materialization GC cannot stale its values.
    g->filters = n00b_alloc_with_opts(
        n00b_dict_t(n00b_string_t *, n00b_audit_filter_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    n00b_dict_init(g->filters,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .scan_kind     = N00B_GC_SCAN_KIND_ALL);
}

/*
 * Parse one `key: value` line out of the body of an `@filter_def`
 * value. Returns true on a recognized key, false otherwise. The
 * filter struct's `expr` / `description` fields are populated
 * directly. Whitespace around the colon separator is stripped.
 *
 * Unknown keys are tolerated silently (forward-compat with future
 * `references:` / `severity:` etc.).
 */
static bool
parse_filter_def_line(n00b_string_t       *line,
                      n00b_audit_filter_t *filter)
{
    if (!line || line->u8_bytes == 0 || !filter) {
        return false;
    }
    const char *buf = line->data;
    size_t      n   = line->u8_bytes;

    size_t i = 0;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    if (i == n) {
        return false;
    }
    size_t key_start = i;
    while (i < n && buf[i] != ':') {
        i++;
    }
    if (i == n) {
        return false;
    }
    size_t key_end = i;
    while (key_end > key_start
           && (buf[key_end - 1] == ' ' || buf[key_end - 1] == '\t')) {
        key_end--;
    }

    i++; /* past ':' */
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    n00b_string_t *value = n00b_string_from_raw(buf + i,
                                                 (int64_t)(n - i));

    size_t klen = key_end - key_start;
    if (klen == 4 && buf[key_start + 0] == 'e'
        && buf[key_start + 1] == 'x'
        && buf[key_start + 2] == 'p'
        && buf[key_start + 3] == 'r') {
        filter->expr = value;
        return true;
    }
    if (klen == 11 && buf[key_start + 0] == 'd'
        && buf[key_start + 1] == 'e'
        && buf[key_start + 2] == 's'
        && buf[key_start + 3] == 'c'
        && buf[key_start + 4] == 'r'
        && buf[key_start + 5] == 'i'
        && buf[key_start + 6] == 'p'
        && buf[key_start + 7] == 't'
        && buf[key_start + 8] == 'i'
        && buf[key_start + 9] == 'o'
        && buf[key_start + 10] == 'n') {
        filter->description = value;
        return true;
    }
    /* Unknown key tolerated. */
    return true;
}

/*
 * Parse the body of a `@filter_def <name>` directive. The REST text
 * carries the filter name; continuation lines carry `key: value`
 * pairs. The body is `value`'s text WITHOUT the name (the loader
 * strips the name out of REST and stashes it as `filter->name`).
 *
 * Returns false on syntactic errors (no name, no `expr:` key in the
 * body). Caller turns this into N00B_AUDIT_ERR_GUIDANCE_SCHEMA.
 *
 * The full value string layout is:
 *
 *     <name>\n<line1>\n<line2>\n...
 *
 * where each continuation line is the trimmed body of the
 * indented `<line>` from the rule file. The loader's
 * `assemble_field_value` joins REST + each continuation with `\n`
 * before this parser sees it.
 */
static bool
parse_filter_def_value(n00b_string_t         *value,
                       n00b_audit_guidance_t *g)
{
    if (!value || value->u8_bytes == 0) {
        return false;
    }

    /* Split off the first line (REST = the filter name). */
    const char *buf = value->data;
    size_t      n   = value->u8_bytes;
    size_t      i   = 0;
    while (i < n && buf[i] != '\n') {
        i++;
    }
    size_t name_end = i;
    while (name_end > 0
           && (buf[name_end - 1] == ' ' || buf[name_end - 1] == '\t')) {
        name_end--;
    }
    if (name_end == 0) {
        return false;
    }
    n00b_string_t *name = n00b_string_from_raw(buf, (int64_t)name_end);

    // All fields are pointers; make the scan policy explicit so large
    // static-grammar materialization GCs cannot stale the filter payload.
    n00b_audit_filter_t *filter = n00b_alloc_with_opts(
        n00b_audit_filter_t,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    filter->name        = name;
    filter->expr        = n00b_string_empty();
    filter->description = n00b_string_empty();

    /* Walk remaining lines. */
    size_t line = (i < n) ? i + 1 : i;
    while (line < n) {
        size_t end = line;
        while (end < n && buf[end] != '\n') {
            end++;
        }
        n00b_string_t *one = n00b_string_from_raw(buf + line,
                                                   (int64_t)(end - line));
        (void)parse_filter_def_line(one, filter);
        line = (end < n) ? end + 1 : end;
    }

    if (filter->expr->u8_bytes == 0) {
        return false;
    }

    ensure_filters(g);
    n00b_dict_put(g->filters, filter->name, filter);
    return true;
}

/*
 * Parse one `@captures $name:<NT>` directive value, append the
 * decl to the rule. The value is a single line "$name:<nt>" (with
 * the leading `@captures` directive name already stripped by the
 * tokenizer's split_directive_line helper). Returns false on
 * malformed input.
 */
static bool
parse_captures_value(n00b_string_t     *value,
                     n00b_audit_rule_t *rule)
{
    if (!value || value->u8_bytes == 0 || !rule) {
        return false;
    }
    const char *buf = value->data;
    size_t      n   = value->u8_bytes;

    size_t i = 0;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    if (i >= n || buf[i] != '$') {
        return false;
    }
    i++; /* past '$' */
    size_t name_start = i;
    while (i < n && buf[i] != ':') {
        i++;
    }
    if (i >= n) {
        return false;
    }
    size_t name_end = i;
    while (name_end > name_start
           && (buf[name_end - 1] == ' ' || buf[name_end - 1] == '\t')) {
        name_end--;
    }
    if (name_end == name_start) {
        return false;
    }
    i++; /* past ':' */
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    /*
     * The NT name may be wrapped in `<...>` brackets per the
     * audit-rule-file convention; strip them if present so the
     * stored NT name is the bare identifier.
     */
    size_t nt_start = i;
    size_t nt_end   = n;
    while (nt_end > nt_start
           && (buf[nt_end - 1] == ' ' || buf[nt_end - 1] == '\t')) {
        nt_end--;
    }
    if (nt_end > nt_start && buf[nt_start] == '<'
        && buf[nt_end - 1] == '>') {
        nt_start++;
        nt_end--;
    }
    if (nt_end <= nt_start) {
        return false;
    }

    // Runtime guidance payloads are pointer-bearing and long-lived across
    // static-grammar materialization GCs; scan them conservatively.
    n00b_audit_capture_decl_t *decl = n00b_alloc_with_opts(
        n00b_audit_capture_decl_t,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    decl->name = n00b_string_from_raw(buf + name_start,
                                       (int64_t)(name_end - name_start));
    decl->nt   = n00b_string_from_raw(buf + nt_start,
                                       (int64_t)(nt_end - nt_start));

    if (!rule->captures) {
        rule->captures = n00b_alloc_with_opts(
            n00b_list_t(n00b_audit_capture_decl_t *),
            &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
        *rule->captures = n00b_list_new(
            n00b_audit_capture_decl_t *,
            .scan_kind = N00B_GC_SCAN_KIND_ALL);
    }
    n00b_list_push(*rule->captures, decl);
    return true;
}

/*
 * Parse a decimal integer string into int64_t. Returns true on
 * success, false on empty input or non-digit characters.
 */
static bool
parse_int64(n00b_string_t *s, int64_t *out)
{
    if (!s || s->u8_bytes == 0) {
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

/* ---------------------------------------------------------------- */
/* @extensions parsing (WP-009 Phase 1)                             */
/* ---------------------------------------------------------------- */

/*
 * Lazily allocate `g->extension_overrides` as a string->string
 * locked dict on first use. Per WP-009 Phase 1 spec, the field
 * stays nullptr when the rule file declares no `@extensions`
 * directive — so allocation is deferred to the first
 * extension-override write.
 */
static void
ensure_extension_overrides(n00b_audit_guidance_t *g)
{
    if (g->extension_overrides) {
        return;
    }
    g->extension_overrides = n00b_alloc_with_opts(
        n00b_dict_t(n00b_string_t *, n00b_string_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    n00b_dict_init(g->extension_overrides,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .scan_kind     = N00B_GC_SCAN_KIND_ALL);
}

/*
 * Parse one line of `@extensions` body. Expected shape:
 *
 *     <lang-name>: <ext1>, <ext2>, ...
 *
 * Where `<lang-name>` is a registered language and each `<extN>`
 * carries the leading `.`. Returns false on syntactic errors (the
 * caller turns this into `N00B_AUDIT_ERR_GUIDANCE_SCHEMA`).
 *
 * Whitespace around the `:` and `,` separators is stripped. Blank
 * lines (after trim) are tolerated as a no-op.
 */
static bool
parse_extensions_line(n00b_string_t         *line,
                      n00b_audit_guidance_t *g)
{
    if (!line || line->u8_bytes == 0) {
        return true;
    }
    const char *buf = line->data;
    size_t      n   = line->u8_bytes;

    /* Skip leading whitespace. */
    size_t i = 0;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }
    if (i == n) {
        return true;
    }

    /* Read the language name up to ':'. */
    size_t name_start = i;
    while (i < n && buf[i] != ':') {
        i++;
    }
    if (i == n) {
        /* No colon — malformed. */
        return false;
    }
    size_t name_end = i;
    /* Trim trailing whitespace from the name. */
    while (name_end > name_start
           && (buf[name_end - 1] == ' ' || buf[name_end - 1] == '\t')) {
        name_end--;
    }
    if (name_end == name_start) {
        return false;
    }
    n00b_string_t *lang = n00b_string_from_raw(buf + name_start,
                                                (int64_t)(name_end
                                                          - name_start));

    /* Skip the colon and any whitespace after it. */
    i++; /* past the ':' */
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
        i++;
    }

    /* Parse comma-separated extensions. */
    bool saw_any = false;
    while (i < n) {
        size_t ext_start = i;
        while (i < n && buf[i] != ',') {
            i++;
        }
        size_t ext_end = i;
        while (ext_end > ext_start
               && (buf[ext_end - 1] == ' '
                   || buf[ext_end - 1] == '\t')) {
            ext_end--;
        }
        if (ext_end > ext_start) {
            n00b_string_t *ext =
                n00b_string_from_raw(buf + ext_start,
                                      (int64_t)(ext_end - ext_start));
            ensure_extension_overrides(g);
            n00b_dict_put(g->extension_overrides, ext, lang);
            saw_any = true;
        }
        if (i < n && buf[i] == ',') {
            i++;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
                i++;
            }
        }
    }
    return saw_any;
}

/*
 * Parse the full `@extensions` directive value. The value text is
 * already assembled (REST + each continuation line joined by
 * `\n`); split it on `\n` and apply `parse_extensions_line` per
 * line. Returns false on malformed body.
 */
static bool
parse_extensions_value(n00b_string_t         *value,
                       n00b_audit_guidance_t *g)
{
    if (!value || value->u8_bytes == 0) {
        return true;
    }
    const char *buf  = value->data;
    size_t      n    = value->u8_bytes;
    size_t      line = 0;
    while (line < n) {
        size_t end = line;
        while (end < n && buf[end] != '\n') {
            end++;
        }
        n00b_string_t *one = n00b_string_from_raw(buf + line,
                                                   (int64_t)(end - line));
        if (!parse_extensions_line(one, g)) {
            return false;
        }
        line = (end < n) ? end + 1 : end;
    }
    return true;
}

/* ---------------------------------------------------------------- */
/* File-level field handler                                         */
/* ---------------------------------------------------------------- */

static bool
file_field_handler(n00b_string_t *name, n00b_string_t *value, void *carry)
{
    file_field_ctx_t      *ctx = (file_field_ctx_t *)carry;
    n00b_audit_guidance_t *g   = ctx->g;

    if (str_eq_cstr(name, "schema_version")) {
        int64_t v = 0;
        if (!parse_int64(value, &v)) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
        g->schema_version       = v;
        ctx->saw_schema_version = true;
        if (v != 1) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA_VERSION;
            return false;
        }
        return true;
    }
    if (str_eq_cstr(name, "project")) {
        g->project = value;
        return true;
    }
    if (str_eq_cstr(name, "description")) {
        g->description = value;
        return true;
    }
    if (str_eq_cstr(name, "source_doc")) {
        g->source_doc = value;
        return true;
    }
    if (str_eq_cstr(name, "expected_roster_sha256")) {
        /*
         * WP-015 (DF-CA): top-level trust-root fingerprint
         * binding directive. The value is a 64-character
         * lowercase-hex SHA-256 of the trust roster the project
         * expects to be in use. The engine compares this against
         * the on-disk SYSTEM-slot roster's hash at audit time
         * (`engine.c::apply_signature_gate`'s WP-015 extension);
         * mismatch refuses the audit with a clear error.
         *
         * Schema validation: 64 hex characters (case-insensitive
         * on read; the directive parser accepts uppercase). The
         * directive is OPTIONAL — when absent,
         * `expected_roster_sha256` stays nullptr and the engine
         * skips the binding check (the operator chose not to bind
         * the repo to a specific trust root).
         */
        if (!value || value->u8_bytes != 64) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
        for (size_t i = 0; i < 64; i++) {
            char c = value->data[i];
            bool is_digit = (c >= '0' && c <= '9');
            bool is_lower = (c >= 'a' && c <= 'f');
            bool is_upper = (c >= 'A' && c <= 'F');
            if (!is_digit && !is_lower && !is_upper) {
                ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
                return false;
            }
        }
        g->expected_roster_sha256 = value;
        return true;
    }
    if (str_eq_cstr(name, "blame_similarity")) {
        /*
         * WP-013: top-level integer override for libgit2's blame
         * similarity threshold (white paper §§ 4.6 / 13.1).
         * Default (50) is set above at allocation time; this
         * directive overrides. Out-of-range values produce
         * `N00B_AUDIT_ERR_GUIDANCE_SCHEMA` (libgit2's field is a
         * `uint16_t`; reject anything that wouldn't fit).
         */
        int64_t v = 0;
        if (!parse_int64(value, &v) || v < 0 || v > UINT16_MAX) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
        g->blame_similarity_threshold = (int)v;
        return true;
    }
    if (str_eq_cstr(name, "filter_def")) {
        /*
         * WP-009 Phase 4: top-level filter definition. The
         * directive form `@filter_def <name>` opens the block,
         * indented `expr:` / `description:` lines follow. The
         * existing `<meta_field>` machinery delivers the joined
         * body (REST + continuations) to this handler; the
         * loader splits the first line (the name) and parses
         * remaining lines as `key: value` pairs.
         *
         * Per WP-009 Phase 4 design rationale (auditor-flagged):
         * this matches the `@extensions` precedent (D-019) by
         * staying inside the existing DIRECTIVE/REST/INDENT_LINE
         * tokens — no metagrammar or tokenizer change needed.
         * The user-visible block syntax `filter NAME { ... }`
         * from the WP-009 spec is conceptually equivalent; the
         * directive form ships with zero infrastructure churn.
         */
        if (!parse_filter_def_value(value, g)) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
        return true;
    }
    if (str_eq_cstr(name, "extensions")) {
        /*
         * WP-009 Phase 1: project-level file-extension overrides
         * for the built-in language registry. The value is a
         * multi-line body — one line per language — assembled by
         * the metagrammar walker via the standard
         * REST + continuation mechanism. The parser populates
         * `g->extension_overrides`; validation of language names
         * against the built-in registry happens after the full
         * walk completes (so the canonical "language unknown"
         * diagnostic is emitted once with full context).
         */
        if (!parse_extensions_value(value, g)) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
        return true;
    }
    if (str_eq_cstr(name, "dependencies")) {
        /*
         * Dependencies value is a whitespace-separated list of
         * paths. Empty value → no dependencies.
         */
        if (!value || value->u8_bytes == 0) {
            return true;
        }
        const char *buf = value->data;
        size_t      n   = value->u8_bytes;
        size_t      i   = 0;
        while (i < n) {
            while (i < n && (buf[i] == ' ' || buf[i] == '\t'
                             || buf[i] == '\n')) {
                i++;
            }
            size_t start = i;
            while (i < n && !(buf[i] == ' ' || buf[i] == '\t'
                              || buf[i] == '\n')) {
                i++;
            }
            if (i > start) {
                n00b_list_push(*g->dependencies,
                               n00b_string_from_raw(buf + start,
                                                    (int64_t)(i - start)));
            }
        }
        return true;
    }
    /* Unknown directive: tolerated silently (forward-compat). */
    return true;
}

/* ---------------------------------------------------------------- */
/* Per-rule field handler                                           */
/* ---------------------------------------------------------------- */

typedef struct {
    n00b_audit_rule_t *rule;
    int                err_code;
} rule_field_ctx_t;

static bool
rule_field_handler(n00b_string_t *name, n00b_string_t *value, void *carry)
{
    rule_field_ctx_t  *ctx = (rule_field_ctx_t *)carry;
    n00b_audit_rule_t *r   = ctx->rule;

    if (str_eq_cstr(name, "title")) {
        r->title = value;
        return true;
    }
    if (str_eq_cstr(name, "section")) {
        r->section = value;
        return true;
    }
    if (str_eq_cstr(name, "violation_nt")) {
        r->violation_nt = value;
        return true;
    }
    if (str_eq_cstr(name, "rationale")) {
        r->rationale = value;
        return true;
    }
    if (str_eq_cstr(name, "bad")) {
        r->bad_example = value;
        return true;
    }
    if (str_eq_cstr(name, "good")) {
        r->good_example = value;
        return true;
    }
    if (str_eq_cstr(name, "guidance")) {
        r->guidance = value;
        return true;
    }
    if (str_eq_cstr(name, "language")) {
        /*
         * WP-009 Phase 1: per-rule language scoping. Multiple
         * `@language <name>` annotations may appear on a single
         * rule (the rule then applies to all listed languages);
         * each new annotation appends to the per-rule list. Empty
         * list (no `@language` present) means "apply to every
         * language whose grammar defines the rule's violation_nt"
         * — semantically the engine's responsibility, not the
         * loader's.
         *
         * Validation of language names against the built-in
         * registry happens after the full walk completes (so the
         * canonical "language unknown" diagnostic carries the
         * rule id).
         */
        if (!r->language) {
            r->language = n00b_alloc(n00b_list_t(n00b_string_t *));
            *r->language = n00b_list_new(n00b_string_t *);
        }
        if (value && value->u8_bytes > 0) {
            n00b_list_push(*r->language, value);
        }
        return true;
    }
    if (str_eq_cstr(name, "filter")) {
        /*
         * WP-009 Phase 4: per-rule filter reference. Stored
         * verbatim; resolved against `guidance->filters` at the
         * end of the load walk (parallel with the `@language`
         * validation pass).
         */
        r->filter_name = value;
        return true;
    }
    if (str_eq_cstr(name, "captures")) {
        /*
         * WP-009 Phase 4: per-rule capture declaration in the
         * DF-T-resolved form `@captures $name:<NT>`. One
         * declaration per `@captures` line; multiple lines on
         * a rule append to the captures list. The engine binds
         * each declaration to a descendant of the matched node
         * in document order at violation emission time (DF-U).
         */
        if (!parse_captures_value(value, r)) {
            ctx->err_code = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
        return true;
    }
    if (str_eq_cstr(name, "applies_to.include")) {
        if (!r->applies_to_include) {
            r->applies_to_include = n00b_alloc(
                n00b_list_t(n00b_string_t *));
            *r->applies_to_include = n00b_list_new(n00b_string_t *);
        }
        n00b_list_push(*r->applies_to_include, value);
        return true;
    }
    if (str_eq_cstr(name, "applies_to.exclude")) {
        if (!r->applies_to_exclude) {
            r->applies_to_exclude = n00b_alloc(
                n00b_list_t(n00b_string_t *));
            *r->applies_to_exclude = n00b_list_new(n00b_string_t *);
        }
        n00b_list_push(*r->applies_to_exclude, value);
        return true;
    }
    /* Unknown directive: tolerated silently. */
    return true;
}

/* ---------------------------------------------------------------- */
/* BNF body extraction                                              */
/* ---------------------------------------------------------------- */

/*
 * Walk a <rule_section> node's <bnf_body> child, concatenating each
 * <bnf_line>'s BNF_LINE text into a single string separated by "\n"
 * with a trailing newline. The resulting string is suitable for
 * direct concatenation into the engine's combined-grammar text in
 * `src/audit/engine.c`.
 */
static n00b_string_t *
assemble_bnf_body(n00b_parse_tree_t *rule_section)
{
    enum { MAX_BNF_LINES = 65536 };
    n00b_parse_tree_t *lines[MAX_BNF_LINES];
    /*
     * <bnf_body> is a regular NT (not a `$$group_N` synthetic) so
     * `n00b_pt_collect_nt_deep` won't recurse into it from
     * `rule_section`. Find it explicitly first.
     */
    n00b_parse_tree_t *body = n00b_pt_find_child_by_nt(rule_section,
                                                      "bnf_body");
    int n = 0;
    if (body) {
        n = n00b_pt_collect_nt_deep(body, "bnf_line",
                                    lines, MAX_BNF_LINES);
    }
    if (n == 0) {
        return n00b_string_empty();
    }
    n00b_buffer_t *acc = n00b_buffer_empty();
    n00b_buffer_t *nl  = n00b_buffer_from_bytes((char *)"\n", 1);
    for (int i = 0; i < n; i++) {
        n00b_token_info_t *tok = nth_token_child(lines[i], 0);
        n00b_string_t     *t   = token_text(tok);
        if (!t) {
            t = n00b_string_empty();
        }
        n00b_buffer_t *lb = n00b_buffer_from_bytes(t->data,
                                                   (int64_t)t->u8_bytes);
        n00b_buffer_concat(acc, lb);
        n00b_buffer_concat(acc, nl);
    }
    return n00b_string_from_raw(acc->data, (int64_t)acc->byte_len);
}

/* ---------------------------------------------------------------- */
/* Metagrammar grammar (built once per load)                        */
/* ---------------------------------------------------------------- */

/*
 * Build the metagrammar grammar by loading the embedded
 * N00B_AUDIT_RULE_FILE_METAGRAMMAR text via `n00b_bnf_load`.
 * Returns nullptr on failure (the metagrammar is build-time-baked,
 * so this should be infallible at runtime; a failure here indicates
 * a regression in either the metagrammar text or the slay BNF
 * loader's behavior).
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

/* ---------------------------------------------------------------- */
/* Public entry                                                     */
/* ---------------------------------------------------------------- */

n00b_result_t(n00b_audit_guidance_t *)
n00b_audit_load_guidance(n00b_string_t *path)
{
    if (!path) {
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }

    /* Canonicalize the input path: expand env-vars / `~`, root to
     * cwd if relative. Diagnostics and downstream file operations
     * then see a single absolute form regardless of caller cwd. */
    path = n00b_path_canonical(path);

    /* Step 1: open the file (MMAP substrate, one-shot read). */
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }
    n00b_buffer_t *src_buf = n00b_result_get(br);

    /*
     * Step 2: build the metagrammar grammar from the embedded
     * `audit-rule-file.bnf` text.
     */
    n00b_grammar_t *meta_g = build_metagrammar();
    if (!meta_g) {
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_PARSE);
    }

    /*
     * Step 3: set up the audit-rule-file tokenizer + token stream.
     * The scanner needs a private state struct (line classifier
     * state); we allocate it here and pass via .state. The .reset_cb
     * lets the scanner reinitialize the state on reset.
     */
    void *st = _n00b_audit_rule_file_scanner_state_new();
    n00b_scanner_t *sc = n00b_scanner_new(
        src_buf, _n00b_audit_rule_file_scan_cb(), meta_g,
        .state    = st,
        .reset_cb = _n00b_audit_rule_file_reset_cb());
    n00b_token_stream_t *ts = n00b_token_stream_new(sc);

    /* Step 4: parse. */
    n00b_parse_result_t *pr = n00b_grammar_parse(meta_g, ts);
    if (!n00b_parse_result_ok(pr)) {
        n00b_parse_result_free(pr);
        n00b_grammar_free(meta_g);
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_PARSE);
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    /*
     * Step 5: allocate the guidance struct. n00b allocation zero-fills
     * the struct; we initialize the list fields explicitly to
     * non-null empty lists so the schema's contract holds (every
     * list field is always-non-null on success).
     */
    // Mixed scalar/pointer runtime state; conservative scanning avoids stale
    // guidance edges when static grammar unmarshalling triggers GC.
    n00b_audit_guidance_t *g = n00b_alloc_with_opts(
        n00b_audit_guidance_t,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    g->dependencies = n00b_alloc_with_opts(
        n00b_list_t(n00b_string_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    *g->dependencies = n00b_list_new(n00b_string_t *,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    g->rules = n00b_alloc_with_opts(
        n00b_list_t(n00b_audit_rule_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    *g->rules = n00b_list_new(n00b_audit_rule_t *,
                              .scan_kind = N00B_GC_SCAN_KIND_ALL);
    g->project     = n00b_string_empty();
    g->description = n00b_string_empty();
    g->source_doc  = n00b_string_empty();
    g->exemptions              = nullptr;
    g->baseline                = nullptr;
    g->allowed_signers_path    = nullptr;
    g->allowed_signers_source  = N00B_AUDIT_ROSTER_SOURCE_NONE;
    g->expected_roster_sha256  = nullptr;
    /*
     * WP-013: white paper § 13.1 — blame similarity threshold,
     * documented default 50. The `@blame_similarity` top-level
     * directive overrides this.
     */
    g->blame_similarity_threshold = 50;
    /*
     * WP-011: stash the directory of the loaded guidance file so the
     * loader can discover `audit/exemptions/(*).bnf` and
     * `audit/baseline/baseline.bnf` relative to it. `path` is
     * already canonicalized to an absolute form above; slice off the
     * trailing file component (everything after the last `/`).
     * `n00b_path_parts` is the wrong primitive here — it splits the
     * filename into name + extension, producing a 3-element list
     * incompatible with the parent_dir reduction shape used by the
     * discovery walk.
     */
    {
        size_t end = path->u8_bytes;
        while (end > 0 && path->data[end - 1] != '/') {
            end--;
        }
        /* Trim the trailing slash unless we're at the filesystem root. */
        size_t trim = end;
        if (trim > 1) {
            trim--;
        }
        if (trim == 0) {
            g->project_root = r"/";
        }
        else {
            g->project_root = n00b_string_from_raw(path->data,
                                                    (int64_t)trim);
        }
    }

    /*
     * Step 6: walk file-level <file_meta> directives. The tree
     * shape is:
     *   <file>
     *     <file_meta>
     *       <meta_field>*
     *     <rule_section>*
     */
    n00b_parse_tree_t *file_meta = n00b_pt_find_child_by_nt(tree,
                                                            "file_meta");
    file_field_ctx_t fctx = {.g = g, .err_code = 0, .saw_schema_version = false};
    if (file_meta) {
        if (!walk_meta_fields(file_meta, file_field_handler, &fctx)) {
            int code = fctx.err_code ? fctx.err_code
                                     : N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            n00b_parse_result_free(pr);
            n00b_grammar_free(meta_g);
            return n00b_result_err(n00b_audit_guidance_t *, code);
        }
    }
    if (!fctx.saw_schema_version) {
        n00b_parse_result_free(pr);
        n00b_grammar_free(meta_g);
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
    }

    /* Step 7: walk per-rule <rule_section> children. */
    enum { MAX_RULES = 4096 };
    n00b_parse_tree_t *sections[MAX_RULES];
    int n_sections = n00b_pt_collect_nt_deep(tree, "rule_section",
                                             sections, MAX_RULES);
    for (int i = 0; i < n_sections; i++) {
        n00b_parse_tree_t *sec = sections[i];

        /*
         * <rule_section>'s first child is <rule_marker>, whose first
         * token leaf is the RULE_MARKER carrying the rule id text.
         */
        n00b_parse_tree_t *marker = n00b_pt_find_child_by_nt(sec,
                                                             "rule_marker");
        n00b_token_info_t *id_tok = nth_token_child(marker, 0);
        n00b_string_t     *id     = token_text(id_tok);
        if (!id || id->u8_bytes == 0) {
            n00b_parse_result_free(pr);
            n00b_grammar_free(meta_g);
            return n00b_result_err(n00b_audit_guidance_t *,
                                   N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
        }

        n00b_audit_rule_t *rule = n00b_alloc_with_opts(
            n00b_audit_rule_t,
            &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
        rule->id                = id;
        rule->title             = n00b_string_empty();
        rule->section           = n00b_string_empty();
        rule->bnf_fragment      = n00b_string_empty();
        rule->violation_nt      = n00b_string_empty();
        rule->rationale         = n00b_string_empty();
        rule->bad_example       = n00b_string_empty();
        rule->good_example      = n00b_string_empty();
        rule->guidance          = n00b_string_empty();
        rule->applies_to_include = nullptr;
        rule->applies_to_exclude = nullptr;
        rule->language           = nullptr;
        rule->filter_name        = nullptr;
        rule->captures           = nullptr;
        rule->content_hash       = nullptr;

        rule_field_ctx_t rctx = {.rule = rule, .err_code = 0};
        if (!walk_meta_fields(sec, rule_field_handler, &rctx)) {
            int code = rctx.err_code ? rctx.err_code
                                     : N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            n00b_parse_result_free(pr);
            n00b_grammar_free(meta_g);
            return n00b_result_err(n00b_audit_guidance_t *, code);
        }

        /*
         * Assemble the rule's BNF body.
         *
         * WP-009 Phase 2: `bnf_fragment` is OPTIONAL. A rule with
         * zero BNF lines is a query-mode rule — the engine queries
         * the base-language grammar directly for the named
         * `violation_nt`. Normalise an empty assembled body to
         * `nullptr` so the engine's fragment-merge loop in
         * `engine.c::get_or_load_grammar` (which skips on
         * `!rule->bnf_fragment`) does the right thing without
         * carrying around a zero-length sentinel string.
         */
        rule->bnf_fragment = assemble_bnf_body(sec);
        if (rule->bnf_fragment && rule->bnf_fragment->u8_bytes == 0) {
            rule->bnf_fragment = nullptr;
        }

        /*
         * WP-011 (D-X3): compute the rule's content hash from its
         * canonical BNF text. Hex-encoded XXH3-128. Query-mode
         * rules (nullptr bnf_fragment) still get a stable hash —
         * `n00b_audit_compute_rule_content_hash` handles the empty
         * input case deterministically.
         */
        rule->content_hash = n00b_audit_compute_rule_content_hash(
            rule->bnf_fragment);

        /*
         * Schema check: required fields must be non-empty.
         *
         * `bnf_fragment` is intentionally absent from this check
         * (WP-009 Phase 2): a query-mode rule legitimately has no
         * fragment and must load cleanly. `violation_nt` remains
         * required — query-mode rules still need an NT to match
         * against the base grammar's tree.
         */
        if (rule->title->u8_bytes == 0
            || rule->section->u8_bytes == 0
            || rule->violation_nt->u8_bytes == 0
            || rule->rationale->u8_bytes == 0
            || rule->bad_example->u8_bytes == 0
            || rule->good_example->u8_bytes == 0
            || rule->guidance->u8_bytes == 0) {
            n00b_parse_result_free(pr);
            n00b_grammar_free(meta_g);
            return n00b_result_err(n00b_audit_guidance_t *,
                                   N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
        }

        n00b_list_push(*g->rules, rule);
    }

    /*
     * Step 7.5 (WP-009 Phase 1): validate language references
     * against the built-in language registry. Two sources:
     *
     *   (a) per-rule `@language <name>` annotations on each
     *       loaded rule.
     *   (b) every value in the file-level `@extensions` block's
     *       extension → language-name map.
     *
     * Either source naming an unknown language is a schema
     * error — return N00B_AUDIT_ERR_GUIDANCE_SCHEMA. This is the
     * DF-W resolution per the WP-009 Phase 1 spec: validate at
     * guidance-load time so dangling-language references fail
     * fast with the same precedent shape as the D-017
     * dangling-violation_nt validation in `engine.c`.
     */
    {
        int64_t nrules = n00b_list_len(*g->rules);
        for (int64_t i = 0; i < nrules; i++) {
            n00b_audit_rule_t *rule = n00b_list_get(*g->rules, i);
            if (!rule || !rule->language) {
                continue;
            }
            int64_t nlangs = n00b_list_len(*rule->language);
            for (int64_t j = 0; j < nlangs; j++) {
                n00b_string_t *lname = n00b_list_get(*rule->language, j);
                if (!lname
                    || !n00b_naudit_lookup_language_by_name(lname)) {
                    n00b_parse_result_free(pr);
                    n00b_grammar_free(meta_g);
                    return n00b_result_err(n00b_audit_guidance_t *,
                                           N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
                }
            }
        }
        if (g->extension_overrides) {
            bool ext_ok = true;
            n00b_dict_foreach(g->extension_overrides, _ext_key, _lang_val, {
                (void)_ext_key;
                if (!_lang_val
                    || !n00b_naudit_lookup_language_by_name(_lang_val)) {
                    ext_ok = false;
                }
            });
            if (!ext_ok) {
                n00b_parse_result_free(pr);
                n00b_grammar_free(meta_g);
                return n00b_result_err(n00b_audit_guidance_t *,
                                       N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
            }
        }
    }

    /*
     * Step 7.6 (WP-009 Phase 4): validate every per-rule
     * `@filter <name>` resolves to a defined `@filter_def <name>`
     * block. Dangling names are GUIDANCE_SCHEMA errors per the
     * D-017 dangling-violation_nt precedent. No-filter rules
     * (filter_name == nullptr) skip this check naturally.
     */
    {
        int64_t nrules = n00b_list_len(*g->rules);
        for (int64_t i = 0; i < nrules; i++) {
            n00b_audit_rule_t *rule = n00b_list_get(*g->rules, i);
            if (!rule || !rule->filter_name
                || rule->filter_name->u8_bytes == 0) {
                continue;
            }
            if (!g->filters
                || !n00b_dict_contains(g->filters, rule->filter_name)) {
                n00b_parse_result_free(pr);
                n00b_grammar_free(meta_g);
                return n00b_result_err(n00b_audit_guidance_t *,
                                       N00B_AUDIT_ERR_GUIDANCE_SCHEMA);
            }
        }
    }

    /*
     * Step 8: dependency walk. WP-001 supports only the empty-list
     * path. Non-empty lists return DEPS_UNIMPLEMENTED (DF-B).
     */
    if (n00b_list_len(*g->dependencies) > 0) {
        n00b_parse_result_free(pr);
        n00b_grammar_free(meta_g);
        return n00b_result_err(n00b_audit_guidance_t *,
                               N00B_AUDIT_ERR_GUIDANCE_DEPS_UNIMPLEMENTED);
    }

    /*
     * Step 9 (WP-011 + WP-012): discover and load exemption +
     * baseline files rooted at the guidance file's directory. Both
     * are silently-empty when the corresponding directory / file is
     * absent — only a malformed file surfaces an error.
     *
     * WP-012 adds roster discovery: if
     * `<project_root>/audit/allowed_signers` exists, record its
     * path on the guidance struct so the engine's signature gate
     * can use it. When absent the field stays nullptr; the engine
     * then applies the documented "warn + accept-all under
     * --allow-unsigned, else refuse-all" policy.
     */
    /*
     * WP-015: replace the WP-012 repo-only roster discovery with
     * the 3-slot trust-root chain (ENV > SYSTEM > REPO; first
     * existing path wins). See `naudit/trust_root.h` for the
     * full design rationale + DF-CA / DF-CB / DF-CC resolutions.
     */
    {
        /*
         * Single chain walk: cache BOTH the path and the source
         * discriminator so the engine doesn't re-walk the chain
         * later (a second walk could see different env-var state
         * and disagree with the path we stored here — see W1 in
         * the WP-015 code audit).
         */
        n00b_audit_roster_resolution_t rr =
            n00b_audit_resolve_roster(g->project_root);
        g->allowed_signers_path   = rr.path;
        g->allowed_signers_source = rr.source;
    }
    {
        auto ex_res = n00b_audit_discover_exemptions(g->project_root);
        if (n00b_result_is_err(ex_res)) {
            n00b_parse_result_free(pr);
            n00b_grammar_free(meta_g);
            return n00b_result_err(n00b_audit_guidance_t *,
                                   n00b_result_get_err(ex_res));
        }
        n00b_list_t(n00b_audit_exemption_t *) *exlist =
            n00b_result_get(ex_res);
        if (exlist && n00b_list_len(*exlist) > 0) {
            g->exemptions = n00b_alloc(n00b_list_t(void *));
            *g->exemptions = n00b_list_new(void *);
            int64_t nex = n00b_list_len(*exlist);
            for (int64_t i = 0; i < nex; i++) {
                n00b_list_push(*g->exemptions,
                               (void *)n00b_list_get(*exlist, i));
            }
        }

        n00b_string_t *base_path = n00b_path_simple_join(
            g->project_root,
            r"audit/baseline/baseline.bnf");
        if (n00b_path_is_file(base_path)) {
            auto br = n00b_audit_load_exemptions(base_path);
            if (n00b_result_is_err(br)) {
                n00b_parse_result_free(pr);
                n00b_grammar_free(meta_g);
                return n00b_result_err(n00b_audit_guidance_t *,
                                       n00b_result_get_err(br));
            }
            n00b_list_t(n00b_audit_exemption_t *) *blist =
                n00b_result_get(br);
            if (blist && n00b_list_len(*blist) > 0) {
                g->baseline = n00b_alloc(n00b_list_t(void *));
                *g->baseline = n00b_list_new(void *);
                int64_t nb = n00b_list_len(*blist);
                for (int64_t i = 0; i < nb; i++) {
                    n00b_list_push(*g->baseline,
                                   (void *)n00b_list_get(*blist, i));
                }
            }
        }
    }

    n00b_parse_result_free(pr);
    n00b_grammar_free(meta_g);
    return n00b_result_ok(n00b_audit_guidance_t *, g);
}

/* ---------------------------------------------------------------- */
/* Guidance-file discovery walk                                     */
/* ---------------------------------------------------------------- */

/*
 * Compute the parent of `dir` using libn00b's path primitives.
 * Same shape as the prior loader's parent_dir helper. Terminates
 * on filesystem root via parent-equals-self.
 */
static n00b_string_t *
parent_dir(n00b_string_t *dir)
{
    n00b_list_t(n00b_string_t *) *parts = n00b_path_parts(dir);
    if (!parts || n00b_list_len(*parts) <= 1) {
        return dir;
    }
    n00b_list_t(n00b_string_t *) *up = n00b_alloc(
        n00b_list_t(n00b_string_t *));
    *up      = n00b_list_new(n00b_string_t *);
    size_t n = n00b_list_len(*parts);
    for (size_t i = 0; i + 1 < n; i++) {
        n00b_list_push(*up, n00b_list_get(*parts, i));
    }
    if (n00b_list_len(*up) == 0) {
        return r"/";
    }
    if (n00b_list_len(*up) == 1) {
        n00b_string_t *only = n00b_list_get(*up, 0);
        if (!only || only->u8_bytes == 0) {
            return r"/";
        }
    }
    return n00b_path_join(up);
}

n00b_result_t(n00b_string_t *)
n00b_audit_find_guidance_file(n00b_string_t *start_dir)
{
    if (!start_dir) {
        return n00b_result_err(n00b_string_t *,
                               N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }

    n00b_string_t *dir = n00b_path_canonical(start_dir);
    if (!dir || dir->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *,
                               N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
    }

    /*
     * Walk up one parent at a time. At each level, build
     * `<dir>/audit-rules.bnf` (WP-005 — was previously
     * `<dir>/.agents/.audit-guidance.json`) and test for
     * existence via `n00b_path_is_file`.
     */
    for (;;) {
        n00b_string_t *candidate = n00b_path_simple_join(
            dir, r"audit-rules.bnf");
        if (n00b_path_is_file(candidate)) {
            return n00b_result_ok(n00b_string_t *, candidate);
        }

        n00b_string_t *up = parent_dir(dir);
        if (!up || up->u8_bytes == 0 || n00b_unicode_str_eq(up, dir)) {
            return n00b_result_err(n00b_string_t *,
                                   N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND);
        }
        dir = up;
    }
}

n00b_string_t *
n00b_audit_err_str(int code)
{
    switch (code) {
    case N00B_AUDIT_ERR_GUIDANCE_NOT_FOUND:
        return r"guidance file not found or unreadable";
    case N00B_AUDIT_ERR_GUIDANCE_PARSE:
        return r"audit-rule file failed to parse";
    case N00B_AUDIT_ERR_GUIDANCE_SCHEMA:
        return r"audit-rule file does not match the v1 schema";
    case N00B_AUDIT_ERR_GUIDANCE_SCHEMA_VERSION:
        return r"audit-rule file schema_version is not 1";
    case N00B_AUDIT_ERR_GUIDANCE_DEPS_UNIMPLEMENTED:
        return r"non-empty dependencies list is not yet supported (deferred to WP-002+)";
    case N00B_AUDIT_ERR_ENGINE_GRAMMAR_LOAD:
        return r"audit engine could not load the base C-ncc grammar";
    case N00B_AUDIT_ERR_ENGINE_RULE_MERGE:
        return r"a rule's BNF fragment failed to merge with the base grammar";
    case N00B_AUDIT_ERR_ENGINE_PARSE:
        return r"target source file failed to parse against the merged grammar";
    case N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND:
        return r"target source file not found or unreadable";
    case N00B_AUDIT_ERR_ENGINE_BAD_ARGS:
        return r"required engine argument was null or uninitialized";
    case N00B_AUDIT_ERR_ENGINE_UNKNOWN_LANGUAGE:
        return r"audited file's extension does not map to any registered language";
    case N00B_AUDIT_ERR_CLI_ARGS:
        return r"CLI argument parsing failed (unknown flag, missing positional, or bad value)";
    case N00B_AUDIT_ERR_CLI_BAD_ARGS:
        return r"required argument to n00b_audit_run_cli was null or out-of-shape";
    case N00B_AUDIT_ERR_CLI_RENDER:
        return r"output renderer could not produce a violation block (missing required rule field)";
    case N00B_AUDIT_ERR_EXEMPTION_NO_SIGNATURE:
        return r"exemption / baseline record carries no detached signature";
    case N00B_AUDIT_ERR_EXEMPTION_BAD_SIGNATURE:
        return r"exemption / baseline signature failed verification";
    case N00B_AUDIT_ERR_EXEMPTION_UNKNOWN_SIGNER:
        return r"exemption signer is not present in audit/allowed_signers";
    case N00B_AUDIT_ERR_SIGN_SUBPROCESS:
        return r"sign / verify subprocess (ssh-keygen) could not be spawned or failed at the OS level";
    default:
        return r"(unknown n00b-audit error code)";
    }
}
