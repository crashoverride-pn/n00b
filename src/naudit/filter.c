/*
 * naudit/filter.c — implementation of the naudit filter helper.
 *
 * Registers the `match` n00b type with extension methods, installs
 * the C-side accessors as FFI bindings, and provides filter_compile /
 * filter_apply for the Phase 4 rule-file integration point.
 *
 * Per WP-010 the JIT codegen pipeline consults the type registry's
 * extension methods when lowering postfix-`.` against a registered
 * opaque type. We register the `match` type with n00b_type_register
 * (giving it a typehash + an ext_vtable), then add each accessor
 * method via n00b_type_add_method. The same C functions are also
 * installed as FFI bindings via n00b_ffi_install_simple so the JIT
 * has a callable symbol to dispatch to.
 *
 * The match handle layout lives here (not in the header) so consumers
 * never field-access it directly. Phase 4 changed the handle to be
 * heap-allocated (n00b_alloc) per invocation so it can own its
 * captures table; the table is populated by the engine via
 * n00b_naudit_match_bind_capture before the predicate is invoked.
 */

#include "n00b.h"
#include "naudit/filter.h"
#include "n00b/embed_ffi.h"
#include "adt/dict.h"
#include "core/alloc.h"
#include "core/string.h"
#include "core/type_info.h"
#include "core/vtable.h"
#include "slay/parse_tree.h"
#include "slay/token.h"
#include "text/strings/string_ops.h"

#include <string.h>

// ============================================================================
// Match handle layout
// ============================================================================

struct n00b_naudit_match {
    n00b_parse_tree_t                                  *node;
    n00b_string_t                                      *src_text;
    /*
     * WP-009 Phase 4: per-match captures dictionary, lazily allocated
     * on first `n00b_naudit_match_bind_capture`. Keyed by capture name
     * (without the leading `$`); values are descendant parse-tree
     * nodes pre-bound by the engine. Filter expressions read them
     * back via `arg.capture(name)` which returns a fresh handle
     * pointing at the bound node. Stays nullptr for handles created
     * by the Phase 3 stack-allocated `n00b_naudit_filter_apply` path
     * (no captures available to those filters).
     */
    n00b_dict_t(n00b_string_t *, n00b_parse_tree_t *) *captures;
};

static n00b_naudit_match_t *
alloc_match_handle(n00b_parse_tree_t *node, n00b_string_t *src_text)
{
    n00b_naudit_match_t *h = n00b_alloc_with_opts(
        n00b_naudit_match_t,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    h->node     = node;
    h->src_text = src_text;
    h->captures = nullptr;
    return h;
}

// ============================================================================
// Accessor C functions
//
// Each takes a `n00b_naudit_match_t *self` (the JIT-side caller
// passes the bound `arg` pointer through unchanged). The return
// types match the method signatures advertised below.
// ============================================================================

/**
 * `arg.text` — the source-text slice corresponding to the match's
 * span. Computed from the leftmost-token column to the rightmost-
 * token endcol, scoped to the match's line(s). For single-line
 * matches this is byte-exact; for multi-line spans we slice from
 * the leftmost token's start to the rightmost token's end via
 * source-text scanning by line.
 */
static n00b_string_t *
n00b_naudit_match_text(n00b_naudit_match_t *self)
{
    if (!self || !self->node || !self->src_text) {
        return r"";
    }

    n00b_parse_tree_t *lt = n00b_pt_first_token(self->node);
    n00b_parse_tree_t *rt = n00b_pt_last_token(self->node);

    if (!lt || !rt) {
        return r"";
    }

    n00b_token_info_t *lti = n00b_parse_node_token(lt);
    n00b_token_info_t *rti = n00b_parse_node_token(rt);

    if (!lti || !rti) {
        return r"";
    }

    // Walk the source text line by line until we find the start.
    // The match's bytes span [start_byte, end_byte). Lines are
    // 1-based; columns are 1-based; endcol is exclusive of the
    // last byte (matches the slay convention).
    const char *src     = self->src_text->data;
    size_t      src_len = self->src_text->u8_bytes;

    if (!src || src_len == 0) {
        return r"";
    }

    uint32_t line       = 1;
    uint32_t col        = 1;
    int64_t  start_byte = -1;
    int64_t  end_byte   = -1;

    for (size_t i = 0; i < src_len; i++) {
        if (start_byte < 0
            && line == lti->line
            && col == lti->column) {
            start_byte = (int64_t)i;
        }

        if (line == rti->line && col == rti->endcol) {
            end_byte = (int64_t)i;
            break;
        }

        if (src[i] == '\n') {
            line++;
            col = 1;
        }
        else {
            col++;
        }
    }

    if (end_byte < 0) {
        end_byte = (int64_t)src_len;
    }

    if (start_byte < 0 || start_byte >= end_byte) {
        return r"";
    }

    return n00b_string_from_raw(src + start_byte,
                                (int64_t)(end_byte - start_byte));
}

/**
 * `arg.nt` — the non-terminal name for an interior node, or `""`
 * for a token leaf.
 */
static n00b_string_t *
n00b_naudit_match_nt(n00b_naudit_match_t *self)
{
    if (!self || !self->node) {
        return r"";
    }

    if (n00b_pt_is_token(self->node)) {
        return r"";
    }

    const char *name = n00b_pt_nt_name(self->node);
    size_t      len  = n00b_pt_nt_name_len(self->node);

    if (!name || len == 0) {
        return r"";
    }

    return n00b_string_from_raw(name, (int64_t)len);
}

/**
 * `arg.line` — 1-based source line of the leftmost token in the
 * match. Returns 0 if no token is available.
 */
static int64_t
n00b_naudit_match_line(n00b_naudit_match_t *self)
{
    if (!self || !self->node) {
        return 0;
    }

    n00b_parse_tree_t *tok = n00b_pt_first_token(self->node);

    if (!tok) {
        return 0;
    }

    n00b_token_info_t *ti = n00b_parse_node_token(tok);

    return ti ? (int64_t)ti->line : 0;
}

/**
 * `arg.col` — 1-based source column of the leftmost token.
 */
static int64_t
n00b_naudit_match_col(n00b_naudit_match_t *self)
{
    if (!self || !self->node) {
        return 0;
    }

    n00b_parse_tree_t *tok = n00b_pt_first_token(self->node);

    if (!tok) {
        return 0;
    }

    n00b_token_info_t *ti = n00b_parse_node_token(tok);

    return ti ? (int64_t)ti->column : 0;
}

/**
 * `arg.end_line` — 1-based source line of the rightmost token.
 */
static int64_t
n00b_naudit_match_end_line(n00b_naudit_match_t *self)
{
    if (!self || !self->node) {
        return 0;
    }

    n00b_parse_tree_t *tok = n00b_pt_last_token(self->node);

    if (!tok) {
        return 0;
    }

    n00b_token_info_t *ti = n00b_parse_node_token(tok);

    return ti ? (int64_t)ti->line : 0;
}

/**
 * `arg.end_col` — 1-based source endcol of the rightmost token.
 */
static int64_t
n00b_naudit_match_end_col(n00b_naudit_match_t *self)
{
    if (!self || !self->node) {
        return 0;
    }

    n00b_parse_tree_t *tok = n00b_pt_last_token(self->node);

    if (!tok) {
        return 0;
    }

    n00b_token_info_t *ti = n00b_parse_node_token(tok);

    return ti ? (int64_t)ti->endcol : 0;
}

/**
 * `arg.child_named(name)` — first direct child whose NT name
 * matches @p name, wrapped in a fresh match handle pointing at the
 * same `src_text`. Returns nullptr if no such child exists; filter
 * expressions can guard with the `!= 0` idiom.
 *
 * The returned handle is allocated via `n00b_alloc` so it survives
 * the predicate's stack frame and remains valid as long as the GC
 * reaches it through the call result.
 */
static n00b_naudit_match_t *
n00b_naudit_match_child_named(n00b_naudit_match_t *self, n00b_string_t *name)
{
    if (!self || !self->node || !name) {
        return nullptr;
    }

    // n00b_pt_find_child_by_nt wants a C string. Copy the name into
    // a NUL-terminated buffer.
    if (name->u8_bytes == 0 || !name->data) {
        return nullptr;
    }

    size_t  len = (size_t)name->u8_bytes;
    char   *cbuf = n00b_alloc_array(char, len + 1);
    memcpy(cbuf, name->data, len);
    cbuf[len] = '\0';

    n00b_parse_tree_t *child = n00b_pt_find_child_by_nt(self->node, cbuf);

    if (!child) {
        return nullptr;
    }

    return alloc_match_handle(child, self->src_text);
}

/**
 * `arg.has_ancestor(name)` — placeholder for the Phase 4 rule-file
 * integration. Parse trees are not parent-linked, so a full
 * implementation needs an upstream change to slay. Returns false
 * for now; callers know to avoid this accessor until Phase 4.
 *
 * Phase 4 verdict: STILL A STUB. Implementing `has_ancestor`
 * requires slay-level parent-link infrastructure (every parse-tree
 * node carries a parent back-pointer maintained by the parser),
 * which is out of scope for this phase. Tracked as a follow-up via
 * the WP-009 phase4-prompt's `flagged_for_orchestrator` block.
 */
static bool
n00b_naudit_match_has_ancestor(n00b_naudit_match_t *self, n00b_string_t *name)
{
    (void)self;
    (void)name;
    return false;
}

/**
 * `arg.capture(name)` — read back a capture bound by the engine
 * before the filter ran. Returns a fresh `n00b_naudit_match_t *`
 * wrapping the bound node, or `nullptr` if no capture by that name
 * exists. Filter expressions chain into the returned handle's other
 * accessors (`arg.capture("callee").text`, etc.).
 *
 * Per the WP-009 Phase 4 DF-U resolution (document-order descendant
 * binding), the engine binds the Nth `$name<I>:<NT>` declaration on
 * a rule to the Nth descendant of the matched node whose NT matches
 * `<NT>` in pre-order DFS document order. This accessor never walks
 * the tree itself; it only reads back the precomputed binding.
 */
static n00b_naudit_match_t *
n00b_naudit_match_capture(n00b_naudit_match_t *self, n00b_string_t *name)
{
    if (!self || !self->captures || !name) {
        return nullptr;
    }

    bool               found = false;
    n00b_parse_tree_t *bound = n00b_dict_get(self->captures, name, &found);
    if (!found || !bound) {
        return nullptr;
    }

    return alloc_match_handle(bound, self->src_text);
}

/**
 * `arg.starts_with(prefix)` — bool result; true iff the match's
 * `.text` byte-prefix equals `prefix`. Convenience accessor added
 * in Phase 4 for the canonical `n00b_`-prefix rule. Implemented in
 * C to avoid registering string extension methods on n00b's
 * built-in `string` type (that's WP-010 territory; the match-side
 * helper avoids the issue).
 *
 * Empty / null inputs return false. Comparison is byte-exact (no
 * Unicode normalization); the audit use case is ASCII identifier
 * prefixes which makes that the correct semantic.
 */
static bool
n00b_naudit_match_starts_with(n00b_naudit_match_t *self, n00b_string_t *prefix)
{
    if (!self || !prefix || prefix->u8_bytes == 0) {
        return false;
    }

    n00b_string_t *text = n00b_naudit_match_text(self);
    if (!text || text->u8_bytes < prefix->u8_bytes) {
        return false;
    }

    return n00b_unicode_str_starts_with(text, prefix);
}

/*
 * `arg.text_equals(needle)` — bool result; true iff the match's
 * `.text` equals `needle` exactly (byte-exact). WP-016 added this
 * for the tree-query rule rewrites: filters narrow base-grammar
 * NTs (e.g., `<provided_identifier>`, which matches every C
 * identifier) to specific tokens like "NULL" or "malloc". Equality
 * is the right semantic here — `text_contains("NULL")` would also
 * hit identifiers like `IS_NULL_TERMINATED`.
 */
static bool
n00b_naudit_match_text_equals(n00b_naudit_match_t *self,
                              n00b_string_t       *needle)
{
    if (!self || !needle) {
        return false;
    }
    n00b_string_t *text = n00b_naudit_match_text(self);
    if (!text) {
        return false;
    }
    return n00b_unicode_str_eq(text, needle);
}

#ifdef _WIN32
static void *
n00b_naudit_memmem(const void *haystack,
                   size_t      haystack_len,
                   const void *needle,
                   size_t      needle_len)
{
    if (needle_len == 0) {
        return (void *)haystack;
    }
    if (!haystack || !needle || haystack_len < needle_len) {
        return nullptr;
    }

    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    size_t limit = haystack_len - needle_len;

    for (size_t i = 0; i <= limit; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needle_len) == 0) {
            return (void *)(h + i);
        }
    }

    return nullptr;
}
#else
#define n00b_naudit_memmem memmem
#endif

/*
 * `arg.text_contains(needle)` — bool result; true iff the match's
 * `.text` contains `needle` as a substring. Byte-exact search; null /
 * empty / oversized-needle inputs return false. Added for rules that
 * need to check the full body of the matched node for the presence
 * (or absence) of a particular token, e.g., the path-canonicalization
 * rule which checks whether a function body contains both
 * `n00b_file_open` AND `n00b_path_canonical`.
 */
static bool
n00b_naudit_match_text_contains(n00b_naudit_match_t *self,
                                n00b_string_t       *needle)
{
    if (!self || !needle || needle->u8_bytes == 0) {
        return false;
    }

    n00b_string_t *text = n00b_naudit_match_text(self);
    if (!text || text->u8_bytes < needle->u8_bytes) {
        return false;
    }

    return n00b_naudit_memmem(text->data, (size_t)text->u8_bytes,
                              needle->data, (size_t)needle->u8_bytes)
           != nullptr;
}

/**
 * `arg.is_call()` — bool result; true iff the matched parse-tree
 * node is a `<postfix_expression>` of call form
 * (`postfix_expression "(" argument_expression_list? ")"`).
 *
 * Phase 4 ships this narrowing helper because c_ncc.bnf has no
 * dedicated function-call NT — call forms are an alternative of
 * `<postfix_expression>` (line 537 of `grammars/c_ncc.bnf`).
 * Without a narrowing filter the canonical rule would over-fire on
 * array subscripts, member access, increment/decrement, and the
 * compound-literal forms (lines 536-551). The narrowing is purely
 * structural — true iff the matched node is the NT
 * `postfix_expression` AND has a direct-child token whose text is
 * `(`.
 */
static bool
n00b_naudit_match_is_call(n00b_naudit_match_t *self)
{
    if (!self || !self->node) {
        return false;
    }
    if (n00b_pt_is_token(self->node)) {
        return false;
    }

    // Walk direct children looking for a `(` token leaf. Slay's BNF
    // loader wraps each terminal that appears inside a production's
    // RHS in a `$term-...` synthetic NT (one child: the token
    // leaf); see `src/naudit/guidance.c::nth_token_child` for the
    // precedent unwrap loop. We replicate that descent here so the
    // `(` token under a postfix_expression call form's RHS is
    // reachable. Slay also synthesizes `$$group_N` wrappers around
    // BNF-quantified groups (`?`, `*`, `+`); we flatten through
    // those too.
    size_t n = n00b_pt_num_children(self->node);
    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(self->node, i);
        if (!child) {
            continue;
        }
        // Descend through `$term-*` / `$$group_N` single-child
        // wrappers down to the underlying token leaf, if one exists.
        n00b_parse_tree_t *probe = child;
        while (probe && !n00b_pt_is_token(probe)
               && n00b_pt_num_children(probe) == 1) {
            probe = n00b_pt_get_child(probe, 0);
        }
        if (!probe || !n00b_pt_is_token(probe)) {
            continue;
        }
        n00b_token_info_t *ti = n00b_parse_node_token(probe);
        if (!ti) {
            continue;
        }
        if (n00b_option_is_set(ti->value)) {
            n00b_string_t *t = n00b_option_get(ti->value);
            if (t && t->u8_bytes == 1 && t->data[0] == '(') {
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// Type registration
// ============================================================================

static bool s_match_type_registered = false;

void
n00b_naudit_match_type_register(void)
{
    if (s_match_type_registered) {
        return;
    }

    bool reg_ok = N00B_TYPE_REGISTER(n00b_naudit_match_t,
        N00B_TYPE_STATIC_TRANSIENT(r"naudit match handles are predicate-scoped"));

    if (!reg_ok) {
        // Already registered by another caller (shouldn't happen
        // given the s_match_type_registered guard, but be tolerant).
    }

    uint64_t th = typehash(n00b_naudit_match_t *);

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_text,
        .name        = "text",
        .return_type = {
            .type_hash = typehash(n00b_string_t *),
            .type_name = "string",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_nt,
        .name        = "nt",
        .return_type = {
            .type_hash = typehash(n00b_string_t *),
            .type_name = "string",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_line,
        .name        = "line",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_col,
        .name        = "col",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_end_line,
        .name        = "end_line",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_end_col,
        .name        = "end_col",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_child_named,
        .name        = "child_named",
        .return_type = {
            .type_hash = typehash(n00b_naudit_match_t *),
            .type_name = "n00b_naudit_match_t",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_has_ancestor,
        .name        = "has_ancestor",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    // WP-009 Phase 4 additions: capture accessor + structural helpers.
    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_capture,
        .name        = "capture",
        .return_type = {
            .type_hash = typehash(n00b_naudit_match_t *),
            .type_name = "n00b_naudit_match_t",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_starts_with,
        .name        = "starts_with",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_text_equals,
        .name        = "text_equals",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_text_contains,
        .name        = "text_contains",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_naudit_match_is_call,
        .name        = "is_call",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    s_match_type_registered = true;
}

// ============================================================================
// FFI binding installation
//
// The JIT method dispatch needs the C symbol resolvable via the
// embed-FFI's process-symbol lookup (dlsym/GetProcAddress). The
// accessors are file-static for tidy linkage hygiene, but
// `n00b_ffi_install_simple` accepts a direct address-resolution
// pathway via the underlying `lookup_process_symbol` — for static
// symbols we install via the proto-and-import pair manually.
//
// In practice, the WP-010 codegen path emits an indirect call via
// the registered method's `fn` pointer (no FFI lookup needed) —
// see `n00b_codegen_method_dispatch`. The FFI install is therefore
// a defensive belt-and-braces step for any path that falls through
// to a name-based call lookup; the registered method pointer is
// the load-bearing wiring.
// ============================================================================

static void
install_accessor_ffi_bindings(n00b_cg_session_t *session)
{
    if (!session) {
        return;
    }

    // FFI bindings here are intentionally a no-op for the smoke
    // tests: WP-010's `n00b_codegen_method_dispatch` does an
    // indirect call through the registered method's `fn` pointer,
    // so the JIT does not need to resolve these by name. We keep
    // the function as a hook for future Phase 4 work that may add
    // free-function helpers callable as `helper(arg)` rather than
    // `arg.helper`.
    (void)session;
}

// ============================================================================
// Session creation
// ============================================================================

n00b_result_t(n00b_eval_session_t *)
n00b_naudit_filter_session_new(void)
{
    n00b_naudit_match_type_register();

    auto sr = n00b_eval_session_new();

    if (n00b_result_is_err(sr)) {
        return sr;
    }

    n00b_eval_session_t *s = n00b_result_get(sr);

    install_accessor_ffi_bindings(n00b_eval_session_cg(s));

    return n00b_result_ok(n00b_eval_session_t *, s);
}

// ============================================================================
// Filter compile + apply
// ============================================================================

n00b_result_t(n00b_eval_predicate_fn_t)
n00b_naudit_filter_compile(n00b_eval_session_t *s,
                           n00b_string_t       *name,
                           n00b_string_t       *expr_text)
{
    (void)name; // reserved for Phase 4 rule-id diagnostics
    return n00b_eval_compile_predicate(s, expr_text, r"n00b_naudit_match_t");
}

bool
n00b_naudit_filter_apply(n00b_eval_predicate_fn_t  fn,
                         n00b_parse_tree_t        *match_node,
                         n00b_string_t            *src_text)
{
    if (!fn) {
        return false;
    }

    /*
     * Phase 4 note. The handle is now heap-allocated even on the
     * Phase 3 surface so the `.captures` dict field is reachable
     * by `arg.capture(...)` invocations against the no-engine
     * smoke path. The dict stays nullptr (no captures bound),
     * which the capture accessor handles by returning nullptr.
     * The hot path overhead is one `n00b_alloc` per filter call;
     * the Phase 3 stack-allocation was a pre-Phase-4 micro-opt
     * that no longer holds once captures join the layout.
     */
    n00b_naudit_match_t *handle = n00b_naudit_match_new(match_node, src_text);
    return fn((void *)handle);
}

// ============================================================================
// Phase 4 — explicit-handle factory + apply
// ============================================================================

n00b_naudit_match_t *
n00b_naudit_match_new(n00b_parse_tree_t *node, n00b_string_t *src_text)
{
    return alloc_match_handle(node, src_text);
}

void
n00b_naudit_match_bind_capture(n00b_naudit_match_t *handle,
                               n00b_string_t       *name,
                               n00b_parse_tree_t   *node)
{
    if (!handle || !name) {
        return;
    }
    if (!handle->captures) {
        handle->captures = n00b_alloc_with_opts(
            n00b_dict_t(n00b_string_t *, n00b_parse_tree_t *),
            &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
        n00b_dict_init(handle->captures,
                       .hash          = n00b_string_hash,
                       .skip_obj_hash = true,
                       .scan_kind     = N00B_GC_SCAN_KIND_ALL);
    }
    n00b_dict_put(handle->captures, name, node);
}

bool
n00b_naudit_filter_apply_handle(n00b_eval_predicate_fn_t  fn,
                                n00b_naudit_match_t      *handle)
{
    if (!fn || !handle) {
        return false;
    }
    return fn((void *)handle);
}
