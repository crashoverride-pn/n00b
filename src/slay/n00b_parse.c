// n00b_parse.c - Unified parse dispatch (PWZ fast path + Earley fallback)

#include "slay/n00b_parse.h"
#include "slay/pwz.h"
#include "slay/earley.h"
#include "internal/slay/grammar_internal.h"
#include "internal/slay/earley_internal.h"
#include "internal/slay/pwz_internal.h"
#include "parsers/token_stream.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/option.h"
#include "text/strings/string_ops.h"
#include "text/strings/format.h"
#include "text/strings/fmt_numbers.h"

#include <string.h>

// ============================================================================
// Internal result struct
// ============================================================================

struct n00b_parse_result_t {
    n00b_grammar_t       *grammar;

    // Trees
    n00b_parse_forest_t   forest;

    // Error diagnostics
    n00b_error_location_t error_loc;
    int64_t              *expected_ids;
    n00b_string_t       **expected_desc;
    int32_t               expected_count;
    n00b_string_t       **active_ctx;
    int32_t               active_ctx_count;

    // Repairs
    n00b_repair_t        *repairs;
    int32_t               repair_count;

    // State
    bool                  ok;
    bool                  ambiguous;
    bool                  repaired;
};

// ============================================================================
// Internal helpers
// ============================================================================

static n00b_parse_result_t *
result_new(n00b_grammar_t *g)
{
    n00b_parse_result_t *r = n00b_alloc(n00b_parse_result_t);
    memset(r, 0, sizeof(*r));
    r->grammar = g;
    return r;
}

static void
populate_from_forest(n00b_parse_result_t *r, n00b_parse_forest_t forest)
{
    r->forest    = forest;
    int32_t count = n00b_parse_forest_count(&forest);
    r->ok        = count > 0;
    r->ambiguous = count > 1;

    // Check the best tree's root node for penalty (indicates error recovery).
    if (r->ok) {
        n00b_parse_tree_t *best = n00b_parse_forest_best(&r->forest);

        if (best && !n00b_tree_is_leaf(best)
                && n00b_tree_node_value(best).penalty > 0) {
            r->repaired = true;
        }
    }
}

static void
populate_diagnostics_from_earley(n00b_parse_result_t  *r,
                                 n00b_earley_parser_t *p)
{
    n00b_earley_diagnostics_t diag = {0};
    n00b_earley_extract_diagnostics(p, &diag);

    r->error_loc        = diag.error_loc;
    r->expected_ids     = diag.expected_ids;
    r->expected_desc    = diag.expected_desc;
    r->expected_count   = diag.expected_count;
    r->active_ctx       = diag.active_ctx;
    r->active_ctx_count = diag.active_ctx_count;
}

// ============================================================================
// Parse dispatch
// ============================================================================

n00b_parse_result_t *
n00b_parse(n00b_grammar_t      *g,
           n00b_token_stream_t *ts,
           n00b_parse_opts_t    opts)
{
    n00b_parse_result_t *r = result_new(g);

    (void)opts;

    // Backend selection is an immutable property of the grammar (set at
    // n00b_grammar_new); UNSET behaves as DEFAULT (PWZ fast path, Earley
    // fallback).
    n00b_parse_mode_t mode = g->parse_mode;
    if (mode == N00B_PARSE_MODE_UNSET) {
        mode = N00B_PARSE_MODE_DEFAULT;
    }

    // ---- PWZ fast path ----
    if (mode != N00B_PARSE_MODE_EARLEY_ONLY) {
        n00b_pwz_parser_t *pwz = n00b_pwz_new(g);

        bool ok = n00b_pwz_parse(pwz, ts);

        if (ok) {
            n00b_parse_forest_t forest = n00b_pwz_get_forest(pwz);
            populate_from_forest(r, forest);

            // Detach the trees from the PWZ parser so freeing it
            // doesn't destroy the forest we just transferred out.
            pwz->result_trees = (n00b_parse_tree_array_t){0};
            n00b_pwz_free(pwz);
            return r;
        }

        n00b_pwz_free(pwz);

        if (mode == N00B_PARSE_MODE_PWZ_ONLY) {
            // PWZ-only mode: don't fall back to Earley.
            r->forest = n00b_parse_forest_empty(g);
            return r;
        }

        // PWZ failed — reset the stream and fall through to Earley.
        n00b_stream_reset(ts);
    }

    // ---- Earley ----
    n00b_earley_parser_t *earley = n00b_earley_new(g);

    bool ok = n00b_earley_parse(earley, ts);

    if (ok) {
        n00b_parse_forest_t forest = n00b_earley_get_forest(earley);
        populate_from_forest(r, forest);
        n00b_earley_free(earley);
        return r;
    }

    // Parse failed — extract diagnostics.
    populate_diagnostics_from_earley(r, earley);
    r->forest = n00b_parse_forest_empty(g);
    n00b_earley_free(earley);

    return r;
}

// ============================================================================
// Outcome queries
// ============================================================================

bool
n00b_parse_result_ok(n00b_parse_result_t *r)
{
    return r && r->ok;
}

bool
n00b_parse_result_ambiguous(n00b_parse_result_t *r)
{
    return r && r->ambiguous;
}

bool
n00b_parse_result_repaired(n00b_parse_result_t *r)
{
    return r && r->repaired;
}

int32_t
n00b_parse_result_tree_count(n00b_parse_result_t *r)
{
    if (!r) {
        return 0;
    }

    return n00b_parse_forest_count(&r->forest);
}

// ============================================================================
// Tree access
// ============================================================================

n00b_parse_tree_t *
n00b_parse_result_tree(n00b_parse_result_t *r)
{
    if (!r) {
        return NULL;
    }

    return n00b_parse_forest_best(&r->forest);
}

n00b_parse_tree_t **
n00b_parse_result_trees(n00b_parse_result_t *r)
{
    if (!r || !r->forest.trees.data) {
        return NULL;
    }

    return r->forest.trees.data;
}

// ============================================================================
// Walk
// ============================================================================

void *
n00b_parse_result_walk(n00b_parse_result_t *r,
                       n00b_parse_tree_t   *tree,
                       void                *thunk)
{
    if (!r || !r->ok) {
        return NULL;
    }

    if (!tree) {
        tree = n00b_parse_forest_best(&r->forest);
    }

    if (!tree) {
        return NULL;
    }

    return n00b_parse_tree_walk(r->grammar, tree, thunk);
}

// ============================================================================
// Error diagnostics
// ============================================================================

n00b_error_location_t
n00b_parse_result_error_location(n00b_parse_result_t *r)
{
    if (!r) {
        return (n00b_error_location_t){0};
    }

    return r->error_loc;
}

int32_t
n00b_parse_result_expected_tokens(n00b_parse_result_t *r,
                                  int64_t *out, int32_t max_out)
{
    if (!r || !r->expected_ids || max_out <= 0) {
        return 0;
    }

    int32_t n = r->expected_count < max_out ? r->expected_count : max_out;
    memcpy(out, r->expected_ids, n * sizeof(int64_t));

    return n;
}

n00b_string_t *
n00b_parse_result_expected_string(n00b_parse_result_t *r)
{
    if (!r || r->expected_count == 0) {
        return r"(none)";
    }

    // Build a comma-separated list of expected terminal names.
    n00b_grammar_t *g = r->grammar;

    n00b_string_t *result = r"";
    bool           first  = true;

    for (int32_t i = 0; i < r->expected_count; i++) {
        n00b_string_t *name;

        // Prefer the human-readable description when available.
        if (r->expected_desc && r->expected_desc[i]) {
            name = r->expected_desc[i];
        }
        else if (r->expected_ids) {
            n00b_string_t *tname = n00b_get_terminal_name(g, r->expected_ids[i]);

            if (tname) {
                name = tname;
            }
            else {
                name = n00b_fmt_int(r->expected_ids[i]);
            }
        }
        else {
            continue;
        }

        if (!first) {
            n00b_string_t *sep = r", ";
            result = n00b_unicode_str_cat(result, sep);
        }

        result = n00b_unicode_str_cat(result, name);
        first  = false;
    }

    return result;
}

n00b_string_t *
n00b_parse_result_error_string(n00b_parse_result_t *r)
{
    if (!r) {
        return r"(no result)";
    }

    if (r->ok) {
        return r"(no error)";
    }

    n00b_string_t *expected = n00b_parse_result_expected_string(r);
    n00b_error_location_t loc = r->error_loc;

    if (loc.got) {
        // Escape non-visible "got" text for readability.
        n00b_string_t *got_display = loc.got;

        if (got_display->u8_bytes == 1 && got_display->data[0] == '\n') {
            got_display = r"newline";
        }
        else if (got_display->u8_bytes == 1 && got_display->data[0] == '\t') {
            got_display = r"tab";
        }
        else if (got_display->u8_bytes == 2
                 && got_display->data[0] == '\r'
                 && got_display->data[1] == '\n') {
            got_display = r"newline";
        }

        return n00b_cformat("parse error at line «#:d», col «#:d»: got '«#»', expected: «#»",
                            (uint64_t)loc.line, (uint64_t)loc.column, got_display, expected);
    }

    return n00b_cformat("parse error at line «#:d», col «#:d»: expected: «#»",
                        (uint64_t)loc.line, (uint64_t)loc.column, expected);
}

// ============================================================================
// Repair diagnostics
// ============================================================================

int32_t
n00b_parse_result_repair_count(n00b_parse_result_t *r)
{
    if (!r) {
        return 0;
    }

    return r->repair_count;
}

n00b_repair_t *
n00b_parse_result_repairs(n00b_parse_result_t *r)
{
    if (!r) {
        return NULL;
    }

    return r->repairs;
}

// ============================================================================
// Ambiguity diagnostics
// ============================================================================

int32_t
n00b_parse_result_ambiguities(n00b_parse_result_t *r,
                              n00b_ambiguity_t *out,
                              int32_t max_out)
{
    if (!r || !r->ambiguous || max_out <= 0) {
        return 0;
    }

    // The forest trees represent root-level ambiguities.
    // Report a single ambiguity entry covering the whole parse.
    int32_t tree_count = n00b_parse_forest_count(&r->forest);

    if (tree_count <= 1) {
        return 0;
    }

    n00b_parse_tree_t *best = n00b_parse_forest_best(&r->forest);

    n00b_string_t *root_name = r"<root>";
    int32_t       root_start = 0;
    int32_t       root_end   = 0;

    if (best && !n00b_tree_is_leaf(best)) {
        n00b_nt_node_t *root_nt = &n00b_tree_node_value(best);
        root_name  = root_nt->name;
        root_start = root_nt->start;
        root_end   = root_nt->end;
    }

    out[0] = (n00b_ambiguity_t){
        .nt_name      = root_name,
        .start_pos    = root_start,
        .end_pos      = root_end,
        .alt_count    = tree_count,
        .alternatives = r->forest.trees.data,
    };

    return 1;
}

// ============================================================================
// Grammar accessor
// ============================================================================

n00b_grammar_t *
n00b_parse_result_grammar(n00b_parse_result_t *r)
{
    if (!r) {
        return NULL;
    }

    return r->grammar;
}

// ============================================================================
// Cleanup
// ============================================================================

void
n00b_parse_result_free(n00b_parse_result_t *r)
{
    if (!r) {
        return;
    }

    n00b_parse_forest_free(&r->forest);

    if (r->expected_ids) {
        n00b_free(r->expected_ids);
    }

    if (r->expected_desc) {
        n00b_free(r->expected_desc);
    }

    if (r->active_ctx) {
        n00b_free(r->active_ctx);
    }

    if (r->repairs) {
        n00b_free(r->repairs);
    }

    n00b_free(r);
}
