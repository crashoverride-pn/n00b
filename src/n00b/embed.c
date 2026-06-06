#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "n00b/embed.h"
#include "slay/bnf.h"
#include "slay/pwz.h"
#include "parsers/token_stream.h"
#include "parsers/scan_recipes.h"
#include "core/alloc.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/dict_untyped.h"

// ============================================================================
// Registry
// ============================================================================

n00b_dict_untyped_t *
n00b_embed_registry_new(void)
{
    n00b_dict_untyped_t *d = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(d, .skip_obj_hash = true);
    return d;
}

// ============================================================================
// Registration
// ============================================================================

void
n00b_embed_register(n00b_dict_untyped_t  *registry,
                     n00b_embed_handler_t *handler)
{
    assert(registry);
    assert(handler);
    assert(handler->name);
    assert(handler->handler);

    // Copy the handler descriptor into GC-managed storage.
    n00b_embed_handler_t *h = n00b_alloc(n00b_embed_handler_t);
    *h = *handler;

    // Key by the string's raw data pointer for hash lookup.
    n00b_dict_untyped_put(registry,
                           (void *)(uintptr_t)n00b_string_hash(h->name),
                           h);
}

// ============================================================================
// Lookup
// ============================================================================

n00b_embed_handler_t *
n00b_embed_lookup(n00b_dict_untyped_t *registry,
                   n00b_string_t       *name)
{
    if (!registry || !name) {
        return nullptr;
    }

    bool found = false;
    void *val  = n00b_dict_untyped_get(
        registry,
        (void *)(uintptr_t)n00b_string_hash(name),
        &found);

    if (found) {
        return (n00b_embed_handler_t *)val;
    }

    return nullptr;
}

// ============================================================================
// Grammar caching
// ============================================================================

static n00b_grammar_t *
ensure_grammar(n00b_embed_handler_t *h)
{
    if (h->grammar) {
        return h->grammar;
    }

    if (!h->bnf) {
        return nullptr;
    }

    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);

    // The BNF's start symbol is assumed to be the first NT defined.
    // n00b_bnf_load picks it up from the start_symbol argument.
    // By convention, embed BNFs use "start" as the start symbol
    // unless the BNF explicitly names one.
    //
    // We pass the first line's NT name.  A simpler convention: always
    // use the modifier name as start symbol.
    bool ok = n00b_bnf_load(h->bnf, h->name, g);

    if (!ok) {
        fprintf(stderr,
                "embed: failed to load BNF grammar for '%.*s'\n",
                (int)h->name->u8_bytes, h->name->data);
        n00b_grammar_free(g);
        return nullptr;
    }

    h->grammar = g;
    return g;
}

// ============================================================================
// Dispatch
// ============================================================================

n00b_embed_result_t
n00b_embed_dispatch(n00b_dict_untyped_t *registry,
                     n00b_cg_session_t   *session,
                     n00b_string_t       *content,
                     n00b_string_t       *modifier)
{
    n00b_embed_result_t void_result = {0};

    n00b_embed_handler_t *h = n00b_embed_lookup(registry, modifier);

    if (!h) {
        fprintf(stderr,
                "embed: no handler registered for modifier '%.*s'\n",
                (int)modifier->u8_bytes, modifier->data);
        return void_result;
    }

    // Buffer-based handler: wrap content as buffer, call handler.
    if (!h->bnf) {
        n00b_buffer_t *buf = n00b_buffer_from_bytes(
            content->data, (int64_t)content->u8_bytes);

        n00b_embed_input_t input = n00b_variant_set(
            n00b_embed_input_t, n00b_buffer_t *, buf);

        return h->handler(session, input, h->user_data);
    }

    // Grammar-based handler: parse content, call handler with tree.
    n00b_grammar_t *g = ensure_grammar(h);

    if (!g) {
        return void_result;
    }

    // Tokenize the content.
    n00b_buffer_t *buf = n00b_buffer_from_bytes(
        content->data, (int64_t)content->u8_bytes);

    n00b_scan_cb_t tok_cb = h->tokenizer;

    // If no custom tokenizer, the BNF system's default character-based
    // tokenizer is used (grammar is passed to the scanner which uses
    // its terminal table for token matching).
    n00b_scanner_t *scanner = n00b_scanner_new(buf, tok_cb, g);
    n00b_token_stream_t *ts = n00b_token_stream_new(scanner);

    n00b_parse_forest_t forest = n00b_pwz_parse_grammar(g, ts);

    n00b_parse_tree_t *tree = n00b_parse_forest_best(&forest);

    if (!tree) {
        fprintf(stderr,
                "embed: parse failed for '%.*s' literal\n",
                (int)modifier->u8_bytes, modifier->data);
        n00b_parse_forest_free(&forest);
        n00b_token_stream_free(ts);
        n00b_scanner_free(scanner);
        return void_result;
    }

    n00b_embed_input_t input = n00b_variant_set(
        n00b_embed_input_t, n00b_parse_tree_t *, tree);

    n00b_embed_result_t result = h->handler(session, input, h->user_data);

    n00b_parse_forest_free(&forest);
    n00b_token_stream_free(ts);
    n00b_scanner_free(scanner);

    return result;
}
