/*
 * x509_parse.c — DER → parse tree (WP-042 Phase 1). See x509_parse.h.
 *
 * The "x509_der" grammar is embedded at build time, has its DER tokenizer IDs
 * registered while mutable, and is finalized before publication so parse workers
 * never race lazy grammar mutation.
 */

#include "n00b.h"

#include "slay/bnf.h"
#include "slay/diagnostic.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "parsers/token_stream.h"
#include "internal/crypto/x509_der_tok.h"
#include "internal/crypto/x509_parse.h"
#include "x509_der_grammar.h"

/* Cached grammar + token-id table. The grammar is built once under the mutex;
 * per-certificate parse state stays private and uses s_x509_der_token_ids
 * read-only. */
static n00b_grammar_t       *s_x509_grammar             = nullptr;
static n00b_der_token_ids_t  s_x509_der_token_ids;
static n00b_mutex_t          s_x509_grammar_mutex;
static _Atomic int           s_x509_grammar_mutex_state = 0;

static void
ensure_x509_grammar_mutex(void)
{
    if (n00b_atomic_load(&s_x509_grammar_mutex_state) == 2) {
        return;
    }
    int expected = 0;
    if (n00b_atomic_cas(&s_x509_grammar_mutex_state, &expected, 1)) {
        n00b_sys_mutex_init(&s_x509_grammar_mutex, (char *)__FILE__);
        n00b_atomic_store(&s_x509_grammar_mutex_state, 2);
        return;
    }
    while (n00b_atomic_load(&s_x509_grammar_mutex_state) != 2) {
        ; /* brief spin until the elected initializer publishes */
    }
}

static n00b_grammar_t *
load_x509_grammar(n00b_string_t **err_out) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (allocator == nullptr) {
        allocator = n00b_default_allocator();
    }

    ensure_x509_grammar_mutex();
    n00b_mutex_lock(&s_x509_grammar_mutex);

    if (s_x509_grammar == nullptr) {
        n00b_allocator_scope_t scope =
            n00b_allocator_scope_enter(allocator);
        n00b_string_t *bnf = n00b_string_from_raw(
            N00B_X509_DER_GRAMMAR,
            sizeof(N00B_X509_DER_GRAMMAR) - 1);
        n00b_grammar_t *g = n00b_grammar_new(
            .error_recovery = false,
            .parse_mode     = N00B_PARSE_MODE_PWZ_ONLY);

        n00b_diag_ctx_t *diag = n00b_diag_ctx_new();
        bool             ok   = n00b_bnf_load(bnf, r"Certificate", g,
                                              .diag = diag);
        n00b_diag_ctx_free(diag);

        if (!ok) {
            n00b_allocator_scope_exit(&scope);
            n00b_mutex_unlock(&s_x509_grammar_mutex);
            *err_out = r"x509_der grammar failed to load";
            return nullptr;
        }

        n00b_x509_der_register_token_ids(g, &s_x509_der_token_ids);
        n00b_grammar_finalize(g);
        s_x509_grammar = g;
        n00b_allocator_scope_exit(&scope);
    }

    n00b_grammar_t *g = s_x509_grammar;
    n00b_mutex_unlock(&s_x509_grammar_mutex);
    return g;
}

bool
n00b_x509_preload_parser() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_string_t  *err = nullptr;
    n00b_grammar_t *g   = load_x509_grammar(&err,
                                            .allocator = allocator);
    return g != nullptr;
}

n00b_x509_parse_t
n00b_x509_parse_der(n00b_buffer_t *der)
{
    n00b_x509_parse_t res = {};
    n00b_allocator_scope_t scope =
        n00b_allocator_scope_enter(n00b_default_allocator());

    n00b_string_t  *err = nullptr;
    n00b_grammar_t *g   = load_x509_grammar(&err);
    if (g == nullptr) {
        res.error = err;
        return res;
    }

    n00b_der_tok_result_t tr = n00b_x509_der_tokenize_with_ids(
        der, &s_x509_der_token_ids);
    if (tr.error != nullptr) {
        res.error = tr.error;
        return res;
    }

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tr.tokens, tr.count);
    n00b_parse_result_t *pr = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(pr)) {
        res.error = n00b_parse_result_error_string(pr);
        return res;
    }

    res.ok   = true;
    res.tree = n00b_parse_result_tree(pr);
    return res;
}
