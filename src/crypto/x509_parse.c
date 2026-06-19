/*
 * x509_parse.c — DER → parse tree (WP-042 Phase 1). See x509_parse.h.
 *
 * The "x509_der" grammar is loaded once from grammars/x509_der.bnf via
 * n00b_bnf_load and cached (the same runtime-load pattern the n00b compiler uses
 * for n00b.bnf in src/n00b/eval.c). Grammar-image baking is the eventual path
 * but is currently blocked by a libn00b marshal bug (see
 * project_grammar_image_marshal_broken); this load path is byte-identical in
 * behavior. The cached pointer is a file-scope static, so ncc auto-roots it for
 * the GC; a once-mutex guards first-build for thread safety.
 */

#include "n00b.h"

#include "slay/bnf.h"
#include "slay/diagnostic.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/string.h"
#include "parsers/token_stream.h"
#include "internal/crypto/x509_der_tok.h"
#include "internal/crypto/x509_parse.h"
#include "audit_paths.h"

static n00b_string_t *
read_file_as_string(const char *abs_path)
{
    if (!abs_path || abs_path[0] == '\0') {
        return nullptr;
    }
    n00b_string_t *path = n00b_string_from_cstr(abs_path);

    n00b_result_t(n00b_file_t *) open_r = n00b_file_open(
        path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(open_r)) {
        return nullptr;
    }
    n00b_file_t *f = n00b_result_get(open_r);

    n00b_result_t(n00b_buffer_t *) buf_r = n00b_file_as_buffer(f);
    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_buffer_t *buf = n00b_result_get(buf_r);
    if (!buf || !buf->data) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_string_t *s = n00b_string_from_raw(buf->data, (int64_t)buf->byte_len);
    n00b_file_close(f);
    return s;
}

/* Cached grammar + a once-mutex (mirrors src/n00b/eval.c). */
static n00b_grammar_t *s_x509_grammar             = nullptr;
static n00b_mutex_t    s_x509_grammar_mutex;
static _Atomic int     s_x509_grammar_mutex_state = 0;

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
load_x509_grammar(n00b_string_t **err_out)
{
    ensure_x509_grammar_mutex();
    n00b_mutex_lock(&s_x509_grammar_mutex);

    if (s_x509_grammar == nullptr) {
        n00b_string_t *bnf = read_file_as_string(N00B_X509_DER_GRAMMAR_PATH);
        if (bnf == nullptr) {
            n00b_mutex_unlock(&s_x509_grammar_mutex);
            *err_out = n00b_string_from_cstr(
                "cannot open x509_der grammar (N00B_X509_DER_GRAMMAR_PATH)");
            return nullptr;
        }
        n00b_grammar_t *g = n00b_grammar_new(
            .error_recovery = false,
            .parse_mode     = N00B_PARSE_MODE_EARLEY_ONLY);

        n00b_diag_ctx_t *diag = n00b_diag_ctx_new();
        bool             ok   = n00b_bnf_load(bnf, r"Certificate", g,
                                              .diag = diag);
        n00b_diag_ctx_free(diag);

        if (!ok) {
            n00b_mutex_unlock(&s_x509_grammar_mutex);
            *err_out = n00b_string_from_cstr("x509_der grammar failed to load");
            return nullptr;
        }
        s_x509_grammar = g;
    }

    n00b_grammar_t *g = s_x509_grammar;
    n00b_mutex_unlock(&s_x509_grammar_mutex);
    return g;
}

n00b_x509_parse_t
n00b_x509_parse_der(const uint8_t *der, size_t len)
{
    n00b_x509_parse_t res = {0};

    n00b_string_t  *err = nullptr;
    n00b_grammar_t *g   = load_x509_grammar(&err);
    if (g == nullptr) {
        res.error = err;
        return res;
    }

    n00b_der_tok_result_t tr = n00b_x509_der_tokenize(der, len, g);
    if (tr.error != NULL) {
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
