/*
 * test_x509_der_tok.c — DER bracketing tokenizer (WP-042 Phase 1).
 *
 * Positive: a hand-built nested TLV tokenizes to the expected OPEN/PRIM/CLOSE
 * sequence with correct tids + primitive content slices (n00b_buffer_t).
 * Negative (X.690 DER default-deny): indefinite length, truncated value,
 * trailing bytes, and non-minimal long-form length are all rejected.
 */

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "slay/grammar.h"
#include "slay/token.h"
#include "internal/crypto/x509_der_tok.h"

static int64_t
tid_of(n00b_grammar_t *g, const char *name)
{
    return n00b_register_literal_type(g, n00b_string_from_cstr(name));
}

static n00b_buffer_t *
buf(char *bytes, int64_t len)
{
    return n00b_buffer_from_bytes(bytes, len);
}

/* compare a content buffer to expected bytes */
static bool
content_is(n00b_buffer_t *got, char *exp, int64_t len)
{
    if (got == NULL || n00b_buffer_len(got) != (n00b_size_t)len) {
        return false;
    }
    if (len == 0) {
        return true;
    }
    n00b_buffer_t *e = buf(exp, len);
    n00b_option_t(int64_t) f = n00b_buffer_find(got, e);
    return n00b_option_is_set(f) && n00b_option_get(f) == 0;
}

/* SEQUENCE { INTEGER 0x05, SEQUENCE { OID 2A8648, NULL }, OCTET STRING AABB } */
static char k_nested[] = {
    0x30, 0x10,
    0x02, 0x01, 0x05,
    0x30, 0x07,
    0x06, 0x03, 0x2a, 0x86, 0x48,
    0x05, 0x00,
    0x04, 0x02, (char)0xaa, (char)0xbb,
};

static n00b_der_value_t *
val(n00b_der_tok_result_t *r, int i)
{
    return (n00b_der_value_t *)r->tokens[i]->user_info;
}

static void
test_positive(n00b_grammar_t *g)
{
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(buf(k_nested, sizeof(k_nested)), g);
    assert(r.error == NULL);
    assert(r.count == 8);

    const char *names[8] = {
        "SEQ_OPEN", "INTEGER", "SEQ_OPEN", "OID",
        "NULL", "CLOSE", "OCTET_STRING", "CLOSE",
    };
    for (int i = 0; i < 8; i++) {
        assert(r.tokens[i]->tid == tid_of(g, names[i]));
    }

    char i05[]  = {0x05};
    char oid[]  = {0x2a, 0x86, 0x48};
    char os[]   = {(char)0xaa, (char)0xbb};
    assert(content_is(val(&r, 1)->content, i05, 1)); /* INTEGER */
    assert(content_is(val(&r, 3)->content, oid, 3)); /* OID */
    assert(val(&r, 4)->content != NULL
           && n00b_buffer_len(val(&r, 4)->content) == 0); /* NULL */
    assert(content_is(val(&r, 6)->content, os, 2));  /* OCTET STRING */

    printf("[der-tok] positive nested TLV: 8 tokens, tids + content OK\n");
}

static void
expect_reject(n00b_grammar_t *g, char *b, int64_t n, const char *what)
{
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(buf(b, n), g);
    assert(r.error != NULL);
    assert(r.tokens == NULL);
    printf("[der-tok] reject %s: OK\n", what);
}

static void
test_negatives(n00b_grammar_t *g)
{
    char indefinite[] = {0x30, (char)0x80, 0x00, 0x00};
    expect_reject(g, indefinite, sizeof(indefinite), "indefinite length");

    char truncated[] = {0x30, 0x05, 0x02, 0x01};
    expect_reject(g, truncated, sizeof(truncated), "truncated value");

    char trailing[] = {0x02, 0x01, 0x05, 0x00};
    expect_reject(g, trailing, sizeof(trailing), "trailing bytes");

    char nonminimal[] = {0x02, (char)0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
    expect_reject(g, nonminimal, sizeof(nonminimal), "non-minimal long-form length");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_grammar_t *g = n00b_grammar_new();

    test_positive(g);
    test_negatives(g);

    printf("[der-tok] all DER tokenizer tests passed\n");
    return 0;
}
