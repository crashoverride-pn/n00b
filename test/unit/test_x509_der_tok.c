/*
 * test_x509_der_tok.c — DER bracketing tokenizer (WP-042 Phase 1).
 *
 * Positive: a hand-built nested TLV tokenizes to the expected OPEN/PRIM/CLOSE
 * sequence with correct tids + primitive content slices.
 * Negative (X.690 DER default-deny): indefinite length, truncated value,
 * trailing bytes, and non-minimal long-form length are all rejected.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "slay/grammar.h"
#include "slay/token.h"
#include "internal/crypto/x509_der_tok.h"

static int64_t
tid_of(n00b_grammar_t *g, const char *name)
{
    return n00b_register_literal_type(g, n00b_string_from_cstr(name));
}

/* SEQUENCE { INTEGER 0x05, SEQUENCE { OID 2A8648, NULL }, OCTET STRING AABB } */
static const uint8_t k_nested[] = {
    0x30, 0x10,                         /* SEQUENCE, len 16            */
    0x02, 0x01, 0x05,                   /*   INTEGER 0x05              */
    0x30, 0x07,                         /*   SEQUENCE, len 7           */
    0x06, 0x03, 0x2a, 0x86, 0x48,       /*     OID (3 bytes)           */
    0x05, 0x00,                         /*     NULL                    */
    0x04, 0x02, 0xaa, 0xbb,             /*   OCTET STRING (2 bytes)    */
};

static void
test_positive(n00b_grammar_t *g)
{
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(k_nested,
                                                     sizeof(k_nested), g);
    assert(r.error == NULL);
    assert(r.count == 8);

    const char *names[8] = {
        "SEQ_OPEN", "INTEGER", "SEQ_OPEN", "OID",
        "NULL", "CLOSE", "OCTET_STRING", "CLOSE",
    };
    for (int i = 0; i < 8; i++) {
        assert(r.tokens[i]->tid == tid_of(g, names[i]));
    }

    /* primitive content slices */
    n00b_der_value_t *iv = (n00b_der_value_t *)r.tokens[1]->user_info; /* INTEGER */
    assert(iv->content_len == 1 && iv->content[0] == 0x05);

    n00b_der_value_t *ov = (n00b_der_value_t *)r.tokens[3]->user_info; /* OID */
    static const uint8_t oid[] = {0x2a, 0x86, 0x48};
    assert(ov->content_len == 3 && memcmp(ov->content, oid, 3) == 0);

    n00b_der_value_t *nv = (n00b_der_value_t *)r.tokens[4]->user_info; /* NULL */
    assert(nv->content_len == 0);

    n00b_der_value_t *sv = (n00b_der_value_t *)r.tokens[6]->user_info; /* OCTET STRING */
    static const uint8_t os[] = {0xaa, 0xbb};
    assert(sv->content_len == 2 && memcmp(sv->content, os, 2) == 0);

    printf("[der-tok] positive nested TLV: 8 tokens, tids + content OK\n");
}

static void
expect_reject(n00b_grammar_t *g, const uint8_t *b, size_t n, const char *what)
{
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(b, n, g);
    assert(r.error != NULL);
    assert(r.tokens == NULL);
    printf("[der-tok] reject %s: OK\n", what);
}

static void
test_negatives(n00b_grammar_t *g)
{
    static const uint8_t indefinite[] = {0x30, 0x80, 0x00, 0x00};
    expect_reject(g, indefinite, sizeof(indefinite), "indefinite length");

    static const uint8_t truncated[] = {0x30, 0x05, 0x02, 0x01};
    expect_reject(g, truncated, sizeof(truncated), "truncated value");

    static const uint8_t trailing[] = {0x02, 0x01, 0x05, 0x00};
    expect_reject(g, trailing, sizeof(trailing), "trailing bytes");

    static const uint8_t nonminimal[] = {0x02, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
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
