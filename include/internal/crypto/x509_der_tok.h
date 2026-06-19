#pragma once

/*
 * x509_der_tok.h — DER (X.690) → slay token-stream tokenizer.
 *
 * Walks the definite-length TLV framing of a DER blob and emits a CFG-parsable
 * token stream for the slay grammar in grammars/x509_der.bnf: every constructed
 * value becomes an OPEN token + a matching %CLOSE; every primitive a single
 * typed token whose content bytes are carried in the token's user_info as an
 * n00b_der_value_t. (The "INDENT/DEDENT" trick for length-framed binary.)
 *
 * Security posture (X.690 DER, RFC 5280): default-deny. Rejects indefinite
 * length, non-minimal length encodings, non-minimal high-tag-number form,
 * lengths that exceed the buffer, and bounds recursion depth. Trailing bytes
 * after the top-level element are reported by the caller (pos must reach end).
 *
 * Allocation-only-via-n00b (GC); safe on any thread.
 */

#include "n00b.h"
#include "core/string.h"
#include "slay/grammar.h"
#include "slay/token.h"

/* Content bytes of a primitive TLV (and tag metadata), hung off
 * n00b_token_info_t.user_info so the parse-tree walk can read field bytes
 * binary-safely (DER content is not valid UTF-8). The pointer aliases into the
 * caller's DER buffer, which must outlive the tokens. */
typedef struct {
    const uint8_t *content;     /* primitive content (NULL for OPEN/CLOSE) */
    size_t         content_len;
    const uint8_t *elem;        /* full TLV (tag..value-end); NULL for CLOSE */
    size_t         elem_len;    /* needed for TBSCertificate (signed bytes) +
                                 * Name (DN) raw-DER comparison */
    uint8_t        tag_class;   /* 0 universal, 1 application, 2 context, 3 private */
    bool           constructed;
    uint32_t       tag_number;
} n00b_der_value_t;

typedef struct {
    n00b_token_info_t **tokens; /* array, NULL on error */
    int32_t             count;
    n00b_string_t      *error;  /* NULL on success, else human-readable reason */
} n00b_der_tok_result_t;

/* Tokenize @p der (@p len bytes) into a slay token stream, resolving %NAME
 * terminal ids against @p g (n00b_register_literal_type is idempotent, so this
 * matches the ids the BNF registered). On success error==NULL and the token
 * array (incl. one balanced %CLOSE per constructed open) is returned. */
extern n00b_der_tok_result_t
n00b_x509_der_tokenize(const uint8_t *der, size_t len, n00b_grammar_t *g);
