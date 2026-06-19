#pragma once

/*
 * x509_der_tok.h — DER (X.690) → slay token-stream tokenizer.
 *
 * Walks the definite-length TLV framing of a DER buffer and emits a CFG-parsable
 * token stream for the slay grammar in grammars/x509_der.bnf: every constructed
 * value becomes an OPEN token + a matching %CLOSE; every primitive a single
 * typed token whose content + full-element bytes ride in the token's user_info
 * as an n00b_der_value_t. (The "INDENT/DEDENT" trick for length-framed binary.)
 *
 * Security posture (X.690 DER, RFC 5280): default-deny. Rejects indefinite
 * length, non-minimal length encodings, non-minimal high-tag-number form,
 * lengths that exceed the buffer, deep nesting, and trailing bytes after the
 * top-level element.
 *
 * n00b primitives only: input + all slices are n00b_buffer_t; GC-allocated.
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "slay/grammar.h"
#include "slay/token.h"

/* Content + tag metadata of a TLV, hung off n00b_token_info_t.user_info so the
 * parse-tree walk can read field bytes. `content` is the primitive value bytes
 * (NULL for OPEN/CLOSE); `elem` is the full TLV (tag..value-end), needed for the
 * signed TBSCertificate bytes + raw Name (DN) comparison (NULL for CLOSE). Both
 * are independent n00b_buffer copies of the source slice. */
typedef struct {
    n00b_buffer_t *content;
    n00b_buffer_t *elem;
    uint8_t        tag_class;   /* 0 universal, 1 application, 2 context, 3 private */
    bool           constructed;
    uint32_t       tag_number;
} n00b_der_value_t;

typedef struct {
    n00b_token_info_t **tokens; /* array, NULL on error */
    int32_t             count;
    n00b_string_t      *error;  /* NULL on success, else human-readable reason */
} n00b_der_tok_result_t;

/* Tokenize @p der into a slay token stream, resolving %NAME terminal ids against
 * @p g (n00b_register_literal_type is idempotent, matching the ids the BNF
 * registered). On success error==NULL and the token array (incl. one balanced
 * %CLOSE per constructed open) is returned. */
extern n00b_der_tok_result_t
n00b_x509_der_tokenize(n00b_buffer_t *der, n00b_grammar_t *g);
