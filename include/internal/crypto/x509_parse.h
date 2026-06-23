#pragma once

/*
 * x509_parse.h — DER → parse tree front door (WP-042 Phase 1).
 *
 * Loads the "x509_der" grammar once, registers the DER tokenizer token IDs,
 * finalizes it before publication, tokenizes the DER via the bracketing
 * tokenizer, and parses the token stream to an unambiguous parse tree. The typed
 * n00b_x509_cert_t walk lands in the next step; for now callers get the raw tree
 * (+ ok/error).
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "slay/parse_tree.h"

typedef struct {
    bool               ok;
    n00b_parse_tree_t *tree;  /* valid iff ok */
    n00b_string_t     *error; /* set iff !ok */
} n00b_x509_parse_t;

/* Preload and finalize the process-global X.509 grammar. */
extern bool
n00b_x509_preload_parser()
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/* Parse a DER-encoded X.509 certificate to an unambiguous parse tree. */
extern n00b_x509_parse_t n00b_x509_parse_der(n00b_buffer_t *der);
