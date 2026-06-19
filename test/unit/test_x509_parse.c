/*
 * test_x509_parse.c — DER → parse tree end-to-end (WP-042 Phase 1).
 *
 * Loads the committed PEM fixture cert, decodes to DER, and parses it through
 * the build-time-baked "x509_der" grammar (x509_der_grammar_image.c is linked
 * into this test). Asserts a single, unambiguous parse tree.
 *
 * Needs workdir: meson.project_source_root() to resolve the relative PEM path.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"

#include "picotls.h"
#include "picotls/pembase64.h"
#include "internal/crypto/x509_parse.h"

static const char k_cert_pem_path[] = "test/unit/data/pkcs7_fixture_cert.pem";

static ptls_iovec_t
load_pem(const char *path, const char *label)
{
    ptls_iovec_t vec = {0};
    size_t       n   = 0;
    int          rc  = ptls_load_pem_objects(path, label, &vec, 1, &n);
    if (rc != 0 || n == 0) {
        fprintf(stderr, "ptls_load_pem_objects(%s, %s) failed rc=%d n=%zu\n",
                path, label, rc, n);
        fprintf(stderr, "  (run from the source-tree root)\n");
        assert(0);
    }
    return vec;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    ptls_iovec_t cert = load_pem(k_cert_pem_path, "CERTIFICATE");
    assert(cert.base != NULL && cert.len > 0);
    fprintf(stderr, "[x509-parse] loaded fixture cert: %zu DER bytes\n", cert.len);

    n00b_x509_parse_t r = n00b_x509_parse_der(cert.base, cert.len);

    if (!r.ok) {
        fprintf(stderr, "[x509-parse] PARSE FAILED: %.*s\n",
                (int)(r.error ? r.error->u8_bytes : 0),
                r.error ? (char *)r.error->data : "");
        assert(0);
    }
    assert(r.tree != NULL);

    printf("[x509-parse] real cert parsed to an unambiguous tree — OK\n");
    return 0;
}
