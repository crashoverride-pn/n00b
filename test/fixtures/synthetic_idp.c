/*
 * synthetic_idp.c — implementation of the in-process IdP fixture.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "crypto/jwt.h"
#include "crypto/oidc.h"
#include "internal/crypto/jws.h"

#include "synthetic_idp.h"

struct n00b_synthetic_idp {
    char               *issuer;
    char               *kid;
    n00b_quic_secret_t *signer;
    char               *jwks_json;
    n00b_oidc_t        *oidc;
};

static n00b_allocator_t *
si_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
si_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t n = strlen(s);
    char *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                           &(n00b_alloc_opts_t){
                                               .allocator = si_alloc(),
                                               .no_scan   = true,
                                           });
    memcpy(out, s, n + 1);
    return out;
}

n00b_synthetic_idp_t *
n00b_synthetic_idp_new(const char *issuer, const char *kid)
{
    if (!issuer || !kid) return nullptr;
    n00b_synthetic_idp_t *s = n00b_alloc_with_opts(n00b_synthetic_idp_t,
        &(n00b_alloc_opts_t){.allocator = si_alloc()});
    s->issuer = si_strdup(issuer);
    s->kid    = si_strdup(kid);

    /* Generate an ephemeral ES256 keypair via the n00b ephemeral
     * provider.  Use a kid-suffixed URI so distinct synthetic IdPs
     * don't collide in the provider's key cache. */
    char uri[256];
    snprintf(uri, sizeof(uri), "ephemeral:idp-%s", kid);
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr(uri));
    if (!n00b_result_is_ok(kr)) {
        return nullptr;
    }
    s->signer = n00b_result_get(kr);

    /* Build the JWKS JSON. */
    auto pkr = n00b_quic_secret_pubkey(s->signer, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(pkr)) {
        return nullptr;
    }
    n00b_buffer_t *pk = n00b_result_get(pkr);
    char *x = n00b_b64url_encode((const uint8_t *)pk->data,      32);
    char *y = n00b_b64url_encode((const uint8_t *)pk->data + 32, 32);
    size_t cap = strlen(x) + strlen(y) + strlen(kid) + 256;
    s->jwks_json = n00b_alloc_array_with_opts(char, (int64_t)cap,
        &(n00b_alloc_opts_t){.allocator = si_alloc(), .no_scan = true});
    snprintf(s->jwks_json, cap,
             "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"%s\","
             "\"x\":\"%s\",\"y\":\"%s\"}]}",
             kid, x, y);

    auto or_ = n00b_oidc_open_with_jwks(issuer, s->jwks_json);
    if (!n00b_result_is_ok(or_)) {
        return nullptr;
    }
    s->oidc = n00b_result_get(or_);
    return s;
}

const char *n00b_synthetic_idp_issuer(n00b_synthetic_idp_t *s) { return s ? s->issuer : nullptr; }
const char *n00b_synthetic_idp_kid(n00b_synthetic_idp_t *s)    { return s ? s->kid    : nullptr; }
n00b_oidc_t *n00b_synthetic_idp_oidc(n00b_synthetic_idp_t *s)   { return s ? s->oidc   : nullptr; }
n00b_quic_secret_t *n00b_synthetic_idp_signer(n00b_synthetic_idp_t *s) { return s ? s->signer : nullptr; }

char *
n00b_synthetic_idp_mint(n00b_synthetic_idp_t *s,
                        const char           *subject,
                        const char           *audience,
                        int64_t               exp_offset_s) _kargs
{
    const char    *scope        = nullptr;
    const char    *role         = nullptr;
    const uint8_t *cnf_x5t_s256 = nullptr;
}
{
    if (!s || !subject || !audience) return nullptr;

    /* Build the protected header. */
    char hdr[256];
    snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"%s\"}", s->kid);

    /* Build the payload.  Optional fields appended only when set. */
    char  *pl     = malloc(2048);
    size_t off    = 0;
    int64_t exp   = (int64_t)time(nullptr) + exp_offset_s;
    off += snprintf(pl + off, 2048 - off,
                    "{\"iss\":\"%s\",\"aud\":\"%s\",\"sub\":\"%s\","
                    "\"exp\":%lld",
                    s->issuer, audience, subject, (long long)exp);
    if (scope) {
        off += snprintf(pl + off, 2048 - off, ",\"scope\":\"%s\"", scope);
    }
    if (role) {
        off += snprintf(pl + off, 2048 - off, ",\"role\":\"%s\"", role);
    }
    if (cnf_x5t_s256) {
        char *fp_b64 = n00b_b64url_encode(cnf_x5t_s256, 32);
        off += snprintf(pl + off, 2048 - off,
                        ",\"cnf\":{\"x5t#S256\":\"%s\"}", fp_b64);
    }
    off += snprintf(pl + off, 2048 - off, "}");

    /* base64url + sign + assemble. */
    char *h_b64 = n00b_b64url_encode((const uint8_t *)hdr, strlen(hdr));
    char *p_b64 = n00b_b64url_encode((const uint8_t *)pl,  strlen(pl));
    size_t ilen = strlen(h_b64) + 1 + strlen(p_b64);
    char  *input = malloc(ilen + 1);
    snprintf(input, ilen + 1, "%s.%s", h_b64, p_b64);
    n00b_buffer_t *msg = n00b_buffer_from_bytes(input, (int64_t)ilen);
    auto sr = n00b_quic_secret_sign(s->signer, msg, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sr)) {
        free(pl); free(input);
        return nullptr;
    }
    n00b_buffer_t *sig = n00b_result_get(sr);
    char *s_b64 = n00b_b64url_encode((const uint8_t *)sig->data,
                                     (size_t)sig->byte_len);
    size_t total = ilen + 1 + strlen(s_b64);
    char  *out   = n00b_alloc_array_with_opts(char, (int64_t)(total + 1),
        &(n00b_alloc_opts_t){.allocator = si_alloc(), .no_scan = true});
    snprintf(out, total + 1, "%s.%s", input, s_b64);
    free(pl); free(input);
    return out;
}

void
n00b_synthetic_idp_close(n00b_synthetic_idp_t *s)
{
    if (!s) return;
    if (s->oidc) {
        n00b_oidc_close(s->oidc);
        s->oidc = nullptr;
    }
    if (s->signer) {
        n00b_quic_secret_close(s->signer);
        s->signer = nullptr;
    }
    /* issuer / kid / jwks_json released with the conduit pool. */
}
