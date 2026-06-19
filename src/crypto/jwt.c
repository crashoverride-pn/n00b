/*
 * jwt.c — JWT validation: parse compact JWS, verify signature, run
 *         claim checks.  Phase 3 § 6.
 *
 * Algorithms supported by this file directly: ES256.  RS256/RS384/
 * RS512 land via `rsa_verify.c` — the dispatch in `verify_signature`
 * picks the path based on the JWS header's `alg`.
 *
 * Allocation discipline: everything from JWK parsing through the
 * returned claims lives in the conduit pool.  Fresh on every
 * `n00b_jwt_verify` call; the verifier handle itself is also
 * conduit-pool-backed.
 */

#define N00B_USE_INTERNAL_API
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "adt/list.h"
#include "adt/result.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "crypto/jwt.h"
#include "internal/crypto/jws.h"
#include "internal/crypto/rsa_pkcs1.h"

#include "uECC.h"

/* ===========================================================================
 * Allocator
 * =========================================================================== */

static n00b_allocator_t *
jwt_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
jwt_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t n = strlen(s);
    char *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                           &(n00b_alloc_opts_t){
                                               .allocator = jwt_alloc(),
                                               .no_scan   = true,
                                           });
    memcpy(out, s, n + 1);
    return out;
}

/* ===========================================================================
 * JSON helpers
 *
 * Phase 2's JSON parser surfaces a tagged `n00b_json_node_t` (see
 * `parsers/json.h`).  We adopt the same accessor shape ACME's
 * directory parser uses (`json_obj_get`, etc.).
 * =========================================================================== */

static n00b_json_node_t *
json_get(n00b_json_node_t *obj, const char *key)
{
    return n00b_json_object_get_cstr(obj, key);
}

static const char *
json_get_string(n00b_json_node_t *obj, const char *key)
{
    n00b_json_node_t *v = json_get(obj, key);
    return n00b_json_as_cstr(v);
}

static int64_t
json_get_int(n00b_json_node_t *obj, const char *key, int64_t fallback)
{
    n00b_json_node_t *v = json_get(obj, key);
    if (!v) return fallback;
    if (n00b_json_is_int(v))    return n00b_json_as_i64(v);
    if (n00b_json_is_double(v)) return (int64_t)n00b_json_as_f64(v);
    return fallback;
}

static n00b_json_node_t *
json_get_array(n00b_json_node_t *obj, const char *key)
{
    n00b_json_node_t *v = json_get(obj, key);
    return (v && n00b_json_is_array(v)) ? v : nullptr;
}

/* ===========================================================================
 * JWK (set) parsing
 * =========================================================================== */

static int
parse_jwk_one(n00b_json_node_t *jv, n00b_jwk_t *out)
{
    if (!jv || !n00b_json_is_object(jv)) return -1;
    const char *kty = json_get_string(jv, "kty");
    if (!kty) return -1;

    out->kty = jwt_strdup(kty);
    out->kid = jwt_strdup(json_get_string(jv, "kid"));
    out->alg = jwt_strdup(json_get_string(jv, "alg"));

    if (strcmp(kty, "EC") == 0) {
        const char *crv = json_get_string(jv, "crv");
        if (!crv || strcmp(crv, "P-256") != 0) return -1;
        out->crv = jwt_strdup(crv);
        const char *x = json_get_string(jv, "x");
        const char *y = json_get_string(jv, "y");
        if (!x || !y) return -1;
        auto xr = n00b_b64url_decode(x, strlen(x));
        auto yr = n00b_b64url_decode(y, strlen(y));
        if (!n00b_result_is_ok(xr) || !n00b_result_is_ok(yr)) return -1;
        n00b_buffer_t *xb = n00b_result_get(xr);
        n00b_buffer_t *yb = n00b_result_get(yr);
        if (xb->byte_len != 32 || yb->byte_len != 32) return -1;
        memcpy(out->ec_x, xb->data, 32);
        memcpy(out->ec_y, yb->data, 32);
        out->ec_coord_len = 32;
        return 0;
    }
    if (strcmp(kty, "RSA") == 0) {
        const char *n_b64 = json_get_string(jv, "n");
        const char *e_b64 = json_get_string(jv, "e");
        if (!n_b64 || !e_b64) return -1;
        auto nr = n00b_b64url_decode(n_b64, strlen(n_b64));
        auto er = n00b_b64url_decode(e_b64, strlen(e_b64));
        if (!n00b_result_is_ok(nr) || !n00b_result_is_ok(er)) return -1;
        n00b_buffer_t *nb = n00b_result_get(nr);
        n00b_buffer_t *eb = n00b_result_get(er);
        out->rsa_n_len = (size_t)nb->byte_len;
        out->rsa_n     = n00b_alloc_array_with_opts(uint8_t,
                            (int64_t)out->rsa_n_len,
                            &(n00b_alloc_opts_t){.allocator = jwt_alloc(),
                                                 .no_scan   = true});
        memcpy(out->rsa_n, nb->data, out->rsa_n_len);
        out->rsa_e_len = (size_t)eb->byte_len;
        out->rsa_e     = n00b_alloc_array_with_opts(uint8_t,
                            (int64_t)out->rsa_e_len,
                            &(n00b_alloc_opts_t){.allocator = jwt_alloc(),
                                                 .no_scan   = true});
        memcpy(out->rsa_e, eb->data, out->rsa_e_len);
        return 0;
    }
    return -1;
}

n00b_result_t(n00b_jwk_set_t *)
n00b_jwk_set_parse(const char *json)
{
    if (!json) {
        return n00b_result_err(n00b_jwk_set_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    const char *err = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);
    if (!root) {
        return n00b_result_err(n00b_jwk_set_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_json_node_t *keys = json_get_array(root, "keys");
    if (!keys) {
        return n00b_result_err(n00b_jwk_set_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    int64_t          n_keys = (int64_t)n00b_json_array_len(keys);
    n00b_jwk_set_t  *set    = n00b_alloc_with_opts(n00b_jwk_set_t,
                                  &(n00b_alloc_opts_t){.allocator = jwt_alloc()});
    set->keys  = n00b_alloc_array_with_opts(n00b_jwk_t *, n_keys,
                     &(n00b_alloc_opts_t){.allocator = jwt_alloc()});
    set->count = 0;
    for (int64_t i = 0; i < n_keys; i++) {
        n00b_json_node_t *kn = n00b_json_array_get(keys, (size_t)i);
        n00b_jwk_t *k = n00b_alloc_with_opts(n00b_jwk_t,
                            &(n00b_alloc_opts_t){.allocator = jwt_alloc()});
        if (parse_jwk_one(kn, k) == 0) {
            set->keys[set->count++] = k;
        }
        /* Else: silently skip unsupported kty. */
    }
    return n00b_result_ok(n00b_jwk_set_t *, set);
}

n00b_option_t(n00b_jwk_t *)
n00b_jwk_set_lookup(n00b_jwk_set_t *set, const char *kid)
{
    if (!set) return n00b_option_none(n00b_jwk_t *);
    if (kid) {
        for (size_t i = 0; i < set->count; i++) {
            if (set->keys[i]->kid && strcmp(set->keys[i]->kid, kid) == 0) {
                return n00b_option_set(n00b_jwk_t *, set->keys[i]);
            }
        }
        return n00b_option_none(n00b_jwk_t *);
    }
    /* kid-less lookup.  We're strict about ambiguity: only return a
     * key when there's exactly ONE kid-less key in the set, OR when
     * the set has exactly one key total (regardless of kid).  When
     * multiple keys exist and the JWS omits kid, returning ANY of
     * them is a confused-deputy risk — an attacker who can choose
     * which kid is omitted would let us validate against whichever
     * key in the set happens to come first.  Refuse instead. */
    if (set->count == 1) return n00b_option_set(n00b_jwk_t *, set->keys[0]);
    n00b_jwk_t *kidless = nullptr;
    size_t      kidless_count = 0;
    for (size_t i = 0; i < set->count; i++) {
        if (!set->keys[i]->kid) {
            kidless = set->keys[i];
            kidless_count++;
        }
    }
    if (kidless_count == 1) {
        return n00b_option_set(n00b_jwk_t *, kidless);
    }
    return n00b_option_none(n00b_jwk_t *);
}

/* ===========================================================================
 * Compact JWS parser
 * =========================================================================== */

typedef struct {
    char          *header_b64;
    char          *payload_b64;
    char          *sig_b64;
    n00b_buffer_t *header_decoded;
    n00b_buffer_t *payload_decoded;
    n00b_buffer_t *sig_decoded;
    char          *signing_input;
    size_t         signing_input_len;
} jws_parts_t;

static int
parse_compact(const char *jws, jws_parts_t *out)
{
    if (!jws) return -1;
    const char *first = strchr(jws, '.');
    if (!first) return -1;
    const char *second = strchr(first + 1, '.');
    if (!second) return -1;
    const char *third = strchr(second + 1, '.');
    if (third) return -1;

    size_t h_len = (size_t)(first - jws);
    size_t p_len = (size_t)(second - (first + 1));
    size_t s_len = strlen(second + 1);

    n00b_allocator_t *al = jwt_alloc();

    out->header_b64  = n00b_alloc_array_with_opts(char, (int64_t)(h_len + 1),
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    out->payload_b64 = n00b_alloc_array_with_opts(char, (int64_t)(p_len + 1),
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    out->sig_b64     = n00b_alloc_array_with_opts(char, (int64_t)(s_len + 1),
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    memcpy(out->header_b64,  jws,         h_len); out->header_b64[h_len]  = '\0';
    memcpy(out->payload_b64, first + 1,   p_len); out->payload_b64[p_len] = '\0';
    memcpy(out->sig_b64,     second + 1,  s_len); out->sig_b64[s_len]     = '\0';

    auto hr = n00b_b64url_decode(out->header_b64,  h_len);
    auto pr = n00b_b64url_decode(out->payload_b64, p_len);
    auto sr = n00b_b64url_decode(out->sig_b64,     s_len);
    if (!n00b_result_is_ok(hr) || !n00b_result_is_ok(pr)
        || !n00b_result_is_ok(sr)) {
        return -1;
    }
    out->header_decoded  = n00b_result_get(hr);
    out->payload_decoded = n00b_result_get(pr);
    out->sig_decoded     = n00b_result_get(sr);

    out->signing_input_len = h_len + 1 + p_len;
    out->signing_input = n00b_alloc_array_with_opts(char,
        (int64_t)(out->signing_input_len + 1),
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    memcpy(out->signing_input, jws, out->signing_input_len);
    out->signing_input[out->signing_input_len] = '\0';
    return 0;
}

/* ===========================================================================
 * Signature verification (per-alg dispatch)
 * =========================================================================== */

static int
verify_es256(n00b_jwk_t *jwk, const uint8_t *msg, size_t msg_len,
             const uint8_t *sig, size_t sig_len)
{
    if (!jwk || strcmp(jwk->kty, "EC") != 0
        || !jwk->crv || strcmp(jwk->crv, "P-256") != 0) {
        return N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND;
    }
    if (sig_len != 64) return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;

    uint8_t pub[64];
    memcpy(pub,      jwk->ec_x, 32);
    memcpy(pub + 32, jwk->ec_y, 32);

    uint8_t digest[32];
    {
        n00b_sha256_digest_t words;
        n00b_sha256_hash(msg, msg_len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            digest[i*4]     = (uint8_t)(w >> 24);
            digest[i*4 + 1] = (uint8_t)(w >> 16);
            digest[i*4 + 2] = (uint8_t)(w >> 8);
            digest[i*4 + 3] = (uint8_t)w;
        }
    }
    int ok = uECC_verify(pub, digest, 32, sig, uECC_secp256r1());
    return ok ? N00B_QUIC_OK : N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
}

/* ===========================================================================
 * Verifier
 * =========================================================================== */

struct n00b_jwt_verifier {
    char                    *expected_audience;
    char                    *expected_issuer;
    int32_t                  leeway_seconds;
    n00b_jwt_resolve_key_fn  resolve_key;
    void                    *resolve_key_ctx;
};

n00b_result_t(n00b_jwt_verifier_t *)
n00b_jwt_verifier_new() _kargs
{
    const char              *expected_audience = nullptr;
    const char              *expected_issuer   = nullptr;
    int32_t                  leeway_seconds    = 60;
    n00b_jwt_resolve_key_fn  resolve_key       = nullptr;
    void                    *resolve_key_ctx   = nullptr;
}
{
    if (!expected_audience || !resolve_key) {
        return n00b_result_err(n00b_jwt_verifier_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_jwt_verifier_t *v = n00b_alloc_with_opts(n00b_jwt_verifier_t,
        &(n00b_alloc_opts_t){.allocator = jwt_alloc()});
    v->expected_audience = jwt_strdup(expected_audience);
    v->expected_issuer   = jwt_strdup(expected_issuer);
    v->leeway_seconds    = leeway_seconds;
    v->resolve_key       = resolve_key;
    v->resolve_key_ctx   = resolve_key_ctx;
    return n00b_result_ok(n00b_jwt_verifier_t *, v);
}

static bool
aud_array_has(n00b_json_node_t *arr, const char *want)
{
    if (!arr || !n00b_json_is_array(arr)) return false;
    int64_t n = (int64_t)n00b_json_array_len(arr);
    for (int64_t i = 0; i < n; i++) {
        n00b_json_node_t *v = n00b_json_array_get(arr, (size_t)i);
        const char       *s = n00b_json_as_cstr(v);
        if (s != nullptr && strcmp(s, want) == 0) {
            return true;
        }
    }
    return false;
}

n00b_result_t(n00b_jwt_claims_t *)
n00b_jwt_verify(n00b_jwt_verifier_t *v, const char *compact_jws)
{
    if (!v || !compact_jws) {
        return n00b_result_err(n00b_jwt_claims_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    jws_parts_t parts;
    memset(&parts, 0, sizeof(parts));
    if (parse_compact(compact_jws, &parts) != 0) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    }

    /* Parse the protected header to read alg + kid. */
    char *hdr_json = n00b_alloc_array_with_opts(char,
        (int64_t)(parts.header_decoded->byte_len + 1),
        &(n00b_alloc_opts_t){.allocator = jwt_alloc(), .no_scan = true});
    memcpy(hdr_json, parts.header_decoded->data,
           (size_t)parts.header_decoded->byte_len);
    hdr_json[parts.header_decoded->byte_len] = '\0';

    const char *jerr = nullptr;
    n00b_json_node_t *hdr = n00b_json_parse(hdr_json,
        (size_t)parts.header_decoded->byte_len, &jerr);
    if (!hdr) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    }
    const char *alg = json_get_string(hdr, "alg");
    const char *kid = json_get_string(hdr, "kid");
    if (!alg) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    }
    /* RFC 7515 § 4.1.1 / § 8.5: `alg=none` is a known attack vector;
     * we never accept it.  HS* is also refused. */
    if (strcmp(alg, "none") == 0
        || strcmp(alg, "HS256") == 0
        || strcmp(alg, "HS384") == 0
        || strcmp(alg, "HS512") == 0) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_ALG_REFUSED);
    }

    /* RFC 7515 § 4.1.11: any header parameter named in `crit` is an
     * extension the verifier MUST understand.  We don't implement any
     * extensions, so the presence of `crit` (non-empty) means we must
     * refuse the token.  Without this check, a producer could include
     * a critical parameter (e.g. nested replay-protection) that we'd
     * silently ignore. */
    n00b_json_node_t *crit = json_get_array(hdr, "crit");
    if (crit) {
        int64_t n_crit = (int64_t)n00b_json_array_len(crit);
        if (n_crit > 0) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   N00B_QUIC_ERR_AUTH_ALG_REFUSED);
        }
    }

    n00b_jwk_t *key = v->resolve_key(v->resolve_key_ctx, kid, alg);
    if (!key) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND);
    }

    int sig_rc = N00B_QUIC_ERR_AUTH_ALG_REFUSED;
    if (strcmp(alg, "ES256") == 0) {
        sig_rc = verify_es256(key,
                              (const uint8_t *)parts.signing_input,
                              parts.signing_input_len,
                              (const uint8_t *)parts.sig_decoded->data,
                              (size_t)parts.sig_decoded->byte_len);
    } else if (strcmp(alg, "RS256") == 0
               || strcmp(alg, "RS384") == 0
               || strcmp(alg, "RS512") == 0) {
        sig_rc = n00b_rsa_verify_pkcs1_v15(key, alg,
                                           (const uint8_t *)parts.signing_input,
                                           parts.signing_input_len,
                                           (const uint8_t *)parts.sig_decoded->data,
                                           (size_t)parts.sig_decoded->byte_len);
    } else {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_ALG_REFUSED);
    }
    if (sig_rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_jwt_claims_t *, sig_rc);
    }

    /* Parse the payload JSON to populate claims. */
    char *pl_json = n00b_alloc_array_with_opts(char,
        (int64_t)(parts.payload_decoded->byte_len + 1),
        &(n00b_alloc_opts_t){.allocator = jwt_alloc(), .no_scan = true});
    memcpy(pl_json, parts.payload_decoded->data,
           (size_t)parts.payload_decoded->byte_len);
    pl_json[parts.payload_decoded->byte_len] = '\0';

    n00b_json_node_t *pl = n00b_json_parse(pl_json,
        (size_t)parts.payload_decoded->byte_len, &jerr);
    if (!pl) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    }

    n00b_jwt_claims_t *claims = n00b_alloc_with_opts(n00b_jwt_claims_t,
        &(n00b_alloc_opts_t){.allocator = jwt_alloc()});
    claims->iss = jwt_strdup(json_get_string(pl, "iss"));
    claims->sub = jwt_strdup(json_get_string(pl, "sub"));
    claims->jti = jwt_strdup(json_get_string(pl, "jti"));
    claims->raw_payload_json = pl_json;

    const char       *aud_str = json_get_string(pl, "aud");
    n00b_json_node_t *aud_arr = json_get_array(pl, "aud");

    int64_t iat = json_get_int(pl, "iat", 0);
    int64_t nbf = json_get_int(pl, "nbf", 0);
    int64_t exp = json_get_int(pl, "exp", 0);
    claims->iat_ms = iat ? iat * 1000 : 0;
    claims->nbf_ms = nbf ? nbf * 1000 : 0;
    claims->exp_ms = exp ? exp * 1000 : 0;

    /* RFC 8705 § 3.1 — `cnf.x5t#S256` carries the b64url(SHA-256)
     * of the client cert.  Surface it as raw bytes for the
     * mtls_token_verify path. */
    claims->has_cnf_x5t_s256 = false;
    n00b_json_node_t *cnf = json_get(pl, "cnf");
    if (cnf && n00b_json_is_object(cnf)) {
        const char *x5t = json_get_string(cnf, "x5t#S256");
        if (x5t) {
            auto dr = n00b_b64url_decode(x5t, strlen(x5t));
            if (n00b_result_is_ok(dr)) {
                n00b_buffer_t *db = n00b_result_get(dr);
                if (db->byte_len == 32) {
                    memcpy(claims->cnf_x5t_s256, db->data, 32);
                    claims->has_cnf_x5t_s256 = true;
                }
            }
        }
    }

    if (v->expected_issuer) {
        if (!claims->iss
            || strcmp(claims->iss, v->expected_issuer) != 0) {
            return n00b_result_err(n00b_jwt_claims_t *,
                                   N00B_QUIC_ERR_AUTH_ISS_MISMATCH);
        }
    }

    bool aud_ok = false;
    if (aud_str && strcmp(aud_str, v->expected_audience) == 0) {
        aud_ok = true;
        claims->aud = jwt_strdup(aud_str);
    } else if (aud_arr && aud_array_has(aud_arr, v->expected_audience)) {
        aud_ok = true;
    }
    if (!aud_ok) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_AUD_MISMATCH);
    }

    int64_t now_ms = (int64_t)(n00b_us_timestamp() / 1000);
    int64_t skew   = (int64_t)v->leeway_seconds * 1000;
    if (claims->exp_ms != 0 && now_ms > claims->exp_ms + skew) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_EXPIRED);
    }
    if (claims->nbf_ms != 0 && now_ms + skew < claims->nbf_ms) {
        return n00b_result_err(n00b_jwt_claims_t *,
                               N00B_QUIC_ERR_AUTH_TOKEN_INVALID);
    }

    return n00b_result_ok(n00b_jwt_claims_t *, claims);
}
