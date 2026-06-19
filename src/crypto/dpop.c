/*
 * dpop.c — DPoP proof issue + verify (RFC 9449).
 *
 * Issue:
 *   - Build header   {"typ":"dpop+jwt","alg":"ES256","jwk":<jwk>}
 *   - Build payload  {"jti":<rand>,"htm":<m>,"htu":<u>,"iat":<now>[,"nonce":<n>]}
 *   - Sign header.payload with the holder secret (ES256).
 *   - Concatenate b64url(header).b64url(payload).b64url(sig).
 *
 * Verify:
 *   - Parse compact JWS; check typ/alg.
 *   - Extract embedded JWK; verify sig using ES256 path from
 *     `jwt.c::verify_es256` (called via direct link, not the
 *     full `n00b_jwt_verify` — DPoP isn't a "JWT" semantically;
 *     it doesn't have iss/aud).
 *   - Validate htm, htu, iat, nonce.
 *   - Optional: jkt thumbprint comparison.
 *   - Optional: replay store insert (jti must be fresh).
 *
 * Replay store: open-addressing hash with FIFO eviction.  At
 * capacity (default 1024), oldest jti gets evicted to make room.
 * Mutex-protected.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/hash.h"
#include "adt/result.h"
#include "adt/dict.h"
#include "parsers/json.h"
#include "net/quic/quic_types.h"
#include "net/quic/secret.h"
#include "crypto/jwt.h"
#include "crypto/dpop.h"
#include "internal/crypto/jws.h"

#include "uECC.h"

/* ===========================================================================
 * Allocator
 * =========================================================================== */

static n00b_allocator_t *
dpop_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
dpop_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t n = strlen(s);
    char *out = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                           &(n00b_alloc_opts_t){
                                               .allocator = dpop_alloc(),
                                               .no_scan   = true,
                                           });
    memcpy(out, s, n + 1);
    return out;
}

/* ===========================================================================
 * Replay store
 * =========================================================================== */

/* Replay store: O(1) presence check via n00b_dict_t keyed by
 * jti string, plus a fixed-size ring buffer holding the eviction
 * order.  Every operation is O(1) regardless of capacity:
 *
 *   - Lookup → n00b_dict_contains.
 *   - Insert (not full) → dict_put + ring[head++].
 *   - Insert (full) → dict_remove(ring[tail]) → ring[tail++] = new;
 *     head also advances.  No O(n) list-shift.
 *
 * The previous implementation used n00b_list_delete(fifo, 0) for the
 * oldest-eviction step, which is O(n) because the underlying array
 * shifts every element down by one.  At capacity 1024 under sustained
 * pressure that's ~1024 word-moves per insert — fine for tests, not
 * fine for production DPoP traffic. */
struct n00b_dpop_replay_store {
    n00b_dict_t(n00b_string_t *, int) *seen; /* n00b_string_t * → 1. */
    n00b_string_t      **ring;        /* capacity slots; nullptr when empty. */
    int32_t              capacity;
    int32_t              head;        /* next insert slot. */
    int32_t              tail;        /* oldest entry, evicted next at full. */
    int32_t              size;        /* live entries in [0, capacity]. */
    n00b_rwlock_t       *mu;
    bool                 closed;
};

n00b_dpop_replay_store_t *
n00b_dpop_replay_store_new() _kargs
{
    int32_t capacity = 1024;
}
{
    if (capacity <= 0) capacity = 1024;
    n00b_dpop_replay_store_t *s = n00b_alloc_with_opts(n00b_dpop_replay_store_t,
        &(n00b_alloc_opts_t){.allocator = dpop_alloc()});
    s->seen = n00b_alloc_with_opts(n00b_dict_t(n00b_string_t *, int),
        &(n00b_alloc_opts_t){.allocator = dpop_alloc()});
    n00b_dict_init(s->seen,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .allocator     = dpop_alloc(),
                   .locked        = false);
    s->ring     = n00b_alloc_array_with_opts(n00b_string_t *,
                      (int64_t)capacity,
                      &(n00b_alloc_opts_t){.allocator = dpop_alloc()});
    s->capacity = capacity;
    s->head     = 0;
    s->tail     = 0;
    s->size     = 0;
    s->mu       = n00b_data_lock_new();
    return s;
}

void
n00b_dpop_replay_store_close(n00b_dpop_replay_store_t *s)
{
    if (!s || s->closed) return;
    n00b_data_write_lock(s->mu);
    s->closed = true;
    n00b_data_unlock(s->mu);
}

/* Returns 1 if jti was already present (replay!); 0 if newly inserted. */
static int
replay_check_and_insert(n00b_dpop_replay_store_t *s, const char *jti)
{
    n00b_data_write_lock(s->mu);
    if (s->closed) {
        n00b_data_unlock(s->mu);
        return 0;  /* closed: behave as "not seen" */
    }
    n00b_string_t *key = n00b_string_from_cstr(jti);
    if (n00b_dict_contains(s->seen, key)) {
        n00b_data_unlock(s->mu);
        return 1;
    }
    /* Evict oldest if at capacity.  O(1) — just advance the tail
     * pointer and drop the dict entry for the slot we're about to
     * overwrite. */
    if (s->size == s->capacity) {
        n00b_string_t *oldest = s->ring[s->tail];
        n00b_dict_remove(s->seen, oldest);
        s->tail = (s->tail + 1) % s->capacity;
        s->size--;
    }
    /* Insert new entry. */
    s->ring[s->head] = key;
    s->head = (s->head + 1) % s->capacity;
    s->size++;
    int present = 1;
    n00b_dict_put(s->seen, key, present);
    n00b_data_unlock(s->mu);
    return 0;
}

/* ===========================================================================
 * Issue
 * =========================================================================== */

/* Build a 32-byte hex jti. */
static char *
mk_jti(void)
{
    uint8_t bytes[16];
    n00b_random_bytes((char *)bytes, sizeof(bytes));
    char *out = n00b_alloc_array_with_opts(char, 33,
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i*2]     = hex[(bytes[i] >> 4) & 0xf];
        out[i*2 + 1] = hex[ bytes[i]       & 0xf];
    }
    out[32] = '\0';
    return out;
}

n00b_result_t(char *)
n00b_dpop_create(n00b_quic_secret_t *holder_key,
                 const char         *htm,
                 const char         *htu) _kargs
{
    const char    *nonce            = nullptr;
    const uint8_t *access_token     = nullptr;
    size_t         access_token_len = 0;
}
{
    if (!holder_key || !htm || !htu) {
        return n00b_result_err(char *, N00B_QUIC_ERR_NULL_ARG);
    }
    /* 1. Get the holder's public key (X || Y). */
    auto pkr = n00b_quic_secret_pubkey(holder_key, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(pkr)) {
        return n00b_result_err(char *, N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND);
    }
    n00b_buffer_t *pk = n00b_result_get(pkr);
    if (pk->byte_len != 64) {
        return n00b_result_err(char *, N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND);
    }

    /* 2. Build the JWK JSON via the existing helper.  Note: the
     *    canonical JWK is the same bytes used for the thumbprint. */
    char *jwk_json = n00b_jwk_p256_canonical((const uint8_t *)pk->data);

    /* 3. Build the header.  RFC 9449 § 4.2: alg=ES256, typ=dpop+jwt,
     *    jwk=<jwk>. */
    size_t hdr_cap = strlen(jwk_json) + 256;
    char  *hdr     = n00b_alloc_array_with_opts(char, (int64_t)hdr_cap,
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    snprintf(hdr, hdr_cap,
             "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":%s}",
             jwk_json);

    /* 4. Build the payload.
     *
     * Optional `ath` claim (RFC 9449 § 4.3): when access_token is set,
     * compute b64url(SHA-256(access_token)) and embed.  Required for
     * any DPoP proof presented alongside an access token. */
    char *ath_b64 = nullptr;
    if (access_token && access_token_len > 0) {
        uint8_t ath_hash[32];
        n00b_sha256_digest_t words;
        n00b_sha256_hash(access_token, access_token_len, words);
        for (int i = 0; i < 8; i++) {
            uint32_t w = words[i];
            ath_hash[i*4]     = (uint8_t)(w >> 24);
            ath_hash[i*4 + 1] = (uint8_t)(w >> 16);
            ath_hash[i*4 + 2] = (uint8_t)(w >> 8);
            ath_hash[i*4 + 3] = (uint8_t)w;
        }
        ath_b64 = n00b_b64url_encode(ath_hash, 32);
    }

    char  *jti    = mk_jti();
    int64_t iat   = n00b_us_timestamp() / N00B_USEC_PER_SEC;
    size_t pl_cap = strlen(jti) + strlen(htm) + strlen(htu)
                  + (nonce ? strlen(nonce) : 0)
                  + (ath_b64 ? strlen(ath_b64) : 0)
                  + 256;
    char  *pl     = n00b_alloc_array_with_opts(char, (int64_t)pl_cap,
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    /* Build payload incrementally to keep the four-way switch readable. */
    int off = snprintf(pl, pl_cap,
                       "{\"jti\":\"%s\",\"htm\":\"%s\",\"htu\":\"%s\","
                       "\"iat\":%lld",
                       jti, htm, htu, (long long)iat);
    if (nonce) {
        off += snprintf(pl + off, pl_cap - (size_t)off,
                        ",\"nonce\":\"%s\"", nonce);
    }
    if (ath_b64) {
        off += snprintf(pl + off, pl_cap - (size_t)off,
                        ",\"ath\":\"%s\"", ath_b64);
    }
    snprintf(pl + off, pl_cap - (size_t)off, "}");

    /* 5. base64url + sign. */
    char *h_b64 = n00b_b64url_encode((const uint8_t *)hdr, strlen(hdr));
    char *p_b64 = n00b_b64url_encode((const uint8_t *)pl,  strlen(pl));
    size_t ilen = strlen(h_b64) + 1 + strlen(p_b64);
    char  *input = n00b_alloc_array_with_opts(char, (int64_t)(ilen + 1),
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    snprintf(input, ilen + 1, "%s.%s", h_b64, p_b64);
    n00b_buffer_t *msg = n00b_buffer_from_bytes(input, (int64_t)ilen);
    auto sr = n00b_quic_secret_sign(holder_key, msg, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sr)) {
        return n00b_result_err(char *, N00B_QUIC_ERR_HANDSHAKE);
    }
    n00b_buffer_t *sig = n00b_result_get(sr);
    char *s_b64 = n00b_b64url_encode((const uint8_t *)sig->data,
                                     (size_t)sig->byte_len);

    size_t total = ilen + 1 + strlen(s_b64);
    char  *out   = n00b_alloc_array_with_opts(char, (int64_t)(total + 1),
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    snprintf(out, total + 1, "%s.%s", input, s_b64);

    return n00b_result_ok(char *, out);
}

/* ===========================================================================
 * Verify
 * =========================================================================== */

/* Compact JWS parse helper (mirrors jwt.c's parse_compact). */
typedef struct {
    char          *header_b64;
    char          *payload_b64;
    char          *sig_b64;
    n00b_buffer_t *header_decoded;
    n00b_buffer_t *payload_decoded;
    n00b_buffer_t *sig_decoded;
    char          *signing_input;
    size_t         signing_input_len;
} dpop_parts_t;

static int
parse_compact_dpop(const char *jws, dpop_parts_t *out)
{
    if (!jws) return -1;
    const char *first = strchr(jws, '.');
    if (!first) return -1;
    const char *second = strchr(first + 1, '.');
    if (!second) return -1;
    if (strchr(second + 1, '.')) return -1;

    size_t h_len = (size_t)(first - jws);
    size_t p_len = (size_t)(second - (first + 1));
    size_t s_len = strlen(second + 1);

    n00b_allocator_t *al = dpop_alloc();

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
        || !n00b_result_is_ok(sr)) return -1;
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

/* Walk the embedded "jwk" object to extract EC P-256 X/Y. */
static int
extract_jwk_xy(n00b_json_node_t *hdr, uint8_t x[32], uint8_t y[32])
{
    if (!hdr || !n00b_json_is_object(hdr)) return -1;
    n00b_json_node_t *jwk = n00b_json_object_get_cstr(hdr, "jwk");
    if (!jwk || !n00b_json_is_object(jwk)) return -1;

    const char *kty = n00b_json_as_cstr(n00b_json_object_get_cstr(jwk, "kty"));
    const char *crv = n00b_json_as_cstr(n00b_json_object_get_cstr(jwk, "crv"));
    const char *xs  = n00b_json_as_cstr(n00b_json_object_get_cstr(jwk, "x"));
    const char *ys  = n00b_json_as_cstr(n00b_json_object_get_cstr(jwk, "y"));
    if (!kty || strcmp(kty, "EC") != 0) return -1;
    if (!crv || strcmp(crv, "P-256") != 0) return -1;
    if (!xs || !ys) return -1;
    auto xr = n00b_b64url_decode(xs, strlen(xs));
    auto yr = n00b_b64url_decode(ys, strlen(ys));
    if (!n00b_result_is_ok(xr) || !n00b_result_is_ok(yr)) return -1;
    n00b_buffer_t *xb = n00b_result_get(xr);
    n00b_buffer_t *yb = n00b_result_get(yr);
    if (xb->byte_len != 32 || yb->byte_len != 32) return -1;
    memcpy(x, xb->data, 32);
    memcpy(y, yb->data, 32);
    return 0;
}

/* RFC 9449 § 4.2 htu canonicalization: drop userinfo, query, and
 * fragment; lowercase scheme + host; drop default port (443 for
 * https, 80 for http); preserve IPv6 literal brackets.
 *
 * Output goes into a caller-provided buffer.  Returns the canonical
 * length, or 0 on bad input.  Buffer must be sized to at least
 * strlen(url) + 1. */
static size_t
canonicalize_htu(const char *url, char *out, size_t out_cap)
{
    if (!url || !out || out_cap == 0) return 0;
    size_t n = strlen(url);
    if (n + 1 > out_cap) return 0;

    /* Find scheme ("://"). */
    const char *sep = strstr(url, "://");
    if (!sep) {
        /* No scheme — copy verbatim (let strcmp catch mismatches). */
        memcpy(out, url, n);
        out[n] = '\0';
        return n;
    }
    size_t scheme_len = (size_t)(sep - url);
    /* Lowercase scheme. */
    for (size_t i = 0; i < scheme_len; i++) {
        char c = url[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        out[i] = c;
    }
    out[scheme_len] = ':';
    out[scheme_len + 1] = '/';
    out[scheme_len + 2] = '/';
    size_t op = scheme_len + 3;
    bool is_https = (scheme_len == 5
                     && out[0] == 'h' && out[1] == 't' && out[2] == 't'
                     && out[3] == 'p' && out[4] == 's');
    bool is_http  = (scheme_len == 4
                     && out[0] == 'h' && out[1] == 't' && out[2] == 't'
                     && out[3] == 'p');

    /* Authority section: [userinfo "@"] host [":" port].
     *
     * Strip userinfo: scan ahead for an "@" before any '/', '?', '#'.
     * RFC 9449 § 4.2 says htu MUST NOT include userinfo, so we drop
     * it on both sides of the comparison. */
    const char *p = sep + 3;
    {
        const char *scan = p;
        const char *at   = nullptr;
        while (*scan && *scan != '/' && *scan != '?' && *scan != '#') {
            if (*scan == '@') {
                at = scan;
                /* Don't break — last '@' wins in case userinfo
                 * contains a percent-encoded '@'. */
            }
            scan++;
        }
        if (at) p = at + 1;
    }

    /* Host: either IPv6 literal "[...]" copied verbatim (case
     * preserved in literal-IPv6 — hex digits aren't case-sensitive,
     * but RFC 3986 § 3.2.2 says the brackets bound the host token),
     * or a regular hostname we lowercase. */
    if (*p == '[') {
        /* IPv6 literal: copy up through the closing ']'. */
        out[op++] = *p++;
        while (*p && *p != ']') {
            char c = *p++;
            /* Lowercase hex digits a-f for canonicalization
             * (RFC 5952 prefers lowercase). */
            if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
            out[op++] = c;
        }
        if (*p == ']') out[op++] = *p++;
    } else {
        while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#') {
            char c = *p++;
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            out[op++] = c;
        }
    }

    /* Port: drop if default. */
    if (*p == ':') {
        const char *port_start = p + 1;
        const char *port_end   = port_start;
        while (*port_end && *port_end >= '0' && *port_end <= '9') {
            port_end++;
        }
        size_t port_len = (size_t)(port_end - port_start);
        bool is_default = (is_https && port_len == 3
                           && port_start[0] == '4'
                           && port_start[1] == '4'
                           && port_start[2] == '3')
                          || (is_http && port_len == 2
                              && port_start[0] == '8'
                              && port_start[1] == '0');
        if (!is_default) {
            out[op++] = ':';
            memcpy(out + op, port_start, port_len);
            op += port_len;
        }
        p = port_end;
    }

    /* Path: copy until '?', '#', or end. */
    while (*p && *p != '?' && *p != '#') {
        out[op++] = *p++;
    }
    out[op] = '\0';
    return op;
}

n00b_result_t(bool)
n00b_dpop_verify(const char *dpop_header,
                 const char *htm,
                 const char *htu) _kargs
{
    const uint8_t            *expected_jkt    = nullptr;
    const char               *expected_nonce  = nullptr;
    const uint8_t            *expected_ath    = nullptr;
    size_t                    expected_ath_len = 0;
    int32_t                   leeway_seconds  = 60;
    n00b_dpop_replay_store_t *replay          = nullptr;
}
{
    if (!dpop_header || !htm || !htu) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    dpop_parts_t parts;
    memset(&parts, 0, sizeof(parts));
    if (parse_compact_dpop(dpop_header, &parts) != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }

    /* Header parse. */
    char *hdr_str = n00b_alloc_array_with_opts(char,
        (int64_t)(parts.header_decoded->byte_len + 1),
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    memcpy(hdr_str, parts.header_decoded->data,
           (size_t)parts.header_decoded->byte_len);
    hdr_str[parts.header_decoded->byte_len] = '\0';
    const char       *err = nullptr;
    n00b_json_node_t *hdr = n00b_json_parse(hdr_str,
                                            strlen(hdr_str), &err);
    if (!hdr || !n00b_json_is_object(hdr)) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }

    /* typ + alg. */
    const char *typ = n00b_json_as_cstr(n00b_json_object_get_cstr(hdr, "typ"));
    if (!typ || strcmp(typ, "dpop+jwt") != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }
    const char *alg = n00b_json_as_cstr(n00b_json_object_get_cstr(hdr, "alg"));
    if (!alg || strcmp(alg, "ES256") != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_ALG_REFUSED);
    }

    /* JWK → pubkey. */
    uint8_t pub[64];
    if (extract_jwk_xy(hdr, pub, pub + 32) != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }

    /* Verify signature (raw r||s, 64 bytes). */
    if (parts.sig_decoded->byte_len != 64) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }
    uint8_t digest[32];
    n00b_sha256_digest_t words;
    n00b_sha256_hash(parts.signing_input, parts.signing_input_len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        digest[i*4]     = (uint8_t)(w >> 24);
        digest[i*4 + 1] = (uint8_t)(w >> 16);
        digest[i*4 + 2] = (uint8_t)(w >> 8);
        digest[i*4 + 3] = (uint8_t)w;
    }
    if (!uECC_verify(pub, digest, 32,
                     (const uint8_t *)parts.sig_decoded->data,
                     uECC_secp256r1())) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }

    /* Optional jkt thumbprint check. */
    if (expected_jkt) {
        uint8_t actual_jkt[32];
        n00b_jwk_p256_thumbprint(pub, actual_jkt);
        if (memcmp(actual_jkt, expected_jkt, 32) != 0) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_MTLS_MISMATCH);
        }
    }

    /* Payload parse. */
    char *pl_str = n00b_alloc_array_with_opts(char,
        (int64_t)(parts.payload_decoded->byte_len + 1),
        &(n00b_alloc_opts_t){.allocator = dpop_alloc(), .no_scan = true});
    memcpy(pl_str, parts.payload_decoded->data,
           (size_t)parts.payload_decoded->byte_len);
    pl_str[parts.payload_decoded->byte_len] = '\0';
    n00b_json_node_t *pl = n00b_json_parse(pl_str, strlen(pl_str), &err);
    if (!pl || !n00b_json_is_object(pl)) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }

#define GET_STR(KEY) n00b_json_as_cstr(n00b_json_object_get_cstr(pl, KEY))
    const char *p_htm   = GET_STR("htm");
    const char *p_htu   = GET_STR("htu");
    const char *p_jti   = GET_STR("jti");
    const char *p_nonce = GET_STR("nonce");
    const char *p_ath   = GET_STR("ath");

    n00b_json_node_t *iat_node = n00b_json_object_get_cstr(pl, "iat");
    int64_t p_iat = 0;
    if (n00b_json_is_int(iat_node)) {
        p_iat = n00b_json_as_i64(iat_node);
    } else if (n00b_json_is_double(iat_node)) {
        p_iat = (int64_t)n00b_json_as_f64(iat_node);
    }
#undef GET_STR

    if (!p_htm || strcmp(p_htm, htm) != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }
    /* htu comparison after RFC 9449 § 4.2 normalization on both sides
     * — strip query/fragment, lowercase scheme + host, drop default
     * port.  Buffers are stack-allocated for typical URL sizes; we
     * cap at 1 KiB which covers basically every real DPoP use. */
    if (!p_htu) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }
    {
        char want[1024];
        char got[1024];
        size_t wn = canonicalize_htu(htu,   want, sizeof(want));
        size_t gn = canonicalize_htu(p_htu, got,  sizeof(got));
        if (wn == 0 || gn == 0 || strcmp(want, got) != 0) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
    }
    if (!p_jti || !*p_jti) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }
    if (expected_nonce) {
        if (!p_nonce || strcmp(p_nonce, expected_nonce) != 0) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
    }
    /* RFC 9449 § 4.3 — access-token binding.  When the caller passes
     * an expected access token, the proof's `ath` claim MUST equal
     * base64url(SHA-256(access_token)).  Without this check, an
     * attacker who captures a DPoP proof for one request can replay
     * it with a stolen access token at the same URL. */
    if (expected_ath && expected_ath_len > 0) {
        if (!p_ath) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
        uint8_t want_hash[32];
        {
            n00b_sha256_digest_t words;
            n00b_sha256_hash(expected_ath, expected_ath_len, words);
            for (int i = 0; i < 8; i++) {
                uint32_t w = words[i];
                want_hash[i*4]     = (uint8_t)(w >> 24);
                want_hash[i*4 + 1] = (uint8_t)(w >> 16);
                want_hash[i*4 + 2] = (uint8_t)(w >> 8);
                want_hash[i*4 + 3] = (uint8_t)w;
            }
        }
        auto ar = n00b_b64url_decode(p_ath, strlen(p_ath));
        if (!n00b_result_is_ok(ar)) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
        n00b_buffer_t *got = n00b_result_get(ar);
        if (got->byte_len != 32) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
        /* Constant-time compare. */
        uint8_t diff = 0;
        for (size_t i = 0; i < 32; i++) {
            diff |= want_hash[i] ^ (uint8_t)got->data[i];
        }
        if (diff != 0) {
            return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
        }
    }
    /* iat freshness — `iat` is seconds since epoch.  Must be within
     * `leeway_seconds` of now (in either direction). */
    int64_t now_s = n00b_us_timestamp() / N00B_USEC_PER_SEC;
    int64_t skew  = (int64_t)leeway_seconds;
    if (p_iat <= 0 || p_iat > now_s + skew || p_iat < now_s - skew) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_DPOP_FAILED);
    }

    /* Replay store check. */
    if (replay && replay_check_and_insert(replay, p_jti)) {
        return n00b_result_err(bool, N00B_QUIC_ERR_AUTH_REPLAY_DETECTED);
    }

    return n00b_result_ok(bool, true);
}
