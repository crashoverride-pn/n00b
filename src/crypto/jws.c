/*
 * jws.c — Base64url + JWK + flattened JSON JWS encoder for ACME.
 *
 * Layout:
 *   §1   Allocator + base64url helpers
 *   §2   Canonical JWK + RFC 7638 thumbprint (EC P-256)
 *   §3   Flattened JSON JWS builder
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/jws.h"

/* ===========================================================================
 * §1   Allocator + base64url
 * =========================================================================== */

static n00b_allocator_t *
jws_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
jws_alloc_chars(size_t n)
{
    /* +1 for NUL terminator. */
    return n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                                      &(n00b_alloc_opts_t){
                                          .allocator = jws_alloc(),
                                          .no_scan   = true,
                                      });
}

static const char b64url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

char *
n00b_b64url_encode(const uint8_t *in, size_t in_len)
{
    /* 4 chars per 3 bytes, rounded up; minus padding chars. */
    size_t triplets = in_len / 3;
    size_t rem      = in_len - triplets * 3;
    size_t out_len  = triplets * 4 + (rem == 0 ? 0 : (rem == 1 ? 2 : 3));

    char  *out = jws_alloc_chars(out_len);
    size_t oi  = 0;

    for (size_t i = 0; i < triplets; i++) {
        uint32_t v = ((uint32_t)in[i*3]     << 16)
                   | ((uint32_t)in[i*3 + 1] << 8)
                   |  (uint32_t)in[i*3 + 2];
        out[oi++] = b64url_alphabet[(v >> 18) & 0x3f];
        out[oi++] = b64url_alphabet[(v >> 12) & 0x3f];
        out[oi++] = b64url_alphabet[(v >>  6) & 0x3f];
        out[oi++] = b64url_alphabet[ v        & 0x3f];
    }
    if (rem == 1) {
        uint32_t v = (uint32_t)in[triplets*3] << 16;
        out[oi++]  = b64url_alphabet[(v >> 18) & 0x3f];
        out[oi++]  = b64url_alphabet[(v >> 12) & 0x3f];
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[triplets*3]     << 16)
                   | ((uint32_t)in[triplets*3 + 1] <<  8);
        out[oi++]  = b64url_alphabet[(v >> 18) & 0x3f];
        out[oi++]  = b64url_alphabet[(v >> 12) & 0x3f];
        out[oi++]  = b64url_alphabet[(v >>  6) & 0x3f];
    }
    out[oi] = '\0';
    return out;
}

/* Inverse-alphabet table; -1 = invalid character.  Built once. */
static int8_t b64url_inv[256];
static int    b64url_inv_inited = 0;

static void
b64url_inv_init(void)
{
    if (b64url_inv_inited) {
        return;
    }
    for (int i = 0; i < 256; i++) {
        b64url_inv[i] = -1;
    }
    for (int i = 0; i < 64; i++) {
        b64url_inv[(unsigned char)b64url_alphabet[i]] = (int8_t)i;
    }
    b64url_inv_inited = 1;
}

n00b_result_t(n00b_buffer_t *)
n00b_b64url_decode(const char *in, size_t in_len)
{
    if (!in && in_len > 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    b64url_inv_init();

    size_t quartets = in_len / 4;
    size_t rem      = in_len - quartets * 4;
    if (rem == 1) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    size_t out_len = quartets * 3 + (rem == 0 ? 0 : (rem == 2 ? 1 : 2));

    n00b_buffer_t *buf = n00b_buffer_empty(.allocator = jws_alloc());
    char *raw = n00b_alloc_array_with_opts(char, (int64_t)out_len,
                                           &(n00b_alloc_opts_t){
                                               .allocator = jws_alloc(),
                                               .no_scan   = true,
                                           });
    size_t oi = 0;

    for (size_t i = 0; i < quartets; i++) {
        int8_t a = b64url_inv[(unsigned char)in[i*4]];
        int8_t b = b64url_inv[(unsigned char)in[i*4 + 1]];
        int8_t c = b64url_inv[(unsigned char)in[i*4 + 2]];
        int8_t d = b64url_inv[(unsigned char)in[i*4 + 3]];
        if ((a | b | c | d) < 0) {
            return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
        }
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12)
                   | ((uint32_t)c <<  6) |  (uint32_t)d;
        raw[oi++] = (char)((v >> 16) & 0xff);
        raw[oi++] = (char)((v >>  8) & 0xff);
        raw[oi++] = (char)( v        & 0xff);
    }
    if (rem == 2) {
        int8_t a = b64url_inv[(unsigned char)in[quartets*4]];
        int8_t b = b64url_inv[(unsigned char)in[quartets*4 + 1]];
        if ((a | b) < 0) {
            return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
        }
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12);
        raw[oi++]  = (char)((v >> 16) & 0xff);
    } else if (rem == 3) {
        int8_t a = b64url_inv[(unsigned char)in[quartets*4]];
        int8_t b = b64url_inv[(unsigned char)in[quartets*4 + 1]];
        int8_t c = b64url_inv[(unsigned char)in[quartets*4 + 2]];
        if ((a | b | c) < 0) {
            return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
        }
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12)
                   | ((uint32_t)c <<  6);
        raw[oi++]  = (char)((v >> 16) & 0xff);
        raw[oi++]  = (char)((v >>  8) & 0xff);
    }

    if (oi > 0) {
        n00b_buffer_t *src = n00b_buffer_from_bytes(raw, (int64_t)oi,
                                                    .allocator = jws_alloc());
        n00b_buffer_concat(buf, src);
    }
    return n00b_result_ok(n00b_buffer_t *, buf);
}

/* ===========================================================================
 * §2   Canonical JWK + RFC 7638 thumbprint
 *
 * RFC 7638 § 3.2 specifies the canonical members for EC keys (in
 * lexicographic order: crv, kty, x, y) with no whitespace between
 * tokens.  No member values include characters that need JSON
 * escaping in our case (b64url alphabet).
 * =========================================================================== */

char *
n00b_jwk_p256_canonical(const uint8_t pubkey[64])
{
    /* X is the first 32 bytes; Y is the next 32. */
    char *bx = n00b_b64url_encode(pubkey,      32);
    char *by = n00b_b64url_encode(pubkey + 32, 32);

    /* Sized worst-case: literal 30 + 4*43 = 202.  Round to 256. */
    char  *out = jws_alloc_chars(256);
    int    n   = snprintf(out, 256,
                          "{\"crv\":\"P-256\",\"kty\":\"EC\","
                          "\"x\":\"%s\",\"y\":\"%s\"}",
                          bx, by);
    (void)n;
    return out;
}

void
n00b_jwk_p256_thumbprint(const uint8_t pubkey[64], uint8_t out[32])
{
    char *jwk = n00b_jwk_p256_canonical(pubkey);

    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    n00b_sha256_update(&ctx, (const uint8_t *)jwk, strlen(jwk));
    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i*4]     = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >> 8);
        out[i*4 + 3] = (uint8_t)w;
    }
}

/* ===========================================================================
 * §3   Flattened JSON JWS builder
 * =========================================================================== */

n00b_result_t(n00b_buffer_t *)
n00b_jws_build(n00b_quic_secret_t *signer,
               const char         *nonce,
               const char         *url,
               const uint8_t      *payload,
               size_t              payload_len) _kargs
{
    const char *kid       = nullptr;
    bool        embed_jwk = false;
}
{
    if (!signer || !nonce || !url) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    /* Exactly one of kid/embed_jwk must be set. */
    if ((kid == nullptr) == (!embed_jwk)) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!payload && payload_len > 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    /* --- Build protected header JSON. ------------------------------ */
    char *jwk = nullptr;
    if (embed_jwk) {
        n00b_result_t(n00b_buffer_t *) pr =
            n00b_quic_secret_pubkey(signer, N00B_QUIC_SIG_ECDSA_P256);
        if (!n00b_result_is_ok(pr)) {
            return n00b_result_err(n00b_buffer_t *,
                                   (int)n00b_result_get_err(pr));
        }
        n00b_buffer_t *pub = n00b_result_get(pr);
        if (pub->byte_len != 64) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_QUIC_ERR_INVALID_ARG);
        }
        jwk = n00b_jwk_p256_canonical((const uint8_t *)pub->data);
    }

    /* Worst case: alg + nonce + url + (kid|jwk).  Generous initial
     * cap; snprintf below will grow if it overruns. */
    size_t hdr_cap = 256
                   + strlen(nonce) + strlen(url)
                   + (kid ? strlen(kid) : 0)
                   + (jwk ? strlen(jwk) : 0);
    char  *hdr = jws_alloc_chars(hdr_cap);
    int    hn;
    if (kid) {
        hn = snprintf(hdr, hdr_cap,
                      "{\"alg\":\"ES256\","
                      "\"nonce\":\"%s\","
                      "\"url\":\"%s\","
                      "\"kid\":\"%s\"}",
                      nonce, url, kid);
    } else {
        hn = snprintf(hdr, hdr_cap,
                      "{\"alg\":\"ES256\","
                      "\"nonce\":\"%s\","
                      "\"url\":\"%s\","
                      "\"jwk\":%s}",
                      nonce, url, jwk);
    }
    if (hn < 0 || (size_t)hn >= hdr_cap) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_FRAME_TOO_LARGE);
    }

    /* --- b64url(header) and b64url(payload). ----------------------- */
    char *bh = n00b_b64url_encode((const uint8_t *)hdr, (size_t)hn);
    char *bp = n00b_b64url_encode(payload, payload_len);

    /* --- Sign: data = bh || "." || bp.  Provider hashes + signs. --- */
    size_t sd_len = strlen(bh) + 1 + strlen(bp);
    char  *sd     = jws_alloc_chars(sd_len);
    memcpy(sd, bh, strlen(bh));
    sd[strlen(bh)] = '.';
    memcpy(sd + strlen(bh) + 1, bp, strlen(bp));
    sd[sd_len] = '\0';

    n00b_buffer_t signing_input;
    memset(&signing_input, 0, sizeof(signing_input));
    n00b_buffer_init(&signing_input,
                     .raw = sd, .length = (int64_t)sd_len,
                     .allocator = jws_alloc());

    n00b_result_t(n00b_buffer_t *) sr =
        n00b_quic_secret_sign(signer, &signing_input,
                              N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sr)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(sr));
    }
    n00b_buffer_t *raw_sig = n00b_result_get(sr);
    if (raw_sig->byte_len != 64) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    char *bs = n00b_b64url_encode((const uint8_t *)raw_sig->data, 64);

    /* --- Assemble flattened JWS JSON. ----------------------------- */
    size_t out_cap = strlen(bh) + strlen(bp) + strlen(bs) + 64;
    char  *out     = jws_alloc_chars(out_cap);
    int    on      = snprintf(out, out_cap,
                              "{\"protected\":\"%s\","
                              "\"payload\":\"%s\","
                              "\"signature\":\"%s\"}",
                              bh, bp, bs);
    if (on < 0 || (size_t)on >= out_cap) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_FRAME_TOO_LARGE);
    }

    n00b_buffer_t *body = n00b_buffer_from_bytes(out, on,
                                                 .allocator = jws_alloc());
    return n00b_result_ok(n00b_buffer_t *, body);
}
