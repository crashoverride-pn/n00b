/*
 * rsa_pkcs1.c — RSA PKCS#1-v1.5 + PSS sign/verify primitives.
 *
 * Public surface:
 *   - n00b_rsa_verify_pkcs1_v15      (internal/net/quic/rsa_pkcs1.h)
 *   - n00b_rsa_verify_pss_sha256     (internal/net/quic/rsa_pkcs1.h)
 *   - n00b_rsa_sign_pss_sha256       (internal/net/quic/rsa_pkcs1.h)
 *   - n00b_rsa_sign_pkcs1_v15_sha256 (util/rsa_sign.h — public)
 *
 * Sign + verify share this translation unit because they share the
 * schoolbook bignum + Knuth-D modular-reduction machinery, the
 * DigestInfo SHA-256 prefix, and the EMSA-PKCS1 padding builder.
 *
 * Bignum design:
 *   - 32-bit words, little-endian word order (word[0] = least
 *     significant).  Carries propagate via 64-bit accumulators.
 *   - Fixed-capacity arrays sized to RSA_MAX_WORDS (4096-bit + 1
 *     for carry headroom during multiplication).
 *
 * Modexp:
 *   - Right-to-left binary square-and-multiply.
 *   - Modular reduction via Knuth's algorithm D (long division)
 *     because we don't pre-compute Montgomery constants.  Speed is
 *     not critical for one verify per JWT.
 *
 * EMSA-PKCS1-v1_5 decoding (RFC 8017 § 9.2 emsa_pkcs1_v1_5_encode):
 *   the recovered message has the exact byte layout
 *     0x00 || 0x01 || PS (0xff bytes) || 0x00 || T
 *   where T = DER(DigestInfo) for the hash.  We compare that
 *   byte-for-byte with our own EM construction over the message hash.
 */

#define N00B_USE_INTERNAL_API
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/sha512.h"
#include "net/quic/quic_types.h"
#include "internal/crypto/rsa_pkcs1.h"
#include "crypto/rsa_sign.h"

/* RS384 / RS512 need SHA-384 / SHA-512.  n00b has SHA-256 only; the
 * cifra SHA-512 is reachable from the picotls subproject but not
 * exposed through picoquic_dep's include path.  Phase 3 v1 ships
 * RS256 only; RS384 / RS512 follow when we vendor (or reach into)
 * a SHA-512 implementation. */

/* ===========================================================================
 * Bignum
 * =========================================================================== */

/* RSA modulus up to 4096 bits = 128 words.  Multiplication produces
 * a 256-word product; we round up to 257 for the long-division
 * scratch space (one extra word for the high overflow during shift). */
#define RSA_MAX_WORDS  128
#define BN_PROD_WORDS  (2 * RSA_MAX_WORDS + 1)

typedef struct {
    uint32_t w[BN_PROD_WORDS];
    int      n;       /* current word count (most-significant nonzero + 1) */
} bn_t;

static void bn_zero(bn_t *a) {
    memset(a->w, 0, sizeof(a->w));
    a->n = 0;
}

static void bn_normalize(bn_t *a) {
    while (a->n > 0 && a->w[a->n - 1] == 0) a->n--;
}

/* Big-endian byte string into words (little-endian word array). */
static int
bn_from_bytes(bn_t *a, const uint8_t *b, size_t blen)
{
    bn_zero(a);
    /* Skip any leading zero pad bytes. */
    while (blen > 0 && b[0] == 0) { b++; blen--; }
    if (blen == 0) return 0;

    size_t needed_words = (blen + 3) / 4;
    if (needed_words > BN_PROD_WORDS) return -1;
    /* Walk b from the rightmost end (least significant). */
    size_t i = 0;
    size_t pos = blen;
    while (pos >= 4) {
        pos -= 4;
        a->w[i++] = ((uint32_t)b[pos]     << 24)
                  | ((uint32_t)b[pos + 1] << 16)
                  | ((uint32_t)b[pos + 2] <<  8)
                  | ((uint32_t)b[pos + 3]);
    }
    if (pos > 0) {
        uint32_t v = 0;
        for (size_t k = 0; k < pos; k++) {
            v = (v << 8) | (uint32_t)b[k];
        }
        a->w[i++] = v;
    }
    a->n = (int)i;
    bn_normalize(a);
    return 0;
}

/* Compare a >= b. */
static int
bn_ge(const bn_t *a, const bn_t *b)
{
    if (a->n != b->n) return a->n > b->n;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->w[i] != b->w[i]) return a->w[i] > b->w[i];
    }
    return 1;
}

/* res = a - b, assumes a >= b. */
static void
bn_sub(bn_t *res, const bn_t *a, const bn_t *b)
{
    int64_t borrow = 0;
    int n = a->n;
    for (int i = 0; i < n; i++) {
        uint32_t bv = (i < b->n) ? b->w[i] : 0;
        int64_t d = (int64_t)a->w[i] - (int64_t)bv - borrow;
        if (d < 0) { d += 0x100000000LL; borrow = 1; } else { borrow = 0; }
        res->w[i] = (uint32_t)d;
    }
    res->n = n;
    bn_normalize(res);
}

/* res = a * b (schoolbook). */
static void
bn_mul(bn_t *res, const bn_t *a, const bn_t *b)
{
    int n = a->n + b->n + 1;
    if (n > BN_PROD_WORDS) n = BN_PROD_WORDS;
    bn_zero(res);
    for (int i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->n; j++) {
            int k = i + j;
            if (k >= BN_PROD_WORDS) break;
            uint64_t prod = (uint64_t)a->w[i] * (uint64_t)b->w[j]
                          + (uint64_t)res->w[k] + carry;
            res->w[k] = (uint32_t)prod;
            carry = prod >> 32;
        }
        int k = i + b->n;
        while (carry && k < BN_PROD_WORDS) {
            uint64_t s = (uint64_t)res->w[k] + carry;
            res->w[k] = (uint32_t)s;
            carry = s >> 32;
            k++;
        }
    }
    res->n = n;
    bn_normalize(res);
}

/* res = a mod m.  Knuth's Algorithm D.  Destroys nothing; works on
 * a copy of @p a internally. */
static void
bn_mod(bn_t *res, const bn_t *a, const bn_t *m)
{
    if (m->n == 0) { bn_zero(res); return; }
    if (a->n < m->n) { *res = *a; return; }

    /* Working buffer 'r' starts as a; we shift m up and subtract
     * iteratively from the top.  This is the simplest correct form
     * for one-shot reductions; not optimal but reliable. */
    bn_t r = *a;
    bn_normalize(&r);

    /* Shift m up so that its top word aligns with r's top word.
     * Then bn_ge → bn_sub, shift right, repeat down to position 0. */
    int shift = (r.n - m->n) * 32;

    /* Within each 32-bit position, do up to 32 single-bit shifts.
     * We approximate by computing m << shift in a fresh bn each
     * iteration of the outer loop.  Simpler than maintaining a
     * sliding shifted m. */

    /* For each bit position from high to low, build (m << bit) and
     * subtract if r is bigger. */
    bn_t shifted;
    int  total_bits = shift + 32;  /* small overshoot is fine */

    for (int s = total_bits; s >= 0; s--) {
        bn_zero(&shifted);
        int word_off = s / 32;
        int bit_off  = s % 32;
        for (int i = 0; i < m->n; i++) {
            int    dst = i + word_off;
            uint64_t val = ((uint64_t)m->w[i]) << bit_off;
            if (dst >= BN_PROD_WORDS) break;
            uint64_t v0 = (uint64_t)shifted.w[dst] + (val & 0xFFFFFFFFULL);
            shifted.w[dst] = (uint32_t)v0;
            uint64_t carry = (v0 >> 32);
            if (dst + 1 < BN_PROD_WORDS) {
                uint64_t v1 = (uint64_t)shifted.w[dst + 1]
                            + (val >> 32) + carry;
                shifted.w[dst + 1] = (uint32_t)v1;
                carry = (v1 >> 32);
                int k = dst + 2;
                while (carry && k < BN_PROD_WORDS) {
                    uint64_t v = (uint64_t)shifted.w[k] + carry;
                    shifted.w[k] = (uint32_t)v;
                    carry = (v >> 32);
                    k++;
                }
            }
        }
        shifted.n = m->n + word_off + 2;
        if (shifted.n > BN_PROD_WORDS) shifted.n = BN_PROD_WORDS;
        bn_normalize(&shifted);

        if (bn_ge(&r, &shifted)) {
            bn_t tmp;
            bn_sub(&tmp, &r, &shifted);
            r = tmp;
        }
    }

    *res = r;
}

/* res = (a * b) mod m. */
static void
bn_mulmod(bn_t *res, const bn_t *a, const bn_t *b, const bn_t *m)
{
    bn_t prod;
    bn_mul(&prod, a, b);
    bn_mod(res, &prod, m);
}

/* res = (s ^ e) mod n.  Right-to-left binary, where e is a small
 * bignum (we read its words bit by bit). */
static void
bn_powmod(bn_t *res, const bn_t *s, const bn_t *e, const bn_t *n)
{
    /* result = 1 */
    bn_zero(res);
    res->w[0] = 1;
    res->n    = 1;

    bn_t base = *s;
    bn_mod(&base, &base, n);

    int total_bits = e->n * 32;
    for (int i = 0; i < total_bits; i++) {
        int word = i / 32;
        int bit  = i % 32;
        uint32_t b = (e->w[word] >> bit) & 1;
        if (b) {
            bn_t t;
            bn_mulmod(&t, res, &base, n);
            *res = t;
        }
        bn_t t2;
        bn_mulmod(&t2, &base, &base, n);
        base = t2;
    }
}

/* Words → big-endian bytes, exactly @p out_len bytes (left-padded
 * with zeros). */
static void
bn_to_bytes(const bn_t *a, uint8_t *out, size_t out_len)
{
    memset(out, 0, out_len);
    int total_bytes = a->n * 4;
    if ((size_t)total_bytes > out_len) total_bytes = (int)out_len;
    for (int i = 0; i < total_bytes; i++) {
        int    word_idx = i / 4;
        int    byte_idx = i % 4;
        uint8_t b = (uint8_t)(a->w[word_idx] >> (byte_idx * 8));
        out[out_len - 1 - i] = b;
    }
}

/* ===========================================================================
 * Hashes
 * =========================================================================== */

static void
sha256_be(const uint8_t *m, size_t mlen, uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(m, mlen, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        out[i*4]     = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >> 8);
        out[i*4 + 3] = (uint8_t)w;
    }
}

/* DigestInfo DER prefixes (RFC 8017 § 9.2 NOTE 1).  These are the
 * fixed ASN.1 SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }
 * headers that get concatenated with the raw digest to form T in
 * EMSA-PKCS1-v1_5. */
static const uint8_t DI_SHA256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};
static const uint8_t DI_SHA384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
};
static const uint8_t DI_SHA512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
};

/* Build EMSA-PKCS1-v1_5 encoded message of @p emlen bytes:
 *   0x00 || 0x01 || PS (0xff..., at least 8) || 0x00 || T
 * where T = digest_info_prefix || digest_value. */
static int
build_em(uint8_t       *em,
         size_t         emlen,
         const uint8_t *di_prefix,
         size_t         di_prefix_len,
         const uint8_t *digest,
         size_t         digest_len)
{
    size_t t_len = di_prefix_len + digest_len;
    if (emlen < t_len + 11) return -1;  /* PS must be >= 8 */
    em[0] = 0x00;
    em[1] = 0x01;
    size_t ps_len = emlen - 3 - t_len;
    memset(em + 2, 0xff, ps_len);
    em[2 + ps_len] = 0x00;
    memcpy(em + 3 + ps_len,                  di_prefix, di_prefix_len);
    memcpy(em + 3 + ps_len + di_prefix_len,  digest,    digest_len);
    return 0;
}

int
n00b_rsa_verify_pkcs1_v15(n00b_jwk_t    *jwk,
                          const char    *alg,
                          const uint8_t *msg,
                          size_t         msg_len,
                          const uint8_t *sig,
                          size_t         sig_len)
{
    if (!jwk || strcmp(jwk->kty, "RSA") != 0) {
        return N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND;
    }
    if (!jwk->rsa_n || jwk->rsa_n_len == 0
        || !jwk->rsa_e || jwk->rsa_e_len == 0
        || !sig || sig_len == 0) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    /* RFC 8017 § 8.2.2: "if signature length != modulus length,
     * output 'invalid signature'." */
    if (sig_len != jwk->rsa_n_len) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }

    /* Bignums.  Each is ~2KB; total stack footprint ~8KB plus
     * powmod's local `base`+temporaries.  Within typical stack
     * limits.  Heap-allocating instead would only matter if we
     * push thread stacks below a few tens of KB, which we don't. */
    bn_t s_bn, n_bn, e_bn, m_bn;
    if (bn_from_bytes(&s_bn, sig, sig_len) != 0) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    if (bn_from_bytes(&n_bn, jwk->rsa_n, jwk->rsa_n_len) != 0) {
        return N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND;
    }
    if (bn_from_bytes(&e_bn, jwk->rsa_e, jwk->rsa_e_len) != 0) {
        return N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND;
    }

    /* RSAVP1: m = s^e mod n. */
    bn_powmod(&m_bn, &s_bn, &e_bn, &n_bn);

    /* Convert m back to a big-endian byte string the modulus length wide. */
    n00b_allocator_t *al = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    uint8_t *em = n00b_alloc_array_with_opts(uint8_t, (int64_t)jwk->rsa_n_len,
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    bn_to_bytes(&m_bn, em, jwk->rsa_n_len);

    /* Build expected EM. */
    uint8_t hash[64];
    size_t  hlen      = 0;
    const uint8_t *di = nullptr;
    size_t  di_len    = 0;
    if (strcmp(alg, "RS256") == 0) {
        sha256_be(msg, msg_len, hash);
        hlen = 32; di = DI_SHA256; di_len = sizeof(DI_SHA256);
    } else if (strcmp(alg, "RS384") == 0) {
        n00b_sha384_hash(msg, msg_len, hash);
        hlen = 48; di = DI_SHA384; di_len = sizeof(DI_SHA384);
    } else if (strcmp(alg, "RS512") == 0) {
        n00b_sha512_hash_be(msg, msg_len, hash);
        hlen = 64; di = DI_SHA512; di_len = sizeof(DI_SHA512);
    } else {
        return N00B_QUIC_ERR_AUTH_ALG_REFUSED;
    }

    uint8_t *expected = n00b_alloc_array_with_opts(uint8_t,
        (int64_t)jwk->rsa_n_len,
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    if (build_em(expected, jwk->rsa_n_len, di, di_len, hash, hlen) != 0) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }

    /* Constant-time compare. */
    uint8_t diff = 0;
    for (size_t i = 0; i < jwk->rsa_n_len; i++) {
        diff |= em[i] ^ expected[i];
    }

    return diff ? N00B_QUIC_ERR_AUTH_TOKEN_INVALID : N00B_QUIC_OK;
}

/* ===========================================================================
 * EMSA-PSS verification (RFC 8017 § 9.1.2, RFC 8446 § 4.2.3 PSS-RSAE)
 *
 * Used by TLS 1.3 CertificateVerify for RSA certs.  Hash = SHA-256;
 * salt length = hash length = 32 (matches rsa_pss_rsae_sha256).
 * =========================================================================== */

static void
mgf1_sha256(const uint8_t *seed, size_t seed_len,
            uint8_t *mask, size_t mask_len)
{
    /* MGF1 with SHA-256.  Iterate counter from 0 until we've produced
     * mask_len bytes; each iteration hashes seed || counter (4 bytes
     * big-endian) and appends to mask. */
    uint8_t buf[256 + 4];
    if (seed_len > sizeof(buf) - 4) return;  /* shouldn't happen for our sizes */

    memcpy(buf, seed, seed_len);
    uint32_t counter = 0;
    size_t   produced = 0;
    while (produced < mask_len) {
        buf[seed_len    ] = (uint8_t)(counter >> 24);
        buf[seed_len + 1] = (uint8_t)(counter >> 16);
        buf[seed_len + 2] = (uint8_t)(counter >> 8);
        buf[seed_len + 3] = (uint8_t)(counter);
        uint8_t hash[32];
        sha256_be(buf, seed_len + 4, hash);
        size_t chunk = mask_len - produced;
        if (chunk > 32) chunk = 32;
        memcpy(mask + produced, hash, chunk);
        produced += chunk;
        counter++;
    }
}

extern int
n00b_rsa_verify_pss_sha256(const uint8_t *rsa_n, size_t rsa_n_len,
                           const uint8_t *rsa_e, size_t rsa_e_len,
                           const uint8_t *msg,   size_t msg_len,
                           const uint8_t *sig,   size_t sig_len);
extern int
n00b_rsa_sign_pss_sha256(const uint8_t *rsa_n,  size_t rsa_n_len,
                         const uint8_t *rsa_d,  size_t rsa_d_len,
                         const uint8_t *salt,   size_t salt_len,
                         const uint8_t *msg,    size_t msg_len,
                         uint8_t       *out_sig, size_t *inout_sig_len);

int
n00b_rsa_verify_pss_sha256(const uint8_t *rsa_n, size_t rsa_n_len,
                           const uint8_t *rsa_e, size_t rsa_e_len,
                           const uint8_t *msg,   size_t msg_len,
                           const uint8_t *sig,   size_t sig_len)
{
    if (!rsa_n || rsa_n_len == 0 || !rsa_e || rsa_e_len == 0
        || !sig || sig_len == 0) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    if (sig_len != rsa_n_len) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }

    /* Recover EM = sig^e mod n. */
    bn_t s_bn, n_bn, e_bn, m_bn;
    if (bn_from_bytes(&s_bn, sig,   sig_len)   != 0
        || bn_from_bytes(&n_bn, rsa_n, rsa_n_len) != 0
        || bn_from_bytes(&e_bn, rsa_e, rsa_e_len) != 0) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    bn_powmod(&m_bn, &s_bn, &e_bn, &n_bn);

    n00b_allocator_t *al = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    uint8_t *em = n00b_alloc_array_with_opts(uint8_t, (int64_t)rsa_n_len,
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    bn_to_bytes(&m_bn, em, rsa_n_len);

    /* RFC 8017 § 9.1.2 — EMSA-PSS-VERIFY. */
    const size_t emLen = rsa_n_len;
    const size_t hLen  = 32;  /* SHA-256 digest size */
    const size_t sLen  = 32;  /* rsa_pss_rsae_sha256 salt length */
    /* emBits = modulus_bits - 1; emLen = ceil(emBits / 8).  For an
     * 8-aligned modulus (the common case: 2048/3072/4096 bits),
     * emBits = 8*emLen - 1, so the topmost bit of em[0] must be 0. */
    if (emLen < hLen + sLen + 2) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    if (em[emLen - 1] != 0xbc) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    if (em[0] & 0x80) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }

    /* maskedDB = em[0..emLen - hLen - 1); H = em[emLen - hLen - 1..emLen - 1). */
    const size_t db_len = emLen - hLen - 1;
    uint8_t      H[32];
    memcpy(H, em + db_len, hLen);

    /* dbMask = MGF1(H, db_len).  Unmask DB. */
    uint8_t *dbMask = n00b_alloc_array_with_opts(uint8_t, (int64_t)db_len,
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});
    mgf1_sha256(H, hLen, dbMask, db_len);
    for (size_t i = 0; i < db_len; i++) {
        em[i] ^= dbMask[i];
    }
    /* Clear the leftmost bit of DB[0] (matches the cleared bit in EM
     * for 8-aligned moduli). */
    em[0] &= 0x7f;

    /* DB = PS (0x00 padding) || 0x01 || salt.  PS length = emLen -
     * hLen - sLen - 2. */
    const size_t ps_len = emLen - hLen - sLen - 2;
    for (size_t i = 0; i < ps_len; i++) {
        if (em[i] != 0x00) {
            return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
        }
    }
    if (em[ps_len] != 0x01) {
        return N00B_QUIC_ERR_AUTH_TOKEN_INVALID;
    }
    const uint8_t *salt = em + ps_len + 1;

    /* M' = (0x00 * 8) || mHash || salt.  H' = SHA-256(M'). */
    uint8_t mHash[32];
    sha256_be(msg, msg_len, mHash);

    uint8_t       *mp    = n00b_alloc_array_with_opts(uint8_t,
                                (int64_t)(8 + hLen + sLen),
                                &(n00b_alloc_opts_t){.allocator = al,
                                                     .no_scan   = true});
    memset(mp, 0, 8);
    memcpy(mp + 8,        mHash, hLen);
    memcpy(mp + 8 + hLen, salt,  sLen);
    uint8_t Hp[32];
    sha256_be(mp, 8 + hLen + sLen, Hp);

    /* Constant-time compare H == H'. */
    uint8_t diff = 0;
    for (size_t i = 0; i < hLen; i++) {
        diff |= H[i] ^ Hp[i];
    }
    return diff ? N00B_QUIC_ERR_AUTH_TOKEN_INVALID : N00B_QUIC_OK;
}

/* ===========================================================================
 * EMSA-PSS sign (RFC 8017 § 9.1.1) + RSASP1 (§ 5.2.1)
 *
 * Companion to n00b_rsa_verify_pss_sha256.  Caller-provided salt for
 * determinism in tests; production callers pass random bytes
 * (sLen = hLen = 32 for rsa_pss_rsae_sha256).
 *
 * Modular exponentiation uses the same bn_powmod as verify — slow but
 * correct.  No CRT optimization (would require p, q, dP, dQ, qInv);
 * the d-exponent path works with just (n, d) which is what tests have
 * easiest access to.
 * =========================================================================== */

int
n00b_rsa_sign_pss_sha256(const uint8_t *rsa_n,  size_t rsa_n_len,
                         const uint8_t *rsa_d,  size_t rsa_d_len,
                         const uint8_t *salt,   size_t salt_len,
                         const uint8_t *msg,    size_t msg_len,
                         uint8_t       *out_sig, size_t *inout_sig_len)
{
    if (!rsa_n || rsa_n_len == 0 || !rsa_d || rsa_d_len == 0
        || !out_sig || !inout_sig_len || *inout_sig_len < rsa_n_len) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    const size_t emLen = rsa_n_len;
    const size_t hLen  = 32;
    if (emLen < hLen + salt_len + 2) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    /* mHash = SHA-256(msg). */
    uint8_t mHash[32];
    sha256_be(msg, msg_len, mHash);

    /* M' = (0x00 * 8) || mHash || salt.  H = SHA-256(M'). */
    n00b_allocator_t *al = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    uint8_t *mp = n00b_alloc_array_with_opts(uint8_t,
                                             (int64_t)(8 + hLen + salt_len),
                                             &(n00b_alloc_opts_t){
                                                 .allocator = al,
                                                 .no_scan   = true});
    memset(mp, 0, 8);
    memcpy(mp + 8,        mHash, hLen);
    memcpy(mp + 8 + hLen, salt,  salt_len);
    uint8_t H[32];
    sha256_be(mp, 8 + hLen + salt_len, H);

    /* DB = PS || 0x01 || salt.  PS length = emLen - sLen - hLen - 2. */
    const size_t db_len = emLen - hLen - 1;
    uint8_t *db = n00b_alloc_array_with_opts(uint8_t, (int64_t)db_len,
                                             &(n00b_alloc_opts_t){
                                                 .allocator = al,
                                                 .no_scan   = true});
    size_t ps_len = emLen - hLen - salt_len - 2;
    memset(db, 0, ps_len);
    db[ps_len] = 0x01;
    memcpy(db + ps_len + 1, salt, salt_len);

    /* dbMask = MGF1(H, db_len).  maskedDB = DB XOR dbMask. */
    uint8_t *dbMask = n00b_alloc_array_with_opts(uint8_t, (int64_t)db_len,
                                                 &(n00b_alloc_opts_t){
                                                     .allocator = al,
                                                     .no_scan   = true});
    mgf1_sha256(H, hLen, dbMask, db_len);
    for (size_t i = 0; i < db_len; i++) {
        db[i] ^= dbMask[i];
    }
    /* Clear the leftmost bit (emBits = 8 * emLen - 1 for 8-aligned
     * moduli — the common case). */
    db[0] &= 0x7f;

    /* EM = maskedDB || H || 0xbc. */
    uint8_t *em = n00b_alloc_array_with_opts(uint8_t, (int64_t)emLen,
                                             &(n00b_alloc_opts_t){
                                                 .allocator = al,
                                                 .no_scan   = true});
    memcpy(em,                       db, db_len);
    memcpy(em + db_len,              H,  hLen);
    em[emLen - 1] = 0xbc;

    /* sig = EM^d mod n. */
    bn_t em_bn, n_bn, d_bn, s_bn;
    if (bn_from_bytes(&em_bn, em, emLen) != 0
        || bn_from_bytes(&n_bn, rsa_n, rsa_n_len) != 0
        || bn_from_bytes(&d_bn, rsa_d, rsa_d_len) != 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    bn_powmod(&s_bn, &em_bn, &d_bn, &n_bn);
    bn_to_bytes(&s_bn, out_sig, emLen);
    *inout_sig_len = emLen;
    return N00B_QUIC_OK;
}

/* ===========================================================================
 * EMSA-PKCS1-v1_5 sign (RFC 8017 § 8.2.1) — SHA-256 only.
 *
 * Companion to the verify-side `n00b_rsa_verify_pkcs1_v15` for the
 * Authenticode + PKCS#7 SignedData callers. The verify side handles
 * RS256/RS384/RS512; the sign side here ships RS256 only since
 * Authenticode v1 + RFC 5652 default-content-types both standardize
 * on SHA-256 for the SignerInfo MessageDigest.
 *
 * Public surface declared in `include/util/rsa_sign.h`.
 * =========================================================================== */

int
n00b_rsa_sign_pkcs1_v15_sha256(const uint8_t *rsa_n,  size_t rsa_n_len,
                               const uint8_t *rsa_d,  size_t rsa_d_len,
                               const uint8_t *msg,    size_t msg_len,
                               uint8_t       *out_sig, size_t *inout_sig_len)
{
    if (!rsa_n || rsa_n_len == 0 || !rsa_d || rsa_d_len == 0
        || !msg || !out_sig || !inout_sig_len
        || *inout_sig_len < rsa_n_len) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    /* mHash = SHA-256(msg). */
    uint8_t mHash[32];
    sha256_be(msg, msg_len, mHash);

    /* EM = 0x00 || 0x01 || PS || 0x00 || DI_SHA256 || mHash. */
    const size_t emLen = rsa_n_len;
    if (emLen < sizeof(DI_SHA256) + 32 + 11) {
        /* PS must be >= 8; total fixed overhead = 11 + T. */
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    n00b_allocator_t *al = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    uint8_t          *em = n00b_alloc_array_with_opts(
        uint8_t,
        (int64_t)emLen,
        &(n00b_alloc_opts_t){.allocator = al, .no_scan = true});

    if (build_em(em, emLen, DI_SHA256, sizeof(DI_SHA256), mHash, 32) != 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    /* sig = EM^d mod n. */
    bn_t em_bn, n_bn, d_bn, s_bn;
    if (bn_from_bytes(&em_bn, em, emLen) != 0
        || bn_from_bytes(&n_bn, rsa_n, rsa_n_len) != 0
        || bn_from_bytes(&d_bn, rsa_d, rsa_d_len) != 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    bn_powmod(&s_bn, &em_bn, &d_bn, &n_bn);
    bn_to_bytes(&s_bn, out_sig, emLen);
    *inout_sig_len = emLen;
    return N00B_QUIC_OK;
}
