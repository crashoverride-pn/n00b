/*
 * secret_libsecret.c — Linux libsecret-1 backed secret provider.
 *
 * URI scheme: `libsecret:<label>`.  The caller stores a PEM-encoded
 * ECDSA P-256 private key (PKCS#8 or SEC1) in a Secret Service
 * daemon under that label.  On open() the provider:
 *
 *   1. Looks the label up via `secret_password_lookup_sync`.
 *   2. Extracts the first PRIVATE KEY / EC PRIVATE KEY PEM block.
 *   3. Base64-decodes the body to DER.
 *   4. Walks the DER (PKCS#8 wrapper or bare SEC1) to find the 32-byte
 *      secp256r1 private scalar.
 *   5. Derives the matching uncompressed public key with uECC.
 *
 * Sign / pubkey use uECC directly; the key never leaves process
 * memory and is zeroed on close().
 *
 * Compiled only when meson detected libsecret-1.0 + glib-2.0.
 */

#define N00B_USE_INTERNAL_API
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "uECC.h"

#include <libsecret/secret.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/secret_internal.h"
#include "internal/crypto/secret_libsecret.h"

typedef struct {
    uint8_t priv[32];
    uint8_t pub[64];
} libsecret_state_t;

static n00b_allocator_t *
ls_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

/* ---------------------------------------------------------------------------
 * Base64 (standard alphabet, RFC 4648) decoder.
 *
 * Self-contained so this provider does not link against the cert
 * provisioner's static helpers.  Whitespace inside the input is
 * silently skipped.  Trailing `=` padding is tolerated.
 * --------------------------------------------------------------------------- */
static int8_t
b64_val(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (int8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int8_t)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int8_t)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int
b64_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_cap,
           size_t *out_len)
{
    char *packed = n00b_alloc_array_with_opts(char, (int64_t)src_len + 1,
                                              &(n00b_alloc_opts_t){
                                                  .allocator = ls_alloc(),
                                                  .no_scan   = true,
                                              });
    size_t pn = 0;
    for (size_t i = 0; i < src_len; i++) {
        char c = src[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '=') {
            continue;
        }
        packed[pn++] = c;
    }

    size_t out = 0;
    size_t i   = 0;
    while (i + 4 <= pn) {
        int8_t a = b64_val((unsigned char)packed[i]);
        int8_t b = b64_val((unsigned char)packed[i + 1]);
        int8_t c = b64_val((unsigned char)packed[i + 2]);
        int8_t d = b64_val((unsigned char)packed[i + 3]);
        if ((a | b | c | d) < 0) return N00B_QUIC_ERR_PROTOCOL;
        if (out + 3 > dst_cap)   return N00B_QUIC_ERR_PROTOCOL;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12)
                   | ((uint32_t)c <<  6) |  (uint32_t)d;
        dst[out++] = (uint8_t)((v >> 16) & 0xff);
        dst[out++] = (uint8_t)((v >>  8) & 0xff);
        dst[out++] = (uint8_t)( v        & 0xff);
        i += 4;
    }
    size_t rem = pn - i;
    if (rem == 1) return N00B_QUIC_ERR_PROTOCOL;
    if (rem == 2) {
        int8_t a = b64_val((unsigned char)packed[i]);
        int8_t b = b64_val((unsigned char)packed[i + 1]);
        if ((a | b) < 0)         return N00B_QUIC_ERR_PROTOCOL;
        if (out + 1 > dst_cap)   return N00B_QUIC_ERR_PROTOCOL;
        dst[out++] = (uint8_t)((a << 2) | (b >> 4));
    } else if (rem == 3) {
        int8_t a = b64_val((unsigned char)packed[i]);
        int8_t b = b64_val((unsigned char)packed[i + 1]);
        int8_t c = b64_val((unsigned char)packed[i + 2]);
        if ((a | b | c) < 0)     return N00B_QUIC_ERR_PROTOCOL;
        if (out + 2 > dst_cap)   return N00B_QUIC_ERR_PROTOCOL;
        uint32_t v = ((uint32_t)a << 12) | ((uint32_t)b << 6) | (uint32_t)c;
        dst[out++] = (uint8_t)((v >> 10) & 0xff);
        dst[out++] = (uint8_t)((v >>  2) & 0xff);
    }

    *out_len = out;
    return N00B_QUIC_OK;
}

/* ---------------------------------------------------------------------------
 * PEM block extraction.  Locates the first PRIVATE KEY (PKCS#8) or
 * EC PRIVATE KEY (SEC1) block and reports which container shape it
 * contains so the DER walker can pick the right grammar.
 * --------------------------------------------------------------------------- */

typedef enum {
    PEM_KIND_PKCS8,
    PEM_KIND_SEC1,
} pem_kind_t;

static int
pem_find_private_block(const char  *pem,
                       size_t       pem_len,
                       const char **out_body,
                       size_t      *out_body_len,
                       pem_kind_t  *out_kind)
{
    static const char p8_beg[] = "-----BEGIN PRIVATE KEY-----";
    static const char p8_end[] = "-----END PRIVATE KEY-----";
    static const char ec_beg[] = "-----BEGIN EC PRIVATE KEY-----";
    static const char ec_end[] = "-----END EC PRIVATE KEY-----";

    char *copy = n00b_alloc_array_with_opts(char, (int64_t)pem_len + 1,
                                            &(n00b_alloc_opts_t){
                                                .allocator = ls_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(copy, pem, pem_len);
    copy[pem_len] = '\0';

    const char *bp = strstr(copy, p8_beg);
    const char *ep = nullptr;
    pem_kind_t  kind;
    if (bp) {
        bp += sizeof(p8_beg) - 1;
        ep  = strstr(bp, p8_end);
        kind = PEM_KIND_PKCS8;
    } else {
        bp = strstr(copy, ec_beg);
        if (!bp) return N00B_QUIC_ERR_PROTOCOL;
        bp += sizeof(ec_beg) - 1;
        ep  = strstr(bp, ec_end);
        kind = PEM_KIND_SEC1;
    }
    if (!ep || ep <= bp) return N00B_QUIC_ERR_PROTOCOL;

    *out_body     = bp;
    *out_body_len = (size_t)(ep - bp);
    *out_kind     = kind;
    return N00B_QUIC_OK;
}

/* ---------------------------------------------------------------------------
 * Minimal DER walker for {SEC1, PKCS#8(SEC1)} containing a P-256
 * private scalar.
 * --------------------------------------------------------------------------- */

/* secp256r1 OID = 1.2.840.10045.3.1.7. */
static const uint8_t OID_SECP256R1[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
};
/* id-ecPublicKey OID = 1.2.840.10045.2.1. */
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
};

/* Read one TLV at @p p (within @p end).  On success returns the
 * pointer to the value, populates *out_tag, *out_len, and *out_next
 * (just past the value).  Returns nullptr on malformed input. */
static const uint8_t *
der_read_tlv(const uint8_t  *p,
             const uint8_t  *end,
             uint8_t        *out_tag,
             size_t         *out_len,
             const uint8_t **out_next)
{
    if (p >= end) return nullptr;
    uint8_t tag = *p++;
    if (p >= end) return nullptr;
    size_t  len = 0;
    uint8_t b   = *p++;
    if ((b & 0x80) == 0) {
        len = b;
    } else {
        size_t n = b & 0x7f;
        if (n == 0 || n > 4 || (size_t)(end - p) < n) return nullptr;
        for (size_t i = 0; i < n; i++) {
            len = (len << 8) | *p++;
        }
    }
    if ((size_t)(end - p) < len) return nullptr;
    *out_tag  = tag;
    *out_len  = len;
    *out_next = p + len;
    return p;
}

/* Walk a SEC1 ECPrivateKey at [sec1, sec1_end) and write the 32-byte
 * scalar to @p out_priv.  Verifies version=1 and a 32-byte OCTET
 * STRING privateKey field. */
static int
der_walk_sec1(const uint8_t *sec1, const uint8_t *sec1_end,
              uint8_t        out_priv[32])
{
    const uint8_t *p, *next;
    uint8_t        tag;
    size_t         len;

    /* SEQUENCE wrapper. */
    p = der_read_tlv(sec1, sec1_end, &tag, &len, &next);
    if (!p || tag != 0x30) return N00B_QUIC_ERR_PROTOCOL;
    const uint8_t *cur     = p;
    const uint8_t *cur_end = next;

    /* version INTEGER (must be 1). */
    p = der_read_tlv(cur, cur_end, &tag, &len, &next);
    if (!p || tag != 0x02 || len != 1 || *p != 0x01) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    cur = next;

    /* privateKey OCTET STRING (32 bytes for P-256). */
    p = der_read_tlv(cur, cur_end, &tag, &len, &next);
    if (!p || tag != 0x04 || len != 32) return N00B_QUIC_ERR_PROTOCOL;
    memcpy(out_priv, p, 32);
    return N00B_QUIC_OK;
}

/* Walk a PKCS#8 PrivateKeyInfo at [p8, p8_end), verify the algorithm
 * OIDs identify secp256r1, then descend into the nested SEC1
 * ECPrivateKey. */
static int
der_walk_pkcs8(const uint8_t *p8, const uint8_t *p8_end,
               uint8_t        out_priv[32])
{
    const uint8_t *p, *next;
    uint8_t        tag;
    size_t         len;

    /* Outer SEQUENCE. */
    p = der_read_tlv(p8, p8_end, &tag, &len, &next);
    if (!p || tag != 0x30) return N00B_QUIC_ERR_PROTOCOL;
    const uint8_t *cur     = p;
    const uint8_t *cur_end = next;

    /* version INTEGER (0). */
    p = der_read_tlv(cur, cur_end, &tag, &len, &next);
    if (!p || tag != 0x02 || len != 1 || *p != 0x00) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    cur = next;

    /* AlgorithmIdentifier SEQUENCE { OID ecPublicKey, OID secp256r1 }. */
    p = der_read_tlv(cur, cur_end, &tag, &len, &next);
    if (!p || tag != 0x30) return N00B_QUIC_ERR_PROTOCOL;
    {
        const uint8_t *a     = p;
        const uint8_t *a_end = next;
        const uint8_t *o     = der_read_tlv(a, a_end, &tag, &len, &next);
        if (!o || tag != 0x06 || len != sizeof(OID_EC_PUBLIC_KEY)
            || memcmp(o, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY)) != 0) {
            return N00B_QUIC_ERR_PROTOCOL;
        }
        o = der_read_tlv(next, a_end, &tag, &len, &next);
        if (!o || tag != 0x06 || len != sizeof(OID_SECP256R1)
            || memcmp(o, OID_SECP256R1, sizeof(OID_SECP256R1)) != 0) {
            return N00B_QUIC_ERR_PROTOCOL;
        }
    }
    cur = next;  /* next was advanced past AlgorithmIdentifier */

    /* privateKey OCTET STRING wrapping the SEC1 ECPrivateKey. */
    p = der_read_tlv(cur, cur_end, &tag, &len, &next);
    if (!p || tag != 0x04) return N00B_QUIC_ERR_PROTOCOL;
    return der_walk_sec1(p, p + len, out_priv);
}

static int
parse_pem_priv_key(const char *pem, size_t pem_len, uint8_t out_priv[32])
{
    const char *body;
    size_t      body_len;
    pem_kind_t  kind;
    int rc = pem_find_private_block(pem, pem_len, &body, &body_len, &kind);
    if (rc != N00B_QUIC_OK) return rc;

    /* DER bound: base64 expands 4 → 3, so DER ≤ 3 * body_len / 4 + 4. */
    size_t   der_cap = (body_len * 3) / 4 + 4;
    uint8_t *der     = n00b_alloc_array_with_opts(uint8_t, (int64_t)der_cap,
                                                  &(n00b_alloc_opts_t){
                                                      .allocator = ls_alloc(),
                                                      .no_scan   = true,
                                                  });
    size_t der_len = 0;
    rc = b64_decode(body, body_len, der, der_cap, &der_len);
    if (rc != N00B_QUIC_OK) return rc;

    if (kind == PEM_KIND_PKCS8) {
        return der_walk_pkcs8(der, der + der_len, out_priv);
    }
    return der_walk_sec1(der, der + der_len, out_priv);
}

/* ---------------------------------------------------------------------------
 * Provider vtable methods.
 * --------------------------------------------------------------------------- */

static int
ls_open(const char              *uri_rest,
        n00b_quic_secret_kind_t  hint_kind,
        void                   **state_out,
        n00b_quic_secret_kind_t *kind_out,
        n00b_string_t          **label_out)
{
    (void)hint_kind;
    if (!uri_rest || !*uri_rest) return N00B_QUIC_ERR_INVALID_ARG;

    GError *gerr = nullptr;
    gchar  *pem  = secret_password_lookup_sync(SECRET_SCHEMA_COMPAT_NETWORK,
                                                nullptr, &gerr,
                                                "user", uri_rest, nullptr);
    if (gerr) {
        g_error_free(gerr);
        if (pem) g_free(pem);
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (!pem) return N00B_QUIC_ERR_INVALID_ARG;

    libsecret_state_t scratch;
    memset(&scratch, 0, sizeof(scratch));
    int rc = parse_pem_priv_key(pem, strlen(pem), scratch.priv);
    /* secret_password_free zeroes the buffer before freeing. */
    secret_password_free(pem);
    if (rc != N00B_QUIC_OK) {
        memset(&scratch, 0, sizeof(scratch));
        return rc;
    }
    if (!uECC_compute_public_key(scratch.priv, scratch.pub, uECC_secp256r1())) {
        memset(&scratch, 0, sizeof(scratch));
        return N00B_QUIC_ERR_PROTOCOL;
    }

    libsecret_state_t *st = n00b_alloc_with_opts(libsecret_state_t,
        &(n00b_alloc_opts_t){.allocator = ls_alloc(), .no_scan = true});
    memcpy(st, &scratch, sizeof(*st));
    memset(&scratch, 0, sizeof(scratch));

    *state_out = st;
    *kind_out  = N00B_QUIC_SECRET_PRIVKEY;
    *label_out = n00b_string_from_cstr((char *)uri_rest);
    return N00B_QUIC_OK;
}

static void
sha256_be(const uint8_t *data, size_t data_len, uint8_t out[32])
{
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    if (data_len > 0) n00b_sha256_update(&ctx, data, data_len);
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

static int
ls_sign(void                 *state,
        const uint8_t        *data,
        size_t                data_len,
        n00b_quic_sig_alg_t   alg,
        n00b_buffer_t       **out_sig)
{
    libsecret_state_t *st = state;
    if (!st || !out_sig) return N00B_QUIC_ERR_NULL_ARG;
    if (alg != N00B_QUIC_SIG_ECDSA_P256) return N00B_QUIC_ERR_INVALID_ARG;

    uint8_t digest[32];
    sha256_be(data, data_len, digest);

    n00b_buffer_t *sig = n00b_alloc_with_opts(n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = ls_alloc()});
    n00b_buffer_init(sig, .length = 64, .allocator = ls_alloc());
    sig->byte_len = 64;
    if (!uECC_sign(st->priv, digest, sizeof(digest),
                   (uint8_t *)sig->data, uECC_secp256r1())) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    *out_sig = sig;
    return N00B_QUIC_OK;
}

static int
ls_pubkey(void                 *state,
          n00b_quic_sig_alg_t   alg,
          n00b_buffer_t       **out_pub)
{
    libsecret_state_t *st = state;
    if (!st || !out_pub) return N00B_QUIC_ERR_NULL_ARG;
    if (alg != N00B_QUIC_SIG_ECDSA_P256) return N00B_QUIC_ERR_INVALID_ARG;

    n00b_buffer_t *pub = n00b_alloc_with_opts(n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = ls_alloc()});
    n00b_buffer_init(pub, .raw = (char *)st->pub, .length = 64,
                     .allocator = ls_alloc());
    *out_pub = pub;
    return N00B_QUIC_OK;
}

static int
ls_wrap(void           *state,
        const uint8_t  *data,
        size_t          data_len,
        n00b_buffer_t **out_wrapped)
{
    (void)state;
    (void)data;
    (void)data_len;
    (void)out_wrapped;
    return N00B_QUIC_ERR_NOT_IMPLEMENTED;
}

static void
ls_close(void *state)
{
    if (state) {
        memset(state, 0, sizeof(libsecret_state_t));
    }
}

const n00b_quic_secret_vtbl_t n00b_libsecret_vtbl = {
    .scheme = "libsecret",
    .open   = ls_open,
    .sign   = ls_sign,
    .wrap   = ls_wrap,
    .pubkey = ls_pubkey,
    .close  = ls_close,
};
