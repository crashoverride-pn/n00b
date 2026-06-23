/*
 * secret.c — Secret-handle dispatch + URI routing + the in-memory ephemeral
 * provider used for unit tests.
 *
 * The real providers (Keychain, libsecret, PKCS#11, ...) plug in via the
 * provider vtable; their bodies land in follow-up patches.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <string.h>

#include "uECC.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/random.h"
#include "core/buffer.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/secret_internal.h"

/* ===========================================================================
 * Provider registry
 *
 * Trivial linear table; we only have one provider in Phase 1, and the
 * full set will be ~10 once everything ships.  Linear scan beats a hash
 * map at that scale.
 * =========================================================================== */

#define MAX_PROVIDERS 16
static const n00b_quic_secret_vtbl_t *g_providers[MAX_PROVIDERS];
static size_t                         g_provider_count = 0;

static int
register_provider(const n00b_quic_secret_vtbl_t *vtbl)
{
    if (g_provider_count >= MAX_PROVIDERS) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    g_providers[g_provider_count++] = vtbl;
    return N00B_QUIC_OK;
}

static const n00b_quic_secret_vtbl_t *
find_provider(const char *scheme, size_t scheme_len)
{
    for (size_t i = 0; i < g_provider_count; i++) {
        const char *s = g_providers[i]->scheme;
        if (s && strlen(s) == scheme_len && memcmp(s, scheme, scheme_len) == 0) {
            return g_providers[i];
        }
    }
    return nullptr;
}

/* ===========================================================================
 * Ephemeral provider — in-memory, test-only.
 *
 * URI form: "ephemeral:<label>".  Stores 32 random bytes as the
 * placeholder "key", produces SHA-256(key||data) as a sign verb's
 * "signature".  Not a real signature; suitable only for handle
 * lifecycle / format-tag tests.
 * =========================================================================== */

/*
 * Ephemeral state holds:
 *   - 32-byte ECDSA-P-256 private scalar (also serves as the test-marker key)
 *   - 64-byte uncompressed public key (X || Y) cached at open time
 *
 * Both fields are populated by uECC_make_key.  uECC validates the
 * scalar is in [1, n-1] before producing the matching public key, so
 * by the time the open call returns we have a usable real keypair.
 */
typedef struct {
    uint8_t priv[32];
    uint8_t pub[64];
} ephemeral_state_t;

static int
ephemeral_open(const char              *uri_rest,
               n00b_quic_secret_kind_t  hint_kind,
               void                   **state_out,
               n00b_quic_secret_kind_t *kind_out,
               n00b_string_t          **label_out)
{
    if (!uri_rest || uri_rest[0] == '\0') {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    ephemeral_state_t *st = n00b_alloc_with_opts(ephemeral_state_t,
        &(n00b_alloc_opts_t){.allocator = alloc, .no_scan = true});

    /* Generate a real P-256 keypair.  uECC_make_key uses the RNG set
     * via uECC_set_rng (or libc's rand if none) — picotls's minicrypto
     * library installs a CSPRNG on first use.  Retry a handful of
     * times to absorb the (astronomically rare) curve-edge rejection. */
    int made = 0;
    for (int attempt = 0; attempt < 8 && !made; attempt++) {
        made = uECC_make_key(st->pub, st->priv, uECC_secp256r1());
    }
    if (!made) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    *state_out = st;
    *kind_out  = hint_kind;  /* honoured as-is for ephemeral */
    *label_out = n00b_string_from_cstr((char *)uri_rest);
    return N00B_QUIC_OK;
}

/* Compute SHA-256 of @p data into a 32-byte big-endian buffer. */
static void
sha256_be(const uint8_t *data, size_t data_len, uint8_t out[32])
{
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    if (data_len > 0) {
        n00b_sha256_update(&ctx, data, data_len);
    }
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
ephemeral_sign(void                 *state,
               const uint8_t        *data,
               size_t                data_len,
               n00b_quic_sig_alg_t   alg,
               n00b_buffer_t       **out_sig)
{
    if (!state || !out_sig) {
        return N00B_QUIC_ERR_NULL_ARG;
    }
    if (!data && data_len > 0) {
        return N00B_QUIC_ERR_NULL_ARG;
    }

    ephemeral_state_t    *st = state;
    n00b_allocator_t     *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    if (alg == N00B_QUIC_SIG_TEST_MARKER) {
        /* Back-compat: SHA-256(priv || data).  Not a real signature. */
        n00b_sha256_ctx_t ctx;
        n00b_sha256_init(&ctx);
        n00b_sha256_update(&ctx, st->priv, sizeof(st->priv));
        if (data_len > 0) {
            n00b_sha256_update(&ctx, data, data_len);
        }
        n00b_sha256_digest_t words;
        n00b_sha256_finalize(&ctx, words);

        n00b_buffer_t *sig = n00b_alloc_with_opts(n00b_buffer_t,
            &(n00b_alloc_opts_t){.allocator = alloc});
        n00b_buffer_init(sig, .length = 32, .allocator = alloc);
        sig->byte_len = 32;
        for (int i = 0; i < 8; i++) {
            uint32_t w        = words[i];
            sig->data[i*4]     = (char)(w >> 24);
            sig->data[i*4 + 1] = (char)(w >> 16);
            sig->data[i*4 + 2] = (char)(w >> 8);
            sig->data[i*4 + 3] = (char)w;
        }

        *out_sig = sig;
        return N00B_QUIC_OK;
    }

    if (alg == N00B_QUIC_SIG_ECDSA_P256) {
        /* SHA-256 the message, then ECDSA-sign with uECC. */
        uint8_t digest[32];
        sha256_be(data, data_len, digest);

        n00b_buffer_t *sig = n00b_alloc_with_opts(n00b_buffer_t,
            &(n00b_alloc_opts_t){.allocator = alloc});
        n00b_buffer_init(sig, .length = 64, .allocator = alloc);
        sig->byte_len = 64;

        if (!uECC_sign(st->priv, digest, sizeof(digest),
                       (uint8_t *)sig->data, uECC_secp256r1())) {
            return N00B_QUIC_ERR_INVALID_ARG;
        }

        *out_sig = sig;
        return N00B_QUIC_OK;
    }

    /* Unsupported algorithm — Ed25519, RSA-PSS, … */
    return N00B_QUIC_ERR_INVALID_ARG;
}

static int
ephemeral_pubkey(void                 *state,
                 n00b_quic_sig_alg_t   alg,
                 n00b_buffer_t       **out_pub)
{
    if (!state || !out_pub) {
        return N00B_QUIC_ERR_NULL_ARG;
    }
    if (alg != N00B_QUIC_SIG_ECDSA_P256) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    ephemeral_state_t *st = state;
    n00b_allocator_t  *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    n00b_buffer_t *pub = n00b_alloc_with_opts(n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_buffer_init(pub, .raw = (char *)st->pub, .length = 64,
                     .allocator = alloc);
    *out_pub = pub;
    return N00B_QUIC_OK;
}

static int
ephemeral_wrap(void           *state,
               const uint8_t  *data,
               size_t          data_len,
               n00b_buffer_t **out_wrapped)
{
    (void)state;
    (void)data;
    (void)data_len;
    (void)out_wrapped;
    /* AEAD wrap is meaningful once picotls is wired up; for now,
     * reject so callers cannot accidentally rely on a no-op. */
    return N00B_QUIC_ERR_NOT_IMPLEMENTED;
}

static void
ephemeral_close(void *state)
{
    if (state) {
        memset(state, 0, sizeof(ephemeral_state_t));
    }
}

static const n00b_quic_secret_vtbl_t ephemeral_vtbl = {
    .scheme = "ephemeral",
    .open   = ephemeral_open,
    .sign   = ephemeral_sign,
    .wrap   = ephemeral_wrap,
    .pubkey = ephemeral_pubkey,
    .close  = ephemeral_close,
};

/* ===========================================================================
 * Lazy provider registration
 *
 * We avoid a global ctor by registering on first use of secret_open.
 * The registration is idempotent and protected against the trivially
 * single-threaded common case (Phase 1 doesn't drive secret_open from
 * multiple threads concurrently).  When that becomes a real concern we
 * promote this to an init function called from n00b_init.
 * =========================================================================== */

#if defined(__APPLE__)
extern const n00b_quic_secret_vtbl_t n00b_keychain_vtbl;
#endif
#if defined(__linux__) && defined(N00B_HAVE_LIBSECRET)
extern const n00b_quic_secret_vtbl_t n00b_libsecret_vtbl;
#endif

static void
ensure_providers_registered(void)
{
    if (g_provider_count == 0) {
        register_provider(&ephemeral_vtbl);
#if defined(__APPLE__)
        register_provider(&n00b_keychain_vtbl);
#endif
#if defined(__linux__) && defined(N00B_HAVE_LIBSECRET)
        register_provider(&n00b_libsecret_vtbl);
#endif
    }
}

/* ===========================================================================
 * Public entry points
 * =========================================================================== */

n00b_result_t(n00b_quic_secret_t *)
n00b_quic_secret_open(n00b_buffer_t *uri) _kargs
{
    n00b_buffer_t *provider = nullptr;
}
{
    if (!uri || !uri->data || uri->byte_len == 0) {
        return n00b_result_err(n00b_quic_secret_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    ensure_providers_registered();

    /* Scheme is everything up to the first colon. */
    const char *raw = uri->data;
    const char *colon = memchr(raw, ':', uri->byte_len);
    if (!colon) {
        return n00b_result_err(n00b_quic_secret_t *, N00B_QUIC_ERR_INVALID_ARG);
    }

    const char *scheme;
    size_t      scheme_len;
    const char *rest = colon + 1;

    if (provider) {
        /* Caller forced provider override; ignore URI scheme. */
        scheme     = provider->data;
        scheme_len = (size_t)provider->byte_len;
    } else {
        scheme     = raw;
        scheme_len = (size_t)(colon - raw);
    }

    /* Explicitly refuse `env:` and `file:` schemes per the design. */
    if ((scheme_len == 3 && memcmp(scheme, "env",  3) == 0) ||
        (scheme_len == 4 && memcmp(scheme, "file", 4) == 0)) {
        return n00b_result_err(n00b_quic_secret_t *, N00B_QUIC_ERR_INVALID_ARG);
    }

    const n00b_quic_secret_vtbl_t *vtbl = find_provider(scheme, scheme_len);
    if (!vtbl) {
        return n00b_result_err(n00b_quic_secret_t *, N00B_QUIC_ERR_NOT_IMPLEMENTED);
    }

    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    n00b_quic_secret_t *s = n00b_alloc_with_opts(n00b_quic_secret_t,
                                &(n00b_alloc_opts_t){.allocator = alloc});

    void                    *state = nullptr;
    n00b_quic_secret_kind_t  kind  = N00B_QUIC_SECRET_PRIVKEY;
    n00b_string_t           *label = nullptr;

    int rc = vtbl->open(rest, kind, &state, &kind, &label);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_quic_secret_t *, rc);
    }

    s->vtbl   = vtbl;
    s->state  = state;
    s->kind   = kind;
    s->label  = label;
    s->closed = false;
    return n00b_result_ok(n00b_quic_secret_t *, s);
}

n00b_string_t *
n00b_quic_secret_format(n00b_quic_secret_t *s)
{
    if (!s) {
        return r"<secret null>";
    }
    if (s->closed) {
        return r"<secret closed>";
    }

    const char *kind_str =
        (s->kind == N00B_QUIC_SECRET_PRIVKEY) ? "privkey"
      : (s->kind == N00B_QUIC_SECRET_SYM_KEY) ? "sym"
      : (s->kind == N00B_QUIC_SECRET_CERT)    ? "cert"
      : "?";
    const char *prov     = (s->vtbl && s->vtbl->scheme) ? s->vtbl->scheme : "?";
    const char *label    = (s->label && s->label->data) ? s->label->data : "";

    /* Bounded scratch.  Labels longer than ~150 bytes are highly
     * unusual; truncate via snprintf. */
    char scratch[256];
    int  n = snprintf(scratch, sizeof(scratch),
                      "<secret kind=%s provider=%s label=%s>",
                      kind_str, prov, label);
    if (n < 0) {
        return r"<secret format-error>";
    }
    return n00b_string_from_cstr(scratch);
}

n00b_quic_secret_kind_t
n00b_quic_secret_kind(n00b_quic_secret_t *s)
{
    /* Defensive default; callers should not pass NULL or closed. */
    return (s && !s->closed) ? s->kind : N00B_QUIC_SECRET_PRIVKEY;
}

n00b_result_t(n00b_buffer_t *)
n00b_quic_secret_sign(n00b_quic_secret_t  *s,
                      n00b_buffer_t       *data,
                      n00b_quic_sig_alg_t  alg)
{
    if (!s) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    if (s->closed) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (s->kind != N00B_QUIC_SECRET_PRIVKEY) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!s->vtbl || !s->vtbl->sign) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NOT_IMPLEMENTED);
    }

    const uint8_t *bytes = nullptr;
    size_t         len   = 0;
    if (data) {
        bytes = (const uint8_t *)data->data;
        len   = (size_t)data->byte_len;
    }

    n00b_buffer_t *sig = nullptr;
    int            rc  = s->vtbl->sign(s->state, bytes, len, alg, &sig);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_buffer_t *, rc);
    }
    return n00b_result_ok(n00b_buffer_t *, sig);
}

n00b_result_t(n00b_buffer_t *)
n00b_quic_secret_wrap(n00b_quic_secret_t *s,
                      n00b_buffer_t      *data)
{
    if (!s) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    if (s->closed) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!s->vtbl || !s->vtbl->wrap) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NOT_IMPLEMENTED);
    }

    const uint8_t *bytes = nullptr;
    size_t         len   = 0;
    if (data) {
        bytes = (const uint8_t *)data->data;
        len   = (size_t)data->byte_len;
    }

    n00b_buffer_t *out = nullptr;
    int            rc  = s->vtbl->wrap(s->state, bytes, len, &out);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_buffer_t *, rc);
    }
    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_quic_secret_pubkey(n00b_quic_secret_t *s, n00b_quic_sig_alg_t alg)
{
    if (!s) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    if (s->closed) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (s->kind != N00B_QUIC_SECRET_PRIVKEY) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    if (!s->vtbl || !s->vtbl->pubkey) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NOT_IMPLEMENTED);
    }

    n00b_buffer_t *pub = nullptr;
    int            rc  = s->vtbl->pubkey(s->state, alg, &pub);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_buffer_t *, rc);
    }
    return n00b_result_ok(n00b_buffer_t *, pub);
}

void
n00b_quic_secret_close(n00b_quic_secret_t *s)
{
    if (!s || s->closed) {
        return;
    }
    if (s->vtbl && s->vtbl->close) {
        s->vtbl->close(s->state);
    }
    s->state  = nullptr;
    s->closed = true;
}
