/*
 * picotls_sni.c — SNI-keyed cert routing wired into picotls's
 *                 per-connection callbacks.
 *
 * Sequence of events for a server-side handshake:
 *
 *   1. Client sends ClientHello with SNI extension.
 *   2. picotls invokes our `on_client_hello` callback.  We read
 *      `params->server_name`, look up the cert_store entry for that
 *      SNI, build a small per-cnx ctx (entry pointer + cached DER
 *      iovecs derived from the entry's PEM chain), and stash it
 *      via `ptls_set_data_ptr`.  If no entry matches, the
 *      handshake fails cleanly.
 *   3. picotls's transcript-driving code reaches the Certificate
 *      message; it calls our `emit_certificate` callback.  We
 *      pull the per-cnx ctx and use `ptls_build_certificate_message`
 *      to write the chain into the emitter's buffer.
 *   4. picotls reaches CertificateVerify; it calls our
 *      `sign_certificate` callback with the handshake transcript
 *      hash as input.  We pull the per-cnx ctx, sign via the
 *      entry's `n00b_quic_secret_t` (ECDSA-P-256), convert the raw
 *      r||s to a DER `SEQUENCE { r, s }`, write to the output
 *      buffer, set `selected_algorithm = 0x0403`.
 *
 * Allocator: per-cnx ctx + DER iovec list live in the conduit
 * pool, alongside the cert_store.  No GC interaction.
 *
 * Threading: each cnx's per-cnx ctx is set once at on_client_hello
 * and not modified afterward.  Lookups during emit/sign just read
 * a pointer.  The cert_store's RCU machinery handles atomicity for
 * mid-flight reloads (Phase 2 § 6).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picoquic.h"
#include "picoquic_internal.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_interpose.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_store.h"
#include "internal/crypto/cert_provisioner_common.h"
#include "internal/crypto/picotls_sni.h"

/* ===========================================================================
 * Per-cnx state
 * =========================================================================== */

typedef struct {
    const n00b_quic_cert_entry_t *entry;       /* borrowed; cert_store owns */
    ptls_iovec_t                 *der_certs;   /* lazily derived from chain_pem */
    size_t                        der_count;
} sni_cnx_t;

static n00b_allocator_t *
sni_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

/* ===========================================================================
 * Multi-cert PEM → DER iovec list
 *
 * `n00b_certp_pem_first_cert_to_der` (cert_provisioner.c) handles a
 * single PEM cert block; here we walk all blocks in the chain.
 * =========================================================================== */

static int
pem_chain_to_der_iovecs(n00b_buffer_t   *pem,
                        ptls_iovec_t   **out_list,
                        size_t          *out_count)
{
    if (!pem || pem->byte_len == 0) return -1;
    const char *src = pem->data;
    const char *end = src + pem->byte_len;
    static const char beg_marker[] = "-----BEGIN CERTIFICATE-----";
    static const char end_marker[] = "-----END CERTIFICATE-----";

    /* First pass: count blocks. */
    size_t n = 0;
    const char *p = src;
    while (p < end) {
        const char *b = strstr(p, beg_marker);
        if (!b) break;
        const char *e = strstr(b, end_marker);
        if (!e || e > end) break;
        n++;
        p = e + sizeof(end_marker) - 1;
    }
    if (n == 0) return -1;

    *out_list = n00b_alloc_array_with_opts(ptls_iovec_t, (int64_t)n,
                                           &(n00b_alloc_opts_t){
                                               .allocator = sni_alloc(),
                                           });

    /* Second pass: decode each block.  The shared helper takes a
     * full buffer; we slice each block into its own buffer. */
    size_t      idx = 0;
    p = src;
    while (idx < n && p < end) {
        const char *b = strstr(p, beg_marker);
        if (!b) break;
        const char *e = strstr(b, end_marker);
        if (!e || e > end) break;
        size_t one_len = (size_t)(e + sizeof(end_marker) - 1 - b);
        n00b_buffer_t *one = n00b_buffer_from_bytes((char *)b, (int64_t)one_len,
                                                    .allocator = sni_alloc());
        auto dr = n00b_certp_pem_first_cert_to_der(one);
        if (!n00b_result_is_ok(dr)) return -1;
        n00b_buffer_t *der = n00b_result_get(dr);
        (*out_list)[idx].base = (uint8_t *)der->data;
        (*out_list)[idx].len  = (size_t)der->byte_len;
        idx++;
        p = e + sizeof(end_marker) - 1;
    }
    *out_count = idx;
    return 0;
}

/* ===========================================================================
 * SNI normalization
 *
 * picotls's params->server_name is an iovec, not NUL-terminated.
 * We copy into a stack buffer and lowercase for lookup matching.
 * =========================================================================== */

static void
sni_to_lookup_key(ptls_iovec_t sni, char out[256])
{
    size_t n = sni.len < 255 ? sni.len : 255;
    for (size_t i = 0; i < n; i++) {
        char c = (char)sni.base[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
        out[i] = c;
    }
    out[n] = '\0';
}

/* ===========================================================================
 * Callbacks
 * =========================================================================== */

/* Side-table layout.
 *
 * picoquic owns `*ptls_get_data_ptr(tls)` — it stores the
 * `picoquic_cnx_t *` there and reads it back in tls_api.c's update-
 * traffic-key callback.  We must NOT overwrite that slot.
 *
 * Instead we keep a per-endpoint hash table keyed on the `ptls_t *`
 * (which stays stable for the duration of one handshake).  Inserts
 * happen at on_client_hello; lookups at emit/sign; removal in the
 * n00b_quic_conn close path (called from picoquic_callback_close).
 * The table is mutex-protected; every code path holds the lock for
 * O(slots) operations only.
 *
 * Sizing: open-addressing fixed cap of SNI_TABLE_CAP.  256 is well
 * above picoquic's default `max_nb_connections` (256) since our
 * entries are pruned on cnx close — only in-flight handshakes count.
 * Doubling to 512 leaves ample slack against the load factor where
 * linear-probe collisions slow noticeably. */
enum { SNI_TABLE_CAP = 512 };

typedef struct {
    ptls_t          *tls;       /* nullptr = empty slot, sentinel = tombstone */
    sni_cnx_t       *value;
    picoquic_cnx_t  *picnx;     /* for cnx-close cleanup */
} sni_slot_t;

#define SNI_SLOT_TOMBSTONE ((ptls_t *)(uintptr_t)1)

/* Shared state for one cert_store wiring.  Lives in the conduit
 * pool (immutable after install) — except the side table, which is
 * mutated under the mutex.  Three small "stubs" hold a back-pointer
 * to this struct + a picotls callback shape, so picoquic's callback
 * slot cleanup at teardown disposes the stubs without our caring
 * about the back-pointed state. */
/* Public-via-internal-header struct so the endpoint can hold a
 * pointer to it (see `endpoint_internal.h::sni_state`).  The
 * `n00b_quic_sni_state_t` typedef itself lives in
 * `internal/quic/picotls_sni.h`. */
struct n00b_quic_sni_state {
    n00b_quic_cert_store_t  *store;          /* borrowed */
    ptls_on_client_hello_t  *fallback_och;
    ptls_emit_certificate_t *fallback_emit;
    ptls_sign_certificate_t *fallback_sign;
    n00b_rwlock_t          *tab_mu;
    sni_slot_t               tab[SNI_TABLE_CAP];
};
typedef struct n00b_quic_sni_state sni_state_t;

typedef struct { ptls_on_client_hello_t  super; sni_state_t *st; } sni_och_stub_t;
typedef struct { ptls_emit_certificate_t super; sni_state_t *st; } sni_emit_stub_t;
typedef struct { ptls_sign_certificate_t super; sni_state_t *st; } sni_sign_stub_t;

/* Map a ptls_t * pointer to a starting slot index.  Mix the bits of
 * the pointer so distinct addresses don't collide on the low bits. */
static size_t
sni_hash(ptls_t *tls)
{
    uintptr_t k = (uintptr_t)tls;
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    return (size_t)(k % SNI_TABLE_CAP);
}

/* Caller holds tab_mu.  Returns SIZE_MAX if the table is full. */
static size_t
sni_find_slot(sni_state_t *self, ptls_t *tls, bool for_insert)
{
    size_t i          = sni_hash(tls);
    size_t first_tomb = SIZE_MAX;
    for (size_t probe = 0; probe < SNI_TABLE_CAP; probe++) {
        size_t j = (i + probe) % SNI_TABLE_CAP;
        if (self->tab[j].tls == tls) {
            return j;
        }
        if (self->tab[j].tls == nullptr) {
            return for_insert ? (first_tomb != SIZE_MAX ? first_tomb : j)
                              : SIZE_MAX;
        }
        if (self->tab[j].tls == SNI_SLOT_TOMBSTONE && first_tomb == SIZE_MAX) {
            first_tomb = j;
        }
    }
    return for_insert ? first_tomb : SIZE_MAX;
}

static int
sni_table_insert(sni_state_t *self, ptls_t *tls, sni_cnx_t *cnx,
                 picoquic_cnx_t *picnx)
{
    n00b_data_write_lock(self->tab_mu);
    size_t j = sni_find_slot(self, tls, true);
    if (j == SIZE_MAX) {
        n00b_data_unlock(self->tab_mu);
        return -1;
    }
    self->tab[j].tls   = tls;
    self->tab[j].value = cnx;
    self->tab[j].picnx = picnx;
    n00b_data_unlock(self->tab_mu);
    return 0;
}

static sni_cnx_t *
sni_table_lookup(sni_state_t *self, ptls_t *tls)
{
    n00b_data_write_lock(self->tab_mu);
    size_t j = sni_find_slot(self, tls, false);
    sni_cnx_t *v = (j == SIZE_MAX) ? nullptr : self->tab[j].value;
    n00b_data_unlock(self->tab_mu);
    return v;
}

void
n00b_quic_picotls_sni_cleanup_cnx(n00b_quic_sni_state_t *self,
                                  picoquic_cnx_t        *picnx)
{
    if (!self || !picnx) return;
    n00b_data_write_lock(self->tab_mu);
    for (size_t k = 0; k < SNI_TABLE_CAP; k++) {
        if (self->tab[k].tls != nullptr
            && self->tab[k].tls != SNI_SLOT_TOMBSTONE
            && self->tab[k].picnx == picnx) {
            self->tab[k].tls   = SNI_SLOT_TOMBSTONE;
            self->tab[k].value = nullptr;
            self->tab[k].picnx = nullptr;
        }
    }
    n00b_data_unlock(self->tab_mu);
}

static int
sni_on_client_hello(ptls_on_client_hello_t            *self_,
                    ptls_t                            *tls,
                    ptls_on_client_hello_parameters_t *params)
{
    sni_och_stub_t *stub = (sni_och_stub_t *)self_;
    sni_state_t    *self = stub->st;

    char key[256] = {0};
    if (params->server_name.len > 0) {
        sni_to_lookup_key(params->server_name, key);
    }
    /* Empty SNI ("") matches the catch-all "*" pattern via our
     * cert_store's matching rules (catch-all has the lowest
     * precedence; if anything else matches, that wins). */
    const n00b_quic_cert_entry_t *entry =
        n00b_quic_cert_store_lookup(self->store,
                                    key[0] ? key : "");
    if (!entry) {
        /* Fall back to the picoquic-installed default cert path
         * (compat for endpoints that have ALSO called
         * picoquic_set_tls_certificate_chain). */
        if (self->fallback_och && self->fallback_och->cb) {
            return self->fallback_och->cb(self->fallback_och, tls, params);
        }
        return PTLS_ALERT_UNRECOGNIZED_NAME;
    }

    /* Build a per-cnx ctx and stash it.
     *
     * `entry` is a borrowed pointer into the cert_store's current
     * view at the time of this lookup.  Phase 3 § 5.3's no-tear
     * property — "a mid-handshake cert reload must not corrupt an
     * in-flight cnx" — relies on two cert_store invariants:
     *
     *   1. Entries are immutable post-publish (install/replace
     *      allocates a fresh entry; the existing one is never
     *      mutated).
     *   2. The rcu graveyard retains every prior view for the
     *      lifetime of the store, so the borrowed pointer stays
     *      valid even after the live view has swapped.
     *
     * If either invariant changes, the borrowed-pointer model here
     * is unsafe and we'd need to move to per-cnx deep-copy or
     * reference counting.  See test/unit/test_quic_reload_race.c
     * for the property test substrate. */
    sni_cnx_t *cnx = n00b_alloc_with_opts(sni_cnx_t,
        &(n00b_alloc_opts_t){.allocator = sni_alloc()});
    cnx->entry = entry;

    if (pem_chain_to_der_iovecs(entry->chain_pem,
                                &cnx->der_certs, &cnx->der_count) != 0) {
        return PTLS_ERROR_LIBRARY;
    }

    /* Insert into the side table.  The picnx pointer is what
     * picoquic stores at *ptls_get_data_ptr(tls); we capture it for
     * the cleanup hook (see n00b_quic_picotls_sni_cleanup_cnx).  We
     * do NOT overwrite the data ptr — picoquic's update-traffic-key
     * callback dereferences it as picoquic_cnx_t *. */
    picoquic_cnx_t *picnx = (picoquic_cnx_t *)*ptls_get_data_ptr(tls);
    if (sni_table_insert(self, tls, cnx, picnx) != 0) {
        /* Side table full → fail the handshake cleanly rather than
         * silently leak.  Operators who hit this need to bump
         * SNI_TABLE_CAP or reduce their max in-flight handshakes. */
        return PTLS_ERROR_LIBRARY;
    }

    if (params->server_name.len > 0) {
        ptls_set_server_name(tls, key, strlen(key));
    }

    /* Chain to the picoquic default if one was installed (rare). */
    if (self->fallback_och && self->fallback_och->cb) {
        (void)self->fallback_och->cb(self->fallback_och, tls, params);
    }
    return 0;
}

static int
sni_emit_certificate(ptls_emit_certificate_t *self_,
                     ptls_t                  *tls,
                     ptls_message_emitter_t  *emitter,
                     ptls_key_schedule_t     *key_sched,
                     ptls_iovec_t             context,
                     int                      push_status_request,
                     const uint16_t          *compress_algos,
                     size_t                   num_compress_algos)
{
    (void)push_status_request;
    (void)compress_algos;
    (void)num_compress_algos;

    sni_emit_stub_t *stub = (sni_emit_stub_t *)self_;
    sni_state_t     *self = stub->st;
    sni_cnx_t       *cnx  = sni_table_lookup(self, tls);
    if (!cnx || cnx->der_count == 0) {
        if (self->fallback_emit && self->fallback_emit->cb) {
            return self->fallback_emit->cb(self->fallback_emit, tls, emitter,
                                           key_sched, context,
                                           push_status_request,
                                           compress_algos,
                                           num_compress_algos);
        }
        return PTLS_ERROR_LIBRARY;
    }

    int ret;
    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
        if ((ret = ptls_build_certificate_message(emitter->buf, context,
                                                  cnx->der_certs,
                                                  cnx->der_count,
                                                  ptls_iovec_init(NULL, 0))) != 0)
            goto Exit;
    });
    ret = 0;
Exit:
    return ret;
}

/* Convert raw 64-byte ECDSA r||s into DER SEQUENCE(r INTEGER, s INTEGER).
 * Same shape as the helper in acme_csr.c — reused here verbatim
 * because both the CSR and the TLS handshake's CertificateVerify use
 * X.509 DER ECDSA signatures. */
static size_t
der_int_size(const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    /* tag + len-octet + body */
    return 1 + 1 + mag + (size_t)pad;
}

static size_t
der_int_emit(uint8_t *out, const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(mag + (size_t)pad);
    size_t off = 2;
    if (pad) out[off++] = 0x00;
    memcpy(out + off, be + i, mag);
    return off + mag;
}

static int
sni_sign_certificate(ptls_sign_certificate_t *self_,
                     ptls_t                  *tls,
                     ptls_async_job_t       **async,
                     uint16_t                *selected_algorithm,
                     ptls_buffer_t           *output,
                     ptls_iovec_t             input,
                     const uint16_t          *algorithms,
                     size_t                   num_algorithms)
{
    (void)async;

    sni_sign_stub_t *stub = (sni_sign_stub_t *)self_;
    sni_state_t     *self = stub->st;
    sni_cnx_t       *cnx  = sni_table_lookup(self, tls);
    if (!cnx || !cnx->entry || !cnx->entry->key) {
        if (self->fallback_sign && self->fallback_sign->cb) {
            return self->fallback_sign->cb(self->fallback_sign, tls, async,
                                           selected_algorithm, output, input,
                                           algorithms, num_algorithms);
        }
        return PTLS_ERROR_LIBRARY;
    }

    /* Confirm the client offered ES256.  If not, fail. */
    bool es256_offered = false;
    for (size_t i = 0; i < num_algorithms; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
            es256_offered = true;
            break;
        }
    }
    if (!es256_offered) {
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }
    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;

    /* Sign via our secret API.  It hashes input with SHA-256 and
     * signs with ECDSA-P-256, returning raw 64-byte r||s. */
    n00b_buffer_t in_buf;
    memset(&in_buf, 0, sizeof(in_buf));
    n00b_buffer_init(&in_buf, .raw = (char *)input.base,
                     .length = (int64_t)input.len,
                     .allocator = sni_alloc());

    auto sr = n00b_quic_secret_sign((n00b_quic_secret_t *)cnx->entry->key,
                                    &in_buf,
                                    N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sr)) {
        return PTLS_ERROR_LIBRARY;
    }
    n00b_buffer_t *raw_sig = n00b_result_get(sr);
    if (raw_sig->byte_len != 64) {
        return PTLS_ERROR_LIBRARY;
    }
    const uint8_t *raw = (const uint8_t *)raw_sig->data;

    /* Convert raw r||s → DER SEQUENCE(r, s). */
    size_t r_sz   = der_int_size(raw,      32);
    size_t s_sz   = der_int_size(raw + 32, 32);
    size_t inner  = r_sz + s_sz;

    /* Reserve in the output buffer.  picotls's ptls_buffer_reserve
     * grows on demand; total bytes = 2 (seq tag+len) + inner.
     * inner < 256 always (each int < 33 + 2 overhead), so the seq
     * length is single-byte short-form. */
    int ret = ptls_buffer_reserve(output, 2 + inner);
    if (ret != 0) return ret;
    output->base[output->off++] = 0x30;            /* SEQUENCE */
    output->base[output->off++] = (uint8_t)inner;
    output->off += der_int_emit(output->base + output->off, raw,      32);
    output->off += der_int_emit(output->base + output->off, raw + 32, 32);
    return 0;
}

/* ===========================================================================
 * Installation
 * =========================================================================== */

static const uint16_t es256_alg_list[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    UINT16_MAX,
};

int
n00b_quic_picotls_sni_install(picoquic_quic_t        *quic,
                              n00b_quic_cert_store_t *store,
                              n00b_quic_sni_state_t **out_state)
{
    if (!quic || !store) return -1;
    (void)es256_alg_list;  /* unused: sign_certificate has no .algos */

    ptls_context_t *ctx = (ptls_context_t *)quic->tls_master_ctx;
    if (!ctx) return -1;

    /* Persistent state — borrowed pointers; lives in the conduit
     * pool for the rest of the process lifetime. */
    sni_state_t *st = n00b_alloc_with_opts(sni_state_t,
        &(n00b_alloc_opts_t){.allocator = sni_alloc()});
    st->store         = store;
    st->fallback_och  = ctx->on_client_hello;
    st->fallback_emit = ctx->emit_certificate;
    st->fallback_sign = ctx->sign_certificate;
    st->tab_mu = n00b_data_lock_new(); 
    /* Side table starts zeroed (calloc semantics on conduit-pool
     * allocations — every slot's tls field is nullptr ⇒ "empty"). */

    /* Three malloc'd stubs.  The shimmed picoquic free path at
     * endpoint teardown can dispose these correctly because
     * `n00b_interposed_free()` delegates non-user-pool pointers back
     * to libc.  The back-pointed `st` stays in the conduit pool (and
     * is leaked when the endpoint goes away — acceptable for v1,
     * single endpoint per process is the common shape). */
    sni_och_stub_t  *och_stub  = malloc(sizeof(*och_stub));
    sni_emit_stub_t *emit_stub = malloc(sizeof(*emit_stub));
    sni_sign_stub_t *sign_stub = malloc(sizeof(*sign_stub));
    if (!och_stub || !emit_stub || !sign_stub) {
        free(och_stub); free(emit_stub); free(sign_stub);
        return -1;
    }
    och_stub->super.cb  = sni_on_client_hello;
    och_stub->st        = st;
    emit_stub->super.cb = sni_emit_certificate;
    emit_stub->st       = st;
    sign_stub->super.cb = sni_sign_certificate;
    sign_stub->st       = st;

    /* If picoquic already installed a fallback at one of these
     * slots, picoquic now considers the slot freed by us when it
     * frees the new pointer.  Free the old one explicitly through
     * the interposed boundary: those fallbacks may have been
     * allocated by the shimmed vendored code's malloc path. */
    if (st->fallback_och) {
        n00b_interposed_free(st->fallback_och);
    }
    if (st->fallback_emit) {
        n00b_interposed_free(st->fallback_emit);
    }
    if (st->fallback_sign) {
        n00b_interposed_free(st->fallback_sign);
    }
    /* Now that we've consumed (and forgotten) the originals,
     * disable the fallbacks — they don't survive past install. */
    st->fallback_och  = nullptr;
    st->fallback_emit = nullptr;
    st->fallback_sign = nullptr;

    ctx->on_client_hello  = &och_stub->super;
    ctx->emit_certificate = &emit_stub->super;
    ctx->sign_certificate = &sign_stub->super;

    if (out_state) {
        *out_state = st;
    }
    return 0;
}
