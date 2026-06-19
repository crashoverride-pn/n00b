/**
 * @file picotls_sni.h
 * @internal
 * @brief Wire a `n00b_quic_cert_store_t` into picotls's
 *        per-connection callbacks.
 *
 * Three callbacks make up the routing:
 *
 *   - `on_client_hello`: reads the SNI from the ClientHello,
 *     looks up the matching cert in the store, allocates a small
 *     per-cnx context struct that caches the DER iovec list +
 *     the signing key handle, registers it in a per-endpoint
 *     side table keyed on the `ptls_t *` (we don't use
 *     `ptls_get_data_ptr` because picoquic owns that slot for the
 *     `picoquic_cnx_t *`).
 *   - `emit_certificate`: looks up the per-cnx context, hands its
 *     iovecs to `ptls_build_certificate_message`.
 *   - `sign_certificate`: looks up the per-cnx context, signs via
 *     `n00b_quic_secret_sign(N00B_QUIC_SIG_ECDSA_P256)`, converts
 *     raw r||s to DER, writes to picotls's output buffer with
 *     `selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256`.
 *
 * Per-cnx state lives in the conduit pool, indexed by `ptls_t *`
 * in the per-endpoint side table; entries are pruned in the
 * `picoquic_callback_close` hook driven by the n00b_quic_conn
 * default callback (see `n00b_quic_picotls_sni_cleanup_cnx`).
 *
 * Phase 2 audit-tail item #12: this is the wiring that turns the
 * cert_store data structure into actual per-cnx atomic SNI
 * routing — the multi-cert successor to the global
 * `picoquic_set_tls_certificate_chain`-based hot reload.
 *
 * @see ~/dd/quic_2.md § 6
 */
#pragma once

#include "n00b.h"
#include "internal/crypto/cert_store.h"

/* Forward decl — public header is `picoquic.h` which is large. */
typedef struct st_picoquic_quic_t picoquic_quic_t;

/**
 * @brief Install the SNI-routing callbacks on @p quic's TLS context.
 *
 * Must be called *after* `picoquic_create` has populated the TLS
 * context, and *instead of* `picoquic_set_tls_certificate_chain` /
 * `picoquic_set_private_key_from_file` (we manage the cert + key
 * ourselves now).
 *
 * @param quic     picoquic context.
 * @param store    Cert store to consult on every ClientHello.
 *                 Must outlive the picoquic context.
 *
 * @return 0 on success; a negative value on argument errors.
 */
/* Opaque type — full definition lives in src/quic/picotls_sni.c. */
typedef struct n00b_quic_sni_state n00b_quic_sni_state_t;

extern int
n00b_quic_picotls_sni_install(picoquic_quic_t        *quic,
                              n00b_quic_cert_store_t *store,
                              n00b_quic_sni_state_t **out_state);

/* Forward decl. */
typedef struct st_picoquic_cnx_t picoquic_cnx_t;

/**
 * @brief Drop side-table entries owned by the dying picoquic cnx.
 *
 * Called from the n00b_quic_conn default callback on
 * `picoquic_callback_close` (and cousins).  Pass the
 * `sni_state` pointer captured at install time (the endpoint
 * caches it in its `sni_state` field).
 */
extern void
n00b_quic_picotls_sni_cleanup_cnx(n00b_quic_sni_state_t *state,
                                  picoquic_cnx_t        *picnx);
