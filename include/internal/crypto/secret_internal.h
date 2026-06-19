/**
 * @file secret_internal.h
 * @internal
 * @brief Internal layout of `n00b_quic_secret_t` and the provider vtable.
 *
 * Public callers see only the opaque type; this header is for the
 * secret module itself and downstream code (handshake / token
 * minting) that needs to dispatch verbs over a handle.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/string.h"
#include "core/buffer.h"
#include "crypto/secret.h"

/**
 * @brief Provider vtable.
 *
 * Each provider implements as much of the verb set as its backing
 * material allows.  Unsupported verbs return
 * @c N00B_QUIC_ERR_NOT_IMPLEMENTED.
 */
typedef struct {
    /** @brief Provider URI scheme prefix without the trailing colon. */
    const char *scheme;

    /** @brief Open a handle from the provider-specific portion of the URI. */
    int (*open)(const char              *uri_rest,
                n00b_quic_secret_kind_t  hint_kind,
                void                   **state_out,
                n00b_quic_secret_kind_t *kind_out,
                n00b_string_t          **label_out);

    /** @brief Sign — see @c n00b_quic_secret_sign for contract. */
    int (*sign)(void                 *state,
                const uint8_t        *data,
                size_t                data_len,
                n00b_quic_sig_alg_t   alg,
                n00b_buffer_t       **out_sig);

    /** @brief Wrap — see @c n00b_quic_secret_wrap for contract. */
    int (*wrap)(void           *state,
                const uint8_t  *data,
                size_t          data_len,
                n00b_buffer_t **out_wrapped);

    /**
     * @brief Export the public key counterpart, if the kind is privkey.
     *
     * The output format depends on the algorithm: for
     * @c N00B_QUIC_SIG_ECDSA_P256 the buffer is 64 bytes
     * (uncompressed: X || Y, no 0x04 prefix).  Providers that don't
     * back the requested algorithm return
     * @c N00B_QUIC_ERR_INVALID_ARG; providers that have no concept of
     * an exportable public key return @c N00B_QUIC_ERR_NOT_IMPLEMENTED.
     */
    int (*pubkey)(void                 *state,
                  n00b_quic_sig_alg_t   alg,
                  n00b_buffer_t       **out_pub);

    /** @brief Release backend-private state.  Zero any key material. */
    void (*close)(void *state);
} n00b_quic_secret_vtbl_t;

/**
 * @brief Internal handle layout.
 *
 * @c label is the human-readable, non-secret identifier extracted from
 * the URI; it appears in the format tag.
 */
struct n00b_quic_secret {
    const n00b_quic_secret_vtbl_t *vtbl;
    void                          *state;
    n00b_quic_secret_kind_t        kind;
    n00b_string_t                 *label;
    bool                           closed;
};
