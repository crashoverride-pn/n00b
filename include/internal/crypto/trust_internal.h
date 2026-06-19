/**
 * @file trust_internal.h
 * @internal
 * @brief Internal layout of `n00b_quic_trust_t` and the backend vtable.
 *
 * Public callers see only the opaque type; this header is for the
 * trust module itself and the pieces (e.g., picotls verify-callback
 * adapter) that need to dispatch into a backend.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "crypto/trust.h"

/**
 * @brief Trust backend vtable.
 *
 * `verify_chain` is the cold-path hook invoked once per handshake.
 * `finalize` releases backend-private state on close.
 *
 * Non-implemented backends return @c N00B_QUIC_ERR_NOT_IMPLEMENTED
 * from `verify_chain`.  This is how `n00b_quic_trust_system` and
 * `n00b_quic_trust_with_extra` behave until picotls integration.
 */
typedef struct {
    /**
     * @brief Verify a peer cert chain against this backend.
     * @return @c N00B_QUIC_OK on success; a negative
     *         @c n00b_quic_err_t code on failure.
     */
    int (*verify_chain)(void              *backend_state,
                        const uint8_t    **chain_der,
                        const size_t      *chain_lens,
                        size_t             count,
                        const char        *sni);

    /** @brief Release backend-private state. */
    void (*finalize)(void *backend_state);

    /** @brief Human-readable backend name (for diagnostics). */
    const char *name;
} n00b_quic_trust_vtbl_t;

/**
 * @brief Internal trust handle layout.
 *
 * Backends store their state in the trailing @c backend_state pointer
 * which is allocated alongside the handle (or separately if it must
 * outlive a single connection).
 */
struct n00b_quic_trust {
    const n00b_quic_trust_vtbl_t *vtbl;
    void                         *backend_state;
    n00b_quic_trust_purpose_t     purpose;
    bool                          closed;
};
