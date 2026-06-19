/**
 * @file sticky_secret.h
 * @brief Rotatable symmetric secret used for picoquic's stateless-
 *        reset and address-validation tokens.
 *
 * "Sticky" because the same key bytes need to be used by every
 * instance of a server farm so any instance can correctly emit a
 * stateless reset for any client (RFC 9000 § 10.3).  Rotation is
 * coordinated at the deployment-playbook layer (operator-driven for
 * v1; multi-instance leader election is § 7.3 option 2 in
 * `~/dd/quic_2.md`, deferred).
 *
 * Phase 2 v1: each instance has its own sticky secret generated
 * locally from the OS CSPRNG.  This is correct for single-instance
 * deployments and is the bootstrap baseline for multi-instance
 * deployments — they need to additionally distribute a shared
 * source through the manifest's secret-source URI (§ 9), which is
 * out of scope for this module.
 *
 * Memory + threading discipline:
 *   - Reads are lock-free: the secret bytes pointer is
 *     `_Atomic(uint8_t *)`, swapped with release on rotation and
 *     read with acquire.
 *   - Old key buffers are kept alive in a graveyard list (same
 *     idea as the cert store) for safety; rotations are infrequent
 *     (24h cadence) so this never grows large.
 *   - All buffers live in the conduit pool.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"

typedef struct n00b_quic_sticky_secret n00b_quic_sticky_secret_t;

/**
 * @brief Allocate a sticky secret with @p bytes_needed bytes of
 *        OS-CSPRNG entropy.
 *
 * @param bytes_needed Length of the secret in bytes (16 for an
 *                     address-validation token key, 32 for a
 *                     stateless-reset secret).  Must be a multiple
 *                     of 16 in [16, 64].
 *
 * @return Result: ok with the new handle on success.
 */
extern n00b_result_t(n00b_quic_sticky_secret_t *)
n00b_quic_sticky_secret_open(size_t bytes_needed);

/**
 * @brief Read the current secret bytes.
 *
 * @param ss        Handle.
 * @param out_len   Receives the byte length set at construction.
 *
 * @return Pointer to the current bytes; valid until the next
 *         `_close` call (rotation does NOT invalidate the previous
 *         pointer — old buffers are preserved in the graveyard).
 *         Returns nullptr on bad arguments.
 */
extern const uint8_t *
n00b_quic_sticky_secret_current(n00b_quic_sticky_secret_t *ss,
                                size_t                    *out_len);

/**
 * @brief Generate fresh CSPRNG bytes and atomically swap them in as
 *        the new current secret.
 *
 * Subsequent calls to @c n00b_quic_sticky_secret_current observe the
 * new bytes.
 *
 * **Important caveat about running endpoints:** picoquic accepts the
 * stateless-reset seed and the address-validation token key only at
 * @c picoquic_create time — there's no setter for live updates.  So
 * calling @c rotate on a sticky secret already consumed by an
 * existing endpoint updates *this module's* bytes but does NOT
 * propagate to that endpoint's QUIC behaviour.  To actually rotate
 * the secret on a running server you must build a new endpoint with
 * the new bytes (typically: drain old conns, swap to new endpoint,
 * close old).
 *
 * The intended deployment story is that operators rotate by rolling
 * instances, not by calling @c rotate against a single long-lived
 * endpoint.  See `~/dd/quic_2.md` § 7.3 and the
 * `.stateless_reset_secret` kwarg comment in
 * `include/quic/endpoint.h`.
 */
extern n00b_result_t(bool)
n00b_quic_sticky_secret_rotate(n00b_quic_sticky_secret_t *ss);

/** @brief Close the handle.  Idempotent. */
extern void
n00b_quic_sticky_secret_close(n00b_quic_sticky_secret_t *ss);
