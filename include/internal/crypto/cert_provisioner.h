/**
 * @file cert_provisioner.h
 * @internal
 * @brief Cert-provisioner abstraction (RFC 8555 § 7.4 / Phase 2 § 10).
 *
 * One handle, three back-ends:
 *   - **static**:   PEM chain + key already on disk (or in a secret
 *                   provider).  Renewal is the operator's problem.
 *   - **acme**:     drives `n00b_acme_acquire_certificate` end-to-end.
 *   - **external**: spawns a configured command (e.g., `step-cli`),
 *                   waits for it to exit, then loads the resulting
 *                   files from disk like the static path.
 *
 * The trait is intentionally tiny.  Callers (currently the cert
 * store / hot-reload swap, landing in the next deliverable) drive
 * the renewal cadence — they call `acquire` once on startup, then
 * periodically check `should_renew` and call `acquire` again when
 * it returns true.
 *
 * @see ~/dd/quic_2.md § 10
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "crypto/secret.h"
#include "internal/crypto/acme.h"

/**
 * @brief A provisioned cert + the key that signed it.
 *
 * @c chain_pem is the bytes the TLS layer presents on the wire:
 * one or more PEM `CERTIFICATE` blocks, leaf first, intermediates
 * after.  @c key is the private-key handle (must outlive any
 * connection that's using the cert).
 *
 * @c not_before_ms and @c not_after_ms are Unix-epoch milliseconds
 * parsed out of the leaf cert.  The provisioner sets them; callers
 * use them to decide when to renew.
 */
typedef struct {
    n00b_buffer_t      *chain_pem;
    n00b_quic_secret_t *key;
    int64_t             not_before_ms;
    int64_t             not_after_ms;
} n00b_quic_cert_t;

typedef struct n00b_quic_cert_provisioner n00b_quic_cert_provisioner_t;

struct n00b_quic_cert_provisioner {
    /** @brief Diagnostic name (used in logs / preflight reports). */
    const char *name;

    /**
     * @brief Acquire the cert (initial fetch) or re-acquire (renewal).
     *
     * Synchronous; may block on network IO (ACME) or subprocess
     * (external).  Returns a freshly allocated @c n00b_quic_cert_t
     * on success.
     */
    n00b_result_t(n00b_quic_cert_t *) (*acquire)(
        n00b_quic_cert_provisioner_t *self);

    /**
     * @brief Decide whether @p current should be renewed.
     *
     * Default implementation returns true when
     * `now > current->not_after_ms - margin`.  Provisioners that
     * never renew (e.g., static-from-disk that the operator
     * manages externally) return false unconditionally.
     *
     * @param current The currently-installed cert; may be NULL on
     *                first-time call (in which case the answer is
     *                always "yes, acquire").
     */
    bool (*should_renew)(n00b_quic_cert_provisioner_t *self,
                         const n00b_quic_cert_t       *current);

    /**
     * @brief Release any provisioner-private resources.  Idempotent.
     */
    void (*close)(n00b_quic_cert_provisioner_t *self);

    /** @brief Provider-private state. */
    void *ctx;
};

/* ===========================================================================
 * Static provisioner: PEM chain + key already on disk.
 * =========================================================================== */

/**
 * @brief Construct a static provisioner from on-disk PEM material.
 *
 * @param chain_pem_path  Path to a PEM file containing the leaf
 *                        certificate first, followed by any
 *                        intermediates back-to-back.
 * @param key_secret      Open secret handle for the private key
 *                        (e.g., from `keychain:` or `ephemeral:`).
 *
 * @return Owned provisioner handle on success; close with
 *         @c n00b_quic_cert_provisioner_close.
 */
extern n00b_result_t(n00b_quic_cert_provisioner_t *)
n00b_quic_cert_provisioner_static(const char         *chain_pem_path,
                                  n00b_quic_secret_t *key_secret);

/* ===========================================================================
 * ACME provisioner: drives the orchestrator.
 *
 * The provisioner does not own the keys or the challenge provider —
 * it just holds borrowed pointers.  Lifetime is the caller's
 * responsibility (typically the manifest entry that constructed it).
 * =========================================================================== */

extern n00b_result_t(n00b_quic_cert_provisioner_t *)
n00b_quic_cert_provisioner_acme(const char                     *directory_url,
                                n00b_quic_secret_t             *account_key,
                                n00b_quic_secret_t             *cert_key,
                                const char *const              *dns_names,
                                size_t                          dns_name_count,
                                n00b_acme_challenge_provider_t *provider)
    _kargs {
        /* Margin before not_after at which `should_renew` flips to true. */
        int64_t renew_margin_ms = (int64_t)30 * 24 * 60 * 60 * 1000; /* 30d */
        int32_t timeout_ms       = 30000;
        int32_t poll_max_wait_ms = 60000;
    };

/* ===========================================================================
 * External provisioner: fork+execvp a command, then load files.
 *
 * Suitable for dev workflows that already have `step-cli` (or
 * similar) producing certs into a known directory.
 *
 * Takes an explicit argv (NULL-terminated string array) — *not* a
 * single shell command — so callers can never accidentally introduce
 * shell injection from config-file substitution.  The child runs
 * with the parent's environment via `execvp` (PATH search applies).
 *
 * Renewal is operator-driven: callers set @c force_refresh on the
 * handle when they want the next `should_renew` to return true.
 * (Future Phase 2 work may add inotify/fsevents-based watches.)
 *
 * @param argv            NULL-terminated `argv` array.  argv[0] is
 *                        the command name; subsequent entries are
 *                        the literal arguments.  E.g.,
 *                        `{"step", "ca", "certificate", domain,
 *                          cert_path, key_path, NULL}`.
 * @param chain_pem_path  Where the command writes the cert chain.
 * @param key_secret      Secret handle for the private key (the
 *                        operator manages its lifecycle).
 * =========================================================================== */

extern n00b_result_t(n00b_quic_cert_provisioner_t *)
n00b_quic_cert_provisioner_external(const char *const  *argv,
                                    const char         *chain_pem_path,
                                    n00b_quic_secret_t *key_secret);

/** @brief Force the next `should_renew` call to return true. */
extern void
n00b_quic_cert_provisioner_external_force_refresh(
    n00b_quic_cert_provisioner_t *self);

/**
 * @brief Attach a filesystem watcher so `should_renew` fires
 *        automatically when the chain PEM file changes on disk.
 *
 * Without this attach, external-cert renewal is operator-driven via
 * @ref n00b_quic_cert_provisioner_external_force_refresh.  With it,
 * any vnode event on the watched path (write / rename / delete)
 * flips the internal force_refresh flag the next time
 * `should_renew` runs (which drains the watch inbox first).
 *
 * Handles in-place rewrites (NOTE_WRITE / IN_MODIFY) directly; for
 * atomic-rename rotations (write tmp + rename) the rename event
 * itself triggers a refresh and the watcher re-opens the path on
 * the subsequent acquire.
 *
 * @param self     Provisioner returned by @ref
 *                 n00b_quic_cert_provisioner_external.
 * @param conduit  Conduit instance to register the watch with.
 *
 * @return  ok(true) on success.  err on path-open or watch-register
 *          failure.
 */
typedef struct n00b_conduit n00b_conduit_t;
extern n00b_result_t(bool)
n00b_quic_cert_provisioner_external_watch(
    n00b_quic_cert_provisioner_t *self,
    n00b_conduit_t               *conduit);

/* ===========================================================================
 * Common close
 * =========================================================================== */

extern void
n00b_quic_cert_provisioner_close(n00b_quic_cert_provisioner_t *self);
