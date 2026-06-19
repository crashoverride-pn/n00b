/**
 * @file secret_libsecret.h
 * @internal
 * @brief Linux `libsecret:` secret-handle provider — vtable declaration.
 *
 * The provider retrieves a PEM-encoded ECDSA P-256 private key stored
 * in a Secret Service daemon (e.g. gnome-keyring) under the supplied
 * label, parses it via the picotls minicrypto helpers, and exposes
 * sign / pubkey operations through the standard
 * `n00b_quic_secret_vtbl_t` interface.
 *
 * URI scheme: `libsecret:<label>`.
 *
 * Compiled only under `__linux__` + `HAVE_LIBSECRET`.  The provider
 * is wired into the dispatch table by `secret.c` when those
 * conditions hold; on every other platform / build it does not exist.
 */
#pragma once

#include "internal/crypto/secret_internal.h"

extern const n00b_quic_secret_vtbl_t n00b_libsecret_vtbl;
