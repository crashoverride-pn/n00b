/**
 * @file secret_keychain_raw.h
 * @internal
 * @brief Pure-C boundary for the macOS Keychain secret provider.
 *
 * The .m file (`src/net/quic/secret_keychain.m`) compiles through
 * Apple's Objective-C compiler so Security.framework headers work;
 * it must NOT see ncc extensions.  This header declares only plain-C
 * functions that the .m exports and that the bridge file
 * (`secret_keychain_bridge.c`, compiled through ncc) calls.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open a SecKeyRef from the user's default keychain by
 *        application-label.
 *
 * @param label       UTF-8 label bytes (not necessarily NUL-terminated).
 * @param label_len   Byte length of @p label.
 * @param sec_key_out Out-pointer: receives an opaque SecKeyRef on
 *                    success.  Caller transfers ownership; must
 *                    release with @ref n00b_keychain_close_raw.
 *
 * @return N00B_QUIC_OK on success; N00B_QUIC_ERR_INVALID_ARG on no
 *         match or unsupported key type (Phase 1: ECDSA-P-256 only).
 */
extern int
n00b_keychain_open_raw(const char *label, size_t label_len,
                       void      **sec_key_out);

/**
 * @brief Extract the 64-byte uncompressed (X || Y) public key.
 *
 * @param sec_key_opaque  An opaque SecKeyRef from @ref
 *                        n00b_keychain_open_raw.
 * @param out             Caller-provided 64-byte output buffer.
 *
 * @return N00B_QUIC_OK on success.
 */
extern int
n00b_keychain_pubkey_raw(void *sec_key_opaque, uint8_t out[64]);

/* Maximum DER-encoded ECDSA-P-256 signature length:
 * SEQUENCE(2) + 2 * INTEGER(2 + 33).  72 is the upper bound. */
#define N00B_KEYCHAIN_SIG_MAX 72

/**
 * @brief Sign @p data (ECDSA-P-256 over SHA-256) with the keychain key.
 *
 * Caller provides the output buffer (no allocation crosses the
 * Apple-framework boundary).  72 bytes is the DER cap for an
 * ECDSA-P-256 signature; see @ref N00B_KEYCHAIN_SIG_MAX.
 *
 * @param sec_key_opaque  An opaque SecKeyRef from @ref
 *                        n00b_keychain_open_raw.
 * @param data            Bytes to sign.
 * @param data_len        Byte length of @p data.
 * @param sig_buf_out     Caller-provided output buffer.
 * @param sig_buf_cap     Capacity of @p sig_buf_out in bytes.
 * @param sig_len_out     Out-pointer: receives the signature length.
 *
 * @return N00B_QUIC_OK on success; FRAME_TOO_LARGE if @p sig_buf_cap
 *         is smaller than the produced signature.
 */
extern int
n00b_keychain_sign_raw(void          *sec_key_opaque,
                       const uint8_t *data,
                       size_t         data_len,
                       uint8_t       *sig_buf_out,
                       size_t         sig_buf_cap,
                       size_t        *sig_len_out);

/**
 * @brief Release the SecKeyRef opened by @ref n00b_keychain_open_raw.
 */
extern void n00b_keychain_close_raw(void *sec_key_opaque);

/* ----------------------------------------------------------------
 * Test-only helpers — used by `test/unit/test_quic_secret.c` to do
 * a hermetic round-trip without depending on a pre-provisioned
 * keychain entry.  Not part of the provider's normal surface.
 * ---------------------------------------------------------------- */

extern int
n00b_keychain_test_create_p256(const char *label, size_t label_len);

extern int
n00b_keychain_test_delete(const char *label, size_t label_len);

extern int
n00b_keychain_test_verify_p256(void           *sec_key_opaque,
                               const uint8_t  *msg,
                               size_t          msg_len,
                               const uint8_t  *sig,
                               size_t          sig_len);

#ifdef __cplusplus
}
#endif
