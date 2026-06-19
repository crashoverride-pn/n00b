/*
 * secret_keychain.m — macOS Keychain boundary for the secret-handle
 * provider.
 *
 * This file holds only the Security.framework / CoreFoundation
 * interactions (which require Apple's Objective-C compiler).  It
 * exposes a pure-C surface — no n00b types — to the bridge file
 * (`secret_keychain_bridge.c`) which is compiled through ncc and
 * does the n00b-side wrapping.  This is the same pattern as
 * `acme_trust_macos.m`.
 *
 * Build is gated on target_os == 'darwin'; the body links against
 * Security.framework and CoreFoundation (already on the link line
 * for acme_trust_macos.m).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "net/quic/quic_types.h"
#include "internal/crypto/secret_keychain_raw.h"

int
n00b_keychain_open_raw(const char *label, size_t label_len,
                       void **sec_key_out)
{
    if (!label || label_len == 0 || !sec_key_out) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    *sec_key_out = NULL;

    CFDataRef label_data = CFDataCreate(kCFAllocatorDefault,
                                        (const uint8_t *)label,
                                        (CFIndex)label_len);
    if (!label_data) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    const void *keys[] = {
        kSecClass,
        kSecAttrKeyClass,
        kSecAttrApplicationTag,
        kSecReturnRef,
        kSecMatchLimit,
    };
    const void *values[] = {
        kSecClassKey,
        kSecAttrKeyClassPrivate,
        label_data,
        kCFBooleanTrue,
        kSecMatchLimitOne,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values,
        sizeof(keys) / sizeof(keys[0]),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(label_data);
    if (!query) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    CFTypeRef found  = NULL;
    OSStatus  status = SecItemCopyMatching(query, &found);
    CFRelease(query);

    if (status != errSecSuccess || !found) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (CFGetTypeID(found) != SecKeyGetTypeID()) {
        CFRelease(found);
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    SecKeyRef sec_key = (SecKeyRef)found;

    /* Reject unsupported key types up front (Phase 1: ECDSA-P-256
     * only). */
    CFDictionaryRef attrs = SecKeyCopyAttributes(sec_key);
    int             ok    = 0;
    if (attrs) {
        CFStringRef key_type = CFDictionaryGetValue(attrs,
                                                    kSecAttrKeyType);
        CFNumberRef key_size = CFDictionaryGetValue(attrs,
                                                    kSecAttrKeySizeInBits);
        if (key_type && CFEqual(key_type, kSecAttrKeyTypeECSECPrimeRandom)
            && key_size) {
            int bits = 0;
            if (CFNumberGetValue(key_size, kCFNumberIntType, &bits)
                && bits == 256) {
                ok = 1;
            }
        }
        CFRelease(attrs);
    }
    if (!ok) {
        CFRelease(sec_key);
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    *sec_key_out = (void *)sec_key;
    return N00B_QUIC_OK;
}

int
n00b_keychain_pubkey_raw(void *sec_key_opaque, uint8_t out[64])
{
    SecKeyRef sec_key = (SecKeyRef)sec_key_opaque;
    if (!sec_key || !out) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    SecKeyRef pub = SecKeyCopyPublicKey(sec_key);
    if (!pub) {
        return N00B_QUIC_ERR_NOT_IMPLEMENTED;
    }

    CFErrorRef err  = NULL;
    CFDataRef  data = SecKeyCopyExternalRepresentation(pub, &err);
    CFRelease(pub);
    if (!data) {
        if (err) CFRelease(err);
        return N00B_QUIC_ERR_NOT_IMPLEMENTED;
    }

    CFIndex        len = CFDataGetLength(data);
    const uint8_t *p   = CFDataGetBytePtr(data);
    if (len != 65 || p[0] != 0x04) {
        CFRelease(data);
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    memcpy(out, p + 1, 64);
    CFRelease(data);
    return N00B_QUIC_OK;
}

int
n00b_keychain_sign_raw(void          *sec_key_opaque,
                       const uint8_t *data,
                       size_t         data_len,
                       uint8_t       *sig_buf_out,
                       size_t         sig_buf_cap,
                       size_t        *sig_len_out)
{
    SecKeyRef sec_key = (SecKeyRef)sec_key_opaque;
    if (!sec_key || !sig_buf_out || !sig_len_out || sig_buf_cap == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    *sig_len_out = 0;

    CFDataRef payload = CFDataCreate(kCFAllocatorDefault,
                                     data ? data : (const uint8_t *)"",
                                     (CFIndex)data_len);
    if (!payload) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    CFErrorRef err = NULL;
    CFDataRef  sig = SecKeyCreateSignature(
        sec_key,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        payload, &err);
    CFRelease(payload);

    if (!sig) {
        if (err) CFRelease(err);
        return N00B_QUIC_ERR_PROTOCOL;
    }

    CFIndex        slen = CFDataGetLength(sig);
    const uint8_t *sptr = CFDataGetBytePtr(sig);
    if ((size_t)slen > sig_buf_cap) {
        /* Caller's buffer too small.  ECDSA-P-256 DER sigs cap at 72
         * bytes; if this fires, the buffer was sized wrong. */
        CFRelease(sig);
        return N00B_QUIC_ERR_FRAME_TOO_LARGE;
    }
    memcpy(sig_buf_out, sptr, (size_t)slen);
    CFRelease(sig);

    *sig_len_out = (size_t)slen;
    return N00B_QUIC_OK;
}

void
n00b_keychain_close_raw(void *sec_key_opaque)
{
    SecKeyRef sec_key = (SecKeyRef)sec_key_opaque;
    if (sec_key) {
        CFRelease(sec_key);
    }
}

/* ========================================================================
 * Test-only helpers
 *
 * These exist so the unit test can do a hermetic round-trip:
 * generate an ECDSA-P-256 keypair in the keychain, open it through
 * the n00b provider, sign with it, verify the signature, then
 * delete the entry.  Not part of the provider's normal surface.
 * ======================================================================== */

int
n00b_keychain_test_create_p256(const char *label, size_t label_len)
{
    if (!label || label_len == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    CFDataRef label_data = CFDataCreate(kCFAllocatorDefault,
                                        (const uint8_t *)label,
                                        (CFIndex)label_len);
    if (!label_data) return N00B_QUIC_ERR_INVALID_ARG;

    int bits = 256;
    CFNumberRef size_num = CFNumberCreate(kCFAllocatorDefault,
                                          kCFNumberIntType, &bits);

    /* Private-key attrs: persistent + the application label we'll
     * look up later.  No access-control / token-id (so the entry
     * lands in the default keychain accessible to this process). */
    const void *priv_keys[] = {
        kSecAttrIsPermanent,
        kSecAttrApplicationTag,
    };
    const void *priv_values[] = {
        kCFBooleanTrue,
        label_data,
    };
    CFDictionaryRef priv_attrs = CFDictionaryCreate(
        kCFAllocatorDefault, priv_keys, priv_values, 2,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    const void *keys[] = {
        kSecAttrKeyType,
        kSecAttrKeySizeInBits,
        kSecPrivateKeyAttrs,
    };
    const void *values[] = {
        kSecAttrKeyTypeECSECPrimeRandom,
        size_num,
        priv_attrs,
    };
    CFDictionaryRef params = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFErrorRef err = NULL;
    SecKeyRef  k   = SecKeyCreateRandomKey(params, &err);

    CFRelease(params);
    CFRelease(priv_attrs);
    CFRelease(size_num);
    CFRelease(label_data);

    if (!k) {
        if (err) CFRelease(err);
        return N00B_QUIC_ERR_PROTOCOL;
    }
    CFRelease(k);  /* keychain holds the persistent reference. */
    return N00B_QUIC_OK;
}

int
n00b_keychain_test_delete(const char *label, size_t label_len)
{
    if (!label || label_len == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    CFDataRef label_data = CFDataCreate(kCFAllocatorDefault,
                                        (const uint8_t *)label,
                                        (CFIndex)label_len);
    if (!label_data) return N00B_QUIC_ERR_INVALID_ARG;

    const void *keys[]   = { kSecClass, kSecAttrApplicationTag };
    const void *values[] = { kSecClassKey, label_data };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 2,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(label_data);

    OSStatus st = SecItemDelete(query);
    CFRelease(query);

    /* errSecItemNotFound is benign (idempotent delete). */
    if (st != errSecSuccess && st != errSecItemNotFound) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    return N00B_QUIC_OK;
}

int
n00b_keychain_test_verify_p256(void           *sec_key_opaque,
                               const uint8_t  *msg,
                               size_t          msg_len,
                               const uint8_t  *sig,
                               size_t          sig_len)
{
    SecKeyRef sec_key = (SecKeyRef)sec_key_opaque;
    if (!sec_key || !sig) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    SecKeyRef pub = SecKeyCopyPublicKey(sec_key);
    if (!pub) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    CFDataRef payload = CFDataCreate(kCFAllocatorDefault,
                                     msg ? msg : (const uint8_t *)"",
                                     (CFIndex)msg_len);
    CFDataRef sig_data = CFDataCreate(kCFAllocatorDefault, sig,
                                      (CFIndex)sig_len);
    if (!payload || !sig_data) {
        if (payload)  CFRelease(payload);
        if (sig_data) CFRelease(sig_data);
        CFRelease(pub);
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    CFErrorRef err = NULL;
    Boolean    ok  = SecKeyVerifySignature(
        pub,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        payload, sig_data, &err);

    CFRelease(payload);
    CFRelease(sig_data);
    CFRelease(pub);
    if (!ok) {
        if (err) CFRelease(err);
        return N00B_QUIC_ERR_TRUST_REJECTED;
    }
    return N00B_QUIC_OK;
}
