/*
 * acme_trust_macos.m — macOS SecTrust integration for the ACME HTTPS
 * shim.  Built only when target_os == 'darwin'.
 *
 * Body is plain C; the .m extension only routes the file through the
 * system Objective-C compiler so Apple's framework headers (which
 * use attribute extensions ncc cannot parse) compile cleanly.
 * No Objective-C runtime calls; no extra link dep beyond Security
 * and CoreFoundation.
 */

#include <stddef.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "net/quic/quic_types.h"
#include "internal/crypto/trust_system.h"

int
n00b_quic_trust_system_verify_chain(const uint8_t **certs,
                             const size_t   *lens,
                             size_t          count,
                             const char     *sni)
{
    if (!certs || !lens || count == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    int rc = N00B_QUIC_ERR_TRUST_REJECTED;

    /* Build CFArray of SecCertificateRef from DER blobs. */
    CFMutableArrayRef cert_array = CFArrayCreateMutable(
        kCFAllocatorDefault, (CFIndex)count, &kCFTypeArrayCallBacks);
    if (!cert_array) {
        return N00B_QUIC_ERR_TRUST_REJECTED;
    }

    for (size_t i = 0; i < count; i++) {
        CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                      certs[i], (CFIndex)lens[i]);
        if (!data) {
            goto cleanup;
        }
        SecCertificateRef sc = SecCertificateCreateWithData(
            kCFAllocatorDefault, data);
        CFRelease(data);
        if (!sc) {
            /* Malformed DER. */
            goto cleanup;
        }
        CFArrayAppendValue(cert_array, sc);
        CFRelease(sc);
    }

    /* Policy: SSL server-auth, with hostname check if SNI provided. */
    CFStringRef host_cf = NULL;
    if (sni) {
        host_cf = CFStringCreateWithCString(kCFAllocatorDefault, sni,
                                            kCFStringEncodingUTF8);
    }
    SecPolicyRef policy = SecPolicyCreateSSL(true, host_cf);
    if (host_cf) {
        CFRelease(host_cf);
    }
    if (!policy) {
        goto cleanup;
    }

    SecTrustRef trust  = NULL;
    OSStatus    status = SecTrustCreateWithCertificates(cert_array, policy,
                                                        &trust);
    CFRelease(policy);
    if (status != errSecSuccess || !trust) {
        if (trust) {
            CFRelease(trust);
        }
        goto cleanup;
    }

    CFErrorRef err     = NULL;
    Boolean    trusted = SecTrustEvaluateWithError(trust, &err);
    if (err) {
        CFRelease(err);
    }
    CFRelease(trust);

    rc = trusted ? N00B_QUIC_OK : N00B_QUIC_ERR_TRUST_REJECTED;

cleanup:
    CFRelease(cert_array);
    return rc;
}

/* Verify with extra trust anchors layered onto the system store.
 *
 * On macOS this is `SecTrustSetAnchorCertificates(t, extras)` —
 * which by default REPLACES the system anchors.  We follow up with
 * `SecTrustSetAnchorCertificatesOnly(t, false)` to put the system
 * anchors back, so the effective anchor set is system ∪ extras.
 * That matches the expected "augment, don't replace" contract.
 */
int
n00b_quic_trust_system_verify_chain_ex(const uint8_t **certs,
                                       const size_t   *lens,
                                       size_t          count,
                                       const char     *sni,
                                       const uint8_t **extras_der,
                                       const size_t   *extras_lens,
                                       size_t          extras_count)
{
    if (extras_count == 0 || !extras_der || !extras_lens) {
        return n00b_quic_trust_system_verify_chain(certs, lens, count, sni);
    }
    if (!certs || !lens || count == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    int rc = N00B_QUIC_ERR_TRUST_REJECTED;

    CFMutableArrayRef cert_array = CFArrayCreateMutable(
        kCFAllocatorDefault, (CFIndex)count, &kCFTypeArrayCallBacks);
    CFMutableArrayRef extras_array = CFArrayCreateMutable(
        kCFAllocatorDefault, (CFIndex)extras_count, &kCFTypeArrayCallBacks);
    if (!cert_array || !extras_array) {
        if (cert_array)   CFRelease(cert_array);
        if (extras_array) CFRelease(extras_array);
        return N00B_QUIC_ERR_TRUST_REJECTED;
    }

    for (size_t i = 0; i < count; i++) {
        CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                      certs[i], (CFIndex)lens[i]);
        if (!data) goto cleanup;
        SecCertificateRef sc = SecCertificateCreateWithData(
            kCFAllocatorDefault, data);
        CFRelease(data);
        if (!sc) goto cleanup;
        CFArrayAppendValue(cert_array, sc);
        CFRelease(sc);
    }
    for (size_t i = 0; i < extras_count; i++) {
        CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                      extras_der[i], (CFIndex)extras_lens[i]);
        if (!data) goto cleanup;
        SecCertificateRef sc = SecCertificateCreateWithData(
            kCFAllocatorDefault, data);
        CFRelease(data);
        if (!sc) goto cleanup;
        CFArrayAppendValue(extras_array, sc);
        CFRelease(sc);
    }

    CFStringRef host_cf = NULL;
    if (sni) {
        host_cf = CFStringCreateWithCString(kCFAllocatorDefault, sni,
                                            kCFStringEncodingUTF8);
    }
    SecPolicyRef policy = SecPolicyCreateSSL(true, host_cf);
    if (host_cf) CFRelease(host_cf);
    if (!policy) goto cleanup;

    SecTrustRef trust  = NULL;
    OSStatus    status = SecTrustCreateWithCertificates(cert_array, policy,
                                                        &trust);
    CFRelease(policy);
    if (status != errSecSuccess || !trust) {
        if (trust) CFRelease(trust);
        goto cleanup;
    }

    /* Install extras, then RESTORE the system anchors via
     * SetAnchorCertificatesOnly(false) so we end up with the union. */
    (void)SecTrustSetAnchorCertificates(trust, extras_array);
    (void)SecTrustSetAnchorCertificatesOnly(trust, false);

    CFErrorRef err     = NULL;
    Boolean    trusted = SecTrustEvaluateWithError(trust, &err);
    if (err) CFRelease(err);
    CFRelease(trust);

    rc = trusted ? N00B_QUIC_OK : N00B_QUIC_ERR_TRUST_REJECTED;

cleanup:
    CFRelease(cert_array);
    CFRelease(extras_array);
    return rc;
}
