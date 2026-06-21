/* -------------------------------------------------------------------------
 * resign_macho_darwin.m — plain-C / ObjC ABI shim for the macOS Mach-O
 * re-sign body. This is the ONLY libchalk source file that:
 *
 *   - Compiles through Apple's ObjC compiler (not ncc).
 *   - Includes <Security/Security.h>, <CoreFoundation/CoreFoundation.h>,
 *     <spawn.h>, <stdio.h>, and other POSIX/CoreFoundation headers.
 *   - Uses NULL (not nullptr), errno, fopen/fread/fclose, fprintf, and
 *     plain `const char *` parameters throughout.
 *
 * This file MUST NOT include n00b.h or any ncc-extended header (which
 * would carry _kargs / _generic_struct / r"..."-literal extensions that
 * Apple's clang front-end cannot parse). All n00b-side state crosses
 * the boundary through `include/internal/chalk/resign_macho_raw.h` —
 * a pure-C header with opaque forward declarations.
 *
 * Same shim pattern as src/net/quic/{acme_trust_macos,secret_keychain}.m.
 * ------------------------------------------------------------------------- */

/*
 * resign_macho_darwin.m — macOS Mach-O re-sign body (WP-005 P5).
 *
 * This file holds the Security framework / CoreFoundation
 * interactions for the macOS-side Mach-O re-sign body. It is
 * compiled through the system Objective-C compiler (separate
 * static library — see src/chalk/meson.build) and links against
 * Security.framework + CoreFoundation. Same pattern as
 * src/net/quic/secret_keychain.m and src/net/quic/acme_trust_macos.m.
 *
 * # Public API choice — codesign(1) wrapper, not SecCodeSigner
 *
 * The `SecCodeSigner` family — `SecCodeSignerCreate`,
 * `SecCodeSignerAddSignature` — is a **private** Apple API: the
 * header `<Security/SecCodeSigner.h>` is NOT in the public macOS
 * SDK (verified against the Xcode 15 / Command Line Tools SDK).
 * Apple's own `codesign(1)` tool consumes this private API; third-
 * party code that wants to sign Mach-O binaries either (a)
 * forward-declares the SPI symbols (fragile across OS versions
 * and rejected by App Store review), or (b) shells out to
 * `codesign(1)` — the supported public path.
 *
 * The WP-005 P5 dispatch named SecCodeSigner as the intended
 * approach but the API is private; this implementation takes path
 * (b): we shell out to `/usr/bin/codesign` from the bridge after
 * resolving the signer identity using the public
 * `SecItemImport` / temp-keychain dance. This matches the
 * established pattern in cross-platform Mach-O code-signing tools
 * (Go's `cmd/internal/codesign` is the same shape; the Rust
 * `apple-codesign` crate also goes through `codesign(1)` for the
 * macOS host path).
 *
 * # Identity resolution
 *
 * - `id == nullptr` → ad-hoc signing. Equivalent to
 *   `codesign --force --sign - <path>`. Apple's standard
 *   convention; sufficient for local dev workflows but not for
 *   Gatekeeper-enforced distribution (App Store / notarization).
 *
 * - `id != nullptr` → real identity. The cert DER + PKCS#8 key
 *   DER bytes are extracted from the opaque
 *   `n00b_chalk_signer_identity_t` via the
 *   `_n00b_chalk_signer_identity_*` accessors (declared in
 *   `internal/chalk/resign_identity_internal.h`). The cert + key
 *   are imported into a fresh temporary keychain via
 *   `SecItemImport`; the resulting SecIdentityRef's subject CN
 *   is passed to `codesign -s <CN>`. The temp keychain is
 *   deleted at exit (cleanup is the responsibility of the
 *   bridge; on error paths we leak the keychain rather than
 *   risk double-free of CF types).
 *
 * # Entitlement / codesign-of-tooling
 *
 * `codesign(1)` itself can be invoked unconditionally on a macOS
 * host — it does NOT require the calling binary to be codesigned.
 * (The "consuming binary must be codesigned" caveat applies to
 * the private SecCodeSigner SPI, not to invocations of the
 * `codesign(1)` tool.) See docs/attest/signing-identities.md for
 * the empirical verification.
 *
 * # CF type retain/release pairing
 *
 * Every `CFCreate*` / `Copy*` is paired with `CFRelease` in
 * reverse order before the function returns. On error paths the
 * scoping is explicit (`CF_RELEASE_IF_NONNULL` style guards).
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
// No libc malloc in our code: the subject-CN buffer is n00b-managed (user pool,
// free-by-pointer), allocated and freed via the explicit interpose API.
#include "core/alloc_interpose.h"
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "internal/chalk/resign_macho_raw.h"

extern char **environ;

/* Forward declaration of bridge entry point (matches resign_macho.c). */
int
_n00b_chalk_macho_resign_darwin(const char                   *path,
                                n00b_chalk_signer_identity_t *id);

/* -------------------------------------------------------------------------
 * codesign(1) subprocess shim.
 *
 * Invokes `/usr/bin/codesign --force --sign <identity> [--keychain <kc>] <path>`.
 * Returns 0 on success, non-zero on failure.
 * ------------------------------------------------------------------------- */
static int
run_codesign(const char *identity,
             const char *keychain_path,
             const char *path)
{
    /* Build the argv vector. The maximum shape is:
     *   /usr/bin/codesign --force --sign <id> --keychain <kc> <path>
     * 7 args + NULL terminator. */
    const char *argv[8];
    int         argc = 0;
    argv[argc++] = "/usr/bin/codesign";
    argv[argc++] = "--force";
    argv[argc++] = "--sign";
    argv[argc++] = identity;
    if (keychain_path) {
        argv[argc++] = "--keychain";
        argv[argc++] = keychain_path;
    }
    argv[argc++] = path;
    argv[argc++] = NULL;

    pid_t pid = 0;
    int   rc  = posix_spawn(&pid,
                            argv[0],
                            NULL, /* file actions */
                            NULL, /* attrp */
                            (char *const *)argv,
                            environ);
    if (rc != 0) {
        return rc;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    if (!WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

/* -------------------------------------------------------------------------
 * Ad-hoc signing path: codesign --force --sign - <path>.
 * ------------------------------------------------------------------------- */
static int
resign_adhoc(const char *path)
{
    return run_codesign("-", NULL, path);
}

/* -------------------------------------------------------------------------
 * CF helper: release a CFTypeRef if non-NULL. Avoids the repeated
 * `if (x) CFRelease(x)` boilerplate at every cleanup point.
 * ------------------------------------------------------------------------- */
static inline void
cf_release_if(CFTypeRef ref)
{
    if (ref) {
        CFRelease(ref);
    }
}

/* -------------------------------------------------------------------------
 * Build a temporary keychain path: $TMPDIR/n00b_chalk_resign_<pid>_<ns>.keychain.
 *
 * The trailing nanoseconds component keeps two concurrent invocations
 * from colliding. Writes into the supplied buffer (caller-sized).
 * Returns 0 on success, non-zero on a buffer-overflow guard.
 * ------------------------------------------------------------------------- */
static int
make_temp_keychain_path(char *out, size_t out_sz)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) {
        tmp = "/tmp";
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    const char *sep = (tmp[strlen(tmp) - 1] == '/') ? "" : "/";
    int rc = snprintf(out,
                      out_sz,
                      "%s%sn00b_chalk_resign_%d_%lld.keychain",
                      tmp,
                      sep,
                      (int)getpid(),
                      (long long)ts.tv_nsec);
    if (rc <= 0 || (size_t)rc >= out_sz) {
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Extract the subject CN from a SecCertificateRef as a malloc'd C
 * string. Returns NULL on failure. Caller frees with free().
 *
 * Uses SecCertificateCopySubjectSummary as the public-API path; this
 * returns the most-specific subject component (CN if present, else
 * O / OU). For test fixtures generated with
 * `-subj "/CN=n00b-attest test fixture"` the summary equals the CN.
 * ------------------------------------------------------------------------- */
static char *
copy_cert_subject_cn(SecCertificateRef cert)
{
    if (!cert) {
        return NULL;
    }
    CFStringRef summary = SecCertificateCopySubjectSummary(cert);
    if (!summary) {
        return NULL;
    }
    CFIndex len = CFStringGetLength(summary);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    char   *out = (char *)n00b_interposed_malloc((size_t)max);
    if (!out) {
        CFRelease(summary);
        return NULL;
    }
    if (!CFStringGetCString(summary, out, max, kCFStringEncodingUTF8)) {
        n00b_interposed_free(out);
        CFRelease(summary);
        return NULL;
    }
    CFRelease(summary);
    return out;
}

/* -------------------------------------------------------------------------
 * Real-identity signing path.
 *
 * Steps (each can fail empirically; the failure path emits a precise
 * stderr line + falls back to ad-hoc rather than leaving the binary
 * unsigned):
 *
 * 1. Pull cert + key DER pointer-pairs out of the opaque identity via
 *    the `_raw` accessors (defined in src/chalk/resign_identity.c).
 * 2. Create a fresh temporary keychain at
 *    $TMPDIR/n00b_chalk_resign_<pid>_<ns>.keychain.
 * 3. Wrap cert + key DER bytes in CFData.
 * 4. SecItemImport(cert_data, format=X509Cert, type=Cert, keychain=kc).
 * 5. SecItemImport(key_data,  format=WrappedPKCS8, type=PrivateKey,
 *                  keychain=kc, passphrase=""). picotls's PEM decoder
 *                  emits raw PKCS#8 DER, so kSecFormatWrappedPKCS8 is
 *                  the format that matches the bytes.
 * 6. SecIdentityCreateWithCertificate(kc, cert) → SecIdentityRef. This
 *    binds the cert to the just-imported key.
 * 7. SecIdentityCopyCertificate → cert ref → SecCertificateCopySubjectSummary
 *    → C string. That string is the `codesign -s <CN>` argument.
 * 8. Invoke `codesign --force --sign <CN> --keychain <kc> <path>`.
 * 9. Release CF types in reverse order, then SecKeychainDelete on the
 *    temp keychain so we don't leave it in the user's keychain list.
 *
 * Returns 0 on success, non-zero on failure.
 *
 * # Empirical-fallback rule (per DF-027 dispatch)
 *
 * If any Security-framework call fails on this host, emit a precise
 * stderr line naming the call + OSStatus, then fall back to
 * resign_adhoc(path). The fallback is honest: the caller gets a
 * signed binary (just not Gatekeeper-acceptable) plus a diagnostic
 * that explains why the real-identity path was bypassed.
 *
 * # SDK-deprecation notes
 *
 * - `SecKeychainCreate` / `SecKeychainDelete` are tagged
 *   `API_DEPRECATED(...)` as of macOS 10.10 but still ship on macOS
 *   15.x and remain the only public-SDK path to a *file-backed*
 *   keychain. The modern `SecKeychain`-free APIs (`SecItemAdd` with
 *   kSecUseDataProtectionKeychain) target the iCloud-style data-
 *   protection keychain, which `codesign(1)` can't enumerate.
 * - `SecItemImport` accepts a `keychain` parameter via its
 *   SecItemImportExportKeyParameters struct; the parameter is the
 *   `SecKeychainRef` we just created.
 *
 * Both deprecations are documented above as inline comments and
 * silenced at the call sites with `#pragma clang diagnostic
 * ignored "-Wdeprecated-declarations"` push/pop pairs — no global
 * suppression at the meson level, so unrelated deprecations still
 * produce diagnostics.
 * ------------------------------------------------------------------------- */
static int
resign_with_identity(const char                   *path,
                     n00b_chalk_signer_identity_t *id)
{
    /* Sanity: require a non-null identity for this code path. */
    if (id == NULL) {
        return -1;
    }

    /* (1) Pull cert + key DER bytes via the _raw accessors. */
    const uint8_t *cert_bytes = NULL;
    size_t         cert_len   = 0;
    const uint8_t *key_bytes  = NULL;
    size_t         key_len    = 0;
    _n00b_chalk_signer_identity_cert_der_raw(id, &cert_bytes, &cert_len);
    _n00b_chalk_signer_identity_key_der_raw(id, &key_bytes, &key_len);

    if (cert_bytes == NULL || cert_len == 0
        || key_bytes == NULL || key_len == 0) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "cert/key DER bytes unavailable on the identity handle "
                "(cert_len=%zu, key_len=%zu); falling back to ad-hoc "
                "signing for: %s\n",
                cert_len, key_len, path);
        return resign_adhoc(path);
    }

    /* (2) Build the temp keychain path + a random-bytes password. */
    char kc_path[1024];
    if (make_temp_keychain_path(kc_path, sizeof(kc_path)) != 0) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "could not compose temp keychain path; falling back "
                "to ad-hoc for: %s\n", path);
        return resign_adhoc(path);
    }

    /* Empty password — SecKeychainCreate accepts a zero-length
     * password when promptUser is false. The keychain is scoped to
     * this process and deleted at exit; no real secrecy needed. */
    const char *pw_bytes = "";
    UInt32      pw_len   = 0;

    /* SecKeychainCreate is deprecated since macOS 10.10 (per
     * Apple's <Security/SecKeychain.h> annotation) but remains the
     * only public-SDK path to a file-backed legacy keychain that
     * codesign(1) can enumerate. Suppress only the deprecation
     * warning at the call site — global suppression in
     * meson.build would mask future, unrelated deprecations. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecKeychainRef kc = NULL;
    OSStatus       st = SecKeychainCreate(kc_path,
                                          pw_len,
                                          pw_bytes,
                                          FALSE,  /* promptUser */
                                          NULL,   /* initialAccess */
                                          &kc);
#pragma clang diagnostic pop
    if (st != errSecSuccess || kc == NULL) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "SecKeychainCreate failed (OSStatus=%d); falling back "
                "to ad-hoc for: %s\n",
                (int)st, path);
        /* nothing to clean up; kc is NULL on failure */
        return resign_adhoc(path);
    }

    int rc = -1;

    /* (3) Wrap cert + key bytes in CFData. */
    CFDataRef cert_data = CFDataCreate(kCFAllocatorDefault,
                                       cert_bytes,
                                       (CFIndex)cert_len);
    CFDataRef key_data  = CFDataCreate(kCFAllocatorDefault,
                                       key_bytes,
                                       (CFIndex)key_len);
    if (!cert_data || !key_data) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "CFDataCreate failed; falling back to ad-hoc for: %s\n",
                path);
        goto cleanup;
    }

    /* (4) Import the cert. SecItemImport et al. are tagged
     * API_DEPRECATED for the file-keychain code path; same
     * justification as SecKeychainCreate above. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecExternalFormat   cert_fmt   = kSecFormatX509Cert;
    SecExternalItemType cert_type  = kSecItemTypeCertificate;
    CFArrayRef          cert_items = NULL;
    SecItemImportExportKeyParameters cert_params = {};
    cert_params.version            = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    cert_params.flags              = 0;
    cert_params.passphrase         = NULL;
    cert_params.alertTitle         = NULL;
    cert_params.alertPrompt        = NULL;
    cert_params.accessRef          = NULL;
    cert_params.keyUsage           = NULL;
    cert_params.keyAttributes      = NULL;

    st = SecItemImport(cert_data,
                       NULL,           /* fileNameOrExtension */
                       &cert_fmt,
                       &cert_type,
                       0,              /* flags */
                       &cert_params,
                       kc,             /* importKeychain */
                       &cert_items);
#pragma clang diagnostic pop
    if (st != errSecSuccess || !cert_items || CFArrayGetCount(cert_items) == 0) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "SecItemImport(cert, kSecFormatX509Cert) failed "
                "(OSStatus=%d); falling back to ad-hoc for: %s\n",
                (int)st, path);
        cf_release_if(cert_items);
        goto cleanup;
    }

    /* (5) Import the PKCS#8 private key. picotls's PEM decoder
     * emits raw PKCS#8 PrivateKeyInfo bytes for "PRIVATE KEY"
     * blocks, which is exactly the kSecFormatWrappedPKCS8 wire
     * shape. The empty-passphrase CFString is required even
     * though the key bytes are not actually encrypted —
     * SecItemImport returns errSecPassphraseRequired without it. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecExternalFormat   key_fmt   = kSecFormatWrappedPKCS8;
    SecExternalItemType key_type  = kSecItemTypePrivateKey;
    CFArrayRef          key_items = NULL;

    CFStringRef empty_pw_str = CFSTR("");
    SecItemImportExportKeyParameters key_params = {};
    key_params.version             = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    key_params.flags               = 0;
    key_params.passphrase          = empty_pw_str;
    key_params.alertTitle          = NULL;
    key_params.alertPrompt         = NULL;
    key_params.accessRef           = NULL;
    key_params.keyUsage            = NULL;
    key_params.keyAttributes       = NULL;

    st = SecItemImport(key_data,
                       NULL,
                       &key_fmt,
                       &key_type,
                       0,
                       &key_params,
                       kc,
                       &key_items);
    if (st != errSecSuccess) {
        /* Second try: some SDK versions reject WrappedPKCS8 for an
         * unencrypted PrivateKeyInfo and require kSecFormatOpenSSL
         * (which matches RSA PRIVATE KEY DER, not PKCS#8). Try
         * kSecFormatUnknown and let the framework auto-detect. */
        key_fmt = kSecFormatUnknown;
        cf_release_if(key_items);
        key_items = NULL;
        st = SecItemImport(key_data,
                           NULL,
                           &key_fmt,
                           &key_type,
                           0,
                           &key_params,
                           kc,
                           &key_items);
    }
#pragma clang diagnostic pop
    if (st != errSecSuccess || !key_items || CFArrayGetCount(key_items) == 0) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "SecItemImport(key) failed (OSStatus=%d); falling back "
                "to ad-hoc for: %s\n",
                (int)st, path);
        cf_release_if(key_items);
        CFRelease(cert_items);
        goto cleanup;
    }

    /* (6) Bind cert + key into a SecIdentityRef.
     * SecIdentityCreateWithCertificate searches the supplied
     * keychain (we restrict to our temp keychain) for a matching
     * private key. */
    SecCertificateRef cert_ref = (SecCertificateRef)CFArrayGetValueAtIndex(
        cert_items, 0);
    SecIdentityRef    ident    = NULL;
    /* The "keychainOrArray" arg accepts a single keychain or a
     * CFArray. We pass the single ref. */
    st = SecIdentityCreateWithCertificate((CFTypeRef)kc, cert_ref, &ident);
    if (st != errSecSuccess || !ident) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "SecIdentityCreateWithCertificate failed (OSStatus=%d); "
                "falling back to ad-hoc for: %s\n",
                (int)st, path);
        cf_release_if(ident);
        CFRelease(key_items);
        CFRelease(cert_items);
        goto cleanup;
    }

    /* (7) Extract the subject CN as a C string for codesign -s. */
    char *cn = copy_cert_subject_cn(cert_ref);
    if (!cn) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "could not extract cert subject CN; falling back to "
                "ad-hoc for: %s\n", path);
        CFRelease(ident);
        CFRelease(key_items);
        CFRelease(cert_items);
        goto cleanup;
    }

    /* (8) Invoke codesign(1) with the identity CN + temp keychain. */
    rc = run_codesign(cn, kc_path, path);
    if (rc != 0) {
        fprintf(stderr,
                "[n00b_chalk] warning: macOS real-identity re-sign: "
                "codesign(1) returned %d for identity '%s'; falling "
                "back to ad-hoc for: %s\n",
                rc, cn, path);
    }

    n00b_interposed_free(cn);
    CFRelease(ident);
    CFRelease(key_items);
    CFRelease(cert_items);

    /* On a non-zero codesign rc the binary still has the prior (or
     * no) signature; ad-hoc is the safer fallback. */
    if (rc != 0) {
        rc = resign_adhoc(path);
    }

cleanup:
    cf_release_if(key_data);
    cf_release_if(cert_data);

    /* SecKeychainDelete both removes the keychain from the
     * search list and deletes the on-disk file. We always do this
     * — leaving it would clutter the test host's keychain list.
     * Same deprecation rationale as SecKeychainCreate above. */
    if (kc) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        SecKeychainDelete(kc);
#pragma clang diagnostic pop
        CFRelease(kc);
    }

    /* If we never made it to step 8 (rc still -1 from initial
     * value) the goto'd to cleanup paths each printed a precise
     * warning + we still need to actually sign. */
    if (rc == -1) {
        rc = resign_adhoc(path);
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * Bridge entry point.
 *
 * 1. Sanity-check that the file exists.
 * 2. Quickly verify it parses as Mach-O (peek the magic bytes) —
 *    full parsing happens in the n00b layer; here we just guard
 *    against feeding nonsense to codesign(1).
 * 3. Dispatch to the ad-hoc or real-identity path.
 *
 * Returns 0 on success, non-zero on failure.
 * ------------------------------------------------------------------------- */
int
_n00b_chalk_macho_resign_darwin(const char                   *path,
                                n00b_chalk_signer_identity_t *id)
{
    if (!path) {
        return -1;
    }

    /* Sanity: the file must exist and be a regular file. */
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        return -1;
    }

    /* Peek the magic bytes to make sure this is Mach-O. The four
     * Mach-O magics are 0xfeedface / 0xfeedfacf (thin LE/BE 32/64)
     * and 0xcafebabe / 0xbebafeca (fat universal). */
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    uint32_t magic = 0;
    size_t   got   = fread(&magic, 1, sizeof(magic), f);
    fclose(f);
    if (got != sizeof(magic)) {
        return -1;
    }
    const uint32_t MH_MAGIC      = 0xfeedfaceU;
    const uint32_t MH_CIGAM      = 0xcefaedfeU;
    const uint32_t MH_MAGIC_64   = 0xfeedfacfU;
    const uint32_t MH_CIGAM_64   = 0xcffaedfeU;
    const uint32_t FAT_MAGIC     = 0xcafebabeU;
    const uint32_t FAT_CIGAM     = 0xbebafecaU;
    if (magic != MH_MAGIC && magic != MH_CIGAM
        && magic != MH_MAGIC_64 && magic != MH_CIGAM_64
        && magic != FAT_MAGIC && magic != FAT_CIGAM) {
        /* Not a Mach-O. The cross-platform dispatcher returns
         * _RESIGN_FAILED on this path; signal that via non-zero rc. */
        return -1;
    }

    if (id == NULL) {
        return resign_adhoc(path);
    }
    return resign_with_identity(path, id);
}
