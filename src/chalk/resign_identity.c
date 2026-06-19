/** @file src/chalk/resign_identity.c — Signer identity resolver.
 *
 *  Implements the n00b_chalk_signer_identity_resolve / _release
 *  surface declared in include/chalk/n00b_chalk_resign.h. Two URI
 *  shapes are supported (WP-005 Phase 4 disposition):
 *
 *   - `file://path/to/cert.pem,file://path/to/key.pem` — paired
 *     PEM files (cert PEM + PKCS#8 PEM private key).
 *   - `store://<name>` — XDG store lookup against
 *     `$XDG_CONFIG_HOME/n00b-attest/signing-identities/`
 *     (mirrors D-052's `registries.json` convention).
 *
 *  The cert is parsed as X.509 DER and the key as a PKCS#8
 *  PrivateKeyInfo via the shared read-side walkers in
 *  include/util/x509_walk.h (`n00b_x509_extract_issuer_serial`,
 *  `n00b_x509_extract_rsa_pkcs8_nd`) — lifted from this file by
 *  the WP-005 mid-stream cleanup so P5 (Mach-O re-sign) can
 *  consume the same surface. PEM decoding remains via picotls's
 *  ptls_load_pem_objects (project-wide PEM decoder, P3 fix-ups
 *  dispatch).
 *
 *  XDG store path lookup is delegated to libn00b core's
 *  `n00b_xdg_config_path` typed-variadic builder
 *  (include/util/path.h), which composes
 *  `$XDG_CONFIG_HOME/n00b-attest/signing-identities/<name>.<ext>`
 *  (or the `$HOME/.config/...` fallback per XDG spec) in one call.
 *
 *  Test-file conventions per D-030. */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/file.h"
#include "chalk/n00b_chalk_resign.h"
#include "internal/chalk/resign_identity_internal.h"
#include "internal/chalk/resign_macho_raw.h"
#include "adt/result.h"
#include "crypto/x509_walk.h"
#include "util/path.h"
#include "text/strings/format.h"

#include "picotls.h"
#include "picotls/pembase64.h"

#include <stdint.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Opaque identity struct
// ---------------------------------------------------------------------------
//
// All interior pointers reference allocator-owned bytes (or, for
// the n/d slices, indices into the PEM-decoded key DER which is
// itself allocator-owned via the n00b_buffer_t copy made at parse
// time). _release scrubs the private-key material before
// returning.

struct n00b_chalk_signer_identity {
    n00b_allocator_t *allocator;

    // X.509 cert DER bytes (whole certificate).
    n00b_buffer_t    *cert_der;

    // PKCS#8 key DER bytes (kept so the n/d byte slices remain
    // valid for the lifetime of the handle).
    n00b_buffer_t    *key_der;

    // Issuer DN — a DER-encoded SEQUENCE (Name) sliced out of the
    // cert's tbsCertificate.
    n00b_buffer_t    *issuer_dn_der;

    // Serial number — big-endian raw bytes from the
    // tbsCertificate.serialNumber INTEGER (sign byte preserved
    // when present).
    uint8_t          *serial_bytes;
    size_t            serial_len;

    // RSA (n, d) big-endian byte slices into key_der->data.
    const uint8_t    *rsa_n;
    size_t            rsa_n_len;
    const uint8_t    *rsa_d;
    size_t            rsa_d_len;
};

// ---------------------------------------------------------------------------
// Accessors (consumed by resign_pe.c)
//
// Declared in the internal header below; ncc generates the per-
// translation-unit linkage we need. The accessor returns const
// pointers so the PE re-sign path cannot accidentally mutate the
// identity mid-call.
// ---------------------------------------------------------------------------

n00b_buffer_t *
_n00b_chalk_signer_identity_cert_der(n00b_chalk_signer_identity_t *id)
{
    return id ? id->cert_der : nullptr;
}

n00b_buffer_t *
_n00b_chalk_signer_identity_issuer_dn(n00b_chalk_signer_identity_t *id)
{
    return id ? id->issuer_dn_der : nullptr;
}

void
_n00b_chalk_signer_identity_serial(n00b_chalk_signer_identity_t *id,
                                   const uint8_t              **bytes,
                                   size_t                       *len)
{
    if (!id) {
        *bytes = nullptr;
        *len   = 0;
        return;
    }
    *bytes = id->serial_bytes;
    *len   = id->serial_len;
}

void
_n00b_chalk_signer_identity_rsa(n00b_chalk_signer_identity_t *id,
                                const uint8_t              **n_bytes,
                                size_t                       *n_len,
                                const uint8_t              **d_bytes,
                                size_t                       *d_len)
{
    if (!id) {
        *n_bytes = nullptr;
        *n_len   = 0;
        *d_bytes = nullptr;
        *d_len   = 0;
        return;
    }
    *n_bytes = id->rsa_n;
    *n_len   = id->rsa_n_len;
    *d_bytes = id->rsa_d;
    *d_len   = id->rsa_d_len;
}

// ---------------------------------------------------------------------------
// Raw (pure-C) accessors for the .m bridge.
//
// Declared in `internal/chalk/resign_macho_raw.h` so the
// Objective-C compiler (which cannot parse the ncc-extended
// `resign_identity_internal.h`) can read the cert + key DER
// pointer-pair from the opaque handle. Behavior mirrors the
// typed accessors above: writes nullptr / 0 on a nullptr handle
// (matches the existing typed-accessor null-handling pattern).
// ---------------------------------------------------------------------------

void
_n00b_chalk_signer_identity_cert_der_raw(n00b_chalk_signer_identity_t *id,
                                         const uint8_t              **out_bytes,
                                         size_t                       *out_len)
{
    if (!id || !id->cert_der) {
        *out_bytes = nullptr;
        *out_len   = 0;
        return;
    }
    *out_bytes = (const uint8_t *)id->cert_der->data;
    *out_len   = id->cert_der->byte_len;
}

void
_n00b_chalk_signer_identity_key_der_raw(n00b_chalk_signer_identity_t *id,
                                        const uint8_t              **out_bytes,
                                        size_t                       *out_len)
{
    // Mirrors the cert-DER accessor; the PKCS#8 key DER is the
    // raw payload SecItemImport accepts under
    // kSecFormatWrappedPKCS8 (the format picotls's PEM decoder
    // emits for "PRIVATE KEY" PEM blocks). When the identity has
    // been scrubbed via n00b_chalk_signer_identity_release, the
    // backing buffer's byte_len is zeroed; we surface that as the
    // "no key bytes available" signal the .m file uses to fall
    // back to ad-hoc.
    if (!id || !id->key_der || id->key_der->byte_len == 0) {
        *out_bytes = nullptr;
        *out_len   = 0;
        return;
    }
    *out_bytes = (const uint8_t *)id->key_der->data;
    *out_len   = id->key_der->byte_len;
}

// ---------------------------------------------------------------------------
// URI parsing — internal helpers
// ---------------------------------------------------------------------------

static bool
str_starts_with(n00b_string_t *s, const char *prefix)
{
    if (s == nullptr) return false;
    size_t plen = strlen(prefix);
    if (s->u8_bytes < plen) return false;
    return memcmp(s->data, prefix, plen) == 0;
}

// Returns the substring of s starting at offset (in bytes), with
// the given byte length. Both bounds are validated against
// s->u8_bytes; out-of-range returns nullptr.
static n00b_string_t *
substring(n00b_string_t *s, size_t off, size_t len, n00b_allocator_t *alloc)
{
    if (s == nullptr) return nullptr;
    if (off > s->u8_bytes) return nullptr;
    if (off + len > s->u8_bytes) return nullptr;
    return n00b_string_from_raw(s->data + off,
                                (int64_t)len,
                                .allocator = alloc);
}

// Find the byte offset of `c` in [start, end) (half-open) within
// s->data; returns SIZE_MAX if not found.
static size_t
find_char(n00b_string_t *s, char c, size_t start)
{
    if (s == nullptr) return SIZE_MAX;
    for (size_t i = start; i < s->u8_bytes; i++) {
        if (s->data[i] == c) return i;
    }
    return SIZE_MAX;
}

// ---------------------------------------------------------------------------
// XDG store path resolution — delegated to libn00b core's
// `n00b_xdg_config_path` typed-variadic builder (include/util/path.h).
// The store:// branch below composes the cert and key paths with
// per-call one-liners; the byte layout matches the pre-lift clones
// in src/attest/oci/auth.c (registries.json) and the prior
// n00b_attest_xdg_path helper exactly.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PEM load — uses picotls's ptls_load_pem_objects with a n00b-owned iovec
// because picotls is built with n00b's allocation shim. The helper frees the
// temporary after copying into an allocator-owned buffer.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
load_pem_object(n00b_string_t    *path,
                const char       *label,
                n00b_allocator_t *alloc)
{
    if (path == nullptr) return nullptr;

    ptls_iovec_t vec = {};
    size_t       n   = 0;
    int rc = ptls_load_pem_objects((const char *)path->data, label, &vec, 1, &n);
    if (rc != 0 || n != 1 || vec.base == nullptr || vec.len == 0) {
        if (vec.base != nullptr) {
            n00b_free(vec.base);
        }
        return nullptr;
    }
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)vec.base,
                                                (int64_t)vec.len,
                                                .allocator = alloc);
    n00b_free(vec.base);
    return buf;
}

// ---------------------------------------------------------------------------
// Compose: cert PEM + key PEM → resolved identity handle.
// ---------------------------------------------------------------------------

static n00b_chalk_signer_identity_t *
build_identity_from_pem(n00b_string_t    *cert_path,
                        n00b_string_t    *key_path,
                        n00b_allocator_t *alloc,
                        int              *err_out)
{
    n00b_buffer_t *cert_der = load_pem_object(cert_path, "CERTIFICATE", alloc);
    if (cert_der == nullptr) {
        *err_out = N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND;
        return nullptr;
    }
    n00b_buffer_t *key_der = load_pem_object(key_path, "PRIVATE KEY", alloc);
    if (key_der == nullptr) {
        *err_out = N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND;
        return nullptr;
    }

    const uint8_t *issuer_dn_start    = nullptr;
    size_t         issuer_dn_total    = 0;
    const uint8_t *serial_bytes       = nullptr;
    size_t         serial_len         = 0;
    if (!n00b_x509_extract_issuer_serial((const uint8_t *)cert_der->data,
                                         cert_der->byte_len,
                                         &issuer_dn_start,
                                         &issuer_dn_total,
                                         &serial_bytes,
                                         &serial_len)) {
        *err_out = N00B_CHALK_ERR_KEY_PARSE_FAILED;
        return nullptr;
    }

    const uint8_t *n_bytes = nullptr;
    size_t         n_len   = 0;
    const uint8_t *d_bytes = nullptr;
    size_t         d_len   = 0;
    if (!n00b_x509_extract_rsa_pkcs8_nd((const uint8_t *)key_der->data,
                                        key_der->byte_len,
                                        &n_bytes, &n_len,
                                        &d_bytes, &d_len)) {
        *err_out = N00B_CHALK_ERR_KEY_PARSE_FAILED;
        return nullptr;
    }

    n00b_chalk_signer_identity_t *id = n00b_alloc(
        n00b_chalk_signer_identity_t,
        .allocator = alloc);
    id->allocator = alloc;
    id->cert_der  = cert_der;
    id->key_der   = key_der;

    // Issuer DN — copy into an allocator-owned buffer so the
    // pointer is independent of the cert_der lifetime semantics
    // and can be passed verbatim to n00b_pkcs7_signed_data_add_signer.
    id->issuer_dn_der = n00b_buffer_from_bytes((char *)issuer_dn_start,
                                               (int64_t)issuer_dn_total,
                                               .allocator = alloc);

    // Serial — copy into allocator-owned bytes for the same reason.
    id->serial_bytes = n00b_alloc_array_with_opts(
        uint8_t,
        serial_len > 0 ? serial_len : 1,
        &(n00b_alloc_opts_t){.allocator = alloc});
    if (serial_len > 0) {
        memcpy(id->serial_bytes, serial_bytes, serial_len);
    }
    id->serial_len = serial_len;

    // RSA (n, d) — the byte slices point into key_der->data, which
    // is allocator-owned and lives as long as the handle. No copy.
    id->rsa_n     = n_bytes;
    id->rsa_n_len = n_len;
    id->rsa_d     = d_bytes;
    id->rsa_d_len = d_len;

    *err_out = 0;
    return id;
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

n00b_result_t(n00b_chalk_signer_identity_t *)
n00b_chalk_signer_identity_resolve(n00b_string_t *uri) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (uri == nullptr) {
        return n00b_result_ok(n00b_chalk_signer_identity_t *, nullptr);
    }

    // file://cert,file://key — paired form.
    if (str_starts_with(uri, "file://")) {
        size_t comma_off = find_char(uri, ',', 0);
        if (comma_off == SIZE_MAX) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        // The cert path is the substring between [7, comma_off);
        // the key path's "file://" prefix starts at comma_off+1.
        n00b_string_t *cert_path = substring(uri,
                                             7,
                                             comma_off - 7,
                                             allocator);
        if (cert_path == nullptr) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        // Require the second half to also start with file://.
        if (uri->u8_bytes < comma_off + 1 + 7) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        if (memcmp(uri->data + comma_off + 1, "file://", 7) != 0) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        n00b_string_t *key_path = substring(
            uri,
            comma_off + 1 + 7,
            uri->u8_bytes - (comma_off + 1 + 7),
            allocator);
        if (key_path == nullptr) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        int err = 0;
        n00b_chalk_signer_identity_t *id = build_identity_from_pem(
            cert_path, key_path, allocator, &err);
        if (id == nullptr) {
            return n00b_result_err(n00b_chalk_signer_identity_t *, err);
        }
        return n00b_result_ok(n00b_chalk_signer_identity_t *, id);
    }

    // store://<name>
    if (str_starts_with(uri, "store://")) {
        size_t name_off = 8;
        if (uri->u8_bytes <= name_off) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        size_t name_len = uri->u8_bytes - name_off;
        n00b_string_t *name = n00b_string_from_raw(uri->data + name_off,
                                                   (int64_t)name_len,
                                                   .allocator = allocator);

        // One logical call per path-lookup: the leaf filename
        // `<name>.cert.pem` / `<name>.key.pem` is composed via
        // n00b_cformat, then n00b_xdg_config_path joins it under
        // `$XDG_CONFIG_HOME/n00b-attest/signing-identities/`. Byte
        // layout matches the pre-lift `xdg_signing_identity_path`
        // clone exactly.
        n00b_string_t *cert_path = n00b_xdg_config_path(
            r"n00b-attest",
            r"signing-identities",
            n00b_cformat("«#».cert.pem", name));
        n00b_string_t *key_path = n00b_xdg_config_path(
            r"n00b-attest",
            r"signing-identities",
            n00b_cformat("«#».key.pem", name));

        if (cert_path == nullptr || key_path == nullptr) {
            return n00b_result_err(n00b_chalk_signer_identity_t *,
                                   N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
        }
        int err = 0;
        n00b_chalk_signer_identity_t *id = build_identity_from_pem(
            cert_path, key_path, allocator, &err);
        if (id == nullptr) {
            return n00b_result_err(n00b_chalk_signer_identity_t *, err);
        }
        return n00b_result_ok(n00b_chalk_signer_identity_t *, id);
    }

    // Unrecognized scheme → NOT_FOUND.
    return n00b_result_err(n00b_chalk_signer_identity_t *,
                           N00B_CHALK_ERR_SIGNER_IDENTITY_NOT_FOUND);
}

void
n00b_chalk_signer_identity_release(n00b_chalk_signer_identity_t *id)
{
    if (id == nullptr) return;

    // Scrub the PKCS#8 key DER (which contains the RSA private
    // exponent d). Both copies — the buffer's backing store and
    // the SERIAL bytes — are zeroed so a subsequent GC sweep or
    // arena reset leaves no residue. The (n, d) byte slices point
    // into key_der->data, so zeroing key_der->data is sufficient
    // for them.
    if (id->key_der != nullptr && id->key_der->data != nullptr
        && id->key_der->byte_len > 0) {
        /* Security scrub — not a zero-init; memset intentional. */
        memset(id->key_der->data, 0, id->key_der->byte_len);
        id->key_der->byte_len = 0;
    }
    if (id->serial_bytes != nullptr && id->serial_len > 0) {
        /* Security scrub — not a zero-init; memset intentional. */
        memset(id->serial_bytes, 0, id->serial_len);
    }
    id->rsa_n     = nullptr;
    id->rsa_n_len = 0;
    id->rsa_d     = nullptr;
    id->rsa_d_len = 0;
}
