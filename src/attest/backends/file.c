/* src/attest/backends/file.c — file signer-backend body.
 *
 * Implements the surface declared in
 * include/internal/attest/backends/file.h:
 *   - n00b_attest_backend_file (the file-scope vtable instance —
 *     populated at module-init time per architecture §6.1)
 *   - file_load    (PKCS#8 PEM + RFC 8410 walk + key-pair derive
 *                   + SPKI assembly + keyid)
 *   - file_pubkey  (returns the pre-built SPKI buffer — no
 *                   allocation, no kwarg, no result wrapping;
 *                   matches architecture §6.1)
 *   - file_sign    (Phase 2 STUB — returns NOT_IMPLEMENTED; body
 *                   in Phase 3)
 *   - file_release (crypto_wipe of the full 64-byte expanded sk
 *                   per FR-SM-3; SPKI DER also wiped as
 *                   defense-in-depth)
 *
 * Header dependencies:
 *
 * - monocypher.h           — for `crypto_wipe` (NOT in monocypher-ed25519.h)
 * - monocypher-ed25519.h   — for `crypto_ed25519_key_pair` (RFC 8032 form;
 *                            we must NOT use `crypto_eddsa_*` from the
 *                            core header — that's the BLAKE2b form and is
 *                            not RFC 8032 compliant; see
 *                            subprojects/monocypher/README.n00b.md)
 * - picotls/pembase64.h    — `ptls_load_pem_objects`
 * - picotls/asn1.h         — `ptls_asn1_get_expected_type_and_length`
 *                            primitive for the RFC 8410 walk
 * - core/sha256.h          — libn00b's SHA-256 for keyid derivation
 *
 * Decision log:
 *
 * - D-039 (resolves DF-003) (D-039 is not yet logged; the
 *   orchestrator will log it after this dispatch returns clean —
 *   pre-stage the reference in source comments and the spec
 *   text): the keyid input is the **SubjectPublicKeyInfo DER**
 *   (44 bytes for Ed25519 = 12-byte fixed prefix + 32-byte
 *   pubkey), and the output is the full SHA-256 of that input
 *   (32 bytes), hex-encoded (64 chars). This matches the cosign
 *   / sigstore ecosystem convention and supersedes the prior
 *   "raw 32-byte pubkey" form. The verifier WP must consume the
 *   same SPKI-DER input form.
 *
 * - Backend registration (architecture §6.1): the vtable is a
 *   file-scope mutable struct, populated at module-init time
 *   from `n00b_attest_module_init`, then read-only for the
 *   process lifetime. The scheme string is built once via
 *   `r"file"` because the §6.1 vtable
 *   shape carries `n00b_string_t *scheme;` (a non-constant-
 *   expression initializer).
 *
 * - D-035 OQ-4 (URI tolerance): the load path accepts both
 *   `file:<absolute-path>` and `file:///<absolute-path>` and
 *   normalizes both forms to a single internal C-string path
 *   before handing it to picotls.
 *
 * - Key-pair API choice: `crypto_ed25519_key_pair` returns a
 *   64-byte *expanded* secret key (seed half + pubkey half, RFC
 *   8032). The sign path (Phase 3) consumes the expanded form,
 *   so we store it verbatim in the backend's per-signer state
 *   and wipe all 64 bytes at release time — not just the 32-
 *   byte seed half. See the auto-memory
 *   `monocypher_ed25519_api_split.md` for the rationale; FR-SM-3
 *   "zeroize on release" requires every private byte the backend
 *   held to be wiped.
 */

#include "internal/attest/backends/file.h"
#include "internal/attest/backends.h"
#include <attest/n00b_attest_signer.h>

#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/sha256.h"

#include "picotls.h"
#include "picotls/pembase64.h"
#include "picotls/asn1.h"

#include <monocypher.h>
#include <monocypher-ed25519.h>

#include <string.h>

// ---------------------------------------------------------------------------
// Constants — RFC 8410 id-Ed25519 OID + SPKI shape; PKCS#8 strings.
// ---------------------------------------------------------------------------

// id-Ed25519 OID: 1.3.101.112 encoded as 3 bytes (0x2B, 0x65, 0x70).
// The OID's DER body (excluding the 0x06 tag + length prefix) is the
// 3-byte sequence; the encoded OID-with-tag is 0x06 0x03 0x2B 0x65 0x70.
static const uint8_t k_ed25519_oid_body[3] = {0x2B, 0x65, 0x70};

// PEM label for a PKCS#8 PrivateKeyInfo (the "PRIVATE KEY" form, not
// "ENCRYPTED PRIVATE KEY" — we don't support PBES2-encrypted PEMs this
// WP).
static const char k_pkcs8_pem_label[] = "PRIVATE KEY";

// SubjectPublicKeyInfo DER for Ed25519 is the fixed 44-byte sequence:
//   30 2A                              SEQUENCE (42 bytes)
//     30 05                            SEQUENCE (5 bytes) AlgorithmIdentifier
//       06 03 2B 65 70                 OID 1.3.101.112 (id-Ed25519)
//     03 21                            BIT STRING (33 bytes)
//       00 <32-byte pubkey>            unused-bits = 0, then key bytes
//
// We assemble the constant prefix once; the variable tail is the
// 32-byte pubkey. Total SPKI = 12-byte prefix + 32-byte key = 44 bytes.
static const uint8_t k_ed25519_spki_prefix[12] = {
    0x30, 0x2A,
    0x30, 0x05,
    0x06, 0x03, 0x2B, 0x65, 0x70,
    0x03, 0x21,
    0x00,
};

// Lowercase-hex table for keyid encoding.
static const char k_hex_lower[] = "0123456789abcdef";

// ASN.1 tag bytes used in the RFC 8410 walk.
#define ASN1_TAG_SEQUENCE   0x30
#define ASN1_TAG_INTEGER    0x02
#define ASN1_TAG_OID        0x06
#define ASN1_TAG_OCTETSTR   0x04

// ---------------------------------------------------------------------------
// Helpers — file-URI normalization.
// ---------------------------------------------------------------------------

// Strip the `file:` scheme prefix (or `file:///`, FR-SM-1 strict vs
// RFC 3986 — D-035 OQ-4) and return a pointer into `uri->data` to the
// path body. Returns nullptr if the input is null or does not begin
// with `file:`.
//
// We do NOT copy: the caller hands the returned pointer to picotls's
// `ptls_load_pem_objects` which only needs a NUL-terminated read-only
// `char const *` for the duration of the call. n00b_string_t's `data`
// field is documented NUL-terminated (n00b_string_from_raw's post-
// condition), and the substring pointer remains NUL-terminated because
// it points into the same allocation.
static const char *
normalize_file_uri(n00b_string_t *uri)
{
    if (uri == nullptr || uri->u8_bytes < 5) {
        return nullptr;
    }
    const char *s = uri->data;
    size_t      n = uri->u8_bytes;

    // Match the literal `file:` prefix (5 bytes).
    if (s[0] != 'f' || s[1] != 'i' || s[2] != 'l' || s[3] != 'e'
        || s[4] != ':') {
        return nullptr;
    }
    // Beyond `file:` we accept either:
    //   `file:<path>`        (FR-SM-1 strict) -> path starts at offset 5
    //   `file:///<path>`     (RFC 3986)        -> path starts at offset 7
    //                                            (the leading `/` of the
    //                                            absolute path itself)
    // The `file://<host>/<path>` form with a non-empty host is rejected:
    // we have no remote-host concept and supporting empty-host-only
    // matches FR-SM-2's "local fs" framing.
    if (n >= 7 && s[5] == '/' && s[6] == '/') {
        // file:///... or file://...
        // We require a third slash (empty host).
        if (n >= 8 && s[7] == '/') {
            return s + 7;  // points at the leading `/` of the abs path
        }
        // `file://<nonempty>...` — not supported.
        return nullptr;
    }
    // `file:<path>` strict form.
    return s + 5;
}

// ---------------------------------------------------------------------------
// Helpers — keyid derivation (hex-encoded SHA-256 of SPKI DER).
// ---------------------------------------------------------------------------

// Compute `keyid = lowercase-hex(SHA-256(SPKI DER))` per D-039
// (resolves DF-003) (D-039 is not yet logged; the orchestrator will
// log it after this dispatch returns clean — pre-stage the reference
// in source comments and the spec text).
//
// The input is the full 44-byte SubjectPublicKeyInfo DER (12-byte
// fixed Ed25519 prefix + 32-byte raw pubkey); the output is the
// full 32-byte SHA-256 hash, hex-encoded (64 chars). This matches
// the cosign / sigstore ecosystem convention and supersedes the
// prior "raw 32-byte pubkey" form. The verifier WP must consume the
// same SPKI-DER input form.
//
// `spki_der` is a pointer to the caller's 44-byte SPKI buffer
// (typically `st->spki_der`); we read it without copying.
static n00b_string_t *
derive_keyid(const uint8_t *spki_der, n00b_allocator_t *allocator)
{
    n00b_sha256_digest_t digest;
    n00b_sha256_hash(spki_der, 44, digest);

    // n00b_sha256_digest_t is uint32_t[8] in host byte order. Spell
    // out the byte view per SHA-256's big-endian word convention so
    // the keyid matches what every other SHA-256 implementation
    // produces against the same input.
    uint8_t digest_bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w = digest[i];
        digest_bytes[i * 4 + 0] = (uint8_t)((w >> 24) & 0xff);
        digest_bytes[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        digest_bytes[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        digest_bytes[i * 4 + 3] = (uint8_t)(w & 0xff);
    }

    char *hex = n00b_alloc_array_with_opts(
        char,
        64,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2]     = k_hex_lower[(digest_bytes[i] >> 4) & 0xf];
        hex[i * 2 + 1] = k_hex_lower[digest_bytes[i] & 0xf];
    }
    return n00b_string_from_raw(hex, 64, .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Helpers — RFC 8410 PrivateKeyInfo walk.
//
// PKCS#8 PrivateKeyInfo (RFC 5208 / RFC 8410):
//
//   SEQUENCE {
//     version                INTEGER (== 0 for v1),
//     privateKeyAlgorithm    AlgorithmIdentifier {
//         algorithm    OID (id-Ed25519 = 1.3.101.112),
//         -- parameters absent per RFC 8410 §3
//     },
//     privateKey             OCTET STRING (contains an inner OCTET STRING
//                                          holding the 32-byte raw seed)
//   }
//
// The walk yields the 32-byte raw seed. Failures route to
// N00B_ATTEST_ERR_DER_PARSE_FAILED (DER shape mismatch) or
// N00B_ATTEST_ERR_UNSUPPORTED_ALGORITHM (OID mismatch).
//
// We use picotls's `ptls_asn1_get_expected_type_and_length` for each
// expected tag and bail on the first failure. The walk is ~35 lines
// total (matches D-034's "30-40 lines" target).
// ---------------------------------------------------------------------------

static int
walk_pkcs8_ed25519_seed(const uint8_t *der, size_t der_len, uint8_t seed[32])
{
    uint32_t  length         = 0;
    int       indefinite     = 0;
    size_t    last_byte      = 0;
    int       decode_error   = 0;
    size_t    byte_index     = 0;

    // Outer SEQUENCE.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, 0, ASN1_TAG_SEQUENCE,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0 || last_byte > der_len) {
        return N00B_ATTEST_ERR_DER_PARSE_FAILED;
    }

    // version INTEGER (must be 0 for PKCS#8 v1).
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_INTEGER,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0 || length != 1 || byte_index >= der_len
        || der[byte_index] != 0x00) {
        return N00B_ATTEST_ERR_DER_PARSE_FAILED;
    }
    byte_index = last_byte;

    // AlgorithmIdentifier SEQUENCE.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_SEQUENCE,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) {
        return N00B_ATTEST_ERR_DER_PARSE_FAILED;
    }
    size_t alg_end = last_byte;

    // OID inside AlgorithmIdentifier.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_OID,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) {
        return N00B_ATTEST_ERR_DER_PARSE_FAILED;
    }
    // OID body == 0x2B 0x65 0x70 (id-Ed25519).
    if (length != 3 || byte_index + 3 > der_len
        || memcmp(der + byte_index, k_ed25519_oid_body, 3) != 0) {
        return N00B_ATTEST_ERR_UNSUPPORTED_ALGORITHM;
    }
    // RFC 8410 §3 forbids parameters; we don't enforce that strictly
    // here (anything between alg_end and the OID end is ignored) but
    // we do require the OID match.
    byte_index = alg_end;

    // privateKey OCTET STRING.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_OCTETSTR,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) {
        return N00B_ATTEST_ERR_DER_PARSE_FAILED;
    }
    // Inner OCTET STRING — RFC 8410 §7 wraps the 32-byte seed in
    // another OCTET STRING.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_OCTETSTR,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0 || length != 32 || byte_index + 32 > der_len) {
        return N00B_ATTEST_ERR_DER_PARSE_FAILED;
    }

    memcpy(seed, der + byte_index, 32);
    return 0;
}

// ---------------------------------------------------------------------------
// Vtable entry — load.
// ---------------------------------------------------------------------------

static n00b_result_t(n00b_attest_signer_t *)
file_load(n00b_string_t                         *ref,
          const n00b_attest_backend_call_opts_t *opts)
{
    n00b_allocator_t *allocator = opts != nullptr ? opts->allocator : nullptr;

    const char *path = normalize_file_uri(ref);
    if (path == nullptr) {
        return n00b_result_err(n00b_attest_signer_t *,
                               N00B_ATTEST_ERR_KEY_NOT_FOUND);
    }

    // Single-object load — pass list_max = 1; bail on any error or zero
    // objects.
    ptls_iovec_t iov[1] = {};
    size_t       nb     = 0;
    int          rc     = ptls_load_pem_objects(path, k_pkcs8_pem_label,
                                                iov, 1, &nb);
    if (rc != 0) {
        // picotls returns -1 for fopen failure and a positive
        // PTLS_ERROR_* code for label/decode failures.
        return n00b_result_err(n00b_attest_signer_t *,
                               rc == -1
                                   ? N00B_ATTEST_ERR_KEY_NOT_FOUND
                                   : N00B_ATTEST_ERR_PEM_PARSE_FAILED);
    }
    if (nb == 0 || iov[0].base == nullptr) {
        return n00b_result_err(n00b_attest_signer_t *,
                               N00B_ATTEST_ERR_PEM_PARSE_FAILED);
    }

    // RFC 8410 walk over the decoded DER.
    uint8_t seed[32] = {};
    int     walk_err = walk_pkcs8_ed25519_seed(iov[0].base, iov[0].len, seed);

    // Release picotls's DER buffer regardless of walk outcome. Picotls is
    // built with n00b's allocation shim, so this buffer is n00b-owned here.
    // Wipe-then-free: the DER contained the raw seed bytes for an instant,
    // and zeroizing before release matches FR-SM-3's spirit ("every private
    // byte wiped").
    crypto_wipe(iov[0].base, iov[0].len);
    n00b_free(iov[0].base);

    if (walk_err != 0) {
        // Also wipe the local seed copy on the error path — we
        // touched bytes that were briefly the secret.
        crypto_wipe(seed, sizeof(seed));
        return n00b_result_err(n00b_attest_signer_t *, walk_err);
    }

    // Derive expanded sk + pubkey. Monocypher's
    // `crypto_ed25519_key_pair` wipes its input seed slot as part
    // of the derivation (we rely on that wipe rather than doing
    // an extra one here).
    n00b_attest_signer_file_t *st = n00b_alloc_with_opts(
        n00b_attest_signer_file_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    crypto_ed25519_key_pair(st->expanded_sk, st->pubkey, seed);
    // (`seed` is wiped by Monocypher; nothing more to do.)

    // Assemble the 44-byte SPKI DER once: 12-byte fixed prefix +
    // 32-byte pubkey. The same bytes feed both the `pubkey` getter
    // (via the pre-built `spki_buffer` wrapper) and the keyid
    // derivation, so we never construct them twice. Per
    // architecture §6.1 the `pubkey` getter is allocation-free
    // post-load.
    memcpy(st->spki_der, k_ed25519_spki_prefix, 12);
    memcpy(st->spki_der + 12, st->pubkey, 32);

    st->spki_buffer = n00b_buffer_from_bytes((char *)st->spki_der,
                                             44,
                                             .allocator = allocator);

    st->base.backend = &n00b_attest_backend_file;
    st->keyid        = derive_keyid(st->spki_der, allocator);
    st->allocator    = allocator;

    return n00b_result_ok(n00b_attest_signer_t *, &st->base);
}

// ---------------------------------------------------------------------------
// Vtable entry — pubkey (SPKI DER).
//
// Per architecture §6.1 the SPKI bytes are built at load time and
// stored on the signer state. The getter is allocation-free: it
// returns the pre-built buffer wrapper verbatim. No `_kargs`, no
// result wrapper, no allocator threading.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
file_pubkey(n00b_attest_signer_t *signer)
{
    return ((n00b_attest_signer_file_t *)signer)->spki_buffer;
}

// ---------------------------------------------------------------------------
// Vtable entry — sign.
//
// Calls Monocypher's RFC-8032-compliant `crypto_ed25519_sign` (NOT
// `crypto_eddsa_sign`, which uses BLAKE2b — see auto-memory
// `monocypher_ed25519_api_split.md`). The secret-key input is the
// full 64-byte expanded form Monocypher's `crypto_ed25519_key_pair`
// produced at load time; we stored it verbatim on the per-signer
// state. The signature output is always 64 bytes (the EdDSA signature
// shape for curve25519 + SHA-512). Ed25519 is deterministic — the
// same key + same message always yields the same signature bytes —
// which the regression test relies on for byte-equality assertions.
//
// Allocator threading per architecture §6.1: the opts struct carries
// `.allocator`; we forward it into the result-buffer allocation.
// Null `opts` means "use the runtime default" (matching the load
// path's null-tolerance contract documented in backends.h).
// ---------------------------------------------------------------------------

static n00b_result_t(n00b_buffer_t *)
file_sign(n00b_attest_signer_t                  *signer,
          n00b_buffer_t                         *bytes_to_sign,
          const n00b_attest_backend_call_opts_t *opts)
{
    if (signer == nullptr || bytes_to_sign == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_SIGN_FAILED);
    }

    n00b_attest_signer_file_t *st = (n00b_attest_signer_file_t *)signer;
    n00b_allocator_t *allocator   = opts != nullptr ? opts->allocator
                                                    : nullptr;

    // Per-call allocator-fallback chain (n00b-code-auditor W-2,
    // D-039-era cleanup): the caller's per-call allocator wins; if
    // null, fall back to the allocator the signer was loaded with;
    // if that's also null, leave it null and let the libn00b
    // allocator-aware entry points pick up the runtime default. A
    // nullptr-after-fallback indicates an internally-corrupt signer
    // (file_load always captures the load-time allocator), so it
    // shouldn't occur in practice.
    if (allocator == nullptr) {
        allocator = st->allocator;
    }

    // Allocate the 64-byte signature output through the threaded
    // allocator. `n00b_buffer_new` gives us an n00b_buffer_t with
    // 64 bytes of capacity; we then write the signature bytes
    // directly into `data` and set `byte_len = 64`. The simpler
    // path is to allocate a raw `uint8_t[64]` scratch on the stack,
    // sign into it, then wrap it via `n00b_buffer_from_bytes` —
    // that yields the canonical owned-buffer shape with a single
    // copy. We use that approach to keep the result buffer's
    // memory profile identical to the rest of the module's
    // allocator-threaded outputs.
    uint8_t sig[64];
    crypto_ed25519_sign(sig,
                        st->expanded_sk,
                        (const uint8_t *)bytes_to_sign->data,
                        bytes_to_sign->byte_len);

    n00b_buffer_t *out = n00b_buffer_from_bytes((char *)sig,
                                                64,
                                                .allocator = allocator);

    // The local `sig` was a brief carrier for the bytes; wipe it
    // before scope exit. The signature itself is a public value (it
    // is what we hand to callers), but defensive wiping is cheap
    // and keeps the FR-SM-3 "no private bytes lingering on the
    // stack" invariant uniform.
    crypto_wipe(sig, sizeof(sig));

    return n00b_result_ok(n00b_buffer_t *, out);
}

// ---------------------------------------------------------------------------
// Vtable entry — keyid.
//
// Symmetric with `file_pubkey` above: the keyid was computed at
// load time and stored on `st->keyid`. The getter returns the
// cached value verbatim — no allocation, no recomputation.
// ---------------------------------------------------------------------------

static n00b_string_t *
file_keyid(n00b_attest_signer_t *signer)
{
    return ((n00b_attest_signer_file_t *)signer)->keyid;
}

// ---------------------------------------------------------------------------
// Vtable entry — release.
//
// Wipes the FULL 64-byte expanded sk before the buffer returns to the
// allocator (FR-SM-3 "zeroize on release" — every private byte the
// backend held). The pubkey and keyid are public values and need not
// be wiped. The 44-byte SPKI DER is also a public value, but we wipe
// it as defense-in-depth (matches the existing wipe pattern for the
// expanded sk).
//
// We do not call any allocator-aware free: under the n00b GC
// convention the allocator owns the lifetime and reclaims at scope /
// arena teardown. The wipe is the only side-effect this path must
// perform; future-proof against the runtime allocator caching pages
// (an attacker who later scans heap pages would not find expanded-sk
// bytes since we wiped them first).
// ---------------------------------------------------------------------------

static void
file_release(n00b_attest_signer_t *signer)
{
    if (signer == nullptr) {
        return;
    }
    n00b_attest_signer_file_t *st = (n00b_attest_signer_file_t *)signer;
    // `crypto_wipe` is declared in monocypher.h (not -ed25519.h); it
    // wipes every byte and serves as the memory barrier the
    // FR-SM-3 obligation requires.
    crypto_wipe(st->expanded_sk, sizeof(st->expanded_sk));
    crypto_wipe(st->spki_der, sizeof(st->spki_der));
}

// ---------------------------------------------------------------------------
// Vtable instance.
//
// Per architecture §6.1 the vtable carries an `n00b_string_t
// *scheme;` field that cannot be a file-scope constant expression.
// The struct is therefore zero-initialized at file scope and
// populated by `n00b_attest_module_init` (see
// `src/attest/n00b_attest_module.c`), which also registers it with
// the resolver. Once init returns, the vtable is read-only for the
// process lifetime.
// ---------------------------------------------------------------------------

n00b_attest_backend_t n00b_attest_backend_file = {};

// File-scope accessors used by `n00b_attest_module_init` to populate
// the vtable without taking dependencies on the static function
// addresses across translation units (the static functions are not
// visible to module-init's TU). We expose four package-internal
// initializer helpers that route through the vtable struct directly.
//
// The cleaner shape is a single `n00b_attest_backend_file_init`
// entry point that the module-init calls; it populates the vtable
// from within this TU (where the static function pointers are in
// scope) and the registration call is the module-init's
// responsibility.

void
_n00b_attest_backend_file_init(void)
{
    // The scheme string lives for the process lifetime; we use the
    // runtime default allocator (passing nullptr) because the
    // module-init is process-scoped — threading an arena here would
    // create lifetime confusion (the scheme outlives any caller
    // arena).
    n00b_attest_backend_file.scheme  = r"file";
    n00b_attest_backend_file.load    = file_load;
    n00b_attest_backend_file.sign    = file_sign;
    n00b_attest_backend_file.pubkey  = file_pubkey;
    n00b_attest_backend_file.keyid   = file_keyid;
    n00b_attest_backend_file.release = file_release;
}
