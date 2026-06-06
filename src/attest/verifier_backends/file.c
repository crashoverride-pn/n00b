/* src/attest/verifier_backends/file.c — file verifier-backend body.
 *
 * Implements the surface declared in
 * include/internal/attest/verifier_backends/file.h:
 *   - n00b_attest_verifier_backend_file (the file-scope vtable
 *                                        instance — populated at
 *                                        module-init time per
 *                                        architecture §6.1)
 *   - file_load    (SPKI PEM + RFC 8410 walk + raw-pubkey extract
 *                   + SPKI cache + keyid)
 *   - file_check   (RFC-8032 Ed25519 verify; Ok(true)=verified,
 *                   Ok(false)=did-not-verify (verdict), Err=
 *                   machinery failure — D-044 OQ-1)
 *   - file_pubkey  (returns the pre-built SPKI buffer — no
 *                   allocation, no kwarg, no result wrapping;
 *                   matches architecture §6.1)
 *   - file_keyid   (returns the pre-built keyid string —
 *                   allocation-free)
 *   - file_release (no crypto_wipe — public-key bytes only;
 *                   structural difference from the signer
 *                   release path)
 *
 * Structurally mirrors `src/attest/backends/file.c` (the signer
 * file backend) function-for-function except for the secret-key
 * material handling (the verifier has none).
 *
 * Header dependencies:
 *
 * - monocypher-ed25519.h   — for `crypto_ed25519_check` (RFC 8032
 *                            form; we must NOT use `crypto_eddsa_*`
 *                            from the core header — that's the
 *                            BLAKE2b form and is not RFC 8032
 *                            compliant; see
 *                            subprojects/monocypher/README.n00b.md)
 * - picotls/pembase64.h    — `ptls_load_pem_objects`
 * - picotls/asn1.h         — `ptls_asn1_get_expected_type_and_length`
 *                            primitive for the SPKI walk
 * - core/sha256.h          — libn00b's SHA-256 for keyid derivation
 *
 * Decision log:
 *
 * - D-016 (algorithm-agnostic verifier surface). The public
 *   surface bakes in no algorithm tags; the algorithm is
 *   identified from the SPKI's AlgorithmIdentifier OID at load
 *   time. WP-003 accepts only id-Ed25519; later WPs add OIDs
 *   without disturbing the surface.
 *
 * - D-039 (keyid form + byte-equality invariant with the signer).
 *   The verifier's keyid input is the **SubjectPublicKeyInfo
 *   DER** (44 bytes for Ed25519 = 12-byte fixed prefix + 32-byte
 *   pubkey), and the output is the full SHA-256 of that input
 *   (32 bytes), hex-encoded (64 chars). The signer-side computes
 *   the same hash over the same input, so the keyid strings are
 *   byte-equal for the same underlying key material. The
 *   `test_attest_verifier_keyid.c` regression gates this
 *   invariant.
 *
 * - D-035 OQ-4 (URI tolerance). The load path accepts both
 *   `file:<absolute-path>` and `file:///<absolute-path>` and
 *   normalizes both forms to a single internal C-string path
 *   before handing it to picotls.
 *
 * - D-044 OQ-3 (strict PEM label). Only the literal
 *   `-----BEGIN PUBLIC KEY-----` armor label is accepted; the
 *   backend does not accept `-----BEGIN ED25519 PUBLIC KEY-----`
 *   or raw-pubkey-without-armor forms. The OID check inside the
 *   SPKI walk is the algorithm-discrimination point.
 *
 * - D-045 (`alloc_for_call` cleanup precedent). The verifier
 *   file backend threads a single `alloc_for_call` local through
 *   every allocation site rather than threading `opts->allocator`
 *   or `st->allocator` directly.
 *
 * - D-039 part 1 (picotls allocation interop). Picotls is built
 *   with n00b's allocation shim, so decoded DER buffers returned
 *   by `ptls_load_pem_objects` are released with `n00b_free()`
 *   at the n00b call boundary.
 */

#include "internal/attest/verifier_backends/file.h"
#include "internal/attest/verifier_backends.h"
#include <attest/n00b_attest_verifier.h>

#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/sha256.h"

#include "picotls.h"
#include "picotls/pembase64.h"
#include "picotls/asn1.h"

#include <monocypher-ed25519.h>

#include <string.h>

// ---------------------------------------------------------------------------
// Constants — RFC 8410 id-Ed25519 OID + SPKI shape; PEM strings.
// ---------------------------------------------------------------------------

// id-Ed25519 OID: 1.3.101.112 encoded as 3 bytes (0x2B, 0x65, 0x70).
// Same OID body the signer file backend checks; mirrors the constant
// from src/attest/backends/file.c — the 3 bytes are intrinsic to the
// RFC 8410 wire form and copying the constant keeps the two backends'
// diffs focused. (Lifting into a shared private header is possible
// but would only save 3 bytes; the trade-off favors locality.)
static const uint8_t k_ed25519_oid_body[3] = {0x2B, 0x65, 0x70};

// PEM label for an SPKI public key (D-044 OQ-3 strict). The backend
// passes this literal string to `ptls_load_pem_objects`, which
// matches against the armor lines byte-for-byte. The legacy
// `ED25519 PUBLIC KEY` armor (some OpenSSL versions) is rejected at
// the PEM-decode layer and surfaces as
// N00B_ATTEST_ERR_VERIFIER_PEM_PARSE_FAILED.
static const char k_spki_pem_label[] = "PUBLIC KEY";

// SubjectPublicKeyInfo DER for Ed25519 is the fixed 44-byte sequence:
//   30 2A                              SEQUENCE (42 bytes)
//     30 05                            SEQUENCE (5 bytes) AlgorithmIdentifier
//       06 03 2B 65 70                 OID 1.3.101.112 (id-Ed25519)
//     03 21                            BIT STRING (33 bytes)
//       00 <32-byte pubkey>            unused-bits = 0, then key bytes
//
// Mirror of the signer file backend's `k_ed25519_spki_prefix`;
// intrinsic to the Ed25519 SPKI shape per RFC 8410. The keyid
// byte-equality invariant with the signer (D-039) depends on the
// two backends producing the SAME 44-byte sequence for the same
// pubkey; keeping the two prefix copies byte-identical is the
// concrete realization of that invariant.
static const uint8_t k_ed25519_spki_prefix[12] = {
    0x30, 0x2A,
    0x30, 0x05,
    0x06, 0x03, 0x2B, 0x65, 0x70,
    0x03, 0x21,
    0x00,
};

// Lowercase-hex table for keyid encoding.
static const char k_hex_lower[] = "0123456789abcdef";

// ASN.1 tag bytes used in the RFC 8410 SPKI walk.
#define ASN1_TAG_SEQUENCE   0x30
#define ASN1_TAG_OID        0x06
#define ASN1_TAG_BITSTRING  0x03

// ---------------------------------------------------------------------------
// Helpers — file-URI normalization.
// ---------------------------------------------------------------------------

// Strip the `file:` scheme prefix (or `file:///`, FR-SM-1 strict
// vs RFC 3986 — D-035 OQ-4) and return a pointer into `uri->data`
// to the path body. Returns nullptr if the input is null or does
// not begin with `file:`.
//
// Identical to the signer-side `normalize_file_uri`. The
// substring pointer remains NUL-terminated because it points
// into the same allocation as `uri->data` (n00b_string_t's
// `data` field is documented NUL-terminated per
// n00b_string_from_raw's post-condition).
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
    //   `file:<path>`        (FR-SM-1 strict) -> offset 5
    //   `file:///<path>`     (RFC 3986)        -> offset 7
    //                                            (the leading `/` of
    //                                            the absolute path)
    // The `file://<host>/<path>` form with a non-empty host is
    // rejected (no remote-host concept in WP-003).
    if (n >= 7 && s[5] == '/' && s[6] == '/') {
        if (n >= 8 && s[7] == '/') {
            return s + 7;  // points at the leading `/` of abs path
        }
        return nullptr;
    }
    return s + 5;
}

// ---------------------------------------------------------------------------
// Helpers — keyid derivation (hex-encoded SHA-256 of SPKI DER).
//
// Mirror of the signer-side `derive_keyid`: same input form
// (44-byte SPKI DER), same hash function (SHA-256), same output
// form (full 32-byte digest, lowercase-hex-encoded, 64 chars).
// The D-039 byte-equality invariant with the signer's keyid
// follows directly from "same input + same hash + same encoding".
// ---------------------------------------------------------------------------

static n00b_string_t *
derive_keyid(const uint8_t *spki_der, n00b_allocator_t *alloc_for_call)
{
    n00b_sha256_digest_t digest;
    n00b_sha256_hash(spki_der, 44, digest);

    // n00b_sha256_digest_t is uint32_t[8] in host byte order.
    // Spell out the byte view per SHA-256's big-endian word
    // convention so the keyid matches what every other SHA-256
    // implementation produces against the same input.
    uint8_t digest_bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w              = digest[i];
        digest_bytes[i * 4 + 0] = (uint8_t)((w >> 24) & 0xff);
        digest_bytes[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        digest_bytes[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        digest_bytes[i * 4 + 3] = (uint8_t)(w & 0xff);
    }

    char *hex = n00b_alloc_array_with_opts(
        char,
        64,
        &(n00b_alloc_opts_t){
            .allocator = alloc_for_call,
        });
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2]     = k_hex_lower[(digest_bytes[i] >> 4) & 0xf];
        hex[i * 2 + 1] = k_hex_lower[digest_bytes[i] & 0xf];
    }
    return n00b_string_from_raw(hex, 64, .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// Helpers — RFC 8410 SubjectPublicKeyInfo walk.
//
// SPKI (RFC 5280 / RFC 8410):
//
//   SEQUENCE {
//     AlgorithmIdentifier {
//       algorithm    OID (id-Ed25519 = 1.3.101.112),
//       -- parameters absent per RFC 8410 §4
//     },
//     subjectPublicKey  BIT STRING (33 bytes: 0x00 unused-bits + 32-byte key)
//   }
//
// Notably shorter than the PKCS#8 walk on the signer side:
//
//   - no `version INTEGER` field
//   - no doubly-nested OCTET STRING wrapping the key bytes
//   - BIT STRING carries an unused-bits indicator byte (0x00 here)
//     before the actual key bytes; the pubkey starts at offset 1
//     of the BIT STRING contents
//
// Off-by-one at the BIT STRING leading-byte step is the classic
// failure mode (would shift the extracted pubkey by 1 byte and
// silently corrupt every downstream verify). The walk explicitly
// asserts the unused-bits indicator equals 0x00 (the only valid
// value for whole-byte payloads like an Ed25519 32-byte key).
//
// Failures route to N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED
// (DER shape mismatch) or
// N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_ALGORITHM (OID mismatch).
// ---------------------------------------------------------------------------

static int
walk_spki_ed25519_pubkey(const uint8_t *der, size_t der_len, uint8_t pubkey[32])
{
    uint32_t length       = 0;
    int      indefinite   = 0;
    size_t   last_byte    = 0;
    int      decode_error = 0;
    size_t   byte_index   = 0;

    // Outer SEQUENCE.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, 0, ASN1_TAG_SEQUENCE,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0 || last_byte > der_len) {
        return N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED;
    }

    // AlgorithmIdentifier SEQUENCE.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_SEQUENCE,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) {
        return N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED;
    }
    size_t alg_end = last_byte;

    // OID inside AlgorithmIdentifier.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_OID,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) {
        return N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED;
    }
    // OID body == 0x2B 0x65 0x70 (id-Ed25519).
    if (length != 3 || byte_index + 3 > der_len
        || memcmp(der + byte_index, k_ed25519_oid_body, 3) != 0) {
        return N00B_ATTEST_ERR_VERIFIER_UNSUPPORTED_ALGORITHM;
    }
    // RFC 8410 §4 forbids parameters; we don't enforce that strictly
    // here (anything between the OID end and alg_end is ignored).
    byte_index = alg_end;

    // subjectPublicKey BIT STRING.
    byte_index = ptls_asn1_get_expected_type_and_length(
        der, der_len, byte_index, ASN1_TAG_BITSTRING,
        &length, &indefinite, &last_byte, &decode_error, nullptr);
    if (decode_error != 0) {
        return N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED;
    }
    // BIT STRING content for Ed25519 is 33 bytes total: 1 unused-bits
    // indicator + 32 key bytes. The leading byte MUST be 0x00 (whole-
    // byte payload). Off-by-one here is the classic SPKI failure
    // mode — explicit assertion below.
    if (length != 33 || byte_index + 33 > der_len) {
        return N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED;
    }
    if (der[byte_index] != 0x00) {
        // Non-zero unused-bits indicator is technically legal for
        // arbitrary BIT STRINGs but is meaningless for a whole-byte
        // key payload. Reject as a DER-shape violation.
        return N00B_ATTEST_ERR_VERIFIER_DER_PARSE_FAILED;
    }

    memcpy(pubkey, der + byte_index + 1, 32);
    return 0;
}

// ---------------------------------------------------------------------------
// Vtable entry — load.
// ---------------------------------------------------------------------------

static n00b_result_t(n00b_attest_verifier_t *)
file_load(n00b_string_t                                  *ref,
          const n00b_attest_verifier_backend_call_opts_t *opts)
{
    // D-045 `alloc_for_call` idiom: thread a single local through
    // every allocation site rather than re-deriving "opts ?
    // opts->allocator : nullptr" per call site.
    n00b_allocator_t *alloc_for_call = opts != nullptr ? opts->allocator
                                                       : nullptr;

    const char *path = normalize_file_uri(ref);
    if (path == nullptr) {
        return n00b_result_err(n00b_attest_verifier_t *,
                               N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND);
    }

    // Single-object load — pass list_max = 1; bail on any error or
    // zero objects. The strict PEM label (D-044 OQ-3) is enforced by
    // picotls's armor-match: only `-----BEGIN PUBLIC KEY-----` /
    // `-----END PUBLIC KEY-----` decode; other labels surface as
    // a decode failure.
    ptls_iovec_t iov[1] = {};
    size_t       nb     = 0;
    int          rc     = ptls_load_pem_objects(path, k_spki_pem_label,
                                                iov, 1, &nb);
    if (rc != 0) {
        // picotls returns -1 for fopen failure and a positive
        // PTLS_ERROR_* code for label/decode failures.
        return n00b_result_err(
            n00b_attest_verifier_t *,
            rc == -1
                ? N00B_ATTEST_ERR_VERIFIER_KEY_NOT_FOUND
                : N00B_ATTEST_ERR_VERIFIER_PEM_PARSE_FAILED);
    }
    if (nb == 0 || iov[0].base == nullptr) {
        return n00b_result_err(n00b_attest_verifier_t *,
                               N00B_ATTEST_ERR_VERIFIER_PEM_PARSE_FAILED);
    }

    // RFC 8410 SPKI walk over the decoded DER.
    uint8_t raw_pubkey[32] = {};
    int     walk_err = walk_spki_ed25519_pubkey(iov[0].base,
                                                iov[0].len,
                                                raw_pubkey);

    // Release picotls's DER buffer regardless of walk outcome. Picotls is
    // built with n00b's allocation shim, so this buffer is n00b-owned here.
    n00b_free(iov[0].base);

    if (walk_err != 0) {
        return n00b_result_err(n00b_attest_verifier_t *, walk_err);
    }

    n00b_attest_verifier_file_t *st = n00b_alloc_with_opts(
        n00b_attest_verifier_file_t,
        &(n00b_alloc_opts_t){
            .allocator = alloc_for_call,
        });

    memcpy(st->pubkey, raw_pubkey, 32);

    // Assemble the 44-byte SPKI DER once: 12-byte fixed prefix +
    // 32-byte pubkey. Identical to the signer-side cache for the
    // same key material (D-039 byte-equality invariant).
    memcpy(st->spki_der, k_ed25519_spki_prefix, 12);
    memcpy(st->spki_der + 12, st->pubkey, 32);

    st->spki_buffer = n00b_buffer_from_bytes((char *)st->spki_der,
                                             44,
                                             .allocator = alloc_for_call);

    st->base.backend = &n00b_attest_verifier_backend_file;
    st->keyid        = derive_keyid(st->spki_der, alloc_for_call);
    st->allocator    = alloc_for_call;

    return n00b_result_ok(n00b_attest_verifier_t *, &st->base);
}

// ---------------------------------------------------------------------------
// Vtable entry — check.
//
// Calls Monocypher's RFC-8032-compliant `crypto_ed25519_check`
// (NOT `crypto_eddsa_check`, which uses BLAKE2b — see auto-memory
// `monocypher_ed25519_api_split.md`). The return-int → verdict
// translation is the load-bearing semantic of this function:
//
//   crypto_ed25519_check returns 0 on signature verified,
//   non-zero on signature did NOT verify.
//
//   We map:
//     rc == 0  -> Ok(true)   verified
//     rc != 0  -> Ok(false)  did NOT verify (verdict, not failure)
//
// Inverting this mapping silently breaks every downstream
// verify. Machinery failures (null inputs, sig length not exactly
// 64 bytes) route through Err — Phase 4's 3-code exit shape
// (exit 0 = Ok(true), exit 1 = Ok(false), exit 2 = Err) depends
// on the verdict/Err split staying intact.
// ---------------------------------------------------------------------------

static n00b_result_t(bool)
file_check(n00b_attest_verifier_t                         *verifier,
           n00b_buffer_t                                  *bytes,
           n00b_buffer_t                                  *sig,
           const n00b_attest_verifier_backend_call_opts_t *opts)
{
    // Allocator fallback (D-042 W-2): per-call → state → runtime
    // default. The check path has no allocator-threaded outputs
    // (the bool verdict is a scalar in the result struct), and
    // Phase 3's envelope-verify wrappers (D-047) confirmed no
    // scratch allocation is needed here: PAE derivation happens
    // one level up in `n00b_attest_envelope_verify`, and
    // `crypto_ed25519_check` is allocation-free.
    //
    // D-047 W-3 confirmed the `(void)opts;` pattern is acceptable
    // for vtable function-pointer parameters: the kwargs-to-opts
    // flattening lives at the resolver edge in `verifier.c`, and
    // the opts struct is part of the inter-translation-unit
    // boundary shape — dropping it would break ABI symmetry with
    // the signer-side `sign` vtable. Phase 3's review re-checked
    // this on the post-wrapper-introduction code path and reached
    // the same conclusion.
    (void)opts;

    if (verifier == nullptr || bytes == nullptr || sig == nullptr) {
        // Null pointer input — per D-047 W-1 this surfaces as the
        // dedicated `_VERIFY_BAD_INPUT` code (Phase 2 placeholder
        // was `_VERIFIER_KEY_NOT_FOUND`).
        return n00b_result_err(bool,
                               N00B_ATTEST_ERR_VERIFY_BAD_INPUT);
    }

    n00b_attest_verifier_file_t *st = (n00b_attest_verifier_file_t *)verifier;

    // Ed25519 signatures are exactly 64 bytes. A buffer of any
    // other length is a machinery failure (the verify routine
    // requires a fixed-size input); route through Err so the
    // Phase 4 caller can distinguish a malformed signature
    // payload from a verdict. Per D-047 W-1 this surfaces as the
    // dedicated `_VERIFY_BAD_SIG_LENGTH` code (Phase 2 placeholder
    // was `_VERIFIER_KEY_NOT_FOUND`).
    if (sig->byte_len != 64) {
        return n00b_result_err(bool,
                               N00B_ATTEST_ERR_VERIFY_BAD_SIG_LENGTH);
    }

    int rc = crypto_ed25519_check(
        (const uint8_t *)sig->data,
        st->pubkey,
        (const uint8_t *)bytes->data,
        bytes->byte_len);

    // Verdict mapping: rc == 0 means "verified" (Ok(true));
    // rc != 0 means "did not verify" (Ok(false), NOT Err).
    return n00b_result_ok(bool, rc == 0);
}

// ---------------------------------------------------------------------------
// Vtable entry — pubkey (SPKI DER).
//
// Per architecture §6.1 the SPKI bytes are built at load time and
// stored on the verifier state. The getter is allocation-free:
// it returns the pre-built buffer wrapper verbatim.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
file_pubkey(n00b_attest_verifier_t *verifier)
{
    return ((n00b_attest_verifier_file_t *)verifier)->spki_buffer;
}

// ---------------------------------------------------------------------------
// Vtable entry — keyid.
//
// Symmetric with `file_pubkey` above: the keyid was computed at
// load time and stored on `st->keyid`. The getter returns the
// cached value verbatim — no allocation, no recomputation.
// ---------------------------------------------------------------------------

static n00b_string_t *
file_keyid(n00b_attest_verifier_t *verifier)
{
    return ((n00b_attest_verifier_file_t *)verifier)->keyid;
}

// ---------------------------------------------------------------------------
// Vtable entry — release.
//
// Public-key bytes only; **no** `crypto_wipe`. This is the
// principal structural difference from the signer-side release
// path (which wipes the full 64-byte expanded sk + 44-byte SPKI
// DER per FR-SM-3). The verifier's release exists for caller-
// uniform lifetime management; under the n00b GC convention the
// allocator owns the lifetime and reclaims at scope / arena
// teardown.
//
// Null `verifier` is a no-op (matches the signer's release
// convention).
// ---------------------------------------------------------------------------

static void
file_release(n00b_attest_verifier_t *verifier)
{
    (void)verifier;
    // No explicit work to do under the n00b GC convention. The
    // backend's cached buffers (`spki_buffer`, `keyid`) and the
    // state struct itself are owned by the load-time allocator
    // and reclaimed when that allocator's scope unwinds. This
    // function exists to satisfy the surface-symmetry contract
    // with the signer-side release (the public surface declares
    // `n00b_attest_verifier_release(v)`, and the resolver
    // dispatches straight through this function pointer).
}

// ---------------------------------------------------------------------------
// Vtable instance.
//
// Per architecture §6.1 the vtable carries an `n00b_string_t
// *scheme;` field that cannot be a file-scope constant
// expression. The struct is therefore zero-initialized at file
// scope and populated by `n00b_attest_module_init` (see
// `src/attest/n00b_attest_module.c`), which also registers it
// with the resolver. Once init returns, the vtable is read-only
// for the process lifetime.
// ---------------------------------------------------------------------------

n00b_attest_verifier_backend_t n00b_attest_verifier_backend_file = {};

void
_n00b_attest_verifier_backend_file_init(void)
{
    // The scheme string lives for the process lifetime; we use
    // the runtime default allocator (passing nullptr) because
    // the module-init is process-scoped — threading an arena
    // here would create lifetime confusion (the scheme outlives
    // any caller arena).
    n00b_attest_verifier_backend_file.scheme  = n00b_string_from_cstr("file");
    n00b_attest_verifier_backend_file.load    = file_load;
    n00b_attest_verifier_backend_file.check   = file_check;
    n00b_attest_verifier_backend_file.pubkey  = file_pubkey;
    n00b_attest_verifier_backend_file.keyid   = file_keyid;
    n00b_attest_verifier_backend_file.release = file_release;
}
