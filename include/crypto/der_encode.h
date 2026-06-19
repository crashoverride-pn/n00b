#pragma once

/**
 * @file util/der_encode.h
 * @brief Allocator-aware DER (X.690) encoder primitives.
 *
 * Pure-byte producer for ASN.1 Distinguished Encoding Rules
 * structures, suitable for composing X.509 / PKCS#7 / Authenticode
 * `SPC_INDIRECT_DATA` blobs from the top down.
 *
 * # Symbol prefix
 *
 * `n00b_der_encode_*` (lower-case symbols, `N00B_DER_*` for the
 * error-code macros). Top-level libn00b utility namespace, matching
 * the `n00b_base64_*` / `n00b_json_*` precedent — these are general-
 * purpose primitives that any libn00b consumer (signed-update
 * channels, signed config bundles, X.509 emission) may need.
 *
 * # What this implements — and what it doesn't
 *
 * The producer is **DER** (X.690 §10), not the broader BER:
 *
 * - All TLV lengths are definite (no indefinite-length 0x80
 *   form).
 * - INTEGER values use the minimum byte count (no leading zero
 *   pad unless required by the sign bit; no leading 0xFF for
 *   negative values that are already minimal).
 * - SET-OF elements are sorted lexicographically over the
 *   encoded child octets per X.690 §11.6 ("the canonical order
 *   for the SET OF type") — n00b_der_encode_set is the
 *   canonical-order variant; callers wanting the BER SET (no
 *   sort) must compose the bytes manually.
 * - BIT STRING carries the leading "number of unused trailing
 *   bits" octet per X.680 §22 + X.690 §8.6.
 * - UTCTime / GeneralizedTime emit the `YYMMDDHHMMSSZ` /
 *   `YYYYMMDDHHMMSSZ` shapes only (Z terminator, no fractional
 *   seconds, UTC). Year disambiguation per RFC 5280 §4.1.2.5:
 *   the caller picks UTCTime for 1950..2049 and
 *   GeneralizedTime for everything else; this module does NOT
 *   second-guess the choice.
 *
 * Out of scope for v1:
 * - INTEGER values larger than `int64_t` (callers that need a
 *   bignum INTEGER pass pre-encoded bytes through
 *   `n00b_der_encode_tagged` or compose the TLV manually).
 * - REAL, ENUMERATED, BMPString, UniversalString, ObjectDescriptor.
 *   (The Authenticode + PKCS#7 paths Phase 3 cares about do not
 *   touch these.)
 * - Indefinite-length / streaming output. Every producer returns
 *   a fully assembled `n00b_buffer_t *`.
 *
 * # Allocator discipline
 *
 * Every producer takes `.allocator = nullptr` per
 * `n00b-api-guidelines.md` §4 + D-060. The returned
 * `n00b_buffer_t *` and every internal scratch allocation are
 * tied to the caller's allocator; arena callers can free the
 * whole sub-graph at once.
 *
 * # Type-class encoding
 *
 * Every producer's first output byte is the identifier octet —
 * tag class + primitive/constructed bit + tag number per X.690
 * §8.1.2. Constants:
 *
 * - `N00B_DER_TAG_UNIVERSAL_*`: universal-class tag numbers
 *   the encoder emits.
 * - `n00b_der_encode_tagged`: context-specific [n] wrapper for
 *   composing PKCS#7 / X.509 constructs that nest a SEQUENCE or
 *   SET inside a tag-class explicit wrapper.
 */

#include <n00b.h>
#include "adt/result.h"

/**
 * @brief Universal class tag numbers used by this encoder.
 *
 * The producers below emit these directly. The public macros are
 * exposed so callers composing custom TLVs via
 * @ref n00b_der_encode_tagged can match them without re-deriving
 * the X.690 numbers.
 */
#define N00B_DER_TAG_BOOLEAN          0x01  ///< X.680 §17
#define N00B_DER_TAG_INTEGER          0x02  ///< X.680 §18
#define N00B_DER_TAG_BIT_STRING       0x03  ///< X.680 §22
#define N00B_DER_TAG_OCTET_STRING     0x04  ///< X.680 §23
#define N00B_DER_TAG_NULL             0x05  ///< X.680 §19
#define N00B_DER_TAG_OID              0x06  ///< X.680 §32
#define N00B_DER_TAG_UTF8_STRING      0x0c  ///< X.680 §41
#define N00B_DER_TAG_SEQUENCE         0x30  ///< X.680 §24 (SEQUENCE / SEQUENCE OF; constructed)
#define N00B_DER_TAG_SET              0x31  ///< X.680 §25 (SET / SET OF; constructed)
#define N00B_DER_TAG_PRINTABLE_STRING 0x13  ///< X.680 §41
#define N00B_DER_TAG_IA5_STRING       0x16  ///< X.680 §41
#define N00B_DER_TAG_UTCTIME          0x17  ///< X.680 §47
#define N00B_DER_TAG_GENERALIZED_TIME 0x18  ///< X.680 §47

/**
 * @brief DER encoder error codes (negative ints, libn00b convention).
 *
 * Surfaces only through diagnostics from internal callers — every
 * encoder in this module currently has a total domain over its
 * input set and returns `n00b_buffer_t *` directly. The codes are
 * declared for the future when bignum INTEGER arrives and other
 * input-domain rejection paths land.
 */
#define N00B_DER_ERR_OID_TOO_FEW_ARCS  (-3100)
#define N00B_DER_ERR_OID_BAD_FIRST_ARC (-3101)
#define N00B_DER_ERR_OID_BAD_SECOND_ARC (-3102)
#define N00B_DER_ERR_BIT_STRING_BAD_UNUSED_BITS (-3103)
#define N00B_DER_ERR_UTCTIME_OUT_OF_RANGE (-3104)
#define N00B_DER_ERR_GENERALIZEDTIME_OUT_OF_RANGE (-3105)

/**
 * @brief DER-encode an INTEGER value (X.680 §18; X.690 §8.3).
 *
 * @param v  Signed 64-bit integer value. Encoded in two's-complement
 *           with the minimum number of octets required to represent
 *           the value (per X.690 §8.3.2 — the first nine bits MUST
 *           NOT be all-zero or all-one, otherwise the leading octet
 *           is redundant).
 *
 * @kw allocator  Optional allocator (default: runtime). Owns the
 *                returned buffer.
 *
 * @return A new `n00b_buffer_t *` carrying the TLV bytes:
 *         `0x02 || L || content`.
 *
 * @details
 *
 * - `v = 0` → `0x02 0x01 0x00`.
 * - `v = 127` → `0x02 0x01 0x7F`.
 * - `v = 128` → `0x02 0x02 0x00 0x80` (leading zero needed
 *   because the high bit of `0x80` would otherwise mark
 *   the value negative).
 * - `v = -128` → `0x02 0x01 0x80`.
 * - `v = -129` → `0x02 0x02 0xFF 0x7F`.
 *
 * The minimum-encoding discipline of DER is implemented by
 * scanning down from the most-significant byte and trimming
 * each octet that's redundant with the sign bit of the next.
 */
extern n00b_buffer_t *
n00b_der_encode_integer(int64_t v) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode an OCTET STRING (X.680 §23; X.690 §8.7).
 *
 * @param bytes  The payload bytes. A nullptr is treated as an
 *               empty OCTET STRING (`0x04 0x00`).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying `0x04 || L || content`.
 *
 * @details Primitive form only — DER uses the primitive form for
 * OCTET STRING (X.690 §8.7.2 / §10.2 forbid the constructed
 * indefinite-length form).
 */
extern n00b_buffer_t *
n00b_der_encode_octet_string(n00b_buffer_t *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode an OBJECT IDENTIFIER (X.680 §32; X.690 §8.19).
 *
 * @param arcs    Pointer to the OID's arc array. Must have at least
 *                two elements (per X.680: the first two arcs are
 *                packed into a single subidentifier as
 *                `40 * arc[0] + arc[1]`).
 * @param n_arcs  Number of arcs in @p arcs.
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying `0x06 || L || content`.
 *         A null `arcs` or `n_arcs < 2` yields an empty buffer with
 *         no header (programming error; not a runtime-validated
 *         input domain).
 *
 * @details
 *
 * Each subidentifier after the first-two-packed one is encoded as a
 * base-128 big-endian variable-length integer, with the high bit
 * set on every byte except the last (X.690 §8.19.2).
 *
 * Example: `1.2.840.113549.1.7.2` (PKCS#7 SignedData OID) encodes
 * to `06 09 2A 86 48 86 F7 0D 01 07 02`.
 *
 * Constraints (X.680): `arc[0]` ∈ {0, 1, 2}; if `arc[0]` < 2 then
 * `arc[1]` ∈ [0, 39]; otherwise `arc[1]` may be any non-negative
 * value. This module does NOT validate those bounds for v1 — the
 * Phase 3 caller set (PKCS#7 + Authenticode + X.509) uses well-
 * known OIDs that satisfy them by construction.
 */
extern n00b_buffer_t *
n00b_der_encode_oid(uint32_t *arcs, size_t n_arcs) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode a SEQUENCE (constructed; X.680 §24).
 *
 * Concatenates the supplied child TLVs and wraps them in
 * `0x30 || L || content`.
 *
 * @param elements    Array of child TLV buffers. Elements may not
 *                    be nullptr; a nullptr element is skipped (so
 *                    callers can pre-build an array sized to the
 *                    maximum number of children and elide unused
 *                    slots).
 * @param n_elements  Number of slots in @p elements.
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying the SEQUENCE TLV.
 *
 * @details Long-form length encoding kicks in for content
 * lengths >= 128 octets per X.690 §8.1.3.5.
 */
extern n00b_buffer_t *
n00b_der_encode_sequence(n00b_buffer_t **elements, size_t n_elements) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode a SET (constructed; X.680 §25; X.690 §11.6).
 *
 * Canonically sorts the supplied child TLVs (lexicographic byte
 * order over each child's TLV octets, ascending) and wraps them
 * in `0x31 || L || content`. The canonical-ordering rule applies
 * to SET OF in X.690; SET (without OF) has no required order in
 * DER, but emitting in canonical order is the safe shape for
 * PKCS#7 SignerInfos / authenticated attributes (RFC 5652 §5.3
 * mandates DER for the `authenticatedAttributes` field, which
 * the SET-OF rule covers).
 *
 * @param elements    Array of child TLV buffers. Element pointers
 *                    must be non-nullptr; entries are not sliced or
 *                    skipped.
 * @param n_elements  Number of slots in @p elements.
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying the SET TLV.
 *
 * @details The sort is stable and side-effect-free: the input
 * array is not mutated. The sort key is the entire encoded child
 * (T + L + V) compared lexicographically as unsigned octets; ties
 * are impossible in DER because distinct ASN.1 values cannot share
 * the same encoding.
 */
extern n00b_buffer_t *
n00b_der_encode_set(n00b_buffer_t **elements, size_t n_elements) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Wrap pre-encoded content in a context-specific [n] tag
 *        (X.690 §8.1.2.4; explicit-tagging shape).
 *
 * Emits `0xA0 | n_low5 || L || content` (constructed; the
 * top-level Authenticode + PKCS#7 sites that use this all wrap a
 * SEQUENCE so the constructed bit applies). The low 5 bits of @p
 * tag encode the tag number; the high 3 bits (class + P/C) are
 * forced to `10 1` (context-specific, constructed).
 *
 * @param tag      Tag number in [0, 30]. (High tag numbers > 30
 *                 require multi-byte identifier encoding per X.690
 *                 §8.1.2.4.2; not supported in v1 since the
 *                 Phase 3 callers all use single-byte tags.)
 * @param content  Pre-encoded inner bytes (typically the TLV of a
 *                 SEQUENCE / SET / OCTET STRING the caller built
 *                 separately).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying `tag-byte || L || content`.
 */
extern n00b_buffer_t *
n00b_der_encode_tagged(uint32_t tag, n00b_buffer_t *content) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Wrap pre-encoded content in a context-specific [n] IMPLICIT tag
 *        (X.690 §8.14.3).
 *
 * Differs from @ref n00b_der_encode_tagged (which is EXPLICIT —
 * the content's tag is preserved and a new outer tag is added) by
 * **REPLACING** the content's outer identifier-octet rather than
 * nesting. Per X.690 §8.14.3 / X.680 §31, an IMPLICIT tag inherits
 * the primitive/constructed bit of the content's underlying ASN.1
 * type (X.690 §8.14.3.1: "the encoding ... shall be derived from the
 * encoding for the type of the implicitly-tagged type, with the
 * identifier octets replaced by those of the implicit tag").
 *
 * The encoder reads the input's leading tag byte to determine
 * constructed-vs-primitive:
 *
 * - **Primitive** content (e.g. OCTET STRING under `[0] IMPLICIT`):
 *   the new identifier octet is `0x80 | (tag & 0x1F)` —
 *   context-specific class, primitive bit clear.
 * - **Constructed** content (e.g. SEQUENCE or SET under `[0] IMPLICIT`):
 *   the new identifier octet is `0xA0 | (tag & 0x1F)` —
 *   context-specific class, constructed bit set.
 *
 * Detection: the high two bits of the content's leading byte give
 * the class (universal/application/context/private); the next bit
 * gives primitive/constructed. For libn00b's encoder outputs the
 * leading byte is always a universal-class identifier (tags 0x01..
 * 0x18) for primitives, or `0x30` / `0x31` for SEQUENCE / SET — so
 * inspecting bit 5 (`0x20`, the constructed flag) of the leading
 * byte is sufficient.
 *
 * @param tag      Tag number in [0, 30]. (High tag numbers > 30
 *                 require multi-byte identifier encoding per X.690
 *                 §8.1.2.4.2; not supported in v1 since the
 *                 PKCS#7 / Authenticode callers all use single-byte
 *                 tags.)
 * @param content  Pre-encoded inner TLV bytes. The leading
 *                 identifier octet is read for the constructed-bit
 *                 decision, then dropped from the output (replaced
 *                 by the new context-specific identifier). The
 *                 length octets and value bytes pass through
 *                 unchanged.
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying
 *         `(0x80|tag) || L || V` (primitive) or
 *         `(0xA0|tag) || L || V` (constructed).
 *         Returns an empty buffer with a primitive zero-length TLV
 *         when @p content is nullptr.
 *
 * @details
 *
 * Use cases:
 * - RFC 5652 §10.2.3 PKCS#7 SignedData `certificates [0] IMPLICIT
 *   CertificateSet` — constructed; the wrapped SET-of-Certificate
 *   becomes `[0] IMPLICIT` SET.
 * - RFC 5652 §10.2.4 `crls [1] IMPLICIT RevocationInfoChoices`.
 * - Authenticode SpcSpOpusInfo `programName [0] IMPLICIT ... `
 *   (when the inner is a CHOICE of primitive strings).
 */
extern n00b_buffer_t *
n00b_der_encode_implicit_tagged(uint32_t tag, n00b_buffer_t *content) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode a UTF8String (X.680 §41; X.690 §8.21).
 *
 * @param s  The string. A nullptr or empty string yields
 *           `0x0C 0x00`.
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying `0x0C || L || utf8-bytes`.
 *
 * @details The encoder copies the string's UTF-8 byte representation
 * (`s->data` for `s->u8_bytes` bytes). The caller is responsible
 * for ensuring the bytes are valid UTF-8 — `n00b_string_t *`
 * already guarantees this by construction for strings built via
 * `n00b_string_from_cstr` / `r"..."` / `n00b_unicode_*`.
 */
extern n00b_buffer_t *
n00b_der_encode_utf8_string(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode a UTCTime value (X.680 §47; RFC 5280 §4.1.2.5.1).
 *
 * @param t  Unix epoch seconds (UTC). Must encode to a year in
 *           1950..2049 per RFC 5280; outside that range the
 *           caller MUST use @ref n00b_der_encode_generalizedtime
 *           instead. v1 does not range-check; values outside the
 *           supported window produce a wraparound in the YY field
 *           (programming error).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying
 *         `0x17 0x0D YYMMDDHHMMSSZ`.
 */
extern n00b_buffer_t *
n00b_der_encode_utctime(int64_t t) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode a GeneralizedTime value (X.680 §47;
 *        RFC 5280 §4.1.2.5.2).
 *
 * @param t  Unix epoch seconds (UTC).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying
 *         `0x18 0x0F YYYYMMDDHHMMSSZ` (no fractional seconds).
 */
extern n00b_buffer_t *
n00b_der_encode_generalizedtime(int64_t t) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode the NULL value (X.680 §19; X.690 §8.8).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying `0x05 0x00`.
 */
extern n00b_buffer_t *
n00b_der_encode_null() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief DER-encode a BIT STRING (X.680 §22; X.690 §8.6).
 *
 * @param bytes        The bit string's octets (most-significant
 *                     bit first within each byte). nullptr is
 *                     treated as an empty bit string and forces
 *                     @p unused_bits to zero.
 * @param unused_bits  Number of unused trailing bits in the final
 *                     octet. Must be in [0, 7]; values outside
 *                     that range are clamped to 0 (programming
 *                     error in the caller).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying
 *         `0x03 || L || unused_bits || content`.
 *
 * @details The Authenticode signature path uses this to wrap RSA
 * public-key bytes inside a `SubjectPublicKeyInfo`.
 */
extern n00b_buffer_t *
n00b_der_encode_bit_string(n00b_buffer_t *bytes, int unused_bits) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};
