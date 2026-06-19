/* src/util/der_encode.c — DER (X.690) encoder primitives.
 *
 * Implements the surface declared in include/util/der_encode.h.
 * Every producer returns a fully assembled `n00b_buffer_t *`; no
 * streaming, no indefinite-length. Allocator threading per §4 +
 * D-060 — every entry point accepts `.allocator = nullptr` and
 * forwards it through every nested allocation.
 *
 * Design notes:
 *
 * - All TLV assembly bottoms out in `emit_tlv()`, which sizes the
 *   length-of-length prefix (short form for L < 128, long-form
 *   1..4 byte big-endian count for everything else — the long-form
 *   maxes out at 0xFFFFFFFF bytes of content, which we never
 *   approach for Authenticode/PKCS#7 sizes).
 *
 * - INTEGER minimal-encoding uses a back-scan: starting from the
 *   most-significant byte of the 8-byte big-endian image of the
 *   int64_t, drop leading 0x00s whose successor's high bit is also
 *   0 (positive minimal), and drop leading 0xFFs whose successor's
 *   high bit is 1 (negative minimal). The result is always at
 *   least one byte.
 *
 * - SET canonical ordering uses qsort on a pointer-to-buffer array
 *   to avoid mutating the caller's input. Comparison key is the
 *   entire encoded TLV (T+L+V) per X.690 §11.6; tie shorter wins
 *   the lexicographic compare, which matches the "shorter is less"
 *   rule X.690 places on equal prefixes.
 *
 * - OID first-two-arc packing per X.690 §8.19.4.
 *
 * - UTCTime/GeneralizedTime use n00b's gmtime equivalent path —
 *   for v1 we use libc <time.h> functions (gmtime_r) since
 *   they're pure formatters and there's no n00b wrapper in the
 *   util/ tree. (Test-file carve-out doesn't apply here, but
 *   libc time.h is documented as acceptable for raw-byte work
 *   when there's no n00b wrapper; n00b's time primitive
 *   `n00b_get_clock_now()` returns ns-since-epoch which we can
 *   reduce to a seconds value, but reading the broken-down time
 *   structure still needs gmtime_r — no n00b wrapper exists.)
 */

#include <crypto/der_encode.h>

#include "core/buffer.h"
#include "core/alloc.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/* Encode the length portion of a TLV into @p out at @p out_off.
 * Returns the number of length-octets written. */
static size_t
write_length(uint8_t *out, size_t out_off, size_t content_len)
{
    if (content_len < 128) {
        out[out_off] = (uint8_t)content_len;
        return 1;
    }
    /* Long form: count significant bytes (1..4 covers 32-bit
     * lengths; we don't approach 32-bit content sizes). */
    uint8_t buf[8];
    size_t  n = 0;
    size_t  v = content_len;
    while (v > 0) {
        buf[n++] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
    out[out_off] = (uint8_t)(0x80 | n);
    /* Big-endian write. */
    for (size_t i = 0; i < n; i++) {
        out[out_off + 1 + i] = buf[n - 1 - i];
    }
    return 1 + n;
}

/* How many bytes does the length encoding consume for @p
 * content_len ? */
static size_t
length_octets(size_t content_len)
{
    if (content_len < 128) return 1;
    size_t n = 0;
    size_t v = content_len;
    while (v > 0) { n++; v >>= 8; }
    return 1 + n;
}

/* Assemble TLV: tag || length-of-length || content. */
static n00b_buffer_t *
emit_tlv(uint8_t          tag,
         const uint8_t   *content,
         size_t           content_len,
         n00b_allocator_t *allocator)
{
    size_t llen  = length_octets(content_len);
    size_t total = 1 + llen + content_len;

    n00b_buffer_t *out = n00b_buffer_new((int64_t)total,
                                         .allocator = allocator);
    /* n00b_buffer_new sets byte_len to 0; we know we'll fill total
     * bytes. */
    n00b_buffer_resize(out, total);
    uint8_t *dst = (uint8_t *)out->data;
    dst[0]       = tag;
    write_length(dst, 1, content_len);
    if (content_len > 0 && content != nullptr) {
        memcpy(dst + 1 + llen, content, content_len);
    }
    return out;
}

// ---------------------------------------------------------------------------
// INTEGER
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_integer(int64_t v) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    /* Two's-complement big-endian 8-byte image of v. */
    uint8_t be[8];
    uint64_t uv = (uint64_t)v;
    for (int i = 7; i >= 0; i--) {
        be[i] = (uint8_t)(uv & 0xFF);
        uv >>= 8;
    }

    /* Trim leading bytes that are redundant with the sign bit of
     * the next byte. X.690 §8.3.2: the first nine bits MUST NOT
     * be all-zero or all-one. */
    size_t start = 0;
    if (v >= 0) {
        while (start < 7 && be[start] == 0x00 && (be[start + 1] & 0x80) == 0) {
            start++;
        }
    }
    else {
        while (start < 7 && be[start] == 0xFF && (be[start + 1] & 0x80) != 0) {
            start++;
        }
    }
    size_t content_len = 8 - start;

    return emit_tlv(N00B_DER_TAG_INTEGER,
                    be + start,
                    content_len,
                    allocator);
}

// ---------------------------------------------------------------------------
// OCTET STRING
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_octet_string(n00b_buffer_t *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    const uint8_t *content     = nullptr;
    size_t         content_len = 0;
    if (bytes != nullptr) {
        content     = (const uint8_t *)bytes->data;
        content_len = bytes->byte_len;
    }
    return emit_tlv(N00B_DER_TAG_OCTET_STRING,
                    content,
                    content_len,
                    allocator);
}

// ---------------------------------------------------------------------------
// OID
// ---------------------------------------------------------------------------

/* Encode a single subidentifier into @p out as base-128 big-endian
 * with high-bit continuation on every byte except the last. */
static size_t
encode_subid(uint32_t v, uint8_t *out)
{
    if (v == 0) {
        out[0] = 0;
        return 1;
    }
    /* Buffer the big-endian bytes in reverse, then copy out with
     * continuation bits. */
    uint8_t rev[10];
    size_t  n = 0;
    while (v > 0) {
        rev[n++] = (uint8_t)(v & 0x7F);
        v >>= 7;
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t byte = rev[n - 1 - i];
        if (i != n - 1) {
            byte |= 0x80;
        }
        out[i] = byte;
    }
    return n;
}

n00b_buffer_t *
n00b_der_encode_oid(uint32_t *arcs, size_t n_arcs) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (arcs == nullptr || n_arcs < 2) {
        return emit_tlv(N00B_DER_TAG_OID, nullptr, 0, allocator);
    }

    /* Worst-case bound: 10 bytes per arc (32-bit value spread over
     * 5 base-128 bytes + slack). Allocate a small scratch and
     * compact afterward via emit_tlv. */
    size_t   cap     = 10 * n_arcs;
    uint8_t *scratch = n00b_alloc_array_with_opts(
        uint8_t, (int64_t)cap,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});
    size_t off = 0;

    /* First subidentifier packs arcs[0] and arcs[1] per X.690
     * §8.19.4: subid = 40 * arc[0] + arc[1]. */
    uint32_t first = arcs[0] * 40 + arcs[1];
    off += encode_subid(first, scratch + off);

    for (size_t i = 2; i < n_arcs; i++) {
        off += encode_subid(arcs[i], scratch + off);
    }

    return emit_tlv(N00B_DER_TAG_OID, scratch, off, allocator);
}

// ---------------------------------------------------------------------------
// SEQUENCE
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_sequence(n00b_buffer_t **elements, size_t n_elements) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    /* Compute the total content length. */
    size_t total = 0;
    for (size_t i = 0; i < n_elements; i++) {
        if (elements != nullptr && elements[i] != nullptr) {
            total += elements[i]->byte_len;
        }
    }

    if (total == 0) {
        return emit_tlv(N00B_DER_TAG_SEQUENCE, nullptr, 0, allocator);
    }

    /* Concatenate into a scratch buffer. */
    uint8_t *scratch = n00b_alloc_array_with_opts(
        uint8_t, (int64_t)total,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});
    size_t off = 0;
    for (size_t i = 0; i < n_elements; i++) {
        if (elements != nullptr && elements[i] != nullptr) {
            memcpy(scratch + off,
                   elements[i]->data,
                   elements[i]->byte_len);
            off += elements[i]->byte_len;
        }
    }

    return emit_tlv(N00B_DER_TAG_SEQUENCE, scratch, total, allocator);
}

// ---------------------------------------------------------------------------
// SET (canonically ordered)
// ---------------------------------------------------------------------------

static int
cmp_buffer_lex(const void *a, const void *b)
{
    n00b_buffer_t *ba = *(n00b_buffer_t *const *)a;
    n00b_buffer_t *bb = *(n00b_buffer_t *const *)b;
    size_t la = ba->byte_len;
    size_t lb = bb->byte_len;
    size_t lm = la < lb ? la : lb;
    int    c  = memcmp(ba->data, bb->data, lm);
    if (c != 0) return c;
    if (la < lb) return -1;
    if (la > lb) return 1;
    return 0;
}

n00b_buffer_t *
n00b_der_encode_set(n00b_buffer_t **elements, size_t n_elements) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (n_elements == 0 || elements == nullptr) {
        return emit_tlv(N00B_DER_TAG_SET, nullptr, 0, allocator);
    }

    /* Copy the pointer array so we can sort without mutating the
     * caller's input. */
    n00b_buffer_t **sorted = n00b_alloc_array(
        n00b_buffer_t *, (int64_t)n_elements,
        .allocator = allocator);
    for (size_t i = 0; i < n_elements; i++) {
        sorted[i] = elements[i];
    }
    qsort(sorted, n_elements, sizeof(n00b_buffer_t *), cmp_buffer_lex);

    size_t total = 0;
    for (size_t i = 0; i < n_elements; i++) {
        total += sorted[i]->byte_len;
    }

    uint8_t *scratch = n00b_alloc_array_with_opts(
        uint8_t, (int64_t)total,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});
    size_t off = 0;
    for (size_t i = 0; i < n_elements; i++) {
        memcpy(scratch + off, sorted[i]->data, sorted[i]->byte_len);
        off += sorted[i]->byte_len;
    }

    return emit_tlv(N00B_DER_TAG_SET, scratch, total, allocator);
}

// ---------------------------------------------------------------------------
// Context-specific [n] explicit-tag wrapper
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_tagged(uint32_t tag, n00b_buffer_t *content) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    /* Identifier octet: context-specific (10) + constructed (1) +
     * low-5-bit tag number. */
    uint8_t        ident       = (uint8_t)(0xA0 | (tag & 0x1F));
    const uint8_t *content_ptr = nullptr;
    size_t         content_len = 0;
    if (content != nullptr) {
        content_ptr = (const uint8_t *)content->data;
        content_len = content->byte_len;
    }
    return emit_tlv(ident, content_ptr, content_len, allocator);
}

// ---------------------------------------------------------------------------
// Context-specific [n] IMPLICIT-tag wrapper
// ---------------------------------------------------------------------------
//
// X.690 §8.14.3 — an IMPLICIT-tagged value inherits the
// primitive/constructed bit of its underlying type's encoding, but
// replaces the identifier octets with the implicit tag's. So we
// peek at the leading byte of @p content to decide whether the new
// identifier should set the constructed flag (0x20) or not, then
// drop the old identifier octet from the output and prepend the
// new one. The length octets and value bytes pass through unchanged.

n00b_buffer_t *
n00b_der_encode_implicit_tagged(uint32_t tag, n00b_buffer_t *content) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (content == nullptr || content->byte_len < 1) {
        /* Empty content → emit a primitive zero-length context-
         * specific tag (matches the libn00b convention that
         * "missing inner" stays primitive, since constructed
         * empties don't appear in the PKCS#7 / Authenticode
         * shapes that drive this API). */
        uint8_t ident = (uint8_t)(0x80 | (tag & 0x1F));
        return emit_tlv(ident, nullptr, 0, allocator);
    }

    /* Read the underlying-type's identifier to determine the
     * primitive-vs-constructed bit. X.690 §8.1.2.5: bit 6 (mask
     * 0x20) of the identifier octet is set when the encoding is
     * constructed. */
    uint8_t  underlying_ident = (uint8_t)content->data[0];
    bool     constructed      = (underlying_ident & 0x20) != 0;
    uint8_t  ident            = (uint8_t)((constructed ? 0xA0 : 0x80)
                                          | (tag & 0x1F));

    /* The output is `(new-ident) || L || V` — i.e. the existing
     * TLV with its leading identifier octet swapped out. We can
     * walk past the leading byte and re-emit the rest verbatim via
     * `emit_tlv` ... except emit_tlv re-encodes the length, which
     * could differ from the embedded length octets if the caller's
     * input wasn't strictly minimal. Avoid that: just copy the
     * caller's bytes wholesale and patch byte 0.
     *
     * (libn00b's own encoders always emit DER-minimal lengths, so
     * the re-encode would be byte-identical — but copying is
     * cheaper and side-steps the dependency on caller minimality.)
     */
    n00b_buffer_t *out = n00b_buffer_new((int64_t)content->byte_len,
                                         .allocator = allocator);
    n00b_buffer_resize(out, content->byte_len);
    memcpy(out->data, content->data, content->byte_len);
    out->data[0] = (char)ident;
    return out;
}

// ---------------------------------------------------------------------------
// UTF8String
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_utf8_string(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    const uint8_t *content     = nullptr;
    size_t         content_len = 0;
    if (s != nullptr) {
        content     = (const uint8_t *)s->data;
        content_len = s->u8_bytes;
    }
    return emit_tlv(N00B_DER_TAG_UTF8_STRING,
                    content,
                    content_len,
                    allocator);
}

// ---------------------------------------------------------------------------
// UTCTime / GeneralizedTime
// ---------------------------------------------------------------------------

/* Write 2-digit decimal at out[0..1] (zero-padded). */
static void
write_dec2(uint8_t *out, int v)
{
    out[0] = (uint8_t)('0' + (v / 10) % 10);
    out[1] = (uint8_t)('0' + v % 10);
}

/* Write 4-digit decimal at out[0..3] (zero-padded). */
static void
write_dec4(uint8_t *out, int v)
{
    out[0] = (uint8_t)('0' + (v / 1000) % 10);
    out[1] = (uint8_t)('0' + (v / 100) % 10);
    out[2] = (uint8_t)('0' + (v / 10) % 10);
    out[3] = (uint8_t)('0' + v % 10);
}

n00b_buffer_t *
n00b_der_encode_utctime(int64_t t) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    time_t     tt = (time_t)t;
    struct tm  g  = {};
    gmtime_r(&tt, &g);

    /* "YYMMDDHHMMSSZ" — 13 octets. */
    uint8_t content[13];
    int     yy = (g.tm_year + 1900) % 100;
    write_dec2(content + 0,  yy);
    write_dec2(content + 2,  g.tm_mon + 1);
    write_dec2(content + 4,  g.tm_mday);
    write_dec2(content + 6,  g.tm_hour);
    write_dec2(content + 8,  g.tm_min);
    write_dec2(content + 10, g.tm_sec);
    content[12] = 'Z';

    return emit_tlv(N00B_DER_TAG_UTCTIME, content, 13, allocator);
}

n00b_buffer_t *
n00b_der_encode_generalizedtime(int64_t t) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    time_t     tt = (time_t)t;
    struct tm  g  = {};
    gmtime_r(&tt, &g);

    /* "YYYYMMDDHHMMSSZ" — 15 octets. */
    uint8_t content[15];
    write_dec4(content + 0,  g.tm_year + 1900);
    write_dec2(content + 4,  g.tm_mon + 1);
    write_dec2(content + 6,  g.tm_mday);
    write_dec2(content + 8,  g.tm_hour);
    write_dec2(content + 10, g.tm_min);
    write_dec2(content + 12, g.tm_sec);
    content[14] = 'Z';

    return emit_tlv(N00B_DER_TAG_GENERALIZED_TIME, content, 15, allocator);
}

// ---------------------------------------------------------------------------
// NULL
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_null() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return emit_tlv(N00B_DER_TAG_NULL, nullptr, 0, allocator);
}

// ---------------------------------------------------------------------------
// BIT STRING
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_der_encode_bit_string(n00b_buffer_t *bytes, int unused_bits) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (unused_bits < 0 || unused_bits > 7) {
        unused_bits = 0;
    }
    size_t payload_len = (bytes != nullptr) ? bytes->byte_len : 0;
    if (payload_len == 0) {
        unused_bits = 0;
    }

    size_t total = 1 + payload_len;
    uint8_t *scratch = n00b_alloc_array_with_opts(
        uint8_t, (int64_t)total,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});
    scratch[0] = (uint8_t)unused_bits;
    if (payload_len > 0) {
        memcpy(scratch + 1, bytes->data, payload_len);
    }
    return emit_tlv(N00B_DER_TAG_BIT_STRING, scratch, total, allocator);
}
