/** @file test/unit/test_der_encode.c — DER (X.690) encoder regression.
 *
 *  WP-005 Phase 3 regression test for the new DER encoder
 *  (include/util/der_encode.h, src/util/der_encode.c). Verifies:
 *
 *    [1] INTEGER minimal-encoding: 0, 127, 128, -128, -129, 256,
 *        65536. Confirms X.690 §8.3.2 minimal-byte rule.
 *
 *    [2] OID byte-stable encoding: 1.2.840.113549.1.7.2 (the
 *        PKCS#7-SignedData OID) emits the documented byte
 *        sequence.
 *
 *    [3] SET-OF canonical ordering: pass entries in non-canonical
 *        order; output must be canonically sorted.
 *
 *    [4] SEQUENCE nesting: 3-level deep, with long-form length
 *        encoding (content > 127 bytes triggers the >= 0x81
 *        length-of-length form).
 *
 *    [5] UTF8String: short (< 128 bytes) and long (> 128 bytes)
 *        length encoding.
 *
 *    [6] NULL: byte-equal to {0x05, 0x00}.
 *
 *    [7] BIT STRING: leading unused-bits octet present;
 *        zero-payload edge case.
 *
 *    [8] Context-specific [0] explicit tag wrapper: identifier
 *        octet equals 0xA0.
 *
 *  Test-file conventions: per D-030 the auditor's relaxed
 *  carve-out applies — libc I/O for log output and <assert.h>
 *  for fail-fast asserts is intentional, not a guideline
 *  violation.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include <crypto/der_encode.h>

#include "picotls/asn1.h"

#define ASSERT_BYTES(buf, expected, expected_len) do {                    \
        assert((buf) != NULL);                                            \
        assert((buf)->byte_len == (expected_len));                        \
        assert(memcmp((buf)->data, (expected), (expected_len)) == 0);     \
    } while (0)

static void
test_integer_minimal_encoding(void)
{
    // INTEGER 0 → 02 01 00
    {
        n00b_buffer_t *b = n00b_der_encode_integer(0);
        const uint8_t exp[] = { 0x02, 0x01, 0x00 };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    // INTEGER 127 → 02 01 7F
    {
        n00b_buffer_t *b = n00b_der_encode_integer(127);
        const uint8_t exp[] = { 0x02, 0x01, 0x7F };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    // INTEGER 128 → 02 02 00 80 (leading zero to disambiguate sign)
    {
        n00b_buffer_t *b = n00b_der_encode_integer(128);
        const uint8_t exp[] = { 0x02, 0x02, 0x00, 0x80 };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    // INTEGER -128 → 02 01 80
    {
        n00b_buffer_t *b = n00b_der_encode_integer(-128);
        const uint8_t exp[] = { 0x02, 0x01, 0x80 };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    // INTEGER -129 → 02 02 FF 7F
    {
        n00b_buffer_t *b = n00b_der_encode_integer(-129);
        const uint8_t exp[] = { 0x02, 0x02, 0xFF, 0x7F };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    // INTEGER 256 → 02 02 01 00
    {
        n00b_buffer_t *b = n00b_der_encode_integer(256);
        const uint8_t exp[] = { 0x02, 0x02, 0x01, 0x00 };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    // INTEGER 65536 → 02 03 01 00 00
    {
        n00b_buffer_t *b = n00b_der_encode_integer(65536);
        const uint8_t exp[] = { 0x02, 0x03, 0x01, 0x00, 0x00 };
        ASSERT_BYTES(b, exp, sizeof(exp));
    }
    fprintf(stderr, "[der] integer minimal-encoding: OK\n");
}

static void
test_oid_pkcs7_signed_data(void)
{
    // 1.2.840.113549.1.7.2
    uint32_t arcs[] = { 1, 2, 840, 113549, 1, 7, 2 };
    n00b_buffer_t *b = n00b_der_encode_oid(arcs,
                                           sizeof(arcs) / sizeof(uint32_t));
    // Tag 0x06, length 9, content: 2A 86 48 86 F7 0D 01 07 02
    const uint8_t exp[] = {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
    };
    ASSERT_BYTES(b, exp, sizeof(exp));
    fprintf(stderr, "[der] OID 1.2.840.113549.1.7.2 byte-stable: OK\n");
}

static void
test_set_canonical_order(void)
{
    // Three INTEGERs in non-canonical order: 3, 1, 2.
    // After canonical sort by encoded TLV bytes (02 01 01 < 02 01 02 < 02 01 03):
    //   SET content == [02 01 01] [02 01 02] [02 01 03] (9 bytes)
    n00b_buffer_t *a = n00b_der_encode_integer(3);
    n00b_buffer_t *b = n00b_der_encode_integer(1);
    n00b_buffer_t *c = n00b_der_encode_integer(2);
    n00b_buffer_t *elems[3] = { a, b, c };

    n00b_buffer_t *s = n00b_der_encode_set(elems, 3);
    // 0x31 09 02 01 01 02 01 02 02 01 03
    const uint8_t exp[] = {
        0x31, 0x09,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02,
        0x02, 0x01, 0x03
    };
    ASSERT_BYTES(s, exp, sizeof(exp));
    fprintf(stderr, "[der] SET-OF canonical order: OK\n");
}

static void
test_sequence_nesting_long_form_length(void)
{
    // Build an inner OCTET STRING of length 200 (which is > 127 and
    // triggers the long-form length-of-length encoding).
    uint8_t bytes[200];
    for (int i = 0; i < 200; i++) {
        bytes[i] = (uint8_t)(i & 0xFF);
    }
    n00b_buffer_t *raw = n00b_buffer_from_bytes((char *)bytes, 200);
    n00b_buffer_t *octet = n00b_der_encode_octet_string(raw);

    // OCTET STRING 200 bytes: 0x04 0x81 0xC8 <200 bytes>
    // Total: 3 + 200 = 203 bytes.
    assert(octet->byte_len == 3 + 200);
    assert((uint8_t)octet->data[0] == 0x04);
    assert((uint8_t)octet->data[1] == 0x81);  // long-form, 1 length byte
    assert((uint8_t)octet->data[2] == 0xC8);  // 200
    assert(memcmp(octet->data + 3, bytes, 200) == 0);

    // Wrap in a 1-element SEQUENCE.
    n00b_buffer_t *elems1[1] = { octet };
    n00b_buffer_t *seq1 = n00b_der_encode_sequence(elems1, 1);
    // SEQUENCE length = octet->byte_len = 203
    // 0x30 0x81 0xCB <203 bytes>  → total 206
    assert(seq1->byte_len == 3 + 203);
    assert((uint8_t)seq1->data[0] == 0x30);
    assert((uint8_t)seq1->data[1] == 0x81);
    assert((uint8_t)seq1->data[2] == 0xCB);

    // Wrap in another SEQUENCE.
    n00b_buffer_t *elems2[1] = { seq1 };
    n00b_buffer_t *seq2 = n00b_der_encode_sequence(elems2, 1);
    // SEQUENCE length = seq1->byte_len = 206
    // 0x30 0x81 0xCE <206 bytes>  → total 209
    assert(seq2->byte_len == 3 + 206);
    assert((uint8_t)seq2->data[0] == 0x30);
    assert((uint8_t)seq2->data[1] == 0x81);
    assert((uint8_t)seq2->data[2] == 0xCE);

    // Third level.
    n00b_buffer_t *elems3[1] = { seq2 };
    n00b_buffer_t *seq3 = n00b_der_encode_sequence(elems3, 1);
    // SEQUENCE length = seq2->byte_len = 209
    // 0x30 0x81 0xD1 <209 bytes> → total 212
    assert(seq3->byte_len == 3 + 209);
    assert((uint8_t)seq3->data[0] == 0x30);
    assert((uint8_t)seq3->data[1] == 0x81);
    assert((uint8_t)seq3->data[2] == 0xD1);

    fprintf(stderr, "[der] SEQUENCE nesting + long-form length: OK\n");
}

static void
test_utf8_string_short_and_long(void)
{
    // Short: "Hello" → 0x0C 0x05 'H' 'e' 'l' 'l' 'o'
    n00b_string_t *s = n00b_string_from_cstr("Hello");
    n00b_buffer_t *b = n00b_der_encode_utf8_string(s);
    const uint8_t exp[] = { 0x0C, 0x05, 'H', 'e', 'l', 'l', 'o' };
    ASSERT_BYTES(b, exp, sizeof(exp));

    // Long: 200 'x' chars triggers long-form length.
    char buf[201];
    for (int i = 0; i < 200; i++) buf[i] = 'x';
    buf[200] = '\0';
    n00b_string_t *s2 = n00b_string_from_cstr(buf);
    n00b_buffer_t *b2 = n00b_der_encode_utf8_string(s2);
    // 0x0C 0x81 0xC8 'x' * 200 → 3 + 200 bytes
    assert(b2->byte_len == 3 + 200);
    assert((uint8_t)b2->data[0] == 0x0C);
    assert((uint8_t)b2->data[1] == 0x81);
    assert((uint8_t)b2->data[2] == 0xC8);

    fprintf(stderr, "[der] UTF8String short+long length: OK\n");
}

static void
test_null_encoding(void)
{
    n00b_buffer_t *b = n00b_der_encode_null();
    const uint8_t exp[] = { 0x05, 0x00 };
    ASSERT_BYTES(b, exp, sizeof(exp));
    fprintf(stderr, "[der] NULL: OK\n");
}

static void
test_bit_string(void)
{
    // BIT STRING with content 0xDE 0xAD and 0 unused bits:
    // 0x03 0x03 0x00 0xDE 0xAD
    uint8_t data[] = { 0xDE, 0xAD };
    n00b_buffer_t *raw = n00b_buffer_from_bytes((char *)data, 2);
    n00b_buffer_t *bs = n00b_der_encode_bit_string(raw, 0);
    const uint8_t exp[] = { 0x03, 0x03, 0x00, 0xDE, 0xAD };
    ASSERT_BYTES(bs, exp, sizeof(exp));

    // BIT STRING empty: 0x03 0x01 0x00
    n00b_buffer_t *empty = n00b_der_encode_bit_string(nullptr, 0);
    const uint8_t exp2[] = { 0x03, 0x01, 0x00 };
    ASSERT_BYTES(empty, exp2, sizeof(exp2));

    fprintf(stderr, "[der] BIT STRING: OK\n");
}

static void
test_context_tag(void)
{
    // [0] EXPLICIT around an INTEGER 1 (02 01 01):
    // 0xA0 0x03 0x02 0x01 0x01
    n00b_buffer_t *i = n00b_der_encode_integer(1);
    n00b_buffer_t *t = n00b_der_encode_tagged(0, i);
    const uint8_t exp[] = { 0xA0, 0x03, 0x02, 0x01, 0x01 };
    ASSERT_BYTES(t, exp, sizeof(exp));
    fprintf(stderr, "[der] context-specific [0] wrapper: OK\n");
}

static void
test_implicit_tag_primitive(void)
{
    /* [0] IMPLICIT OCTET STRING "hello":
     *   underlying OCTET STRING "hello"  -> 0x04 0x05 'h' 'e' 'l' 'l' 'o'
     *   IMPLICIT replaces 0x04 with 0x80 (context-specific, primitive)
     *   -> 0x80 0x05 'h' 'e' 'l' 'l' 'o'
     */
    n00b_buffer_t *raw = n00b_buffer_from_bytes((char *)"hello", 5);
    n00b_buffer_t *oct = n00b_der_encode_octet_string(raw);
    /* Confirm the underlying is primitive (high-bit nibble has the
     * 0x20 constructed-bit clear). */
    assert(((uint8_t)oct->data[0] & 0x20) == 0);

    n00b_buffer_t *t = n00b_der_encode_implicit_tagged(0, oct);
    const uint8_t exp[] = { 0x80, 0x05, 'h', 'e', 'l', 'l', 'o' };
    ASSERT_BYTES(t, exp, sizeof(exp));
    fprintf(stderr, "[der] [0] IMPLICIT (primitive) wrapper: OK\n");
}

static void
test_implicit_tag_constructed(void)
{
    /* [0] IMPLICIT SEQUENCE { INTEGER 1, INTEGER 2 }:
     *   underlying SEQUENCE                  -> 0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x02
     *   IMPLICIT replaces 0x30 with 0xA0 (context-specific, constructed)
     *   -> 0xA0 0x06 0x02 0x01 0x01 0x02 0x01 0x02
     */
    n00b_buffer_t *one = n00b_der_encode_integer(1);
    n00b_buffer_t *two = n00b_der_encode_integer(2);
    n00b_buffer_t *elems[2] = { one, two };
    n00b_buffer_t *seq = n00b_der_encode_sequence(elems, 2);
    /* Confirm the underlying is constructed (0x30 = SEQUENCE — high
     * nibble's 0x20 bit is set). */
    assert(((uint8_t)seq->data[0] & 0x20) != 0);

    n00b_buffer_t *t = n00b_der_encode_implicit_tagged(0, seq);
    const uint8_t exp[] = {
        0xA0, 0x06,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02
    };
    ASSERT_BYTES(t, exp, sizeof(exp));

    /* The IMPLICIT-tagged constructed form is itself a constructed
     * context-specific element — picotls's ASN.1 walker should
     * accept it as a top-level structure. */
    int rc = ptls_asn1_validation((const uint8_t *)t->data,
                                  t->byte_len, NULL);
    assert(rc == 0);
    fprintf(stderr, "[der] [0] IMPLICIT (constructed) wrapper: OK\n");
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    n00b_init_simple(argc, argv);

    test_integer_minimal_encoding();
    test_oid_pkcs7_signed_data();
    test_set_canonical_order();
    test_sequence_nesting_long_form_length();
    test_utf8_string_short_and_long();
    test_null_encoding();
    test_bit_string();
    test_context_tag();
    test_implicit_tag_primitive();
    test_implicit_tag_constructed();

    fprintf(stderr, "All DER encoder regression tests passed.\n");
    return 0;
}
