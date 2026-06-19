/** @file test/unit/test_attest_base64.c — n00b_base64_* util regression.
 *
 *  WP-002 Phase 1 regression test for the lifted base64 utility
 *  (include/util/base64.h, src/util/base64.c). Verifies:
 *
 *    (a) Round-trip stability across all four base64 padding-residue
 *        cases (input lengths 0, 1, 2, 3 mod 3 — yielding "", XX==,
 *        XXX=, XXXX final groups respectively). Also covers a larger
 *        randomized buffer.
 *
 *    (b) The canonical RFC 4648 fixture vector: encode("Many hands
 *        make light work.") == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu".
 *
 *    (c) Decode-error surfacing: a malformed string ("not!base64!")
 *        returns n00b_result_err(...) with
 *        N00B_BASE64_ERR_DECODE_FAILED.
 *
 *    (d) Null-input handling: n00b_base64_decode(nullptr) returns
 *        N00B_BASE64_ERR_NULL_INPUT; n00b_base64_encode(nullptr)
 *        returns an OK empty string.
 *
 *  Test-file conventions: per D-030 the auditor's relaxed
 *  carve-out applies — libc I/O for log output and <assert.h>
 *  for fail-fast asserts is intentional, not a guideline
 *  violation. main() signature matches the rest of test/unit/.
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
#include <crypto/base64.h>

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                n00b_result_get_err(r)); \
        assert(0); } } while (0)

static void
test_rfc4648_fixture(void)
{
    static const char k_plain[] = "Many hands make light work.";
    static const char k_b64[]   = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

    n00b_buffer_t *in = n00b_buffer_from_bytes((char *)k_plain,
                                               (int64_t)(sizeof(k_plain) - 1));
    auto er = n00b_base64_encode(in);
    ASSERT_OK(er);
    n00b_string_t *enc = n00b_result_get(er);

    assert(enc->u8_bytes == sizeof(k_b64) - 1);
    assert(memcmp(enc->data, k_b64, sizeof(k_b64) - 1) == 0);

    // Round-trip back.
    auto dr = n00b_base64_decode(enc);
    ASSERT_OK(dr);
    n00b_buffer_t *dec = n00b_result_get(dr);
    assert(dec->byte_len == sizeof(k_plain) - 1);
    assert(memcmp(dec->data, k_plain, sizeof(k_plain) - 1) == 0);

    printf("  [PASS] rfc4648_fixture\n");
}

// Encode → decode → byte-equality for a payload sized to cover one of
// the four padding-residue cases.
static void
roundtrip_size(size_t len)
{
    uint8_t *raw = nullptr;
    if (len > 0) {
        raw = (uint8_t *)n00b_alloc_array(char, len);
        // Deterministic but non-trivial fill so padding bugs surface
        // as content mismatches, not zero-fill confusion.
        for (size_t i = 0; i < len; i++) {
            raw[i] = (uint8_t)((i * 131 + 17) & 0xff);
        }
    }
    n00b_buffer_t *in = n00b_buffer_from_bytes((char *)raw, (int64_t)len);

    auto er = n00b_base64_encode(in);
    ASSERT_OK(er);
    n00b_string_t *enc = n00b_result_get(er);

    // Expected encoded length: ceil(len / 3) * 4 for non-empty input;
    // 0 for empty input.
    size_t expected_enc = len == 0 ? 0 : ((len + 2) / 3) * 4;
    assert(enc->u8_bytes == expected_enc);

    auto dr = n00b_base64_decode(enc);
    ASSERT_OK(dr);
    n00b_buffer_t *dec = n00b_result_get(dr);

    assert(dec->byte_len == len);
    if (len > 0) {
        assert(memcmp(dec->data, raw, len) == 0);
    }
}

static void
test_padding_residues(void)
{
    // The four residue classes the base64 encoder distinguishes:
    //   len % 3 == 0 → no padding ("XXXX")
    //   len % 3 == 1 → two '=' padding chars ("XX==")
    //   len % 3 == 2 → one  '=' padding char  ("XXX=")
    // Cover 0 explicitly because picotls's encoder special-cases it.
    roundtrip_size(0);
    roundtrip_size(1);  // → "XX=="
    roundtrip_size(2);  // → "XXX="
    roundtrip_size(3);  // → "XXXX"

    // A handful of larger lengths around each residue class to make
    // sure the encoder's main loop is right too.
    roundtrip_size(33);
    roundtrip_size(64);
    roundtrip_size(127);
    roundtrip_size(255);

    printf("  [PASS] padding_residues\n");
}

static void
test_decode_malformed(void)
{
    // A string with characters that are not in the RFC 4648 alphabet
    // and not '='. picotls's decoder bails immediately on a
    // non-alphabet byte mid-stream.
    n00b_string_t *bad = n00b_string_from_cstr("not!base64!");
    auto           r   = n00b_base64_decode(bad);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_BASE64_ERR_DECODE_FAILED);

    // A truncated string (length not a multiple of 4 and no trailing
    // padding) — picotls's decoder consumes 4 chars at a time, so
    // input "AAA" never produces a complete group and the decoder
    // returns IN_PROGRESS with nbc != 0. Our wrapper surfaces that
    // as DECODE_FAILED too.
    n00b_string_t *trunc = n00b_string_from_cstr("AAA");
    auto           r2    = n00b_base64_decode(trunc);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_BASE64_ERR_DECODE_FAILED);

    printf("  [PASS] decode_malformed\n");
}

static void
test_null_inputs(void)
{
    // Decoding a null string yields N00B_BASE64_ERR_NULL_INPUT (the
    // wrapper's structured signal for "you gave me nothing to work
    // with"). Encoding a null buffer succeeds and yields an empty
    // string (consistent with empty-buffer-in → empty-string-out).
    auto rd = n00b_base64_decode(nullptr);
    assert(n00b_result_is_err(rd));
    assert(n00b_result_get_err(rd) == N00B_BASE64_ERR_NULL_INPUT);

    auto re = n00b_base64_encode(nullptr);
    ASSERT_OK(re);
    n00b_string_t *s = n00b_result_get(re);
    assert(s != nullptr);
    assert(s->u8_bytes == 0);

    printf("  [PASS] null_inputs\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    printf("== n00b_base64 util regression ==\n");
    test_rfc4648_fixture();
    test_padding_residues();
    test_decode_malformed();
    test_null_inputs();

    printf("All n00b_base64 util tests passed.\n");
    return 0;
}
