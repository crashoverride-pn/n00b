/** @file test/unit/test_attest_mark_elf_e2e.c — WP-005 Phase 6
 *  end-to-end mark+extract regression on the ELF code path.
 *
 *  Coverage:
 *
 *    [A] ELF round-trip with `signer_identity = nullptr` — the
 *        no-resign code path. The IC-4 invariant is verified
 *        end-to-end: the SHA-256 of the artifact's bytes BEFORE
 *        mark insertion equals the extracted envelope's
 *        `subject.digest.sha256` (recorded in the Statement we
 *        signed; the verifier cross-check restated through the
 *        envelope's payload).
 *
 *  # IC-4 invariant (per dispatch correction)
 *
 *  The envelope's `subject.digest.sha256` is the SHA-256 of the
 *  artifact's bytes BEFORE mark insertion. We compute and record
 *  that hash BEFORE calling `n00b_attest_mark_artifact`; after
 *  extraction we recover the per-envelope Statement and assert
 *  the embedded digest equals the pre-mark hash. We do NOT
 *  compare against a freshly-hashed post-mark binary.
 *
 *  # Why ELF
 *
 *  ELF has no post-mark resign step (libchalk has no ELF-native
 *  signature concept on the mark surface) so this test exercises
 *  the codec-conditional dispatch's "skip resign" path against a
 *  null identity. The Mach-O and PE E2E tests cover the active
 *  resign paths.
 *
 *  # Fixture
 *
 *  Uses the same supported minimal ELF fixture shape as the public
 *  chalk ELF rewrite tests.
 *
 *  # Test-file carve-out (D-030)
 *
 *  libc I/O for tmpfile setup + stdout logging is acceptable per
 *  the established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "attest/n00b_attest.h"

#include "chalk/n00b_chalk.h"
#include "objfile_elf_casegen.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                (int)n00b_result_get_err(r)); \
        assert(0); } } while (0)

static const char k_signer_keyid[] =
    "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

static uint8_t k_signature[64];

// Hash `bytes` via the SHA-256 primitive used elsewhere in this
// test (the artifact's full bytes, NOT the libchalk unchalked
// hash — the IC-4 contract is over the FILE bytes the verifier
// receives, which for ELF means the bytes as written to disk
// pre-mark).
static void
sha256_of(const uint8_t *bytes, size_t len, uint8_t out[32])
{
    n00b_sha256_digest_t digest;
    n00b_sha256_hash(bytes, len, digest);
    for (int i = 0; i < 8; i++) {
        uint32_t w = digest[i];
        out[i * 4 + 0] = (uint8_t)((w >> 24) & 0xff);
        out[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        out[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        out[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
}

// Build a Statement whose subject digest is the supplied
// pre-mark sha256:<hex>. The verifier-side cross-check (IC-4)
// compares this digest to the libchalk unchalked-hash of the
// extracted artifact bytes.
static n00b_attest_envelope_t *
build_envelope_for_hash(const uint8_t pre_mark_hash[32])
{
    static const char hex[] = "0123456789abcdef";
    char digest_hex[65];
    for (int i = 0; i < 32; i++) {
        digest_hex[i * 2 + 0] = hex[(pre_mark_hash[i] >> 4) & 0xf];
        digest_hex[i * 2 + 1] = hex[pre_mark_hash[i] & 0xf];
    }
    digest_hex[64] = '\0';

    char stmt_json[1024];
    int n = snprintf(stmt_json, sizeof(stmt_json),
        "{\"_type\":\"https://in-toto.io/Statement/v1\","
        "\"subject\":[{\"name\":\"hello.elf\","
        "\"digest\":{\"sha256\":\"%s\"}}],"
        "\"predicateType\":\"https://slsa.dev/provenance/v1\","
        "\"predicate\":{\"builder\":{\"id\":\"test\"},\"buildType\":\"test\"}}",
        digest_hex);
    assert(n > 0 && (size_t)n < sizeof(stmt_json));

    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    n00b_buffer_t          *pay = n00b_buffer_from_bytes(stmt_json,
                                                          (int64_t)n);
    auto sp = n00b_attest_envelope_set_payload(env, pay);
    ASSERT_OK(sp);
    n00b_string_t *kid = n00b_string_from_cstr(k_signer_keyid);
    n00b_buffer_t *sig = n00b_buffer_from_bytes((char *)k_signature, 64);
    auto add = n00b_attest_envelope_add_signature(env, kid, sig);
    ASSERT_OK(add);
    return env;
}

static n00b_buffer_t *
build_elf_fixture(void)
{
    n00b_buffer_t *buf = n00b_test_elf_minimal_exec(0x400080,
                                                    0,
                                                    0x400000,
                                                    256,
                                                    512,
                                                    true,
                                                    false,
                                                    true,
                                                    false);
    buf->byte_len = 395;
    return buf;
}

static char *
write_tempfile(n00b_buffer_t *bytes, const char *prefix)
{
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX", prefix);
    char *path = strdup(tmpl);
    int   fd   = mkstemp(path);
    assert(fd >= 0);
    ssize_t n = write(fd, bytes->data, (size_t)bytes->byte_len);
    assert(n >= 0);
    assert((size_t)n == (size_t)bytes->byte_len);
    close(fd);
    return path;
}

static void
test_elf_round_trip_no_resign(void)
{
    fprintf(stderr, "[elf-e2e] round-trip no-resign (IC-4 verified)\n");

    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_tempfile(elf_bytes, "attest_elf_e2e");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    // (1) Record the SHA-256 of the artifact's bytes BEFORE mark
    // insertion. This is the IC-4 invariant value that the
    // envelope's subject.digest.sha256 must equal at extract time.
    uint8_t pre_mark_hash[32];
    sha256_of((const uint8_t *)elf_bytes->data,
              (size_t)elf_bytes->byte_len,
              pre_mark_hash);

    // (2) Build an envelope whose Statement records that hash as
    // the subject digest.
    n00b_attest_envelope_t *env = build_envelope_for_hash(pre_mark_hash);
    n00b_list_t(n00b_attest_envelope_t *) envs =
        n00b_list_new(n00b_attest_envelope_t *);
    n00b_list_push(envs, env);

    // (3) Call mark_artifact with `signer_identity = nullptr` —
    // the no-resign code path. ELF has no platform signature; the
    // kwarg is documented as ignored for ELF, but we pass nullptr
    // explicitly to confirm the dispatch handles it.
    auto mr = n00b_attest_mark_artifact(path_str,
                                         &envs,
                                         .signer_identity = nullptr);
    ASSERT_OK(mr);
    n00b_attest_mark_result_t *row = n00b_result_get(mr);
    assert(row != nullptr);
    assert(row->unchalked_sha256_32 != nullptr);
    assert(row->unchalked_sha256_32->byte_len == 32);
    assert(row->kind == N00B_CHALK_OUT_IN_BAND);

    // (4) Extract.
    auto er = n00b_attest_extract_from_artifact(path_str);
    ASSERT_OK(er);
    n00b_attest_extract_result_t *exrow = n00b_result_get(er);
    assert(exrow != nullptr);
    assert(exrow->bundled);
    assert(exrow->envelopes != nullptr);
    assert(exrow->envelopes->len == 1);

    // (5) Recover the extracted envelope's Statement bytes and
    // assert the embedded subject.digest.sha256 equals the
    // pre-mark hash we recorded BEFORE step (3). DF-028 closure:
    // the typed accessor n00b_attest_subject_get_digest_sha256
    // replaces the previous textual JSON scan over the payload.
    n00b_attest_envelope_t *out_env = exrow->envelopes->data[0];
    auto pr = n00b_attest_envelope_get_payload(out_env);
    ASSERT_OK(pr);
    n00b_buffer_t *pay = n00b_result_get(pr);
    auto sr = n00b_attest_statement_parse(pay);
    ASSERT_OK(sr);
    n00b_attest_statement_t *parsed_stmt = n00b_result_get(sr);

    n00b_option_t(n00b_string_t *) got_opt
        = n00b_attest_subject_get_digest_sha256(parsed_stmt, 0);
    assert(n00b_option_is_set(got_opt));
    n00b_string_t *got = n00b_option_get(got_opt);
    assert(got != nullptr);
    assert(got->u8_bytes == 64);

    // Convert pre_mark_hash to hex and compare.
    static const char hex[] = "0123456789abcdef";
    char expected_hex[65];
    for (int i = 0; i < 32; i++) {
        expected_hex[i * 2 + 0] = hex[(pre_mark_hash[i] >> 4) & 0xf];
        expected_hex[i * 2 + 1] = hex[pre_mark_hash[i] & 0xf];
    }
    expected_hex[64] = '\0';

    int cmp = memcmp(got->data, expected_hex, 64);
    if (cmp != 0) {
        fprintf(stderr, "  digest mismatch:\n    extracted: %.64s\n"
                        "    pre-mark : %s\n",
                got->data, expected_hex);
        assert(0);
    }

    // (6) Round-trip envelope-shape sanity: signer_keyid, one
    // predicate_type, bundled mode.
    assert(exrow->signer_keyid != nullptr);
    assert(exrow->predicate_types != nullptr);
    assert(exrow->predicate_types->len == 1);

    fprintf(stderr,
            "  [PASS] elf_round_trip_no_resign "
            "(pre-mark digest verified end-to-end)\n");

    unlink(path);
    free(path);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    fprintf(stderr, "test_attest_mark_elf_e2e:\n");
    test_elf_round_trip_no_resign();
    fprintf(stderr, "All attest mark ELF E2E tests passed.\n");
    return 0;
}
