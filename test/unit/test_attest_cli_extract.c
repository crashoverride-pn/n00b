/** @file test/unit/test_attest_cli_extract.c — `n00b-attest extract`
 *  verb regression test (WP-005 Phase 2).
 *
 *  Drives the library-shaped core (`n00b_attest_cli_extract`)
 *  end-to-end via in-memory buffers. Round-trip coverage:
 *
 *    [A] Mark a fixture ELF with a known ATTESTATION tree, then
 *        extract via `_cli_extract`; assert the returned row
 *        carries the expected predicate-type, signer keyid,
 *        registry hint, and a non-empty envelopes list (bundled
 *        mode). The base64-encoded envelope bytes round-trip
 *        back to a parseable envelope.
 *
 *    [B] Lazy-mode mark → extract returns `bundled = false` +
 *        empty envelopes[] + non-empty predicate_types[].
 *
 *    [C] Extract from a never-marked artifact → `_CHALK_NO_MARK`
 *        (IC-5 case (i)).
 *
 *    [D] Null/empty artifact path → `_DSSE_BAD_INPUT`.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the tempfile
 *  setup and stdout logging is acceptable per the established
 *  test-file precedent.
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
#include "text/strings/string_ops.h"
#include "attest/n00b_attest.h"
#include "crypto/base64.h"

#include "chalk/n00b_chalk.h"
#include "objfile_elf_casegen.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                (int)n00b_result_get_err(r)); \
        assert(0); } } while (0)

static const char k_statement_json[] =
    "{\"_type\":\"https://in-toto.io/Statement/v1\","
    "\"subject\":[{\"name\":\"hello.elf\","
    "\"digest\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}],"
    "\"predicateType\":\"https://slsa.dev/provenance/v1\","
    "\"predicate\":{\"builder\":{\"id\":\"test\"},\"buildType\":\"test\"}}";

static const char k_signer_keyid[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

static const char k_predicate_type[] = "https://slsa.dev/provenance/v1";

static uint8_t k_signature[64];

static n00b_buffer_t *
build_envelope_bytes(void)
{
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    n00b_buffer_t          *pay = n00b_buffer_from_bytes(
        (char *)k_statement_json,
        (int64_t)(sizeof(k_statement_json) - 1));
    auto sp = n00b_attest_envelope_set_payload(env, pay);
    ASSERT_OK(sp);

    n00b_string_t *kid = n00b_string_from_cstr(k_signer_keyid);
    n00b_buffer_t *sig = n00b_buffer_from_bytes((char *)k_signature, 64);
    auto add = n00b_attest_envelope_add_signature(env, kid, sig);
    ASSERT_OK(add);

    auto sr = n00b_attest_envelope_serialize(env);
    ASSERT_OK(sr);
    return n00b_result_get(sr);
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
write_elf_tempfile(n00b_buffer_t *bytes, const char *prefix)
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

// ---------------------------------------------------------------------------
// [A] Bundled-mode mark → extract round-trip.
// ---------------------------------------------------------------------------

static void
test_cli_extract_bundled_round_trip(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_extract");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *env_bytes = build_envelope_bytes();
    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env_bytes);

    n00b_string_t *hint = n00b_string_from_cstr(
        "ghcr.io/example/repo@sha256:"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    auto mr = n00b_attest_cli_mark(path_str, &envs,
                                    .registry_hint = hint);
    ASSERT_OK(mr);

    auto er = n00b_attest_cli_extract(path_str);
    ASSERT_OK(er);
    n00b_attest_extract_result_t *row = n00b_result_get(er);
    assert(row != nullptr);

    // bundled = true; envelopes[] has one entry; predicate_types[]
    // has one entry; signer_keyid + registry_hint are set.
    assert(row->bundled == true);
    assert(row->envelopes != nullptr);
    assert(row->envelopes->len == 1);
    assert(row->predicate_types != nullptr);
    assert(row->predicate_types->len == 1);

    n00b_string_t *expected_pt = n00b_string_from_cstr(k_predicate_type);
    assert(n00b_unicode_str_eq(row->predicate_types->data[0], expected_pt));

    n00b_string_t *expected_kid = n00b_string_from_cstr(k_signer_keyid);
    assert(row->signer_keyid != nullptr);
    assert(n00b_unicode_str_eq(row->signer_keyid, expected_kid));

    assert(row->registry_hint != nullptr);
    assert(n00b_unicode_str_eq(row->registry_hint, hint));

    // libchalk's `HASH` field is the raw lowercase hex (64 chars) —
    // the `sha256:` prefix is the mark builder's `envelope_digest`
    // shape, not the artifact-hash shape. Check the length + that
    // every char is a lowercase hex digit.
    assert(row->unchalked_hash_hex != nullptr);
    assert(row->unchalked_hash_hex->u8_bytes == 64);
    for (size_t i = 0; i < 64; i++) {
        char c = row->unchalked_hash_hex->data[i];
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    // The envelope_digest field carries the `sha256:` prefix.
    assert(row->envelope_digest != nullptr);
    assert(row->envelope_digest->u8_bytes > 7);
    assert(memcmp(row->envelope_digest->data, "sha256:", 7) == 0);

    // The extracted envelope re-serializes and re-parses.
    n00b_attest_envelope_t *ev = row->envelopes->data[0];
    assert(ev != nullptr);
    auto ev_pay_r = n00b_attest_envelope_get_payload(ev);
    ASSERT_OK(ev_pay_r);
    n00b_buffer_t *payload = n00b_result_get(ev_pay_r);
    assert(payload != nullptr);
    assert(payload->byte_len > 0);

    // The payload is the canonical Statement bytes — confirm it
    // parses cleanly as a Statement.
    auto st_r = n00b_attest_statement_parse(payload);
    ASSERT_OK(st_r);
    n00b_attest_statement_t *st = n00b_result_get(st_r);
    n00b_option_t(n00b_string_t *) pt_opt
        = n00b_attest_statement_get_predicate_type(st);
    assert(n00b_option_is_set(pt_opt));
    n00b_string_t *pt = n00b_option_get(pt_opt);
    assert(pt != nullptr);
    assert(n00b_unicode_str_eq(pt, expected_pt));

    printf("  [PASS] cli_extract_bundled_round_trip\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [B] Lazy-mode extract.
// ---------------------------------------------------------------------------

static void
test_cli_extract_lazy_mode(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_extract_lazy");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *env_bytes = build_envelope_bytes();
    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env_bytes);

    auto mr = n00b_attest_cli_mark(path_str, &envs, .bundled = false);
    ASSERT_OK(mr);

    auto er = n00b_attest_cli_extract(path_str);
    ASSERT_OK(er);
    n00b_attest_extract_result_t *row = n00b_result_get(er);
    assert(row != nullptr);
    assert(row->bundled == false);
    assert(row->envelopes != nullptr);
    assert(row->envelopes->len == 0);
    assert(row->predicate_types != nullptr);
    assert(row->predicate_types->len == 1);

    printf("  [PASS] cli_extract_lazy_mode\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [C] No mark → CHALK_NO_MARK.
// ---------------------------------------------------------------------------

static void
test_cli_extract_no_mark(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_extract_unmarked");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    auto er = n00b_attest_cli_extract(path_str);
    assert(n00b_result_is_err(er));
    assert(n00b_result_get_err(er) == N00B_ATTEST_ERR_CHALK_NO_MARK);

    printf("  [PASS] cli_extract_no_mark\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [D] Null / empty input.
// ---------------------------------------------------------------------------

static void
test_cli_extract_null_path(void)
{
    auto r1 = n00b_attest_cli_extract(nullptr);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    n00b_string_t *empty = n00b_string_from_cstr("");
    auto r2 = n00b_attest_cli_extract(empty);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    printf("  [PASS] cli_extract_null_path\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest CLI extract verb ==\n");
    test_cli_extract_bundled_round_trip();
    test_cli_extract_lazy_mode();
    test_cli_extract_no_mark();
    test_cli_extract_null_path();
    printf("All n00b_attest CLI extract tests passed.\n");
    return 0;
}
