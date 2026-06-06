/** @file test/unit/test_attest_cli_unmark.c — `n00b-attest unmark`
 *  verb regression test (WP-005 Phase 2).
 *
 *  Drives the library-shaped core (`n00b_attest_cli_unmark`)
 *  end-to-end via in-memory buffers. Round-trip coverage:
 *
 *    [A] Mark a fixture ELF via `_cli_mark`, then unmark via
 *        `_cli_unmark`; assert the post-unmark extract returns
 *        `_CHALK_NO_MARK` (IC-5 case (i)).
 *
 *    [B] Null/empty artifact path → `_DSSE_BAD_INPUT`.
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
#include "attest/n00b_attest.h"

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
// [A] Mark → unmark → extract NO_MARK round-trip.
// ---------------------------------------------------------------------------

static void
test_cli_unmark_round_trip(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_unmark");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *env_bytes = build_envelope_bytes();
    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env_bytes);

    // Mark.
    auto mr = n00b_attest_cli_mark(path_str, &envs);
    ASSERT_OK(mr);

    // Pre-unmark: extract should succeed.
    auto pre_er = n00b_attest_cli_extract(path_str);
    ASSERT_OK(pre_er);

    // Unmark.
    auto ur = n00b_attest_cli_unmark(path_str);
    ASSERT_OK(ur);
    assert(n00b_result_get(ur) == true);

    // Post-unmark: extract returns CHALK_NO_MARK (IC-5 case (i)).
    auto er = n00b_attest_cli_extract(path_str);
    assert(n00b_result_is_err(er));
    assert(n00b_result_get_err(er) == N00B_ATTEST_ERR_CHALK_NO_MARK);

    printf("  [PASS] cli_unmark_round_trip\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [B] Null/empty artifact path.
// ---------------------------------------------------------------------------

static void
test_cli_unmark_null_path(void)
{
    auto r1 = n00b_attest_cli_unmark(nullptr);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    n00b_string_t *empty = n00b_string_from_cstr("");
    auto r2 = n00b_attest_cli_unmark(empty);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    printf("  [PASS] cli_unmark_null_path\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest CLI unmark verb ==\n");
    test_cli_unmark_round_trip();
    test_cli_unmark_null_path();
    printf("All n00b_attest CLI unmark tests passed.\n");
    return 0;
}
