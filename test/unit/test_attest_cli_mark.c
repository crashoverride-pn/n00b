/** @file test/unit/test_attest_cli_mark.c — `n00b-attest mark`
 *  verb regression test (WP-005 Phase 2).
 *
 *  Drives the **library-shaped core** of the `mark` verb
 *  (`n00b_attest_cli_mark`) end-to-end via in-memory buffers per
 *  the plan's library-API-first framing (WP-002 plan §727): the
 *  test does NOT spawn the `n00b-attest` binary, does NOT redirect
 *  stdin/stdout, and does NOT shell out.
 *
 *  Coverage:
 *
 *    [A] Construct an envelope in-process, serialize to wire bytes,
 *        pass the bytes through `_cli_mark` (which parses + marks);
 *        assert the returned `n00b_attest_mark_result_t` carries
 *        the IC-4 unchalked SHA-256 byte-equal to libchalk's
 *        `hash_buffer` on the pre-mark file. Same IC-4 contract as
 *        `test_attest_mark_artifact.c`, but exercised through the
 *        Phase-2 envelope-bytes wrapper.
 *
 *    [B] `--lazy` (bundled = false) — the mark is produced
 *        successfully; subsequent `_extract_from_artifact` returns
 *        Ok with `bundled = false` and an empty envelopes list (the
 *        ATTESTATION JSON omits `envelopes[]` in lazy mode).
 *
 *    [C] Multi-envelope mark — pass TWO envelope-bytes blobs;
 *        assert `_cli_mark` succeeds and the post-mark extract
 *        returns both predicate types. Exercises the library
 *        surface's CR-13 multi-envelope contract (the slay
 *        repeatable-flag substrate is not yet available to the
 *        binary; the library still honors the multi-envelope shape).
 *
 *    [D] Null/empty input validation: null artifact_path, null list,
 *        empty list, and a list with a null entry all return
 *        `N00B_ATTEST_ERR_DSSE_BAD_INPUT`.
 *
 *    [E] Shim-level multi-envelope via parse-then-dispatch (WP-005
 *        retrofit, post-DF-023 slay multi-flag lift): four cases
 *        covering `--envelope` registered as a multi flag and
 *        accessed via `n00b_cmdr_flag_list`. `verb_mark` itself is
 *        static to the n00b-attest binary, so the test rebuilds the
 *        same flag-registration shape, parses a synthesized command
 *        string via `n00b_cmdr_parse_string`, reads back the flag
 *        list, materializes envelope-bytes from on-disk fixtures, and
 *        forwards through `n00b_attest_cli_mark`. Sub-cases:
 *
 *          [E1] repeat:        --envelope <e1> --envelope <e2>
 *          [E2] comma-split:   --envelope <e1>,<e2>
 *          [E3] mixed:         --envelope <e1>,<e2> --envelope <e3>
 *          [E4] single value:  --envelope <e1>
 *
 *        Each case asserts the parsed list length matches the
 *        expected envelope count and that `n00b_attest_cli_mark`
 *        succeeds with the materialized envelope-bytes list.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for the tempfile
 *  setup and stdout logging is acceptable per the established
 *  test-file precedent. The fixture envelope reuses the
 *  `test_attest_mark_artifact.c` keypair (RFC 8032 §7.1 vector #1).
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
#include "text/strings/format.h"
#include "attest/n00b_attest.h"
#include "slay/commander.h"

#include "chalk/n00b_chalk.h"
#include "objfile_elf_casegen.h"

#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                (int)n00b_result_get_err(r)); \
        assert(0); } } while (0)

// ---------------------------------------------------------------------------
// Fixture builders.
// ---------------------------------------------------------------------------

static const char k_statement_provenance[] =
    "{\"_type\":\"https://in-toto.io/Statement/v1\","
    "\"subject\":[{\"name\":\"hello.elf\","
    "\"digest\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}],"
    "\"predicateType\":\"https://slsa.dev/provenance/v1\","
    "\"predicate\":{\"builder\":{\"id\":\"test\"},\"buildType\":\"test\"}}";

static const char k_statement_sbom[] =
    "{\"_type\":\"https://in-toto.io/Statement/v1\","
    "\"subject\":[{\"name\":\"hello.elf\","
    "\"digest\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}],"
    "\"predicateType\":\"https://spdx.dev/Document\","
    "\"predicate\":{\"spdxVersion\":\"SPDX-2.3\"}}";

// Third predicate-type for the shim-level mixed case (test [E3]).
static const char k_statement_vuln[] =
    "{\"_type\":\"https://in-toto.io/Statement/v1\","
    "\"subject\":[{\"name\":\"hello.elf\","
    "\"digest\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}],"
    "\"predicateType\":\"https://in-toto.io/attestation/vuln/v0.1\","
    "\"predicate\":{\"scanner\":{\"uri\":\"test\"}}}";

static const char k_signer_keyid[]
    = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

static uint8_t k_signature[64];  // 64 zero bytes — algorithm-agnostic.

// Build an envelope from a Statement JSON payload, return its wire
// bytes (already canonical, ready to feed back into _cli_mark).
static n00b_buffer_t *
build_envelope_bytes(const char *stmt_json, size_t stmt_len)
{
    n00b_attest_envelope_t *env = n00b_attest_envelope_new();
    n00b_buffer_t          *pay = n00b_buffer_from_bytes((char *)stmt_json,
                                                         (int64_t)stmt_len);
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

static n00b_buffer_t *
slurp_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    assert(f != nullptr);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz);
    size_t nr = fread(buf, 1, (size_t)sz, f);
    assert(nr == (size_t)sz);
    fclose(f);
    n00b_buffer_t *out = n00b_buffer_from_bytes(buf, (int64_t)sz);
    free(buf);
    return out;
}

// ---------------------------------------------------------------------------
// [A] IC-4 unchalked-hash contract via the CLI wrapper.
// ---------------------------------------------------------------------------

static void
test_cli_mark_unchalked_hash(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_mark");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *pre_bytes = slurp_file(path);
    auto pre_r = n00b_chalk_hash_buffer(pre_bytes);
    ASSERT_OK(pre_r);
    n00b_buffer_t *pre_hash = n00b_result_get(pre_r);
    assert(pre_hash->byte_len == 32);

    n00b_buffer_t *env_bytes = build_envelope_bytes(
        k_statement_provenance, sizeof(k_statement_provenance) - 1);

    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env_bytes);

    auto mr = n00b_attest_cli_mark(path_str, &envs);
    ASSERT_OK(mr);
    n00b_attest_mark_result_t *row = n00b_result_get(mr);
    assert(row != nullptr);
    assert(row->unchalked_sha256_32 != nullptr);
    assert(row->unchalked_sha256_32->byte_len == 32);
    assert(row->kind == N00B_CHALK_OUT_IN_BAND);

    assert(memcmp(row->unchalked_sha256_32->data,
                   pre_hash->data,
                   32)
            == 0);

    printf("  [PASS] cli_mark_unchalked_hash\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [B] --lazy → bundled = false.
// ---------------------------------------------------------------------------

static void
test_cli_mark_lazy_mode(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_mark_lazy");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *env_bytes = build_envelope_bytes(
        k_statement_provenance, sizeof(k_statement_provenance) - 1);

    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env_bytes);

    auto mr = n00b_attest_cli_mark(path_str, &envs, .bundled = false);
    ASSERT_OK(mr);

    // Post-mark extract: bundled = false, envelopes list empty,
    // predicate_types still has one entry.
    auto er = n00b_attest_cli_extract(path_str);
    ASSERT_OK(er);
    n00b_attest_extract_result_t *row = n00b_result_get(er);
    assert(row != nullptr);
    assert(row->bundled == false);
    assert(row->envelopes != nullptr);
    assert(row->envelopes->len == 0);
    assert(row->predicate_types != nullptr);
    assert(row->predicate_types->len == 1);

    printf("  [PASS] cli_mark_lazy_mode\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [C] Multi-envelope (library-level — CR-13 contract).
// ---------------------------------------------------------------------------

static void
test_cli_mark_multi_envelope(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_mark_multi");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *env1 = build_envelope_bytes(
        k_statement_provenance, sizeof(k_statement_provenance) - 1);
    n00b_buffer_t *env2 = build_envelope_bytes(
        k_statement_sbom, sizeof(k_statement_sbom) - 1);

    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env1);
    n00b_list_push(envs, env2);

    auto mr = n00b_attest_cli_mark(path_str, &envs);
    ASSERT_OK(mr);

    // Extract: both predicate types should appear.
    auto er = n00b_attest_cli_extract(path_str);
    ASSERT_OK(er);
    n00b_attest_extract_result_t *row = n00b_result_get(er);
    assert(row != nullptr);
    assert(row->predicate_types != nullptr);
    assert(row->predicate_types->len == 2);

    n00b_string_t *p0 = row->predicate_types->data[0];
    n00b_string_t *p1 = row->predicate_types->data[1];
    assert(p0 != nullptr && p1 != nullptr);

    bool seen_prov = false;
    bool seen_sbom = false;
    n00b_string_t *prov = n00b_string_from_cstr("https://slsa.dev/provenance/v1");
    n00b_string_t *sbom = n00b_string_from_cstr("https://spdx.dev/Document");
    if (n00b_unicode_str_eq(p0, prov) || n00b_unicode_str_eq(p1, prov)) {
        seen_prov = true;
    }
    if (n00b_unicode_str_eq(p0, sbom) || n00b_unicode_str_eq(p1, sbom)) {
        seen_sbom = true;
    }
    assert(seen_prov);
    assert(seen_sbom);

    printf("  [PASS] cli_mark_multi_envelope\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [D] Null / empty input validation.
// ---------------------------------------------------------------------------

static void
test_cli_mark_null_inputs(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *path      = write_elf_tempfile(elf_bytes, "n00b_attest_cli_mark_null");
    n00b_string_t *path_str  = n00b_string_from_cstr(path);

    n00b_buffer_t *env_bytes = build_envelope_bytes(
        k_statement_provenance, sizeof(k_statement_provenance) - 1);
    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(envs, env_bytes);

    n00b_list_t(n00b_buffer_t *) empty_envs = n00b_list_new(n00b_buffer_t *);

    n00b_list_t(n00b_buffer_t *) null_entry = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(null_entry, (n00b_buffer_t *)nullptr);

    // (1) Null artifact path.
    auto r1 = n00b_attest_cli_mark(nullptr, &envs);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    // (2) Null envelope list.
    auto r2 = n00b_attest_cli_mark(path_str, nullptr);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    // (3) Empty envelope list.
    auto r3 = n00b_attest_cli_mark(path_str, &empty_envs);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    // (4) Null entry in envelope list.
    auto r4 = n00b_attest_cli_mark(path_str, &null_entry);
    assert(n00b_result_is_err(r4));
    assert(n00b_result_get_err(r4) == N00B_ATTEST_ERR_DSSE_BAD_INPUT);

    printf("  [PASS] cli_mark_null_inputs\n");
    unlink(path);
    free(path);
}

// ---------------------------------------------------------------------------
// [E] Shim-level multi-envelope (parse-then-dispatch).
// ---------------------------------------------------------------------------
//
// `verb_mark` in src/tools/n00b-attest.c is file-static, so the test
// cannot call it directly (audit fix V-5b). Instead, the test builds
// a commander whose `mark` subcommand registers `--envelope` as a
// multi flag (mirroring the production registration), parses a
// synthesized command string via `n00b_cmdr_parse_string`, retrieves
// the envelope-path list via `n00b_cmdr_flag_list`, materializes
// envelope-bytes from on-disk tempfiles, and forwards to
// `n00b_attest_cli_mark`. The materialization mirrors the production
// `verb_mark` body's per-path read-and-accumulate loop one-to-one.

// Write an envelope-bytes blob to a tempfile and return the malloc'd path.
// Caller owns the path string (libc free) and the on-disk file (unlink).
static char *
write_envelope_tempfile(const char *stmt_json, size_t stmt_len,
                        const char *prefix)
{
    n00b_buffer_t *bytes = build_envelope_bytes(stmt_json, stmt_len);
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX.json", prefix);
    char *path = strdup(tmpl);
    int   fd   = mkstemps(path, 5);  // ".json" suffix is 5 chars.
    assert(fd >= 0);
    ssize_t n = write(fd, bytes->data, (size_t)bytes->byte_len);
    assert(n >= 0);
    assert((size_t)n == (size_t)bytes->byte_len);
    close(fd);
    return path;
}

// Build a commander whose `mark` subcommand mirrors the production
// flag registration (the slice this test exercises is the multi
// `--envelope`; other flags are registered for fidelity).
static n00b_cmdr_t *
build_mark_commander(void)
{
    n00b_cmdr_t *c = n00b_cmdr_new();
    n00b_cmdr_set_name(c, r"n00b-attest");

    n00b_cmdr_add_command(c, r"mark",
                          r"Mark an artifact in place with a DSSE envelope ATTESTATION tree");
    n00b_cmdr_add_flag(c, r"mark", r"--artifact",
                       N00B_CMDR_TYPE_WORD, true,
                       r"Filesystem path to the artifact to mark (required)");
    n00b_cmdr_add_flag_multi(c, r"mark", r"--envelope",
                             N00B_CMDR_TYPE_WORD,
                             r"DSSE envelope JSON path (repeatable; accepts comma-separated values)");
    n00b_cmdr_add_flag(c, r"mark", r"--lazy",
                       N00B_CMDR_TYPE_BOOL, false,
                       r"Record only envelope digest+predicate-type");
    n00b_cmdr_add_flag(c, r"mark", r"--registry-hint",
                       N00B_CMDR_TYPE_WORD, true,
                       r"OCI image reference to record");
    return c;
}

// Drive the shim-side parse-then-dispatch path: given a synthesized
// command string, parse via the commander, materialize the envelope-
// bytes list from the parsed paths, and dispatch through
// `n00b_attest_cli_mark`. Returns the parsed list length on success
// (asserts inside on parse/mark failure).
static int
parse_and_dispatch(n00b_cmdr_t *c, n00b_string_t *cmdline,
                   n00b_string_t *artifact_path)
{
    n00b_cmdr_result_t *r = n00b_cmdr_parse_string(c, cmdline);
    assert(r != nullptr);
    if (!r->ok) {
        int32_t nerr = n00b_cmdr_error_count(r);
        for (int32_t i = 0; i < nerr; i++) {
            fprintf(stderr, "  parse error: %s\n",
                    n00b_cmdr_error_get(r, i)->data);
        }
        assert(r->ok);
    }

    assert(n00b_cmdr_flag_present(r, r"--envelope"));
    n00b_option_t(n00b_list_t(n00b_string_t *) *) env_paths_opt
        = n00b_cmdr_flag_list(r, r"--envelope");
    assert(n00b_option_is_set(env_paths_opt));
    n00b_list_t(n00b_string_t *) *env_paths = n00b_option_get(env_paths_opt);
    assert(env_paths != nullptr);
    int parsed_count = (int)env_paths->len;

    // Materialize envelope-bytes list (mirrors verb_mark body).
    n00b_list_t(n00b_buffer_t *) envs = n00b_list_new(n00b_buffer_t *);
    for (size_t i = 0; i < (size_t)env_paths->len; i++) {
        n00b_string_t *env_path = env_paths->data[i];
        assert(env_path != nullptr && env_path->u8_bytes > 0);
        n00b_buffer_t *bytes = slurp_file(env_path->data);
        assert(bytes != nullptr && bytes->byte_len > 0);
        n00b_list_push(envs, bytes);
    }

    auto mr = n00b_attest_cli_mark(artifact_path, &envs);
    ASSERT_OK(mr);

    n00b_cmdr_result_free(r);
    return parsed_count;
}

// [E1] Repeat at shim: --envelope <e1> --envelope <e2> → list-of-2.
static void
test_shim_multi_envelope_repeat(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *art_path  = write_elf_tempfile(elf_bytes,
                                                   "n00b_attest_shim_repeat");
    n00b_string_t *art_str   = n00b_string_from_cstr(art_path);

    char *e1 = write_envelope_tempfile(
        k_statement_provenance, sizeof(k_statement_provenance) - 1,
        "n00b_attest_env_prov");
    char *e2 = write_envelope_tempfile(
        k_statement_sbom, sizeof(k_statement_sbom) - 1,
        "n00b_attest_env_sbom");

    n00b_cmdr_t   *c       = build_mark_commander();
    n00b_string_t *cmdline = n00b_cformat(
        "mark --artifact «#» --envelope «#» --envelope «#»",
        art_str,
        n00b_string_from_cstr(e1),
        n00b_string_from_cstr(e2));

    int parsed = parse_and_dispatch(c, cmdline, art_str);
    assert(parsed == 2);

    n00b_cmdr_free(c);
    printf("  [PASS] shim_multi_envelope_repeat\n");
    unlink(e1); free(e1);
    unlink(e2); free(e2);
    unlink(art_path); free(art_path);
}

// [E2] Comma-split at shim: --envelope <e1>,<e2> → list-of-2.
static void
test_shim_multi_envelope_comma_split(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *art_path  = write_elf_tempfile(elf_bytes,
                                                   "n00b_attest_shim_csplit");
    n00b_string_t *art_str   = n00b_string_from_cstr(art_path);

    char *e1 = write_envelope_tempfile(
        k_statement_provenance, sizeof(k_statement_provenance) - 1,
        "n00b_attest_env_prov");
    char *e2 = write_envelope_tempfile(
        k_statement_sbom, sizeof(k_statement_sbom) - 1,
        "n00b_attest_env_sbom");

    n00b_cmdr_t   *c       = build_mark_commander();
    n00b_string_t *cmdline = n00b_cformat(
        "mark --artifact «#» --envelope «#»,«#»",
        art_str,
        n00b_string_from_cstr(e1),
        n00b_string_from_cstr(e2));

    int parsed = parse_and_dispatch(c, cmdline, art_str);
    assert(parsed == 2);

    n00b_cmdr_free(c);
    printf("  [PASS] shim_multi_envelope_comma_split\n");
    unlink(e1); free(e1);
    unlink(e2); free(e2);
    unlink(art_path); free(art_path);
}

// [E3] Mixed at shim: --envelope <e1>,<e2> --envelope <e3> → list-of-3.
static void
test_shim_multi_envelope_mixed(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *art_path  = write_elf_tempfile(elf_bytes,
                                                   "n00b_attest_shim_mixed");
    n00b_string_t *art_str   = n00b_string_from_cstr(art_path);

    char *e1 = write_envelope_tempfile(
        k_statement_provenance, sizeof(k_statement_provenance) - 1,
        "n00b_attest_env_prov");
    char *e2 = write_envelope_tempfile(
        k_statement_sbom, sizeof(k_statement_sbom) - 1,
        "n00b_attest_env_sbom");
    char *e3 = write_envelope_tempfile(
        k_statement_vuln, sizeof(k_statement_vuln) - 1,
        "n00b_attest_env_vuln");

    n00b_cmdr_t   *c       = build_mark_commander();
    n00b_string_t *cmdline = n00b_cformat(
        "mark --artifact «#» --envelope «#»,«#» --envelope «#»",
        art_str,
        n00b_string_from_cstr(e1),
        n00b_string_from_cstr(e2),
        n00b_string_from_cstr(e3));

    int parsed = parse_and_dispatch(c, cmdline, art_str);
    assert(parsed == 3);

    n00b_cmdr_free(c);
    printf("  [PASS] shim_multi_envelope_mixed\n");
    unlink(e1); free(e1);
    unlink(e2); free(e2);
    unlink(e3); free(e3);
    unlink(art_path); free(art_path);
}

// [E4] Single value with multi flag: --envelope <e1> → list-of-1.
static void
test_shim_multi_envelope_single(void)
{
    n00b_buffer_t *elf_bytes = build_elf_fixture();
    char          *art_path  = write_elf_tempfile(elf_bytes,
                                                   "n00b_attest_shim_single");
    n00b_string_t *art_str   = n00b_string_from_cstr(art_path);

    char *e1 = write_envelope_tempfile(
        k_statement_provenance, sizeof(k_statement_provenance) - 1,
        "n00b_attest_env_prov");

    n00b_cmdr_t   *c       = build_mark_commander();
    n00b_string_t *cmdline = n00b_cformat(
        "mark --artifact «#» --envelope «#»",
        art_str,
        n00b_string_from_cstr(e1));

    int parsed = parse_and_dispatch(c, cmdline, art_str);
    assert(parsed == 1);

    n00b_cmdr_free(c);
    printf("  [PASS] shim_multi_envelope_single\n");
    unlink(e1); free(e1);
    unlink(art_path); free(art_path);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest CLI mark verb ==\n");
    test_cli_mark_unchalked_hash();
    test_cli_mark_lazy_mode();
    test_cli_mark_multi_envelope();
    test_cli_mark_null_inputs();

    // [E] Shim-level multi-envelope via parse-then-dispatch (WP-005
    // retrofit, post-DF-023 slay multi-flag lift).
    test_shim_multi_envelope_repeat();
    test_shim_multi_envelope_comma_split();
    test_shim_multi_envelope_mixed();
    test_shim_multi_envelope_single();

    printf("All n00b_attest CLI mark tests passed.\n");
    return 0;
}
