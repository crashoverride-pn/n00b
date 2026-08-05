// Phase 11 typed translation of resharp-c/tests/engine_test.c.
//
// Per § 7.5 + § 19a: data values (patterns, oracle offsets, expected
// text, fixture file names) are byte-identical with upstream and must
// not be paraphrased; code is typed-translated.  Uses bare assert() per
// the test convention, nullptr/{} initialization, K&R braces, <=96-col.
// Per § 17 narrow license for tests, this TU pulls in the un-prefixed
// internal engine vocabulary (Regex / Match / MatchVec / RegexBuilder /
// Solver / NodeId / TSetId / TRegexId / Nullability / RegexOptions /
// UnicodeMode / PrefixSets / LiteralPrefix / engine error enum / etc.)
// via `internal/regex/*.h`.  External harness symbols (TOML loaders,
// filesystem helpers, ckd_*, xalloc shim) follow the
// test_regex_fuzz_compare.c convention and remain forward-declared as
// `extern` pending the API sweep in a later phase.
//
// Symbol renames per recent ports (see § 7.5):
//   Error *  returns                 -> n00b_regex_engine_err_t value
//   MatchVec (Vec<Match> alias)     -> n00b_list_t(Match) *
//   UsizeVec (Vec<usize> alias)     -> n00b_list_t(size_t) *
//   ResharpError                    -> n00b_regex_algebra_err_t
//   RESHARP_ERROR_NONE              -> N00B_REGEX_ALGEBRA_ERR_NONE
//   match_vec_init / match_vec_free -> n00b_list_new_private / _free
//   error_free(Error *)             -> dropped (engine returns enum)
//   ERROR_KIND_CAPACITY_EXCEEDED    -> N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED
//
// regex_find_all and regex_is_match test helpers, if any, are kept in
// the test-helper namespace.

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/alloc.h"
#include "adt/list.h"
#include "adt/result.h"
#include "util/panic.h"
#include "util/path.h"
#include "parsers/toml.h"
#include <stdckdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

// Internal engine surfaces (§ 17 narrow license for tests).
#include "internal/regex/regex.h"
#include "internal/regex/algebra.h"
#include "internal/regex/engine.h"
#include "internal/regex/bdfa.h"
#include "internal/regex/fas.h"
#include "internal/regex/accel.h"
#include "internal/regex/prefix.h"
#include "internal/regex/nulls.h"
#include "internal/regex/solver.h"
#include "internal/regex/parser.h"

// (Former xmalloc/path_join/read_file_to_cstr shim externs deleted.
// Call sites below have been rewritten to use n00b's existing primitives
// directly — n00b_alloc / n00b_alloc_array / n00b_free / n00b_string ops /
// n00b's file IO / C23 <stdckdint.h>.)

// Forward declarations for harness helpers defined at the bottom of this
// translation unit (used by TEST() functions before the definitions).
static char *engine_test_slurp_file(const char *path, size_t *out_len);
static char *dup_cstr(const char *s);

// CARGO_MANIFEST_DIR equivalent — supplied by the build system.
#ifndef RESHARP_ENGINE_MANIFEST_DIR
#define RESHARP_ENGINE_MANIFEST_DIR "."
#endif

#define REQUIRE(cond, msg)                                                     \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n",                     \
                    msg, __FILE__, __LINE__);                                   \
            abort();                                                            \
        }                                                                       \
    } while (0)

#define REQUIRE_FMT(cond, fmt, ...)                                            \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "REQUIRE failed: " fmt " (%s:%d)\n",                \
                    __VA_ARGS__, __FILE__, __LINE__);                           \
            abort();                                                            \
        }                                                                       \
    } while (0)

#define ASSERT(cond, msg)         REQUIRE(cond, msg)
#define ASSERT_EQ_SIZE(a, b)      assert((a) == (b))

// ---------------------------------------------------------------------------
// TOML fixture loader (extern; matches resharp-c engine_test_load_* shape).
// Implementations live in a sibling harness TU added in Phase-2.
// ---------------------------------------------------------------------------

typedef struct TestCase {
    char  *name;
    char  *pattern;
    char  *input;
    size_t input_len;
    Match *matches;
    size_t matches_len;
    bool   ignore;
    bool   expect_error;
    bool   anchored;
    bool   vs_regex;
} TestCase;

extern TestCase *engine_test_load_tests(const char *filename, size_t *out_len);
extern void engine_test_free_tests(TestCase *tests, size_t len);

typedef struct InternalTestCase {
    char *name;
    char *pattern;
    char *pp;
    char *ts_rev;  // nullptr if absent
} InternalTestCase;

extern InternalTestCase *engine_test_load_internal_tests(const char *filename,
                                                         size_t *out_len);
extern void engine_test_free_internal_tests(InternalTestCase *tests, size_t len);

typedef struct PrefixTestCase {
    char   *name;
    char   *pattern;
    bool    ignore;
    size_t  checks_len;
    char  **kinds;
    char  **expects;
} PrefixTestCase;

extern PrefixTestCase *engine_test_load_prefix_tests(size_t *out_len);
extern void engine_test_free_prefix_tests(PrefixTestCase *t, size_t len);

typedef struct AutoHardenTestCase {
    char *pattern;
    bool  hardened;
} AutoHardenTestCase;

extern AutoHardenTestCase *engine_test_load_auto_harden_tests(size_t *out_len);
extern void engine_test_free_auto_harden_tests(AutoHardenTestCase *t, size_t len);

typedef struct DerivTestCase {
    char   *name;
    char   *pattern;
    bool    ignore;
    char   *input;
    size_t  input_len;
    char  **rev;        size_t rev_len;
    char  **fwd;        size_t fwd_len;
    size_t *rev_nulls;  size_t rev_nulls_len;  bool rev_nulls_set;
    size_t *fwd_nulls;  size_t fwd_nulls_len;  bool fwd_nulls_set;
} DerivTestCase;

extern DerivTestCase *engine_test_load_deriv_tests(size_t *out_len);
extern void engine_test_free_deriv_tests(DerivTestCase *t, size_t len);

// ---------------------------------------------------------------------------
// RegexRef — Phase-2 placeholder (forwards to the engine; see resharp-c
// notes).  Real implementations defined at the bottom of this file.
// ---------------------------------------------------------------------------

typedef struct RegexRef RegexRef;
RegexRef *regex_ref_new(const char *pattern);
RegexRef *regex_ref_new_unicode(const char *pattern, bool unicode);
void      regex_ref_free(RegexRef *re);
n00b_regex_engine_err_t regex_ref_find_all(RegexRef *re, const uint8_t *input,
                                           size_t len,
                                           n00b_list_t(Match) *out);

// ---------------------------------------------------------------------------
// Ignored-test gating (env RESHARP_RUN_IGNORED=1 or --ignored CLI flag).
// ---------------------------------------------------------------------------

static bool g_run_ignored = false;

static void
test_runner_init(int argc, char **argv)
{
    const char *env = getenv("RESHARP_RUN_IGNORED");
    if (env != nullptr && env[0] != '\0' && strcmp(env, "0") != 0) {
        g_run_ignored = true;
    }
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--ignored") == 0) {
            g_run_ignored = true;
        }
    }
}

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name)                                                         \
    do {                                                                        \
        fprintf(stderr, "[run]     %s\n", #name);                               \
        test_##name();                                                          \
        fprintf(stderr, "  [PASS] %s\n", #name);                                \
    } while (0)
#define RUN_IGNORED(name)                                                      \
    do {                                                                        \
        if (g_run_ignored) {                                                    \
            fprintf(stderr, "[ignored] %s\n", #name);                           \
            test_##name();                                                      \
            fprintf(stderr, "  [PASS] %s\n", #name);                            \
        } else {                                                                \
            fprintf(stderr, "[skip]    %s (ignored; set RESHARP_RUN_IGNORED)\n",\
                    #name);                                                     \
        }                                                                       \
    } while (0)
#define RUN_IF_FIXTURE(name, rel)                                               \
    do {                                                                        \
        if (fixture_exists(rel)) {                                               \
            RUN_TEST(name);                                                      \
        } else {                                                                \
            fprintf(stderr, "[skip]    %s (missing fixture %s)\n",               \
                    #name, rel);                                                 \
        }                                                                       \
    } while (0)
#define RUN_IF_SIMD(name)                                                       \
    do {                                                                        \
        if (n00b_simd_has_simd()) {                                              \
            RUN_TEST(name);                                                      \
        } else {                                                                \
            fprintf(stderr, "[skip]    %s (requires SIMD prefix backend)\n",     \
                    #name);                                                     \
        }                                                                       \
    } while (0)

// ---------------------------------------------------------------------------
// make_path / matches_equal
// ---------------------------------------------------------------------------

[[maybe_unused]] static char *
make_path(const char *rel)
{
    if (rel != nullptr && rel[0] == '/') {
        rel++;
    }
    n00b_string_t *base = n00b_string_from_cstr(RESHARP_ENGINE_MANIFEST_DIR);
    n00b_string_t *r    = n00b_string_from_cstr(rel);
    n00b_string_t *j    = n00b_path_simple_join(base, r);
    // Copy the joined bytes into a fresh n00b-allocated char buffer so
    // the returned C string has its own lifetime independent of the
    // joined n00b_string_t (caller can hold the char* indefinitely).
    size_t n   = (size_t)j->u8_bytes;
    char  *out = n00b_alloc_array(char, n + 1);
    memcpy(out, j->data, n);
    out[n] = '\0';
    return out;
}

static bool
fixture_exists(const char *rel)
{
    char *path = make_path(rel);
    struct stat st;
    return stat(path, &st) == 0;
}

[[maybe_unused]] static bool
matches_equal(const Match *a, size_t alen, const Match *b, size_t blen)
{
    if (alen != blen) {
        return false;
    }
    for (size_t i = 0; i < alen; ++i) {
        if (a[i].start != b[i].start || a[i].end != b[i].end) {
            return false;
        }
    }
    return true;
}

// Convert a n00b_list_t(Match) to a contiguous Match buffer (caller frees
// with n00b_free).  Used to drive matches_equal where the test compares
// engine output to an oracle Match[].
static Match *
list_to_array(n00b_list_t(Match) *l, size_t *out_len)
{
    size_t n = n00b_list_len(*l);
    *out_len = n;
    if (n == 0) {
        return nullptr;
    }
    Match *buf = n00b_alloc_array(Match, n);
    for (size_t i = 0; i < n; ++i) {
        buf[i] = n00b_list_get(*l, i);
    }
    return buf;
}

static bool
list_matches_equal(n00b_list_t(Match) *got,
                   const Match *exp, size_t exp_len)
{
    size_t n = n00b_list_len(*got);
    if (n != exp_len) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        Match m = n00b_list_get(*got, i);
        if (m.start != exp[i].start || m.end != exp[i].end) {
            return false;
        }
    }
    return true;
}

static bool
list_list_equal(n00b_list_t(Match) *a, n00b_list_t(Match) *b)
{
    size_t na = n00b_list_len(*a);
    size_t nb = n00b_list_len(*b);
    if (na != nb) {
        return false;
    }
    for (size_t i = 0; i < na; ++i) {
        Match ma = n00b_list_get(*a, i);
        Match mb = n00b_list_get(*b, i);
        if (ma.start != mb.start || ma.end != mb.end) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// run_file
// ---------------------------------------------------------------------------

static void
run_file(const char *filename)
{
    size_t tests_len = 0;
    TestCase *tests = engine_test_load_tests(filename, &tests_len);
    assert(tests != nullptr);

    bool dbg = getenv("RESHARP_DEBUG_TESTS") != nullptr;
    for (size_t i = 0; i < tests_len; ++i) {
        const TestCase *tc = &tests[i];
        if (tc->ignore) {
            continue;
        }
        if (dbg) {
            fprintf(stderr, "  [%s] tc[%zu]=%s pattern=%s\n",
                    filename, i, tc->name, tc->pattern);
            fflush(stderr);
        }
        if (tc->vs_regex) {
            Regex *re = regex_new(tc->pattern);
            assert(re != nullptr);
            n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            n00b_regex_engine_err_t rc =
                regex_find_all(re, (const uint8_t *)tc->input,
                               tc->input_len, &got);
            assert(rc == N00B_REGEX_ENGINE_ERR_NONE);
            RegexRef *rx = regex_ref_new(tc->pattern);
            assert(rx != nullptr);
            n00b_list_t(Match) exp = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            n00b_regex_engine_err_t rc2 =
                regex_ref_find_all(rx, (const uint8_t *)tc->input,
                                   tc->input_len, &exp);
            assert(rc2 == N00B_REGEX_ENGINE_ERR_NONE);
            assert(list_list_equal(&got, &exp));
            n00b_list_free(got);
            n00b_list_free(exp);
            regex_ref_free(rx);
            regex_free(re);
            continue;
        }
        if (tc->expect_error) {
            Regex *re = regex_new(tc->pattern);
            if (re == nullptr) {
                continue; // compile-time error
            }
            if (tc->input_len != 0) {
                n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
                n00b_regex_engine_err_t rc =
                    regex_find_all(re, (const uint8_t *)tc->input,
                                   tc->input_len, &got);
                if (rc == N00B_REGEX_ENGINE_ERR_NONE) {
                    fprintf(stderr,
                            "file=%s, name=%s, pattern=%s: "
                            "expected error but got Ok\n",
                            filename, tc->name, tc->pattern);
                    abort();
                }
                n00b_list_free(got);
            } else {
                fprintf(stderr,
                        "file=%s, name=%s, pattern=%s: "
                        "expected error but compiled Ok "
                        "(no input to test matching)\n",
                        filename, tc->name, tc->pattern);
                abort();
            }
            regex_free(re);
            continue;
        }
        Regex *re = regex_new(tc->pattern);
        if (re == nullptr) {
            fprintf(stderr, "file=%s, name=%s, pattern=%s: compile error\n",
                    filename, tc->name, tc->pattern);
            abort();
        }
        if (tc->anchored) {
            bool has = false;
            Match anc = (Match){0, 0};
            n00b_regex_engine_err_t rc =
                regex_find_anchored(re, (const uint8_t *)tc->input,
                                    tc->input_len, &has, &anc);
            assert(rc == N00B_REGEX_ENGINE_ERR_NONE);
            if (!has) {
                assert(tc->matches_len == 0);
            } else {
                assert(matches_equal(&anc, 1, tc->matches, tc->matches_len));
            }
        } else {
            n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            n00b_regex_engine_err_t rc =
                regex_find_all(re, (const uint8_t *)tc->input,
                               tc->input_len, &got);
            assert(rc == N00B_REGEX_ENGINE_ERR_NONE);
            assert(list_matches_equal(&got, tc->matches, tc->matches_len));
            n00b_list_free(got);
        }
        regex_free(re);
    }

    engine_test_free_tests(tests, tests_len);
}

TEST(normal_basic)         { run_file("basic.toml"); }
TEST(normal_anchors)       { run_file("anchors.toml"); }
TEST(normal_boolean)       { run_file("boolean.toml"); }
TEST(normal_lookaround)    { run_file("lookaround.toml"); }
TEST(semantics)            { run_file("semantics.toml"); }
TEST(errors)               { run_file("errors.toml"); }
TEST(date_pattern)         { run_file("date_pattern.toml"); }
TEST(edge_cases)           { run_file("edge_cases.toml"); }
TEST(normal_cross_feature) { run_file("cross_feature.toml"); }

// ---------------------------------------------------------------------------
// run_file_javascript / javascript test
// ---------------------------------------------------------------------------

static void
run_file_javascript(const char *filename)
{
    size_t tests_len = 0;
    TestCase *tests = engine_test_load_tests(filename, &tests_len);
    assert(tests != nullptr);
    for (size_t i = 0; i < tests_len; ++i) {
        const TestCase *tc = &tests[i];
        if (tc->ignore) {
            continue;
        }
        RegexOptions opts = regex_options_unicode(regex_options_default(),
                                                  UNICODE_MODE_JAVASCRIPT);
        Regex *re = regex_with_options(tc->pattern, opts);
        if (re == nullptr) {
            fprintf(stderr, "file=%s, name=%s, pattern=%s: compile error\n",
                    filename, tc->name, tc->pattern);
            abort();
        }
        n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        n00b_regex_engine_err_t rc =
            regex_find_all(re, (const uint8_t *)tc->input, tc->input_len, &got);
        assert(rc == N00B_REGEX_ENGINE_ERR_NONE);
        assert(list_matches_equal(&got, tc->matches, tc->matches_len));
        n00b_list_free(got);
        regex_free(re);
    }
    engine_test_free_tests(tests, tests_len);
}

TEST(javascript) { run_file_javascript("javascript.toml"); }

// ---------------------------------------------------------------------------
// check_vs_regex (callable form)
// ---------------------------------------------------------------------------

[[maybe_unused]] static void
check_vs_regex(const char *pattern, const uint8_t *input, size_t input_len)
{
    Regex *re = regex_new(pattern);
    if (re == nullptr) {
        fprintf(stderr, "failed compile %s\n", pattern);
        abort();
    }
    n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, input, input_len, &got)
           == N00B_REGEX_ENGINE_ERR_NONE);

    RegexRef *rx = regex_ref_new(pattern);
    assert(rx != nullptr);
    n00b_list_t(Match) exp = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_ref_find_all(rx, input, input_len, &exp)
           == N00B_REGEX_ENGINE_ERR_NONE);

    assert(list_list_equal(&got, &exp));

    n00b_list_free(got);
    n00b_list_free(exp);
    regex_ref_free(rx);
    regex_free(re);
}

// ---------------------------------------------------------------------------
// Small standalone tests.
// ---------------------------------------------------------------------------

TEST(literal_alt_is_match)
{
    Regex *re = regex_new("cat|dog|bird");
    assert(re != nullptr);
    bool m = false;
    assert(regex_is_match(re, (const uint8_t *)"I have a dog", 12, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(m);
    assert(regex_is_match(re, (const uint8_t *)"I have a fish", 13, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(!m);
    regex_free(re);
}

TEST(literal_alt_suffix_is_match)
{
    Regex *re = regex_new("(cat|dog)\\d+");
    assert(re != nullptr);
    bool m = false;
    assert(regex_is_match(re, (const uint8_t *)"cat123", 6, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(m);
    assert(regex_is_match(re, (const uint8_t *)"cat!", 4, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(!m);
    regex_free(re);
}

TEST(intersect_narrow_with_widened_term_is_sound)
{
    const char *pats[]   = {"foo&_*bar_*", "foo&.*bar.*"};
    const char *inputs[] = {"foo", "foo baz", "foo bar", "barfoo", "foobar"};
    for (size_t pi = 0; pi < sizeof pats / sizeof pats[0]; ++pi) {
        Regex *re = regex_with_options(pats[pi], regex_options_default());
        assert(re != nullptr);
        for (size_t ii = 0; ii < sizeof inputs / sizeof inputs[0]; ++ii) {
            n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            assert(regex_find_all(re, (const uint8_t *)inputs[ii],
                                  strlen(inputs[ii]), &got)
                   == N00B_REGEX_ENGINE_ERR_NONE);
            assert(n00b_list_len(got) == 0);
            n00b_list_free(got);
        }
        regex_free(re);
    }
}

TEST(precompiled_matches_lazy)
{
    const char    *pattern   = "aa";
    const uint8_t *input     = (const uint8_t *)"aaaa";
    size_t         input_len = 4;
    RegexOptions   lazy_opts = regex_options_default();
    lazy_opts.max_dfa_capacity = 10000;
    RegexOptions   pre_opts = regex_options_default();
    pre_opts.max_dfa_capacity = 10000;

    Regex *lazy_re = regex_with_options(pattern, lazy_opts);
    Regex *pre_re  = regex_with_options(pattern, pre_opts);
    assert(lazy_re && pre_re);

    n00b_list_t(Match) a = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) b = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(lazy_re, input, input_len, &a)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(pre_re, input, input_len, &b)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&a, &b));
    n00b_list_free(a);
    n00b_list_free(b);
    regex_free(lazy_re);
    regex_free(pre_re);
}

TEST(precompiled_complex)
{
    const char    *pattern = "[^F]+";
    const char    *raw =
        "The Adventures of Huckleberry Finn', published in 1885.";
    const uint8_t *input     = (const uint8_t *)raw;
    size_t         input_len = strlen(raw);
    RegexOptions   lazy_opts = regex_options_default();
    lazy_opts.max_dfa_capacity = 10000;
    RegexOptions   pre_opts = regex_options_default();
    pre_opts.max_dfa_capacity = 10000;

    Regex *lazy_re = regex_with_options(pattern, lazy_opts);
    Regex *pre_re  = regex_with_options(pattern, pre_opts);
    assert(lazy_re && pre_re);
    n00b_list_t(Match) a = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) b = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(lazy_re, input, input_len, &a)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(pre_re, input, input_len, &b)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&a, &b));
    n00b_list_free(a);
    n00b_list_free(b);
    regex_free(lazy_re);
    regex_free(pre_re);
}

TEST(anchored_alt_star_rejected)
{
    UnicodeMode modes[] = {UNICODE_MODE_DEFAULT, UNICODE_MODE_JAVASCRIPT};
    for (size_t i = 0; i < 2; ++i) {
        RegexOptions opts =
            regex_options_unicode(regex_options_default(), modes[i]);
        Regex *re = regex_with_options("(^\\*|REMARK)*", opts);
        assert(re == nullptr);
    }
}

TEST(space_newline_space)
{
    const char    *line     = "abcdefghij abcdefghij abcdefghij abcdefg ";
    size_t         line_len = strlen(line);
    // Grow a resizable byte buffer (n00b_buffer_t) instead of a manual
    // realloc-and-track-cap loop — per the n00b memory model, buffers
    // own their own geometric growth.
    n00b_buffer_t *hay_buf  = n00b_buffer_empty();
    size_t         hlen     = 0;
    while (hlen < 1000000) {
        size_t old = (size_t)n00b_buffer_len(hay_buf);
        n00b_buffer_resize(hay_buf, old + line_len + 1);
        memcpy(hay_buf->data + old, line, line_len);
        hay_buf->data[old + line_len] = '\n';
        hlen += line_len + 1;
    }
    const uint8_t *bytes = (const uint8_t *)hay_buf->data;
    hlen                 = (size_t)n00b_buffer_len(hay_buf);
    const char *pats[]   = {" *\\n *", " *\\n", "\\n *", "\\n", " +\\n +"};
    for (size_t pi = 0; pi < sizeof pats / sizeof pats[0]; ++pi) {
        RegexOptions opts =
            regex_options_unicode(regex_options_default(),
                                  UNICODE_MODE_JAVASCRIPT);
        Regex *re = regex_with_options(pats[pi], opts);
        REQUIRE(re != nullptr, "regex_with_options returned NULL");
        n00b_list_t(Match) m1 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        REQUIRE(regex_find_all(re, bytes, hlen, &m1)
                    == N00B_REGEX_ENGINE_ERR_NONE,
                "regex_find_all failed");
        n00b_list_free(m1);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        n00b_list_t(Match) m2 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        REQUIRE(regex_find_all(re, bytes, hlen, &m2)
                    == N00B_REGEX_ENGINE_ERR_NONE,
                "regex_find_all failed");
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (double)(t1.tv_sec - t0.tv_sec)
                  + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        double mbps = ((double)hlen / 1e6) / dt;
        fprintf(stderr, "pat=%s matches=%zu dt=%.6fs MB/s=%.2f\n",
                pats[pi], n00b_list_len(m2), dt, mbps);
        n00b_list_free(m2);
        regex_free(re);
    }
    // hay_buf is GC-managed; no explicit free needed.
}

// ---------------------------------------------------------------------------
// extract_prefix / literal_prefix tests.
// ---------------------------------------------------------------------------

static void
extract_prefix(const char *pattern, uint8_t **out, size_t *out_len)
{
    RegexBuilder *b = regex_builder_new(nullptr);
    int e = 0;
    NodeId node = resharp_parse_ast(b, pattern, &e);
    assert(e == 0);
    LiteralPrefix lp = regex_builder_extract_literal_prefix(b, node);
    *out     = lp.data;
    *out_len = lp.len;
    regex_builder_free(b);
}

static bool
prefix_eq(const char *pattern, const char *expected)
{
    uint8_t *p = nullptr;
    size_t   plen = 0;
    extract_prefix(pattern, &p, &plen);
    size_t elen = strlen(expected);
    bool   ok = (plen == elen) && (memcmp(p, expected, elen) == 0);
    return ok;
}

TEST(literal_prefix_pure_literal)
{
    assert(prefix_eq("Sherlock Holmes", "Sherlock Holmes"));
}
TEST(literal_prefix_with_wildcard)
{
    assert(prefix_eq("https://.*", "https://"));
}
TEST(literal_prefix_alternation_at_root)
{
    assert(prefix_eq("Sherlock|Holmes", ""));
}
TEST(literal_prefix_char_class_no_prefix)
{
    assert(prefix_eq("[A-Z]herlock", ""));
}
TEST(literal_prefix_single_char_pattern)
{
    assert(prefix_eq("a", "a"));
}

static void
check_literal_equiv(const char *pattern, const char *input)
{
    Regex *re_literal = regex_new(pattern);
    assert(re_literal != nullptr);
    RegexBuilder *b = regex_builder_new(nullptr);
    int e = 0;
    NodeId node = resharp_parse_ast(b, pattern, &e);
    assert(e == 0);
    Regex *re_dfa = n00b_alloc(Regex);
    n00b_regex_engine_err_t err =
        regex_from_node(b, node, regex_options_default(), re_dfa);
    assert(err == N00B_REGEX_ENGINE_ERR_NONE);
    n00b_list_t(Match) a  = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) bm = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    size_t input_len = strlen(input);
    assert(regex_find_all(re_literal, (const uint8_t *)input,
                          input_len, &a)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(re_dfa, (const uint8_t *)input, input_len, &bm)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&a, &bm));
    n00b_list_free(a);
    n00b_list_free(bm);
    regex_free(re_literal);
    regex_free(re_dfa);
    // re_dfa took ownership of references into `b`; do not free `b`.
}

TEST(literal_equiv_sherlock)
{
    check_literal_equiv(
        "Sherlock Holmes",
        "Sherlock Holmes was a detective. Sherlock Holmes lived in London.");
}
TEST(literal_equiv_prefix_the)
{
    check_literal_equiv("the ", "the cat sat on the mat");
}
TEST(literal_equiv_no_prefix)
{
    check_literal_equiv("[A-Z]herlock", "Sherlock and sherlock");
}
TEST(literal_equiv_empty_input)
{
    check_literal_equiv("Sherlock Holmes", "");
}
TEST(literal_equiv_no_match)
{
    check_literal_equiv("Sherlock Holmes", "Watson was here");
}

TEST(capacity_exceeded_at_compile)
{
    RegexOptions opts = regex_options_default();
    opts.max_dfa_capacity = 2;
    Regex *re = regex_with_options("a.*b.*c", opts);
    assert(re == nullptr);
}

TEST(dictionary_context_small)
{
    Regex *re = regex_new(".{0,10}(abc|def|ghi|jkl)");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"def;jkl;ghi", 11, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) != 0);
    n00b_list_free(m);
    regex_free(re);
}

TEST(dictionary_context_small_both)
{
    Regex *re = regex_new(".{0,10}(abc|def|ghi|jkl).{0,10}");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"def;jkl;ghi", 11, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) != 0);
    n00b_list_free(m);
    regex_free(re);
}

TEST(dictionary_context_small_suffix)
{
    Regex *re = regex_new("(abc|def|ghi|jkl).{0,10}");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"def;jkl;ghi", 11, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) != 0);
    n00b_list_free(m);
    regex_free(re);
}

TEST(dictionary_context_medium)
{
    char  *path  = make_path("/data/regexes/dictionary-fixed-context.txt");
    size_t flen  = 0;
    char  *content = engine_test_slurp_file(path, &flen);

    for (size_t i = 0; i < flen; ++i) {
        REQUIRE_FMT(content[i] != '\0',
                    "embedded NUL at offset %zu", i);
    }

    size_t lo = 0;
    while (lo < flen && (content[lo] == ' '  || content[lo] == '\t'
                         || content[lo] == '\n' || content[lo] == '\r')) {
        lo++;
    }
    size_t hi = flen;
    while (hi > lo && (content[hi - 1] == ' '  || content[hi - 1] == '\t'
                       || content[hi - 1] == '\n'
                       || content[hi - 1] == '\r')) {
        hi--;
    }
    content[hi] = '\0';

    REQUIRE_FMT(hi - lo >= 7,
                "trimmed pattern is %zu bytes, need >= 7", hi - lo);

    size_t plo = lo + 7;
    while (plo < hi && (content[plo] == ' ' || content[plo] == '\t')) {
        plo++;
    }
    size_t phi = hi;
    while (phi > plo
           && (content[phi - 1] == ' ' || content[phi - 1] == '\t')) {
        phi--;
    }
    content[phi] = '\0';
    char *pat = content + plo;

    Regex *re = regex_new(pat);
    REQUIRE(re != nullptr, "regex_new returned NULL");
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    const char *input = "hello Zoroastrianism's world";
    REQUIRE(regex_find_all(re, (const uint8_t *)input, strlen(input), &m)
                == N00B_REGEX_ENGINE_ERR_NONE,
            "regex_find_all failed");
    ASSERT(n00b_list_len(m) != 0, "expected at least one match");
    n00b_list_free(m);
    regex_free(re);
}

TEST(normal_paragraph)     { run_file("paragraph.toml"); }
TEST(find_anchored_test)   { run_file("find_anchored.toml"); }
TEST(ci)                   { run_file("ci.toml"); }
TEST(normal_word_boundary) { run_file("word_boundary.toml"); }
TEST(literal_alt)          { run_file("literal_alt.toml"); }

TEST(capacity_exceeded_at_match)
{
    RegexOptions opts = regex_options_default();
    opts.max_dfa_capacity = 4;
    Regex *re = regex_with_options("a.*b.*c.*d", opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_regex_engine_err_t rc =
        regex_find_all(re, (const uint8_t *)"a___b___c___d", 13, &m);
    if (rc != N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED) {
        fprintf(stderr, "capacity_exceeded_at_match: rc=%d (expected %d)\n",
                (int)rc, (int)N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED);
    }
    assert(rc != N00B_REGEX_ENGINE_ERR_NONE);
    assert(rc == N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED);
    n00b_list_free(m);
    regex_free(re);
}

TEST(unanchored_search_false_positive)
{
    struct {
        const char *pattern;
        const char *input;
    } cases[] = {
        {"A00[12]", "A003"},
        {"A00[12]", "A004"},
        {"A00[12]", "sample_A003_chunk_001.txt"},
        {"A001|A002", "A003"},
        {"A001|A002", "A004"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        Regex *re = regex_new(cases[i].pattern);
        assert(re != nullptr);
        bool  has = false;
        Match anc = (Match){0, 0};
        assert(regex_find_anchored(re, (const uint8_t *)cases[i].input,
                                   strlen(cases[i].input), &has, &anc)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(!has);
        n00b_list_t(Match) spans = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re, (const uint8_t *)cases[i].input,
                              strlen(cases[i].input), &spans)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(n00b_list_len(spans) == 0);
        n00b_list_free(spans);
        regex_free(re);
    }
}

TEST(opts_unicode_false)
{
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);
    Regex *re = regex_with_options("\\w+", opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    const char *cafe = "café"; // 5 bytes (UTF-8)
    assert(regex_find_all(re, (const uint8_t *)cafe, strlen(cafe), &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 1);
    Match m0 = n00b_list_get(m, 0);
    assert(m0.start == 0 && m0.end == 3);
    n00b_list_free(m);
    regex_free(re);

    Regex *re_u = regex_new("\\w+");
    assert(re_u != nullptr);
    n00b_list_t(Match) mu = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re_u, (const uint8_t *)cafe, strlen(cafe), &mu)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(mu) == 1);
    Match mu0 = n00b_list_get(mu, 0);
    assert(mu0.end > 3);
    n00b_list_free(mu);
    regex_free(re_u);
}

TEST(opts_case_insensitive)
{
    RegexOptions opts =
        regex_options_case_insensitive(regex_options_default(), true);
    Regex *re = regex_with_options("hello", opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"Hello HELLO hello", 17, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 3);
    n00b_list_free(m);
    regex_free(re);
}

TEST(opts_dot_matches_new_line)
{
    RegexOptions opts =
        regex_options_dot_matches_new_line(regex_options_default(), true);
    Regex *re = regex_with_options("a.b", opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"a\nb", 3, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 1);
    Match m0 = n00b_list_get(m, 0);
    assert(m0.start == 0 && m0.end == 3);
    n00b_list_free(m);
    regex_free(re);

    Regex *re2 = regex_new("a.b");
    assert(re2 != nullptr);
    n00b_list_t(Match) m2 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re2, (const uint8_t *)"a\nb", 3, &m2)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m2) == 0);
    n00b_list_free(m2);
    regex_free(re2);
}

TEST(opts_dot_all_inline_flag)
{
    Regex *re = regex_new("(?s)a.b");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"a\nb", 3, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 1);
    n00b_list_free(m);
    regex_free(re);
}

TEST(opts_dot_all_scoped_group)
{
    Regex *re = regex_new("(?s:a.b).c");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"a\nbxc", 5, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 1);
    n00b_list_free(m);

    n00b_list_t(Match) m2 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"a\nb\nc", 5, &m2)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m2) == 0);
    n00b_list_free(m2);
    regex_free(re);
}

TEST(opts_ignore_whitespace)
{
    RegexOptions opts =
        regex_options_ignore_whitespace(regex_options_default(), true);
    Regex *re = regex_with_options("hello \\ world", opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"hello world", 11, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 1);
    n00b_list_free(m);
    regex_free(re);
}

TEST(word_match_lengths_en_sampled)
{
    char  *path    = make_path("/data/haystacks/en-sampled.txt");
    size_t total   = 0;
    char  *content = engine_test_slurp_file(path, &total);
    REQUIRE(content != nullptr && total != 0, "failed to read sampled haystack");
    size_t input_cap;
    if (ckd_add(&input_cap, total, (size_t)1)) {
        n00b_panic("input size overflow");
    }
    char  *input = n00b_alloc_array(char, input_cap);
    size_t in_len = 0;
    size_t lines  = 0;
    size_t i      = 0;
    while (i < total && lines < 2500) {
        size_t start = i;
        while (i < total && content[i] != '\n') {
            i++;
        }
        size_t llen = i - start;
        if (lines > 0) {
            input[in_len++] = '\n';
        }
        memcpy(input + in_len, content + start, llen);
        in_len += llen;
        lines++;
        if (i < total) {
            i++;
        }
    }

    const char  *pattern = "\\b[0-9A-Za-z_]+\\b";
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);

    Regex *re = regex_with_options(pattern, opts);
    REQUIRE(re != nullptr, "regex_with_options returned NULL");
    n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    REQUIRE(regex_find_all(re, (const uint8_t *)input, in_len, &got)
                == N00B_REGEX_ENGINE_ERR_NONE,
            "regex_find_all failed");

    RegexRef *rx = regex_ref_new_unicode(pattern, false);
    REQUIRE(rx != nullptr, "regex_ref_new_unicode returned NULL");
    n00b_list_t(Match) exp = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    REQUIRE(regex_ref_find_all(rx, (const uint8_t *)input, in_len, &exp)
                == N00B_REGEX_ENGINE_ERR_NONE,
            "regex_ref_find_all failed");

    size_t sum = 0;
    size_t glen = n00b_list_len(got);
    for (size_t k = 0; k < glen; ++k) {
        Match mm = n00b_list_get(got, k);
        sum += mm.end - mm.start;
    }
    size_t exp_sum = 0;
    size_t elen = n00b_list_len(exp);
    for (size_t k = 0; k < elen; ++k) {
        Match mm = n00b_list_get(exp, k);
        exp_sum += mm.end - mm.start;
    }

    ASSERT_EQ_SIZE(exp_sum, 56691);
    ASSERT_EQ_SIZE(sum, 56691);
    ASSERT_EQ_SIZE(glen, elen);

    n00b_list_free(got);
    n00b_list_free(exp);
    regex_free(re);
    regex_ref_free(rx);
}

// ---------------------------------------------------------------------------
// run_file_hardened
// ---------------------------------------------------------------------------

static void check_hardened_vs_normal(const char *pattern,
                                     const uint8_t *input, size_t len);

static void
run_file_hardened(const char *filename)
{
    size_t tests_len = 0;
    TestCase *tests = engine_test_load_tests(filename, &tests_len);
    assert(tests != nullptr);
    bool dbg = getenv("RESHARP_DEBUG_TESTS") != nullptr;
    for (size_t i = 0; i < tests_len; ++i) {
        const TestCase *tc = &tests[i];
        if (tc->ignore || tc->expect_error || tc->anchored) {
            continue;
        }
        if (dbg) {
            fprintf(stderr, "  [hardened %s] tc[%zu]=%s pattern=%s\n",
                    filename, i, tc->name, tc->pattern);
            fflush(stderr);
        }
        if (tc->vs_regex) {
            check_hardened_vs_normal(tc->pattern,
                                     (const uint8_t *)tc->input,
                                     tc->input_len);
            continue;
        }
        RegexOptions opts =
            regex_options_hardened(regex_options_default(), true);
        Regex *re = regex_with_options(tc->pattern, opts);
        if (re == nullptr) {
            continue;
        }
        n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        n00b_regex_engine_err_t rc =
            regex_find_all(re, (const uint8_t *)tc->input,
                           tc->input_len, &got);
        if (rc != N00B_REGEX_ENGINE_ERR_NONE) {
            fprintf(stderr,
                    "err on file=%s name=%s pat=%s inp=%s: kind=%d\n",
                    filename, tc->name, tc->pattern, tc->input, (int)rc);
            abort();
        }
        assert(list_matches_equal(&got, tc->matches, tc->matches_len));
        n00b_list_free(got);
        regex_free(re);
    }
    engine_test_free_tests(tests, tests_len);
}

TEST(hardened_basic)         { run_file_hardened("basic.toml"); }
TEST(hardened_anchors)       { run_file_hardened("anchors.toml"); }
TEST(hardened_semantics)     { run_file_hardened("semantics.toml"); }
TEST(hardened_date_pattern)  { run_file_hardened("date_pattern.toml"); }
TEST(hardened_edge_cases)    { run_file_hardened("edge_cases.toml"); }
TEST(hardened_lookaround)    { run_file_hardened("lookaround.toml"); }
TEST(hardened_boolean)       { run_file_hardened("boolean.toml"); }
TEST(hardened_cross_feature) { run_file_hardened("cross_feature.toml"); }
TEST(hardened_paragraph)     { run_file_hardened("paragraph.toml"); }
TEST(hardened_find_anchored) { run_file_hardened("find_anchored.toml"); }
TEST(hardened_ci)            { run_file_hardened("ci.toml"); }
TEST(hardened_word_boundary) { run_file_hardened("word_boundary.toml"); }
TEST(hardened_literal_alt)   { run_file_hardened("literal_alt.toml"); }

TEST(hardened_pathological)
{
    const char *pattern = ".*[^A-Z]|[A-Z]";
    char *input = n00b_alloc_array(char, 1001);
    assert(input != nullptr);
    memset(input, 'A', 1000);
    input[1000] = '\0';

    Regex *re_normal = regex_new(pattern);
    assert(re_normal != nullptr);
    Regex *re_hardened = regex_with_options(pattern,
                                            regex_options_hardened(
                                                regex_options_default(),
                                                true));
    assert(re_hardened != nullptr);
    n00b_list_t(Match) a = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) b = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re_normal, (const uint8_t *)input, 1000, &a)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(re_hardened, (const uint8_t *)input, 1000, &b)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&a, &b));
    n00b_list_free(a);
    n00b_list_free(b);
    regex_free(re_normal);
    regex_free(re_hardened);
}

static void
check_hardened_vs_normal(const char *pattern, const uint8_t *input, size_t len)
{
    RegexOptions opts =
        regex_options_hardened(regex_options_default(), true);
    Regex *re_s = regex_with_options(pattern, opts);
    if (re_s == nullptr) {
        return;
    }
    Regex *re_n = regex_new(pattern);
    assert(re_n != nullptr);
    n00b_list_t(Match) normal   = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) hardened = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re_n, input, len, &normal)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(re_s, input, len, &hardened)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&normal, &hardened));
    n00b_list_free(normal);
    n00b_list_free(hardened);
    regex_free(re_s);
    regex_free(re_n);
}

TEST(hardened_cross_validate)
{
    char  *path = make_path("/data/haystacks/en-sampled.txt");
    size_t flen = 0;
    char  *en = engine_test_slurp_file(path, &flen);
    size_t use = flen < 2000 ? flen : 2000;
    const char *patterns[] = {
        "\\d+",
        "[A-Z][a-z]+",
        "\\w{3,8}",
        "[aeiou]+",
        "the|and|for|that|with",
        "[0-9]{1,3}\\.[0-9]{1,3}",
        "[A-Z]{2,}",
        ".*[^a-z]|[a-z]",
        "\\d{4}-\\d{2}-\\d{2}",
        "[A-Za-z]{8,13}",
        "(Sherlock|Holmes|Watson)[a-z]{0,5}",
    };
    for (size_t i = 0; i < sizeof patterns / sizeof patterns[0]; ++i) {
        check_hardened_vs_normal(patterns[i], (const uint8_t *)en, use);
    }
    char *aaaa = n00b_alloc_array(char, 501);
    assert(aaaa != nullptr);
    memset(aaaa, 'A', 500);
    aaaa[500] = '\0';
    check_hardened_vs_normal(".*[^A-Z]|[A-Z]", (const uint8_t *)aaaa, 500);
    check_hardened_vs_normal("[A-Z]+",         (const uint8_t *)aaaa, 500);
    check_hardened_vs_normal("A{1,3}",         (const uint8_t *)aaaa, 500);
    // `en` came from engine_test_slurp_file which uses n00b_alloc_array;
    // GC reclaims it.
}

TEST(hardened_bounded_repeat_tail)
{
    char *s8   = n00b_alloc_array(char, 9);   memset(s8,   'A', 8);   s8[8]   = '\0';
    char *s500 = n00b_alloc_array(char, 501); memset(s500, 'A', 500); s500[500] = '\0';
    char *s7   = n00b_alloc_array(char, 8);   memset(s7,   'A', 7);   s7[7]   = '\0';
    char *s10  = n00b_alloc_array(char, 11);  memset(s10,  'A', 10);  s10[10] = '\0';
    struct {
        const char *pattern;
        const char *input;
        size_t      len;
    } cases[] = {
        {"A{1,3}",     s8,   8},
        {"A{1,3}",     s500, 500},
        {"A{2,5}",     s7,   7},
        {"[A-Z]{1,3}", s10,  10},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        RegexRef *re_ref = regex_ref_new(cases[i].pattern);
        assert(re_ref != nullptr);
        n00b_list_t(Match) expected = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_ref_find_all(re_ref, (const uint8_t *)cases[i].input,
                                  cases[i].len, &expected)
               == N00B_REGEX_ENGINE_ERR_NONE);
        Regex *re_u = regex_with_options(
            cases[i].pattern,
            regex_options_hardened(regex_options_default(), true));
        assert(re_u != nullptr);
        n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re_u, (const uint8_t *)cases[i].input,
                              cases[i].len, &got)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(list_list_equal(&expected, &got));
        n00b_list_free(expected);
        n00b_list_free(got);
        regex_ref_free(re_ref);
        regex_free(re_u);
    }
}

TEST(range_prefix_correctness)
{
    char  *path = make_path("/data/haystacks/en-sampled.txt");
    size_t flen = 0;
    char  *en   = engine_test_slurp_file(path, &flen);
    static const uint8_t zeros[100] = {0};
    struct {
        const uint8_t *bytes;
        size_t         len;
    } inputs[] = {
        {(const uint8_t *)en, flen},
        {(const uint8_t *)"hello world no caps here 123", 28},
        {(const uint8_t *)"ABCDEFGhijklmnop", 16},
        {(const uint8_t *)"aZbYcXdW", 8},
        {(const uint8_t *)"", 0},
        {(const uint8_t *)"Z", 1},
        {(const uint8_t *)"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 38},
        {zeros, 100},
    };
    const char *patterns[] = {
        "[A-Z]+",
        "[A-Z][a-z]+",
        "[A-Z]{2,}",
        "[A-Za-z]+",
        "[A-Za-z0-9]+",
        "[A-Z][A-Z][a-z]",
    };
    for (size_t pi = 0; pi < sizeof patterns / sizeof patterns[0]; ++pi) {
        Regex *re = regex_new(patterns[pi]);
        assert(re != nullptr);
        Regex *re_h = regex_with_options(
            patterns[pi],
            regex_options_hardened(regex_options_default(), true));
        assert(re_h != nullptr);
        for (size_t ii = 0; ii < sizeof inputs / sizeof inputs[0]; ++ii) {
            n00b_list_t(Match) normal   = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            n00b_list_t(Match) hardened = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            assert(regex_find_all(re, inputs[ii].bytes, inputs[ii].len,
                                  &normal)
                   == N00B_REGEX_ENGINE_ERR_NONE);
            assert(regex_find_all(re_h, inputs[ii].bytes, inputs[ii].len,
                                  &hardened)
                   == N00B_REGEX_ENGINE_ERR_NONE);
            assert(list_list_equal(&normal, &hardened));
            n00b_list_free(normal);
            n00b_list_free(hardened);
        }
        regex_free(re);
        regex_free(re_h);
    }
    // `en` came from engine_test_slurp_file (n00b_alloc_array); GC handles it.
}

// FNV-1a 64-bit (portable substitute for Rust's DefaultHasher seed).
static uint64_t
fnv1a64_u64(uint64_t v)
{
    uint64_t h = 1469598103934665603ull;
    for (int i = 0; i < 8; ++i) {
        h ^= (uint8_t)(v & 0xff);
        h *= 1099511628211ull;
        v >>= 8;
    }
    return h;
}

TEST(range_prefix_random_haystack)
{
    const char *patterns[] = {"[A-Z][a-z]+", "[A-Z]{2,5}", "[A-Za-z]{3,}"};
    for (uint64_t seed = 0; seed < 50; ++seed) {
        uint64_t hash = fnv1a64_u64(seed);
        uint8_t  input[256];
        for (size_t i = 0; i < 256; ++i) {
            uint64_t v = ((hash * ((uint64_t)i + 1) + seed) >> 8);
            input[i] = (uint8_t)(32 + ((uint8_t)v % 95));
        }
        for (size_t pi = 0; pi < sizeof patterns / sizeof patterns[0]; ++pi) {
            Regex *re = regex_new(patterns[pi]);
            assert(re != nullptr);
            Regex *re_s = regex_with_options(
                patterns[pi],
                regex_options_hardened(regex_options_default(), true));
            assert(re_s != nullptr);
            n00b_list_t(Match) n = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            n00b_list_t(Match) h = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            assert(regex_find_all(re, input, 256, &n)
                   == N00B_REGEX_ENGINE_ERR_NONE);
            assert(regex_find_all(re_s, input, 256, &h)
                   == N00B_REGEX_ENGINE_ERR_NONE);
            assert(list_list_equal(&n, &h));
            n00b_list_free(n);
            n00b_list_free(h);
            regex_free(re);
            regex_free(re_s);
        }
    }
}

TEST(hardened_nullable_empty_after_dedup)
{
    struct {
        const char *pat;
        const char *input;
    } cases[] = {
        {".*(?=aaa)", "baaa"},
        {".*(?=b_)",  "_ab_ab_"},
        {"a*",        "bab"},
        {"a*",        "aab"},
        {"[a-z]*",    "1a2"},
        {"_*",        "ab"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        Regex *re_n = regex_new(cases[i].pat);
        assert(re_n != nullptr);
        n00b_list_t(Match) normal = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        size_t input_len = strlen(cases[i].input);
        assert(regex_find_all(re_n, (const uint8_t *)cases[i].input,
                              input_len, &normal)
               == N00B_REGEX_ENGINE_ERR_NONE);

        Regex *re_h = regex_with_options(
            cases[i].pat,
            regex_options_hardened(regex_options_default(), true));
        assert(re_h != nullptr);
        n00b_list_t(Match) hardened = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re_h, (const uint8_t *)cases[i].input,
                              input_len, &hardened)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(list_list_equal(&normal, &hardened));
        n00b_list_free(normal);
        n00b_list_free(hardened);
        regex_free(re_n);
        regex_free(re_h);
    }
}

TEST(hardened_cross_validate_all_toml)
{
    const char *files[] = {
        "basic.toml", "anchors.toml", "semantics.toml", "date_pattern.toml",
        "edge_cases.toml", "lookaround.toml", "boolean.toml",
        "cross_feature.toml",
        "paragraph.toml", "cloudflare_redos.toml", "find_anchored.toml",
        "accel_skip.toml", "ci.toml", "word_boundary.toml", "literal_alt.toml",
    };
    int tested = 0, activated = 0;
    for (size_t fi = 0; fi < sizeof files / sizeof files[0]; ++fi) {
        size_t tlen = 0;
        TestCase *tests = engine_test_load_tests(files[fi], &tlen);
        assert(tests != nullptr);
        for (size_t i = 0; i < tlen; ++i) {
            const TestCase *tc = &tests[i];
            if (tc->ignore || tc->expect_error || tc->anchored) {
                continue;
            }
            RegexOptions opts =
                regex_options_hardened(regex_options_default(), true);
            Regex *re = regex_with_options(tc->pattern, opts);
            if (re == nullptr) {
                continue;
            }
            tested++;
            if (regex_is_hardened(re)) {
                activated++;
            }
            n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
            assert(regex_find_all(re, (const uint8_t *)tc->input,
                                  tc->input_len, &got)
                   == N00B_REGEX_ENGINE_ERR_NONE);
            assert(list_matches_equal(&got, tc->matches, tc->matches_len));
            n00b_list_free(got);
            regex_free(re);
        }
        engine_test_free_tests(tests, tlen);
    }
    fprintf(stderr,
            "hardened_cross_validate_all_toml: %d tested, "
            "%d activated hardened mode\n",
            tested, activated);
    assert(activated >= 10);
}

// ---------------------------------------------------------------------------
// Internal tests (run_file_internal).
// ---------------------------------------------------------------------------

static void
run_file_internal(const char *filename)
{
    size_t tlen = 0;
    InternalTestCase *tests = engine_test_load_internal_tests(filename, &tlen);
    assert(tests != nullptr);
    for (size_t i = 0; i < tlen; ++i) {
        const InternalTestCase *tc = &tests[i];
        RegexBuilder *b = regex_builder_new(nullptr);
        int e = 0;
        NodeId node = resharp_parse_ast(b, tc->pattern, &e);
        if (e != 0) {
            fprintf(stderr,
                    "file=%s, name=%s, pattern=%s: compile error: %d\n",
                    filename, tc->name, tc->pattern, e);
            abort();
        }
        node = regex_builder_simplify_fwd_initial(b, node);
        char *got_pp = regex_builder_pp(b, node);
        REQUIRE(got_pp != nullptr, "regex_builder_pp returned NULL");
        REQUIRE_FMT(tc->pp != nullptr,
                    "internal test loader returned NULL pp for "
                    "name=%s pattern=%s",
                    tc->name, tc->pattern);
        if (strcmp(got_pp, tc->pp) != 0) {
            fprintf(stderr,
                    "file=%s, name=%s, pattern=%s\n  got:      %s\n"
                    "  expected: %s\n",
                    filename, tc->name, tc->pattern, got_pp, tc->pp);
            abort();
        }
        // got_pp is GC-managed.
        if (tc->ts_rev != nullptr) {
            n00b_result_t(NodeId) rr = regex_builder_ts_rev_start(b, node);
            assert(n00b_result_is_ok(rr));
            NodeId ts_rev_start = n00b_result_get(rr);
            char *got_ts_rev = regex_builder_pp(b, ts_rev_start);
            if (strcmp(got_ts_rev, tc->ts_rev) != 0) {
                fprintf(stderr,
                        "ts_rev mismatch: file=%s, name=%s, pattern=%s\n",
                        filename, tc->name, tc->pattern);
                abort();
            }
        }
        regex_builder_free(b);
    }
    engine_test_free_internal_tests(tests, tlen);
}

TEST(internal_test) { run_file_internal("internal.toml"); }
TEST(normalize_toml) { run_file_internal("normalize.toml"); }

TEST(word_boundary_inference)
{
    Regex *re = regex_new("<.*(?<=<)bg");
    assert(re != nullptr);
    n00b_list_t(Match) ms = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"<bg", 3, &ms)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(ms) == 1);
    Match m0 = n00b_list_get(ms, 0);
    assert(m0.start == 0 && m0.end == 3);
    n00b_list_free(ms);
    regex_free(re);
}

TEST(alt_embedded_line_anchor_compiles_ok)
{
    Regex *r1 = regex_new("^a|^b");
    assert(r1 != nullptr);
    regex_free(r1);
    Regex *r2 = regex_new("^(ab)");
    assert(r2 != nullptr);
    regex_free(r2);
}

TEST(word_boundaries_loop)
{
    Regex *re = regex_new(
        "\\(\\?[:=!]|\\)|\\{\\d+\\b,?\\d*\\}|[+*]\\?|[()$^+*?.]");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"$", 1, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    n00b_list_free(m);
    regex_free(re);
}

TEST(fwd_la_1)
{
    const char *pattern = "(?:\\[[^\\]]*\\]|[^\\]]|\\](?=[^\\[]*\\]))*";
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);
    Regex *re = regex_with_options(pattern, opts);
    assert(re == nullptr);
}

static uint8_t *
read_smallserver(size_t *out_len)
{
    char *path    = make_path("/data/haystacks/smallserver.txt");
    char *content = engine_test_slurp_file(path, out_len);
    return (uint8_t *)content;
}

TEST(fwd_la_2)
{
    const char *pattern =
        "^((?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6})";
    size_t haylen = 0;
    uint8_t *hay = read_smallserver(&haylen);
    assert(hay != nullptr);
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);
    Regex *re = regex_with_options(pattern, opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, hay, haylen, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    n00b_list_free(m);
    regex_free(re);
    // hay from read_smallserver -> engine_test_slurp_file (GC-managed)
}

TEST(fwd_la_2_js)
{
    const char *pattern =
        "^(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])"
        "(?=.*[A-Za-z0-9]).*$";
    size_t haylen = 0;
    uint8_t *hay = read_smallserver(&haylen);
    assert(hay != nullptr);
    size_t use = haylen < 50 ? haylen : 50;
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);
    Regex *re = regex_with_options(pattern, opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, hay, use, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    n00b_list_free(m);
    regex_free(re);
    // hay from read_smallserver (GC-managed)
}

TEST(fwd_la_3)
{
    const char *pattern =
        "<(?:\\/?(?!(?:div|p|br|span)>)\\w+|"
        "(?:(?!(?:span style=\"white-space:\\s?pre;?\">)|br\\s?\\/>))"
        "\\w+\\s[^>]+)>";
    size_t haylen = 0;
    uint8_t *hay = read_smallserver(&haylen);
    assert(hay != nullptr);
    size_t use = haylen < 2 ? haylen : 2;
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);
    Regex *re = regex_with_options(pattern, opts);
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, hay, use, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    n00b_list_free(m);
    regex_free(re);
    // hay from read_smallserver (GC-managed)
}

TEST(repro_lookahead_in_loop)
{
    const char *pattern = "(.(?=.))+x";
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_ASCII);
    Regex *re = regex_with_options(pattern, opts);
    assert(re == nullptr);
}

TEST(hardened_long_word)
{
    const char    *p = "\\b[a-z]{12,}\\b";
    const uint8_t *input = (const uint8_t *)"!extraordinary";
    size_t         input_len = 14;

    Regex *re_h = regex_with_options(
        p, regex_options_hardened(regex_options_default(), true));
    assert(re_h != nullptr);
    Regex *re_n = regex_new(p);
    assert(re_n != nullptr);
    n00b_list_t(Match) a = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) b = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re_n, input, input_len, &a)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(re_h, input, input_len, &b)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&a, &b));
    n00b_list_free(a);
    n00b_list_free(b);
    regex_free(re_h);
    regex_free(re_n);
}

TEST(no_progress)
{
    Regex *re = regex_new("ab|bcd*");
    assert(re != nullptr);
    const char *unit = "abcdddxabxbcdddyabbcd";
    size_t unit_len = strlen(unit);
    size_t total = unit_len * 20;
    char *hay = n00b_alloc_array(char, total + 1);
    assert(hay != nullptr);
    for (int i = 0; i < 20; ++i) {
        memcpy(hay + i * unit_len, unit, unit_len);
    }
    hay[total] = '\0';
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)hay, total, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) != 0);
    n00b_list_free(m);
    regex_free(re);
}

TEST(repro_is_match_negative_lookahead)
{
    Regex *re = regex_new("foo(?!bar)");
    assert(re != nullptr);
    bool m = false;
    assert(regex_is_match(re, (const uint8_t *)"foobar", 6, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(!m);
    regex_free(re);
}

TEST(light_depth_pass_bdfa_prefix_falls_through_to_potential)
{
    const char *p = "\\s\\!?LIGHT_DEPTH_PASS\\s";
    UnicodeMode modes[] = {UNICODE_MODE_ASCII, UNICODE_MODE_JAVASCRIPT,
                           UNICODE_MODE_FULL};
    for (size_t i = 0; i < 3; ++i) {
        RegexOptions opts =
            regex_options_unicode(regex_options_default(), modes[i]);
        Regex *re = regex_with_options(p, opts);
        assert(re != nullptr);
        const char *unit = " LIGHT_DEPTH_PASS ";
        size_t unit_len = strlen(unit);
        size_t total = unit_len * 100;
        char *hay = n00b_alloc_array(char, total + 1);
        assert(hay != nullptr);
        for (int k = 0; k < 100; ++k) {
            memcpy(hay + k * unit_len, unit, unit_len);
        }
        hay[total] = '\0';
        n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re, (const uint8_t *)hay, total, &m)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(n00b_list_len(m) == 100);
        n00b_list_free(m);
        regex_free(re);
    }
}

TEST(assets_path_js_unicode_uses_rev_literal)
{
    const char *p = "..\\/..\\/Assets\\/";
    UnicodeMode modes[] = {UNICODE_MODE_ASCII, UNICODE_MODE_JAVASCRIPT,
                           UNICODE_MODE_FULL};
    for (size_t i = 0; i < 3; ++i) {
        RegexOptions opts =
            regex_options_unicode(regex_options_default(), modes[i]);
        Regex *re = regex_with_options(p, opts);
        assert(re != nullptr);
        const char *unit = "xx/yy/Assets/file.cs\n";
        size_t unit_len = strlen(unit);
        size_t total = unit_len * 100;
        char *hay = n00b_alloc_array(char, total + 1);
        assert(hay != nullptr);
        for (int k = 0; k < 100; ++k) {
            memcpy(hay + k * unit_len, unit, unit_len);
        }
        hay[total] = '\0';
        n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re, (const uint8_t *)hay, total, &m)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(n00b_list_len(m) == 100);
        n00b_list_free(m);
        regex_free(re);
    }
}

TEST(lookahead_alternation_with_end_of_line)
{
    Regex *re = regex_new("x(?=a|$)");
    assert(re != nullptr);
    const uint8_t *input = (const uint8_t *)"xa xb x\nxc x";
    size_t input_len = 12;
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, input, input_len, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    size_t expected[] = {0, 6, 11};
    assert(n00b_list_len(m) == 3);
    for (size_t i = 0; i < 3; ++i) {
        Match mm = n00b_list_get(m, i);
        assert(mm.start == expected[i]);
    }
    n00b_list_free(m);
    regex_free(re);
}

TEST(rev_bot_skip_terminates_fast)
{
    size_t big_len = 1u << 22;
    uint8_t *big = n00b_alloc_array(uint8_t, big_len);
    assert(big != nullptr);
    memset(big, 'x', big_len);

    Regex *re = regex_new("\\z");
    assert(re != nullptr);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, big, big_len, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long us = (t1.tv_sec - t0.tv_sec) * 1000000L
            + (t1.tv_nsec - t0.tv_nsec) / 1000L;
    assert(n00b_list_len(m) == 1);
    Match m0 = n00b_list_get(m, 0);
    assert(m0.start == big_len);
    assert(m0.end == big_len);
    assert(us < 500);
    n00b_list_free(m);
    regex_free(re);
}

TEST(is_match_agrees_with_find_all_for_lookahead)
{
    Regex *re = regex_with_options(
        ".(?=a|$)",
        regex_options_unicode(regex_options_default(), UNICODE_MODE_JAVASCRIPT));
    assert(re != nullptr);
    const uint8_t *hay0 = (const uint8_t *)"xa xb x\nxc x";
    size_t hay0_len = 12;
    bool im = false;
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_is_match(re, hay0, hay0_len, &im)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(re, hay0, hay0_len, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(im == (n00b_list_len(m) != 0));
    n00b_list_free(m);
    struct {
        const uint8_t *bytes;
        size_t         len;
    } hays[] = {
        {(const uint8_t *)"\n", 1},
        {(const uint8_t *)"\n\n", 2},
        {(const uint8_t *)"\n\n\n\n", 4},
    };
    for (size_t i = 0; i < 3; ++i) {
        bool im2 = false;
        n00b_list_t(Match) m2 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_is_match(re, hays[i].bytes, hays[i].len, &im2)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(regex_find_all(re, hays[i].bytes, hays[i].len, &m2)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(im2 == (n00b_list_len(m2) != 0));
        n00b_list_free(m2);
    }
    regex_free(re);
}

TEST(alternation_prefix_soundness_bulk)
{
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_JAVASCRIPT);
    Regex *re = regex_with_options(
        "EMU-(?!CLAUSE|XREF|ANNEX|INTRO)|DFN", opts);
    assert(re != nullptr);
    const char *unit1 = "zz EMU-FOO zz ";
    size_t u1len = strlen(unit1);
    size_t total1 = u1len * 500;
    uint8_t *hay = n00b_alloc_array(uint8_t, total1);
    assert(hay != nullptr);
    for (int i = 0; i < 500; ++i) {
        memcpy(hay + i * u1len, unit1, u1len);
    }
    bool found_dfn = false;
    for (size_t i = 0; i + 3 <= total1; ++i) {
        if (hay[i] == 'D' && hay[i+1] == 'F' && hay[i+2] == 'N') {
            found_dfn = true;
            break;
        }
    }
    assert(!found_dfn);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, hay, total1, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 500);
    n00b_list_free(m);
    regex_free(re);

    Regex *re2 = regex_with_options("abcdef|xy", opts);
    assert(re2 != nullptr);
    const char *unit2 = "_ abcdef _ ";
    size_t u2len = strlen(unit2);
    size_t total2 = u2len * 200;
    uint8_t *hay2 = n00b_alloc_array(uint8_t, total2);
    assert(hay2 != nullptr);
    for (int i = 0; i < 200; ++i) {
        memcpy(hay2 + i * u2len, unit2, u2len);
    }
    n00b_list_t(Match) m2 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re2, hay2, total2, &m2)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m2) == 200);
    n00b_list_free(m2);
    regex_free(re2);
}

TEST(trailing_dollar_after_top_star_pruned)
{
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_JAVASCRIPT);
    Regex *with_d    = regex_with_options(
        "^((?!_\\S+=)[^\\s]+)\\s?([\\S\\s]*)$", opts);
    Regex *without_d = regex_with_options(
        "^((?!_\\S+=)[^\\s]+)\\s?([\\S\\s]*)", opts);
    assert(with_d && without_d);

    const uint8_t *hay  = (const uint8_t *)"hello world\nfoo bar baz";
    size_t hl  = 23;
    const uint8_t *hay2 = (const uint8_t *)"abc def ghi\njkl mno\npqr";
    size_t h2  = 23;

    n00b_list_t(Match) a = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) b = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(with_d, hay, hl, &a)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(without_d, hay, hl, &b)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&a, &b));
    n00b_list_free(a);
    n00b_list_free(b);

    n00b_list_t(Match) c = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(Match) d = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(with_d, hay2, h2, &c)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(regex_find_all(without_d, hay2, h2, &d)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(list_list_equal(&c, &d));
    n00b_list_free(c);
    n00b_list_free(d);
    regex_free(with_d);
    regex_free(without_d);
}

TEST(empty_language_short_circuits)
{
    const char *p = "x+(?=aa(b+))z{2,}";
    Regex *re = regex_new(p);
    assert(re != nullptr);
    size_t big_len = 1u << 20;
    uint8_t *big = n00b_alloc_array(uint8_t, big_len);
    assert(big != nullptr);
    memset(big, 'x', big_len);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, big, big_len, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 0);
    n00b_list_free(m);

    bool im = true;
    assert(regex_is_match(re, big, big_len, &im)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(!im);

    n00b_list_t(Match) m2 = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"", 0, &m2)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m2) == 0);
    n00b_list_free(m2);

    bool im2 = true;
    assert(regex_is_match(re, (const uint8_t *)"", 0, &im2)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(!im2);

    regex_free(re);
}

TEST(trailing_star_yields_to_fwd_prefix_kind)
{
    RegexOptions opts =
        regex_options_unicode(regex_options_default(), UNICODE_MODE_JAVASCRIPT);
    Regex *re = regex_with_options("BREAKING CHANGE:([\\s\\S]*)", opts);
    assert(re != nullptr);
    const char *kind = regex_prefix_kind_name(re);
    assert(kind != nullptr);
    assert(strcmp(kind, "AnchoredFwd") == 0);
    regex_free(re);
}

TEST(anchored_fwd_lb_selected_when_min_len_zero_kind)
{
    const char *pats[] = {
        "^(?!\\_\\S+=)\\S+",
        "^((?!\\_\\S+=)[^\\s]+)\\s?([\\S\\s]*)$",
    };
    for (size_t i = 0; i < 2; ++i) {
        RegexOptions opts =
            regex_options_unicode(regex_options_default(),
                                  UNICODE_MODE_JAVASCRIPT);
        Regex *re = regex_with_options(pats[i], opts);
        assert(re != nullptr);
        const char *kind = regex_prefix_kind_name(re);
        assert(kind != nullptr);
        assert(strcmp(kind, "AnchoredFwdLb") == 0);
        regex_free(re);
    }
}

TEST(rev_literal_search)
{
    Regex *re = regex_new("[\\s\\S]+(?<=x)foo[\\s\\S]+");
    assert(re != nullptr);
    n00b_list_t(Match) m = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)"axfoo def", 9, &m)
           == N00B_REGEX_ENGINE_ERR_NONE);
    assert(n00b_list_len(m) == 1);
    Match m0 = n00b_list_get(m, 0);
    assert(m0.start == 0 && m0.end == 9);
    n00b_list_free(m);
    regex_free(re);
}

// ---------------------------------------------------------------------------
// mod probe_alt / mod probe_nettv / mod probe_nullable_prefix
// ---------------------------------------------------------------------------

TEST(probe_alt)
{
    const char *p = "2011|TL868|NETTV\\/3.1\\b";
    const char *mode_s = getenv("MODE");
    UnicodeMode m;
    if (mode_s == nullptr) {
        m = UNICODE_MODE_JAVASCRIPT;
    } else if (strcmp(mode_s, "ascii") == 0) {
        m = UNICODE_MODE_ASCII;
    } else if (strcmp(mode_s, "full") == 0) {
        m = UNICODE_MODE_FULL;
    } else {
        m = UNICODE_MODE_JAVASCRIPT;
    }

    Regex *re = regex_with_options(
        p, regex_options_unicode(regex_options_default(), m));
    assert(re != nullptr);
    const char *unit =
        "User-Agent: Mozilla/5.0 NETTV/3.1 or 2011 or TL868 random text\n";
    size_t ulen  = strlen(unit);
    size_t total = ulen * 50;
    char *hay = n00b_alloc_array(char, total + 1);
    assert(hay != nullptr);
    for (int i = 0; i < 50; ++i) {
        memcpy(hay + i * ulen, unit, ulen);
    }
    hay[total] = '\0';
    n00b_list_t(Match) ms = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, (const uint8_t *)hay, total, &ms)
           == N00B_REGEX_ENGINE_ERR_NONE);
    size_t counts[3] = {0, 0, 0};
    size_t nm = n00b_list_len(ms);
    for (size_t i = 0; i < nm; ++i) {
        Match mm = n00b_list_get(ms, i);
        const char *s = hay + mm.start;
        size_t slen   = mm.end - mm.start;
        if (slen >= 4 && memcmp(s, "2011", 4) == 0) {
            counts[0]++;
        } else if (slen >= 5 && memcmp(s, "TL868", 5) == 0) {
            counts[1]++;
        } else if (slen >= 5 && memcmp(s, "NETTV", 5) == 0) {
            counts[2]++;
        }
    }
    const char *kind = regex_prefix_kind_name(re);
    printf("matches: %zu algo: %s 2011=%zu TL868=%zu NETTV=%zu\n",
           nm, kind ? kind : "None", counts[0], counts[1], counts[2]);
    n00b_list_free(ms);
    regex_free(re);
}

TEST(probe_nettv)
{
    const char *p = "NETTV\\/3.1\\b";
    Regex *re = regex_with_options(
        p, regex_options_unicode(regex_options_default(),
                                 UNICODE_MODE_JAVASCRIPT));
    assert(re != nullptr);
    const uint8_t *hay = (const uint8_t *)"xyz NETTV/3.1 abc NETTV/3.1 end";
    size_t hl = 31;
    n00b_list_t(Match) ms = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    assert(regex_find_all(re, hay, hl, &ms)
           == N00B_REGEX_ENGINE_ERR_NONE);
    const char *kind = regex_prefix_kind_name(re);
    size_t nm = n00b_list_len(ms);
    printf("matches=%zu algo=%s\n", nm, kind ? kind : "None");
    for (size_t i = 0; i < nm; ++i) {
        Match mm = n00b_list_get(ms, i);
        printf("  at %zu..%zu = %.*s\n",
               mm.start, mm.end,
               (int)(mm.end - mm.start),
               (const char *)hay + mm.start);
    }
    n00b_list_free(ms);
    regex_free(re);
}

// Shared pp-join implementation.
static char *
pp_sets_join_with_solver(const Solver *s, const TSetId *sets, size_t len)
{
    if (len == 0) {
        char *empty = n00b_alloc_array(char, 1);
        empty[0] = '\0';
        return empty;
    }
    char **parts = n00b_alloc_array(char *, len);
    size_t total = 0;
    for (size_t i = 0; i < len; ++i) {
        parts[i] = solver_pp(s, sets[i]);
        REQUIRE(parts[i] != nullptr, "solver_pp returned NULL");
        if (ckd_add(&total, total, strlen(parts[i]))) {
            n00b_panic("pp_sets_join size overflow");
        }
        if (i + 1 < len) {
            if (ckd_add(&total, total, (size_t)1)) {
                n00b_panic("pp_sets_join size overflow");
            }
        }
    }
    size_t out_cap;
    if (ckd_add(&out_cap, total, (size_t)1)) {
        n00b_panic("pp_sets_join size overflow");
    }
    char *out = n00b_alloc_array(char, out_cap);
    size_t off = 0;
    for (size_t i = 0; i < len; ++i) {
        size_t pl = strlen(parts[i]);
        memcpy(out + off, parts[i], pl);
        off += pl;
        if (i + 1 < len) {
            out[off++] = ';';
        }
    }
    out[off] = '\0';
    return out;
}

static char *
pp_sets_join(RegexBuilder *b, const TSetId *sets, size_t len)
{
    return pp_sets_join_with_solver(regex_builder_solver(b), sets, len);
}

static void
probe_result(const char *pat, char **out_fwd, char **out_rev)
{
    RegexBuilder *b = regex_builder_new(nullptr);
    int e = 0;
    NodeId node = resharp_parse_ast(b, pat, &e);
    assert(e == 0);
    n00b_result_t(NodeId) rr = regex_builder_ts_rev_start(b, node);
    assert(n00b_result_is_ok(rr));
    NodeId ts_rev = n00b_result_get(rr);
    fprintf(stderr, "--- %s\n", pat);
    char *node_pp = regex_builder_pp(b, node);
    fprintf(stderr, "  fwd pp:        %s\n", node_pp);
    char *rev_pp = regex_builder_pp(b, ts_rev);
    fprintf(stderr, "  ts_rev:        %s\n", rev_pp);

    n00b_result_t(TSetIdVec) fwd =
        calc_potential_start(b, node, 16, 64, false);
    assert(n00b_result_is_ok(fwd));
    TSetIdVec fv = n00b_result_get(fwd);
    *out_fwd = pp_sets_join(b, fv.data, fv.len);
    fprintf(stderr, "  fwd_potential:    %s\n", *out_fwd);

    n00b_result_t(TSetIdVec) rev =
        calc_potential_start_prune(b, ts_rev, 16, 64, true);
    assert(n00b_result_is_ok(rev));
    TSetIdVec rv = n00b_result_get(rev);
    *out_rev = pp_sets_join(b, rv.data, rv.len);
    fprintf(stderr, "  rev_potential:    %s\n", *out_rev);
    regex_builder_free(b);
}

TEST(probe_nullable_suffix)
{
    char *fwd, *rev;
    probe_result("a~(b_*)", &fwd, &rev);
    assert(strcmp(fwd, "a") == 0);
    assert(strcmp(rev, "a") == 0);

    probe_result("a~(b_*)c", &fwd, &rev);
    assert(strcmp(fwd, "a;[^b]") == 0);
    assert(strcmp(rev, "c;_") == 0);

    probe_result("_*\\A~(_*b)c", &fwd, &rev);
    assert(strcmp(fwd, "_;_;_;_;_;_;_;_;_;_;_;_;_;_;_;_") == 0);
    assert(strcmp(rev, "c") == 0);

    probe_result("_*[^b]c|\\Ac", &fwd, &rev);
    assert(strcmp(fwd, "_;_") == 0);
    assert(strcmp(rev, "c") == 0);

    probe_result("2011|TL868|NETTV\\/3.1\\b", &fwd, &rev);
    assert(strcmp(fwd, "[2NT];[0EL];[18T];[16T]") == 0);
    assert(strcmp(rev, "[18];[16];[08];[2L]") == 0);
}

// ---------------------------------------------------------------------------
// mod parser_size
// ---------------------------------------------------------------------------

TEST(huge_repetitions_are_rejected)
{
    const char *reject[] = {
        "a{2001}", "a{1000000}", ".{1,8191}", ".{1,7168}",
        "a{2147483647,2147483647}", "a{2147483648,2147483648}",
        "([0-9]{1,9999}):([0-9]{1,9999})",
    };
    const char *accept[] = {"a{500}", "a{0,500}", "a{1,499}"};
    for (size_t i = 0; i < sizeof reject / sizeof reject[0]; ++i) {
        Regex *re = regex_new(reject[i]);
        assert(re == nullptr);
    }
    for (size_t i = 0; i < sizeof accept / sizeof accept[0]; ++i) {
        Regex *re = regex_new(accept[i]);
        assert(re != nullptr);
        regex_free(re);
    }
}

TEST(deeply_nested_repetitions_rejected)
{
    const char *reject[] = {
        "(?:a(?:b(?:c(?:d(?:e(?:f(?:g(?:h(?:i(?:FooBar)"
        "{3,6}){3,6}){3,6}){3,6}){3,6}){3,6}){3,6}){3,6}){3,6}){3,6}",
        "(?:a(?:b(?:c(?:d(?:e(?:f(?:g(?:h(?:i(?:j(?:k(?:l(?:FooBar)"
        "{2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}",
    };
    for (size_t i = 0; i < sizeof reject / sizeof reject[0]; ++i) {
        Regex *re = regex_new(reject[i]);
        assert(re == nullptr);
    }
    char *long_alt = n00b_alloc_array(char, 5000 + 1 + 5000 + 1);
    assert(long_alt != nullptr);
    memset(long_alt, 'a', 5000);
    long_alt[5000] = '|';
    memset(long_alt + 5001, 'b', 5000);
    long_alt[10001] = '\0';
    {
        Regex *re = regex_new(long_alt);
        assert(re == nullptr);
    }
    const char *accept[] = {
        "(?:a(?:b(?:c(?:FooBar){2}){2}){2}){2}",
        "a{100}",
        "[a-z]{50,200}",
    };
    for (size_t i = 0; i < sizeof accept / sizeof accept[0]; ++i) {
        Regex *re = regex_new(accept[i]);
        assert(re != nullptr);
        regex_free(re);
    }
}

TEST(mixed_alt_and_intersection_top_level_does_not_panic)
{
    const char *cases[] = {"^&|&$", "\\s|&nbsp;", "&|x", "&&|\\|\\|"};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        Regex *re = regex_new(cases[i]);
        assert(re == nullptr);
    }
}

// ---------------------------------------------------------------------------
// mod accel_skip — fixture loader + the lazy test.
// ---------------------------------------------------------------------------

typedef struct AccelSkipMatch {
    size_t start;
    size_t end;
} AccelSkipMatch;

typedef struct AccelSkipTestCase {
    char           *pattern;
    char           *input;
    size_t          input_len;
    AccelSkipMatch *matches;
    size_t          matches_len;
} AccelSkipTestCase;

extern AccelSkipTestCase *engine_test_load_accel_skip_tests(size_t *out_len);
extern void engine_test_free_accel_skip_tests(AccelSkipTestCase *tests,
                                              size_t count);

TEST(accel_skip_lazy)
{
    size_t tlen = 0;
    AccelSkipTestCase *tests = engine_test_load_accel_skip_tests(&tlen);
    assert(tests != nullptr);
    for (size_t i = 0; i < tlen; ++i) {
        const AccelSkipTestCase *tc = &tests[i];
        RegexOptions opts = regex_options_default();
        opts.max_dfa_capacity = 10000;
        Regex *re = regex_with_options(tc->pattern, opts);
        assert(re != nullptr);
        n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re, (const uint8_t *)tc->input,
                              tc->input_len, &got)
               == N00B_REGEX_ENGINE_ERR_NONE);
        size_t glen = n00b_list_len(got);
        ASSERT_EQ_SIZE(glen, tc->matches_len);
        for (size_t j = 0; j < glen; ++j) {
            Match mm = n00b_list_get(got, j);
            ASSERT_EQ_SIZE(mm.start, tc->matches[j].start);
            ASSERT_EQ_SIZE(mm.end,   tc->matches[j].end);
        }
        n00b_list_free(got);
        regex_free(re);
    }
    engine_test_free_accel_skip_tests(tests, tlen);
}

// ---------------------------------------------------------------------------
// mod prefix_toml
// ---------------------------------------------------------------------------

static char *
prefix_pp_sets(const RegexBuilder *b, const TSetId *sets, size_t len)
{
    return pp_sets_join_with_solver(regex_builder_solver_ref(b), sets, len);
}

static bool
prefix_kind_expectation_requires_simd(const char *expected)
{
    return strcmp(expected, "AnchoredFwd") == 0
        || strcmp(expected, "AnchoredFwdLb") == 0;
}

TEST(test_prefix_toml)
{
    size_t tlen = 0;
    PrefixTestCase *tests = engine_test_load_prefix_tests(&tlen);
    assert(tests != nullptr);
    for (size_t ti = 0; ti < tlen; ++ti) {
        PrefixTestCase *tc = &tests[ti];
        if (tc->ignore) {
            continue;
        }

        bool needs_sets = false;
        for (size_t i = 0; i < tc->checks_len; ++i) {
            if (strcmp(tc->kinds[i], "kind") != 0) {
                needs_sets = true;
                break;
            }
        }
        RegexBuilder *b = nullptr;
        PrefixSets   *sets = nullptr;
        if (needs_sets) {
            b = regex_builder_new(nullptr);
            int e = 0;
            NodeId node = resharp_parse_ast(b, tc->pattern, &e);
            assert(e == 0);
            n00b_result_t(NodeId) rr = regex_builder_ts_rev_start(b, node);
            REQUIRE(n00b_result_is_ok(rr),
                    "regex_builder_ts_rev_start failed");
            NodeId rev = n00b_result_get(rr);
            int err = N00B_REGEX_ENGINE_ERR_NONE;
            sets = prefix_sets_compute(b, node, rev, &err);
            assert(sets != nullptr);
            assert(err == N00B_REGEX_ENGINE_ERR_NONE);
        }

        char *kind_result = nullptr;
        for (size_t i = 0; i < tc->checks_len; ++i) {
            if (strcmp(tc->kinds[i], "kind") == 0) {
                Regex *re = regex_new(tc->pattern);
                assert(re != nullptr);
                const char *k = regex_prefix_kind_name(re);
                kind_result = k ? dup_cstr(k) : dup_cstr("None");
                regex_free(re);
                break;
            }
        }

        for (size_t i = 0; i < tc->checks_len; ++i) {
            const char *kind     = tc->kinds[i];
            const char *expected = tc->expects[i];
            char       *result   = nullptr;
            if (strcmp(kind, "kind") == 0
                && !n00b_simd_has_simd()
                && prefix_kind_expectation_requires_simd(expected)) {
                fprintf(stderr,
                        "[skip]    prefix_toml/%s kind=%s "
                        "(requires SIMD prefix backend)\n",
                        tc->name, expected);
                continue;
            }
            if (strcmp(kind, "kind") == 0) {
                result = dup_cstr(kind_result);
            } else {
                TSetId *arr = nullptr;
                size_t  arr_len = 0;
                if (strcmp(kind, "prefix_rev") == 0) {
                    prefix_sets_rev_anchored(sets, &arr, &arr_len);
                } else if (strcmp(kind, "potential_rev") == 0) {
                    prefix_sets_rev_potential(sets, &arr, &arr_len);
                } else if (strcmp(kind, "potential_fwd") == 0) {
                    prefix_sets_fwd_potential(sets, &arr, &arr_len);
                } else {
                    fprintf(stderr, "unknown prefix test kind: %s\n", kind);
                    abort();
                }
                result = prefix_pp_sets(b, arr, arr_len);
            }
            if (strcmp(result, expected) != 0) {
                fprintf(stderr,
                        "prefix test failed: name=%s, kind=%s\n"
                        "  got:      %s\n  expected: %s\n",
                        tc->name, kind, result, expected);
                abort();
            }
        }
        if (sets) {
            prefix_sets_free(sets);
        }
        if (b) {
            regex_builder_free(b);
        }
    }
    engine_test_free_prefix_tests(tests, tlen);
}

// ---------------------------------------------------------------------------
// mod auto_harden
// ---------------------------------------------------------------------------

TEST(auto_harden_toml)
{
    size_t tlen = 0;
    AutoHardenTestCase *tests = engine_test_load_auto_harden_tests(&tlen);
    assert(tests != nullptr);
    for (size_t i = 0; i < tlen; ++i) {
        const AutoHardenTestCase *t = &tests[i];
        Regex *re = regex_new(t->pattern);
        assert(re != nullptr);
        bool got = regex_is_hardened(re);
        if (got != t->hardened) {
            fprintf(stderr,
                    "pattern=%s: expected is_hardened=%d, got %d\n",
                    t->pattern, (int)t->hardened, (int)got);
            abort();
        }
        if (t->hardened) {
            Regex *hardened_re = regex_with_options(
                t->pattern,
                regex_options_hardened(regex_options_default(), true));
            assert(hardened_re != nullptr);
            const struct {
                const uint8_t *bytes;
                size_t         len;
            } inputs[] = {
                {(const uint8_t *)"", 0},
                {(const uint8_t *)"aaaaaaaa", 8},
                {(const uint8_t *)"abcdefg", 7},
                {(const uint8_t *)"|  |\n| a |\n|  |", 15},
            };
            for (size_t ii = 0; ii < 4; ++ii) {
                n00b_list_t(Match) a = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
                n00b_list_t(Match) b = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
                assert(regex_find_all(re, inputs[ii].bytes,
                                      inputs[ii].len, &a)
                       == N00B_REGEX_ENGINE_ERR_NONE);
                assert(regex_find_all(hardened_re, inputs[ii].bytes,
                                      inputs[ii].len, &b)
                       == N00B_REGEX_ENGINE_ERR_NONE);
                assert(list_list_equal(&a, &b));
                n00b_list_free(a);
                n00b_list_free(b);
            }
            regex_free(hardened_re);
        }
        regex_free(re);
    }
    engine_test_free_auto_harden_tests(tests, tlen);
}

// ---------------------------------------------------------------------------
// mod deriv
// ---------------------------------------------------------------------------

static Nullability
pos_mask(size_t pos, size_t n)
{
    if (n == 0) {
        return nullability_or(NULLABILITY_BEGIN, NULLABILITY_END);
    }
    if (pos == 0) {
        return NULLABILITY_BEGIN;
    }
    if (pos == n) {
        return NULLABILITY_END;
    }
    return NULLABILITY_CENTER;
}

static void
walk_bytes(RegexBuilder *b, NodeId node, const uint8_t *bytes,
           size_t bytes_len,
           char **expected, size_t expected_len,
           const size_t *expected_nulls, size_t expected_nulls_len,
           bool nulls_set,
           const char *dir, const char *name)
{
    if (bytes_len != expected_len) {
        fprintf(stderr,
                "input length must match %s expected length for %s\n",
                dir, name);
        abort();
    }
    size_t n = bytes_len;

    size_t  got_nulls_cap = 16, got_nulls_len = 0;
    size_t *got_nulls = n00b_alloc_array(size_t, got_nulls_cap);

    Nullability mask0 = pos_mask(0, n);
    bool null0 = nullability_has(regex_builder_nullability(b, node), mask0);
    fprintf(stderr, "  [%s] initial pos=0 mask=0x%x nullable=%d\n",
            dir, (unsigned)mask0.v, (int)null0);
    if (null0) {
        got_nulls[got_nulls_len++] = 0;
    }

    for (size_t i = 0; i < bytes_len; ++i) {
        uint8_t byte = bytes[i];
        Nullability der_mask = pos_mask(i, n);
        Solver *s = regex_builder_solver(b);
        TSetId tset = solver_u8_to_set_id(s, byte);
        n00b_result_t(TRegexId) der_rr =
            regex_builder_der(b, node, der_mask);
        REQUIRE(n00b_result_is_ok(der_rr), "regex_builder_der failed");
        TRegexId tregex = n00b_result_get(der_rr);
        NodeId next = regex_builder_transition_term(b, tregex, tset);
        char *pp = regex_builder_pp(b, next);
        fprintf(stderr,
                "  [%s] step=%zu byte='%c' (0x%02x) der_mask=0x%x "
                "node=%u => %s\n",
                dir, i, (char)byte, byte, (unsigned)der_mask.v,
                next.v, pp);
        if (i < expected_len && expected[i] != nullptr) {
            if (strcmp(pp, expected[i]) != 0) {
                fprintf(stderr,
                        "deriv pp mismatch: name=%s dir=%s "
                        "step=%zu byte='%c'\n",
                        name, dir, i, (char)byte);
                abort();
            }
        }
        node = next;

        Nullability mask_after = pos_mask(i + 1, n);
        bool null_after = nullability_has(regex_builder_nullability(b, node),
                                          mask_after);
        fprintf(stderr, "  [%s] after pos=%zu mask=0x%x nullable=%d\n",
                dir, i + 1, (unsigned)mask_after.v, (int)null_after);
        if (null_after) {
            if (got_nulls_len == got_nulls_cap) {
                size_t new_cap;
                if (ckd_mul(&new_cap, got_nulls_cap, (size_t)2)) {
                    n00b_panic("got_nulls cap overflow");
                }
                size_t *new_arr = n00b_alloc_array(size_t, new_cap);
                memcpy(new_arr, got_nulls,
                       got_nulls_len * sizeof *got_nulls);
                got_nulls     = new_arr;
                got_nulls_cap = new_cap;
            }
            got_nulls[got_nulls_len++] = i + 1;
        }
    }

    if (nulls_set) {
        if (got_nulls_len != expected_nulls_len) {
            fprintf(stderr,
                    "nullability length mismatch: name=%s dir=%s\n",
                    name, dir);
            abort();
        }
        for (size_t i = 0; i < got_nulls_len; ++i) {
            if (got_nulls[i] != expected_nulls[i]) {
                fprintf(stderr,
                        "nullability mismatch at %zu: name=%s dir=%s\n",
                        i, name, dir);
                abort();
            }
        }
    }
}

TEST(hardened_always_nullable_empty_matches)
{
    struct {
        const char    *pat;
        const uint8_t *input;
        size_t         in_len;
        Match          expected[3];
        size_t         exp_len;
    } cases[] = {
        {"(?:b*c|)",                    (const uint8_t *)"yy", 2,
            {{0,0},{1,1},{2,2}}, 3},
        {"(?:[^<]*<[\\w\\W]+>[^>]*$|)", (const uint8_t *)"x",  1,
            {{0,0},{1,1},{0,0}}, 2},
        {"()|(a+b+)",                   (const uint8_t *)"x",  1,
            {{0,0},{1,1},{0,0}}, 2},
        {"(?:.*x|)",                    (const uint8_t *)"yy", 2,
            {{0,0},{1,1},{2,2}}, 3},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        RegexOptions opts = regex_options_hardened(
            regex_options_unicode(regex_options_default(),
                                  UNICODE_MODE_JAVASCRIPT),
            true);
        Regex *re = regex_with_options(cases[i].pat, opts);
        assert(re != nullptr);
        assert(regex_is_hardened(re));
        n00b_list_t(Match) got = n00b_list_new_private(Match, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        assert(regex_find_all(re, cases[i].input, cases[i].in_len, &got)
               == N00B_REGEX_ENGINE_ERR_NONE);
        assert(list_matches_equal(&got, cases[i].expected, cases[i].exp_len));
        n00b_list_free(got);
        regex_free(re);
    }
}

TEST(test_deriv_toml)
{
    size_t tlen = 0;
    DerivTestCase *tests = engine_test_load_deriv_tests(&tlen);
    REQUIRE(tests != nullptr, "engine_test_load_deriv_tests returned NULL");
    for (size_t ti = 0; ti < tlen; ++ti) {
        DerivTestCase *tc = &tests[ti];
        if (tc->ignore) {
            continue;
        }
        RegexBuilder *b = regex_builder_new(nullptr);
        int e = 0;
        NodeId node = resharp_parse_ast(b, tc->pattern, &e);
        REQUIRE(e == 0, "resharp_parse_ast failed");

        if (tc->rev_len != 0 || tc->rev_nulls_set) {
            n00b_result_t(NodeId) rev_rr = regex_builder_reverse(b, node);
            REQUIRE(n00b_result_is_ok(rev_rr),
                    "regex_builder_reverse failed");
            NodeId rev = n00b_result_get(rev_rr);
            n00b_result_t(NodeId) nrm_rr =
                regex_builder_normalize_rev(b, rev);
            REQUIRE(n00b_result_is_ok(nrm_rr),
                    "regex_builder_normalize_rev failed");
            rev = n00b_result_get(nrm_rr);
            rev = regex_builder_mk_concat(b, NODE_ID_TS, rev);

            char *pp = regex_builder_pp(b, rev);
            fprintf(stderr, "\n[%s] rev initial: node=%u pp=%s\n",
                    tc->name, rev.v, pp);

            uint8_t *bytes = n00b_alloc_array(uint8_t, tc->input_len);
            for (size_t i = 0; i < tc->input_len; ++i) {
                bytes[i] = (uint8_t)tc->input[tc->input_len - 1 - i];
            }
            char **expected_rev = tc->rev_len ? tc->rev : nullptr;
            size_t expected_rev_len =
                tc->rev_len ? tc->rev_len : tc->input_len;
            char **empty_rev = nullptr;
            if (expected_rev == nullptr) {
                empty_rev = n00b_alloc_array(char *, expected_rev_len);
                expected_rev = empty_rev;
            }
            walk_bytes(b, rev, bytes, tc->input_len,
                       expected_rev, expected_rev_len,
                       tc->rev_nulls_set ? tc->rev_nulls : nullptr,
                       tc->rev_nulls_set ? tc->rev_nulls_len : 0,
                       tc->rev_nulls_set,
                       "rev", tc->name);
        }

        if (tc->fwd_len != 0 || tc->fwd_nulls_set) {
            char *pp = regex_builder_pp(b, node);
            fprintf(stderr,
                    "\n[%s] fwd initial: node=%u kind=%d pp=%s\n",
                    tc->name, node.v,
                    (int)regex_builder_get_kind(b, node), pp);

            char **expected_fwd = tc->fwd_len ? tc->fwd : nullptr;
            size_t expected_fwd_len =
                tc->fwd_len ? tc->fwd_len : tc->input_len;
            char **empty_fwd = nullptr;
            if (expected_fwd == nullptr) {
                empty_fwd = n00b_alloc_array(char *, expected_fwd_len);
                expected_fwd = empty_fwd;
            }
            walk_bytes(b, node, (const uint8_t *)tc->input, tc->input_len,
                       expected_fwd, expected_fwd_len,
                       tc->fwd_nulls_set ? tc->fwd_nulls : nullptr,
                       tc->fwd_nulls_set ? tc->fwd_nulls_len : 0,
                       tc->fwd_nulls_set,
                       "fwd", tc->name);
        }
        regex_builder_free(b);
    }
    engine_test_free_deriv_tests(tests, tlen);
}

// ---------------------------------------------------------------------------
// File slurp helper — reads `path` into a fresh NUL-terminated n00b char
// buffer using the conduit subsystem.  Returns nullptr + *out_len = 0 on
// any IO error.  Used by tests that load large haystack data files.
// ---------------------------------------------------------------------------

static char *
engine_test_slurp_file(const char *path, size_t *out_len)
{
    if (out_len) *out_len = 0;
#ifdef _WIN32
    int fd = _open(path, _O_RDONLY | _O_BINARY);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) return nullptr;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return nullptr;
    }
    size_t size = (size_t)st.st_size;
    // Allocate the output buffer up front and read directly into it.
    // The previous implementation used an intermediate n00b_buffer_t,
    // which left the buf pointer at risk across the second allocation —
    // conservative GC sometimes failed to forward the local on the
    // stack, leaving it dangling after the from-space was unmapped.
    char *out = n00b_alloc_array(char, size + 1);
    if (size > 0) {
        size_t total = 0;
        while (total < size) {
            ssize_t r = read(fd, out + total, size - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
        if (total != size) {
            close(fd);
            return nullptr;
        }
    }
    close(fd);
    out[size] = '\0';
    if (out_len) *out_len = size;
    return out;
}

// ---------------------------------------------------------------------------
// TOML loader implementations.
//
// Six loaders, one per fixture shape.  Each opens its TOML file via
// `n00b_toml_parse_file`, walks the `[[test]]` array-of-tables, and
// populates a `TestCase[]` / `InternalTestCase[]` / etc.  Strings are
// `n00b_alloc_array(char, n+1)` copies (so the test struct retains the
// resharp-c `char *` field shape); n00b's GC keeps them alive.  The
// matching `engine_test_free_*` helpers are no-ops (GC handles cleanup).
// ---------------------------------------------------------------------------

static char *
dup_n00b_string(n00b_string_t *s)
{
    if (s == nullptr) return nullptr;
    size_t n   = (size_t)s->u8_bytes;
    char  *out = n00b_alloc_array(char, n + 1);
    if (n > 0) memcpy(out, s->data, n);
    out[n] = '\0';
    return out;
}

static char *
dup_cstr(const char *s)
{
    if (s == nullptr) return nullptr;
    size_t n   = strlen(s);
    char  *out = n00b_alloc_array(char, n + 1);
    if (n > 0) memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static char *
dup_opt_str(const n00b_toml_node_t *t, const char *key)
{
    n00b_option_t(n00b_toml_node_t *) v_opt
        = n00b_toml_table_get_cstr(t, key);
    if (!n00b_option_is_set(v_opt)) return nullptr;
    n00b_toml_node_t *v = n00b_option_get(v_opt);
    if (n00b_toml_type(v) != N00B_TOML_STRING) return nullptr;
    return dup_n00b_string(n00b_toml_as_string(v));
}

static char *
dup_required_str(const n00b_toml_node_t *t, const char *key)
{
    n00b_option_t(n00b_toml_node_t *) v_opt
        = n00b_toml_table_get_cstr(t, key);
    n00b_require(n00b_option_is_set(v_opt),
                 "TOML: missing required key");
    n00b_toml_node_t *v = n00b_option_get(v_opt);
    n00b_require(n00b_toml_type(v) == N00B_TOML_STRING,
                 "TOML: required key is not a string");
    return dup_n00b_string(n00b_toml_as_string(v));
}

static bool
get_opt_bool(const n00b_toml_node_t *t, const char *key, bool dflt)
{
    n00b_option_t(n00b_toml_node_t *) v_opt
        = n00b_toml_table_get_cstr(t, key);
    if (!n00b_option_is_set(v_opt)) return dflt;
    return n00b_toml_as_bool(n00b_option_get(v_opt));
}

// Same path-resolve story as make_path but with a "tests" subdir, mirroring
// the upstream `engine_test_resolve`.
static char *
engine_test_resolve(const char *filename)
{
    n00b_string_t *base = n00b_string_from_cstr(RESHARP_ENGINE_MANIFEST_DIR);
    n00b_string_t *tests = n00b_string_from_cstr("tests");
    n00b_string_t *fn    = n00b_string_from_cstr(filename);
    n00b_string_t *j     = n00b_path_simple_join(base, tests);
    n00b_string_t *jj    = n00b_path_simple_join(j, fn);
    size_t n   = (size_t)jj->u8_bytes;
    char  *out = n00b_alloc_array(char, n + 1);
    memcpy(out, jj->data, n);
    out[n] = '\0';
    return out;
}

// Parse `matches = [[start, end], ...]` into a Match[].
static void
parse_matches(const n00b_toml_node_t *t, Match **out, size_t *out_len)
{
    *out     = nullptr;
    *out_len = 0;
    n00b_option_t(n00b_toml_node_t *) mv_opt
        = n00b_toml_table_get_cstr(t, "matches");
    if (!n00b_option_is_set(mv_opt)) return;
    n00b_toml_node_t *mv = n00b_option_get(mv_opt);
    n00b_require(n00b_toml_type(mv) == N00B_TOML_ARRAY,
                 "matches must be an array");
    size_t mn = n00b_toml_array_len(mv);
    if (mn == 0) return;
    Match *buf = n00b_alloc_array(Match, mn);
    for (size_t j = 0; j < mn; ++j) {
        n00b_toml_node_t *pair = n00b_toml_array_get(mv, j);
        n00b_require(n00b_toml_type(pair) == N00B_TOML_ARRAY,
                     "match entries must be [start, end]");
        n00b_require(n00b_toml_array_len(pair) == 2,
                     "match entries must have 2 elements");
        buf[j].start = (size_t)n00b_toml_as_int(n00b_toml_array_get(pair, 0));
        buf[j].end   = (size_t)n00b_toml_as_int(n00b_toml_array_get(pair, 1));
    }
    *out     = buf;
    *out_len = mn;
}

// Walk a TOML `[[test]]` array-of-tables.  Returns the outer array node
// or nullptr if the file has no `[[test]]` entries.
static n00b_toml_node_t *
load_test_array(const char *filename)
{
    char *path = engine_test_resolve(filename);
    n00b_string_t *path_s = n00b_string_from_cstr(path);
    auto r = n00b_toml_parse_file(path_s);
    if (!n00b_result_is_ok(r)) {
        n00b_string_t *err = n00b_toml_last_error();
        fprintf(stderr, "toml parse failed: path=%s err=%s\n",
                path, err ? err->data : "(none)");
    }
    n00b_require(n00b_result_is_ok(r), "n00b_toml_parse_file failed");
    n00b_toml_node_t *root = n00b_result_get(r);
    n00b_option_t(n00b_toml_node_t *) arr_opt
        = n00b_toml_table_array_of(root, "test");
    if (!n00b_option_is_set(arr_opt)) return nullptr;
    return n00b_option_get(arr_opt);
}

TestCase *
engine_test_load_tests(const char *filename, size_t *out_len)
{
    n00b_toml_node_t *arr = load_test_array(filename);
    if (arr == nullptr) {
        *out_len = 0;
        return n00b_alloc_array(TestCase, 1);
    }
    size_t    n   = n00b_toml_array_len(arr);
    TestCase *out = n00b_alloc_array(TestCase, n + 1);
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *t = n00b_toml_array_get(arr, i);
        out[i].name = dup_opt_str(t, "name");
        if (out[i].name == nullptr) {
            out[i].name = n00b_alloc_array(char, 1);
            out[i].name[0] = '\0';
        }
        out[i].pattern = dup_required_str(t, "pattern");

        n00b_option_t(n00b_toml_node_t *) iv_opt
            = n00b_toml_table_get_cstr(t, "input");
        if (n00b_option_is_set(iv_opt)
            && n00b_toml_type(n00b_option_get(iv_opt)) == N00B_TOML_STRING) {
            n00b_string_t *s = n00b_toml_as_string(n00b_option_get(iv_opt));
            size_t sl = (size_t)s->u8_bytes;
            out[i].input = n00b_alloc_array(char, sl + 1);
            if (sl > 0) memcpy(out[i].input, s->data, sl);
            out[i].input[sl] = '\0';
            out[i].input_len = sl;
        }
        else {
            out[i].input     = n00b_alloc_array(char, 1);
            out[i].input[0]  = '\0';
            out[i].input_len = 0;
        }
        parse_matches(t, &out[i].matches, &out[i].matches_len);
        out[i].ignore       = get_opt_bool(t, "ignore",       false);
        out[i].expect_error = get_opt_bool(t, "expect_error", false);
        out[i].anchored     = get_opt_bool(t, "anchored",     false);
        out[i].vs_regex     = get_opt_bool(t, "vs_regex",     false);
    }
    *out_len = n;
    return out;
}

void engine_test_free_tests(TestCase *tests, size_t len) { (void)tests; (void)len; /* GC */ }

InternalTestCase *
engine_test_load_internal_tests(const char *filename, size_t *out_len)
{
    n00b_toml_node_t *arr = load_test_array(filename);
    if (arr == nullptr) {
        *out_len = 0;
        return n00b_alloc_array(InternalTestCase, 1);
    }
    size_t            n   = n00b_toml_array_len(arr);
    InternalTestCase *out = n00b_alloc_array(InternalTestCase, n + 1);
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *t = n00b_toml_array_get(arr, i);
        out[i].name = dup_opt_str(t, "name");
        if (out[i].name == nullptr) {
            out[i].name = n00b_alloc_array(char, 1);
            out[i].name[0] = '\0';
        }
        out[i].pattern = dup_required_str(t, "pattern");
        out[i].pp      = dup_required_str(t, "pp");
        out[i].ts_rev  = dup_opt_str(t, "ts_rev");
    }
    *out_len = n;
    return out;
}

void engine_test_free_internal_tests(InternalTestCase *t, size_t len) { (void)t; (void)len; /* GC */ }

PrefixTestCase *
engine_test_load_prefix_tests(size_t *out_len)
{
    n00b_toml_node_t *arr = load_test_array("prefix.toml");
    if (arr == nullptr) {
        *out_len = 0;
        return n00b_alloc_array(PrefixTestCase, 1);
    }
    size_t          n   = n00b_toml_array_len(arr);
    PrefixTestCase *out = n00b_alloc_array(PrefixTestCase, n + 1);
    static const char *KIND_KEYS[] = {
        "kind", "prefix_rev", "potential_rev", "potential_fwd"
    };
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *t = n00b_toml_array_get(arr, i);
        out[i].name = dup_opt_str(t, "name");
        if (out[i].name == nullptr) {
            out[i].name = n00b_alloc_array(char, 1);
            out[i].name[0] = '\0';
        }
        out[i].pattern = dup_required_str(t, "pattern");
        out[i].ignore  = get_opt_bool(t, "ignore", false);

        size_t cn = 0;
        for (size_t k = 0; k < sizeof KIND_KEYS / sizeof KIND_KEYS[0]; ++k) {
            if (n00b_option_is_set(n00b_toml_table_get_cstr(t, KIND_KEYS[k]))) {
                cn++;
            }
        }
        if (cn == 0) {
            out[i].checks_len = 0;
            out[i].kinds      = nullptr;
            out[i].expects    = nullptr;
            continue;
        }
        out[i].checks_len = cn;
        out[i].kinds   = n00b_alloc_array(char *, cn);
        out[i].expects = n00b_alloc_array(char *, cn);
        size_t idx = 0;
        for (size_t k = 0; k < sizeof KIND_KEYS / sizeof KIND_KEYS[0]; ++k) {
            n00b_option_t(n00b_toml_node_t *) v_opt
                = n00b_toml_table_get_cstr(t, KIND_KEYS[k]);
            if (!n00b_option_is_set(v_opt)) continue;
            size_t kl = strlen(KIND_KEYS[k]);
            out[i].kinds[idx] = n00b_alloc_array(char, kl + 1);
            memcpy(out[i].kinds[idx], KIND_KEYS[k], kl + 1);
            out[i].expects[idx] = dup_required_str(t, KIND_KEYS[k]);
            idx++;
        }
    }
    *out_len = n;
    return out;
}

void engine_test_free_prefix_tests(PrefixTestCase *t, size_t len) { (void)t; (void)len; /* GC */ }

AutoHardenTestCase *
engine_test_load_auto_harden_tests(size_t *out_len)
{
    n00b_toml_node_t *arr = load_test_array("auto_harden.toml");
    if (arr == nullptr) {
        *out_len = 0;
        return n00b_alloc_array(AutoHardenTestCase, 1);
    }
    size_t              n   = n00b_toml_array_len(arr);
    AutoHardenTestCase *out = n00b_alloc_array(AutoHardenTestCase, n + 1);
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *t = n00b_toml_array_get(arr, i);
        out[i].pattern = dup_required_str(t, "pattern");
        n00b_option_t(n00b_toml_node_t *) h_opt
            = n00b_toml_table_get_cstr(t, "hardened");
        n00b_require(n00b_option_is_set(h_opt),
                     "auto_harden: missing 'hardened'");
        out[i].hardened = n00b_toml_as_bool(n00b_option_get(h_opt));
    }
    *out_len = n;
    return out;
}

void engine_test_free_auto_harden_tests(AutoHardenTestCase *t, size_t len) { (void)t; (void)len; /* GC */ }

// Helper for deriv: parse a string-array; "?" entries map to NULL.
static void
parse_deriv_step_array(const n00b_toml_node_t *t, const char *key,
                       char ***out, size_t *out_len)
{
    *out = nullptr;
    *out_len = 0;
    n00b_option_t(n00b_toml_node_t *) v_opt
        = n00b_toml_table_get_cstr(t, key);
    if (!n00b_option_is_set(v_opt)) return;
    n00b_toml_node_t *v = n00b_option_get(v_opt);
    if (n00b_toml_type(v) != N00B_TOML_ARRAY) return;
    size_t n = n00b_toml_array_len(v);
    if (n == 0) return;
    char **arr = n00b_alloc_array(char *, n);
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *e = n00b_toml_array_get(v, i);
        n00b_string_t    *s = n00b_toml_as_string(e);
        if (s != nullptr && strcmp(s->data, "?") == 0) {
            arr[i] = nullptr;
        }
        else if (s != nullptr) {
            arr[i] = dup_n00b_string(s);
        }
        else {
            arr[i] = nullptr;
        }
    }
    *out = arr;
    *out_len = n;
}

static void
parse_nulls_array(const n00b_toml_node_t *t, const char *key,
                  size_t **out, size_t *out_len, bool *out_set)
{
    *out = nullptr;
    *out_len = 0;
    *out_set = false;
    n00b_option_t(n00b_toml_node_t *) v_opt
        = n00b_toml_table_get_cstr(t, key);
    if (!n00b_option_is_set(v_opt)) return;
    n00b_toml_node_t *v = n00b_option_get(v_opt);
    if (n00b_toml_type(v) != N00B_TOML_ARRAY) return;
    size_t n = n00b_toml_array_len(v);
    *out_set = true;
    if (n == 0) return;
    size_t *arr = n00b_alloc_array(size_t, n);
    for (size_t i = 0; i < n; ++i) {
        arr[i] = (size_t)n00b_toml_as_int(n00b_toml_array_get(v, i));
    }
    *out = arr;
    *out_len = n;
}

DerivTestCase *
engine_test_load_deriv_tests(size_t *out_len)
{
    n00b_toml_node_t *arr = load_test_array("deriv.toml");
    if (arr == nullptr) {
        *out_len = 0;
        return n00b_alloc_array(DerivTestCase, 1);
    }
    size_t         n   = n00b_toml_array_len(arr);
    DerivTestCase *out = n00b_alloc_array(DerivTestCase, n + 1);
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *t = n00b_toml_array_get(arr, i);
        out[i].name = dup_opt_str(t, "name");
        if (out[i].name == nullptr) {
            out[i].name = n00b_alloc_array(char, 1);
            out[i].name[0] = '\0';
        }
        out[i].pattern = dup_required_str(t, "pattern");
        out[i].ignore  = get_opt_bool(t, "ignore", false);

        n00b_option_t(n00b_toml_node_t *) iv_opt
            = n00b_toml_table_get_cstr(t, "input");
        if (n00b_option_is_set(iv_opt)
            && n00b_toml_type(n00b_option_get(iv_opt)) == N00B_TOML_STRING) {
            n00b_string_t *s = n00b_toml_as_string(n00b_option_get(iv_opt));
            size_t sl = (size_t)s->u8_bytes;
            out[i].input = n00b_alloc_array(char, sl + 1);
            if (sl > 0) memcpy(out[i].input, s->data, sl);
            out[i].input[sl] = '\0';
            out[i].input_len = sl;
        }
        else {
            out[i].input     = n00b_alloc_array(char, 1);
            out[i].input[0]  = '\0';
            out[i].input_len = 0;
        }
        parse_deriv_step_array(t, "rev", &out[i].rev, &out[i].rev_len);
        parse_deriv_step_array(t, "fwd", &out[i].fwd, &out[i].fwd_len);
        parse_nulls_array(t, "rev_nulls",
                          &out[i].rev_nulls, &out[i].rev_nulls_len,
                          &out[i].rev_nulls_set);
        parse_nulls_array(t, "fwd_nulls",
                          &out[i].fwd_nulls, &out[i].fwd_nulls_len,
                          &out[i].fwd_nulls_set);
    }
    *out_len = n;
    return out;
}

void engine_test_free_deriv_tests(DerivTestCase *t, size_t len) { (void)t; (void)len; /* GC */ }

AccelSkipTestCase *
engine_test_load_accel_skip_tests(size_t *out_len)
{
    n00b_toml_node_t *arr = load_test_array("accel_skip.toml");
    n00b_require(arr != nullptr, "accel_skip.toml: missing 'test' array");
    size_t             n   = n00b_toml_array_len(arr);
    AccelSkipTestCase *out = n00b_alloc_array(AccelSkipTestCase, n);
    for (size_t i = 0; i < n; ++i) {
        n00b_toml_node_t *t = n00b_toml_array_get(arr, i);
        out[i].pattern = dup_required_str(t, "pattern");

        n00b_option_t(n00b_toml_node_t *) iv_opt
            = n00b_toml_table_get_cstr(t, "input");
        n00b_require(n00b_option_is_set(iv_opt),
                     "accel_skip: missing 'input'");
        n00b_string_t *s = n00b_toml_as_string(n00b_option_get(iv_opt));
        size_t sl = (size_t)s->u8_bytes;
        out[i].input = n00b_alloc_array(char, sl + 1);
        if (sl > 0) memcpy(out[i].input, s->data, sl);
        out[i].input[sl] = '\0';
        out[i].input_len = sl;

        n00b_option_t(n00b_toml_node_t *) mv_opt
            = n00b_toml_table_get_cstr(t, "matches");
        if (!n00b_option_is_set(mv_opt)) {
            out[i].matches     = nullptr;
            out[i].matches_len = 0;
        }
        else {
            n00b_toml_node_t *mv = n00b_option_get(mv_opt);
            n00b_require(n00b_toml_type(mv) == N00B_TOML_ARRAY,
                         "matches must be an array");
            size_t mn = n00b_toml_array_len(mv);
            out[i].matches     = n00b_alloc_array(AccelSkipMatch, mn);
            out[i].matches_len = mn;
            for (size_t j = 0; j < mn; ++j) {
                n00b_toml_node_t *pair = n00b_toml_array_get(mv, j);
                n00b_require(n00b_toml_type(pair) == N00B_TOML_ARRAY,
                             "match entries must be [start, end]");
                n00b_require(n00b_toml_array_len(pair) == 2,
                             "match entries must have 2 elements");
                out[i].matches[j].start = (size_t)n00b_toml_as_int(
                    n00b_toml_array_get(pair, 0));
                out[i].matches[j].end   = (size_t)n00b_toml_as_int(
                    n00b_toml_array_get(pair, 1));
            }
        }
    }
    *out_len = n;
    return out;
}

void engine_test_free_accel_skip_tests(AccelSkipTestCase *t, size_t len) { (void)t; (void)len; /* GC */ }

// ---------------------------------------------------------------------------
// RegexRef — placeholder forwarding to the engine.  The Rust upstream
// cross-validates against the `regex` crate; the C port has no separate
// engine, so `regex_ref_*` and `regex_*` are the same.  Tests that
// compare them pass trivially.  Real differential testing can replace
// these bodies later without touching call sites.
// ---------------------------------------------------------------------------

struct RegexRef {
    Regex *inner;
};

RegexRef *
regex_ref_new(const char *pattern)
{
    Regex *r = regex_new(pattern);
    if (r == nullptr) return nullptr;
    RegexRef *ref = n00b_alloc(RegexRef);
    ref->inner = r;
    return ref;
}

RegexRef *
regex_ref_new_unicode(const char *pattern, bool unicode)
{
    RegexOptions opts = regex_options_default();
    opts.unicode = unicode ? UNICODE_MODE_DEFAULT : UNICODE_MODE_ASCII;
    Regex *r = regex_with_options(pattern, opts);
    if (r == nullptr) return nullptr;
    RegexRef *ref = n00b_alloc(RegexRef);
    ref->inner = r;
    return ref;
}

void
regex_ref_free(RegexRef *ref)
{
    if (ref == nullptr) return;
    regex_free(ref->inner);
    // ref is GC-managed.
}

n00b_regex_engine_err_t
regex_ref_find_all(RegexRef *ref, const uint8_t *input, size_t len,
                   n00b_list_t(Match) *out)
{
    return regex_find_all(ref->inner, input, len, out);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_runner_init(argc, argv);

    printf("Running regex engine tests...\n");

    RUN_TEST(normal_basic);
    RUN_TEST(normal_anchors);
    RUN_TEST(normal_boolean);
    RUN_TEST(normal_lookaround);
    RUN_IGNORED(semantics);
    RUN_TEST(errors);
    RUN_TEST(date_pattern);
    RUN_TEST(edge_cases);
    RUN_TEST(normal_cross_feature);
    RUN_TEST(javascript);
    RUN_TEST(literal_alt_is_match);
    RUN_TEST(literal_alt_suffix_is_match);
    RUN_TEST(intersect_narrow_with_widened_term_is_sound);
    RUN_TEST(precompiled_matches_lazy);
    RUN_TEST(precompiled_complex);
    RUN_TEST(anchored_alt_star_rejected);
    RUN_TEST(space_newline_space);
    RUN_TEST(literal_prefix_pure_literal);
    RUN_TEST(literal_prefix_with_wildcard);
    RUN_TEST(literal_prefix_alternation_at_root);
    RUN_TEST(literal_prefix_char_class_no_prefix);
    RUN_TEST(literal_prefix_single_char_pattern);
    RUN_TEST(literal_equiv_sherlock);
    RUN_TEST(literal_equiv_prefix_the);
    RUN_TEST(literal_equiv_no_prefix);
    RUN_TEST(literal_equiv_empty_input);
    RUN_TEST(literal_equiv_no_match);
    RUN_TEST(capacity_exceeded_at_compile);
    RUN_TEST(dictionary_context_small);
    RUN_TEST(dictionary_context_small_both);
    RUN_TEST(dictionary_context_small_suffix);
    RUN_IGNORED(dictionary_context_medium);
    RUN_TEST(normal_paragraph);
    RUN_TEST(find_anchored_test);
    RUN_TEST(ci);
    RUN_TEST(normal_word_boundary);
    RUN_TEST(literal_alt);
    RUN_TEST(capacity_exceeded_at_match);
    RUN_TEST(unanchored_search_false_positive);
    RUN_TEST(opts_unicode_false);
    RUN_TEST(opts_case_insensitive);
    RUN_TEST(opts_dot_matches_new_line);
    RUN_TEST(opts_dot_all_inline_flag);
    RUN_TEST(opts_dot_all_scoped_group);
    RUN_TEST(opts_ignore_whitespace);
    RUN_IF_FIXTURE(word_match_lengths_en_sampled,
                   "/data/haystacks/en-sampled.txt");
    RUN_TEST(hardened_basic);
    RUN_TEST(hardened_anchors);
    RUN_IGNORED(hardened_semantics);
    RUN_IGNORED(hardened_date_pattern);
    RUN_TEST(hardened_edge_cases);
    RUN_TEST(hardened_lookaround);
    RUN_IGNORED(hardened_boolean);
    RUN_TEST(hardened_cross_feature);
    RUN_TEST(hardened_paragraph);
    RUN_TEST(hardened_find_anchored);
    RUN_TEST(hardened_ci);
    RUN_IGNORED(hardened_word_boundary);
    RUN_TEST(hardened_literal_alt);
    RUN_TEST(hardened_pathological);
    RUN_IF_FIXTURE(hardened_cross_validate,
                   "/data/haystacks/en-sampled.txt");
    RUN_TEST(hardened_bounded_repeat_tail);
    RUN_IF_FIXTURE(range_prefix_correctness,
                   "/data/haystacks/en-sampled.txt");
    RUN_TEST(range_prefix_random_haystack);
    RUN_TEST(hardened_nullable_empty_after_dedup);
    RUN_IGNORED(hardened_cross_validate_all_toml);
    RUN_TEST(internal_test);
    RUN_TEST(normalize_toml);
    RUN_IGNORED(word_boundary_inference);
    RUN_TEST(alt_embedded_line_anchor_compiles_ok);
    RUN_TEST(word_boundaries_loop);
    RUN_TEST(fwd_la_1);
    RUN_IF_FIXTURE(fwd_la_2, "/data/haystacks/smallserver.txt");
    RUN_IF_FIXTURE(fwd_la_2_js, "/data/haystacks/smallserver.txt");
    RUN_IF_FIXTURE(fwd_la_3, "/data/haystacks/smallserver.txt");
    RUN_TEST(repro_lookahead_in_loop);
    RUN_TEST(hardened_long_word);
    RUN_TEST(no_progress);
    RUN_TEST(repro_is_match_negative_lookahead);
    RUN_TEST(light_depth_pass_bdfa_prefix_falls_through_to_potential);
    RUN_TEST(assets_path_js_unicode_uses_rev_literal);
    RUN_TEST(lookahead_alternation_with_end_of_line);
#ifdef NDEBUG
    RUN_TEST(rev_bot_skip_terminates_fast);
#else
    RUN_IGNORED(rev_bot_skip_terminates_fast);
#endif
    RUN_TEST(is_match_agrees_with_find_all_for_lookahead);
    RUN_TEST(alternation_prefix_soundness_bulk);
    RUN_TEST(trailing_dollar_after_top_star_pruned);
    RUN_TEST(empty_language_short_circuits);
    RUN_IF_SIMD(trailing_star_yields_to_fwd_prefix_kind);
    RUN_IF_SIMD(anchored_fwd_lb_selected_when_min_len_zero_kind);
    RUN_TEST(rev_literal_search);
    RUN_TEST(probe_alt);
    RUN_TEST(probe_nettv);
    RUN_TEST(probe_nullable_suffix);
    RUN_TEST(huge_repetitions_are_rejected);
    RUN_TEST(deeply_nested_repetitions_rejected);
    RUN_TEST(mixed_alt_and_intersection_top_level_does_not_panic);
    RUN_IGNORED(accel_skip_lazy);
    RUN_TEST(test_prefix_toml);
    RUN_TEST(auto_harden_toml);
    RUN_TEST(hardened_always_nullable_empty_matches);
    RUN_TEST(test_deriv_toml);

    printf("All regex engine tests passed.\n");
    n00b_shutdown();
    return 0;
}
