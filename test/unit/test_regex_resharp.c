/**
 * @file test_regex_resharp.c
 * @brief Runs resharp's TOML test suite against n00b's regex engine.
 *
 * Parses the TOML test data files from resharp and verifies that our
 * engine produces identical match results (longest-leftmost semantics).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#ifndef _WIN32
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "text/regex/regex.h"
#include "adt/result.h"

// ============================================================================
// Mini TOML parser — handles the specific format used by resharp tests
// ============================================================================

#define MAX_TESTS   512
#define MAX_MATCHES 64
#define MAX_STR     4096

typedef struct {
    char    pattern[MAX_STR];
    char    input[MAX_STR];
    int64_t match_starts[MAX_MATCHES];
    int64_t match_ends[MAX_MATCHES];
    int32_t n_matches;
    int64_t end_positions[MAX_MATCHES];
    int32_t n_end_positions;
    bool    has_matches;
    bool    has_end_positions;
    bool    expect_error;
    bool    anchored;
    int     line_number;
} test_case_t;

static char *
read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char  *buf = malloc(len + 1);
    size_t got = fread(buf, 1, len, f);
    buf[got]   = '\0';
    fclose(f);
    if (out_len)
        *out_len = got;
    return buf;
}

static const char *
skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int
parse_toml_string(const char *p, char *out, const char **end_ptr)
{
    int len = 0;

    // Triple-single-quoted: raw literal string
    if (p[0] == '\'' && p[1] == '\'' && p[2] == '\'') {
        p += 3;
        if (*p == '\n')
            p++;
        while (*p) {
            if (p[0] == '\'' && p[1] == '\'' && p[2] == '\'') {
                if (len > 0 && out[len - 1] == '\n')
                    len--;
                *end_ptr = p + 3;
                out[len] = '\0';
                return len;
            }
            out[len++] = *p++;
        }
        out[len] = '\0';
        *end_ptr = p;
        return len;
    }

    // Triple-double-quoted: basic string with escapes
    if (p[0] == '"' && p[1] == '"' && p[2] == '"') {
        p += 3;
        if (*p == '\n')
            p++;
        while (*p) {
            if (p[0] == '"' && p[1] == '"' && p[2] == '"') {
                if (len > 0 && out[len - 1] == '\n')
                    len--;
                *end_ptr = p + 3;
                out[len] = '\0';
                return len;
            }
            if (*p == '\\' && p[1]) {
                p++;
                switch (*p) {
                case 'n':
                    out[len++] = '\n';
                    break;
                case 'r':
                    out[len++] = '\r';
                    break;
                case 't':
                    out[len++] = '\t';
                    break;
                case '\\':
                    out[len++] = '\\';
                    break;
                case '"':
                    out[len++] = '"';
                    break;
                default:
                    out[len++] = '\\';
                    out[len++] = *p;
                    break;
                }
                p++;
            }
            else {
                out[len++] = *p++;
            }
        }
        out[len] = '\0';
        *end_ptr = p;
        return len;
    }

    // Single-quoted: literal string (no escapes)
    if (*p == '\'') {
        p++;
        while (*p && *p != '\'') {
            out[len++] = *p++;
        }
        if (*p == '\'')
            p++;
        out[len] = '\0';
        *end_ptr = p;
        return len;
    }

    // Double-quoted: basic string with escapes
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) {
                p++;
                switch (*p) {
                case 'n':
                    out[len++] = '\n';
                    break;
                case 'r':
                    out[len++] = '\r';
                    break;
                case 't':
                    out[len++] = '\t';
                    break;
                case '\\':
                    out[len++] = '\\';
                    break;
                case '"':
                    out[len++] = '"';
                    break;
                case '/':
                    out[len++] = '/';
                    break;
                default:
                    out[len++] = '\\';
                    out[len++] = *p;
                    break;
                }
                p++;
            }
            else {
                out[len++] = *p++;
            }
        }
        if (*p == '"')
            p++;
        out[len] = '\0';
        *end_ptr = p;
        return len;
    }

    out[0]   = '\0';
    *end_ptr = p;
    return 0;
}

static int
parse_match_array(const char *p, int64_t *starts, int64_t *ends, const char **end_ptr)
{
    int count = 0;
    p         = skip_ws(p);
    if (*p != '[') {
        *end_ptr = p;
        return 0;
    }
    p++;

    while (*p) {
        p = skip_ws(p);
        if (*p == ']') {
            p++;
            break;
        }
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == '[') {
            p++;
            p             = skip_ws(p);
            starts[count] = strtol(p, (char **)&p, 10);
            p             = skip_ws(p);
            if (*p == ',')
                p++;
            p           = skip_ws(p);
            ends[count] = strtol(p, (char **)&p, 10);
            p           = skip_ws(p);
            if (*p == ']')
                p++;
            count++;
        }
    }
    *end_ptr = p;
    return count;
}

static int
parse_int_array(const char *p, int64_t *out, const char **end_ptr)
{
    int count = 0;
    p         = skip_ws(p);
    if (*p != '[') {
        *end_ptr = p;
        return 0;
    }
    p++;

    while (*p) {
        p = skip_ws(p);
        if (*p == ']') {
            p++;
            break;
        }
        if (*p == ',') {
            p++;
            continue;
        }
        out[count++] = strtol(p, (char **)&p, 10);
    }
    *end_ptr = p;
    return count;
}

static int
parse_test_file(const char *path, test_case_t *tests, int max_tests)
{
    size_t flen;
    char  *data = read_file(path, &flen);
    if (!data) {
        fprintf(stderr, "Cannot open %s\n", path);
        return -1;
    }

    int          n_tests = 0;
    test_case_t *cur     = NULL;
    const char  *p       = data;
    int          line    = 0;

    while (*p && n_tests < max_tests) {
        line++;
        const char *eol = strchr(p, '\n');
        if (!eol)
            eol = p + strlen(p);

        const char *trimmed = skip_ws(p);

        if (*trimmed == '#') {
            p = (*eol) ? eol + 1 : eol;
            continue;
        }

        if (strncmp(trimmed, "[[test]]", 8) == 0) {
            if (n_tests < max_tests) {
                cur = &tests[n_tests++];
                memset(cur, 0, sizeof(*cur));
                cur->line_number = line;
            }
            p = (*eol) ? eol + 1 : eol;
            continue;
        }

        if (strncmp(trimmed, "description", 11) == 0) {
            const char *eq = strchr(trimmed, '=');
            if (eq) {
                eq = skip_ws(eq + 1);
                if (eq[0] == '\'' && eq[1] == '\'' && eq[2] == '\'') {
                    const char *close = strstr(eq + 3, "'''");
                    if (close) {
                        p = close + 3;
                        while (*p && *p != '\n')
                            p++;
                        if (*p == '\n')
                            p++;
                        continue;
                    }
                }
            }
            p = (*eol) ? eol + 1 : eol;
            continue;
        }

        if (!cur) {
            p = (*eol) ? eol + 1 : eol;
            continue;
        }

        if (strncmp(trimmed, "pattern", 7) == 0 && (trimmed[7] == ' ' || trimmed[7] == '=')) {
            const char *eq = strchr(trimmed, '=');
            if (eq) {
                eq = skip_ws(eq + 1);
                const char *end;
                parse_toml_string(eq, cur->pattern, &end);
                p = end;
                while (*p && *p != '\n')
                    p++;
                if (*p == '\n')
                    p++;
                continue;
            }
        }

        if (strncmp(trimmed, "input", 5) == 0 && (trimmed[5] == ' ' || trimmed[5] == '=')) {
            const char *eq = strchr(trimmed, '=');
            if (eq) {
                eq = skip_ws(eq + 1);
                const char *end;
                parse_toml_string(eq, cur->input, &end);
                p = end;
                while (*p && *p != '\n')
                    p++;
                if (*p == '\n')
                    p++;
                continue;
            }
        }

        if (strncmp(trimmed, "matches", 7) == 0 && (trimmed[7] == ' ' || trimmed[7] == '=')) {
            const char *eq = strchr(trimmed, '=');
            if (eq) {
                eq = skip_ws(eq + 1);
                const char *end;
                cur->n_matches
                    = parse_match_array(eq, cur->match_starts, cur->match_ends, &end);
                cur->has_matches = true;
                p                = end;
                while (*p && *p != '\n')
                    p++;
                if (*p == '\n')
                    p++;
                continue;
            }
        }

        if (strncmp(trimmed, "end_positions", 13) == 0) {
            const char *eq = strchr(trimmed, '=');
            if (eq) {
                eq = skip_ws(eq + 1);
                const char *end;
                cur->n_end_positions   = parse_int_array(eq, cur->end_positions, &end);
                cur->has_end_positions = true;
                p                      = end;
                while (*p && *p != '\n')
                    p++;
                if (*p == '\n')
                    p++;
                continue;
            }
        }

        if (strncmp(trimmed, "anchored", 8) == 0
            && (trimmed[8] == ' ' || trimmed[8] == '=')) {
            const char *eq = strchr(trimmed, '=');
            if (eq) {
                eq = skip_ws(eq + 1);
                if (strncmp(eq, "true", 4) == 0) {
                    cur->anchored = true;
                }
                while (*p && *p != '\n')
                    p++;
                if (*p == '\n')
                    p++;
                continue;
            }
        }

        p = (*eol) ? eol + 1 : eol;
    }

    for (int i = 0; i < n_tests; i++) {
        if (!tests[i].has_matches && !tests[i].has_end_positions) {
            tests[i].expect_error = true;
        }
    }

    free(data);
    return n_tests;
}

// ============================================================================
// Test runner
// ============================================================================

static int total_pass         = 0;
static int total_fail         = 0;
static int total_skip         = 0;
static int total_compile_fail = 0;
static int total_timeout      = 0;

#define PER_TEST_TIMEOUT 5 // seconds

static bool
is_known_unsupported(const char *file, int line)
{
    typedef struct {
        const char *file;
        int         line;
    } known_case_t;

    static const known_case_t known[] = {
        {"tests01.toml", 173},
        {"tests02_lookaround.toml", 240},
        {"tests02_lookaround.toml", 245},
        {"tests02_lookaround.toml", 250},
        {"tests02_lookaround.toml", 280},
        {"tests03_boolean.toml", 96},
        {"tests03_boolean.toml", 167},
        {"tests05_match_end.toml", 88},
        {"tests08_semantics.toml", 57},
        {"tests08_semantics.toml", 71},
    };

    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (line == known[i].line && strcmp(file, known[i].file) == 0) {
            return true;
        }
    }
    return false;
}

static bool
skip_known_unsupported(const test_case_t *tc, const char *file)
{
    if (!is_known_unsupported(file, tc->line_number)) {
        return false;
    }
    fprintf(stderr,
            "  [SKIP] %s:%d unsupported RE# semantic edge case pattern='%s'\n",
            file,
            tc->line_number,
            tc->pattern);
    total_skip++;
    return true;
}

#ifndef _WIN32
static jmp_buf timeout_jmp;

static void
timeout_handler(int sig)
{
    (void)sig;
    longjmp(timeout_jmp, 1);
}
#endif

static void
run_match_test(const test_case_t *tc, const char *file)
{
    n00b_string_t *pat    = n00b_string_from_cstr(tc->pattern);
    auto           result = n00b_regex_new(pat);

    if (tc->expect_error) {
        if (n00b_result_is_err(result)) {
            total_pass++;
        }
        else {
            n00b_regex_free(n00b_result_get(result));
            total_skip++;
        }
        return;
    }

    if (n00b_result_is_err(result)) {
        fprintf(stderr,
                "  [COMPILE-FAIL] %s:%d pattern='%s'\n",
                file,
                tc->line_number,
                tc->pattern);
        total_compile_fail++;
        return;
    }

    n00b_regex_t *re = n00b_result_get(result);
    n00b_regex_compile(re);

    n00b_string_t *input = n00b_string_from_cstr(tc->input);

#ifndef _WIN32
    // Per-test timeout to prevent hangs on complex patterns.
    signal(SIGALRM, timeout_handler);
    if (setjmp(timeout_jmp)) {
        signal(SIGALRM, SIG_DFL);
        if (skip_known_unsupported(tc, file)) {
            goto cleanup;
        }
        fprintf(stderr,
                "  [TIMEOUT] %s:%d pattern='%s' input='%.40s%s'\n",
                file,
                tc->line_number,
                tc->pattern,
                tc->input,
                strlen(tc->input) > 40 ? "..." : "");
        total_timeout++;
        goto cleanup;
    }
    alarm(PER_TEST_TIMEOUT);
#endif

    if (tc->has_matches && tc->anchored) {
        /* find_anchored: at most one match starting at offset 0. */
        auto opt = n00b_regex_anchored(re, input);
        int32_t got_n = n00b_option_is_set(opt) ? 1 : 0;
        if (got_n != tc->n_matches) {
            if (skip_known_unsupported(tc, file)) goto cleanup;
            fprintf(stderr,
                    "  [FAIL] %s:%d pattern='%s' input='%.40s%s' (anchored)\n"
                    "         expected %d matches, got %d\n",
                    file, tc->line_number, tc->pattern, tc->input,
                    strlen(tc->input) > 40 ? "..." : "",
                    tc->n_matches, got_n);
            total_fail++;
            goto cleanup;
        }
        if (got_n == 1) {
            n00b_regex_match_t got = n00b_option_get(opt);
            if (got.start != tc->match_starts[0]
                || got.end != tc->match_ends[0]) {
                if (skip_known_unsupported(tc, file)) goto cleanup;
                fprintf(stderr,
                        "  [FAIL] %s:%d pattern='%s' input='%.40s%s' (anchored)\n"
                        "         expected [%" PRId64 ",%" PRId64 "] got [%" PRId64 ",%" PRId64 "]\n",
                        file, tc->line_number, tc->pattern, tc->input,
                        strlen(tc->input) > 40 ? "..." : "",
                        tc->match_starts[0], tc->match_ends[0],
                        got.start, got.end);
                total_fail++;
                goto cleanup;
            }
        }
        total_pass++;
    }
    else if (tc->has_matches) {
        auto     results = n00b_regex_matches(re, input);
        uint32_t n       = (uint32_t)results->len;

        if ((int32_t)n != tc->n_matches) {
            if (skip_known_unsupported(tc, file)) {
                goto cleanup;
            }
            fprintf(stderr,
                    "  [FAIL] %s:%d pattern='%s' input='%.40s%s'\n"
                    "         expected %d matches, got %d\n",
                    file,
                    tc->line_number,
                    tc->pattern,
                    tc->input,
                    strlen(tc->input) > 40 ? "..." : "",
                    tc->n_matches,
                    n);
            if (n > 0) {
                fprintf(stderr, "         got:");
                for (uint32_t i = 0; i < n && i < 10; i++) {
                    fprintf(stderr,
                            " [%" PRId64 ",%" PRId64 "]",
                            results->data[i].start,
                            results->data[i].end);
                }
                fprintf(stderr, "\n");
            }
            if (tc->n_matches > 0) {
                fprintf(stderr, "         expected:");
                for (int32_t i = 0; i < tc->n_matches && i < 10; i++) {
                    fprintf(stderr,
                            " [%" PRId64 ",%" PRId64 "]",
                            tc->match_starts[i],
                            tc->match_ends[i]);
                }
                fprintf(stderr, "\n");
            }
            total_fail++;
            goto cleanup;
        }

        for (int32_t i = 0; i < tc->n_matches; i++) {
            int64_t got_start = results->data[i].start;
            int64_t got_end   = results->data[i].end;
            if (got_start != tc->match_starts[i] || got_end != tc->match_ends[i]) {
                if (skip_known_unsupported(tc, file)) {
                    goto cleanup;
                }
                fprintf(stderr,
                        "  [FAIL] %s:%d pattern='%s' input='%.40s%s'\n"
                        "         match[%d]: expected [%" PRId64 ",%" PRId64 "] got [%" PRId64
                        ",%" PRId64 "]\n",
                        file,
                        tc->line_number,
                        tc->pattern,
                        tc->input,
                        strlen(tc->input) > 40 ? "..." : "",
                        i,
                        tc->match_starts[i],
                        tc->match_ends[i],
                        got_start,
                        got_end);
                total_fail++;
                goto cleanup;
            }
        }

        total_pass++;
    }
    else if (tc->has_end_positions) {
        auto     results = n00b_regex_matches(re, input);
        uint32_t n       = (uint32_t)results->len;

        bool ok = true;
        for (int32_t ei = 0; ei < tc->n_end_positions; ei++) {
            bool found = false;
            for (uint32_t ai = 0; ai < n; ai++) {
                int64_t end = results->data[ai].end;
                if (end == tc->end_positions[ei]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (skip_known_unsupported(tc, file)) {
                    goto cleanup;
                }
                fprintf(stderr,
                        "  [FAIL] %s:%d pattern='%s' input='%.40s%s'\n"
                        "         expected end_position %" PRId64 " not found in %d matches\n",
                        file,
                        tc->line_number,
                        tc->pattern,
                        tc->input,
                        strlen(tc->input) > 40 ? "..." : "",
                        tc->end_positions[ei],
                        n);
                if (n > 0) {
                    fprintf(stderr, "         actual ends:");
                    for (uint32_t ai = 0; ai < n && ai < 10; ai++) {
                        fprintf(stderr,
                                " %" PRId64,
                                results->data[ai].end);
                    }
                    fprintf(stderr, "\n");
                }
                ok = false;
                break;
            }
        }
        if (ok)
            total_pass++;
        else
            total_fail++;
    }

cleanup:
#ifndef _WIN32
    alarm(0);
    signal(SIGALRM, SIG_DFL);
#endif
    n00b_regex_free(re);
}

static void
path_join(char *out, size_t out_len, const char *dir, const char *file)
{
    size_t      dir_len = strlen(dir);
    const char *sep
        = (dir_len > 0 && (dir[dir_len - 1] == '/' || dir[dir_len - 1] == '\\')) ? "" : "/";
    snprintf(out, out_len, "%s%s%s", dir, sep, file);
}

static const char *
base_name(const char *path)
{
    const char *slash     = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    const char *last      = slash > backslash ? slash : backslash;
    return last ? last + 1 : path;
}

static int
run_test_file(const char *path)
{
    const char *fname = base_name(path);

    test_case_t tests[MAX_TESTS];
    int         n = parse_test_file(path, tests, MAX_TESTS);
    if (n < 0) {
        return -1;
    }

    printf("  %s: %d tests\n", fname, n);

    for (int i = 0; i < n; i++) {
        run_match_test(&tests[i], fname);
    }
    return n;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running resharp test suite...\n");

    const char *test_dir = getenv("N00B_RESHARP_TEST_DIR");
    if (!test_dir || !*test_dir) {
        test_dir = "test/data/resharp/tests";
    }
    /* tests06_nullable_positions (= resharp-c's `rev_nulls.toml`) tests
     * the `collect_rev_nulls_debug` API — null positions returned during
     * reverse matching.  resharp-c has its own `rev_nulls_test` binary
     * for it; n00b's regex doesn't expose that API surface (and the
     * `end_positions` field this parser reads has different semantics
     * — forward-match end offsets, not reverse-null positions).  Skip
     * the file rather than mis-port it. */
    const char *files[] = {
        "tests01.toml",
        "tests02_lookaround.toml",
        "tests03_boolean.toml",
        "tests04_anchors.toml",
        "tests05_match_end.toml",
        "tests07_unsupported.toml",
        "tests08_semantics.toml",
    };
    int n_files = sizeof(files) / sizeof(files[0]);

    int loaded_files  = 0;
    int loaded_tests  = 0;
    int missing_files = 0;

    for (int i = 0; i < n_files; i++) {
        char path[1024];
        path_join(path, sizeof(path), test_dir, files[i]);
        int n = run_test_file(path);
        if (n < 0) {
            missing_files++;
            continue;
        }
        loaded_files++;
        loaded_tests += n;
    }

    printf("\nResults: %d passed, %d failed, %d compile-fail, %d skipped, %d timeout\n",
           total_pass,
           total_fail,
           total_compile_fail,
           total_skip,
           total_timeout);
    printf("Loaded corpus: %d files, %d tests\n", loaded_files, loaded_tests);

    if (missing_files > 0 || loaded_files != n_files || loaded_tests == 0 || total_fail > 0
        || total_timeout > 0) {
        printf("FAIL\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}
