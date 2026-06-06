#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_layout.h"
#include "compiler/objfile/elf_rewrite_admit.h"

#include "objfile_elf_casegen.h"

#if defined(_WIN32)

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("  [SKIP] objfile_elf_oracle is POSIX-only for now.\n");
    return 0;
}

#else

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    int  exit_status;
    char output[4096];
} oracle_run_result_t;

static bool
env_is_one(const char *name)
{
    const char *value = getenv(name);
    return value != nullptr && strcmp(value, "1") == 0;
}

static bool
path_join(char *out, size_t out_len, const char *base, const char *suffix)
{
    int n = snprintf(out, out_len, "%s/%s", base, suffix);
    return n >= 0 && (size_t)n < out_len;
}

static bool
file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static bool
case_filter_matches(const char *filter, const char *name)
{
    if (filter == nullptr || filter[0] == '\0') {
        return true;
    }

    const char *p = filter;
    while (*p != '\0') {
        while (*p == ',' || *p == ' ') {
            p++;
        }

        const char *start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }

        const char *end = p;
        while (end > start && end[-1] == ' ') {
            end--;
        }

        size_t len = (size_t)(end - start);
        if (strlen(name) == len && strncmp(start, name, len) == 0) {
            return true;
        }
    }

    return false;
}

static bool
parse_succeeds(n00b_buffer_t *buf)
{
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            result = n00b_elf_parse(stream);

    return n00b_result_is_ok(result);
}

static n00b_string_t *
admission_request_name(n00b_test_elf_admission_request_t request)
{
    switch (request) {
    case N00B_TEST_ELF_ADMISSION_NONE:
        return r"none";
    case N00B_TEST_ELF_ADMISSION_RELAXED_EOF:
        return r"relaxed-eof";
    case N00B_TEST_ELF_ADMISSION_STRICT_EOF:
        return r"strict-eof";
    case N00B_TEST_ELF_ADMISSION_RELAXED_PREFERRED_GAP:
        return r"relaxed-preferred-gap";
    case N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_PRESERVE:
        return r"relaxed-overlay-preserve";
    case N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_APPEND:
        return r"relaxed-overlay-append";
    }

    return r"none";
}

static n00b_elf_rewrite_admit_metadata_request_t
admission_request_make(n00b_test_elf_admission_request_t request)
{
    n00b_elf_rewrite_admit_metadata_request_t admission = {
        .section_name    = r".n00b.test",
        .payload_size    = 16,
        .file_alignment  = 8,
        .section_type    = SHT_PROGBITS,
        .section_flags   = 0,
        .policy          = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };

    switch (request) {
    case N00B_TEST_ELF_ADMISSION_STRICT_EOF:
        admission.policy.flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION;
        break;
    case N00B_TEST_ELF_ADMISSION_RELAXED_PREFERRED_GAP:
        admission.preferred_file_offset = n00b_option_set(uint64_t, 288);
        admission.file_alignment        = 16;
        break;
    case N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_APPEND:
        admission.policy.flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;
        break;
    case N00B_TEST_ELF_ADMISSION_NONE:
    case N00B_TEST_ELF_ADMISSION_RELAXED_EOF:
    case N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_PRESERVE:
        break;
    }

    return admission;
}

static void
print_admission_facts(const n00b_test_elf_case_t *test_case,
                      n00b_buffer_t              *buf)
{
    if (!n00b_test_elf_case_has_admission(test_case)) {
        return;
    }

    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            parsed = n00b_elf_parse(stream);

    if (n00b_result_is_err(parsed)) {
        n00b_printf("    n00b_admission=side-by-side parse-error "
                    "request=«#» expected_outcome=«#» expected_reason=«#»",
                    admission_request_name(test_case->admission_request),
                    n00b_elf_rewrite_admit_outcome_str(
                        test_case->admission_outcome),
                    n00b_elf_rewrite_admit_rejection_reason_str(
                        test_case->admission_reason));
        return;
    }

    n00b_elf_rewrite_admit_metadata_request_t request =
        admission_request_make(test_case->admission_request);
    auto result = n00b_elf_rewrite_admit_metadata_insert(n00b_result_get(parsed),
                                                         &request);
    if (n00b_result_is_err(result)) {
        n00b_printf("    n00b_admission=side-by-side api-error=«#» "
                    "request=«#» expected_outcome=«#» expected_reason=«#»",
                    n00b_elf_rewrite_admit_err_str(n00b_result_get_err(result)),
                    admission_request_name(test_case->admission_request),
                    n00b_elf_rewrite_admit_outcome_str(
                        test_case->admission_outcome),
                    n00b_elf_rewrite_admit_rejection_reason_str(
                        test_case->admission_reason));
        return;
    }

    n00b_elf_rewrite_admit_result_t admit = n00b_result_get(result);
    n00b_elf_rewrite_admit_placement_kind_t placement_kind =
        N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE;
    if (n00b_option_is_set(admit.placement)) {
        n00b_elf_rewrite_admit_placement_t placement =
            n00b_option_get(admit.placement);
        placement_kind = placement.kind;
    }

    n00b_printf("    n00b_admission=side-by-side request=«#» outcome=«#» "
                "reason=«#» placement=«#» expected_outcome=«#» "
                "expected_reason=«#» expected_placement=«#»",
                admission_request_name(test_case->admission_request),
                n00b_elf_rewrite_admit_outcome_str(admit.outcome),
                n00b_elf_rewrite_admit_rejection_reason_str(
                    admit.rejection_reason),
                n00b_elf_rewrite_admit_placement_kind_str(placement_kind),
                n00b_elf_rewrite_admit_outcome_str(
                    test_case->admission_outcome),
                n00b_elf_rewrite_admit_rejection_reason_str(
                    test_case->admission_reason),
                n00b_elf_rewrite_admit_placement_kind_str(
                    test_case->admission_placement));
}

static void
print_layout_facts(const n00b_test_elf_case_t *test_case, n00b_buffer_t *buf)
{
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            parsed = n00b_elf_parse(stream);

    if (n00b_result_is_err(parsed)) {
        printf("    n00b_layout=parse-error\n");
        return;
    }

    auto layout_res = n00b_elf_layout_build(n00b_result_get(parsed));
    if (n00b_result_is_err(layout_res)) {
        printf("    n00b_layout=layout-error:%d\n",
               n00b_result_get_err(layout_res));
        return;
    }

    n00b_elf_layout_t *layout = n00b_result_get(layout_res);
    printf("    n00b_layout=file_size=%llu file_intervals=%llu "
           "vaddr_intervals=%llu coverage=%llu\n",
           (unsigned long long)layout->file_size,
           (unsigned long long)layout->file_interval_count,
           (unsigned long long)layout->vaddr_interval_count,
           (unsigned long long)layout->coverage_count);

    if (strcmp(test_case->name, "phtab_not_in_load") == 0) {
        auto collision = n00b_elf_layout_file_collision(layout, 64, 120);
        if (n00b_result_is_ok(collision)) {
            n00b_elf_layout_collision_t c = n00b_result_get(collision);
            printf("    n00b_fact=phtab_file_collision_count:%llu\n",
                   (unsigned long long)c.interval_count);
        }
    }
    else if (strcmp(test_case->name, "entry_in_mem_not_file") == 0) {
        auto file = n00b_elf_layout_file_overlap(layout, 0x101, 0x102);
        auto mem  = n00b_elf_layout_vaddr_overlap(layout, 0x400101, 0x400102);

        if (n00b_result_is_ok(file) && n00b_result_is_ok(mem)) {
            n00b_option_t(n00b_elf_layout_interval_node_t *) file_opt =
                n00b_result_get(file);
            n00b_option_t(n00b_elf_layout_interval_node_t *) mem_opt =
                n00b_result_get(mem);
            printf("    n00b_fact=entry_file_backed:%s entry_memory_mapped:%s\n",
                   n00b_option_is_set(file_opt) ? "yes" : "no",
                   n00b_option_is_set(mem_opt) ? "yes" : "no");
        }
    }
    else if (strcmp(test_case->name, "pt_phdr_bad_size") == 0) {
        auto collision = n00b_elf_layout_file_collision(layout, 64, 176);
        if (n00b_result_is_ok(collision)) {
            n00b_elf_layout_collision_t c = n00b_result_get(collision);
            printf("    n00b_fact=pt_phdr_probe_collision_count:%llu\n",
                   (unsigned long long)c.interval_count);
        }
    }
    else if (strcmp(test_case->name, "shstrtab_not_terminated") == 0) {
        auto overlaps = n00b_elf_layout_file_overlaps(layout, 384, 394);
        if (n00b_result_is_ok(overlaps)) {
            n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);
            printf("    n00b_fact=shstrtab_interval_count:%llu\n",
                   (unsigned long long)list.count);
        }
    }
}

static bool
write_fixture_file(const n00b_test_elf_case_t *test_case,
                   n00b_buffer_t              *buf,
                   char                       *path,
                   size_t                      path_len)
{
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == nullptr || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }

    int n = snprintf(path,
                     path_len,
                     "%s/n00b_elf_oracle_%ld_%s.elf",
                     tmpdir,
                     (long)getpid(),
                     test_case->name);
    if (n < 0 || (size_t)n >= path_len) {
        return false;
    }

    FILE *f = fopen(path, "wb");
    if (f == nullptr) {
        return false;
    }

    size_t written = fwrite(buf->data, 1, n00b_buffer_len(buf), f);
    int    err     = ferror(f);
    int    closed  = fclose(f);

    return written == n00b_buffer_len(buf) && err == 0 && closed == 0;
}

static oracle_run_result_t
run_argv(char *const argv[])
{
    oracle_run_result_t result = {
        .exit_status = 127,
    };

    int fds[2];
    if (pipe(fds) != 0) {
        snprintf(result.output, sizeof(result.output), "pipe failed: %s\n",
                 strerror(errno));
        return result;
    }

    pid_t pid = fork();
    if (pid < 0) {
        snprintf(result.output, sizeof(result.output), "fork failed: %s\n",
                 strerror(errno));
        close(fds[0]);
        close(fds[1]);
        return result;
    }

    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);

        execvp(argv[0], argv);
        _exit(127);
    }

    close(fds[1]);

    size_t used = 0;
    while (used + 1 < sizeof(result.output)) {
        ssize_t n = read(fds[0],
                         result.output + used,
                         sizeof(result.output) - used - 1);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
    }
    result.output[used] = '\0';
    close(fds[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        result.exit_status = 127;
        return result;
    }

    if (WIFEXITED(status)) {
        result.exit_status = WEXITSTATUS(status);
    }
    else {
        result.exit_status = 128;
    }

    return result;
}

static oracle_run_result_t
run_oracle(const char *oracle_bin, const char *mode, const char *fixture_path)
{
    char *const argv[] = {
        (char *)oracle_bin,
        (char *)"--mode",
        (char *)mode,
        (char *)fixture_path,
        nullptr,
    };

    return run_argv(argv);
}

static void
remove_auto_oracle_files(const char *bin, const char *dir)
{
    if (bin != nullptr && bin[0] != '\0') {
        unlink(bin);
    }

    if (dir != nullptr && dir[0] != '\0') {
        rmdir(dir);
    }
}

#if defined(__linux__) && defined(__x86_64__)
static bool
build_oracle_from_root(const char *root,
                       char       *out_bin,
                       size_t      out_bin_len,
                       char       *out_dir,
                       size_t      out_dir_len)
{
    char zerocool_dir[512];
    char read_target_c[512];
    char phtab_adjustment_c[512];
    char patch_x86_64_c[512];
    char interval_tree_c[512];
    char zerocool_c[512];

    if (!path_join(zerocool_dir, sizeof(zerocool_dir), root, "zerocool") ||
        !path_join(read_target_c,
                   sizeof(read_target_c),
                   zerocool_dir,
                   "read_target_elf.c") ||
        !path_join(phtab_adjustment_c,
                   sizeof(phtab_adjustment_c),
                   zerocool_dir,
                   "phtab_adjustment.c") ||
        !path_join(patch_x86_64_c,
                   sizeof(patch_x86_64_c),
                   zerocool_dir,
                   "patch_x86_64.c") ||
        !path_join(interval_tree_c,
                   sizeof(interval_tree_c),
                   zerocool_dir,
                   "interval_tree.c") ||
        !path_join(zerocool_c, sizeof(zerocool_c), zerocool_dir, "zerocool.c")) {
        printf("  [FAIL] N00B_ELF_ORACLE_ROOT path is too long.\n");
        return false;
    }

    if (!file_exists(read_target_c) ||
        !file_exists(phtab_adjustment_c) ||
        !file_exists(patch_x86_64_c) ||
        !file_exists(interval_tree_c) ||
        !file_exists(zerocool_c)) {
        printf("  [FAIL] N00B_ELF_ORACLE_ROOT does not look like Brandon's "
               "packager root: %s\n",
               root);
        return false;
    }

    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == nullptr || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }

    int n = snprintf(out_dir,
                     out_dir_len,
                     "%s/n00b_elf_oracle_build_XXXXXX",
                     tmpdir);
    if (n < 0 || (size_t)n >= out_dir_len) {
        printf("  [FAIL] oracle build directory path is too long.\n");
        return false;
    }

    if (mkdtemp(out_dir) == nullptr) {
        printf("  [FAIL] could not create oracle build directory %s: %s\n",
               out_dir,
               strerror(errno));
        out_dir[0] = '\0';
        return false;
    }

    if (!path_join(out_bin, out_bin_len, out_dir, "brandon_read_target_oracle")) {
        printf("  [FAIL] oracle binary path is too long.\n");
        remove_auto_oracle_files(nullptr, out_dir);
        out_dir[0] = '\0';
        return false;
    }

    char include_arg[640];
    n = snprintf(include_arg, sizeof(include_arg), "-I%s", zerocool_dir);
    if (n < 0 || (size_t)n >= sizeof(include_arg)) {
        printf("  [FAIL] oracle include path is too long.\n");
        remove_auto_oracle_files(out_bin, out_dir);
        out_bin[0] = '\0';
        out_dir[0] = '\0';
        return false;
    }

    const char *cc = getenv("CC");
    if (cc == nullptr || cc[0] == '\0') {
        cc = "cc";
    }

    char *const argv[] = {
        (char *)cc,
        (char *)"-std=gnu99",
        (char *)"-Wall",
        (char *)"-Wextra",
        (char *)"-Wno-unused-parameter",
        include_arg,
        (char *)"test/fixtures/elf/oracle/brandon_read_target_oracle.c",
        read_target_c,
        phtab_adjustment_c,
        patch_x86_64_c,
        interval_tree_c,
        zerocool_c,
        (char *)"-o",
        out_bin,
        nullptr,
    };

    oracle_run_result_t build = run_argv(argv);
    if (build.exit_status != 0) {
        printf("  [FAIL] could not build Brandon oracle helper "
               "(exit %d):\n%s\n",
               build.exit_status,
               build.output);
        remove_auto_oracle_files(out_bin, out_dir);
        out_bin[0] = '\0';
        out_dir[0] = '\0';
        return false;
    }

    return true;
}
#else
static bool
build_oracle_from_root(const char *root,
                       char       *out_bin,
                       size_t      out_bin_len,
                       char       *out_dir,
                       size_t      out_dir_len)
{
    (void)root;
    (void)out_bin;
    (void)out_bin_len;
    (void)out_dir;
    (void)out_dir_len;

    printf("  [FAIL] N00B_ELF_ORACLE_ROOT auto-build is Linux/x86-64 only; "
           "set N00B_ELF_ORACLE_BIN to a prebuilt helper on this host.\n");
    return false;
}
#endif

static void
cleanup_auto_oracle(const char *bin, const char *dir)
{
    if (env_is_one("N00B_ELF_ORACLE_KEEP_TMP")) {
        printf("  [INFO] kept oracle helper %s\n", bin);
        return;
    }

    remove_auto_oracle_files(bin, dir);
}

static bool
extract_verdict(const char *output, char *verdict, size_t verdict_len)
{
    const char *p = strstr(output, "verdict=");
    if (p == nullptr) {
        return false;
    }

    p += strlen("verdict=");

    size_t i = 0;
    while (p[i] != '\0' && p[i] != '\n' && p[i] != '\r') {
        if (i + 1 >= verdict_len) {
            return false;
        }

        verdict[i] = p[i];
        i++;
    }

    verdict[i] = '\0';
    return i > 0;
}

static bool
extract_numeric_code(const char *output, int *out_code)
{
    const char *p = strstr(output, "code=");
    if (p == nullptr) {
        return false;
    }

    p += strlen("code=");
    if (*p < '0' || *p > '9') {
        return false;
    }

    int code = 0;
    while (*p >= '0' && *p <= '9') {
        int digit = *p - '0';

        if (code > (INT32_MAX - digit) / 10) {
            return false;
        }

        code = code * 10 + digit;
        p++;
    }

    if (*p != '\0' && *p != '\n' && *p != '\r') {
        return false;
    }

    *out_code = code;
    return true;
}

static bool
run_oracle_case(const char *oracle_bin, const n00b_test_elf_case_t *test_case)
{
    if (test_case->oracle_mode == N00B_TEST_ELF_ORACLE_NONE) {
        fprintf(stderr, "Case %s has no oracle mode.\n", test_case->name);
        return false;
    }

    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    if (buf == nullptr) {
        fprintf(stderr, "Could not generate case %s.\n", test_case->name);
        return false;
    }

    bool n00b_parse_ok = parse_succeeds(buf);

    char fixture_path[512];
    if (!write_fixture_file(test_case, buf, fixture_path, sizeof(fixture_path))) {
        fprintf(stderr, "Could not write fixture for %s.\n", test_case->name);
        return false;
    }

    const char *mode = n00b_test_elf_oracle_mode_arg(test_case->oracle_mode);
    oracle_run_result_t oracle = run_oracle(oracle_bin, mode, fixture_path);

    if (!env_is_one("N00B_ELF_ORACLE_KEEP_TMP")) {
        unlink(fixture_path);
    }
    else {
        printf("  [INFO] kept %s\n", fixture_path);
    }

    if (oracle.exit_status != 0) {
        fprintf(stderr,
                "Oracle failed for %s with exit status %d:\n%s\n",
                test_case->name,
                oracle.exit_status,
                oracle.output);
        return false;
    }

    char verdict[128];
    if (!extract_verdict(oracle.output, verdict, sizeof(verdict))) {
        fprintf(stderr,
                "Oracle output for %s did not contain verdict=...:\n%s\n",
                test_case->name,
                oracle.output);
        return false;
    }

    const char *expected = n00b_test_elf_oracle_expect_name(test_case->oracle_expect);
    if (strcmp(verdict, expected) != 0) {
        fprintf(stderr,
                "Oracle verdict mismatch for %s: expected %s, got %s\n%s\n",
                test_case->name,
                expected,
                verdict,
                oracle.output);
        return false;
    }

    if (n00b_test_elf_case_has_oracle_code(test_case)) {
        int code = 0;

        if (!extract_numeric_code(oracle.output, &code)) {
            fprintf(stderr,
                    "Oracle output for %s did not contain numeric code=...:\n%s\n",
                    test_case->name,
                    oracle.output);
            return false;
        }

        if (code != test_case->oracle_expected_code) {
            fprintf(stderr,
                    "Oracle code mismatch for %s: expected %d, got %d\n%s\n",
                    test_case->name,
                    test_case->oracle_expected_code,
                    code,
                    oracle.output);
            return false;
        }
    }

    printf("  [PASS] %s n00b_parse=%s oracle=%s state=%s divergence=%s\n",
           test_case->name,
           n00b_parse_ok ? "ok" : "reject",
           verdict,
           n00b_test_elf_case_state_name(test_case->state),
           n00b_test_elf_divergence_name(test_case->divergence));
    print_admission_facts(test_case, buf);
    print_layout_facts(test_case, buf);
    return true;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    if (!env_is_one("N00B_TEST_ELF_ORACLE")) {
        printf("  [SKIP] N00B_TEST_ELF_ORACLE!=1\n");
        return 0;
    }

    const char *oracle_bin = getenv("N00B_ELF_ORACLE_BIN");
    bool        auto_built = false;
    char        auto_bin[512];
    char        auto_dir[512];

    if (oracle_bin == nullptr || oracle_bin[0] == '\0') {
        const char *root = getenv("N00B_ELF_ORACLE_ROOT");
        if (root == nullptr || root[0] == '\0') {
            printf("  [FAIL] N00B_TEST_ELF_ORACLE=1 but neither "
                   "N00B_ELF_ORACLE_BIN nor N00B_ELF_ORACLE_ROOT is set.\n");
            return 1;
        }

        if (!build_oracle_from_root(root,
                                    auto_bin,
                                    sizeof(auto_bin),
                                    auto_dir,
                                    sizeof(auto_dir))) {
            return 1;
        }

        oracle_bin = auto_bin;
        auto_built = true;
    }

    if (access(oracle_bin, X_OK) != 0) {
        printf("  [FAIL] N00B_ELF_ORACLE_BIN is not executable: %s\n",
               oracle_bin);
        if (auto_built) {
            cleanup_auto_oracle(auto_bin, auto_dir);
        }
        return 1;
    }

    const char *filter = getenv("N00B_ELF_ORACLE_CASE");
    size_t      ran    = 0;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];

        if (!case_filter_matches(filter, test_case->name)) {
            continue;
        }

        if (test_case->oracle_mode == N00B_TEST_ELF_ORACLE_NONE) {
            if (filter != nullptr && filter[0] != '\0') {
                fprintf(stderr, "Requested case %s has no oracle mode.\n",
                        test_case->name);
                return 1;
            }
            continue;
        }

        if (!run_oracle_case(oracle_bin, test_case)) {
            if (auto_built) {
                cleanup_auto_oracle(auto_bin, auto_dir);
            }
            return 1;
        }
        ran++;
    }

    if (filter != nullptr && filter[0] != '\0' && ran == 0) {
        fprintf(stderr, "No oracle cases matched N00B_ELF_ORACLE_CASE=%s\n",
                filter);
        if (auto_built) {
            cleanup_auto_oracle(auto_bin, auto_dir);
        }
        return 1;
    }

    printf("ELF oracle checks passed (%zu cases).\n", ran);
    if (auto_built) {
        cleanup_auto_oracle(auto_bin, auto_dir);
    }

    return 0;
}

#endif
