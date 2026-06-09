/* test/unit/test_rocs_wax_demo_smoke.c - WP-013 Phase 5 demo smoke. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/print.h"
#include "conduit/subproc.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/file.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/path.h"

#define ROCS_WAX_DEMO_SKIP 77

#ifndef ROCS_TEST_SOURCE_ROOT
#define ROCS_TEST_SOURCE_ROOT "."
#endif

#ifndef ROCS_WAX_CACHE_TOOL_PATH
#define ROCS_WAX_CACHE_TOOL_PATH "n00b-rocs-wax-cache"
#endif

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    int            exit_code;
    n00b_string_t *out;
    n00b_string_t *err;
} wax_demo_run_t;

static n00b_string_t *cache_env_dir = nullptr;

static bool
string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static int
skip(n00b_string_t *reason)
{
    n00b_printf("[SKIP] [|#|]", reason);
    return ROCS_WAX_DEMO_SKIP;
}

static n00b_string_t *
repo_file(n00b_string_t *rel)
{
    return n00b_unicode_str_cat(n00b_string_from_cstr(ROCS_TEST_SOURCE_ROOT),
                                rel);
}

static n00b_string_t *
daemon_fixture(void)
{
    return repo_file(r"/test/unit/data/rocs_wax/daemon_events.ndjson");
}

static n00b_string_t *
live_fixture(void)
{
    return repo_file(r"/test/unit/data/rocs_wax/live_events.ndjson");
}

static n00b_string_t *
demo_doc(void)
{
    return repo_file(r"/docs/rocs_wax_demo.md");
}

static n00b_string_t *
new_tmpdir(n00b_string_t *prefix)
{
    auto tmp_r = n00b_new_temp_dir(prefix, nullptr);
    CHECK(n00b_result_is_ok(tmp_r));
    return n00b_result_get(tmp_r);
}

static void
cleanup_tmpdir(n00b_string_t *path)
{
    auto rm_r = n00b_path_remove_tree(path, .ignore_missing = true);
    CHECK(n00b_result_is_ok(rm_r));
}

static void
configure_cache_env(n00b_string_t *cache_dir, n00b_string_t *name)
{
    cache_env_dir = cache_dir;
    CHECK(n00b_putenv(r"ROCS_PROFILE", r"service_local"));
    CHECK(n00b_putenv(r"ROCS_NAME", name));
    CHECK(n00b_putenv(r"ROCS_CACHE_DIR", cache_dir));
}

static n00b_array_t(n00b_string_t *) *
tool_args(uint64_t count)
{
    n00b_array_t(n00b_string_t *) *args =
        n00b_alloc(n00b_array_t(n00b_string_t *));
    *args = n00b_array_new(n00b_string_t *, count);
    return args;
}

static void
tool_arg_set(n00b_array_t(n00b_string_t *) *args,
             uint64_t                       index,
             n00b_string_t                 *value)
{
    n00b_array_set(*args, index, value);
}

static n00b_array_t(n00b_string_t *) *
tool_env(n00b_string_t *name)
{
    n00b_array_t(n00b_string_t *) *env =
        n00b_alloc(n00b_array_t(n00b_string_t *));
    *env = n00b_array_new(n00b_string_t *, 4);
    n00b_array_set(*env, 0, r"ROCS_PROFILE=service_local");
    n00b_array_set(*env, 1, n00b_cformat("ROCS_NAME=«#»", name));
    n00b_array_set(*env,
                   2,
                   n00b_cformat("ROCS_CACHE_DIR=«#»", cache_env_dir));
    n00b_array_set(*env, 3, r"N00B_TEST=1");
    return env;
}

static n00b_string_t *
buffer_string(n00b_buffer_t *buf)
{
    if (buf == nullptr || buf->byte_len == 0) {
        return r"";
    }
    return n00b_buffer_to_string(n00b_buffer_copy(buf));
}

static wax_demo_run_t
run_tool(n00b_array_t(n00b_string_t *) *args, n00b_string_t *name)
{
    n00b_conduit_t            *conduit = nullptr;
    n00b_conduit_io_backend_t *io      = nullptr;
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    conduit = n00b_result_get(conduit_r);

    auto io_r = n00b_conduit_io_new_default(conduit);
    CHECK(n00b_result_is_ok(io_r));
    io = n00b_result_get(io_r);

    n00b_subproc_t sp = {};
    n00b_subproc_init(&sp,
                      .cmd            = n00b_string_from_cstr(
                          ROCS_WAX_CACHE_TOOL_PATH),
                      .conduit        = conduit,
                      .io             = io,
                      .args           = args,
                      .env            = tool_env(name),
                      .capture_stdout = true,
                      .capture_stderr = true,
                      .merge          = false);

    auto run_r = n00b_subproc_run(&sp);
    CHECK(n00b_result_is_ok(run_r));

    auto code_r = n00b_subproc_exit_code(&sp);
    CHECK(n00b_result_is_ok(code_r));

    wax_demo_run_t result = {
        .exit_code = n00b_result_get(code_r),
        .out       = buffer_string(n00b_subproc_stdout(&sp)),
        .err       = buffer_string(n00b_subproc_stderr(&sp)),
    };

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(conduit);
    return result;
}

static void
check_run_ok(wax_demo_run_t run, n00b_string_t *label)
{
    if (run.exit_code != 0) {
        n00b_eprintf("command failed for «#»: out=«#» err=«#»",
                     label,
                     run.out,
                     run.err);
    }
    CHECK(run.exit_code == 0);
}

static n00b_string_t *
read_text(n00b_string_t *path)
{
    auto open_r = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    CHECK(n00b_result_is_ok(open_r));

    n00b_file_t *file = n00b_result_get(open_r);
    auto buf_r = n00b_file_as_buffer(file);
    CHECK(n00b_result_is_ok(buf_r));
    n00b_string_t *text =
        n00b_buffer_to_string(n00b_buffer_copy(n00b_result_get(buf_r)));
    n00b_file_close(file);
    return text;
}

static void
test_doc_mentions_demo_surface(void)
{
    n00b_string_t *doc = read_text(demo_doc());
    CHECK(n00b_unicode_str_contains(doc, r"n00b-rocs-wax-cache"));
    CHECK(n00b_unicode_str_contains(doc, r"--run-fixture"));
    CHECK(n00b_unicode_str_contains(doc, r"--search"));
    CHECK(n00b_unicode_str_contains(doc, r"--live"));
    CHECK(n00b_unicode_str_contains(doc, r"ROCS_WAX_GATEWAY_NDJSON"));
    n00b_printf("  [PASS] demo doc covers cache, search, live, and optional replay");
}

static void
run_fixture_replay(n00b_string_t *root, n00b_string_t *name, n00b_string_t *src)
{
    n00b_array_t(n00b_string_t *) *args = tool_args(3);
    tool_arg_set(args, 0, r"--run-fixture");
    tool_arg_set(args, 1, src);
    tool_arg_set(args, 2, n00b_path_join_v(root, r"checkpoint.txt"));

    wax_demo_run_t run = run_tool(args, name);
    check_run_ok(run, r"run-fixture");
    CHECK(n00b_unicode_str_contains(run.out, r"ingested="));
    CHECK(n00b_unicode_str_contains(run.out, r"checkpoint="));
}

static void
test_fixture_demo_end_to_end(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_demo_");
    n00b_string_t *name = r"rocs-wax-demo-smoke";
    configure_cache_env(root, name);

    n00b_array_t(n00b_string_t *) *check = tool_args(1);
    tool_arg_set(check, 0, r"--check-config");
    wax_demo_run_t run = run_tool(check, name);
    check_run_ok(run, r"check-config");
    CHECK(n00b_unicode_str_contains(run.out, r"config ok"));

    run_fixture_replay(root, name, daemon_fixture());

    n00b_array_t(n00b_string_t *) *finite = tool_args(5);
    tool_arg_set(finite, 0, r"--search");
    tool_arg_set(finite, 1, r"--contains");
    tool_arg_set(finite, 2, r"codex");
    tool_arg_set(finite, 3, r"--format");
    tool_arg_set(finite, 4, r"jsonl");
    run = run_tool(finite, name);
    check_run_ok(run, r"finite-search");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:ai:1"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:daemon:proc:1"));

    n00b_array_t(n00b_string_t *) *table = tool_args(5);
    tool_arg_set(table, 0, r"--search");
    tool_arg_set(table, 1, r"--kind");
    tool_arg_set(table, 2, r"file.modify");
    tool_arg_set(table, 3, r"--format");
    tool_arg_set(table, 4, r"table");
    run = run_tool(table, name);
    check_run_ok(run, r"table-search");
    CHECK(n00b_unicode_str_contains(run.out, r"event_id"));
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:file:1"));

    n00b_array_t(n00b_string_t *) *live = tool_args(10);
    tool_arg_set(live, 0, r"--search");
    tool_arg_set(live, 1, r"--live");
    tool_arg_set(live, 2, r"--live-fixture");
    tool_arg_set(live, 3, live_fixture());
    tool_arg_set(live, 4, r"--contains");
    tool_arg_set(live, 5, r"codex");
    tool_arg_set(live, 6, r"--format");
    tool_arg_set(live, 7, r"jsonl");
    tool_arg_set(live, 8, r"--limit");
    tool_arg_set(live, 9, r"10");
    run = run_tool(live, name);
    check_run_ok(run, r"live-search");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:ai:1"));
    CHECK(n00b_unicode_str_contains(run.out, r"wax:live:ai:2"));
    CHECK(n00b_unicode_str_contains(run.err, r"ingested=3"));
    CHECK(n00b_unicode_str_contains(run.err, r"rejected=1"));
    CHECK(n00b_unicode_str_contains(run.err, r"resume="));

    n00b_array_t(n00b_string_t *) *all = tool_args(3);
    tool_arg_set(all, 0, r"--search");
    tool_arg_set(all, 1, r"--format");
    tool_arg_set(all, 2, r"jsonl");
    run = run_tool(all, name);
    check_run_ok(run, r"cache-after-live");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:proc:1"));
    CHECK(n00b_unicode_str_contains(run.out, r"wax:live:proc:2"));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] fixture replay, finite search, live search, and cleanup");
}

static int
run_optional_gateway_replay(void)
{
    n00b_string_t *capture = n00b_getenv(r"ROCS_WAX_GATEWAY_NDJSON");
    if (string_empty(capture)) {
        return skip(r"ROCS_WAX_GATEWAY_NDJSON not set");
    }

    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_gateway_");
    n00b_string_t *name = r"rocs-wax-gateway-optional";
    configure_cache_env(root, name);

    run_fixture_replay(root, name, capture);

    n00b_array_t(n00b_string_t *) *args = tool_args(3);
    tool_arg_set(args, 0, r"--search");
    tool_arg_set(args, 1, r"--format");
    tool_arg_set(args, 2, r"jsonl");
    wax_demo_run_t run = run_tool(args, name);
    check_run_ok(run, r"optional-gateway-search");
    if (!n00b_unicode_str_contains(run.out, r"wax.normalized.v1")) {
        cleanup_tmpdir(root);
        return skip(r"gateway capture produced no accepted normalized records");
    }

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] optional gateway capture replay");
    return 0;
}

static int
run_mandatory_demo(void)
{
    n00b_printf("test_rocs_wax_demo_smoke:");
    test_doc_mentions_demo_surface();
    test_fixture_demo_end_to_end();
    return 0;
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    int rc = 0;
    if (argc == 2 && n00b_unicode_str_eq(n00b_string_from_cstr(argv[1]),
                                         r"--gateway")) {
        rc = run_optional_gateway_replay();
    }
    else {
        rc = run_mandatory_demo();
    }

    n00b_shutdown();
    return rc;
}
