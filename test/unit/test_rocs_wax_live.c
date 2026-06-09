/* test/unit/test_rocs_wax_live.c - WP-013 Phase 4 wax live CLI mode. */

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

#include <rocs/n00b_rocs.h>
#include <rocs/wax.h>

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
} wax_live_run_t;

#define CHECK_RUN_OK(run, label)                                               \
    do {                                                                       \
        if ((run).exit_code != 0) {                                            \
            n00b_eprintf("command failed for «#»: out=«#» err=«#»",           \
                         (label),                                             \
                         (run).out,                                           \
                         (run).err);                                          \
        }                                                                      \
        CHECK((run).exit_code == 0);                                           \
    } while (0)

static n00b_string_t *cache_env_dir = nullptr;

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
write_text(n00b_string_t *path, n00b_string_t *text)
{
    auto open_r = n00b_file_open(path, .mode = N00B_FILE_W);
    CHECK(n00b_result_is_ok(open_r));

    n00b_buffer_t *buf = n00b_buffer_from_bytes(text->data,
                                                (int64_t)text->u8_bytes);
    auto write_r = n00b_file_write_all(n00b_result_get(open_r), buf);
    CHECK(n00b_result_is_ok(write_r));

    auto close_r = n00b_file_close_result(n00b_result_get(open_r));
    CHECK(n00b_result_is_ok(close_r));
}

static void
set_env(n00b_string_t *key, n00b_string_t *value)
{
    CHECK(n00b_putenv(key, value));
}

static void
configure_cache_env(n00b_string_t *cache_dir)
{
    cache_env_dir = cache_dir;
    set_env(r"ROCS_PROFILE", r"service_local");
    set_env(r"ROCS_NAME", r"rocs-wax-live-test");
    set_env(r"ROCS_CACHE_DIR", cache_dir);
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

static n00b_conduit_t *
new_conduit(void)
{
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    return n00b_result_get(conduit_r);
}

static n00b_conduit_io_backend_t *
new_io(n00b_conduit_t *conduit)
{
    auto io_r = n00b_conduit_io_new_default(conduit);
    CHECK(n00b_result_is_ok(io_r));
    return n00b_result_get(io_r);
}

static n00b_string_t *
buffer_string(n00b_buffer_t *buf)
{
    if (buf == nullptr || buf->byte_len == 0) {
        return r"";
    }
    return n00b_buffer_to_string(n00b_buffer_copy(buf));
}

static n00b_array_t(n00b_string_t *) *
tool_env(void)
{
    n00b_array_t(n00b_string_t *) *env =
        n00b_alloc(n00b_array_t(n00b_string_t *));
    *env = n00b_array_new(n00b_string_t *, 4);
    n00b_array_set(*env, 0, r"ROCS_PROFILE=service_local");
    n00b_array_set(*env, 1, r"ROCS_NAME=rocs-wax-live-test");
    n00b_array_set(*env,
                   2,
                   n00b_cformat("ROCS_CACHE_DIR=«#»", cache_env_dir));
    n00b_array_set(*env, 3, r"N00B_TEST=1");
    return env;
}

static wax_live_run_t
run_tool(n00b_array_t(n00b_string_t *) *args)
{
    n00b_conduit_t            *conduit = new_conduit();
    n00b_conduit_io_backend_t *io      = new_io(conduit);
    n00b_subproc_t             sp      = {};

    n00b_subproc_init(&sp,
                      .cmd            = n00b_string_from_cstr(
                          ROCS_WAX_CACHE_TOOL_PATH),
                      .conduit        = conduit,
                      .io             = io,
                      .args           = args,
                      .env            = tool_env(),
                      .capture_stdout = true,
                      .capture_stderr = true,
                      .merge          = false);

    auto run_r = n00b_subproc_run(&sp);
    CHECK(n00b_result_is_ok(run_r));

    auto code_r = n00b_subproc_exit_code(&sp);
    CHECK(n00b_result_is_ok(code_r));

    wax_live_run_t result = {
        .exit_code = n00b_result_get(code_r),
        .out       = buffer_string(n00b_subproc_stdout(&sp)),
        .err       = buffer_string(n00b_subproc_stderr(&sp)),
    };

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(conduit);
    return result;
}

static n00b_store_schema_t *
wax_schema(void)
{
    auto schema_r = n00b_rocs_wax_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_rocs_wax_daemon_config_t *
daemon_config(n00b_store_config_t *store_config,
              n00b_string_t       *source,
              n00b_string_t       *checkpoint)
{
    auto config_r = n00b_rocs_wax_daemon_config_new(store_config);
    CHECK(n00b_result_is_ok(config_r));
    n00b_rocs_wax_daemon_config_t *config = n00b_result_get(config_r);
    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_fixture_source(config, source)));
    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_checkpoint_path(config, checkpoint)));
    return config;
}

static void
create_cache_direct(n00b_string_t *root)
{
    configure_cache_env(root);

    auto store_config_r = n00b_store_config_from_env();
    CHECK(n00b_result_is_ok(store_config_r));

    n00b_rocs_wax_daemon_config_t *config =
        daemon_config(n00b_result_get(store_config_r),
                      daemon_fixture(),
                      n00b_path_join_v(root, r"checkpoint.txt"));

    auto start_r = n00b_rocs_wax_daemon_start(config);
    CHECK(n00b_result_is_ok(start_r));
    n00b_rocs_wax_daemon_t *daemon = n00b_result_get(start_r);

    auto run_r = n00b_rocs_wax_daemon_run(daemon);
    CHECK(n00b_result_is_ok(run_r));

    auto stop_r = n00b_rocs_wax_daemon_stop(daemon);
    CHECK(n00b_result_is_ok(stop_r));
}

static n00b_store_t *
open_cache(void)
{
    auto config_r = n00b_store_config_from_env();
    CHECK(n00b_result_is_ok(config_r));

    auto store_r = n00b_store_open_config(wax_schema(),
                                          n00b_result_get(config_r));
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_filter_t *
exists_filter(n00b_string_t *field)
{
    auto field_r = n00b_filter_field(field);
    CHECK(n00b_result_is_ok(field_r));

    auto filter_r = n00b_filter_exists(n00b_result_get(field_r));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static uint64_t
query_count(n00b_store_t *store, n00b_filter_t *filter)
{
    auto query_r = n00b_query_new(filter);
    CHECK(n00b_result_is_ok(query_r));

    auto result_r = n00b_query_run(store, n00b_result_get(query_r));
    CHECK(n00b_result_is_ok(result_r));
    n00b_query_result_t *result = n00b_result_get(result_r);
    uint64_t             count  = n00b_query_count(result);
    CHECK(n00b_result_is_ok(n00b_query_result_close(result)));
    return count;
}

static int32_t
find_index(n00b_string_t *haystack, n00b_string_t *needle)
{
    auto found = n00b_unicode_str_find(haystack, needle);
    CHECK(n00b_option_is_set(found));
    return n00b_option_get(found);
}

static bool
raw_has_at(n00b_string_t *text, size_t offset, n00b_string_t *needle)
{
    if (text == nullptr || needle == nullptr
        || offset + needle->u8_bytes > text->u8_bytes) {
        return false;
    }
    for (size_t i = 0; i < needle->u8_bytes; i++) {
        if (text->data[offset + i] != needle->data[i]) {
            return false;
        }
    }
    return true;
}

static n00b_string_t *
extract_resume(n00b_string_t *text)
{
    n00b_string_t *prefix = r"resume=";
    for (size_t i = 0; i < text->u8_bytes; i++) {
        if (!raw_has_at(text, i, prefix)) {
            continue;
        }

        size_t start = i + prefix->u8_bytes;
        size_t end   = start;
        while (end < text->u8_bytes
               && text->data[end] != ' '
               && text->data[end] != '\n'
               && text->data[end] != '\r'
               && text->data[end] != '\t') {
            end++;
        }
        CHECK(end > start);
        return n00b_string_from_raw(text->data + start,
                                    (int64_t)(end - start));
    }

    CHECK(false);
    return r"";
}

static n00b_array_t(n00b_string_t *) *
live_search_args(uint64_t extra)
{
    n00b_array_t(n00b_string_t *) *args = tool_args(2 + extra);
    tool_arg_set(args, 0, r"--search");
    tool_arg_set(args, 1, r"--live");
    return args;
}

static void
test_history_then_live_order(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_live_order_");
    create_cache_direct(root);

    n00b_array_t(n00b_string_t *) *args = live_search_args(8);
    tool_arg_set(args, 2, r"--live-fixture");
    tool_arg_set(args, 3, live_fixture());
    tool_arg_set(args, 4, r"--kind");
    tool_arg_set(args, 5, r"proc.spawn");
    tool_arg_set(args, 6, r"--format");
    tool_arg_set(args, 7, r"text");
    tool_arg_set(args, 8, r"--limit");
    tool_arg_set(args, 9, r"10");

    wax_live_run_t run = run_tool(args);
    CHECK_RUN_OK(run, r"history-live-order");
    CHECK(find_index(run.out, r"wax:daemon:proc:1")
          < find_index(run.out, r"wax:live:proc:2"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:live:file:2"));
    CHECK(n00b_unicode_str_contains(run.err, r"ingested=3"));
    CHECK(n00b_unicode_str_contains(run.err, r"rejected=1"));
    CHECK(n00b_unicode_str_contains(run.err, r"delivered=2"));
    CHECK(n00b_unicode_str_contains(run.err, r"dropped=0"));
    CHECK(n00b_unicode_str_contains(run.err, r"resume="));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] history then live order");
}

static void
test_live_filter_selectivity(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_live_filter_");
    create_cache_direct(root);

    n00b_array_t(n00b_string_t *) *args = live_search_args(6);
    tool_arg_set(args, 2, r"--live-fixture");
    tool_arg_set(args, 3, live_fixture());
    tool_arg_set(args, 4, r"--contains");
    tool_arg_set(args, 5, r"codex");
    tool_arg_set(args, 6, r"--format");
    tool_arg_set(args, 7, r"jsonl");

    wax_live_run_t run = run_tool(args);
    CHECK_RUN_OK(run, r"live-filter-selectivity");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:ai:1"));
    CHECK(n00b_unicode_str_contains(run.out, r"wax:live:ai:2"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:live:proc:2"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:live:file:2"));
    CHECK(n00b_unicode_str_contains(run.err, r"delivered=2"));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] live filter selectivity");
}

static void
test_limit_cancels_and_cache_reopens(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_live_limit_");
    create_cache_direct(root);

    n00b_array_t(n00b_string_t *) *args = live_search_args(8);
    tool_arg_set(args, 2, r"--live-fixture");
    tool_arg_set(args, 3, live_fixture());
    tool_arg_set(args, 4, r"--kind");
    tool_arg_set(args, 5, r"proc.spawn");
    tool_arg_set(args, 6, r"--limit");
    tool_arg_set(args, 7, r"1");
    tool_arg_set(args, 8, r"--format");
    tool_arg_set(args, 9, r"text");

    wax_live_run_t run = run_tool(args);
    CHECK_RUN_OK(run, r"live-limit");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:proc:1"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:live:proc:2"));
    CHECK(n00b_unicode_str_contains(run.err, r"delivered=1"));

    n00b_store_t *store = open_cache();
    CHECK(query_count(store, exists_filter(r"event_id")) == 6);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] live limit and clean reopen");
}

static void
test_resume_marker_suppresses_duplicates(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_live_resume_");
    create_cache_direct(root);

    n00b_array_t(n00b_string_t *) *first = live_search_args(8);
    tool_arg_set(first, 2, r"--live-fixture");
    tool_arg_set(first, 3, live_fixture());
    tool_arg_set(first, 4, r"--kind");
    tool_arg_set(first, 5, r"proc.spawn");
    tool_arg_set(first, 6, r"--limit");
    tool_arg_set(first, 7, r"1");
    tool_arg_set(first, 8, r"--format");
    tool_arg_set(first, 9, r"text");

    wax_live_run_t run = run_tool(first);
    CHECK_RUN_OK(run, r"resume-first");
    n00b_string_t *resume = extract_resume(run.err);

    n00b_array_t(n00b_string_t *) *second = live_search_args(6);
    tool_arg_set(second, 2, r"--resume");
    tool_arg_set(second, 3, resume);
    tool_arg_set(second, 4, r"--kind");
    tool_arg_set(second, 5, r"proc.spawn");
    tool_arg_set(second, 6, r"--format");
    tool_arg_set(second, 7, r"text");

    run = run_tool(second);
    CHECK_RUN_OK(run, r"resume-second");
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:daemon:proc:1"));
    CHECK(n00b_unicode_str_contains(run.out, r"wax:live:proc:2"));
    CHECK(n00b_unicode_str_contains(run.err, r"delivered=1"));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] resume marker suppresses duplicate delivery");
}

static void
test_empty_live_fixture_stops(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_live_empty_");
    configure_cache_env(root);
    n00b_string_t *empty = n00b_path_join_v(root, r"empty.ndjson");
    write_text(empty, r"");

    n00b_array_t(n00b_string_t *) *args = live_search_args(6);
    tool_arg_set(args, 2, r"--live-fixture");
    tool_arg_set(args, 3, empty);
    tool_arg_set(args, 4, r"--kind");
    tool_arg_set(args, 5, r"proc.spawn");
    tool_arg_set(args, 6, r"--format");
    tool_arg_set(args, 7, r"jsonl");

    wax_live_run_t run = run_tool(args);
    CHECK_RUN_OK(run, r"empty-live");
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:"));
    CHECK(n00b_unicode_str_contains(run.err, r"lines=0"));
    CHECK(n00b_unicode_str_contains(run.err, r"delivered=0"));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] empty live fixture stops");
}

static void
test_invalid_live_options(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_live_invalid_");
    configure_cache_env(root);

    n00b_array_t(n00b_string_t *) *bad_resume = live_search_args(2);
    tool_arg_set(bad_resume, 2, r"--resume");
    tool_arg_set(bad_resume, 3, r"not-a-token");
    wax_live_run_t run = run_tool(bad_resume);
    CHECK(run.exit_code != 0);
    CHECK(n00b_unicode_str_contains(run.err, r"live search error"));

    n00b_array_t(n00b_string_t *) *no_live = tool_args(3);
    tool_arg_set(no_live, 0, r"--search");
    tool_arg_set(no_live, 1, r"--live-fixture");
    tool_arg_set(no_live, 2, live_fixture());
    run = run_tool(no_live);
    CHECK(run.exit_code != 0);
    CHECK(n00b_unicode_str_contains(run.err, r"require --live"));

    n00b_array_t(n00b_string_t *) *ranked = live_search_args(2);
    tool_arg_set(ranked, 2, r"--order");
    tool_arg_set(ranked, 3, r"ranked");
    run = run_tool(ranked);
    CHECK(run.exit_code != 0);
    CHECK(n00b_unicode_str_contains(run.err, r"ranked"));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] invalid live options");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_wax_live:");
    test_history_then_live_order();
    test_live_filter_selectivity();
    test_limit_cancels_and_cache_reopens();
    test_resume_marker_suppresses_duplicates();
    test_empty_live_fixture_stops();
    test_invalid_live_options();

    n00b_shutdown();
    return 0;
}
