/* test/unit/test_rocs_wax_cli.c - WP-013 Phase 3 wax finite search CLI. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/print.h"
#include "conduit/subproc.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "internal/rocs/index.h"
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
} wax_cli_run_t;

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
set_env(n00b_string_t *key, n00b_string_t *value)
{
    CHECK(n00b_putenv(key, value));
}

static void
configure_cache_env(n00b_string_t *cache_dir)
{
    cache_env_dir = cache_dir;
    set_env(r"ROCS_PROFILE", r"service_local");
    set_env(r"ROCS_NAME", r"rocs-wax-cli-test");
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
    n00b_array_set(*env, 1, r"ROCS_NAME=rocs-wax-cli-test");
    n00b_array_set(*env,
                   2,
                   n00b_cformat("ROCS_CACHE_DIR=«#»", cache_env_dir));
    n00b_array_set(*env, 3, r"N00B_TEST=1");
    return env;
}

static wax_cli_run_t
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

    wax_cli_run_t result = {
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

static void
create_cache_direct(n00b_string_t *root)
{
    configure_cache_env(root);

    auto store_config_r = n00b_store_config_from_env();
    CHECK(n00b_result_is_ok(store_config_r));

    auto daemon_config_r =
        n00b_rocs_wax_daemon_config_new(n00b_result_get(store_config_r));
    CHECK(n00b_result_is_ok(daemon_config_r));
    n00b_rocs_wax_daemon_config_t *daemon_config =
        n00b_result_get(daemon_config_r);

    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_fixture_source(daemon_config,
                                                       daemon_fixture())));
    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_checkpoint_path(
            daemon_config,
            n00b_path_join_v(root, r"checkpoint.txt"))));

    auto start_r = n00b_rocs_wax_daemon_start(daemon_config);
    CHECK(n00b_result_is_ok(start_r));
    n00b_rocs_wax_daemon_t *daemon = n00b_result_get(start_r);

    auto run_r = n00b_rocs_wax_daemon_run(daemon);
    CHECK(n00b_result_is_ok(run_r));

    auto stats_r = n00b_rocs_wax_daemon_stats(daemon);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_rocs_wax_daemon_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.events_ingested == 3);
    CHECK(stats.events_rejected == 3);

    auto stop_r = n00b_rocs_wax_daemon_stop(daemon);
    CHECK(n00b_result_is_ok(stop_r));
}

static n00b_filter_field_t *
field_ok(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
filter_ok(n00b_result_t(n00b_filter_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_filter_t *
exists_filter(n00b_string_t *field)
{
    return filter_ok(n00b_filter_exists(field_ok(field)));
}

static n00b_filter_t *
eq_filter(n00b_string_t *field, n00b_string_t *value)
{
    return filter_ok(n00b_filter_eq(field_ok(field), n00b_fv_utf8(value)));
}

static n00b_filter_t *
contains_filter(n00b_string_t *field, n00b_string_t *term)
{
    return filter_ok(n00b_filter_contains(field_ok(field), term));
}

static n00b_filter_t *
timestamp_filter(int64_t from, int64_t to)
{
    return filter_ok(n00b_filter_between(field_ok(r"timestamp"),
                                         n00b_fv_i64(from),
                                         n00b_fv_i64(to)));
}

static uint64_t
query_count(n00b_store_t   *store,
            n00b_filter_t  *filter,
            uint64_t        limit,
            n00b_string_t  *label)
{
    auto query_r = n00b_query_new(filter, .limit = limit);
    CHECK(n00b_result_is_ok(query_r));

    auto result_r = n00b_query_run(store, n00b_result_get(query_r));
    if (n00b_result_is_err(result_r)) {
        n00b_eprintf("query_count failed for «#»: «#»",
                     label,
                     n00b_query_err_str(n00b_result_get_err(result_r)));
    }
    CHECK(n00b_result_is_ok(result_r));
    n00b_query_result_t *result = n00b_result_get(result_r);
    uint64_t             count  = n00b_query_count(result);
    CHECK(n00b_result_is_ok(n00b_query_result_close(result)));
    return count;
}

static n00b_string_t *
first_raw_json(n00b_store_t *store, n00b_filter_t *filter)
{
    auto query_r = n00b_query_new(filter, .limit = 1);
    CHECK(n00b_result_is_ok(query_r));

    auto result_r = n00b_query_run(store, n00b_result_get(query_r));
    CHECK(n00b_result_is_ok(result_r));
    n00b_query_result_t *result = n00b_result_get(result_r);

    auto records_r = n00b_query_records(result);
    CHECK(n00b_result_is_ok(records_r));
    n00b_query_hit_list_t *records = n00b_result_get(records_r);
    CHECK(n00b_list_len(*records) == 1);

    n00b_query_hit_t *hit = n00b_list_get(*records, 0);
    auto record_r = n00b_query_hit_record(hit);
    CHECK(n00b_result_is_ok(record_r));

    auto json_r = n00b_store_record_view_json(n00b_result_get(record_r));
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *raw =
        n00b_json_object_get(n00b_result_get(json_r), r"raw_json");
    CHECK(n00b_json_is_string(raw));
    n00b_string_t *raw_text = n00b_json_as_string(raw);
    n00b_string_t *raw_copy = n00b_string_from_raw(raw_text->data,
                                                   (int64_t)raw_text->u8_bytes);

    CHECK(n00b_result_is_ok(n00b_query_result_close(result)));
    return raw_copy;
}

static void
create_cache_with_tool(n00b_string_t *root)
{
    configure_cache_env(root);

    n00b_array_t(n00b_string_t *) *args = tool_args(3);
    tool_arg_set(args, 0, r"--run-fixture");
    tool_arg_set(args, 1, daemon_fixture());
    tool_arg_set(args, 2, n00b_path_join_v(root, r"checkpoint.txt"));

    wax_cli_run_t run = run_tool(args);
    CHECK(run.exit_code == 0);
    CHECK(n00b_unicode_str_contains(run.out, r"ingested=3"));
    CHECK(n00b_unicode_str_contains(run.out, r"rejected=3"));
}

static void
test_run_fixture_command_smoke(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_cli_fixture_");
    create_cache_with_tool(root);
    cleanup_tmpdir(root);
    n00b_printf("  [PASS] run-fixture command smoke");
}

static void
test_public_query_filters_over_cache(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_cli_query_");
    create_cache_direct(root);

    n00b_store_t *store = open_cache();
    CHECK(query_count(store, exists_filter(r"event_id"), 0, r"exists") == 3);
    CHECK(query_count(store, eq_filter(r"kind", r"proc.spawn"), 0, r"kind")
          == 1);
    CHECK(query_count(store, eq_filter(r"class", r"file"), 0, r"class")
          == 1);
    CHECK(query_count(store, eq_filter(r"family", r"ai"), 0, r"family")
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"quality", r"degraded"),
                      0,
                      r"quality") == 1);
    CHECK(query_count(store,
                      contains_filter(r"search_text", r"codex"),
                      0,
                      r"contains") == 1);
    CHECK(query_count(store,
                      timestamp_filter(1777557900000000000,
                                       1777557900000000000),
                      0,
                      r"timestamp") == 1);
    CHECK(query_count(store, exists_filter(r"event_id"), 2, r"limit") == 2);
    CHECK(query_count(store,
                      eq_filter(r"kind", r"does.not.exist"),
                      0,
                      r"empty") == 0);

    n00b_string_t *raw = first_raw_json(store,
                                        eq_filter(r"event_id",
                                                  r"wax:daemon:ai:1"));
    CHECK(n00b_unicode_str_contains(raw, r"ai.session_start"));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] public query filters over cache");
}

static void
test_command_search_modes(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_cli_cmd_");
    create_cache_direct(root);

    n00b_array_t(n00b_string_t *) *help = tool_args(1);
    tool_arg_set(help, 0, r"--help");
    wax_cli_run_t run = run_tool(help);
    CHECK(run.exit_code == 0);
    CHECK(n00b_unicode_str_contains(run.err, r"--search"));

    n00b_array_t(n00b_string_t *) *kind = tool_args(5);
    tool_arg_set(kind, 0, r"--search");
    tool_arg_set(kind, 1, r"--kind");
    tool_arg_set(kind, 2, r"proc.spawn");
    tool_arg_set(kind, 3, r"--format");
    tool_arg_set(kind, 4, r"jsonl");
    run = run_tool(kind);
    CHECK_RUN_OK(run, r"kind");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:proc:1"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:daemon:file:1"));

    n00b_array_t(n00b_string_t *) *field_eq = tool_args(5);
    tool_arg_set(field_eq, 0, r"--search");
    tool_arg_set(field_eq, 1, r"--field-eq");
    tool_arg_set(field_eq, 2, r"quality=degraded");
    tool_arg_set(field_eq, 3, r"--format");
    tool_arg_set(field_eq, 4, r"jsonl");
    run = run_tool(field_eq);
    CHECK_RUN_OK(run, r"field-eq");
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:file:1"));
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:daemon:proc:1"));

    n00b_array_t(n00b_string_t *) *ranked_table = tool_args(9);
    tool_arg_set(ranked_table, 0, r"--search");
    tool_arg_set(ranked_table, 1, r"--contains");
    tool_arg_set(ranked_table, 2, r"codex");
    tool_arg_set(ranked_table, 3, r"--order");
    tool_arg_set(ranked_table, 4, r"ranked");
    tool_arg_set(ranked_table, 5, r"--format");
    tool_arg_set(ranked_table, 6, r"table");
    tool_arg_set(ranked_table, 7, r"--limit");
    tool_arg_set(ranked_table, 8, r"1");
    run = run_tool(ranked_table);
    CHECK_RUN_OK(run, r"ranked-table");
    CHECK(n00b_unicode_str_contains(run.out, r"event_id"));
    CHECK(n00b_unicode_str_contains(run.out, r"wax:daemon:ai:1"));

    n00b_array_t(n00b_string_t *) *empty = tool_args(5);
    tool_arg_set(empty, 0, r"--search");
    tool_arg_set(empty, 1, r"--kind");
    tool_arg_set(empty, 2, r"missing.kind");
    tool_arg_set(empty, 3, r"--format");
    tool_arg_set(empty, 4, r"jsonl");
    run = run_tool(empty);
    CHECK_RUN_OK(run, r"empty");
    CHECK(!n00b_unicode_str_contains(run.out, r"wax:daemon:"));

    n00b_array_t(n00b_string_t *) *bad = tool_args(3);
    tool_arg_set(bad, 0, r"--search");
    tool_arg_set(bad, 1, r"--field-eq");
    tool_arg_set(bad, 2, r"not-a-field-eq");
    run = run_tool(bad);
    CHECK(run.exit_code != 0);
    CHECK(n00b_unicode_str_contains(run.err, r"invalid --field-eq"));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] command search modes");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_wax_cli:");
    test_run_fixture_command_smoke();
    test_public_query_filters_over_cache();
    test_command_search_modes();

    n00b_shutdown();
    return 0;
}
