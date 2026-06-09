/* test/unit/test_rocs_wax_daemon.c - WP-013 Phase 2 wax cache daemon. */

#include <stdint.h>

#include "n00b.h"
#include "core/buffer.h"
#include "conduit/print.h"
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

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_wax_daemon_err_r = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_wax_daemon_err_r));                       \
        CHECK(n00b_result_get_err(_bl_wax_daemon_err_r) == (expected));        \
    } while (0)

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
write_empty_file(n00b_string_t *path)
{
    auto open_r = n00b_file_open(path, .mode = N00B_FILE_W);
    CHECK(n00b_result_is_ok(open_r));

    auto close_r = n00b_file_close_result(n00b_result_get(open_r));
    CHECK(n00b_result_is_ok(close_r));
}

static void
set_prefixed_env(n00b_string_t *prefix,
                 n00b_string_t *key,
                 n00b_string_t *value)
{
    n00b_string_t *full_key = n00b_unicode_str_cat(prefix, key);
    CHECK(n00b_putenv(full_key, value));
}

static n00b_store_config_t *
store_config_from_env(n00b_string_t *prefix, n00b_string_t *cache_dir)
{
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"service_local");
    set_prefixed_env(prefix, r"ROCS_NAME", prefix);
    set_prefixed_env(prefix, r"ROCS_CACHE_DIR", cache_dir);

    auto config_r = n00b_store_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));
    return n00b_result_get(config_r);
}

static n00b_rocs_wax_daemon_config_t *
daemon_config(n00b_store_config_t *store_config,
              n00b_string_t       *source,
              n00b_string_t       *checkpoint,
              uint64_t             max_lines)
{
    auto config_r = n00b_rocs_wax_daemon_config_new(store_config);
    CHECK(n00b_result_is_ok(config_r));
    n00b_rocs_wax_daemon_config_t *config = n00b_result_get(config_r);
    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_fixture_source(config, source)));
    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_checkpoint_path(config, checkpoint)));
    CHECK(n00b_result_is_ok(
        n00b_rocs_wax_daemon_config_set_max_lines(config, max_lines)));
    return config;
}

static n00b_rocs_wax_daemon_t *
start_daemon(n00b_rocs_wax_daemon_config_t *config)
{
    auto start_r = n00b_rocs_wax_daemon_start(config);
    CHECK(n00b_result_is_ok(start_r));
    n00b_rocs_wax_daemon_t *daemon = n00b_result_get(start_r);

    auto healthy_r = n00b_rocs_wax_daemon_healthy(daemon);
    CHECK(n00b_result_is_ok(healthy_r));
    CHECK(n00b_result_get(healthy_r));
    return daemon;
}

static n00b_rocs_wax_daemon_stats_t
daemon_stats(n00b_rocs_wax_daemon_t *daemon)
{
    auto stats_r = n00b_rocs_wax_daemon_stats(daemon);
    CHECK(n00b_result_is_ok(stats_r));
    return n00b_result_get(stats_r);
}

static n00b_store_t *
daemon_store(n00b_rocs_wax_daemon_t *daemon)
{
    auto store_r = n00b_rocs_wax_daemon_store(daemon);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static void
stop_daemon(n00b_rocs_wax_daemon_t *daemon)
{
    n00b_store_t *store  = daemon_store(daemon);
    auto          pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    CHECK(n00b_result_get(pins_r) == 0);

    auto stop_r = n00b_rocs_wax_daemon_stop(daemon);
    CHECK(n00b_result_is_ok(stop_r));
    CHECK(n00b_result_get(stop_r));

    stop_r = n00b_rocs_wax_daemon_stop(daemon);
    CHECK(n00b_result_is_ok(stop_r));
    CHECK(!n00b_result_get(stop_r));

    CHECK_ERR(n00b_rocs_wax_daemon_store(daemon),
              N00B_ROCS_WAX_ERR_CLOSED);
}

static n00b_store_schema_t *
wax_schema(void)
{
    auto schema_r = n00b_rocs_wax_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_cache(n00b_string_t *prefix, n00b_string_t *cache_dir)
{
    n00b_store_config_t *config = store_config_from_env(prefix, cache_dir);
    auto store_r = n00b_store_open_config(wax_schema(), config);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_filter_field_t *
filter_field(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
exists_filter(n00b_string_t *field_name)
{
    auto filter_r = n00b_filter_exists(filter_field(field_name));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static n00b_filter_t *
contains_filter(n00b_string_t *field_name, n00b_string_t *term)
{
    auto filter_r = n00b_filter_contains(filter_field(field_name), term);
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

static void
check_reopened_counts(n00b_string_t *prefix,
                      n00b_string_t *cache_dir,
                      uint64_t       expected)
{
    n00b_store_t *store = open_cache(prefix, cache_dir);
    CHECK(query_count(store, exists_filter(r"event_id")) == expected);
    CHECK(query_count(store, contains_filter(r"search_text", r"codex")) == 1);
    CHECK(query_count(store, contains_filter(r"search_text", r"metadata"))
          == 1);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_fixture_ingest_reopen_and_stats(void)
{
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_WAX_DAEMON_DECLS)
                  != 0);
    CHECK(n00b_unicode_str_eq(
        n00b_rocs_wax_err_str(N00B_ROCS_WAX_ERR_SOURCE),
        r"SOURCE"));

    n00b_string_t *root       = new_tmpdir(r"n00b_rocs_wax_daemon_a_");
    n00b_string_t *checkpoint = n00b_path_join_v(root, r"checkpoint.txt");
    n00b_string_t *prefix     = r"ROCS_WAX_DAEMON_A_";

    n00b_store_config_t *store_config = store_config_from_env(prefix, root);
    n00b_rocs_wax_daemon_config_t *config =
        daemon_config(store_config, daemon_fixture(), checkpoint, 0);
    n00b_rocs_wax_daemon_t *daemon = start_daemon(config);

    CHECK(n00b_result_is_ok(n00b_rocs_wax_daemon_run(daemon)));
    n00b_rocs_wax_daemon_stats_t stats = daemon_stats(daemon);
    CHECK(stats.lines_read == 6);
    CHECK(stats.events_ingested == 3);
    CHECK(stats.events_rejected == 3);
    CHECK(stats.store_errors == 0);
    CHECK(stats.source_disconnects == 1);
    CHECK(stats.checkpoint_writes == 6);
    CHECK(stats.checkpoint_errors == 0);
    CHECK(stats.checkpoint_line == 6);
    CHECK(stats.last_error == N00B_ROCS_WAX_ERR_MISSING_KIND);

    stop_daemon(daemon);
    check_reopened_counts(r"ROCS_WAX_DAEMON_A_REOPEN_", root, 3);
    cleanup_tmpdir(root);
    n00b_printf("  [PASS] fixture ingest, stats, reopen");
}

static void
test_checkpoint_resume_advances_past_malformed(void)
{
    n00b_string_t *root       = new_tmpdir(r"n00b_rocs_wax_daemon_b_");
    n00b_string_t *checkpoint = n00b_path_join_v(root, r"checkpoint.txt");

    n00b_store_config_t *first_store =
        store_config_from_env(r"ROCS_WAX_DAEMON_B1_", root);
    n00b_rocs_wax_daemon_config_t *first_config =
        daemon_config(first_store, daemon_fixture(), checkpoint, 2);
    n00b_rocs_wax_daemon_t *first = start_daemon(first_config);
    CHECK(n00b_result_is_ok(n00b_rocs_wax_daemon_run(first)));

    n00b_rocs_wax_daemon_stats_t stats = daemon_stats(first);
    CHECK(stats.lines_read == 2);
    CHECK(stats.events_ingested == 1);
    CHECK(stats.events_rejected == 1);
    CHECK(stats.checkpoint_writes == 2);
    CHECK(stats.checkpoint_line == 2);
    CHECK(stats.source_disconnects == 0);
    stop_daemon(first);

    n00b_store_config_t *second_store =
        store_config_from_env(r"ROCS_WAX_DAEMON_B2_", root);
    n00b_rocs_wax_daemon_config_t *second_config =
        daemon_config(second_store, daemon_fixture(), checkpoint, 0);
    n00b_rocs_wax_daemon_t *second = start_daemon(second_config);
    CHECK(n00b_result_is_ok(n00b_rocs_wax_daemon_run(second)));

    stats = daemon_stats(second);
    CHECK(stats.lines_read == 4);
    CHECK(stats.events_ingested == 2);
    CHECK(stats.events_rejected == 2);
    CHECK(stats.checkpoint_writes == 4);
    CHECK(stats.checkpoint_line == 6);
    CHECK(stats.source_disconnects == 1);
    stop_daemon(second);

    check_reopened_counts(r"ROCS_WAX_DAEMON_B_REOPEN_", root, 3);
    cleanup_tmpdir(root);
    n00b_printf("  [PASS] checkpoint resume");
}

static void
test_config_source_errors_and_health(void)
{
    n00b_string_t *root = new_tmpdir(r"n00b_rocs_wax_daemon_c_");

    n00b_store_config_t *store_config =
        store_config_from_env(r"ROCS_WAX_DAEMON_C_", root);
    auto bare_r = n00b_rocs_wax_daemon_config_new(store_config);
    CHECK(n00b_result_is_ok(bare_r));
    CHECK_ERR(n00b_rocs_wax_daemon_start(n00b_result_get(bare_r)),
              N00B_ROCS_WAX_ERR_CONFIG);

    n00b_rocs_wax_daemon_config_t *config =
        daemon_config(store_config,
                      n00b_path_join_v(root, r"missing.ndjson"),
                      nullptr,
                      0);
    n00b_rocs_wax_daemon_t *daemon = start_daemon(config);
    CHECK_ERR(n00b_rocs_wax_daemon_run(daemon), N00B_ROCS_WAX_ERR_SOURCE);

    n00b_rocs_wax_daemon_stats_t stats = daemon_stats(daemon);
    CHECK(stats.events_ingested == 0);
    CHECK(stats.events_rejected == 0);
    CHECK(stats.last_error == N00B_ROCS_WAX_ERR_SOURCE);

    auto healthy_r = n00b_rocs_wax_daemon_healthy(daemon);
    CHECK(n00b_result_is_ok(healthy_r));
    CHECK(!n00b_result_get(healthy_r));
    stop_daemon(daemon);

    n00b_store_t *store = open_cache(r"ROCS_WAX_DAEMON_C_REOPEN_", root);
    CHECK(query_count(store, exists_filter(r"event_id")) == 0);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] config/source errors and health");
}

static void
test_checkpoint_parse_error_blocks_replay(void)
{
    n00b_string_t *root       = new_tmpdir(r"n00b_rocs_wax_daemon_d_");
    n00b_string_t *checkpoint = n00b_path_join_v(root, r"checkpoint.txt");
    write_text(checkpoint, r"not-a-line-number\n");

    n00b_store_config_t *store_config =
        store_config_from_env(r"ROCS_WAX_DAEMON_D_", root);
    n00b_rocs_wax_daemon_config_t *config =
        daemon_config(store_config, daemon_fixture(), checkpoint, 0);

    CHECK_ERR(n00b_rocs_wax_daemon_start(config),
              N00B_ROCS_WAX_ERR_CHECKPOINT);

    n00b_store_t *store = open_cache(r"ROCS_WAX_DAEMON_D_REOPEN_", root);
    CHECK(query_count(store, exists_filter(r"event_id")) == 0);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] checkpoint parse errors block replay");
}

static void
test_empty_checkpoint_blocks_replay(void)
{
    n00b_string_t *root       = new_tmpdir(r"n00b_rocs_wax_daemon_e_");
    n00b_string_t *checkpoint = n00b_path_join_v(root, r"checkpoint.txt");
    write_empty_file(checkpoint);

    n00b_store_config_t *store_config =
        store_config_from_env(r"ROCS_WAX_DAEMON_E_", root);
    n00b_rocs_wax_daemon_config_t *config =
        daemon_config(store_config, daemon_fixture(), checkpoint, 0);

    CHECK_ERR(n00b_rocs_wax_daemon_start(config),
              N00B_ROCS_WAX_ERR_CHECKPOINT);

    n00b_store_t *store = open_cache(r"ROCS_WAX_DAEMON_E_REOPEN_", root);
    CHECK(query_count(store, exists_filter(r"event_id")) == 0);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    cleanup_tmpdir(root);
    n00b_printf("  [PASS] empty checkpoint blocks replay");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_wax_daemon:");
    test_fixture_ingest_reopen_and_stats();
    test_checkpoint_resume_advances_past_malformed();
    test_config_source_errors_and_health();
    test_checkpoint_parse_error_blocks_replay();
    test_empty_checkpoint_blocks_replay();

    n00b_shutdown();
    return 0;
}
