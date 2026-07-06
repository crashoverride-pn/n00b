/* test/unit/test_rocs_async_seal.c - regression for async seal + standby shard.
 *
 * Exercises the keep_standby path: the single ingest worker rotates the hot
 * shard with a pointer swap + pre-built standby and hands the marshal to a
 * dedicated seal-worker pool.  The invariants under test:
 *
 *   1. No record loss.  Every ingested record ends up in a sealed shard after a
 *      successful flush; transient seal failures retain the detached shard for
 *      retry instead of shortening sealed_records permanently.
 *   2. Parity.  The async path (keep_standby = true) seals exactly the same
 *      number of records as the inline path (keep_standby = false).
 *   3. Clean teardown.  flush() drains the ordered seal worklist and
 *      close() shuts the pool down and frees the standby without hanging or
 *      leaking a hot shard.
 */

#include <stdint.h>

#include "n00b.h"
#include "core/platform.h"
#include "core/runtime.h"
#include "core/time.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/hooks.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static n00b_vfs_t *
new_memory_vfs() _kargs
{
    n00b_vfs_mount_t **mount_out = nullptr;
}
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    if (mount_out != nullptr) {
        *mount_out = n00b_result_get(mount_r);
    }
    return vfs;
}

typedef struct {
    bool enabled;
} fail_shard_write_t;

typedef struct {
    bool enabled;
} fail_catalog_write_t;

typedef struct {
    bool     enabled;
    uint64_t sleep_ns;
} slow_shard_write_t;

static void
deny_shard_write_open(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    fail_shard_write_t *state = cookie;
    if (state == nullptr || !state->enabled || ctx == nullptr
        || ctx->path == nullptr || (ctx->flags & N00B_VFS_OPEN_WRITE) == 0
        || !n00b_unicode_str_contains(ctx->path,
                                      r"/shards/",
                                      .normalize = false)) {
        return;
    }

    ctx->denied   = true;
    ctx->deny_err = N00B_VFS_ERR_IO;
}

static void
slow_shard_write_open(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    slow_shard_write_t *state = cookie;
    if (state == nullptr || !state->enabled || ctx == nullptr
        || ctx->path == nullptr
        || (ctx->flags & N00B_VFS_OPEN_WRITE) == 0
        || !n00b_unicode_str_contains(ctx->path,
                                      r"/shards/",
                                      .normalize = false)) {
        return;
    }

    base_nanosleep_ns(state->sleep_ns);
}

static void
deny_catalog_write_open(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    fail_catalog_write_t *state = cookie;
    if (state == nullptr || !state->enabled || ctx == nullptr
        || ctx->path == nullptr || (ctx->flags & N00B_VFS_OPEN_WRITE) == 0
        || !n00b_unicode_str_eq(ctx->path, r"/rocs/catalog.rocs")) {
        return;
    }

    ctx->denied   = true;
    ctx->deny_err = N00B_VFS_ERR_IO;
}

static n00b_store_schema_t *
make_schema(void)
{
    n00b_store_schema_t *schema = n00b_result_get(n00b_store_schema_new());
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"term",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

static n00b_json_node_t *
make_record(int64_t i)
{
    // ~256 distinct terms => dense posting structure, the case the flagset
    // no-scan seal fix was about.
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_string_t    *term   = n00b_cformat("term-[|#|]", (int64_t)(i & 0xff));
    n00b_json_object_put_n00b(record,
                              r"term",
                              n00b_json_string_new_from_n00b(term));
    return record;
}

static uint64_t
elapsed_ns_since(int64_t start)
{
    int64_t end = n00b_ns_timestamp();
    CHECK(end >= start);
    return (uint64_t)(end - start);
}

static void
check_health_status_stats_fast(n00b_store_t *store, uint64_t max_ns)
{
    int64_t start = n00b_ns_timestamp();
    CHECK(start >= 0);

    // Mirror the ROCS calls made by the gateway health/status path. A
    // non-service store may reject service-ingest stats, but it must do so
    // promptly and without waiting for async seal workers.
    auto ingest_r = n00b_store_service_ingest_stats(store);
    CHECK(n00b_result_is_ok(ingest_r)
          || n00b_result_get_err(ingest_r) == N00B_STORE_ERR_STATE);

    CHECK(n00b_result_is_ok(n00b_store_oldest_available_pos(store)));
    CHECK(n00b_result_is_ok(n00b_store_oldest_available_expires_at_ns(store)));
    CHECK(n00b_result_is_ok(n00b_store_residency_stats(store)));
    CHECK(n00b_result_is_ok(n00b_store_memory_stats(store)));

    CHECK(elapsed_ns_since(start) < max_ns);
}

// Ingest n single records (auto-sealing every 50) into a store opened with the
// given keep_standby setting, flush, and report sealed counts.
static void
run_ingest(bool      keep_standby,
           int64_t   n,
           uint64_t *sealed_records_out,
           uint64_t *sealed_shards_out)
{
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = 50);
    CHECK(n00b_result_is_ok(seal_r));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       schema,
                                       .seal_policy  = n00b_result_get(seal_r),
                                       .keep_standby = keep_standby);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < n; i++) {
        auto ing_r = n00b_store_ingest(store, make_record(i));
        CHECK(n00b_result_is_ok(ing_r));
    }

    // flush waits behind any earlier async seals and seals the live hot shard,
    // so afterward every record must be accounted for in a sealed shard.
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);

    CHECK(stats.hot_record_count == 0);

    *sealed_records_out = stats.sealed_records;
    *sealed_shards_out  = stats.sealed_shards;

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_async_seal_failure_retains_records(void)
{
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .seal_policy  = n00b_result_get(seal_r),
                                       .keep_standby = true);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    fail_shard_write_t fail_shards = {
        .enabled = false,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              deny_shard_write_open,
                                              &fail_shards,
                                              0)));

    fail_shards.enabled = true;
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(1))));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(2))));

    auto failed_flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_err(failed_flush_r));
    CHECK(n00b_result_get_err(failed_flush_r) == N00B_STORE_ERR_VFS);

    auto failed_stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(failed_stats_r));
    n00b_store_memory_stats_t failed_stats = n00b_result_get(failed_stats_r);
    CHECK(failed_stats.failed_seal_jobs == 2);
    CHECK(failed_stats.failed_seal_records == 2);
    CHECK(failed_stats.sealed_records == 0);

    auto failed_visible_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(failed_visible_r));
    CHECK(n00b_result_get(failed_visible_r) == 0);

    auto failed_backlog_r = n00b_store_catalog_backlog(store, nullptr);
    CHECK(n00b_result_is_ok(failed_backlog_r));
    n00b_store_backlog_t failed_backlog = n00b_result_get(failed_backlog_r);
    CHECK(failed_backlog.records_remaining == 0);
    CHECK(failed_backlog.shards_remaining == 0);

    fail_shards.enabled = false;
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);

    CHECK(stats.failed_seal_jobs == 0);
    CHECK(stats.failed_seal_records == 0);
    CHECK(stats.sealed_records == 2);
    CHECK(stats.hot_record_count == 0);

    auto visible_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(visible_r));
    CHECK(n00b_result_get(visible_r) == stats.sealed_shards);

    auto backlog_r = n00b_store_catalog_backlog(store, nullptr);
    CHECK(n00b_result_is_ok(backlog_r));
    n00b_store_backlog_t backlog = n00b_result_get(backlog_r);
    CHECK(backlog.records_remaining == 2);
    CHECK(backlog.shards_remaining == stats.sealed_shards);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_async_catalog_failure_retains_records(void)
{
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .seal_policy  = n00b_result_get(seal_r),
                                       .keep_standby = true);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    fail_catalog_write_t fail_catalog = {
        .enabled = false,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              deny_catalog_write_open,
                                              &fail_catalog,
                                              0)));

    fail_catalog.enabled = true;
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(10))));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(11))));

    auto failed_flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_err(failed_flush_r));
    CHECK(n00b_result_get_err(failed_flush_r) == N00B_STORE_ERR_VFS);

    auto failed_stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(failed_stats_r));
    n00b_store_memory_stats_t failed_stats = n00b_result_get(failed_stats_r);
    CHECK(failed_stats.failed_seal_jobs == 2);
    CHECK(failed_stats.failed_seal_records == 2);
    CHECK(failed_stats.sealed_records == 0);

    auto failed_visible_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(failed_visible_r));
    CHECK(n00b_result_get(failed_visible_r) == 0);

    auto orphan_r = n00b_vfs_stat(vfs, r"/rocs/shards/1.n00b");
    CHECK(n00b_result_is_err(orphan_r));
    CHECK(n00b_result_get_err(orphan_r) == N00B_VFS_ERR_NOT_FOUND);

    fail_catalog.enabled = false;
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.failed_seal_jobs == 0);
    CHECK(stats.failed_seal_records == 0);
    CHECK(stats.sealed_records == 2);
    CHECK(stats.hot_record_count == 0);

    auto visible_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(visible_r));
    CHECK(n00b_result_get(visible_r) == stats.sealed_shards);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_async_seal_backlog_stats(void)
{
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .seal_policy      = n00b_result_get(seal_r),
                                       .keep_standby     = true,
                                       .seal_worker_count = 1);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    slow_shard_write_t slow_shards = {
        .enabled  = true,
        .sleep_ns = 200ULL * N00B_NS_PER_MS,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              slow_shard_write_open,
                                              &slow_shards,
                                              0)));

    for (int64_t i = 0; i < 8; i++) {
        CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(100 + i))));
    }

    bool saw_backlog = false;
    for (uint32_t i = 0; i < 100; i++) {
        auto stats_r = n00b_store_memory_stats(store);
        CHECK(n00b_result_is_ok(stats_r));
        n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
        CHECK(stats.seal_worker_count == 1);
        if (stats.seal_queue_in_flight > 0
            && stats.seal_queue_pending > 0) {
            saw_backlog = true;
            break;
        }
        base_nanosleep_ns(1ULL * N00B_NS_PER_MS);
    }
    CHECK(saw_backlog);

    // T048-19: health/status may take short catalog/residency read locks, but
    // must not wait on seal IO. The VFS hook keeps the seal worker asleep for
    // 200ms per shard write; status snapshots should stay comfortably below
    // that while seal work is active.
    for (uint32_t i = 0; i < 5; i++) {
        check_health_status_stats_fast(store, 100ULL * N00B_NS_PER_MS);
        base_nanosleep_ns(1ULL * N00B_NS_PER_MS);
    }

    slow_shards.enabled = false;
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.seal_queue_pending == 0);
    CHECK(stats.seal_queue_in_flight == 0);
    CHECK(stats.failed_seal_jobs == 0);
    CHECK(stats.failed_seal_records == 0);
    CHECK(stats.sealed_records == 8);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_close_drains_in_flight_async_seals(void)
{
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .seal_policy      = n00b_result_get(seal_r),
                                       .keep_standby     = true,
                                       .seal_worker_count = 1);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    slow_shard_write_t slow_shards = {
        .enabled  = true,
        .sleep_ns = 20ULL * N00B_NS_PER_MS,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              slow_shard_write_open,
                                              &slow_shards,
                                              0)));

    for (int64_t i = 0; i < 6; i++) {
        CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(200 + i))));
    }

    bool saw_backlog = false;
    for (uint32_t i = 0; i < 100; i++) {
        auto stats_r = n00b_store_memory_stats(store);
        CHECK(n00b_result_is_ok(stats_r));
        n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
        if (stats.seal_queue_in_flight > 0
            && stats.seal_queue_pending > 0) {
            saw_backlog = true;
            break;
        }
        base_nanosleep_ns(1ULL * N00B_NS_PER_MS);
    }
    CHECK(saw_backlog);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    slow_shards.enabled = false;

    auto reopen_r = n00b_store_open_vfs(vfs, r"/rocs", make_schema());
    CHECK(n00b_result_is_ok(reopen_r));
    n00b_store_t *reopened = n00b_result_get(reopen_r);

    auto stats_r = n00b_store_memory_stats(reopened);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.sealed_records == 6);
    CHECK(stats.hot_record_count == 0);
    CHECK(stats.failed_seal_jobs == 0);
    CHECK(stats.failed_seal_records == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(reopened)));
}

static void
test_close_failed_async_seal_remains_retryable(void)
{
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(.mount_out = &mount);
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema,
                                       .seal_policy      = n00b_result_get(seal_r),
                                       .keep_standby     = true,
                                       .seal_worker_count = 1);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    fail_shard_write_t fail_shards = {
        .enabled = true,
    };
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              deny_shard_write_open,
                                              &fail_shards,
                                              0)));

    CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(300))));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(301))));

    auto failed_close_r = n00b_store_close(store);
    CHECK(n00b_result_is_err(failed_close_r));
    CHECK(n00b_result_get_err(failed_close_r) == N00B_STORE_ERR_VFS);

    auto failed_stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(failed_stats_r));
    n00b_store_memory_stats_t failed_stats = n00b_result_get(failed_stats_r);
    CHECK(failed_stats.failed_seal_jobs == 2);
    CHECK(failed_stats.failed_seal_records == 2);
    CHECK(failed_stats.sealed_records == 0);

    fail_shards.enabled = false;
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    auto reopen_r = n00b_store_open_vfs(vfs, r"/rocs", make_schema());
    CHECK(n00b_result_is_ok(reopen_r));
    n00b_store_t *reopened = n00b_result_get(reopen_r);

    auto stats_r = n00b_store_memory_stats(reopened);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.sealed_records == 2);
    CHECK(stats.hot_record_count == 0);
    CHECK(stats.failed_seal_jobs == 0);
    CHECK(stats.failed_seal_records == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(reopened)));
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    const int64_t N = 1000;

    // 1. Async path: no record loss; many seals actually happened.
    uint64_t async_records = 0;
    uint64_t async_shards  = 0;
    run_ingest(true, N, &async_records, &async_shards);
    CHECK(async_records == (uint64_t)N);
    CHECK(async_shards >= (uint64_t)(N / 50) - 1);

    // 2. Inline path: no record loss.
    uint64_t inline_records = 0;
    uint64_t inline_shards  = 0;
    run_ingest(false, N, &inline_records, &inline_shards);
    CHECK(inline_records == (uint64_t)N);

    // 3. Parity: async and inline seal the same records.
    CHECK(async_records == inline_records);

    test_async_seal_failure_retains_records();
    test_async_catalog_failure_retains_records();
    test_async_seal_backlog_stats();
    test_close_drains_in_flight_async_seals();
    test_close_failed_async_seal_remains_retryable();

    n00b_eprintf("test_rocs_async_seal OK: N=[|#|] async_shards=[|#|] "
                 "inline_shards=[|#|]\n",
                 N,
                 (int64_t)async_shards,
                 (int64_t)inline_shards);
    return 0;
}
