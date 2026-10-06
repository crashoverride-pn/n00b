/* test/unit/test_rocs_query_cancel.c - cancel polls in the long query loops.
 *
 * Every loop here polls the caller's cancel hook on its first unit of work and
 * every 1024 after. Each test proves a loop polls by counting calls, never by
 * timing: either an exact count that drops when the loop's poll is removed, or
 * a store counter read inside the hook that places the poll before or after a
 * shard is touched.
 */

#include <stdint.h>
#include <time.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/eval.h"
#include "internal/rocs/filter.h"
#include "internal/rocs/index.h"
#include "internal/rocs/query.h"
#include "internal/rocs/store.h"
#include "test_check.h"

#define NEVER UINT64_MAX

// Records in the large shard: three poll intervals, so a loop over them polls
// at units 0, 1024 and 2048.
#define LARGE_N     3000
#define LARGE_POLLS 3

typedef struct {
    uint64_t      polls;
    uint64_t      cancel_at;
    // When set, only the call numbered cancel_at returns true.
    bool          once;
    // When set, the resident acquisitions made so far are recorded per poll.
    n00b_store_t *store;
    uint64_t     *acquired;
    uint64_t      acquired_cap;
} probe_t;

static uint64_t
acquisitions(n00b_store_t *store)
{
    auto stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_residency_stats_t stats = n00b_result_get(stats_r);
    return stats.cache_hits + stats.cache_misses;
}

// Returns true from the call numbered cancel_at (zero-based) on.
static bool
probe_poll(void *ctx)
{
    probe_t *probe = ctx;
    if (probe->store != nullptr && probe->polls < probe->acquired_cap) {
        probe->acquired[probe->polls] = acquisitions(probe->store);
    }
    uint64_t poll = probe->polls++;
    return probe->once ? poll == probe->cancel_at : poll >= probe->cancel_at;
}

static probe_t
probe_new(uint64_t cancel_at)
{
    return (probe_t){.cancel_at = cancel_at};
}

static probe_t
probe_tracking(uint64_t cancel_at, n00b_store_t *store)
{
    probe_t probe = {
        .cancel_at    = cancel_at,
        .store        = store,
        .acquired_cap = 4096,
    };
    probe.acquired = n00b_alloc_array(uint64_t, probe.acquired_cap);
    return probe;
}

static uint64_t
polls_seeing(probe_t *probe, uint64_t acquired)
{
    uint64_t n = 0;
    for (uint64_t i = 0; i < probe->polls && i < probe->acquired_cap; i++) {
        if (probe->acquired[i] == acquired) {
            n++;
        }
    }
    return n;
}

static n00b_vfs_t *
new_memory_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    return vfs;
}

static n00b_store_schema_t *
cancel_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"id")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"level")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"message",
        .index_kind     = N00B_STORE_INDEX_FULLTEXT,
        .include_in_all = true)));
    return schema;
}

typedef struct {
    n00b_store_t  *store;
    _Atomic(bool)  done;
} seal_ctx_t;

static void *
seal_main(void *arg)
{
    seal_ctx_t *ctx = arg;
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(ctx->store,
                                                      .seal_ts = 1000)));
    n00b_atomic_store(&ctx->done, true);
    return ctx;
}

// Seals from another thread, so a hot pin left held fails the check below
// instead of hanging the test. A hang detector: the bound is far past what an
// unpinned seal needs.
static void
seal_unblocked(n00b_store_t *store)
{
    seal_ctx_t ctx      = {.store = store};
    auto       thread_r = n00b_thread_spawn(seal_main, &ctx);
    CHECK(n00b_result_is_ok(thread_r));

    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (int i = 0; i < 120000 && !n00b_atomic_load(&ctx.done); i++) {
        nanosleep(&pause, nullptr);
    }
    CHECK(n00b_atomic_load(&ctx.done));
    CHECK(n00b_thread_join(n00b_result_get(thread_r)) == &ctx);
}

static n00b_store_t *
open_store(n00b_store_commit_topic_t *topic)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs-cancel",
                                       cancel_schema(),
                                       .commit_topic = topic);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static void
ingest(n00b_store_t *store, int64_t id, n00b_string_t *level)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(level));
    n00b_json_object_put_n00b(record,
                              r"message",
                              n00b_json_string_new_from_n00b(r"alpha beta"));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record)));
}

static void
seal(n00b_store_t *store, uint64_t seal_ts)
{
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(store,
                                                      .seal_ts = seal_ts)));
}

// `shards` sealed shards of `per_shard` records each, and an empty hot shard.
static void
fill_sealed(n00b_store_t  *store,
            uint64_t       shards,
            uint64_t       per_shard,
            n00b_string_t *level)
{
    int64_t id = 0;
    for (uint64_t s = 0; s < shards; s++) {
        for (uint64_t i = 0; i < per_shard; i++) {
            ingest(store, id++, level);
        }
        seal(store, 1000 + s);
    }
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static void
close_store(n00b_store_t *store)
{
    CHECK(active_pins(store) == 0);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static n00b_filter_field_t *
field_ok(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
level_is(n00b_string_t *level)
{
    auto filter_r = n00b_filter_eq(field_ok(r"level"), n00b_fv_utf8(level));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static n00b_filter_t *
contains_alpha(void)
{
    auto filter_r = n00b_filter_contains(field_ok(r"message"), r"alpha");
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static n00b_plan_predicate_t *
lowered(n00b_filter_t *filter)
{
    auto pred_r = n00b_filter_lower_to_plan(filter);
    CHECK(n00b_result_is_ok(pred_r));
    return n00b_result_get(pred_r);
}

// Polls a snapshot cursor makes over `filter` with no limit: the baseline
// every n00b_query_run below shares, since each is built on that cursor.
// Checks every poll happened before the first hit, which is what lets a
// later poll index be attributed to the loop after the cursor.
static uint64_t
cursor_polls(n00b_store_t *store, n00b_filter_t *filter, uint64_t *hits)
{
    auto view_r = n00b_query_view(store, filter, .limit = 0);
    CHECK(n00b_result_is_ok(view_r));
    n00b_query_view_t *view = n00b_result_get(view_r);

    probe_t probe    = probe_new(NEVER);
    auto    cursor_r = n00b_query_cursor(view,
                                         .cancel_cb  = probe_poll,
                                         .cancel_ctx = &probe);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    uint64_t count = 0;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        CHECK(n00b_result_is_ok(next_r));
        if (!n00b_option_is_set(n00b_result_get(next_r))) {
            break;
        }
        count++;
    }
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    *hits = count;
    return probe.polls;
}

typedef struct {
    bool                 ranked;
    uint64_t             limit;
    n00b_query_group_by_list_t *group_by;
    bool                 count;
} run_shape_t;

static n00b_query_t *
query_for(n00b_filter_t *filter, run_shape_t shape, probe_t *probe)
{
    n00b_query_agg_spec_list_t *aggregates = nullptr;
    if (shape.count) {
        aggregates  = n00b_alloc(n00b_query_agg_spec_list_t);
        *aggregates = n00b_list_new_private(n00b_query_agg_spec_t *,
                                            .scan_kind = N00B_GC_SCAN_KIND_ALL);
        auto spec_r = n00b_query_agg(N00B_QUERY_AGG_COUNT, nullptr);
        CHECK(n00b_result_is_ok(spec_r));
        n00b_list_push(*aggregates, n00b_result_get(spec_r));
    }
    auto query_r = n00b_query_new(filter,
                                  .ranked     = shape.ranked,
                                  .limit      = shape.limit,
                                  .group_by   = shape.group_by,
                                  .aggregates = aggregates,
                                  .cancel_cb  = probe_poll,
                                  .cancel_ctx = probe);
    CHECK(n00b_result_is_ok(query_r));
    return n00b_result_get(query_r);
}

// Polls a full run makes, with the result checked and released.
static uint64_t
run_polls(n00b_store_t *store, n00b_filter_t *filter, run_shape_t shape)
{
    probe_t probe    = probe_new(NEVER);
    auto    result_r = n00b_query_run(store, query_for(filter, shape, &probe));
    CHECK(n00b_result_is_ok(result_r));
    CHECK(n00b_result_is_ok(n00b_query_result_close(n00b_result_get(result_r))));
    return probe.polls;
}

// Cancels on poll `at` and checks the run stops there and releases everything.
static void
run_cancels_at(n00b_store_t  *store,
               n00b_filter_t *filter,
               run_shape_t    shape,
               uint64_t       at)
{
    probe_t probe    = probe_new(at);
    auto    result_r = n00b_query_run(store, query_for(filter, shape, &probe));
    CHECK(n00b_result_is_err(result_r));
    CHECK(n00b_result_get_err(result_r) == N00B_QUERY_ERR_CANCELED);
    CHECK(probe.polls == at + 1);
    CHECK(active_pins(store) == 0);
}

// ---------------------------------------------------------------------------
// Ranked path. Before the cursor, n00b_query_run prepares each term, polling
// per boundary and through the term's postings. Each position the cursor
// yields then polls once per 1024, whether it is kept, scored, or offered to
// the top-N heap. One sealed shard, every record matching the one term.
// ---------------------------------------------------------------------------
static void
test_ranked_path_polls_each_loop(void)
{
    n00b_store_t  *store  = open_store(nullptr);
    n00b_filter_t *filter = contains_alpha();
    fill_sealed(store, 1, LARGE_N, r"info");

    uint64_t hits = 0;
    uint64_t c    = cursor_polls(store, filter, &hits);
    CHECK(hits == LARGE_N);

    run_shape_t unranked = {.limit = 0};
    run_shape_t ranked   = {.ranked = true, .limit = 0};
    run_shape_t top      = {.ranked = true, .limit = 10};

    // The position walk. Its last poll comes after the cursor's last, so
    // cancelling there stops the run's own loop.
    uint64_t u = run_polls(store, filter, unranked);
    CHECK(u == c + LARGE_POLLS);
    run_cancels_at(store, filter, unranked, u - 1);

    // Term preparation, which runs first: one boundary poll, then the
    // postings walk over df == LARGE_N.
    uint64_t prepare = 1 + LARGE_POLLS;
    uint64_t r0      = run_polls(store, filter, ranked);
    CHECK(r0 == u + prepare);
    run_cancels_at(store, filter, ranked, 0);
    run_cancels_at(store, filter, ranked, 1);
    run_cancels_at(store, filter, ranked, r0 - 1);

    // The top-N heap is fed by the same walk and adds no polls of its own; a
    // cancel inside the walk must still leave every hit released.
    uint64_t rl = run_polls(store, filter, top);
    CHECK(rl == r0);
    run_cancels_at(store, filter, top, rl - 1);

    close_store(store);
    printf("  [PASS] ranked path polls prepare and the position walk "
           "(cursor=%llu ranked=%llu)\n",
           (unsigned long long)c,
           (unsigned long long)rl);
}

// ---------------------------------------------------------------------------
// Ranked path over hot records. Preparation looks the term up in the hot shard
// under the hot pin and walks its postings. A seal waits on that pin, so the
// walk has to answer the hook.
// ---------------------------------------------------------------------------
static void
test_ranked_hot_walk_polls(void)
{
    n00b_store_t  *store  = open_store(nullptr);
    n00b_filter_t *filter = contains_alpha();
    for (int64_t i = 0; i < LARGE_N; i++) {
        ingest(store, i, r"info");
    }

    uint64_t hits = 0;
    uint64_t c    = cursor_polls(store, filter, &hits);
    CHECK(hits == LARGE_N);

    run_shape_t unranked = {.limit = 0};
    run_shape_t ranked   = {.ranked = true, .limit = 0};
    uint64_t    u        = run_polls(store, filter, unranked);
    CHECK(u == c + LARGE_POLLS);

    // The boundary poll, then the hot postings walk, then the position walk.
    uint64_t prepare = 1 + LARGE_POLLS;
    uint64_t r       = run_polls(store, filter, ranked);
    CHECK(r == prepare + u);

    // Poll 1 is the first of the hot postings walk, after the boundary poll. A seal waits on the hot pin, so it finishing shows the cancel
    // released it.
    run_cancels_at(store, filter, ranked, 1);
    seal_unblocked(store);

    close_store(store);
    printf("  [PASS] ranked hot postings walk polls under the hot pin "
           "(ranked=%llu)\n",
           (unsigned long long)r);
}

// ---------------------------------------------------------------------------
// Aggregate path. COUNT alone sums each boundary's matches without walking
// them, so it polls only while planning, where the cursor also polls once per
// 1024 positions it walks. A group-by walks every hit and polls per hit; its
// row is found by digest, with no search to poll.
// ---------------------------------------------------------------------------
static void
test_aggregate_path_polls_each_hit(void)
{
    n00b_store_t  *store  = open_store(nullptr);
    n00b_filter_t *filter = contains_alpha();
    fill_sealed(store, 1, LARGE_N, r"info");

    uint64_t hits = 0;
    uint64_t c    = cursor_polls(store, filter, &hits);
    CHECK(hits == LARGE_N);

    run_shape_t count = {.count = true};
    uint64_t    a     = run_polls(store, filter, count);
    CHECK(a == c - LARGE_POLLS);
    run_cancels_at(store, filter, count, a - 1);

    n00b_query_group_by_list_t *group_by =
        n00b_alloc(n00b_query_group_by_list_t);
    *group_by = n00b_list_new_private(n00b_filter_field_t *,
                                      .scan_kind = N00B_GC_SCAN_KIND_ALL);
    n00b_list_push(*group_by, field_ok(r"id"));
    run_shape_t grouped = {.count = true, .group_by = group_by};

    uint64_t g = run_polls(store, filter, grouped);
    CHECK(g == c + LARGE_POLLS);
    run_cancels_at(store, filter, grouped, g - 1);

    close_store(store);
    printf("  [PASS] aggregate path polls per hit (grouped=%llu)\n",
           (unsigned long long)g);
}

// ---------------------------------------------------------------------------
// n00b_plan_store_sealed polls before each kept shard in both passes. The
// predicate has no index, so the collect pass reaches no shard and the only
// polls made before the first shard is acquired are those S collect polls and
// the first execute poll.
// ---------------------------------------------------------------------------
static void
test_store_sealed_polls_per_shard(void)
{
    const uint64_t shards = 4;
    n00b_store_t  *store  = open_store(nullptr);
    fill_sealed(store, shards, 100, r"error");
    n00b_plan_predicate_t *predicate = lowered(level_is(r"error"));

    uint64_t a0    = acquisitions(store);
    probe_t  probe = probe_tracking(NEVER, store);
    auto     all_r = n00b_plan_store_sealed(store,
                                            predicate,
                                            nullptr,
                                            .cancel_cb  = probe_poll,
                                            .cancel_ctx = &probe);
    CHECK(n00b_result_is_ok(all_r));
    CHECK(n00b_result_is_ok(n00b_plan_shard_result_count(
        n00b_result_get(all_r))));
    CHECK(n00b_result_get(n00b_plan_shard_result_count(
              n00b_result_get(all_r)))
          == shards);
    CHECK(polls_seeing(&probe, a0) == shards + 1);
    // Each shard's own execution polls too, past the 2 * S of the fan-out.
    CHECK(probe.polls > 2 * shards);

    // Canceled on the first execute poll, before any shard is acquired.
    uint64_t a1       = acquisitions(store);
    probe_t  at_exec  = probe_new(shards);
    auto     cancel_r = n00b_plan_store_sealed(store,
                                               predicate,
                                               nullptr,
                                               .cancel_cb  = probe_poll,
                                               .cancel_ctx = &at_exec);
    CHECK(n00b_result_is_err(cancel_r));
    CHECK(n00b_result_get_err(cancel_r) == N00B_PLAN_ERR_CANCELED);
    CHECK(at_exec.polls == shards + 1);
    CHECK(acquisitions(store) == a1);
    CHECK(active_pins(store) == 0);

    close_store(store);
    printf("  [PASS] store_sealed polls per shard in both passes\n");
}

// ---------------------------------------------------------------------------
// Hot tail scan. Collect and execution get the hook, and copying matches out
// polls every 1024. `through` caps how many records execution scans without
// changing the collect walk, and a filter nothing matches leaves the copy loop
// empty, so each difference below is one of the two.
// ---------------------------------------------------------------------------
static uint64_t
hot_scan_polls(n00b_store_t     *store,
               n00b_string_t    *level,
               n00b_store_pos_t *through,
               uint64_t         *matches)
{
    probe_t probe  = probe_new(NEVER);
    auto    scan_r = n00b_store_hot_tail_scan_after(store,
                                                    lowered(level_is(level)),
                                                    nullptr,
                                                    .through    = through,
                                                    .cancel_cb  = probe_poll,
                                                    .cancel_ctx = &probe);
    CHECK(n00b_result_is_ok(scan_r));
    *matches = (uint64_t)n00b_list_len(*n00b_result_get(scan_r).matches);
    return probe.polls;
}

static void
test_hot_tail_scan_polls_execution_and_copy(void)
{
    n00b_store_t *store = open_store(nullptr);
    for (int64_t i = 0; i < LARGE_N; i++) {
        ingest(store, i, r"error");
    }

    uint64_t matches = 0;
    uint64_t all     = hot_scan_polls(store, r"error", nullptr, &matches);
    CHECK(matches == LARGE_N);
    uint64_t none    = hot_scan_polls(store, r"nomatch", nullptr, &matches);
    CHECK(matches == 0);
    CHECK(all - none == LARGE_POLLS);

    auto scan_r = n00b_store_hot_tail_scan_after(store,
                                                 lowered(level_is(r"error")),
                                                 nullptr);
    CHECK(n00b_result_is_ok(scan_r));
    n00b_store_pos_t through = n00b_result_get(scan_r).last_observed;
    through.ordinal          = 999;
    uint64_t capped = hot_scan_polls(store, r"nomatch", &through, &matches);
    CHECK(none - capped == LARGE_POLLS - 1);

    // Canceled on the first poll, inside the plan's collect: the plan's
    // cancel has to come back as the store's.
    probe_t first    = probe_new(0);
    auto    first_r  = n00b_store_hot_tail_scan_after(store,
                                                      lowered(level_is(r"error")),
                                                      nullptr,
                                                      .cancel_cb  = probe_poll,
                                                      .cancel_ctx = &first);
    CHECK(n00b_result_is_err(first_r));
    CHECK(n00b_result_get_err(first_r) == N00B_STORE_ERR_CANCELED);
    CHECK(first.polls == 1);

    // Canceled on the last poll, inside the copy loop: the hot pin must be
    // released, or the seal below waits on it forever.
    probe_t probe    = probe_new(all - 1);
    auto    cancel_r = n00b_store_hot_tail_scan_after(store,
                                                      lowered(level_is(r"error")),
                                                      nullptr,
                                                      .cancel_cb  = probe_poll,
                                                      .cancel_ctx = &probe);
    CHECK(n00b_result_is_err(cancel_r));
    CHECK(n00b_result_get_err(cancel_r) == N00B_STORE_ERR_CANCELED);
    seal(store, 1000);

    close_store(store);
    printf("  [PASS] hot tail scan polls execution and copy (all=%llu)\n",
           (unsigned long long)all);
}

// A snapshot query over hot records reaches the scan through the cursor, and
// a cancel inside the scan comes back as a query cancel, not a fault.
static void
test_hot_boundary_cancel_maps_to_query_canceled(void)
{
    n00b_store_t *store = open_store(nullptr);
    for (int64_t i = 0; i < LARGE_N; i++) {
        ingest(store, i, r"error");
    }
    n00b_filter_t *filter = level_is(r"error");

    uint64_t matches = 0;
    uint64_t scan    = hot_scan_polls(store, r"error", nullptr, &matches);
    uint64_t hits    = 0;
    uint64_t c       = cursor_polls(store, filter, &hits);
    CHECK(hits == LARGE_N);
    // The scan's polls, then the cursor's copy of each match.
    CHECK(c == scan + LARGE_POLLS);

    run_cancels_at(store, filter, (run_shape_t){.limit = 0}, scan - 1);

    close_store(store);
    printf("  [PASS] hot scan cancel surfaces as N00B_QUERY_ERR_CANCELED\n");
}

// ---------------------------------------------------------------------------
// A snapshot cursor that fails has already moved past the boundary that
// failed, so calling it again must return the failure again rather than end
// the scan short. Covered for the bulk and streaming paths, on hot and sealed
// boundaries, through next and through hit_count.
// ---------------------------------------------------------------------------
typedef n00b_result_t(n00b_option_t(n00b_query_hit_t *)) next_result_t;

typedef struct {
    n00b_query_view_t   *view;
    n00b_query_cursor_t *cursor;
} scan_t;

static scan_t
open_scan(n00b_store_t  *store,
          n00b_filter_t *filter,
          bool           streaming,
          probe_t       *probe)
{
    auto view_r = n00b_query_view(store, filter, .limit = 0);
    CHECK(n00b_result_is_ok(view_r));
    scan_t scan     = {.view = n00b_result_get(view_r)};
    auto   cursor_r = n00b_query_cursor(scan.view,
                                        .cancel_cb  = probe_poll,
                                        .cancel_ctx = probe);
    CHECK(n00b_result_is_ok(cursor_r));
    scan.cursor = n00b_result_get(cursor_r);
    n00b_query_cursor_set_streaming(scan.cursor, streaming);
    return scan;
}

static void
close_scan(scan_t scan)
{
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(scan.cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(scan.view)));
}

// Calls next until it stops returning hits.
static next_result_t
drain(n00b_query_cursor_t *cursor)
{
    next_result_t next_r;
    do {
        next_r = n00b_query_cursor_next(cursor);
    } while (n00b_result_is_ok(next_r)
             && n00b_option_is_set(n00b_result_get(next_r)));
    return next_r;
}

static bool
is_canceled(next_result_t next_r)
{
    return n00b_result_is_err(next_r)
        && n00b_result_get_err(next_r) == N00B_QUERY_ERR_CANCELED;
}

// Polls a streaming cursor over `filter` makes with nothing canceled.
static uint64_t
streaming_polls(n00b_store_t *store, n00b_filter_t *filter)
{
    probe_t       probe = probe_new(NEVER);
    scan_t        scan  = open_scan(store, filter, true, &probe);
    next_result_t end_r = drain(scan.cursor);
    CHECK(n00b_result_is_ok(end_r));
    close_scan(scan);
    return probe.polls;
}

// Cancels on poll `at` only, then checks a second next is canceled too. A
// hook that cancels once shows a cursor that resumed as well as one that
// skipped ahead.
static void
check_cancel_sticks(n00b_store_t  *store,
                    n00b_filter_t *filter,
                    bool           streaming,
                    uint64_t       at)
{
    probe_t probe = probe_new(at);
    probe.once    = true;
    scan_t  scan  = open_scan(store, filter, streaming, &probe);
    CHECK(is_canceled(drain(scan.cursor)));
    CHECK(probe.polls == at + 1);
    CHECK(is_canceled(n00b_query_cursor_next(scan.cursor)));
    close_scan(scan);
}

static void
test_cursor_cancel_is_sticky(void)
{
    // Hot: cancel on the scan's last poll, inside the scan, and on the
    // second poll of the bulk path's copy loop, after 1024 hits are built.
    n00b_store_t *hot_store = open_store(nullptr);
    for (int64_t i = 0; i < LARGE_N; i++) {
        ingest(hot_store, i, r"error");
    }
    n00b_filter_t *errors  = level_is(r"error");
    uint64_t       matches = 0;
    uint64_t       scan    = hot_scan_polls(hot_store, r"error", nullptr, &matches);
    check_cancel_sticks(hot_store, errors, false, scan - 1);
    check_cancel_sticks(hot_store, errors, true, scan - 1);
    check_cancel_sticks(hot_store, errors, false, scan + 1);
    close_store(hot_store);

    // One sealed shard serves the sealed cases. Every record contains
    // "alpha", and its levels span "error" without holding one, so a level
    // filter keeps the shard unpruned and makes planning verify every record.
    //
    // Bulk: cancel on the last poll of the loop that builds the boundary's
    // hits, after 2048 of them are built, through next and through hit_count.
    // Streaming: cancel on the last poll of the loop that delivers hits one
    // at a time, and on the first poll, inside planning the boundary.
    n00b_store_t *sealed_store = open_store(nullptr);
    for (int64_t i = 0; i < LARGE_N; i++) {
        ingest(sealed_store, i, (i & 1) ? r"info" : r"debug");
    }
    seal(sealed_store, 1000);
    n00b_filter_t *alpha = contains_alpha();
    uint64_t       hits  = 0;
    uint64_t       c     = cursor_polls(sealed_store, alpha, &hits);
    CHECK(hits == LARGE_N);
    check_cancel_sticks(sealed_store, alpha, false, c - 1);

    probe_t probe   = probe_new(c - 1);
    probe.once      = true;
    scan_t  counted = open_scan(sealed_store, alpha, false, &probe);
    auto    count_r = n00b_query_cursor_hit_count(counted.cursor);
    CHECK(n00b_result_is_err(count_r));
    CHECK(n00b_result_get_err(count_r) == N00B_QUERY_ERR_CANCELED);
    count_r = n00b_query_cursor_hit_count(counted.cursor);
    CHECK(n00b_result_is_err(count_r));
    CHECK(n00b_result_get_err(count_r) == N00B_QUERY_ERR_CANCELED);
    CHECK(is_canceled(n00b_query_cursor_next(counted.cursor)));
    close_scan(counted);

    uint64_t s = streaming_polls(sealed_store, alpha);
    check_cancel_sticks(sealed_store, alpha, true, s - 1);
    check_cancel_sticks(sealed_store, errors, true, 0);
    close_store(sealed_store);

    printf("  [PASS] a canceled cursor stays canceled (scan=%llu cursor=%llu "
           "streaming=%llu)\n",
           (unsigned long long)scan,
           (unsigned long long)c,
           (unsigned long long)s);
}

// The same holds for a failure that is not a cancel. The second shard's object
// is deleted after the scan began, so staging its boundary fails, and next
// keeps returning that failure.
static void
test_cursor_failure_is_sticky(void)
{
    for (int streaming = 0; streaming < 2; streaming++) {
        n00b_vfs_t *vfs     = new_memory_vfs();
        auto        store_r = n00b_store_open_vfs(vfs,
                                                  r"/rocs-cancel",
                                                  cancel_schema());
        CHECK(n00b_result_is_ok(store_r));
        n00b_store_t *store = n00b_result_get(store_r);
        for (int64_t i = 0; i < 100; i++) {
            ingest(store, i, r"error");
        }
        seal(store, 1000);
        for (int64_t i = 100; i < 200; i++) {
            ingest(store, i, r"error");
        }
        auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 1001);
        CHECK(n00b_result_is_ok(seal_r));
        auto path_r = n00b_store_catalog_entry_get_object_path(
            n00b_result_get(seal_r));
        CHECK(n00b_result_is_ok(path_r));
        CHECK(n00b_result_is_ok(n00b_store_residency_trim(store)));

        probe_t probe   = probe_new(NEVER);
        scan_t  scan    = open_scan(store, level_is(r"error"), streaming, &probe);
        auto    first_r = n00b_query_cursor_next(scan.cursor);
        CHECK(n00b_result_is_ok(first_r));
        CHECK(n00b_option_is_set(n00b_result_get(first_r)));
        CHECK(n00b_result_is_ok(n00b_vfs_delete(vfs, n00b_result_get(path_r))));

        CHECK(n00b_result_is_err(drain(scan.cursor)));
        CHECK(n00b_result_is_err(n00b_query_cursor_next(scan.cursor)));
        close_scan(scan);
        CHECK(active_pins(store) == 0);
    }
    printf("  [PASS] a failed cursor stays failed\n");
}

// ---------------------------------------------------------------------------
// Every cursor kind, every way to fail. After a cursor's first error, next,
// hit_count, and hit_position_at all return that error, and the hits it
// delivered before failing are a prefix of an unfailed run's, so none was
// skipped or repeated.
//
// Snapshot cursors fail while staging the second of two sealed shards: by a
// cancel, or because the shard's object was deleted. A live cursor fails in
// its tail scan by a cancel, or while building hits for positions already
// pending in a shard whose object was deleted.
// ---------------------------------------------------------------------------
typedef enum {
    KIND_BULK,
    KIND_STREAMING,
    KIND_LIVE,
} cursor_kind_t;

typedef enum {
    FAIL_CANCEL,
    FAIL_STAGING,
} fail_route_t;

#define MAX_DELIVERED 256

typedef struct {
    n00b_vfs_t          *vfs;
    n00b_conduit_t      *conduit;
    n00b_store_t        *store;
    n00b_query_view_t   *view;
    n00b_query_cursor_t *cursor;
    probe_t              probe;
    n00b_store_pos_t     delivered[MAX_DELIVERED];
    uint64_t             n;
} fixture_t;

static uint32_t next_topic_id = 9700;

static void
fixture_open(fixture_t *f, cursor_kind_t kind)
{
    *f            = (fixture_t){.vfs = new_memory_vfs()};
    f->probe      = probe_new(NEVER);
    f->probe.once = true;

    n00b_store_commit_topic_t *topic = nullptr;
    if (kind == KIND_LIVE) {
        auto conduit_r = n00b_conduit_new();
        CHECK(n00b_result_is_ok(conduit_r));
        f->conduit   = n00b_result_get(conduit_r);
        auto topic_r = n00b_store_commit_topic_get(
            f->conduit,
            N00B_CONDUIT_URI_USER_EVENT(next_topic_id++));
        CHECK(n00b_result_is_ok(topic_r));
        topic = n00b_result_get(topic_r);
    }
    auto store_r = n00b_store_open_vfs(f->vfs,
                                       r"/rocs-cancel",
                                       cancel_schema(),
                                       .commit_topic = topic);
    CHECK(n00b_result_is_ok(store_r));
    f->store = n00b_result_get(store_r);

    if (kind != KIND_LIVE) {
        fill_sealed(f->store, 2, 100, r"error");
    }
    auto view_r = n00b_query_view(f->store,
                                  level_is(r"error"),
                                  .mode = kind == KIND_LIVE
                                              ? N00B_QUERY_MODE_LIVE
                                              : N00B_QUERY_MODE_SNAPSHOT);
    CHECK(n00b_result_is_ok(view_r));
    f->view       = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(f->view,
                                      .cancel_cb  = probe_poll,
                                      .cancel_ctx = &f->probe);
    CHECK(n00b_result_is_ok(cursor_r));
    f->cursor = n00b_result_get(cursor_r);
    n00b_query_cursor_set_streaming(f->cursor, kind == KIND_STREAMING);
}

static void
fixture_close(fixture_t *f)
{
    CHECK(n00b_result_is_ok(n00b_query_cursor_close(f->cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(f->view)));
    CHECK(active_pins(f->store) == 0);
    if (f->conduit != nullptr) {
        n00b_conduit_destroy(f->conduit);
    }
}

// Calls next `count` times, or until it stops returning hits, and records
// each hit's position. Returns the result that ended the calls.
static next_result_t
take(fixture_t *f, uint64_t count)
{
    next_result_t next_r = {};
    for (uint64_t i = 0; i < count; i++) {
        next_r = n00b_query_cursor_next(f->cursor);
        if (n00b_result_is_err(next_r)
            || !n00b_option_is_set(n00b_result_get(next_r))) {
            return next_r;
        }
        auto pos_r = n00b_query_hit_pos(n00b_option_get(n00b_result_get(next_r)));
        CHECK(n00b_result_is_ok(pos_r));
        CHECK(f->n < MAX_DELIVERED);
        f->delivered[f->n++] = n00b_result_get(pos_r);
    }
    return next_r;
}

// Unloads the store's unpinned shards and deletes the object of the shard
// sealed last, so staging any of its records fails.
static void
break_last_shard(fixture_t *f, n00b_store_catalog_entry_t *entry)
{
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_result_is_ok(n00b_store_residency_trim(f->store)));
    CHECK(n00b_result_is_ok(n00b_vfs_delete(f->vfs, n00b_result_get(path_r))));
}

static n00b_store_catalog_entry_t *
last_entry(n00b_store_t *store)
{
    auto count_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) > 0);
    auto at_r = n00b_store_catalog_visible_entry_at(store,
                                                    n00b_result_get(count_r) - 1);
    CHECK(n00b_result_is_ok(at_r));
    CHECK(n00b_option_is_set(n00b_result_get(at_r)));
    return n00b_option_get(n00b_result_get(at_r));
}

static bool
same_error(n00b_result_error_t a, n00b_result_error_t b)
{
    return a.kind == b.kind && a.code == b.code && a.payload == b.payload;
}

// Drives one cursor through its failure and returns the error. With `fail`
// false, it makes the same store changes and calls without the failure, so
// its positions are the reference.
static n00b_result_error_t
drive(fixture_t *f, cursor_kind_t kind, fail_route_t route, bool fail)
{
    next_result_t end_r;
    if (kind != KIND_LIVE) {
        end_r = take(f, 1);
        CHECK(n00b_result_is_ok(end_r)
              && n00b_option_is_set(n00b_result_get(end_r)));
        if (fail && route == FAIL_CANCEL) {
            f->probe.cancel_at = f->probe.polls;
        }
        if (fail && route == FAIL_STAGING) {
            break_last_shard(f, last_entry(f->store));
        }
        end_r = take(f, MAX_DELIVERED);
    }
    else {
        for (int64_t i = 0; i < 2; i++) {
            ingest(f->store, i, r"error");
        }
        end_r = take(f, 2);
        CHECK(n00b_result_is_ok(end_r) && f->n == 2);
        if (fail && route == FAIL_CANCEL) {
            f->probe.cancel_at = f->probe.polls;
        }
        for (int64_t i = 2; i < 6; i++) {
            ingest(f->store, i, r"error");
        }
        if (route == FAIL_STAGING) {
            // Every new position is pending before any of its hits is built.
            CHECK(n00b_result_is_ok(n00b_query_live_tail_scan_once(f->view)));
            auto pending_r = n00b_query_live_tail_pending_count(f->view);
            CHECK(n00b_result_is_ok(pending_r));
            CHECK(n00b_result_get(pending_r) >= 4);
            auto seal_r = n00b_store_seal_hot_shard(f->store, .seal_ts = 1000);
            CHECK(n00b_result_is_ok(seal_r));
            if (fail) {
                break_last_shard(f, n00b_result_get(seal_r));
            }
        }
        end_r = take(f, 4);
        // One more record, so that a call after the failure has something to
        // deliver rather than waiting for a commit.
        ingest(f->store, 6, r"error");
        if (!fail) {
            end_r = take(f, 1);
            CHECK(n00b_result_is_ok(end_r) && f->n == 7);
            return (n00b_result_error_t){};
        }
    }

    if (!fail) {
        CHECK(n00b_result_is_ok(end_r));
        return (n00b_result_error_t){};
    }
    CHECK(n00b_result_is_err(end_r));
    if (route == FAIL_CANCEL) {
        CHECK(n00b_result_get_err(end_r) == N00B_QUERY_ERR_CANCELED);
    }
    return n00b_result_get_error(end_r);
}

static void
test_every_cursor_failure_is_sticky(void)
{
    for (int kind = KIND_BULK; kind <= KIND_LIVE; kind++) {
        for (int route = FAIL_CANCEL; route <= FAIL_STAGING; route++) {
            fixture_t ref;
            fixture_open(&ref, kind);
            (void)drive(&ref, kind, route, false);

            fixture_t f;
            fixture_open(&f, kind);
            n00b_result_error_t first = drive(&f, kind, route, true);

            CHECK(f.n < ref.n);
            for (uint64_t i = 0; i < f.n; i++) {
                CHECK(n00b_store_pos_compare(f.delivered[i], ref.delivered[i])
                      == 0);
            }

            next_result_t again_r = n00b_query_cursor_next(f.cursor);
            CHECK(n00b_result_is_err(again_r));
            CHECK(same_error(n00b_result_get_error(again_r), first));
            auto count_r = n00b_query_cursor_hit_count(f.cursor);
            CHECK(n00b_result_is_err(count_r));
            CHECK(same_error(n00b_result_get_error(count_r), first));
            auto at_r = n00b_query_cursor_hit_position_at(f.cursor, 0);
            CHECK(n00b_result_is_err(at_r));
            CHECK(same_error(n00b_result_get_error(at_r), first));

            fixture_close(&ref);
            fixture_close(&f);
        }
    }
    printf("  [PASS] every cursor kind stays failed after its first error\n");
}

// ---------------------------------------------------------------------------
// Live cursors. Construction plans the sealed history with
// n00b_plan_store_sealed, and each next runs a tail scan over what arrived
// since. Both answer to the cursor's hook, and the tail scan also stops when
// the cursor or its view is closed.
// ---------------------------------------------------------------------------
typedef struct {
    n00b_conduit_t            *conduit;
    n00b_store_commit_topic_t *topic;
    n00b_store_t              *store;
} live_ctx_t;

static live_ctx_t
live_ctx_new(uint32_t topic_id)
{
    live_ctx_t ctx       = {};
    auto       conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    ctx.conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_commit_topic_get(
        ctx.conduit,
        N00B_CONDUIT_URI_USER_EVENT(topic_id));
    CHECK(n00b_result_is_ok(topic_r));
    ctx.topic = n00b_result_get(topic_r);
    ctx.store = open_store(ctx.topic);
    return ctx;
}

static void
live_ctx_destroy(live_ctx_t *ctx)
{
    close_store(ctx->store);
    n00b_conduit_destroy(ctx->conduit);
}

static n00b_query_view_t *
live_view(n00b_store_t *store)
{
    auto view_r = n00b_query_view(store,
                                  level_is(r"error"),
                                  .mode = N00B_QUERY_MODE_LIVE);
    CHECK(n00b_result_is_ok(view_r));
    return n00b_result_get(view_r);
}

// A live cursor walks its sealed history on its first next, one shard at a
// time, and construction does no work for a cancel to cut short.
static void
test_live_cursor_history_passes_cancel(void)
{
    const uint64_t shards = 4;
    live_ctx_t     ctx    = live_ctx_new(9601);
    fill_sealed(ctx.store, shards, 100, r"error");
    n00b_query_view_t *view = live_view(ctx.store);

    probe_t probe    = probe_new(0);
    auto    cursor_r = n00b_query_cursor(view,
                                         .cancel_cb  = probe_poll,
                                         .cancel_ctx = &probe);
    CHECK(n00b_result_is_ok(cursor_r));
    CHECK(probe.polls == 0);
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_err(next_r));
    CHECK(n00b_result_get_err(next_r) == N00B_QUERY_ERR_CANCELED);
    CHECK(probe.polls == 1);

    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    live_ctx_destroy(&ctx);
    printf("  [PASS] live cursor history honors the cursor's hook\n");
}

static void
test_live_tail_scan_passes_cancel(void)
{
    const uint64_t shards = 4;
    live_ctx_t     ctx    = live_ctx_new(9602);
    n00b_query_view_t *view = live_view(ctx.store);

    probe_t probe    = probe_new(NEVER);
    auto    cursor_r = n00b_query_cursor(view,
                                         .cancel_cb  = probe_poll,
                                         .cancel_ctx = &probe);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    fill_sealed(ctx.store, shards, 100, r"error");
    uint64_t a0     = acquisitions(ctx.store);
    probe.cancel_at = probe.polls;

    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_err(next_r));
    CHECK(n00b_result_get_err(next_r) == N00B_QUERY_ERR_CANCELED);
    CHECK(acquisitions(ctx.store) == a0);

    CHECK(n00b_result_is_ok(n00b_query_cursor_close(cursor)));
    CHECK(n00b_result_is_ok(n00b_query_view_close(view)));
    live_ctx_destroy(&ctx);
    printf("  [PASS] live tail scan honors the cursor's hook\n");
}

typedef struct {
    n00b_query_view_t *view;
    n00b_thread_t     *closer;
    uint64_t           polls;
    bool               armed;
} close_probe_t;

static bool
view_closed(n00b_query_view_t *view)
{
    auto closed_r = n00b_query_view_is_closed(view);
    CHECK(n00b_result_is_ok(closed_r));
    return n00b_result_get(closed_r);
}

static void *
close_view_main(void *arg)
{
    close_probe_t *probe = arg;
    CHECK(n00b_result_is_ok(n00b_query_view_close(probe->view)));
    return probe;
}

// On the first poll, starts closing the view from another thread and waits
// until the close is visible, then lets the scan go on. Every later poll must
// see the close and stop without consulting this hook again.
static bool
close_on_first_poll(void *ctx)
{
    close_probe_t *probe = ctx;
    if (!probe->armed || probe->polls++ != 0) {
        return false;
    }

    auto thread_r = n00b_thread_spawn(close_view_main, probe);
    CHECK(n00b_result_is_ok(thread_r));
    probe->closer = n00b_result_get(thread_r);

    // A hang detector: the close sets the flag before it waits on anything.
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (int i = 0; i < 120000 && !view_closed(probe->view);
         i++) {
        nanosleep(&pause, nullptr);
    }
    CHECK(view_closed(probe->view));
    return false;
}

static void
test_live_tail_scan_stops_on_close(void)
{
    const uint64_t shards = 4;
    live_ctx_t     ctx    = live_ctx_new(9603);
    n00b_query_view_t *view = live_view(ctx.store);

    close_probe_t probe    = {.view = view};
    auto          cursor_r = n00b_query_cursor(view,
                                               .cancel_cb  = close_on_first_poll,
                                               .cancel_ctx = &probe);
    CHECK(n00b_result_is_ok(cursor_r));
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    // Armed after construction so the first poll it acts on is the tail
    // scan's.
    fill_sealed(ctx.store, shards, 100, r"error");
    probe.armed = true;

    auto next_r = n00b_query_cursor_next(cursor);
    CHECK(n00b_result_is_ok(next_r));
    CHECK(!n00b_option_is_set(n00b_result_get(next_r)));
    CHECK(probe.polls == 1);
    CHECK(probe.closer != nullptr);
    CHECK(n00b_thread_join(probe.closer) == &probe);

    live_ctx_destroy(&ctx);
    printf("  [PASS] closing a live view interrupts its tail scan\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    printf("test_rocs_query_cancel:\n");
    test_ranked_path_polls_each_loop();
    test_ranked_hot_walk_polls();
    test_aggregate_path_polls_each_hit();
    test_store_sealed_polls_per_shard();
    test_hot_tail_scan_polls_execution_and_copy();
    test_hot_boundary_cancel_maps_to_query_canceled();
    test_cursor_cancel_is_sticky();
    test_cursor_failure_is_sticky();
    test_every_cursor_failure_is_sticky();
    test_live_cursor_history_passes_cancel();
    test_live_tail_scan_passes_cancel();
    test_live_tail_scan_stops_on_close();

    n00b_shutdown();
    return 0;
}
