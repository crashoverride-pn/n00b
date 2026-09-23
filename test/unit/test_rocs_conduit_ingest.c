/* test/unit/test_rocs_conduit_ingest.c - WP-005 Phase 7 conduit ingest. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

/* Assert on an ingest counter, and on failure print EVERY counter first
 * (n00b#350).
 *
 * Plain CHECK reports only WHICH comparison failed, never the value it got --
 * so a CI failure on `stats.submitted == 8` could not distinguish 7 (a submit
 * was lost) from 0 (stats never published) from 9 (double counted), and those
 * are three different bugs. This turns the next occurrence into a diagnosis
 * rather than another re-run.
 *
 * Prints only on failure, so a passing run stays quiet.
 *
 * stderr, not stdout: n00b#352 established that n00b_require -> abort
 * discards buffered stdout on Linux, which is exactly the platform where this
 * fires.
 */
#define CHECK_STAT(st, field, expected)                                        \
    do {                                                                       \
        if ((st).field != (uint64_t)(expected)) {                              \
            fprintf(stderr,                                                    \
                    "ingest stats at failure (%s != %llu): submitted=%llu "    \
                    "committed=%llu failed=%llu malformed=%llu "               \
                    "inbox_queued=%llu worker_queued=%llu "                    \
                    "worker_in_flight=%llu last_error=%d\n",                   \
                    #field,                                                    \
                    (unsigned long long)(expected),                            \
                    (unsigned long long)(st).submitted,                        \
                    (unsigned long long)(st).committed,                        \
                    (unsigned long long)(st).failed,                           \
                    (unsigned long long)(st).malformed,                        \
                    (unsigned long long)(st).inbox_queued,                     \
                    (unsigned long long)(st).worker_queued,                    \
                    (unsigned long long)(st).worker_in_flight,                 \
                    (int)(st).last_error);                                     \
        }                                                                      \
        CHECK((st).field == (uint64_t)(expected));                             \
    } while (0)

#define CONCURRENT_PUBLISHERS 4
#define CONCURRENT_RECORDS    256

typedef struct {
    n00b_store_t *store;
    uint32_t      publisher;
} concurrent_submit_ctx_t;

typedef struct {
    n00b_store_ingest_topic_t *topic;
    _Atomic bool               started;
    _Atomic bool               done;
    bool                       published;
    n00b_err_t                 err;
} reject_contended_ctx_t;

static _Atomic bool     concurrent_submit_start;
static _Atomic uint64_t concurrent_submit_ready;
static _Atomic uint64_t concurrent_submit_admitted;
static _Atomic uint64_t concurrent_submit_rejected;

static n00b_json_node_t *record_with_id(int64_t id);

static void *
concurrent_submit_main(void *arg)
{
    concurrent_submit_ctx_t *ctx = arg;
    atomic_fetch_add(&concurrent_submit_ready, 1);
    while (!atomic_load(&concurrent_submit_start)) {
        base_nanosleep_ns(1000);
    }

    for (uint32_t i = 0; i < CONCURRENT_RECORDS; i++) {
        int64_t id = (int64_t)ctx->publisher * CONCURRENT_RECORDS + i;
        auto payload_r = n00b_store_ingest_payload_record(record_with_id(id));
        CHECK(n00b_result_is_ok(payload_r));
        auto submit_r = n00b_store_ingest_submit(ctx->store,
                                                 n00b_result_get(payload_r));
        CHECK(n00b_result_is_ok(submit_r));
        n00b_store_ingest_receipt_t receipt = n00b_result_get(submit_r);
        if (receipt.state == N00B_STORE_INGEST_RECEIPT_ADMITTED_QUEUED) {
            atomic_fetch_add(&concurrent_submit_admitted, 1);
        } else {
            atomic_fetch_add(&concurrent_submit_rejected, 1);
        }
    }
    return nullptr;
}

static void *
reject_contended_submit_main(void *arg)
{
    reject_contended_ctx_t *ctx = arg;
    auto payload_r = n00b_store_ingest_payload_record(record_with_id(1));
    CHECK(n00b_result_is_ok(payload_r));

    atomic_store(&ctx->started, true);
    auto publish_r = n00b_store_ingest_topic_publish_ex(
        ctx->topic,
        n00b_result_get(payload_r),
        .backpressure = N00B_STORE_INGEST_BACKPRESSURE_REJECT);
    ctx->published = n00b_result_is_ok(publish_r);
    ctx->err = ctx->published ? N00B_STORE_OK : n00b_result_get_err(publish_r);
    atomic_store(&ctx->done, true);
    return nullptr;
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
new_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_store(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(), r"/rocs", new_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_with_id(int64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    return record;
}

static n00b_buffer_t *
buffer_from_literal(const char *s)
{
    return n00b_buffer_from_cstr(s);
}

static n00b_store_conduit_ingest_stats_t
wait_for_stats(n00b_store_conduit_ingest_t *adapter,
               uint64_t submitted,
               uint64_t committed,
               uint64_t failed)
{
    n00b_store_conduit_ingest_stats_t stats = {};
    for (uint32_t i = 0; i < 100; i++) {
        auto stats_r = n00b_store_conduit_ingest_stats(adapter);
        CHECK(n00b_result_is_ok(stats_r));
        stats = n00b_result_get(stats_r);
        if (stats.submitted >= submitted
            && stats.committed >= committed
            && stats.failed >= failed) {
            return stats;
        }
        usleep(10000);
    }

    return stats;
}

static void
publish_record(n00b_store_ingest_topic_t *topic, n00b_json_node_t *record)
{
    auto payload_r = n00b_store_ingest_payload_record(record);
    CHECK(n00b_result_is_ok(payload_r));

    auto publish_r = n00b_store_ingest_topic_publish(topic,
                                                     n00b_result_get(payload_r));
    CHECK(n00b_result_is_ok(publish_r));
}

static void
publish_source(n00b_store_ingest_topic_t *topic, const char *source)
{
    auto payload_r = n00b_store_ingest_payload_source(
        buffer_from_literal(source));
    CHECK(n00b_result_is_ok(payload_r));

    auto publish_r = n00b_store_ingest_topic_publish(topic,
                                                     n00b_result_get(payload_r));
    CHECK(n00b_result_is_ok(publish_r));
}

static uint64_t
stream_record_count(n00b_store_t *store)
{
    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    uint64_t count = 0;
    while (true) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(next_opt)) {
            break;
        }
        count++;
    }

    auto close_r = n00b_store_record_stream_close(stream);
    CHECK(n00b_result_is_ok(close_r));
    return count;
}


/* n00b-lang/n00b#350: the multi-worker case waited only on the hot record
 * count, then read the service ingest stats. The record lands before the
 * worker publishes `submitted`/`committed` for it, so on a loaded runner
 * the count could reach its target while the stats were one behind, and
 * the assertion read a stale value. Wait on the stats themselves. */
static n00b_store_conduit_ingest_stats_t
wait_for_service_stats(n00b_store_t *store, uint64_t submitted, uint64_t committed)
{
    n00b_store_conduit_ingest_stats_t stats = {};
    for (uint32_t i = 0; i < 300; i++) {
        auto stats_r = n00b_store_service_ingest_stats(store);
        CHECK(n00b_result_is_ok(stats_r));
        stats = n00b_result_get(stats_r);
        if (stats.submitted >= submitted && stats.committed >= committed
            && stats.worker_queued == 0 && stats.worker_in_flight == 0) {
            return stats;
        }
        usleep(10000);
    }
    return stats;
}

static void
wait_for_stream_records(n00b_store_t *store, uint64_t expected)
{
    for (uint32_t i = 0; i < 100; i++) {
        if (stream_record_count(store) >= expected) {
            return;
        }
        usleep(10000);
    }
    CHECK(stream_record_count(store) >= expected);
}

static void
test_conduit_ingests_variant_payloads(void)
{
    n00b_conduit_t *c = n00b_result_get(n00b_conduit_new());
    n00b_store_t   *store = open_store();

    auto topic_r = n00b_store_ingest_topic_get(
        c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 7201));
    CHECK(n00b_result_is_ok(topic_r));
    n00b_store_ingest_topic_t *topic = n00b_result_get(topic_r);

    auto adapter_r = n00b_store_conduit_ingest_start(store,
                                                     topic,
                                                     .worker_count = 1,
                                                     .queue_capacity = 1);
    CHECK(n00b_result_is_ok(adapter_r));
    n00b_store_conduit_ingest_t *adapter = n00b_result_get(adapter_r);

    publish_record(topic, record_with_id(1));
    publish_source(topic, "{\"id\":2}");
    publish_source(topic, "{bad-json");

    n00b_store_conduit_ingest_stats_t stats =
        wait_for_stats(adapter, 3, 3, 0);
    CHECK_STAT(stats, submitted, 3);
    CHECK_STAT(stats, committed, 3);
    CHECK_STAT(stats, failed, 0);
    CHECK_STAT(stats, malformed, 1);
    CHECK(stats.last_error == N00B_STORE_ERR_PARSE);

    auto close_r = n00b_store_conduit_ingest_close(adapter);
    CHECK(n00b_result_is_ok(close_r));

    auto payload_r = n00b_store_ingest_payload_record(record_with_id(3));
    CHECK(n00b_result_is_ok(payload_r));
    auto publish_r = n00b_store_ingest_topic_publish(
        topic,
        n00b_result_get(payload_r));
    CHECK(n00b_result_is_err(publish_r));
    CHECK(n00b_result_get_err(publish_r) == N00B_STORE_ERR_STATE);
    usleep(50000);

    auto after_r = n00b_store_conduit_ingest_stats(adapter);
    CHECK(n00b_result_is_ok(after_r));
    CHECK(n00b_result_get(after_r).submitted == 3);
    CHECK(n00b_result_get(after_r).committed == 3);
    CHECK(n00b_result_get(after_r).failed == 0);
    CHECK(n00b_result_get(after_r).malformed == 1);

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    auto find_r = n00b_store_catalog_find_shard(store, 1);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    n00b_store_catalog_entry_t *entry =
        n00b_option_get(n00b_result_get(find_r));

    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 3);

    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    for (uint64_t i = 0; i < 3; i++) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next_opt = n00b_result_get(next_r);
        CHECK(n00b_option_is_set(next_opt));

        n00b_store_record_stream_item_t item = n00b_option_get(next_opt);
        CHECK(item.pos.ordinal == i);

        const char       *parse_err = nullptr;
        n00b_json_node_t *row =
            n00b_json_parse((const char *)item.bytes.data,
                            (size_t)item.bytes.byte_len,
                            &parse_err);
        CHECK(row != nullptr);
        CHECK(parse_err == nullptr);

        if (i < 2) {
            n00b_json_node_t *id = n00b_json_object_get(row, r"id");
            CHECK(n00b_json_is_int(id));
            CHECK(n00b_json_as_i64(id) == (int64_t)i + 1);
        }
        else {
            n00b_json_node_t *kind = n00b_json_object_get(row, r"kind");
            CHECK(n00b_json_is_string(kind));
            CHECK(strcmp(n00b_json_as_cstr(kind), "rocs.ingest_error") == 0);

            n00b_json_node_t *tombstone =
                n00b_json_object_get(row, r"rocs_tombstone");
            CHECK(n00b_json_is_bool(tombstone));
            CHECK(n00b_json_as_bool(tombstone));

            n00b_json_node_t *err = n00b_json_object_get(row, r"error_code");
            CHECK(n00b_json_is_int(err));
            CHECK(n00b_json_as_i64(err) == N00B_STORE_ERR_PARSE);

            n00b_json_node_t *source_hex =
                n00b_json_object_get(row, r"source_hex");
            CHECK(n00b_json_is_string(source_hex));
            CHECK(strcmp(n00b_json_as_cstr(source_hex),
                         "7b6261642d6a736f6e") == 0);
        }
    }

    auto eof_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(eof_r));
    CHECK(!n00b_option_is_set(n00b_result_get(eof_r)));

    auto stream_close_r = n00b_store_record_stream_close(stream);
    CHECK(n00b_result_is_ok(stream_close_r));

    n00b_conduit_destroy(c);
}

static void
test_conduit_publish_rejects_without_subscriber(void)
{
    n00b_conduit_t *c = n00b_result_get(n00b_conduit_new());

    auto topic_r = n00b_store_ingest_topic_get(
        c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 7204));
    CHECK(n00b_result_is_ok(topic_r));
    n00b_store_ingest_topic_t *topic = n00b_result_get(topic_r);

    auto payload_r = n00b_store_ingest_payload_record(record_with_id(1));
    CHECK(n00b_result_is_ok(payload_r));

    auto publish_r = n00b_store_ingest_topic_publish_ex(
        topic,
        n00b_result_get(payload_r),
        .backpressure = N00B_STORE_INGEST_BACKPRESSURE_REJECT);
    CHECK(n00b_result_is_err(publish_r));
    CHECK(n00b_result_get_err(publish_r) == N00B_STORE_ERR_STATE);

    n00b_conduit_destroy(c);
}

static void
test_reject_policy_serializes_before_admission(void)
{
    n00b_conduit_t *c = n00b_result_get(n00b_conduit_new());
    n00b_store_t   *store = open_store();

    auto topic_r = n00b_store_ingest_topic_get(
        c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 7205));
    CHECK(n00b_result_is_ok(topic_r));
    n00b_store_ingest_topic_t *topic = n00b_result_get(topic_r);

    auto adapter_r = n00b_store_conduit_ingest_start(store,
                                                     topic,
                                                     .worker_count = 1,
                                                     .queue_capacity = 1);
    CHECK(n00b_result_is_ok(adapter_r));
    n00b_store_conduit_ingest_t *adapter = n00b_result_get(adapter_r);

    auto holder_r = n00b_conduit_publish_claim(
        (n00b_conduit_topic_base_t *)topic);
    CHECK(n00b_result_is_ok(holder_r));
    n00b_conduit_publisher_t *holder = n00b_result_get(holder_r);

    reject_contended_ctx_t ctx = {.topic = topic};
    auto thread_r = n00b_thread_spawn(reject_contended_submit_main, &ctx);
    CHECK(n00b_result_is_ok(thread_r));
    n00b_thread_t *thread = n00b_result_get(thread_r);
    while (!atomic_load(&ctx.started)) {
        base_nanosleep_ns(1000);
    }
    for (uint32_t i = 0; i < 100 && !atomic_load(&ctx.done); i++) {
        base_nanosleep_ns(N00B_NS_PER_MS);
    }
    bool returned_while_contended = atomic_load(&ctx.done);

    n00b_conduit_publish_yield(holder);
    n00b_thread_join(thread);
    CHECK(!returned_while_contended);
    CHECK(ctx.published);
    CHECK(ctx.err == N00B_STORE_OK);
    n00b_store_conduit_ingest_stats_t stats = wait_for_stats(adapter, 1, 1, 0);
    CHECK_STAT(stats, submitted, 1);
    CHECK_STAT(stats, committed, 1);
    CHECK_STAT(stats, failed, 0);
    CHECK(stream_record_count(store) == 1);

    auto adapter_close_r = n00b_store_conduit_ingest_close(adapter);
    CHECK(n00b_result_is_ok(adapter_close_r));
    auto store_close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(store_close_r));
    n00b_conduit_destroy(c);
}

static void
test_service_profile_submit_routes_through_conduit(void)
{
    auto profile_r = n00b_store_service_profile_new(
        .ingest_worker_count = 1,
        .seal_worker_count   = 1,
        .ingest_queue_bound  = 4,
        .ingest_backpressure = N00B_STORE_INGEST_BACKPRESSURE_BLOCK);
    CHECK(n00b_result_is_ok(profile_r));

    auto store_r = n00b_store_open_service(new_memory_vfs(),
                                           r"/rocs",
                                           new_schema(),
                                           n00b_result_get(profile_r));
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < 4; i++) {
        auto payload_r = n00b_store_ingest_payload_record(record_with_id(i));
        CHECK(n00b_result_is_ok(payload_r));
        auto submit_r = n00b_store_ingest_submit(store,
                                                 n00b_result_get(payload_r));
        CHECK(n00b_result_is_ok(submit_r));
        n00b_store_ingest_receipt_t receipt = n00b_result_get(submit_r);
        CHECK(receipt.state == N00B_STORE_INGEST_RECEIPT_ADMITTED_QUEUED);
        CHECK(receipt.admitted == 1);
        CHECK(receipt.rejected == 0);
        CHECK(receipt.err == N00B_STORE_OK);
    }

    wait_for_stream_records(store, 4);
    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_record_count == 4);
    CHECK(memory.hot_live_index == 4);
    CHECK(memory.hot_active_writers == 0);
    CHECK(memory.hot_writer_reservations == 4);
    CHECK(memory.hot_writer_completions == 4);
    CHECK(memory.seal_active_writer_waits == 0);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_service_profile_accepts_multi_worker_count(void)
{
    auto profile_r = n00b_store_service_profile_new(
        .ingest_worker_count = 2,
        .seal_worker_count   = 1,
        .ingest_queue_bound  = 4,
        .ingest_backpressure = N00B_STORE_INGEST_BACKPRESSURE_BLOCK);
    CHECK(n00b_result_is_ok(profile_r));

    auto store_r = n00b_store_open_service(new_memory_vfs(),
                                           r"/rocs",
                                           new_schema(),
                                           n00b_result_get(profile_r));
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < 8; i++) {
        auto payload_r = n00b_store_ingest_payload_record(record_with_id(i));
        CHECK(n00b_result_is_ok(payload_r));
        auto submit_r = n00b_store_ingest_submit(store,
                                                 n00b_result_get(payload_r));
        CHECK(n00b_result_is_ok(submit_r));
    }

    wait_for_stream_records(store, 8);
    n00b_store_conduit_ingest_stats_t stats = wait_for_service_stats(store, 8, 8);
    CHECK_STAT(stats, submitted, 8);
    CHECK_STAT(stats, committed, 8);
    CHECK_STAT(stats, failed, 0);
    CHECK_STAT(stats, worker_queued, 0);
    CHECK_STAT(stats, worker_in_flight, 0);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_live_index == 8);
    // NB: hot_worker_range_commits is NOT asserted exactly. It counts only
    // records committed through the parallel range-commit path; the conduit
    // loop drains a variable number of records per batch, and any count==1
    // drain clamps workers to 1 and commits via the serial single-record path
    // (which bumps hot_live_index but not range_commits). So the split between
    // range and serial commits is timing-dependent. Correctness is fully
    // covered by committed==8, hot_live_index==8, and tombstones==0.
    CHECK(memory.hot_worker_range_tombstones == 0);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_service_profile_accepts_concurrent_publishers(void)
{
    auto profile_r = n00b_store_service_profile_new(
        .ingest_worker_count = 2,
        .seal_worker_count   = 1,
        .ingest_queue_bound  = 128,
        .ingest_backpressure = N00B_STORE_INGEST_BACKPRESSURE_BLOCK);
    CHECK(n00b_result_is_ok(profile_r));
    auto store_r = n00b_store_open_service(new_memory_vfs(),
                                           r"/rocs",
                                           new_schema(),
                                           n00b_result_get(profile_r));
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    atomic_store(&concurrent_submit_start, false);
    atomic_store(&concurrent_submit_ready, 0);
    atomic_store(&concurrent_submit_admitted, 0);
    atomic_store(&concurrent_submit_rejected, 0);
    concurrent_submit_ctx_t contexts[CONCURRENT_PUBLISHERS] = {};
    n00b_thread_t *threads[CONCURRENT_PUBLISHERS] = {};
    for (uint32_t i = 0; i < CONCURRENT_PUBLISHERS; i++) {
        contexts[i] = (concurrent_submit_ctx_t){
            .store = store,
            .publisher = i,
        };
        auto thread_r = n00b_thread_spawn(concurrent_submit_main, &contexts[i]);
        CHECK(n00b_result_is_ok(thread_r));
        threads[i] = n00b_result_get(thread_r);
    }
    while (atomic_load(&concurrent_submit_ready) != CONCURRENT_PUBLISHERS) {
        base_nanosleep_ns(1000);
    }
    atomic_store(&concurrent_submit_start, true);
    for (uint32_t i = 0; i < CONCURRENT_PUBLISHERS; i++) {
        n00b_thread_join(threads[i]);
    }

    uint64_t expected = CONCURRENT_PUBLISHERS * CONCURRENT_RECORDS;
    CHECK(atomic_load(&concurrent_submit_admitted) == expected);
    CHECK(atomic_load(&concurrent_submit_rejected) == 0);
    n00b_store_conduit_ingest_stats_t stats =
        wait_for_service_stats(store, expected, expected);
    CHECK_STAT(stats, submitted, expected);
    CHECK_STAT(stats, committed, expected);
    CHECK_STAT(stats, failed, 0);
    CHECK(stream_record_count(store) == expected);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_service_profile_accepts_multi_seal_worker_count(void)
{
    auto profile_r = n00b_store_service_profile_new(
        .ingest_worker_count = 1,
        .seal_worker_count   = 2,
        .ingest_queue_bound  = 4,
        .ingest_backpressure = N00B_STORE_INGEST_BACKPRESSURE_BLOCK);
    CHECK(n00b_result_is_ok(profile_r));

    auto seal_r = n00b_store_seal_policy_new(.max_records = 1);
    CHECK(n00b_result_is_ok(seal_r));

    auto store_r = n00b_store_open_service(new_memory_vfs(),
                                           r"/rocs",
                                           new_schema(),
                                           n00b_result_get(profile_r),
                                           .seal_policy = n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < 6; i++) {
        auto payload_r = n00b_store_ingest_payload_record(record_with_id(i));
        CHECK(n00b_result_is_ok(payload_r));
        auto submit_r = n00b_store_ingest_submit(store,
                                                 n00b_result_get(payload_r));
        CHECK(n00b_result_is_ok(submit_r));
    }

    wait_for_stream_records(store, 6);

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    n00b_store_conduit_ingest_stats_t stats =
        wait_for_service_stats(store, 6, 6);
    CHECK_STAT(stats, submitted, 6);
    CHECK_STAT(stats, committed, 6);
    CHECK_STAT(stats, failed, 0);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.failed_seal_jobs == 0);
    CHECK(memory.failed_seal_records == 0);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_conduit_close_drains_accepted_input(void)
{
    n00b_conduit_t *c = n00b_result_get(n00b_conduit_new());
    n00b_store_t   *store = open_store();

    auto topic_r = n00b_store_ingest_topic_get(
        c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 7202));
    CHECK(n00b_result_is_ok(topic_r));
    n00b_store_ingest_topic_t *topic = n00b_result_get(topic_r);

    auto adapter_r = n00b_store_conduit_ingest_start(store,
                                                     topic,
                                                     .worker_count = 1,
                                                     .queue_capacity = 1);
    CHECK(n00b_result_is_ok(adapter_r));
    n00b_store_conduit_ingest_t *adapter = n00b_result_get(adapter_r);

    for (int64_t i = 0; i < 64; i++) {
        publish_record(topic, record_with_id(i));
    }

    auto close_r = n00b_store_conduit_ingest_close(adapter);
    CHECK(n00b_result_is_ok(close_r));

    auto stats_r = n00b_store_conduit_ingest_stats(adapter);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_conduit_ingest_stats_t stats = n00b_result_get(stats_r);
    CHECK_STAT(stats, submitted, 64);
    CHECK_STAT(stats, committed, 64);
    CHECK_STAT(stats, failed, 0);

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    auto find_r = n00b_store_catalog_find_shard(store, 1);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));

    auto records_r = n00b_store_catalog_entry_get_record_count(
        n00b_option_get(n00b_result_get(find_r)));
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == 64);

    n00b_conduit_destroy(c);
}

static void
test_conduit_batches_source_payloads_in_order(void)
{
    n00b_conduit_t *c = n00b_result_get(n00b_conduit_new());
    n00b_store_t   *store = open_store();

    auto topic_r = n00b_store_ingest_topic_get(
        c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 7203));
    CHECK(n00b_result_is_ok(topic_r));
    n00b_store_ingest_topic_t *topic = n00b_result_get(topic_r);

    auto adapter_r = n00b_store_conduit_ingest_start(store,
                                                     topic,
                                                     .worker_count = 4,
                                                     .queue_capacity = 8);
    CHECK(n00b_result_is_ok(adapter_r));
    n00b_store_conduit_ingest_t *adapter = n00b_result_get(adapter_r);

    char expected[8][64] = {};
    for (int64_t i = 0; i < 8; i++) {
        int n = snprintf(expected[i],
                         sizeof(expected[i]),
                         "{\"id\":%lld,\"marker\":\"rocs-source-batch-%lld\"}",
                         (long long)i,
                         (long long)i);
        CHECK(n > 0);
        CHECK((size_t)n < sizeof(expected[i]));
        publish_source(topic, expected[i]);
    }

    n00b_store_conduit_ingest_stats_t stats =
        wait_for_stats(adapter, 8, 8, 0);
    CHECK_STAT(stats, submitted, 8);
    CHECK_STAT(stats, committed, 8);
    CHECK_STAT(stats, failed, 0);

    auto memory_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(memory_r));
    n00b_store_memory_stats_t memory = n00b_result_get(memory_r);
    CHECK(memory.hot_record_count == 8);
    CHECK(memory.hot_live_index == 8);
    CHECK(memory.hot_active_writers == 0);
    CHECK(memory.hot_writer_reservations == 8);
    CHECK(memory.hot_writer_completions == 8);
    CHECK(memory.seal_active_writer_waits == 0);

    auto close_r = n00b_store_conduit_ingest_close(adapter);
    CHECK(n00b_result_is_ok(close_r));

    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    for (uint64_t i = 0; i < 8; i++) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next_opt = n00b_result_get(next_r);
        CHECK(n00b_option_is_set(next_opt));

        n00b_store_record_stream_item_t item = n00b_option_get(next_opt);
        CHECK(item.hot);
        CHECK(item.pos.generation == 0);
        CHECK(item.pos.shard_id == 1);
        CHECK(item.pos.ordinal == i);

        const char       *parse_err = nullptr;
        n00b_json_node_t *row =
            n00b_json_parse((const char *)item.bytes.data,
                            (size_t)item.bytes.byte_len,
                            &parse_err);
        CHECK(row != nullptr);
        CHECK(parse_err == nullptr);

        n00b_json_node_t *id = n00b_json_object_get(row, r"id");
        CHECK(n00b_json_is_int(id));
        CHECK(n00b_json_as_i64(id) == (int64_t)i);

        n00b_json_node_t *marker = n00b_json_object_get(row, r"marker");
        CHECK(marker != nullptr);
        CHECK(n00b_json_is_string(marker));
        CHECK(strcmp(n00b_json_as_cstr(marker),
                     n00b_cformat("rocs-source-batch-[|#|]", i)->data)
              == 0);
    }

    auto eof_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(eof_r));
    CHECK(!n00b_option_is_set(n00b_result_get(eof_r)));

    auto stream_close_r = n00b_store_record_stream_close(stream);
    CHECK(n00b_result_is_ok(stream_close_r));

    n00b_conduit_destroy(c);
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_conduit_ingests_variant_payloads();
    test_conduit_publish_rejects_without_subscriber();
    test_reject_policy_serializes_before_admission();
    test_service_profile_submit_routes_through_conduit();
    test_service_profile_accepts_multi_worker_count();
    test_service_profile_accepts_concurrent_publishers();
    test_service_profile_accepts_multi_seal_worker_count();
    test_conduit_close_drains_accepted_input();
    test_conduit_batches_source_payloads_in_order();

    n00b_print(r"rocs_conduit_ingest: ok");
    n00b_shutdown();
    return 0;
}
