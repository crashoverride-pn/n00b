/* test/unit/test_rocs_record_stream_pin_order.c - regression for n00b#198.
 *
 * n00b_store_record_stream_open must publish its hot-snapshot pin before any
 * borrowed hot-shard record pointer can be observed by the reclaim side, or a
 * concurrent seal (keep_standby puts the retire/reclaim on the seal-worker
 * thread) frees the hot arena mid-open and the cursor returns byte spans into
 * freed memory. The invariants under test:
 *
 *   1. Pin visibility. A hot snapshot taken by open blocks retired-hot arena
 *      reclaim triggered by an asynchronous seal for the stream's lifetime,
 *      and the borrowed spans stay byte-intact across that seal.
 *   2. No invalid borrows under churn. Streams opened while the seal worker
 *      concurrently rotates and retires hot shards never observe corrupt or
 *      empty record spans, and pin accounting drains back to zero. The
 *      pre-fix borrow window is microseconds wide, so in a plain build this
 *      loop is primarily a liveness/deadlock canary for the open-path
 *      locking; detecting the original use-after-free reliably needs a
 *      sanitizer build.
 */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

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
make_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_json_node_t *
make_record(int64_t i)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_string_t    *marker = n00b_cformat("pin-race-[|#|]-end", i);
    n00b_json_object_put_n00b(record,
                              r"marker",
                              n00b_json_string_new_from_n00b(marker));
    return record;
}

static bool
span_contains(n00b_store_byte_span_t bytes, n00b_string_t *needle)
{
    if (needle == nullptr || needle->data == nullptr || needle->u8_bytes == 0
        || bytes.data == nullptr || bytes.byte_len < needle->u8_bytes) {
        return false;
    }
    uint64_t limit = bytes.byte_len - needle->u8_bytes;
    for (uint64_t i = 0; i <= limit; i++) {
        uint64_t j = 0;
        while (j < needle->u8_bytes
               && bytes.data[i + j] == (uint8_t)needle->data[j]) {
            j++;
        }
        if (j == needle->u8_bytes) {
            return true;
        }
    }
    return false;
}

// Async-seal analog of the inline retired-allocator test: the pin taken at
// open must be visible to the seal WORKER's reclaim pass, not just to inline
// sealing on the opener's own thread.
static void
test_open_snapshot_pin_blocks_async_reclaim(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       make_schema(),
                                       .keep_standby = true);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < 4; i++) {
        CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(i))));
    }

    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

    // flush waits behind the async seal, so the worker's retire pass has run
    // by the time it returns; the stream's pin must have kept the old hot
    // arena alive rather than letting the worker destroy it.
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_residency_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.active_pins == 1);
    CHECK(stats.retired_hot_allocators == 1);

    for (int64_t i = 0; i < 4; i++) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next = n00b_result_get(next_r);
        CHECK(n00b_option_is_set(next));
        n00b_store_record_stream_item_t item = n00b_option_get(next);
        CHECK(item.hot);
        CHECK(item.pos.ordinal == (uint64_t)i);
        CHECK(span_contains(item.bytes,
                            n00b_cformat("pin-race-[|#|]-end", i)));
    }

    auto eof_r = n00b_store_record_stream_next(stream);
    CHECK(n00b_result_is_ok(eof_r));
    CHECK(!n00b_option_is_set(n00b_result_get(eof_r)));

    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    stats = n00b_result_get(stats_r);
    CHECK(stats.active_pins == 0);
    CHECK(stats.retired_hot_allocators == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

// Churn: the ingest thread repeatedly opens streams while the seal worker
// rotates and retires hot shards underneath it. Under the pre-fix ordering
// (borrow before pin) the worker can free an arena an open is copying from;
// with the fix every span handed out must remain byte-intact.
static void
test_open_under_async_seal_churn_yields_intact_spans(void)
{
    auto seal_r = n00b_store_seal_policy_new(.max_records = 256);
    CHECK(n00b_result_is_ok(seal_r));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       make_schema(),
                                       .seal_policy  = n00b_result_get(seal_r),
                                       .keep_standby = true);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    n00b_string_t *prefix = r"pin-race-";

    // Most opens resume just past the previous walk, which borrows only the
    // hot tail's new suffix but keeps walks short enough to open thousands of
    // streams across the worker's rotations; every 61st open starts from the
    // beginning so some opens copy a full hot tail (the widest borrow
    // window). Exact delivery counts are not asserted mid-churn (records
    // mid-async-seal are transiently invisible); the post-flush walk asserts
    // the full count.
    int64_t          total      = 0;
    bool             have_after = false;
    n00b_store_pos_t after      = {};
    for (int64_t i = 0; i < 6000; i++) {
        CHECK(n00b_result_is_ok(n00b_store_ingest(store, make_record(i))));
        total++;

        bool from_start = !have_after || i % 61 == 0;
        auto stream_r   = n00b_store_record_stream_open(
            store,
            from_start ? nullptr : &after);
        CHECK(n00b_result_is_ok(stream_r));
        n00b_store_record_stream_t *stream = n00b_result_get(stream_r);

        bool             have_pos = false;
        n00b_store_pos_t last_pos = {};
        while (true) {
            auto next_r = n00b_store_record_stream_next(stream);
            CHECK(n00b_result_is_ok(next_r));
            auto next = n00b_result_get(next_r);
            if (!n00b_option_is_set(next)) {
                break;
            }
            n00b_store_record_stream_item_t item = n00b_option_get(next);
            CHECK(item.bytes.data != nullptr);
            CHECK(item.bytes.byte_len != 0);
            CHECK(span_contains(item.bytes, prefix));
            if (have_pos) {
                CHECK(n00b_store_pos_compare(last_pos, item.pos) < 0);
            }
            last_pos = item.pos;
            have_pos = true;
        }
        if (have_pos) {
            after      = last_pos;
            have_after = true;
        }

        CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));
    }

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    int64_t count = 0;
    while (true) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next = n00b_result_get(next_r);
        if (!n00b_option_is_set(next)) {
            break;
        }
        n00b_store_record_stream_item_t item = n00b_option_get(next);
        CHECK(!item.hot);
        CHECK(span_contains(item.bytes, prefix));
        count++;
    }
    CHECK(count == total);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));

    auto stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_residency_stats_t stats = n00b_result_get(stats_r);
    CHECK(stats.active_pins == 0);
    CHECK(stats.retired_hot_allocators == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_open_snapshot_pin_blocks_async_reclaim();
    test_open_under_async_seal_churn_yields_intact_spans();

    n00b_print(r"rocs_record_stream_pin_order: ok");
    return 0;
}
