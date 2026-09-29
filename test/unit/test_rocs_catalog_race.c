/* test/unit/test_rocs_catalog_race.c - catalog readers against catalog writers.
 *
 * The catalog list has no lock of its own, and n00b_list_get aborts on an
 * index past the end. Readers work from a published catalog view they pin,
 * and every writer publishes a new view and waits for pinned readers to leave
 * before freeing the old one. Each test here stops a reader inside its read
 * through the debug read hook, starts a writer on another thread at exactly
 * that point, and resumes the reader once the writer thread has finished,
 * paused, or blocked inside the store:
 *
 *   1. Record stream open counts its sealed entries, then fills an array of
 *      that size. A drop and a seal between the two must not let the fill
 *      write past the array.
 *   2. Memory stats reads its totals while a drop shrinks the catalog.
 *   3. find_shard and visible_entry_after read while a drop shrinks the
 *      catalog; find_shard must still find a shard that was never dropped.
 *   4. Retired hot allocator detach (reached from stream close) runs while a
 *      failed-seal retry detaches entries from the catalog.
 *   5. Memory stats reads the hot shard under the hot pin while the store
 *      closes and frees it, both through close's seal and at its teardown.
 *
 * A reader that walked the live list would overrun an array, abort on a stale
 * length, or miss an entry; one on a pinned view sees the catalog whole. A
 * close that did not drain the hot pin would free the shard under the read.
 */

#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>
#include "internal/rocs/store.h"
#include "rocs_test_support.h"
#include "test_check.h"

#ifndef N00B_DEBUG
#error "test_rocs_catalog_race requires N00B_DEBUG for the catalog read hook"
#endif

// A hang detector, not a timing claim: a passing run leaves each wait the
// moment its condition holds.
#define RACE_HANG_NS (UINT64_C(60) * UINT64_C(1000000000))

typedef struct race race_t;

struct race {
    n00b_store_t              *store;
    n00b_store_catalog_read_t  site;
    // The hook call, counted on the reader thread at `site`, that starts the
    // writer. 1 is the first.
    uint64_t                   trigger;
    uint64_t                   calls;
    bool                       fired;
    uint64_t                   reader_tid;
    uint64_t                   writer_tid;
    _Atomic(n00b_thread_t *)   writer_thread;
    void                     (*mutate)(race_t *race);
    // Scratch the writer reads and writes.
    uint64_t                   shard_id;
    n00b_err_t                 drop_err;
    _Atomic(bool)              go;
    _Atomic(bool)              writer_done;
    _Atomic(bool)              writer_paused;
    _Atomic(bool)              reader_done;
};

static void
wait_until_reader_can_resume(race_t *race)
{
    uint64_t deadline = now_ns() + RACE_HANG_NS;
    // Only the writer's own state resumes the reader: another thread parked
    // on a store lock, such as an async seal worker, says nothing about
    // whether the writer has reached the point under test.
    while (!atomic_load(&race->writer_done)
           && !atomic_load(&race->writer_paused)
           && !n00b_store_thread_blocked(race->store,
                                         atomic_load(&race->writer_thread))) {
        CHECK(now_ns() < deadline);
    }
}

static void
race_hook(n00b_store_t *store, n00b_store_catalog_read_t site, void *ctx)
{
    race_t *race = ctx;
    if (store != race->store || site != race->site || race->fired
        || (uint64_t)n00b_self_os_id() != race->reader_tid) {
        return;
    }
    if (++race->calls < race->trigger) {
        return;
    }
    race->fired = true;
    atomic_store(&race->go, true);
    wait_until_reader_can_resume(race);
}

static void *
race_writer(void *raw)
{
    race_t *race     = raw;
    race->writer_tid = (uint64_t)n00b_self_os_id();
    atomic_store(&race->writer_thread, n00b_thread_self());
    while (!atomic_load(&race->go)) {
        __asm__ volatile("" ::: "memory");
    }
    race->mutate(race);
    atomic_store(&race->writer_done, true);
    return nullptr;
}

static void
race_begin(race_t *race)
{
    race->reader_tid = (uint64_t)n00b_self_os_id();
    n00b_store_catalog_read_hook_set(race_hook, race);
}

static n00b_thread_t *
race_spawn_writer(race_t *race)
{
    auto spawn_r = n00b_thread_spawn(race_writer, race);
    CHECK(n00b_result_is_ok(spawn_r));
    return n00b_result_get(spawn_r);
}

// Called once the reader has returned. A reader that never reached its hook
// would pass by never meeting the writer, so that is a failure here.
static void
race_end(race_t *race, n00b_thread_t *writer)
{
    atomic_store(&race->reader_done, true);
    bool fired = race->fired;
    atomic_store(&race->go, true);
    n00b_thread_join(writer);
    n00b_store_catalog_read_hook_set(nullptr, nullptr);
    CHECK(fired);
}

static n00b_vfs_t *
new_memory_vfs(n00b_vfs_mount_t **mount_out)
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

static n00b_store_schema_t *
make_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_store(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(nullptr),
                                       r"/rocs",
                                       make_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static void
ingest_marker(n00b_store_t *store, int64_t tag, int64_t i)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(
        record,
        r"marker",
        n00b_json_string_new_from_n00b(n00b_cformat("m-[|#|]-[|#|]", tag, i)));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record)));
}

static uint64_t
seal_shard(n00b_store_t *store, int64_t tag, int64_t records)
{
    for (int64_t i = 0; i < records; i++) {
        ingest_marker(store, tag, i);
    }
    auto seal_r = n00b_store_seal_hot_shard(store);
    CHECK(n00b_result_is_ok(seal_r));
    auto id_r = n00b_store_catalog_entry_get_shard_id(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(id_r));
    return n00b_result_get(id_r);
}

static n00b_store_memory_stats_t
memory_stats(n00b_store_t *store)
{
    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    return n00b_result_get(stats_r);
}

static void
write_drop(race_t *race)
{
    auto drop_r = n00b_store_drop_sealed_shard(race->store, race->shard_id);
    race->drop_err = n00b_result_is_ok(drop_r) ? N00B_STORE_OK
                                               : n00b_result_get_err(drop_r);
}

// Drop the quarantined shard that sits ahead of the stream's one visible
// shard, then seal the hot records into a new shard at the end. A fill pass
// over the live list would then see two visible entries inside the length
// the count pass read, and the count pass sized the array for one.
static void
write_drop_then_seal(race_t *race)
{
    write_drop(race);
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(race->store)));
}

static void
test_stream_open_fill_stays_inside_its_count(void)
{
    n00b_store_t *store      = open_store();
    uint64_t      quarantined = seal_shard(store, 1, 2);
    uint64_t      visible    = seal_shard(store, 2, 3);
    CHECK(n00b_result_is_ok(n00b_store_quarantine_shard(store, quarantined)));
    ingest_marker(store, 3, 0);
    ingest_marker(store, 3, 1);

    race_t race = {
        .store    = store,
        .site     = N00B_STORE_CATALOG_READ_STREAM_OPEN,
        .trigger  = 1,
        .mutate   = write_drop_then_seal,
        .shard_id = quarantined,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    race_end(&race, writer);
    CHECK(n00b_result_is_ok(stream_r));

    // The drop lands after the snapshot either way; it is refused only when
    // the stream's hot snapshot pinned first.
    CHECK(race.drop_err == N00B_STORE_OK
          || race.drop_err == N00B_STORE_ERR_PINNED);

    // Every sealed item comes from the one shard that was visible at open.
    n00b_store_record_stream_t *stream = n00b_result_get(stream_r);
    int64_t sealed = 0;
    while (true) {
        auto next_r = n00b_store_record_stream_next(stream);
        CHECK(n00b_result_is_ok(next_r));
        auto next = n00b_result_get(next_r);
        if (!n00b_option_is_set(next)) {
            break;
        }
        n00b_store_record_stream_item_t item = n00b_option_get(next);
        if (!item.hot) {
            CHECK(item.pos.shard_id == visible);
            sealed++;
        }
    }
    CHECK(sealed == 3);
    CHECK(n00b_result_is_ok(n00b_store_record_stream_close(stream)));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_memory_stats_read_excludes_a_drop(void)
{
    n00b_store_t *store = open_store();
    uint64_t      first = seal_shard(store, 1, 1);
    seal_shard(store, 2, 1);
    seal_shard(store, 3, 1);
    for (int64_t i = 0; i < 4; i++) {
        ingest_marker(store, 4, i);
    }

    // The hot record text total is a counter the writers keep, so check it
    // against the hot shard's own byte estimate, which charges each record
    // its text plus a fixed overhead.
    n00b_store_memory_stats_t before = memory_stats(store);
    CHECK(before.hot_record_count == 4);
    CHECK(before.hot_record_text_bytes != 0);
    CHECK(before.hot_byte_estimate
          == before.hot_record_text_bytes
                 + (4 * N00B_STORE_SHARD_RECORD_OVERHEAD));

    race_t race = {
        .store    = store,
        .site     = N00B_STORE_CATALOG_READ_MEMORY_STATS,
        .trigger  = 1,
        .mutate   = write_drop,
        .shard_id = first,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    n00b_store_memory_stats_t during = memory_stats(store);
    race_end(&race, writer);
    CHECK(race.drop_err == N00B_STORE_OK);

    // The reader saw the catalog whole, before the drop.
    CHECK(during.sealed_shards == 3);
    CHECK(during.sealed_records == 3);
    CHECK(during.catalog_entries == 3);
    CHECK(memory_stats(store).sealed_shards == 2);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_find_shard_read_excludes_a_drop(void)
{
    n00b_store_t *store  = open_store();
    uint64_t      first  = seal_shard(store, 1, 1);
    seal_shard(store, 2, 1);
    uint64_t      target = seal_shard(store, 3, 1);

    // Stop after the search has compared its second entry, with the drop of
    // the first entry waiting on the reader.
    race_t race = {
        .store    = store,
        .site     = N00B_STORE_CATALOG_READ_FIND_SHARD,
        .trigger  = 2,
        .mutate   = write_drop,
        .shard_id = first,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    auto find_r = n00b_store_catalog_find_shard(store, target);
    race_end(&race, writer);
    CHECK(race.drop_err == N00B_STORE_OK);

    CHECK(n00b_result_is_ok(find_r));
    n00b_option_t(n00b_store_catalog_entry_t *) found = n00b_result_get(find_r);
    CHECK(n00b_option_is_set(found));
    auto id_r = n00b_store_catalog_entry_get_shard_id(n00b_option_get(found));
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_get(id_r) == target);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_visible_entry_after_read_excludes_a_drop(void)
{
    n00b_store_t *store = open_store();
    uint64_t      first = seal_shard(store, 1, 1);
    seal_shard(store, 2, 1);
    uint64_t      last  = seal_shard(store, 3, 1);

    // Past every record, so the search finds no entry.
    auto last_r = n00b_store_catalog_find_shard(store, last);
    CHECK(n00b_result_is_ok(last_r));
    auto gen_r = n00b_store_catalog_entry_get_generation(
        n00b_option_get(n00b_result_get(last_r)));
    CHECK(n00b_result_is_ok(gen_r));
    n00b_store_pos_t after = {
        .generation = n00b_result_get(gen_r),
        .shard_id   = last,
        .ordinal    = 0,
    };

    race_t race = {
        .store    = store,
        .site     = N00B_STORE_CATALOG_READ_ENTRY_AFTER,
        .trigger  = 1,
        .mutate   = write_drop,
        .shard_id = first,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    auto entry_r = n00b_store_catalog_visible_entry_after(store, &after);
    race_end(&race, writer);
    CHECK(race.drop_err == N00B_STORE_OK);

    CHECK(n00b_result_is_ok(entry_r));
    CHECK(!n00b_option_is_set(n00b_result_get(entry_r)));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

// Resume just past the first shard while its drop waits on the reader. The
// reader's catalog version still holds the second shard, which is the answer.
static void
test_visible_entry_after_answers_from_its_version(void)
{
    n00b_store_t *store  = open_store();
    uint64_t      first  = seal_shard(store, 1, 1);
    uint64_t      second = seal_shard(store, 2, 1);
    seal_shard(store, 3, 1);

    auto first_r = n00b_store_catalog_find_shard(store, first);
    CHECK(n00b_result_is_ok(first_r));
    auto gen_r = n00b_store_catalog_entry_get_generation(
        n00b_option_get(n00b_result_get(first_r)));
    CHECK(n00b_result_is_ok(gen_r));
    n00b_store_pos_t after = {
        .generation = n00b_result_get(gen_r),
        .shard_id   = first,
        .ordinal    = 0,
    };

    race_t race = {
        .store    = store,
        .site     = N00B_STORE_CATALOG_READ_ENTRY_AFTER,
        .trigger  = 1,
        .mutate   = write_drop,
        .shard_id = first,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    auto entry_r = n00b_store_catalog_visible_entry_after(store, &after);
    race_end(&race, writer);
    CHECK(race.drop_err == N00B_STORE_OK);

    CHECK(n00b_result_is_ok(entry_r));
    CHECK(n00b_option_is_set(n00b_result_get(entry_r)));
    n00b_store_catalog_resume_entry_t next =
        n00b_option_get(n00b_result_get(entry_r));
    CHECK(next.shard_id == second);
    CHECK(next.start_ordinal == 0);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

typedef struct {
    bool    deny;
    race_t *race;
} shard_write_gate_t;

// Shard writes fail while `deny` is set, leaving failed-seal entries in the
// catalog. During the race, the writer's first shard write pauses until the
// reader is done: that write is the retry's, which runs only after the retry
// has detached the failed entries, so the pause holds the catalog shrunk.
static void
shard_write_gate(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    shard_write_gate_t *gate = cookie;
    if (ctx == nullptr || ctx->path == nullptr
        || (ctx->flags & N00B_VFS_OPEN_WRITE) == 0
        || !n00b_unicode_str_contains(ctx->path,
                                      r"/shards/",
                                      .normalize = false)) {
        return;
    }
    if (gate->deny) {
        ctx->denied   = true;
        ctx->deny_err = N00B_VFS_ERR_IO;
        return;
    }
    race_t *race = gate->race;
    if (race == nullptr || atomic_load(&race->writer_paused)
        || (uint64_t)n00b_self_os_id() != race->writer_tid) {
        return;
    }
    atomic_store(&race->writer_paused, true);
    uint64_t deadline = now_ns() + RACE_HANG_NS;
    while (!atomic_load(&race->reader_done)) {
        CHECK(now_ns() < deadline);
    }
}

static void
write_retry_failed_seals(race_t *race)
{
    CHECK(n00b_result_is_ok(n00b_store_flush(race->store)));
}

// A seal while a stream holds a hot snapshot leaves the sealed shard's hot
// allocator retired, so closing the stream walks the catalog to free it.
static void
test_retired_hot_detach_excludes_a_failed_seal_retry(void)
{
    n00b_vfs_mount_t *mount = nullptr;
    auto store_r = n00b_store_open_vfs(new_memory_vfs(&mount),
                                       r"/rocs",
                                       make_schema());
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    shard_write_gate_t gate = {.deny = true};
    CHECK(n00b_result_is_ok(n00b_vfs_hook_add(mount,
                                              N00B_VFS_HOOK_PRE_OPEN,
                                              shard_write_gate,
                                              &gate,
                                              0)));
    for (int64_t i = 0; i < 2; i++) {
        ingest_marker(store, 1, i);
        CHECK(n00b_result_is_err(n00b_store_seal_hot_shard(store)));
    }
    CHECK(memory_stats(store).failed_seal_jobs == 2);
    gate.deny = false;

    ingest_marker(store, 2, 0);
    auto stream_r = n00b_store_record_stream_open(store, nullptr);
    CHECK(n00b_result_is_ok(stream_r));
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(store)));
    CHECK(memory_stats(store).retired_hot_allocators == 1);

    race_t race = {
        .store   = store,
        .site    = N00B_STORE_CATALOG_READ_RETIRED_HOT,
        .trigger = 1,
        .mutate  = write_retry_failed_seals,
    };
    gate.race = &race;
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    CHECK(n00b_result_is_ok(
        n00b_store_record_stream_close(n00b_result_get(stream_r))));
    race_end(&race, writer);
    gate.race = nullptr;

    n00b_store_memory_stats_t after = memory_stats(store);
    CHECK(after.retired_hot_allocators == 0);
    CHECK(after.failed_seal_jobs == 0);
    CHECK(after.sealed_records == 3);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
write_close(race_t *race)
{
    CHECK(n00b_result_is_ok(n00b_store_close(race->store)));
}

static void
test_memory_stats_hot_read_excludes_close(void)
{
    n00b_store_t *store = open_store();
    seal_shard(store, 1, 1);
    for (int64_t i = 0; i < 3; i++) {
        ingest_marker(store, 2, i);
    }
    n00b_store_memory_stats_t before = memory_stats(store);
    CHECK(before.hot_record_count == 3);

    race_t race = {
        .store   = store,
        .site    = N00B_STORE_CATALOG_READ_HOT_STATS,
        .trigger = 1,
        .mutate  = write_close,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    n00b_store_memory_stats_t during = memory_stats(store);
    race_end(&race, writer);

    // The read finished on the shard the store had before close freed it.
    CHECK(during.hot_shard_id == before.hot_shard_id);
    CHECK(during.hot_record_count == 3);
    CHECK(during.hot_record_text_bytes == before.hot_record_text_bytes);
    CHECK(during.hot_byte_estimate == before.hot_byte_estimate);
}

// With nothing hot to seal, close frees the hot shard itself at teardown.
static void
test_memory_stats_empty_hot_read_excludes_close(void)
{
    n00b_store_t *store = open_store();
    seal_shard(store, 1, 1);
    n00b_store_memory_stats_t before = memory_stats(store);
    CHECK(before.hot_record_count == 0);

    race_t race = {
        .store   = store,
        .site    = N00B_STORE_CATALOG_READ_HOT_STATS,
        .trigger = 1,
        .mutate  = write_close,
    };
    race_begin(&race);
    n00b_thread_t *writer = race_spawn_writer(&race);
    n00b_store_memory_stats_t during = memory_stats(store);
    race_end(&race, writer);

    CHECK(during.hot_shard_id == before.hot_shard_id);
    CHECK(during.hot_record_count == 0);
    CHECK(during.hot_pool_mapped_bytes == before.hot_pool_mapped_bytes);
}

typedef struct {
    const char *name;
    void      (*run)(void);
} named_test_t;

static const named_test_t tests[] = {
    {"stream_open", test_stream_open_fill_stays_inside_its_count},
    {"memory_stats", test_memory_stats_read_excludes_a_drop},
    {"find_shard", test_find_shard_read_excludes_a_drop},
    {"visible_entry_after", test_visible_entry_after_read_excludes_a_drop},
    {"visible_entry_after_version",
     test_visible_entry_after_answers_from_its_version},
    {"retired_hot", test_retired_hot_detach_excludes_a_failed_seal_retry},
    {"hot_stats_close", test_memory_stats_hot_read_excludes_close},
    {"hot_stats_close_empty", test_memory_stats_empty_hot_read_excludes_close},
};

// With no argument every test runs. A name runs that test alone, so a broken
// reader can show each failure on its own.
int
main(int argc, char *argv[])
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    const char *only = argc > 1 ? argv[1] : nullptr;
    bool        ran  = false;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (only == nullptr || strcmp(only, tests[i].name) == 0) {
            tests[i].run();
            ran = true;
        }
    }
    CHECK(ran);

    n00b_print(r"rocs_catalog_race: ok");
    n00b_shutdown();
    return 0;
}
