/* test/unit/test_rocs_recovery_journal.c - rocs recovery journal (WAL). */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
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
schema_with_level(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"level",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

static n00b_store_t *
open_journaled(n00b_vfs_t *vfs)
{
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       schema_with_level(),
                                       .recovery_journal = true);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_string_t *
level_for(uint64_t i)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "lvl-%llu", (unsigned long long)i);
    return n00b_string_from_raw(buf, (int64_t)strlen(buf), .allocator = nullptr);
}

static void
ingest_buf_level(n00b_store_t *store, uint64_t i)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "{\"level\":\"lvl-%llu\"}",
             (unsigned long long)i);
    n00b_buffer_t *source =
        n00b_buffer_from_bytes(buf, (int64_t)strlen(buf));
    auto r = n00b_store_ingest_buf(store, source);
    CHECK(n00b_result_is_ok(r));
}

static n00b_store_catalog_entry_t *
catalog_shard(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    n00b_option_t(n00b_store_catalog_entry_t *) opt = n00b_result_get(find_r);
    CHECK(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static n00b_store_map_shard_t *
resident_root(n00b_store_t                *store,
              n00b_store_catalog_entry_t  *entry,
              n00b_store_resident_shard_t **handle_out)
{
    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    CHECK(n00b_result_is_ok(map_r));

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    if (handle_out != nullptr) {
        *handle_out = resident;
    }
    return n00b_result_get(root_r);
}

static void
check_mapped_level_hit(n00b_store_map_shard_t *root,
                       n00b_string_t          *level,
                       uint64_t                shard_id,
                       uint64_t                ordinal)
{
    auto index_r = n00b_store_index_new(r"level", N00B_STORE_INDEX_TERM);
    CHECK(n00b_result_is_ok(index_r));

    n00b_json_node_t *value = n00b_json_string_new_from_n00b(level);
    auto lookup_r = n00b_store_index_lookup_mapped(n00b_result_get(index_r),
                                                   root,
                                                   value);
    CHECK(n00b_result_is_ok(lookup_r));
    n00b_store_postings_t *postings = n00b_result_get(lookup_r);

    auto len_r = n00b_store_postings_len(postings);
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == 1);

    auto posting_r = n00b_store_postings_get(postings, 0);
    CHECK(n00b_result_is_ok(posting_r));
    n00b_option_t(n00b_store_posting_t) opt = n00b_result_get(posting_r);
    CHECK(n00b_option_is_set(opt));
    n00b_store_posting_t posting = n00b_option_get(opt);
    CHECK(posting.pos.shard_id == shard_id);
    CHECK(posting.pos.ordinal == ordinal);
}

// Assert: exactly one sealed shard (id 1) holding all `count` records, each
// queryable at the expected ordinal. No duplicates.
static void
assert_recovered(n00b_store_t *store, uint64_t count)
{
    auto count_r = n00b_store_catalog_get_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    n00b_store_catalog_entry_t *entry = catalog_shard(store, 1);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_get(records_r) == count);

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_store_map_shard_t      *root = resident_root(store, entry, &resident);

    auto list_r = n00b_store_map_shard_records(root);
    CHECK(n00b_result_is_ok(list_r));
    auto len_r = n00b_store_map_list_len(n00b_result_get(list_r));
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == count);

    for (uint64_t i = 0; i < count; i++) {
        check_mapped_level_hit(root, level_for(i), 1, i);
    }

    CHECK(n00b_result_is_ok(n00b_store_resident_shard_release(resident)));
}

// Ingest N records with the journal active, then abandon the store WITHOUT
// sealing/flushing/closing (simulating a crash).  Reopen and confirm recovery
// rebuilds a sealed shard holding all N records.  A second reopen (journal now
// deleted) must still see exactly the same — recovery is idempotent.
static void
test_recovery_replays_orphan_journal(void)
{
    const uint64_t n   = 5;
    n00b_vfs_t    *vfs = new_memory_vfs();

    n00b_store_t *crashed = open_journaled(vfs);
    for (uint64_t i = 0; i < n; i++) {
        ingest_buf_level(crashed, i);
    }
    // Simulate crash: do NOT seal/flush/close `crashed`.

    n00b_store_t *recovered = open_journaled(vfs);
    assert_recovered(recovered, n);
    CHECK(n00b_result_is_ok(n00b_store_close(recovered)));

    // Reopen once more: the journal was deleted by the first recovery, so this
    // is a normal open. State must be unchanged (no duplicate shards/records).
    n00b_store_t *again = open_journaled(vfs);
    assert_recovered(again, n);
    CHECK(n00b_result_is_ok(n00b_store_close(again)));
}

// A partial prior recovery can leave a sealed object at the deterministic shard
// path without a catalog entry, while the journal still exists.  Recovery must
// overwrite that object and commit cleanly — no duplicates, no failure.
static void
test_recovery_overwrites_partial_object(void)
{
    const uint64_t n   = 4;
    n00b_vfs_t    *vfs = new_memory_vfs();

    n00b_store_t *crashed = open_journaled(vfs);
    for (uint64_t i = 0; i < n; i++) {
        ingest_buf_level(crashed, i);
    }
    // Simulate crash before seal: journals/1.jrnl exists; shards/1.n00b does not.

    // Plant a bogus partial image at the deterministic object path.
    n00b_string_t *object_path = r"/rocs/shards/1.n00b";
    auto open_r = n00b_vfs_open(vfs, object_path, N00B_VFS_O_W);
    CHECK(n00b_result_is_ok(open_r));
    n00b_vfs_fh_t fh = n00b_result_get(open_r);
    n00b_buffer_t *garbage =
        n00b_buffer_from_bytes((char *)"not a real shard image", 22);
    CHECK(n00b_result_is_ok(n00b_vfs_write(vfs, fh, garbage)));
    CHECK(n00b_result_is_ok(n00b_vfs_close(vfs, fh)));

    n00b_store_t *recovered = open_journaled(vfs);
    assert_recovered(recovered, n);
    CHECK(n00b_result_is_ok(n00b_store_close(recovered)));
}

// A clean close seals + commits the hot shard and removes its journal, so a
// later open has nothing to recover and no orphaned shard appears.
static void
test_clean_close_leaves_no_orphan_journal(void)
{
    const uint64_t n   = 3;
    n00b_vfs_t    *vfs = new_memory_vfs();

    n00b_store_t *store = open_journaled(vfs);
    for (uint64_t i = 0; i < n; i++) {
        ingest_buf_level(store, i);
    }
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    n00b_store_t *reopened = open_journaled(vfs);
    assert_recovered(reopened, n);
    CHECK(n00b_result_is_ok(n00b_store_close(reopened)));
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_recovery_replays_orphan_journal();
    test_recovery_overwrites_partial_object();
    test_clean_close_leaves_no_orphan_journal();

    return 0;
}
