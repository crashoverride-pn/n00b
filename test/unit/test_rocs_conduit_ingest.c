/* test/unit/test_rocs_conduit_ingest.c - WP-005 Phase 7 conduit ingest. */

#include <stdint.h>
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
        wait_for_stats(adapter, 3, 2, 1);
    CHECK(stats.submitted == 3);
    CHECK(stats.committed == 2);
    CHECK(stats.failed == 1);
    CHECK(stats.last_error == N00B_STORE_ERR_PARSE);

    auto close_r = n00b_store_conduit_ingest_close(adapter);
    CHECK(n00b_result_is_ok(close_r));

    publish_record(topic, record_with_id(3));
    usleep(50000);

    auto after_r = n00b_store_conduit_ingest_stats(adapter);
    CHECK(n00b_result_is_ok(after_r));
    CHECK(n00b_result_get(after_r).submitted == 3);
    CHECK(n00b_result_get(after_r).committed == 2);
    CHECK(n00b_result_get(after_r).failed == 1);

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
    CHECK(n00b_result_get(records_r) == 2);

    n00b_conduit_destroy(c);
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
    CHECK(stats.submitted == 64);
    CHECK(stats.committed == 64);
    CHECK(stats.failed == 0);

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

int
main(int argc, char *argv[])
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_conduit_ingests_variant_payloads();
    test_conduit_close_drains_accepted_input();

    n00b_print(r"rocs_conduit_ingest: ok");
    return 0;
}
