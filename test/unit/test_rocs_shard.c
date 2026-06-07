/** @file test/unit/test_rocs_shard.c - WP-003 shard root smoke tests. */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "n00b.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/shard.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static void
check_empty_hot_shard(n00b_store_shard_t *shard,
                      uint64_t            shard_id,
                      uint64_t            open_ts,
                      bool                expect_raw)
{
    CHECK(shard != nullptr);
    CHECK(shard->records != nullptr);
    CHECK(shard->columns != nullptr);
    CHECK(shard->state == N00B_SHARD_STATE_OPEN);
    CHECK(shard->reserved == 0);
    CHECK(shard->record_count == 0);
    CHECK(shard->byte_estimate == 0);
    CHECK(shard->open_ts == open_ts);
    CHECK(shard->seal_ts == 0);
    CHECK(shard->shard_id == shard_id);

    CHECK(shard->records->lock == nullptr);
    CHECK(n00b_list_len(*shard->records) == 0);

    CHECK(shard->columns->lock == nullptr);
    CHECK(atomic_load(&shard->columns->length) == 0);

    if (expect_raw) {
        CHECK(shard->retain_raw != nullptr);
        CHECK(shard->raw_bytes != nullptr);
        CHECK(shard->retain_raw->lock == nullptr);
        CHECK(n00b_list_len(*shard->retain_raw) == 0);
        CHECK(shard->raw_bytes->data == nullptr);
        CHECK(shard->raw_bytes->byte_len == 0);
    }
    else {
        CHECK(shard->retain_raw == nullptr);
        CHECK(shard->raw_bytes == nullptr);
    }
}

static n00b_json_node_t *
test_record_marker(n00b_string_t *name)
{
    return (n00b_json_node_t *)name;
}

typedef struct {
    uint64_t marker;
} test_seal_record_t;

static n00b_json_node_t *
test_seal_record(uint64_t marker)
{
    test_seal_record_t *record = n00b_alloc_size_with_opts(
        1,
        sizeof(test_seal_record_t),
        &(n00b_alloc_opts_t){
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });

    record->marker = marker;
    return (n00b_json_node_t *)record;
}

static n00b_store_map_shard_t *
open_sealed_root(n00b_buffer_t *image, n00b_store_map_t **out_map)
{
    auto open = n00b_store_map_open_buffer(image);
    CHECK(n00b_result_is_ok(open));

    n00b_store_map_t *map = n00b_result_get(open);
    auto              root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));

    *out_map = map;
    return n00b_result_get(root_r);
}

static void
check_buffers_equal(n00b_buffer_t *actual, n00b_buffer_t *expected)
{
    CHECK(actual != nullptr);
    CHECK(expected != nullptr);

    n00b_size_t len = n00b_buffer_len(expected);
    CHECK(n00b_buffer_len(actual) == len);

    for (n00b_size_t i = 0; i < len; i++) {
        auto a = n00b_buffer_get_index(actual, (int64_t)i);
        auto e = n00b_buffer_get_index(expected, (int64_t)i);
        CHECK(n00b_result_is_ok(a));
        CHECK(n00b_result_is_ok(e));
        CHECK(n00b_result_get(a) == n00b_result_get(e));
    }
}

static void
check_raw_blob_span_equal(n00b_store_raw_blob_t *blob,
                          n00b_store_raw_span_t *span,
                          n00b_buffer_t         *expected)
{
    CHECK(blob != nullptr);
    CHECK(span != nullptr);
    CHECK(expected != nullptr);
    CHECK(span->offset <= blob->byte_len);
    CHECK(span->byte_len <= blob->byte_len - span->offset);
    CHECK(span->byte_len == (uint64_t)n00b_buffer_len(expected));

    for (uint64_t i = 0; i < span->byte_len; i++) {
        auto e = n00b_buffer_get_index(expected, (int64_t)i);
        CHECK(n00b_result_is_ok(e));
        CHECK(blob->data[span->offset + i] == n00b_result_get(e));
    }
}

static void
check_cold_buffer_equal(n00b_store_map_buffer_t *actual,
                        n00b_buffer_t           *expected)
{
    CHECK(actual != nullptr);
    CHECK(expected != nullptr);

    auto len_r = n00b_store_map_buffer_len(actual);
    CHECK(n00b_result_is_ok(len_r));
    CHECK(n00b_result_get(len_r) == (uint64_t)n00b_buffer_len(expected));

    for (uint64_t i = 0; i < n00b_result_get(len_r); i++) {
        auto a = n00b_store_map_buffer_byte(actual, i);
        auto e = n00b_buffer_get_index(expected, (int64_t)i);
        CHECK(n00b_result_is_ok(a));
        CHECK(n00b_result_is_ok(e));
        CHECK(n00b_result_get(a) == n00b_result_get(e));
    }

    auto copy_r = n00b_store_map_buffer_copy(actual);
    CHECK(n00b_result_is_ok(copy_r));
    check_buffers_equal(n00b_result_get(copy_r), expected);
}

static n00b_gc_scan_kind_t
test_alloc_scan_kind(void *ptr)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(ptr);

    CHECK(n00b_alloc_info_is_heap(info));
    if (n00b_alloc_info_is_oob(info)) {
        return (n00b_gc_scan_kind_t)info.hdr.oob->scan_kind;
    }
    return (n00b_gc_scan_kind_t)info.hdr.in_line->scan_kind;
}

static void
test_default_constructor(void)
{
    auto r = n00b_store_shard_new(.shard_id = UINT64_C(0x12345678),
                                  .open_ts  = 99);
    CHECK(n00b_result_is_ok(r));
    check_empty_hot_shard(n00b_result_get(r), UINT64_C(0x12345678), 99, false);
}

static void
test_retain_raw_constructor(void)
{
    auto r = n00b_store_shard_new(.shard_id   = UINT64_C(0xaabbccdd),
                                  .retain_raw = true,
                                  .open_ts    = 1234);
    CHECK(n00b_result_is_ok(r));
    check_empty_hot_shard(n00b_result_get(r), UINT64_C(0xaabbccdd), 1234, true);
}

static void
test_append_without_raw_retention(void)
{
    auto r = n00b_store_shard_new(.shard_id = 1);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    n00b_json_node_t *rec0 = test_record_marker(r"rec0");
    n00b_json_node_t *rec1 = test_record_marker(r"rec1");
    n00b_buffer_t    *raw  = n00b_buffer_from_cstr("{\"ignored\":true}");

    auto a0 = n00b_store_shard_append(shard, rec0);
    CHECK(n00b_result_is_ok(a0));
    CHECK(n00b_result_get(a0) == 0);

    auto a1 = n00b_store_shard_append(shard, rec1, .raw = raw);
    CHECK(n00b_result_is_ok(a1));
    CHECK(n00b_result_get(a1) == 1);

    CHECK(shard->record_count == 2);
    CHECK(n00b_list_len(*shard->records) == 2);
    CHECK(n00b_list_get(*shard->records, 0) == rec0);
    CHECK(n00b_list_get(*shard->records, 1) == rec1);
    CHECK(shard->retain_raw == nullptr);
    CHECK(shard->raw_bytes == nullptr);
    CHECK(shard->byte_estimate == 2 * N00B_STORE_SHARD_RECORD_OVERHEAD);
}

static void
test_append_with_raw_retention(void)
{
    auto r = n00b_store_shard_new(.shard_id = 2, .retain_raw = true);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    n00b_json_node_t *rec0 = test_record_marker(r"raw-rec0");
    n00b_json_node_t *rec1 = test_record_marker(r"raw-rec1");
    n00b_buffer_t    *raw0 = n00b_buffer_from_cstr("{\"a\":1}");
    n00b_buffer_t    *raw1 = n00b_buffer_from_cstr("{\"b\":2}");

    auto missing_raw = n00b_store_shard_append(shard, rec0);
    CHECK(n00b_result_is_err(missing_raw));
    CHECK(n00b_result_get_err(missing_raw) == N00B_STORE_SHARD_ERR_ARG);
    CHECK(shard->record_count == 0);
    CHECK(n00b_list_len(*shard->records) == 0);
    CHECK(n00b_list_len(*shard->retain_raw) == 0);
    CHECK(shard->raw_bytes->byte_len == 0);

    auto a0 = n00b_store_shard_append(shard, rec0, .raw = raw0);
    auto a1 = n00b_store_shard_append(shard, rec1, .raw = raw1);
    CHECK(n00b_result_is_ok(a0));
    CHECK(n00b_result_is_ok(a1));
    CHECK(n00b_result_get(a0) == 0);
    CHECK(n00b_result_get(a1) == 1);

    CHECK(shard->record_count == 2);
    CHECK(n00b_list_len(*shard->records) == 2);
    CHECK(n00b_list_get(*shard->records, 0) == rec0);
    CHECK(n00b_list_get(*shard->records, 1) == rec1);
    CHECK(n00b_list_len(*shard->retain_raw) == 2);
    CHECK(shard->raw_bytes != nullptr);

    n00b_store_raw_span_t *span0 = n00b_list_get(*shard->retain_raw, 0);
    n00b_store_raw_span_t *span1 = n00b_list_get(*shard->retain_raw, 1);
    CHECK(span0 != nullptr);
    CHECK(span1 != nullptr);
    CHECK(span0->offset == 0);
    CHECK(span0->byte_len == (uint64_t)n00b_buffer_len(raw0));
    CHECK(span1->offset == span0->byte_len);
    CHECK(span1->byte_len == (uint64_t)n00b_buffer_len(raw1));
    CHECK(shard->raw_bytes->byte_len == span0->byte_len + span1->byte_len);
    CHECK(test_alloc_scan_kind(shard->raw_bytes) == N00B_GC_SCAN_KIND_EVERY_OTHER);
    CHECK(test_alloc_scan_kind(span0) == N00B_GC_SCAN_KIND_NONE);
    CHECK(test_alloc_scan_kind(span1) == N00B_GC_SCAN_KIND_NONE);
    CHECK(test_alloc_scan_kind(shard->raw_bytes->data) == N00B_GC_SCAN_KIND_NONE);
    check_raw_blob_span_equal(shard->raw_bytes, span0, raw0);
    check_raw_blob_span_equal(shard->raw_bytes, span1, raw1);

    auto mutate = n00b_buffer_set_index(raw0, 0, (uint8_t)'!');
    CHECK(n00b_result_is_ok(mutate));
    CHECK(n00b_result_get(mutate));
    CHECK(shard->raw_bytes->data[span0->offset] == (uint8_t)'{');

    CHECK(shard->byte_estimate
          == (2 * N00B_STORE_SHARD_RECORD_OVERHEAD)
                 + (uint64_t)n00b_buffer_len(raw0)
                 + (uint64_t)n00b_buffer_len(raw1));
}

static void
test_append_error_states(void)
{
    auto r = n00b_store_shard_new(.shard_id = 3, .retain_raw = true);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    n00b_json_node_t *rec = test_record_marker(r"state-rec");
    n00b_buffer_t    *raw = n00b_buffer_from_cstr("{\"state\":true}");

    shard->state = N00B_SHARD_STATE_SEALED;
    auto sealed = n00b_store_shard_append(shard, rec, .raw = raw);
    CHECK(n00b_result_is_err(sealed));
    CHECK(n00b_result_get_err(sealed) == N00B_STORE_SHARD_ERR_STATE);
    CHECK(shard->record_count == 0);
    CHECK(n00b_list_len(*shard->records) == 0);
    CHECK(n00b_list_len(*shard->retain_raw) == 0);
    CHECK(shard->raw_bytes->byte_len == 0);

    shard->state = N00B_SHARD_STATE_DROPPED;
    auto dropped = n00b_store_shard_append(shard, rec, .raw = raw);
    CHECK(n00b_result_is_err(dropped));
    CHECK(n00b_result_get_err(dropped) == N00B_STORE_SHARD_ERR_STATE);
    CHECK(shard->record_count == 0);
    CHECK(n00b_list_len(*shard->records) == 0);
    CHECK(n00b_list_len(*shard->retain_raw) == 0);
    CHECK(shard->raw_bytes->byte_len == 0);

    shard->state = N00B_SHARD_STATE_OPEN;
    auto bad_record = n00b_store_shard_append(shard, nullptr, .raw = raw);
    CHECK(n00b_result_is_err(bad_record));
    CHECK(n00b_result_get_err(bad_record) == N00B_STORE_SHARD_ERR_ARG);
    CHECK(shard->record_count == 0);

    shard->byte_estimate = UINT64_MAX - N00B_STORE_SHARD_RECORD_OVERHEAD;
    auto overflow = n00b_store_shard_append(shard, rec, .raw = raw);
    CHECK(n00b_result_is_err(overflow));
    CHECK(n00b_result_get_err(overflow) == N00B_STORE_SHARD_ERR_ARG);
    CHECK(shard->record_count == 0);
    CHECK(n00b_list_len(*shard->records) == 0);
    CHECK(n00b_list_len(*shard->retain_raw) == 0);
    CHECK(shard->raw_bytes->byte_len == 0);

    shard->byte_estimate = 0;
    shard->raw_bytes->byte_len = (uint64_t)INT64_MAX;
    auto raw_store_overflow = n00b_store_shard_append(shard, rec, .raw = raw);
    CHECK(n00b_result_is_err(raw_store_overflow));
    CHECK(n00b_result_get_err(raw_store_overflow) == N00B_STORE_SHARD_ERR_ARG);
    CHECK(shard->record_count == 0);
    CHECK(n00b_list_len(*shard->records) == 0);
    CHECK(n00b_list_len(*shard->retain_raw) == 0);
    CHECK(shard->raw_bytes->byte_len == (uint64_t)INT64_MAX);

    shard->raw_bytes->byte_len = 0;
    shard->record_count  = UINT64_MAX;
    auto record_overflow = n00b_store_shard_append(shard, rec, .raw = raw);
    CHECK(n00b_result_is_err(record_overflow));
    CHECK(n00b_result_get_err(record_overflow) == N00B_STORE_SHARD_ERR_ARG);
    CHECK(shard->record_count == UINT64_MAX);
    CHECK(n00b_list_len(*shard->records) == 0);
    CHECK(n00b_list_len(*shard->retain_raw) == 0);
    CHECK(shard->raw_bytes->byte_len == 0);
}

static void
test_seal_empty_shard(void)
{
    uint64_t shard_id = UINT64_C(0x5100f00d11223344);
    auto     r        = n00b_store_shard_new(.shard_id = shard_id,
                                             .open_ts  = 11);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    auto seal = n00b_store_shard_seal(shard,
                                      .seal_ts      = 22,
                                      .base_address = 0x741ced00u);
    CHECK(n00b_result_is_ok(seal));
    n00b_buffer_t *image = n00b_result_get(seal);
    CHECK(image != nullptr);
    CHECK(n00b_buffer_len(image) > 0);
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);
    CHECK(shard->seal_ts == 22);
    CHECK(shard->record_count == 0);
    CHECK(shard->byte_estimate == 0);

    auto append = n00b_store_shard_append(shard, test_seal_record(1));
    CHECK(n00b_result_is_err(append));
    CHECK(n00b_result_get_err(append) == N00B_STORE_SHARD_ERR_STATE);

    n00b_store_map_t       *map  = nullptr;
    n00b_store_map_shard_t *root = open_sealed_root(image, &map);

    auto id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_get(id_r) == shard_id);
    auto count_r = n00b_store_map_shard_records_len(root);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
    auto state_r = n00b_store_map_shard_state(root);
    CHECK(n00b_result_is_ok(state_r));
    CHECK(n00b_result_get(state_r) == N00B_SHARD_STATE_SEALED);
    auto seal_ts_r = n00b_store_map_shard_seal_ts(root);
    CHECK(n00b_result_is_ok(seal_ts_r));
    CHECK(n00b_result_get(seal_ts_r) == 22);

    auto records_r = n00b_store_map_shard_records(root);
    CHECK(n00b_result_is_ok(records_r));
    auto list_len_r = n00b_store_map_list_len(n00b_result_get(records_r));
    CHECK(n00b_result_is_ok(list_len_r));
    CHECK(n00b_result_get(list_len_r) == 0);

    auto raw_r = n00b_store_map_shard_retain_raw(root);
    CHECK(n00b_result_is_ok(raw_r));
    CHECK(!n00b_option_is_set(n00b_result_get(raw_r)));
    auto raw_buf_r = n00b_store_map_shard_raw_buffer(root, 0);
    CHECK(n00b_result_is_ok(raw_buf_r));
    CHECK(!n00b_option_is_set(n00b_result_get(raw_buf_r)));

    auto close = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close));
    CHECK(n00b_result_get(close));
}

static void
test_seal_populated_shard_without_raw(void)
{
    uint64_t shard_id = UINT64_C(0x5100f00d99aabbcc);
    auto     r        = n00b_store_shard_new(.shard_id = shard_id,
                                             .open_ts  = 27);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    auto a0 = n00b_store_shard_append(shard, test_seal_record(10));
    auto a1 = n00b_store_shard_append(shard, test_seal_record(11));
    CHECK(n00b_result_is_ok(a0));
    CHECK(n00b_result_is_ok(a1));

    auto seal = n00b_store_shard_seal(shard,
                                      .seal_ts      = 28,
                                      .base_address = 0x6e00b002u);
    CHECK(n00b_result_is_ok(seal));

    n00b_store_map_t       *map  = nullptr;
    n00b_store_map_shard_t *root = open_sealed_root(n00b_result_get(seal), &map);

    auto id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_get(id_r) == shard_id);
    auto count_r = n00b_store_map_shard_records_len(root);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);
    auto raw_r = n00b_store_map_shard_retain_raw(root);
    CHECK(n00b_result_is_ok(raw_r));
    CHECK(!n00b_option_is_set(n00b_result_get(raw_r)));
    auto raw_buf_r = n00b_store_map_shard_raw_buffer(root, 0);
    CHECK(n00b_result_is_ok(raw_buf_r));
    CHECK(!n00b_option_is_set(n00b_result_get(raw_buf_r)));

    auto close = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close));
    CHECK(n00b_result_get(close));
}

static void
test_seal_populated_retain_raw_shard(void)
{
    uint64_t shard_id = UINT64_C(0x5100f00d55667788);
    auto     r        = n00b_store_shard_new(.shard_id   = shard_id,
                                             .retain_raw = true,
                                             .open_ts    = 33);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    n00b_buffer_t *raw0 = n00b_buffer_from_cstr("{\"seal\":0}");
    n00b_buffer_t *raw1 = n00b_buffer_from_cstr("{\"seal\":1}");
    auto           a0   = n00b_store_shard_append(shard,
                                                  test_seal_record(0),
                                                  .raw = raw0);
    auto           a1   = n00b_store_shard_append(shard,
                                                  test_seal_record(1),
                                                  .raw = raw1);
    CHECK(n00b_result_is_ok(a0));
    CHECK(n00b_result_is_ok(a1));
    CHECK(n00b_result_get(a0) == 0);
    CHECK(n00b_result_get(a1) == 1);

    uint64_t expected_bytes = shard->byte_estimate;

    auto seal = n00b_store_shard_seal(shard,
                                      .seal_ts      = 44,
                                      .base_address = 0x6e00b003u);
    CHECK(n00b_result_is_ok(seal));
    n00b_buffer_t *image = n00b_result_get(seal);
    CHECK(image != nullptr);
    CHECK(n00b_buffer_len(image) > 0);
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);
    CHECK(shard->seal_ts == 44);
    CHECK(shard->record_count == 2);
    CHECK(shard->byte_estimate == expected_bytes);

    auto append = n00b_store_shard_append(shard,
                                          test_seal_record(2),
                                          .raw = raw0);
    CHECK(n00b_result_is_err(append));
    CHECK(n00b_result_get_err(append) == N00B_STORE_SHARD_ERR_STATE);

    n00b_store_map_t       *map  = nullptr;
    n00b_store_map_shard_t *root = open_sealed_root(image, &map);

    auto id_r = n00b_store_map_shard_id(root);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_get(id_r) == shard_id);
    auto count_r = n00b_store_map_shard_records_len(root);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);
    auto state_r = n00b_store_map_shard_state(root);
    CHECK(n00b_result_is_ok(state_r));
    CHECK(n00b_result_get(state_r) == N00B_SHARD_STATE_SEALED);
    auto seal_ts_r = n00b_store_map_shard_seal_ts(root);
    CHECK(n00b_result_is_ok(seal_ts_r));
    CHECK(n00b_result_get(seal_ts_r) == 44);

    auto records_r = n00b_store_map_shard_records(root);
    CHECK(n00b_result_is_ok(records_r));
    n00b_store_map_list_t *records = n00b_result_get(records_r);
    auto                  records_len_r = n00b_store_map_list_len(records);
    CHECK(n00b_result_is_ok(records_len_r));
    CHECK(n00b_result_get(records_len_r) == 2);

    auto slot_r = n00b_store_map_list_slot(records, 0);
    CHECK(n00b_result_is_ok(slot_r));
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    CHECK(n00b_option_is_set(slot_opt));
    auto ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    CHECK(n00b_result_is_ok(ref_r));
    CHECK(n00b_option_is_set(n00b_result_get(ref_r)));
    auto missing_slot_r = n00b_store_map_list_slot(records, 99);
    CHECK(n00b_result_is_ok(missing_slot_r));
    CHECK(!n00b_option_is_set(n00b_result_get(missing_slot_r)));

    auto raw_r = n00b_store_map_shard_retain_raw(root);
    CHECK(n00b_result_is_ok(raw_r));
    n00b_option_t(n00b_store_map_list_t *) raw_opt = n00b_result_get(raw_r);
    CHECK(n00b_option_is_set(raw_opt));
    n00b_store_map_list_t *raw = n00b_option_get(raw_opt);
    auto                  raw_len_r = n00b_store_map_list_len(raw);
    CHECK(n00b_result_is_ok(raw_len_r));
    CHECK(n00b_result_get(raw_len_r) == 2);

    auto raw_slot_r = n00b_store_map_list_slot(raw, 0);
    CHECK(n00b_result_is_ok(raw_slot_r));
    n00b_option_t(n00b_store_map_slot_t *) raw_slot_opt =
        n00b_result_get(raw_slot_r);
    CHECK(n00b_option_is_set(raw_slot_opt));
    auto raw_ref_r = n00b_store_map_slot_ref(n00b_option_get(raw_slot_opt));
    CHECK(n00b_result_is_ok(raw_ref_r));
    CHECK(n00b_option_is_set(n00b_result_get(raw_ref_r)));

    auto raw0_buf_r = n00b_store_map_shard_raw_buffer(root, 0);
    CHECK(n00b_result_is_ok(raw0_buf_r));
    n00b_option_t(n00b_store_map_buffer_t *) raw0_buf_opt =
        n00b_result_get(raw0_buf_r);
    CHECK(n00b_option_is_set(raw0_buf_opt));
    check_cold_buffer_equal(n00b_option_get(raw0_buf_opt), raw0);

    auto raw1_buf_r = n00b_store_map_shard_raw_buffer(root, 1);
    CHECK(n00b_result_is_ok(raw1_buf_r));
    n00b_option_t(n00b_store_map_buffer_t *) raw1_buf_opt =
        n00b_result_get(raw1_buf_r);
    CHECK(n00b_option_is_set(raw1_buf_opt));
    check_cold_buffer_equal(n00b_option_get(raw1_buf_opt), raw1);

    auto raw_missing_r = n00b_store_map_shard_raw_buffer(root, 99);
    CHECK(n00b_result_is_ok(raw_missing_r));
    CHECK(!n00b_option_is_set(n00b_result_get(raw_missing_r)));

    auto close = n00b_store_map_close(map);
    CHECK(n00b_result_is_ok(close));
    CHECK(n00b_result_get(close));
}

static void
test_seal_error_states(void)
{
    auto null_seal = n00b_store_shard_seal(nullptr);
    CHECK(n00b_result_is_err(null_seal));
    CHECK(n00b_result_get_err(null_seal) == N00B_STORE_SHARD_ERR_ARG);

    auto r = n00b_store_shard_new(.shard_id = 4);
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    auto seal = n00b_store_shard_seal(shard, .seal_ts = 55);
    CHECK(n00b_result_is_ok(seal));
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);
    CHECK(shard->seal_ts == 55);

    auto repeated = n00b_store_shard_seal(shard, .seal_ts = 66);
    CHECK(n00b_result_is_err(repeated));
    CHECK(n00b_result_get_err(repeated) == N00B_STORE_SHARD_ERR_STATE);
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);
    CHECK(shard->seal_ts == 55);

    auto dropped_r = n00b_store_shard_new(.shard_id = 5);
    CHECK(n00b_result_is_ok(dropped_r));
    n00b_store_shard_t *dropped = n00b_result_get(dropped_r);
    dropped->state              = N00B_SHARD_STATE_DROPPED;
    auto dropped_seal = n00b_store_shard_seal(dropped, .seal_ts = 77);
    CHECK(n00b_result_is_err(dropped_seal));
    CHECK(n00b_result_get_err(dropped_seal) == N00B_STORE_SHARD_ERR_STATE);
    CHECK(dropped->state == N00B_SHARD_STATE_DROPPED);
    CHECK(dropped->seal_ts == 0);

    auto broken_r = n00b_store_shard_new(.shard_id = 6);
    CHECK(n00b_result_is_ok(broken_r));
    n00b_store_shard_t       *broken       = n00b_result_get(broken_r);
    n00b_store_record_list_t *saved_records = broken->records;
    broken->records                         = nullptr;
    auto broken_seal = n00b_store_shard_seal(broken, .seal_ts = 88);
    CHECK(n00b_result_is_err(broken_seal));
    CHECK(n00b_result_get_err(broken_seal) == N00B_STORE_SHARD_ERR_ARG);
    CHECK(broken->state == N00B_SHARD_STATE_OPEN);
    CHECK(broken->seal_ts == 0);
    broken->records = saved_records;
}

static void
test_public_contracts(void)
{
    static_assert(N00B_ROCS_API_VERSION == 1);
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_STORE_SHARD_DECLS) != 0);
    static_assert(sizeof(n00b_store_raw_blob_t) == 16);
    static_assert(offsetof(n00b_store_raw_blob_t, data) == 0);
    static_assert(offsetof(n00b_store_raw_blob_t, byte_len) == 8);
    static_assert(sizeof(n00b_store_raw_span_t) == 16);
    static_assert(offsetof(n00b_store_raw_span_t, offset) == 0);
    static_assert(offsetof(n00b_store_raw_span_t, byte_len) == 8);
    static_assert(sizeof(n00b_store_shard_t) == 80);
    static_assert(offsetof(n00b_store_shard_t, records) == 0);
    static_assert(offsetof(n00b_store_shard_t, columns) == 8);
    static_assert(offsetof(n00b_store_shard_t, retain_raw) == 16);
    static_assert(offsetof(n00b_store_shard_t, raw_bytes) == 24);
    static_assert(offsetof(n00b_store_shard_t, state) == 32);
    static_assert(offsetof(n00b_store_shard_t, record_count) == 40);
    static_assert(offsetof(n00b_store_shard_t, shard_id) == 72);

    n00b_store_lifecycle_t sealed = {
        .kind         = N00B_STORE_LIFECYCLE_SEALED,
        .shard_id     = 7,
        .record_count = 0,
        .byte_size    = 0,
        .open_ts      = 11,
        .seal_ts      = 22,
        .drop_reason  = nullptr,
    };
    CHECK(sealed.kind == N00B_STORE_LIFECYCLE_SEALED);
    CHECK(sealed.drop_reason == nullptr);

    n00b_store_lifecycle_msg_t *msg = nullptr;
    n00b_store_lifecycle_inbox_t *inbox = nullptr;
    n00b_store_lifecycle_topic_t *topic = nullptr;
    CHECK(msg == nullptr);
    CHECK(inbox == nullptr);
    CHECK(topic == nullptr);

    CHECK(n00b_store_shard_err_str(N00B_STORE_SHARD_OK) != nullptr);
    CHECK(n00b_store_shard_err_str(N00B_STORE_SHARD_ERR_STATE) != nullptr);
    CHECK(n00b_store_shard_err_str(N00B_STORE_SHARD_ERR_MARSHAL) != nullptr);
    CHECK(n00b_store_shard_err_str(-9999) != nullptr);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_public_contracts();
    test_default_constructor();
    test_retain_raw_constructor();
    test_append_without_raw_retention();
    test_append_with_raw_retention();
    test_append_error_states();
    test_seal_empty_shard();
    test_seal_populated_shard_without_raw();
    test_seal_populated_retain_raw_shard();
    test_seal_error_states();

    return 0;
}
