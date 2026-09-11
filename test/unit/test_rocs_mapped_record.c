#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "n00b.h"
#include "core/arena.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "internal/rocs/eval.h"
#include "internal/rocs/index.h"
#include "internal/rocs/map.h"
#include "internal/rocs/plan_ir.h"
#include "rocs/n00b_rocs.h"
#include "util/assert.h"
#include "util/marshal.h"

#ifndef N00B_DEBUG
#error "test_rocs_mapped_record requires N00B_DEBUG; use -Dbuild_tests=true"
#endif

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)
#define OK(expr)                                                                               \
    ({                                                                                         \
        auto _r = (expr);                                                                      \
        CHECK(n00b_result_is_ok(_r));                                                          \
        n00b_result_get(_r);                                                                   \
    })

static n00b_calloc_fn child_alloc;
static n00b_free_fn   child_free;
static uint64_t       allocations;
static uint64_t       frees;

static void *
count_alloc(n00b_allocator_t *allocator, size_t size, void *info)
{
    allocations++;
    return child_alloc(allocator, size, info);
}

static void
count_free(n00b_allocator_t *allocator, void *ptr)
{
    frees++;
    child_free(allocator, ptr);
}

static n00b_buffer_t *
make_image(uint64_t count)
{
    n00b_store_shard_t *shard = OK(n00b_store_shard_new(.shard_id = 271));
    for (uint64_t i = 0; i < count; i++) {
        n00b_json_node_t *record = n00b_json_object_new();
        n00b_json_object_put_n00b(
            record,
            r"session",
            n00b_json_string_new_from_n00b(i % 4 == 0 ? r"target" : r"other"));
        n00b_json_object_put_n00b(record, r"ordinal", n00b_json_int_new(i));
        CHECK(OK(n00b_store_shard_append(shard, record)) == i);
    }
    return OK(n00b_store_shard_seal(shard, .seal_ts = 91, .base_address = 0x9271u));
}

static n00b_buffer_t *
benchmark_image(const char *path, uint64_t count)
{
    FILE *file = fopen(path, "rb");
    if (file != nullptr) {
        CHECK(fseek(file, 0, SEEK_END) == 0);
        long size = ftell(file);
        CHECK(size > 0 && fseek(file, 0, SEEK_SET) == 0);
        n00b_buffer_t *image = n00b_buffer_new(0);
        n00b_buffer_resize(image, size);
        CHECK(fread(image->data, 1, size, file) == (size_t)size);
        CHECK(fclose(file) == 0);
        return image;
    }
    n00b_buffer_t *image = make_image(count);
    file                 = fopen(path, "wb");
    CHECK(file != nullptr);
    CHECK(fwrite(image->data, 1, image->byte_len, file) == image->byte_len);
    CHECK(fclose(file) == 0);
    return image;
}

static n00b_store_record_t *
check_view(n00b_store_map_shard_t *root,
           uint64_t                ordinal,
           n00b_allocator_t       *scratch,
           n00b_err_t              expected)
{
    n00b_store_pos_t pos = {.shard_id = 271, .ordinal = ordinal, .generation = 123};
    auto             at = n00b_store_record_view_mapped_at(root, ordinal, .allocator = scratch);
    auto by_pos         = n00b_store_record_view_mapped_pos(root, pos, .allocator = scratch);
    if (expected != N00B_STORE_INDEX_OK) {
        CHECK(n00b_result_is_err(at));
        CHECK(n00b_result_get_err(at) == expected);
        CHECK(n00b_result_is_err(by_pos));
        CHECK(n00b_result_get_err(by_pos) == expected);
        return nullptr;
    }
    CHECK(n00b_result_is_ok(at));
    CHECK(n00b_result_is_ok(by_pos));
    n00b_store_pos_t actual = OK(n00b_store_record_pos(n00b_result_get(at)));
    CHECK(actual.shard_id == 271 && actual.ordinal == ordinal && actual.generation == 91);
    actual = OK(n00b_store_record_pos(n00b_result_get(by_pos)));
    CHECK(actual.shard_id == pos.shard_id && actual.ordinal == ordinal
          && actual.generation == pos.generation);
    return n00b_result_get(at);
}

typedef struct {
    uint64_t magic;
    uint32_t version, base, root, flags;
} image_header_t;

typedef struct {
    uint64_t records, columns, retain_raw, raw_bytes;
    uint32_t state, reserved;
    uint64_t count, byte_estimate, open_ts, seal_ts, shard_id;
} shard_wire_t;

static void *
wire_at(uint8_t *payload, uint64_t vaddr)
{
    return payload + (uint32_t)vaddr;
}

static void
test_errors(n00b_buffer_t *image, n00b_allocator_t *scratch)
{
    n00b_store_map_t       *map  = OK(n00b_store_map_open_buffer(image));
    n00b_store_map_shard_t *root = OK(n00b_store_map_root(map));
    uint8_t        *bytes   = (void *)(uintptr_t)OK(n00b_store_map_resident_base_for_test(map));
    image_header_t *header  = (void *)bytes;
    uint8_t        *payload = bytes + ((sizeof(*header) + 15u) & ~(size_t)15u);
    shard_wire_t   *wire    = wire_at(payload, header->root);
    n00b_list_t(void *) *records = wire_at(payload, wire->records);
    uint64_t      *slots         = wire_at(payload, (uint64_t)(uintptr_t)records->data);
    uint64_t       saved_ref     = slots[0];
    n00b_string_t *string        = wire_at(payload, saved_ref);
    n00b_string_t  saved_string  = *string;
    uint64_t       saved_records = wire->records;
    void         **saved_data    = records->data;
    size_t         saved_len     = records->len;

    check_view(nullptr, 0, scratch, N00B_STORE_INDEX_ERR_ARG);
    check_view(root, wire->count, scratch, N00B_STORE_INDEX_ERR_ARG);
    wire->state = N00B_SHARD_STATE_OPEN;
    check_view(root, 1, scratch, N00B_STORE_INDEX_ERR_STATE);
    wire->state   = N00B_SHARD_STATE_SEALED;
    wire->records = 0;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_STATE);
    wire->records = UINT64_MAX;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_STATE);
    wire->records = saved_records;
    records->len  = 0;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_ARG);
    records->len = saved_len - 1;
    auto view    = check_view(root, 0, scratch, N00B_STORE_INDEX_OK);
    auto json    = n00b_store_record_view_json(view, .allocator = scratch);
    CHECK(n00b_result_is_err(json) && n00b_result_get_err(json) == N00B_STORE_INDEX_ERR_STATE);
    records->len = SIZE_MAX;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_STATE);
    records->len  = saved_len;
    records->data = nullptr;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_STATE);
    records->data = saved_data;
    slots[0]      = 0;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_STATE);
    slots[0] = UINT64_MAX;
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_STATE);
    slots[0] = saved_ref;

    // Construction only validates a reference; parsing owns string validation.
    string->data = nullptr;
    view         = check_view(root, 0, scratch, N00B_STORE_INDEX_OK);
    json         = n00b_store_record_view_json(view, .allocator = scratch);
    CHECK(n00b_result_is_err(json) && n00b_result_get_err(json) == N00B_STORE_INDEX_ERR_STATE);
    *string          = saved_string;
    string->u8_bytes = SIZE_MAX;
    check_view(root, 0, scratch, N00B_STORE_INDEX_OK);
    *string = saved_string;

    n00b_store_pos_t wrong = {.shard_id = 272};
    auto             bad = n00b_store_record_view_mapped_pos(root, wrong, .allocator = scratch);
    CHECK(n00b_result_is_err(bad) && n00b_result_get_err(bad) == N00B_STORE_INDEX_ERR_STATE);
    wrong.shard_id = 0;
    bad            = n00b_store_record_view_mapped_pos(root, wrong, .allocator = scratch);
    CHECK(n00b_result_is_err(bad) && n00b_result_get_err(bad) == N00B_STORE_INDEX_ERR_ARG);
    view = OK(n00b_store_record_view_mapped_at(root, 0, .allocator = scratch));
    CHECK(OK(n00b_store_map_close(map)));
    check_view(root, 0, scratch, N00B_STORE_INDEX_ERR_ARG);
    json = n00b_store_record_view_json(view, .allocator = scratch);
    CHECK(n00b_result_is_err(json) && n00b_result_get_err(json) == N00B_STORE_INDEX_ERR_ARG);
}

static void
test_json_graph(n00b_allocator_t *scratch)
{
    n00b_store_shard_t *shard = OK(n00b_store_shard_new(.shard_id = 271));
    n00b_json_node_t   *node  = n00b_json_int_new(42);
    CHECK(OK(n00b_store_shard_append(shard, node)) == 0);
    // Older images can store a JSON graph in place of compact JSON text.
    n00b_list_set(*shard->records, 0, (n00b_string_t *)node);
    shard->state                  = N00B_SHARD_STATE_SEALED;
    shard->seal_ts                = 91;
    n00b_buffer_t          *image = n00b_marshal(shard, .base_address = 0x9272u);
    n00b_store_map_t       *map   = OK(n00b_store_map_open_buffer(image));
    n00b_store_map_shard_t *root  = OK(n00b_store_map_root(map));
    auto                    view  = check_view(root, 0, scratch, N00B_STORE_INDEX_OK);
    auto                    json  = OK(n00b_store_record_view_json(view, .allocator = scratch));
    CHECK(n00b_json_is_int(json) && n00b_json_as_i64(json) == 42);
    CHECK(OK(n00b_store_map_close(map)));
    CHECK(n00b_json_as_i64(json) == 42);
}

static double
seconds(void)
{
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);
    bool           bench = argc > 1 && strcmp(argv[1], "--bench") == 0;
    uint64_t       count = bench ? 16384 : 16;
    n00b_buffer_t *image
        = bench && argc > 2 ? benchmark_image(argv[2], count) : make_image(count);
    n00b_arena_t     *scratch   = n00b_new_arena(.use_gc = false, .no_map = true);
    n00b_allocator_t *allocator = (void *)scratch;
    if (!bench) {
        test_errors(image, allocator);
        test_json_graph(allocator);
        n00b_arena_reset(scratch);
    }

    n00b_pool_t       pool         = {};
    n00b_allocator_t *children     = n00b_pool_init(&pool);
    child_alloc                    = children->zero_alloc;
    child_free                     = children->free;
    children->zero_alloc           = count_alloc;
    children->free                 = count_free;
    n00b_store_map_t       *map    = OK(n00b_store_map_open_buffer(image));
    n00b_store_map_shard_t *root   = OK(n00b_store_map_root(map, .view_allocator = children));
    n00b_plan_target_t     *target = OK(n00b_plan_target_field(r"session"));
    n00b_plan_predicate_t  *predicate = OK(n00b_plan_predicate_prefix(target, r"target"));

    int runs = bench && argc > 3 ? atoi(argv[3]) : (bench ? 6 : 1);
    CHECK(runs > 0);
    for (int run = 0; run < runs; run++) {
        allocations = frees = 0;
        n00b_plan_records_scanned_reset();
        double              start = seconds();
        n00b_plan_ordset_t *set   = OK(
            n00b_plan_record_scan_mapped(root, nullptr, predicate, .allocator = allocator));
        double elapsed = seconds() - start;
        CHECK(n00b_plan_records_scanned() == count);
        CHECK(set->count == count / 4);
        uint64_t hash = UINT64_C(14695981039346656037);
        for (uint64_t i = 0; i < set->count; i++) {
            auto ordinal = OK(n00b_plan_ordset_at(set, i));
            CHECK(n00b_option_is_set(ordinal));
            uint64_t value = n00b_option_get(ordinal);
            CHECK(value == i * 4);
            hash = (hash ^ value) * UINT64_C(1099511628211);
        }
        printf(
            "run=%d seconds=%.6f scanned=%llu matched=%llu hash=%016llx child_alloc=%llu "
            "child_free=%llu\n",
            run,
            elapsed,
            (unsigned long long)n00b_plan_records_scanned(),
            (unsigned long long)set->count,
            (unsigned long long)hash,
            (unsigned long long)allocations,
            (unsigned long long)frees);
        fflush(stdout);
        if (!bench) {
            CHECK(allocations == 0 && frees == 0);
        }
        n00b_arena_reset(scratch);
        children->zero_alloc = child_alloc;
        children->free       = child_free;
        n00b_allocator_destroy(children);
        children             = n00b_pool_init(&pool);
        children->zero_alloc = count_alloc;
        children->free       = count_free;
    }
    if (!bench) {
        allocations = frees = 0;
        for (uint64_t i = 0; i < count; i++) {
            auto view  = check_view(root, i, allocator, N00B_STORE_INDEX_OK);
            auto json  = OK(n00b_store_record_view_json(view, .allocator = allocator));
            auto value = n00b_json_object_get(json, r"ordinal");
            CHECK(n00b_json_is_int(value) && n00b_json_as_i64(value) == (int64_t)i);
            auto text = OK(n00b_store_record_view_json_string(view, .allocator = allocator));
            auto span = OK(n00b_store_map_shard_record_span(root, i));
            CHECK(text->u8_bytes == span.byte_len
                  && memcmp(text->data, span.data, text->u8_bytes) == 0);
            n00b_arena_reset(scratch);
        }
        CHECK(allocations == 0 && frees == 0);
    }
    CHECK(OK(n00b_store_map_close(map)));
    children->zero_alloc = child_alloc;
    children->free       = child_free;
    n00b_allocator_destroy(children);
    n00b_allocator_destroy(allocator);
    n00b_shutdown();
    return 0;
}
