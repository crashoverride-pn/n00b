#include "internal/rocs/query.h"

#include "adt/list.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "internal/rocs/filter.h"
#include "internal/rocs/index.h"
#include "internal/rocs/plan.h"
#include "internal/rocs/store.h"
#include "rocs/map.h"
#include "text/strings/string_ops.h"

typedef n00b_list_t(n00b_query_boundary_entry_t)
    rocs_query_boundary_list_t;
typedef n00b_list_t(n00b_query_cursor_t *) rocs_query_cursor_list_t;
typedef n00b_list_t(n00b_query_hit_t *) rocs_query_hit_list_t;
typedef n00b_list_t(n00b_store_resident_shard_t *)
    rocs_query_resident_list_t;
typedef n00b_list_t(n00b_plan_ordset_t *) rocs_query_ordset_ref_list_t;
typedef struct rocs_query_cache_entry_t rocs_query_cache_entry_t;
typedef n00b_list_t(rocs_query_cache_entry_t *)
    rocs_query_cache_entry_list_t;

typedef struct {
    n00b_buffer_t *bytes;
    bool           cacheable;
} rocs_query_cache_key_t;

typedef struct {
    n00b_plan_ordset_t *ordinals;
    bool                found;
} rocs_query_cache_lookup_t;

struct rocs_query_cache_entry_t {
    n00b_buffer_t      *key;
    uint64_t            shard_id;
    uint64_t            generation;
    uint64_t            schema_generation;
    uint64_t            record_count;
    uint64_t            seal_ts;
    n00b_plan_ordset_t *ordinals;
};

typedef struct {
    rocs_query_cache_entry_list_t *entries;
    n00b_query_cache_stats_t       stats;
    bool                           disabled;
} rocs_query_cache_t;

struct n00b_query_retention_error_t {
    n00b_query_err_t           code;
    n00b_query_boundary_kind_t boundary;
    n00b_store_pos_t           requested;
    bool                       has_oldest_available;
    n00b_store_pos_t           oldest_available;
};

struct n00b_query_view_t {
    n00b_store_t              *store;
    n00b_filter_t             *filter;
    n00b_store_pin_t          *pin;
    rocs_query_boundary_list_t *boundary;
    rocs_query_cursor_list_t  *cursors;
    rocs_query_cache_t        *cache;
    n00b_allocator_t          *allocator;
    n00b_query_mode_t          mode;
    uint64_t                   limit;
    bool                       has_resume;
    n00b_store_pos_t           resume;
    bool                       has_as_of;
    n00b_store_pos_t           as_of;
    bool                       closed;
};

struct n00b_query_cursor_t {
    n00b_query_view_t         *view;
    rocs_query_hit_list_t     *hits;
    rocs_query_resident_list_t *residents;
    n00b_query_hit_t          *current_hit;
    n00b_allocator_t          *allocator;
    uint64_t                   next_index;
    bool                       has_position;
    n00b_store_pos_t           position;
    bool                       closed;
};

struct n00b_query_hit_t {
    n00b_query_cursor_t *cursor;
    n00b_store_pos_t     pos;
    n00b_store_record_t *record;
    double               score;
    bool                 valid;
};

n00b_string_t *
n00b_query_err_str(n00b_err_t err)
{
    switch ((n00b_query_err_t)err) {
    case N00B_QUERY_OK:
        return r"N00B_QUERY_OK";
    case N00B_QUERY_ERR_ARG:
        return r"N00B_QUERY_ERR_ARG";
    case N00B_QUERY_ERR_CLOSED:
        return r"N00B_QUERY_ERR_CLOSED";
    case N00B_QUERY_ERR_STATE:
        return r"N00B_QUERY_ERR_STATE";
    case N00B_QUERY_ERR_SCHEMA:
        return r"N00B_QUERY_ERR_SCHEMA";
    case N00B_QUERY_ERR_RETENTION:
        return r"N00B_QUERY_ERR_RETENTION";
    case N00B_QUERY_ERR_UNSUPPORTED_MODE:
        return r"N00B_QUERY_ERR_UNSUPPORTED_MODE";
    case N00B_QUERY_ERR_UNSUPPORTED_FILTER:
        return r"N00B_QUERY_ERR_UNSUPPORTED_FILTER";
    case N00B_QUERY_ERR_EXECUTION:
        return r"N00B_QUERY_ERR_EXECUTION";
    case N00B_QUERY_ERR_INTERNAL:
        return r"N00B_QUERY_ERR_INTERNAL";
    }

    return r"N00B_QUERY_ERR_UNKNOWN";
}

static n00b_query_err_t
rocs_query_err_from_store(n00b_err_t err)
{
    switch ((n00b_store_err_t)err) {
    case N00B_STORE_ERR_ARG:
        return N00B_QUERY_ERR_ARG;
    case N00B_STORE_ERR_STATE:
    case N00B_STORE_ERR_PINNED:
        return N00B_QUERY_ERR_STATE;
    case N00B_STORE_ERR_FIELD:
        return N00B_QUERY_ERR_SCHEMA;
    case N00B_STORE_ERR_RESIDENCY:
    case N00B_STORE_ERR_VFS:
    case N00B_STORE_ERR_CORRUPT:
    case N00B_STORE_ERR_PARSE:
    case N00B_STORE_ERR_INDEX:
        return N00B_QUERY_ERR_EXECUTION;
    case N00B_STORE_ERR_RETENTION:
        return N00B_QUERY_ERR_RETENTION;
    case N00B_STORE_ERR_DUP_FIELD:
    case N00B_STORE_ERR_POLICY:
        return N00B_QUERY_ERR_STATE;
    case N00B_STORE_ERR_INTERNAL:
    case N00B_STORE_OK:
        return N00B_QUERY_ERR_INTERNAL;
    }

    return N00B_QUERY_ERR_INTERNAL;
}

static n00b_query_err_t
rocs_query_err_from_filter(n00b_err_t err)
{
    switch ((n00b_filter_err_t)err) {
    case N00B_FILTER_ERR_ARG:
        return N00B_QUERY_ERR_ARG;
    case N00B_FILTER_ERR_UNSUPPORTED:
        return N00B_QUERY_ERR_UNSUPPORTED_FILTER;
    case N00B_FILTER_ERR_PATH:
    case N00B_FILTER_ERR_IR:
    case N00B_FILTER_ERR_STATE:
        return N00B_QUERY_ERR_UNSUPPORTED_FILTER;
    case N00B_FILTER_OK:
        return N00B_QUERY_ERR_INTERNAL;
    }

    return N00B_QUERY_ERR_INTERNAL;
}

static n00b_query_err_t
rocs_query_err_from_plan(n00b_err_t err)
{
    switch ((n00b_plan_err_t)err) {
    case N00B_PLAN_ERR_ARG:
        return N00B_QUERY_ERR_ARG;
    case N00B_PLAN_ERR_ANY_UNSUPPORTED:
    case N00B_PLAN_ERR_EMPTY:
        return N00B_QUERY_ERR_UNSUPPORTED_FILTER;
    case N00B_PLAN_ERR_STATE:
    case N00B_PLAN_ERR_ORDINAL:
    case N00B_PLAN_ERR_UNIVERSE:
        return N00B_QUERY_ERR_EXECUTION;
    case N00B_PLAN_OK:
        return N00B_QUERY_ERR_INTERNAL;
    }

    return N00B_QUERY_ERR_INTERNAL;
}

static n00b_query_err_t
rocs_query_err_from_index(n00b_err_t err)
{
    switch ((n00b_store_index_err_t)err) {
    case N00B_STORE_INDEX_ERR_ARG:
        return N00B_QUERY_ERR_ARG;
    case N00B_STORE_INDEX_ERR_KIND:
    case N00B_STORE_INDEX_ERR_UNREADY:
        return N00B_QUERY_ERR_UNSUPPORTED_FILTER;
    case N00B_STORE_INDEX_ERR_STATE:
        return N00B_QUERY_ERR_EXECUTION;
    case N00B_STORE_INDEX_ERR_INTERNAL:
    case N00B_STORE_INDEX_OK:
        return N00B_QUERY_ERR_INTERNAL;
    }

    return N00B_QUERY_ERR_INTERNAL;
}

static n00b_query_err_t
rocs_query_err_from_map(n00b_err_t err)
{
    switch ((n00b_store_map_err_t)err) {
    case N00B_STORE_MAP_ERR_ARG:
        return N00B_QUERY_ERR_ARG;
    case N00B_STORE_MAP_ERR_IO:
    case N00B_STORE_MAP_ERR_BAD_MAGIC:
    case N00B_STORE_MAP_ERR_BAD_VERSION:
    case N00B_STORE_MAP_ERR_BAD_LAYOUT:
    case N00B_STORE_MAP_ERR_RANGE:
    case N00B_STORE_MAP_ERR_SCHEMA:
    case N00B_STORE_MAP_ERR_BACKING:
    case N00B_STORE_MAP_ERR_CACHE:
        return N00B_QUERY_ERR_EXECUTION;
    case N00B_STORE_MAP_OK:
        return N00B_QUERY_ERR_INTERNAL;
    }

    return N00B_QUERY_ERR_INTERNAL;
}

static rocs_query_boundary_list_t *
rocs_query_boundary_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_boundary_list_t *list = n00b_alloc_with_opts(
        rocs_query_boundary_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_boundary_entry_t,
                                  .allocator = allocator);
    return list;
}

static rocs_query_cursor_list_t *
rocs_query_cursor_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_cursor_list_t *list = n00b_alloc_with_opts(
        rocs_query_cursor_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_cursor_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_hit_list_t *
rocs_query_hit_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_hit_list_t *list = n00b_alloc_with_opts(
        rocs_query_hit_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_hit_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_resident_list_t *
rocs_query_resident_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_resident_list_t *list = n00b_alloc_with_opts(
        rocs_query_resident_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_store_resident_shard_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_ordset_ref_list_t *
rocs_query_ordset_ref_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_ordset_ref_list_t *list = n00b_alloc_with_opts(
        rocs_query_ordset_ref_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_plan_ordset_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_cache_entry_list_t *
rocs_query_cache_entry_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_cache_entry_list_t *list = n00b_alloc_with_opts(
        rocs_query_cache_entry_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(rocs_query_cache_entry_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_cache_t *
rocs_query_cache_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_cache_t *cache = n00b_alloc_with_opts(
        rocs_query_cache_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    cache->entries  = rocs_query_cache_entry_list_new(.allocator = allocator);
    cache->stats    = (n00b_query_cache_stats_t){};
    cache->disabled = false;
    return cache;
}

static void
rocs_query_cache_evict_to_bound(rocs_query_cache_t *cache,
                                n00b_allocator_t   *allocator)
{
    if (cache == nullptr || cache->entries == nullptr
        || cache->stats.max_entries == 0) {
        return;
    }

    size_t len = n00b_list_len(*cache->entries);
    if ((uint64_t)len <= cache->stats.max_entries) {
        cache->stats.entries = (uint64_t)len;
        return;
    }

    size_t keep  = (size_t)cache->stats.max_entries;
    size_t start = len - keep;
    rocs_query_cache_entry_list_t *retained =
        rocs_query_cache_entry_list_new(.allocator = allocator);

    for (size_t i = start; i < len; i++) {
        rocs_query_cache_entry_t *entry =
            n00b_list_get(*cache->entries, i);
        n00b_list_push(*retained, entry);
    }

    cache->entries = retained;
    cache->stats.evictions += (uint64_t)start;
    cache->stats.entries = (uint64_t)n00b_list_len(*cache->entries);
}

static n00b_buffer_t *
rocs_query_key_buffer_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_buffer_t *buffer = n00b_alloc_with_opts(
        n00b_buffer_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    n00b_buffer_init(buffer, .length = 0, .allocator = allocator);
    return buffer;
}

static n00b_result_t(uint64_t)
rocs_query_key_append_space(n00b_buffer_t *key, uint64_t len)
{
    if (key == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    size_t old_len = key->byte_len;
    if (len > (uint64_t)(SIZE_MAX - old_len)) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_INTERNAL);
    }

    n00b_buffer_resize(key, (uint64_t)old_len + len);
    return n00b_result_ok(uint64_t, (uint64_t)old_len);
}

static n00b_result_t(bool)
rocs_query_key_append_u8(n00b_buffer_t *key, uint8_t value)
{
    auto off_r = rocs_query_key_append_space(key, sizeof(value));
    if (n00b_result_is_err(off_r)) {
        return n00b_result_err(bool, n00b_result_get_err(off_r));
    }

    memcpy(key->data + (size_t)n00b_result_get(off_r),
           &value,
           sizeof(value));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_key_append_bool(n00b_buffer_t *key, bool value)
{
    uint8_t encoded = value ? UINT8_C(1) : UINT8_C(0);
    return rocs_query_key_append_u8(key, encoded);
}

static n00b_result_t(bool)
rocs_query_key_append_u64(n00b_buffer_t *key, uint64_t value)
{
    auto off_r = rocs_query_key_append_space(key, sizeof(value));
    if (n00b_result_is_err(off_r)) {
        return n00b_result_err(bool, n00b_result_get_err(off_r));
    }

    memcpy(key->data + (size_t)n00b_result_get(off_r),
           &value,
           sizeof(value));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_key_append_i64(n00b_buffer_t *key, int64_t value)
{
    auto off_r = rocs_query_key_append_space(key, sizeof(value));
    if (n00b_result_is_err(off_r)) {
        return n00b_result_err(bool, n00b_result_get_err(off_r));
    }

    memcpy(key->data + (size_t)n00b_result_get(off_r),
           &value,
           sizeof(value));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_key_append_f64(n00b_buffer_t *key, double value)
{
    auto off_r = rocs_query_key_append_space(key, sizeof(value));
    if (n00b_result_is_err(off_r)) {
        return n00b_result_err(bool, n00b_result_get_err(off_r));
    }

    memcpy(key->data + (size_t)n00b_result_get(off_r),
           &value,
           sizeof(value));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_key_append_buffer(n00b_buffer_t *key, n00b_buffer_t *bytes)
{
    if (key == nullptr || bytes == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (bytes->byte_len == 0) {
        return n00b_result_ok(bool, true);
    }

    auto off_r = rocs_query_key_append_space(key, (uint64_t)bytes->byte_len);
    if (n00b_result_is_err(off_r)) {
        return n00b_result_err(bool, n00b_result_get_err(off_r));
    }

    memcpy(key->data + (size_t)n00b_result_get(off_r),
           bytes->data,
           bytes->byte_len);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_key_append_string(n00b_buffer_t *key, n00b_string_t *value)
{
    if (value == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto len_r = rocs_query_key_append_u64(key, (uint64_t)value->u8_bytes);
    if (n00b_result_is_err(len_r)) {
        return len_r;
    }
    if (value->u8_bytes == 0) {
        return n00b_result_ok(bool, true);
    }

    auto off_r = rocs_query_key_append_space(key, (uint64_t)value->u8_bytes);
    if (n00b_result_is_err(off_r)) {
        return n00b_result_err(bool, n00b_result_get_err(off_r));
    }

    memcpy(key->data + (size_t)n00b_result_get(off_r),
           value->data,
           (size_t)value->u8_bytes);
    return n00b_result_ok(bool, true);
}

static bool
rocs_query_key_bytes_equal(n00b_buffer_t *left, n00b_buffer_t *right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    if (left->byte_len != right->byte_len) {
        return false;
    }
    if (left->byte_len == 0) {
        return true;
    }
    return memcmp(left->data, right->data, left->byte_len) == 0;
}

static n00b_result_t(bool)
rocs_query_cache_key_value(n00b_buffer_t *key, n00b_filter_value_t value);

static n00b_result_t(bool)
rocs_query_cache_key_field(n00b_buffer_t *key, n00b_filter_field_t *field)
{
    if (key == nullptr || field == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto any_r = n00b_filter_field_is_any(field);
    if (n00b_result_is_err(any_r)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
    }

    auto marker_r = rocs_query_key_append_bool(key, n00b_result_get(any_r));
    if (n00b_result_is_err(marker_r)) {
        return marker_r;
    }
    if (n00b_result_get(any_r)) {
        return n00b_result_ok(bool, true);
    }

    auto name_r = n00b_filter_field_name(field);
    if (n00b_result_is_err(name_r)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
    }
    n00b_option_t(n00b_string_t *) name_opt = n00b_result_get(name_r);
    if (!n00b_option_is_set(name_opt)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
    }
    return rocs_query_key_append_string(key, n00b_option_get(name_opt));
}

static n00b_result_t(bool)
rocs_query_cache_key_value_list(n00b_buffer_t             *key,
                                n00b_filter_value_list_t *values)
{
    if (key == nullptr || values == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto count_r = n00b_filter_value_list_count(values);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
    }

    uint64_t count = n00b_result_get(count_r);
    auto append_count_r = rocs_query_key_append_u64(key, count);
    if (n00b_result_is_err(append_count_r)) {
        return append_count_r;
    }

    for (uint64_t i = 0; i < count; i++) {
        auto value_r = n00b_filter_value_list_at(values, i);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }
        n00b_option_t(n00b_filter_value_t) value_opt =
            n00b_result_get(value_r);
        if (!n00b_option_is_set(value_opt)) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }

        auto item_r =
            rocs_query_cache_key_value(key, n00b_option_get(value_opt));
        if (n00b_result_is_err(item_r)) {
            return item_r;
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_cache_key_value(n00b_buffer_t *key, n00b_filter_value_t value)
{
    if (key == nullptr || !n00b_variant_is_set(value)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
    }

    if (n00b_variant_is_type(value, n00b_filter_null_t)) {
        return rocs_query_key_append_u64(key, typehash(n00b_filter_null_t));
    }
    if (n00b_variant_is_type(value, bool)) {
        auto tag_r = rocs_query_key_append_u64(key, typehash(bool));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        return rocs_query_key_append_bool(key, n00b_variant_get(value, bool));
    }
    if (n00b_variant_is_type(value, int64_t)) {
        auto tag_r = rocs_query_key_append_u64(key, typehash(int64_t));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        return rocs_query_key_append_i64(key,
                                         n00b_variant_get(value, int64_t));
    }
    if (n00b_variant_is_type(value, uint64_t)) {
        auto tag_r = rocs_query_key_append_u64(key, typehash(uint64_t));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        return rocs_query_key_append_u64(key,
                                         n00b_variant_get(value, uint64_t));
    }
    if (n00b_variant_is_type(value, double)) {
        auto tag_r = rocs_query_key_append_u64(key, typehash(double));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        return rocs_query_key_append_f64(key,
                                         n00b_variant_get(value, double));
    }
    if (n00b_variant_is_type(value, n00b_string_t *)) {
        n00b_string_t *s = n00b_variant_get(value, n00b_string_t *);
        if (s == nullptr) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }
        auto tag_r = rocs_query_key_append_u64(key, typehash(n00b_string_t *));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        return rocs_query_key_append_string(key, s);
    }
    if (n00b_variant_is_type(value, n00b_buffer_t *)) {
        n00b_buffer_t *b = n00b_variant_get(value, n00b_buffer_t *);
        if (b == nullptr) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }
        auto tag_r = rocs_query_key_append_u64(key, typehash(n00b_buffer_t *));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        auto len_r = rocs_query_key_append_u64(key, (uint64_t)b->byte_len);
        if (n00b_result_is_err(len_r)) {
            return len_r;
        }
        return rocs_query_key_append_buffer(key, b);
    }
    if (n00b_variant_is_type(value, n00b_filter_value_list_t *)) {
        n00b_filter_value_list_t *values =
            n00b_variant_get(value, n00b_filter_value_list_t *);
        auto tag_r = rocs_query_key_append_u64(
            key,
            typehash(n00b_filter_value_list_t *));
        if (n00b_result_is_err(tag_r)) {
            return tag_r;
        }
        return rocs_query_cache_key_value_list(key, values);
    }

    return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
}

static n00b_result_t(bool)
rocs_query_cache_key_path(n00b_buffer_t *key, n00b_filter_path_t *path)
{
    if (key == nullptr || path == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto count_r = n00b_filter_path_component_count(path);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_UNSUPPORTED_FILTER);
    }

    uint64_t count = n00b_result_get(count_r);
    auto count_key_r = rocs_query_key_append_u64(key, count);
    if (n00b_result_is_err(count_key_r)) {
        return count_key_r;
    }

    for (uint64_t i = 0; i < count; i++) {
        auto component_r = n00b_filter_path_component_at(path, i);
        if (n00b_result_is_err(component_r)) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }
        n00b_option_t(n00b_filter_path_component_t *) component_opt =
            n00b_result_get(component_r);
        if (!n00b_option_is_set(component_opt)) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }

        n00b_filter_path_component_t *component =
            n00b_option_get(component_opt);
        auto kind_r = n00b_filter_path_component_kind(component);
        if (n00b_result_is_err(kind_r)) {
            return n00b_result_err(bool,
                                   N00B_QUERY_ERR_UNSUPPORTED_FILTER);
        }

        n00b_filter_path_component_kind_t kind = n00b_result_get(kind_r);
        auto kind_key_r = rocs_query_key_append_u64(key, (uint64_t)kind);
        if (n00b_result_is_err(kind_key_r)) {
            return kind_key_r;
        }

        switch (kind) {
        case N00B_FILTER_PATH_KEY: {
            auto key_r = n00b_filter_path_component_key(component);
            if (n00b_result_is_err(key_r)) {
                return n00b_result_err(
                    bool,
                    N00B_QUERY_ERR_UNSUPPORTED_FILTER);
            }
            n00b_option_t(n00b_string_t *) key_opt = n00b_result_get(key_r);
            if (!n00b_option_is_set(key_opt)) {
                return n00b_result_err(
                    bool,
                    N00B_QUERY_ERR_UNSUPPORTED_FILTER);
            }
            auto append_r =
                rocs_query_key_append_string(key, n00b_option_get(key_opt));
            if (n00b_result_is_err(append_r)) {
                return append_r;
            }
            break;
        }
        case N00B_FILTER_PATH_INDEX: {
            auto index_r = n00b_filter_path_component_index(component);
            if (n00b_result_is_err(index_r)) {
                return n00b_result_err(
                    bool,
                    N00B_QUERY_ERR_UNSUPPORTED_FILTER);
            }
            n00b_option_t(uint64_t) index_opt = n00b_result_get(index_r);
            if (!n00b_option_is_set(index_opt)) {
                return n00b_result_err(
                    bool,
                    N00B_QUERY_ERR_UNSUPPORTED_FILTER);
            }
            auto append_r =
                rocs_query_key_append_u64(key, n00b_option_get(index_opt));
            if (n00b_result_is_err(append_r)) {
                return append_r;
            }
            break;
        }
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(rocs_query_cache_key_t)
rocs_query_cache_key_build_inner(n00b_filter_t    *filter,
                                 n00b_allocator_t *allocator)
{
    rocs_query_cache_key_t out = {};
    if (filter == nullptr) {
        return n00b_result_err(rocs_query_cache_key_t, N00B_QUERY_ERR_ARG);
    }

    out.bytes = rocs_query_key_buffer_new(.allocator = allocator);

    auto kind_r = n00b_filter_predicate_kind(filter);
    if (n00b_result_is_err(kind_r)) {
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    n00b_filter_predicate_kind_t kind = n00b_result_get(kind_r);
    auto kind_key_r = rocs_query_key_append_u64(out.bytes, (uint64_t)kind);
    if (n00b_result_is_err(kind_key_r)) {
        return n00b_result_err(rocs_query_cache_key_t,
                               n00b_result_get_err(kind_key_r));
    }

    switch (kind) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        auto count_r = n00b_filter_predicate_child_count(filter);
        if (n00b_result_is_err(count_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        uint64_t count = n00b_result_get(count_r);
        auto count_key_r = rocs_query_key_append_u64(out.bytes, count);
        if (n00b_result_is_err(count_key_r)) {
            return n00b_result_err(rocs_query_cache_key_t,
                                   n00b_result_get_err(count_key_r));
        }
        for (uint64_t i = 0; i < count; i++) {
            auto child_r = n00b_filter_predicate_child_at(filter, i);
            if (n00b_result_is_err(child_r)) {
                return n00b_result_ok(rocs_query_cache_key_t, out);
            }
            n00b_option_t(n00b_filter_t *) child_opt =
                n00b_result_get(child_r);
            if (!n00b_option_is_set(child_opt)) {
                return n00b_result_ok(rocs_query_cache_key_t, out);
            }
            auto child_key_r =
                rocs_query_cache_key_build_inner(n00b_option_get(child_opt),
                                                 allocator);
            if (n00b_result_is_err(child_key_r)) {
                return child_key_r;
            }
            rocs_query_cache_key_t child_key = n00b_result_get(child_key_r);
            if (!child_key.cacheable || child_key.bytes == nullptr) {
                return n00b_result_ok(rocs_query_cache_key_t, out);
            }
            auto len_r =
                rocs_query_key_append_u64(out.bytes,
                                          (uint64_t)child_key.bytes->byte_len);
            if (n00b_result_is_err(len_r)) {
                return n00b_result_err(rocs_query_cache_key_t,
                                       n00b_result_get_err(len_r));
            }
            auto bytes_r =
                rocs_query_key_append_buffer(out.bytes, child_key.bytes);
            if (n00b_result_is_err(bytes_r)) {
                return n00b_result_err(rocs_query_cache_key_t,
                                       n00b_result_get_err(bytes_r));
            }
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_PREDICATE_NOT: {
        auto child_r = n00b_filter_predicate_child_at(filter, 0);
        if (n00b_result_is_err(child_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        n00b_option_t(n00b_filter_t *) child_opt = n00b_result_get(child_r);
        if (!n00b_option_is_set(child_opt)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto child_key_r =
            rocs_query_cache_key_build_inner(n00b_option_get(child_opt),
                                             allocator);
        if (n00b_result_is_err(child_key_r)) {
            return child_key_r;
        }
        rocs_query_cache_key_t child_key = n00b_result_get(child_key_r);
        if (!child_key.cacheable || child_key.bytes == nullptr) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto len_r = rocs_query_key_append_u64(
            out.bytes,
            (uint64_t)child_key.bytes->byte_len);
        if (n00b_result_is_err(len_r)) {
            return n00b_result_err(rocs_query_cache_key_t,
                                   n00b_result_get_err(len_r));
        }
        auto bytes_r = rocs_query_key_append_buffer(out.bytes,
                                                    child_key.bytes);
        if (n00b_result_is_err(bytes_r)) {
            return n00b_result_err(rocs_query_cache_key_t,
                                   n00b_result_get_err(bytes_r));
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_PREDICATE_LEAF:
        break;
    }

    auto op_r = n00b_filter_predicate_leaf_op(filter);
    if (n00b_result_is_err(op_r)) {
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }
    n00b_filter_leaf_op_t op = n00b_result_get(op_r);

    auto op_key_r = rocs_query_key_append_u64(out.bytes, (uint64_t)op);
    if (n00b_result_is_err(op_key_r)) {
        return n00b_result_err(rocs_query_cache_key_t,
                               n00b_result_get_err(op_key_r));
    }

    auto field_r = n00b_filter_predicate_field(filter);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }
    n00b_option_t(n00b_filter_field_t *) field_opt = n00b_result_get(field_r);
    if (!n00b_option_is_set(field_opt)) {
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }
    auto field_key_r =
        rocs_query_cache_key_field(out.bytes, n00b_option_get(field_opt));
    if (n00b_result_is_err(field_key_r)) {
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    switch (op) {
    case N00B_FILTER_LEAF_EQ: {
        auto value_r = n00b_filter_predicate_value(filter);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        n00b_option_t(n00b_filter_value_t) value_opt =
            n00b_result_get(value_r);
        if (!n00b_option_is_set(value_opt)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto value_key_r =
            rocs_query_cache_key_value(out.bytes,
                                       n00b_option_get(value_opt));
        if (n00b_result_is_err(value_key_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_LEAF_IN: {
        auto values_r = n00b_filter_predicate_values(filter);
        if (n00b_result_is_err(values_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        n00b_option_t(n00b_filter_value_list_t *) values_opt =
            n00b_result_get(values_r);
        if (!n00b_option_is_set(values_opt)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto values_key_r =
            rocs_query_cache_key_value_list(out.bytes,
                                            n00b_option_get(values_opt));
        if (n00b_result_is_err(values_key_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_LEAF_RANGE: {
        auto lower_r = n00b_filter_predicate_range_lower(filter);
        auto upper_r = n00b_filter_predicate_range_upper(filter);
        auto incl_lower_r = n00b_filter_predicate_range_include_lower(filter);
        auto incl_upper_r = n00b_filter_predicate_range_include_upper(filter);
        if (n00b_result_is_err(lower_r) || n00b_result_is_err(upper_r)
            || n00b_result_is_err(incl_lower_r)
            || n00b_result_is_err(incl_upper_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        n00b_option_t(n00b_filter_value_t) lower_opt =
            n00b_result_get(lower_r);
        n00b_option_t(n00b_filter_value_t) upper_opt =
            n00b_result_get(upper_r);
        if (!n00b_option_is_set(lower_opt)
            || !n00b_option_is_set(upper_opt)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto lower_key_r =
            rocs_query_cache_key_value(out.bytes,
                                       n00b_option_get(lower_opt));
        auto upper_key_r =
            rocs_query_cache_key_value(out.bytes,
                                       n00b_option_get(upper_opt));
        if (n00b_result_is_err(lower_key_r)
            || n00b_result_is_err(upper_key_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto il_r =
            rocs_query_key_append_bool(out.bytes, n00b_result_get(incl_lower_r));
        auto iu_r =
            rocs_query_key_append_bool(out.bytes, n00b_result_get(incl_upper_r));
        if (n00b_result_is_err(il_r) || n00b_result_is_err(iu_r)) {
            return n00b_result_err(rocs_query_cache_key_t,
                                   N00B_QUERY_ERR_INTERNAL);
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_LEAF_EXISTS:
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);

    case N00B_FILTER_LEAF_CONTAINS:
    case N00B_FILTER_LEAF_PREFIX: {
        auto text_r = n00b_filter_predicate_text(filter);
        if (n00b_result_is_err(text_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        n00b_option_t(n00b_string_t *) text_opt = n00b_result_get(text_r);
        if (!n00b_option_is_set(text_opt)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto text_key_r =
            rocs_query_key_append_string(out.bytes, n00b_option_get(text_opt));
        if (n00b_result_is_err(text_key_r)) {
            return n00b_result_err(rocs_query_cache_key_t,
                                   n00b_result_get_err(text_key_r));
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_LEAF_UNDER: {
        auto path_r = n00b_filter_predicate_path(filter);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        n00b_option_t(n00b_filter_path_t *) path_opt =
            n00b_result_get(path_r);
        if (!n00b_option_is_set(path_opt)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        auto path_key_r =
            rocs_query_cache_key_path(out.bytes, n00b_option_get(path_opt));
        if (n00b_result_is_err(path_key_r)) {
            return n00b_result_ok(rocs_query_cache_key_t, out);
        }
        out.cacheable = true;
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    case N00B_FILTER_LEAF_REGEX:
        return n00b_result_ok(rocs_query_cache_key_t, out);
    }

    return n00b_result_ok(rocs_query_cache_key_t, out);
}

static n00b_result_t(rocs_query_cache_key_t)
rocs_query_cache_key_build(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return rocs_query_cache_key_build_inner(filter, allocator);
}

static n00b_result_t(n00b_plan_ordset_t *)
rocs_query_ordset_copy(n00b_plan_ordset_t *src) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (src == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_QUERY_ERR_ARG);
    }

    auto records_r = n00b_plan_ordset_record_count(src);
    auto count_r   = n00b_plan_ordset_count(src);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(
            n00b_plan_ordset_t *,
            rocs_query_err_from_plan(n00b_result_get_err(records_r)));
    }
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(
            n00b_plan_ordset_t *,
            rocs_query_err_from_plan(n00b_result_get_err(count_r)));
    }

    auto copy_r = n00b_plan_ordset_empty(n00b_result_get(records_r),
                                         .allocator = allocator);
    if (n00b_result_is_err(copy_r)) {
        return n00b_result_err(
            n00b_plan_ordset_t *,
            rocs_query_err_from_plan(n00b_result_get_err(copy_r)));
    }

    n00b_plan_ordset_t *copy  = n00b_result_get(copy_r);
    uint64_t            count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto ordinal_r = n00b_plan_ordset_at(src, i);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(
                n00b_plan_ordset_t *,
                rocs_query_err_from_plan(n00b_result_get_err(ordinal_r)));
        }
        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_QUERY_ERR_EXECUTION);
        }
        auto insert_r =
            n00b_plan_ordset_insert(copy, n00b_option_get(ordinal_opt));
        if (n00b_result_is_err(insert_r)) {
            return n00b_result_err(
                n00b_plan_ordset_t *,
                rocs_query_err_from_plan(n00b_result_get_err(insert_r)));
        }
    }

    return n00b_result_ok(n00b_plan_ordset_t *, copy);
}

static bool
rocs_query_cache_entry_matches_boundary(
    rocs_query_cache_entry_t      *entry,
    n00b_query_boundary_entry_t    boundary)
{
    return entry != nullptr
        && entry->shard_id == boundary.shard_id
        && entry->generation == boundary.generation
        && entry->schema_generation == boundary.schema_generation
        && entry->record_count == boundary.record_count
        && entry->seal_ts == boundary.seal_ts;
}

static n00b_result_t(rocs_query_cache_lookup_t)
rocs_query_cache_lookup(n00b_query_view_t            *view,
                        n00b_buffer_t               *key,
                        n00b_query_boundary_entry_t  boundary)
{
    rocs_query_cache_lookup_t out = {};
    if (view == nullptr || view->cache == nullptr || key == nullptr) {
        return n00b_result_err(rocs_query_cache_lookup_t,
                               N00B_QUERY_ERR_ARG);
    }

    view->cache->stats.lookups++;
    uint64_t len = (uint64_t)n00b_list_len(*view->cache->entries);
    for (uint64_t i = 0; i < len; i++) {
        rocs_query_cache_entry_t *entry =
            n00b_list_get(*view->cache->entries, (size_t)i);
        if (entry == nullptr || entry->shard_id != boundary.shard_id
            || !rocs_query_key_bytes_equal(entry->key, key)) {
            continue;
        }

        if (!rocs_query_cache_entry_matches_boundary(entry, boundary)) {
            view->cache->stats.stale_rejects++;
            continue;
        }
        if (entry->ordinals == nullptr) {
            view->cache->stats.stale_rejects++;
            continue;
        }

        auto records_r = n00b_plan_ordset_record_count(entry->ordinals);
        if (n00b_result_is_err(records_r)
            || n00b_result_get(records_r) != boundary.record_count) {
            view->cache->stats.stale_rejects++;
            continue;
        }

        out.ordinals = entry->ordinals;
        out.found    = true;
        view->cache->stats.hits++;
        return n00b_result_ok(rocs_query_cache_lookup_t, out);
    }

    view->cache->stats.misses++;
    return n00b_result_ok(rocs_query_cache_lookup_t, out);
}

static n00b_result_t(n00b_plan_ordset_t *)
rocs_query_cache_populate(n00b_query_view_t            *view,
                          n00b_buffer_t               *key,
                          n00b_query_boundary_entry_t  boundary,
                          n00b_plan_ordset_t          *ordinals)
{
    if (view == nullptr || view->cache == nullptr || key == nullptr
        || ordinals == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_QUERY_ERR_ARG);
    }

    auto copy_r = rocs_query_ordset_copy(ordinals,
                                         .allocator = view->allocator);
    if (n00b_result_is_err(copy_r)) {
        return copy_r;
    }

    n00b_buffer_t *key_copy = rocs_query_key_buffer_new(
        .allocator = view->allocator);
    auto key_bytes_r = rocs_query_key_append_buffer(key_copy, key);
    if (n00b_result_is_err(key_bytes_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(key_bytes_r));
    }

    rocs_query_cache_entry_t *entry = n00b_alloc_with_opts(
        rocs_query_cache_entry_t,
        &(n00b_alloc_opts_t){
            .allocator = view->allocator,
        });
    entry->key               = key_copy;
    entry->shard_id          = boundary.shard_id;
    entry->generation        = boundary.generation;
    entry->schema_generation = boundary.schema_generation;
    entry->record_count      = boundary.record_count;
    entry->seal_ts           = boundary.seal_ts;
    entry->ordinals          = n00b_result_get(copy_r);

    n00b_list_push(*view->cache->entries, entry);
    view->cache->stats.populates++;
    rocs_query_cache_evict_to_bound(view->cache, view->allocator);
    if (view->cache->stats.max_entries == 0) {
        view->cache->stats.entries =
            (uint64_t)n00b_list_len(*view->cache->entries);
    }
    return n00b_result_ok(n00b_plan_ordset_t *, entry->ordinals);
}

static n00b_result_t(n00b_string_t *)
rocs_query_copy_string(n00b_string_t *src) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (src == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_QUERY_ERR_INTERNAL);
    }

    n00b_string_t *copy = n00b_unicode_str_copy(src,
                                                .allocator = allocator);
    if (copy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_QUERY_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_string_t *, copy);
}

static n00b_store_pos_t
rocs_query_entry_first_pos(n00b_query_boundary_entry_t entry)
{
    return (n00b_store_pos_t){
        .generation = entry.generation,
        .shard_id   = entry.shard_id,
        .ordinal    = 0,
    };
}

static int32_t
rocs_query_entry_compare(n00b_query_boundary_entry_t a,
                         n00b_query_boundary_entry_t b)
{
    return n00b_store_pos_compare(rocs_query_entry_first_pos(a),
                                  rocs_query_entry_first_pos(b));
}

static int32_t
rocs_query_entry_compare_boundary(n00b_query_boundary_entry_t entry,
                                  n00b_store_pos_t            pos)
{
    n00b_store_pos_t start = rocs_query_entry_first_pos(entry);
    if (start.generation != pos.generation) {
        return start.generation < pos.generation ? -1 : 1;
    }
    if (start.shard_id != pos.shard_id) {
        return start.shard_id < pos.shard_id ? -1 : 1;
    }
    return 0;
}

static bool
rocs_query_entry_in_requested_window(n00b_query_view_t          *view,
                                     n00b_query_boundary_entry_t entry)
{
    if (view->has_resume
        && rocs_query_entry_compare_boundary(entry, view->resume) < 0) {
        return false;
    }
    if (view->has_as_of
        && rocs_query_entry_compare_boundary(entry, view->as_of) > 0) {
        return false;
    }
    return true;
}

static void
rocs_query_boundary_insert_sorted(rocs_query_boundary_list_t   *boundary,
                                  n00b_query_boundary_entry_t  entry)
{
    size_t len = n00b_list_len(*boundary);
    for (size_t i = 0; i < len; i++) {
        n00b_query_boundary_entry_t current = n00b_list_get(*boundary, i);
        if (rocs_query_entry_compare(entry, current) < 0) {
            n00b_list_insert(*boundary, i, entry);
            return;
        }
    }

    n00b_list_push(*boundary, entry);
}

static n00b_result_t(n00b_query_boundary_entry_t)
rocs_query_copy_catalog_entry(n00b_store_catalog_entry_t *entry) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto id_r      = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r     = n00b_store_catalog_entry_get_generation(entry);
    auto schema_r  = n00b_store_catalog_entry_get_schema_generation(entry);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    auto seal_r    = n00b_store_catalog_entry_get_seal_ts(entry);
    auto path_r    = n00b_store_catalog_entry_get_object_path(entry);
    auto bytes_r   = n00b_store_catalog_entry_get_byte_len(entry);
    auto part_r    = n00b_store_catalog_entry_get_partition_key(entry);
    auto etag_r    = n00b_store_catalog_entry_get_etag(entry);

    if (n00b_result_is_err(id_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(schema_r) || n00b_result_is_err(records_r)
        || n00b_result_is_err(seal_r) || n00b_result_is_err(path_r)
        || n00b_result_is_err(bytes_r) || n00b_result_is_err(part_r)
        || n00b_result_is_err(etag_r)) {
        return n00b_result_err(n00b_query_boundary_entry_t,
                               N00B_QUERY_ERR_INTERNAL);
    }

    auto path_copy_r = rocs_query_copy_string(n00b_result_get(path_r),
                                              .allocator = allocator);
    if (n00b_result_is_err(path_copy_r)) {
        return n00b_result_err(n00b_query_boundary_entry_t,
                               n00b_result_get_err(path_copy_r));
    }
    auto part_copy_r = rocs_query_copy_string(n00b_result_get(part_r),
                                              .allocator = allocator);
    if (n00b_result_is_err(part_copy_r)) {
        return n00b_result_err(n00b_query_boundary_entry_t,
                               n00b_result_get_err(part_copy_r));
    }

    n00b_option_t(n00b_string_t *) etag_copy =
        n00b_option_none(n00b_string_t *);
    n00b_option_t(n00b_string_t *) etag = n00b_result_get(etag_r);
    if (n00b_option_is_set(etag)) {
        auto copy_r = rocs_query_copy_string(n00b_option_get(etag),
                                             .allocator = allocator);
        if (n00b_result_is_err(copy_r)) {
            return n00b_result_err(n00b_query_boundary_entry_t,
                                   n00b_result_get_err(copy_r));
        }
        etag_copy = n00b_option_set(n00b_string_t *, n00b_result_get(copy_r));
    }

    return n00b_result_ok(
        n00b_query_boundary_entry_t,
        ((n00b_query_boundary_entry_t){
            .shard_id          = n00b_result_get(id_r),
            .generation        = n00b_result_get(gen_r),
            .schema_generation = n00b_result_get(schema_r),
            .record_count      = n00b_result_get(records_r),
            .seal_ts           = n00b_result_get(seal_r),
            .partition_key     = n00b_result_get(part_copy_r),
            .object_path       = n00b_result_get(path_copy_r),
            .byte_len          = n00b_result_get(bytes_r),
            .etag              = etag_copy,
        }));
}

static n00b_result_t(bool)
rocs_query_capture_boundary(n00b_query_view_t *view)
{
    auto count_r = n00b_store_catalog_visible_entry_count(view->store);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(count_r)));
    }

    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto entry_opt_r = n00b_store_catalog_visible_entry_at(view->store, i);
        if (n00b_result_is_err(entry_opt_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_store(n00b_result_get_err(entry_opt_r)));
        }

        n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
            n00b_result_get(entry_opt_r);
        if (!n00b_option_is_set(entry_opt)) {
            continue;
        }

        auto copied_r = rocs_query_copy_catalog_entry(
            n00b_option_get(entry_opt),
            .allocator = view->allocator);
        if (n00b_result_is_err(copied_r)) {
            return n00b_result_err(bool, n00b_result_get_err(copied_r));
        }

        n00b_query_boundary_entry_t copied = n00b_result_get(copied_r);
        if (rocs_query_entry_in_requested_window(view, copied)) {
            rocs_query_boundary_insert_sorted(view->boundary, copied);
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_query_retention_error_t *
rocs_query_retention_payload(n00b_query_boundary_kind_t  boundary,
                             n00b_store_pos_t            requested,
                             n00b_store_resume_check_t   check)
    _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_retention_error_t *payload = n00b_alloc_with_opts(
        n00b_query_retention_error_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    payload->code                  = N00B_QUERY_ERR_RETENTION;
    payload->boundary              = boundary;
    payload->requested             = requested;
    payload->oldest_available      = check.oldest_available;
    payload->has_oldest_available  = check.oldest_available.shard_id != 0;
    return payload;
}

static n00b_result_t(n00b_query_view_t *)
rocs_query_retention_result(n00b_query_boundary_kind_t  boundary,
                            n00b_store_pos_t            requested,
                            n00b_store_resume_check_t   check,
                            n00b_allocator_t           *allocator)
{
    n00b_query_retention_error_t *payload =
        rocs_query_retention_payload(boundary,
                                     requested,
                                     check,
                                     .allocator = allocator);
    return n00b_result_err_payload(n00b_query_view_t *,
                                   n00b_query_retention_error_t *,
                                   payload);
}

static n00b_result_t(bool)
rocs_query_release_resident(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr) {
        return n00b_result_ok(bool, true);
    }

    auto release_r = n00b_store_resident_shard_release(resident);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(release_r)));
    }
    return n00b_result_ok(bool, true);
}

static void
rocs_query_release_pin_for_failure(n00b_store_pin_t *pin)
{
    if (pin != nullptr) {
        auto release_r = n00b_store_pin_release(pin);
        if (n00b_result_is_err(release_r)) {
            return;
        }
    }
}

static n00b_result_t(bool)
rocs_query_validate_boundary_entry(n00b_query_view_t           *view,
                                   n00b_query_boundary_entry_t  boundary,
                                   n00b_allocator_t            *allocator)
{
    n00b_store_pos_t first_pos = rocs_query_entry_first_pos(boundary);

    auto find_r = n00b_store_catalog_find_shard(view->store,
                                                boundary.shard_id);
    if (n00b_result_is_err(find_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(find_r)));
    }

    n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
        n00b_result_get(find_r);
    if (!n00b_option_is_set(entry_opt)) {
        auto check_r = n00b_store_resume_check(view->store, first_pos);
        if (n00b_result_is_err(check_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_store(n00b_result_get_err(check_r)));
        }
        return n00b_result_err_payload(
            bool,
            n00b_query_retention_error_t *,
            rocs_query_retention_payload(N00B_QUERY_BOUNDARY_SNAPSHOT,
                                         first_pos,
                                         n00b_result_get(check_r),
                                         .allocator = allocator));
    }

    n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
    auto id_r      = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r     = n00b_store_catalog_entry_get_generation(entry);
    auto schema_r  = n00b_store_catalog_entry_get_schema_generation(entry);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    auto seal_r    = n00b_store_catalog_entry_get_seal_ts(entry);
    auto path_r    = n00b_store_catalog_entry_get_object_path(entry);
    auto bytes_r   = n00b_store_catalog_entry_get_byte_len(entry);
    auto part_r    = n00b_store_catalog_entry_get_partition_key(entry);
    auto etag_r    = n00b_store_catalog_entry_get_etag(entry);

    if (n00b_result_is_err(id_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(schema_r) || n00b_result_is_err(records_r)
        || n00b_result_is_err(seal_r) || n00b_result_is_err(path_r)
        || n00b_result_is_err(bytes_r) || n00b_result_is_err(part_r)
        || n00b_result_is_err(etag_r)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    if (n00b_result_get(id_r) != boundary.shard_id
        || n00b_result_get(gen_r) != boundary.generation) {
        auto check_r = n00b_store_resume_check(view->store, first_pos);
        if (n00b_result_is_err(check_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_store(n00b_result_get_err(check_r)));
        }
        return n00b_result_err_payload(
            bool,
            n00b_query_retention_error_t *,
            rocs_query_retention_payload(N00B_QUERY_BOUNDARY_SNAPSHOT,
                                         first_pos,
                                         n00b_result_get(check_r),
                                         .allocator = allocator));
    }

    if (n00b_result_get(schema_r) != boundary.schema_generation) {
        return n00b_result_err(bool, N00B_QUERY_ERR_SCHEMA);
    }

    if (n00b_result_get(records_r) != boundary.record_count
        || n00b_result_get(seal_r) != boundary.seal_ts
        || n00b_result_get(bytes_r) != boundary.byte_len
        || !n00b_unicode_str_eq(n00b_result_get(path_r), boundary.object_path)
        || !n00b_unicode_str_eq(n00b_result_get(part_r),
                                boundary.partition_key)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    n00b_option_t(n00b_string_t *) current_etag = n00b_result_get(etag_r);
    if (n00b_option_is_set(current_etag)
        != n00b_option_is_set(boundary.etag)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }
    if (n00b_option_is_set(current_etag)
        && !n00b_unicode_str_eq(n00b_option_get(current_etag),
                                n00b_option_get(boundary.etag))) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    auto verify_r = n00b_store_catalog_entry_verify_object(view->store, entry);
    if (n00b_result_is_err(verify_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(verify_r)));
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_validate_snapshot_boundary(n00b_query_view_t *view) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (view == nullptr || view->boundary == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*view->boundary);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_boundary_entry_t entry =
            n00b_list_get(*view->boundary, (size_t)i);
        auto valid_r = rocs_query_validate_boundary_entry(view,
                                                          entry,
                                                          allocator);
        if (n00b_result_is_err(valid_r)) {
            return n00b_result_err(bool, n00b_result_get_error(valid_r));
        }
    }

    return n00b_result_ok(bool, true);
}

static bool
rocs_query_position_in_window(n00b_query_view_t *view, n00b_store_pos_t pos)
{
    if (view->has_resume
        && n00b_store_pos_compare(pos, view->resume) <= 0) {
        return false;
    }
    if (view->has_as_of && n00b_store_pos_compare(pos, view->as_of) > 0) {
        return false;
    }
    return true;
}

static bool
rocs_query_boundary_matches_result(n00b_query_boundary_entry_t  boundary,
                                   n00b_plan_shard_result_t    *result)
{
    auto id_r      = n00b_plan_shard_result_shard_id(result);
    auto gen_r     = n00b_plan_shard_result_generation(result);
    auto schema_r  = n00b_plan_shard_result_schema_generation(result);
    auto records_r = n00b_plan_shard_result_record_count(result);
    auto seal_r    = n00b_plan_shard_result_seal_ts(result);

    if (n00b_result_is_err(id_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(schema_r) || n00b_result_is_err(records_r)
        || n00b_result_is_err(seal_r)) {
        return false;
    }

    return n00b_result_get(id_r) == boundary.shard_id
        && n00b_result_get(gen_r) == boundary.generation
        && n00b_result_get(schema_r) == boundary.schema_generation
        && n00b_result_get(records_r) == boundary.record_count
        && n00b_result_get(seal_r) == boundary.seal_ts;
}

static n00b_option_t(n00b_plan_shard_result_t *)
rocs_query_find_plan_result(n00b_plan_shard_result_list_t *results,
                            n00b_query_boundary_entry_t    boundary)
{
    auto count_r = n00b_plan_shard_result_count(results);
    if (n00b_result_is_err(count_r)) {
        return n00b_option_none(n00b_plan_shard_result_t *);
    }

    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto result_r = n00b_plan_shard_result_at(results, i);
        if (n00b_result_is_err(result_r)) {
            return n00b_option_none(n00b_plan_shard_result_t *);
        }
        n00b_option_t(n00b_plan_shard_result_t *) result_opt =
            n00b_result_get(result_r);
        if (!n00b_option_is_set(result_opt)) {
            continue;
        }
        n00b_plan_shard_result_t *result = n00b_option_get(result_opt);
        if (rocs_query_boundary_matches_result(boundary, result)) {
            return n00b_option_set(n00b_plan_shard_result_t *, result);
        }
    }

    return n00b_option_none(n00b_plan_shard_result_t *);
}

static n00b_result_t(n00b_store_catalog_entry_t *)
rocs_query_current_catalog_entry(n00b_query_view_t           *view,
                                 n00b_query_boundary_entry_t  boundary,
                                 n00b_allocator_t            *allocator)
{
    auto find_r = n00b_store_catalog_find_shard(view->store,
                                                boundary.shard_id);
    if (n00b_result_is_err(find_r)) {
        return n00b_result_err(
            n00b_store_catalog_entry_t *,
            rocs_query_err_from_store(n00b_result_get_err(find_r)));
    }

    n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
        n00b_result_get(find_r);
    if (!n00b_option_is_set(entry_opt)) {
        n00b_store_pos_t first_pos = rocs_query_entry_first_pos(boundary);
        auto check_r = n00b_store_resume_check(view->store, first_pos);
        if (n00b_result_is_err(check_r)) {
            return n00b_result_err(
                n00b_store_catalog_entry_t *,
                rocs_query_err_from_store(n00b_result_get_err(check_r)));
        }
        return n00b_result_err_payload(
            n00b_store_catalog_entry_t *,
            n00b_query_retention_error_t *,
            rocs_query_retention_payload(N00B_QUERY_BOUNDARY_SNAPSHOT,
                                         first_pos,
                                         n00b_result_get(check_r),
                                         .allocator = allocator));
    }

    return n00b_result_ok(n00b_store_catalog_entry_t *,
                          n00b_option_get(entry_opt));
}

static n00b_result_t(bool)
rocs_query_validate_mapped_boundary(n00b_store_map_shard_t      *root,
                                    n00b_query_boundary_entry_t  boundary)
{
    auto state_r   = n00b_store_map_shard_state(root);
    auto id_r      = n00b_store_map_shard_id(root);
    auto records_r = n00b_store_map_shard_records_len(root);
    auto seal_r    = n00b_store_map_shard_seal_ts(root);

    if (n00b_result_is_err(state_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_map(n00b_result_get_err(state_r)));
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(bool, N00B_QUERY_ERR_EXECUTION);
    }
    if (n00b_result_is_err(id_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_map(n00b_result_get_err(id_r)));
    }
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_map(n00b_result_get_err(records_r)));
    }
    if (n00b_result_is_err(seal_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_map(n00b_result_get_err(seal_r)));
    }

    if (n00b_result_get(id_r) != boundary.shard_id
        || n00b_result_get(records_r) != boundary.record_count
        || n00b_result_get(seal_r) != boundary.seal_ts) {
        return n00b_result_err(bool, N00B_QUERY_ERR_EXECUTION);
    }

    return n00b_result_ok(bool, true);
}

static n00b_query_hit_t *
rocs_query_hit_new(n00b_query_cursor_t *cursor,
                   n00b_store_pos_t     pos,
                   n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_hit_t *hit = n00b_alloc_with_opts(
        n00b_query_hit_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    hit->cursor = cursor;
    hit->pos    = pos;
    hit->record = record;
    hit->score  = 0.0;
    hit->valid  = false;
    return hit;
}

static void
rocs_query_cursor_invalidate_current(n00b_query_cursor_t *cursor)
{
    if (cursor != nullptr && cursor->current_hit != nullptr) {
        cursor->current_hit->valid = false;
        cursor->current_hit        = nullptr;
    }
}

static void
rocs_query_cursor_invalidate_all(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->hits == nullptr) {
        return;
    }

    uint64_t len = (uint64_t)n00b_list_len(*cursor->hits);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_hit_t *hit = n00b_list_get(*cursor->hits, (size_t)i);
        if (hit != nullptr) {
            hit->valid = false;
        }
    }
    cursor->current_hit = nullptr;
}

static n00b_result_t(bool)
rocs_query_cursor_release_residents(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->residents == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_err_t err = N00B_QUERY_OK;
    uint64_t   len = (uint64_t)n00b_list_len(*cursor->residents);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_resident_shard_t *resident =
            n00b_list_get(*cursor->residents, (size_t)i);
        if (resident == nullptr) {
            continue;
        }

        auto release_r = rocs_query_release_resident(resident);
        if (n00b_result_is_err(release_r) && err == N00B_QUERY_OK) {
            err = n00b_result_get_err(release_r);
        }
        n00b_list_set(*cursor->residents,
                      (size_t)i,
                      (n00b_store_resident_shard_t *)nullptr);
    }

    if (err != N00B_QUERY_OK) {
        return n00b_result_err(bool, err);
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_cursor_close_internal(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (cursor->closed) {
        return n00b_result_ok(bool, false);
    }

    cursor->closed = true;
    rocs_query_cursor_invalidate_all(cursor);

    auto release_r = rocs_query_cursor_release_residents(cursor);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(bool, n00b_result_get_err(release_r));
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_cursor_add_boundary_ordset(n00b_query_cursor_t        *cursor,
                                      n00b_query_boundary_entry_t boundary,
                                      n00b_plan_ordset_t         *ordinals)
{
    if (ordinals == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto count_r = n00b_plan_ordset_count(ordinals);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_plan(n00b_result_get_err(count_r)));
    }

    uint64_t                       count    = n00b_result_get(count_r);
    n00b_store_resident_shard_t   *resident = nullptr;
    n00b_store_map_shard_t        *root     = nullptr;

    for (uint64_t i = 0; i < count; i++) {
        auto ordinal_r = n00b_plan_ordset_at(ordinals, i);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_plan(n00b_result_get_err(ordinal_r)));
        }
        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            return n00b_result_err(bool, N00B_QUERY_ERR_EXECUTION);
        }

        n00b_store_pos_t pos = {
            .generation = boundary.generation,
            .shard_id   = boundary.shard_id,
            .ordinal    = n00b_option_get(ordinal_opt),
        };
        if (!rocs_query_position_in_window(cursor->view, pos)) {
            continue;
        }

        if (cursor->view->limit != 0
            && (uint64_t)n00b_list_len(*cursor->hits) >= cursor->view->limit) {
            return n00b_result_ok(bool, false);
        }

        if (resident == nullptr) {
            auto entry_r = rocs_query_current_catalog_entry(cursor->view,
                                                           boundary,
                                                           cursor->allocator);
            if (n00b_result_is_err(entry_r)) {
                return n00b_result_err(bool, n00b_result_get_error(entry_r));
            }

            auto resident_r = n00b_store_resident_shard_acquire(
                cursor->view->store,
                n00b_result_get(entry_r),
                .allocator = cursor->allocator);
            if (n00b_result_is_err(resident_r)) {
                return n00b_result_err(
                    bool,
                    rocs_query_err_from_store(
                        n00b_result_get_err(resident_r)));
            }
            resident = n00b_result_get(resident_r);
            n00b_list_push(*cursor->residents, resident);

            auto map_r = n00b_store_resident_shard_map(resident);
            if (n00b_result_is_err(map_r)) {
                return n00b_result_err(
                    bool,
                    rocs_query_err_from_store(n00b_result_get_err(map_r)));
            }

            auto root_r = n00b_store_map_root(n00b_result_get(map_r));
            if (n00b_result_is_err(root_r)) {
                return n00b_result_err(
                    bool,
                    rocs_query_err_from_map(n00b_result_get_err(root_r)));
            }
            root = n00b_result_get(root_r);

            auto valid_r = rocs_query_validate_mapped_boundary(root,
                                                               boundary);
            if (n00b_result_is_err(valid_r)) {
                return n00b_result_err(bool, n00b_result_get_err(valid_r));
            }
        }

        auto record_r = n00b_store_record_view_mapped_pos(
            root,
            pos,
            .allocator = cursor->allocator);
        if (n00b_result_is_err(record_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_index(n00b_result_get_err(record_r)));
        }

        n00b_query_hit_t *hit =
            rocs_query_hit_new(cursor,
                               pos,
                               n00b_result_get(record_r),
                               .allocator = cursor->allocator);
        n00b_list_push(*cursor->hits, hit);
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_cursor_add_boundary_result(n00b_query_cursor_t        *cursor,
                                      n00b_query_boundary_entry_t boundary,
                                      n00b_plan_shard_result_t   *result)
{
    auto ordinals_r = n00b_plan_shard_result_ordinals(result);
    if (n00b_result_is_err(ordinals_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_plan(n00b_result_get_err(ordinals_r)));
    }
    return rocs_query_cursor_add_boundary_ordset(cursor,
                                                boundary,
                                                n00b_result_get(ordinals_r));
}

static n00b_result_t(bool)
rocs_query_cursor_build_hits(n00b_query_cursor_t *cursor)
{
    auto valid_r = rocs_query_validate_snapshot_boundary(
        cursor->view,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(bool, n00b_result_get_error(valid_r));
    }

    uint64_t boundary_len = (uint64_t)n00b_list_len(*cursor->view->boundary);
    if (boundary_len == 0) {
        return n00b_result_ok(bool, true);
    }

    auto key_r = rocs_query_cache_key_build(
        cursor->view->filter,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }
    rocs_query_cache_key_t key = n00b_result_get(key_r);
    bool use_cache = key.cacheable
        && key.bytes != nullptr
        && cursor->view->cache != nullptr
        && !cursor->view->cache->disabled;

    rocs_query_ordset_ref_list_t *cached_refs = nullptr;
    bool                         need_plan   = true;
    if (use_cache) {
        need_plan   = false;
        cached_refs = rocs_query_ordset_ref_list_new(
            .allocator = cursor->allocator);

        for (uint64_t i = 0; i < boundary_len; i++) {
            n00b_query_boundary_entry_t boundary =
                n00b_list_get(*cursor->view->boundary, (size_t)i);
            auto lookup_r = rocs_query_cache_lookup(cursor->view,
                                                    key.bytes,
                                                    boundary);
            if (n00b_result_is_err(lookup_r)) {
                return n00b_result_err(bool, n00b_result_get_err(lookup_r));
            }
            rocs_query_cache_lookup_t lookup = n00b_result_get(lookup_r);
            n00b_list_push(*cached_refs, lookup.ordinals);
            if (!lookup.found) {
                need_plan = true;
            }
        }

        if (!need_plan) {
            for (uint64_t i = 0; i < boundary_len; i++) {
                n00b_query_boundary_entry_t boundary =
                    n00b_list_get(*cursor->view->boundary, (size_t)i);
                n00b_plan_ordset_t *ordinals =
                    n00b_list_get(*cached_refs, (size_t)i);
                auto add_r = rocs_query_cursor_add_boundary_ordset(
                    cursor,
                    boundary,
                    ordinals);
                if (n00b_result_is_err(add_r)) {
                    return n00b_result_err(bool,
                                           n00b_result_get_error(add_r));
                }
                if (!n00b_result_get(add_r)) {
                    break;
                }
            }
            return n00b_result_ok(bool, true);
        }
    }
    else if (cursor->view->cache != nullptr) {
        cursor->view->cache->stats.bypasses++;
    }

    auto lowered_r = n00b_filter_lower_to_plan(
        cursor->view->filter,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(lowered_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(lowered_r)));
    }

    auto plan_r = n00b_plan_store_sealed(cursor->view->store,
                                         n00b_result_get(lowered_r),
                                         nullptr,
                                         .allocator = cursor->allocator);
    if (n00b_result_is_err(plan_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_plan(n00b_result_get_err(plan_r)));
    }

    n00b_plan_shard_result_list_t *results = n00b_result_get(plan_r);
    for (uint64_t i = 0; i < boundary_len; i++) {
        n00b_query_boundary_entry_t boundary =
            n00b_list_get(*cursor->view->boundary, (size_t)i);

        n00b_plan_ordset_t *ordinals = nullptr;
        if (use_cache && cached_refs != nullptr) {
            ordinals = n00b_list_get(*cached_refs, (size_t)i);
        }

        if (ordinals == nullptr) {
            n00b_option_t(n00b_plan_shard_result_t *) result_opt =
                rocs_query_find_plan_result(results, boundary);
            n00b_plan_ordset_t *source = nullptr;
            if (n00b_option_is_set(result_opt)) {
                auto ordinals_r =
                    n00b_plan_shard_result_ordinals(
                        n00b_option_get(result_opt));
                if (n00b_result_is_err(ordinals_r)) {
                    return n00b_result_err(
                        bool,
                        rocs_query_err_from_plan(
                            n00b_result_get_err(ordinals_r)));
                }
                source = n00b_result_get(ordinals_r);
            }
            else {
                auto empty_r =
                    n00b_plan_ordset_empty(boundary.record_count,
                                           .allocator = cursor->allocator);
                if (n00b_result_is_err(empty_r)) {
                    return n00b_result_err(
                        bool,
                        rocs_query_err_from_plan(
                            n00b_result_get_err(empty_r)));
                }
                source = n00b_result_get(empty_r);
            }

            if (use_cache) {
                auto populate_r = rocs_query_cache_populate(cursor->view,
                                                            key.bytes,
                                                            boundary,
                                                            source);
                if (n00b_result_is_err(populate_r)) {
                    return n00b_result_err(bool,
                                           n00b_result_get_err(populate_r));
                }
                ordinals = n00b_result_get(populate_r);
            }
            else {
                ordinals = source;
            }
        }

        auto add_r = rocs_query_cursor_add_boundary_ordset(cursor,
                                                          boundary,
                                                          ordinals);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(bool, n00b_result_get_error(add_r));
        }
        if (!n00b_result_get(add_r)) {
            break;
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_validate_boundary(n00b_store_t               *store,
                             n00b_query_boundary_kind_t  boundary,
                             n00b_store_pos_t            pos,
                             n00b_store_resume_check_t  *check_out)
{
    auto check_r = n00b_store_resume_check(store, pos);
    if (n00b_result_is_err(check_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(check_r)));
    }

    n00b_store_resume_check_t check = n00b_result_get(check_r);
    *check_out = check;
    if (!check.available) {
        return n00b_result_ok(bool, false);
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_query_view_t *)
n00b_query_view(n00b_store_t  *store,
                n00b_filter_t *filter) _kargs
{
    n00b_query_mode_t  mode      = N00B_QUERY_MODE_SNAPSHOT;
    n00b_store_pos_t  *resume    = nullptr;
    n00b_store_pos_t  *as_of     = nullptr;
    n00b_conduit_t    *out       = nullptr;
    uint64_t           limit     = 0;
    n00b_allocator_t  *allocator = nullptr;
}
{
    if (store == nullptr || filter == nullptr) {
        return n00b_result_err(n00b_query_view_t *, N00B_QUERY_ERR_ARG);
    }
    if (mode != N00B_QUERY_MODE_SNAPSHOT
        && mode != N00B_QUERY_MODE_LIVE) {
        return n00b_result_err(n00b_query_view_t *, N00B_QUERY_ERR_ARG);
    }
    if (out != nullptr || mode == N00B_QUERY_MODE_LIVE) {
        return n00b_result_err(n00b_query_view_t *,
                               N00B_QUERY_ERR_UNSUPPORTED_MODE);
    }

    auto pin_r = n00b_store_pin_acquire(store, .allocator = allocator);
    if (n00b_result_is_err(pin_r)) {
        return n00b_result_err(
            n00b_query_view_t *,
            rocs_query_err_from_store(n00b_result_get_err(pin_r)));
    }
    n00b_store_pin_t *pin = n00b_result_get(pin_r);

    n00b_query_view_t *view = n00b_alloc_with_opts(
        n00b_query_view_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    view->store     = store;
    view->filter    = filter;
    view->pin       = pin;
    view->allocator = allocator;
    view->mode      = mode;
    view->limit     = limit;
    view->closed    = false;
    view->boundary  = rocs_query_boundary_list_new(.allocator = allocator);
    view->cursors   = rocs_query_cursor_list_new(.allocator = allocator);
    view->cache     = rocs_query_cache_new(.allocator = allocator);

    if (resume != nullptr) {
        n00b_store_resume_check_t check = {};
        auto valid_r = rocs_query_validate_boundary(store,
                                                    N00B_QUERY_BOUNDARY_RESUME,
                                                    *resume,
                                                    &check);
        if (n00b_result_is_err(valid_r)) {
            rocs_query_release_pin_for_failure(pin);
            return n00b_result_err(n00b_query_view_t *,
                                   n00b_result_get_err(valid_r));
        }
        if (!n00b_result_get(valid_r)) {
            rocs_query_release_pin_for_failure(pin);
            return rocs_query_retention_result(N00B_QUERY_BOUNDARY_RESUME,
                                               *resume,
                                               check,
                                               allocator);
        }
        view->has_resume = true;
        view->resume     = *resume;
    }

    if (as_of != nullptr) {
        n00b_store_resume_check_t check = {};
        auto valid_r = rocs_query_validate_boundary(store,
                                                    N00B_QUERY_BOUNDARY_AS_OF,
                                                    *as_of,
                                                    &check);
        if (n00b_result_is_err(valid_r)) {
            rocs_query_release_pin_for_failure(pin);
            return n00b_result_err(n00b_query_view_t *,
                                   n00b_result_get_err(valid_r));
        }
        if (!n00b_result_get(valid_r)) {
            rocs_query_release_pin_for_failure(pin);
            return rocs_query_retention_result(N00B_QUERY_BOUNDARY_AS_OF,
                                               *as_of,
                                               check,
                                               allocator);
        }
        view->has_as_of = true;
        view->as_of     = *as_of;
    }

    if (view->has_resume && view->has_as_of
        && n00b_store_pos_compare(view->resume, view->as_of) > 0) {
        return n00b_result_ok(n00b_query_view_t *, view);
    }

    auto capture_r = rocs_query_capture_boundary(view);
    if (n00b_result_is_err(capture_r)) {
        rocs_query_release_pin_for_failure(pin);
        return n00b_result_err(n00b_query_view_t *,
                               n00b_result_get_err(capture_r));
    }

    return n00b_result_ok(n00b_query_view_t *, view);
}

n00b_result_t(bool)
n00b_query_view_close(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (view->closed) {
        return n00b_result_ok(bool, false);
    }

    view->closed = true;
    n00b_err_t err = N00B_QUERY_OK;
    if (view->cursors != nullptr) {
        uint64_t len = (uint64_t)n00b_list_len(*view->cursors);
        for (uint64_t i = 0; i < len; i++) {
            n00b_query_cursor_t *cursor =
                n00b_list_get(*view->cursors, (size_t)i);
            if (cursor == nullptr || cursor->closed) {
                continue;
            }
            auto close_r = rocs_query_cursor_close_internal(cursor);
            if (n00b_result_is_err(close_r) && err == N00B_QUERY_OK) {
                err = n00b_result_get_err(close_r);
            }
        }
    }

    if (view->pin != nullptr) {
        auto release_r = n00b_store_pin_release(view->pin);
        if (n00b_result_is_err(release_r) && err == N00B_QUERY_OK) {
            err = rocs_query_err_from_store(n00b_result_get_err(release_r));
        }
        view->pin = nullptr;
    }

    if (err != N00B_QUERY_OK) {
        return n00b_result_err(bool, err);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_query_cursor_t *)
n00b_query_cursor(n00b_query_view_t *view) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (view == nullptr) {
        return n00b_result_err(n00b_query_cursor_t *, N00B_QUERY_ERR_ARG);
    }
    if (view->closed) {
        return n00b_result_err(n00b_query_cursor_t *, N00B_QUERY_ERR_CLOSED);
    }
    if (view->mode != N00B_QUERY_MODE_SNAPSHOT) {
        return n00b_result_err(n00b_query_cursor_t *,
                               N00B_QUERY_ERR_UNSUPPORTED_MODE);
    }

    n00b_query_cursor_t *cursor = n00b_alloc_with_opts(
        n00b_query_cursor_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    cursor->view        = view;
    cursor->hits        = rocs_query_hit_list_new(.allocator = allocator);
    cursor->residents   = rocs_query_resident_list_new(.allocator = allocator);
    cursor->allocator   = allocator;
    cursor->next_index  = 0;
    cursor->closed      = false;
    cursor->has_position = false;

    auto build_r = rocs_query_cursor_build_hits(cursor);
    if (n00b_result_is_err(build_r)) {
        auto close_r = rocs_query_cursor_close_internal(cursor);
        if (n00b_result_is_err(close_r)) {
            return n00b_result_err(n00b_query_cursor_t *,
                                   n00b_result_get_err(close_r));
        }
        return n00b_result_err(n00b_query_cursor_t *,
                               n00b_result_get_error(build_r));
    }

    n00b_list_push(*view->cursors, cursor);
    return n00b_result_ok(n00b_query_cursor_t *, cursor);
}

n00b_result_t(n00b_option_t(n00b_query_hit_t *))
n00b_query_cursor_next(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                               N00B_QUERY_ERR_ARG);
    }
    if (cursor->closed || cursor->view == nullptr || cursor->view->closed) {
        return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                               N00B_QUERY_ERR_CLOSED);
    }

    rocs_query_cursor_invalidate_current(cursor);

    uint64_t len = (uint64_t)n00b_list_len(*cursor->hits);
    if (cursor->next_index >= len || cursor->next_index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                              n00b_option_none(n00b_query_hit_t *));
    }

    n00b_query_hit_t *hit =
        n00b_list_get(*cursor->hits, (size_t)cursor->next_index);
    if (hit == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                               N00B_QUERY_ERR_INTERNAL);
    }

    cursor->next_index++;
    cursor->current_hit  = hit;
    cursor->has_position = true;
    cursor->position     = hit->pos;
    hit->valid           = true;

    return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                          n00b_option_set(n00b_query_hit_t *, hit));
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_cursor_position(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    if (cursor->closed || cursor->view == nullptr || cursor->view->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_CLOSED);
    }
    if (!cursor->has_position) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                          n00b_option_set(n00b_store_pos_t,
                                          cursor->position));
}

n00b_result_t(bool)
n00b_query_cursor_close(n00b_query_cursor_t *cursor)
{
    return rocs_query_cursor_close_internal(cursor);
}

static n00b_result_t(bool)
rocs_query_hit_check(n00b_query_hit_t *hit)
{
    if (hit == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (!hit->valid || hit->cursor == nullptr || hit->cursor->closed
        || hit->cursor->view == nullptr || hit->cursor->view->closed) {
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_pos_t)
n00b_query_hit_pos(n00b_query_hit_t *hit)
{
    auto valid_r = rocs_query_hit_check(hit);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_store_pos_t,
                               n00b_result_get_err(valid_r));
    }
    return n00b_result_ok(n00b_store_pos_t, hit->pos);
}

n00b_result_t(double)
n00b_query_hit_score(n00b_query_hit_t *hit)
{
    auto valid_r = rocs_query_hit_check(hit);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(double, n00b_result_get_err(valid_r));
    }
    return n00b_result_ok(double, hit->score);
}

n00b_result_t(n00b_store_record_t *)
n00b_query_hit_record(n00b_query_hit_t *hit)
{
    auto valid_r = rocs_query_hit_check(hit);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               n00b_result_get_err(valid_r));
    }
    if (hit->record == nullptr) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_QUERY_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_store_record_t *, hit->record);
}

n00b_result_t(n00b_query_err_t)
n00b_query_retention_error_code(n00b_query_retention_error_t *error)
{
    if (error == nullptr) {
        return n00b_result_err(n00b_query_err_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(n00b_query_err_t, error->code);
}

n00b_result_t(n00b_query_boundary_kind_t)
n00b_query_retention_error_boundary(n00b_query_retention_error_t *error)
{
    if (error == nullptr) {
        return n00b_result_err(n00b_query_boundary_kind_t,
                               N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(n00b_query_boundary_kind_t, error->boundary);
}

n00b_result_t(n00b_store_pos_t)
n00b_query_retention_error_requested(n00b_query_retention_error_t *error)
{
    if (error == nullptr) {
        return n00b_result_err(n00b_store_pos_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_pos_t, error->requested);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_retention_error_oldest_available(
    n00b_query_retention_error_t *error)
{
    if (error == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    n00b_option_t(n00b_store_pos_t) result =
        error->has_oldest_available
            ? n00b_option_set(n00b_store_pos_t, error->oldest_available)
            : n00b_option_none(n00b_store_pos_t);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(uint64_t)
n00b_query_view_boundary_count(n00b_query_view_t *view)
{
    if (view == nullptr || view->boundary == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*view->boundary));
}

n00b_result_t(n00b_option_t(n00b_query_boundary_entry_t))
n00b_query_view_boundary_entry_at(n00b_query_view_t *view, uint64_t index)
{
    if (view == nullptr || view->boundary == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_query_boundary_entry_t),
                               N00B_QUERY_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*view->boundary);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_query_boundary_entry_t),
                              n00b_option_none(n00b_query_boundary_entry_t));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_query_boundary_entry_t),
        n00b_option_set(n00b_query_boundary_entry_t,
                        n00b_list_get(*view->boundary, (size_t)index)));
}

n00b_result_t(n00b_query_mode_t)
n00b_query_view_mode(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_query_mode_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(n00b_query_mode_t, view->mode);
}

n00b_result_t(uint64_t)
n00b_query_view_limit(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, view->limit);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_resume(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    n00b_option_t(n00b_store_pos_t) result =
        view->has_resume
            ? n00b_option_set(n00b_store_pos_t, view->resume)
            : n00b_option_none(n00b_store_pos_t);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_as_of(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    n00b_option_t(n00b_store_pos_t) result =
        view->has_as_of
            ? n00b_option_set(n00b_store_pos_t, view->as_of)
            : n00b_option_none(n00b_store_pos_t);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_snapshot_upper_bound(n00b_query_view_t *view)
{
    if (view == nullptr || view->boundary == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*view->boundary);
    if (len == 0) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    for (uint64_t i = len; i > 0; i--) {
        n00b_query_boundary_entry_t entry =
            n00b_list_get(*view->boundary, (size_t)(i - 1));
        if (entry.record_count == 0) {
            continue;
        }

        n00b_store_pos_t upper = {
            .generation = entry.generation,
            .shard_id   = entry.shard_id,
            .ordinal    = entry.record_count - 1,
        };
        if (view->has_as_of
            && n00b_store_pos_compare(view->as_of, upper) < 0) {
            upper = view->as_of;
        }

        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_set(n00b_store_pos_t, upper));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                          n00b_option_none(n00b_store_pos_t));
}

n00b_result_t(bool)
n00b_query_view_is_closed(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(bool, view->closed);
}

n00b_result_t(uint64_t)
n00b_query_cursor_hit_count(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->hits == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    if (cursor->closed || cursor->view == nullptr || cursor->view->closed) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_CLOSED);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*cursor->hits));
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_cursor_hit_position_at(n00b_query_cursor_t *cursor,
                                  uint64_t             index)
{
    if (cursor == nullptr || cursor->hits == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    if (cursor->closed || cursor->view == nullptr || cursor->view->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_CLOSED);
    }

    uint64_t len = (uint64_t)n00b_list_len(*cursor->hits);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    n00b_query_hit_t *hit = n00b_list_get(*cursor->hits, (size_t)index);
    if (hit == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                          n00b_option_set(n00b_store_pos_t, hit->pos));
}

n00b_result_t(n00b_query_cache_stats_t)
n00b_query_cache_stats(n00b_query_view_t *view)
{
    if (view == nullptr || view->cache == nullptr) {
        return n00b_result_err(n00b_query_cache_stats_t,
                               N00B_QUERY_ERR_ARG);
    }

    n00b_query_cache_stats_t stats = view->cache->stats;
    stats.disabled = view->cache->disabled;
    stats.entries  = view->cache->entries == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*view->cache->entries);
    return n00b_result_ok(n00b_query_cache_stats_t, stats);
}

n00b_result_t(bool)
n00b_query_cache_clear(n00b_query_view_t *view)
{
    if (view == nullptr || view->cache == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    view->cache->entries = rocs_query_cache_entry_list_new(
        .allocator = view->allocator);
    view->cache->stats.clears++;
    view->cache->stats.entries = 0;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_query_cache_set_disabled(n00b_query_view_t *view, bool disabled)
{
    if (view == nullptr || view->cache == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    view->cache->disabled = disabled;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_query_cache_set_max_entries(n00b_query_view_t *view,
                                 uint64_t           max_entries)
{
    if (view == nullptr || view->cache == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    view->cache->stats.max_entries = max_entries;
    rocs_query_cache_evict_to_bound(view->cache, view->allocator);
    if (max_entries == 0 && view->cache->entries != nullptr) {
        view->cache->stats.entries =
            (uint64_t)n00b_list_len(*view->cache->entries);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_query_cache_test_corrupt_first_metadata(n00b_query_view_t *view)
{
    if (view == nullptr || view->cache == nullptr
        || view->cache->entries == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    if (n00b_list_len(*view->cache->entries) == 0) {
        return n00b_result_ok(bool, false);
    }

    rocs_query_cache_entry_t *entry =
        n00b_list_get(*view->cache->entries, 0);
    if (entry == nullptr) {
        return n00b_result_ok(bool, false);
    }

    entry->schema_generation++;
    return n00b_result_ok(bool, true);
}
