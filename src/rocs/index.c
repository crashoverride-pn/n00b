#include "rocs/index.h"

#include "adt/list.h"
#include "core/hash.h"
#include "internal/rocs/index.h"
#include "internal/rocs/map.h"
#include "rocs/map.h"
#include "rocs/normalizer.h"
#include "text/strings/string_ops.h"

typedef n00b_list_t(n00b_store_record_t *) rocs_record_view_list_t;
typedef n00b_list_t(uint64_t) rocs_vaddr_list_t;

struct n00b_store_index_t {
    n00b_string_t           *field;
    n00b_store_index_kind_t  kind;
};

struct n00b_store_record_t {
    n00b_store_pos_t          pos;
    n00b_store_shard_t       *hot_shard;
    n00b_store_map_shard_t   *mapped_shard;
    n00b_json_node_t         *owned_json;
};

struct n00b_store_postings_t {
    rocs_record_view_list_t *records;
    uint64_t                 shard_id;
    uint64_t                 generation;
};

static bool
rocs_index_kind_known(n00b_store_index_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_INDEX_TERM:
    case N00B_STORE_INDEX_FULLTEXT:
    case N00B_STORE_INDEX_NGRAM:
    case N00B_STORE_INDEX_NUMERIC:
    case N00B_STORE_INDEX_BOOL:
    case N00B_STORE_INDEX_VECTOR:
        return true;
    case N00B_STORE_INDEX_NONE:
        return false;
    }
    return false;
}

static rocs_record_view_list_t *
rocs_record_view_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_record_view_list_t *records = n00b_alloc_with_opts(
        rocs_record_view_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *records = n00b_list_new_private(n00b_store_record_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return records;
}

static rocs_vaddr_list_t *
rocs_vaddr_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_vaddr_list_t *items = n00b_alloc_with_opts(
        rocs_vaddr_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *items = n00b_list_new_private(uint64_t,
                                   .allocator = allocator,
                                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return items;
}

static n00b_store_postings_t *
rocs_postings_new(uint64_t          shard_id,
                  uint64_t          generation) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_postings_t *postings = n00b_alloc_with_opts(
        n00b_store_postings_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    postings->records    = rocs_record_view_list_new(.allocator = allocator);
    postings->shard_id   = shard_id;
    postings->generation = generation;
    return postings;
}

static n00b_store_record_t *
_rocs_record_view_new(n00b_store_pos_t        pos,
                      n00b_store_shard_t     *hot_shard,
                      n00b_store_map_shard_t *mapped_shard) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_record_t *view = n00b_alloc_with_opts(
        n00b_store_record_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    view->pos          = pos;
    view->hot_shard    = hot_shard;
    view->mapped_shard = mapped_shard;
    view->owned_json   = nullptr;
    return view;
}

static n00b_result_t(n00b_json_node_t *)
rocs_json_node_copy(n00b_json_node_t *node,
                    n00b_allocator_t *allocator);

static n00b_result_t(n00b_json_node_t *)
rocs_json_array_copy(n00b_json_node_t *node,
                     n00b_allocator_t *allocator)
{
    n00b_json_node_t *copy = n00b_json_array_new(.allocator = allocator);
    size_t            len  = n00b_json_array_len(node);

    for (size_t i = 0; i < len; i++) {
        n00b_json_node_t *child = n00b_json_array_get(node, i);
        if (child == nullptr) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        auto child_r = rocs_json_node_copy(child, allocator);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        n00b_json_array_push(copy, n00b_result_get(child_r));
    }

    return n00b_result_ok(n00b_json_node_t *, copy);
}

static n00b_result_t(n00b_json_node_t *)
rocs_json_object_copy(n00b_json_node_t *node,
                      n00b_allocator_t *allocator)
{
    auto entries_r = n00b_json_object_entries(node,
                                              .allocator = allocator);
    if (n00b_result_is_err(entries_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_json_node_t              *copy    =
        n00b_json_object_new(.allocator = allocator);
    n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
    size_t                        len     = n00b_list_len(*entries);

    for (size_t i = 0; i < len; i++) {
        n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
        if (entry == nullptr || entry->key == nullptr
            || entry->value == nullptr) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        n00b_string_t *key =
            n00b_unicode_str_copy(entry->key, .allocator = allocator);
        if (key == nullptr) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_INTERNAL);
        }

        auto value_r = rocs_json_node_copy(entry->value, allocator);
        if (n00b_result_is_err(value_r)) {
            return value_r;
        }

        n00b_json_object_put_n00b(copy, key, n00b_result_get(value_r));
    }

    return n00b_result_ok(n00b_json_node_t *, copy);
}

static n00b_result_t(n00b_json_node_t *)
rocs_json_node_copy(n00b_json_node_t *node,
                    n00b_allocator_t *allocator)
{
    if (node == nullptr) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    switch (n00b_json_type(node)) {
    case N00B_JSON_NULL:
        return n00b_result_ok(
            n00b_json_node_t *,
            n00b_json_null_new(.allocator = allocator));
    case N00B_JSON_BOOL:
        return n00b_result_ok(
            n00b_json_node_t *,
            n00b_json_bool_new(n00b_json_as_bool(node),
                               .allocator = allocator));
    case N00B_JSON_INT:
        return n00b_result_ok(
            n00b_json_node_t *,
            n00b_json_int_new(n00b_json_as_i64(node),
                              .allocator = allocator));
    case N00B_JSON_DOUBLE:
        return n00b_result_ok(
            n00b_json_node_t *,
            n00b_json_double_new(n00b_json_as_f64(node),
                                 .allocator = allocator));
    case N00B_JSON_STRING:
        return n00b_result_ok(
            n00b_json_node_t *,
            n00b_json_string_new_from_n00b(n00b_json_as_string(node),
                                           .allocator = allocator));
    case N00B_JSON_ARRAY:
        return rocs_json_array_copy(node, allocator);
    case N00B_JSON_OBJECT:
        return rocs_json_object_copy(node, allocator);
    }

    return n00b_result_err(n00b_json_node_t *,
                           N00B_STORE_INDEX_ERR_STATE);
}

static n00b_result_t(n00b_store_postings_t *)
rocs_empty_postings(uint64_t shard_id, uint64_t generation) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_result_ok(n00b_store_postings_t *,
                          rocs_postings_new(shard_id,
                                            generation,
                                            .allocator = allocator));
}

static n00b_err_t
rocs_index_norm_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_NORM_ERR_ARG:     return N00B_STORE_INDEX_ERR_ARG;
    case N00B_STORE_NORM_ERR_TYPE:    return N00B_STORE_INDEX_ERR_ARG;
    case N00B_STORE_NORM_ERR_NUMERIC: return N00B_STORE_INDEX_ERR_ARG;
    case N00B_STORE_NORM_ERR_STATE:   return N00B_STORE_INDEX_ERR_STATE;
    default:                          return N00B_STORE_INDEX_ERR_INTERNAL;
    }
}

static n00b_err_t
rocs_index_map_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_MAP_ERR_ARG: return N00B_STORE_INDEX_ERR_ARG;
    default:                    return N00B_STORE_INDEX_ERR_STATE;
    }
}

static n00b_err_t
rocs_index_term_ready(n00b_store_index_t *index)
{
    if (index == nullptr || index->field == nullptr) {
        return N00B_STORE_INDEX_ERR_ARG;
    }
    if (index->kind != N00B_STORE_INDEX_TERM) {
        return N00B_STORE_INDEX_ERR_UNREADY;
    }
    return N00B_STORE_INDEX_OK;
}

static n00b_store_posting_list_t *
rocs_posting_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_posting_list_t *records = n00b_alloc_with_opts(
        n00b_store_posting_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *records = n00b_list_new_private(n00b_json_node_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return records;
}

static n00b_store_column_t *
rocs_column_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_column_t *column = n00b_alloc_with_opts(
        n00b_store_column_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    /*
     * Column keys are normalized 128-bit term hashes stored by value. The
     * typed dict's raw-key mode hashes those 16 key bytes for its bucket hv.
     */
    n00b_dict_init(column,
                   .allocator       = allocator,
                   .skip_obj_hash   = true,
                   .locked          = false,
                   .key_scan_kind   = N00B_GC_SCAN_KIND_NONE,
                   .value_scan_kind = N00B_GC_SCAN_KIND_ALL);
    return column;
}

static n00b_result_t(n00b_store_column_t *)
rocs_column_get_or_create(n00b_store_shard_t *shard, n00b_string_t *field)
{
    if (shard == nullptr || shard->columns == nullptr || field == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    bool found = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns, field, &found);
    if (found) {
        if (column == nullptr) {
            return n00b_result_err(n00b_store_column_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }
        return n00b_result_ok(n00b_store_column_t *, column);
    }

    n00b_allocator_t *allocator = shard->columns->allocator;
    column = rocs_column_new(.allocator = allocator);

    /*
     * Store a heap string inside the shard graph, even when the descriptor
     * field is a static r-string. Mapped readers can resolve heap string
     * vaddrs in the sealed image; static pointer patch slots are not shard
     * vaddrs and must not become mapped column keys.
     */
    n00b_string_t *stored_field =
        n00b_string_from_raw(field->data,
                             (int64_t)field->u8_bytes,
                             .allocator = allocator);
    n00b_dict_put(shard->columns, stored_field, column);
    return n00b_result_ok(n00b_store_column_t *, column);
}

static n00b_result_t(n00b_store_posting_list_t *)
rocs_column_postings_get_or_create(n00b_store_column_t *column,
                                   n00b_uint128_t       key)
{
    if (column == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    bool found = false;
    n00b_store_posting_list_t *postings = n00b_dict_get(column, key, &found);
    if (found) {
        if (postings == nullptr) {
            return n00b_result_err(n00b_store_posting_list_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }
        return n00b_result_ok(n00b_store_posting_list_t *, postings);
    }

    postings = rocs_posting_list_new(.allocator = column->allocator);
    n00b_dict_put(column, key, postings);
    return n00b_result_ok(n00b_store_posting_list_t *, postings);
}

static n00b_result_t(n00b_option_t(n00b_store_posting_list_t *))
rocs_column_postings_find(n00b_store_column_t *column, n00b_uint128_t key)
{
    if (column == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_posting_list_t *),
                               N00B_STORE_INDEX_ERR_ARG);
    }

    bool found = false;
    n00b_store_posting_list_t *postings = n00b_dict_get(column, key, &found);
    if (!found) {
        return n00b_result_ok(n00b_option_t(n00b_store_posting_list_t *),
                              n00b_option_none(n00b_store_posting_list_t *));
    }
    if (postings == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_posting_list_t *),
                               N00B_STORE_INDEX_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_store_posting_list_t *),
                          n00b_option_set(n00b_store_posting_list_t *,
                                          postings));
}

static n00b_result_t(n00b_uint128_t)
rocs_term_key(n00b_store_index_kind_t kind,
              n00b_store_normalized_t *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto hash_r = n00b_store_normalize_hash(kind,
                                            term,
                                            .allocator = allocator);
    if (n00b_result_is_err(hash_r)) {
        return n00b_result_err(n00b_uint128_t,
                               rocs_index_norm_err(n00b_result_get_err(hash_r)));
    }
    return n00b_result_ok(n00b_uint128_t, n00b_result_get(hash_r));
}

static n00b_uint128_t
rocs_column_bucket_hash(n00b_uint128_t key)
{
    return n00b_hash_raw(&key, sizeof(key));
}

static bool
rocs_record_in_list(n00b_store_posting_list_t *records, n00b_json_node_t *record)
{
    if (records == nullptr || record == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*records);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*records, i) == record) {
            return true;
        }
    }
    return false;
}

static n00b_store_posting_list_t *
rocs_filter_hot_candidates(n00b_store_posting_list_t *candidates,
                           n00b_store_posting_list_t *current) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_posting_list_t *filtered =
        rocs_posting_list_new(.allocator = allocator);

    if (candidates == nullptr || current == nullptr) {
        return filtered;
    }

    size_t len = n00b_list_len(*candidates);
    for (size_t i = 0; i < len; i++) {
        n00b_json_node_t *record = n00b_list_get(*candidates, i);
        if (rocs_record_in_list(current, record)) {
            n00b_list_push(*filtered, record);
        }
    }
    return filtered;
}

static bool
rocs_hot_record_ordinal(n00b_store_shard_t *shard,
                        n00b_json_node_t   *record,
                        uint64_t           *ordinal)
{
    if (shard == nullptr || shard->records == nullptr || record == nullptr
        || ordinal == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*shard->records);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*shard->records, i) == record) {
            *ordinal = (uint64_t)i;
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
rocs_postings_add_hot(n00b_store_postings_t *postings,
                      n00b_store_shard_t    *shard,
                      n00b_json_node_t      *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (postings == nullptr || postings->records == nullptr || shard == nullptr
        || record == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t ordinal = 0;
    if (!rocs_hot_record_ordinal(shard, record, &ordinal)) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_record_t *view = _rocs_record_view_new(
        (n00b_store_pos_t){
            .shard_id   = shard->shard_id,
            .ordinal    = ordinal,
            .generation = shard->seal_ts,
        },
        shard,
        nullptr,
        .allocator = allocator);

    n00b_list_push(*postings->records, view);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_mapped_list_contains_vaddr(n00b_store_map_list_t *list, uint64_t vaddr)
{
    auto len_r = n00b_store_map_list_len(list);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(bool,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }

    uint64_t len = n00b_result_get(len_r);
    for (uint64_t i = 0; i < len; i++) {
        auto slot_r = n00b_store_map_list_slot(list, i);
        if (n00b_result_is_err(slot_r)) {
            return n00b_result_err(bool,
                                   rocs_index_map_err(n00b_result_get_err(slot_r)));
        }
        n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
        if (!n00b_option_is_set(slot_opt)) {
            return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
        }
        auto raw_r = n00b_store_map_slot_u64(n00b_option_get(slot_opt));
        if (n00b_result_is_err(raw_r)) {
            return n00b_result_err(bool,
                                   rocs_index_map_err(n00b_result_get_err(raw_r)));
        }
        if (n00b_result_get(raw_r) == vaddr) {
            return n00b_result_ok(bool, true);
        }
    }
    return n00b_result_ok(bool, false);
}

static n00b_result_t(rocs_vaddr_list_t *)
rocs_vaddr_list_from_mapped_postings(n00b_store_map_list_t *list) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto len_r = n00b_store_map_list_len(list);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(rocs_vaddr_list_t *,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }

    rocs_vaddr_list_t *out = rocs_vaddr_list_new(.allocator = allocator);
    uint64_t           len = n00b_result_get(len_r);
    for (uint64_t i = 0; i < len; i++) {
        auto slot_r = n00b_store_map_list_slot(list, i);
        if (n00b_result_is_err(slot_r)) {
            return n00b_result_err(rocs_vaddr_list_t *,
                                   rocs_index_map_err(n00b_result_get_err(slot_r)));
        }
        n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
        if (!n00b_option_is_set(slot_opt)) {
            return n00b_result_err(rocs_vaddr_list_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        auto raw_r = n00b_store_map_slot_u64(n00b_option_get(slot_opt));
        if (n00b_result_is_err(raw_r)) {
            return n00b_result_err(rocs_vaddr_list_t *,
                                   rocs_index_map_err(n00b_result_get_err(raw_r)));
        }

        uint64_t vaddr = n00b_result_get(raw_r);
        if (vaddr == 0) {
            return n00b_result_err(rocs_vaddr_list_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }
        n00b_list_push(*out, vaddr);
    }

    return n00b_result_ok(rocs_vaddr_list_t *, out);
}

static n00b_result_t(rocs_vaddr_list_t *)
rocs_filter_mapped_candidates(rocs_vaddr_list_t     *candidates,
                              n00b_store_map_list_t *current) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (candidates == nullptr || current == nullptr) {
        return n00b_result_err(rocs_vaddr_list_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    rocs_vaddr_list_t *filtered = rocs_vaddr_list_new(.allocator = allocator);
    size_t             len      = n00b_list_len(*candidates);
    for (size_t i = 0; i < len; i++) {
        uint64_t vaddr = n00b_list_get(*candidates, i);
        auto     has_r = rocs_mapped_list_contains_vaddr(current, vaddr);
        if (n00b_result_is_err(has_r)) {
            return n00b_result_err(rocs_vaddr_list_t *,
                                   n00b_result_get_err(has_r));
        }
        if (n00b_result_get(has_r)) {
            n00b_list_push(*filtered, vaddr);
        }
    }

    return n00b_result_ok(rocs_vaddr_list_t *, filtered);
}

static n00b_result_t(bool)
rocs_postings_add_mapped(n00b_store_postings_t  *postings,
                         n00b_store_map_shard_t *shard,
                         n00b_store_map_list_t  *records,
                         uint64_t                record_vaddr,
                         uint64_t                shard_id,
                         uint64_t                generation) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (postings == nullptr || postings->records == nullptr || shard == nullptr
        || records == nullptr || record_vaddr == 0) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }

    auto len_r = n00b_store_map_list_len(records);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(bool,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }

    uint64_t len = n00b_result_get(len_r);
    for (uint64_t i = 0; i < len; i++) {
        auto slot_r = n00b_store_map_list_slot(records, i);
        if (n00b_result_is_err(slot_r)) {
            return n00b_result_err(bool,
                                   rocs_index_map_err(n00b_result_get_err(slot_r)));
        }
        n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
        if (!n00b_option_is_set(slot_opt)) {
            return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
        }
        auto raw_r = n00b_store_map_slot_u64(n00b_option_get(slot_opt));
        if (n00b_result_is_err(raw_r)) {
            return n00b_result_err(bool,
                                   rocs_index_map_err(n00b_result_get_err(raw_r)));
        }
        if (n00b_result_get(raw_r) != record_vaddr) {
            continue;
        }

        n00b_store_record_t *view = _rocs_record_view_new(
            (n00b_store_pos_t){
                .shard_id   = shard_id,
                .ordinal    = i,
                .generation = generation,
            },
            nullptr,
            shard,
            .allocator = allocator);

        n00b_list_push(*postings->records, view);
        return n00b_result_ok(bool, true);
    }

    return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
}

n00b_string_t *
n00b_store_index_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_INDEX_OK:           return r"OK";
    case N00B_STORE_INDEX_ERR_ARG:      return r"ARG";
    case N00B_STORE_INDEX_ERR_STATE:    return r"STATE";
    case N00B_STORE_INDEX_ERR_KIND:     return r"KIND";
    case N00B_STORE_INDEX_ERR_UNREADY:  return r"UNREADY";
    case N00B_STORE_INDEX_ERR_INTERNAL: return r"INTERNAL";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_store_index_t *)
n00b_store_index_new(n00b_string_t          *field,
                     n00b_store_index_kind_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (field == nullptr) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_ARG);
    }
    if (!rocs_index_kind_known(kind)) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_KIND);
    }

    n00b_store_index_t *index = n00b_alloc_with_opts(
        n00b_store_index_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    index->field = field;
    index->kind  = kind;

    return n00b_result_ok(n00b_store_index_t *, index);
}

n00b_result_t(n00b_store_index_kind_t)
n00b_store_index_kind(n00b_store_index_t *index)
{
    if (index == nullptr) {
        return n00b_result_err(n00b_store_index_kind_t, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_index_kind_t, index->kind);
}

n00b_result_t(n00b_string_t *)
n00b_store_index_field(n00b_store_index_t *index)
{
    if (index == nullptr || index->field == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(n00b_string_t *, index->field);
}

n00b_store_advert_t
n00b_store_index_advertise(n00b_store_index_t *index,
                           n00b_string_t      *field,
                           int64_t             op)
{
    (void)op;

    if (index == nullptr || field == nullptr || index->field == nullptr) {
        return (n00b_store_advert_t){
            .accelerates = false,
            .kind        = N00B_STORE_INDEX_NONE,
        };
    }

    bool accelerates = n00b_unicode_str_eq(index->field, field)
                    && index->kind == N00B_STORE_INDEX_TERM;
    return (n00b_store_advert_t){
        .accelerates      = accelerates,
        .kind             = accelerates ? N00B_STORE_INDEX_TERM
                                        : N00B_STORE_INDEX_NONE,
        .selectivity_hint = accelerates ? 0.10 : 1.0,
    };
}

n00b_result_t(uint64_t)
n00b_store_index_add(n00b_store_index_t *index,
                     n00b_store_shard_t *shard,
                     uint64_t            record_ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t ready = rocs_index_term_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(uint64_t, ready);
    }
    if (shard == nullptr || shard->records == nullptr || shard->columns == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
    }

    size_t records_len = n00b_list_len(*shard->records);
    if (record_ordinal >= (uint64_t)records_len) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_json_node_t *record = n00b_list_get(*shard->records,
                                             (size_t)record_ordinal);
    if (record == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_json_node_t *field_value = n00b_json_object_get(record, index->field);
    if (field_value == nullptr) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto terms_r = n00b_store_normalize_json(field_value,
                                             .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(uint64_t,
                               rocs_index_norm_err(n00b_result_get_err(terms_r)));
    }

    n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
    size_t                        len   = n00b_list_len(*terms);
    if (len == 0) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto column_r = rocs_column_get_or_create(shard, index->field);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(column_r));
    }
    n00b_store_column_t *column = n00b_result_get(column_r);

    uint64_t added = 0;
    for (size_t i = 0; i < len; i++) {
        n00b_store_normalized_t *term = n00b_list_get(*terms, i);
        auto                    key_r = rocs_term_key(index->kind,
                                                      term,
                                                      .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(key_r));
        }

        auto postings_r = rocs_column_postings_get_or_create(column,
                                                             n00b_result_get(key_r));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(postings_r));
        }

        n00b_list_push(*n00b_result_get(postings_r), record);
        added++;
    }

    return n00b_result_ok(uint64_t, added);
}

n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup(n00b_store_index_t *index,
                        n00b_store_shard_t *shard,
                        n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t ready = rocs_index_term_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(n00b_store_postings_t *, ready);
    }
    if (shard == nullptr || value == nullptr || shard->records == nullptr
        || shard->columns == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    uint64_t shard_id   = shard->shard_id;
    uint64_t generation = shard->seal_ts;

    auto terms_r = n00b_store_normalize_json(value, .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_norm_err(n00b_result_get_err(terms_r)));
    }

    n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
    size_t                        len   = n00b_list_len(*terms);
    if (len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }

    bool found_column = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns,
                                                index->field,
                                                &found_column);
    if (!found_column) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }
    if (column == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_posting_list_t *candidates = nullptr;
    for (size_t i = 0; i < len; i++) {
        n00b_store_normalized_t *term = n00b_list_get(*terms, i);
        auto                    key_r = rocs_term_key(index->kind,
                                                      term,
                                                      .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(key_r));
        }

        auto postings_r = rocs_column_postings_find(column, n00b_result_get(key_r));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_posting_list_t *) current_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(current_opt)) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }
        n00b_store_posting_list_t *current = n00b_option_get(current_opt);
        candidates = candidates == nullptr
                       ? current
                       : rocs_filter_hot_candidates(candidates,
                                                    current,
                                                    .allocator = allocator);
        if (n00b_list_len(*candidates) == 0) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }
    }

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    size_t candidate_len = n00b_list_len(*candidates);
    for (size_t i = 0; i < candidate_len; i++) {
        auto add_r = rocs_postings_add_hot(postings,
                                           shard,
                                           n00b_list_get(*candidates, i),
                                           .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_postings_t *, postings);
}

n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup_mapped(n00b_store_index_t     *index,
                               n00b_store_map_shard_t *shard,
                               n00b_json_node_t       *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t ready = rocs_index_term_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(n00b_store_postings_t *, ready);
    }
    if (shard == nullptr || value == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto state_r = n00b_store_map_shard_state(shard);
    if (n00b_result_is_err(state_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(state_r)));
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto shard_id_r = n00b_store_map_shard_id(shard);
    if (n00b_result_is_err(shard_id_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(shard_id_r)));
    }
    auto generation_r = n00b_store_map_shard_seal_ts(shard);
    if (n00b_result_is_err(generation_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(generation_r)));
    }

    uint64_t shard_id   = n00b_result_get(shard_id_r);
    uint64_t generation = n00b_result_get(generation_r);

    auto terms_r = n00b_store_normalize_json(value, .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_norm_err(n00b_result_get_err(terms_r)));
    }

    n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
    size_t                        len   = n00b_list_len(*terms);
    if (len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }

    auto records_r = n00b_store_map_shard_records(shard);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(records_r)));
    }

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(columns_r)));
    }

    auto field_entry_r = n00b_store_map_dict_find_hv(n00b_result_get(columns_r),
                                                     n00b_string_hash(index->field));
    if (n00b_result_is_err(field_entry_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(field_entry_r)));
    }
    n00b_option_t(n00b_store_map_dict_entry_t *) field_entry_opt =
        n00b_result_get(field_entry_r);
    if (!n00b_option_is_set(field_entry_opt)) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }

    n00b_store_map_dict_entry_t *field_entry = n00b_option_get(field_entry_opt);
    auto                         field_eq_r =
        n00b_store_map_slot_string_eq(field_entry->key, index->field);
    if (n00b_result_is_err(field_eq_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(field_eq_r)));
    }
    if (!n00b_result_get(field_eq_r)) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }

    auto column_r = n00b_store_map_slot_column(field_entry->value);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(column_r)));
    }

    rocs_vaddr_list_t *candidates = nullptr;
    for (size_t i = 0; i < len; i++) {
        n00b_store_normalized_t *term = n00b_list_get(*terms, i);
        auto                    key_r = rocs_term_key(index->kind,
                                                      term,
                                                      .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(key_r));
        }

        n00b_uint128_t term_key  = n00b_result_get(key_r);
        n00b_uint128_t bucket_hv = rocs_column_bucket_hash(term_key);
        auto entry_r = n00b_store_map_dict_find_hv(n00b_result_get(column_r),
                                                   bucket_hv);
        if (n00b_result_is_err(entry_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   rocs_index_map_err(n00b_result_get_err(entry_r)));
        }

        n00b_option_t(n00b_store_map_dict_entry_t *) entry_opt =
            n00b_result_get(entry_r);
        if (!n00b_option_is_set(entry_opt)) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }

        n00b_store_map_dict_entry_t *entry = n00b_option_get(entry_opt);
        auto                         key_slot_r = n00b_store_map_slot_u128(entry->key);
        if (n00b_result_is_err(key_slot_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   rocs_index_map_err(n00b_result_get_err(key_slot_r)));
        }
        if (n00b_result_get(key_slot_r) != term_key) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }

        auto list_r = n00b_store_map_slot_list(entry->value);
        if (n00b_result_is_err(list_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   rocs_index_map_err(n00b_result_get_err(list_r)));
        }

        if (candidates == nullptr) {
            auto first_r =
                rocs_vaddr_list_from_mapped_postings(n00b_result_get(list_r),
                                                     .allocator = allocator);
            if (n00b_result_is_err(first_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(first_r));
            }
            candidates = n00b_result_get(first_r);
        }
        else {
            auto filtered_r =
                rocs_filter_mapped_candidates(candidates,
                                              n00b_result_get(list_r),
                                              .allocator = allocator);
            if (n00b_result_is_err(filtered_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(filtered_r));
            }
            candidates = n00b_result_get(filtered_r);
        }

        if (n00b_list_len(*candidates) == 0) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }
    }

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    size_t candidate_len = n00b_list_len(*candidates);
    for (size_t i = 0; i < candidate_len; i++) {
        auto add_r = rocs_postings_add_mapped(postings,
                                              shard,
                                              n00b_result_get(records_r),
                                              n00b_list_get(*candidates, i),
                                              shard_id,
                                              generation,
                                              .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_postings_t *, postings);
}

n00b_result_t(n00b_store_postings_t *)
n00b_store_postings_empty() _kargs
{
    uint64_t          shard_id   = 0;
    uint64_t          generation = 0;
    n00b_allocator_t *allocator  = nullptr;
}
{
    return rocs_empty_postings(shard_id, generation, .allocator = allocator);
}

n00b_result_t(uint64_t)
n00b_store_postings_len(n00b_store_postings_t *postings)
{
    if (postings == nullptr || postings->records == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*postings->records));
}

n00b_result_t(n00b_option_t(n00b_store_posting_t))
n00b_store_postings_get(n00b_store_postings_t *postings, uint64_t ordinal)
{
    if (postings == nullptr || postings->records == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_posting_t),
                               N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*postings->records);
    if (ordinal >= len) {
        return n00b_result_ok(n00b_option_t(n00b_store_posting_t),
                              n00b_option_none(n00b_store_posting_t));
    }

    n00b_store_record_t *record = n00b_list_get(*postings->records, ordinal);
    if (record == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_posting_t),
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_posting_t posting = {
        .pos    = record->pos,
        .record = record,
    };
    return n00b_result_ok(n00b_option_t(n00b_store_posting_t),
                          n00b_option_set(n00b_store_posting_t, posting));
}

n00b_result_t(n00b_store_pos_t)
n00b_store_record_pos(n00b_store_record_t *record)
{
    if (record == nullptr) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_pos_t, record->pos);
}

n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_hot_at(n00b_store_shard_t *shard,
                              uint64_t            ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (shard == nullptr || shard->records == nullptr) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*shard->records);
    if (len != shard->record_count || ordinal >= len) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    if (n00b_list_get(*shard->records, (size_t)ordinal) == nullptr) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_record_t *view = _rocs_record_view_new(
        (n00b_store_pos_t){
            .shard_id   = shard->shard_id,
            .ordinal    = ordinal,
            .generation = shard->seal_ts,
        },
        shard,
        nullptr,
        .allocator = allocator);
    return n00b_result_ok(n00b_store_record_t *, view);
}

n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_hot_pos(n00b_store_shard_t *shard,
                               n00b_store_pos_t    pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (shard == nullptr || shard->records == nullptr || pos.shard_id == 0) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN
        && shard->state != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }
    if (pos.shard_id != shard->shard_id) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*shard->records);
    if (len != shard->record_count || pos.ordinal >= len) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    if (n00b_list_get(*shard->records, (size_t)pos.ordinal) == nullptr) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_record_t *view = _rocs_record_view_new(pos,
                                                      shard,
                                                      nullptr,
                                                      .allocator = allocator);
    return n00b_result_ok(n00b_store_record_t *, view);
}

n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_mapped_at(n00b_store_map_shard_t *shard,
                                 uint64_t                ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_pos_t pos = {};
    if (shard == nullptr) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto state_r = n00b_store_map_shard_state(shard);
    if (n00b_result_is_err(state_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(state_r)));
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto len_r = n00b_store_map_shard_records_len(shard);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }
    if (ordinal >= n00b_result_get(len_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto records_r = n00b_store_map_shard_records(shard);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(records_r)));
    }
    auto slot_r = n00b_store_map_list_slot(n00b_result_get(records_r), ordinal);
    if (n00b_result_is_err(slot_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(slot_r)));
    }
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    if (!n00b_option_is_set(slot_opt)) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    auto ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    if (n00b_result_is_err(ref_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(ref_r)));
    }
    if (!n00b_option_is_set(n00b_result_get(ref_r))) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto shard_id_r = n00b_store_map_shard_id(shard);
    if (n00b_result_is_err(shard_id_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(shard_id_r)));
    }
    auto generation_r = n00b_store_map_shard_seal_ts(shard);
    if (n00b_result_is_err(generation_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(generation_r)));
    }

    pos = (n00b_store_pos_t){
        .shard_id   = n00b_result_get(shard_id_r),
        .ordinal    = ordinal,
        .generation = n00b_result_get(generation_r),
    };

    n00b_store_record_t *view = _rocs_record_view_new(pos,
                                                      nullptr,
                                                      shard,
                                                      .allocator = allocator);
    return n00b_result_ok(n00b_store_record_t *, view);
}

n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_mapped_pos(n00b_store_map_shard_t *shard,
                                  n00b_store_pos_t        pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (shard == nullptr || pos.shard_id == 0) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto state_r = n00b_store_map_shard_state(shard);
    if (n00b_result_is_err(state_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(state_r)));
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto shard_id_r = n00b_store_map_shard_id(shard);
    if (n00b_result_is_err(shard_id_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(shard_id_r)));
    }
    if (n00b_result_get(shard_id_r) != pos.shard_id) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto len_r = n00b_store_map_shard_records_len(shard);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }
    if (pos.ordinal >= n00b_result_get(len_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto records_r = n00b_store_map_shard_records(shard);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(records_r)));
    }
    auto slot_r = n00b_store_map_list_slot(n00b_result_get(records_r),
                                           pos.ordinal);
    if (n00b_result_is_err(slot_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(slot_r)));
    }
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    if (!n00b_option_is_set(slot_opt)) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    auto ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    if (n00b_result_is_err(ref_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(ref_r)));
    }
    if (!n00b_option_is_set(n00b_result_get(ref_r))) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_record_t *view = _rocs_record_view_new(
        pos,
        nullptr,
        shard,
        .allocator = allocator);
    return n00b_result_ok(n00b_store_record_t *, view);
}

n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_owned_json(n00b_store_pos_t   pos,
                                  n00b_json_node_t  *json) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (json == nullptr || pos.shard_id == 0) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_store_record_t *view = _rocs_record_view_new(
        pos,
        nullptr,
        nullptr,
        .allocator = allocator);
    view->owned_json = json;
    return n00b_result_ok(n00b_store_record_t *, view);
}

n00b_result_t(n00b_json_node_t *)
n00b_store_record_view_json(n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (record == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    if (record->owned_json != nullptr) {
        return n00b_result_ok(n00b_json_node_t *, record->owned_json);
    }

    if (record->hot_shard != nullptr) {
        n00b_store_shard_t *shard = record->hot_shard;
        if (shard->records == nullptr
            || (shard->state != N00B_SHARD_STATE_OPEN
                && shard->state != N00B_SHARD_STATE_SEALED)) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        uint64_t len = (uint64_t)n00b_list_len(*shard->records);
        if (record->pos.ordinal >= len || len != shard->record_count) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        n00b_json_node_t *node =
            n00b_list_get(*shard->records, (size_t)record->pos.ordinal);
        if (node == nullptr) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }
        return n00b_result_ok(n00b_json_node_t *, node);
    }

    if (record->mapped_shard == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    auto node_r =
        n00b_store_map_shard_record_json_copy(record->mapped_shard,
                                             record->pos.ordinal,
                                             .allocator = allocator);
    if (n00b_result_is_err(node_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               rocs_index_map_err(n00b_result_get_err(node_r)));
    }

    return n00b_result_ok(n00b_json_node_t *, n00b_result_get(node_r));
}

n00b_result_t(n00b_json_node_t *)
n00b_store_record_view_json_copy(n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto json_r = n00b_store_record_view_json(record,
                                             .allocator = allocator);
    if (n00b_result_is_err(json_r)) {
        return json_r;
    }

    return rocs_json_node_copy(n00b_result_get(json_r), allocator);
}
