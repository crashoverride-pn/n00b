#include "rocs/index.h"

#include "adt/list.h"
#include "core/hash.h"
#include "internal/rocs/index.h"
#include "internal/rocs/json_field.h"
#include "internal/rocs/map.h"
#include "rocs/map.h"
#include "rocs/normalizer.h"
#include "text/strings/string_ops.h"

typedef n00b_list_t(n00b_store_record_t *) rocs_record_view_list_t;
typedef n00b_list_t(n00b_store_pos_t) rocs_posting_pos_list_t;
typedef n00b_list_t(uint64_t) rocs_posting_value_list_t;

struct n00b_store_index_t {
    n00b_string_t                 *field;
    n00b_store_index_field_list_t *catch_all_fields;
    n00b_store_index_kind_t        kind;
    n00b_store_postings_kind_t     postings;
    uint8_t                        ngram_n;
    bool                           catch_all;
};

struct n00b_store_record_t {
    n00b_store_pos_t          pos;
    n00b_store_shard_t       *hot_shard;
    n00b_store_map_shard_t   *mapped_shard;
    n00b_json_node_t         *owned_json;
};

struct n00b_store_postings_t {
    rocs_record_view_list_t *records;
    rocs_posting_pos_list_t *positions;
    n00b_store_shard_t      *hot_shard;
    n00b_store_map_shard_t  *mapped_shard;
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

static bool
rocs_index_ngram_n_valid(uint8_t ngram_n)
{
    return ngram_n >= N00B_STORE_NGRAM_MIN_N
        && ngram_n <= N00B_STORE_NGRAM_MAX_N;
}

static bool
rocs_postings_kind_valid(n00b_store_postings_kind_t kind)
{
    return kind == N00B_STORE_POSTINGS_SPARSE
        || kind == N00B_STORE_POSTINGS_DENSE;
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

static rocs_posting_value_list_t *
rocs_posting_value_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_posting_value_list_t *items = n00b_alloc_with_opts(
        rocs_posting_value_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *items = n00b_list_new_private(uint64_t,
                                   .allocator = allocator,
                                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return items;
}

static int
rocs_u64_compare(const void *left, const void *right)
{
    uint64_t l = *(uint64_t const *)left;
    uint64_t r = *(uint64_t const *)right;

    if (l < r) {
        return -1;
    }
    if (l > r) {
        return 1;
    }
    return 0;
}

static rocs_posting_pos_list_t *
rocs_posting_pos_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_posting_pos_list_t *items = n00b_alloc_with_opts(
        rocs_posting_pos_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *items = n00b_list_new_private(n00b_store_pos_t,
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

    postings->records      = rocs_record_view_list_new(.allocator = allocator);
    postings->positions    = rocs_posting_pos_list_new(.allocator = allocator);
    postings->hot_shard    = nullptr;
    postings->mapped_shard = nullptr;
    postings->shard_id     = shard_id;
    postings->generation   = generation;
    return postings;
}

static n00b_result_t(bool)
rocs_postings_add_pos(n00b_store_postings_t *postings,
                      n00b_store_pos_t       pos)
{
    if (postings == nullptr || postings->positions == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_list_push(*postings->positions, pos);
    return n00b_result_ok(bool, true);
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

extern n00b_result_t(n00b_json_node_t *)
rocs_json_node_copy(n00b_json_node_t *node) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

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

        auto child_r = rocs_json_node_copy(child, .allocator = allocator);
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

        auto value_r = rocs_json_node_copy(entry->value,
                                           .allocator = allocator);
        if (n00b_result_is_err(value_r)) {
            return value_r;
        }

        n00b_json_object_put_n00b(copy, key, n00b_result_get(value_r));
    }

    return n00b_result_ok(n00b_json_node_t *, copy);
}

n00b_result_t(n00b_json_node_t *)
rocs_json_node_copy(n00b_json_node_t *node) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
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

static n00b_result_t(n00b_json_node_t *)
rocs_hot_shard_record_json(n00b_store_shard_t *shard,
                           uint64_t            ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (shard == nullptr || shard->records == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*shard->records);
    if (ordinal >= len || len != shard->record_count) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_string_t *text = n00b_list_get(*shard->records, (size_t)ordinal);
    if (text == nullptr || (text->u8_bytes != 0 && text->data == nullptr)) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    const char       *err  = nullptr;
    n00b_json_node_t *node = n00b_json_parse(text->data,
                                             text->u8_bytes,
                                             &err,
                                             .allocator = allocator);
    if (node == nullptr || err != nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    return n00b_result_ok(n00b_json_node_t *, node);
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
rocs_index_hot_ready(n00b_store_index_t *index)
{
    if (index == nullptr) {
        return N00B_STORE_INDEX_ERR_ARG;
    }
    if (index->catch_all) {
        if (index->catch_all_fields == nullptr
            || n00b_list_len(*index->catch_all_fields) == 0
            || index->kind != N00B_STORE_INDEX_FULLTEXT) {
            return N00B_STORE_INDEX_ERR_STATE;
        }
        return N00B_STORE_INDEX_OK;
    }
    if (index->field == nullptr) {
        return N00B_STORE_INDEX_ERR_ARG;
    }
    switch (index->kind) {
    case N00B_STORE_INDEX_TERM:
    case N00B_STORE_INDEX_FULLTEXT:
    case N00B_STORE_INDEX_NGRAM:
        return N00B_STORE_INDEX_OK;
    case N00B_STORE_INDEX_NONE:
    case N00B_STORE_INDEX_NUMERIC:
    case N00B_STORE_INDEX_BOOL:
    case N00B_STORE_INDEX_VECTOR:
        return N00B_STORE_INDEX_ERR_UNREADY;
    }
    return N00B_STORE_INDEX_ERR_UNREADY;
}

static n00b_store_posting_list_t *
rocs_posting_list_new() _kargs
{
    n00b_store_postings_kind_t kind      = N00B_STORE_POSTINGS_SPARSE;
    n00b_allocator_t          *allocator = nullptr;
}
{
    n00b_store_posting_list_t *postings = n00b_alloc_with_opts(
        n00b_store_posting_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    postings->kind     = rocs_postings_kind_valid(kind)
                           ? kind
                           : N00B_STORE_POSTINGS_SPARSE;
    postings->reserved = 0;
    postings->count    = 0;
    postings->ordinals = nullptr;
    postings->flags    = nullptr;

    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        postings->flags = n00b_flagset_new(.length = 64,
                                           .allocator = allocator);
    }
    else {
        postings->ordinals = n00b_alloc_with_opts(
            n00b_store_posting_ordinal_list_t,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
            });
        *postings->ordinals = n00b_list_new_private(
            uint64_t,
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE);
    }
    return postings;
}

static uint64_t
rocs_posting_list_len(n00b_store_posting_list_t *postings)
{
    if (postings == nullptr) {
        return 0;
    }
    if (postings->kind == N00B_STORE_POSTINGS_SPARSE) {
        return postings->ordinals == nullptr
                 ? 0
                 : (uint64_t)n00b_list_len(*postings->ordinals);
    }
    return postings->count;
}

static n00b_result_t(uint64_t)
rocs_posting_list_ordinal_at(n00b_store_posting_list_t *postings,
                             uint64_t                   index)
{
    if (postings == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }
    if (postings->kind == N00B_STORE_POSTINGS_SPARSE) {
        if (postings->ordinals == nullptr
            || index >= n00b_list_len(*postings->ordinals)) {
            return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
        }
        return n00b_result_ok(uint64_t,
                              n00b_list_get(*postings->ordinals, index));
    }

    if (postings->flags == nullptr || index >= postings->count) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
    }
    uint64_t seen   = 0;
    uint64_t cursor = 0;
    while (n00b_flagset_next_set(postings->flags, cursor, &cursor)) {
        if (seen == index) {
            return n00b_result_ok(uint64_t, cursor);
        }
        seen++;
        cursor++;
    }
    return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
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
                                   n00b_uint128_t       key,
                                   n00b_store_postings_kind_t kind)
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

    postings = rocs_posting_list_new(.kind      = kind,
                                     .allocator = column->allocator);
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
rocs_posting_list_contains_ordinal(n00b_store_posting_list_t *postings,
                                   uint64_t                   ordinal)
{
    if (postings == nullptr) {
        return false;
    }

    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        return n00b_flagset_index(postings->flags, (int64_t)ordinal);
    }

    if (postings->ordinals == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*postings->ordinals);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*postings->ordinals, i) == ordinal) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
rocs_posting_list_push(n00b_store_posting_list_t *postings,
                       uint64_t                   ordinal,
                       bool                       unique);

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

    size_t len = (size_t)rocs_posting_list_len(candidates);
    for (size_t i = 0; i < len; i++) {
        auto ordinal_r = rocs_posting_list_ordinal_at(candidates, i);
        if (n00b_result_is_err(ordinal_r)) {
            return filtered;
        }
        uint64_t ordinal = n00b_result_get(ordinal_r);
        if (rocs_posting_list_contains_ordinal(current, ordinal)) {
            (void)rocs_posting_list_push(filtered, ordinal, true);
        }
    }
    return filtered;
}

static n00b_result_t(bool)
rocs_postings_add_hot(n00b_store_postings_t *postings,
                      n00b_store_shard_t    *shard,
                      uint64_t               ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (postings == nullptr || postings->records == nullptr
        || postings->positions == nullptr || shard == nullptr
        || shard->records == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }

    if (ordinal >= (uint64_t)n00b_list_len(*shard->records)
        || n00b_list_get(*shard->records, (size_t)ordinal) == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_pos_t pos = {
        .shard_id   = shard->shard_id,
        .ordinal    = ordinal,
        .generation = shard->seal_ts,
    };
    n00b_store_record_t *view = _rocs_record_view_new(pos,
                                                      shard,
                                                      nullptr,
                                                      .allocator = allocator);

    postings->hot_shard = shard;
    n00b_list_push(*postings->records, view);
    auto pos_r = rocs_postings_add_pos(postings, pos);
    if (n00b_result_is_err(pos_r)) {
        return pos_r;
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_mapped_posting_list_contains_value(n00b_store_map_posting_list_t *list,
                                        uint64_t                       value)
{
    auto has_r = n00b_store_map_posting_list_contains(list, value);
    if (n00b_result_is_err(has_r)) {
        return n00b_result_err(bool,
                               rocs_index_map_err(n00b_result_get_err(has_r)));
    }
    return n00b_result_ok(bool, n00b_result_get(has_r));
}

static n00b_result_t(rocs_posting_value_list_t *)
rocs_posting_value_list_from_mapped_postings(
    n00b_store_map_posting_list_t *list) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto len_r = n00b_store_map_posting_list_len(list);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(rocs_posting_value_list_t *,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }

    rocs_posting_value_list_t *out =
        rocs_posting_value_list_new(.allocator = allocator);
    uint64_t len = n00b_result_get(len_r);
    for (uint64_t i = 0; i < len; i++) {
        auto raw_r = n00b_store_map_posting_list_ordinal_at(list, i);
        if (n00b_result_is_err(raw_r)) {
            return n00b_result_err(rocs_posting_value_list_t *,
                                   rocs_index_map_err(n00b_result_get_err(raw_r)));
        }

        n00b_list_push(*out, n00b_result_get(raw_r));
    }

    return n00b_result_ok(rocs_posting_value_list_t *, out);
}

static bool
rocs_posting_value_list_contains(rocs_posting_value_list_t *items,
                                 uint64_t                   value)
{
    if (items == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*items);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*items, i) == value) {
            return true;
        }
    }
    return false;
}

static void
rocs_posting_value_list_push_unique(rocs_posting_value_list_t *items,
                                    uint64_t                   value)
{
    if (items == nullptr
        || rocs_posting_value_list_contains(items, value)) {
        return;
    }
    n00b_list_push(*items, value);
}

static void
rocs_posting_value_list_sort(rocs_posting_value_list_t *items)
{
    if (items != nullptr && n00b_list_len(*items) > 1) {
        n00b_list_sort(*items, rocs_u64_compare);
    }
}

// A mapped posting entry IS the record ordinal: postings are stored as a sparse
// ordinal list or a dense bitset indexed by ordinal
// (n00b_store_map_posting_list_ordinal_at).  The shard's records list maps
// ordinal -> record-bytes vaddr (n00b_store_map_shard_record_json_string reads
// records[ord] as a ref->vaddr), NOT ordinal -> ordinal.  So the former
// {vaddr -> ordinal} translation dict could never match an ordinal-valued
// candidate (a small ordinal never equals a large image vaddr): every lookup
// missed and fell through to this same identity bounds-check.  Building that
// dict was O(records-per-shard) per shard per query AND its per-record slot
// n00b_free walked the mmap interval-tree registry under a lock, so it was both
// pure waste and the dominant query cost.  Removed; the ordinal is used directly.
static n00b_result_t(uint64_t)
rocs_mapped_posting_to_ordinal(uint64_t posting_value, uint64_t record_count)
{
    if (posting_value < record_count) {
        return n00b_result_ok(uint64_t, posting_value);
    }
    return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
}

static n00b_result_t(rocs_posting_value_list_t *)
rocs_filter_mapped_candidates(rocs_posting_value_list_t *candidates,
                              n00b_store_map_posting_list_t *current) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (candidates == nullptr || current == nullptr) {
        return n00b_result_err(rocs_posting_value_list_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    rocs_posting_value_list_t *filtered =
        rocs_posting_value_list_new(.allocator = allocator);
    size_t len = n00b_list_len(*candidates);
    for (size_t i = 0; i < len; i++) {
        uint64_t value = n00b_list_get(*candidates, i);
        auto     has_r = rocs_mapped_posting_list_contains_value(current, value);
        if (n00b_result_is_err(has_r)) {
            return n00b_result_err(rocs_posting_value_list_t *,
                                   n00b_result_get_err(has_r));
        }
        if (n00b_result_get(has_r)) {
            n00b_list_push(*filtered, value);
        }
    }

    return n00b_result_ok(rocs_posting_value_list_t *, filtered);
}

static n00b_result_t(n00b_option_t(n00b_store_map_dict_t *))
rocs_mapped_column_find(n00b_store_map_dict_t *columns,
                        n00b_string_t         *field)
{
    if (columns == nullptr || field == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_map_dict_t *),
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto field_entry_r =
        n00b_store_map_dict_find_hv(columns, n00b_string_hash(field));
    if (n00b_result_is_err(field_entry_r)) {
        return n00b_result_err(
            n00b_option_t(n00b_store_map_dict_t *),
            rocs_index_map_err(n00b_result_get_err(field_entry_r)));
    }

    n00b_option_t(n00b_store_map_dict_entry_t *) field_entry_opt =
        n00b_result_get(field_entry_r);
    if (!n00b_option_is_set(field_entry_opt)) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_dict_t *),
                              n00b_option_none(n00b_store_map_dict_t *));
    }

    n00b_store_map_dict_entry_t *field_entry =
        n00b_option_get(field_entry_opt);
    auto field_eq_r =
        n00b_store_map_slot_string_eq(field_entry->key, field);
    if (n00b_result_is_err(field_eq_r)) {
        return n00b_result_err(
            n00b_option_t(n00b_store_map_dict_t *),
            rocs_index_map_err(n00b_result_get_err(field_eq_r)));
    }
    if (!n00b_result_get(field_eq_r)) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_dict_t *),
                              n00b_option_none(n00b_store_map_dict_t *));
    }

    auto column_r = n00b_store_map_slot_column(field_entry->value);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_dict_t *),
                               rocs_index_map_err(n00b_result_get_err(column_r)));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_map_dict_t *),
                          n00b_option_set(n00b_store_map_dict_t *,
                                          n00b_result_get(column_r)));
}

static n00b_result_t(n00b_option_t(n00b_store_map_posting_list_t *))
rocs_mapped_column_postings_find(n00b_store_map_dict_t *column,
                                 n00b_uint128_t         key)
{
    if (column == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_map_posting_list_t *),
                               N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_uint128_t bucket_hv = rocs_column_bucket_hash(key);
    auto           entry_r   = n00b_store_map_dict_find_hv(column, bucket_hv);
    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_posting_list_t *),
                               rocs_index_map_err(n00b_result_get_err(entry_r)));
    }

    n00b_option_t(n00b_store_map_dict_entry_t *) entry_opt =
    n00b_result_get(entry_r);
    if (!n00b_option_is_set(entry_opt)) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_posting_list_t *),
                              n00b_option_none(n00b_store_map_posting_list_t *));
    }

    n00b_store_map_dict_entry_t *entry = n00b_option_get(entry_opt);
    auto                         key_slot_r =
        n00b_store_map_slot_u128(entry->key);
    if (n00b_result_is_err(key_slot_r)) {
        return n00b_result_err(
            n00b_option_t(n00b_store_map_posting_list_t *),
            rocs_index_map_err(n00b_result_get_err(key_slot_r)));
    }
    if (n00b_result_get(key_slot_r) != key) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_posting_list_t *),
                              n00b_option_none(n00b_store_map_posting_list_t *));
    }

    auto list_r = n00b_store_map_slot_posting_list(entry->value);
    if (n00b_result_is_err(list_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_posting_list_t *),
                               rocs_index_map_err(n00b_result_get_err(list_r)));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_map_posting_list_t *),
                          n00b_option_set(n00b_store_map_posting_list_t *,
                                          n00b_result_get(list_r)));
}

static n00b_result_t(bool)
rocs_postings_add_mapped_pos(n00b_store_postings_t  *postings,
                             n00b_store_map_shard_t *shard,
                             uint64_t                ordinal,
                             uint64_t                record_count,
                             uint64_t                shard_id,
                             uint64_t                generation)
{
    if (postings == nullptr || postings->positions == nullptr
        || shard == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    if (ordinal >= record_count) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }

    postings->mapped_shard = shard;
    return rocs_postings_add_pos(
        postings,
        (n00b_store_pos_t){
            .shard_id   = shard_id,
            .ordinal    = ordinal,
            .generation = generation,
        });
}

static n00b_result_t(bool)
rocs_postings_add_mapped(n00b_store_postings_t  *postings,
                         n00b_store_map_shard_t *shard,
                         n00b_store_map_list_t  *records,
                         uint64_t                posting_value,
                         uint64_t                shard_id,
                         uint64_t                generation) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (postings == nullptr || postings->records == nullptr
        || postings->positions == nullptr || shard == nullptr
        || records == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }

    auto len_r = n00b_store_map_list_len(records);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(bool,
                               rocs_index_map_err(n00b_result_get_err(len_r)));
    }

    uint64_t len = n00b_result_get(len_r);
    uint64_t ordinal = posting_value;
    if (posting_value >= len) {
        for (uint64_t i = 0; i < len; i++) {
            auto slot_r = n00b_store_map_list_slot(records, i);
            if (n00b_result_is_err(slot_r)) {
                return n00b_result_err(
                    bool,
                    rocs_index_map_err(n00b_result_get_err(slot_r)));
            }
            n00b_option_t(n00b_store_map_slot_t *) slot_opt =
                n00b_result_get(slot_r);
            if (!n00b_option_is_set(slot_opt)) {
                return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
            }
            auto raw_r = n00b_store_map_slot_u64(n00b_option_get(slot_opt));
            if (n00b_result_is_err(raw_r)) {
                return n00b_result_err(
                    bool,
                    rocs_index_map_err(n00b_result_get_err(raw_r)));
            }
            uint64_t raw = n00b_result_get(raw_r);
            // Recycle the transient per-record slot back to the per-query view
            // pool so this scan stays ~one slot, not one-per-record.
            n00b_free(n00b_option_get(slot_opt));
            if (raw == posting_value) {
                ordinal = i;
                break;
            }
        }
        if (ordinal == posting_value) {
            return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
        }
    }

    auto slot_r = n00b_store_map_list_slot(records, ordinal);
    if (n00b_result_is_err(slot_r)) {
        return n00b_result_err(bool,
                               rocs_index_map_err(n00b_result_get_err(slot_r)));
    }
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    if (!n00b_option_is_set(slot_opt)) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }
    auto ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    if (n00b_result_is_err(ref_r)) {
        return n00b_result_err(bool,
                               rocs_index_map_err(n00b_result_get_err(ref_r)));
    }
    if (!n00b_option_is_set(n00b_result_get(ref_r))) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_pos_t pos = {
        .shard_id   = shard_id,
        .ordinal    = ordinal,
        .generation = generation,
    };
    n00b_store_record_t *view = _rocs_record_view_new(pos,
                                                      nullptr,
                                                      shard,
                                                      .allocator = allocator);

    postings->mapped_shard = shard;
    n00b_list_push(*postings->records, view);
    auto pos_r = rocs_postings_add_pos(postings, pos);
    if (n00b_result_is_err(pos_r)) {
        return pos_r;
    }
    return n00b_result_ok(bool, true);
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
    uint8_t                    ngram_n   = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_store_postings_kind_t postings  = N00B_STORE_POSTINGS_SPARSE;
    n00b_allocator_t          *allocator = nullptr;
}
{
    if (!rocs_json_field_name_valid(field)) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_ARG);
    }
    if (!rocs_index_kind_known(kind)) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_KIND);
    }
    if (kind == N00B_STORE_INDEX_NGRAM) {
        if (!rocs_index_ngram_n_valid(ngram_n)) {
            return n00b_result_err(n00b_store_index_t *,
                                   N00B_STORE_INDEX_ERR_ARG);
        }
    }
    else if (ngram_n != N00B_STORE_NGRAM_DEFAULT_N) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_ARG);
    }
    if (!rocs_postings_kind_valid(postings)) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_ARG);
    }
    if ((kind == N00B_STORE_INDEX_NONE
         || kind == N00B_STORE_INDEX_NUMERIC
         || kind == N00B_STORE_INDEX_BOOL
         || kind == N00B_STORE_INDEX_VECTOR)
        && postings != N00B_STORE_POSTINGS_SPARSE) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_store_index_t *index = n00b_alloc_with_opts(
        n00b_store_index_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    index->field    = field;
    index->kind     = kind;
    index->postings = postings;
    index->ngram_n  = ngram_n;
    index->catch_all_fields = nullptr;
    index->catch_all        = false;

    return n00b_result_ok(n00b_store_index_t *, index);
}

n00b_result_t(n00b_store_index_t *)
n00b_store_index_new_catch_all(n00b_store_index_field_list_t *fields) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (fields == nullptr || n00b_list_len(*fields) == 0) {
        return n00b_result_err(n00b_store_index_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_store_index_t *index = n00b_alloc_with_opts(
        n00b_store_index_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    index->field            = nullptr;
    index->catch_all_fields = fields;
    index->kind             = N00B_STORE_INDEX_FULLTEXT;
    index->postings         = N00B_STORE_POSTINGS_SPARSE;
    index->ngram_n          = N00B_STORE_NGRAM_DEFAULT_N;
    index->catch_all        = true;

    return n00b_result_ok(n00b_store_index_t *, index);
}

n00b_result_t(bool)
n00b_store_index_is_catch_all(n00b_store_index_t *index)
{
    if (index == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    return n00b_result_ok(bool, index->catch_all);
}

n00b_result_t(n00b_store_index_kind_t)
n00b_store_index_kind(n00b_store_index_t *index)
{
    if (index == nullptr) {
        return n00b_result_err(n00b_store_index_kind_t, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_index_kind_t, index->kind);
}

n00b_result_t(uint8_t)
n00b_store_index_ngram_n(n00b_store_index_t *index)
{
    if (index == nullptr) {
        return n00b_result_err(uint8_t, N00B_STORE_INDEX_ERR_ARG);
    }
    if (index->kind != N00B_STORE_INDEX_NGRAM) {
        return n00b_result_err(uint8_t, N00B_STORE_INDEX_ERR_KIND);
    }
    if (!rocs_index_ngram_n_valid(index->ngram_n)) {
        return n00b_result_err(uint8_t, N00B_STORE_INDEX_ERR_STATE);
    }

    return n00b_result_ok(uint8_t, index->ngram_n);
}

n00b_result_t(n00b_store_postings_kind_t)
n00b_store_index_postings_kind(n00b_store_index_t *index)
{
    if (index == nullptr) {
        return n00b_result_err(n00b_store_postings_kind_t,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_postings_kind_t, index->postings);
}

n00b_result_t(n00b_string_t *)
n00b_store_index_field(n00b_store_index_t *index)
{
    if (index == nullptr || index->field == nullptr || index->catch_all) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(n00b_string_t *, index->field);
}

n00b_store_advert_t
n00b_store_index_advertise(n00b_store_index_t *index,
                           n00b_string_t      *field,
                           int64_t             op)
{
    if (index == nullptr || field == nullptr || index->field == nullptr
        || index->catch_all) {
        return (n00b_store_advert_t){
            .accelerates = false,
            .kind        = N00B_STORE_INDEX_NONE,
        };
    }

    bool same_field = n00b_unicode_str_eq(index->field, field);
    bool term_eq    = same_field
                   && index->kind == N00B_STORE_INDEX_TERM
                   && (op == (int64_t)N00B_STORE_INDEX_OP_UNSPECIFIED
                       || op == (int64_t)N00B_STORE_INDEX_OP_EQ);
    bool fulltext_contains = same_field
                          && index->kind == N00B_STORE_INDEX_FULLTEXT
                          && op == (int64_t)N00B_STORE_INDEX_OP_CONTAINS;
    bool ngram_text = same_field
                   && index->kind == N00B_STORE_INDEX_NGRAM
                   && op == (int64_t)N00B_STORE_INDEX_OP_PREFIX;
    bool accelerates = term_eq || fulltext_contains || ngram_text;
    return (n00b_store_advert_t){
        .accelerates      = accelerates,
        .kind             = term_eq ? N00B_STORE_INDEX_TERM
                                    : (fulltext_contains
                                           ? N00B_STORE_INDEX_FULLTEXT
                                           : (ngram_text
                                                  ? N00B_STORE_INDEX_NGRAM
                                                  : N00B_STORE_INDEX_NONE)),
        .selectivity_hint = fulltext_contains ? 0.05
                           : (term_eq ? 0.10
                                      : (ngram_text ? 0.20 : 1.0)),
    };
}

static n00b_result_t(n00b_store_postings_t *)
rocs_index_lookup_catch_all_terms(n00b_store_index_t            *index,
                                  n00b_store_shard_t            *shard,
                                  n00b_store_normalized_list_t  *terms) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index == nullptr || shard == nullptr || terms == nullptr
        || index->catch_all_fields == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t shard_id   = shard->shard_id;
    uint64_t generation = shard->seal_ts;
    size_t   term_len   = n00b_list_len(*terms);
    if (term_len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }
    if (term_len != 1) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_store_normalized_t *term = n00b_list_get(*terms, 0);
    auto                    key_r =
        rocs_term_key(N00B_STORE_INDEX_FULLTEXT, term, .allocator = allocator);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               n00b_result_get_err(key_r));
    }
    n00b_uint128_t key = n00b_result_get(key_r);

    n00b_store_posting_list_t *ordinals =
        rocs_posting_list_new(.allocator = allocator);
    size_t field_count = n00b_list_len(*index->catch_all_fields);
    for (size_t i = 0; i < field_count; i++) {
        n00b_string_t *field = n00b_list_get(*index->catch_all_fields, i);
        if (field == nullptr) {
            return n00b_result_err(n00b_store_postings_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        bool found_column = false;
        n00b_store_column_t *column = n00b_dict_get(shard->columns,
                                                    field,
                                                    &found_column);
        if (!found_column) {
            continue;
        }
        if (column == nullptr) {
            return n00b_result_err(n00b_store_postings_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        auto postings_r = rocs_column_postings_find(column, key);
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_posting_list_t *) postings_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(postings_opt)) {
            continue;
        }

        n00b_store_posting_list_t *postings = n00b_option_get(postings_opt);
        uint64_t                   len      = rocs_posting_list_len(postings);
        for (uint64_t j = 0; j < len; j++) {
            auto ordinal_r = rocs_posting_list_ordinal_at(postings, j);
            if (n00b_result_is_err(ordinal_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(ordinal_r));
            }
            uint64_t ordinal = n00b_result_get(ordinal_r);
            if (!rocs_posting_list_contains_ordinal(ordinals, ordinal)) {
                (void)rocs_posting_list_push(ordinals, ordinal, true);
            }
        }
    }

    n00b_store_posting_ordinal_list_t *ordinal_list = ordinals->ordinals;
    if (ordinal_list != nullptr) {
        rocs_posting_value_list_sort(ordinal_list);
    }

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    size_t len = ordinal_list == nullptr ? 0 : n00b_list_len(*ordinal_list);
    for (size_t i = 0; i < len; i++) {
        auto add_r = rocs_postings_add_hot(postings,
                                           shard,
                                           n00b_list_get(*ordinal_list, i),
                                           .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_postings_t *, postings);
}

static n00b_result_t(n00b_store_normalized_list_t *)
rocs_index_hot_terms(n00b_store_index_t *index,
                     n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index == nullptr || value == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    if (index->kind == N00B_STORE_INDEX_TERM) {
        auto terms_r = n00b_store_normalize_json(value,
                                                 .allocator = allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(
                n00b_store_normalized_list_t *,
                rocs_index_norm_err(n00b_result_get_err(terms_r)));
        }
        return terms_r;
    }

    if (index->kind == N00B_STORE_INDEX_FULLTEXT) {
        auto terms_r = n00b_store_normalize_text_tokens(
            value,
            .allocator = allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(
                n00b_store_normalized_list_t *,
                rocs_index_norm_err(n00b_result_get_err(terms_r)));
        }
        return terms_r;
    }

    if (index->kind == N00B_STORE_INDEX_NGRAM) {
        auto terms_r = n00b_store_normalize_text_ngrams(
            value,
            .ngram_n   = index->ngram_n,
            .allocator = allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(
                n00b_store_normalized_list_t *,
                rocs_index_norm_err(n00b_result_get_err(terms_r)));
        }
        return terms_r;
    }

    return n00b_result_err(n00b_store_normalized_list_t *,
                           N00B_STORE_INDEX_ERR_UNREADY);
}

static n00b_result_t(n00b_store_normalized_list_t *)
rocs_index_hot_query_terms(n00b_store_index_t *index,
                           n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto terms_r = rocs_index_hot_terms(index,
                                        value,
                                        .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return terms_r;
    }

    n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
    if (index->kind == N00B_STORE_INDEX_FULLTEXT) {
        if (n00b_list_len(*terms) == 0) {
            return n00b_result_err(n00b_store_normalized_list_t *,
                                   N00B_STORE_INDEX_ERR_ARG);
        }
        if (n00b_list_len(*terms) == 1) {
            return n00b_result_ok(n00b_store_normalized_list_t *, terms);
        }

        n00b_store_normalized_list_t *query_terms = n00b_alloc_with_opts(
            n00b_store_normalized_list_t,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
            });
        *query_terms = n00b_list_new_private(n00b_store_normalized_t *,
                                             .allocator = allocator,
                                             .scan_kind = N00B_GC_SCAN_KIND_ALL);
        n00b_list_push(*query_terms, n00b_list_get(*terms, 0));
        return n00b_result_ok(n00b_store_normalized_list_t *, query_terms);
    }
    if (index->kind == N00B_STORE_INDEX_NGRAM
        && n00b_list_len(*terms) == 0) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_normalized_list_t *, terms);
}

static bool
rocs_index_unique_postings(n00b_store_index_kind_t kind)
{
    return kind == N00B_STORE_INDEX_FULLTEXT
        || kind == N00B_STORE_INDEX_NGRAM;
}

static n00b_result_t(bool)
rocs_posting_list_push(n00b_store_posting_list_t *postings,
                       uint64_t                   ordinal,
                       bool                       unique)
{
    if (postings == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    bool already_present = postings->kind == N00B_STORE_POSTINGS_DENSE
                         || unique;
    if (already_present
        && rocs_posting_list_contains_ordinal(postings, ordinal)) {
        return n00b_result_ok(bool, false);
    }
    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        n00b_flagset_set_index(postings->flags, (int64_t)ordinal, true);
        postings->count++;
        return n00b_result_ok(bool, true);
    }
    if (postings->ordinals == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }
    if (!unique) {
        n00b_list_push(*postings->ordinals, ordinal);
        postings->count++;
        return n00b_result_ok(bool, true);
    }
    n00b_list_push(*postings->ordinals, ordinal);
    postings->count++;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(uint64_t)
rocs_index_add_terms(n00b_store_index_t            *index,
                     n00b_store_shard_t            *shard,
                     uint64_t                       record_ordinal,
                     n00b_store_normalized_list_t  *terms) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index == nullptr || shard == nullptr || terms == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }

    size_t len = n00b_list_len(*terms);
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

        auto postings_r = rocs_column_postings_get_or_create(
            column,
            n00b_result_get(key_r),
            index->postings);
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(postings_r));
        }

        auto push_r = rocs_posting_list_push(
            n00b_result_get(postings_r),
            record_ordinal,
            rocs_index_unique_postings(index->kind));
        if (n00b_result_is_err(push_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(push_r));
        }
        if (n00b_result_get(push_r)) {
            added++;
        }
    }

    return n00b_result_ok(uint64_t, added);
}

static n00b_result_t(n00b_store_postings_t *)
rocs_index_lookup_terms(n00b_store_index_t            *index,
                        n00b_store_shard_t            *shard,
                        n00b_store_normalized_list_t  *terms) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index == nullptr || shard == nullptr || terms == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t shard_id   = shard->shard_id;
    uint64_t generation = shard->seal_ts;
    size_t   len        = n00b_list_len(*terms);
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
        if (rocs_posting_list_len(candidates) == 0) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }
    }

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    uint64_t candidate_len = rocs_posting_list_len(candidates);
    for (uint64_t i = 0; i < candidate_len; i++) {
        auto ordinal_r = rocs_posting_list_ordinal_at(candidates, i);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(ordinal_r));
        }
        auto add_r = rocs_postings_add_hot(postings,
                                           shard,
                                           n00b_result_get(ordinal_r),
                                           .allocator = allocator);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_postings_t *, postings);
}

static n00b_result_t(n00b_store_postings_t *)
rocs_index_lookup_mapped_terms(n00b_store_index_t           *index,
                               n00b_store_map_shard_t      *shard,
                               n00b_store_map_list_t       *records,
                               n00b_store_map_dict_t       *columns,
                               n00b_store_normalized_list_t *terms,
                               uint64_t                     shard_id,
                               uint64_t                     generation) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index == nullptr || shard == nullptr || records == nullptr
        || columns == nullptr || terms == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    size_t len = n00b_list_len(*terms);
    if (len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }

    auto column_r = rocs_mapped_column_find(columns, index->field);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               n00b_result_get_err(column_r));
    }

    n00b_option_t(n00b_store_map_dict_t *) column_opt =
        n00b_result_get(column_r);
    if (!n00b_option_is_set(column_opt)) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }
    n00b_store_map_dict_t *column = n00b_option_get(column_opt);

    rocs_posting_value_list_t *candidates = nullptr;
    for (size_t i = 0; i < len; i++) {
        n00b_store_normalized_t *term = n00b_list_get(*terms, i);
        auto                    key_r = rocs_term_key(index->kind,
                                                      term,
                                                      .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(key_r));
        }

        auto postings_r =
            rocs_mapped_column_postings_find(column, n00b_result_get(key_r));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_map_posting_list_t *) current_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(current_opt)) {
            return rocs_empty_postings(shard_id,
                                       generation,
                                       .allocator = allocator);
        }
        n00b_store_map_posting_list_t *current = n00b_option_get(current_opt);

        if (candidates == nullptr) {
            auto first_r =
                rocs_posting_value_list_from_mapped_postings(
                    current,
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
                                              current,
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

    auto record_count_r = n00b_store_map_list_len(records);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(
                                   record_count_r)));
    }
    uint64_t record_count = n00b_result_get(record_count_r);

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    rocs_posting_value_list_t *ordinals =
        rocs_posting_value_list_new(.allocator = allocator);
    size_t candidate_len = n00b_list_len(*candidates);
    for (size_t i = 0; i < candidate_len; i++) {
        auto ordinal_r = rocs_mapped_posting_to_ordinal(
            n00b_list_get(*candidates, i),
            record_count);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(ordinal_r));
        }

        rocs_posting_value_list_push_unique(ordinals,
                                            n00b_result_get(ordinal_r));
    }

    rocs_posting_value_list_sort(ordinals);
    size_t ordinal_len = n00b_list_len(*ordinals);
    for (size_t i = 0; i < ordinal_len; i++) {
        auto add_r = rocs_postings_add_mapped_pos(
            postings,
            shard,
            n00b_list_get(*ordinals, i),
            record_count,
            shard_id,
            generation);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_postings_t *, postings);
}

static n00b_result_t(n00b_store_postings_t *)
rocs_index_lookup_mapped_catch_all_terms(
    n00b_store_index_t           *index,
    n00b_store_map_shard_t       *shard,
    n00b_store_map_list_t        *records,
    n00b_store_map_dict_t        *columns,
    n00b_store_normalized_list_t *terms,
    uint64_t                      shard_id,
    uint64_t                      generation) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index == nullptr || shard == nullptr || records == nullptr
        || columns == nullptr || terms == nullptr
        || index->catch_all_fields == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    size_t term_len = n00b_list_len(*terms);
    if (term_len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }
    if (term_len != 1) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_store_normalized_t *term = n00b_list_get(*terms, 0);
    auto                    key_r =
        rocs_term_key(N00B_STORE_INDEX_FULLTEXT, term, .allocator = allocator);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               n00b_result_get_err(key_r));
    }

    rocs_posting_value_list_t *candidates =
        rocs_posting_value_list_new(.allocator = allocator);
    size_t field_count = n00b_list_len(*index->catch_all_fields);
    for (size_t i = 0; i < field_count; i++) {
        n00b_string_t *field = n00b_list_get(*index->catch_all_fields, i);
        if (field == nullptr) {
            return n00b_result_err(n00b_store_postings_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }

        auto column_r = rocs_mapped_column_find(columns, field);
        if (n00b_result_is_err(column_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(column_r));
        }
        n00b_option_t(n00b_store_map_dict_t *) column_opt =
            n00b_result_get(column_r);
        if (!n00b_option_is_set(column_opt)) {
            continue;
        }

        auto postings_r = rocs_mapped_column_postings_find(
            n00b_option_get(column_opt),
            n00b_result_get(key_r));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }
        n00b_option_t(n00b_store_map_posting_list_t *) postings_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(postings_opt)) {
            continue;
        }

        n00b_store_map_posting_list_t *mapped_postings =
            n00b_option_get(postings_opt);
        auto len_r = n00b_store_map_posting_list_len(mapped_postings);
        if (n00b_result_is_err(len_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   rocs_index_map_err(n00b_result_get_err(len_r)));
        }
        uint64_t len = n00b_result_get(len_r);
        for (uint64_t j = 0; j < len; j++) {
            auto raw_r = n00b_store_map_posting_list_ordinal_at(mapped_postings,
                                                                j);
            if (n00b_result_is_err(raw_r)) {
                return n00b_result_err(
                    n00b_store_postings_t *,
                    rocs_index_map_err(n00b_result_get_err(raw_r)));
            }
            uint64_t raw = n00b_result_get(raw_r);
            rocs_posting_value_list_push_unique(candidates, raw);
        }
    }

    auto record_count_r = n00b_store_map_list_len(records);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(
                                   record_count_r)));
    }
    uint64_t record_count = n00b_result_get(record_count_r);

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    rocs_posting_value_list_t *ordinals =
        rocs_posting_value_list_new(.allocator = allocator);
    size_t candidate_len = n00b_list_len(*candidates);
    for (size_t i = 0; i < candidate_len; i++) {
        auto ordinal_r = rocs_mapped_posting_to_ordinal(
            n00b_list_get(*candidates, i),
            record_count);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(ordinal_r));
        }

        rocs_posting_value_list_push_unique(ordinals,
                                            n00b_result_get(ordinal_r));
    }

    rocs_posting_value_list_sort(ordinals);
    size_t ordinal_len = n00b_list_len(*ordinals);
    for (size_t i = 0; i < ordinal_len; i++) {
        auto add_r = rocs_postings_add_mapped_pos(
            postings,
            shard,
            n00b_list_get(*ordinals, i),
            record_count,
            shard_id,
            generation);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(add_r));
        }
    }

    return n00b_result_ok(n00b_store_postings_t *, postings);
}

n00b_result_t(uint64_t)
n00b_store_index_add(n00b_store_index_t *index,
                     n00b_store_shard_t *shard,
                     uint64_t            record_ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (index != nullptr && index->catch_all) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_UNREADY);
    }

    n00b_err_t ready = rocs_index_hot_ready(index);
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

    auto record_r = rocs_hot_shard_record_json(shard,
                                               record_ordinal,
                                               .allocator = allocator);
    if (n00b_result_is_err(record_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(record_r));
    }
    n00b_json_node_t *record = n00b_result_get(record_r);

    n00b_json_node_t *field_value =
        rocs_json_object_get_field(record, index->field);
    if (field_value == nullptr) {
        return n00b_result_ok(uint64_t, 0);
    }
    if ((index->kind == N00B_STORE_INDEX_FULLTEXT
         || index->kind == N00B_STORE_INDEX_NGRAM)
        && !n00b_json_is_string(field_value)) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto terms_r = rocs_index_hot_terms(index,
                                        field_value,
                                        .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(terms_r));
    }

    return rocs_index_add_terms(index,
                                shard,
                                record_ordinal,
                                n00b_result_get(terms_r),
                                .allocator = allocator);
}

n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup(n00b_store_index_t *index,
                        n00b_store_shard_t *shard,
                        n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
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

    auto terms_r = rocs_index_hot_query_terms(index,
                                              value,
                                              .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               n00b_result_get_err(terms_r));
    }

    if (index->catch_all) {
        return rocs_index_lookup_catch_all_terms(index,
                                                 shard,
                                                 n00b_result_get(terms_r),
                                                 .allocator = allocator);
    }

    return rocs_index_lookup_terms(index,
                                   shard,
                                   n00b_result_get(terms_r),
                                   .allocator = allocator);
}

n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup_mapped(n00b_store_index_t     *index,
                               n00b_store_map_shard_t *shard,
                               n00b_json_node_t       *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
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

    auto terms_r = rocs_index_hot_query_terms(index,
                                              value,
                                              .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               n00b_result_get_err(terms_r));
    }

    n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);

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

    if (index->catch_all) {
        return rocs_index_lookup_mapped_catch_all_terms(
            index,
            shard,
            n00b_result_get(records_r),
            n00b_result_get(columns_r),
            terms,
            shard_id,
            generation,
            .allocator = allocator);
    }

    return rocs_index_lookup_mapped_terms(index,
                                          shard,
                                          n00b_result_get(records_r),
                                          n00b_result_get(columns_r),
                                          terms,
                                          shard_id,
                                          generation,
                                          .allocator = allocator);
}

static n00b_store_index_stats_t
rocs_index_stats_from_counts(uint64_t record_count, uint64_t df)
{
    return (n00b_store_index_stats_t){
        .record_count       = record_count,
        .document_frequency = df,
        .selectivity        = record_count == 0
                                  ? 0.0
                                  : (double)df / (double)record_count,
    };
}

n00b_result_t(n00b_store_index_stats_t)
n00b_store_index_stats_hot(n00b_store_index_t *index,
                           n00b_store_shard_t *shard,
                           n00b_json_node_t   *value)
{
    if (shard == nullptr) {
        return n00b_result_err(n00b_store_index_stats_t,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto postings_r = n00b_store_index_lookup(index, shard, value);
    if (n00b_result_is_err(postings_r)) {
        return n00b_result_err(n00b_store_index_stats_t,
                               n00b_result_get_err(postings_r));
    }

    auto len_r = n00b_store_postings_len(n00b_result_get(postings_r));
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_store_index_stats_t,
                               n00b_result_get_err(len_r));
    }

    return n00b_result_ok(
        n00b_store_index_stats_t,
        rocs_index_stats_from_counts(shard->record_count,
                                     n00b_result_get(len_r)));
}

n00b_result_t(n00b_store_index_stats_t)
n00b_store_index_stats_mapped(n00b_store_index_t     *index,
                              n00b_store_map_shard_t *shard,
                              n00b_json_node_t       *value)
{
    if (shard == nullptr) {
        return n00b_result_err(n00b_store_index_stats_t,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto record_count_r = n00b_store_map_shard_records_len(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(
            n00b_store_index_stats_t,
            rocs_index_map_err(n00b_result_get_err(record_count_r)));
    }

    auto postings_r = n00b_store_index_lookup_mapped(index, shard, value);
    if (n00b_result_is_err(postings_r)) {
        return n00b_result_err(n00b_store_index_stats_t,
                               n00b_result_get_err(postings_r));
    }

    auto len_r = n00b_store_postings_len(n00b_result_get(postings_r));
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_store_index_stats_t,
                               n00b_result_get_err(len_r));
    }

    return n00b_result_ok(
        n00b_store_index_stats_t,
        rocs_index_stats_from_counts(n00b_result_get(record_count_r),
                                     n00b_result_get(len_r)));
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
    if (postings == nullptr || postings->positions == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*postings->positions));
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_store_postings_pos(n00b_store_postings_t *postings, uint64_t ordinal)
{
    if (postings == nullptr || postings->positions == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*postings->positions);
    if (ordinal >= len) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_store_pos_t),
        n00b_option_set(n00b_store_pos_t,
                        n00b_list_get(*postings->positions, ordinal)));
}

n00b_result_t(n00b_option_t(n00b_store_posting_t))
n00b_store_postings_get(n00b_store_postings_t *postings, uint64_t ordinal)
{
    if (postings == nullptr || postings->records == nullptr
        || postings->positions == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_posting_t),
                               N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*postings->positions);
    if (ordinal >= len) {
        return n00b_result_ok(n00b_option_t(n00b_store_posting_t),
                              n00b_option_none(n00b_store_posting_t));
    }

    n00b_store_pos_t     pos    = n00b_list_get(*postings->positions, ordinal);
    n00b_store_record_t *record = nullptr;
    if (ordinal < (uint64_t)n00b_list_len(*postings->records)) {
        record = n00b_list_get(*postings->records, ordinal);
    }
    if (record == nullptr && postings->hot_shard != nullptr) {
        record = _rocs_record_view_new(pos,
                                       postings->hot_shard,
                                       nullptr,
                                       .allocator =
                                           postings->records->allocator);
    }
    if (record == nullptr && postings->mapped_shard != nullptr) {
        record = _rocs_record_view_new(pos,
                                       nullptr,
                                       postings->mapped_shard,
                                       .allocator =
                                           postings->records->allocator);
    }
    if (record == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_posting_t),
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_posting_t posting = {
        .pos    = pos,
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

    // Validation-only handles; the returned view holds pos+shard, not these.
    // Recycle them into the per-query view pool so per-record reads don't
    // accumulate a slot+ref per row.
    n00b_free(n00b_option_get(slot_opt));
    n00b_free(n00b_option_get(n00b_result_get(ref_r)));

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

    // These slot/ref handles were only used to validate the record exists; the
    // returned view holds pos+shard, not them. Free them back to the per-query
    // view pool so per-record delivery doesn't accumulate a slot+ref per row.
    n00b_free(n00b_option_get(slot_opt));
    n00b_free(n00b_option_get(n00b_result_get(ref_r)));

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

        return rocs_hot_shard_record_json(shard,
                                          record->pos.ordinal,
                                          .allocator = allocator);
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

    return rocs_json_node_copy(n00b_result_get(json_r),
                               .allocator = allocator);
}

// Serialize a JSON node graph to a compact n00b string. n00b_json_encode is a
// char*-returning API with no allocator kwarg, so the char* boundary is
// confined here in a static helper (per the n00b char*-in-static-.c-helper
// exception). The returned string honors `allocator`; the transient encode
// buffer is default-allocated and freed immediately, so it never persists in
// the wrong arena.
static n00b_result_t(n00b_string_t *)
rocs_json_node_to_string(n00b_json_node_t *node, n00b_allocator_t *allocator)
{
    char *encoded = n00b_json_encode(node, .pretty = false);
    if (encoded == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_STATE);
    }
    n00b_string_t *text = n00b_string_from_cstr(encoded, .allocator = allocator);
    n00b_free(encoded);
    return n00b_result_ok(n00b_string_t *, text);
}

n00b_result_t(n00b_string_t *)
n00b_store_record_view_json_string(n00b_store_record_t *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (record == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_ARG);
    }
    if (record->owned_json == nullptr && record->hot_shard == nullptr
        && record->mapped_shard == nullptr) {
        // Malformed/empty record: no backing for any path.
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    // Fast path: a sealed mapped record is persisted as a compact JSON string
    // in the read-only image. Return those bytes verbatim — no parse, no node
    // graph, no re-encode. This is the egress drain's hot path; parsing and
    // re-encoding every record was the dominant GC-heap allocation source.
    if (record->owned_json == nullptr && record->hot_shard == nullptr) {
        auto str_r = n00b_store_map_shard_record_json_string(
            record->mapped_shard,
            record->pos.ordinal,
            .allocator = allocator);
        if (n00b_result_is_err(str_r)) {
            return n00b_result_err(n00b_string_t *,
                                   rocs_index_map_err(
                                       n00b_result_get_err(str_r)));
        }
        return n00b_result_ok(n00b_string_t *, n00b_result_get(str_r));
    }

    // Hot / already-owned records: materialize the node graph, then encode it
    // compact. (Not the egress hot path; correctness for general callers.)
    auto json_r = n00b_store_record_view_json(record, .allocator = allocator);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(json_r));
    }
    return rocs_json_node_to_string(n00b_result_get(json_r), allocator);
}
