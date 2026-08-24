#include "rocs/index.h"

#include "adt/list.h"
#include "core/hash.h"
#include <stdio.h>
#include <stdlib.h>

#include "internal/rocs/index.h"
#include "internal/rocs/store.h"
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
    // Stored compact JSON copied verbatim out of a hot shard. Mutually
    // exclusive with owned_json on construction; n00b_store_record_view_json
    // parses it into owned_json on the first caller that wants a node graph.
    n00b_string_t            *owned_text;
};

typedef n00b_list_t(n00b_uint128_t) rocs_index_key_list_t;
typedef n00b_list_t(n00b_store_posting_list_t *) rocs_hot_posting_list_t;
typedef n00b_list_t(n00b_store_map_posting_list_t *) rocs_mapped_posting_list_t;

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
    view->owned_text   = nullptr;
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
    if (ordinal >= len) {
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

// Sibling of rocs_hot_shard_record_json that stops at the stored bytes. A hot
// shard already holds each record as compact JSON, so a caller that wants the
// JSON *string* needs a copy of those bytes and nothing else -- no parse, no
// node graph, no re-encode. Mirrors what the sealed path gets for free from the
// mapped image (n00b_store_map_shard_record_json_string).
n00b_result_t(n00b_string_t *)
rocs_hot_shard_record_text(n00b_store_shard_t *shard,
                           uint64_t            ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (shard == nullptr || shard->records == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_ARG);
    }

    // Live callers bound ordinals by the post-fill publication watermark.
    uint64_t len = (uint64_t)n00b_list_len(*shard->records);
    if (ordinal >= len) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_string_t *text = n00b_list_get(*shard->records, (size_t)ordinal);
    if (text == nullptr || (text->u8_bytes != 0 && text->data == nullptr)) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_string_t *copy = n00b_string_from_raw(text->data,
                                               (int64_t)text->u8_bytes,
                                               .allocator = allocator);
    if (copy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_INDEX_ERR_STATE);
    }

    return n00b_result_ok(n00b_string_t *, copy);
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
    // Empty, so trivially ascending; pushes clear this when one lands low.
    n00b_atomic_store(&postings->reserved, N00B_STORE_POSTINGS_ORDERED);
    n00b_atomic_store(&postings->count, 0);
    postings->ordinals = nullptr;
    postings->flags    = nullptr;

    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        // Locked. Setting a bit is a read-modify-write of the 64-bit word it
        // sits in, so two writers on ordinals 8 apart are writing the same
        // location and one of them loses the other's bit. Growing the bitmap
        // is worse: it allocates, copies and frees, under readers holding the
        // old pointer. Neither is hypothetical: two threads indexing one
        // dense field drop records outright, and crash more often than not.
        //
        // Same allocator as the set it guards, which n00b_flagset_init
        // arranges, so the lock has the lifetime and non-moving properties the
        // ordinals lock below is chosen for.
        postings->flags = n00b_flagset_new(.length    = 64,
                                           .locked    = true,
                                           .allocator = allocator);
        n00b_lock_set_debug_name(postings->flags->lock,
                                 "rocs dense postings");
        // Inside a posting list, so it ranks below one. A list is sparse or
        // dense and never both, so the two are not nested; ranking it costs
        // nothing and means a future nesting is reported rather than found.
        n00b_lock_set_rank(postings->flags->lock, N00B_LOCK_RANK_FLAGSET);
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
        // Same allocator as the list it guards. A store's hot pool is
        // non-moving and freed wholesale at seal or retire, so the lock
        // neither relocates under a futex waiter nor outlives the shard.
        // Callers without a store pass a pool with the same properties; the
        // default moving heap would relocate it.
        //
        // The runtime system pool would also never move, but never frees
        // either: one rwlock per distinct term per field per shard. Pinning
        // individual allocations would drop the constraint altogether, but
        // that GC work is designed and unbuilt
        // (doc/gc-mostly-copying-pinning.md).
        postings->ordinals->lock = n00b_data_lock_new(.allocator = allocator);
        n00b_lock_set_debug_name(postings->ordinals->lock,
                                 "rocs posting ordinals");
        n00b_lock_set_rank(postings->ordinals->lock, N00B_LOCK_RANK_POSTINGS);
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
    return postings->flags == nullptr ? 0 : n00b_flagset_count(postings->flags);
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

    if (postings->flags == nullptr
        || index >= n00b_flagset_count(postings->flags)) {
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
                   .locked          = true,
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
    if (stored_field == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_INDEX_ERR_INTERNAL);
    }
    if (n00b_dict_add(shard->columns, stored_field, column)) {
        return n00b_result_ok(n00b_store_column_t *, column);
    }

    column = n00b_dict_get(shard->columns, field, &found);
    if (!found || column == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }
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
    if (postings == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_INDEX_ERR_INTERNAL);
    }
    if (n00b_dict_add(column, key, postings)) {
        return n00b_result_ok(n00b_store_posting_list_t *, postings);
    }

    postings = n00b_dict_get(column, key, &found);
    if (!found || postings == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }
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

// Put a sparse list in ascending order, and drop repeats.
//
// For the list's owner only: sealing, or a caller ordering a list it just
// built. A reader must not call this. It takes the write lock and renumbers
// the list, so a reader that called it would be mutating shared state to
// answer a question, and would shift the elements under any other reader
// walking the same list positionally. Readers that want order either take a
// private copy and sort that (rocs_posting_snapshot_ordinals) or consult
// N00B_STORE_POSTINGS_ORDERED and scan when it is clear.
//
// Pushes append, so a list stays ascending until an ordinal arrives below the
// tail. Ordering here rather than placing on arrival is what keeps indexing n
// records O(n) instead of O(n^2) when a caller supplies them in any order but
// ascending, which n00b_store_index_add permits.
void
rocs_posting_list_ensure_ordered(n00b_store_posting_list_t *postings)
{
    if (postings == nullptr || postings->kind != N00B_STORE_POSTINGS_SPARSE
        || postings->ordinals == nullptr) {
        return;
    }
    if ((n00b_atomic_load(&postings->reserved)
         & N00B_STORE_POSTINGS_ORDERED)
        != 0) {
        return;
    }

    _n00b_list_write_lock(postings->ordinals);

    // Re-checked under the lock: another writer may have sorted it between the
    // test above and here.
    if ((n00b_atomic_load(&postings->reserved) & N00B_STORE_POSTINGS_ORDERED) == 0) {
        size_t len = postings->ordinals->len;
        if (len > 1) {
            // Sorted through the raw array rather than n00b_list_sort: the
            // write lock is already held here, and the list API takes it.
            qsort(postings->ordinals->data, len, sizeof(uint64_t),
                  rocs_u64_compare);

            size_t out = 1;
            for (size_t i = 1; i < len; i++) {
                if (postings->ordinals->data[i]
                    != postings->ordinals->data[out - 1]) {
                    postings->ordinals->data[out++]
                        = postings->ordinals->data[i];
                }
            }
            postings->ordinals->len = out;
            n00b_atomic_store(&postings->count, (uint64_t)out);
        }
        n00b_atomic_store(&postings->reserved,
                          n00b_atomic_load(&postings->reserved)
                              | N00B_STORE_POSTINGS_ORDERED);
    }

    _n00b_list_unlock(postings->ordinals);
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

    // Note this is not the push path's tail check, which is a dedup predicate
    // and answers membership only for the ordinal being appended.
    //
    // One lock for the whole search, not one per step. A search that took the
    // lock per access would see each element intact and still answer wrongly:
    // an insert below the tail shifts everything above it, so the halves this
    // has already ruled out stop describing the list it is still searching,
    // and an ordinal that is present reads as absent. Held across the search,
    // the list cannot move under it. The push side holds the write lock over
    // the same span for the same reason.
    _n00b_list_read_lock(postings->ordinals);

    // The order bit is read under the same lock as the data it describes.
    // Push clears it while holding the write lock, so a reader cannot see the
    // bit set and an out-of-order element already appended past it, which is
    // a binary search over data that stopped being sorted underneath it.
    // An unordered list is scanned, which is right regardless and is what the
    // sealed reader does with the same bit clear.
    if ((n00b_atomic_load(&postings->reserved) & N00B_STORE_POSTINGS_ORDERED) == 0) {
        bool   hit = false;
        size_t len = postings->ordinals->len;
        for (size_t i = 0; i < len; i++) {
            if (postings->ordinals->data[i] == ordinal) {
                hit = true;
                break;
            }
        }
        _n00b_list_unlock(postings->ordinals);
        return hit;
    }

    uint64_t lo    = 0;
    uint64_t hi    = (uint64_t)postings->ordinals->len;
    bool     found = false;
    while (lo < hi) {
        uint64_t mid   = lo + (hi - lo) / 2;
        uint64_t value = postings->ordinals->data[mid];
        if (value == ordinal) {
            found = true;
            break;
        }
        if (value < ordinal) {
            lo = mid + 1;
        }
        else {
            hi = mid;
        }
    }
    _n00b_list_unlock(postings->ordinals);
    return found;
}

// A private copy of a sparse list's ordinals, taken under one lock.
//
// Walking the live list by index takes the lock per element, so the list can
// change between two of them: pushes append, and a sort in place renumbers
// (rocs_posting_list_ensure_ordered). A walk that sampled the length and then
// read elements one at a time could see an element twice and never see
// another, which drops a record from the answer. One copy under one lock
// cannot straddle either mutation.
//
// A copy rather than holding the lock across the walk: callers do work per
// element that takes another posting list's lock, and holding both would let
// two queries pairing the same lists in opposite orders deadlock.
//
// Dense lists are returned as null and walked in place. That walk addresses by
// rank, counting set bits from zero, so it stays sound only while bits arrive
// above the current maximum. Store ingest gives it that, taking ordinals from
// n00b_store_shard_reserve in order under the store's commit_lock. A caller
// pushing out of order through n00b_store_index_add while a reader walks does
// not, and n00b_store_index_add does not constrain arrival order.
static uint64_t *
rocs_posting_snapshot_ordinals(n00b_store_posting_list_t *postings,
                               uint64_t                  *len_out,
                               n00b_allocator_t          *allocator)
{
    *len_out = 0;
    if (postings == nullptr || postings->kind != N00B_STORE_POSTINGS_SPARSE
        || postings->ordinals == nullptr) {
        return nullptr;
    }

    _n00b_list_read_lock(postings->ordinals);
    uint64_t  len     = (uint64_t)postings->ordinals->len;
    bool      ordered = (n00b_atomic_load(&postings->reserved)
                         & N00B_STORE_POSTINGS_ORDERED)
                     != 0;
    uint64_t *copy    = nullptr;
    if (len != 0) {
        copy = n00b_alloc_array_with_opts(
            uint64_t,
            (size_t)len,
            &(n00b_alloc_opts_t){.allocator = allocator,
                                 .scan_kind = N00B_GC_SCAN_KIND_NONE});
        memcpy(copy, postings->ordinals->data, (size_t)len * sizeof(uint64_t));
    }
    _n00b_list_unlock(postings->ordinals);

    // Callers walk this ascending. Sorted here, on the private copy, rather
    // than by ordering the shared list: a reader that sorted what it was
    // reading would be taking a write lock to answer a question, and would
    // renumber the list under any other reader walking it positionally.
    if (!ordered && len > 1) {
        qsort(copy, (size_t)len, sizeof(uint64_t), rocs_u64_compare);
    }

    *len_out = len;
    return copy;
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

    uint64_t  len  = 0;
    uint64_t *snap = rocs_posting_snapshot_ordinals(candidates,
                                                    &len,
                                                    allocator);
    if (snap == nullptr) {
        len = rocs_posting_list_len(candidates);
    }

    for (uint64_t i = 0; i < len; i++) {
        uint64_t ordinal;
        if (snap != nullptr) {
            ordinal = snap[i];
        }
        else {
            auto ordinal_r = rocs_posting_list_ordinal_at(candidates, i);
            if (n00b_result_is_err(ordinal_r)) {
                return filtered;
            }
            ordinal = n00b_result_get(ordinal_r);
        }
        if (rocs_posting_list_contains_ordinal(current, ordinal)) {
            (void)rocs_posting_list_push(filtered, ordinal, true);
        }
    }
    // Built by appending in candidate order, which callers read positionally.
    rocs_posting_list_ensure_ordered(filtered);
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

n00b_result_t(n00b_store_index_field_list_t *)
n00b_store_index_catch_all_fields(n00b_store_index_t *index)
{
    if (index == nullptr || !index->catch_all) {
        return n00b_result_err(n00b_store_index_field_list_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_index_field_list_t *,
                          index->catch_all_fields);
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

        n00b_store_normalized_t *term = n00b_list_get(*terms, 0);
        auto key_r = rocs_term_key(N00B_STORE_INDEX_FULLTEXT,
                                   term,
                                   .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(key_r));
        }

        auto postings_r =
            rocs_column_postings_find(column, n00b_result_get(key_r));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_posting_list_t *) postings_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(postings_opt)) {
            continue;
        }

        n00b_store_posting_list_t *field_candidates =
            n00b_option_get(postings_opt);
        // Walked positionally in whatever order the list holds, because the
        // merged list below is ordered once, after every field is in. A
        // concurrent writer only adds past the sampled length: a sparse list
        // appends, and a dense one gains bits above its maximum because store
        // ingest assigns ordinals in order under commit_lock. See
        // rocs_posting_snapshot_ordinals for what that rests on.
        uint64_t len = rocs_posting_list_len(field_candidates);
        for (uint64_t j = 0; j < len; j++) {
            auto ordinal_r = rocs_posting_list_ordinal_at(field_candidates, j);
            if (n00b_result_is_err(ordinal_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(ordinal_r));
            }
            uint64_t ordinal = n00b_result_get(ordinal_r);
            (void)rocs_posting_list_push(ordinals, ordinal, true);
        }
    }

    // Each field's list is ascending on its own, but they are concatenated
    // here, so the merged list is not. This both orders it and drops the
    // ordinals that more than one covered field carried, which is the dedup
    // the union needs, and which the push path catches only for arrivals that
    // are consecutive.
    rocs_posting_list_ensure_ordered(ordinals);

    n00b_store_posting_ordinal_list_t *ordinal_list = ordinals->ordinals;

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

        // Indexing a multi-token value stores the whole value as a term
        // beside each token. Looking the whole value up would ask for a field
        // equal to it, so a query is reduced to its tokens and the lookup
        // intersects them. That is the whole-token containment a record scan
        // performs, which is what makes an indexed query and an unindexed one
        // answer alike.
        auto tokens_r = n00b_store_normalize_text_tokens(
            value,
            .include_full_value = false,
            .allocator          = allocator);
        if (n00b_result_is_err(tokens_r)) {
            return n00b_result_err(
                n00b_store_normalized_list_t *,
                rocs_index_norm_err(n00b_result_get_err(tokens_r)));
        }
        n00b_store_normalized_list_t *tokens = n00b_result_get(tokens_r);
        if (n00b_list_len(*tokens) == 0) {
            return n00b_result_err(n00b_store_normalized_list_t *,
                                   N00B_STORE_INDEX_ERR_ARG);
        }
        return n00b_result_ok(n00b_store_normalized_list_t *, tokens);
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

n00b_result_t(bool)
rocs_posting_list_push(n00b_store_posting_list_t *postings,
                       uint64_t                   ordinal,
                       bool                       unique)
{
    if (postings == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        if (postings->flags == nullptr) {
            return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
        }
        // The bit and the count move together, under the set's own write
        // lock. Taking it per operation instead lets a reader land between
        // them and see a member the count does not describe. The rwlock is
        // reentrant, so the locked entry point below is safe to call inside
        // this hold.
        //
        // The count is kept rather than popcounted because a count read is
        // O(1) that way, where popcounting the bitmap is a pass over
        // record_count/64 words on every df read.
        n00b_flagset_write_lock(postings->flags);
        bool old = n00b_flagset_test_and_set_index(postings->flags,
                                                   (int64_t)ordinal,
                                                   true);
        if (!old) {
            n00b_atomic_add(&postings->count, 1);
        }

        n00b_flagset_unlock(postings->flags);
        return n00b_result_ok(bool, !old);
    }
    if (postings->ordinals == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }

    _n00b_list_write_lock(postings->ordinals);
    size_t len = postings->ordinals->len;

    // Ascending order is a property readers want, not a promise asked of
    // callers, so it is established when a reader needs it rather than on
    // every push. n00b_store_index_add is public and does not constrain
    // arrival order; placing each ordinal on arrival would cost a descending
    // caller a shift per element, and quadratic time overall.
    //
    // Appending instead is O(1) whatever the order, and an append that lands
    // below the tail clears N00B_STORE_POSTINGS_ORDERED. That bit is what
    // rocs_posting_list_contains_ordinal consults before binary-searching; a
    // list that loses it stays unordered and is scanned until sealing sorts
    // it, which costs speed on a hot shard and nothing on a sealed image.
    //
    // The tail check below still catches the duplicate that actually occurs: a
    // full-text or n-gram field emitting the same term twice pushes the same
    // ordinal twice in a row. A duplicate arriving non-consecutively survives
    // until the sort, which drops it.
    if (len != 0) {
        uint64_t last = postings->ordinals->data[len - 1];

        if (unique && ordinal == last) {
            _n00b_list_unlock(postings->ordinals);
            return n00b_result_ok(bool, false);
        }
        if (ordinal < last) {
            n00b_atomic_store(&postings->reserved,
                              n00b_atomic_load(&postings->reserved)
                                  & ~N00B_STORE_POSTINGS_ORDERED);
        }
    }

    _n00b_list_ensure_cap(postings->ordinals, len + 1);
    postings->ordinals->data[len] = ordinal;
    postings->ordinals->len       = len + 1;
    n00b_atomic_add(&postings->count, 1);
    _n00b_list_unlock(postings->ordinals);
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
                        n00b_store_column_t           *column,
                        n00b_store_normalized_list_t  *terms) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
}
{
    if (index == nullptr || shard == nullptr
        || (terms == nullptr && keys == nullptr)) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    uint64_t shard_id   = shard->shard_id;
    uint64_t generation = shard->seal_ts;
    // The walk is the common path, so it wants the resolved keys as much as
    // the posting-count read does: without them a fan-out normalizes and
    // hashes the same value once per shard it visits.
    size_t len = keys != nullptr ? (size_t)n00b_store_index_keys_count(keys)
                                 : n00b_list_len(*terms);
    if (len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }
    if (column == nullptr) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_posting_list_t *candidates = nullptr;
    for (size_t i = 0; i < len; i++) {
        n00b_uint128_t key;
        if (keys != nullptr) {
            key = n00b_store_index_keys_at(keys, (uint64_t)i);
        }
        else {
            auto key_r = rocs_term_key(index->kind,
                                       n00b_list_get(*terms, i),
                                       .allocator = allocator);
            if (n00b_result_is_err(key_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(key_r));
            }
            key = n00b_result_get(key_r);
        }

        auto postings_r = rocs_column_postings_find(column, key);
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_posting_list_t *) current_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(current_opt)) {
            return rocs_empty_postings(shard_id, generation, .allocator = allocator);
        }
        n00b_store_posting_list_t *current = n00b_option_get(current_opt);
        candidates = candidates == nullptr
                       ? current
                       : rocs_filter_hot_candidates(candidates,
                                                    current,
                                                    .allocator = allocator);
        if (rocs_posting_list_len(candidates) == 0) {
            return rocs_empty_postings(shard_id, generation, .allocator = allocator);
        }
    }

    n00b_store_postings_t *postings =
        rocs_postings_new(shard_id, generation, .allocator = allocator);
    uint64_t  candidate_len = 0;
    uint64_t *snap          = rocs_posting_snapshot_ordinals(candidates,
                                                             &candidate_len,
                                                             allocator);
    if (snap == nullptr) {
        candidate_len = rocs_posting_list_len(candidates);
    }

    for (uint64_t i = 0; i < candidate_len; i++) {
        uint64_t ordinal;
        if (snap != nullptr) {
            ordinal = snap[i];
        }
        else {
            auto ordinal_r = rocs_posting_list_ordinal_at(candidates, i);
            if (n00b_result_is_err(ordinal_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(ordinal_r));
            }
            ordinal = n00b_result_get(ordinal_r);
        }
        auto add_r = rocs_postings_add_hot(postings,
                                           shard,
                                           ordinal,
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
                               n00b_store_map_dict_t       *column,
                               n00b_store_normalized_list_t *terms,
                               uint64_t                     shard_id,
                               uint64_t                     generation) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
}
{
    if (index == nullptr || shard == nullptr || records == nullptr
        || column == nullptr || (terms == nullptr && keys == nullptr)) {
        return n00b_result_err(n00b_store_postings_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    size_t len = keys != nullptr ? (size_t)n00b_store_index_keys_count(keys)
                                 : n00b_list_len(*terms);
    if (len == 0) {
        return rocs_empty_postings(shard_id, generation, .allocator = allocator);
    }

    rocs_posting_value_list_t *candidates = nullptr;
    for (size_t i = 0; i < len; i++) {
        n00b_uint128_t key;
        if (keys != nullptr) {
            key = n00b_store_index_keys_at(keys, (uint64_t)i);
        }
        else {
            auto key_r = rocs_term_key(index->kind,
                                       n00b_list_get(*terms, i),
                                       .allocator = allocator);
            if (n00b_result_is_err(key_r)) {
                return n00b_result_err(n00b_store_postings_t *,
                                       n00b_result_get_err(key_r));
            }
            key = n00b_result_get(key_r);
        }

        auto postings_r = rocs_mapped_column_postings_find(column, key);
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_map_posting_list_t *) current_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(current_opt)) {
            return rocs_empty_postings(shard_id, generation, .allocator = allocator);
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
            return rocs_empty_postings(shard_id, generation, .allocator = allocator);
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
    // Candidates are unique by construction: a mapped posting list stores each
    // ordinal once (sparse list or bitset), and the multi-term path intersects
    // such lists. Map to ordinals with a plain push — the previous per-value
    // uniqueness probe was O(n²) over the whole match set and dominated query
    // CPU on shards with many matches. The sort stays as cheap insurance for
    // list-ordered inputs, and adjacent-duplicate skipping below preserves the
    // old dedup semantics at O(n).
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

        n00b_list_push(*ordinals, n00b_result_get(ordinal_r));
    }

    rocs_posting_value_list_sort(ordinals);
    size_t ordinal_len = n00b_list_len(*ordinals);
    for (size_t i = 0; i < ordinal_len; i++) {
        uint64_t ordinal = n00b_list_get(*ordinals, i);
        if (i > 0 && ordinal == n00b_list_get(*ordinals, i - 1)) {
            continue;
        }
        auto add_r = rocs_postings_add_mapped_pos(
            postings,
            shard,
            ordinal,
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

        n00b_store_map_dict_t *column = n00b_option_get(column_opt);
        n00b_store_normalized_t *term = n00b_list_get(*terms, 0);
        auto key_r = rocs_term_key(N00B_STORE_INDEX_FULLTEXT,
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
        n00b_option_t(n00b_store_map_posting_list_t *) postings_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(postings_opt)) {
            continue;
        }

        n00b_store_map_posting_list_t *mapped_postings =
            n00b_option_get(postings_opt);
        auto values_r = rocs_posting_value_list_from_mapped_postings(
            mapped_postings,
            .allocator = allocator);
        if (n00b_result_is_err(values_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(values_r));
        }

        // Cross-column union CAN produce duplicate ordinals (one record
        // matching in several columns); the sort + adjacent-duplicate skip in
        // the ordinal loop below dedups in O(n log n), so plain pushes here.
        rocs_posting_value_list_t *field_candidates = n00b_result_get(values_r);
        size_t len = n00b_list_len(*field_candidates);
        for (size_t j = 0; j < len; j++) {
            n00b_list_push(*candidates,
                           n00b_list_get(*field_candidates, j));
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
    // Candidates are unique by construction: a mapped posting list stores each
    // ordinal once (sparse list or bitset), and the multi-term path intersects
    // such lists. Map to ordinals with a plain push — the previous per-value
    // uniqueness probe was O(n²) over the whole match set and dominated query
    // CPU on shards with many matches. The sort stays as cheap insurance for
    // list-ordered inputs, and adjacent-duplicate skipping below preserves the
    // old dedup semantics at O(n).
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

        n00b_list_push(*ordinals, n00b_result_get(ordinal_r));
    }

    rocs_posting_value_list_sort(ordinals);
    size_t ordinal_len = n00b_list_len(*ordinals);
    for (size_t i = 0; i < ordinal_len; i++) {
        uint64_t ordinal = n00b_list_get(*ordinals, i);
        if (i > 0 && ordinal == n00b_list_get(*ordinals, i - 1)) {
            continue;
        }
        auto add_r = rocs_postings_add_mapped_pos(
            postings,
            shard,
            ordinal,
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
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
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

    if (index->catch_all) {
        auto terms_r = rocs_index_hot_terms(index, value, .allocator = allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(terms_r));
        }
        return rocs_index_lookup_catch_all_terms(index,
                                                 shard,
                                                 n00b_result_get(terms_r),
                                                 .allocator = allocator);
    }

    // A shard that never held the column can hold no match, so answer that
    // before paying for key normalization. Term indexes only: for full-text and
    // n-gram, normalizing the value is also what rejects a malformed query, and
    // the documented contract is that those errors surface.
    bool                 found_column = false;
    n00b_store_column_t *column       = nullptr;
    if (index->kind == N00B_STORE_INDEX_TERM) {
        column = n00b_dict_get(shard->columns, index->field, &found_column);
        if (!found_column) {
            return rocs_empty_postings(shard->shard_id,
                                       shard->seal_ts,
                                       .allocator = allocator);
        }
    }

    // Resolved keys already carry the normalized terms and their hashes, and
    // resolving them ran this same normalization, so a value that would fail
    // here failed there. Skipping it is the point of handing them over: a
    // fan-out otherwise normalizes once per shard, which for n-gram and
    // full-text is the expensive half.
    n00b_store_normalized_list_t *terms = nullptr;
    if (keys == nullptr) {
        auto terms_r = rocs_index_hot_query_terms(index,
                                                  value,
                                                  .allocator = allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(terms_r));
        }
        terms = n00b_result_get(terms_r);
    }

    if (!found_column) {
        column = n00b_dict_get(shard->columns, index->field, &found_column);
        if (!found_column) {
            return rocs_empty_postings(shard->shard_id,
                                       shard->seal_ts,
                                       .allocator = allocator);
        }
    }

    return rocs_index_lookup_terms(index,
                                   shard,
                                   column,
                                   terms,
                                   .allocator = allocator,
                                   .keys      = keys);
}

n00b_result_t(n00b_store_postings_t *)
n00b_store_index_lookup_mapped(n00b_store_index_t     *index,
                               n00b_store_map_shard_t *shard,
                               n00b_json_node_t       *value) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
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

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(columns_r)));
    }

    // A shard that never held the column can hold no match, so answer that
    // before paying for key normalization and the record fetch. Term indexes
    // only: for full-text and n-gram, normalizing the value is also what
    // rejects a malformed query, and the documented contract is that those
    // errors surface.
    n00b_store_map_dict_t *column = nullptr;
    if (!index->catch_all && index->kind == N00B_STORE_INDEX_TERM) {
        auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                                index->field);
        if (n00b_result_is_err(column_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(column_r));
        }
        n00b_option_t(n00b_store_map_dict_t *) column_opt =
            n00b_result_get(column_r);
        if (!n00b_option_is_set(column_opt)) {
            return rocs_empty_postings(shard_id, generation, .allocator = allocator);
        }
        column = n00b_option_get(column_opt);
    }

    // Resolved keys carry the normalized terms and their hashes, and resolving
    // them ran this same normalization, so a value that would fail here failed
    // there. Skipping it is what makes handing them over worth it across a
    // fan-out. The catch-all has no resolved keys and always normalizes.
    n00b_store_normalized_list_t *terms = nullptr;
    if (keys == nullptr || index->catch_all) {
        auto terms_r = index->catch_all
                         ? rocs_index_hot_terms(index,
                                                value,
                                                .allocator = allocator)
                         : rocs_index_hot_query_terms(index,
                                                      value,
                                                      .allocator = allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(terms_r));
        }
        terms = n00b_result_get(terms_r);
    }

    auto records_r = n00b_store_map_shard_records(shard);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(n00b_store_postings_t *,
                               rocs_index_map_err(n00b_result_get_err(records_r)));
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

    if (column == nullptr) {
        auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                                index->field);
        if (n00b_result_is_err(column_r)) {
            return n00b_result_err(n00b_store_postings_t *,
                                   n00b_result_get_err(column_r));
        }
        n00b_option_t(n00b_store_map_dict_t *) column_opt =
            n00b_result_get(column_r);
        if (!n00b_option_is_set(column_opt)) {
            return rocs_empty_postings(shard_id, generation, .allocator = allocator);
        }
        column = n00b_option_get(column_opt);
    }

    return rocs_index_lookup_mapped_terms(index,
                                          shard,
                                          n00b_result_get(records_r),
                                          column,
                                          terms,
                                          shard_id,
                                          generation,
                                          .allocator = allocator,
                                          .keys      = keys);
}

n00b_result_t(bool)
n00b_store_index_declare(n00b_store_index_t *index, n00b_store_shard_t *shard)
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(bool, ready);
    }
    if (shard == nullptr || shard->columns == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }
    // The catch-all is virtual: it has no physical column of its own, and
    // n00b_store_index_present_mapped already reports it present everywhere.
    if (index->catch_all) {
        return n00b_result_ok(bool, false);
    }

    bool found = false;
    (void)n00b_dict_get(shard->columns, index->field, &found);
    if (found) {
        return n00b_result_ok(bool, false);
    }

    auto column_r = rocs_column_get_or_create(shard, index->field);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(bool, n00b_result_get_err(column_r));
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_index_present_mapped(n00b_store_index_t     *index,
                                n00b_store_map_shard_t *shard)
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(bool, ready);
    }
    if (shard == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    if (index->catch_all) {
        return n00b_result_ok(bool, true);
    }

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return n00b_result_err(
            bool,
            rocs_index_map_err(n00b_result_get_err(columns_r)));
    }
    auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                            index->field);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(bool, n00b_result_get_err(column_r));
    }
    return n00b_result_ok(bool,
                          n00b_option_is_set(n00b_result_get(column_r)));
}

// The hot half of the same question. A count of zero from a shard with no
// column for the field means nobody indexed it, not that nothing matches it,
// and only the caller that can tell those apart may act on the zero.
n00b_result_t(bool)
n00b_store_index_present_hot(n00b_store_index_t *index,
                             n00b_store_shard_t *shard)
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(bool, ready);
    }
    if (shard == nullptr || shard->columns == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }
    if (index->catch_all) {
        return n00b_result_ok(bool, true);
    }

    bool                 found  = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns,
                                                index->field,
                                                &found);
    return n00b_result_ok(bool, found && column != nullptr);
}

// The shard-independent half of a lookup, resolved once.
//
// Finding a posting list means normalizing the query value into terms and
// hashing each into a column key. Neither step touches a shard: both depend
// only on the descriptor's kind and the value being looked up. Left where they
// were, they ran again for every shard a query visited and again for every
// caller that asked the same node a question, which on a plan with many
// indexed leaves cost more than the posting counts it was fetching.
//
// Resolved here, a posting-count read is a dict probe and a field load.
struct n00b_store_index_keys_t {
    rocs_index_key_list_t *keys;
    // A value that normalizes to no terms matches nothing, which is different
    // from a value whose terms are simply absent from this shard.
    bool                   matches_nothing;
};

static n00b_result_t(n00b_store_index_keys_t *)
rocs_index_keys_for(n00b_store_index_t      *index,
                    n00b_json_node_t        *value,
                    n00b_store_index_keys_t *keys,
                    n00b_allocator_t        *allocator);

n00b_result_t(n00b_store_index_keys_t *)
n00b_store_index_keys_new(n00b_store_index_t *index,
                          n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(n00b_store_index_keys_t *, ready);
    }
    if (value == nullptr || index->catch_all) {
        return n00b_result_err(n00b_store_index_keys_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto terms_r = rocs_index_hot_query_terms(index,
                                              value,
                                              .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_store_index_keys_t *,
                               n00b_result_get_err(terms_r));
    }

    n00b_store_index_keys_t *out = n00b_alloc_with_opts(
        n00b_store_index_keys_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    out->keys = n00b_alloc_with_opts(
        rocs_index_key_list_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    // Private, so no rwlock is installed. A locked list would put the lock in
    // the collected heap, and this list is declared N00B_GC_SCAN_KIND_NONE, so
    // a collect traces none of its words and the lock field would dangle. No
    // lock is needed regardless: the key set is filled once here and only ever
    // read afterwards.
    *out->keys = n00b_list_new_private(n00b_uint128_t,
                                       .allocator = allocator,
                                       .scan_kind = N00B_GC_SCAN_KIND_NONE);

    n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
    size_t                        len   = n00b_list_len(*terms);
    out->matches_nothing                = len == 0;

    for (size_t i = 0; i < len; i++) {
        auto key_r = rocs_term_key(index->kind,
                                   n00b_list_get(*terms, i),
                                   .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(n00b_store_index_keys_t *,
                                   n00b_result_get_err(key_r));
        }
        n00b_list_push(*out->keys, n00b_result_get(key_r));
    }

    return n00b_result_ok(n00b_store_index_keys_t *, out);
}

bool
n00b_store_index_keys_equal(n00b_store_index_keys_t *a,
                            n00b_store_index_keys_t *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    if (a == b) {
        return true;
    }
    if (a->matches_nothing != b->matches_nothing) {
        return false;
    }

    size_t len = n00b_list_len(*a->keys);
    if (len != (size_t)n00b_list_len(*b->keys)) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        n00b_uint128_t x = n00b_list_get(*a->keys, i);
        n00b_uint128_t y = n00b_list_get(*b->keys, i);
        if (x != y) {
            return false;
        }
    }
    return true;
}

n00b_uint128_t
n00b_store_index_keys_at(n00b_store_index_keys_t *keys, uint64_t index)
{
    return n00b_list_get(*keys->keys, (size_t)index);
}

uint64_t
n00b_store_index_keys_digest(n00b_store_index_keys_t *keys)
{
    if (keys == nullptr) {
        return 0;
    }

    // Order-sensitive, matching n00b_store_index_keys_equal: the same terms in
    // a different order are a different lookup, so they must digest
    // differently. Mixing constant is the 64-bit FNV prime; the keys are
    // already hashes, so this only needs to spread them, not to hash them.
    uint64_t h   = keys->matches_nothing ? UINT64_C(0x9e3779b97f4a7c15) : 0;
    size_t   len = n00b_list_len(*keys->keys);

    for (size_t i = 0; i < len; i++) {
        n00b_uint128_t k = n00b_list_get(*keys->keys, i);
        h ^= (uint64_t)k;
        h *= UINT64_C(0x100000001b3);
        h ^= (uint64_t)(k >> 64);
        h *= UINT64_C(0x100000001b3);
    }
    return h;
}

uint64_t
n00b_store_index_keys_count(n00b_store_index_keys_t *keys)
{
    if (keys == nullptr || keys->matches_nothing) {
        return 0;
    }
    return (uint64_t)n00b_list_len(*keys->keys);
}

static n00b_result_t(n00b_store_index_keys_t *)
rocs_index_keys_for(n00b_store_index_t      *index,
                    n00b_json_node_t        *value,
                    n00b_store_index_keys_t *keys,
                    n00b_allocator_t        *allocator)
{
    if (keys != nullptr) {
        return n00b_result_ok(n00b_store_index_keys_t *, keys);
    }
    return n00b_store_index_keys_new(index, value, .allocator = allocator);
}

// Upper bound on a lookup's matches, read from the posting headers rather than
// from the postings. Both representations maintain their count on insert and
// the sealed image stores it in the header, so each term costs a dict probe
// and a field read.
//
// A multi-term lookup intersects its terms, so the smallest term's count
// bounds the result. Bounding rather than resolving is the point: a caller
// deciding whether the lookup is worth doing must not pay for the lookup to
// find out.
// A hot posting list's size.
//
// Read with no lock, which is why the field is atomic. Both writers hold a
// lock over the update, but not the same one: a sparse list's is the ordinal
// list's, a dense list's is the flag set's, and sealing writes the field under
// neither. There is no single lock for a reader to take, and taking a writer's
// would put a query behind ingest to read one word.
//
// So it is an estimate at the moment it is read, which is what every caller
// wants it for. Callers size work from it; none decides membership by it.
static uint64_t
rocs_hot_posting_count(n00b_store_posting_list_t *postings)
{
    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        // The maintained count, not a popcount: O(1) where popcounting the
        // bitmap is a pass over record_count/64 words on every df read.
        return n00b_atomic_load(&postings->count);
    }
    if (postings->ordinals == nullptr) {
        return 0;
    }

    return n00b_atomic_load(&postings->count);
}

static n00b_result_t(uint64_t)
rocs_index_df_hot_keys(n00b_store_index_keys_t *keys,
                       n00b_store_column_t     *column)
{
    size_t len = n00b_list_len(*keys->keys);
    if (keys->matches_nothing || len == 0) {
        return n00b_result_ok(uint64_t, 0);
    }

    uint64_t bound = UINT64_MAX;
    for (size_t i = 0; i < len; i++) {
        auto postings_r = rocs_column_postings_find(
            column,
            n00b_list_get(*keys->keys, i));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_posting_list_t *) current_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(current_opt)) {
            return n00b_result_ok(uint64_t, 0);
        }

        n00b_store_posting_list_t *current = n00b_option_get(current_opt);
        if (current == nullptr) {
            return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
        }
        uint64_t count = rocs_hot_posting_count(current);
        if (count < bound) {
            bound = count;
        }
    }

    return n00b_result_ok(uint64_t, bound);
}

// A resolved lookup that answers membership instead of enumerating. The term
// posting lists are found once; each ordinal after that costs a bitmap bit or
// a binary search, not a walk.
//
// This is the other way to read an index. Enumerating costs one step per
// posting; probing costs one step per candidate. Which is cheaper depends on
// how many of each there are, and the caller decides with the df bound.
struct n00b_store_index_probe_t {
    rocs_hot_posting_list_t    *hot;
    rocs_mapped_posting_list_t *mapped;
};

n00b_result_t(n00b_store_index_probe_t *)
n00b_store_index_probe_hot(n00b_store_index_t *index,
                           n00b_store_shard_t *shard,
                           n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(n00b_store_index_probe_t *, ready);
    }
    if (shard == nullptr || value == nullptr || shard->columns == nullptr
        || index->catch_all) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto keys_r = rocs_index_keys_for(index, value, keys, allocator);
    if (n00b_result_is_err(keys_r)) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               n00b_result_get_err(keys_r));
    }
    n00b_store_index_keys_t *resolved = n00b_result_get(keys_r);

    n00b_store_index_probe_t *probe = n00b_alloc_with_opts(
        n00b_store_index_probe_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    probe->hot = n00b_alloc_with_opts(
        rocs_hot_posting_list_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    *probe->hot = n00b_list_new_private(n00b_store_posting_list_t *,
                                        .allocator = allocator,
                                        .scan_kind = N00B_GC_SCAN_KIND_ALL);
    probe->mapped = nullptr;

    size_t len = resolved->matches_nothing
                   ? 0
                   : n00b_list_len(*resolved->keys);

    bool                 found  = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns,
                                                index->field,
                                                &found);
    if (!found || column == nullptr || len == 0) {
        // No column and no terms both mean no record can match. An empty term
        // list answers false for every ordinal, which is that.
        return n00b_result_ok(n00b_store_index_probe_t *, probe);
    }

    for (size_t i = 0; i < len; i++) {
        auto postings_r = rocs_column_postings_find(
            column,
            n00b_list_get(*resolved->keys, i));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_index_probe_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_posting_list_t *) opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(opt)) {
            *probe->hot = n00b_list_new_private(
                n00b_store_posting_list_t *,
                .allocator = allocator,
                .scan_kind = N00B_GC_SCAN_KIND_ALL);
            n00b_list_push(*probe->hot, nullptr);
            return n00b_result_ok(n00b_store_index_probe_t *, probe);
        }
        n00b_list_push(*probe->hot, n00b_option_get(opt));
    }

    return n00b_result_ok(n00b_store_index_probe_t *, probe);
}

n00b_result_t(n00b_store_index_probe_t *)
n00b_store_index_probe_mapped(n00b_store_index_t     *index,
                              n00b_store_map_shard_t *shard,
                              n00b_json_node_t       *value) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(n00b_store_index_probe_t *, ready);
    }
    if (shard == nullptr || value == nullptr || index->catch_all) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    auto state_r = n00b_store_map_shard_state(shard);
    if (n00b_result_is_err(state_r)) {
        return n00b_result_err(
            n00b_store_index_probe_t *,
            rocs_index_map_err(n00b_result_get_err(state_r)));
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto keys_r = rocs_index_keys_for(index, value, keys, allocator);
    if (n00b_result_is_err(keys_r)) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               n00b_result_get_err(keys_r));
    }
    n00b_store_index_keys_t *resolved = n00b_result_get(keys_r);

    n00b_store_index_probe_t *probe = n00b_alloc_with_opts(
        n00b_store_index_probe_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    probe->hot    = nullptr;
    probe->mapped = n00b_alloc_with_opts(
        rocs_mapped_posting_list_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    *probe->mapped = n00b_list_new_private(n00b_store_map_posting_list_t *,
                                           .allocator = allocator,
                                           .scan_kind = N00B_GC_SCAN_KIND_ALL);

    size_t len = resolved->matches_nothing
                   ? 0
                   : n00b_list_len(*resolved->keys);
    if (len == 0) {
        n00b_list_push(*probe->mapped, nullptr);
        return n00b_result_ok(n00b_store_index_probe_t *, probe);
    }

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return n00b_result_err(
            n00b_store_index_probe_t *,
            rocs_index_map_err(n00b_result_get_err(columns_r)));
    }

    auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                            index->field);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(n00b_store_index_probe_t *,
                               n00b_result_get_err(column_r));
    }

    n00b_option_t(n00b_store_map_dict_t *) column_opt =
        n00b_result_get(column_r);
    if (!n00b_option_is_set(column_opt)) {
        n00b_list_push(*probe->mapped, nullptr);
        return n00b_result_ok(n00b_store_index_probe_t *, probe);
    }
    n00b_store_map_dict_t *column = n00b_option_get(column_opt);

    for (size_t i = 0; i < len; i++) {
        auto postings_r = rocs_mapped_column_postings_find(
            column,
            n00b_list_get(*resolved->keys, i));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(n00b_store_index_probe_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_map_posting_list_t *) opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(opt)) {
            n00b_list_push(*probe->mapped, nullptr);
            return n00b_result_ok(n00b_store_index_probe_t *, probe);
        }
        n00b_list_push(*probe->mapped, n00b_option_get(opt));
    }

    return n00b_result_ok(n00b_store_index_probe_t *, probe);
}

n00b_result_t(bool)
n00b_store_index_probe_contains(n00b_store_index_probe_t *probe,
                                uint64_t                  ordinal)
{
    if (probe == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_ARG);
    }

    if (probe->hot != nullptr) {
        size_t len = n00b_list_len(*probe->hot);
        if (len == 0) {
            return n00b_result_ok(bool, false);
        }
        for (size_t i = 0; i < len; i++) {
            // A multi-term lookup intersects, so every term must carry it.
            if (!rocs_posting_list_contains_ordinal(n00b_list_get(*probe->hot, i),
                                           ordinal)) {
                return n00b_result_ok(bool, false);
            }
        }
        return n00b_result_ok(bool, true);
    }

    if (probe->mapped == nullptr) {
        return n00b_result_err(bool, N00B_STORE_INDEX_ERR_STATE);
    }

    size_t len = n00b_list_len(*probe->mapped);
    if (len == 0) {
        return n00b_result_ok(bool, false);
    }
    for (size_t i = 0; i < len; i++) {
        n00b_store_map_posting_list_t *list = n00b_list_get(*probe->mapped, i);
        if (list == nullptr) {
            return n00b_result_ok(bool, false);
        }
        auto has_r = n00b_store_map_posting_list_contains(list, ordinal);
        if (n00b_result_is_err(has_r)) {
            return n00b_result_err(
                bool,
                rocs_index_map_err(n00b_result_get_err(has_r)));
        }
        if (!n00b_result_get(has_r)) {
            return n00b_result_ok(bool, false);
        }
    }
    return n00b_result_ok(bool, true);
}

// Whether this probe answers membership by search or by scan.
//
// The cost model prices a membership test at ceil(log2(df)) steps, which is
// what a binary search over an ascending list costs. A sparse list that lost
// N00B_STORE_POSTINGS_ORDERED is scanned instead, at df steps, and a caller
// that priced the scan as a search picks the probe exactly where it is worst:
// the wider the term, the further the estimate is from the work.
//
// Dense lists answer from a bitmap bit and are always searchable. A null
// entry is a term the shard never indexed, which answers false for every
// ordinal without reading anything.
//
// A concurrent push can clear the bit after this returns, which downgrades
// the probe to a scan and costs speed only.
bool
n00b_store_index_probe_searchable(n00b_store_index_probe_t *probe)
{
    if (probe == nullptr) {
        return false;
    }

    if (probe->hot != nullptr) {
        size_t len = n00b_list_len(*probe->hot);
        for (size_t i = 0; i < len; i++) {
            n00b_store_posting_list_t *list = n00b_list_get(*probe->hot, i);
            if (list == nullptr
                || list->kind == N00B_STORE_POSTINGS_DENSE) {
                continue;
            }
            if ((n00b_atomic_load(&list->reserved)
                 & N00B_STORE_POSTINGS_ORDERED)
                == 0) {
                return false;
            }
        }
        return true;
    }

    if (probe->mapped == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*probe->mapped);
    for (size_t i = 0; i < len; i++) {
        n00b_store_map_posting_list_t *list = n00b_list_get(*probe->mapped, i);
        if (list != nullptr
            && !rocs_mapped_postings_advertise_order(list)) {
            return false;
        }
    }
    return true;
}

n00b_result_t(uint64_t)
n00b_store_index_df_hot(n00b_store_index_t *index,
                        n00b_store_shard_t *shard,
                        n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(uint64_t, ready);
    }
    if (shard == nullptr || value == nullptr || shard->columns == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }
    if (shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
    }
    // The catch-all unions across the fields it covers, so no single posting
    // count bounds it. Callers never need one: an unusable catch-all has no
    // legal fallback, so it is not a lookup anybody may decline.
    if (index->catch_all) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_KIND);
    }

    auto keys_r = rocs_index_keys_for(index, value, keys, allocator);
    if (n00b_result_is_err(keys_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(keys_r));
    }

    bool                 found  = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns,
                                                index->field,
                                                &found);
    if (!found) {
        return n00b_result_ok(uint64_t, 0);
    }
    if (column == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
    }

    return rocs_index_df_hot_keys(n00b_result_get(keys_r), column);
}

// Whether the posting lists this lookup would read advertise ascending order.
//
// For tests only. A reader falls back to a linear scan when the bit is clear,
// so a seal that stopped setting it would answer every query correctly while
// silently giving up the binary search, and nothing else would fail.
bool
n00b_store_index_sealed_is_ordered(n00b_store_index_t     *index,
                                   n00b_store_map_shard_t *shard,
                                   n00b_json_node_t       *value)
{
    auto keys_r = n00b_store_index_keys_new(index, value);
    if (n00b_result_is_err(keys_r)) {
        return false;
    }
    n00b_store_index_keys_t *keys = n00b_result_get(keys_r);

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return false;
    }
    auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                            index->field);
    if (n00b_result_is_err(column_r)) {
        return false;
    }
    n00b_option_t(n00b_store_map_dict_t *) column_opt =
        n00b_result_get(column_r);
    if (!n00b_option_is_set(column_opt)) {
        return false;
    }

    uint64_t len = n00b_store_index_keys_count(keys);
    if (len == 0) {
        return false;
    }

    for (uint64_t i = 0; i < len; i++) {
        auto pl_r = rocs_mapped_column_postings_find(
            n00b_option_get(column_opt),
            n00b_store_index_keys_at(keys, i));
        if (n00b_result_is_err(pl_r)) {
            return false;
        }
        n00b_option_t(n00b_store_map_posting_list_t *) pl_opt =
            n00b_result_get(pl_r);
        if (!n00b_option_is_set(pl_opt)) {
            return false;
        }
        if (!rocs_mapped_postings_advertise_order(n00b_option_get(pl_opt))) {
            return false;
        }
    }
    return true;
}

#ifdef N00B_DEBUG
uint64_t
n00b_store_index_sealed_clear_ordered(n00b_store_index_t     *index,
                                      n00b_store_map_shard_t *shard,
                                      n00b_json_node_t       *value)
{
    auto keys_r = n00b_store_index_keys_new(index, value);
    if (n00b_result_is_err(keys_r)) {
        return 0;
    }
    n00b_store_index_keys_t *keys = n00b_result_get(keys_r);

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return 0;
    }
    auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                            index->field);
    if (n00b_result_is_err(column_r)) {
        return 0;
    }
    n00b_option_t(n00b_store_map_dict_t *) column_opt =
        n00b_result_get(column_r);
    if (!n00b_option_is_set(column_opt)) {
        return 0;
    }

    uint64_t len     = n00b_store_index_keys_count(keys);
    uint64_t cleared = 0;
    for (uint64_t i = 0; i < len; i++) {
        auto pl_r = rocs_mapped_column_postings_find(
            n00b_option_get(column_opt),
            n00b_store_index_keys_at(keys, i));
        if (n00b_result_is_err(pl_r)) {
            continue;
        }
        n00b_option_t(n00b_store_map_posting_list_t *) pl_opt =
            n00b_result_get(pl_r);
        if (!n00b_option_is_set(pl_opt)) {
            continue;
        }
        if (rocs_mapped_postings_clear_order(n00b_option_get(pl_opt))) {
            cleared++;
        }
    }
    return cleared;
}
#endif

n00b_result_t(uint64_t)
n00b_store_index_df_mapped(n00b_store_index_t     *index,
                           n00b_store_map_shard_t *shard,
                           n00b_json_node_t       *value) _kargs
{
    n00b_allocator_t        *allocator = nullptr;
    n00b_store_index_keys_t *keys      = nullptr;
}
{
    n00b_err_t ready = rocs_index_hot_ready(index);
    if (ready != N00B_STORE_INDEX_OK) {
        return n00b_result_err(uint64_t, ready);
    }
    if (shard == nullptr || value == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_ARG);
    }
    if (index->catch_all) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_KIND);
    }

    auto state_r = n00b_store_map_shard_state(shard);
    if (n00b_result_is_err(state_r)) {
        return n00b_result_err(uint64_t,
                               rocs_index_map_err(n00b_result_get_err(state_r)));
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(uint64_t, N00B_STORE_INDEX_ERR_STATE);
    }

    auto keys_r = rocs_index_keys_for(index, value, keys, allocator);
    if (n00b_result_is_err(keys_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(keys_r));
    }

    n00b_store_index_keys_t *resolved = n00b_result_get(keys_r);
    size_t                   len      = n00b_list_len(*resolved->keys);
    if (resolved->matches_nothing || len == 0) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto columns_r = n00b_store_map_shard_columns(shard);
    if (n00b_result_is_err(columns_r)) {
        return n00b_result_err(
            uint64_t,
            rocs_index_map_err(n00b_result_get_err(columns_r)));
    }

    auto column_r = rocs_mapped_column_find(n00b_result_get(columns_r),
                                            index->field);
    if (n00b_result_is_err(column_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(column_r));
    }

    n00b_option_t(n00b_store_map_dict_t *) column_opt =
        n00b_result_get(column_r);
    if (!n00b_option_is_set(column_opt)) {
        return n00b_result_ok(uint64_t, 0);
    }
    n00b_store_map_dict_t *column = n00b_option_get(column_opt);

    uint64_t bound = UINT64_MAX;
    for (size_t i = 0; i < len; i++) {
        auto postings_r = rocs_mapped_column_postings_find(
            column,
            n00b_list_get(*resolved->keys, i));
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(postings_r));
        }

        n00b_option_t(n00b_store_map_posting_list_t *) current_opt =
            n00b_result_get(postings_r);
        if (!n00b_option_is_set(current_opt)) {
            return n00b_result_ok(uint64_t, 0);
        }

        auto count_r =
            n00b_store_map_posting_list_len(n00b_option_get(current_opt));
        if (n00b_result_is_err(count_r)) {
            return n00b_result_err(
                uint64_t,
                rocs_index_map_err(n00b_result_get_err(count_r)));
        }

        uint64_t count = n00b_result_get(count_r);
        if (count < bound) {
            bound = count;
        }
    }

    return n00b_result_ok(uint64_t, bound);
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

    // Live callers bound ordinals by the post-fill publication watermark.
    uint64_t len = (uint64_t)n00b_list_len(*shard->records);
    if (ordinal >= len) {
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

    // Live callers bound ordinals by the post-fill publication watermark.
    uint64_t len = (uint64_t)n00b_list_len(*shard->records);
    if (pos.ordinal >= len) {
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
        if (getenv("ROCS_QUERY_DEBUG") != NULL) {
            fprintf(stderr,
                    "rocs index: mapped pos state mismatch "
                    "shard=%llu ordinal=%llu state=%lld\n",
                    (unsigned long long)pos.shard_id,
                    (unsigned long long)pos.ordinal,
                    (long long)n00b_result_get(state_r));
        }
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
        if (getenv("ROCS_QUERY_DEBUG") != NULL) {
            fprintf(stderr,
                    "rocs index: mapped pos state mismatch "
                    "shard=%llu ordinal=%llu state=%lld\n",
                    (unsigned long long)pos.shard_id,
                    (unsigned long long)pos.ordinal,
                    (long long)n00b_result_get(state_r));
        }
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    auto shard_id_r = n00b_store_map_shard_id(shard);
    if (n00b_result_is_err(shard_id_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               rocs_index_map_err(n00b_result_get_err(shard_id_r)));
    }
    if (n00b_result_get(shard_id_r) != pos.shard_id) {
        if (getenv("ROCS_QUERY_DEBUG") != NULL) {
            fprintf(stderr,
                    "rocs index: mapped pos shard mismatch "
                    "wanted=%llu mapped=%llu ordinal=%llu\n",
                    (unsigned long long)pos.shard_id,
                    (unsigned long long)n00b_result_get(shard_id_r),
                    (unsigned long long)pos.ordinal);
        }
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
        if (getenv("ROCS_QUERY_DEBUG") != NULL) {
            fprintf(stderr,
                    "rocs index: mapped pos empty record ref "
                    "shard=%llu ordinal=%llu\n",
                    (unsigned long long)pos.shard_id,
                    (unsigned long long)pos.ordinal);
        }
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

n00b_result_t(n00b_store_record_t *)
n00b_store_record_view_owned_text(n00b_store_pos_t  pos,
                                  n00b_string_t    *text) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (text == nullptr || pos.shard_id == 0) {
        return n00b_result_err(n00b_store_record_t *,
                               N00B_STORE_INDEX_ERR_ARG);
    }

    n00b_store_record_t *view = _rocs_record_view_new(
        pos,
        nullptr,
        nullptr,
        .allocator = allocator);
    view->owned_text = text;
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

    // Text-backed record: parse for the caller that actually wants a node
    // graph, into the allocator that caller named. Deliberately not cached on
    // the record -- caching would hand a later caller a graph owned by an
    // earlier caller's allocator, which for a per-row scratch arena is a
    // use-after-reset. Every current caller asks once.
    if (record->owned_text != nullptr) {
        const char       *err  = nullptr;
        n00b_json_node_t *node = n00b_json_parse(record->owned_text->data,
                                                 record->owned_text->u8_bytes,
                                                 &err,
                                                 .allocator = allocator);
        if (node == nullptr || err != nullptr) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_INDEX_ERR_STATE);
        }
        return n00b_result_ok(n00b_json_node_t *, node);
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
        if (record->pos.ordinal >= len) {
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

// Serialize a JSON node graph to a compact n00b string. The returned char*
// boundary is confined here and allocated from the caller's allocator.
static n00b_result_t(n00b_string_t *)
rocs_json_node_to_string(n00b_json_node_t *node, n00b_allocator_t *allocator)
{
    char *encoded = n00b_json_encode(node,
                                     .pretty = false,
                                     .allocator = allocator);
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
    // Fast path: the record already IS the stored compact JSON (a hot record
    // copied verbatim). Same deal as the mapped fast path below.
    if (record->owned_text != nullptr) {
        return n00b_result_ok(n00b_string_t *, record->owned_text);
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
