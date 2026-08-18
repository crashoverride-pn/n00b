#include "internal/rocs/plan.h"

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#include "core/arena.h"
#include "core/buffer.h"
#include "internal/rocs/index.h"
#include "internal/rocs/json_field.h"
#include "internal/rocs/store.h"
#include "rocs/map.h"
#include "rocs/normalizer.h"
#include "text/strings/string_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool
rocs_plan_debug_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ROCS_QUERY_DEBUG") != nullptr ? 1 : 0;
    }
    return enabled != 0;
}

typedef n00b_list_t(n00b_string_t *) _rocs_plan_route_list_t;

typedef enum : int32_t {
    _rocs_plan_ordset_op_union,
    _rocs_plan_ordset_op_intersection,
    _rocs_plan_ordset_op_difference,
} _rocs_plan_ordset_binary_op_t;

typedef struct {
    n00b_store_partition_policy_t *policy;
    n00b_string_t                 *field;
    n00b_allocator_t              *allocator;
} _rocs_plan_prune_ctx_t;

typedef struct {
    bool                    constrained;
    _rocs_plan_route_list_t *routes;
} _rocs_plan_prune_t;

#define N00B_ROCS_PLAN_BROAD_CANDIDATE_MIN_RECORDS UINT64_C(8)
#define N00B_ROCS_PLAN_BROAD_CANDIDATE_PERCENT UINT64_C(75)

n00b_err_t
_rocs_plan_store_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_ERR_ARG:
        return N00B_PLAN_ERR_ARG;
    default:
        return N00B_PLAN_ERR_STATE;
    }
}

n00b_err_t
_rocs_plan_map_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_MAP_ERR_ARG:
        return N00B_PLAN_ERR_ARG;
    default:
        return N00B_PLAN_ERR_STATE;
    }
}

static _rocs_plan_route_list_t *
_rocs_plan_route_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    _rocs_plan_route_list_t *routes = n00b_alloc_with_opts(
        _rocs_plan_route_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *routes = n00b_list_new_private(n00b_string_t *,
                                    .allocator = allocator,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return routes;
}

static bool
_rocs_plan_route_list_contains(_rocs_plan_route_list_t *routes,
                               n00b_string_t           *route)
{
    if (routes == nullptr || route == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*routes);
    for (size_t i = 0; i < len; i++) {
        n00b_string_t *item = n00b_list_get(*routes, i);
        if (item != nullptr && n00b_unicode_str_eq(item, route)) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
_rocs_plan_route_list_append_unique(_rocs_plan_route_list_t *routes,
                                    n00b_string_t           *route)
{
    if (routes == nullptr || route == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    if (_rocs_plan_route_list_contains(routes, route)) {
        return n00b_result_ok(bool, false);
    }

    n00b_list_push(*routes, route);
    return n00b_result_ok(bool, true);
}

static _rocs_plan_route_list_t *
_rocs_plan_route_list_intersection(_rocs_plan_route_list_t *left,
                                   _rocs_plan_route_list_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    _rocs_plan_route_list_t *out =
        _rocs_plan_route_list_new(.allocator = allocator);
    if (left == nullptr || right == nullptr) {
        return out;
    }

    size_t len = n00b_list_len(*left);
    for (size_t i = 0; i < len; i++) {
        n00b_string_t *route = n00b_list_get(*left, i);
        if (_rocs_plan_route_list_contains(right, route)) {
            auto append_r = _rocs_plan_route_list_append_unique(out, route);
            if (n00b_result_is_err(append_r)) {
                return out;
            }
        }
    }
    return out;
}

static _rocs_plan_prune_t
_rocs_plan_prune_unconstrained(void)
{
    return (_rocs_plan_prune_t){
        .constrained = false,
        .routes      = nullptr,
    };
}

static n00b_result_t(_rocs_plan_prune_t)
_rocs_plan_prune_for_predicate(_rocs_plan_prune_ctx_t *ctx,
                               n00b_plan_predicate_t  *predicate);

static bool
_rocs_plan_value_is_set(n00b_plan_value_t value)
{
    return n00b_variant_is_set(value);
}

bool
_rocs_plan_path_component_is_valid(n00b_plan_path_component_t *component)
{
    if (component == nullptr) {
        return false;
    }

    switch (component->kind) {
    case N00B_PLAN_PATH_KEY:
        return component->key != nullptr;
    case N00B_PLAN_PATH_INDEX:
        return true;
    }

    return false;
}

static n00b_plan_path_component_t *
_rocs_plan_path_component_copy(n00b_plan_path_component_t *component) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_path_component_t *copy = n00b_alloc_with_opts(
        n00b_plan_path_component_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    copy->kind  = component->kind;
    copy->key   = component->key;
    copy->index = component->index;
    return copy;
}

static n00b_err_t
_rocs_plan_check_target(n00b_plan_target_t *target, n00b_plan_leaf_op_t op)
{
    if (target == nullptr) {
        return N00B_PLAN_ERR_ARG;
    }

    if (target->kind == N00B_PLAN_TARGET_FIELD) {
        if (target->field == nullptr || target->field->u8_bytes == 0) {
            return N00B_PLAN_ERR_ARG;
        }
        return N00B_PLAN_OK;
    }

    if (target->kind == N00B_PLAN_TARGET_ANY) {
        if (op == N00B_PLAN_LEAF_CONTAINS) {
            return N00B_PLAN_OK;
        }
        return N00B_PLAN_ERR_ANY_UNSUPPORTED;
    }

    return N00B_PLAN_ERR_ARG;
}

static n00b_plan_predicate_t *
_rocs_plan_predicate_new(n00b_plan_predicate_kind_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_predicate_t *predicate = n00b_alloc_with_opts(
        n00b_plan_predicate_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    predicate->kind = kind;
    return predicate;
}

static n00b_result_t(n00b_plan_predicate_t *)
_rocs_plan_leaf_new(n00b_plan_target_t *target,
                    n00b_plan_leaf_op_t op) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t target_err = _rocs_plan_check_target(target, op);
    if (target_err != N00B_PLAN_OK) {
        return n00b_result_err(n00b_plan_predicate_t *, target_err);
    }

    n00b_plan_predicate_t *predicate =
        _rocs_plan_predicate_new(N00B_PLAN_PREDICATE_LEAF,
                                 .allocator = allocator);
    predicate->leaf_op = op;
    predicate->target  = target;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

static n00b_err_t
_rocs_plan_check_children(n00b_plan_predicate_list_t *children)
{
    if (children == nullptr) {
        return N00B_PLAN_ERR_ARG;
    }

    size_t len = n00b_list_len(*children);
    if (len < 2) {
        return N00B_PLAN_ERR_EMPTY;
    }

    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*children, i) == nullptr) {
            return N00B_PLAN_ERR_ARG;
        }
    }

    return N00B_PLAN_OK;
}

static n00b_result_t(uint64_t)
_rocs_plan_ordset_byte_count(uint64_t record_count)
{
    uint64_t bytes = record_count >> 3;
    if ((record_count & UINT64_C(7)) != 0) {
        bytes++;
    }
    if (bytes > (uint64_t)INT64_MAX) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, bytes);
}

static uint8_t
_rocs_plan_ordset_tail_mask(uint64_t record_count)
{
    uint64_t bits = record_count & UINT64_C(7);
    if (bits == 0) {
        return UINT8_MAX;
    }
    return (uint8_t)((UINT32_C(1) << bits) - UINT32_C(1));
}

static uint64_t
_rocs_plan_ordset_popcount_byte(uint8_t byte)
{
    uint64_t count = 0;
    for (uint8_t bit = 0; bit < 8; bit++) {
        if ((byte & (uint8_t)(UINT8_C(1) << bit)) != 0) {
            count++;
        }
    }
    return count;
}

// Materialize a lazily-allocated bitmap. Empty sets carry bits == nullptr:
// query plans build one ordset per (shard, disjunct) and in a whole-store
// walk nearly all of them stay empty, so eagerly mapping a record_count-sized
// buffer for each dominated the walk (one mmap-registered buffer per empty
// set, plus one registry teardown per buffer at request end).
static n00b_result_t(bool)
_rocs_plan_ordset_bits_ensure(n00b_plan_ordset_t *set)
{
    if (set->bits != nullptr) {
        return n00b_result_ok(bool, true);
    }

    auto bytes_r = _rocs_plan_ordset_byte_count(set->record_count);
    if (n00b_result_is_err(bytes_r)) {
        return n00b_result_err(bool, n00b_result_get_err(bytes_r));
    }

    set->bits = n00b_buffer_new((int64_t)n00b_result_get(bytes_r),
                                .allocator = set->allocator);
    if (set->bits == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
_rocs_plan_ordset_check(n00b_plan_ordset_t *set)
{
    if (set == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    auto bytes_r = _rocs_plan_ordset_byte_count(set->record_count);
    if (n00b_result_is_err(bytes_r)) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    if (set->bits == nullptr) {
        // Lazily-allocated set: valid only while empty. count > 0 always
        // materializes the bitmap first (see _rocs_plan_ordset_bits_ensure).
        if (set->count != 0) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        return n00b_result_ok(bool, true);
    }

    uint64_t bytes = n00b_result_get(bytes_r);
    if ((uint64_t)set->bits->byte_len != bytes
        || (bytes != 0 && set->bits->data == nullptr)
        || set->count > set->record_count) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(bool, true);
}

static bool
_rocs_plan_ordset_bit_is_set(n00b_plan_ordset_t *set, uint64_t ordinal)
{
    if (set->bits == nullptr) {
        return false;
    }
    uint64_t byte_ix = ordinal >> 3;
    uint8_t  mask    = (uint8_t)(UINT8_C(1) << (ordinal & UINT64_C(7)));
    return (((uint8_t)set->bits->data[byte_ix]) & mask) != 0;
}

static bool
_rocs_plan_ordset_bit_insert(n00b_plan_ordset_t *set, uint64_t ordinal)
{
    uint64_t byte_ix = ordinal >> 3;
    uint8_t  mask    = (uint8_t)(UINT8_C(1) << (ordinal & UINT64_C(7)));
    uint8_t  byte    = (uint8_t)set->bits->data[byte_ix];

    if ((byte & mask) != 0) {
        return false;
    }

    set->bits->data[byte_ix] = (char)(byte | mask);
    set->count++;
    // Any in-place mutation invalidates the ascending-ordinal cache.
    set->ord_cache = nullptr;
    return true;
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_ordset_new(uint64_t record_count, bool full) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto bytes_r = _rocs_plan_ordset_byte_count(record_count);
    if (n00b_result_is_err(bytes_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(bytes_r));
    }

    uint64_t bytes = n00b_result_get(bytes_r);
    n00b_plan_ordset_t *set = n00b_alloc_with_opts(
        n00b_plan_ordset_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    set->record_count = record_count;
    set->count        = 0;
    set->allocator    = allocator;
    set->ord_cache    = nullptr;
    // The bitmap is allocated lazily on first insert; an empty set never
    // carries one. See _rocs_plan_ordset_bits_ensure for why.
    set->bits         = nullptr;

    if (full) {
        auto ensure_r = _rocs_plan_ordset_bits_ensure(set);
        if (n00b_result_is_err(ensure_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(ensure_r));
        }
        if (bytes != 0) {
            for (uint64_t i = 0; i < bytes; i++) {
                set->bits->data[i] = (char)UINT8_MAX;
            }
            if ((record_count & UINT64_C(7)) != 0) {
                set->bits->data[bytes - 1] =
                    (char)_rocs_plan_ordset_tail_mask(record_count);
            }
        }
        set->count = record_count;
    }

    return n00b_result_ok(n00b_plan_ordset_t *, set);
}

// Deep copy. Callers pass a checked set; an empty source yields an empty
// (bitmap-free) copy.
static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_ordset_clone(n00b_plan_ordset_t *set) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto out_r = _rocs_plan_ordset_new(set->record_count,
                                       false,
                                       .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }

    n00b_plan_ordset_t *out = n00b_result_get(out_r);
    if (set->count != 0) {
        auto ensure_r = _rocs_plan_ordset_bits_ensure(out);
        if (n00b_result_is_err(ensure_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(ensure_r));
        }
        memcpy(out->bits->data,
               set->bits->data,
               (size_t)set->bits->byte_len);
        out->count = set->count;
    }

    return n00b_result_ok(n00b_plan_ordset_t *, out);
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_ordset_binary(n00b_plan_ordset_t             *left,
                         n00b_plan_ordset_t             *right,
                         _rocs_plan_ordset_binary_op_t    op) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto left_ok = _rocs_plan_ordset_check(left);
    if (n00b_result_is_err(left_ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(left_ok));
    }
    auto right_ok = _rocs_plan_ordset_check(right);
    if (n00b_result_is_err(right_ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(right_ok));
    }
    if (left->record_count != right->record_count) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               N00B_PLAN_ERR_UNIVERSE);
    }

    // Empty operands take the allocation-free path. A whole-store walk builds
    // one empty set per (shard, disjunct) and then ORs them together, so both
    // the operands and the combined results must stay bitmap-free or the
    // combining tree re-creates the very buffers laziness removed.
    if (left->count == 0 || right->count == 0) {
        switch (op) {
        case _rocs_plan_ordset_op_union: {
            n00b_plan_ordset_t *src = left->count == 0 ? right : left;
            if (src->count == 0) {
                break;
            }
            return _rocs_plan_ordset_clone(src, .allocator = allocator);
        }
        case _rocs_plan_ordset_op_intersection:
            break;
        case _rocs_plan_ordset_op_difference:
            if (left->count != 0) {
                return _rocs_plan_ordset_clone(left, .allocator = allocator);
            }
            break;
        }
        return _rocs_plan_ordset_new(left->record_count,
                                     false,
                                     .allocator = allocator);
    }

    auto out_r = _rocs_plan_ordset_new(left->record_count,
                                       false,
                                       .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }

    n00b_plan_ordset_t *out = n00b_result_get(out_r);
    {
        auto ensure_r = _rocs_plan_ordset_bits_ensure(out);
        if (n00b_result_is_err(ensure_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(ensure_r));
        }
    }
    uint64_t bytes = (uint64_t)left->bits->byte_len;
    uint64_t            count = 0;
    for (uint64_t i = 0; i < bytes; i++) {
        uint8_t l = (uint8_t)left->bits->data[i];
        uint8_t r = (uint8_t)right->bits->data[i];
        uint8_t v = 0;

        switch (op) {
        case _rocs_plan_ordset_op_union:
            v = (uint8_t)(l | r);
            break;
        case _rocs_plan_ordset_op_intersection:
            v = (uint8_t)(l & r);
            break;
        case _rocs_plan_ordset_op_difference:
            v = (uint8_t)(l & (uint8_t)~r);
            break;
        }

        if (i + 1 == bytes && (out->record_count & UINT64_C(7)) != 0) {
            v &= _rocs_plan_ordset_tail_mask(out->record_count);
        }
        out->bits->data[i] = (char)v;
        count += _rocs_plan_ordset_popcount_byte(v);
    }

    out->count = count;
    return n00b_result_ok(n00b_plan_ordset_t *, out);
}

bool
_rocs_plan_candidate_set_is_broad(n00b_plan_ordset_t *candidates)
{
    if (candidates == nullptr
        || candidates->record_count < N00B_ROCS_PLAN_BROAD_CANDIDATE_MIN_RECORDS
        || candidates->count == 0) {
        return false;
    }

    uint64_t whole = candidates->record_count / UINT64_C(100);
    uint64_t rem   = candidates->record_count % UINT64_C(100);
    uint64_t threshold =
        whole * N00B_ROCS_PLAN_BROAD_CANDIDATE_PERCENT
        + (rem * N00B_ROCS_PLAN_BROAD_CANDIDATE_PERCENT
           + UINT64_C(99)) / UINT64_C(100);
    if (threshold == 0) {
        threshold = 1;
    }

    return candidates->count >= threshold;
}

// Term, full-text, and n-gram selection differ only in the advertised operator
// and the accepted descriptor kind. The hint is a function of (index, field,
// op) with no value, so it cannot tell a selective literal from a common one.
static n00b_store_index_t *
_rocs_plan_choose_index(n00b_plan_index_list_t *indexes,
                        n00b_string_t          *field,
                        n00b_store_index_op_t   op,
                        n00b_store_index_kind_t kind)
{
    if (indexes == nullptr || field == nullptr) {
        return nullptr;
    }

    n00b_store_index_t *best        = nullptr;
    double              best_hint   = 0.0;
    size_t              index_count = n00b_list_len(*indexes);
    for (size_t i = 0; i < index_count; i++) {
        n00b_store_index_t *index = n00b_list_get(*indexes, i);
        if (index == nullptr) {
            continue;
        }

        n00b_store_advert_t advert =
            n00b_store_index_advertise(index, field, (int64_t)op);
        if (!advert.accelerates || advert.kind != kind) {
            continue;
        }

        if (best == nullptr || advert.selectivity_hint < best_hint) {
            best      = index;
            best_hint = advert.selectivity_hint;
        }
    }

    return best;
}

static n00b_store_index_t *
_rocs_plan_choose_catch_all_index(n00b_plan_index_list_t *indexes)
{
    if (indexes == nullptr) {
        return nullptr;
    }

    size_t index_count = n00b_list_len(*indexes);
    for (size_t i = 0; i < index_count; i++) {
        n00b_store_index_t *index = n00b_list_get(*indexes, i);
        if (index == nullptr) {
            continue;
        }

        auto catch_all_r = n00b_store_index_is_catch_all(index);
        if (n00b_result_is_err(catch_all_r)
            || !n00b_result_get(catch_all_r)) {
            continue;
        }

        auto kind_r = n00b_store_index_kind(index);
        if (n00b_result_is_ok(kind_r)
            && n00b_result_get(kind_r) == N00B_STORE_INDEX_FULLTEXT) {
            return index;
        }
    }

    return nullptr;
}

n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_ordset_from_postings(n00b_store_postings_t *postings,
                                uint64_t               record_count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (postings == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    auto set_r = _rocs_plan_ordset_new(record_count,
                                      false,
                                      .allocator = allocator);
    if (n00b_result_is_err(set_r)) {
        return set_r;
    }
    n00b_plan_ordset_t *set = n00b_result_get(set_r);

    auto len_r = n00b_store_postings_len(postings);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_STATE);
    }

    uint64_t posting_count = n00b_result_get(len_r);
    for (uint64_t i = 0; i < posting_count; i++) {
        auto pos_r = n00b_store_postings_pos(postings, i);
        if (n00b_result_is_err(pos_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        n00b_option_t(n00b_store_pos_t) pos_opt = n00b_result_get(pos_r);
        if (!n00b_option_is_set(pos_opt)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        n00b_store_pos_t pos = n00b_option_get(pos_opt);
        if (pos.ordinal >= record_count) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_ORDINAL);
        }

        auto insert_r = n00b_plan_ordset_insert(set, pos.ordinal);
        if (n00b_result_is_err(insert_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(insert_r));
        }
    }

    return n00b_result_ok(n00b_plan_ordset_t *, set);
}

static n00b_result_t(n00b_json_node_t *)
_rocs_plan_ngram_query_node(n00b_string_t    *text,
                            n00b_store_index_t *index) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (text == nullptr || index == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_STATE);
    }

    auto ngram_n_r = n00b_store_index_ngram_n(index);
    if (n00b_result_is_err(ngram_n_r)) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_json_node_t *query =
        n00b_json_string_new_from_n00b(text, .allocator = allocator);
    if (query == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_STATE);
    }

    auto terms_r =
        n00b_store_normalize_text_ngrams(query,
                                         .ngram_n   = n00b_result_get(ngram_n_r),
                                         .allocator = allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_STATE);
    }
    if (n00b_list_len(*n00b_result_get(terms_r)) == 0) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_EMPTY);
    }

    return n00b_result_ok(n00b_json_node_t *, query);
}

// True when `field` is declared in the schema with the given index kind. A
// declared index is authoritative: every record that populates the field is
// indexed, so "declared indexed + no built index on this shard" means no record
// populated it here -> an equality on it has zero matches, and must resolve to
// an EMPTY exact set, never a residual full scan. Returns false (caller falls
// back to the residual path) when the schema is unavailable or the field is not
// declared with that index kind.
static bool
_rocs_plan_field_declared_indexed(n00b_store_schema_t     *schema,
                                  n00b_string_t           *field,
                                  n00b_store_index_kind_t  want_kind)
{
    if (schema == nullptr || field == nullptr) {
        return false;
    }
    auto field_r = n00b_store_schema_find_field(schema, field);
    if (n00b_result_is_err(field_r)) {
        return false;
    }
    n00b_option_t(n00b_store_field_t *) field_opt = n00b_result_get(field_r);
    if (!n00b_option_is_set(field_opt)) {
        return false;
    }
    auto kind_r = n00b_store_field_get_index_kind(n00b_option_get(field_opt));
    if (n00b_result_is_err(kind_r)) {
        return false;
    }
    return n00b_result_get(kind_r) == want_kind;
}

n00b_result_t(uint64_t)
_rocs_plan_hot_record_count(n00b_store_shard_t *shard)
{
    if (shard == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    if (shard->records == nullptr || shard->state != N00B_SHARD_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_STATE);
    }

    uint64_t records_len = (uint64_t)n00b_list_len(*shard->records);
    if (records_len != shard->record_count) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(uint64_t, records_len);
}

n00b_result_t(uint64_t)
_rocs_plan_mapped_record_count(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }

    auto state_r = n00b_store_map_shard_state(shard);
    if (n00b_result_is_err(state_r)) {
        n00b_err_t err = n00b_result_get_err(state_r);
        return n00b_result_err(
            uint64_t,
            err == N00B_STORE_MAP_ERR_ARG ? N00B_PLAN_ERR_ARG
                                          : N00B_PLAN_ERR_STATE);
    }
    if (n00b_result_get(state_r) != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_STATE);
    }

    auto len_r = n00b_store_map_shard_records_len(shard);
    if (n00b_result_is_err(len_r)) {
        n00b_err_t err = n00b_result_get_err(len_r);
        return n00b_result_err(
            uint64_t,
            err == N00B_STORE_MAP_ERR_ARG ? N00B_PLAN_ERR_ARG
                                          : N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(uint64_t, n00b_result_get(len_r));
}

n00b_err_t
_rocs_plan_index_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_INDEX_ERR_ARG:
        return N00B_PLAN_ERR_ARG;
    default:
        return N00B_PLAN_ERR_STATE;
    }
}

n00b_result_t(n00b_json_node_t *)
_rocs_plan_value_node(n00b_plan_value_t value)
{
    if (!_rocs_plan_value_is_set(value)
        || !n00b_variant_is_type(value, n00b_json_node_t *)) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_json_node_t *node = n00b_variant_get(value, n00b_json_node_t *);
    if (node == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(n00b_json_node_t *, node);
}

static n00b_result_t(n00b_string_t *)
_rocs_plan_partition_route_for_value(_rocs_plan_prune_ctx_t *ctx,
                                     n00b_plan_value_t       value)
{
    if (ctx == nullptr || ctx->policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_ARG);
    }

    auto value_r = _rocs_plan_value_node(value);
    if (n00b_result_is_err(value_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(value_r));
    }

    auto route_r = n00b_store_partition_route_value_for_plan(
        ctx->policy,
        n00b_result_get(value_r),
        .allocator = ctx->allocator);
    if (n00b_result_is_err(route_r)) {
        return n00b_result_err(n00b_string_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(route_r)));
    }
    return route_r;
}

static n00b_result_t(_rocs_plan_prune_t)
_rocs_plan_prune_for_leaf(_rocs_plan_prune_ctx_t *ctx,
                          n00b_plan_predicate_t  *predicate)
{
    if (ctx == nullptr || predicate == nullptr) {
        return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_ARG);
    }
    if (ctx->field == nullptr || predicate->target == nullptr
        || predicate->target->kind != N00B_PLAN_TARGET_FIELD
        || predicate->target->field == nullptr
        || !n00b_unicode_str_eq(predicate->target->field, ctx->field)) {
        return n00b_result_ok(_rocs_plan_prune_t,
                              _rocs_plan_prune_unconstrained());
    }

    // Under ingest-clock time partitioning the shard's partition key reflects
    // arrival time, not this field, so it cannot soundly prune an event-time
    // predicate (matching events may live in any arrival bucket).  Leave the
    // query unconstrained at the partition layer; the field index still filters,
    // and per-shard event-ts range pruning is the planned fast-follow.
    auto kind_r = n00b_store_partition_policy_get_kind(ctx->policy);
    if (n00b_result_is_ok(kind_r)
        && n00b_result_get(kind_r) == N00B_STORE_PARTITION_TIME) {
        auto src_r = n00b_store_partition_policy_get_time_source(ctx->policy);
        if (n00b_result_is_ok(src_r)
            && n00b_result_get(src_r)
                   == N00B_STORE_TIME_SOURCE_INGEST_CLOCK) {
            return n00b_result_ok(_rocs_plan_prune_t,
                                  _rocs_plan_prune_unconstrained());
        }
    }

    _rocs_plan_route_list_t *routes =
        _rocs_plan_route_list_new(.allocator = ctx->allocator);

    switch (predicate->leaf_op) {
    case N00B_PLAN_LEAF_EQ: {
        auto route_r = _rocs_plan_partition_route_for_value(ctx,
                                                            predicate->value);
        if (n00b_result_is_err(route_r)) {
            return n00b_result_err(_rocs_plan_prune_t,
                                   n00b_result_get_err(route_r));
        }
        auto append_r =
            _rocs_plan_route_list_append_unique(routes, n00b_result_get(route_r));
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(_rocs_plan_prune_t,
                                   n00b_result_get_err(append_r));
        }
        return n00b_result_ok(
            _rocs_plan_prune_t,
            ((_rocs_plan_prune_t){
                .constrained = true,
                .routes      = routes,
            }));
    }

    case N00B_PLAN_LEAF_IN: {
        if (predicate->values == nullptr) {
            return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->values);
        if (len == 0) {
            return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_STATE);
        }
        for (size_t i = 0; i < len; i++) {
            auto route_r = _rocs_plan_partition_route_for_value(
                ctx,
                n00b_list_get(*predicate->values, i));
            if (n00b_result_is_err(route_r)) {
                return n00b_result_err(_rocs_plan_prune_t,
                                       n00b_result_get_err(route_r));
            }
            auto append_r = _rocs_plan_route_list_append_unique(
                routes,
                n00b_result_get(route_r));
            if (n00b_result_is_err(append_r)) {
                return n00b_result_err(_rocs_plan_prune_t,
                                       n00b_result_get_err(append_r));
            }
        }
        return n00b_result_ok(
            _rocs_plan_prune_t,
            ((_rocs_plan_prune_t){
                .constrained = true,
                .routes      = routes,
            }));
    }

    case N00B_PLAN_LEAF_RANGE:
    case N00B_PLAN_LEAF_EXISTS:
    case N00B_PLAN_LEAF_CONTAINS:
    case N00B_PLAN_LEAF_PREFIX:
    case N00B_PLAN_LEAF_REGEX:
    case N00B_PLAN_LEAF_UNDER:
        return n00b_result_ok(_rocs_plan_prune_t,
                              _rocs_plan_prune_unconstrained());
    }

    return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(_rocs_plan_prune_t)
_rocs_plan_prune_for_and(_rocs_plan_prune_ctx_t *ctx,
                         n00b_plan_predicate_t  *predicate)
{
    if (ctx == nullptr || predicate == nullptr || predicate->children == nullptr) {
        return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_ARG);
    }

    size_t len = n00b_list_len(*predicate->children);
    if (len < 2) {
        return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_STATE);
    }

    _rocs_plan_prune_t out = _rocs_plan_prune_unconstrained();
    for (size_t i = 0; i < len; i++) {
        auto child_r =
            _rocs_plan_prune_for_predicate(ctx,
                                           n00b_list_get(*predicate->children,
                                                         i));
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }

        _rocs_plan_prune_t child = n00b_result_get(child_r);
        if (!child.constrained) {
            continue;
        }
        if (!out.constrained) {
            out = child;
            continue;
        }

        out.routes = _rocs_plan_route_list_intersection(
            out.routes,
            child.routes,
            .allocator = ctx->allocator);
    }

    return n00b_result_ok(_rocs_plan_prune_t, out);
}

static n00b_result_t(_rocs_plan_prune_t)
_rocs_plan_prune_for_predicate(_rocs_plan_prune_ctx_t *ctx,
                               n00b_plan_predicate_t  *predicate)
{
    if (ctx == nullptr || predicate == nullptr) {
        return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind == N00B_PLAN_PREDICATE_FALSE) {
        return n00b_result_ok(
            _rocs_plan_prune_t,
            ((_rocs_plan_prune_t){
                .constrained = true,
                .routes      = _rocs_plan_route_list_new(
                    .allocator = ctx->allocator),
            }));
    }
    if (ctx->field == nullptr) {
        return n00b_result_ok(_rocs_plan_prune_t,
                              _rocs_plan_prune_unconstrained());
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
        return _rocs_plan_prune_for_leaf(ctx, predicate);
    case N00B_PLAN_PREDICATE_AND:
        return _rocs_plan_prune_for_and(ctx, predicate);
    case N00B_PLAN_PREDICATE_FALSE:
        return n00b_result_ok(
            _rocs_plan_prune_t,
            ((_rocs_plan_prune_t){
                .constrained = true,
                .routes      = _rocs_plan_route_list_new(
                    .allocator = ctx->allocator),
            }));
    case N00B_PLAN_PREDICATE_OR:
    case N00B_PLAN_PREDICATE_NOT:
        return n00b_result_ok(_rocs_plan_prune_t,
                              _rocs_plan_prune_unconstrained());
    }

    return n00b_result_err(_rocs_plan_prune_t, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(bool)
_rocs_plan_partition_may_match(_rocs_plan_prune_t  prune,
                               n00b_string_t      *partition_key)
{
    if (!prune.constrained) {
        return n00b_result_ok(bool, true);
    }
    if (prune.routes == nullptr || partition_key == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(
        bool,
        _rocs_plan_route_list_contains(prune.routes, partition_key));
}

static n00b_result_t(n00b_plan_predicate_t *)
_rocs_plan_bool_new(n00b_plan_predicate_kind_t  kind,
                    n00b_plan_predicate_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_err_t child_err = _rocs_plan_check_children(children);
    if (child_err != N00B_PLAN_OK) {
        return n00b_result_err(n00b_plan_predicate_t *, child_err);
    }

    n00b_plan_predicate_t *predicate =
        _rocs_plan_predicate_new(kind, .allocator = allocator);
    predicate->children = children;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

static n00b_plan_path_component_list_t *
_rocs_plan_path_component_list_copy(
    n00b_plan_path_component_list_t *components) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_path_component_list_t *copy =
        n00b_plan_path_component_list_new(.allocator = allocator);

    size_t len = n00b_list_len(*components);
    for (size_t i = 0; i < len; i++) {
        n00b_plan_path_component_t *component =
            n00b_list_get(*components, i);
        n00b_plan_path_component_t *component_copy =
            _rocs_plan_path_component_copy(component,
                                           .allocator = allocator);
        n00b_list_push(*copy, component_copy);
    }

    return copy;
}

n00b_string_t *
n00b_plan_err_str(n00b_err_t err)
{
    switch ((n00b_plan_err_t)err) {
    case N00B_PLAN_OK:
        return r"N00B_PLAN_OK";
    case N00B_PLAN_ERR_ARG:
        return r"N00B_PLAN_ERR_ARG";
    case N00B_PLAN_ERR_STATE:
        return r"N00B_PLAN_ERR_STATE";
    case N00B_PLAN_ERR_EMPTY:
        return r"N00B_PLAN_ERR_EMPTY";
    case N00B_PLAN_ERR_ANY_UNSUPPORTED:
        return r"N00B_PLAN_ERR_ANY_UNSUPPORTED";
    case N00B_PLAN_ERR_ORDINAL:
        return r"N00B_PLAN_ERR_ORDINAL";
    case N00B_PLAN_ERR_UNIVERSE:
        return r"N00B_PLAN_ERR_UNIVERSE";
    }

    return r"N00B_PLAN_ERR_UNKNOWN";
}

n00b_result_t(n00b_plan_target_t *)
n00b_plan_target_field(n00b_string_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (field == nullptr || field->u8_bytes == 0) {
        return n00b_result_err(n00b_plan_target_t *, N00B_PLAN_ERR_ARG);
    }

    n00b_plan_target_t *target = n00b_alloc_with_opts(
        n00b_plan_target_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    target->kind  = N00B_PLAN_TARGET_FIELD;
    target->field = field;
    return n00b_result_ok(n00b_plan_target_t *, target);
}

n00b_result_t(n00b_plan_target_t *)
n00b_plan_target_any() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_target_t *target = n00b_alloc_with_opts(
        n00b_plan_target_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    target->kind = N00B_PLAN_TARGET_ANY;
    return n00b_result_ok(n00b_plan_target_t *, target);
}

n00b_result_t(n00b_plan_target_kind_t)
n00b_plan_target_kind(n00b_plan_target_t *target)
{
    if (target == nullptr) {
        return n00b_result_err(n00b_plan_target_kind_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(n00b_plan_target_kind_t, target->kind);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_plan_target_field_name(n00b_plan_target_t *target)
{
    if (target == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (target->kind != N00B_PLAN_TARGET_FIELD) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }
    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, target->field));
}

n00b_plan_predicate_list_t *
n00b_plan_predicate_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_predicate_list_t *list = n00b_alloc_with_opts(
        n00b_plan_predicate_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_plan_predicate_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

n00b_result_t(bool)
n00b_plan_predicate_list_append(n00b_plan_predicate_list_t *list,
                                n00b_plan_predicate_t      *child)
{
    if (list == nullptr || child == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    n00b_list_push(*list, child);
    return n00b_result_ok(bool, true);
}

n00b_plan_index_list_t *
n00b_plan_index_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_index_list_t *list = n00b_alloc_with_opts(
        n00b_plan_index_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_store_index_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

n00b_result_t(bool)
n00b_plan_index_list_append(n00b_plan_index_list_t *list,
                            n00b_store_index_t     *index)
{
    if (list == nullptr || index == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    n00b_list_push(*list, index);
    return n00b_result_ok(bool, true);
}

n00b_plan_value_list_t *
n00b_plan_value_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_value_list_t *list = n00b_alloc_with_opts(
        n00b_plan_value_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_plan_value_t,
                                  .allocator = allocator);
    return list;
}

n00b_result_t(bool)
n00b_plan_value_list_append(n00b_plan_value_list_t *list,
                            n00b_plan_value_t      value)
{
    if (list == nullptr || !_rocs_plan_value_is_set(value)) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    n00b_list_push(*list, value);
    return n00b_result_ok(bool, true);
}

n00b_plan_path_component_list_t *
n00b_plan_path_component_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_path_component_list_t *list = n00b_alloc_with_opts(
        n00b_plan_path_component_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_plan_path_component_t *,
                                  .allocator = allocator);
    return list;
}

n00b_result_t(bool)
n00b_plan_path_component_list_append_key(
    n00b_plan_path_component_list_t *list,
    n00b_string_t                   *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (list == nullptr || key == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    n00b_plan_path_component_t *component = n00b_alloc_with_opts(
        n00b_plan_path_component_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    component->kind = N00B_PLAN_PATH_KEY;
    component->key  = key;
    n00b_list_push(*list, component);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_plan_path_component_list_append_index(
    n00b_plan_path_component_list_t *list,
    uint64_t                         index) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (list == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    n00b_plan_path_component_t *component = n00b_alloc_with_opts(
        n00b_plan_path_component_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    component->kind  = N00B_PLAN_PATH_INDEX;
    component->index = index;
    n00b_list_push(*list, component);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_plan_path_t *)
n00b_plan_path_new(n00b_plan_path_component_list_t *components) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (components == nullptr) {
        return n00b_result_err(n00b_plan_path_t *, N00B_PLAN_ERR_ARG);
    }

    size_t len = n00b_list_len(*components);
    for (size_t i = 0; i < len; i++) {
        if (!_rocs_plan_path_component_is_valid(
                n00b_list_get(*components, i))) {
            return n00b_result_err(n00b_plan_path_t *, N00B_PLAN_ERR_ARG);
        }
    }

    n00b_plan_path_t *path = n00b_alloc_with_opts(
        n00b_plan_path_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    path->components =
        _rocs_plan_path_component_list_copy(components,
                                           .allocator = allocator);
    return n00b_result_ok(n00b_plan_path_t *, path);
}

n00b_result_t(uint64_t)
n00b_plan_path_component_count(n00b_plan_path_t *path)
{
    if (path == nullptr || path->components == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*path->components));
}

n00b_result_t(n00b_option_t(n00b_plan_path_component_t *))
n00b_plan_path_component_at(n00b_plan_path_t *path, uint64_t ordinal)
{
    if (path == nullptr || path->components == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_path_component_t *),
                               N00B_PLAN_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*path->components);
    if (ordinal >= len) {
        return n00b_result_ok(n00b_option_t(n00b_plan_path_component_t *),
                              n00b_option_none(n00b_plan_path_component_t *));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_plan_path_component_t *),
        n00b_option_set(n00b_plan_path_component_t *,
                        n00b_list_get(*path->components, (size_t)ordinal)));
}

n00b_result_t(n00b_plan_path_component_kind_t)
n00b_plan_path_component_kind(n00b_plan_path_component_t *component)
{
    if (!_rocs_plan_path_component_is_valid(component)) {
        return n00b_result_err(n00b_plan_path_component_kind_t,
                               N00B_PLAN_ERR_ARG);
    }

    return n00b_result_ok(n00b_plan_path_component_kind_t, component->kind);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_plan_path_component_key(n00b_plan_path_component_t *component)
{
    if (!_rocs_plan_path_component_is_valid(component)) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_PLAN_ERR_ARG);
    }

    if (component->kind != N00B_PLAN_PATH_KEY) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, component->key));
}

n00b_result_t(n00b_option_t(uint64_t))
n00b_plan_path_component_index(n00b_plan_path_component_t *component)
{
    if (!_rocs_plan_path_component_is_valid(component)) {
        return n00b_result_err(n00b_option_t(uint64_t), N00B_PLAN_ERR_ARG);
    }

    if (component->kind != N00B_PLAN_PATH_INDEX) {
        return n00b_result_ok(n00b_option_t(uint64_t),
                              n00b_option_none(uint64_t));
    }

    return n00b_result_ok(n00b_option_t(uint64_t),
                          n00b_option_set(uint64_t, component->index));
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_empty(uint64_t record_count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_ordset_new(record_count,
                                false,
                                .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_full(uint64_t record_count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_ordset_new(record_count, true, .allocator = allocator);
}

n00b_result_t(uint64_t)
n00b_plan_ordset_record_count(n00b_plan_ordset_t *set)
{
    auto ok = _rocs_plan_ordset_check(set);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(ok));
    }
    return n00b_result_ok(uint64_t, set->record_count);
}

n00b_result_t(uint64_t)
n00b_plan_ordset_count(n00b_plan_ordset_t *set)
{
    auto ok = _rocs_plan_ordset_check(set);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(ok));
    }
    return n00b_result_ok(uint64_t, set->count);
}

n00b_result_t(bool)
n00b_plan_ordset_insert(n00b_plan_ordset_t *set, uint64_t ordinal)
{
    auto ok = _rocs_plan_ordset_check(set);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(bool, n00b_result_get_err(ok));
    }
    if (ordinal >= set->record_count) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ORDINAL);
    }

    auto ensure_r = _rocs_plan_ordset_bits_ensure(set);
    if (n00b_result_is_err(ensure_r)) {
        return n00b_result_err(bool, n00b_result_get_err(ensure_r));
    }

    return n00b_result_ok(bool, _rocs_plan_ordset_bit_insert(set, ordinal));
}

void
n00b_plan_ordset_free(n00b_plan_ordset_t *set)
{
    if (set == nullptr) {
        return;
    }
    if (set->bits != nullptr) {
        n00b_free(set->bits);
    }
    n00b_free(set);
}

n00b_result_t(bool)
n00b_plan_ordset_contains(n00b_plan_ordset_t *set, uint64_t ordinal)
{
    auto ok = _rocs_plan_ordset_check(set);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(bool, n00b_result_get_err(ok));
    }
    if (ordinal >= set->record_count) {
        return n00b_result_ok(bool, false);
    }

    return n00b_result_ok(bool, _rocs_plan_ordset_bit_is_set(set, ordinal));
}

n00b_result_t(n00b_option_t(uint64_t))
n00b_plan_ordset_at(n00b_plan_ordset_t *set, uint64_t index)
{
    auto ok = _rocs_plan_ordset_check(set);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_option_t(uint64_t),
                               n00b_result_get_err(ok));
    }
    if (index >= set->count) {
        return n00b_result_ok(n00b_option_t(uint64_t),
                              n00b_option_none(uint64_t));
    }

    // Build the ascending-ordinal cache once (single O(record_count) bitmap
    // walk, byte-at-a-time skipping empty bytes), then serve every at() from it
    // in O(1). This turns an ordset_at(0..count-1) iteration from O(count *
    // record_count) into O(record_count + count).
    if (set->ord_cache == nullptr && set->count != 0) {
        uint64_t *cache = n00b_alloc_array_with_opts(
            uint64_t,
            set->count,
            &(n00b_alloc_opts_t){.allocator = set->allocator});
        if (cache == nullptr) {
            return n00b_result_err(n00b_option_t(uint64_t),
                                   N00B_PLAN_ERR_STATE);
        }
        uint64_t             seen = 0;
        const uint8_t *const data = (const uint8_t *)set->bits->data;
        for (uint64_t ordinal = 0; ordinal < set->record_count;) {
            uint8_t b = data[ordinal >> 3];
            if (b == 0) {
                // Skip the rest of an all-zero byte in one step.
                ordinal = (ordinal & ~UINT64_C(7)) + 8;
                continue;
            }
            if ((b & (uint8_t)(UINT8_C(1) << (ordinal & UINT64_C(7)))) != 0) {
                cache[seen++] = ordinal;
                if (seen == set->count) {
                    break;
                }
            }
            ordinal++;
        }
        if (seen != set->count) {
            return n00b_result_err(n00b_option_t(uint64_t),
                                   N00B_PLAN_ERR_STATE);
        }
        set->ord_cache = cache;
    }

    return n00b_result_ok(n00b_option_t(uint64_t),
                          n00b_option_set(uint64_t, set->ord_cache[index]));
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_union(n00b_plan_ordset_t *left,
                       n00b_plan_ordset_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_ordset_binary(left,
                                   right,
                                   _rocs_plan_ordset_op_union,
                                   .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_intersection(n00b_plan_ordset_t *left,
                              n00b_plan_ordset_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_ordset_binary(left,
                                   right,
                                   _rocs_plan_ordset_op_intersection,
                                   .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_difference(n00b_plan_ordset_t *left,
                            n00b_plan_ordset_t *right) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_ordset_binary(left,
                                   right,
                                   _rocs_plan_ordset_op_difference,
                                   .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_ordset_complement(n00b_plan_ordset_t *set) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto ok = _rocs_plan_ordset_check(set);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(ok));
    }

    // Complement of an empty set is the full universe; the empty operand has
    // no bitmap to invert.
    if (set->count == 0) {
        return _rocs_plan_ordset_new(set->record_count,
                                     true,
                                     .allocator = allocator);
    }

    auto out_r = _rocs_plan_ordset_new(set->record_count,
                                      false,
                                      .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }

    n00b_plan_ordset_t *out = n00b_result_get(out_r);
    {
        auto ensure_r = _rocs_plan_ordset_bits_ensure(out);
        if (n00b_result_is_err(ensure_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(ensure_r));
        }
    }
    uint64_t bytes = (uint64_t)set->bits->byte_len;
    uint64_t count = 0;
    for (uint64_t i = 0; i < bytes; i++) {
        uint8_t v = (uint8_t)~((uint8_t)set->bits->data[i]);
        if (i + 1 == bytes && (set->record_count & UINT64_C(7)) != 0) {
            v &= _rocs_plan_ordset_tail_mask(set->record_count);
        }
        out->bits->data[i] = (char)v;
        count += _rocs_plan_ordset_popcount_byte(v);
    }

    out->count = count;
    return n00b_result_ok(n00b_plan_ordset_t *, out);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_eq(n00b_plan_target_t *target,
                       n00b_plan_value_t   value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!_rocs_plan_value_is_set(value)) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_EQ,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->value = value;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_in(n00b_plan_target_t     *target,
                       n00b_plan_value_list_t *values) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (values == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    size_t len = n00b_list_len(*values);
    if (len == 0) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_EMPTY);
    }
    for (size_t i = 0; i < len; i++) {
        if (!_rocs_plan_value_is_set(n00b_list_get(*values, i))) {
            return n00b_result_err(n00b_plan_predicate_t *,
                                   N00B_PLAN_ERR_ARG);
        }
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_IN,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->values = values;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_range(n00b_plan_target_t *target,
                          n00b_plan_value_t   lower,
                          n00b_plan_value_t   upper) _kargs
{
    bool              include_lower = true;
    bool              include_upper = true;
    n00b_allocator_t *allocator     = nullptr;
}
{
    if (!_rocs_plan_value_is_set(lower) || !_rocs_plan_value_is_set(upper)) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_RANGE,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->lower         = lower;
    predicate->upper         = upper;
    predicate->include_lower = include_lower;
    predicate->include_upper = include_upper;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_exists(n00b_plan_target_t *target) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_leaf_new(target,
                              N00B_PLAN_LEAF_EXISTS,
                              .allocator = allocator);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_contains(n00b_plan_target_t *target,
                             n00b_string_t      *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (term == nullptr || term->u8_bytes == 0) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_CONTAINS,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->text = term;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_prefix(n00b_plan_target_t *target,
                           n00b_string_t      *prefix) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (prefix == nullptr || prefix->u8_bytes == 0) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_PREFIX,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->text = prefix;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_regex(n00b_plan_target_t *target,
                          n00b_regex_t       *regex) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (regex == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_REGEX,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->regex = regex;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_under(n00b_plan_target_t *target,
                          n00b_plan_path_t   *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (path == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    auto leaf_r = _rocs_plan_leaf_new(target,
                                     N00B_PLAN_LEAF_UNDER,
                                     .allocator = allocator);
    if (n00b_result_is_err(leaf_r)) {
        return leaf_r;
    }

    n00b_plan_predicate_t *predicate = n00b_result_get(leaf_r);
    predicate->path = path;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_and(n00b_plan_predicate_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_bool_new(N00B_PLAN_PREDICATE_AND,
                              children,
                              .allocator = allocator);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_or(n00b_plan_predicate_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return _rocs_plan_bool_new(N00B_PLAN_PREDICATE_OR,
                              children,
                              .allocator = allocator);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_not(n00b_plan_predicate_t *child) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (child == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    n00b_plan_predicate_t *predicate =
        _rocs_plan_predicate_new(N00B_PLAN_PREDICATE_NOT,
                                .allocator = allocator);
    predicate->child = child;
    return n00b_result_ok(n00b_plan_predicate_t *, predicate);
}

n00b_result_t(n00b_plan_predicate_t *)
n00b_plan_predicate_false() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_result_ok(
        n00b_plan_predicate_t *,
        _rocs_plan_predicate_new(N00B_PLAN_PREDICATE_FALSE,
                                 .allocator = allocator));
}

n00b_result_t(n00b_plan_predicate_kind_t)
n00b_plan_predicate_kind(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_plan_predicate_kind_t,
                               N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(n00b_plan_predicate_kind_t, predicate->kind);
}

n00b_result_t(n00b_plan_leaf_op_t)
n00b_plan_predicate_leaf_op(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_plan_leaf_op_t, N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF) {
        return n00b_result_err(n00b_plan_leaf_op_t, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_plan_leaf_op_t, predicate->leaf_op);
}

n00b_result_t(n00b_option_t(n00b_plan_target_t *))
n00b_plan_predicate_target(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_target_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF) {
        return n00b_result_ok(n00b_option_t(n00b_plan_target_t *),
                              n00b_option_none(n00b_plan_target_t *));
    }
    if (predicate->target == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_target_t *),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_target_t *),
                          n00b_option_set(n00b_plan_target_t *,
                                          predicate->target));
}

n00b_result_t(uint64_t)
n00b_plan_predicate_child_count(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_AND:
    case N00B_PLAN_PREDICATE_OR:
        if (predicate->children == nullptr) {
            return n00b_result_err(uint64_t, N00B_PLAN_ERR_STATE);
        }
        return n00b_result_ok(uint64_t,
                              (uint64_t)n00b_list_len(*predicate->children));

    case N00B_PLAN_PREDICATE_NOT:
        return n00b_result_ok(uint64_t,
                              predicate->child == nullptr ? 0 : 1);

    case N00B_PLAN_PREDICATE_LEAF:
    case N00B_PLAN_PREDICATE_FALSE:
        return n00b_result_ok(uint64_t, 0);
    }

    return n00b_result_err(uint64_t, N00B_PLAN_ERR_STATE);
}

n00b_result_t(n00b_option_t(n00b_plan_predicate_t *))
n00b_plan_predicate_child_at(n00b_plan_predicate_t *predicate,
                             uint64_t               ordinal)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_predicate_t *),
                               N00B_PLAN_ERR_ARG);
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_AND:
    case N00B_PLAN_PREDICATE_OR: {
        if (predicate->children == nullptr) {
            return n00b_result_err(n00b_option_t(n00b_plan_predicate_t *),
                                   N00B_PLAN_ERR_STATE);
        }
        uint64_t len = (uint64_t)n00b_list_len(*predicate->children);
        if (ordinal >= len) {
            return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                                  n00b_option_none(n00b_plan_predicate_t *));
        }
        return n00b_result_ok(
            n00b_option_t(n00b_plan_predicate_t *),
            n00b_option_set(n00b_plan_predicate_t *,
                            n00b_list_get(*predicate->children,
                                          (size_t)ordinal)));
    }

    case N00B_PLAN_PREDICATE_NOT:
        if (ordinal == 0 && predicate->child != nullptr) {
            return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                                  n00b_option_set(n00b_plan_predicate_t *,
                                                  predicate->child));
        }
        return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                              n00b_option_none(n00b_plan_predicate_t *));

    case N00B_PLAN_PREDICATE_LEAF:
    case N00B_PLAN_PREDICATE_FALSE:
        return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                              n00b_option_none(n00b_plan_predicate_t *));
    }

    return n00b_result_err(n00b_option_t(n00b_plan_predicate_t *),
                           N00B_PLAN_ERR_STATE);
}

n00b_result_t(n00b_option_t(n00b_plan_value_t))
n00b_plan_predicate_value(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_t),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_EQ) {
        return n00b_result_ok(n00b_option_t(n00b_plan_value_t),
                              n00b_option_none(n00b_plan_value_t));
    }
    if (!_rocs_plan_value_is_set(predicate->value)) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_t),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_value_t),
                          n00b_option_set(n00b_plan_value_t,
                                          predicate->value));
}

n00b_result_t(n00b_option_t(n00b_plan_value_list_t *))
n00b_plan_predicate_values(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_list_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_IN) {
        return n00b_result_ok(n00b_option_t(n00b_plan_value_list_t *),
                              n00b_option_none(n00b_plan_value_list_t *));
    }
    if (predicate->values == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_list_t *),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_value_list_t *),
                          n00b_option_set(n00b_plan_value_list_t *,
                                          predicate->values));
}

n00b_result_t(n00b_option_t(n00b_plan_value_t))
n00b_plan_predicate_range_lower(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_t),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_RANGE) {
        return n00b_result_ok(n00b_option_t(n00b_plan_value_t),
                              n00b_option_none(n00b_plan_value_t));
    }
    if (!_rocs_plan_value_is_set(predicate->lower)) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_t),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_value_t),
                          n00b_option_set(n00b_plan_value_t,
                                          predicate->lower));
}

n00b_result_t(n00b_option_t(n00b_plan_value_t))
n00b_plan_predicate_range_upper(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_t),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_RANGE) {
        return n00b_result_ok(n00b_option_t(n00b_plan_value_t),
                              n00b_option_none(n00b_plan_value_t));
    }
    if (!_rocs_plan_value_is_set(predicate->upper)) {
        return n00b_result_err(n00b_option_t(n00b_plan_value_t),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_value_t),
                          n00b_option_set(n00b_plan_value_t,
                                          predicate->upper));
}

n00b_result_t(bool)
n00b_plan_predicate_range_include_lower(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_RANGE) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(bool, predicate->include_lower);
}

n00b_result_t(bool)
n00b_plan_predicate_range_include_upper(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_RANGE) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(bool, predicate->include_upper);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_plan_predicate_text(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || (predicate->leaf_op != N00B_PLAN_LEAF_CONTAINS
            && predicate->leaf_op != N00B_PLAN_LEAF_PREFIX)) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }
    if (predicate->text == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *,
                                          predicate->text));
}

n00b_result_t(n00b_option_t(n00b_regex_t *))
n00b_plan_predicate_regex_handle(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_regex_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_REGEX) {
        return n00b_result_ok(n00b_option_t(n00b_regex_t *),
                              n00b_option_none(n00b_regex_t *));
    }
    if (predicate->regex == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_regex_t *),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_regex_t *),
                          n00b_option_set(n00b_regex_t *,
                                          predicate->regex));
}

n00b_result_t(n00b_option_t(n00b_plan_path_t *))
n00b_plan_predicate_path(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_path_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->leaf_op != N00B_PLAN_LEAF_UNDER) {
        return n00b_result_ok(n00b_option_t(n00b_plan_path_t *),
                              n00b_option_none(n00b_plan_path_t *));
    }
    if (predicate->path == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_path_t *),
                               N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_path_t *),
                          n00b_option_set(n00b_plan_path_t *,
                                          predicate->path));
}

// ---------------------------------------------------------------------------
// Plan construction. Nothing below reads a shard, a posting list, or a record.
// Index choice uses n00b_store_index_advertise, which answers from descriptor
// metadata, so a plan can be built with no store open at all.
// ---------------------------------------------------------------------------

typedef struct {
    n00b_plan_index_list_t *indexes;
    n00b_store_schema_t    *schema;
    n00b_allocator_t       *allocator;
} _rocs_plan_build_ctx_t;

static n00b_plan_node_t *
_rocs_plan_node_new(_rocs_plan_build_ctx_t *ctx, n00b_plan_node_kind_t kind)
{
    n00b_plan_node_t *node = n00b_alloc_with_opts(
        n00b_plan_node_t,
        &(n00b_alloc_opts_t){
            .allocator = ctx->allocator,
        });
    node->kind      = kind;
    node->index     = nullptr;
    node->key       = nullptr;
    node->lossy     = false;
    node->recovery  = N00B_PLAN_RECOVER_ALL;
    node->fallback  = nullptr;
    node->predicate = nullptr;
    node->children  = nullptr;
    node->child     = nullptr;
    return node;
}

static n00b_plan_node_t *
_rocs_plan_node_record_scan(_rocs_plan_build_ctx_t *ctx,
                            n00b_plan_predicate_t  *predicate)
{
    n00b_plan_node_t *node = _rocs_plan_node_new(ctx,
                                                 N00B_PLAN_NODE_RECORD_SCAN);
    node->predicate        = predicate;
    return node;
}

static n00b_plan_node_t *
_rocs_plan_node_index_scan(_rocs_plan_build_ctx_t *ctx,
                           n00b_store_index_t     *index,
                           n00b_json_node_t       *key,
                           bool                    lossy,
                           n00b_plan_recovery_t    recovery,
                           n00b_plan_predicate_t  *fallback)
{
    n00b_plan_node_t *node = _rocs_plan_node_new(ctx,
                                                 N00B_PLAN_NODE_INDEX_SCAN);
    node->index            = index;
    node->key              = key;
    node->lossy            = lossy;
    node->recovery         = recovery;
    node->fallback         = fallback;
    return node;
}

static n00b_plan_node_list_t *
_rocs_plan_node_list_new(_rocs_plan_build_ctx_t *ctx)
{
    n00b_plan_node_list_t *list = n00b_alloc_with_opts(
        n00b_plan_node_list_t,
        &(n00b_alloc_opts_t){
            .allocator = ctx->allocator,
        });
    *list = n00b_list_new_private(n00b_plan_node_t *,
                                  .allocator = ctx->allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

// A lossy index scan narrows but does not decide, so it is paired with the
// record scan that settles it. This replaces the old separate residual field.
static n00b_plan_node_t *
_rocs_plan_node_lossy_pair(_rocs_plan_build_ctx_t *ctx,
                           n00b_store_index_t     *index,
                           n00b_json_node_t       *key,
                           n00b_plan_predicate_t  *predicate)
{
    n00b_plan_node_t *node = _rocs_plan_node_new(ctx,
                                                 N00B_PLAN_NODE_INTERSECT);
    node->children         = _rocs_plan_node_list_new(ctx);
    n00b_list_push(*node->children,
                     _rocs_plan_node_index_scan(ctx, index, key, true,
                                                N00B_PLAN_RECOVER_ALL,
                                                nullptr));
    n00b_list_push(*node->children,
                     _rocs_plan_node_record_scan(ctx, predicate));
    return node;
}

static n00b_result_t(n00b_plan_node_t *)
_rocs_plan_build_node(_rocs_plan_build_ctx_t *ctx,
                      n00b_plan_predicate_t  *predicate);

static n00b_result_t(n00b_plan_node_t *)
_rocs_plan_build_leaf(_rocs_plan_build_ctx_t *ctx,
                      n00b_plan_predicate_t  *predicate)
{
    if (predicate->target == nullptr) {
        return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_STATE);
    }

    if (predicate->target->kind == N00B_PLAN_TARGET_ANY) {
        if (predicate->leaf_op != N00B_PLAN_LEAF_CONTAINS) {
            return n00b_result_err(n00b_plan_node_t *,
                                   N00B_PLAN_ERR_ANY_UNSUPPORTED);
        }
        n00b_store_index_t *index = _rocs_plan_choose_catch_all_index(
            ctx->indexes);
        if (index == nullptr || predicate->text == nullptr) {
            // No schema opt-in list means raw verification would match fields
            // the catch-all deliberately excludes, so the answer is empty.
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_new(ctx,
                                                      N00B_PLAN_NODE_EMPTY));
        }
        n00b_json_node_t *key = n00b_json_string_new_from_n00b(
            predicate->text,
            .allocator = ctx->allocator);
        if (key == nullptr) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_new(ctx,
                                                      N00B_PLAN_NODE_EMPTY));
        }
        return n00b_result_ok(n00b_plan_node_t *,
                              _rocs_plan_node_index_scan(
                                  ctx, index, key, false,
                                  N00B_PLAN_RECOVER_EMPTY, nullptr));
    }

    n00b_string_t *field = predicate->target->field;
    if (field == nullptr) {
        return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_STATE);
    }

    switch (predicate->leaf_op) {
    case N00B_PLAN_LEAF_EQ: {
        if (!_rocs_plan_value_is_set(predicate->value)) {
            return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_STATE);
        }
        n00b_store_index_t *index = _rocs_plan_choose_index(
            ctx->indexes, field,
            N00B_STORE_INDEX_OP_EQ, N00B_STORE_INDEX_TERM);
        if (index == nullptr) {
            // Declared term-indexed with no built index means no record here
            // populated the field, so there is nothing to match.
            if (ctx->schema != nullptr
                && _rocs_plan_field_declared_indexed(ctx->schema, field,
                                                     N00B_STORE_INDEX_TERM)) {
                return n00b_result_ok(n00b_plan_node_t *,
                                      _rocs_plan_node_new(
                                          ctx, N00B_PLAN_NODE_EMPTY));
            }
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        auto key_r = _rocs_plan_value_node(predicate->value);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        return n00b_result_ok(n00b_plan_node_t *,
                              _rocs_plan_node_index_scan(
                                  ctx, index, n00b_result_get(key_r), false,
                                  N00B_PLAN_RECOVER_RECORD_SCAN, predicate));
    }

    case N00B_PLAN_LEAF_CONTAINS: {
        n00b_store_index_t *index = _rocs_plan_choose_index(
            ctx->indexes, field,
            N00B_STORE_INDEX_OP_CONTAINS, N00B_STORE_INDEX_FULLTEXT);
        if (index == nullptr || predicate->text == nullptr) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        n00b_json_node_t *key = n00b_json_string_new_from_n00b(
            predicate->text,
            .allocator = ctx->allocator);
        if (key == nullptr) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        return n00b_result_ok(n00b_plan_node_t *,
                              _rocs_plan_node_index_scan(
                                  ctx, index, key, false,
                                  N00B_PLAN_RECOVER_RECORD_SCAN, predicate));
    }

    case N00B_PLAN_LEAF_PREFIX:
    case N00B_PLAN_LEAF_REGEX: {
        n00b_store_index_t *index = _rocs_plan_choose_index(
            ctx->indexes, field,
            N00B_STORE_INDEX_OP_PREFIX, N00B_STORE_INDEX_NGRAM);
        if (index == nullptr) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        n00b_string_t *literal = predicate->text;
        if (predicate->leaf_op == N00B_PLAN_LEAF_REGEX) {
            if (predicate->regex == nullptr) {
                return n00b_result_err(n00b_plan_node_t *,
                                       N00B_PLAN_ERR_STATE);
            }
            n00b_option_t(n00b_string_t *) lit = n00b_regex_required_literal_prefix(
                predicate->regex,
                .allocator = ctx->allocator);
            if (!n00b_option_is_set(lit)) {
                return n00b_result_ok(n00b_plan_node_t *,
                                      _rocs_plan_node_record_scan(ctx,
                                                                  predicate));
            }
            literal = n00b_option_get(lit);
        }
        if (literal == nullptr) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        auto key_r = _rocs_plan_ngram_query_node(literal, index,
                                                 .allocator = ctx->allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_ok(n00b_plan_node_t *,
                                  _rocs_plan_node_record_scan(ctx, predicate));
        }
        return n00b_result_ok(n00b_plan_node_t *,
                              _rocs_plan_node_lossy_pair(
                                  ctx, index, n00b_result_get(key_r),
                                  predicate));
    }

    default:
        // EXISTS, IN, RANGE and UNDER have no index path.
        return n00b_result_ok(n00b_plan_node_t *,
                              _rocs_plan_node_record_scan(ctx, predicate));
    }
}

static n00b_result_t(n00b_plan_node_t *)
_rocs_plan_build_nary(_rocs_plan_build_ctx_t *ctx,
                      n00b_plan_predicate_t  *predicate,
                      n00b_plan_node_kind_t   kind)
{
    if (predicate->children == nullptr) {
        return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_ARG);
    }
    size_t count = n00b_list_len(*predicate->children);
    if (count < 2) {
        return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_plan_node_t *node = _rocs_plan_node_new(ctx, kind);
    node->children         = _rocs_plan_node_list_new(ctx);
    for (size_t i = 0; i < count; i++) {
        auto child_r = _rocs_plan_build_node(
            ctx, n00b_list_get(*predicate->children, i));
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        n00b_list_push(*node->children, n00b_result_get(child_r));
    }
    return n00b_result_ok(n00b_plan_node_t *, node);
}

static n00b_result_t(n00b_plan_node_t *)
_rocs_plan_build_node(_rocs_plan_build_ctx_t *ctx,
                      n00b_plan_predicate_t  *predicate)
{
    if (ctx == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_ARG);
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
        return _rocs_plan_build_leaf(ctx, predicate);
    case N00B_PLAN_PREDICATE_AND:
        return _rocs_plan_build_nary(ctx, predicate,
                                     N00B_PLAN_NODE_INTERSECT);
    case N00B_PLAN_PREDICATE_OR:
        return _rocs_plan_build_nary(ctx, predicate, N00B_PLAN_NODE_UNION);
    case N00B_PLAN_PREDICATE_NOT: {
        if (predicate->child == nullptr) {
            return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_ARG);
        }
        auto child_r = _rocs_plan_build_node(ctx, predicate->child);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        n00b_plan_node_t *node = _rocs_plan_node_new(
            ctx, N00B_PLAN_NODE_COMPLEMENT);
        node->child = n00b_result_get(child_r);
        return n00b_result_ok(n00b_plan_node_t *, node);
    }
    case N00B_PLAN_PREDICATE_FALSE:
        return n00b_result_ok(n00b_plan_node_t *,
                              _rocs_plan_node_new(ctx, N00B_PLAN_NODE_EMPTY));
    }

    return n00b_result_err(n00b_plan_node_t *, N00B_PLAN_ERR_STATE);
}

n00b_result_t(n00b_plan_node_t *)
n00b_plan_build(n00b_plan_predicate_t  *predicate,
                n00b_plan_index_list_t *indexes) _kargs
{
    n00b_allocator_t    *allocator = nullptr;
    n00b_store_schema_t *schema    = nullptr;
}
{
    _rocs_plan_build_ctx_t ctx = {
        .indexes   = indexes,
        .schema    = schema,
        .allocator = allocator,
    };
    return _rocs_plan_build_node(&ctx, predicate);
}

// ---------------------------------------------------------------------------
// Plan inspection. No shard, no data; a plan can be examined on its own.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_plan_node_kind_t)
n00b_plan_node_kind(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return n00b_result_err(n00b_plan_node_kind_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(n00b_plan_node_kind_t, node->kind);
}

n00b_result_t(uint64_t)
n00b_plan_node_child_count(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    if (node->kind == N00B_PLAN_NODE_COMPLEMENT) {
        return n00b_result_ok(uint64_t, node->child == nullptr ? 0 : 1);
    }
    if (node->children == nullptr) {
        return n00b_result_ok(uint64_t, 0);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*node->children));
}

n00b_result_t(n00b_option_t(n00b_plan_node_t *))
n00b_plan_node_child_at(n00b_plan_node_t *node, uint64_t index)
{
    if (node == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_node_t *),
                               N00B_PLAN_ERR_ARG);
    }
    if (node->kind == N00B_PLAN_NODE_COMPLEMENT) {
        if (index != 0 || node->child == nullptr) {
            return n00b_result_ok(n00b_option_t(n00b_plan_node_t *),
                                  n00b_option_none(n00b_plan_node_t *));
        }
        return n00b_result_ok(n00b_option_t(n00b_plan_node_t *),
                              n00b_option_set(n00b_plan_node_t *,
                                              node->child));
    }
    if (node->children == nullptr
        || index >= (uint64_t)n00b_list_len(*node->children)) {
        return n00b_result_ok(n00b_option_t(n00b_plan_node_t *),
                              n00b_option_none(n00b_plan_node_t *));
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_node_t *),
                          n00b_option_set(n00b_plan_node_t *,
                                          n00b_list_get(*node->children,
                                                        (size_t)index)));
}

static bool
_rocs_plan_tree_has(n00b_plan_node_t *node, n00b_plan_node_kind_t want)
{
    if (node == nullptr) {
        return false;
    }
    if (node->kind == want) {
        return true;
    }
    if (node->kind == N00B_PLAN_NODE_COMPLEMENT) {
        return _rocs_plan_tree_has(node->child, want);
    }
    if (node->children == nullptr) {
        return false;
    }
    size_t count = n00b_list_len(*node->children);
    for (size_t i = 0; i < count; i++) {
        if (_rocs_plan_tree_has(n00b_list_get(*node->children, i), want)) {
            return true;
        }
    }
    return false;
}

n00b_result_t(bool)
n00b_plan_uses_index(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(bool,
                          _rocs_plan_tree_has(node,
                                              N00B_PLAN_NODE_INDEX_SCAN));
}

n00b_result_t(bool)
n00b_plan_is_exact(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(bool,
                          !_rocs_plan_tree_has(node,
                                               N00B_PLAN_NODE_RECORD_SCAN));
}

static void
_rocs_plan_collect_record_scans(n00b_plan_node_t       *node,
                                n00b_plan_predicate_t **found,
                                uint64_t               *count)
{
    if (node == nullptr) {
        return;
    }
    if (node->kind == N00B_PLAN_NODE_RECORD_SCAN) {
        if (*count == 0) {
            *found = node->predicate;
        }
        *count += 1;
        return;
    }
    if (node->kind == N00B_PLAN_NODE_COMPLEMENT) {
        _rocs_plan_collect_record_scans(node->child, found, count);
        return;
    }
    if (node->children == nullptr) {
        return;
    }
    size_t n = n00b_list_len(*node->children);
    for (size_t i = 0; i < n; i++) {
        _rocs_plan_collect_record_scans(n00b_list_get(*node->children, i),
                                        found,
                                        count);
    }
}

n00b_result_t(n00b_option_t(n00b_plan_predicate_t *))
n00b_plan_sole_record_scan(n00b_plan_node_t *node)
{
    if (node == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_predicate_t *),
                               N00B_PLAN_ERR_ARG);
    }
    n00b_plan_predicate_t *found = nullptr;
    uint64_t               count = 0;
    _rocs_plan_collect_record_scans(node, &found, &count);
    if (count != 1) {
        return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                              n00b_option_none(n00b_plan_predicate_t *));
    }
    return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                          n00b_option_set(n00b_plan_predicate_t *, found));
}

// ---------------------------------------------------------------------------
// Partition pruning.
//
// Answers which shards a predicate can possibly match, from the partition
// policy and each shard's route key. Both are catalog metadata, so this needs
// no shard contents.
// ---------------------------------------------------------------------------

struct n00b_plan_partition_filter_t {
    _rocs_plan_prune_t prune;
};

n00b_result_t(n00b_plan_partition_filter_t *)
n00b_plan_partition_filter(n00b_store_t          *store,
                           n00b_plan_predicate_t *predicate) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_partition_filter_t *,
                               N00B_PLAN_ERR_ARG);
    }

    auto policy_r = n00b_store_partition_policy_for_plan(store);
    if (n00b_result_is_err(policy_r)) {
        return n00b_result_err(n00b_plan_partition_filter_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(policy_r)));
    }

    n00b_string_t *partition_field = nullptr;
    auto field_r =
        n00b_store_partition_policy_field_for_plan(n00b_result_get(policy_r));
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_plan_partition_filter_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(field_r)));
    }
    n00b_option_t(n00b_string_t *) field_opt = n00b_result_get(field_r);
    if (n00b_option_is_set(field_opt)) {
        partition_field = n00b_option_get(field_opt);
    }

    _rocs_plan_prune_ctx_t prune_ctx = {
        .policy    = n00b_result_get(policy_r),
        .field     = partition_field,
        .allocator = allocator,
    };
    auto prune_r = _rocs_plan_prune_for_predicate(&prune_ctx, predicate);
    if (n00b_result_is_err(prune_r)) {
        return n00b_result_err(n00b_plan_partition_filter_t *,
                               n00b_result_get_err(prune_r));
    }

    n00b_plan_partition_filter_t *filter = n00b_alloc_with_opts(
        n00b_plan_partition_filter_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    filter->prune = n00b_result_get(prune_r);
    return n00b_result_ok(n00b_plan_partition_filter_t *, filter);
}

n00b_result_t(bool)
n00b_plan_partition_may_match(n00b_plan_partition_filter_t *filter,
                              n00b_string_t                *partition_key)
{
    if (filter == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }
    return _rocs_plan_partition_may_match(filter->prune, partition_key);
}

