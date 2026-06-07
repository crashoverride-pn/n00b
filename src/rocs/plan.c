#include "internal/rocs/plan.h"

#include "core/buffer.h"
#include "internal/rocs/index.h"
#include "internal/rocs/store.h"
#include "rocs/map.h"
#include "text/strings/string_ops.h"

typedef n00b_list_t(n00b_string_t *) _rocs_plan_route_list_t;

struct n00b_plan_target_t {
    n00b_plan_target_kind_t kind;
    n00b_string_t          *field;
};

struct n00b_plan_path_t {
    n00b_plan_path_component_list_t *components;
};

struct n00b_plan_path_component_t {
    n00b_plan_path_component_kind_t kind;
    n00b_string_t                  *key;
    uint64_t                        index;
};

struct n00b_plan_ordset_t {
    uint64_t       record_count;
    uint64_t       count;
    n00b_buffer_t *bits;
};

struct n00b_plan_dispatch_t {
    n00b_plan_ordset_t   *candidates;
    n00b_plan_predicate_t *residual;
    bool                  used_index;
};

struct n00b_plan_shard_result_t {
    uint64_t             shard_id;
    uint64_t             generation;
    uint64_t             schema_generation;
    uint64_t             record_count;
    uint64_t             seal_ts;
    n00b_string_t       *partition_key;
    n00b_plan_ordset_t  *ordinals;
};

struct n00b_plan_predicate_t {
    n00b_plan_predicate_kind_t  kind;
    n00b_plan_leaf_op_t         leaf_op;
    n00b_plan_target_t         *target;
    n00b_plan_predicate_list_t *children;
    n00b_plan_predicate_t      *child;
    n00b_plan_value_t           value;
    n00b_plan_value_t           lower;
    n00b_plan_value_t           upper;
    n00b_plan_value_list_t     *values;
    n00b_string_t              *text;
    n00b_regex_t               *regex;
    n00b_plan_path_t           *path;
    bool                        include_lower;
    bool                        include_upper;
};

typedef enum : int32_t {
    _rocs_plan_ordset_op_union,
    _rocs_plan_ordset_op_intersection,
    _rocs_plan_ordset_op_difference,
} _rocs_plan_ordset_binary_op_t;

typedef enum : int32_t {
    _rocs_plan_dispatch_hot,
    _rocs_plan_dispatch_mapped,
} _rocs_plan_dispatch_source_t;

typedef struct {
    _rocs_plan_dispatch_source_t source;
    n00b_store_shard_t          *hot_shard;
    n00b_store_map_shard_t      *mapped_shard;
    n00b_plan_index_list_t      *indexes;
    uint64_t                     record_count;
    n00b_allocator_t            *allocator;
} _rocs_plan_dispatch_ctx_t;

typedef enum : int32_t {
    _rocs_plan_verify_hot,
    _rocs_plan_verify_mapped,
} _rocs_plan_verify_source_t;

typedef struct {
    _rocs_plan_verify_source_t source;
    n00b_store_shard_t        *hot_shard;
    n00b_store_map_shard_t    *mapped_shard;
    uint64_t                   record_count;
    n00b_allocator_t          *allocator;
} _rocs_plan_verify_ctx_t;

typedef struct {
    n00b_store_partition_policy_t *policy;
    n00b_string_t                 *field;
    n00b_allocator_t              *allocator;
} _rocs_plan_prune_ctx_t;

typedef struct {
    bool                    constrained;
    _rocs_plan_route_list_t *routes;
} _rocs_plan_prune_t;

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_predicate(_rocs_plan_dispatch_ctx_t *ctx,
                              n00b_plan_predicate_t     *predicate);

static n00b_result_t(bool)
_rocs_plan_eval_predicate(_rocs_plan_verify_ctx_t *ctx,
                          n00b_plan_predicate_t   *predicate,
                          n00b_json_node_t        *record);

static n00b_err_t
_rocs_plan_store_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_ERR_ARG:
        return N00B_PLAN_ERR_ARG;
    default:
        return N00B_PLAN_ERR_STATE;
    }
}

static n00b_err_t
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

static bool
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

static n00b_result_t(bool)
_rocs_plan_ordset_check(n00b_plan_ordset_t *set)
{
    if (set == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }
    if (set->bits == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    auto bytes_r = _rocs_plan_ordset_byte_count(set->record_count);
    if (n00b_result_is_err(bytes_r)) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
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
    set->bits         = n00b_buffer_new((int64_t)bytes,
                                        .allocator = allocator);

    if (full && bytes != 0) {
        for (uint64_t i = 0; i < bytes; i++) {
            set->bits->data[i] = (char)UINT8_MAX;
        }
        if ((record_count & UINT64_C(7)) != 0) {
            set->bits->data[bytes - 1] =
                (char)_rocs_plan_ordset_tail_mask(record_count);
        }
        set->count = record_count;
    }

    return n00b_result_ok(n00b_plan_ordset_t *, set);
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

    auto out_r = _rocs_plan_ordset_new(left->record_count,
                                       false,
                                       .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }

    n00b_plan_ordset_t *out   = n00b_result_get(out_r);
    uint64_t            bytes = (uint64_t)left->bits->byte_len;
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

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_new(n00b_plan_ordset_t    *candidates,
                        n00b_plan_predicate_t *residual,
                        bool                   used_index) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto ok = _rocs_plan_ordset_check(candidates);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_dispatch_t *,
                               n00b_result_get_err(ok));
    }

    n00b_plan_dispatch_t *dispatch = n00b_alloc_with_opts(
        n00b_plan_dispatch_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    dispatch->candidates = candidates;
    dispatch->residual   = residual;
    dispatch->used_index = used_index;
    return n00b_result_ok(n00b_plan_dispatch_t *, dispatch);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_full_residual(_rocs_plan_dispatch_ctx_t *ctx,
                                  n00b_plan_predicate_t     *residual,
                                  bool                       used_index)
{
    if (ctx == nullptr || residual == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    auto set_r = _rocs_plan_ordset_new(ctx->record_count,
                                      true,
                                      .allocator = ctx->allocator);
    if (n00b_result_is_err(set_r)) {
        return n00b_result_err(n00b_plan_dispatch_t *,
                               n00b_result_get_err(set_r));
    }

    return _rocs_plan_dispatch_new(n00b_result_get(set_r),
                                  residual,
                                  used_index,
                                  .allocator = ctx->allocator);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_exact(_rocs_plan_dispatch_ctx_t *ctx,
                          n00b_plan_ordset_t        *candidates,
                          bool                       used_index)
{
    if (ctx == nullptr || candidates == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    return _rocs_plan_dispatch_new(candidates,
                                  nullptr,
                                  used_index,
                                  .allocator = ctx->allocator);
}

static n00b_store_index_t *
_rocs_plan_choose_term_index(n00b_plan_index_list_t *indexes,
                             n00b_string_t          *field)
{
    if (indexes == nullptr || field == nullptr) {
        return nullptr;
    }

    n00b_store_index_t *best       = nullptr;
    double              best_hint  = 0.0;
    size_t              index_count = n00b_list_len(*indexes);
    for (size_t i = 0; i < index_count; i++) {
        n00b_store_index_t *index = n00b_list_get(*indexes, i);
        if (index == nullptr) {
            continue;
        }

        n00b_store_advert_t advert =
            n00b_store_index_advertise(index,
                                       field,
                                       (int64_t)N00B_PLAN_LEAF_EQ);
        if (!advert.accelerates || advert.kind != N00B_STORE_INDEX_TERM) {
            continue;
        }

        if (best == nullptr || advert.selectivity_hint < best_hint) {
            best      = index;
            best_hint = advert.selectivity_hint;
        }
    }

    return best;
}

static n00b_result_t(n00b_plan_ordset_t *)
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
        auto posting_r = n00b_store_postings_get(postings, i);
        if (n00b_result_is_err(posting_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        n00b_option_t(n00b_store_posting_t) posting_opt =
            n00b_result_get(posting_r);
        if (!n00b_option_is_set(posting_opt)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        n00b_store_posting_t posting = n00b_option_get(posting_opt);
        if (posting.pos.ordinal >= record_count) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_ORDINAL);
        }

        auto insert_r = n00b_plan_ordset_insert(set, posting.pos.ordinal);
        if (n00b_result_is_err(insert_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(insert_r));
        }
    }

    return n00b_result_ok(n00b_plan_ordset_t *, set);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_leaf(_rocs_plan_dispatch_ctx_t *ctx,
                         n00b_plan_predicate_t     *predicate)
{
    if (ctx == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }
    if (predicate->kind != N00B_PLAN_PREDICATE_LEAF
        || predicate->target == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_STATE);
    }

    if (predicate->leaf_op != N00B_PLAN_LEAF_EQ
        || predicate->target->kind != N00B_PLAN_TARGET_FIELD) {
        return _rocs_plan_dispatch_full_residual(ctx, predicate, false);
    }

    n00b_string_t *field = predicate->target->field;
    if (field == nullptr || !_rocs_plan_value_is_set(predicate->value)
        || !n00b_variant_is_type(predicate->value, n00b_json_node_t *)) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_json_node_t *value =
        n00b_variant_get(predicate->value, n00b_json_node_t *);
    if (value == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_store_index_t *index =
        _rocs_plan_choose_term_index(ctx->indexes, field);
    if (index == nullptr) {
        return _rocs_plan_dispatch_full_residual(ctx, predicate, false);
    }

    n00b_result_t(n00b_store_postings_t *) postings_r;
    if (ctx->source == _rocs_plan_dispatch_hot) {
        postings_r = n00b_store_index_lookup(index,
                                             ctx->hot_shard,
                                             value,
                                             .allocator = ctx->allocator);
    }
    else {
        postings_r = n00b_store_index_lookup_mapped(index,
                                                    ctx->mapped_shard,
                                                    value,
                                                    .allocator = ctx->allocator);
    }

    if (n00b_result_is_err(postings_r)) {
        return _rocs_plan_dispatch_full_residual(ctx, predicate, true);
    }

    auto candidates_r =
        _rocs_plan_ordset_from_postings(n00b_result_get(postings_r),
                                        ctx->record_count,
                                        .allocator = ctx->allocator);
    if (n00b_result_is_err(candidates_r)) {
        return _rocs_plan_dispatch_full_residual(ctx, predicate, true);
    }

    return _rocs_plan_dispatch_exact(ctx,
                                    n00b_result_get(candidates_r),
                                    true);
}

static n00b_result_t(n00b_plan_predicate_t *)
_rocs_plan_residual_from_list(n00b_plan_predicate_kind_t   kind,
                              n00b_plan_predicate_list_t  *residuals) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (residuals == nullptr) {
        return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_ARG);
    }

    size_t residual_count = n00b_list_len(*residuals);
    if (residual_count == 0) {
        return n00b_result_ok(n00b_plan_predicate_t *, nullptr);
    }
    if (residual_count == 1) {
        return n00b_result_ok(n00b_plan_predicate_t *,
                              n00b_list_get(*residuals, 0));
    }

    if (kind == N00B_PLAN_PREDICATE_AND) {
        return n00b_plan_predicate_and(residuals, .allocator = allocator);
    }
    if (kind == N00B_PLAN_PREDICATE_OR) {
        return n00b_plan_predicate_or(residuals, .allocator = allocator);
    }

    return n00b_result_err(n00b_plan_predicate_t *, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_and(_rocs_plan_dispatch_ctx_t *ctx,
                        n00b_plan_predicate_t     *predicate)
{
    if (ctx == nullptr || predicate == nullptr || predicate->children == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    size_t child_count = n00b_list_len(*predicate->children);
    if (child_count < 2) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_plan_predicate_list_t *residuals =
        n00b_plan_predicate_list_new(.allocator = ctx->allocator);
    n00b_plan_ordset_t *candidates = nullptr;
    bool                used_index = false;

    for (size_t i = 0; i < child_count; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*predicate->children, i);
        auto child_r = _rocs_plan_dispatch_predicate(ctx, child);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }

        n00b_plan_dispatch_t *child_dispatch = n00b_result_get(child_r);
        used_index = used_index || child_dispatch->used_index;

        if (candidates == nullptr) {
            candidates = child_dispatch->candidates;
        }
        else {
            auto intersect_r =
                n00b_plan_ordset_intersection(candidates,
                                              child_dispatch->candidates,
                                              .allocator = ctx->allocator);
            if (n00b_result_is_err(intersect_r)) {
                return n00b_result_err(n00b_plan_dispatch_t *,
                                       n00b_result_get_err(intersect_r));
            }
            candidates = n00b_result_get(intersect_r);
        }

        if (child_dispatch->residual != nullptr) {
            auto append_r =
                n00b_plan_predicate_list_append(residuals,
                                                child_dispatch->residual);
            if (n00b_result_is_err(append_r)) {
                return n00b_result_err(n00b_plan_dispatch_t *,
                                       n00b_result_get_err(append_r));
            }
        }
    }

    auto residual_r =
        _rocs_plan_residual_from_list(N00B_PLAN_PREDICATE_AND,
                                      residuals,
                                      .allocator = ctx->allocator);
    if (n00b_result_is_err(residual_r)) {
        return n00b_result_err(n00b_plan_dispatch_t *,
                               n00b_result_get_err(residual_r));
    }

    return _rocs_plan_dispatch_new(candidates,
                                  n00b_result_get(residual_r),
                                  used_index,
                                  .allocator = ctx->allocator);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_or(_rocs_plan_dispatch_ctx_t *ctx,
                       n00b_plan_predicate_t     *predicate)
{
    if (ctx == nullptr || predicate == nullptr || predicate->children == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    size_t child_count = n00b_list_len(*predicate->children);
    if (child_count < 2) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_STATE);
    }

    n00b_plan_ordset_t *candidates     = nullptr;
    bool                used_index     = false;
    bool                has_residual   = false;

    for (size_t i = 0; i < child_count; i++) {
        n00b_plan_predicate_t *child = n00b_list_get(*predicate->children, i);
        auto child_r = _rocs_plan_dispatch_predicate(ctx, child);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }

        n00b_plan_dispatch_t *child_dispatch = n00b_result_get(child_r);
        used_index   = used_index || child_dispatch->used_index;
        has_residual = has_residual || child_dispatch->residual != nullptr;

        if (candidates == nullptr) {
            candidates = child_dispatch->candidates;
        }
        else {
            auto union_r = n00b_plan_ordset_union(candidates,
                                                  child_dispatch->candidates,
                                                  .allocator = ctx->allocator);
            if (n00b_result_is_err(union_r)) {
                return n00b_result_err(n00b_plan_dispatch_t *,
                                       n00b_result_get_err(union_r));
            }
            candidates = n00b_result_get(union_r);
        }
    }

    return _rocs_plan_dispatch_new(candidates,
                                  has_residual ? predicate : nullptr,
                                  used_index,
                                  .allocator = ctx->allocator);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_not(_rocs_plan_dispatch_ctx_t *ctx,
                        n00b_plan_predicate_t     *predicate)
{
    if (ctx == nullptr || predicate == nullptr || predicate->child == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    auto child_r = _rocs_plan_dispatch_predicate(ctx, predicate->child);
    if (n00b_result_is_err(child_r)) {
        return child_r;
    }

    n00b_plan_dispatch_t *child = n00b_result_get(child_r);
    if (child->residual != nullptr) {
        return _rocs_plan_dispatch_full_residual(ctx,
                                                predicate,
                                                child->used_index);
    }

    auto complement_r = n00b_plan_ordset_complement(child->candidates,
                                                    .allocator = ctx->allocator);
    if (n00b_result_is_err(complement_r)) {
        return n00b_result_err(n00b_plan_dispatch_t *,
                               n00b_result_get_err(complement_r));
    }

    return _rocs_plan_dispatch_exact(ctx,
                                    n00b_result_get(complement_r),
                                    child->used_index);
}

static n00b_result_t(n00b_plan_dispatch_t *)
_rocs_plan_dispatch_predicate(_rocs_plan_dispatch_ctx_t *ctx,
                              n00b_plan_predicate_t     *predicate)
{
    if (ctx == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
        return _rocs_plan_dispatch_leaf(ctx, predicate);
    case N00B_PLAN_PREDICATE_AND:
        return _rocs_plan_dispatch_and(ctx, predicate);
    case N00B_PLAN_PREDICATE_OR:
        return _rocs_plan_dispatch_or(ctx, predicate);
    case N00B_PLAN_PREDICATE_NOT:
        return _rocs_plan_dispatch_not(ctx, predicate);
    }

    return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(uint64_t)
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

static n00b_result_t(uint64_t)
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

static n00b_err_t
_rocs_plan_index_err(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_INDEX_ERR_ARG:
        return N00B_PLAN_ERR_ARG;
    default:
        return N00B_PLAN_ERR_STATE;
    }
}

static n00b_result_t(n00b_json_node_t *)
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
    if (ctx->field == nullptr) {
        return n00b_result_ok(_rocs_plan_prune_t,
                              _rocs_plan_prune_unconstrained());
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
        return _rocs_plan_prune_for_leaf(ctx, predicate);
    case N00B_PLAN_PREDICATE_AND:
        return _rocs_plan_prune_for_and(ctx, predicate);
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

static n00b_result_t(bool)
_rocs_plan_json_equal(_rocs_plan_verify_ctx_t *ctx,
                      n00b_json_node_t        *left,
                      n00b_json_node_t        *right)
{
    if (left == nullptr || right == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    n00b_json_type_t left_type  = n00b_json_type(left);
    n00b_json_type_t right_type = n00b_json_type(right);
    if (left_type != right_type) {
        return n00b_result_ok(bool, false);
    }

    switch (left_type) {
    case N00B_JSON_NULL:
        return n00b_result_ok(bool, true);
    case N00B_JSON_BOOL:
        return n00b_result_ok(bool,
                              n00b_json_as_bool(left)
                                  == n00b_json_as_bool(right));
    case N00B_JSON_INT:
        return n00b_result_ok(bool,
                              n00b_json_as_i64(left)
                                  == n00b_json_as_i64(right));
    case N00B_JSON_DOUBLE: {
        double l = n00b_json_as_f64(left);
        double r = n00b_json_as_f64(right);
        return n00b_result_ok(bool, l == r);
    }
    case N00B_JSON_STRING: {
        n00b_string_t *l = n00b_json_as_string(left);
        n00b_string_t *r = n00b_json_as_string(right);
        return n00b_result_ok(bool,
                              l != nullptr && r != nullptr
                                  && n00b_unicode_str_eq(l, r));
    }
    case N00B_JSON_ARRAY: {
        size_t len = n00b_json_array_len(left);
        if (len != n00b_json_array_len(right)) {
            return n00b_result_ok(bool, false);
        }
        for (size_t i = 0; i < len; i++) {
            auto item_r =
                _rocs_plan_json_equal(ctx,
                                      n00b_json_array_get(left, i),
                                      n00b_json_array_get(right, i));
            if (n00b_result_is_err(item_r) || !n00b_result_get(item_r)) {
                return item_r;
            }
        }
        return n00b_result_ok(bool, true);
    }
    case N00B_JSON_OBJECT: {
        if (n00b_json_length(left) != n00b_json_length(right)) {
            return n00b_result_ok(bool, false);
        }

        auto entries_r =
            n00b_json_object_entries(left, .allocator = ctx->allocator);
        if (n00b_result_is_err(entries_r)) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }

        n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
        size_t                         len     = n00b_list_len(*entries);
        for (size_t i = 0; i < len; i++) {
            n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
            if (entry == nullptr || entry->key == nullptr
                || entry->value == nullptr) {
                return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
            }

            n00b_json_node_t *other =
                n00b_json_object_get(right, entry->key);
            if (other == nullptr) {
                return n00b_result_ok(bool, false);
            }

            auto item_r = _rocs_plan_json_equal(ctx, entry->value, other);
            if (n00b_result_is_err(item_r) || !n00b_result_get(item_r)) {
                return item_r;
            }
        }

        return n00b_result_ok(bool, true);
    }
    }

    return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
}

static bool
_rocs_plan_json_numeric(n00b_json_node_t *node, double *out)
{
    if (node == nullptr || out == nullptr) {
        return false;
    }
    if (n00b_json_is_int(node)) {
        *out = (double)n00b_json_as_i64(node);
        return true;
    }
    if (n00b_json_is_double(node)) {
        double value = n00b_json_as_f64(node);
        if (value != value) {
            return false;
        }
        *out = value;
        return true;
    }
    return false;
}

static n00b_result_t(bool)
_rocs_plan_json_order_cmp(n00b_json_node_t *value,
                          n00b_json_node_t *bound,
                          int32_t          *cmp)
{
    if (value == nullptr || bound == nullptr || cmp == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    if (n00b_json_is_int(value) && n00b_json_is_int(bound)) {
        int64_t l = n00b_json_as_i64(value);
        int64_t r = n00b_json_as_i64(bound);
        *cmp = l < r ? -1 : (l > r ? 1 : 0);
        return n00b_result_ok(bool, true);
    }

    double lv = 0.0;
    double rv = 0.0;
    if (_rocs_plan_json_numeric(value, &lv)
        && _rocs_plan_json_numeric(bound, &rv)) {
        *cmp = lv < rv ? -1 : (lv > rv ? 1 : 0);
        return n00b_result_ok(bool, true);
    }

    if (n00b_json_is_string(value) && n00b_json_is_string(bound)) {
        n00b_string_t *l = n00b_json_as_string(value);
        n00b_string_t *r = n00b_json_as_string(bound);
        if (l == nullptr || r == nullptr) {
            return n00b_result_ok(bool, false);
        }
        int raw = n00b_unicode_str_cmp(l, r);
        *cmp = raw < 0 ? -1 : (raw > 0 ? 1 : 0);
        return n00b_result_ok(bool, true);
    }

    return n00b_result_ok(bool, false);
}

static n00b_result_t(bool)
_rocs_plan_json_range_match(n00b_json_node_t        *value,
                            n00b_plan_predicate_t  *predicate)
{
    auto lower_r = _rocs_plan_value_node(predicate->lower);
    if (n00b_result_is_err(lower_r)) {
        return n00b_result_err(bool, n00b_result_get_err(lower_r));
    }
    auto upper_r = _rocs_plan_value_node(predicate->upper);
    if (n00b_result_is_err(upper_r)) {
        return n00b_result_err(bool, n00b_result_get_err(upper_r));
    }

    int32_t lower_cmp = 0;
    auto    lower_order_r =
        _rocs_plan_json_order_cmp(value, n00b_result_get(lower_r), &lower_cmp);
    if (n00b_result_is_err(lower_order_r) || !n00b_result_get(lower_order_r)) {
        return lower_order_r;
    }

    int32_t upper_cmp = 0;
    auto    upper_order_r =
        _rocs_plan_json_order_cmp(value, n00b_result_get(upper_r), &upper_cmp);
    if (n00b_result_is_err(upper_order_r) || !n00b_result_get(upper_order_r)) {
        return upper_order_r;
    }

    bool above_lower = predicate->include_lower ? lower_cmp >= 0
                                                : lower_cmp > 0;
    bool below_upper = predicate->include_upper ? upper_cmp <= 0
                                                : upper_cmp < 0;
    return n00b_result_ok(bool, above_lower && below_upper);
}

static n00b_result_t(n00b_option_t(n00b_json_node_t *))
_rocs_plan_field_value(n00b_json_node_t    *record,
                       n00b_plan_target_t  *target)
{
    if (record == nullptr || target == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                               N00B_PLAN_ERR_STATE);
    }
    if (target->kind != N00B_PLAN_TARGET_FIELD || target->field == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                               N00B_PLAN_ERR_STATE);
    }
    if (!n00b_json_is_object(record)) {
        return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                              n00b_option_none(n00b_json_node_t *));
    }

    n00b_json_node_t *field = n00b_json_object_get(record, target->field);
    if (field == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                              n00b_option_none(n00b_json_node_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                          n00b_option_set(n00b_json_node_t *, field));
}

static n00b_result_t(n00b_option_t(n00b_json_node_t *))
_rocs_plan_path_resolve(n00b_json_node_t *root, n00b_plan_path_t *path)
{
    if (root == nullptr || path == nullptr || path->components == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                               N00B_PLAN_ERR_STATE);
    }

    n00b_json_node_t *current = root;
    size_t            len     = n00b_list_len(*path->components);
    for (size_t i = 0; i < len; i++) {
        n00b_plan_path_component_t *component =
            n00b_list_get(*path->components, i);
        if (!_rocs_plan_path_component_is_valid(component)) {
            return n00b_result_err(n00b_option_t(n00b_json_node_t *),
                                   N00B_PLAN_ERR_STATE);
        }

        switch (component->kind) {
        case N00B_PLAN_PATH_KEY:
            if (!n00b_json_is_object(current)) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            current = n00b_json_object_get(current, component->key);
            if (current == nullptr) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            break;
        case N00B_PLAN_PATH_INDEX:
            if (!n00b_json_is_array(current)
                || component->index > (uint64_t)SIZE_MAX) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            current = n00b_json_array_get(current, (size_t)component->index);
            if (current == nullptr) {
                return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                                      n00b_option_none(n00b_json_node_t *));
            }
            break;
        }
    }

    return n00b_result_ok(n00b_option_t(n00b_json_node_t *),
                          n00b_option_set(n00b_json_node_t *, current));
}

static n00b_result_t(bool)
_rocs_plan_json_any_contains(_rocs_plan_verify_ctx_t *ctx,
                             n00b_json_node_t        *node,
                             n00b_string_t           *needle)
{
    if (node == nullptr || needle == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    if (n00b_json_is_string(node)) {
        n00b_string_t *s = n00b_json_as_string(node);
        return n00b_result_ok(bool,
                              s != nullptr
                                  && n00b_unicode_str_contains(s, needle));
    }
    if (n00b_json_is_array(node)) {
        size_t len = n00b_json_array_len(node);
        for (size_t i = 0; i < len; i++) {
            n00b_json_node_t *child = n00b_json_array_get(node, i);
            if (child == nullptr) {
                return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
            }
            auto child_r = _rocs_plan_json_any_contains(ctx, child, needle);
            if (n00b_result_is_err(child_r) || n00b_result_get(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, false);
    }
    if (n00b_json_is_object(node)) {
        auto entries_r =
            n00b_json_object_entries(node, .allocator = ctx->allocator);
        if (n00b_result_is_err(entries_r)) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }

        n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
        size_t                         len     = n00b_list_len(*entries);
        for (size_t i = 0; i < len; i++) {
            n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
            if (entry == nullptr || entry->value == nullptr) {
                return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
            }
            auto child_r =
                _rocs_plan_json_any_contains(ctx, entry->value, needle);
            if (n00b_result_is_err(child_r) || n00b_result_get(child_r)) {
                return child_r;
            }
        }
    }

    return n00b_result_ok(bool, false);
}

static n00b_result_t(bool)
_rocs_plan_eval_leaf(_rocs_plan_verify_ctx_t *ctx,
                     n00b_plan_predicate_t   *predicate,
                     n00b_json_node_t        *record)
{
    if (predicate == nullptr || predicate->target == nullptr
        || record == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    n00b_plan_target_t *target = predicate->target;

    if (predicate->leaf_op == N00B_PLAN_LEAF_CONTAINS
        && target->kind == N00B_PLAN_TARGET_ANY) {
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        return _rocs_plan_json_any_contains(ctx, record, predicate->text);
    }
    if (target->kind != N00B_PLAN_TARGET_FIELD) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    auto field_r = _rocs_plan_field_value(record, target);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(bool, n00b_result_get_err(field_r));
    }

    n00b_option_t(n00b_json_node_t *) field_opt = n00b_result_get(field_r);
    bool field_present = n00b_option_is_set(field_opt);
    n00b_json_node_t *field =
        field_present ? n00b_option_get(field_opt) : nullptr;

    switch (predicate->leaf_op) {
    case N00B_PLAN_LEAF_EQ: {
        auto value_r = _rocs_plan_value_node(predicate->value);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_err(bool, n00b_result_get_err(value_r));
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        return _rocs_plan_json_equal(ctx, field, n00b_result_get(value_r));
    }
    case N00B_PLAN_LEAF_IN: {
        if (predicate->values == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->values);
        if (len == 0) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }

        for (size_t i = 0; i < len; i++) {
            auto value_r =
                _rocs_plan_value_node(n00b_list_get(*predicate->values, i));
            if (n00b_result_is_err(value_r)) {
                return n00b_result_err(bool, n00b_result_get_err(value_r));
            }
            auto equal_r =
                _rocs_plan_json_equal(ctx, field, n00b_result_get(value_r));
            if (n00b_result_is_err(equal_r) || n00b_result_get(equal_r)) {
                return equal_r;
            }
        }
        return n00b_result_ok(bool, false);
    }
    case N00B_PLAN_LEAF_RANGE:
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        return _rocs_plan_json_range_match(field, predicate);

    case N00B_PLAN_LEAF_EXISTS:
        return n00b_result_ok(bool, field_present);

    case N00B_PLAN_LEAF_CONTAINS:
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        return _rocs_plan_json_any_contains(ctx, field, predicate->text);

    case N00B_PLAN_LEAF_PREFIX: {
        if (predicate->text == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present || !n00b_json_is_string(field)) {
            return n00b_result_ok(bool, false);
        }
        n00b_string_t *s = n00b_json_as_string(field);
        return n00b_result_ok(bool,
                              s != nullptr
                                  && n00b_unicode_str_starts_with(s,
                                                                  predicate->text));
    }
    case N00B_PLAN_LEAF_REGEX: {
        if (predicate->regex == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present || !n00b_json_is_string(field)) {
            return n00b_result_ok(bool, false);
        }
        n00b_string_t *s = n00b_json_as_string(field);
        return n00b_result_ok(bool,
                              s != nullptr
                                  && n00b_regex_is_match(predicate->regex, s));
    }
    case N00B_PLAN_LEAF_UNDER: {
        if (predicate->path == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        if (!field_present) {
            return n00b_result_ok(bool, false);
        }
        auto path_r = _rocs_plan_path_resolve(field, predicate->path);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_err(bool, n00b_result_get_err(path_r));
        }
        return n00b_result_ok(bool,
                              n00b_option_is_set(n00b_result_get(path_r)));
    }
    }

    return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(bool)
_rocs_plan_eval_predicate(_rocs_plan_verify_ctx_t *ctx,
                          n00b_plan_predicate_t   *predicate,
                          n00b_json_node_t        *record)
{
    if (ctx == nullptr || predicate == nullptr || record == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    switch (predicate->kind) {
    case N00B_PLAN_PREDICATE_LEAF:
        return _rocs_plan_eval_leaf(ctx, predicate, record);

    case N00B_PLAN_PREDICATE_AND: {
        if (predicate->children == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->children);
        if (len < 2) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        for (size_t i = 0; i < len; i++) {
            auto child_r = _rocs_plan_eval_predicate(
                ctx,
                n00b_list_get(*predicate->children, i),
                record);
            if (n00b_result_is_err(child_r) || !n00b_result_get(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, true);
    }

    case N00B_PLAN_PREDICATE_OR: {
        if (predicate->children == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        size_t len = n00b_list_len(*predicate->children);
        if (len < 2) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        for (size_t i = 0; i < len; i++) {
            auto child_r = _rocs_plan_eval_predicate(
                ctx,
                n00b_list_get(*predicate->children, i),
                record);
            if (n00b_result_is_err(child_r) || n00b_result_get(child_r)) {
                return child_r;
            }
        }
        return n00b_result_ok(bool, false);
    }

    case N00B_PLAN_PREDICATE_NOT: {
        if (predicate->child == nullptr) {
            return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
        }
        auto child_r = _rocs_plan_eval_predicate(ctx,
                                                predicate->child,
                                                record);
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        return n00b_result_ok(bool, !n00b_result_get(child_r));
    }
    }

    return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
}

static n00b_result_t(n00b_store_record_t *)
_rocs_plan_record_view_for_ordinal(_rocs_plan_verify_ctx_t *ctx,
                                   uint64_t                 ordinal)
{
    if (ctx == nullptr) {
        return n00b_result_err(n00b_store_record_t *, N00B_PLAN_ERR_ARG);
    }

    if (ctx->source == _rocs_plan_verify_hot) {
        auto record_r = n00b_store_record_view_hot_at(ctx->hot_shard,
                                                      ordinal,
                                                      .allocator = ctx->allocator);
        if (n00b_result_is_err(record_r)) {
            return n00b_result_err(n00b_store_record_t *,
                                   _rocs_plan_index_err(
                                       n00b_result_get_err(record_r)));
        }
        return record_r;
    }

    auto record_r = n00b_store_record_view_mapped_at(ctx->mapped_shard,
                                                    ordinal,
                                                    .allocator = ctx->allocator);
    if (n00b_result_is_err(record_r)) {
        return n00b_result_err(n00b_store_record_t *,
                               _rocs_plan_index_err(
                                   n00b_result_get_err(record_r)));
    }
    return record_r;
}

static n00b_result_t(n00b_plan_ordset_t *)
_rocs_plan_verify_candidates(_rocs_plan_verify_ctx_t *ctx,
                             n00b_plan_ordset_t      *candidates,
                             n00b_plan_predicate_t   *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (ctx == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    auto ok = _rocs_plan_ordset_check(candidates);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(ok));
    }
    if (candidates->record_count != ctx->record_count) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               N00B_PLAN_ERR_UNIVERSE);
    }
    if (residual == nullptr) {
        return n00b_result_ok(n00b_plan_ordset_t *, candidates);
    }

    auto out_r = _rocs_plan_ordset_new(ctx->record_count,
                                      false,
                                      .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }
    n00b_plan_ordset_t *out = n00b_result_get(out_r);

    uint64_t candidate_count = candidates->count;
    for (uint64_t i = 0; i < candidate_count; i++) {
        auto ordinal_r = n00b_plan_ordset_at(candidates, i);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(ordinal_r));
        }
        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_PLAN_ERR_STATE);
        }
        uint64_t ordinal = n00b_option_get(ordinal_opt);

        auto record_r = _rocs_plan_record_view_for_ordinal(ctx, ordinal);
        if (n00b_result_is_err(record_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(record_r));
        }

        auto json_r = n00b_store_record_view_json(n00b_result_get(record_r),
                                                  .allocator = ctx->allocator);
        if (n00b_result_is_err(json_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   _rocs_plan_index_err(
                                       n00b_result_get_err(json_r)));
        }

        auto match_r = _rocs_plan_eval_predicate(ctx,
                                                residual,
                                                n00b_result_get(json_r));
        if (n00b_result_is_err(match_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   n00b_result_get_err(match_r));
        }
        if (n00b_result_get(match_r)) {
            auto insert_r = n00b_plan_ordset_insert(out, ordinal);
            if (n00b_result_is_err(insert_r)) {
                return n00b_result_err(n00b_plan_ordset_t *,
                                       n00b_result_get_err(insert_r));
            }
        }
    }

    return n00b_result_ok(n00b_plan_ordset_t *, out);
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

static n00b_plan_shard_result_list_t *
_rocs_plan_shard_result_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_plan_shard_result_list_t *results = n00b_alloc_with_opts(
        n00b_plan_shard_result_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *results = n00b_list_new_private(n00b_plan_shard_result_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return results;
}

static n00b_result_t(n00b_string_t *)
_rocs_plan_string_copy(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (s == nullptr || s->data == nullptr
        || s->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(
        n00b_string_t *,
        n00b_string_from_raw(s->data,
                             (int64_t)s->u8_bytes,
                             .allocator = allocator));
}

static n00b_result_t(bool)
_rocs_plan_release_resident(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr) {
        return n00b_result_ok(bool, true);
    }

    auto release_r = n00b_store_resident_shard_release(resident);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(release_r)));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_plan_shard_result_t *)
_rocs_plan_shard_result_new(n00b_store_catalog_entry_t *entry,
                            n00b_plan_ordset_t         *ordinals) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (entry == nullptr || ordinals == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_t *, N00B_PLAN_ERR_ARG);
    }

    auto shard_id_r = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r      = n00b_store_catalog_entry_get_generation(entry);
    auto schema_r   = n00b_store_catalog_entry_get_schema_generation(entry);
    auto records_r  = n00b_store_catalog_entry_get_record_count(entry);
    auto seal_r     = n00b_store_catalog_entry_get_seal_ts(entry);
    auto part_r     = n00b_store_catalog_entry_get_partition_key(entry);

    if (n00b_result_is_err(shard_id_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(schema_r) || n00b_result_is_err(records_r)
        || n00b_result_is_err(seal_r) || n00b_result_is_err(part_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_STATE);
    }

    auto ord_records_r = n00b_plan_ordset_record_count(ordinals);
    if (n00b_result_is_err(ord_records_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               n00b_result_get_err(ord_records_r));
    }
    if (n00b_result_get(ord_records_r) != n00b_result_get(records_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_STATE);
    }

    auto part_copy_r =
        _rocs_plan_string_copy(n00b_result_get(part_r),
                               .allocator = allocator);
    if (n00b_result_is_err(part_copy_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               n00b_result_get_err(part_copy_r));
    }

    n00b_plan_shard_result_t *result = n00b_alloc_with_opts(
        n00b_plan_shard_result_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    result->shard_id          = n00b_result_get(shard_id_r);
    result->generation        = n00b_result_get(gen_r);
    result->schema_generation = n00b_result_get(schema_r);
    result->record_count      = n00b_result_get(records_r);
    result->seal_ts           = n00b_result_get(seal_r);
    result->partition_key     = n00b_result_get(part_copy_r);
    result->ordinals          = ordinals;
    return n00b_result_ok(n00b_plan_shard_result_t *, result);
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

    return n00b_result_ok(bool, _rocs_plan_ordset_bit_insert(set, ordinal));
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

    uint64_t seen = 0;
    for (uint64_t ordinal = 0; ordinal < set->record_count; ordinal++) {
        if (!_rocs_plan_ordset_bit_is_set(set, ordinal)) {
            continue;
        }
        if (seen == index) {
            return n00b_result_ok(n00b_option_t(uint64_t),
                                  n00b_option_set(uint64_t, ordinal));
        }
        seen++;
    }

    return n00b_result_err(n00b_option_t(uint64_t), N00B_PLAN_ERR_STATE);
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

    auto out_r = _rocs_plan_ordset_new(set->record_count,
                                      false,
                                      .allocator = allocator);
    if (n00b_result_is_err(out_r)) {
        return out_r;
    }

    n00b_plan_ordset_t *out   = n00b_result_get(out_r);
    uint64_t            bytes = (uint64_t)set->bits->byte_len;
    uint64_t            count = 0;
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

n00b_result_t(n00b_plan_dispatch_t *)
n00b_plan_dispatch_hot(n00b_plan_predicate_t  *predicate,
                       n00b_plan_index_list_t *indexes,
                       n00b_store_shard_t     *shard) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (predicate == nullptr || shard == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    auto record_count_r = _rocs_plan_hot_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_dispatch_t *,
                               n00b_result_get_err(record_count_r));
    }

    _rocs_plan_dispatch_ctx_t ctx = {
        .source       = _rocs_plan_dispatch_hot,
        .hot_shard    = shard,
        .mapped_shard = nullptr,
        .indexes      = indexes,
        .record_count = n00b_result_get(record_count_r),
        .allocator    = allocator,
    };

    return _rocs_plan_dispatch_predicate(&ctx, predicate);
}

n00b_result_t(n00b_plan_dispatch_t *)
n00b_plan_dispatch_mapped(n00b_plan_predicate_t    *predicate,
                          n00b_plan_index_list_t   *indexes,
                          n00b_store_map_shard_t   *shard) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (predicate == nullptr || shard == nullptr) {
        return n00b_result_err(n00b_plan_dispatch_t *, N00B_PLAN_ERR_ARG);
    }

    auto record_count_r = _rocs_plan_mapped_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_dispatch_t *,
                               n00b_result_get_err(record_count_r));
    }

    _rocs_plan_dispatch_ctx_t ctx = {
        .source       = _rocs_plan_dispatch_mapped,
        .hot_shard    = nullptr,
        .mapped_shard = shard,
        .indexes      = indexes,
        .record_count = n00b_result_get(record_count_r),
        .allocator    = allocator,
    };

    return _rocs_plan_dispatch_predicate(&ctx, predicate);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_dispatch_candidates(n00b_plan_dispatch_t *dispatch)
{
    if (dispatch == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }

    auto ok = _rocs_plan_ordset_check(dispatch->candidates);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(ok));
    }

    return n00b_result_ok(n00b_plan_ordset_t *, dispatch->candidates);
}

n00b_result_t(n00b_option_t(n00b_plan_predicate_t *))
n00b_plan_dispatch_residual(n00b_plan_dispatch_t *dispatch)
{
    if (dispatch == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_predicate_t *),
                               N00B_PLAN_ERR_ARG);
    }

    if (dispatch->residual == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                              n00b_option_none(n00b_plan_predicate_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_plan_predicate_t *),
                          n00b_option_set(n00b_plan_predicate_t *,
                                          dispatch->residual));
}

n00b_result_t(bool)
n00b_plan_dispatch_residual_needed(n00b_plan_dispatch_t *dispatch)
{
    if (dispatch == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    return n00b_result_ok(bool, dispatch->residual != nullptr);
}

n00b_result_t(bool)
n00b_plan_dispatch_is_exact(n00b_plan_dispatch_t *dispatch)
{
    if (dispatch == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    return n00b_result_ok(bool, dispatch->residual == nullptr);
}

n00b_result_t(bool)
n00b_plan_dispatch_used_index(n00b_plan_dispatch_t *dispatch)
{
    if (dispatch == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    return n00b_result_ok(bool, dispatch->used_index);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_verify_hot(n00b_store_shard_t     *shard,
                     n00b_plan_ordset_t    *candidates,
                     n00b_plan_predicate_t *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto record_count_r = _rocs_plan_hot_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(record_count_r));
    }

    _rocs_plan_verify_ctx_t ctx = {
        .source       = _rocs_plan_verify_hot,
        .hot_shard    = shard,
        .mapped_shard = nullptr,
        .record_count = n00b_result_get(record_count_r),
        .allocator    = allocator,
    };

    return _rocs_plan_verify_candidates(&ctx,
                                        candidates,
                                        residual,
                                        .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_verify_mapped(n00b_store_map_shard_t *shard,
                        n00b_plan_ordset_t     *candidates,
                        n00b_plan_predicate_t  *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto record_count_r = _rocs_plan_mapped_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(record_count_r));
    }

    _rocs_plan_verify_ctx_t ctx = {
        .source       = _rocs_plan_verify_mapped,
        .hot_shard    = nullptr,
        .mapped_shard = shard,
        .record_count = n00b_result_get(record_count_r),
        .allocator    = allocator,
    };

    return _rocs_plan_verify_candidates(&ctx,
                                        candidates,
                                        residual,
                                        .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_scan_verify_hot(n00b_store_shard_t     *shard,
                          n00b_plan_predicate_t *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto record_count_r = _rocs_plan_hot_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(record_count_r));
    }

    auto candidates_r = n00b_plan_ordset_full(n00b_result_get(record_count_r),
                                              .allocator = allocator);
    if (n00b_result_is_err(candidates_r)) {
        return candidates_r;
    }

    return n00b_plan_verify_hot(shard,
                                n00b_result_get(candidates_r),
                                residual,
                                .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_scan_verify_mapped(n00b_store_map_shard_t *shard,
                             n00b_plan_predicate_t  *residual) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto record_count_r = _rocs_plan_mapped_record_count(shard);
    if (n00b_result_is_err(record_count_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(record_count_r));
    }

    auto candidates_r = n00b_plan_ordset_full(n00b_result_get(record_count_r),
                                              .allocator = allocator);
    if (n00b_result_is_err(candidates_r)) {
        return candidates_r;
    }

    return n00b_plan_verify_mapped(shard,
                                   n00b_result_get(candidates_r),
                                   residual,
                                   .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_dispatch_verify_hot(n00b_plan_dispatch_t *dispatch,
                              n00b_store_shard_t   *shard) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto candidates_r = n00b_plan_dispatch_candidates(dispatch);
    if (n00b_result_is_err(candidates_r)) {
        return candidates_r;
    }

    auto residual_r = n00b_plan_dispatch_residual(dispatch);
    if (n00b_result_is_err(residual_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(residual_r));
    }

    n00b_option_t(n00b_plan_predicate_t *) residual_opt =
        n00b_result_get(residual_r);
    return n00b_plan_verify_hot(shard,
                                n00b_result_get(candidates_r),
                                n00b_option_is_set(residual_opt)
                                    ? n00b_option_get(residual_opt)
                                    : nullptr,
                                .allocator = allocator);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_dispatch_verify_mapped(n00b_plan_dispatch_t   *dispatch,
                                 n00b_store_map_shard_t *shard) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto candidates_r = n00b_plan_dispatch_candidates(dispatch);
    if (n00b_result_is_err(candidates_r)) {
        return candidates_r;
    }

    auto residual_r = n00b_plan_dispatch_residual(dispatch);
    if (n00b_result_is_err(residual_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(residual_r));
    }

    n00b_option_t(n00b_plan_predicate_t *) residual_opt =
        n00b_result_get(residual_r);
    return n00b_plan_verify_mapped(shard,
                                   n00b_result_get(candidates_r),
                                   n00b_option_is_set(residual_opt)
                                       ? n00b_option_get(residual_opt)
                                       : nullptr,
                                   .allocator = allocator);
}

static n00b_result_t(bool)
_rocs_plan_validate_mapped_catalog(n00b_store_map_shard_t      *root,
                                   n00b_store_catalog_entry_t  *entry)
{
    if (root == nullptr || entry == nullptr) {
        return n00b_result_err(bool, N00B_PLAN_ERR_ARG);
    }

    auto catalog_id_r = n00b_store_catalog_entry_get_shard_id(entry);
    auto catalog_records_r = n00b_store_catalog_entry_get_record_count(entry);
    auto catalog_seal_r = n00b_store_catalog_entry_get_seal_ts(entry);
    auto root_id_r = n00b_store_map_shard_id(root);
    auto root_records_r = n00b_store_map_shard_records_len(root);
    auto root_seal_r = n00b_store_map_shard_seal_ts(root);

    if (n00b_result_is_err(catalog_id_r)
        || n00b_result_is_err(catalog_records_r)
        || n00b_result_is_err(catalog_seal_r)) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }
    if (n00b_result_is_err(root_id_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_map_err(
                                   n00b_result_get_err(root_id_r)));
    }
    if (n00b_result_is_err(root_records_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_map_err(
                                   n00b_result_get_err(root_records_r)));
    }
    if (n00b_result_is_err(root_seal_r)) {
        return n00b_result_err(bool,
                               _rocs_plan_map_err(
                                   n00b_result_get_err(root_seal_r)));
    }

    if (n00b_result_get(catalog_id_r) != n00b_result_get(root_id_r)
        || n00b_result_get(catalog_records_r) != n00b_result_get(root_records_r)
        || n00b_result_get(catalog_seal_r) != n00b_result_get(root_seal_r)) {
        return n00b_result_err(bool, N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_plan_shard_result_t *)
_rocs_plan_catalog_entry_mapped(n00b_store_t               *store,
                                n00b_store_catalog_entry_t *entry,
                                n00b_plan_predicate_t      *predicate,
                                n00b_plan_index_list_t     *indexes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || entry == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               N00B_PLAN_ERR_ARG);
    }

    n00b_store_resident_shard_t *resident = nullptr;
    n00b_plan_shard_result_t    *result   = nullptr;
    n00b_err_t                   err      = N00B_PLAN_OK;

    auto resident_r = n00b_store_resident_shard_acquire(
        store,
        entry,
        .allocator = allocator);
    if (n00b_result_is_err(resident_r)) {
        return n00b_result_err(n00b_plan_shard_result_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(resident_r)));
    }
    resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        err = _rocs_plan_store_err(n00b_result_get_err(map_r));
        goto release;
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    if (n00b_result_is_err(root_r)) {
        err = _rocs_plan_map_err(n00b_result_get_err(root_r));
        goto release;
    }
    n00b_store_map_shard_t *root = n00b_result_get(root_r);

    auto valid_r = _rocs_plan_validate_mapped_catalog(root, entry);
    if (n00b_result_is_err(valid_r)) {
        err = n00b_result_get_err(valid_r);
        goto release;
    }

    auto dispatch_r =
        n00b_plan_dispatch_mapped(predicate,
                                  indexes,
                                  root,
                                  .allocator = allocator);
    if (n00b_result_is_err(dispatch_r)) {
        err = n00b_result_get_err(dispatch_r);
        goto release;
    }

    auto ordinals_r =
        n00b_plan_dispatch_verify_mapped(n00b_result_get(dispatch_r),
                                         root,
                                         .allocator = allocator);
    if (n00b_result_is_err(ordinals_r)) {
        err = n00b_result_get_err(ordinals_r);
        goto release;
    }

    auto result_r =
        _rocs_plan_shard_result_new(entry,
                                    n00b_result_get(ordinals_r),
                                    .allocator = allocator);
    if (n00b_result_is_err(result_r)) {
        err = n00b_result_get_err(result_r);
        goto release;
    }
    result = n00b_result_get(result_r);

release:
    {
        auto release_r = _rocs_plan_release_resident(resident);
        if (n00b_result_is_err(release_r) && err == N00B_PLAN_OK) {
            err = n00b_result_get_err(release_r);
        }
    }

    if (err != N00B_PLAN_OK) {
        return n00b_result_err(n00b_plan_shard_result_t *, err);
    }
    return n00b_result_ok(n00b_plan_shard_result_t *, result);
}

n00b_result_t(n00b_plan_shard_result_list_t *)
n00b_plan_store_sealed(n00b_store_t           *store,
                       n00b_plan_predicate_t  *predicate,
                       n00b_plan_index_list_t *indexes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               N00B_PLAN_ERR_ARG);
    }

    auto policy_r = n00b_store_partition_policy_for_plan(store);
    if (n00b_result_is_err(policy_r)) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(policy_r)));
    }

    n00b_string_t *partition_field = nullptr;
    auto field_r =
        n00b_store_partition_policy_field_for_plan(n00b_result_get(policy_r));
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
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
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               n00b_result_get_err(prune_r));
    }
    _rocs_plan_prune_t prune = n00b_result_get(prune_r);

    n00b_plan_shard_result_list_t *results =
        _rocs_plan_shard_result_list_new(.allocator = allocator);

    auto count_r = n00b_store_catalog_visible_entry_count(store);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(n00b_plan_shard_result_list_t *,
                               _rocs_plan_store_err(
                                   n00b_result_get_err(count_r)));
    }

    uint64_t entry_count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < entry_count; i++) {
        auto entry_r = n00b_store_catalog_visible_entry_at(store, i);
        if (n00b_result_is_err(entry_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   _rocs_plan_store_err(
                                       n00b_result_get_err(entry_r)));
        }

        n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
            n00b_result_get(entry_r);
        if (!n00b_option_is_set(entry_opt)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
        auto partition_r = n00b_store_catalog_entry_get_partition_key(entry);
        if (n00b_result_is_err(partition_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   N00B_PLAN_ERR_STATE);
        }

        auto may_match_r =
            _rocs_plan_partition_may_match(prune,
                                           n00b_result_get(partition_r));
        if (n00b_result_is_err(may_match_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   n00b_result_get_err(may_match_r));
        }
        if (!n00b_result_get(may_match_r)) {
            continue;
        }

        auto result_r = _rocs_plan_catalog_entry_mapped(store,
                                                       entry,
                                                       predicate,
                                                       indexes,
                                                       .allocator = allocator);
        if (n00b_result_is_err(result_r)) {
            return n00b_result_err(n00b_plan_shard_result_list_t *,
                                   n00b_result_get_err(result_r));
        }

        n00b_list_push(*results, n00b_result_get(result_r));
    }

    return n00b_result_ok(n00b_plan_shard_result_list_t *, results);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_count(n00b_plan_shard_result_list_t *results)
{
    if (results == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*results));
}

n00b_result_t(n00b_option_t(n00b_plan_shard_result_t *))
n00b_plan_shard_result_at(n00b_plan_shard_result_list_t *results,
                          uint64_t                       index)
{
    if (results == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_shard_result_t *),
                               N00B_PLAN_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*results);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_plan_shard_result_t *),
                              n00b_option_none(n00b_plan_shard_result_t *));
    }

    n00b_plan_shard_result_t *result =
        n00b_list_get(*results, (size_t)index);
    if (result == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_plan_shard_result_t *),
                               N00B_PLAN_ERR_STATE);
    }

    return n00b_result_ok(n00b_option_t(n00b_plan_shard_result_t *),
                          n00b_option_set(n00b_plan_shard_result_t *,
                                          result));
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_shard_id(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->shard_id);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_generation(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->generation);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_schema_generation(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->schema_generation);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_record_count(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->record_count);
}

n00b_result_t(uint64_t)
n00b_plan_shard_result_seal_ts(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(uint64_t, N00B_PLAN_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, result->seal_ts);
}

n00b_result_t(n00b_string_t *)
n00b_plan_shard_result_partition_key(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_ARG);
    }
    if (result->partition_key == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_PLAN_ERR_STATE);
    }
    return n00b_result_ok(n00b_string_t *, result->partition_key);
}

n00b_result_t(n00b_plan_ordset_t *)
n00b_plan_shard_result_ordinals(n00b_plan_shard_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(n00b_plan_ordset_t *, N00B_PLAN_ERR_ARG);
    }
    auto ok = _rocs_plan_ordset_check(result->ordinals);
    if (n00b_result_is_err(ok)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(ok));
    }
    return n00b_result_ok(n00b_plan_ordset_t *, result->ordinals);
}
