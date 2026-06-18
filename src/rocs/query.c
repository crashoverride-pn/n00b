#include "internal/rocs/query.h"

#include "adt/heap.h"
#include "adt/list.h"
#include "conduit/conduit.h"
#include "conduit/subscription.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/condition.h"
#include "core/data_lock.h"
#include "core/thread.h"
#include "core/time.h"
#include "internal/rocs/filter.h"
#include "internal/rocs/index.h"
#include "internal/rocs/json_field.h"
#include "internal/rocs/plan.h"
#include "internal/rocs/store.h"
#include "rocs/map.h"
#include "text/strings/string_ops.h"

N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_query_hit_t *);
N00B_CONDUIT_TOPIC_IMPL(n00b_query_hit_t *);

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
typedef n00b_list_t(n00b_store_pos_t) rocs_query_pos_list_t;
typedef struct rocs_query_agg_state_t rocs_query_agg_state_t;
typedef n00b_list_t(rocs_query_agg_state_t *) rocs_query_agg_state_list_t;
typedef struct rocs_query_rank_term_t rocs_query_rank_term_t;
typedef struct rocs_query_rank_shard_t rocs_query_rank_shard_t;
typedef n00b_list_t(rocs_query_rank_term_t *)
    rocs_query_rank_term_list_t;
typedef n00b_list_t(rocs_query_rank_shard_t *)
    rocs_query_rank_shard_list_t;
typedef n00b_heap_t(n00b_query_hit_t *) rocs_query_rank_hit_heap_t;

#define ROCS_QUERY_LIVE_COMMIT_INBOX_LIMIT 64u

typedef struct rocs_query_output_state_t rocs_query_output_state_t;

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

typedef struct {
    bool             has_start_after;
    n00b_store_pos_t start_after;
    bool             has_historical_upper_bound;
    n00b_store_pos_t historical_upper_bound;
    bool             has_cutover_after;
    n00b_store_pos_t cutover_after;
    n00b_store_commit_topic_t     *commit_topic;
    n00b_store_commit_inbox_t     *commit_inbox;
    n00b_conduit_sub_handle_t      commit_sub;
    rocs_query_pos_list_t         *pending_positions;
    n00b_query_live_tail_stats_t   stats;
    n00b_rwlock_t                 *lock;
    n00b_condition_t               wait_cv;
} rocs_query_live_state_t;

struct rocs_query_output_state_t {
    n00b_conduit_t          *conduit;
    n00b_query_hit_topic_t  *topic;
    n00b_thread_t           *thread;
    n00b_rwlock_t           *lock;
    n00b_allocator_t        *allocator;
    uint64_t                 live_pending_index;
    n00b_query_output_stats_t stats;
};

struct n00b_query_retention_error_t {
    n00b_query_err_t           code;
    n00b_query_boundary_kind_t boundary;
    n00b_store_pos_t           requested;
    bool                       has_oldest_available;
    n00b_store_pos_t           oldest_available;
};

struct n00b_query_agg_spec_t {
    n00b_query_agg_op_t  op;
    n00b_filter_field_t *field;
    n00b_string_t       *name;
};

struct n00b_query_boost_t {
    n00b_filter_field_t *field;
    double               boost;
};

struct n00b_query_t {
    n00b_filter_t                *filter;
    n00b_query_group_by_list_t   *group_by;
    n00b_query_agg_spec_list_t   *aggregates;
    n00b_query_boost_list_t      *boosts;
    n00b_allocator_t             *allocator;
    bool                          ranked;
    bool                          has_as_of;
    n00b_store_pos_t              as_of;
    uint64_t                      limit;
};

struct n00b_query_agg_row_t {
    n00b_query_group_key_list_t *keys;
    n00b_query_value_list_t     *values;
    rocs_query_agg_state_list_t *states;
    uint64_t                     record_count;
    bool                         valid;
};

struct n00b_query_group_key_t {
    n00b_filter_field_t *field;
    n00b_query_value_t   value;
    bool                 valid;
};

struct n00b_query_note_t {
    n00b_query_agg_spec_t *aggregate;
    n00b_filter_field_t   *field;
    n00b_string_t         *message;
    n00b_query_value_t     value;
    n00b_store_pos_t       pos;
    bool                   has_value;
    bool                   has_pos;
    bool                   valid;
};

struct n00b_query_result_t {
    n00b_query_hit_list_t     *records;
    n00b_query_agg_row_list_t *rows;
    n00b_query_note_list_t    *notes;
    n00b_allocator_t          *allocator;
    _Atomic(bool)              closed;
};

struct n00b_query_view_t {
    n00b_store_t              *store;
    n00b_filter_t             *filter;
    n00b_store_pin_t          *pin;
    rocs_query_boundary_list_t *boundary;
    rocs_query_cursor_list_t  *cursors;
    rocs_query_cache_t        *cache;
    rocs_query_live_state_t   *live;
    rocs_query_output_state_t *output;
    n00b_allocator_t          *allocator;
    n00b_query_mode_t          mode;
    uint64_t                   limit;
    bool                       has_resume;
    n00b_store_pos_t           resume;
    bool                       has_as_of;
    n00b_store_pos_t           as_of;
    _Atomic(bool)              closed;
};

struct n00b_query_cursor_t {
    n00b_query_view_t         *view;
    rocs_query_hit_list_t     *hits;
    rocs_query_resident_list_t *residents;
    n00b_plan_predicate_t     *snapshot_predicate;
    n00b_plan_index_list_t    *snapshot_indexes;
    rocs_query_ordset_ref_list_t *snapshot_cached_refs;
    rocs_query_cache_key_t     snapshot_cache_key;
    n00b_query_hit_t          *current_hit;
    n00b_allocator_t          *allocator;
    uint64_t                   next_index;
    uint64_t                   snapshot_boundary_index;
    uint64_t                   live_pending_index;
    uint64_t                   active_next;
    n00b_condition_t           state_cv;
    _Atomic(bool)              live_waiting;
    bool                       snapshot_prepared;
    bool                       snapshot_use_cache;
    bool                       snapshot_exhausted;
    // Streaming mode (set via n00b_query_cursor_set_streaming): a consumer that
    // copies each hit's data out (e.g. n00b_query_hit_json_copy) before calling
    // n00b_query_cursor_next again. When set, the snapshot fill path releases the
    // prior boundary's resident shard(s) and clears already-delivered hits before
    // loading the next boundary, so only a bounded working set stays resident —
    // the LRU/residency budget then actually bounds RSS regardless of --limit.
    // Unsafe for the buffered path (which retains borrowed record views), so it
    // is opt-in and defaults off.
    bool                       stream_release;
    bool                       has_position;
    n00b_store_pos_t           position;
    _Atomic(bool)              closed;
    _Atomic(bool)              close_complete;
};

struct n00b_query_hit_t {
    n00b_query_cursor_t *cursor;
    n00b_store_pos_t     pos;
    n00b_store_record_t *record;
    n00b_store_resident_shard_t *resident;
    double               score;
    bool                 valid;
    bool                 owned;
};

struct rocs_query_agg_state_t {
    n00b_query_agg_spec_t *spec;
    n00b_query_value_t     selected;
    n00b_store_pos_t       selected_pos;
    double                 double_sum;
    int64_t                int_sum;
    uint64_t               numeric_count;
    uint64_t               count;
    bool                   has_selected;
    bool                   saw_double;
    bool                   int_overflow;
};

struct rocs_query_rank_shard_t {
    uint64_t              shard_id;
    uint64_t              generation;
    uint64_t              record_count;
    n00b_plan_ordset_t   *ordinals;
};

struct rocs_query_rank_term_t {
    n00b_filter_field_t          *field;
    n00b_string_t                *text;
    rocs_query_rank_shard_list_t *shards;
    double                        boost;
    double                        idf;
    uint64_t                      record_count;
    uint64_t                      document_frequency;
    bool                          scoreable;
};

static void rocs_query_cursor_invalidate_current(n00b_query_cursor_t *cursor);
static n00b_query_cursor_t *
rocs_query_cursor_new(n00b_query_view_t *view,
                      n00b_allocator_t  *allocator);
static bool rocs_query_cursor_limit_reached(n00b_query_cursor_t *cursor);
static n00b_result_t(bool)
rocs_query_output_close(rocs_query_output_state_t *output);

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
    case N00B_QUERY_ERR_INVALID_OPTION:
        return r"N00B_QUERY_ERR_INVALID_OPTION";
    case N00B_QUERY_ERR_NOT_READY:
        return r"N00B_QUERY_ERR_NOT_READY";
    case N00B_QUERY_ERR_RANGE:
        return r"N00B_QUERY_ERR_RANGE";
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
    case N00B_STORE_ERR_CONFIG:
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

static n00b_query_group_by_list_t *
rocs_query_group_by_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_group_by_list_t *list = n00b_alloc_with_opts(
        n00b_query_group_by_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_filter_field_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_agg_spec_list_t *
rocs_query_agg_spec_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_agg_spec_list_t *list = n00b_alloc_with_opts(
        n00b_query_agg_spec_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_agg_spec_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_boost_list_t *
rocs_query_boost_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_boost_list_t *list = n00b_alloc_with_opts(
        n00b_query_boost_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_boost_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_hit_list_t *
rocs_query_result_hit_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_hit_list_t *list = n00b_alloc_with_opts(
        n00b_query_hit_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_hit_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_agg_row_list_t *
rocs_query_agg_row_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_agg_row_list_t *list = n00b_alloc_with_opts(
        n00b_query_agg_row_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_agg_row_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_group_key_list_t *
rocs_query_group_key_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_group_key_list_t *list = n00b_alloc_with_opts(
        n00b_query_group_key_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_group_key_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_value_list_t *
rocs_query_value_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_value_list_t *list = n00b_alloc_with_opts(
        n00b_query_value_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_value_t,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_agg_state_list_t *
rocs_query_agg_state_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_agg_state_list_t *list = n00b_alloc_with_opts(
        rocs_query_agg_state_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(rocs_query_agg_state_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_query_note_list_t *
rocs_query_note_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_note_list_t *list = n00b_alloc_with_opts(
        n00b_query_note_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_query_note_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
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

static rocs_query_pos_list_t *
rocs_query_pos_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_pos_list_t *list = n00b_alloc_with_opts(
        rocs_query_pos_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(n00b_store_pos_t,
                                  .allocator = allocator);
    return list;
}

static rocs_query_rank_term_list_t *
rocs_query_rank_term_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_rank_term_list_t *list = n00b_alloc_with_opts(
        rocs_query_rank_term_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(rocs_query_rank_term_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static rocs_query_rank_shard_list_t *
rocs_query_rank_shard_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_rank_shard_list_t *list = n00b_alloc_with_opts(
        rocs_query_rank_shard_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(rocs_query_rank_shard_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_result_t(n00b_query_group_by_list_t *)
rocs_query_group_by_list_copy(n00b_query_group_by_list_t *src) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_group_by_list_t *copy =
        rocs_query_group_by_list_new(.allocator = allocator);
    if (src == nullptr) {
        return n00b_result_ok(n00b_query_group_by_list_t *, copy);
    }

    uint64_t len = (uint64_t)n00b_list_len(*src);
    for (uint64_t i = 0; i < len; i++) {
        n00b_filter_field_t *field = n00b_list_get(*src, (size_t)i);
        if (field == nullptr) {
            return n00b_result_err(n00b_query_group_by_list_t *,
                                   N00B_QUERY_ERR_INVALID_OPTION);
        }
        n00b_list_push(*copy, field);
    }

    return n00b_result_ok(n00b_query_group_by_list_t *, copy);
}

static n00b_result_t(n00b_query_agg_spec_list_t *)
rocs_query_agg_spec_list_copy(n00b_query_agg_spec_list_t *src) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_agg_spec_list_t *copy =
        rocs_query_agg_spec_list_new(.allocator = allocator);
    if (src == nullptr) {
        return n00b_result_ok(n00b_query_agg_spec_list_t *, copy);
    }

    uint64_t len = (uint64_t)n00b_list_len(*src);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_agg_spec_t *spec = n00b_list_get(*src, (size_t)i);
        if (spec == nullptr) {
            return n00b_result_err(n00b_query_agg_spec_list_t *,
                                   N00B_QUERY_ERR_INVALID_OPTION);
        }
        n00b_list_push(*copy, spec);
    }

    return n00b_result_ok(n00b_query_agg_spec_list_t *, copy);
}

static n00b_result_t(n00b_query_boost_list_t *)
rocs_query_boost_list_copy(n00b_query_boost_list_t *src) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_boost_list_t *copy =
        rocs_query_boost_list_new(.allocator = allocator);
    if (src == nullptr) {
        return n00b_result_ok(n00b_query_boost_list_t *, copy);
    }

    uint64_t len = (uint64_t)n00b_list_len(*src);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_boost_t *spec = n00b_list_get(*src, (size_t)i);
        if (spec == nullptr) {
            return n00b_result_err(n00b_query_boost_list_t *,
                                   N00B_QUERY_ERR_INVALID_OPTION);
        }
        n00b_list_push(*copy, spec);
    }

    return n00b_result_ok(n00b_query_boost_list_t *, copy);
}

static n00b_query_result_t *
rocs_query_result_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_result_t *result = n00b_alloc_with_opts(
        n00b_query_result_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    result->records   = rocs_query_result_hit_list_new(.allocator = allocator);
    result->rows      = rocs_query_agg_row_list_new(.allocator = allocator);
    result->notes     = rocs_query_note_list_new(.allocator = allocator);
    result->allocator = allocator;
    n00b_atomic_store(&result->closed, false);
    return result;
}

static bool
rocs_query_result_is_closed_raw(n00b_query_result_t *result)
{
    return result == nullptr || n00b_atomic_load(&result->closed);
}

typedef enum : int32_t {
    ROCS_QUERY_VALUE_MISSING = 0,
    ROCS_QUERY_VALUE_NULL    = 1,
    ROCS_QUERY_VALUE_BOOL    = 2,
    ROCS_QUERY_VALUE_I64     = 3,
    ROCS_QUERY_VALUE_U64     = 4,
    ROCS_QUERY_VALUE_F64     = 5,
    ROCS_QUERY_VALUE_STRING  = 6,
    ROCS_QUERY_VALUE_BYTES   = 7,
} rocs_query_value_rank_t;

typedef struct {
    n00b_query_value_t value;
    bool               has_value;
} rocs_query_field_value_t;

typedef struct {
    double  as_double;
    int64_t as_i64;
    bool    is_numeric;
    bool    is_double;
} rocs_query_numeric_t;

static n00b_query_value_t
rocs_query_value_missing(void)
{
    return n00b_variant_set(n00b_query_value_t,
                            n00b_query_missing_t,
                            ((n00b_query_missing_t){0}));
}

static n00b_query_value_t
rocs_query_value_null(void)
{
    return n00b_variant_set(n00b_query_value_t,
                            n00b_query_null_t,
                            ((n00b_query_null_t){0}));
}

static rocs_query_value_rank_t
rocs_query_value_rank(n00b_query_value_t value)
{
    if (n00b_variant_is_type(value, n00b_query_missing_t)) {
        return ROCS_QUERY_VALUE_MISSING;
    }
    if (n00b_variant_is_type(value, n00b_query_null_t)) {
        return ROCS_QUERY_VALUE_NULL;
    }
    if (n00b_variant_is_type(value, bool)) {
        return ROCS_QUERY_VALUE_BOOL;
    }
    if (n00b_variant_is_type(value, int64_t)) {
        return ROCS_QUERY_VALUE_I64;
    }
    if (n00b_variant_is_type(value, uint64_t)) {
        return ROCS_QUERY_VALUE_U64;
    }
    if (n00b_variant_is_type(value, double)) {
        return ROCS_QUERY_VALUE_F64;
    }
    if (n00b_variant_is_type(value, n00b_string_t *)) {
        return ROCS_QUERY_VALUE_STRING;
    }
    if (n00b_variant_is_type(value, n00b_buffer_t *)) {
        return ROCS_QUERY_VALUE_BYTES;
    }
    return ROCS_QUERY_VALUE_MISSING;
}

static int
rocs_query_u64_compare(uint64_t left, uint64_t right)
{
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}

static int
rocs_query_i64_compare(int64_t left, int64_t right)
{
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}

static int
rocs_query_double_compare(double left, double right)
{
    bool left_nan  = __builtin_isnan(left);
    bool right_nan = __builtin_isnan(right);
    if (left_nan || right_nan) {
        if (left_nan && right_nan) {
            return 0;
        }
        return left_nan ? -1 : 1;
    }
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}

static int
rocs_query_i64_double_compare(int64_t left, double right)
{
    if (__builtin_isnan(right)) {
        return 0;
    }
    if (__builtin_isinf(right)) {
        return right > 0.0 ? -1 : 1;
    }
    if (right < -0x1p63) {
        return 1;
    }
    if (right >= 0x1p63) {
        return -1;
    }

    int64_t truncated = (int64_t)right;
    double  exact     = (double)truncated;
    if (exact == right) {
        return rocs_query_i64_compare(left, truncated);
    }
    if (right > 0.0) {
        return left <= truncated ? -1 : 1;
    }
    return left < truncated ? -1 : 1;
}

static int
rocs_query_bytes_compare(char *left,
                         size_t left_len,
                         char *right,
                         size_t right_len)
{
    size_t min_len = left_len < right_len ? left_len : right_len;
    if (min_len != 0) {
        int cmp = memcmp(left, right, min_len);
        if (cmp != 0) {
            return cmp < 0 ? -1 : 1;
        }
    }
    return rocs_query_u64_compare((uint64_t)left_len, (uint64_t)right_len);
}

static int
rocs_query_value_compare(n00b_query_value_t left,
                         n00b_query_value_t right)
{
    rocs_query_value_rank_t left_rank  = rocs_query_value_rank(left);
    rocs_query_value_rank_t right_rank = rocs_query_value_rank(right);
    if (left_rank != right_rank) {
        return (int)left_rank < (int)right_rank ? -1 : 1;
    }

    switch (left_rank) {
    case ROCS_QUERY_VALUE_MISSING:
    case ROCS_QUERY_VALUE_NULL:
        return 0;
    case ROCS_QUERY_VALUE_BOOL: {
        bool l = n00b_variant_get(left, bool);
        bool r = n00b_variant_get(right, bool);
        return l == r ? 0 : (l ? 1 : -1);
    }
    case ROCS_QUERY_VALUE_I64:
        return rocs_query_i64_compare(n00b_variant_get(left, int64_t),
                                      n00b_variant_get(right, int64_t));
    case ROCS_QUERY_VALUE_U64:
        return rocs_query_u64_compare(n00b_variant_get(left, uint64_t),
                                      n00b_variant_get(right, uint64_t));
    case ROCS_QUERY_VALUE_F64:
        return rocs_query_double_compare(n00b_variant_get(left, double),
                                         n00b_variant_get(right, double));
    case ROCS_QUERY_VALUE_STRING: {
        n00b_string_t *l = n00b_variant_get(left, n00b_string_t *);
        n00b_string_t *r = n00b_variant_get(right, n00b_string_t *);
        if (l == r) {
            return 0;
        }
        if (l == nullptr || r == nullptr) {
            return l == nullptr ? -1 : 1;
        }
        return rocs_query_bytes_compare(l->data, l->u8_bytes,
                                        r->data, r->u8_bytes);
    }
    case ROCS_QUERY_VALUE_BYTES: {
        n00b_buffer_t *l = n00b_variant_get(left, n00b_buffer_t *);
        n00b_buffer_t *r = n00b_variant_get(right, n00b_buffer_t *);
        if (l == r) {
            return 0;
        }
        if (l == nullptr || r == nullptr) {
            return l == nullptr ? -1 : 1;
        }
        return rocs_query_bytes_compare(l->data, l->byte_len,
                                        r->data, r->byte_len);
    }
    }
    return 0;
}

static rocs_query_numeric_t
rocs_query_value_numeric(n00b_query_value_t value)
{
    if (n00b_variant_is_type(value, int64_t)) {
        int64_t i = n00b_variant_get(value, int64_t);
        return (rocs_query_numeric_t){
            .as_double  = (double)i,
            .as_i64     = i,
            .is_numeric = true,
            .is_double  = false,
        };
    }
    if (n00b_variant_is_type(value, double)) {
        double d = n00b_variant_get(value, double);
        return (rocs_query_numeric_t){
            .as_double  = d,
            .as_i64     = 0,
            .is_numeric = !__builtin_isnan(d),
            .is_double  = true,
        };
    }
    return (rocs_query_numeric_t){};
}

static int
rocs_query_numeric_compare_value(n00b_query_value_t left,
                                 n00b_query_value_t right)
{
    rocs_query_numeric_t l = rocs_query_value_numeric(left);
    rocs_query_numeric_t r = rocs_query_value_numeric(right);
    if (!l.is_numeric || !r.is_numeric) {
        return 0;
    }
    if (!l.is_double && !r.is_double) {
        return rocs_query_i64_compare(l.as_i64, r.as_i64);
    }
    if (!l.is_double && r.is_double) {
        return rocs_query_i64_double_compare(l.as_i64, r.as_double);
    }
    if (l.is_double && !r.is_double) {
        return -rocs_query_i64_double_compare(r.as_i64, l.as_double);
    }
    return rocs_query_double_compare(l.as_double, r.as_double);
}

static n00b_result_t(rocs_query_field_value_t)
rocs_query_value_from_json(n00b_json_node_t *node,
                           n00b_allocator_t *allocator)
{
    if (node == nullptr) {
        return n00b_result_ok(rocs_query_field_value_t,
                              ((rocs_query_field_value_t){
                                  .value     = rocs_query_value_missing(),
                                  .has_value = true,
                              }));
    }

    switch (n00b_json_type(node)) {
    case N00B_JSON_NULL:
        return n00b_result_ok(rocs_query_field_value_t,
                              ((rocs_query_field_value_t){
                                  .value     = rocs_query_value_null(),
                                  .has_value = true,
                              }));
    case N00B_JSON_BOOL:
        return n00b_result_ok(
            rocs_query_field_value_t,
            ((rocs_query_field_value_t){
                .value = n00b_variant_set(n00b_query_value_t,
                                          bool,
                                          n00b_json_as_bool(node)),
                .has_value = true,
            }));
    case N00B_JSON_INT:
        return n00b_result_ok(
            rocs_query_field_value_t,
            ((rocs_query_field_value_t){
                .value = n00b_variant_set(n00b_query_value_t,
                                          int64_t,
                                          n00b_json_as_i64(node)),
                .has_value = true,
            }));
    case N00B_JSON_DOUBLE:
        return n00b_result_ok(
            rocs_query_field_value_t,
            ((rocs_query_field_value_t){
                .value = n00b_variant_set(n00b_query_value_t,
                                          double,
                                          n00b_json_as_f64(node)),
                .has_value = true,
            }));
    case N00B_JSON_STRING: {
        n00b_string_t *s = n00b_json_as_string(node);
        if (s == nullptr) {
            return n00b_result_err(rocs_query_field_value_t,
                                   N00B_QUERY_ERR_EXECUTION);
        }
        n00b_string_t *copy =
            n00b_unicode_str_copy(s, .allocator = allocator);
        if (copy == nullptr) {
            return n00b_result_err(rocs_query_field_value_t,
                                   N00B_QUERY_ERR_INTERNAL);
        }
        return n00b_result_ok(
            rocs_query_field_value_t,
            ((rocs_query_field_value_t){
                .value = n00b_variant_set(n00b_query_value_t,
                                          n00b_string_t *,
                                          copy),
                .has_value = true,
            }));
    }
    case N00B_JSON_ARRAY:
    case N00B_JSON_OBJECT:
        return n00b_result_ok(rocs_query_field_value_t,
                              ((rocs_query_field_value_t){
                                  .value     = rocs_query_value_missing(),
                                  .has_value = false,
                              }));
    }

    return n00b_result_err(rocs_query_field_value_t,
                           N00B_QUERY_ERR_EXECUTION);
}

static n00b_result_t(n00b_string_t *)
rocs_query_named_field(n00b_filter_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_QUERY_ERR_ARG);
    }

    auto name_r = n00b_filter_field_name(field);
    if (n00b_result_is_err(name_r)) {
        return n00b_result_err(
            n00b_string_t *,
            rocs_query_err_from_filter(n00b_result_get_err(name_r)));
    }

    n00b_option_t(n00b_string_t *) name_opt = n00b_result_get(name_r);
    if (!n00b_option_is_set(name_opt)) {
        return n00b_result_err(n00b_string_t *,
                               N00B_QUERY_ERR_INVALID_OPTION);
    }
    return n00b_result_ok(n00b_string_t *, n00b_option_get(name_opt));
}

static n00b_result_t(rocs_query_field_value_t)
rocs_query_record_field_value(n00b_store_record_t  *record,
                              n00b_filter_field_t *field,
                              n00b_allocator_t    *allocator)
{
    if (record == nullptr || field == nullptr) {
        return n00b_result_err(rocs_query_field_value_t,
                               N00B_QUERY_ERR_ARG);
    }

    auto name_r = rocs_query_named_field(field);
    if (n00b_result_is_err(name_r)) {
        return n00b_result_err(rocs_query_field_value_t,
                               n00b_result_get_err(name_r));
    }

    auto json_r = n00b_store_record_view_json(record,
                                             .allocator = allocator);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(
            rocs_query_field_value_t,
            rocs_query_err_from_index(n00b_result_get_err(json_r)));
    }

    n00b_json_node_t *json = n00b_result_get(json_r);
    n00b_json_node_t *node = nullptr;
    if (n00b_json_type(json) == N00B_JSON_OBJECT) {
        node = rocs_json_object_get_field(json, n00b_result_get(name_r));
    }
    return rocs_query_value_from_json(node, allocator);
}

static n00b_query_group_key_t *
rocs_query_group_key_new(n00b_filter_field_t *field,
                         n00b_query_value_t   value,
                         n00b_allocator_t    *allocator)
{
    n00b_query_group_key_t *key = n00b_alloc_with_opts(
        n00b_query_group_key_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    key->field = field;
    key->value = value;
    key->valid = true;
    return key;
}

static rocs_query_agg_state_t *
rocs_query_agg_state_new(n00b_query_agg_spec_t *spec,
                         n00b_allocator_t      *allocator)
{
    rocs_query_agg_state_t *state = n00b_alloc_with_opts(
        rocs_query_agg_state_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    state->spec        = spec;
    state->selected    = rocs_query_value_missing();
    state->selected_pos = (n00b_store_pos_t){};
    return state;
}

static n00b_query_agg_row_t *
rocs_query_row_new(n00b_query_group_key_list_t *keys,
                   n00b_query_agg_spec_list_t  *aggregates,
                   n00b_allocator_t            *allocator)
{
    n00b_query_agg_row_t *row = n00b_alloc_with_opts(
        n00b_query_agg_row_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    row->keys         = keys;
    row->values       = rocs_query_value_list_new(.allocator = allocator);
    row->states       = rocs_query_agg_state_list_new(.allocator = allocator);
    row->record_count = 0;
    row->valid        = true;

    uint64_t agg_len = aggregates == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*aggregates);
    for (uint64_t i = 0; i < agg_len; i++) {
        n00b_query_agg_spec_t *spec =
            n00b_list_get(*aggregates, (size_t)i);
        n00b_list_push(*row->states,
                       rocs_query_agg_state_new(spec, allocator));
    }
    return row;
}

static int
rocs_query_key_list_compare(n00b_query_group_key_list_t *left,
                            n00b_query_group_key_list_t *right)
{
    uint64_t left_len  = left == nullptr ? 0 : (uint64_t)n00b_list_len(*left);
    uint64_t right_len = right == nullptr ? 0 : (uint64_t)n00b_list_len(*right);
    uint64_t min_len   = left_len < right_len ? left_len : right_len;

    for (uint64_t i = 0; i < min_len; i++) {
        n00b_query_group_key_t *l = n00b_list_get(*left, (size_t)i);
        n00b_query_group_key_t *r = n00b_list_get(*right, (size_t)i);
        int cmp = rocs_query_value_compare(l->value, r->value);
        if (cmp != 0) {
            return cmp;
        }
    }

    return rocs_query_u64_compare(left_len, right_len);
}

static int
rocs_query_row_compare(const void *left, const void *right)
{
    n00b_query_agg_row_t * const *l = left;
    n00b_query_agg_row_t * const *r = right;
    return rocs_query_key_list_compare((*l)->keys, (*r)->keys);
}

static n00b_query_agg_row_t *
rocs_query_find_row(n00b_query_agg_row_list_t   *rows,
                    n00b_query_group_key_list_t *keys)
{
    uint64_t len = rows == nullptr ? 0 : (uint64_t)n00b_list_len(*rows);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_agg_row_t *row = n00b_list_get(*rows, (size_t)i);
        if (row != nullptr
            && rocs_query_key_list_compare(row->keys, keys) == 0) {
            return row;
        }
    }
    return nullptr;
}

static n00b_query_note_t *
rocs_query_note_new(n00b_query_agg_spec_t   *aggregate,
                    n00b_filter_field_t     *field,
                    n00b_store_pos_t         pos,
                    bool                     has_pos,
                    rocs_query_field_value_t value,
                    n00b_string_t           *message,
                    n00b_allocator_t        *allocator)
{
    n00b_query_note_t *note = n00b_alloc_with_opts(
        n00b_query_note_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    note->aggregate = aggregate;
    note->field     = field;
    note->message   = message;
    note->pos       = pos;
    note->has_pos   = has_pos;
    note->has_value = value.has_value;
    note->value     = value.value;
    note->valid     = true;
    return note;
}

static n00b_result_t(bool)
rocs_query_add_non_numeric_note(n00b_query_result_t     *result,
                                n00b_query_agg_spec_t   *spec,
                                n00b_store_pos_t         pos,
                                rocs_query_field_value_t value,
                                n00b_allocator_t        *allocator)
{
    if (result == nullptr || spec == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    n00b_query_note_t *note =
        rocs_query_note_new(spec,
                            spec->field,
                            pos,
                            true,
                            value,
                            r"non_numeric_aggregate_operand",
                            allocator);
    n00b_list_push(*result->notes, note);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_query_group_key_list_t *)
rocs_query_group_keys_for_record(n00b_query_t        *query,
                                 n00b_store_record_t *record,
                                 n00b_allocator_t    *allocator)
{
    if (query == nullptr || record == nullptr) {
        return n00b_result_err(n00b_query_group_key_list_t *,
                               N00B_QUERY_ERR_ARG);
    }

    n00b_query_group_key_list_t *keys =
        rocs_query_group_key_list_new(.allocator = allocator);
    uint64_t group_len = query->group_by == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*query->group_by);

    for (uint64_t i = 0; i < group_len; i++) {
        n00b_filter_field_t *field =
            n00b_list_get(*query->group_by, (size_t)i);
        auto value_r =
            rocs_query_record_field_value(record, field, allocator);
        if (n00b_result_is_err(value_r)) {
            return n00b_result_err(n00b_query_group_key_list_t *,
                                   n00b_result_get_err(value_r));
        }
        rocs_query_field_value_t value = n00b_result_get(value_r);
        if (!value.has_value) {
            return n00b_result_err(n00b_query_group_key_list_t *,
                                   N00B_QUERY_ERR_EXECUTION);
        }
        n00b_list_push(*keys,
                       rocs_query_group_key_new(field,
                                                value.value,
                                                allocator));
    }

    return n00b_result_ok(n00b_query_group_key_list_t *, keys);
}

static n00b_query_agg_row_t *
rocs_query_get_or_create_row(n00b_query_result_t         *result,
                             n00b_query_t                *query,
                             n00b_query_group_key_list_t *keys,
                             n00b_allocator_t            *allocator)
{
    n00b_query_agg_row_t *row = rocs_query_find_row(result->rows, keys);
    if (row != nullptr) {
        return row;
    }

    row = rocs_query_row_new(keys, query->aggregates, allocator);
    n00b_list_push(*result->rows, row);
    return row;
}

static n00b_result_t(bool)
rocs_query_agg_apply_state(n00b_query_result_t    *result,
                           rocs_query_agg_state_t *state,
                           n00b_store_record_t    *record,
                           n00b_store_pos_t        pos,
                           n00b_allocator_t       *allocator)
{
    if (result == nullptr || state == nullptr || state->spec == nullptr
        || record == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    n00b_query_agg_spec_t *spec = state->spec;
    if (spec->op == N00B_QUERY_AGG_COUNT) {
        if (state->count == UINT64_MAX) {
            return n00b_result_err(bool, N00B_QUERY_ERR_RANGE);
        }
        state->count++;
        return n00b_result_ok(bool, true);
    }

    if (spec->field == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto value_r =
        rocs_query_record_field_value(record, spec->field, allocator);
    if (n00b_result_is_err(value_r)) {
        return n00b_result_err(bool, n00b_result_get_err(value_r));
    }

    rocs_query_field_value_t value = n00b_result_get(value_r);
    rocs_query_numeric_t     num   = value.has_value
        ? rocs_query_value_numeric(value.value)
        : (rocs_query_numeric_t){};
    if (!num.is_numeric) {
        auto note_r =
            rocs_query_add_non_numeric_note(result,
                                            spec,
                                            pos,
                                            value,
                                            allocator);
        if (n00b_result_is_err(note_r)) {
            return note_r;
        }
        return n00b_result_ok(bool, true);
    }

    if (state->numeric_count == UINT64_MAX) {
        return n00b_result_err(bool, N00B_QUERY_ERR_RANGE);
    }
    state->numeric_count++;

    switch (spec->op) {
    case N00B_QUERY_AGG_SUM:
        state->double_sum += num.as_double;
        if (num.is_double) {
            state->saw_double = true;
        }
        else if (!state->int_overflow) {
            int64_t next = 0;
            if (__builtin_add_overflow(state->int_sum, num.as_i64, &next)) {
                state->int_overflow = true;
            }
            else {
                state->int_sum = next;
            }
        }
        break;
    case N00B_QUERY_AGG_AVG:
        state->double_sum += num.as_double;
        break;
    case N00B_QUERY_AGG_MIN:
    case N00B_QUERY_AGG_MAX: {
        bool replace = !state->has_selected;
        if (!replace) {
            int cmp = rocs_query_numeric_compare_value(value.value,
                                                       state->selected);
            if (spec->op == N00B_QUERY_AGG_MIN) {
                replace = cmp < 0
                    || (cmp == 0
                        && n00b_store_pos_compare(pos,
                                                  state->selected_pos) < 0);
            }
            else {
                replace = cmp > 0
                    || (cmp == 0
                        && n00b_store_pos_compare(pos,
                                                  state->selected_pos) < 0);
            }
        }
        if (replace) {
            state->selected     = value.value;
            state->selected_pos = pos;
            state->has_selected = true;
        }
        break;
    }
    case N00B_QUERY_AGG_COUNT:
        break;
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_row_apply_record(n00b_query_result_t  *result,
                            n00b_query_agg_row_t *row,
                            n00b_store_record_t  *record,
                            n00b_store_pos_t      pos,
                            n00b_allocator_t     *allocator)
{
    if (row == nullptr || record == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    if (row->record_count == UINT64_MAX) {
        return n00b_result_err(bool, N00B_QUERY_ERR_RANGE);
    }
    row->record_count++;

    uint64_t len = row->states == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*row->states);
    for (uint64_t i = 0; i < len; i++) {
        rocs_query_agg_state_t *state =
            n00b_list_get(*row->states, (size_t)i);
        auto apply_r =
            rocs_query_agg_apply_state(result, state, record, pos, allocator);
        if (n00b_result_is_err(apply_r)) {
            return apply_r;
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_query_value_t)
rocs_query_agg_state_value(rocs_query_agg_state_t *state)
{
    if (state == nullptr || state->spec == nullptr) {
        return n00b_result_err(n00b_query_value_t, N00B_QUERY_ERR_ARG);
    }

    switch (state->spec->op) {
    case N00B_QUERY_AGG_COUNT:
        return n00b_result_ok(
            n00b_query_value_t,
            n00b_variant_set(n00b_query_value_t, uint64_t, state->count));
    case N00B_QUERY_AGG_SUM:
        if (state->numeric_count == 0) {
            return n00b_result_ok(n00b_query_value_t,
                                  rocs_query_value_missing());
        }
        if (state->saw_double) {
            return n00b_result_ok(
                n00b_query_value_t,
                n00b_variant_set(n00b_query_value_t,
                                  double,
                                  state->double_sum));
        }
        if (state->int_overflow) {
            return n00b_result_err(n00b_query_value_t,
                                   N00B_QUERY_ERR_RANGE);
        }
        return n00b_result_ok(
            n00b_query_value_t,
            n00b_variant_set(n00b_query_value_t, int64_t, state->int_sum));
    case N00B_QUERY_AGG_MIN:
    case N00B_QUERY_AGG_MAX:
        return n00b_result_ok(
            n00b_query_value_t,
            state->has_selected ? state->selected
                                : rocs_query_value_missing());
    case N00B_QUERY_AGG_AVG:
        if (state->numeric_count == 0) {
            return n00b_result_ok(n00b_query_value_t,
                                  rocs_query_value_missing());
        }
        return n00b_result_ok(
            n00b_query_value_t,
            n00b_variant_set(n00b_query_value_t,
                              double,
                              state->double_sum
                                  / (double)state->numeric_count));
    }

    return n00b_result_err(n00b_query_value_t, N00B_QUERY_ERR_INTERNAL);
}

static n00b_result_t(bool)
rocs_query_finalize_rows(n00b_query_result_t *result,
                         n00b_query_t        *query)
{
    if (result == nullptr || query == nullptr || result->rows == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*result->rows);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_agg_row_t *row =
            n00b_list_get(*result->rows, (size_t)i);
        uint64_t state_len = row->states == nullptr
            ? 0
            : (uint64_t)n00b_list_len(*row->states);
        for (uint64_t j = 0; j < state_len; j++) {
            rocs_query_agg_state_t *state =
                n00b_list_get(*row->states, (size_t)j);
            auto value_r = rocs_query_agg_state_value(state);
            if (n00b_result_is_err(value_r)) {
                return n00b_result_err(bool, n00b_result_get_err(value_r));
            }
            n00b_list_push(*row->values, n00b_result_get(value_r));
        }
    }

    if (len > 1) {
        n00b_list_sort(*result->rows, rocs_query_row_compare);
    }

    len = (uint64_t)n00b_list_len(*result->rows);
    if (query->limit != 0 && len > query->limit
        && query->limit <= (uint64_t)SIZE_MAX) {
        n00b_list_delete_range(*result->rows,
                               (size_t)query->limit,
                               (size_t)(len - query->limit));
    }

    return n00b_result_ok(bool, true);
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

static rocs_query_live_state_t *
rocs_query_live_state_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_live_state_t *state = n00b_alloc_with_opts(
        rocs_query_live_state_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    *state = (rocs_query_live_state_t){};
    state->commit_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    state->lock       = n00b_data_lock_new(.allocator = allocator);
    state->pending_positions =
        rocs_query_pos_list_new(.allocator = allocator);
    n00b_condition_init(&state->wait_cv);
    return state;
}

static rocs_query_output_state_t *
rocs_query_output_state_new(n00b_conduit_t *conduit,
                            uint64_t        limit) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_query_output_state_t *state = n00b_alloc_with_opts(
        rocs_query_output_state_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    *state = (rocs_query_output_state_t){};
    state->conduit   = conduit;
    state->allocator = allocator;
    state->lock      = n00b_data_lock_new(.allocator = allocator);
    state->stats = (n00b_query_output_stats_t){
        .configured = true,
        .limit      = limit,
    };
    return state;
}

static bool
rocs_query_view_is_closed_raw(n00b_query_view_t *view)
{
    return view == nullptr || n00b_atomic_load(&view->closed);
}

static bool
rocs_query_cursor_is_closed_raw(n00b_query_cursor_t *cursor)
{
    return cursor == nullptr || n00b_atomic_load(&cursor->closed);
}

static bool
rocs_query_cursor_close_complete_raw(n00b_query_cursor_t *cursor)
{
    return cursor == nullptr || n00b_atomic_load(&cursor->close_complete);
}

static bool
rocs_query_cursor_or_view_closed(n00b_query_cursor_t *cursor)
{
    return rocs_query_cursor_is_closed_raw(cursor)
        || cursor->view == nullptr
        || rocs_query_view_is_closed_raw(cursor->view);
}

static void
rocs_query_live_notify_waiters(n00b_query_view_t *view)
{
    if (view == nullptr || view->live == nullptr) {
        return;
    }

    rocs_query_live_state_t *live  = view->live;
    n00b_store_commit_inbox_t *inbox = nullptr;
    n00b_data_read_lock(live->lock);
    inbox = live->commit_inbox;
    n00b_data_unlock(live->lock);

    n00b_condition_notify(&live->wait_cv,
                          .all         = true,
                          .auto_unlock = true);
    if (inbox != nullptr) {
        n00b_condition_notify(&inbox->cv,
                              .all         = true,
                              .auto_unlock = true);
    }
}

static void
rocs_query_cursor_set_live_waiting(n00b_query_cursor_t *cursor, bool waiting)
{
    if (cursor == nullptr) {
        return;
    }

    n00b_atomic_store(&cursor->live_waiting, waiting);
    n00b_condition_notify(&cursor->state_cv,
                          .all         = true,
                          .auto_unlock = true);
}

static n00b_result_t(bool)
rocs_query_cursor_begin_next(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    n00b_condition_lock(&cursor->state_cv);
    if (rocs_query_cursor_or_view_closed(cursor)) {
        n00b_condition_unlock(&cursor->state_cv);
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }

    cursor->active_next++;
    n00b_condition_unlock(&cursor->state_cv);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_option_t(n00b_query_hit_t *))
rocs_query_cursor_finish_next(
    n00b_query_cursor_t                                  *cursor,
    bool                                                  live,
    n00b_result_t(n00b_option_t(n00b_query_hit_t *))      result)
{
    if (cursor == nullptr) {
        return result;
    }

    n00b_condition_lock(&cursor->state_cv);
    bool closed = rocs_query_cursor_or_view_closed(cursor);
    if (cursor->active_next != 0) {
        cursor->active_next--;
    }
    if (closed) {
        rocs_query_cursor_invalidate_current(cursor);
        if (live) {
            result = n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                                    n00b_option_none(n00b_query_hit_t *));
        }
        else {
            result = n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                                     N00B_QUERY_ERR_CLOSED);
        }
    }
    n00b_condition_notify(&cursor->state_cv,
                          .all         = true,
                          .auto_unlock = true);
    return result;
}

static n00b_result_t(bool)
rocs_query_cursor_mark_closed(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    n00b_condition_lock(&cursor->state_cv);
    if (rocs_query_cursor_is_closed_raw(cursor)) {
        n00b_condition_unlock(&cursor->state_cv);
        return n00b_result_ok(bool, false);
    }

    n00b_atomic_store(&cursor->closed, true);
    n00b_atomic_store(&cursor->live_waiting, false);
    n00b_condition_notify(&cursor->state_cv,
                          .all         = true,
                          .auto_unlock = true);
    return n00b_result_ok(bool, true);
}

static void
rocs_query_cursor_wait_for_active_next(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return;
    }

    n00b_condition_lock(&cursor->state_cv);
    while (cursor->active_next != 0) {
        n00b_condition_wait(&cursor->state_cv);
    }
    n00b_condition_unlock(&cursor->state_cv);
}

static void
rocs_query_cursor_mark_close_complete(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return;
    }

    n00b_condition_lock(&cursor->state_cv);
    n00b_atomic_store(&cursor->close_complete, true);
    n00b_condition_notify(&cursor->state_cv,
                          .all         = true,
                          .auto_unlock = true);
}

static void
rocs_query_cursor_wait_for_close_complete(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return;
    }

    n00b_condition_lock(&cursor->state_cv);
    while (!rocs_query_cursor_close_complete_raw(cursor)) {
        n00b_condition_wait(&cursor->state_cv);
    }
    n00b_condition_unlock(&cursor->state_cv);
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

static n00b_store_pos_t
rocs_query_entry_first_pos(n00b_query_boundary_entry_t entry)
{
    return (n00b_store_pos_t){
        .generation = entry.generation,
        .shard_id   = entry.shard_id,
        .ordinal    = 0,
    };
}

static n00b_store_pos_t
rocs_query_entry_last_pos(n00b_query_boundary_entry_t entry)
{
    return (n00b_store_pos_t){
        .generation = entry.generation,
        .shard_id   = entry.shard_id,
        .ordinal    = entry.record_count == 0 ? 0 : entry.record_count - 1,
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

static n00b_query_boundary_entry_t
rocs_query_boundary_from_snapshot(n00b_store_catalog_snapshot_entry_t entry)
{
    return (n00b_query_boundary_entry_t){
        .shard_id          = entry.shard_id,
        .generation        = entry.generation,
        .schema_generation = entry.schema_generation,
        .record_count      = entry.record_count,
        .seal_ts           = entry.seal_ts,
        .partition_key     = entry.partition_key,
        .object_path       = entry.object_path,
        .byte_len          = entry.byte_len,
        .etag              = entry.etag,
    };
}

static n00b_result_t(bool)
rocs_query_capture_boundary(n00b_query_view_t *view)
{
    auto snapshot_r = n00b_store_catalog_visible_snapshot(
        view->store,
        .allocator = view->allocator);
    if (n00b_result_is_err(snapshot_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(snapshot_r)));
    }

    n00b_store_catalog_snapshot_t *snapshot = n00b_result_get(snapshot_r);
    if (snapshot == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_INTERNAL);
    }

    uint64_t count = (uint64_t)n00b_list_len(*snapshot);
    for (uint64_t i = 0; i < count; i++) {
        n00b_query_boundary_entry_t copied =
            rocs_query_boundary_from_snapshot(
                n00b_list_get(*snapshot, (size_t)i));
        if (rocs_query_entry_in_requested_window(view, copied)) {
            rocs_query_boundary_insert_sorted(view->boundary, copied);
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_option_t(n00b_store_pos_t))
rocs_query_snapshot_upper_bound(n00b_query_view_t *view)
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

static n00b_result_t(bool)
rocs_query_capture_live_state(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE) {
        return n00b_result_ok(bool, true);
    }

    rocs_query_live_state_t *live =
        rocs_query_live_state_new(.allocator = view->allocator);
    if (view->has_resume) {
        live->has_start_after = true;
        live->start_after     = view->resume;
    }

    auto upper_r = rocs_query_snapshot_upper_bound(view);
    if (n00b_result_is_err(upper_r)) {
        return n00b_result_err(bool, n00b_result_get_err(upper_r));
    }
    n00b_option_t(n00b_store_pos_t) upper_opt = n00b_result_get(upper_r);
    if (n00b_option_is_set(upper_opt)) {
        live->has_historical_upper_bound = true;
        live->historical_upper_bound     = n00b_option_get(upper_opt);
        live->has_cutover_after          = true;
        live->cutover_after              = live->historical_upper_bound;
    }
    else if (live->has_start_after) {
        live->has_cutover_after = true;
        live->cutover_after     = live->start_after;
    }
    if (live->has_cutover_after) {
        live->stats.has_last_observed = true;
        live->stats.last_observed     = live->cutover_after;
    }

    view->live = live;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_live_subscribe(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE || view->live == nullptr) {
        return n00b_result_ok(bool, true);
    }

    auto topic_r = n00b_store_commit_topic_for_query(view->store);
    if (n00b_result_is_err(topic_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(topic_r)));
    }

    n00b_option_t(n00b_store_commit_topic_t *) topic_opt =
        n00b_result_get(topic_r);
    if (!n00b_option_is_set(topic_opt)) {
        return n00b_result_ok(bool, true);
    }

    n00b_store_commit_topic_t *topic = n00b_option_get(topic_opt);
    auto inbox_r = n00b_store_commit_inbox_for_query(
        topic,
        ROCS_QUERY_LIVE_COMMIT_INBOX_LIMIT,
        .allocator = view->allocator);
    if (n00b_result_is_err(inbox_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(inbox_r)));
    }

    n00b_store_commit_inbox_t *inbox = n00b_result_get(inbox_r);
    auto sub_r = n00b_store_commit_subscribe(topic, inbox);
    if (n00b_result_is_err(sub_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(sub_r)));
    }

    view->live->commit_topic             = topic;
    view->live->commit_inbox             = inbox;
    view->live->commit_sub               = n00b_result_get(sub_r);
    view->live->stats.subscribed         = true;
    view->live->stats.subscription_active = true;
    view->live->stats.has_inbox          = true;
    view->live->stats.inbox_limit        = ROCS_QUERY_LIVE_COMMIT_INBOX_LIMIT;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_live_cancel_subscription(rocs_query_live_state_t *live)
{
    if (live == nullptr) {
        return n00b_result_ok(bool, false);
    }

    n00b_data_write_lock(live->lock);
    n00b_conduit_sub_handle_t sub = live->commit_sub;
    n00b_store_commit_topic_t *topic = live->commit_topic;
    live->commit_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    live->stats.subscribed          = false;
    live->stats.subscription_active = false;
    live->stats.has_inbox           = false;
    live->commit_inbox = nullptr;
    live->commit_topic = nullptr;
    n00b_data_unlock(live->lock);

    if (sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_ok(bool, false);
    }

    auto cancel_r = n00b_store_commit_unsubscribe_for_query(topic, sub);
    if (n00b_result_is_err(cancel_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(cancel_r)));
    }

    return cancel_r;
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
    hit->resident = nullptr;
    hit->score  = 0.0;
    hit->valid  = false;
    hit->owned  = false;
    return hit;
}

static n00b_query_hit_t *
rocs_query_owned_hit_new(n00b_store_pos_t              pos,
                         n00b_store_record_t         *record,
                         n00b_store_resident_shard_t *resident) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_query_hit_t *hit = n00b_alloc_with_opts(
        n00b_query_hit_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    hit->cursor   = nullptr;
    hit->pos      = pos;
    hit->record   = record;
    hit->resident = resident;
    hit->score    = 0.0;
    hit->valid    = true;
    hit->owned    = true;
    return hit;
}

static n00b_result_t(bool)
rocs_query_owned_hit_release(n00b_query_hit_t *hit)
{
    if (hit == nullptr || !hit->owned) {
        return n00b_result_ok(bool, false);
    }
    if (!hit->valid) {
        return n00b_result_ok(bool, false);
    }

    hit->valid = false;
    if (hit->resident == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_store_resident_shard_t *resident = hit->resident;
    hit->resident = nullptr;
    return rocs_query_release_resident(resident);
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

    auto mark_r = rocs_query_cursor_mark_closed(cursor);
    if (n00b_result_is_err(mark_r) || !n00b_result_get(mark_r)) {
        if (n00b_result_is_ok(mark_r)) {
            rocs_query_cursor_wait_for_close_complete(cursor);
        }
        return mark_r;
    }

    rocs_query_live_notify_waiters(cursor->view);
    rocs_query_cursor_wait_for_active_next(cursor);
    rocs_query_cursor_invalidate_all(cursor);

    auto release_r = rocs_query_cursor_release_residents(cursor);
    if (n00b_result_is_err(release_r)) {
        rocs_query_cursor_mark_close_complete(cursor);
        return n00b_result_err(bool, n00b_result_get_err(release_r));
    }

    rocs_query_cursor_mark_close_complete(cursor);
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

static n00b_result_t(rocs_query_live_state_t *)
rocs_query_live_state_for_tail(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(rocs_query_live_state_t *, N00B_QUERY_ERR_ARG);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE || view->live == nullptr) {
        return n00b_result_err(rocs_query_live_state_t *, N00B_QUERY_ERR_STATE);
    }
    return n00b_result_ok(rocs_query_live_state_t *, view->live);
}

static uint64_t
rocs_query_live_first_unobserved_ordinal(rocs_query_live_state_t    *live,
                                         n00b_query_boundary_entry_t  boundary,
                                         bool                         has_last,
                                         n00b_store_pos_t             last)
{
    if (live == nullptr || !has_last) {
        return 0;
    }
    if (last.generation != boundary.generation
        || last.shard_id != boundary.shard_id) {
        return 0;
    }
    if (last.ordinal == UINT64_MAX || last.ordinal + 1 >= boundary.record_count) {
        return boundary.record_count;
    }
    return last.ordinal + 1;
}

static n00b_result_t(rocs_query_boundary_list_t *)
rocs_query_live_tail_boundaries(n00b_query_view_t               *view,
                                n00b_store_catalog_snapshot_t   *snapshot,
                                bool                            has_last,
                                n00b_store_pos_t                last)
{
    if (view == nullptr || snapshot == nullptr) {
        return n00b_result_err(rocs_query_boundary_list_t *,
                               N00B_QUERY_ERR_ARG);
    }

    rocs_query_boundary_list_t *tail =
        rocs_query_boundary_list_new(.allocator = view->allocator);
    uint64_t count = (uint64_t)n00b_list_len(*snapshot);
    for (uint64_t i = 0; i < count; i++) {
        n00b_query_boundary_entry_t boundary =
            rocs_query_boundary_from_snapshot(
                n00b_list_get(*snapshot, (size_t)i));
        if (boundary.record_count == 0) {
            continue;
        }

        n00b_store_pos_t max_pos = rocs_query_entry_last_pos(boundary);
        if (has_last && n00b_store_pos_compare(max_pos, last) <= 0) {
            continue;
        }

        rocs_query_boundary_insert_sorted(tail, boundary);
    }

    return n00b_result_ok(rocs_query_boundary_list_t *, tail);
}

static n00b_result_t(uint64_t)
rocs_query_live_tail_drain_wakeups_locked(rocs_query_live_state_t *live)
{
    if (live == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    if (live->commit_inbox == nullptr) {
        return n00b_result_ok(uint64_t, 0);
    }

    uint64_t queued_before =
        (uint64_t)n00b_store_commit_inbox_msg_count(live->commit_inbox);
    if (live->stats.inbox_limit != 0
        && queued_before >= (uint64_t)live->stats.inbox_limit) {
        live->stats.wakeup_full_observations++;
    }

    uint64_t drained = 0;
    while (true) {
        n00b_store_commit_msg_t *msg =
            n00b_store_commit_inbox_pop(live->commit_inbox);
        if (msg == nullptr) {
            break;
        }
        drained++;
    }

    live->stats.wakeups_drained += drained;
    return n00b_result_ok(uint64_t, drained);
}

static n00b_result_t(uint64_t)
rocs_query_live_tail_scan_once_locked(n00b_query_view_t       *view,
                                      rocs_query_live_state_t *live)
{
    auto drain_r = rocs_query_live_tail_drain_wakeups_locked(live);
    if (n00b_result_is_err(drain_r)) {
        return drain_r;
    }

    bool             has_last = live->stats.has_last_observed;
    n00b_store_pos_t last     = live->stats.last_observed;
    auto tail_snapshot_r = n00b_store_tail_snapshot(
        view->store,
        .allocator = view->allocator);
    if (n00b_result_is_err(tail_snapshot_r)) {
        return n00b_result_err(
            uint64_t,
            rocs_query_err_from_store(n00b_result_get_err(tail_snapshot_r)));
    }

    n00b_store_tail_snapshot_t tail_snapshot =
        n00b_result_get(tail_snapshot_r);
    auto boundary_r = rocs_query_live_tail_boundaries(view,
                                                      tail_snapshot.sealed,
                                                      has_last,
                                                      last);
    if (n00b_result_is_err(boundary_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(boundary_r));
    }

    auto lowered_r = n00b_filter_lower_to_plan(
        view->filter,
        .allocator = view->allocator);
    if (n00b_result_is_err(lowered_r)) {
        return n00b_result_err(
            uint64_t,
            rocs_query_err_from_filter(n00b_result_get_err(lowered_r)));
    }
    n00b_plan_predicate_t *predicate = n00b_result_get(lowered_r);

    rocs_query_pos_list_t *new_positions =
        rocs_query_pos_list_new(.allocator = view->allocator);
    uint64_t observed_delta = 0;
    uint64_t matched_delta  = 0;

    rocs_query_boundary_list_t *boundaries = n00b_result_get(boundary_r);
    uint64_t boundary_len = (uint64_t)n00b_list_len(*boundaries);
    if (boundary_len != 0) {
        auto indexes_r = n00b_store_plan_indexes_for_query(
            view->store,
            .allocator = view->allocator);
        if (n00b_result_is_err(indexes_r)) {
            return n00b_result_err(
                uint64_t,
                rocs_query_err_from_store(n00b_result_get_err(indexes_r)));
        }

        auto plan_r = n00b_plan_store_sealed(view->store,
                                             predicate,
                                             n00b_result_get(indexes_r),
                                             .allocator = view->allocator);
        if (n00b_result_is_err(plan_r)) {
            return n00b_result_err(
                uint64_t,
                rocs_query_err_from_plan(n00b_result_get_err(plan_r)));
        }

        n00b_plan_shard_result_list_t *results = n00b_result_get(plan_r);
        for (uint64_t i = 0; i < boundary_len; i++) {
            n00b_query_boundary_entry_t boundary =
                n00b_list_get(*boundaries, (size_t)i);
            uint64_t first_ordinal =
                rocs_query_live_first_unobserved_ordinal(live,
                                                         boundary,
                                                         has_last,
                                                         last);
            if (first_ordinal >= boundary.record_count) {
                continue;
            }

            n00b_store_pos_t max_pos = rocs_query_entry_last_pos(boundary);
            observed_delta += boundary.record_count - first_ordinal;
            has_last = true;
            last     = max_pos;

            n00b_option_t(n00b_plan_shard_result_t *) result_opt =
                rocs_query_find_plan_result(results, boundary);
            if (!n00b_option_is_set(result_opt)) {
                continue;
            }

            auto ordinals_r =
                n00b_plan_shard_result_ordinals(n00b_option_get(result_opt));
            if (n00b_result_is_err(ordinals_r)) {
                return n00b_result_err(
                    uint64_t,
                    rocs_query_err_from_plan(
                        n00b_result_get_err(ordinals_r)));
            }

            n00b_plan_ordset_t *ordinals = n00b_result_get(ordinals_r);
            auto count_r = n00b_plan_ordset_count(ordinals);
            if (n00b_result_is_err(count_r)) {
                return n00b_result_err(
                    uint64_t,
                    rocs_query_err_from_plan(n00b_result_get_err(count_r)));
            }

            uint64_t count = n00b_result_get(count_r);
            for (uint64_t j = 0; j < count; j++) {
                auto ordinal_r = n00b_plan_ordset_at(ordinals, j);
                if (n00b_result_is_err(ordinal_r)) {
                    return n00b_result_err(
                        uint64_t,
                        rocs_query_err_from_plan(
                            n00b_result_get_err(ordinal_r)));
                }

                n00b_option_t(uint64_t) ordinal_opt =
                    n00b_result_get(ordinal_r);
                if (!n00b_option_is_set(ordinal_opt)) {
                    return n00b_result_err(uint64_t, N00B_QUERY_ERR_EXECUTION);
                }

                uint64_t ordinal = n00b_option_get(ordinal_opt);
                if (ordinal < first_ordinal
                    || ordinal >= boundary.record_count) {
                    continue;
                }

                n00b_store_pos_t pos = {
                    .generation = boundary.generation,
                    .shard_id   = boundary.shard_id,
                    .ordinal    = ordinal,
                };
                n00b_list_push(*new_positions, pos);
                matched_delta++;
            }
        }
    }

    if (tail_snapshot.has_hot_through) {
        auto hot_r = n00b_store_hot_tail_scan_after(
            view->store,
            predicate,
            has_last ? &last : nullptr,
            .allocator = view->allocator,
            .through   = &tail_snapshot.hot_through);
        if (n00b_result_is_err(hot_r)) {
            return n00b_result_err(
                uint64_t,
                rocs_query_err_from_store(n00b_result_get_err(hot_r)));
        }

        n00b_store_hot_tail_scan_t hot_scan = n00b_result_get(hot_r);
        if (hot_scan.matches != nullptr) {
            uint64_t hot_match_count =
                (uint64_t)n00b_list_len(*hot_scan.matches);
            for (uint64_t i = 0; i < hot_match_count; i++) {
                n00b_store_pos_t pos =
                    n00b_list_get(*hot_scan.matches, (size_t)i);
                n00b_list_push(*new_positions, pos);
            }
            matched_delta += hot_match_count;
        }
        if (hot_scan.has_last_observed) {
            observed_delta += hot_scan.scanned_records;
            has_last = true;
            last     = hot_scan.last_observed;
        }
    }

    uint64_t new_count = (uint64_t)n00b_list_len(*new_positions);
    for (uint64_t i = 0; i < new_count; i++) {
        n00b_store_pos_t pos = n00b_list_get(*new_positions, (size_t)i);
        n00b_list_push(*live->pending_positions, pos);
    }

    live->stats.scans++;
    live->stats.observed_positions += observed_delta;
    live->stats.matched_positions += matched_delta;
    live->stats.has_last_observed = has_last;
    live->stats.last_observed     = last;
    return n00b_result_ok(uint64_t, matched_delta);
}

static n00b_result_t(uint64_t)
rocs_query_live_tail_scan_once_internal(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_view_is_closed_raw(view)) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_CLOSED);
    }

    auto live_r = rocs_query_live_state_for_tail(view);
    if (n00b_result_is_err(live_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(live_r));
    }

    rocs_query_live_state_t *live = n00b_result_get(live_r);
    n00b_data_write_lock(live->lock);
    if (rocs_query_view_is_closed_raw(view)) {
        n00b_data_unlock(live->lock);
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_CLOSED);
    }

    auto scan_r = rocs_query_live_tail_scan_once_locked(view, live);
    uint64_t matched = n00b_result_is_ok(scan_r) ? n00b_result_get(scan_r) : 0;
    n00b_data_unlock(live->lock);
    if (matched != 0) {
        rocs_query_live_notify_waiters(view);
    }
    return scan_r;
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

    auto indexes_r = n00b_store_plan_indexes_for_query(
        cursor->view->store,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(indexes_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(indexes_r)));
    }

    auto plan_r = n00b_plan_store_sealed(cursor->view->store,
                                         n00b_result_get(lowered_r),
                                         n00b_result_get(indexes_r),
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
rocs_query_cursor_prepare_snapshot(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (cursor->snapshot_prepared) {
        return n00b_result_ok(bool, true);
    }

    auto lowered_r = n00b_filter_lower_to_plan(
        cursor->view->filter,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(lowered_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(lowered_r)));
    }

    auto indexes_r = n00b_store_plan_indexes_for_query(
        cursor->view->store,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(indexes_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_store(n00b_result_get_err(indexes_r)));
    }

    auto key_r = rocs_query_cache_key_build(
        cursor->view->filter,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }

    cursor->snapshot_predicate = n00b_result_get(lowered_r);
    cursor->snapshot_indexes   = n00b_result_get(indexes_r);
    cursor->snapshot_cache_key = n00b_result_get(key_r);
    cursor->snapshot_use_cache = cursor->snapshot_cache_key.cacheable
        && cursor->snapshot_cache_key.bytes != nullptr
        && cursor->view->cache != nullptr
        && !cursor->view->cache->disabled;

    if (cursor->snapshot_use_cache) {
        cursor->snapshot_cached_refs = rocs_query_ordset_ref_list_new(
            .allocator = cursor->allocator);

        uint64_t boundary_len =
            (uint64_t)n00b_list_len(*cursor->view->boundary);
        for (uint64_t i = 0; i < boundary_len; i++) {
            n00b_query_boundary_entry_t boundary =
                n00b_list_get(*cursor->view->boundary, (size_t)i);
            auto lookup_r = rocs_query_cache_lookup(
                cursor->view,
                cursor->snapshot_cache_key.bytes,
                boundary);
            if (n00b_result_is_err(lookup_r)) {
                return n00b_result_err(bool, n00b_result_get_err(lookup_r));
            }

            rocs_query_cache_lookup_t lookup = n00b_result_get(lookup_r);
            n00b_list_push(*cursor->snapshot_cached_refs,
                           lookup.found ? lookup.ordinals : nullptr);
        }
    }
    else if (cursor->view->cache != nullptr) {
        cursor->view->cache->stats.bypasses++;
    }

    cursor->snapshot_prepared = true;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_plan_ordset_t *)
rocs_query_cursor_plan_boundary(n00b_query_cursor_t        *cursor,
                                n00b_query_boundary_entry_t boundary)
{
    auto entry_r = rocs_query_current_catalog_entry(cursor->view,
                                                   boundary,
                                                   cursor->allocator);
    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               n00b_result_get_err(entry_r));
    }

    auto result_r = n00b_plan_catalog_entry_sealed(
        cursor->view->store,
        n00b_result_get(entry_r),
        cursor->snapshot_predicate,
        cursor->snapshot_indexes,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(result_r)) {
        return n00b_result_err(
            n00b_plan_ordset_t *,
            rocs_query_err_from_plan(n00b_result_get_err(result_r)));
    }

    auto ordinals_r = n00b_plan_shard_result_ordinals(n00b_result_get(result_r));
    if (n00b_result_is_err(ordinals_r)) {
        return n00b_result_err(
            n00b_plan_ordset_t *,
            rocs_query_err_from_plan(n00b_result_get_err(ordinals_r)));
    }

    return n00b_result_ok(n00b_plan_ordset_t *, n00b_result_get(ordinals_r));
}

// See n00b_query_cursor_t.stream_release. Releases every resident shard the
// cursor holds and clears already-delivered hits so only the next boundary's
// working set stays resident. Caller guarantees the consumer has drained +
// copied all prior hits (next_index >= len(hits)), so the borrowed record views
// in those hits are dead and the residents are safe to drop.
static n00b_err_t
rocs_query_cursor_stream_recycle(n00b_query_cursor_t *cursor)
{
    rocs_query_cursor_invalidate_current(cursor);
    n00b_err_t err  = N00B_QUERY_OK;
    uint64_t   rlen = (uint64_t)n00b_list_len(*cursor->residents);
    for (uint64_t i = 0; i < rlen; i++) {
        n00b_store_resident_shard_t *resident =
            n00b_list_get(*cursor->residents, (size_t)i);
        auto release_r = rocs_query_release_resident(resident);
        if (n00b_result_is_err(release_r) && err == N00B_QUERY_OK) {
            err = n00b_result_get_err(release_r);
        }
    }
    n00b_list_clear(*cursor->residents);
    n00b_list_clear(*cursor->hits);
    cursor->next_index = 0;
    return err;
}

static n00b_result_t(bool)
rocs_query_cursor_fill_next_snapshot_boundary(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (cursor->snapshot_exhausted) {
        return n00b_result_ok(bool, false);
    }

    // Streaming mode: before loading the next boundary, drop the prior
    // boundary's residents + delivered hits (the consumer has copied them out).
    // Bounds the resident working set to ~one boundary regardless of --limit.
    if (cursor->stream_release
        && cursor->next_index >= (uint64_t)n00b_list_len(*cursor->hits)) {
        n00b_err_t recycle_err = rocs_query_cursor_stream_recycle(cursor);
        if (recycle_err != N00B_QUERY_OK) {
            return n00b_result_err(bool, recycle_err);
        }
    }

    auto prepare_r = rocs_query_cursor_prepare_snapshot(cursor);
    if (n00b_result_is_err(prepare_r)) {
        return prepare_r;
    }

    uint64_t boundary_len = (uint64_t)n00b_list_len(*cursor->view->boundary);
    while (cursor->snapshot_boundary_index < boundary_len) {
        if (rocs_query_cursor_limit_reached(cursor)) {
            cursor->snapshot_exhausted = true;
            return n00b_result_ok(bool, false);
        }

        uint64_t boundary_index = cursor->snapshot_boundary_index;
        n00b_query_boundary_entry_t boundary =
            n00b_list_get(*cursor->view->boundary, (size_t)boundary_index);
        cursor->snapshot_boundary_index++;

        auto valid_r = rocs_query_validate_boundary_entry(cursor->view,
                                                          boundary,
                                                          cursor->allocator);
        if (n00b_result_is_err(valid_r)) {
            return n00b_result_err(bool, n00b_result_get_err(valid_r));
        }

        uint64_t before = (uint64_t)n00b_list_len(*cursor->hits);
        n00b_plan_ordset_t *ordinals = nullptr;
        if (cursor->snapshot_use_cache
            && cursor->snapshot_cached_refs != nullptr) {
            ordinals = n00b_list_get(*cursor->snapshot_cached_refs,
                                     (size_t)boundary_index);
        }

        if (ordinals == nullptr) {
            auto planned_r = rocs_query_cursor_plan_boundary(cursor, boundary);
            if (n00b_result_is_err(planned_r)) {
                return n00b_result_err(bool, n00b_result_get_err(planned_r));
            }

            if (cursor->snapshot_use_cache) {
                auto populate_r = rocs_query_cache_populate(
                    cursor->view,
                    cursor->snapshot_cache_key.bytes,
                    boundary,
                    n00b_result_get(planned_r));
                if (n00b_result_is_err(populate_r)) {
                    return n00b_result_err(bool,
                                           n00b_result_get_err(populate_r));
                }
                ordinals = n00b_result_get(populate_r);
            }
            else {
                ordinals = n00b_result_get(planned_r);
            }
        }

        auto add_r = rocs_query_cursor_add_boundary_ordset(cursor,
                                                          boundary,
                                                          ordinals);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(bool, n00b_result_get_err(add_r));
        }

        uint64_t after = (uint64_t)n00b_list_len(*cursor->hits);
        if (!n00b_result_get(add_r)) {
            cursor->snapshot_exhausted = true;
            return n00b_result_ok(bool, after > before);
        }
        if (after > before) {
            return n00b_result_ok(bool, true);
        }
    }

    cursor->snapshot_exhausted = true;
    return n00b_result_ok(bool, false);
}

static n00b_result_t(bool)
rocs_query_cursor_build_remaining_snapshot(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (cursor->view == nullptr
        || cursor->view->mode != N00B_QUERY_MODE_SNAPSHOT) {
        return n00b_result_ok(bool, true);
    }

    while (!cursor->snapshot_exhausted) {
        auto fill_r = rocs_query_cursor_fill_next_snapshot_boundary(cursor);
        if (n00b_result_is_err(fill_r)) {
            return fill_r;
        }
        if (!n00b_result_get(fill_r)) {
            break;
        }
    }

    return n00b_result_ok(bool, true);
}

static bool
rocs_query_cursor_limit_reached(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->view == nullptr
        || cursor->view->limit == 0 || cursor->hits == nullptr) {
        return false;
    }

    return (uint64_t)n00b_list_len(*cursor->hits) >= cursor->view->limit;
}

static n00b_result_t(n00b_store_catalog_entry_t *)
rocs_query_current_catalog_entry_pos(n00b_query_view_t  *view,
                                     n00b_store_pos_t    pos,
                                     n00b_allocator_t   *allocator)
{
    auto find_r = n00b_store_catalog_find_shard(view->store, pos.shard_id);
    if (n00b_result_is_err(find_r)) {
        return n00b_result_err(
            n00b_store_catalog_entry_t *,
            rocs_query_err_from_store(n00b_result_get_err(find_r)));
    }

    n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
        n00b_result_get(find_r);
    if (!n00b_option_is_set(entry_opt)) {
        auto check_r = n00b_store_resume_check(view->store, pos);
        if (n00b_result_is_err(check_r)) {
            return n00b_result_err(
                n00b_store_catalog_entry_t *,
                rocs_query_err_from_store(n00b_result_get_err(check_r)));
        }
        return n00b_result_err_payload(
            n00b_store_catalog_entry_t *,
            n00b_query_retention_error_t *,
            rocs_query_retention_payload(N00B_QUERY_BOUNDARY_SNAPSHOT,
                                         pos,
                                         n00b_result_get(check_r),
                                         .allocator = allocator));
    }

    n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
    auto gen_r     = n00b_store_catalog_entry_get_generation(entry);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    if (n00b_result_is_err(gen_r) || n00b_result_is_err(records_r)) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_QUERY_ERR_STATE);
    }
    if (n00b_result_get(gen_r) != pos.generation
        || pos.ordinal >= n00b_result_get(records_r)) {
        auto check_r = n00b_store_resume_check(view->store, pos);
        if (n00b_result_is_err(check_r)) {
            return n00b_result_err(
                n00b_store_catalog_entry_t *,
                rocs_query_err_from_store(n00b_result_get_err(check_r)));
        }
        return n00b_result_err_payload(
            n00b_store_catalog_entry_t *,
            n00b_query_retention_error_t *,
            rocs_query_retention_payload(N00B_QUERY_BOUNDARY_SNAPSHOT,
                                         pos,
                                         n00b_result_get(check_r),
                                         .allocator = allocator));
    }

    return n00b_result_ok(n00b_store_catalog_entry_t *, entry);
}

static n00b_result_t(n00b_query_hit_t *)
rocs_query_cursor_live_hit_from_sealed_pos(n00b_query_cursor_t *cursor,
                                           n00b_store_pos_t     pos)
{
    auto entry_r = rocs_query_current_catalog_entry_pos(cursor->view,
                                                       pos,
                                                       cursor->allocator);
    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(n00b_query_hit_t *,
                               n00b_result_get_error(entry_r));
    }

    n00b_store_resident_shard_t *resident = nullptr;
    auto resident_r = n00b_store_resident_shard_acquire(
        cursor->view->store,
        n00b_result_get(entry_r),
        .allocator = cursor->allocator);
    if (n00b_result_is_err(resident_r)) {
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_store(n00b_result_get_err(resident_r)));
    }
    resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_store(n00b_result_get_err(map_r)));
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    if (n00b_result_is_err(root_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_map(n00b_result_get_err(root_r)));
    }

    auto record_r = n00b_store_record_view_mapped_pos(
        n00b_result_get(root_r),
        pos,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(record_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_index(n00b_result_get_err(record_r)));
    }

    n00b_list_push(*cursor->residents, resident);
    return n00b_result_ok(
        n00b_query_hit_t *,
        rocs_query_hit_new(cursor,
                           pos,
                           n00b_result_get(record_r),
                           .allocator = cursor->allocator));
}

static n00b_result_t(n00b_query_hit_t *)
rocs_query_cursor_live_hit_from_pos(n00b_query_cursor_t *cursor,
                                    n00b_store_pos_t     pos)
{
    auto hot_r = n00b_store_hot_record_copy_for_pos(
        cursor->view->store,
        pos,
        .allocator = cursor->allocator);
    if (n00b_result_is_err(hot_r)) {
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_store(n00b_result_get_err(hot_r)));
    }

    n00b_option_t(n00b_store_record_t *) hot_opt = n00b_result_get(hot_r);
    if (n00b_option_is_set(hot_opt)) {
        return n00b_result_ok(
            n00b_query_hit_t *,
            rocs_query_hit_new(cursor,
                               pos,
                               n00b_option_get(hot_opt),
                               .allocator = cursor->allocator));
    }

    return rocs_query_cursor_live_hit_from_sealed_pos(cursor, pos);
}

static n00b_result_t(n00b_option_t(n00b_query_hit_t *))
rocs_query_owned_hit_from_hot_pos(n00b_query_view_t *view,
                                  n00b_store_pos_t   pos,
                                  n00b_allocator_t  *allocator)
{
    auto hot_r = n00b_store_hot_record_copy_for_pos(view->store,
                                                    pos,
                                                    .allocator = allocator);
    if (n00b_result_is_err(hot_r)) {
        return n00b_result_err(
            n00b_option_t(n00b_query_hit_t *),
            rocs_query_err_from_store(n00b_result_get_err(hot_r)));
    }

    n00b_option_t(n00b_store_record_t *) hot_opt = n00b_result_get(hot_r);
    if (!n00b_option_is_set(hot_opt)) {
        return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                              n00b_option_none(n00b_query_hit_t *));
    }

    n00b_query_hit_t *hit =
        rocs_query_owned_hit_new(pos,
                                 n00b_option_get(hot_opt),
                                 nullptr,
                                 .allocator = allocator);
    return n00b_result_ok(
        n00b_option_t(n00b_query_hit_t *),
        n00b_option_set(n00b_query_hit_t *, hit));
}

static n00b_result_t(n00b_query_hit_t *)
rocs_query_owned_hit_from_sealed_pos(n00b_query_view_t *view,
                                     n00b_store_pos_t   pos,
                                     n00b_allocator_t  *allocator)
{
    auto entry_r = rocs_query_current_catalog_entry_pos(view,
                                                       pos,
                                                       allocator);
    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(n00b_query_hit_t *,
                               n00b_result_get_error(entry_r));
    }

    n00b_store_resident_shard_t *resident = nullptr;
    auto resident_r = n00b_store_resident_shard_acquire(
        view->store,
        n00b_result_get(entry_r),
        .allocator = allocator);
    if (n00b_result_is_err(resident_r)) {
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_store(n00b_result_get_err(resident_r)));
    }
    resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_store(n00b_result_get_err(map_r)));
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    if (n00b_result_is_err(root_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_map(n00b_result_get_err(root_r)));
    }

    auto record_r = n00b_store_record_view_mapped_pos(
        n00b_result_get(root_r),
        pos,
        .allocator = allocator);
    if (n00b_result_is_err(record_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_query_hit_t *,
            rocs_query_err_from_index(n00b_result_get_err(record_r)));
    }

    return n00b_result_ok(
        n00b_query_hit_t *,
        rocs_query_owned_hit_new(pos,
                                 n00b_result_get(record_r),
                                 resident,
                                 .allocator = allocator));
}

static n00b_result_t(n00b_query_hit_t *)
rocs_query_owned_hit_from_pos(n00b_query_view_t *view,
                              n00b_store_pos_t   pos,
                              n00b_allocator_t  *allocator)
{
    auto hot_r = rocs_query_owned_hit_from_hot_pos(view, pos, allocator);
    if (n00b_result_is_err(hot_r)) {
        return n00b_result_err(n00b_query_hit_t *,
                               n00b_result_get_error(hot_r));
    }

    n00b_option_t(n00b_query_hit_t *) hot_opt = n00b_result_get(hot_r);
    if (n00b_option_is_set(hot_opt)) {
        return n00b_result_ok(n00b_query_hit_t *,
                              n00b_option_get(hot_opt));
    }

    return rocs_query_owned_hit_from_sealed_pos(view, pos, allocator);
}

static n00b_result_t(bool)
rocs_query_fields_equal(n00b_filter_field_t *left,
                        n00b_filter_field_t *right)
{
    if (left == nullptr || right == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (left == right) {
        return n00b_result_ok(bool, true);
    }

    auto left_any_r = n00b_filter_field_is_any(left);
    if (n00b_result_is_err(left_any_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(left_any_r)));
    }
    auto right_any_r = n00b_filter_field_is_any(right);
    if (n00b_result_is_err(right_any_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(right_any_r)));
    }

    bool left_any  = n00b_result_get(left_any_r);
    bool right_any = n00b_result_get(right_any_r);
    if (left_any || right_any) {
        return n00b_result_ok(bool, left_any && right_any);
    }

    auto left_name_r = rocs_query_named_field(left);
    if (n00b_result_is_err(left_name_r)) {
        return n00b_result_err(bool, n00b_result_get_err(left_name_r));
    }
    auto right_name_r = rocs_query_named_field(right);
    if (n00b_result_is_err(right_name_r)) {
        return n00b_result_err(bool, n00b_result_get_err(right_name_r));
    }

    return n00b_result_ok(
        bool,
        n00b_unicode_str_eq(n00b_result_get(left_name_r),
                            n00b_result_get(right_name_r)));
}

static n00b_result_t(double)
rocs_query_boost_for_field(n00b_query_t        *query,
                           n00b_filter_field_t *field)
{
    if (query == nullptr || field == nullptr) {
        return n00b_result_err(double, N00B_QUERY_ERR_ARG);
    }
    if (query->boosts == nullptr) {
        return n00b_result_ok(double, 1.0);
    }

    uint64_t len = (uint64_t)n00b_list_len(*query->boosts);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_boost_t *boost =
            n00b_list_get(*query->boosts, (size_t)i);
        if (boost == nullptr || boost->field == nullptr) {
            return n00b_result_err(double, N00B_QUERY_ERR_STATE);
        }
        auto equal_r = rocs_query_fields_equal(boost->field, field);
        if (n00b_result_is_err(equal_r)) {
            return n00b_result_err(double, n00b_result_get_err(equal_r));
        }
        if (n00b_result_get(equal_r)) {
            return n00b_result_ok(double, boost->boost);
        }
    }
    return n00b_result_ok(double, 1.0);
}

static n00b_result_t(bool)
rocs_query_rank_terms_contains(rocs_query_rank_term_list_t *terms,
                               n00b_filter_field_t         *field,
                               n00b_string_t               *text)
{
    if (terms == nullptr || field == nullptr || text == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*terms);
    for (uint64_t i = 0; i < len; i++) {
        rocs_query_rank_term_t *term =
            n00b_list_get(*terms, (size_t)i);
        if (term == nullptr || term->field == nullptr || term->text == nullptr) {
            return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
        }

        auto equal_r = rocs_query_fields_equal(term->field, field);
        if (n00b_result_is_err(equal_r)) {
            return n00b_result_err(bool, n00b_result_get_err(equal_r));
        }
        if (n00b_result_get(equal_r)
            && n00b_unicode_str_eq(term->text, text)) {
            return n00b_result_ok(bool, true);
        }
    }
    return n00b_result_ok(bool, false);
}

static n00b_result_t(bool)
rocs_query_rank_terms_add(rocs_query_rank_term_list_t *terms,
                          n00b_query_t               *query,
                          n00b_filter_field_t        *field,
                          n00b_string_t              *text,
                          n00b_allocator_t           *allocator)
{
    auto found_r = rocs_query_rank_terms_contains(terms, field, text);
    if (n00b_result_is_err(found_r)) {
        return found_r;
    }
    if (n00b_result_get(found_r)) {
        return n00b_result_ok(bool, true);
    }

    auto boost_r = rocs_query_boost_for_field(query, field);
    if (n00b_result_is_err(boost_r)) {
        return n00b_result_err(bool, n00b_result_get_err(boost_r));
    }

    rocs_query_rank_term_t *term = n00b_alloc_with_opts(
        rocs_query_rank_term_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    term->field              = field;
    term->text               = text;
    term->shards             = rocs_query_rank_shard_list_new(
        .allocator = allocator);
    term->boost              = n00b_result_get(boost_r);
    term->idf                = 0.0;
    term->record_count       = 0;
    term->document_frequency = 0;
    term->scoreable          = false;
    n00b_list_push(*terms, term);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_rank_terms_extract_predicate(rocs_query_rank_term_list_t *terms,
                                        n00b_query_t               *query,
                                        n00b_filter_t              *filter,
                                        n00b_allocator_t           *allocator)
{
    if (terms == nullptr || query == nullptr || filter == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto kind_r = n00b_filter_predicate_kind(filter);
    if (n00b_result_is_err(kind_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(kind_r)));
    }

    switch (n00b_result_get(kind_r)) {
    case N00B_FILTER_PREDICATE_AND:
    case N00B_FILTER_PREDICATE_OR: {
        auto count_r = n00b_filter_predicate_child_count(filter);
        if (n00b_result_is_err(count_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_filter(n00b_result_get_err(count_r)));
        }

        uint64_t count = n00b_result_get(count_r);
        for (uint64_t i = 0; i < count; i++) {
            auto child_r = n00b_filter_predicate_child_at(filter, i);
            if (n00b_result_is_err(child_r)) {
                return n00b_result_err(
                    bool,
                    rocs_query_err_from_filter(n00b_result_get_err(child_r)));
            }
            n00b_option_t(n00b_filter_t *) child_opt =
                n00b_result_get(child_r);
            if (!n00b_option_is_set(child_opt)) {
                return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
            }

            auto extract_r = rocs_query_rank_terms_extract_predicate(
                terms,
                query,
                n00b_option_get(child_opt),
                allocator);
            if (n00b_result_is_err(extract_r)) {
                return extract_r;
            }
        }
        return n00b_result_ok(bool, true);
    }
    case N00B_FILTER_PREDICATE_NOT:
        return n00b_result_ok(bool, true);
    case N00B_FILTER_PREDICATE_LEAF:
        break;
    }

    auto op_r = n00b_filter_predicate_leaf_op(filter);
    if (n00b_result_is_err(op_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(op_r)));
    }
    if (n00b_result_get(op_r) != N00B_FILTER_LEAF_CONTAINS) {
        return n00b_result_ok(bool, true);
    }

    auto field_r = n00b_filter_predicate_field(filter);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(field_r)));
    }
    auto text_r = n00b_filter_predicate_text(filter);
    if (n00b_result_is_err(text_r)) {
        return n00b_result_err(
            bool,
            rocs_query_err_from_filter(n00b_result_get_err(text_r)));
    }

    n00b_option_t(n00b_filter_field_t *) field_opt =
        n00b_result_get(field_r);
    n00b_option_t(n00b_string_t *) text_opt = n00b_result_get(text_r);
    if (!n00b_option_is_set(field_opt) || !n00b_option_is_set(text_opt)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    return rocs_query_rank_terms_add(terms,
                                     query,
                                     n00b_option_get(field_opt),
                                     n00b_option_get(text_opt),
                                     allocator);
}

static n00b_result_t(rocs_query_rank_term_list_t *)
rocs_query_rank_terms_extract(n00b_query_t     *query,
                              n00b_allocator_t *allocator)
{
    if (query == nullptr || query->filter == nullptr) {
        return n00b_result_err(rocs_query_rank_term_list_t *,
                               N00B_QUERY_ERR_ARG);
    }

    rocs_query_rank_term_list_t *terms =
        rocs_query_rank_term_list_new(.allocator = allocator);
    auto extract_r = rocs_query_rank_terms_extract_predicate(terms,
                                                            query,
                                                            query->filter,
                                                            allocator);
    if (n00b_result_is_err(extract_r)) {
        return n00b_result_err(rocs_query_rank_term_list_t *,
                               n00b_result_get_err(extract_r));
    }
    return n00b_result_ok(rocs_query_rank_term_list_t *, terms);
}

static n00b_result_t(n00b_option_t(n00b_store_index_t *))
rocs_query_rank_index_for_term(n00b_plan_index_list_t *indexes,
                               n00b_filter_field_t    *field)
{
    if (field == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_index_t *),
                               N00B_QUERY_ERR_ARG);
    }
    if (indexes == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_store_index_t *),
                              n00b_option_none(n00b_store_index_t *));
    }

    auto any_r = n00b_filter_field_is_any(field);
    if (n00b_result_is_err(any_r)) {
        return n00b_result_err(
            n00b_option_t(n00b_store_index_t *),
            rocs_query_err_from_filter(n00b_result_get_err(any_r)));
    }

    bool              any  = n00b_result_get(any_r);
    n00b_string_t    *name = nullptr;
    if (!any) {
        auto name_r = rocs_query_named_field(field);
        if (n00b_result_is_err(name_r)) {
            return n00b_result_err(n00b_option_t(n00b_store_index_t *),
                                   n00b_result_get_err(name_r));
        }
        name = n00b_result_get(name_r);
    }

    uint64_t len = (uint64_t)n00b_list_len(*indexes);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_index_t *index = n00b_list_get(*indexes, (size_t)i);
        if (index == nullptr) {
            return n00b_result_err(n00b_option_t(n00b_store_index_t *),
                                   N00B_QUERY_ERR_STATE);
        }
        if (any) {
            auto catch_all_r = n00b_store_index_is_catch_all(index);
            if (n00b_result_is_err(catch_all_r)) {
                return n00b_result_err(
                    n00b_option_t(n00b_store_index_t *),
                    rocs_query_err_from_index(
                        n00b_result_get_err(catch_all_r)));
            }
            if (n00b_result_get(catch_all_r)) {
                return n00b_result_ok(
                    n00b_option_t(n00b_store_index_t *),
                    n00b_option_set(n00b_store_index_t *, index));
            }
            continue;
        }

        n00b_store_advert_t advert =
            n00b_store_index_advertise(index,
                                       name,
                                       N00B_STORE_INDEX_OP_CONTAINS);
        if (advert.accelerates
            && advert.kind == N00B_STORE_INDEX_FULLTEXT) {
            return n00b_result_ok(
                n00b_option_t(n00b_store_index_t *),
                n00b_option_set(n00b_store_index_t *, index));
        }
    }

    return n00b_result_ok(n00b_option_t(n00b_store_index_t *),
                          n00b_option_none(n00b_store_index_t *));
}

static bool
rocs_query_rank_index_err_is_nonscoreable(n00b_err_t err)
{
    switch ((n00b_store_index_err_t)err) {
    case N00B_STORE_INDEX_ERR_ARG:
    case N00B_STORE_INDEX_ERR_KIND:
    case N00B_STORE_INDEX_ERR_UNREADY:
        return true;
    case N00B_STORE_INDEX_OK:
    case N00B_STORE_INDEX_ERR_STATE:
    case N00B_STORE_INDEX_ERR_INTERNAL:
        return false;
    }
    return false;
}

static n00b_result_t(n00b_store_map_shard_t *)
rocs_query_rank_boundary_root(n00b_query_view_t             *view,
                              n00b_query_boundary_entry_t    boundary,
                              n00b_store_resident_shard_t  **resident_out,
                              n00b_allocator_t             *allocator)
{
    if (view == nullptr || resident_out == nullptr) {
        return n00b_result_err(n00b_store_map_shard_t *,
                               N00B_QUERY_ERR_ARG);
    }
    *resident_out = nullptr;

    auto entry_r = rocs_query_current_catalog_entry(view,
                                                   boundary,
                                                   allocator);
    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(n00b_store_map_shard_t *,
                               n00b_result_get_error(entry_r));
    }

    auto resident_r = n00b_store_resident_shard_acquire(
        view->store,
        n00b_result_get(entry_r),
        .allocator = allocator);
    if (n00b_result_is_err(resident_r)) {
        return n00b_result_err(
            n00b_store_map_shard_t *,
            rocs_query_err_from_store(n00b_result_get_err(resident_r)));
    }
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_store_map_shard_t *,
            rocs_query_err_from_store(n00b_result_get_err(map_r)));
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    if (n00b_result_is_err(root_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(
            n00b_store_map_shard_t *,
            rocs_query_err_from_map(n00b_result_get_err(root_r)));
    }

    auto valid_r = rocs_query_validate_mapped_boundary(n00b_result_get(root_r),
                                                       boundary);
    if (n00b_result_is_err(valid_r)) {
        (void)rocs_query_release_resident(resident);
        return n00b_result_err(n00b_store_map_shard_t *,
                               n00b_result_get_err(valid_r));
    }

    *resident_out = resident;
    return n00b_result_ok(n00b_store_map_shard_t *,
                          n00b_result_get(root_r));
}

static n00b_result_t(n00b_plan_ordset_t *)
rocs_query_rank_ordset_from_postings(n00b_store_postings_t *postings,
                                     uint64_t               record_count,
                                     n00b_allocator_t      *allocator)
{
    auto set_r = n00b_plan_ordset_empty(record_count,
                                        .allocator = allocator);
    if (n00b_result_is_err(set_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               rocs_query_err_from_plan(
                                   n00b_result_get_err(set_r)));
    }
    n00b_plan_ordset_t *set = n00b_result_get(set_r);

    auto len_r = n00b_store_postings_len(postings);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_plan_ordset_t *,
                               rocs_query_err_from_index(
                                   n00b_result_get_err(len_r)));
    }

    uint64_t len = n00b_result_get(len_r);
    for (uint64_t i = 0; i < len; i++) {
        auto posting_r = n00b_store_postings_get(postings, i);
        if (n00b_result_is_err(posting_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   rocs_query_err_from_index(
                                       n00b_result_get_err(posting_r)));
        }

        n00b_option_t(n00b_store_posting_t) posting_opt =
            n00b_result_get(posting_r);
        if (!n00b_option_is_set(posting_opt)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_QUERY_ERR_EXECUTION);
        }

        n00b_store_posting_t posting = n00b_option_get(posting_opt);
        if (posting.pos.ordinal >= record_count) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   N00B_QUERY_ERR_EXECUTION);
        }

        auto insert_r = n00b_plan_ordset_insert(set, posting.pos.ordinal);
        if (n00b_result_is_err(insert_r)) {
            return n00b_result_err(n00b_plan_ordset_t *,
                                   rocs_query_err_from_plan(
                                       n00b_result_get_err(insert_r)));
        }
    }
    return n00b_result_ok(n00b_plan_ordset_t *, set);
}

static n00b_result_t(uint64_t)
rocs_query_rank_boundary_visible_count(n00b_query_view_t          *view,
                                       n00b_query_boundary_entry_t boundary)
{
    if (view == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    if (boundary.record_count == 0) {
        return n00b_result_ok(uint64_t, 0);
    }

    uint64_t first = 0;
    uint64_t last  = boundary.record_count - 1;
    if (view->has_resume
        && view->resume.generation == boundary.generation
        && view->resume.shard_id == boundary.shard_id) {
        if (view->resume.ordinal >= last) {
            return n00b_result_ok(uint64_t, 0);
        }
        first = view->resume.ordinal + 1;
    }
    if (view->has_as_of
        && view->as_of.generation == boundary.generation
        && view->as_of.shard_id == boundary.shard_id) {
        if (view->as_of.ordinal < first) {
            return n00b_result_ok(uint64_t, 0);
        }
        if (view->as_of.ordinal < last) {
            last = view->as_of.ordinal;
        }
    }
    if (last < first) {
        return n00b_result_ok(uint64_t, 0);
    }
    return n00b_result_ok(uint64_t, last - first + 1);
}

static n00b_result_t(uint64_t)
rocs_query_rank_ordset_visible_count(n00b_query_view_t          *view,
                                     n00b_query_boundary_entry_t boundary,
                                     n00b_plan_ordset_t         *ordinals)
{
    if (view == nullptr || ordinals == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    auto count_r = n00b_plan_ordset_count(ordinals);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(
            uint64_t,
            rocs_query_err_from_plan(n00b_result_get_err(count_r)));
    }

    uint64_t visible = 0;
    uint64_t count   = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto ordinal_r = n00b_plan_ordset_at(ordinals, i);
        if (n00b_result_is_err(ordinal_r)) {
            return n00b_result_err(
                uint64_t,
                rocs_query_err_from_plan(n00b_result_get_err(ordinal_r)));
        }
        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            return n00b_result_err(uint64_t, N00B_QUERY_ERR_EXECUTION);
        }

        n00b_store_pos_t pos = {
            .generation = boundary.generation,
            .shard_id   = boundary.shard_id,
            .ordinal    = n00b_option_get(ordinal_opt),
        };
        if (rocs_query_position_in_window(view, pos)) {
            visible++;
        }
    }

    return n00b_result_ok(uint64_t, visible);
}

static rocs_query_rank_shard_t *
rocs_query_rank_shard_new(n00b_query_boundary_entry_t boundary,
                          uint64_t                    record_count,
                          n00b_plan_ordset_t         *ordinals,
                          n00b_allocator_t           *allocator)
{
    rocs_query_rank_shard_t *shard = n00b_alloc_with_opts(
        rocs_query_rank_shard_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    shard->shard_id     = boundary.shard_id;
    shard->generation   = boundary.generation;
    shard->record_count = record_count;
    shard->ordinals     = ordinals;
    return shard;
}

static n00b_result_t(bool)
rocs_query_rank_term_prepare(rocs_query_rank_term_t *term,
                             n00b_query_view_t      *view,
                             n00b_plan_index_list_t *indexes,
                             n00b_allocator_t       *allocator)
{
    if (term == nullptr || view == nullptr || term->field == nullptr
        || term->text == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto index_r = rocs_query_rank_index_for_term(indexes, term->field);
    if (n00b_result_is_err(index_r)) {
        return n00b_result_err(bool, n00b_result_get_err(index_r));
    }

    n00b_option_t(n00b_store_index_t *) index_opt =
        n00b_result_get(index_r);
    if (!n00b_option_is_set(index_opt)) {
        return n00b_result_ok(bool, true);
    }

    n00b_store_index_t *index = n00b_option_get(index_opt);
    n00b_json_node_t   *value =
        n00b_json_string_new_from_n00b(term->text,
                                       .allocator = allocator);

    uint64_t boundary_len = (uint64_t)n00b_list_len(*view->boundary);
    for (uint64_t i = 0; i < boundary_len; i++) {
        n00b_query_boundary_entry_t boundary =
            n00b_list_get(*view->boundary, (size_t)i);
        n00b_store_resident_shard_t *resident = nullptr;
        auto root_r = rocs_query_rank_boundary_root(view,
                                                    boundary,
                                                    &resident,
                                                    allocator);
        if (n00b_result_is_err(root_r)) {
            return n00b_result_err(bool, n00b_result_get_error(root_r));
        }
        n00b_store_map_shard_t *root = n00b_result_get(root_r);

        auto stats_r = n00b_store_index_stats_mapped(index, root, value);
        if (n00b_result_is_err(stats_r)) {
            n00b_err_t stats_err = n00b_result_get_err(stats_r);
            (void)rocs_query_release_resident(resident);
            if (rocs_query_rank_index_err_is_nonscoreable(stats_err)) {
                term->scoreable = false;
                return n00b_result_ok(bool, true);
            }
            return n00b_result_err(bool,
                                   rocs_query_err_from_index(stats_err));
        }
        n00b_store_index_stats_t stats = n00b_result_get(stats_r);

        auto postings_r = n00b_store_index_lookup_mapped(index,
                                                         root,
                                                         value,
                                                         .allocator = allocator);
        if (n00b_result_is_err(postings_r)) {
            n00b_err_t postings_err = n00b_result_get_err(postings_r);
            (void)rocs_query_release_resident(resident);
            if (rocs_query_rank_index_err_is_nonscoreable(postings_err)) {
                term->scoreable = false;
                return n00b_result_ok(bool, true);
            }
            return n00b_result_err(bool,
                                   rocs_query_err_from_index(postings_err));
        }

        auto ordset_r = rocs_query_rank_ordset_from_postings(
            n00b_result_get(postings_r),
            stats.record_count,
            allocator);
        (void)rocs_query_release_resident(resident);
        if (n00b_result_is_err(ordset_r)) {
            return n00b_result_err(bool, n00b_result_get_err(ordset_r));
        }

        auto visible_records_r =
            rocs_query_rank_boundary_visible_count(view, boundary);
        auto visible_df_r =
            rocs_query_rank_ordset_visible_count(view,
                                                boundary,
                                                n00b_result_get(ordset_r));
        if (n00b_result_is_err(visible_records_r)) {
            return n00b_result_err(bool,
                                   n00b_result_get_err(visible_records_r));
        }
        if (n00b_result_is_err(visible_df_r)) {
            return n00b_result_err(bool,
                                   n00b_result_get_err(visible_df_r));
        }

        term->record_count += n00b_result_get(visible_records_r);
        term->document_frequency += n00b_result_get(visible_df_r);
        n00b_list_push(
            *term->shards,
            rocs_query_rank_shard_new(boundary,
                                      n00b_result_get(visible_records_r),
                                      n00b_result_get(ordset_r),
                                      allocator));
    }

    if (term->record_count != 0) {
        double n  = (double)term->record_count + 1.0;
        double df = (double)term->document_frequency + 1.0;
        term->idf = __builtin_log(n / df) + 1.0;
        term->scoreable = true;
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_rank_term_contains_pos(rocs_query_rank_term_t *term,
                                  n00b_store_pos_t       pos)
{
    if (term == nullptr || term->shards == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (!term->scoreable) {
        return n00b_result_ok(bool, false);
    }

    uint64_t len = (uint64_t)n00b_list_len(*term->shards);
    for (uint64_t i = 0; i < len; i++) {
        rocs_query_rank_shard_t *shard =
            n00b_list_get(*term->shards, (size_t)i);
        if (shard == nullptr || shard->ordinals == nullptr) {
            return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
        }
        if (shard->shard_id != pos.shard_id
            || shard->generation != pos.generation) {
            continue;
        }

        auto contains_r = n00b_plan_ordset_contains(shard->ordinals,
                                                    pos.ordinal);
        if (n00b_result_is_err(contains_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_plan(n00b_result_get_err(contains_r)));
        }
        return contains_r;
    }
    return n00b_result_ok(bool, false);
}

static n00b_result_t(bool)
rocs_query_rank_score_records(n00b_query_result_t          *result,
                              rocs_query_rank_term_list_t *terms)
{
    if (result == nullptr || result->records == nullptr || terms == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    uint64_t record_len = (uint64_t)n00b_list_len(*result->records);
    uint64_t term_len   = (uint64_t)n00b_list_len(*terms);
    for (uint64_t i = 0; i < record_len; i++) {
        n00b_query_hit_t *hit =
            n00b_list_get(*result->records, (size_t)i);
        if (hit == nullptr || !hit->valid) {
            return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
        }

        double score = 0.0;
        for (uint64_t j = 0; j < term_len; j++) {
            rocs_query_rank_term_t *term =
                n00b_list_get(*terms, (size_t)j);
            if (term == nullptr) {
                return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
            }
            auto contains_r = rocs_query_rank_term_contains_pos(term,
                                                               hit->pos);
            if (n00b_result_is_err(contains_r)) {
                return contains_r;
            }
            if (n00b_result_get(contains_r)) {
                score += term->idf * term->boost;
            }
        }
        hit->score = score;
    }
    return n00b_result_ok(bool, true);
}

static int
rocs_query_rank_hit_compare(const void *left, const void *right)
{
    n00b_query_hit_t * const *l = left;
    n00b_query_hit_t * const *r = right;
    int score_cmp = rocs_query_double_compare((*l)->score, (*r)->score);
    if (score_cmp != 0) {
        return -score_cmp;
    }
    return n00b_store_pos_compare((*l)->pos, (*r)->pos);
}

static int
rocs_query_rank_hit_worst_compare(const void *left, const void *right)
{
    int cmp = rocs_query_rank_hit_compare(left, right);
    if (cmp < 0) {
        return 1;
    }
    if (cmp > 0) {
        return -1;
    }
    return 0;
}

static n00b_result_t(bool)
rocs_query_rank_apply_ordering(n00b_query_result_t *result,
                               uint64_t             limit,
                               n00b_allocator_t    *allocator)
{
    if (result == nullptr || result->records == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_list_len(*result->records);
    if (limit == 0 || len <= limit) {
        if (len > 1) {
            n00b_list_sort(*result->records, rocs_query_rank_hit_compare);
        }
        return n00b_result_ok(bool, true);
    }

    rocs_query_rank_hit_heap_t top =
        n00b_heap_new(n00b_query_hit_t *,
                      rocs_query_rank_hit_worst_compare,
                      .start_capacity = (size_t)limit,
                      .allocator      = allocator,
                      .no_lock        = true);
    n00b_err_t err = N00B_QUERY_OK;

    for (uint64_t i = 0; i < len; i++) {
        n00b_query_hit_t *hit =
            n00b_list_get(*result->records, (size_t)i);
        if (hit == nullptr || !hit->valid) {
            return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
        }

        if ((uint64_t)n00b_heap_len(top) < limit) {
            n00b_heap_push(top, hit);
            continue;
        }

        n00b_query_hit_t *dropped = nullptr;
        (void)n00b_heap_pushpop(top, hit, &dropped);
        auto release_r = rocs_query_owned_hit_release(dropped);
        if (n00b_result_is_err(release_r) && err == N00B_QUERY_OK) {
            err = n00b_result_get_err(release_r);
        }
    }

    if (err != N00B_QUERY_OK) {
        return n00b_result_err(bool, err);
    }

    n00b_query_hit_list_t *retained =
        rocs_query_result_hit_list_new(.allocator = allocator);
    while (n00b_heap_len(top) != 0) {
        n00b_query_hit_t *hit = nullptr;
        if (!n00b_heap_pop(top, &hit)) {
            break;
        }
        if (hit != nullptr) {
            n00b_list_push(*retained, hit);
        }
    }

    result->records = retained;
    if (n00b_list_len(*result->records) > 1) {
        n00b_list_sort(*result->records, rocs_query_rank_hit_compare);
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_rank_records(n00b_query_view_t   *view,
                        n00b_query_t        *query,
                        n00b_query_result_t *result,
                        n00b_allocator_t    *allocator)
{
    if (view == nullptr || query == nullptr || result == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    auto terms_r = rocs_query_rank_terms_extract(query, allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(bool, n00b_result_get_err(terms_r));
    }
    rocs_query_rank_term_list_t *terms = n00b_result_get(terms_r);

    uint64_t term_len = (uint64_t)n00b_list_len(*terms);
    if (term_len != 0) {
        auto indexes_r = n00b_store_plan_indexes_for_query(
            view->store,
            .allocator = allocator);
        if (n00b_result_is_err(indexes_r)) {
            return n00b_result_err(
                bool,
                rocs_query_err_from_store(n00b_result_get_err(indexes_r)));
        }
        n00b_plan_index_list_t *indexes = n00b_result_get(indexes_r);

        for (uint64_t i = 0; i < term_len; i++) {
            rocs_query_rank_term_t *term =
                n00b_list_get(*terms, (size_t)i);
            auto prepare_r = rocs_query_rank_term_prepare(term,
                                                          view,
                                                          indexes,
                                                          allocator);
            if (n00b_result_is_err(prepare_r)) {
                return prepare_r;
            }
        }

        auto score_r = rocs_query_rank_score_records(result, terms);
        if (n00b_result_is_err(score_r)) {
            return score_r;
        }
    }

    return rocs_query_rank_apply_ordering(result,
                                          query->limit,
                                          allocator);
}

static bool
rocs_query_agg_op_valid(n00b_query_agg_op_t op)
{
    switch (op) {
    case N00B_QUERY_AGG_COUNT:
    case N00B_QUERY_AGG_SUM:
    case N00B_QUERY_AGG_MIN:
    case N00B_QUERY_AGG_MAX:
    case N00B_QUERY_AGG_AVG:
        return true;
    }

    return false;
}

n00b_result_t(n00b_query_agg_spec_t *)
n00b_query_agg(n00b_query_agg_op_t  op,
               n00b_filter_field_t *field) _kargs
{
    n00b_string_t    *name      = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_query_agg_op_valid(op)) {
        return n00b_result_err(n00b_query_agg_spec_t *,
                               N00B_QUERY_ERR_INVALID_OPTION);
    }
    if (op != N00B_QUERY_AGG_COUNT && field == nullptr) {
        return n00b_result_err(n00b_query_agg_spec_t *,
                               N00B_QUERY_ERR_ARG);
    }

    n00b_query_agg_spec_t *spec = n00b_alloc_with_opts(
        n00b_query_agg_spec_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    spec->op    = op;
    spec->field = field;
    spec->name  = name;
    return n00b_result_ok(n00b_query_agg_spec_t *, spec);
}

n00b_result_t(n00b_query_boost_t *)
n00b_query_boost(n00b_filter_field_t *field,
                 double               boost) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (field == nullptr) {
        return n00b_result_err(n00b_query_boost_t *, N00B_QUERY_ERR_ARG);
    }
    if (!(boost > 0.0) || __builtin_isnan(boost)
        || __builtin_isinf(boost)) {
        return n00b_result_err(n00b_query_boost_t *,
                               N00B_QUERY_ERR_INVALID_OPTION);
    }

    n00b_query_boost_t *spec = n00b_alloc_with_opts(
        n00b_query_boost_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    spec->field = field;
    spec->boost = boost;
    return n00b_result_ok(n00b_query_boost_t *, spec);
}

n00b_result_t(n00b_query_t *)
n00b_query_new(n00b_filter_t *filter) _kargs
{
    n00b_query_group_by_list_t  *group_by   = nullptr;
    n00b_query_agg_spec_list_t  *aggregates = nullptr;
    bool                         ranked     = false;
    n00b_query_boost_list_t     *boosts     = nullptr;
    n00b_store_pos_t            *as_of      = nullptr;
    uint64_t                     limit      = 100;
    n00b_allocator_t            *allocator  = nullptr;
}
{
    if (filter == nullptr) {
        return n00b_result_err(n00b_query_t *, N00B_QUERY_ERR_ARG);
    }

    auto group_copy_r =
        rocs_query_group_by_list_copy(group_by, .allocator = allocator);
    if (n00b_result_is_err(group_copy_r)) {
        return n00b_result_err(n00b_query_t *,
                               n00b_result_get_err(group_copy_r));
    }

    auto agg_copy_r =
        rocs_query_agg_spec_list_copy(aggregates, .allocator = allocator);
    if (n00b_result_is_err(agg_copy_r)) {
        return n00b_result_err(n00b_query_t *,
                               n00b_result_get_err(agg_copy_r));
    }

    auto boost_copy_r =
        rocs_query_boost_list_copy(boosts, .allocator = allocator);
    if (n00b_result_is_err(boost_copy_r)) {
        return n00b_result_err(n00b_query_t *,
                               n00b_result_get_err(boost_copy_r));
    }

    n00b_query_t *query = n00b_alloc_with_opts(
        n00b_query_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    query->filter     = filter;
    query->group_by   = n00b_result_get(group_copy_r);
    query->aggregates = n00b_result_get(agg_copy_r);
    query->boosts     = n00b_result_get(boost_copy_r);
    query->allocator  = allocator;
    query->ranked     = ranked;
    query->limit      = limit;
    query->has_as_of  = as_of != nullptr;
    if (as_of != nullptr) {
        query->as_of = *as_of;
    }

    return n00b_result_ok(n00b_query_t *, query);
}

static bool
rocs_query_wants_ranking(n00b_query_t *query)
{
    if (query == nullptr) {
        return false;
    }
    if (query->ranked) {
        return true;
    }
    if (query->boosts != nullptr && n00b_list_len(*query->boosts) != 0) {
        return true;
    }

    return false;
}

static bool
rocs_query_has_aggregation_features(n00b_query_t *query)
{
    if (query == nullptr) {
        return false;
    }
    if (query->group_by != nullptr && n00b_list_len(*query->group_by) != 0) {
        return true;
    }
    if (query->aggregates != nullptr
        && n00b_list_len(*query->aggregates) != 0) {
        return true;
    }
    return false;
}

static n00b_result_t(bool)
rocs_query_result_release_records(n00b_query_result_t *result)
{
    if (result == nullptr || result->records == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_err_t err = N00B_QUERY_OK;
    uint64_t   len = (uint64_t)n00b_list_len(*result->records);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_hit_t *hit =
            n00b_list_get(*result->records, (size_t)i);
        auto release_r = rocs_query_owned_hit_release(hit);
        if (n00b_result_is_err(release_r) && err == N00B_QUERY_OK) {
            err = n00b_result_get_err(release_r);
        }
    }

    if (err != N00B_QUERY_OK) {
        return n00b_result_err(bool, err);
    }
    return n00b_result_ok(bool, true);
}

static void
rocs_query_result_invalidate_rows(n00b_query_result_t *result)
{
    if (result == nullptr || result->rows == nullptr) {
        return;
    }

    uint64_t len = (uint64_t)n00b_list_len(*result->rows);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_agg_row_t *row =
            n00b_list_get(*result->rows, (size_t)i);
        if (row != nullptr) {
            if (row->keys != nullptr) {
                uint64_t key_len = (uint64_t)n00b_list_len(*row->keys);
                for (uint64_t j = 0; j < key_len; j++) {
                    n00b_query_group_key_t *key =
                        n00b_list_get(*row->keys, (size_t)j);
                    if (key != nullptr) {
                        key->valid = false;
                    }
                }
            }
            row->valid = false;
        }
    }
}

static void
rocs_query_result_invalidate_notes(n00b_query_result_t *result)
{
    if (result == nullptr || result->notes == nullptr) {
        return;
    }

    uint64_t len = (uint64_t)n00b_list_len(*result->notes);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_note_t *note =
            n00b_list_get(*result->notes, (size_t)i);
        if (note != nullptr) {
            note->valid = false;
        }
    }
}

static n00b_result_t(n00b_query_result_t *)
rocs_query_run_return_error(n00b_query_result_t *result,
                            n00b_query_cursor_t *cursor,
                            n00b_query_view_t   *view,
                            n00b_result_error_t  error)
{
    if (result != nullptr) {
        (void)n00b_query_result_close(result);
    }
    if (cursor != nullptr) {
        (void)n00b_query_cursor_close(cursor);
    }
    if (view != nullptr) {
        (void)n00b_query_view_close(view);
    }
    return n00b_result_err(n00b_query_result_t *, error);
}

static n00b_result_t(n00b_query_result_t *)
rocs_query_run_records(n00b_store_t      *store,
                       n00b_query_t      *query,
                       n00b_allocator_t  *allocator)
{
    if (store == nullptr || query == nullptr || query->filter == nullptr) {
        return n00b_result_err(n00b_query_result_t *, N00B_QUERY_ERR_ARG);
    }

    n00b_store_pos_t *as_of = query->has_as_of ? &query->as_of : nullptr;
    bool wants_ranking = rocs_query_wants_ranking(query);
    auto view_r = n00b_query_view(store,
                                  query->filter,
                                  .as_of = as_of,
                                  .limit = wants_ranking ? 0 : query->limit,
                                  .allocator = allocator);
    if (n00b_result_is_err(view_r)) {
        return n00b_result_err(n00b_query_result_t *,
                               n00b_result_get_error(view_r));
    }
    n00b_query_view_t *view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_cursor(view, .allocator = allocator);
    if (n00b_result_is_err(cursor_r)) {
        n00b_result_error_t error = n00b_result_get_error(cursor_r);
        (void)n00b_query_view_close(view);
        return n00b_result_err(n00b_query_result_t *, error);
    }
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    n00b_query_result_t *result =
        rocs_query_result_new(.allocator = allocator);
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(next_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(next_r));
        }

        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            break;
        }

        n00b_query_hit_t *cursor_hit = n00b_option_get(hit_opt);
        auto pos_r = n00b_query_hit_pos(cursor_hit);
        if (n00b_result_is_err(pos_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(pos_r));
        }

        auto owned_r = rocs_query_owned_hit_from_pos(
            view,
            n00b_result_get(pos_r),
            allocator);
        if (n00b_result_is_err(owned_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(owned_r));
        }
        n00b_list_push(*result->records, n00b_result_get(owned_r));
    }

    auto cursor_close_r = n00b_query_cursor_close(cursor);
    if (n00b_result_is_err(cursor_close_r)) {
        return rocs_query_run_return_error(
            result,
            nullptr,
            view,
            n00b_result_get_error(cursor_close_r));
    }

    if (wants_ranking) {
        auto rank_r = rocs_query_rank_records(view,
                                              query,
                                              result,
                                              allocator);
        if (n00b_result_is_err(rank_r)) {
            return rocs_query_run_return_error(
                result,
                nullptr,
                view,
                n00b_result_get_error(rank_r));
        }
    }

    auto view_close_r = n00b_query_view_close(view);
    if (n00b_result_is_err(view_close_r)) {
        return rocs_query_run_return_error(
            result,
            nullptr,
            nullptr,
            n00b_result_get_error(view_close_r));
    }

    return n00b_result_ok(n00b_query_result_t *, result);
}

static n00b_result_t(n00b_query_result_t *)
rocs_query_run_aggregate(n00b_store_t      *store,
                         n00b_query_t      *query,
                         n00b_allocator_t  *allocator)
{
    if (store == nullptr || query == nullptr || query->filter == nullptr) {
        return n00b_result_err(n00b_query_result_t *, N00B_QUERY_ERR_ARG);
    }

    n00b_store_pos_t *as_of = query->has_as_of ? &query->as_of : nullptr;
    auto view_r = n00b_query_view(store,
                                  query->filter,
                                  .as_of = as_of,
                                  .limit = 0,
                                  .allocator = allocator);
    if (n00b_result_is_err(view_r)) {
        return n00b_result_err(n00b_query_result_t *,
                               n00b_result_get_error(view_r));
    }
    n00b_query_view_t *view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_cursor(view, .allocator = allocator);
    if (n00b_result_is_err(cursor_r)) {
        n00b_result_error_t error = n00b_result_get_error(cursor_r);
        (void)n00b_query_view_close(view);
        return n00b_result_err(n00b_query_result_t *, error);
    }
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    n00b_query_result_t *result =
        rocs_query_result_new(.allocator = allocator);

    bool has_group_by = query->group_by != nullptr
        && n00b_list_len(*query->group_by) != 0;

    if (!has_group_by) {
        n00b_query_group_key_list_t *keys =
            rocs_query_group_key_list_new(.allocator = allocator);
        n00b_query_agg_row_t *row =
            rocs_query_row_new(keys, query->aggregates, allocator);
        n00b_list_push(*result->rows, row);
    }

    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(next_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(next_r));
        }

        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            break;
        }

        n00b_query_hit_t *hit = n00b_option_get(hit_opt);

        auto pos_r = n00b_query_hit_pos(hit);
        if (n00b_result_is_err(pos_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(pos_r));
        }
        n00b_store_pos_t pos = n00b_result_get(pos_r);

        auto record_r = n00b_query_hit_record(hit);
        if (n00b_result_is_err(record_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(record_r));
        }
        n00b_store_record_t *record = n00b_result_get(record_r);

        n00b_query_agg_row_t *row = nullptr;
        if (has_group_by) {
            auto keys_r =
                rocs_query_group_keys_for_record(query, record, allocator);
            if (n00b_result_is_err(keys_r)) {
                return rocs_query_run_return_error(
                    result,
                    cursor,
                    view,
                    n00b_result_get_error(keys_r));
            }
            row = rocs_query_get_or_create_row(result,
                                               query,
                                               n00b_result_get(keys_r),
                                               allocator);
        }
        else {
            row = n00b_list_get(*result->rows, 0);
        }

        auto apply_r =
            rocs_query_row_apply_record(result,
                                        row,
                                        record,
                                        pos,
                                        allocator);
        if (n00b_result_is_err(apply_r)) {
            return rocs_query_run_return_error(
                result,
                cursor,
                view,
                n00b_result_get_error(apply_r));
        }
    }

    auto finalize_r = rocs_query_finalize_rows(result, query);
    if (n00b_result_is_err(finalize_r)) {
        return rocs_query_run_return_error(
            result,
            cursor,
            view,
            n00b_result_get_error(finalize_r));
    }

    auto cursor_close_r = n00b_query_cursor_close(cursor);
    if (n00b_result_is_err(cursor_close_r)) {
        return rocs_query_run_return_error(
            result,
            nullptr,
            view,
            n00b_result_get_error(cursor_close_r));
    }

    auto view_close_r = n00b_query_view_close(view);
    if (n00b_result_is_err(view_close_r)) {
        return rocs_query_run_return_error(
            result,
            nullptr,
            nullptr,
            n00b_result_get_error(view_close_r));
    }

    return n00b_result_ok(n00b_query_result_t *, result);
}

n00b_result_t(n00b_query_result_t *)
n00b_query_run(n00b_store_t *store,
               n00b_query_t *query) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || query == nullptr || query->filter == nullptr) {
        return n00b_result_err(n00b_query_result_t *, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_has_aggregation_features(query)
        && rocs_query_wants_ranking(query)) {
        return n00b_result_err(n00b_query_result_t *,
                               N00B_QUERY_ERR_NOT_READY);
    }
    if (rocs_query_has_aggregation_features(query)) {
        return rocs_query_run_aggregate(store, query, allocator);
    }
    return rocs_query_run_records(store, query, allocator);
}

uint64_t
n00b_query_count(n00b_query_result_t *result)
{
    if (rocs_query_result_is_closed_raw(result)) {
        return 0;
    }
    if (result->rows != nullptr && n00b_list_len(*result->rows) != 0) {
        return (uint64_t)n00b_list_len(*result->rows);
    }
    if (result->records == nullptr) {
        return 0;
    }
    return (uint64_t)n00b_list_len(*result->records);
}

n00b_result_t(n00b_query_hit_list_t *)
n00b_query_records(n00b_query_result_t *result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (result == nullptr) {
        return n00b_result_err(n00b_query_hit_list_t *, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_result_is_closed_raw(result)) {
        return n00b_result_err(n00b_query_hit_list_t *,
                               N00B_QUERY_ERR_CLOSED);
    }

    n00b_query_hit_list_t *copy =
        rocs_query_result_hit_list_new(.allocator = allocator);
    uint64_t len = (uint64_t)n00b_list_len(*result->records);
    for (uint64_t i = 0; i < len; i++) {
        n00b_list_push(*copy, n00b_list_get(*result->records, (size_t)i));
    }
    return n00b_result_ok(n00b_query_hit_list_t *, copy);
}

n00b_result_t(n00b_query_agg_row_list_t *)
n00b_query_rows(n00b_query_result_t *result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (result == nullptr) {
        return n00b_result_err(n00b_query_agg_row_list_t *,
                               N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_result_is_closed_raw(result)) {
        return n00b_result_err(n00b_query_agg_row_list_t *,
                               N00B_QUERY_ERR_CLOSED);
    }

    n00b_query_agg_row_list_t *copy =
        rocs_query_agg_row_list_new(.allocator = allocator);
    uint64_t len = (uint64_t)n00b_list_len(*result->rows);
    for (uint64_t i = 0; i < len; i++) {
        n00b_list_push(*copy, n00b_list_get(*result->rows, (size_t)i));
    }
    return n00b_result_ok(n00b_query_agg_row_list_t *, copy);
}

n00b_result_t(n00b_query_note_list_t *)
n00b_query_result_notes(n00b_query_result_t *result) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (result == nullptr) {
        return n00b_result_err(n00b_query_note_list_t *, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_result_is_closed_raw(result)) {
        return n00b_result_err(n00b_query_note_list_t *,
                               N00B_QUERY_ERR_CLOSED);
    }

    n00b_query_note_list_t *copy =
        rocs_query_note_list_new(.allocator = allocator);
    uint64_t len = (uint64_t)n00b_list_len(*result->notes);
    for (uint64_t i = 0; i < len; i++) {
        n00b_list_push(*copy, n00b_list_get(*result->notes, (size_t)i));
    }
    return n00b_result_ok(n00b_query_note_list_t *, copy);
}

static n00b_result_t(bool)
rocs_query_row_check(n00b_query_agg_row_t *row)
{
    if (row == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (!row->valid) {
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_group_key_check(n00b_query_group_key_t *key)
{
    if (key == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (!key->valid) {
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_query_note_check(n00b_query_note_t *note)
{
    if (note == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (!note->valid) {
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_query_row_group_key_count(n00b_query_agg_row_t *row)
{
    auto valid_r = rocs_query_row_check(row);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(valid_r));
    }
    if (row->keys == nullptr) {
        return n00b_result_ok(uint64_t, 0);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*row->keys));
}

n00b_result_t(n00b_option_t(n00b_query_group_key_t *))
n00b_query_row_group_key_at(n00b_query_agg_row_t *row, uint64_t index)
{
    auto valid_r = rocs_query_row_check(row);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_option_t(n00b_query_group_key_t *),
                               n00b_result_get_err(valid_r));
    }
    uint64_t len = row->keys == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*row->keys);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_query_group_key_t *),
                              n00b_option_none(n00b_query_group_key_t *));
    }
    return n00b_result_ok(
        n00b_option_t(n00b_query_group_key_t *),
        n00b_option_set(n00b_query_group_key_t *,
                        n00b_list_get(*row->keys, (size_t)index)));
}

n00b_result_t(uint64_t)
n00b_query_row_value_count(n00b_query_agg_row_t *row)
{
    auto valid_r = rocs_query_row_check(row);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(valid_r));
    }
    if (row->values == nullptr) {
        return n00b_result_ok(uint64_t, 0);
    }
    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*row->values));
}

n00b_result_t(n00b_option_t(n00b_query_value_t))
n00b_query_row_value_at(n00b_query_agg_row_t *row, uint64_t index)
{
    auto valid_r = rocs_query_row_check(row);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_option_t(n00b_query_value_t),
                               n00b_result_get_err(valid_r));
    }
    uint64_t len = row->values == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*row->values);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_query_value_t),
                              n00b_option_none(n00b_query_value_t));
    }
    return n00b_result_ok(
        n00b_option_t(n00b_query_value_t),
        n00b_option_set(n00b_query_value_t,
                        n00b_list_get(*row->values, (size_t)index)));
}

n00b_result_t(n00b_filter_field_t *)
n00b_query_group_key_field(n00b_query_group_key_t *key)
{
    auto valid_r = rocs_query_group_key_check(key);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_filter_field_t *,
                               n00b_result_get_err(valid_r));
    }
    if (key->field == nullptr) {
        return n00b_result_err(n00b_filter_field_t *,
                               N00B_QUERY_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_filter_field_t *, key->field);
}

n00b_result_t(n00b_query_value_t)
n00b_query_group_key_value(n00b_query_group_key_t *key)
{
    auto valid_r = rocs_query_group_key_check(key);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_query_value_t,
                               n00b_result_get_err(valid_r));
    }
    return n00b_result_ok(n00b_query_value_t, key->value);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_note_pos(n00b_query_note_t *note)
{
    auto valid_r = rocs_query_note_check(note);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               n00b_result_get_err(valid_r));
    }
    n00b_option_t(n00b_store_pos_t) result =
        note->has_pos ? n00b_option_set(n00b_store_pos_t, note->pos)
                      : n00b_option_none(n00b_store_pos_t);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(n00b_option_t(n00b_query_agg_spec_t *))
n00b_query_note_aggregate(n00b_query_note_t *note)
{
    auto valid_r = rocs_query_note_check(note);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_option_t(n00b_query_agg_spec_t *),
                               n00b_result_get_err(valid_r));
    }
    n00b_option_t(n00b_query_agg_spec_t *) result =
        note->aggregate == nullptr
            ? n00b_option_none(n00b_query_agg_spec_t *)
            : n00b_option_set(n00b_query_agg_spec_t *, note->aggregate);
    return n00b_result_ok(n00b_option_t(n00b_query_agg_spec_t *), result);
}

n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_query_note_field(n00b_query_note_t *note)
{
    auto valid_r = rocs_query_note_check(note);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_option_t(n00b_filter_field_t *),
                               n00b_result_get_err(valid_r));
    }
    n00b_option_t(n00b_filter_field_t *) result =
        note->field == nullptr
            ? n00b_option_none(n00b_filter_field_t *)
            : n00b_option_set(n00b_filter_field_t *, note->field);
    return n00b_result_ok(n00b_option_t(n00b_filter_field_t *), result);
}

n00b_result_t(n00b_option_t(n00b_query_value_t))
n00b_query_note_value(n00b_query_note_t *note)
{
    auto valid_r = rocs_query_note_check(note);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_option_t(n00b_query_value_t),
                               n00b_result_get_err(valid_r));
    }
    n00b_option_t(n00b_query_value_t) result =
        note->has_value ? n00b_option_set(n00b_query_value_t, note->value)
                        : n00b_option_none(n00b_query_value_t);
    return n00b_result_ok(n00b_option_t(n00b_query_value_t), result);
}

n00b_result_t(n00b_string_t *)
n00b_query_note_message(n00b_query_note_t *note)
{
    auto valid_r = rocs_query_note_check(note);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_string_t *,
                               n00b_result_get_err(valid_r));
    }
    if (note->message == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_QUERY_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_string_t *, note->message);
}

n00b_result_t(bool)
n00b_query_result_close(n00b_query_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_result_is_closed_raw(result)) {
        return n00b_result_ok(bool, false);
    }

    n00b_atomic_store(&result->closed, true);
    auto release_r = rocs_query_result_release_records(result);
    rocs_query_result_invalidate_rows(result);
    rocs_query_result_invalidate_notes(result);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(bool, n00b_result_get_err(release_r));
    }
    return n00b_result_ok(bool, true);
}

static void
rocs_query_hit_msg_finalize(void *ptr)
{
    n00b_query_hit_msg_t *msg = ptr;
    if (msg == nullptr) {
        return;
    }

    if (msg->payload != nullptr) {
        (void)rocs_query_owned_hit_release(msg->payload);
        msg->payload = nullptr;
    }
}

static n00b_query_hit_msg_t *
rocs_query_hit_msg_new(n00b_query_hit_topic_t *topic,
                       n00b_query_hit_t       *hit,
                       n00b_allocator_t       *allocator)
{
    if (topic == nullptr || hit == nullptr) {
        return nullptr;
    }

    n00b_query_hit_msg_t *msg = n00b_alloc_with_opts(
        n00b_query_hit_msg_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    if (msg == nullptr) {
        return nullptr;
    }
    n00b_add_finalizer(msg, rocs_query_hit_msg_finalize, msg);

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = base;
    msg->header.generation = n00b_conduit_topic_generation(base);
    msg->header.epoch      = n00b_conduit_topic_epoch(base);
    msg->header.timestamp  = n00b_ns_timestamp();
    msg->header.next       = nullptr;
    msg->payload           = hit;
    return msg;
}

static void
rocs_query_output_record_delivery(rocs_query_output_state_t *output,
                                  uint64_t                   delivered,
                                  uint64_t                   dropped,
                                  uint64_t                   subscriber_count)
{
    if (output == nullptr || output->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(output->lock);
    output->stats.delivered_messages += delivered;
    output->stats.dropped_messages += dropped;
    output->stats.subscriber_count = subscriber_count;
    n00b_data_unlock(output->lock);
}

static n00b_result_t(uint64_t)
rocs_query_output_deliver_pos(n00b_query_view_t         *view,
                              rocs_query_output_state_t *output,
                              n00b_store_pos_t           pos)
{
    if (view == nullptr || output == nullptr || output->topic == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    n00b_conduit_topic_base_t *base =
        (n00b_conduit_topic_base_t *)output->topic;
    if (!n00b_conduit_topic_is_active(base)) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_CLOSED);
    }

    uint64_t delivered        = 0;
    uint64_t dropped          = 0;
    uint64_t subscriber_count = 0;
    auto    *subs             = &output->topic->subscriptions;

    _n00b_list_write_lock(subs);
    size_t write_i = 0;
    for (size_t read_i = 0; read_i < subs->len; read_i++) {
        n00b_conduit_subscription_t(n00b_query_hit_t *) *sub =
            subs->data[read_i];
        if (sub == nullptr) {
            continue;
        }

        int state = n00b_atomic_load(&sub->state);
        if (state == N00B_CONDUIT_SUB_REMOVED) {
            continue;
        }

        subs->data[write_i++] = sub;
        if (state != N00B_CONDUIT_SUB_ACTIVE) {
            continue;
        }
        subscriber_count++;
        auto hit_r = rocs_query_owned_hit_from_pos(view,
                                                   pos,
                                                   output->allocator);
        if (n00b_result_is_err(hit_r)) {
            subs->len = write_i;
            _n00b_list_unlock(subs);
            rocs_query_output_record_delivery(output,
                                              delivered,
                                              dropped,
                                              subscriber_count);
            return n00b_result_err(uint64_t, n00b_result_get_error(hit_r));
        }

        n00b_query_hit_t *hit = n00b_result_get(hit_r);
        n00b_query_hit_msg_t *msg =
            rocs_query_hit_msg_new(output->topic, hit, output->allocator);
        if (msg == nullptr) {
            (void)rocs_query_owned_hit_release(hit);
            subs->len = write_i;
            _n00b_list_unlock(subs);
            rocs_query_output_record_delivery(output,
                                              delivered,
                                              dropped,
                                              subscriber_count);
            return n00b_result_err(uint64_t, N00B_QUERY_ERR_INTERNAL);
        }

        if (n00b_conduit_sub_deliver(n00b_query_hit_t *, sub, msg)) {
            delivered++;
        }
        else {
            n00b_free(msg);
            dropped++;
        }

        if (n00b_atomic_load(&sub->state) == N00B_CONDUIT_SUB_REMOVED) {
            n00b_conduit_sub_cancel(sub->handle);
            continue;
        }
    }
    subs->len = write_i;
    _n00b_list_unlock(subs);

    rocs_query_output_record_delivery(output,
                                      delivered,
                                      dropped,
                                      subscriber_count);
    return n00b_result_ok(uint64_t, delivered);
}

static n00b_result_t(uint64_t)
rocs_query_cursor_append_pending_live_hits(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->view == nullptr
        || cursor->view->live == nullptr
        || cursor->view->live->pending_positions == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    rocs_query_live_state_t *live = cursor->view->live;
    rocs_query_pos_list_t *positions =
        rocs_query_pos_list_new(.allocator = cursor->allocator);
    if (positions == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_INTERNAL);
    }

    n00b_data_read_lock(live->lock);
    uint64_t pending_len =
        (uint64_t)n00b_list_len(*live->pending_positions);

    while (cursor->live_pending_index < pending_len) {
        n00b_store_pos_t pos =
            n00b_list_get(*live->pending_positions,
                          (size_t)cursor->live_pending_index);
        cursor->live_pending_index++;

        if (live->has_cutover_after
            && n00b_store_pos_compare(pos, live->cutover_after) <= 0) {
            continue;
        }
        if (cursor->has_position
            && n00b_store_pos_compare(pos, cursor->position) <= 0) {
            continue;
        }

        n00b_list_push(*positions, pos);
    }
    n00b_data_unlock(live->lock);

    uint64_t appended = 0;
    uint64_t count = (uint64_t)n00b_list_len(*positions);
    for (uint64_t i = 0; i < count; i++) {
        if (rocs_query_cursor_limit_reached(cursor)) {
            break;
        }
        if (rocs_query_cursor_or_view_closed(cursor)) {
            break;
        }

        n00b_store_pos_t pos = n00b_list_get(*positions, (size_t)i);

        auto hit_r = rocs_query_cursor_live_hit_from_pos(cursor, pos);
        if (n00b_result_is_err(hit_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_error(hit_r));
        }

        n00b_list_push(*cursor->hits, n00b_result_get(hit_r));
        appended++;
    }

    return n00b_result_ok(uint64_t, appended);
}

static n00b_result_t(n00b_option_t(n00b_query_hit_t *))
rocs_query_cursor_deliver_built_hit(n00b_query_cursor_t *cursor)
{
    rocs_query_cursor_invalidate_current(cursor);

    uint64_t len = (uint64_t)n00b_list_len(*cursor->hits);
    while (cursor->view != nullptr
           && cursor->view->mode == N00B_QUERY_MODE_SNAPSHOT
           && cursor->next_index >= len
           && !cursor->snapshot_exhausted) {
        auto fill_r = rocs_query_cursor_fill_next_snapshot_boundary(cursor);
        if (n00b_result_is_err(fill_r)) {
            return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                                   n00b_result_get_err(fill_r));
        }
        len = (uint64_t)n00b_list_len(*cursor->hits);
        if (!n00b_result_get(fill_r)) {
            break;
        }
    }

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

static void
rocs_query_cursor_wait_for_live_wakeup(n00b_query_cursor_t *cursor)
{
    rocs_query_live_state_t *live = cursor->view->live;
    n00b_store_commit_inbox_t *inbox = live->commit_inbox;

    rocs_query_cursor_set_live_waiting(cursor, true);
    if (inbox != nullptr) {
        n00b_condition_lock(&inbox->cv);
        if (!rocs_query_cursor_or_view_closed(cursor)
            && !n00b_store_commit_inbox_has_messages(inbox)
            && !n00b_conduit_inbox_has_sys(inbox)) {
            n00b_condition_wait(&inbox->cv, .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&inbox->cv);
        }
    }
    else {
        n00b_condition_lock(&live->wait_cv);
        if (!rocs_query_cursor_or_view_closed(cursor)) {
            n00b_condition_wait(&live->wait_cv,
                                .timeout_ms  = 100,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&live->wait_cv);
        }
    }
    rocs_query_cursor_set_live_waiting(cursor, false);
}

static n00b_result_t(n00b_option_t(n00b_query_hit_t *))
rocs_query_cursor_next_live(n00b_query_cursor_t *cursor)
{
    while (true) {
        if (rocs_query_cursor_or_view_closed(cursor)) {
            rocs_query_cursor_invalidate_current(cursor);
            return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                                  n00b_option_none(n00b_query_hit_t *));
        }

        uint64_t len = (uint64_t)n00b_list_len(*cursor->hits);
        if (cursor->next_index < len) {
            return rocs_query_cursor_deliver_built_hit(cursor);
        }
        if (rocs_query_cursor_limit_reached(cursor)) {
            rocs_query_cursor_invalidate_current(cursor);
            return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                                  n00b_option_none(n00b_query_hit_t *));
        }

        auto append_r = rocs_query_cursor_append_pending_live_hits(cursor);
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                                   n00b_result_get_error(append_r));
        }
        len = (uint64_t)n00b_list_len(*cursor->hits);
        if (cursor->next_index < len) {
            return rocs_query_cursor_deliver_built_hit(cursor);
        }
        if (rocs_query_cursor_limit_reached(cursor)) {
            rocs_query_cursor_invalidate_current(cursor);
            return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                                  n00b_option_none(n00b_query_hit_t *));
        }

        auto scan_r = rocs_query_live_tail_scan_once_internal(cursor->view);
        if (n00b_result_is_err(scan_r)) {
            if (rocs_query_cursor_or_view_closed(cursor)) {
                rocs_query_cursor_invalidate_current(cursor);
                return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                                      n00b_option_none(n00b_query_hit_t *));
            }
            return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                                   n00b_result_get_error(scan_r));
        }

        append_r = rocs_query_cursor_append_pending_live_hits(cursor);
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                                   n00b_result_get_error(append_r));
        }
        len = (uint64_t)n00b_list_len(*cursor->hits);
        if (cursor->next_index < len) {
            return rocs_query_cursor_deliver_built_hit(cursor);
        }
        if (rocs_query_cursor_limit_reached(cursor)) {
            rocs_query_cursor_invalidate_current(cursor);
            return n00b_result_ok(n00b_option_t(n00b_query_hit_t *),
                                  n00b_option_none(n00b_query_hit_t *));
        }

        rocs_query_cursor_wait_for_live_wakeup(cursor);
    }
}

static n00b_err_t
rocs_query_error_code_from_carrier(n00b_result_error_t error)
{
    if (error.kind == N00B_RESULT_ERROR_CODE) {
        return error.code;
    }
    if (error.payload_type == typehash(n00b_query_retention_error_t *)
        && error.payload != nullptr) {
        n00b_query_retention_error_t *payload = error.payload;
        return payload->code;
    }
    return N00B_QUERY_ERR_INTERNAL;
}

static void
rocs_query_output_record_error_carrier(rocs_query_output_state_t *output,
                                       n00b_result_error_t        error)
{
    if (output == nullptr || output->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(output->lock);
    output->stats.has_last_error = true;
    output->stats.last_error     = error;
    output->stats.last_error_code =
        rocs_query_error_code_from_carrier(error);
    n00b_data_unlock(output->lock);
}

static bool
rocs_query_output_should_stop(n00b_query_view_t         *view,
                              rocs_query_output_state_t *output)
{
    if (view == nullptr || output == nullptr || output->lock == nullptr) {
        return true;
    }
    if (rocs_query_view_is_closed_raw(view)) {
        return true;
    }

    n00b_data_read_lock(output->lock);
    bool stop = output->stats.stop_requested || output->stats.closed;
    n00b_data_unlock(output->lock);
    return stop;
}

static bool
rocs_query_output_limit_reached(rocs_query_output_state_t *output)
{
    if (output == nullptr || output->lock == nullptr) {
        return true;
    }

    n00b_data_read_lock(output->lock);
    bool reached = output->stats.limit != 0
                && output->stats.emitted_positions >= output->stats.limit;
    n00b_data_unlock(output->lock);
    return reached;
}

static void
rocs_query_output_record_position(rocs_query_output_state_t *output,
                                  n00b_store_pos_t           pos,
                                  bool                       historical)
{
    if (output == nullptr || output->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(output->lock);
    if (historical) {
        output->stats.historical_positions++;
    }
    else {
        output->stats.live_positions++;
    }
    output->stats.emitted_positions++;
    output->stats.has_last_position = true;
    output->stats.last_position     = pos;
    n00b_data_unlock(output->lock);
}

static n00b_result_t(uint64_t)
rocs_query_output_publish_history(n00b_query_view_t         *view,
                                  rocs_query_output_state_t *output)
{
    n00b_query_cursor_t *cursor =
        rocs_query_cursor_new(view, output->allocator);

    auto build_r = rocs_query_cursor_build_hits(cursor);
    if (n00b_result_is_err(build_r)) {
        (void)rocs_query_cursor_release_residents(cursor);
        return n00b_result_err(uint64_t, n00b_result_get_error(build_r));
    }

    uint64_t published = 0;
    uint64_t len = cursor->hits == nullptr
                 ? 0
                 : (uint64_t)n00b_list_len(*cursor->hits);
    for (uint64_t i = 0; i < len; i++) {
        if (rocs_query_output_should_stop(view, output)
            || rocs_query_output_limit_reached(output)) {
            break;
        }

        n00b_query_hit_t *hit = n00b_list_get(*cursor->hits, (size_t)i);
        if (hit == nullptr) {
            (void)rocs_query_cursor_release_residents(cursor);
            return n00b_result_err(uint64_t, N00B_QUERY_ERR_INTERNAL);
        }

        auto deliver_r = rocs_query_output_deliver_pos(view,
                                                       output,
                                                       hit->pos);
        if (n00b_result_is_err(deliver_r)) {
            (void)rocs_query_cursor_release_residents(cursor);
            return n00b_result_err(uint64_t,
                                   n00b_result_get_error(deliver_r));
        }

        rocs_query_output_record_position(output, hit->pos, true);
        published++;
    }

    auto release_r = rocs_query_cursor_release_residents(cursor);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(release_r));
    }

    return n00b_result_ok(uint64_t, published);
}

static n00b_result_t(uint64_t)
rocs_query_output_publish_pending(n00b_query_view_t         *view,
                                  rocs_query_output_state_t *output)
{
    if (view == nullptr || output == nullptr || view->live == nullptr
        || view->live->pending_positions == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    rocs_query_pos_list_t *positions =
        rocs_query_pos_list_new(.allocator = output->allocator);
    if (positions == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_INTERNAL);
    }

    rocs_query_live_state_t *live = view->live;
    n00b_data_read_lock(live->lock);
    uint64_t pending_len =
        (uint64_t)n00b_list_len(*live->pending_positions);
    while (output->live_pending_index < pending_len) {
        n00b_store_pos_t pos =
            n00b_list_get(*live->pending_positions,
                          (size_t)output->live_pending_index);
        output->live_pending_index++;

        if (live->has_cutover_after
            && n00b_store_pos_compare(pos, live->cutover_after) <= 0) {
            continue;
        }
        n00b_list_push(*positions, pos);
    }
    n00b_data_unlock(live->lock);

    uint64_t published = 0;
    uint64_t count = (uint64_t)n00b_list_len(*positions);
    for (uint64_t i = 0; i < count; i++) {
        if (rocs_query_output_should_stop(view, output)
            || rocs_query_output_limit_reached(output)) {
            break;
        }

        n00b_store_pos_t pos = n00b_list_get(*positions, (size_t)i);
        auto deliver_r = rocs_query_output_deliver_pos(view, output, pos);
        if (n00b_result_is_err(deliver_r)) {
            return n00b_result_err(uint64_t,
                                   n00b_result_get_error(deliver_r));
        }

        rocs_query_output_record_position(output, pos, false);
        published++;
    }

    return n00b_result_ok(uint64_t, published);
}

static void
rocs_query_output_wait(n00b_query_view_t         *view,
                       rocs_query_output_state_t *output)
{
    if (view == nullptr || output == nullptr || view->live == nullptr) {
        return;
    }

    rocs_query_live_state_t *live = view->live;
    n00b_store_commit_inbox_t *inbox = nullptr;
    n00b_data_read_lock(live->lock);
    inbox = live->commit_inbox;
    n00b_data_unlock(live->lock);

    if (inbox != nullptr) {
        n00b_condition_lock(&inbox->cv);
        if (!rocs_query_output_should_stop(view, output)
            && !n00b_store_commit_inbox_has_messages(inbox)
            && !n00b_conduit_inbox_has_sys(inbox)) {
            n00b_condition_wait(&inbox->cv,
                                .timeout_ms  = 100,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&inbox->cv);
        }
        return;
    }

    n00b_condition_lock(&live->wait_cv);
    if (!rocs_query_output_should_stop(view, output)) {
        n00b_condition_wait(&live->wait_cv,
                            .timeout_ms  = 100,
                            .auto_unlock = true);
    }
    else {
        n00b_condition_unlock(&live->wait_cv);
    }
}

static void
rocs_query_output_mark_closed(rocs_query_output_state_t *output)
{
    if (output == nullptr || output->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(output->lock);
    output->stats.closed     = true;
    output->stats.has_thread = false;
    n00b_data_unlock(output->lock);
}

static void *
rocs_query_output_loop(void *arg)
{
    n00b_query_view_t *view = arg;
    if (view == nullptr || view->output == nullptr) {
        return nullptr;
    }

    rocs_query_output_state_t *output = view->output;
    auto history_r = rocs_query_output_publish_history(view, output);
    if (n00b_result_is_err(history_r)
        && !rocs_query_view_is_closed_raw(view)) {
        rocs_query_output_record_error_carrier(
            output,
            n00b_result_get_error(history_r));
    }

    while (n00b_result_is_ok(history_r)
           && !rocs_query_output_should_stop(view, output)
           && !rocs_query_output_limit_reached(output)) {
        auto scan_r = rocs_query_live_tail_scan_once_internal(view);
        if (n00b_result_is_err(scan_r)) {
            if (!rocs_query_view_is_closed_raw(view)) {
                rocs_query_output_record_error_carrier(
                    output,
                    n00b_result_get_error(scan_r));
            }
            break;
        }

        auto pending_r = rocs_query_output_publish_pending(view, output);
        if (n00b_result_is_err(pending_r)) {
            if (!rocs_query_view_is_closed_raw(view)) {
                rocs_query_output_record_error_carrier(
                    output,
                    n00b_result_get_error(pending_r));
            }
            break;
        }

        if (rocs_query_output_limit_reached(output)) {
            break;
        }
        rocs_query_output_wait(view, output);
    }

    if (output->topic != nullptr) {
        n00b_conduit_topic_close((n00b_conduit_topic_base_t *)output->topic);
    }
    rocs_query_output_mark_closed(output);
    return nullptr;
}

static n00b_result_t(rocs_query_output_state_t *)
rocs_query_output_configure(n00b_conduit_t *conduit,
                            uint64_t        limit,
                            n00b_allocator_t *allocator)
{
    if (conduit == nullptr) {
        return n00b_result_err(rocs_query_output_state_t *,
                               N00B_QUERY_ERR_ARG);
    }

    rocs_query_output_state_t *output =
        rocs_query_output_state_new(conduit,
                                    limit,
                                    .allocator = allocator);
    if (output == nullptr) {
        return n00b_result_err(rocs_query_output_state_t *,
                               N00B_QUERY_ERR_INTERNAL);
    }

    uint64_t topic_id = n00b_atomic_add(&conduit->next_user_event_id, 1) + 1;
    n00b_query_hit_topic_t *topic =
        n00b_conduit_topic_init(n00b_query_hit_t *,
                                conduit,
                                N00B_CONDUIT_URI_USER_EVENT(topic_id));
    if (topic == nullptr) {
        return n00b_result_err(rocs_query_output_state_t *,
                               N00B_QUERY_ERR_INTERNAL);
    }

    output->topic = topic;
    (void)n00b_conduit_topic_set_name((n00b_conduit_topic_base_t *)topic,
                                      "rocs-query-output");
    return n00b_result_ok(rocs_query_output_state_t *, output);
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
    if (mode == N00B_QUERY_MODE_LIVE && as_of != nullptr) {
        return n00b_result_err(n00b_query_view_t *,
                               N00B_QUERY_ERR_INVALID_OPTION);
    }
    if (out != nullptr && mode != N00B_QUERY_MODE_LIVE) {
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
    n00b_atomic_store(&view->closed, false);
    view->boundary  = rocs_query_boundary_list_new(.allocator = allocator);
    view->cursors   = rocs_query_cursor_list_new(.allocator = allocator);
    view->cache     = rocs_query_cache_new(.allocator = allocator);
    view->live      = nullptr;
    view->output    = nullptr;

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

    auto live_r = rocs_query_capture_live_state(view);
    if (n00b_result_is_err(live_r)) {
        rocs_query_release_pin_for_failure(pin);
        return n00b_result_err(n00b_query_view_t *,
                               n00b_result_get_err(live_r));
    }

    auto sub_r = rocs_query_live_subscribe(view);
    if (n00b_result_is_err(sub_r)) {
        (void)rocs_query_live_cancel_subscription(view->live);
        rocs_query_release_pin_for_failure(pin);
        return n00b_result_err(n00b_query_view_t *,
                               n00b_result_get_err(sub_r));
    }

    if (out != nullptr) {
        auto output_r = rocs_query_output_configure(out,
                                                    limit,
                                                    allocator);
        if (n00b_result_is_err(output_r)) {
            (void)rocs_query_live_cancel_subscription(view->live);
            rocs_query_release_pin_for_failure(pin);
            return n00b_result_err(n00b_query_view_t *,
                                   n00b_result_get_err(output_r));
        }
        view->output = n00b_result_get(output_r);
    }

    return n00b_result_ok(n00b_query_view_t *, view);
}

n00b_result_t(bool)
n00b_query_view_close(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_view_is_closed_raw(view)) {
        return n00b_result_ok(bool, false);
    }

    n00b_atomic_store(&view->closed, true);
    rocs_query_live_notify_waiters(view);
    n00b_err_t err = N00B_QUERY_OK;

    auto output_close_r = rocs_query_output_close(view->output);
    if (n00b_result_is_err(output_close_r) && err == N00B_QUERY_OK) {
        err = n00b_result_get_err(output_close_r);
    }

    if (view->cursors != nullptr) {
        uint64_t len = (uint64_t)n00b_list_len(*view->cursors);
        for (uint64_t i = 0; i < len; i++) {
            n00b_query_cursor_t *cursor =
                n00b_list_get(*view->cursors, (size_t)i);
            if (cursor == nullptr) {
                continue;
            }
            auto close_r = rocs_query_cursor_close_internal(cursor);
            if (n00b_result_is_err(close_r) && err == N00B_QUERY_OK) {
                err = n00b_result_get_err(close_r);
            }
        }
    }

    auto cancel_r = rocs_query_live_cancel_subscription(view->live);
    if (n00b_result_is_err(cancel_r) && err == N00B_QUERY_OK) {
        err = n00b_result_get_err(cancel_r);
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

n00b_result_t(n00b_query_hit_inbox_t *)
n00b_query_hit_inbox_new(n00b_conduit_t *conduit) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_DROP_NEWEST;
    uint32_t                    limit        = 1024;
    n00b_allocator_t           *allocator    = nullptr;
}
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_query_hit_inbox_t *,
                               N00B_QUERY_ERR_ARG);
    }
    if (allocator == nullptr) {
        allocator = conduit->allocator;
    }

    n00b_query_hit_inbox_t *inbox = n00b_alloc_with_opts(
        n00b_query_hit_inbox_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    if (inbox == nullptr) {
        return n00b_result_err(n00b_query_hit_inbox_t *,
                               N00B_QUERY_ERR_INTERNAL);
    }

    n00b_conduit_inbox_init(n00b_query_hit_t *,
                            inbox,
                            conduit,
                            backpressure,
                            limit);
    return n00b_result_ok(n00b_query_hit_inbox_t *, inbox);
}

n00b_result_t(n00b_query_hit_topic_t *)
n00b_query_view_output_topic(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_query_hit_topic_t *,
                               N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_view_is_closed_raw(view)) {
        return n00b_result_err(n00b_query_hit_topic_t *,
                               N00B_QUERY_ERR_CLOSED);
    }
    if (view->output == nullptr || view->output->topic == nullptr) {
        return n00b_result_err(n00b_query_hit_topic_t *,
                               N00B_QUERY_ERR_STATE);
    }

    return n00b_result_ok(n00b_query_hit_topic_t *, view->output->topic);
}

static bool
rocs_query_hit_topic_ready(n00b_query_hit_topic_t *topic)
{
    if (topic == nullptr) {
        return false;
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    return base->conduit != nullptr
        && n00b_conduit_topic_is_active(base)
        && topic->subscriptions.data != nullptr;
}

n00b_result_t(n00b_conduit_sub_handle_t)
n00b_query_hit_subscribe(n00b_query_hit_topic_t *topic,
                         n00b_query_hit_inbox_t *inbox) _kargs
{
    uint32_t operations = N00B_CONDUIT_OP_ALL;
    uint32_t flags      = 0;
    uint32_t timeout_ms = 0;
}
{
    if (topic == nullptr || inbox == nullptr) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_QUERY_ERR_ARG);
    }
    if (!rocs_query_hit_topic_ready(topic)) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_QUERY_ERR_CLOSED);
    }

    n00b_conduit_sub_handle_t handle =
        n00b_conduit_subscribe(n00b_query_hit_t *,
                               topic,
                               inbox,
                               .operations = operations,
                               .flags      = flags,
                               .timeout_ms = timeout_ms);
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_QUERY_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_conduit_sub_handle_t, handle);
}

n00b_result_t(bool)
n00b_query_hit_unsubscribe(n00b_query_hit_topic_t   *topic,
                           n00b_conduit_sub_handle_t sub)
{
    if (sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_ok(bool, false);
    }
    if (topic == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    _n00b_list_write_lock(&topic->subscriptions);
    n00b_conduit_sub_cancel(sub);
    _n00b_list_unlock(&topic->subscriptions);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_query_view_output_start(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_view_is_closed_raw(view)) {
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE || view->output == nullptr
        || view->output->topic == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    rocs_query_output_state_t *output = view->output;
    n00b_data_write_lock(output->lock);
    if (output->stats.stop_requested || output->stats.closed) {
        n00b_data_unlock(output->lock);
        return n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    if (output->stats.started) {
        n00b_data_unlock(output->lock);
        return n00b_result_ok(bool, false);
    }

    auto thread_r = n00b_thread_spawn(rocs_query_output_loop, view);
    if (n00b_result_is_err(thread_r)) {
        n00b_data_unlock(output->lock);
        return n00b_result_err(bool, N00B_QUERY_ERR_INTERNAL);
    }

    output->thread           = n00b_result_get(thread_r);
    output->stats.started    = true;
    output->stats.has_thread = true;
    n00b_data_unlock(output->lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_query_hit_msg_drop(n00b_query_hit_msg_t *msg)
{
    if (msg == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }

    n00b_free(msg);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_query_hit_inbox_drain(n00b_query_hit_inbox_t *inbox)
{
    if (inbox == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }

    uint64_t dropped = 0;
    while (true) {
        n00b_query_hit_msg_t *msg = n00b_query_hit_inbox_pop(inbox);
        if (msg == nullptr) {
            break;
        }
        n00b_free(msg);
        dropped++;
    }

    while (true) {
        n00b_conduit_sys_msg_t *sys = n00b_conduit_inbox_pop_sys(inbox);
        if (sys == nullptr) {
            break;
        }
        n00b_free(sys);
    }

    return n00b_result_ok(uint64_t, dropped);
}

static n00b_result_t(bool)
rocs_query_output_close(rocs_query_output_state_t *output)
{
    if (output == nullptr || output->lock == nullptr) {
        return n00b_result_ok(bool, false);
    }

    n00b_data_write_lock(output->lock);
    bool already = output->stats.stop_requested && output->stats.joined;
    output->stats.stop_requested = true;
    n00b_thread_t *thread = output->thread;
    bool joined = output->stats.joined;
    n00b_query_hit_topic_t *topic = output->topic;
    n00b_data_unlock(output->lock);

    if (topic != nullptr) {
        n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);
    }
    if (thread != nullptr && !joined) {
        n00b_thread_join(thread);
    }

    n00b_data_write_lock(output->lock);
    output->stats.closed     = true;
    output->stats.joined     = true;
    output->stats.has_thread = false;
    n00b_data_unlock(output->lock);
    return n00b_result_ok(bool, !already);
}

static n00b_query_cursor_t *
rocs_query_cursor_new(n00b_query_view_t *view,
                      n00b_allocator_t  *allocator)
{
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
    cursor->live_pending_index = 0;
    cursor->active_next = 0;
    n00b_condition_init(&cursor->state_cv);
    n00b_atomic_store(&cursor->live_waiting, false);
    n00b_atomic_store(&cursor->closed, false);
    n00b_atomic_store(&cursor->close_complete, false);
    cursor->has_position = false;
    cursor->stream_release = false;
    return cursor;
}

void
n00b_query_cursor_set_streaming(n00b_query_cursor_t *cursor, bool on)
{
    if (cursor != nullptr) {
        cursor->stream_release = on;
    }
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
    if (rocs_query_view_is_closed_raw(view)) {
        return n00b_result_err(n00b_query_cursor_t *, N00B_QUERY_ERR_CLOSED);
    }
    if (view->mode != N00B_QUERY_MODE_SNAPSHOT
        && view->mode != N00B_QUERY_MODE_LIVE) {
        return n00b_result_err(n00b_query_cursor_t *,
                               N00B_QUERY_ERR_UNSUPPORTED_MODE);
    }

    n00b_query_cursor_t *cursor = rocs_query_cursor_new(view, allocator);

    if (view->mode == N00B_QUERY_MODE_LIVE) {
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
    }
    else {
        auto valid_r = rocs_query_validate_snapshot_boundary(
            view,
            .allocator = allocator);
        if (n00b_result_is_err(valid_r)) {
            auto close_r = rocs_query_cursor_close_internal(cursor);
            if (n00b_result_is_err(close_r)) {
                return n00b_result_err(n00b_query_cursor_t *,
                                       n00b_result_get_err(close_r));
            }
            return n00b_result_err(n00b_query_cursor_t *,
                                   n00b_result_get_error(valid_r));
        }
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

    auto begin_r = rocs_query_cursor_begin_next(cursor);
    if (n00b_result_is_err(begin_r)) {
        return n00b_result_err(n00b_option_t(n00b_query_hit_t *),
                               n00b_result_get_err(begin_r));
    }

    bool live = cursor->view != nullptr
             && cursor->view->mode == N00B_QUERY_MODE_LIVE;
    n00b_result_t(n00b_option_t(n00b_query_hit_t *)) result;
    if (cursor->view->mode == N00B_QUERY_MODE_LIVE) {
        result = rocs_query_cursor_next_live(cursor);
    }
    else {
        result = rocs_query_cursor_deliver_built_hit(cursor);
    }

    return rocs_query_cursor_finish_next(cursor, live, result);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_cursor_position(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_cursor_or_view_closed(cursor)) {
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
    if (hit->owned) {
        return hit->valid
             ? n00b_result_ok(bool, true)
             : n00b_result_err(bool, N00B_QUERY_ERR_CLOSED);
    }
    if (!hit->valid || hit->cursor == nullptr
        || rocs_query_cursor_or_view_closed(hit->cursor)) {
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

n00b_result_t(n00b_json_node_t *)
n00b_query_hit_json_copy(n00b_query_hit_t *hit) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    ensures {
        true;
    }
{
    auto record_r = n00b_query_hit_record(hit);
    if (n00b_result_is_err(record_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(record_r));
    }
    auto json_r =
        n00b_store_record_view_json_copy(n00b_result_get(record_r),
                                         .allocator = allocator);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(json_r));
    }
    return json_r;
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

n00b_result_t(bool)
n00b_query_spec_ranked(n00b_query_t *query)
{
    if (query == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(bool, query->ranked);
}

n00b_result_t(uint64_t)
n00b_query_spec_limit(n00b_query_t *query)
{
    if (query == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, query->limit);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_spec_as_of(n00b_query_t *query)
{
    if (query == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    n00b_option_t(n00b_store_pos_t) result =
        query->has_as_of
            ? n00b_option_set(n00b_store_pos_t, query->as_of)
            : n00b_option_none(n00b_store_pos_t);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(uint64_t)
n00b_query_spec_group_by_count(n00b_query_t *query)
{
    if (query == nullptr || query->group_by == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*query->group_by));
}

n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_query_spec_group_by_at(n00b_query_t *query, uint64_t index)
{
    if (query == nullptr || query->group_by == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_field_t *),
                               N00B_QUERY_ERR_ARG);
    }
    uint64_t len = (uint64_t)n00b_list_len(*query->group_by);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_filter_field_t *),
                              n00b_option_none(n00b_filter_field_t *));
    }
    return n00b_result_ok(
        n00b_option_t(n00b_filter_field_t *),
        n00b_option_set(n00b_filter_field_t *,
                        n00b_list_get(*query->group_by, (size_t)index)));
}

n00b_result_t(uint64_t)
n00b_query_spec_aggregate_count(n00b_query_t *query)
{
    if (query == nullptr || query->aggregates == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*query->aggregates));
}

n00b_result_t(n00b_option_t(n00b_query_agg_spec_t *))
n00b_query_spec_aggregate_at(n00b_query_t *query, uint64_t index)
{
    if (query == nullptr || query->aggregates == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_query_agg_spec_t *),
                               N00B_QUERY_ERR_ARG);
    }
    uint64_t len = (uint64_t)n00b_list_len(*query->aggregates);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_query_agg_spec_t *),
                              n00b_option_none(n00b_query_agg_spec_t *));
    }
    return n00b_result_ok(
        n00b_option_t(n00b_query_agg_spec_t *),
        n00b_option_set(n00b_query_agg_spec_t *,
                        n00b_list_get(*query->aggregates, (size_t)index)));
}

n00b_result_t(uint64_t)
n00b_query_spec_boost_count(n00b_query_t *query)
{
    if (query == nullptr || query->boosts == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(uint64_t,
                          (uint64_t)n00b_list_len(*query->boosts));
}

n00b_result_t(n00b_option_t(n00b_query_boost_t *))
n00b_query_spec_boost_at(n00b_query_t *query, uint64_t index)
{
    if (query == nullptr || query->boosts == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_query_boost_t *),
                               N00B_QUERY_ERR_ARG);
    }
    uint64_t len = (uint64_t)n00b_list_len(*query->boosts);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_query_boost_t *),
                              n00b_option_none(n00b_query_boost_t *));
    }
    return n00b_result_ok(
        n00b_option_t(n00b_query_boost_t *),
        n00b_option_set(n00b_query_boost_t *,
                        n00b_list_get(*query->boosts, (size_t)index)));
}

n00b_result_t(n00b_query_agg_op_t)
n00b_query_agg_spec_op(n00b_query_agg_spec_t *spec)
{
    if (spec == nullptr) {
        return n00b_result_err(n00b_query_agg_op_t, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(n00b_query_agg_op_t, spec->op);
}

n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_query_agg_spec_field(n00b_query_agg_spec_t *spec)
{
    if (spec == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_filter_field_t *),
                               N00B_QUERY_ERR_ARG);
    }
    n00b_option_t(n00b_filter_field_t *) result =
        spec->field == nullptr
            ? n00b_option_none(n00b_filter_field_t *)
            : n00b_option_set(n00b_filter_field_t *, spec->field);
    return n00b_result_ok(n00b_option_t(n00b_filter_field_t *), result);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_query_agg_spec_name(n00b_query_agg_spec_t *spec)
{
    if (spec == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_QUERY_ERR_ARG);
    }
    n00b_option_t(n00b_string_t *) result =
        spec->name == nullptr
            ? n00b_option_none(n00b_string_t *)
            : n00b_option_set(n00b_string_t *, spec->name);
    return n00b_result_ok(n00b_option_t(n00b_string_t *), result);
}

n00b_result_t(n00b_filter_field_t *)
n00b_query_boost_spec_field(n00b_query_boost_t *spec)
{
    if (spec == nullptr || spec->field == nullptr) {
        return n00b_result_err(n00b_filter_field_t *, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(n00b_filter_field_t *, spec->field);
}

n00b_result_t(double)
n00b_query_boost_spec_value(n00b_query_boost_t *spec)
{
    if (spec == nullptr) {
        return n00b_result_err(double, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(double, spec->boost);
}

n00b_result_t(bool)
n00b_query_result_is_closed(n00b_query_result_t *result)
{
    if (result == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(bool, rocs_query_result_is_closed_raw(result));
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
n00b_query_view_live_start_after(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE || view->live == nullptr
        || !view->live->has_start_after) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                          n00b_option_set(n00b_store_pos_t,
                                          view->live->start_after));
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_live_historical_upper_bound(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE || view->live == nullptr
        || !view->live->has_historical_upper_bound) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                          n00b_option_set(
                              n00b_store_pos_t,
                              view->live->historical_upper_bound));
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_live_cutover_after(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_ARG);
    }
    if (view->mode != N00B_QUERY_MODE_LIVE || view->live == nullptr
        || !view->live->has_cutover_after) {
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                          n00b_option_set(n00b_store_pos_t,
                                          view->live->cutover_after));
}

n00b_result_t(uint64_t)
n00b_query_live_tail_drain_wakeups(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_view_is_closed_raw(view)) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_CLOSED);
    }

    auto live_r = rocs_query_live_state_for_tail(view);
    if (n00b_result_is_err(live_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(live_r));
    }
    rocs_query_live_state_t *live = n00b_result_get(live_r);

    n00b_data_write_lock(live->lock);
    auto drain_r = rocs_query_live_tail_drain_wakeups_locked(live);
    n00b_data_unlock(live->lock);
    return drain_r;
}

n00b_result_t(uint64_t)
n00b_query_live_tail_scan_once(n00b_query_view_t *view)
{
    return rocs_query_live_tail_scan_once_internal(view);
}

n00b_result_t(n00b_query_live_tail_stats_t)
n00b_query_live_tail_stats(n00b_query_view_t *view)
{
    auto live_r = rocs_query_live_state_for_tail(view);
    if (n00b_result_is_err(live_r)) {
        return n00b_result_err(n00b_query_live_tail_stats_t,
                               n00b_result_get_err(live_r));
    }

    rocs_query_live_state_t *live = n00b_result_get(live_r);
    n00b_data_read_lock(live->lock);
    n00b_query_live_tail_stats_t stats = live->stats;
    stats.subscription_active =
        live->commit_sub != N00B_CONDUIT_INVALID_SUB_HANDLE
        && n00b_conduit_sub_is_active(live->commit_sub);
    stats.has_inbox = live->commit_inbox != nullptr;
    stats.queued_wakeups = live->commit_inbox == nullptr
        ? 0
        : (uint64_t)n00b_store_commit_inbox_msg_count(live->commit_inbox);
    stats.pending_positions = live->pending_positions == nullptr
        ? 0
        : (uint64_t)n00b_list_len(*live->pending_positions);
    n00b_data_unlock(live->lock);
    return n00b_result_ok(n00b_query_live_tail_stats_t, stats);
}

n00b_result_t(n00b_query_output_stats_t)
n00b_query_output_stats(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(n00b_query_output_stats_t,
                               N00B_QUERY_ERR_ARG);
    }
    if (view->output == nullptr || view->output->lock == nullptr) {
        return n00b_result_err(n00b_query_output_stats_t,
                               N00B_QUERY_ERR_STATE);
    }

    n00b_data_read_lock(view->output->lock);
    n00b_query_output_stats_t stats = view->output->stats;
    if (view->output->topic != nullptr) {
        stats.subscriber_count =
            (uint64_t)n00b_list_len(view->output->topic->subscriptions);
    }
    n00b_data_unlock(view->output->lock);
    return n00b_result_ok(n00b_query_output_stats_t, stats);
}

n00b_result_t(uint64_t)
n00b_query_live_tail_pending_count(n00b_query_view_t *view)
{
    auto live_r = rocs_query_live_state_for_tail(view);
    if (n00b_result_is_err(live_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(live_r));
    }

    rocs_query_live_state_t *live = n00b_result_get(live_r);
    n00b_data_read_lock(live->lock);
    uint64_t count = 0;
    if (live->pending_positions == nullptr) {
        n00b_data_unlock(live->lock);
        return n00b_result_ok(uint64_t, count);
    }
    count = (uint64_t)n00b_list_len(*live->pending_positions);
    n00b_data_unlock(live->lock);
    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_live_tail_pending_position_at(n00b_query_view_t *view,
                                         uint64_t           index)
{
    auto live_r = rocs_query_live_state_for_tail(view);
    if (n00b_result_is_err(live_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               n00b_result_get_err(live_r));
    }

    rocs_query_live_state_t *live = n00b_result_get(live_r);
    n00b_data_read_lock(live->lock);
    if (live->pending_positions == nullptr
        || index >= (uint64_t)n00b_list_len(*live->pending_positions)) {
        n00b_data_unlock(live->lock);
        return n00b_result_ok(n00b_option_t(n00b_store_pos_t),
                              n00b_option_none(n00b_store_pos_t));
    }

    n00b_store_pos_t pos =
        n00b_list_get(*live->pending_positions, (size_t)index);
    n00b_data_unlock(live->lock);
    return n00b_result_ok(
        n00b_option_t(n00b_store_pos_t),
        n00b_option_set(n00b_store_pos_t, pos));
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_query_view_snapshot_upper_bound(n00b_query_view_t *view)
{
    return rocs_query_snapshot_upper_bound(view);
}

n00b_result_t(bool)
n00b_query_view_is_closed(n00b_query_view_t *view)
{
    if (view == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    return n00b_result_ok(bool, rocs_query_view_is_closed_raw(view));
}

n00b_result_t(uint64_t)
n00b_query_cursor_hit_count(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr || cursor->hits == nullptr) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_ARG);
    }
    if (rocs_query_cursor_or_view_closed(cursor)) {
        return n00b_result_err(uint64_t, N00B_QUERY_ERR_CLOSED);
    }

    auto build_r = rocs_query_cursor_build_remaining_snapshot(cursor);
    if (n00b_result_is_err(build_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(build_r));
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
    if (rocs_query_cursor_or_view_closed(cursor)) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_QUERY_ERR_CLOSED);
    }

    auto build_r = rocs_query_cursor_build_remaining_snapshot(cursor);
    if (n00b_result_is_err(build_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               n00b_result_get_err(build_r));
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

n00b_result_t(bool)
n00b_query_cursor_live_is_waiting(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (cursor->view == nullptr
        || cursor->view->mode != N00B_QUERY_MODE_LIVE) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    return n00b_result_ok(bool, n00b_atomic_load(&cursor->live_waiting));
}

n00b_result_t(bool)
n00b_query_cursor_live_wait_until_waiting(n00b_query_cursor_t *cursor)
{
    if (cursor == nullptr) {
        return n00b_result_err(bool, N00B_QUERY_ERR_ARG);
    }
    if (cursor->view == nullptr
        || cursor->view->mode != N00B_QUERY_MODE_LIVE) {
        return n00b_result_err(bool, N00B_QUERY_ERR_STATE);
    }

    n00b_condition_lock(&cursor->state_cv);
    while (!n00b_atomic_load(&cursor->live_waiting)
           && !rocs_query_cursor_or_view_closed(cursor)) {
        n00b_condition_wait(&cursor->state_cv);
    }
    bool waiting = n00b_atomic_load(&cursor->live_waiting);
    n00b_condition_unlock(&cursor->state_cv);
    return n00b_result_ok(bool, waiting);
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
