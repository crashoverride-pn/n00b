#include "rocs/wax.h"

#include "core/buffer.h"
#include "core/file.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/parse_num.h"
#include "util/path.h"

#include <stdint.h>


struct n00b_rocs_wax_daemon_config_t {
    n00b_store_config_t *store_config;
    n00b_string_t       *fixture_source_path;
    n00b_string_t       *checkpoint_path;
    uint64_t             max_lines;
    n00b_allocator_t    *allocator;
};

struct n00b_rocs_wax_daemon_t {
    n00b_rocs_wax_daemon_config_t *config;
    n00b_store_t                  *store;
    n00b_rocs_wax_daemon_stats_t   stats;
    bool                           stopped;
    bool                           healthy;
    n00b_allocator_t              *allocator;
};

n00b_string_t *
n00b_rocs_wax_normalized_schema(void)
{
    return r"wax.normalized.v1";
}

static bool
rocs_wax_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_string_t *
rocs_wax_string_copy(n00b_string_t *s, n00b_allocator_t *allocator)
{
    if (s == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(s->data,
                                (int64_t)s->u8_bytes,
                                .allocator = allocator);
}

static n00b_json_node_t *
rocs_wax_json_string(n00b_string_t *s, n00b_allocator_t *allocator)
{
    return n00b_json_string_new_from_n00b(s, .allocator = allocator);
}

static n00b_json_node_t *
rocs_wax_get_nested(n00b_json_node_t *root,
                    n00b_string_t    *flat_key,
                    n00b_string_t    *outer_key,
                    n00b_string_t    *inner_key)
{
    n00b_json_node_t *flat = n00b_json_object_get(root, flat_key);
    if (flat != nullptr) {
        return flat;
    }

    n00b_json_node_t *outer = n00b_json_object_get(root, outer_key);
    if (outer == nullptr || !n00b_json_is_object(outer)) {
        return nullptr;
    }
    return n00b_json_object_get(outer, inner_key);
}

static n00b_string_t *
rocs_wax_get_string(n00b_json_node_t *root, n00b_string_t *key)
{
    n00b_json_node_t *node = n00b_json_object_get(root, key);
    return n00b_json_is_string(node) ? n00b_json_as_string(node) : nullptr;
}

static n00b_string_t *
rocs_wax_get_nested_string(n00b_json_node_t *root,
                           n00b_string_t    *flat_key,
                           n00b_string_t    *outer_key,
                           n00b_string_t    *inner_key)
{
    n00b_json_node_t *node =
        rocs_wax_get_nested(root, flat_key, outer_key, inner_key);
    return n00b_json_is_string(node) ? n00b_json_as_string(node) : nullptr;
}

static void
rocs_wax_ensure_top_level_ts_ns(n00b_json_node_t *root,
                                n00b_allocator_t *allocator)
{
    if (root == nullptr || n00b_json_object_get(root, r"ts_ns") != nullptr) {
        return;
    }

    n00b_json_node_t *event = n00b_json_object_get(root, r"event");
    if (event == nullptr || !n00b_json_is_object(event)) {
        return;
    }

    n00b_json_node_t *ts = n00b_json_object_get(event, r"ts_ns");
    if (ts == nullptr || !n00b_json_is_int(ts)) {
        return;
    }

    n00b_json_object_put_n00b(root,
                              rocs_wax_string_copy(r"ts_ns", allocator),
                              n00b_json_int_new(n00b_json_as_i64(ts),
                                                .allocator = allocator));
}

static n00b_result_t(bool)
rocs_wax_add_field(n00b_store_schema_t     *schema,
                   n00b_string_t           *name,
                   n00b_store_index_kind_t  index_kind,
                   bool                     include_in_all,
                   n00b_store_postings_kind_t postings)
{
    auto field_r = n00b_store_schema_add_field(schema,
                                               name,
                                               .index_kind = index_kind,
                                               .include_in_all = include_in_all,
                                               .postings = postings);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(bool, n00b_result_get_err(field_r));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_wax_add_term_sparse(n00b_store_schema_t *schema, n00b_string_t *name)
{
    return rocs_wax_add_field(schema,
                              name,
                              N00B_STORE_INDEX_TERM,
                              false,
                              N00B_STORE_POSTINGS_SPARSE);
}

static n00b_result_t(bool)
rocs_wax_add_unindexed(n00b_store_schema_t *schema, n00b_string_t *name)
{
    return rocs_wax_add_field(schema,
                              name,
                              N00B_STORE_INDEX_NONE,
                              false,
                              N00B_STORE_POSTINGS_SPARSE);
}

n00b_string_t *
n00b_rocs_wax_err_str(n00b_err_t err)
{
    switch ((n00b_rocs_wax_err_t)err) {
    case N00B_ROCS_WAX_OK:
        return r"OK";
    case N00B_ROCS_WAX_ERR_ARG:
        return r"ARG";
    case N00B_ROCS_WAX_ERR_MALFORMED_JSON:
        return r"MALFORMED_JSON";
    case N00B_ROCS_WAX_ERR_NON_OBJECT:
        return r"NON_OBJECT";
    case N00B_ROCS_WAX_ERR_UNSUPPORTED_SCHEMA:
        return r"UNSUPPORTED_SCHEMA";
    case N00B_ROCS_WAX_ERR_MISSING_KIND:
        return r"MISSING_KIND";
    case N00B_ROCS_WAX_ERR_MISSING_EVENT_ID:
        return r"MISSING_EVENT_ID";
    case N00B_ROCS_WAX_ERR_INTERNAL:
        return r"INTERNAL";
    case N00B_ROCS_WAX_ERR_CONFIG:
        return r"CONFIG";
    case N00B_ROCS_WAX_ERR_SOURCE:
        return r"SOURCE";
    case N00B_ROCS_WAX_ERR_CHECKPOINT:
        return r"CHECKPOINT";
    case N00B_ROCS_WAX_ERR_STORE:
        return r"STORE";
    case N00B_ROCS_WAX_ERR_CLOSED:
        return r"CLOSED";
    case N00B_ROCS_WAX_ERR_STATE:
        return r"STATE";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_store_schema_t *)
n00b_rocs_wax_schema_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto schema_r = n00b_store_schema_new(.allocator   = allocator,
                                          .search_text = true);
    if (n00b_result_is_err(schema_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }

    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    auto add_r = rocs_wax_add_field(schema,
                                    r"schema",
                                    N00B_STORE_INDEX_TERM,
                                    false,
                                    N00B_STORE_POSTINGS_DENSE);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"kind",
                               N00B_STORE_INDEX_TERM,
                               false,
                               N00B_STORE_POSTINGS_DENSE);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"class",
                               N00B_STORE_INDEX_TERM,
                               false,
                               N00B_STORE_POSTINGS_DENSE);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"source.family",
                               N00B_STORE_INDEX_TERM,
                               false,
                               N00B_STORE_POSTINGS_DENSE);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_term_sparse(schema, r"event_id");
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_term_sparse(schema, r"lineage.event_id");
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_unindexed(schema, r"ts_ns");
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_unindexed(schema, r"event.ts_ns");
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_unindexed(schema, r"source.seq");
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_unindexed(schema, r"source.sequence");
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }

    n00b_string_t *sparse_exact_fields[] = {
        r"process.pid",
        r"process.ppid",
        r"process.exe_path",
        r"file.path",
        r"file.old_path",
        r"file.new_path",
        r"ai.session_id",
        r"ai.session_uuid",
        r"ai.parent_session_id",
        r"ai.event_id",
        r"ai.process_ref",
        r"ai.file_ref",
        r"ai.repo_ref",
        r"ai.pricing_id",
        r"ai.usage_id",
        r"ai.request_id",
        r"ai.response_id",
        r"chalker.chalk_id",
        r"chalker.artifact_ref",
        r"chalker.artifact_path",
        r"chalker.artifact_digest",
        r"chalker.file_ref",
        r"chalker.process_ref",
        r"chalker.repo_ref",
        r"body.pid",
        r"body.ppid",
        r"body.actor_pid",
        r"body.root_pid",
        r"body.exe_path",
        r"body.path",
        r"body.old_path",
        r"body.new_path",
        r"body.session_id",
        r"body.session_uuid",
        r"body.file_type",
        r"body.parent_session_id",
        r"body.event_id",
        r"body.process_ref",
        r"body.file_ref",
        r"body.repo_ref",
        r"body.pricing_id",
        r"body.usage_id",
        r"body.request_id",
        r"body.response_id",
        r"body.chalk_id",
        r"body.artifact_ref",
        r"body.artifact_path",
        r"body.artifact_digest",
        r"body.signer_keyid",
        r"body.envelope_digest",
        r"body.subject_digest",
        r"body.referrer_manifest_digest",
        r"source.name",
        r"host.boot_id",
    };

    for (size_t i = 0; i < sizeof(sparse_exact_fields) /
                               sizeof(sparse_exact_fields[0]);
         i++) {
        add_r = rocs_wax_add_term_sparse(schema, sparse_exact_fields[i]);
        if (n00b_result_is_err(add_r)) {
            return n00b_result_err(n00b_store_schema_t *,
                                   N00B_ROCS_WAX_ERR_INTERNAL);
        }
    }

    // The full-text catch-all is now the reserved, index-only search_text column
    // (n00b_store_schema_new .search_text=true) — populated at ingest from every
    // record string, never a JSON field. No user-named "search_text" field.

    return n00b_result_ok(n00b_store_schema_t *, schema);
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_rocs_wax_partition_policy_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    // Route shards by ROCS's own ingest clock, not the event ts_ns: the gateway
    // ingests from many providers whose timestamps vary in clock source and
    // quality (CLOCK_MONOTONIC vs epoch, missing, skewed).  Trusting that field
    // for shard cadence thrashed the hot-shard route (every other event flipped
    // time/<day> <-> time/0) and sealed thousands of tiny shards.  ts_ns is
    // still stored + indexed for event-time queries.
    return n00b_store_partition_policy_new_time(
        r"ts_ns",
        N00B_ROCS_WAX_DAY_NS,
        N00B_STORE_TIME_SOURCE_INGEST_CLOCK,
        .allocator = allocator);
}

n00b_result_t(n00b_store_seal_policy_t *)
n00b_rocs_wax_seal_policy_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_store_seal_policy_new(
        .max_records   = N00B_ROCS_WAX_SHARD_MAX_RECORDS,
        .max_bytes     = N00B_ROCS_WAX_SHARD_MAX_BYTES,
        .max_hot_bytes = N00B_ROCS_WAX_SHARD_MAX_HOT_BYTES,
        .allocator     = allocator);
}

static n00b_result_t(n00b_json_node_t *)
rocs_wax_record_from_bytes(const char       *data,
                           size_t            len,
                           n00b_allocator_t *allocator)
    requires {
        data != nullptr;
    }
    ensures {
        n00b_result_is_ok(result) || n00b_result_is_err(result);
    }
{
    if (len == 0) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_MALFORMED_JSON);
    }

    n00b_json_node_t *root = n00b_json_parse(data,
                                             len,
                                             nullptr,
                                             .allocator = allocator);
    if (root == nullptr) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_MALFORMED_JSON);
    }
    if (!n00b_json_is_object(root)) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_NON_OBJECT);
    }

    n00b_string_t *schema = rocs_wax_get_string(root, r"schema");
    if (rocs_wax_string_empty(schema)
        || !n00b_unicode_str_eq(schema, N00B_ROCS_WAX_NORMALIZED_SCHEMA)) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_UNSUPPORTED_SCHEMA);
    }

    n00b_string_t *kind = rocs_wax_get_string(root, r"kind");
    if (rocs_wax_string_empty(kind)) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_MISSING_KIND);
    }

    n00b_string_t *event_id =
        rocs_wax_get_nested_string(root,
                                   r"lineage.event_id",
                                   r"lineage",
                                   r"event_id");
    if (rocs_wax_string_empty(event_id)) {
        event_id = rocs_wax_get_string(root, r"event_id");
    }
    if (rocs_wax_string_empty(event_id)) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_MISSING_EVENT_ID);
    }

    rocs_wax_ensure_top_level_ts_ns(root, allocator);

    // Derive the top-level category column `class` from `kind` (the segment
    // before the first '.') when the producer didn't supply one. `class` is a
    // TERM-indexed column, so a forgiving `--kind <category>` resolves to
    // class == <category> and matches every <category>.* subtype with no
    // hardcoded taxonomy and no extra storage beyond this one short column.
    n00b_string_t *existing_class = rocs_wax_get_string(root, r"class");
    if (rocs_wax_string_empty(existing_class)) {
        n00b_string_t *cls   = kind;
        auto           dot_r = n00b_unicode_str_find(kind, r".");
        if (n00b_option_is_set(dot_r)) {
            cls = n00b_unicode_str_slice(kind, 0, n00b_option_get(dot_r));
        }
        n00b_json_object_put_n00b(
            root,
            r"class",
            n00b_json_string_new_from_n00b(cls, .allocator = allocator));
    }

    // Full-text search is the reserved, index-only search_text column populated
    // by rocs at ingest from every record string — no longer materialized into
    // the record JSON here (that leaked an internal index into the event body
    // and collided with the user field namespace).

    return n00b_result_ok(n00b_json_node_t *, root);
}

n00b_result_t(n00b_json_node_t *)
n00b_rocs_wax_record_from_line(n00b_string_t *line) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (line == nullptr || line->data == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_ROCS_WAX_ERR_ARG);
    }
    return rocs_wax_record_from_bytes(line->data,
                                      line->u8_bytes,
                                      allocator);
}

n00b_result_t(n00b_json_node_t *)
n00b_rocs_wax_record_from_source(n00b_buffer_t    *source,
                                 n00b_allocator_t *allocator)
    requires {
        source != nullptr;
    }
    ensures {
        n00b_result_is_ok(result) || n00b_result_is_err(result);
    }
{
    if (source == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_ROCS_WAX_ERR_ARG);
    }

    uint64_t len = (uint64_t)n00b_buffer_len(source);
    if (len > (uint64_t)SIZE_MAX) {
        return n00b_result_err(n00b_json_node_t *, N00B_ROCS_WAX_ERR_ARG);
    }

    _n00b_buffer_rlock(source);
    auto result = rocs_wax_record_from_bytes(source->data,
                                             (size_t)len,
                                             allocator);
    _n00b_buffer_unlock(source);
    return result;
}

n00b_result_t(n00b_rocs_wax_daemon_config_t *)
n00b_rocs_wax_daemon_config_new(n00b_store_config_t *store_config) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store_config == nullptr) {
        return n00b_result_err(n00b_rocs_wax_daemon_config_t *,
                               N00B_ROCS_WAX_ERR_CONFIG);
    }

    n00b_rocs_wax_daemon_config_t *config =
        n00b_alloc_with_opts(n00b_rocs_wax_daemon_config_t,
                             &(n00b_alloc_opts_t){
                                 .allocator = allocator,
                             });
    config->store_config = store_config;
    config->allocator    = allocator;
    return n00b_result_ok(n00b_rocs_wax_daemon_config_t *, config);
}

static n00b_result_t(bool)
rocs_wax_daemon_set_string(n00b_string_t **slot,
                           n00b_string_t   *value,
                           n00b_allocator_t *allocator)
{
    if (slot == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_ARG);
    }
    *slot = rocs_wax_string_copy(value, allocator);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_rocs_wax_daemon_config_set_fixture_source(
    n00b_rocs_wax_daemon_config_t *config,
    n00b_string_t                 *path)
{
    if (config == nullptr || rocs_wax_string_empty(path)) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CONFIG);
    }
    return rocs_wax_daemon_set_string(&config->fixture_source_path,
                                      path,
                                      config->allocator);
}

n00b_result_t(bool)
n00b_rocs_wax_daemon_config_set_checkpoint_path(
    n00b_rocs_wax_daemon_config_t *config,
    n00b_string_t                 *path)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CONFIG);
    }
    return rocs_wax_daemon_set_string(&config->checkpoint_path,
                                      path,
                                      config->allocator);
}

n00b_result_t(bool)
n00b_rocs_wax_daemon_config_set_max_lines(
    n00b_rocs_wax_daemon_config_t *config,
    uint64_t                       max_lines)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CONFIG);
    }
    config->max_lines = max_lines;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_string_t *)
rocs_wax_read_text_file(n00b_string_t *path)
{
    if (rocs_wax_string_empty(path)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    auto open_r = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_file_t *file  = n00b_result_get(open_r);
    auto         buf_r = n00b_file_as_buffer(file);
    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(file);
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_buffer_t *copy = n00b_buffer_copy(n00b_result_get(buf_r));
    n00b_file_close(file);
    return n00b_result_ok(n00b_string_t *, n00b_buffer_to_string(copy));
}

static n00b_result_t(uint64_t)
rocs_wax_checkpoint_read(n00b_string_t                    *path,
                         n00b_rocs_wax_daemon_stats_t    *stats)
{
    if (rocs_wax_string_empty(path)) {
        return n00b_result_ok(uint64_t, 0);
    }
    if (!n00b_file_exists(path)) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto text_r = rocs_wax_read_text_file(path);
    if (n00b_result_is_err(text_r)) {
        if (stats != nullptr) {
            stats->checkpoint_errors++;
            stats->last_error = N00B_ROCS_WAX_ERR_CHECKPOINT;
        }
        return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    n00b_string_t *text = n00b_result_get(text_r);
    if (rocs_wax_string_empty(text)) {
        if (stats != nullptr) {
            stats->checkpoint_errors++;
            stats->last_error = N00B_ROCS_WAX_ERR_CHECKPOINT;
        }
        return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    auto parsed_r = n00b_parse_i64(text);
    if (n00b_result_is_err(parsed_r) || n00b_result_get(parsed_r) < 0) {
        if (stats != nullptr) {
            stats->checkpoint_errors++;
            stats->last_error = N00B_ROCS_WAX_ERR_CHECKPOINT;
        }
        return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_result_get(parsed_r));
}

static n00b_result_t(bool)
rocs_wax_checkpoint_write(n00b_rocs_wax_daemon_t *daemon, uint64_t line_no)
{
    daemon->stats.checkpoint_line = line_no;
    if (rocs_wax_string_empty(daemon->config->checkpoint_path)) {
        return n00b_result_ok(bool, true);
    }

    n00b_string_t *text = n00b_cformat("[|#|]\n", (int64_t)line_no);
    n00b_buffer_t *buf  = n00b_buffer_from_bytes(text->data,
                                                 (int64_t)text->u8_bytes);

    auto open_r = n00b_file_open(daemon->config->checkpoint_path,
                                 .mode = N00B_FILE_W);
    if (n00b_result_is_err(open_r)) {
        daemon->stats.checkpoint_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_CHECKPOINT;
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    n00b_file_t *file = n00b_result_get(open_r);
    auto         wr_r = n00b_file_write_all(file, buf);
    auto         cl_r = n00b_file_close_result(file);
    if (n00b_result_is_err(wr_r) || n00b_result_is_err(cl_r)) {
        daemon->stats.checkpoint_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_CHECKPOINT;
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    daemon->stats.checkpoint_writes++;
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_rocs_wax_daemon_t *)
n00b_rocs_wax_daemon_start(n00b_rocs_wax_daemon_config_t *config) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (config == nullptr || config->store_config == nullptr
        || rocs_wax_string_empty(config->fixture_source_path)) {
        return n00b_result_err(n00b_rocs_wax_daemon_t *,
                               N00B_ROCS_WAX_ERR_CONFIG);
    }

    n00b_rocs_wax_daemon_t *daemon =
        n00b_alloc_with_opts(n00b_rocs_wax_daemon_t,
                             &(n00b_alloc_opts_t){
                                 .allocator = allocator,
                             });
    daemon->config    = config;
    daemon->allocator = allocator;
    daemon->healthy   = false;
    daemon->stopped   = false;

    auto checkpoint_r = rocs_wax_checkpoint_read(config->checkpoint_path,
                                                 &daemon->stats);
    if (n00b_result_is_err(checkpoint_r)) {
        return n00b_result_err(n00b_rocs_wax_daemon_t *,
                               n00b_result_get_err(checkpoint_r));
    }
    daemon->stats.checkpoint_line = n00b_result_get(checkpoint_r);

    auto schema_r = n00b_rocs_wax_schema_new(.allocator = allocator);
    if (n00b_result_is_err(schema_r)) {
        daemon->stats.store_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
        return n00b_result_err(n00b_rocs_wax_daemon_t *,
                               N00B_ROCS_WAX_ERR_STORE);
    }

    auto partition_r =
        n00b_rocs_wax_partition_policy_new(.allocator = allocator);
    auto seal_r = n00b_rocs_wax_seal_policy_new(.allocator = allocator);
    if (n00b_result_is_err(partition_r) || n00b_result_is_err(seal_r)) {
        daemon->stats.store_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
        return n00b_result_err(n00b_rocs_wax_daemon_t *,
                               N00B_ROCS_WAX_ERR_STORE);
    }

    auto store_r = n00b_store_open_config(n00b_result_get(schema_r),
                                          config->store_config,
                                          .partition_policy =
                                              n00b_result_get(partition_r),
                                          .seal_policy = n00b_result_get(seal_r),
                                          .allocator   = allocator);
    if (n00b_result_is_err(store_r)) {
        daemon->stats.store_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
        return n00b_result_err(n00b_rocs_wax_daemon_t *,
                               N00B_ROCS_WAX_ERR_STORE);
    }

    daemon->store   = n00b_result_get(store_r);
    daemon->healthy = true;
    return n00b_result_ok(n00b_rocs_wax_daemon_t *, daemon);
}

static n00b_result_t(bool)
rocs_wax_daemon_ingest_line(n00b_rocs_wax_daemon_t *daemon,
                            n00b_string_t          *line,
                            uint64_t                line_no)
{
    auto record_r = n00b_rocs_wax_record_from_line(line,
                                                   .allocator = daemon->allocator);
    if (n00b_result_is_err(record_r)) {
        daemon->stats.events_rejected++;
        daemon->stats.last_error = n00b_result_get_err(record_r);
        return rocs_wax_checkpoint_write(daemon, line_no);
    }

    auto ingest_r = n00b_store_ingest(daemon->store, n00b_result_get(record_r));
    if (n00b_result_is_err(ingest_r)) {
        daemon->stats.store_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
        daemon->healthy = false;
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_STORE);
    }

    auto flush_r = n00b_store_flush(daemon->store);
    if (n00b_result_is_err(flush_r)) {
        daemon->stats.store_errors++;
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
        daemon->healthy = false;
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_STORE);
    }

    daemon->stats.events_ingested++;
    return rocs_wax_checkpoint_write(daemon, line_no);
}

n00b_result_t(bool)
n00b_rocs_wax_daemon_run(n00b_rocs_wax_daemon_t *daemon)
{
    if (daemon == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_ARG);
    }
    if (daemon->stopped || daemon->store == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CLOSED);
    }

    auto source_r = rocs_wax_read_text_file(daemon->config->fixture_source_path);
    if (n00b_result_is_err(source_r)) {
        daemon->stats.last_error = N00B_ROCS_WAX_ERR_SOURCE;
        daemon->healthy = false;
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_string_t *text          = n00b_result_get(source_r);
    uint64_t       line_no       = 0;
    uint64_t       processed_now = 0;
    size_t         start         = 0;
    bool           reached_eof   = true;

    for (size_t i = 0; i <= text->u8_bytes; i++) {
        if (i < text->u8_bytes && text->data[i] != '\n') {
            continue;
        }
        if (i == text->u8_bytes && start == i) {
            break;
        }

        line_no++;
        size_t end = i;
        if (end > start && text->data[end - 1] == '\r') {
            end--;
        }

        if (line_no <= daemon->stats.checkpoint_line) {
            start = i + 1;
            continue;
        }
        if (daemon->config->max_lines != 0
            && processed_now >= daemon->config->max_lines) {
            reached_eof = false;
            break;
        }

        n00b_string_t *line =
            n00b_string_from_raw(text->data + start,
                                 (int64_t)(end - start),
                                 .allocator = daemon->allocator);
        daemon->stats.lines_read++;
        processed_now++;

        auto ingest_r = rocs_wax_daemon_ingest_line(daemon, line, line_no);
        if (n00b_result_is_err(ingest_r)) {
            return ingest_r;
        }
        start = i + 1;
    }

    if (reached_eof) {
        daemon->stats.source_disconnects++;
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_rocs_wax_daemon_stop(n00b_rocs_wax_daemon_t *daemon)
{
    if (daemon == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_ARG);
    }
    if (daemon->stopped) {
        return n00b_result_ok(bool, false);
    }

    daemon->healthy = false;
    if (daemon->store != nullptr) {
        auto flush_r = n00b_store_flush(daemon->store);
        if (n00b_result_is_err(flush_r)) {
            daemon->stats.store_errors++;
            daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
            (void)n00b_store_close(daemon->store);
            daemon->store   = nullptr;
            daemon->stopped = true;
            return n00b_result_err(bool, N00B_ROCS_WAX_ERR_STORE);
        }

        auto close_r = n00b_store_close(daemon->store);
        daemon->store = nullptr;
        if (n00b_result_is_err(close_r)) {
            daemon->stats.store_errors++;
            daemon->stats.last_error = N00B_ROCS_WAX_ERR_STORE;
            daemon->stopped = true;
            return n00b_result_err(bool, N00B_ROCS_WAX_ERR_STORE);
        }
    }

    daemon->stopped = true;
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_rocs_wax_daemon_stats_t)
n00b_rocs_wax_daemon_stats(n00b_rocs_wax_daemon_t *daemon)
{
    if (daemon == nullptr) {
        return n00b_result_err(n00b_rocs_wax_daemon_stats_t,
                               N00B_ROCS_WAX_ERR_ARG);
    }
    return n00b_result_ok(n00b_rocs_wax_daemon_stats_t, daemon->stats);
}

n00b_result_t(bool)
n00b_rocs_wax_daemon_healthy(n00b_rocs_wax_daemon_t *daemon)
{
    if (daemon == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_ARG);
    }
    return n00b_result_ok(bool,
                          daemon->healthy && !daemon->stopped
                              && daemon->store != nullptr);
}

n00b_result_t(n00b_store_t *)
n00b_rocs_wax_daemon_store(n00b_rocs_wax_daemon_t *daemon)
{
    if (daemon == nullptr) {
        return n00b_result_err(n00b_store_t *, N00B_ROCS_WAX_ERR_ARG);
    }
    if (daemon->stopped || daemon->store == nullptr) {
        return n00b_result_err(n00b_store_t *, N00B_ROCS_WAX_ERR_CLOSED);
    }
    return n00b_result_ok(n00b_store_t *, daemon->store);
}
