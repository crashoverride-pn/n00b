#include "rocs/wax.h"

#include "core/buffer.h"
#include "core/file.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/parse_num.h"
#include "util/path.h"

#define ROCS_WAX_SEARCH_TEXT_MAX_BYTES 4096u

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

static void
rocs_wax_put_string(n00b_json_node_t *obj,
                    n00b_string_t    *key,
                    n00b_string_t    *value,
                    n00b_allocator_t *allocator)
{
    if (rocs_wax_string_empty(value)) {
        return;
    }
    n00b_json_object_put_n00b(obj,
                              rocs_wax_string_copy(key, allocator),
                              rocs_wax_json_string(value, allocator));
}

static void
rocs_wax_put_i64(n00b_json_node_t *obj,
                 n00b_string_t    *key,
                 n00b_json_node_t *value,
                 n00b_allocator_t *allocator)
{
    if (value == nullptr || !n00b_json_is_int(value)) {
        return;
    }
    n00b_json_object_put_n00b(obj,
                              rocs_wax_string_copy(key, allocator),
                              n00b_json_int_new(n00b_json_as_i64(value),
                                                .allocator = allocator));
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

static n00b_json_node_t *
rocs_wax_get_int_any(n00b_json_node_t *root,
                     n00b_string_t    *key_a,
                     n00b_string_t    *key_b,
                     n00b_string_t    *flat_c,
                     n00b_string_t    *outer_c,
                     n00b_string_t    *inner_c)
{
    n00b_json_node_t *node = n00b_json_object_get(root, key_a);
    if (n00b_json_is_int(node)) {
        return node;
    }

    node = n00b_json_object_get(root, key_b);
    if (n00b_json_is_int(node)) {
        return node;
    }

    node = rocs_wax_get_nested(root, flat_c, outer_c, inner_c);
    return n00b_json_is_int(node) ? node : nullptr;
}

static n00b_string_t *
rocs_wax_kind_prefix(n00b_string_t *kind, n00b_allocator_t *allocator)
{
    if (rocs_wax_string_empty(kind)) {
        return nullptr;
    }

    for (size_t i = 0; i < kind->u8_bytes; i++) {
        if (kind->data[i] == '.') {
            if (i == 0) {
                return nullptr;
            }
            return n00b_string_from_raw(kind->data,
                                        (int64_t)i,
                                        .allocator = allocator);
        }
    }

    return nullptr;
}

static n00b_string_t *
rocs_wax_quality_string(n00b_json_node_t *root)
{
    n00b_json_node_t *quality = n00b_json_object_get(root, r"quality");
    if (n00b_json_is_string(quality)) {
        return n00b_json_as_string(quality);
    }
    if (quality == nullptr || !n00b_json_is_object(quality)) {
        return nullptr;
    }

    n00b_json_node_t *state = n00b_json_object_get(quality, r"state");
    if (n00b_json_is_string(state)) {
        return n00b_json_as_string(state);
    }

    n00b_json_node_t *degraded = n00b_json_object_get(quality,
                                                      r"degraded_by_loss");
    if (n00b_json_is_bool(degraded) && n00b_json_as_bool(degraded)) {
        return r"degraded";
    }

    degraded = n00b_json_object_get(quality, r"degraded");
    if (n00b_json_is_bool(degraded) && n00b_json_as_bool(degraded)) {
        return r"degraded";
    }

    n00b_json_node_t *synthetic = n00b_json_object_get(quality, r"synthetic");
    if (n00b_json_is_bool(synthetic) && n00b_json_as_bool(synthetic)) {
        return r"synthetic";
    }

    return nullptr;
}

static bool
rocs_wax_search_can_append(n00b_string_t *acc, n00b_string_t *token)
{
    if (rocs_wax_string_empty(token)) {
        return false;
    }
    size_t acc_len = rocs_wax_string_empty(acc) ? 0 : acc->u8_bytes;
    size_t sep_len = acc_len == 0 ? 0 : 1;
    return acc_len + sep_len + token->u8_bytes <= ROCS_WAX_SEARCH_TEXT_MAX_BYTES;
}

static n00b_string_t *
rocs_wax_search_append(n00b_string_t    *acc,
                       n00b_string_t    *token,
                       n00b_allocator_t *allocator)
{
    if (!rocs_wax_search_can_append(acc, token)) {
        return acc;
    }
    if (rocs_wax_string_empty(acc)) {
        return rocs_wax_string_copy(token, allocator);
    }

    n00b_string_t *with_space = n00b_unicode_str_cat(acc,
                                                     r" ",
                                                     .allocator = allocator);
    return n00b_unicode_str_cat(with_space,
                                token,
                                .allocator = allocator);
}

static n00b_string_t *
rocs_wax_search_append_scalar(n00b_string_t    *acc,
                              n00b_json_node_t *node,
                              n00b_allocator_t *allocator)
{
    if (n00b_json_is_string(node)) {
        return rocs_wax_search_append(acc,
                                      n00b_json_as_string(node),
                                      allocator);
    }
    return acc;
}

static n00b_string_t *
rocs_wax_search_append_array(n00b_string_t    *acc,
                             n00b_json_node_t *node,
                             n00b_allocator_t *allocator)
{
    if (!n00b_json_is_array(node)) {
        return acc;
    }

    size_t len = n00b_json_array_len(node);
    for (size_t i = 0; i < len; i++) {
        acc = rocs_wax_search_append_scalar(acc,
                                            n00b_json_array_get(node, i),
                                            allocator);
    }
    return acc;
}

static n00b_string_t *
rocs_wax_search_append_object_scalars(n00b_string_t    *acc,
                                      n00b_json_node_t *obj,
                                      n00b_allocator_t *allocator)
{
    if (obj == nullptr || !n00b_json_is_object(obj)) {
        return acc;
    }

    auto entries_r = n00b_json_object_entries(obj, .allocator = allocator);
    if (n00b_result_is_err(entries_r)) {
        return acc;
    }

    n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
    size_t                         len     = n00b_list_len(*entries);
    for (size_t i = 0; i < len; i++) {
        n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
        acc = rocs_wax_search_append_scalar(acc, entry->value, allocator);
        acc = rocs_wax_search_append_array(acc, entry->value, allocator);
    }
    return acc;
}

static n00b_string_t *
rocs_wax_search_append_child_object_scalars(n00b_string_t    *acc,
                                            n00b_json_node_t *obj,
                                            n00b_allocator_t *allocator)
{
    if (obj == nullptr || !n00b_json_is_object(obj)) {
        return acc;
    }

    auto entries_r = n00b_json_object_entries(obj, .allocator = allocator);
    if (n00b_result_is_err(entries_r)) {
        return acc;
    }

    n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
    size_t                         len     = n00b_list_len(*entries);
    for (size_t i = 0; i < len; i++) {
        n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
        acc = rocs_wax_search_append_object_scalars(acc,
                                                    entry->value,
                                                    allocator);
    }
    return acc;
}

static n00b_string_t *
rocs_wax_build_search_text(n00b_json_node_t *root,
                           n00b_string_t    *schema,
                           n00b_string_t    *kind,
                           n00b_string_t    *class_name,
                           n00b_string_t    *family,
                           n00b_string_t    *event_id,
                           n00b_string_t    *policy_revision,
                           n00b_string_t    *quality,
                           n00b_allocator_t *allocator)
{
    n00b_string_t *acc = nullptr;

    acc = rocs_wax_search_append(acc, schema, allocator);
    acc = rocs_wax_search_append(acc, kind, allocator);
    acc = rocs_wax_search_append(acc, class_name, allocator);
    acc = rocs_wax_search_append(acc, family, allocator);
    acc = rocs_wax_search_append(acc, event_id, allocator);
    acc = rocs_wax_search_append(acc, policy_revision, allocator);
    acc = rocs_wax_search_append(acc, quality, allocator);
    acc = rocs_wax_search_append_object_scalars(acc, root, allocator);
    acc = rocs_wax_search_append_child_object_scalars(acc, root, allocator);

    n00b_json_node_t *domain = n00b_json_object_get(root, class_name);
    acc = rocs_wax_search_append_object_scalars(acc, domain, allocator);

    if (acc == nullptr) {
        return n00b_string_empty(.allocator = allocator);
    }
    return acc;
}

static n00b_result_t(bool)
rocs_wax_add_field(n00b_store_schema_t     *schema,
                   n00b_string_t           *name,
                   n00b_store_index_kind_t  index_kind,
                   bool                     include_in_all)
{
    auto field_r = n00b_store_schema_add_field(schema,
                                               name,
                                               .index_kind = index_kind,
                                               .include_in_all = include_in_all);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(bool, n00b_result_get_err(field_r));
    }
    return n00b_result_ok(bool, true);
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
    auto schema_r = n00b_store_schema_new(.allocator = allocator);
    if (n00b_result_is_err(schema_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }

    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    auto add_r = rocs_wax_add_field(schema,
                                    r"schema",
                                    N00B_STORE_INDEX_TERM,
                                    false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema, r"kind", N00B_STORE_INDEX_TERM, false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema, r"class", N00B_STORE_INDEX_TERM, false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema, r"family", N00B_STORE_INDEX_TERM, false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"event_id",
                               N00B_STORE_INDEX_TERM,
                               false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"timestamp",
                               N00B_STORE_INDEX_NONE,
                               false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"source_sequence",
                               N00B_STORE_INDEX_NONE,
                               false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"policy_revision",
                               N00B_STORE_INDEX_TERM,
                               false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"quality",
                               N00B_STORE_INDEX_TERM,
                               false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"raw_json",
                               N00B_STORE_INDEX_NONE,
                               false);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }
    add_r = rocs_wax_add_field(schema,
                               r"search_text",
                               N00B_STORE_INDEX_FULLTEXT,
                               true);
    if (n00b_result_is_err(add_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               N00B_ROCS_WAX_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_store_schema_t *, schema);
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_rocs_wax_partition_policy_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_store_partition_policy_new_time(
        r"timestamp",
        N00B_ROCS_WAX_DAY_NS,
        .allocator = allocator);
}

n00b_result_t(n00b_store_seal_policy_t *)
n00b_rocs_wax_seal_policy_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_store_seal_policy_new(
        .max_records = N00B_ROCS_WAX_SHARD_MAX_RECORDS,
        .max_bytes   = N00B_ROCS_WAX_SHARD_MAX_BYTES,
        .allocator   = allocator);
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
    if (line->u8_bytes == 0) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_MALFORMED_JSON);
    }

    n00b_json_node_t *root = n00b_json_parse(line->data,
                                             line->u8_bytes,
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

    n00b_string_t *class_name = rocs_wax_get_string(root, r"class");
    if (rocs_wax_string_empty(class_name)) {
        class_name = rocs_wax_kind_prefix(kind, allocator);
    }
    if (rocs_wax_string_empty(class_name)) {
        class_name = kind;
    }

    n00b_string_t *family =
        rocs_wax_get_nested_string(root, r"source.family", r"source", r"family");
    if (rocs_wax_string_empty(family)) {
        family = rocs_wax_get_string(root, r"family");
    }
    if (rocs_wax_string_empty(family)) {
        family = class_name;
    }

    n00b_string_t *policy_revision =
        rocs_wax_get_nested_string(root,
                                   r"policy.revision",
                                   r"policy",
                                   r"revision");
    if (rocs_wax_string_empty(policy_revision)) {
        policy_revision =
            rocs_wax_get_nested_string(root,
                                       r"install.policy_revision",
                                       r"install",
                                       r"policy_revision");
    }
    if (rocs_wax_string_empty(policy_revision)) {
        policy_revision = rocs_wax_get_string(root, r"policy_revision");
    }

    n00b_string_t *quality = rocs_wax_quality_string(root);
    n00b_json_node_t *timestamp =
        rocs_wax_get_int_any(root,
                             r"ts_ns",
                             r"timestamp",
                             r"event.ts_ns",
                             r"event",
                             r"ts_ns");
    n00b_json_node_t *source_sequence =
        rocs_wax_get_int_any(root,
                             r"source_sequence",
                             r"sequence",
                             r"source.seq",
                             r"source",
                             r"seq");
    if (source_sequence == nullptr) {
        source_sequence = rocs_wax_get_nested(root,
                                              r"source.sequence",
                                              r"source",
                                              r"sequence");
    }

    n00b_json_node_t *record = n00b_json_object_new(.allocator = allocator);
    rocs_wax_put_string(record, r"schema", schema, allocator);
    rocs_wax_put_string(record, r"kind", kind, allocator);
    rocs_wax_put_string(record, r"class", class_name, allocator);
    rocs_wax_put_string(record, r"family", family, allocator);
    rocs_wax_put_string(record, r"event_id", event_id, allocator);
    rocs_wax_put_i64(record, r"timestamp", timestamp, allocator);
    rocs_wax_put_i64(record,
                     r"source_sequence",
                     source_sequence,
                     allocator);
    rocs_wax_put_string(record,
                        r"policy_revision",
                        policy_revision,
                        allocator);
    rocs_wax_put_string(record, r"quality", quality, allocator);
    rocs_wax_put_string(record, r"raw_json", line, allocator);

    n00b_string_t *search_text =
        rocs_wax_build_search_text(root,
                                   schema,
                                   kind,
                                   class_name,
                                   family,
                                   event_id,
                                   policy_revision,
                                   quality,
                                   allocator);
    rocs_wax_put_string(record, r"search_text", search_text, allocator);

    return n00b_result_ok(n00b_json_node_t *, record);
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
