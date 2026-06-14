/* Output helpers for the WP-013 wax cache tool. */

#include "n00b.h"
#include "conduit/print.h"
#include "internal/rocs/index.h"
#include "internal/rocs/map.h"
#include "internal/rocs/store.h"
#include "rocs/map.h"
#include "rocs/n00b_rocs.h"

typedef enum : int32_t {
    ROCS_WAX_CACHE_FORMAT_TEXT,
    ROCS_WAX_CACHE_FORMAT_TABLE,
    ROCS_WAX_CACHE_FORMAT_JSONL,
} rocs_wax_cache_output_format_t;

static bool
rocs_wax_cache_str_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_string_t *
rocs_wax_cache_json_string(n00b_json_node_t *json, n00b_string_t *field)
{
    n00b_json_node_t *node = n00b_json_object_get(json, field);
    if (n00b_json_is_string(node)) {
        return n00b_json_as_string(node);
    }
    if (n00b_json_is_int(node)) {
        return n00b_cformat("[|#|]", n00b_json_as_i64(node));
    }
    if (n00b_json_is_bool(node)) {
        return n00b_json_as_bool(node) ? r"true" : r"false";
    }
    if (n00b_json_is_double(node)) {
        double value = n00b_json_as_f64(node);
        return n00b_cformat("[|#:.6f|]", &value);
    }
    return r"";
}

static n00b_string_t *
rocs_wax_cache_event_tail(n00b_string_t *event_id)
{
    if (rocs_wax_cache_str_empty(event_id)) {
        return r"";
    }

    size_t tail = 0;
    for (size_t i = 0; i < event_id->u8_bytes; i++) {
        if (event_id->data[i] == ':') {
            tail = i + 1;
        }
    }

    return n00b_string_from_raw(event_id->data + tail,
                                (int64_t)(event_id->u8_bytes - tail));
}

static n00b_string_t *
rocs_wax_cache_payload_json(n00b_json_node_t *record)
{
    char *encoded = n00b_json_encode(record);
    return encoded == nullptr ? r"{}" : n00b_string_from_cstr(encoded);
}

static n00b_string_t *
rocs_wax_cache_short_pos(n00b_store_pos_t pos)
{
    if (pos.generation == 0) {
        return n00b_cformat("[|#|]:[|#|]",
                            (int64_t)pos.shard_id,
                            (int64_t)pos.ordinal);
    }

    return n00b_cformat("[|#|]:[|#|]:[|#|]",
                        (int64_t)pos.generation,
                        (int64_t)pos.shard_id,
                        (int64_t)pos.ordinal);
}

static n00b_result_t(n00b_json_node_t *)
rocs_wax_cache_hit_json(n00b_store_t *store, n00b_query_hit_t *hit)
{
    auto record_r = n00b_query_hit_record(hit);
    if (n00b_result_is_ok(record_r)) {
        auto json_r =
            n00b_store_record_view_json_copy(n00b_result_get(record_r));
        if (n00b_result_is_ok(json_r)) {
            return json_r;
        }
    }

    auto pos_r = n00b_query_hit_pos(hit);
    if (n00b_result_is_err(pos_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(pos_r));
    }
    n00b_store_pos_t pos = n00b_result_get(pos_r);

    auto hot_r = n00b_store_hot_record_copy_for_pos(store, pos);
    if (n00b_result_is_err(hot_r)) {
        return n00b_result_err(n00b_json_node_t *, n00b_result_get_err(hot_r));
    }
    n00b_option_t(n00b_store_record_t *) hot_opt = n00b_result_get(hot_r);
    if (n00b_option_is_set(hot_opt)) {
        return n00b_store_record_view_json_copy(n00b_option_get(hot_opt));
    }

    auto entry_r = n00b_store_catalog_find_shard(store, pos.shard_id);
    if (n00b_result_is_err(entry_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(entry_r));
    }
    n00b_option_t(n00b_store_catalog_entry_t *) entry_opt =
        n00b_result_get(entry_r);
    if (!n00b_option_is_set(entry_opt)) {
        return n00b_result_err(n00b_json_node_t *,
                               N00B_STORE_INDEX_ERR_STATE);
    }

    n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    if (n00b_result_is_err(resident_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(resident_r));
    }
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        (void)n00b_store_resident_shard_release(resident);
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(map_r));
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    if (n00b_result_is_err(root_r)) {
        (void)n00b_store_resident_shard_release(resident);
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(root_r));
    }

    auto json_r =
        n00b_store_map_shard_record_json_copy(n00b_result_get(root_r),
                                              pos.ordinal);
    auto release_r = n00b_store_resident_shard_release(resident);
    if (n00b_result_is_err(json_r)) {
        return json_r;
    }
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(n00b_json_node_t *,
                               n00b_result_get_err(release_r));
    }
    return json_r;
}

static n00b_result_t(n00b_string_t *)
rocs_wax_cache_hit_pos(n00b_query_hit_t *hit)
{
    auto pos_r = n00b_query_hit_pos(hit);
    if (n00b_result_is_err(pos_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(pos_r));
    }
    return n00b_result_ok(n00b_string_t *,
                          rocs_wax_cache_short_pos(n00b_result_get(pos_r)));
}

static n00b_result_t(bool)
rocs_wax_cache_print_jsonl(n00b_store_t *store, n00b_query_hit_t *hit)
{
    auto json_r = rocs_wax_cache_hit_json(store, hit);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(bool, n00b_result_get_err(json_r));
    }

    n00b_printf("«#»", rocs_wax_cache_payload_json(n00b_result_get(json_r)));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_wax_cache_print_table(n00b_store_t *store, n00b_query_hit_t *hit)
{
    auto json_r = rocs_wax_cache_hit_json(store, hit);
    auto pos_r  = rocs_wax_cache_hit_pos(hit);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(bool, n00b_result_get_err(json_r));
    }
    if (n00b_result_is_err(pos_r)) {
        return n00b_result_err(bool, n00b_result_get_err(pos_r));
    }

    n00b_json_node_t *json = n00b_result_get(json_r);
    n00b_printf("«#»\t«#»\t«#»\t«#»",
                n00b_result_get(pos_r),
                rocs_wax_cache_event_tail(
                    rocs_wax_cache_json_string(json, r"event_id")),
                rocs_wax_cache_json_string(json, r"kind"),
                rocs_wax_cache_payload_json(json));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_wax_cache_print_text(n00b_store_t *store, n00b_query_hit_t *hit)
{
    auto json_r = rocs_wax_cache_hit_json(store, hit);
    auto pos_r  = rocs_wax_cache_hit_pos(hit);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(bool, n00b_result_get_err(json_r));
    }
    if (n00b_result_is_err(pos_r)) {
        return n00b_result_err(bool, n00b_result_get_err(pos_r));
    }

    n00b_json_node_t *json = n00b_result_get(json_r);
    n00b_printf("pos=«#» id=«#» kind=«#» json=«#»",
                n00b_result_get(pos_r),
                rocs_wax_cache_event_tail(
                    rocs_wax_cache_json_string(json, r"event_id")),
                rocs_wax_cache_json_string(json, r"kind"),
                rocs_wax_cache_payload_json(json));
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
rocs_wax_cache_print_header(int32_t format)
{
    if (format == ROCS_WAX_CACHE_FORMAT_TABLE) {
        n00b_printf("pos\tid\tkind\tjson");
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
rocs_wax_cache_print_hit(n00b_store_t      *store,
                         n00b_query_hit_t  *hit,
                         int32_t            format)
{
    switch (format) {
    case ROCS_WAX_CACHE_FORMAT_JSONL:
        return rocs_wax_cache_print_jsonl(store, hit);
    case ROCS_WAX_CACHE_FORMAT_TABLE:
        return rocs_wax_cache_print_table(store, hit);
    case ROCS_WAX_CACHE_FORMAT_TEXT:
    default:
        return rocs_wax_cache_print_text(store, hit);
    }
}

n00b_result_t(bool)
rocs_wax_cache_print_result(n00b_store_t        *store,
                            n00b_query_result_t *result,
                            int32_t              format)
{
    auto records_r = n00b_query_records(result);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(bool, n00b_result_get_err(records_r));
    }

    n00b_query_hit_list_t *records = n00b_result_get(records_r);
    size_t                 len     = n00b_list_len(*records);
    auto header_r = rocs_wax_cache_print_header(format);
    if (n00b_result_is_err(header_r)) {
        return header_r;
    }

    if (len == 0 && format != ROCS_WAX_CACHE_FORMAT_JSONL) {
        n00b_printf("(No records)");
    }

    for (size_t i = 0; i < len; i++) {
        n00b_query_hit_t *hit = n00b_list_get(*records, i);
        auto print_r = rocs_wax_cache_print_hit(store, hit, format);
        if (n00b_result_is_err(print_r)) {
            return print_r;
        }
    }

    return n00b_result_ok(bool, true);
}
