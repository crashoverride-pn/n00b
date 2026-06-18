/* src/aws/n00b_aws_dynamodb.c — libn00b_aws's DynamoDB wrap.
 *
 * Phase 1 (WP-026 DynamoDB takeover; ported from WP-034a):
 *   - Constructor helpers for the tagged-union attribute-value type.
 *     Phase 2's item operations are the first to actually transport
 *     these through the shim; Phase 1 declares them so Phase 2
 *     inherits a stable surface.
 *   - End-to-end `DescribeTable` wrap, production-quality (not a
 *     stub).  Phase 3 will NOT re-implement DescribeTable; it will
 *     add sibling table-level operations alongside it.
 *
 * Pattern (per-op, inherited from STS / SQS / SNS on this base):
 *   1. Validate required positional args.
 *   2. Marshal kwargs into the shim's repr(C) input shape.
 *   3. Call the shim (the Tokio runtime blocks on AWS I/O).  No STW
 *      bracketing is needed (WP-001): the GC stop-the-world cycle
 *      preempts a thread blocked in the shim rather than waiting for
 *      it to cooperatively self-park.  (This mirrors n00b_aws_sts.c
 *      on this base, which calls the shim directly.)
 *   4. Translate the shim's repr(C) output into n00b GC-heap structs.
 *   5. Call the shim's matching `_free` function.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/stw.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "adt/result.h"

#include "aws/n00b_aws.h"
#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_dynamodb.h"

#include "n00b_aws_shim_generated.h"
#include "internal/aws/config.h"

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/* Copy an owned C string out of the shim's output (NULL-tolerant). */
static n00b_string_t *
ddb_cstr_to_n00b(char *p)
{
    return n00b_string_from_cstr(p ? p : "");
}

/* =========================================================================
 * Attribute-value constructors
 *
 * Every constructor:
 *   - Allocates the new `n00b_aws_ddb_value_t` from the supplied
 *     allocator (default = runtime allocator via nullptr).
 *   - Sets `.type` and the matching union member.
 *   - Returns the heap pointer.
 *
 * No deep copy of inputs — the constructed value borrows whatever
 * `n00b_string_t *` / `n00b_buffer_t *` / `n00b_dict_t *` /
 * `n00b_list_t *` the caller hands in.  Phase 2's marshaling code
 * is responsible for any ownership transfer / lifetime extension
 * needed at the wire boundary.
 * ========================================================================= */

#define N00B_AWS_DDB_NEW(allocator)                                    \
    n00b_alloc(n00b_aws_ddb_value_t, N00B_ALLOC_OPTS(allocator))

n00b_aws_ddb_value_t *
n00b_aws_ddb_s(n00b_string_t *s) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_S;
    v->v.s  = s ? s : n00b_string_empty();
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_s_cstr(const char *s) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_S;
    v->v.s  = n00b_string_from_cstr(s ? s : "");
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_n(n00b_string_t *n) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_N;
    v->v.n  = n ? n : n00b_string_empty();
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_n_cstr(const char *n) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_N;
    v->v.n  = n00b_string_from_cstr(n ? n : "0");
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_b(n00b_buffer_t *b) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_B;
    v->v.b  = b;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_bool(bool b) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type    = N00B_AWS_DDB_TYPE_BOOL;
    v->v.bool_ = b;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_null(void)
{
    n00b_aws_ddb_value_t *v = n00b_alloc(n00b_aws_ddb_value_t);
    v->type = N00B_AWS_DDB_TYPE_NULL;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_m(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *m) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_M;
    v->v.m  = m;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_l(n00b_list_t(n00b_aws_ddb_value_t *) *l) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_L;
    v->v.l  = l;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_ss(n00b_list_t(n00b_string_t *) *ss) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_SS;
    v->v.ss = ss;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_ns(n00b_list_t(n00b_string_t *) *ns) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_NS;
    v->v.ns = ns;
    return v;
}

n00b_aws_ddb_value_t *
n00b_aws_ddb_bs(n00b_list_t(n00b_buffer_t *) *bs) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_aws_ddb_value_t *v = N00B_AWS_DDB_NEW(allocator);
    v->type = N00B_AWS_DDB_TYPE_BS;
    v->v.bs = bs;
    return v;
}

/* =========================================================================
 * DescribeTable
 * ========================================================================= */

n00b_result_t(n00b_aws_dynamodb_describe_table_result_t *)
n00b_aws_dynamodb_describe_table(n00b_aws_config_t *cfg,
                                 n00b_string_t     *table_name)
{
    if (!cfg || !cfg->shim
        || !table_name || table_name->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_dynamodb_describe_table_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_ddb_describe_table_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_dynamodb_describe_table(cfg->shim,
                                                   table_name->data,
                                                   &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_dynamodb_describe_table_result_t *,
                               rc);
    }

    n00b_aws_dynamodb_describe_table_result_t *out
        = n00b_alloc(n00b_aws_dynamodb_describe_table_result_t);

    out->table_name       = ddb_cstr_to_n00b(raw->table_name);
    out->table_status     = ddb_cstr_to_n00b(raw->table_status);
    out->table_arn        = ddb_cstr_to_n00b(raw->table_arn);
    out->table_id         = ddb_cstr_to_n00b(raw->table_id);
    out->table_size_bytes = raw->table_size_bytes;
    out->item_count       = raw->item_count;
    out->creation_ms      = raw->creation_ms;
    out->billing_mode     = ddb_cstr_to_n00b(raw->billing_mode);
    out->deletion_protection_enabled = raw->deletion_protection_enabled;
    out->sse_status       = ddb_cstr_to_n00b(raw->sse_status);

    /* Key schema list.  Allocate a heap slot for the list struct
     * itself, then assign the freshly-built list value into it —
     * matches the SQS / SNS pattern.  Private (unlocked) is fine:
     * the result struct is owned by the calling thread until the
     * caller publishes it elsewhere. */
    n00b_list_t(n00b_aws_dynamodb_key_schema_element_t *) *ks
        = n00b_alloc(n00b_list_t(n00b_aws_dynamodb_key_schema_element_t *));
    *ks = n00b_list_new_private(n00b_aws_dynamodb_key_schema_element_t *);
    if (raw->key_schema && raw->key_schema_count > 0) {
        for (size_t i = 0; i < raw->key_schema_count; i++) {
            n00b_aws_shim_ddb_key_schema_element_t *src = &raw->key_schema[i];
            n00b_aws_dynamodb_key_schema_element_t *dst
                = n00b_alloc(n00b_aws_dynamodb_key_schema_element_t);
            dst->attribute_name = ddb_cstr_to_n00b(src->attribute_name);
            dst->key_type       = ddb_cstr_to_n00b(src->key_type);
            n00b_list_push(*ks, dst);
        }
    }
    out->key_schema = ks;

    /* Attribute definitions list. */
    n00b_list_t(n00b_aws_dynamodb_attribute_definition_t *) *ad
        = n00b_alloc(n00b_list_t(n00b_aws_dynamodb_attribute_definition_t *));
    *ad = n00b_list_new_private(n00b_aws_dynamodb_attribute_definition_t *);
    if (raw->attribute_definitions && raw->attribute_definitions_count > 0) {
        for (size_t i = 0; i < raw->attribute_definitions_count; i++) {
            n00b_aws_shim_ddb_attribute_definition_t *src
                = &raw->attribute_definitions[i];
            n00b_aws_dynamodb_attribute_definition_t *dst
                = n00b_alloc(n00b_aws_dynamodb_attribute_definition_t);
            dst->attribute_name = ddb_cstr_to_n00b(src->attribute_name);
            dst->attribute_type = ddb_cstr_to_n00b(src->attribute_type);
            n00b_list_push(*ad, dst);
        }
    }
    out->attribute_definitions = ad;

    n00b_aws_shim_dynamodb_describe_table_free(raw);
    return n00b_result_ok(n00b_aws_dynamodb_describe_table_result_t *, out);
}

/* =========================================================================
 * Item operations (Phase 2)
 *
 * Marshaling strategy: an item / key is an
 * `n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *)`.  We flatten it
 * into a contiguous array of `n00b_aws_shim_ddb_attribute_t` (the shim's
 * repr(C) record) for the C→shim direction, and rebuild a fresh dict
 * from the shim's returned array for the shim→C direction.  Scalar
 * variants (S/N/B/BOOL/NULL) are fully supported; the collection
 * variants (M/L/SS/NS/BS) are a documented TODO — `attr_to_shim`
 * signals "unsupported" so the caller fails the op with INVALID_ARG.
 * ========================================================================= */

/* attr_type discriminants — these are exactly n00b_aws_ddb_attr_type_t. */

/* Returns false when the value carries an unsupported (collection)
 * variant, leaving *rec untouched. */
static bool
attr_to_shim(n00b_string_t                   *name,
             n00b_aws_ddb_value_t            *val,
             n00b_aws_shim_ddb_attribute_t   *rec)
{
    rec->name      = (char *)(name ? name->data : "");
    rec->attr_type = (int32_t)val->type;
    rec->s_or_n    = nullptr;
    rec->b         = nullptr;
    rec->b_len     = 0;
    rec->bool_val  = 0;

    switch (val->type) {
    case N00B_AWS_DDB_TYPE_S:
        rec->s_or_n = (char *)(val->v.s ? val->v.s->data : "");
        return true;
    case N00B_AWS_DDB_TYPE_N:
        rec->s_or_n = (char *)(val->v.n ? val->v.n->data : "0");
        return true;
    case N00B_AWS_DDB_TYPE_B:
        if (val->v.b) {
            rec->b     = (uint8_t *)val->v.b->data;
            rec->b_len = (size_t)val->v.b->byte_len;
        }
        return true;
    case N00B_AWS_DDB_TYPE_BOOL:
        rec->bool_val = val->v.bool_ ? 1 : 0;
        return true;
    case N00B_AWS_DDB_TYPE_NULL:
        return true;
    default:
        /* M / L / SS / NS / BS — documented TODO. */
        return false;
    }
}

/* Flatten an item dict into a freshly-allocated shim attribute array.
 * On an unsupported variant sets *ok=false and returns (nullptr, 0). */
typedef struct {
    n00b_aws_shim_ddb_attribute_t *items;
    size_t                         count;
} ddb_attr_array_t;

static ddb_attr_array_t
item_to_shim_array(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *item,
                   bool *ok)
{
    ddb_attr_array_t out = {.items = nullptr, .count = 0};
    *ok                  = true;
    if (!item) {
        return out;
    }
    size_t n = (size_t)n00b_dict_internal_len((_n00b_dict_internal_t *)item);
    if (n == 0) {
        return out;
    }
    out.items = n00b_alloc_array(n00b_aws_shim_ddb_attribute_t, (int64_t)n);
    size_t i  = 0;
    n00b_dict_foreach(item, k, v, {
        if (i < n) {
            if (!attr_to_shim(k, v, &out.items[i])) {
                *ok = false;
            }
            i++;
        }
    });
    out.count = i;
    return out;
}

/* Rebuild one attribute value from a shim record. */
static n00b_aws_ddb_value_t *
shim_to_attr(n00b_aws_shim_ddb_attribute_t *rec)
{
    n00b_aws_ddb_value_t *v = n00b_alloc(n00b_aws_ddb_value_t);
    v->type                 = (n00b_aws_ddb_attr_type_t)rec->attr_type;
    switch ((n00b_aws_ddb_attr_type_t)rec->attr_type) {
    case N00B_AWS_DDB_TYPE_S:
        v->v.s = ddb_cstr_to_n00b(rec->s_or_n);
        break;
    case N00B_AWS_DDB_TYPE_N:
        v->v.n = ddb_cstr_to_n00b(rec->s_or_n);
        break;
    case N00B_AWS_DDB_TYPE_B:
        v->v.b = n00b_buffer_from_bytes((char *)rec->b, (int64_t)rec->b_len);
        break;
    case N00B_AWS_DDB_TYPE_BOOL:
        v->v.bool_ = rec->bool_val != 0;
        break;
    default:
        /* NULL and any collection placeholder the shim down-mapped. */
        v->type = N00B_AWS_DDB_TYPE_NULL;
        break;
    }
    return v;
}

/* Rebuild an item dict from a shim attribute array. */
static n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *
shim_array_to_item(n00b_aws_shim_ddb_attribute_t *arr, size_t count)
{
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *item
        = n00b_dict_new_private(n00b_string_t *, n00b_aws_ddb_value_t *);
    for (size_t i = 0; i < count; i++) {
        n00b_string_t        *name = ddb_cstr_to_n00b(arr[i].name);
        n00b_aws_ddb_value_t *val  = shim_to_attr(&arr[i]);
        n00b_dict_put(item, name, val);
    }
    return item;
}

/* ----------------------------------------------------------------------
 * GetItem
 * ---------------------------------------------------------------------- */
n00b_result_t(n00b_aws_dynamodb_get_item_result_t *)
n00b_aws_dynamodb_get_item(n00b_aws_config_t *cfg, n00b_string_t *table_name,
                           n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key)
    _kargs {
    bool consistent_read = false;
}
{
    if (!cfg || !cfg->shim || !table_name || table_name->u8_bytes == 0 || !key) {
        return n00b_result_err(n00b_aws_dynamodb_get_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok;
    ddb_attr_array_t ka = item_to_shim_array(key, &ok);
    if (!ok || ka.count == 0) {
        return n00b_result_err(n00b_aws_dynamodb_get_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_ddb_get_item_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_dynamodb_get_item(cfg->shim,
                                             table_name->data,
                                             ka.items,
                                             ka.count,
                                             consistent_read ? 1 : 0,
                                             &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_dynamodb_get_item_result_t *, rc);
    }

    n00b_aws_dynamodb_get_item_result_t *out
        = n00b_alloc(n00b_aws_dynamodb_get_item_result_t);
    out->found = raw->found != 0;
    out->item  = shim_array_to_item(raw->item, raw->item_count);

    n00b_aws_shim_dynamodb_get_item_free(raw);
    return n00b_result_ok(n00b_aws_dynamodb_get_item_result_t *, out);
}

/* ----------------------------------------------------------------------
 * PutItem
 * ---------------------------------------------------------------------- */
n00b_result_t(n00b_aws_dynamodb_put_item_result_t *)
n00b_aws_dynamodb_put_item(n00b_aws_config_t *cfg, n00b_string_t *table_name,
                           n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *item)
    _kargs {
    n00b_string_t *condition_expression = nullptr;
}
{
    if (!cfg || !cfg->shim || !table_name || table_name->u8_bytes == 0 || !item) {
        return n00b_result_err(n00b_aws_dynamodb_put_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok;
    ddb_attr_array_t ia = item_to_shim_array(item, &ok);
    if (!ok || ia.count == 0) {
        return n00b_result_err(n00b_aws_dynamodb_put_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    const char *cond = condition_expression ? condition_expression->data : nullptr;

    n00b_aws_shim_ddb_put_item_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_dynamodb_put_item(cfg->shim,
                                             table_name->data,
                                             ia.items,
                                             ia.count,
                                             cond,
                                             &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_dynamodb_put_item_result_t *, rc);
    }

    n00b_aws_dynamodb_put_item_result_t *out
        = n00b_alloc(n00b_aws_dynamodb_put_item_result_t);
    out->ok = raw->ok != 0;
    n00b_aws_shim_dynamodb_put_item_free(raw);
    return n00b_result_ok(n00b_aws_dynamodb_put_item_result_t *, out);
}

/* ----------------------------------------------------------------------
 * DeleteItem
 * ---------------------------------------------------------------------- */
n00b_result_t(n00b_aws_dynamodb_delete_item_result_t *)
n00b_aws_dynamodb_delete_item(n00b_aws_config_t *cfg, n00b_string_t *table_name,
                              n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key)
    _kargs {
    n00b_string_t *condition_expression = nullptr;
}
{
    if (!cfg || !cfg->shim || !table_name || table_name->u8_bytes == 0 || !key) {
        return n00b_result_err(n00b_aws_dynamodb_delete_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok;
    ddb_attr_array_t ka = item_to_shim_array(key, &ok);
    if (!ok || ka.count == 0) {
        return n00b_result_err(n00b_aws_dynamodb_delete_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    const char *cond = condition_expression ? condition_expression->data : nullptr;

    n00b_aws_shim_ddb_delete_item_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_dynamodb_delete_item(cfg->shim,
                                                table_name->data,
                                                ka.items,
                                                ka.count,
                                                cond,
                                                &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_dynamodb_delete_item_result_t *, rc);
    }

    n00b_aws_dynamodb_delete_item_result_t *out
        = n00b_alloc(n00b_aws_dynamodb_delete_item_result_t);
    out->ok = raw->ok != 0;
    n00b_aws_shim_dynamodb_delete_item_free(raw);
    return n00b_result_ok(n00b_aws_dynamodb_delete_item_result_t *, out);
}

/* ----------------------------------------------------------------------
 * UpdateItem
 * ---------------------------------------------------------------------- */
n00b_result_t(n00b_aws_dynamodb_update_item_result_t *)
n00b_aws_dynamodb_update_item(n00b_aws_config_t *cfg, n00b_string_t *table_name,
                              n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key,
                              n00b_string_t *update_expression)
    _kargs {
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *expression_values = nullptr;
    n00b_string_t                                        *condition_expression = nullptr;
}
{
    if (!cfg || !cfg->shim || !table_name || table_name->u8_bytes == 0 || !key
        || !update_expression || update_expression->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_dynamodb_update_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok;
    ddb_attr_array_t ka = item_to_shim_array(key, &ok);
    if (!ok || ka.count == 0) {
        return n00b_result_err(n00b_aws_dynamodb_update_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok_v;
    ddb_attr_array_t va = item_to_shim_array(expression_values, &ok_v);
    if (!ok_v) {
        return n00b_result_err(n00b_aws_dynamodb_update_item_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    const char *cond = condition_expression ? condition_expression->data : nullptr;

    n00b_aws_shim_ddb_update_item_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_dynamodb_update_item(cfg->shim,
                                                table_name->data,
                                                ka.items,
                                                ka.count,
                                                update_expression->data,
                                                va.items,
                                                va.count,
                                                cond,
                                                &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_dynamodb_update_item_result_t *, rc);
    }

    n00b_aws_dynamodb_update_item_result_t *out
        = n00b_alloc(n00b_aws_dynamodb_update_item_result_t);
    out->ok = raw->ok != 0;
    n00b_aws_shim_dynamodb_update_item_free(raw);
    return n00b_result_ok(n00b_aws_dynamodb_update_item_result_t *, out);
}

/* ----------------------------------------------------------------------
 * Query
 * ---------------------------------------------------------------------- */
n00b_result_t(n00b_aws_dynamodb_query_result_t *)
n00b_aws_dynamodb_query(n00b_aws_config_t *cfg, n00b_string_t *table_name,
                        n00b_string_t *key_condition_expression,
                        n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *expression_values)
    _kargs {
    n00b_string_t                                        *index_name = nullptr;
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *exclusive_start_key = nullptr;
    int64_t                                               limit = 0;
}
{
    if (!cfg || !cfg->shim || !table_name || table_name->u8_bytes == 0
        || !key_condition_expression || key_condition_expression->u8_bytes == 0
        || !expression_values) {
        return n00b_result_err(n00b_aws_dynamodb_query_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok_v;
    ddb_attr_array_t va = item_to_shim_array(expression_values, &ok_v);
    if (!ok_v) {
        return n00b_result_err(n00b_aws_dynamodb_query_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    bool             ok_sk;
    ddb_attr_array_t sk = item_to_shim_array(exclusive_start_key, &ok_sk);
    if (!ok_sk) {
        return n00b_result_err(n00b_aws_dynamodb_query_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    const char *index = index_name ? index_name->data : nullptr;

    n00b_aws_shim_ddb_query_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_dynamodb_query(cfg->shim,
                                          table_name->data,
                                          key_condition_expression->data,
                                          va.items,
                                          va.count,
                                          index,
                                          sk.items,
                                          sk.count,
                                          limit,
                                          &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_dynamodb_query_result_t *, rc);
    }

    n00b_aws_dynamodb_query_result_t *out
        = n00b_alloc(n00b_aws_dynamodb_query_result_t);
    out->count = raw->count;

    n00b_list_t(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *) *items
        = n00b_alloc(n00b_list_t(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *));
    *items = n00b_list_new_private(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *);
    for (size_t i = 0; i < raw->items_count; i++) {
        n00b_aws_shim_ddb_item_t *src = &raw->items[i];
        n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *d
            = shim_array_to_item(src->attrs, src->attrs_count);
        n00b_list_push(*items, d);
    }
    out->items = items;

    if (raw->last_key && raw->last_key_count > 0) {
        out->last_evaluated_key
            = shim_array_to_item(raw->last_key, raw->last_key_count);
    }
    else {
        out->last_evaluated_key = nullptr;
    }

    n00b_aws_shim_dynamodb_query_free(raw);
    return n00b_result_ok(n00b_aws_dynamodb_query_result_t *, out);
}
