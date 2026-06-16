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
#include "core/stw.h"
#include "adt/list.h"
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
