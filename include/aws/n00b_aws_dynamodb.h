/**
 * @file aws/n00b_aws_dynamodb.h
 * @brief DynamoDB — the wide-table NoSQL service.
 *
 * Phase 1 of WP-034a establishes:
 *   - the per-Operation wrap pattern for DynamoDB,
 *   - the tagged-union attribute-value surface
 *     (`n00b_aws_ddb_value_t`) that every item-level Operation in
 *     Phases 2-5 consumes / produces,
 *   - the first end-to-end Operation, `DescribeTable`, exercised in
 *     `test/integration/aws/test_dynamodb_smoke.c`.
 *
 * Phases 2-5 extend coverage:
 *   - Phase 2: item ops (Get/Put/Update/Delete + batch + transact).
 *   - Phase 3: Query, Scan, table-level mutators.
 *   - Phase 4: backups, exports, replication, tagging,
 *              contributor-insights, kinesis-streaming.
 *   - Phase 5: PartiQL operations (if 1:1 translatable).
 *
 * Coverage rule (inherited from libn00b_aws): every public
 * Operation in the aws-sdk-dynamodb Smithy model has a wrap before
 * WP-034a closes.  DynamoDBStreams is a separate Smithy service
 * and is OUT of scope for WP-034a.
 *
 * @note **First-call latency.** The Rust shim's tokio runtime
 *       initialises lazily on the first AWS call after process
 *       startup.  On a typical x86-64 / arm64 dev host that adds
 *       ~10–50 ms to the latency of the first call; every
 *       subsequent call (DDB, STS, SQS — runtime is shared across
 *       services) pays only the SDK + network cost.  Pay the cost
 *       once with a cheap warm-up call (e.g.,
 *       `n00b_aws_sts_get_caller_identity`) at program start when
 *       tight first-call latency matters.
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "core/buffer.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "adt/result.h"
#include "aws/n00b_aws.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * Attribute-value tagged union
 *
 * DynamoDB AttributeValues are a tagged union of ten variants.  The
 * n00b-idiomatic mapping uses dynamic n00b types (`n00b_string_t`,
 * `n00b_buffer_t`, `n00b_dict_t`, `n00b_list_t`) instead of fixed
 * caps — there's no protocol-level cap on map / list nesting depth
 * or on string / set sizes beyond the per-item 400 KB limit, which
 * the SDK enforces at the wire boundary.
 *
 * Strings used for type `N` carry the number in canonical
 * DDB textual form — the caller parses to whatever numeric type
 * fits their precision needs.  This matches how `aws-sdk-dynamodb`
 * surfaces the value: as `String`, never as a parsed numeric.
 *
 * Phase 1 declares the type + constructor surface.  Phase 2 (item
 * operations) is the first phase that actually marshals values
 * through this representation on the wire.
 * ------------------------------------------------------------------ */

typedef enum {
    N00B_AWS_DDB_TYPE_S    = 1,
    N00B_AWS_DDB_TYPE_N    = 2,
    N00B_AWS_DDB_TYPE_B    = 3,
    N00B_AWS_DDB_TYPE_BOOL = 4,
    N00B_AWS_DDB_TYPE_NULL = 5,
    N00B_AWS_DDB_TYPE_M    = 6,
    N00B_AWS_DDB_TYPE_L    = 7,
    N00B_AWS_DDB_TYPE_SS   = 8,
    N00B_AWS_DDB_TYPE_NS   = 9,
    N00B_AWS_DDB_TYPE_BS   = 10,
} n00b_aws_ddb_attr_type_t;

typedef struct n00b_aws_ddb_value_t n00b_aws_ddb_value_t;

struct n00b_aws_ddb_value_t {
    n00b_aws_ddb_attr_type_t type;
    union {
        n00b_string_t *s;
        n00b_string_t *n;
        n00b_buffer_t *b;
        bool           bool_;
        n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *m;
        n00b_list_t(n00b_aws_ddb_value_t *)                  *l;
        n00b_list_t(n00b_string_t *)                         *ss;
        n00b_list_t(n00b_string_t *)                         *ns;
        n00b_list_t(n00b_buffer_t *)                         *bs;
    } v;
};

/* Constructor helpers — one per variant.  Each returns a
 * heap-allocated `n00b_aws_ddb_value_t *` ready for placement into a
 * dict / list / item map.  The `_cstr` variants accept a C string
 * convenience input.
 *
 * Allocator threading: every constructor accepts `.allocator` so
 * arena callers control the lifetime of the marshaled tree.
 */

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_s(n00b_string_t *s) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_s_cstr(const char *s) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_n(n00b_string_t *n) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_n_cstr(const char *n) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_b(n00b_buffer_t *b) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_bool(bool v) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an attribute-value representing DynamoDB NULL.
 *
 * No `_kargs` — ncc doesn't accept `_kargs` on zero-positional-arg
 * signatures (same constraint as `n00b_aws_config`).  Callers that
 * need an arena-allocated NULL value can build one manually with
 * `n00b_alloc(n00b_aws_ddb_value_t, .allocator = a)` and assign
 * `.type = N00B_AWS_DDB_TYPE_NULL`.
 */
extern n00b_aws_ddb_value_t *
n00b_aws_ddb_null(void);

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_m(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *m) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_l(n00b_list_t(n00b_aws_ddb_value_t *) *l) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_ss(n00b_list_t(n00b_string_t *) *ss) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_ns(n00b_list_t(n00b_string_t *) *ns) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_aws_ddb_value_t *
n00b_aws_ddb_bs(n00b_list_t(n00b_buffer_t *) *bs) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/* ------------------------------------------------------------------
 * DescribeTable
 * ------------------------------------------------------------------ */

/**
 * @brief One key-schema element (partition or sort key).
 *
 * `key_type` is `r"HASH"` for partition keys, `r"RANGE"` for sort
 * keys.  Returned as a string rather than an enum so future DDB
 * key-type values (none today) surface without ABI changes.
 */
typedef struct {
    n00b_string_t *attribute_name;
    n00b_string_t *key_type;
} n00b_aws_dynamodb_key_schema_element_t;

/**
 * @brief One attribute-definition entry.
 *
 * `attribute_type` is `r"S"` (string), `r"N"` (number), or `r"B"`
 * (binary).
 */
typedef struct {
    n00b_string_t *attribute_name;
    n00b_string_t *attribute_type;
} n00b_aws_dynamodb_attribute_definition_t;

/**
 * @brief Describe-table response payload.
 *
 * Fields default to empty strings / `-1` numerics when absent so
 * callers never need to NULL-check inside the struct.
 *
 * Phase 1 covers the high-traffic TableDescription fields the
 * downstream consumer (WP-034b entitlements-svc) needs; less-used
 * fields (LSI / GSI / Stream specification / replicas / throughput
 * metrics) are added in Phase 4 alongside their sibling Operations.
 */
typedef struct {
    n00b_string_t *table_name;
    /** SDK's `TableStatus::as_str()` — `r"ACTIVE"`, `r"CREATING"`, … */
    n00b_string_t *table_status;
    n00b_string_t *table_arn;
    n00b_string_t *table_id;
    /** Bytes used by the table, or -1 if absent. */
    int64_t        table_size_bytes;
    /** Approximate item count, or -1 if absent. */
    int64_t        item_count;
    /** Table creation time (unix-ms-since-epoch). -1 if absent. */
    int64_t        creation_ms;
    /** `r"PROVISIONED"` / `r"PAY_PER_REQUEST"` / `r""` if absent. */
    n00b_string_t *billing_mode;
    /** 1 = on, 0 = off, -1 = absent in the response. */
    int32_t        deletion_protection_enabled;
    /** SSE description's status: `r"ENABLING"`, `r"ENABLED"`, … */
    n00b_string_t *sse_status;
    n00b_list_t(n00b_aws_dynamodb_key_schema_element_t *)        *key_schema;
    n00b_list_t(n00b_aws_dynamodb_attribute_definition_t *)      *attribute_definitions;
} n00b_aws_dynamodb_describe_table_result_t;

/**
 * @brief Describe an existing DynamoDB table.
 *
 * Returns the table's schema (partition / sort key, attribute
 * definitions, status, billing mode, creation time, size /
 * item-count statistics, etc.).
 *
 * @param cfg          Required. AWS config from `n00b_aws_config(...)`.
 * @param table_name   Required. The table's name.
 *
 * @return `n00b_result_ok(...)` with a populated result on
 *         success; `n00b_result_err(...)` with `N00B_AWS_ERR_NOT_FOUND`
 *         when the table doesn't exist, or the appropriate
 *         `N00B_AWS_ERR_*` for other failures
 *         (NETWORK / SERVICE / THROTTLED / AUTHZ / …).
 *
 * @note **First-call latency.** First AWS call after program start
 *       pays the ~10–50 ms tokio-runtime initialisation cost (see
 *       file-level note).  Subsequent calls amortise that to zero.
 */
extern n00b_result_t(n00b_aws_dynamodb_describe_table_result_t *)
n00b_aws_dynamodb_describe_table(n00b_aws_config_t *cfg,
                                 n00b_string_t     *table_name);

#ifdef __cplusplus
}
#endif
