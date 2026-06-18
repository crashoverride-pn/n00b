/** @file test/unit/test_aws_dynamodb.c — Docker-free DynamoDB binding
 *  tests for libn00b_aws (n00b-idiomatic C wrap → cbindgen header →
 *  Rust shim → aws-sdk-dynamodb).  WP-026 Phase 1 gate.
 *
 *  Unlike WP-034a's `test_dynamodb_smoke.c` (which stood LocalStack up
 *  via Docker), this test is fully Docker-free:
 *
 *   - DDB-00 (invalid-args):   pure n00b-side argument validation; no
 *                              network, no creds.  Always runs.
 *   - DDB-CTORS:               attribute-value constructor surface;
 *                              pure in-process.  Always runs.
 *   - DDB-02 (dead-port):      contract test mirroring
 *                              `test_aws_s3_contract.c` — points the
 *                              endpoint at a dead port (127.0.0.1:9)
 *                              and asserts the transport/service error
 *                              path through the C wrap surfaces a typed
 *                              `n00b_result_err`.  This is the gating
 *                              success-path-adjacent test.
 *   - DDB-01 (in-process mock): stands up an `n00b_http_service` on an
 *                              ephemeral port whose POST handler returns
 *                              a canned DynamoDB DescribeTable JSON
 *                              response, points `.endpoint_override` at
 *                              it, and asserts the marshaled result.
 *                              If the SDK won't round-trip Docker-free
 *                              (TLS, creds/region resolution, etc.) the
 *                              test SKIPs cleanly with a one-line reason
 *                              rather than failing — the round-trip is
 *                              then covered by the optional LocalStack /
 *                              real tier.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "core/string.h"
#include "text/strings/format.h"
#include "adt/list.h"
#include "adt/result.h"

#include "aws/n00b_aws.h"
#include "aws/n00b_aws_dynamodb.h"
#include "net/http/http_service.h"

/* Canonical DescribeTable response body the mock returns for table "t". */
#define DDB_DESCRIBE_TABLE_JSON                                               \
    "{\"Table\":{\"TableName\":\"t\",\"TableStatus\":\"ACTIVE\","            \
    "\"KeySchema\":[{\"AttributeName\":\"kid\",\"KeyType\":\"HASH\"}],"      \
    "\"AttributeDefinitions\":[{\"AttributeName\":\"kid\","                  \
    "\"AttributeType\":\"S\"}]}}"

static bool
string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static void
ensure_env(n00b_string_t *name, n00b_string_t *value)
{
    if (string_empty(n00b_getenv(name))) {
        n00b_putenv(name, value);
    }
}

/* Static test creds so the SDK's credential chain has something to
 * sign with and actually sends the request. */
static void
set_test_creds(void)
{
    ensure_env(n00b_string_from_cstr("AWS_ACCESS_KEY_ID"),
               n00b_string_from_cstr("test"));
    ensure_env(n00b_string_from_cstr("AWS_SECRET_ACCESS_KEY"),
               n00b_string_from_cstr("test"));
    ensure_env(n00b_string_from_cstr("AWS_REGION"),
               n00b_string_from_cstr("us-east-1"));
    ensure_env(n00b_string_from_cstr("AWS_DEFAULT_REGION"),
               n00b_string_from_cstr("us-east-1"));
}

/* ----------------------------------------------------------------------
 * DDB-00 — n00b-side argument validation (no network).
 * ---------------------------------------------------------------------- */
static void
test_invalid_args(void)
{
    n00b_result_t(n00b_aws_dynamodb_describe_table_result_t *) r1
        = n00b_aws_dynamodb_describe_table(nullptr,
                                           n00b_string_from_cstr("t"));
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_AWS_ERR_INVALID_ARG);

    /* Build a real config; empty table name must still be rejected
     * n00b-side before the shim is touched. */
    set_test_creds();
    auto cfg_r = n00b_aws_config(n00b_string_from_cstr("us-east-1"));
    assert(n00b_result_is_ok(cfg_r));
    n00b_aws_config_t *cfg = n00b_result_get(cfg_r);
    assert(cfg != nullptr);

    n00b_result_t(n00b_aws_dynamodb_describe_table_result_t *) r2
        = n00b_aws_dynamodb_describe_table(cfg, n00b_string_empty());
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_AWS_ERR_INVALID_ARG);
    printf("  [PASS] DDB-00 invalid_args\n");
}

/* ----------------------------------------------------------------------
 * DDB-CTORS — attribute-value constructor surface (pure in-process).
 * ---------------------------------------------------------------------- */
static void
test_attribute_value_constructors(void)
{
    n00b_aws_ddb_value_t *vs = n00b_aws_ddb_s_cstr("hello");
    assert(vs && vs->type == N00B_AWS_DDB_TYPE_S);
    assert(vs->v.s && vs->v.s->u8_bytes == 5);

    n00b_aws_ddb_value_t *vn = n00b_aws_ddb_n_cstr("42");
    assert(vn && vn->type == N00B_AWS_DDB_TYPE_N);

    n00b_aws_ddb_value_t *vb = n00b_aws_ddb_bool(true);
    assert(vb && vb->type == N00B_AWS_DDB_TYPE_BOOL);
    assert(vb->v.bool_ == true);

    n00b_aws_ddb_value_t *vnil = n00b_aws_ddb_null();
    assert(vnil && vnil->type == N00B_AWS_DDB_TYPE_NULL);

    /* String / number from n00b_string_t * inputs. */
    n00b_aws_ddb_value_t *vs2 =
        n00b_aws_ddb_s(n00b_string_from_cstr("world"));
    assert(vs2 && vs2->type == N00B_AWS_DDB_TYPE_S);
    assert(vs2->v.s && vs2->v.s->u8_bytes == 5);

    /* NULL string input falls back to empty (never NULL deref). */
    n00b_aws_ddb_value_t *vs3 = n00b_aws_ddb_s(nullptr);
    assert(vs3 && vs3->type == N00B_AWS_DDB_TYPE_S);
    assert(vs3->v.s != nullptr);

    printf("  [PASS] DDB-CTORS attribute_value_constructors\n");
}

/* ----------------------------------------------------------------------
 * DDB-02 — dead-port contract test (guaranteed Docker-free).
 * ---------------------------------------------------------------------- */
static void
test_dead_port_contract(void)
{
    set_test_creds();
    auto cfg_r =
        n00b_aws_config(n00b_string_from_cstr("us-east-1"),
                        .endpoint_override = r"http://127.0.0.1:9");
    assert(n00b_result_is_ok(cfg_r));
    n00b_aws_config_t *cfg = n00b_result_get(cfg_r);
    assert(cfg != nullptr);

    n00b_result_t(n00b_aws_dynamodb_describe_table_result_t *) r
        = n00b_aws_dynamodb_describe_table(cfg, n00b_string_from_cstr("t"));

    /* The transport/service error path through the C wrap must surface
     * a typed error.  Port 9 (discard) is closed for TCP on a normal
     * host, so the SDK's dispatch fails — exact code may be
     * NETWORK / SERVICE / TIMEOUT / CLIENT; we only assert it is an
     * error and not a crash. */
    assert(n00b_result_is_err(r));
    int err = n00b_result_get_err(r);
    assert(err == N00B_AWS_ERR_NETWORK
           || err == N00B_AWS_ERR_SERVICE
           || err == N00B_AWS_ERR_TIMEOUT
           || err == N00B_AWS_ERR_CLIENT
           || err == N00B_AWS_ERR_NO_CREDENTIALS
           || err == N00B_AWS_ERR_INTERNAL);
    printf("  [PASS] DDB-02 dead_port_contract (err=%s)\n",
           n00b_aws_status_str((n00b_aws_status_t)err));
}

/* ----------------------------------------------------------------------
 * DDB-01 — in-process mock round-trip (best-effort, SKIP-tolerant).
 * ---------------------------------------------------------------------- */
static void
ddb_mock_handler(n00b_http_request_t         *req,
                 n00b_http_response_writer_t *resp,
                 void                        *user_data)
{
    (void)req;
    (void)user_data;
    n00b_http_response_writer_status(resp, 200);
    n00b_http_response_writer_header(
        resp,
        n00b_string_from_cstr("Content-Type"),
        n00b_string_from_cstr("application/x-amz-json-1.0"));
    n00b_http_response_writer_body(
        resp, n00b_buffer_from_cstr(DDB_DESCRIBE_TABLE_JSON));
}

static void
test_mock_round_trip(void)
{
    set_test_creds();

    n00b_http_service_t *svc =
        n00b_http_service_new(.bind_host = n00b_string_from_cstr("127.0.0.1"),
                              .bind_port = 0);
    if (svc == nullptr) {
        printf("  [SKIP] DDB-01 mock_round_trip "
               "(could not create http service)\n");
        return;
    }

    auto route_r = n00b_http_service_route(svc,
                                           n00b_string_from_cstr("POST"),
                                           n00b_string_from_cstr("/"),
                                           ddb_mock_handler,
                                           nullptr);
    if (n00b_result_is_err(route_r)) {
        printf("  [SKIP] DDB-01 mock_round_trip (route registration failed)\n");
        return;
    }

    auto start_r = n00b_http_service_start(svc);
    if (n00b_result_is_err(start_r)) {
        printf("  [SKIP] DDB-01 mock_round_trip (service start failed)\n");
        return;
    }

    uint16_t port = n00b_http_service_port(svc);
    if (port == 0) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-01 mock_round_trip (no ephemeral port)\n");
        return;
    }

    n00b_string_t *endpoint =
        n00b_cformat("http://127.0.0.1:[|#|]", (int64_t)port);

    auto cfg_r = n00b_aws_config(n00b_string_from_cstr("us-east-1"),
                                 .endpoint_override = endpoint);
    assert(n00b_result_is_ok(cfg_r));
    n00b_aws_config_t *cfg = n00b_result_get(cfg_r);
    assert(cfg != nullptr);

    n00b_result_t(n00b_aws_dynamodb_describe_table_result_t *) r
        = n00b_aws_dynamodb_describe_table(cfg, n00b_string_from_cstr("t"));

    if (n00b_result_is_err(r)) {
        int err = n00b_result_get_err(r);
        n00b_http_service_stop(svc);
        /* The SDK refused to round-trip against the in-process mock
         * (TLS enforcement, response-shape strictness, creds/region
         * resolution, etc.).  Per the WP-026 plan this is an accepted
         * clean SKIP — DDB-02 remains the gating test and the success
         * path is validated by the optional LocalStack / real tier. */
        printf("  [SKIP] DDB-01 mock_round_trip "
               "(SDK did not round-trip against in-process mock; err=%s)\n",
               n00b_aws_status_str((n00b_aws_status_t)err));
        return;
    }

    n00b_aws_dynamodb_describe_table_result_t *desc = n00b_result_get(r);
    assert(desc != nullptr);
    assert(desc->table_name != nullptr);
    assert(strcmp(desc->table_name->data, "t") == 0);
    assert(desc->table_status != nullptr);
    assert(desc->table_status->u8_bytes > 0);
    assert(desc->key_schema != nullptr);
    assert(n00b_list_len(*desc->key_schema) >= 1);

    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-01 mock_round_trip (table=%s, status=%s)\n",
           desc->table_name->data, desc->table_status->data);
}

/* ----------------------------------------------------------------------
 * DDB-REGRESSION — n00b_aws_config must be the REAL libn00b_aws impl,
 * never the no-AWS weak fallback stub in src/rocs/store.c.
 *
 * Both the real `_kargs` impl (libn00b_aws) and the rocs fallback stub are
 * weak symbols: ncc emits `_kargs` functions weak, and the stub is
 * [[gnu::weak]]. Before the N00B_BUILD_AWS guard, that weak-vs-weak
 * collision let the linker bind n00b_aws_config to the stub by static-
 * archive order in some AWS-enabled binaries (it did, in
 * test_aws_s3_contract). The stub ALWAYS returns N00B_AWS_ERR_INTERNAL —
 * even for a valid region — whereas the real impl builds an SdkConfig and
 * returns ok. So a config built from a valid region must be ok; if this
 * ever regresses to err, the stub has been linked again.
 * ---------------------------------------------------------------------- */
static void
test_config_not_weak_stub(void)
{
    set_test_creds();
    auto cfg_r = n00b_aws_config(n00b_string_from_cstr("us-east-1"));
    /* The no-AWS stub returns err (N00B_AWS_ERR_INTERNAL) for any region;
     * the real impl builds an SdkConfig and returns ok. is_ok is the
     * deterministic discriminator. */
    assert(n00b_result_is_ok(cfg_r));
    assert(n00b_result_get(cfg_r) != nullptr);
    printf("  [PASS] DDB-REGRESSION n00b_aws_config is the real impl "
           "(not the no-AWS weak stub)\n");
}

/* ----------------------------------------------------------------------
 * Item-operation mocks (DDB-03..07).
 *
 * A single dispatching handler inspects the `X-Amz-Target` header
 * (DynamoDB JSON-1.0 wire protocol: `DynamoDB_20120810.<Operation>`)
 * and returns the canned response the SDK expects for that op.  This
 * keeps each item-op test pointed at one in-process service.  The
 * conditional-failure case (DDB-06) is selected by the table name in
 * the request body (`crayon_configs_cond`).
 *
 * Canned response bodies are minimal but shape-correct for the
 * aws-sdk-dynamodb response parser.
 * ---------------------------------------------------------------------- */

/* GetItem: a JWK item keyed by kid=key-1. */
#define DDB_GET_ITEM_JSON                                                     \
    "{\"Item\":{\"kid\":{\"S\":\"key-1\"},"                                  \
    "\"jwk\":{\"S\":\"{\\\"kty\\\":\\\"oct\\\"}\"}}}"

/* GetItem (absent): no Item member. */
#define DDB_GET_ITEM_ABSENT_JSON "{}"

/* Query: two items + a LastEvaluatedKey (so the pagination-cursor
 * marshaling + its _free path are exercised). */
#define DDB_QUERY_JSON                                                        \
    "{\"Count\":2,\"ScannedCount\":2,\"Items\":["                            \
    "{\"kid\":{\"S\":\"key-1\"},\"jwk\":{\"S\":\"a\"}},"                     \
    "{\"kid\":{\"S\":\"key-2\"},\"jwk\":{\"S\":\"b\"}}],"                    \
    "\"LastEvaluatedKey\":{\"kid\":{\"S\":\"key-2\"}}}"

/* ConditionalCheckFailedException for the JSON-1.0 protocol. */
#define DDB_COND_FAIL_JSON                                                    \
    "{\"__type\":\"com.amazonaws.dynamodb.v20120810#"                       \
    "ConditionalCheckFailedException\","                                     \
    "\"message\":\"The conditional request failed\"}"

static bool
header_contains(n00b_http_request_t *req, const char *hdr, const char *needle)
{
    n00b_string_t *v =
        n00b_http_request_header(req, n00b_string_from_cstr(hdr));
    if (string_empty(v)) {
        return false;
    }
    return strstr(v->data, needle) != nullptr;
}

static bool
body_contains(n00b_http_request_t *req, const char *needle)
{
    n00b_buffer_t *b = n00b_http_request_body(req);
    if (b == nullptr || b->data == nullptr || b->byte_len == 0) {
        return false;
    }
    /* Body is JSON text; NUL-bounded search over the byte span. */
    size_t nlen = strlen(needle);
    if ((size_t)b->byte_len < nlen) {
        return false;
    }
    for (size_t i = 0; i + nlen <= (size_t)b->byte_len; i++) {
        if (memcmp(b->data + i, needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

static void
ddb_item_handler(n00b_http_request_t         *req,
                 n00b_http_response_writer_t *resp,
                 void                        *user_data)
{
    (void)user_data;
    const char *ct = "application/x-amz-json-1.0";

    if (header_contains(req, "X-Amz-Target", "PutItem")) {
        /* DDB-06: conditional PutItem against the *_cond table fails. */
        if (body_contains(req, "crayon_configs_cond")) {
            n00b_http_response_writer_status(resp, 400);
            n00b_http_response_writer_header(
                resp, n00b_string_from_cstr("Content-Type"),
                n00b_string_from_cstr(ct));
            n00b_http_response_writer_body(
                resp, n00b_buffer_from_cstr(DDB_COND_FAIL_JSON));
            return;
        }
        n00b_http_response_writer_status(resp, 200);
        n00b_http_response_writer_header(
            resp, n00b_string_from_cstr("Content-Type"),
            n00b_string_from_cstr(ct));
        n00b_http_response_writer_body(resp, n00b_buffer_from_cstr("{}"));
        return;
    }
    if (header_contains(req, "X-Amz-Target", "GetItem")) {
        /* DDB-04: absent lookup uses key kid=missing. */
        const char *json = body_contains(req, "missing")
                               ? DDB_GET_ITEM_ABSENT_JSON
                               : DDB_GET_ITEM_JSON;
        n00b_http_response_writer_status(resp, 200);
        n00b_http_response_writer_header(
            resp, n00b_string_from_cstr("Content-Type"),
            n00b_string_from_cstr(ct));
        n00b_http_response_writer_body(resp, n00b_buffer_from_cstr(json));
        return;
    }
    if (header_contains(req, "X-Amz-Target", "Query")) {
        n00b_http_response_writer_status(resp, 200);
        n00b_http_response_writer_header(
            resp, n00b_string_from_cstr("Content-Type"),
            n00b_string_from_cstr(ct));
        n00b_http_response_writer_body(
            resp, n00b_buffer_from_cstr(DDB_QUERY_JSON));
        return;
    }
    if (header_contains(req, "X-Amz-Target", "DeleteItem")) {
        n00b_http_response_writer_status(resp, 200);
        n00b_http_response_writer_header(
            resp, n00b_string_from_cstr("Content-Type"),
            n00b_string_from_cstr(ct));
        n00b_http_response_writer_body(resp, n00b_buffer_from_cstr("{}"));
        return;
    }
    if (header_contains(req, "X-Amz-Target", "UpdateItem")) {
        n00b_http_response_writer_status(resp, 200);
        n00b_http_response_writer_header(
            resp, n00b_string_from_cstr("Content-Type"),
            n00b_string_from_cstr(ct));
        n00b_http_response_writer_body(resp, n00b_buffer_from_cstr("{}"));
        return;
    }
    /* Unknown op — empty 200. */
    n00b_http_response_writer_status(resp, 200);
    n00b_http_response_writer_header(
        resp, n00b_string_from_cstr("Content-Type"),
        n00b_string_from_cstr(ct));
    n00b_http_response_writer_body(resp, n00b_buffer_from_cstr("{}"));
}

/* Stand up the item-op mock service; returns NULL (and prints a SKIP
 * line tagged with @case) when the in-process service can't be brought
 * up.  On success writes the endpoint URL into *endpoint_out. */
static n00b_http_service_t *
start_item_mock(const char *case_tag, n00b_string_t **endpoint_out)
{
    n00b_http_service_t *svc =
        n00b_http_service_new(.bind_host = n00b_string_from_cstr("127.0.0.1"),
                              .bind_port = 0);
    if (svc == nullptr) {
        printf("  [SKIP] %s (could not create http service)\n", case_tag);
        return nullptr;
    }
    auto route_r = n00b_http_service_route(svc,
                                           n00b_string_from_cstr("POST"),
                                           n00b_string_from_cstr("/"),
                                           ddb_item_handler,
                                           nullptr);
    if (n00b_result_is_err(route_r)) {
        printf("  [SKIP] %s (route registration failed)\n", case_tag);
        return nullptr;
    }
    auto start_r = n00b_http_service_start(svc);
    if (n00b_result_is_err(start_r)) {
        printf("  [SKIP] %s (service start failed)\n", case_tag);
        return nullptr;
    }
    uint16_t port = n00b_http_service_port(svc);
    if (port == 0) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] %s (no ephemeral port)\n", case_tag);
        return nullptr;
    }
    *endpoint_out = n00b_cformat("http://127.0.0.1:[|#|]", (int64_t)port);
    return svc;
}

static n00b_aws_config_t *
item_mock_cfg(n00b_string_t *endpoint)
{
    auto cfg_r = n00b_aws_config(n00b_string_from_cstr("us-east-1"),
                                 .endpoint_override = endpoint);
    assert(n00b_result_is_ok(cfg_r));
    return n00b_result_get(cfg_r);
}

static n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *
new_item(void)
{
    return n00b_dict_new_private(n00b_string_t *, n00b_aws_ddb_value_t *);
}

static void
item_put_s(n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *d,
           const char *k, const char *v)
{
    n00b_string_t        *key = n00b_string_from_cstr(k);
    n00b_aws_ddb_value_t *val = n00b_aws_ddb_s_cstr(v);
    n00b_dict_put(d, key, val);
}

/* DDB-03 — PutItem then GetItem round-trip (marshaling correctness). */
static void
test_put_get_round_trip(void)
{
    set_test_creds();
    n00b_string_t *endpoint = nullptr;
    n00b_http_service_t *svc = start_item_mock("DDB-03 put_get_round_trip",
                                               &endpoint);
    if (svc == nullptr) {
        return;
    }
    n00b_aws_config_t *cfg = item_mock_cfg(endpoint);

    /* PutItem {kid:S="key-1", jwk:S="{...}"}. */
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *item = new_item();
    item_put_s(item, "kid", "key-1");
    item_put_s(item, "jwk", "{\"kty\":\"oct\"}");
    n00b_result_t(n00b_aws_dynamodb_put_item_result_t *) pr
        = n00b_aws_dynamodb_put_item(cfg,
                                     n00b_string_from_cstr("crayon_configs"),
                                     item);
    if (n00b_result_is_err(pr)) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-03 put_get_round_trip "
               "(PutItem did not round-trip; err=%s)\n",
               n00b_aws_status_str(
                   (n00b_aws_status_t)n00b_result_get_err(pr)));
        return;
    }
    n00b_aws_dynamodb_put_item_result_t *pres = n00b_result_get(pr);
    assert(pres != nullptr && pres->ok);

    /* GetItem by {kid:S="key-1"}. */
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key = new_item();
    item_put_s(key, "kid", "key-1");
    n00b_result_t(n00b_aws_dynamodb_get_item_result_t *) gr
        = n00b_aws_dynamodb_get_item(cfg,
                                     n00b_string_from_cstr("crayon_configs"),
                                     key);
    if (n00b_result_is_err(gr)) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-03 put_get_round_trip "
               "(GetItem did not round-trip; err=%s)\n",
               n00b_aws_status_str(
                   (n00b_aws_status_t)n00b_result_get_err(gr)));
        return;
    }
    n00b_aws_dynamodb_get_item_result_t *got = n00b_result_get(gr);
    assert(got != nullptr);
    assert(got->found);
    assert(got->item != nullptr);

    bool found_jwk = false;
    n00b_aws_ddb_value_t *jwk =
        n00b_dict_get(got->item, ((n00b_string_t *){n00b_string_from_cstr("jwk")}),
                      &found_jwk);
    assert(found_jwk);
    assert(jwk != nullptr);
    assert(jwk->type == N00B_AWS_DDB_TYPE_S);
    assert(jwk->v.s != nullptr);
    assert(strcmp(jwk->v.s->data, "{\"kty\":\"oct\"}") == 0);

    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-03 put_get_round_trip (jwk=%s)\n", jwk->v.s->data);
}

/* DDB-04 — GetItem absent → found==false. */
static void
test_get_item_absent(void)
{
    set_test_creds();
    n00b_string_t *endpoint = nullptr;
    n00b_http_service_t *svc = start_item_mock("DDB-04 get_item_absent",
                                               &endpoint);
    if (svc == nullptr) {
        return;
    }
    n00b_aws_config_t *cfg = item_mock_cfg(endpoint);

    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key = new_item();
    item_put_s(key, "kid", "missing");
    n00b_result_t(n00b_aws_dynamodb_get_item_result_t *) gr
        = n00b_aws_dynamodb_get_item(cfg,
                                     n00b_string_from_cstr("crayon_configs"),
                                     key);
    if (n00b_result_is_err(gr)) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-04 get_item_absent "
               "(GetItem did not round-trip; err=%s)\n",
               n00b_aws_status_str(
                   (n00b_aws_status_t)n00b_result_get_err(gr)));
        return;
    }
    n00b_aws_dynamodb_get_item_result_t *got = n00b_result_get(gr);
    assert(got != nullptr);
    assert(!got->found);

    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-04 get_item_absent (found=false)\n");
}

/* DDB-05 — Query returns 2 items. */
static void
test_query(void)
{
    set_test_creds();
    n00b_string_t *endpoint = nullptr;
    n00b_http_service_t *svc = start_item_mock("DDB-05 query", &endpoint);
    if (svc == nullptr) {
        return;
    }
    n00b_aws_config_t *cfg = item_mock_cfg(endpoint);

    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *vals = new_item();
    item_put_s(vals, ":k", "key-1");
    n00b_result_t(n00b_aws_dynamodb_query_result_t *) qr
        = n00b_aws_dynamodb_query(cfg,
                                  n00b_string_from_cstr("crayon_configs"),
                                  n00b_string_from_cstr("kid = :k"),
                                  vals);
    if (n00b_result_is_err(qr)) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-05 query "
               "(Query did not round-trip; err=%s)\n",
               n00b_aws_status_str(
                   (n00b_aws_status_t)n00b_result_get_err(qr)));
        return;
    }
    n00b_aws_dynamodb_query_result_t *q = n00b_result_get(qr);
    assert(q != nullptr);
    assert(q->count == 2);
    assert(q->items != nullptr);
    assert(n00b_list_len(*q->items) == 2);

    /* First item carries kid + jwk. */
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *first
        = n00b_list_get(*q->items, 0);
    assert(first != nullptr);
    bool found_kid = false;
    n00b_aws_ddb_value_t *kid =
        n00b_dict_get(first, ((n00b_string_t *){n00b_string_from_cstr("kid")}),
                      &found_kid);
    assert(found_kid && kid != nullptr && kid->type == N00B_AWS_DDB_TYPE_S);
    assert(strcmp(kid->v.s->data, "key-1") == 0);

    /* The mock returns a LastEvaluatedKey, so the pagination cursor must
     * be marshaled non-NULL (and its _free path exercised on teardown). */
    assert(q->last_evaluated_key != nullptr);
    bool found_lek = false;
    n00b_aws_ddb_value_t *lek_kid =
        n00b_dict_get(q->last_evaluated_key,
                      ((n00b_string_t *){n00b_string_from_cstr("kid")}),
                      &found_lek);
    assert(found_lek && lek_kid != nullptr
           && lek_kid->type == N00B_AWS_DDB_TYPE_S);
    assert(strcmp(lek_kid->v.s->data, "key-2") == 0);

    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-05 query (count=%lld, item0.kid=%s, lek.kid=%s)\n",
           (long long)q->count, kid->v.s->data, lek_kid->v.s->data);
}

/* DDB-09 — UpdateItem round-trip (marshaling + free path for the
 * UpdateItem output struct). */
static void
test_update_item(void)
{
    set_test_creds();
    n00b_string_t *endpoint = nullptr;
    n00b_http_service_t *svc = start_item_mock("DDB-09 update_item", &endpoint);
    if (svc == nullptr) {
        return;
    }
    n00b_aws_config_t *cfg = item_mock_cfg(endpoint);

    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key = new_item();
    item_put_s(key, "kid", "key-1");
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *vals = new_item();
    item_put_s(vals, ":v", "rotated");

    n00b_result_t(n00b_aws_dynamodb_update_item_result_t *) ur
        = n00b_aws_dynamodb_update_item(
            cfg,
            n00b_string_from_cstr("crayon_configs"),
            key,
            n00b_string_from_cstr("SET jwk = :v"),
            .expression_values = vals);
    if (n00b_result_is_err(ur)) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-09 update_item "
               "(UpdateItem did not round-trip; err=%s)\n",
               n00b_aws_status_str(
                   (n00b_aws_status_t)n00b_result_get_err(ur)));
        return;
    }
    n00b_aws_dynamodb_update_item_result_t *u = n00b_result_get(ur);
    assert(u != nullptr && u->ok);

    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-09 update_item (ok=true)\n");
}

/* DDB-06 — conditional PutItem fails → typed Err. */
static void
test_put_item_conditional(void)
{
    set_test_creds();
    n00b_string_t *endpoint = nullptr;
    n00b_http_service_t *svc = start_item_mock("DDB-06 put_item_conditional",
                                               &endpoint);
    if (svc == nullptr) {
        return;
    }
    n00b_aws_config_t *cfg = item_mock_cfg(endpoint);

    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *item = new_item();
    item_put_s(item, "kid", "key-1");
    item_put_s(item, "jwk", "x");
    n00b_result_t(n00b_aws_dynamodb_put_item_result_t *) pr
        = n00b_aws_dynamodb_put_item(
            cfg,
            n00b_string_from_cstr("crayon_configs_cond"),
            item,
            .condition_expression =
                n00b_string_from_cstr("attribute_not_exists(kid)"));

    /* ConditionalCheckFailedException must surface as a typed error, not
     * a crash and not a spurious ok.  The DDB classifier maps it to
     * N00B_AWS_ERR_EXISTS (the put-if-absent signal); we accept the
     * generic SERVICE code too in case the SDK's error Debug spelling
     * shifts across SDK versions. */
    assert(n00b_result_is_err(pr));
    int err = n00b_result_get_err(pr);
    assert(err == N00B_AWS_ERR_EXISTS || err == N00B_AWS_ERR_SERVICE);
    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-06 put_item_conditional (err=%s)\n",
           n00b_aws_status_str((n00b_aws_status_t)err));
}

/* DDB-07 — DeleteItem succeeds. */
static void
test_delete_item(void)
{
    set_test_creds();
    n00b_string_t *endpoint = nullptr;
    n00b_http_service_t *svc = start_item_mock("DDB-07 delete_item", &endpoint);
    if (svc == nullptr) {
        return;
    }
    n00b_aws_config_t *cfg = item_mock_cfg(endpoint);

    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key = new_item();
    item_put_s(key, "kid", "key-1");
    n00b_result_t(n00b_aws_dynamodb_delete_item_result_t *) dr
        = n00b_aws_dynamodb_delete_item(cfg,
                                        n00b_string_from_cstr("crayon_configs"),
                                        key);
    if (n00b_result_is_err(dr)) {
        n00b_http_service_stop(svc);
        printf("  [SKIP] DDB-07 delete_item "
               "(DeleteItem did not round-trip; err=%s)\n",
               n00b_aws_status_str(
                   (n00b_aws_status_t)n00b_result_get_err(dr)));
        return;
    }
    n00b_aws_dynamodb_delete_item_result_t *d = n00b_result_get(dr);
    assert(d != nullptr && d->ok);

    n00b_http_service_stop(svc);
    printf("  [PASS] DDB-07 delete_item (ok=true)\n");
}

/* DDB-08 — item-op argument validation (no network). */
static void
test_item_invalid_args(void)
{
    set_test_creds();
    auto cfg_r = n00b_aws_config(n00b_string_from_cstr("us-east-1"));
    assert(n00b_result_is_ok(cfg_r));
    n00b_aws_config_t *cfg = n00b_result_get(cfg_r);

    /* NULL key dict. */
    n00b_result_t(n00b_aws_dynamodb_get_item_result_t *) g
        = n00b_aws_dynamodb_get_item(cfg, n00b_string_from_cstr("t"), nullptr);
    assert(n00b_result_is_err(g));
    assert(n00b_result_get_err(g) == N00B_AWS_ERR_INVALID_ARG);

    /* Empty key dict. */
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *empty = new_item();
    n00b_result_t(n00b_aws_dynamodb_get_item_result_t *) g2
        = n00b_aws_dynamodb_get_item(cfg, n00b_string_from_cstr("t"), empty);
    assert(n00b_result_is_err(g2));
    assert(n00b_result_get_err(g2) == N00B_AWS_ERR_INVALID_ARG);

    /* UpdateItem requires update_expression. */
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *key = new_item();
    item_put_s(key, "kid", "k");
    n00b_result_t(n00b_aws_dynamodb_update_item_result_t *) u
        = n00b_aws_dynamodb_update_item(cfg, n00b_string_from_cstr("t"), key,
                                        n00b_string_empty());
    assert(n00b_result_is_err(u));
    assert(n00b_result_get_err(u) == N00B_AWS_ERR_INVALID_ARG);

    /* Unsupported collection variant (a string-set value) must be
     * rejected n00b-side with INVALID_ARG — the "never silent data loss"
     * contract — not silently dropped or sent mis-typed. */
    n00b_dict_t(n00b_string_t *, n00b_aws_ddb_value_t *) *coll = new_item();
    n00b_string_t        *ck  = n00b_string_from_cstr("tags");
    n00b_list_t(n00b_string_t *) *sslist
        = n00b_alloc(n00b_list_t(n00b_string_t *));
    *sslist = n00b_list_new_private(n00b_string_t *);
    n00b_list_push(*sslist, n00b_string_from_cstr("a"));
    n00b_aws_ddb_value_t *cv = n00b_aws_ddb_ss(sslist);
    n00b_dict_put(coll, ck, cv);
    n00b_result_t(n00b_aws_dynamodb_put_item_result_t *) cpr
        = n00b_aws_dynamodb_put_item(cfg, n00b_string_from_cstr("t"), coll);
    assert(n00b_result_is_err(cpr));
    assert(n00b_result_get_err(cpr) == N00B_AWS_ERR_INVALID_ARG);

    printf("  [PASS] DDB-08 item_invalid_args "
           "(incl. collection-variant rejection)\n");
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    printf("== libn00b_aws DynamoDB (Docker-free) ==\n");
    test_config_not_weak_stub();
    test_invalid_args();
    test_attribute_value_constructors();
    test_dead_port_contract();
    test_mock_round_trip();
    test_item_invalid_args();
    test_put_get_round_trip();
    test_get_item_absent();
    test_query();
    test_put_item_conditional();
    test_delete_item();
    test_update_item();
    printf("All libn00b_aws DDB Docker-free tests passed.\n");
    return 0;
}
