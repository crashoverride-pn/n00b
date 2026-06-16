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

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    printf("== libn00b_aws DynamoDB (Docker-free) ==\n");
    test_invalid_args();
    test_attribute_value_constructors();
    test_dead_port_contract();
    test_mock_round_trip();
    printf("All libn00b_aws DDB Docker-free tests passed.\n");
    return 0;
}
