/*
 * test_http_json_parquet.c — integrated local landing harness.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "internal/win32_sockets.h"
#define TSOCK SOCKET
#define TBAD  INVALID_SOCKET
#define TCLOSE(s) closesocket((SOCKET)(s))
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define TSOCK int
#define TBAD  (-1)
#define TCLOSE(s) close(s)
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "data/parquet.h"
#include "net/http/http_service.h"
#include "parsers/json.h"
#include "parsers/json_contract.h"

typedef struct {
    n00b_parquet_writer_t *writer;
    n00b_string_t         *path;
    int                    accepted;
} landing_state_t;

static n00b_parquet_column_t landing_columns[] = {
    {.name = "case_name", .type = N00B_PARQUET_UTF8, .nullable = false},
    {.name = "passed", .type = N00B_PARQUET_BOOL, .nullable = false},
    {.name = "duration_us", .type = N00B_PARQUET_I64, .nullable = false},
    {.name = "artifact_id", .type = N00B_PARQUET_UTF8, .nullable = true},
    {.name = "observed_at", .type = N00B_PARQUET_TIMESTAMP_MICROS, .nullable = true},
};

static n00b_string_t *
test_path(const char *suffix)
{
    static int counter = 0;
    const char *tmp = getenv("TMPDIR");
    char path[512];

    if (!tmp || tmp[0] == '\0') {
        tmp = "/tmp";
    }

    snprintf(path,
             sizeof(path),
             "%s/n00b_http_json_parquet_%d_%s.parquet",
             tmp,
             counter++,
             suffix);
    remove(path);
    return n00b_string_from_cstr(path);
}

static bool
send_all(TSOCK fd, const char *p, size_t n)
{
    size_t off = 0;
    while (off < n) {
#ifdef _WIN32
        int rc = send(fd, p + off, (int)(n - off), 0);
#else
        ssize_t rc = send(fd, p + off, n - off, 0);
#endif
        if (rc <= 0) return false;
        off += (size_t)rc;
    }
    return true;
}

static char *
http_round_trip(uint16_t port, const char *request)
{
    TSOCK fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd != TBAD);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(send_all(fd, request, strlen(request)));

    size_t cap = 4096;
    size_t len = 0;
    char  *buf = n00b_alloc_array(char, cap + 1);
    while (true) {
        if (len + 1024 >= cap) {
            cap *= 2;
            char *next = n00b_alloc_array(char, cap + 1);
            memcpy(next, buf, len);
            buf = next;
        }
#ifdef _WIN32
        int rc = recv(fd, buf + len, 1024, 0);
#else
        ssize_t rc = recv(fd, buf + len, 1024, 0);
#endif
        if (rc <= 0) break;
        len += (size_t)rc;
    }
    TCLOSE(fd);
    buf[len] = '\0';
    return buf;
}

static int
status_code(char *resp)
{
    int code = 0;
    assert(sscanf(resp, "HTTP/1.1 %d", &code) == 1);
    return code;
}

static char *
body_ptr(char *resp)
{
    char *p = strstr(resp, "\r\n\r\n");
    assert(p != nullptr);
    return p + 4;
}

static char *
post_request(const char *path, const char *body)
{
    char *req = n00b_alloc_array(char, strlen(body) + 512);

    snprintf(req,
             strlen(body) + 512,
             "POST %s HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             path,
             strlen(body),
             body);
    return req;
}

static void
landing_handler(n00b_http_request_t *req,
                n00b_http_response_writer_t *resp,
                void *user_data)
{
    landing_state_t *state = user_data;
    n00b_buffer_t *body = n00b_http_request_body(req);
    const char *parse_error = nullptr;
    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             body->byte_len,
                                             &parse_error);

    if (!root) {
        n00b_http_response_writer_status(resp, 400);
        n00b_http_response_writer_text(resp, r"bad json");
        return;
    }

    n00b_json_contract_t *contract = n00b_json_contract_new();
    n00b_json_contract_validate(contract,
                                root,
                                r"$",
                                N00B_JSON_CONTRACT_OBJECT);

    n00b_json_node_t *case_name = n00b_json_contract_required(
        contract,
        root,
        r"case_name",
        N00B_JSON_CONTRACT_STRING);
    n00b_json_node_t *passed = n00b_json_contract_required(
        contract,
        root,
        r"passed",
        N00B_JSON_CONTRACT_BOOL);
    n00b_json_node_t *duration = n00b_json_contract_required(
        contract,
        root,
        r"duration_us",
        N00B_JSON_CONTRACT_INT);
    n00b_json_node_t *artifact = n00b_json_contract_optional(
        contract,
        root,
        r"artifact_id",
        N00B_JSON_CONTRACT_STRING,
        n00b_json_null_new(),
        .nullable = true);
    n00b_json_node_t *observed = n00b_json_contract_optional(
        contract,
        root,
        r"observed_at",
        N00B_JSON_CONTRACT_INT,
        n00b_json_null_new(),
        .nullable = true);

    if (!n00b_json_contract_ok(contract)) {
        n00b_http_response_writer_status(resp, 422);
        n00b_http_response_writer_text(resp,
                                       n00b_json_contract_summary(contract));
        return;
    }

    n00b_parquet_value_t row[] = {
        n00b_parquet_cstr(n00b_json_as_cstr(case_name)),
        n00b_parquet_bool(n00b_json_as_bool(passed)),
        n00b_parquet_i64(n00b_json_as_i64(duration)),
        n00b_json_is_null(artifact)
            ? n00b_parquet_null()
            : n00b_parquet_cstr(n00b_json_as_cstr(artifact)),
        n00b_json_is_null(observed)
            ? n00b_parquet_null()
            : n00b_parquet_timestamp_micros(n00b_json_as_i64(observed)),
    };

    auto ar = n00b_parquet_writer_add_row(state->writer, row);
    if (n00b_result_is_err(ar)) {
        n00b_http_response_writer_status(resp, 500);
        n00b_http_response_writer_text(resp, r"parquet add failed");
        return;
    }

    auto wr = n00b_parquet_writer_write_file(state->writer, state->path);
    if (n00b_result_is_err(wr)) {
        n00b_http_response_writer_status(resp, 500);
        n00b_http_response_writer_text(resp, r"parquet write failed");
        return;
    }

    state->accepted++;
    n00b_http_response_writer_status(resp, 202);
    n00b_http_response_writer_text(resp,
                                   r"{\"accepted\":1}",
                                   .content_type = r"application/json");
}

static n00b_http_service_t *
start_landing_service(landing_state_t *state)
{
    n00b_http_service_t *svc = n00b_http_service_new(.bind_port = 0);
    auto rr = n00b_http_service_route(svc,
                                      r"POST",
                                      r"/land",
                                      landing_handler,
                                      state);
    assert(n00b_result_is_ok(rr));
    auto sr = n00b_http_service_start(svc);
    if (n00b_result_is_err(sr)) {
        fprintf(stderr, "http service start failed: err=%d\n",
                n00b_result_get_err(sr));
    }
    assert(n00b_result_is_ok(sr));
    return svc;
}

static void
test_successful_post_lands_parquet(void)
{
    landing_state_t state = {
        .writer = n00b_parquet_writer_new(landing_columns, 5),
        .path   = test_path("success"),
    };
    n00b_http_service_t *svc = start_landing_service(&state);
    char *req = post_request(
        "/land",
        "{\"case_name\":\"unit:parquet\","
        "\"passed\":true,"
        "\"duration_us\":42,"
        "\"artifact_id\":\"sha256:abc\","
        "\"observed_at\":1700000000000001}");
    char *resp = http_round_trip(n00b_http_service_port(svc), req);

    assert(status_code(resp) == 202);
    assert(strcmp(body_ptr(resp), "{\"accepted\":1}") == 0);
    assert(state.accepted == 1);
    n00b_http_service_stop(svc);

    auto rr = n00b_parquet_read_file(state.path, landing_columns, 5);
    assert(n00b_result_is_ok(rr));
    n00b_parquet_table_t *table = n00b_result_get(rr);
    assert(n00b_parquet_table_row_count(table) == 1);
    assert(n00b_parquet_table_value(table, 0, 1)->as.boolean);
    assert(n00b_parquet_table_value(table, 0, 2)->as.i64 == 42);
    assert(n00b_parquet_table_value(table, 0, 3)->as.bytes->byte_len
           == strlen("sha256:abc"));
    assert(n00b_parquet_table_value(table, 0, 4)->as.i64 == 1700000000000001LL);

    remove((const char *)state.path->data);
    printf("  [PASS] successful POST lands Parquet\n");
}

static void
test_bad_json_and_contract_failure(void)
{
    landing_state_t state = {
        .writer = n00b_parquet_writer_new(landing_columns, 5),
        .path   = test_path("reject"),
    };
    n00b_http_service_t *svc = start_landing_service(&state);

    char *resp = http_round_trip(n00b_http_service_port(svc),
                                 post_request("/land", "{"));
    assert(status_code(resp) == 400);

    resp = http_round_trip(n00b_http_service_port(svc),
                           post_request("/land",
                                        "{\"case_name\":\"unit:bad\","
                                        "\"passed\":\"yes\","
                                        "\"duration_us\":10}"));
    assert(status_code(resp) == 422);
    assert(strstr(body_ptr(resp), "passed") != nullptr);
    assert(state.accepted == 0);

    n00b_http_service_stop(svc);
    remove((const char *)state.path->data);
    printf("  [PASS] bad JSON and contract failure rejected\n");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

#ifdef _WIN32
    WSADATA wsa;
    assert(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#endif

    printf("test_http_json_parquet:\n");
    test_successful_post_lands_parquet();
    test_bad_json_and_contract_failure();
    return 0;
}
