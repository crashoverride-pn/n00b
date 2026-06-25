/* src/clickhouse/n00b_clickhouse_query.c — wire-layer exec + query
 * helpers for libn00b_clickhouse.
 *
 * The transport is `n00b_http_request_sync` with `allow_plain_http`
 * set so the default ClickHouse port (8123) works without TLS. HTTPS
 * URLs route through the same call without the plain-http opt-in.
 * Responses are byte-for-byte exposed to the caller; ClickHouse
 * negotiates the format via FORMAT clauses in the SQL itself, so the
 * substrate stays format-agnostic.
 */

#include "n00b.h"
#include "clickhouse/n00b_clickhouse.h"
#include "internal/clickhouse/client.h"

#include "conduit/print.h"
#include "core/buffer.h"
#include "core/string.h"
#include "net/http/http_client.h"
#include "text/strings/format.h"

/* Percent-encode every byte that isn't an "unreserved" URI character per
 * RFC 3986 §2.3. The set is intentionally narrow — ClickHouse passwords
 * tend to contain `+`, `&`, and `=`, all of which are valid inside an
 * unreserved-set-only encoder but lethal in a raw query string.
 *
 * Mirrors the `url_encode` helper in `src/attest/oci/registry.c`: same
 * raw-byte loop, same `alloc_for_call` threading idiom (D-045). Both
 * could share an `n00b_uri_percent_encode` helper at some point — for
 * now they intentionally stay narrow and per-module. */
static n00b_string_t *
percent_encode(const n00b_string_t *raw, n00b_allocator_t *alloc_for_call)
{
    if (!raw || raw->u8_bytes == 0) {
        return n00b_string_empty(.allocator = alloc_for_call);
    }
    static const char    hex[] = "0123456789ABCDEF";
    const unsigned char *src   = (const unsigned char *)raw->data;
    size_t               n     = raw->u8_bytes;
    char                *buf   = n00b_alloc_array_with_opts(
        char,
        n * 3 + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    size_t out = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c          = src[i];
        bool          unreserved = (c >= 'A' && c <= 'Z')
                       || (c >= 'a' && c <= 'z')
                       || (c >= '0' && c <= '9')
                       || c == '-' || c == '.' || c == '_' || c == '~';
        if (unreserved) {
            buf[out++] = (char)c;
        }
        else {
            buf[out++] = '%';
            buf[out++] = hex[c >> 4];
            buf[out++] = hex[c & 0x0F];
        }
    }
    buf[out] = '\0';
    return n00b_string_from_raw(buf, (int64_t)out, .allocator = alloc_for_call);
}

static n00b_string_t *
build_endpoint(const n00b_clickhouse_client_t *client)
{
    n00b_allocator_t *alloc_for_call = client->allocator;
    n00b_string_t    *scheme = client->https ? r"https" : r"http";
    n00b_string_t    *base   = n00b_cformat("[|#|]://[|#|]:[|#|]/",
                                       scheme,
                                       client->host,
                                       (int64_t)client->port);
    if (!client->username || !client->password) {
        return base;
    }
    n00b_string_t *user = percent_encode(client->username, alloc_for_call);
    n00b_string_t *pass = percent_encode(client->password, alloc_for_call);
    return n00b_cformat("[|#|]?user=[|#|]&password=[|#|]", base, user, pass);
}

static n00b_clickhouse_status_t
post_query(const n00b_clickhouse_client_t *client,
           n00b_string_t                  *sql,
           n00b_string_t                 **out_body)
{
    if (out_body) {
        *out_body = nullptr;
    }
    if (!client || !sql) {
        return N00B_CLICKHOUSE_ERR_INVALID_ARG;
    }

    n00b_string_t *url = build_endpoint(client);
    n00b_buffer_t *body = n00b_buffer_from_bytes(
        sql->data,
        (int64_t)sql->u8_bytes);

    n00b_string_t *method       = r"POST";
    n00b_string_t *content_type = n00b_string_from_cstr(
        "text/plain; charset=utf-8");

    auto request_result = n00b_http_request_sync(
        url,
        .method           = method,
        .body             = body,
        .content_type     = content_type,
        /* ClickHouse's HTTP API is HTTP/1.1 only — neither ClickHouse
         * Cloud nor self-hosted setups advertise h3 on the HTTP API
         * port, so letting n00b's default `prefer_h3` win burns ~1.5s
         * per request on a doomed handshake and has been observed to
         * leave stale entries in the connection pool that fail every
         * subsequent call once the server closes its keep-alive. */
        .prefer_h3        = false,
        .allow_plain_http = !client->https);

    if (n00b_result_is_err(request_result)) {
        /* Surface the actual transport error so callers can see
         * the difference between "TLS failed", "connection refused",
         * "DNS failed", etc. without a separate logging pass. */
        n00b_eprintf("[clickhouse] HTTP transport error [|#|] for [|#|]",
                     (int64_t)n00b_result_get_err(request_result),
                     url);
        return N00B_CLICKHOUSE_ERR_HTTP;
    }

    n00b_http_response_t *resp   = n00b_result_get(request_result);
    int                   status = n00b_http_response_status(resp);
    n00b_buffer_t        *raw    = n00b_http_response_body(resp);
    n00b_string_t        *resp_text = raw ? n00b_buffer_to_string(raw)
                                          : n00b_string_empty();

    if (out_body) {
        *out_body = resp_text;
    }

    if (status == 0) {
        n00b_eprintf("[clickhouse] HTTP response had status 0 for [|#|]",
                     url);
        return N00B_CLICKHOUSE_ERR_HTTP;
    }
    if (status < 200 || status >= 300) {
        return N00B_CLICKHOUSE_ERR_STATUS;
    }
    return N00B_CLICKHOUSE_OK;
}

n00b_clickhouse_status_t
n00b_clickhouse_exec(n00b_clickhouse_client_t *client,
                     n00b_string_t            *sql)
{
    n00b_string_t *unused = nullptr;
    return post_query(client, sql, &unused);
}

n00b_clickhouse_status_t
n00b_clickhouse_query(n00b_clickhouse_client_t *client,
                      n00b_string_t            *sql,
                      n00b_string_t           **out_body)
{
    return post_query(client, sql, out_body);
}
