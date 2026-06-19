/*
 * http_auth.c — HTTP auth helper (Phase 6 chunk 10).
 *
 * Builds the Authorization + DPoP headers from the n00b_http_auth_t
 * struct and merges with any caller-supplied headers.  mTLS is just
 * captured on the struct here; the actual TLS-cert plumbing into
 * the h1/h3 transports lands in chunks 11/12.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "crypto/dpop.h"
#include "net/http/http_auth.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_h1.h"

/* ----------------------------------------------------------------- */
/* Helpers                                                           */
/* ----------------------------------------------------------------- */

static n00b_allocator_t *
default_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
build_authorization(n00b_buffer_t *bearer, n00b_allocator_t *a)
{
    static const char prefix[] = "Bearer ";
    size_t plen = sizeof(prefix) - 1;
    size_t blen = (size_t)bearer->byte_len;
    char  *out  = n00b_alloc_array(char, plen + blen + 1, .allocator = a);
    memcpy(out, prefix, plen);
    memcpy(out + plen, bearer->data, blen);
    out[plen + blen] = '\0';
    return out;
}

/* Build the `htu` claim — absolute URL minus query / fragment.  RFC
 * 9449 § 4.2: `htu` is the request-URI's "URL without query and
 * fragment". */
static char *
build_htu(n00b_http_url_t *url, n00b_allocator_t *a)
{
    /* origin already carries `https://host[:port]`; append the
     * path with no query. */
    const char *path  = (url->path && url->path->u8_bytes)
                            ? url->path->data : "/";
    size_t      plen  = (url->path && url->path->u8_bytes)
                            ? (size_t)url->path->u8_bytes : 1;
    size_t      total = url->origin->u8_bytes + plen;
    char       *out   = n00b_alloc_array(char, total + 1, .allocator = a);
    memcpy(out, url->origin->data, url->origin->u8_bytes);
    memcpy(out + url->origin->u8_bytes, path, plen);
    out[total] = '\0';
    return out;
}

/* ----------------------------------------------------------------- */
/* Public                                                            */
/* ----------------------------------------------------------------- */

n00b_http_h1_headers_t *
n00b_http_auth_apply(n00b_http_auth_t       *auth,
                     n00b_http_h1_headers_t *base,
                     const char             *method,
                     n00b_http_url_t        *url)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    n00b_allocator_t      *a = allocator ? allocator : default_pool();
    n00b_http_h1_headers_t *h = n00b_http_h1_headers_new(.allocator = a);

    /* Bearer first (DPoP needs to be paired with a bearer when
     * binding access tokens — chunk-3 docs spell it out). */
    if (auth && auth->bearer_token && auth->bearer_token->byte_len > 0) {
        char *line = build_authorization(auth->bearer_token, a);
        n00b_http_h1_headers_set(h, "Authorization", line);
    }

    /* DPoP proof. */
    if (auth && auth->dpop_signer && method && url) {
        char *htu = build_htu(url, a);
        auto  pr  = n00b_dpop_create(auth->dpop_signer, method, htu);
        if (n00b_result_is_ok(pr)) {
            const char *proof = n00b_result_get(pr);
            n00b_http_h1_headers_set(h, "DPoP", proof);
        }
        /* Sign failure: omit the header.  The server will reject
         * with 401, surfacing the misconfiguration. */
    }

    /* Caller-supplied headers overlay last so they can override
     * anything we set. */
    if (base) {
        size_t n = n00b_http_h1_headers_len(base);
        for (size_t i = 0; i < n; i++) {
            const char *name;
            const char *value;
            if (n00b_http_h1_headers_at(base, i, &name, &value)) {
                n00b_http_h1_headers_set(h, name, value);
            }
        }
    }
    return h;
}

bool
n00b_http_auth_verify_response(n00b_http_auth_t     *auth,
                               n00b_http_response_t *resp)
{
    if (!auth || !auth->response_verifier) return true;
    return auth->response_verifier(resp, auth->response_verifier_ctx);
}
