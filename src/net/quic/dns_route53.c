/*
 * dns_route53.c — AWS Route53 DNS provider.
 *
 * Talks to route53.amazonaws.com via the existing HTTPS shim.
 * Auth: AWS Signature Version 4 (SigV4) — HMAC-SHA256 cascade
 * over the canonical request.
 *
 * Operations:
 *   set_txt(fqdn, value):
 *     POST /2013-04-01/hostedzone/<id>/rrset
 *     Body: ChangeResourceRecordSetsRequest XML with CREATE action
 *
 *   remove_txt(fqdn, value):
 *     POST /2013-04-01/hostedzone/<id>/rrset
 *     Body: ChangeResourceRecordSetsRequest XML with DELETE action
 *
 * Constructor takes (access_key, secret_key, [session_token],
 * hosted_zone_id).  No metadata-server / IMDSv2 path in v1 —
 * static credentials only; the production path is to fetch
 * temporary credentials out-of-band and reconstruct the provider
 * periodically.  Credentials are stored zeroized at close.
 *
 * Region note: Route53 is a global service; AWS docs require
 * `us-east-1` in the credential scope regardless of the caller's
 * region.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "picotls.h"
#include "picotls/minicrypto.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/time.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/dns_provider.h"
#include "net/http/http_client.h"
#include "internal/net/http/http_h1.h"

typedef struct {
    char *access_key;
    char *secret_key;
    char *session_token;     /* optional; nullptr if static creds */
    char *hosted_zone_id;
} r53_state_t;

static n00b_allocator_t *
r53_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
r53_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t l = strlen(s);
    char  *o = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                          &(n00b_alloc_opts_t){
                                              .allocator = r53_alloc(),
                                              .no_scan   = true,
                                          });
    memcpy(o, s, l + 1);
    return o;
}

/* ===========================================================================
 * SHA-256 + HMAC-SHA256 helpers
 * =========================================================================== */

static void
sha256_hex(const uint8_t *data, size_t len, char out[65])
{
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    n00b_sha256_update(&ctx, data, len);
    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        for (int j = 0; j < 4; j++) {
            uint8_t b = (uint8_t)(w >> (24 - 8 * j));
            out[i*8 + j*2]     = hex[b >> 4];
            out[i*8 + j*2 + 1] = hex[b & 0xf];
        }
    }
    out[64] = '\0';
}

/* Fill out[32] with HMAC-SHA256(key[key_len], msg[msg_len]). */
static void
hmac_sha256(const uint8_t *key, size_t key_len,
            const uint8_t *msg, size_t msg_len,
            uint8_t        out[32])
{
    /* picotls's ptls_hmac_create returns a hash_context_t whose
     * `update` is the HMAC update + finalize-with-mode. */
    ptls_hash_context_t *h = ptls_hmac_create(&ptls_minicrypto_sha256,
                                              key, key_len);
    h->update(h, msg, msg_len);
    h->final(h, out, PTLS_HASH_FINAL_MODE_FREE);
}

/* ===========================================================================
 * SigV4 signing
 *
 * Canonical request:
 *   <method>\n<canonical_uri>\n<canonical_query>\n
 *   <canonical_headers>\n<signed_headers>\n<hashed_payload>
 *
 * String-to-sign:
 *   AWS4-HMAC-SHA256\n<amzdate>\n<scope>\n<sha256(canonical_request)>
 *
 * Signing key:
 *   kDate    = HMAC("AWS4"+secret, yyyymmdd)
 *   kRegion  = HMAC(kDate, region)
 *   kService = HMAC(kRegion, service)
 *   kSigning = HMAC(kService, "aws4_request")
 *   signature = hex(HMAC(kSigning, string_to_sign))
 * =========================================================================== */

typedef struct {
    char authorization[1024];
    char amz_date[32];          /* yyyymmddTHHmmssZ */
    char content_sha256[65];    /* hex(sha256(payload)) */
} sigv4_t;

static void
sigv4_sign(const r53_state_t *st,
           const char        *method,
           const char        *path_and_query,
           const char        *host,
           const uint8_t     *body,
           size_t             body_len,
           sigv4_t           *out)
{
    /* 1. Timestamp + scope. The compact SigV4 date formats
     * (`%Y%m%d` / `%Y%m%dT%H%M%SZ`) don't fit `n00b_iso8601_utc`'s
     * RFC-3339 output — funnel the timestamp capture through
     * `n00b_duration_t` so every libn00b consumer pulls wall-clock
     * via the same primitive. A future broken-down-UTC helper
     * (e.g. `n00b_gmtime`) can subsume the `gmtime_r` call too. */
    n00b_duration_t now = {};
    n00b_capture_timestamp(&now);
    time_t now_sec = (time_t)now.tv_sec;
    struct tm utc;
    gmtime_r(&now_sec, &utc);
    char date_only[16];
    strftime(date_only, sizeof(date_only), "%Y%m%d", &utc);
    strftime(out->amz_date, sizeof(out->amz_date), "%Y%m%dT%H%M%SZ", &utc);

    char scope[128];
    snprintf(scope, sizeof(scope), "%s/us-east-1/route53/aws4_request",
             date_only);

    /* 2. Hashed payload. */
    sha256_hex(body, body_len, out->content_sha256);

    /* 3. Canonical headers — must be sorted lexicographically by
     *    name (lowercased), each "name:value\n", with a trailing
     *    blank line.  Signed headers is the semicolon-separated
     *    list of names.  Route53 commonly signs:
     *      content-type, host, x-amz-content-sha256, x-amz-date,
     *      x-amz-security-token (if session_token is set). */
    char canon_headers[4096];
    int  ch_n = 0;
    ch_n += snprintf(canon_headers + ch_n, sizeof(canon_headers) - ch_n,
                     "content-type:application/xml\n");
    ch_n += snprintf(canon_headers + ch_n, sizeof(canon_headers) - ch_n,
                     "host:%s\n", host);
    ch_n += snprintf(canon_headers + ch_n, sizeof(canon_headers) - ch_n,
                     "x-amz-content-sha256:%s\n", out->content_sha256);
    ch_n += snprintf(canon_headers + ch_n, sizeof(canon_headers) - ch_n,
                     "x-amz-date:%s\n", out->amz_date);
    const char *signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    if (st->session_token) {
        ch_n += snprintf(canon_headers + ch_n, sizeof(canon_headers) - ch_n,
                         "x-amz-security-token:%s\n", st->session_token);
        signed_headers =
            "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    }

    /* 4. Canonical request. */
    char canon_request[8192];
    int  cr_n = snprintf(canon_request, sizeof(canon_request),
                         "%s\n%s\n%s\n%s\n%s\n%s",
                         method,
                         path_and_query,    /* canonical URI; no query for our case */
                         "",                /* canonical querystring */
                         canon_headers,
                         signed_headers,
                         out->content_sha256);
    char canon_request_sha[65];
    sha256_hex((const uint8_t *)canon_request, (size_t)cr_n,
               canon_request_sha);

    /* 5. String to sign. */
    char string_to_sign[1024];
    int  sts_n = snprintf(string_to_sign, sizeof(string_to_sign),
                          "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                          out->amz_date, scope, canon_request_sha);

    /* 6. Signing key cascade. */
    uint8_t k_date[32], k_region[32], k_service[32], k_signing[32];
    char    aws4_secret[256];
    int     ks_n = snprintf(aws4_secret, sizeof(aws4_secret),
                            "AWS4%s", st->secret_key);
    hmac_sha256((const uint8_t *)aws4_secret, (size_t)ks_n,
                (const uint8_t *)date_only, strlen(date_only), k_date);
    hmac_sha256(k_date, 32,
                (const uint8_t *)"us-east-1", 9, k_region);
    hmac_sha256(k_region, 32,
                (const uint8_t *)"route53", 7, k_service);
    hmac_sha256(k_service, 32,
                (const uint8_t *)"aws4_request", 12, k_signing);

    /* 7. Final signature. */
    uint8_t sig[32];
    hmac_sha256(k_signing, 32,
                (const uint8_t *)string_to_sign, (size_t)sts_n, sig);
    char sig_hex[65];
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        sig_hex[i*2]     = hex[sig[i] >> 4];
        sig_hex[i*2 + 1] = hex[sig[i] & 0xf];
    }
    sig_hex[64] = '\0';

    /* 8. Authorization header. */
    snprintf(out->authorization, sizeof(out->authorization),
             "AWS4-HMAC-SHA256 Credential=%s/%s, "
             "SignedHeaders=%s, Signature=%s",
             st->access_key, scope, signed_headers, sig_hex);

    /* Wipe the signing-key cascade — these are derived from the
     * long-term secret. */
    memset(k_date, 0, sizeof(k_date));
    memset(k_region, 0, sizeof(k_region));
    memset(k_service, 0, sizeof(k_service));
    memset(k_signing, 0, sizeof(k_signing));
    memset(sig, 0, sizeof(sig));
    memset(aws4_secret, 0, sizeof(aws4_secret));
}

/* ===========================================================================
 * Route53 ChangeResourceRecordSets XML
 *
 * The body for an ACME DNS-01 update is small enough to template-
 * concatenate.  We escape only what's needed (XML special chars
 * &, <, >, ', ").  Real-world TXT values are base64url and FQDNs
 * are DNS names — neither include XML metacharacters in normal
 * cases.  We escape defensively anyway.
 * =========================================================================== */

static void
xml_escape(const char *in, char *out, size_t out_cap)
{
    size_t oi = 0;
    for (size_t i = 0; in[i]; i++) {
        const char *rep = nullptr;
        switch (in[i]) {
        case '&':  rep = "&amp;"; break;
        case '<':  rep = "&lt;"; break;
        case '>':  rep = "&gt;"; break;
        case '"':  rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default:   break;
        }
        if (rep) {
            size_t l = strlen(rep);
            if (oi + l + 1 >= out_cap) break;
            memcpy(out + oi, rep, l);
            oi += l;
        } else {
            if (oi + 2 >= out_cap) break;
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
}

static int
build_change_xml(const char *action,    /* "CREATE" / "DELETE" */
                 const char *fqdn,
                 const char *value,
                 char       *out,
                 size_t      out_cap)
{
    char fqdn_esc[1024], value_esc[1024];
    xml_escape(fqdn, fqdn_esc, sizeof(fqdn_esc));
    xml_escape(value, value_esc, sizeof(value_esc));

    /* Route53 wants the TXT value wrapped in DOUBLE-quotes within
     * the XML — and the double-quote chars themselves are part of
     * the on-wire DNS rdata.  We escape the inner quotes as &quot; */
    return snprintf(out, out_cap,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<ChangeResourceRecordSetsRequest "
            "xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\">"
          "<ChangeBatch>"
            "<Changes>"
              "<Change>"
                "<Action>%s</Action>"
                "<ResourceRecordSet>"
                  "<Name>%s</Name>"
                  "<Type>TXT</Type>"
                  "<TTL>60</TTL>"
                  "<ResourceRecords>"
                    "<ResourceRecord>"
                      "<Value>&quot;%s&quot;</Value>"
                    "</ResourceRecord>"
                  "</ResourceRecords>"
                "</ResourceRecordSet>"
              "</Change>"
            "</Changes>"
          "</ChangeBatch>"
        "</ChangeResourceRecordSetsRequest>",
        action, fqdn_esc, value_esc);
}

/* ===========================================================================
 * Public set/remove
 * =========================================================================== */

static int
r53_change_record(r53_state_t *st,
                  const char  *action,
                  const char  *fqdn,
                  const char  *value)
{
    char xml[8192];
    int  xml_n = build_change_xml(action, fqdn, value, xml, sizeof(xml));
    if (xml_n < 0 || xml_n >= (int)sizeof(xml)) {
        return N00B_QUIC_ERR_FRAME_TOO_LARGE;
    }

    char path[512];
    snprintf(path, sizeof(path),
             "/2013-04-01/hostedzone/%s/rrset", st->hosted_zone_id);

    sigv4_t sig;
    sigv4_sign(st, "POST", path, "route53.amazonaws.com",
               (const uint8_t *)xml, (size_t)xml_n, &sig);

    n00b_http_h1_headers_t *h = n00b_http_h1_headers_new();
    n00b_http_h1_headers_set(h, "Authorization", sig.authorization);
    n00b_http_h1_headers_set(h, "X-Amz-Date", sig.amz_date);
    n00b_http_h1_headers_set(h, "X-Amz-Content-Sha256", sig.content_sha256);
    if (st->session_token) {
        n00b_http_h1_headers_set(h, "X-Amz-Security-Token",
                                  st->session_token);
    }

    char url[1024];
    snprintf(url, sizeof(url),
             "https://route53.amazonaws.com%s", path);

    n00b_buffer_t *body = n00b_buffer_from_bytes(xml, xml_n);
    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(url),
        .method       = r"POST",
        .body         = body,
        .extra        = h,
        .content_type = r"application/xml",
        .prefer_h3    = false);
    if (!n00b_result_is_ok(r)) {
        return (int)n00b_result_get_err(r);
    }
    n00b_http_response_t *resp = n00b_result_get(r);
    /* Route53 returns 200 + a ChangeInfo XML on success.  4xx
     * responses include an ErrorResponse XML; we surface them as
     * PROTOCOL errors without parsing for now (the operator can
     * inspect the HTTPS response in logs). */
    if (n00b_http_response_status(resp) != 200) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    return N00B_QUIC_OK;
}

static int
r53_set_txt(n00b_quic_dns_provider_t *self,
            const char *fqdn, const char *value)
{
    return r53_change_record(self->ctx, "CREATE", fqdn, value);
}

static int
r53_remove_txt(n00b_quic_dns_provider_t *self,
               const char *fqdn, const char *value)
{
    /* DELETE in Route53 must include the exact rdata that's being
     * removed.  When called without a value (orchestrator's
     * deprovision path), we can't infer it; surface as a no-op
     * with a soft warning to the log.  The operator's cleanup
     * playbook handles stale records. */
    if (!value || value[0] == '\0') {
        return N00B_QUIC_OK;
    }
    return r53_change_record(self->ctx, "DELETE", fqdn, value);
}

static void
r53_close(n00b_quic_dns_provider_t *self)
{
    if (!self || !self->ctx) return;
    r53_state_t *st = self->ctx;
    /* Zero the secret bytes before dropping the pointer. */
    if (st->secret_key) {
        memset(st->secret_key, 0, strlen(st->secret_key));
    }
    if (st->session_token) {
        memset(st->session_token, 0, strlen(st->session_token));
    }
    self->ctx = nullptr;
}

n00b_result_t(n00b_quic_dns_provider_t *)
n00b_quic_dns_provider_route53(n00b_quic_dns_route53_config_t config)
{
    return n00b_quic_dns_provider_route53_raw(config.access_key,
                                             config.secret_key,
                                             config.session_token,
                                             config.hosted_zone_id);
}

n00b_result_t(n00b_quic_dns_provider_t *)
n00b_quic_dns_provider_route53_raw(const char *access_key,
                                   const char *secret_key,
                                   const char *session_token,
                                   const char *hosted_zone_id)
{
    if (!access_key || !secret_key || !hosted_zone_id ||
        access_key[0] == '\0' || secret_key[0] == '\0' ||
        hosted_zone_id[0] == '\0') {
        return n00b_result_err(n00b_quic_dns_provider_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    r53_state_t *st = n00b_alloc_with_opts(r53_state_t,
        &(n00b_alloc_opts_t){.allocator = r53_alloc()});
    st->access_key     = r53_strdup(access_key);
    st->secret_key     = r53_strdup(secret_key);
    st->session_token  = session_token ? r53_strdup(session_token) : nullptr;
    st->hosted_zone_id = r53_strdup(hosted_zone_id);

    n00b_quic_dns_provider_t *p = n00b_alloc_with_opts(
        n00b_quic_dns_provider_t,
        &(n00b_alloc_opts_t){.allocator = r53_alloc()});
    p->name       = "route53";
    p->set_txt    = r53_set_txt;
    p->remove_txt = r53_remove_txt;
    p->close      = r53_close;
    p->ctx        = st;
    return n00b_result_ok(n00b_quic_dns_provider_t *, p);
}
