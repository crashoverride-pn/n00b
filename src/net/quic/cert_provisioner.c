/*
 * cert_provisioner.c — common dispatch + shared helpers (file load,
 * PEM → DER, X.509 validity parse).
 */

#define N00B_USE_INTERNAL_API
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/file.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "internal/net/quic/cert_provisioner.h"
#include "internal/net/quic/cert_provisioner_common.h"

/* ===========================================================================
 * Allocator + close dispatch
 * =========================================================================== */

static n00b_allocator_t *
certp_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

void
n00b_quic_cert_provisioner_close(n00b_quic_cert_provisioner_t *self)
{
    if (!self) {
        return;
    }
    if (self->close) {
        self->close(self);
    }
}

/* ===========================================================================
 * File load
 * =========================================================================== */

n00b_result_t(n00b_buffer_t *)
n00b_certp_load_file(const char *path)
{
    if (!path) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    n00b_string_t *p  = n00b_string_from_cstr(path);
    auto           fr = n00b_file_open(p, .mode = N00B_FILE_R);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }
    n00b_file_t *f = n00b_result_get(fr);

    /* Accumulate chunks into our own buffer.  Under the MMAP substrate
     * the chunks alias the mapping; the concat copies bytes out before
     * we close the file. */
    n00b_buffer_t *acc = n00b_buffer_new(0);
    while (!n00b_file_at_eof(f)) {
        auto rr = n00b_file_read(f, 65536);
        if (n00b_result_is_err(rr)) {
            n00b_file_close(f);
            return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
        }
        n00b_buffer_t *chunk = n00b_result_get(rr);
        if (!chunk || chunk->byte_len == 0) break;
        n00b_buffer_concat(acc, chunk);
    }
    n00b_file_close(f);
    return n00b_result_ok(n00b_buffer_t *, acc);
}

/* ===========================================================================
 * PEM → DER (first CERTIFICATE block)
 *
 * Standard base64 alphabet (RFC 4648) with '=' padding.  PEM line
 * endings can be \n or \r\n; both are stripped.
 * =========================================================================== */

static const char b64std_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int8_t b64std_inv[256];
static int    b64std_inv_inited = 0;

static void
b64std_inv_init(void)
{
    if (b64std_inv_inited) {
        return;
    }
    for (int i = 0; i < 256; i++) {
        b64std_inv[i] = -1;
    }
    for (int i = 0; i < 64; i++) {
        b64std_inv[(unsigned char)b64std_alphabet[i]] = (int8_t)i;
    }
    b64std_inv_inited = 1;
}

/* Decode one PEM CERTIFICATE block starting at `cursor` (which must
 * be at or before the BEGIN marker).  On success: fills `*out_der`
 * with the decoded buffer and `*out_next` with a pointer just past
 * the END marker (so the caller can keep walking for more blocks).
 * Returns N00B_QUIC_OK on success.  Returns
 * N00B_QUIC_ERR_NOT_FOUND_OK if no BEGIN marker remains in the
 * input (a clean end-of-input — distinct from PROTOCOL). */
#define N00B_PEM_NO_MORE_BLOCKS  1

static int
decode_one_pem_cert(const char     *cursor,
                    const char     *end,
                    n00b_buffer_t **out_der,
                    const char    **out_next)
{
    static const char beg_marker[] = "-----BEGIN CERTIFICATE-----";
    static const char end_marker[] = "-----END CERTIFICATE-----";

    const char *beg = strstr(cursor, beg_marker);
    if (!beg || beg >= end) {
        return N00B_PEM_NO_MORE_BLOCKS;
    }
    beg += sizeof(beg_marker) - 1;
    const char *fin = strstr(beg, end_marker);
    if (!fin || fin > end) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    /* Strip whitespace and decode. */
    size_t b64_cap = (size_t)(fin - beg);
    char  *b64     = n00b_alloc_array_with_opts(char, (int64_t)b64_cap + 1,
                                                &(n00b_alloc_opts_t){
                                                    .allocator = certp_alloc(),
                                                    .no_scan   = true,
                                                });
    size_t bi = 0;
    for (size_t i = 0; i < b64_cap; i++) {
        char c = beg[i];
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
            b64[bi++] = c;
        }
    }

    /* Trim trailing '='. */
    while (bi > 0 && b64[bi - 1] == '=') {
        bi--;
    }

    size_t   der_cap = (bi * 3) / 4 + 4;
    uint8_t *der     = n00b_alloc_array_with_opts(uint8_t, (int64_t)der_cap,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = certp_alloc(),
                                                       .no_scan   = true,
                                                   });
    size_t   dlen = 0;
    for (size_t i = 0; i + 4 <= bi; i += 4) {
        int8_t a = b64std_inv[(unsigned char)b64[i]];
        int8_t b = b64std_inv[(unsigned char)b64[i + 1]];
        int8_t cc = b64std_inv[(unsigned char)b64[i + 2]];
        int8_t d = b64std_inv[(unsigned char)b64[i + 3]];
        if ((a | b | cc | d) < 0) {
            return N00B_QUIC_ERR_PROTOCOL;
        }
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12)
                   | ((uint32_t)cc <<  6) |  (uint32_t)d;
        der[dlen++] = (uint8_t)((v >> 16) & 0xff);
        der[dlen++] = (uint8_t)((v >>  8) & 0xff);
        der[dlen++] = (uint8_t)( v        & 0xff);
    }
    size_t rem = bi % 4;
    if (rem == 2) {
        int8_t a = b64std_inv[(unsigned char)b64[bi - 2]];
        int8_t b = b64std_inv[(unsigned char)b64[bi - 1]];
        if ((a | b) < 0) {
            return N00B_QUIC_ERR_PROTOCOL;
        }
        der[dlen++] = (uint8_t)((a << 2) | (b >> 4));
    } else if (rem == 3) {
        int8_t a = b64std_inv[(unsigned char)b64[bi - 3]];
        int8_t b = b64std_inv[(unsigned char)b64[bi - 2]];
        int8_t cc = b64std_inv[(unsigned char)b64[bi - 1]];
        if ((a | b | cc) < 0) {
            return N00B_QUIC_ERR_PROTOCOL;
        }
        uint32_t v = ((uint32_t)a << 12) | ((uint32_t)b << 6) | (uint32_t)cc;
        der[dlen++] = (uint8_t)((v >> 10) & 0xff);
        der[dlen++] = (uint8_t)((v >>  2) & 0xff);
    } else if (rem == 1) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    *out_der = n00b_buffer_from_bytes((char *)der, (int64_t)dlen,
                                       .allocator = certp_alloc());
    /* Advance past the END marker. */
    *out_next = fin + sizeof(end_marker) - 1;
    return N00B_QUIC_OK;
}

n00b_result_t(n00b_buffer_t *)
n00b_certp_pem_first_cert_to_der(n00b_buffer_t *pem)
{
    if (!pem || !pem->data || pem->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    b64std_inv_init();

    n00b_buffer_t *out  = nullptr;
    const char    *next = nullptr;
    int rc = decode_one_pem_cert(pem->data, pem->data + pem->byte_len,
                                 &out, &next);
    if (rc == N00B_PEM_NO_MORE_BLOCKS) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_PROTOCOL);
    }
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_buffer_t *, rc);
    }
    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_list_t(n00b_buffer_t *))
n00b_certp_pem_all_certs_to_der(n00b_buffer_t *pem)
{
    if (!pem || !pem->data || pem->byte_len == 0) {
        return n00b_result_err(n00b_list_t(n00b_buffer_t *),
                               N00B_QUIC_ERR_NULL_ARG);
    }
    b64std_inv_init();

    n00b_list_t(n00b_buffer_t *) out =
        n00b_list_new(n00b_buffer_t *, .allocator = certp_alloc());

    /* Fast path: the buffer starts with 0x30 (ASN.1 SEQUENCE) and
     * contains no BEGIN marker → treat as raw DER, return as single
     * entry.  Avoids the "PEM-only" callers losing a pure-DER input. */
    if ((uint8_t)pem->data[0] == 0x30
        && !strstr(pem->data, "-----BEGIN CERTIFICATE-----")) {
        n00b_buffer_t *one = n00b_buffer_from_bytes(
            pem->data, (int64_t)pem->byte_len,
            .allocator = certp_alloc());
        n00b_list_push(out, one);
        return n00b_result_ok(n00b_list_t(n00b_buffer_t *), out);
    }

    const char *cursor = pem->data;
    const char *end    = pem->data + pem->byte_len;
    for (;;) {
        n00b_buffer_t *block = nullptr;
        const char    *next  = nullptr;
        int rc = decode_one_pem_cert(cursor, end, &block, &next);
        if (rc == N00B_PEM_NO_MORE_BLOCKS) {
            break;
        }
        if (rc != N00B_QUIC_OK) {
            return n00b_result_err(n00b_list_t(n00b_buffer_t *), rc);
        }
        n00b_list_push(out, block);
        cursor = next;
    }
    if (n00b_list_len(out) == 0) {
        return n00b_result_err(n00b_list_t(n00b_buffer_t *),
                               N00B_QUIC_ERR_PROTOCOL);
    }
    return n00b_result_ok(n00b_list_t(n00b_buffer_t *), out);
}

/* ===========================================================================
 * X.509 validity parse
 *
 * Walks DER:
 *   Certificate SEQUENCE
 *     TBSCertificate SEQUENCE  ← we open this
 *       [0] EXPLICIT Version (optional; tag 0xa0)
 *       INTEGER serialNumber
 *       SEQUENCE signature
 *       SEQUENCE issuer
 *       SEQUENCE Validity
 *         Time notBefore
 *         Time notAfter
 *       ...
 *
 * We tolerate both UTCTime (tag 0x17) and GeneralizedTime (tag 0x18).
 * =========================================================================== */

typedef struct {
    const uint8_t *p;
    size_t         n;
} dview_t;

static int
read_tlv(dview_t *v, uint8_t *tag_out,
         const uint8_t **body_out, size_t *body_len_out)
{
    if (v->n < 2) return -1;
    *tag_out = v->p[0];
    size_t i = 1;
    size_t len;
    uint8_t l = v->p[i++];
    if ((l & 0x80) == 0) {
        len = l;
    } else {
        size_t n = l & 0x7f;
        if (n == 0 || n > 4 || i + n > v->n) return -1;
        len = 0;
        for (size_t k = 0; k < n; k++) {
            len = (len << 8) | v->p[i++];
        }
    }
    if (i + len > v->n) return -1;
    *body_out     = v->p + i;
    *body_len_out = len;
    v->p += i + len;
    v->n -= i + len;
    return 0;
}

/* Parse "YY" → 19xx if YY >= 50, else 20xx (RFC 5280 § 4.1.2.5.1). */
static int
parse_2digit(const uint8_t *p, int *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') return -1;
    *out = (p[0] - '0') * 10 + (p[1] - '0');
    return 0;
}

static int
parse_4digit(const uint8_t *p, int *out)
{
    int a, b;
    if (parse_2digit(p, &a) != 0 || parse_2digit(p + 2, &b) != 0) return -1;
    *out = a * 100 + b;
    return 0;
}

static int
asn1_time_to_unix_ms(uint8_t tag, const uint8_t *body, size_t len,
                     int64_t *out_ms)
{
    int year, mon, day, hh, mm, ss;
    if (tag == 0x17) {
        /* UTCTime: YYMMDDHHMMSSZ — 13 bytes */
        if (len != 13 || body[12] != 'Z') return -1;
        int yy;
        if (parse_2digit(body, &yy)        != 0) return -1;
        if (parse_2digit(body + 2, &mon)   != 0) return -1;
        if (parse_2digit(body + 4, &day)   != 0) return -1;
        if (parse_2digit(body + 6, &hh)    != 0) return -1;
        if (parse_2digit(body + 8, &mm)    != 0) return -1;
        if (parse_2digit(body + 10, &ss)   != 0) return -1;
        year = yy >= 50 ? 1900 + yy : 2000 + yy;
    } else if (tag == 0x18) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ — 15 bytes */
        if (len != 15 || body[14] != 'Z') return -1;
        if (parse_4digit(body, &year)     != 0) return -1;
        if (parse_2digit(body + 4, &mon)  != 0) return -1;
        if (parse_2digit(body + 6, &day)  != 0) return -1;
        if (parse_2digit(body + 8, &hh)   != 0) return -1;
        if (parse_2digit(body + 10, &mm)  != 0) return -1;
        if (parse_2digit(body + 12, &ss)  != 0) return -1;
    } else {
        return -1;
    }
    if (mon < 1 || mon > 12 || day < 1 || day > 31
        || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60) {
        return -1;
    }

    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = year - 1900;
    tm.tm_mon  = mon - 1;
    tm.tm_mday = day;
    tm.tm_hour = hh;
    tm.tm_min  = mm;
    tm.tm_sec  = ss;

    /* timegm interprets struct tm as UTC; on macOS + glibc this is
     * available unconditionally. */
    time_t t = timegm(&tm);
    if (t == (time_t)-1) {
        return -1;
    }
    *out_ms = (int64_t)t * 1000;
    return 0;
}

int
n00b_certp_parse_validity(const uint8_t *der, size_t der_len,
                          int64_t *not_before_ms,
                          int64_t *not_after_ms)
{
    if (!der || der_len == 0 || !not_before_ms || !not_after_ms) {
        return -1;
    }
    dview_t v = {.p = der, .n = der_len};

    /* Outer Certificate SEQUENCE. */
    uint8_t tag;
    const uint8_t *body;
    size_t blen;
    if (read_tlv(&v, &tag, &body, &blen) != 0 || tag != 0x30) return -1;

    dview_t cert = {.p = body, .n = blen};
    /* TBSCertificate SEQUENCE. */
    if (read_tlv(&cert, &tag, &body, &blen) != 0 || tag != 0x30) return -1;
    dview_t tbs = {.p = body, .n = blen};

    /* Optional [0] EXPLICIT Version. */
    if (tbs.n >= 1 && tbs.p[0] == 0xa0) {
        if (read_tlv(&tbs, &tag, &body, &blen) != 0) return -1;
    }
    /* serialNumber INTEGER. */
    if (read_tlv(&tbs, &tag, &body, &blen) != 0 || tag != 0x02) return -1;
    /* signature SEQUENCE. */
    if (read_tlv(&tbs, &tag, &body, &blen) != 0 || tag != 0x30) return -1;
    /* issuer SEQUENCE. */
    if (read_tlv(&tbs, &tag, &body, &blen) != 0 || tag != 0x30) return -1;
    /* Validity SEQUENCE. */
    const uint8_t *val_body;
    size_t         val_len;
    if (read_tlv(&tbs, &tag, &val_body, &val_len) != 0 || tag != 0x30) return -1;

    dview_t val = {.p = val_body, .n = val_len};
    uint8_t        nb_tag, na_tag;
    const uint8_t *nb_body, *na_body;
    size_t         nb_len,  na_len;
    if (read_tlv(&val, &nb_tag, &nb_body, &nb_len) != 0) return -1;
    if (read_tlv(&val, &na_tag, &na_body, &na_len) != 0) return -1;

    if (asn1_time_to_unix_ms(nb_tag, nb_body, nb_len, not_before_ms) != 0) {
        return -1;
    }
    if (asn1_time_to_unix_ms(na_tag, na_body, na_len, not_after_ms) != 0) {
        return -1;
    }
    return 0;
}
