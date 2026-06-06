/*
 * http_alt_svc.c — RFC 7838 Alt-Svc parser + per-origin cache.
 *
 * Phase 6 chunk 6.  The parser walks header bytes once, splitting
 * on commas (separating alternatives) and semicolons (separating
 * params), respecting quoted-string escapes.  The cache is a small
 * per-origin map with TTL eviction.
 *
 * Reference: RFC 7838 § 3 (Alt-Svc field) and § 3.1 (parameters).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/time.h"
#include "adt/list.h"
#include "util/parse_num.h"
#include "internal/net/http/http_alt_svc.h"

#define DEFAULT_MA_SECONDS  (24 * 60 * 60)   /* RFC 7838 § 3.1 default */

/* ----------------------------------------------------------------- */
/* Helpers                                                           */
/* ----------------------------------------------------------------- */

static n00b_allocator_t *
default_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static void
skip_ows(const char **pp, const char *end)
{
    const char *p = *pp;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    *pp = p;
}

/* RFC 7230 § 3.2.6 token = 1*tchar ; we accept the practical superset
 * that's safe for header names. */
static bool
is_token_char(unsigned char c)
{
    if (c >= '0' && c <= '9') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    /* tchar punctuation per RFC 7230 § 3.2.6.  We're lenient on
     * anything servers might send. */
    static const char *tchars = "!#$%&'*+-.^_`|~";
    return strchr(tchars, c) != nullptr;
}

static n00b_string_t *
make_string_lower(const char       *p,
                  size_t            len,
                  n00b_allocator_t *a)
{
    char  stack[64];
    char *tmp = (len < sizeof(stack))
                    ? stack
                    : n00b_alloc_array(char, len, .allocator = a);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        tmp[i] = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : (char)c;
    }
    return n00b_string_from_raw(tmp, (int64_t)len, .allocator = a);
}

static n00b_string_t *
make_string_raw(const char *p, size_t len, n00b_allocator_t *a)
{
    return n00b_string_from_raw(p, (int64_t)len, .allocator = a);
}

/* Parse a token starting at *pp; advance *pp past it; return length. */
static size_t
parse_token(const char **pp, const char *end)
{
    const char *start = *pp;
    while (*pp < end && is_token_char((unsigned char)**pp)) (*pp)++;
    return (size_t)(*pp - start);
}

/* Parse a quoted-string (RFC 7230 § 3.2.6) — caller already saw '"'.
 * On entry *pp points AT the leading '"'.  On exit *pp points one
 * past the trailing '"'.  Returns the unquoted contents; advances
 * across simple `\"` and `\\` escapes. */
static n00b_string_t *
parse_quoted_string(const char       **pp,
                    const char        *end,
                    n00b_allocator_t  *a)
{
    if (*pp >= end || **pp != '"') return nullptr;
    (*pp)++;                                      /* consume opening " */
    const char *content_start = *pp;
    /* First pass: locate closing quote, track whether we saw escapes. */
    bool        had_escape = false;
    while (*pp < end && **pp != '"') {
        if (**pp == '\\' && *pp + 1 < end) {
            had_escape = true;
            (*pp)     += 2;
        } else {
            (*pp)++;
        }
    }
    size_t raw_len = (size_t)(*pp - content_start);
    if (*pp < end && **pp == '"') (*pp)++;        /* consume closing " */

    if (!had_escape) {
        return make_string_raw(content_start, raw_len, a);
    }
    /* Escape pass — at most raw_len bytes. */
    char  stack[256];
    char *out = (raw_len < sizeof(stack))
                    ? stack
                    : n00b_alloc_array(char, raw_len, .allocator = a);
    size_t k = 0;
    for (size_t i = 0; i < raw_len; i++) {
        unsigned char c = (unsigned char)content_start[i];
        if (c == '\\' && i + 1 < raw_len) {
            out[k++] = content_start[++i];
        } else {
            out[k++] = (char)c;
        }
    }
    return n00b_string_from_raw(out, (int64_t)k, .allocator = a);
}

/* Parse alt-authority `[host]:port` from a string into (host, port).
 * Returns false on malformed input. */
static bool
parse_alt_authority(n00b_string_t *raw,
                    n00b_string_t **host_out,
                    uint16_t      *port_out,
                    n00b_allocator_t *a)
{
    if (!raw) return false;
    const char *p   = raw->data;
    const char *end = p + raw->u8_bytes;

    /* Optional [host] for IPv6 literals; otherwise host until ':'. */
    const char *host_start = p;
    const char *host_end;
    if (p < end && *p == '[') {
        p++;
        host_start    = p;
        const char *rb = memchr(p, ']', (size_t)(end - p));
        if (!rb) return false;
        host_end = rb;
        p        = rb + 1;
    } else {
        while (p < end && *p != ':') p++;
        host_end = p;
    }
    /* `:` is mandatory in alt-authority — port is required. */
    if (p >= end || *p != ':') return false;
    p++;
    /* Parse port. */
    unsigned long pv = 0;
    if (p == end) return false;
    while (p < end && *p >= '0' && *p <= '9') {
        pv = pv * 10 + (unsigned long)(*p - '0');
        if (pv > 65535) return false;
        p++;
    }
    if (p != end) return false;        /* trailing junk */
    if (pv == 0)  return false;        /* RFC 7838 disallows port 0 */

    *host_out = make_string_raw(host_start,
                                 (size_t)(host_end - host_start), a);
    *port_out = (uint16_t)pv;
    return true;
}

/* ----------------------------------------------------------------- */
/* Parser                                                            */
/* ----------------------------------------------------------------- */

n00b_http_alt_svc_entry_t *
n00b_http_alt_svc_parse(const char *header,
                        size_t     *n_out,
                        bool       *clear_out)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    if (clear_out) *clear_out = false;
    if (n_out) *n_out = 0;
    if (!header) return nullptr;
    n00b_allocator_t *a = allocator ? allocator : default_pool();

    const char *p   = header;
    const char *end = p + strlen(header);

    /* Skip leading OWS. */
    skip_ows(&p, end);

    /* `clear` literal — case-insensitive per RFC 7838 § 3. */
    if ((size_t)(end - p) >= 5
        && strncasecmp(p, "clear", 5) == 0) {
        const char *q = p + 5;
        skip_ows(&q, end);
        if (q == end) {
            if (clear_out) *clear_out = true;
            return nullptr;
        }
    }

    /* Up to 16 alternatives per header.  Larger headers truncate;
     * none of the wild values we've seen exceed 4. */
    const size_t cap = 16;
    n00b_http_alt_svc_entry_t *out = n00b_alloc_array(
        n00b_http_alt_svc_entry_t, cap, .allocator = a);
    size_t n = 0;

    while (p < end && n < cap) {
        skip_ows(&p, end);
        if (p == end) break;

        /* protocol-id = token */
        const char *proto_start = p;
        size_t      proto_len   = parse_token(&p, end);
        if (proto_len == 0) {
            /* Junk; skip to next comma. */
            while (p < end && *p != ',') p++;
            if (p < end) p++;
            continue;
        }
        n00b_string_t *proto = make_string_lower(proto_start, proto_len, a);

        skip_ows(&p, end);
        if (p >= end || *p != '=') {
            /* Malformed alt — skip to next. */
            while (p < end && *p != ',') p++;
            if (p < end) p++;
            continue;
        }
        p++;                                            /* '=' */
        skip_ows(&p, end);

        /* alt-authority is a quoted-string. */
        n00b_string_t *raw_auth = parse_quoted_string(&p, end, a);
        if (!raw_auth) {
            while (p < end && *p != ',') p++;
            if (p < end) p++;
            continue;
        }

        n00b_string_t *host = nullptr;
        uint16_t       port = 0;
        if (!parse_alt_authority(raw_auth, &host, &port, a)) {
            while (p < end && *p != ',') p++;
            if (p < end) p++;
            continue;
        }

        n00b_http_alt_svc_entry_t entry = {
            .protocol_id = proto,
            .host        = host,
            .port        = port,
            .ma_seconds  = DEFAULT_MA_SECONDS,
            .persist     = false,
        };

        /* Parameter list. */
        while (true) {
            skip_ows(&p, end);
            if (p >= end || *p != ';') break;
            p++;                                        /* ';' */
            skip_ows(&p, end);
            const char *name_start = p;
            size_t      name_len   = parse_token(&p, end);
            if (name_len == 0) break;
            skip_ows(&p, end);
            if (p >= end || *p != '=') break;
            p++;                                        /* '=' */
            skip_ows(&p, end);

            /* Value: token or quoted-string. */
            n00b_string_t *val = nullptr;
            if (p < end && *p == '"') {
                val = parse_quoted_string(&p, end, a);
            } else {
                const char *val_start = p;
                size_t      val_len   = parse_token(&p, end);
                if (val_len == 0) break;
                val = make_string_raw(val_start, val_len, a);
            }
            if (!val) break;

            if (name_len == 2
                && strncasecmp(name_start, "ma", 2) == 0) {
                /* libc-free: strtol traps on off-libc workers (NULL TLS
                 * locale); the HTTP client parses headers on conduit
                 * workers. */
                int64_t ma = n00b_result_get_or_else(
                    n00b_parse_i64(val), -1);
                if (ma >= 0) entry.ma_seconds = (int32_t)ma;
            } else if (name_len == 7
                       && strncasecmp(name_start, "persist", 7) == 0) {
                entry.persist = (val->u8_bytes == 1
                                  && val->data[0] == '1');
            }
            /* Unknown params silently ignored. */
        }

        out[n++] = entry;

        skip_ows(&p, end);
        if (p < end && *p == ',') {
            p++;
        }
    }

    if (n_out) *n_out = n;
    return out;
}

/* =================================================================== */
/* Cache                                                                */
/* =================================================================== */

typedef struct cache_entry {
    n00b_http_alt_svc_entry_t  *entries;       /* owned slice */
    size_t                      n_entries;
    uint64_t                    inserted_at_ms;
    uint64_t                    expires_at_ms; /* min(insert+ma) */
    n00b_string_t              *origin;
    struct cache_entry         *next;
} cache_entry_t;

#define ALT_SVC_BUCKETS 32

struct n00b_http_alt_svc_cache {
    n00b_allocator_t *allocator;
    cache_entry_t    *buckets[ALT_SVC_BUCKETS];
    size_t            count;
    size_t            max_origins;
    bool              fake_now_active;
    uint64_t          fake_now_ms;
};

static uint64_t
now_ms(n00b_http_alt_svc_cache_t *cache)
{
    if (cache->fake_now_active) return cache->fake_now_ms;
    return n00b_ns_timestamp() / 1000000ULL;
}

static uint32_t
hash_origin(n00b_string_t *o)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < o->u8_bytes; i++) {
        h ^= (unsigned char)o->data[i];
        h *= 16777619u;
    }
    return h;
}

static cache_entry_t *
bucket_find(n00b_http_alt_svc_cache_t *cache,
             n00b_string_t            *origin,
             cache_entry_t           ***slot_out)
{
    uint32_t        idx  = hash_origin(origin) & (ALT_SVC_BUCKETS - 1);
    cache_entry_t **slot = &cache->buckets[idx];
    cache_entry_t  *e;
    for (e = *slot; e; slot = &e->next, e = e->next) {
        if (e->origin->u8_bytes == origin->u8_bytes
            && memcmp(e->origin->data, origin->data,
                      origin->u8_bytes) == 0) {
            if (slot_out) *slot_out = slot;
            return e;
        }
    }
    if (slot_out) *slot_out = slot;
    return nullptr;
}

static void
remove_at(n00b_http_alt_svc_cache_t *cache, cache_entry_t **slot)
{
    cache_entry_t *e = *slot;
    if (!e) return;
    *slot = e->next;
    cache->count--;
}

n00b_http_alt_svc_cache_t *
n00b_http_alt_svc_cache_new()
    _kargs {
        size_t            max_origins = 64;
        n00b_allocator_t *allocator   = nullptr;
    }
{
    n00b_allocator_t *a = allocator ? allocator : default_pool();
    n00b_http_alt_svc_cache_t *c = n00b_alloc_with_opts(
        n00b_http_alt_svc_cache_t,
        &(n00b_alloc_opts_t){.allocator = a});
    c->allocator   = a;
    c->max_origins = max_origins;
    return c;
}

void
n00b_http_alt_svc_cache_close(n00b_http_alt_svc_cache_t *cache)
{
    if (!cache) return;
    for (size_t i = 0; i < ALT_SVC_BUCKETS; i++) {
        cache->buckets[i] = nullptr;
    }
    cache->count = 0;
}

void
n00b_http_alt_svc_cache_set(n00b_http_alt_svc_cache_t       *cache,
                            n00b_string_t                   *origin,
                            const n00b_http_alt_svc_entry_t *entries,
                            size_t                           n_entries)
{
    if (!cache || !origin) return;
    cache_entry_t **slot;
    cache_entry_t  *existing = bucket_find(cache, origin, &slot);
    if (existing) {
        remove_at(cache, slot);
    }

    /* Evict an arbitrary entry when we're at the cap. */
    if (cache->count >= cache->max_origins) {
        for (size_t i = 0; i < ALT_SVC_BUCKETS; i++) {
            if (cache->buckets[i]) {
                cache->buckets[i] = cache->buckets[i]->next;
                cache->count--;
                break;
            }
        }
    }

    cache_entry_t *e = n00b_alloc_with_opts(
        cache_entry_t,
        &(n00b_alloc_opts_t){.allocator = cache->allocator});
    e->origin    = origin;
    e->n_entries = n_entries;
    e->entries   = (n_entries > 0)
        ? n00b_alloc_array(n00b_http_alt_svc_entry_t, n_entries,
                           .allocator = cache->allocator)
        : nullptr;
    if (n_entries > 0) {
        memcpy(e->entries, entries,
               n_entries * sizeof(*entries));
    }
    uint64_t now = now_ms(cache);
    e->inserted_at_ms = now;
    /* Use the LARGEST ma in the set as the cache-line TTL.  Per-entry
     * expiry is checked at lookup time so individual entries can age
     * out independently. */
    int64_t max_ma = 0;
    for (size_t i = 0; i < n_entries; i++) {
        if (entries[i].ma_seconds > max_ma) max_ma = entries[i].ma_seconds;
    }
    e->expires_at_ms = now + (uint64_t)max_ma * 1000ULL;

    /* Push at bucket head. */
    uint32_t idx = hash_origin(origin) & (ALT_SVC_BUCKETS - 1);
    e->next = cache->buckets[idx];
    cache->buckets[idx] = e;
    cache->count++;
}

void
n00b_http_alt_svc_cache_clear(n00b_http_alt_svc_cache_t *cache,
                              n00b_string_t             *origin)
{
    if (!cache || !origin) return;
    cache_entry_t **slot;
    cache_entry_t  *e = bucket_find(cache, origin, &slot);
    if (e) remove_at(cache, slot);
}

bool
n00b_http_alt_svc_cache_lookup_h3(n00b_http_alt_svc_cache_t  *cache,
                                  n00b_string_t              *origin,
                                  n00b_string_t             **host_out,
                                  uint16_t                   *port_out)
{
    if (!cache || !origin) return false;
    cache_entry_t **slot;
    cache_entry_t  *e = bucket_find(cache, origin, &slot);
    if (!e) return false;
    uint64_t now = now_ms(cache);
    if (now >= e->expires_at_ms) {
        remove_at(cache, slot);
        return false;
    }
    /* First live h3 entry wins (RFC 7838 doesn't define preference;
     * server is expected to list in priority order). */
    for (size_t i = 0; i < e->n_entries; i++) {
        n00b_http_alt_svc_entry_t *ent = &e->entries[i];
        if (!ent->protocol_id) continue;
        if (ent->protocol_id->u8_bytes != 2) continue;
        if (memcmp(ent->protocol_id->data, "h3", 2) != 0) continue;
        uint64_t entry_expire = e->inserted_at_ms
            + (uint64_t)ent->ma_seconds * 1000ULL;
        if (now >= entry_expire) continue;
        if (host_out) *host_out = ent->host;
        if (port_out) *port_out = ent->port;
        return true;
    }
    return false;
}

void
n00b_http_alt_svc_cache_reap(n00b_http_alt_svc_cache_t *cache,
                             uint64_t                   now)
{
    if (!cache) return;
    for (size_t i = 0; i < ALT_SVC_BUCKETS; i++) {
        cache_entry_t **slot = &cache->buckets[i];
        while (*slot) {
            cache_entry_t *e = *slot;
            if (now >= e->expires_at_ms) {
                *slot = e->next;
                cache->count--;
            } else {
                slot = &e->next;
            }
        }
    }
}

void
n00b_http_alt_svc_cache_set_now_for_test(n00b_http_alt_svc_cache_t *cache,
                                         uint64_t                   now)
{
    if (!cache) return;
    cache->fake_now_active = true;
    cache->fake_now_ms     = now;
}

size_t
n00b_http_alt_svc_cache_size(n00b_http_alt_svc_cache_t *cache)
{
    return cache ? cache->count : 0;
}
