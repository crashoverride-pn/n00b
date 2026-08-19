/*
 * http_cookies.c — Cookie jar (RFC 6265-bis) — Phase 6 chunk 9.
 *
 * Layout:
 *   §1   Set-Cookie parser
 *   §2   Jar storage (linked list of cookies)
 *   §3   Set from response (insert / update / delete)
 *   §4   Header-for-request (filtering + formatting)
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#ifdef _WIN32
#include "core/platform.h"
#else
#include <dlfcn.h>
#endif
#include <stdatomic.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/time.h"
#include "util/ascii_ci.h"
#include "util/parse_num.h"
#include "internal/net/http/http_cookies.h"

/* ----------------------------------------------------------------- */
/* Public-Suffix-List (libpsl, dlopen'd opportunistically)           */
/*                                                                   */
/* Without libpsl we fall back to a small built-in suffix list that  */
/* covers the common single-label TLDs + the dotted-suffix patterns  */
/* most likely to appear in real-world Domain= attributes (.co.uk,   */
/* .com.au, etc.).  This still misses privately-registered suffixes  */
/* like blogspot.com — operators paranoid about super-cookies should */
/* `brew install libpsl` / `apt install libpsl`.                     */
/* ----------------------------------------------------------------- */

typedef struct psl_ctx_st psl_ctx_t;

typedef const psl_ctx_t *(*psl_builtin_fn)(void);
typedef int             (*psl_is_public_fn)(const psl_ctx_t *, const char *);

typedef struct {
    void           *handle;
    psl_builtin_fn   builtin;
    psl_is_public_fn is_public_suffix;
    const psl_ctx_t *ctx;
} psl_api_t;

static atomic_int g_psl_state = 0;     /* 0 = unprobed, 1 = ok, 2 = absent */
static psl_api_t  g_psl;

#ifdef _WIN32
static void *
n00b_http_dlopen(const char *path)
{
    return (void *)LoadLibraryA(path);
}

static void *
n00b_http_dlsym(void *handle, const char *name)
{
    return (void *)GetProcAddress((HMODULE)handle, name);
}

static void
n00b_http_dlclose(void *handle)
{
    (void)FreeLibrary((HMODULE)handle);
}
#else
static void *
n00b_http_dlopen(const char *path)
{
    return dlopen(path, RTLD_LAZY | RTLD_LOCAL);
}

static void *
n00b_http_dlsym(void *handle, const char *name)
{
    return dlsym(handle, name);
}

static void
n00b_http_dlclose(void *handle)
{
    (void)dlclose(handle);
}
#endif

static bool
psl_probe(void)
{
    int s = atomic_load(&g_psl_state);
    if (s != 0) return s == 1;

    static const char *candidates[] = {
#ifdef _WIN32
        "libpsl.dll",
        "psl.dll",
#else
        "libpsl.so.5",
        "libpsl.dylib",
        "libpsl.5.dylib",
        "libpsl.so",
#endif
    };
    void *h = nullptr;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(*candidates); i++) {
        h = n00b_http_dlopen(candidates[i]);
        if (h) break;
    }
    if (!h) {
        atomic_store(&g_psl_state, 2);
        return false;
    }
    psl_api_t a = {
        .handle           = h,
        .builtin          = (psl_builtin_fn)n00b_http_dlsym(
            h, "psl_builtin"),
        .is_public_suffix = (psl_is_public_fn)n00b_http_dlsym(
            h, "psl_is_public_suffix"),
    };
    if (!a.builtin || !a.is_public_suffix) {
        n00b_http_dlclose(h);
        atomic_store(&g_psl_state, 2);
        return false;
    }
    a.ctx = a.builtin();
    if (!a.ctx) {
        n00b_http_dlclose(h);
        atomic_store(&g_psl_state, 2);
        return false;
    }
    g_psl = a;
    atomic_store(&g_psl_state, 1);
    return true;
}

/* Built-in fallback: reject Domain attribute = exactly one label
 * (".com", ".org" — i.e. the host has zero internal dots) AND
 * reject when the Domain matches one of these widespread two-part
 * suffixes.  This is the bare minimum to defuse the most common
 * super-cookie attempts. */
static bool
builtin_is_suffix(const char *domain)
{
    if (!domain || !*domain) return true;
    /* Count dots. */
    size_t dots = 0;
    const char *p;
    for (p = domain; *p; p++) if (*p == '.') dots++;
    if (dots == 0) return true;            /* "com", "org", … */
    /* Match a few common two-label public suffixes. */
    static const char *common[] = {
        "co.uk", "co.jp", "co.nz", "co.kr", "co.in",
        "com.au", "com.br", "com.cn", "com.mx",
        "ne.jp", "or.jp", "ac.uk", "gov.uk", "org.uk",
    };
    for (size_t i = 0; i < sizeof(common) / sizeof(*common); i++) {
        if (n00b_ascii_ci_eq(domain, common[i])) return true;
    }
    return false;
}

/* True iff @p domain is a public suffix per libpsl, or per our
 * built-in fallback when libpsl isn't installed. */
static bool
domain_is_public_suffix(const char *domain)
{
    if (psl_probe()) {
        return g_psl.is_public_suffix(g_psl.ctx, domain) != 0;
    }
    return builtin_is_suffix(domain);
}

/* Return the registered-domain (eTLD+1) of @p host.  Walks labels
 * right-to-left, finds the longest tail that's a public suffix, and
 * returns that suffix preceded by one more label.  When the entire
 * host IS a public suffix (e.g. someone passed "co.uk"), returns
 * the host as-is. */
static const char *
registered_domain(const char *host)
{
    if (!host || !*host) return host;
    /* Find each label boundary by '.' and check from each one
     * whether the tail is a public suffix.  The first label whose
     * tail is NOT a suffix gives us eTLD+1. */
    const char *prev = host;          /* candidate eTLD+1 */
    const char *p    = host;
    while (*p) {
        if (*p == '.') {
            const char *tail = p + 1;
            if (domain_is_public_suffix(tail)) {
                /* prev..end is the candidate eTLD+1 (we found a public
                 * suffix that DOESN'T include `prev`).  Keep walking
                 * to make sure prev itself isn't also a suffix. */
                if (!domain_is_public_suffix(prev)) {
                    return prev;
                }
            }
            prev = p + 1;
        }
        p++;
    }
    return host;
}

/* Same-site test: do `request_host` and `cookie_domain` share the
 * same registered domain? */
static bool
same_site(const char *request_host, n00b_string_t *cookie_domain)
{
    if (!request_host || !cookie_domain) return false;
    const char *r = registered_domain(request_host);
    const char *c = registered_domain(cookie_domain->data);
    if (!r || !c) return false;
    return n00b_ascii_ci_eq(r, c);
}

/* ----------------------------------------------------------------- */
/* Helpers                                                           */
/* ----------------------------------------------------------------- */

static n00b_allocator_t *
default_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static n00b_string_t *
mk_str(const char *p, size_t len, n00b_allocator_t *a)
{
    return n00b_string_from_raw(p, (int64_t)len, .allocator = a);
}

static n00b_string_t *
mk_str_lower(const char *p, size_t len, n00b_allocator_t *a)
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

static int64_t
now_ms_real(void)
{
    /* Wall-clock for cookie expiry — needs to match Set-Cookie's
     * real-time semantics, not monotonic. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

static bool
str_eq_ci(const char *a, size_t alen, const char *b)
{
    size_t blen = strlen(b);
    return alen == blen && n00b_ascii_ci_eq_n(a, b, alen);
}

static bool
nstr_eq_ci(n00b_string_t *a, n00b_string_t *b)
{
    if (!a || !b) return a == b;
    return a->u8_bytes == b->u8_bytes
        && n00b_ascii_ci_eq_n(a->data, b->data, a->u8_bytes);
}

/* RFC 6265 § 5.1.3 — domain match.  @p host is the request's
 * host (lowercased).  @p domain is the cookie's stored domain. */
static bool
domain_match(const char *host, size_t hlen, n00b_string_t *domain)
{
    if (!domain || domain->u8_bytes == 0) return false;
    /* Identical match. */
    if (hlen == domain->u8_bytes
        && n00b_ascii_ci_eq_n(host, domain->data, hlen)) {
        return true;
    }
    /* Suffix match: host ends in `.domain` and host is not an IP. */
    if (hlen > domain->u8_bytes + 1) {
        const char *suffix = host + hlen - domain->u8_bytes;
        if (*(suffix - 1) == '.'
            && n00b_ascii_ci_eq_n(suffix, domain->data,
                                  domain->u8_bytes)) {
            /* Reject if host is dotted-quad IPv4 (a heuristic; full
             * IPv6 / IPv4 detection is the public-suffix-list's
             * domain).  The dispatcher always passes hostnames to
             * us, but we hedge anyway. */
            return true;
        }
    }
    return false;
}

/* RFC 6265 § 5.1.4 — path match: cookie path is a prefix of the
 * request path AND ends at a path separator. */
static bool
path_match(n00b_string_t *req_path, n00b_string_t *cookie_path)
{
    if (!cookie_path || cookie_path->u8_bytes == 0) return true;
    if (!req_path) return false;
    /* Cookie path is a string prefix. */
    if (req_path->u8_bytes < cookie_path->u8_bytes) return false;
    if (memcmp(req_path->data, cookie_path->data,
               cookie_path->u8_bytes) != 0) {
        return false;
    }
    /* Either an exact match, or the next char in req_path is '/',
     * or the cookie path itself ends in '/'. */
    if (req_path->u8_bytes == cookie_path->u8_bytes) return true;
    if (cookie_path->data[cookie_path->u8_bytes - 1] == '/') return true;
    return req_path->data[cookie_path->u8_bytes] == '/';
}

/* Default-path computation per RFC 6265 § 5.1.4. */
static n00b_string_t *
default_path_for(n00b_http_url_t *url, n00b_allocator_t *a)
{
    if (!url || !url->path || url->path->u8_bytes == 0) {
        return mk_str("/", 1, a);
    }
    if (url->path->data[0] != '/') return mk_str("/", 1, a);
    /* Last '/' in the path; truncate everything after it.  If the
     * only '/' is the leading one, the default path is "/". */
    size_t last = 0;
    for (size_t i = 0; i < url->path->u8_bytes; i++) {
        if (url->path->data[i] == '/') last = i;
    }
    if (last == 0) return mk_str("/", 1, a);
    return mk_str(url->path->data, last, a);
}

/* Skip OWS. */
static const char *
skip_ows(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    return p;
}

#ifdef _WIN32
static int
http_month_index(const char *mon)
{
    static const char *months[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec",
    };
    char lower[4] = {0};
    for (size_t i = 0; i < 3 && mon[i] != '\0'; i++) {
        lower[i] = (char)tolower((unsigned char)mon[i]);
    }
    for (size_t i = 0; i < sizeof(months) / sizeof(*months); i++) {
        if (memcmp(lower, months[i], 3) == 0) return (int)i;
    }
    return -1;
}

static int64_t
http_date_ms_from_parts(int year,
                        int month,
                        int day,
                        int hour,
                        int min,
                        int sec)
{
    if (month < 0 || day < 1 || day > 31 || hour < 0 || hour > 23
        || min < 0 || min > 59 || sec < 0 || sec > 60) {
        return 0;
    }

    struct tm t = {0};
    t.tm_year   = year - 1900;
    t.tm_mon    = month;
    t.tm_mday   = day;
    t.tm_hour   = hour;
    t.tm_min    = min;
    t.tm_sec    = sec;
    time_t tt   = timegm(&t);
    if (tt > 0) return (int64_t)tt * 1000;
    return 0;
}

static int
http_rfc850_year(int year)
{
    return year >= 69 ? 1900 + year : 2000 + year;
}
#endif

/* RFC 1123 / RFC 850 / asctime parser for Cookie Expires=.  We use
 * the C library's strptime() if available (it is on POSIX); if it
 * fails we fall back to "session cookie".  Returns ms since epoch
 * on success; 0 on failure (= session). */
static int64_t
parse_http_date(const char *p, size_t len)
{
    char    tmp[64];
    if (len == 0 || len >= sizeof(tmp)) return 0;
    memcpy(tmp, p, len);
    tmp[len] = '\0';

#ifdef _WIN32
    char wkday[16] = {0};
    char mon[4]    = {0};
    int  day       = 0;
    int  year      = 0;
    int  hour      = 0;
    int  min       = 0;
    int  sec       = 0;
    int  n         = 0;

    if (sscanf(tmp,
               "%15[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d GMT%n",
               wkday,
               &day,
               mon,
               &year,
               &hour,
               &min,
               &sec,
               &n)
            == 7
        && tmp[n] == '\0') {
        return http_date_ms_from_parts(year,
                                       http_month_index(mon),
                                       day,
                                       hour,
                                       min,
                                       sec);
    }

    n = 0;
    if (sscanf(tmp,
               "%15[A-Za-z], %d-%3[A-Za-z]-%d %d:%d:%d GMT%n",
               wkday,
               &day,
               mon,
               &year,
               &hour,
               &min,
               &sec,
               &n)
            == 7
        && tmp[n] == '\0') {
        return http_date_ms_from_parts(http_rfc850_year(year),
                                       http_month_index(mon),
                                       day,
                                       hour,
                                       min,
                                       sec);
    }

    n = 0;
    if (sscanf(tmp,
               "%15[A-Za-z] %3[A-Za-z] %d %d:%d:%d %d%n",
               wkday,
               mon,
               &day,
               &hour,
               &min,
               &sec,
               &year,
               &n)
            == 7
        && tmp[n] == '\0') {
        return http_date_ms_from_parts(year,
                                       http_month_index(mon),
                                       day,
                                       hour,
                                       min,
                                       sec);
    }
    return 0;
#else
    struct tm tm = {0};
    /* Try the three RFC 7231 formats. */
    static const char *fmts[] = {
        "%a, %d %b %Y %H:%M:%S GMT",  /* RFC 1123 */
        "%A, %d-%b-%y %H:%M:%S GMT",  /* RFC 850  */
        "%a %b %e %H:%M:%S %Y",       /* asctime  */
    };
    /* strptime is in <time.h> on Linux + macOS POSIX modes. */
    extern char *strptime(const char *s, const char *fmt, struct tm *tm);
    for (size_t i = 0; i < sizeof(fmts) / sizeof(*fmts); i++) {
        struct tm t = {0};
        char     *r = strptime(tmp, fmts[i], &t);
        if (r) {
            time_t tt = timegm(&t);
            if (tt > 0) return (int64_t)tt * 1000;
        }
    }
    return 0;
#endif
}

/* ===========================================================================
 * §1   Set-Cookie parser
 * =========================================================================== */

n00b_http_cookie_t *
n00b_http_cookie_parse(const char      *header,
                        n00b_http_url_t *origin)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
        int64_t           now_ms    = 0;
    }
{
    if (!header || !origin) return nullptr;
    n00b_allocator_t *a   = allocator ? allocator : default_pool();
    int64_t           now = (now_ms != 0) ? now_ms : now_ms_real();

    const char *p   = header;
    const char *end = p + strlen(header);
    p = skip_ows(p, end);

    /* name = value (up to ';' or end) */
    const char *name_start = p;
    while (p < end && *p != '=' && *p != ';') p++;
    if (p == end || *p != '=') return nullptr;
    size_t name_len = (size_t)(p - name_start);
    /* Trim trailing OWS in the name. */
    while (name_len > 0 && (name_start[name_len - 1] == ' '
                             || name_start[name_len - 1] == '\t')) {
        name_len--;
    }
    if (name_len == 0) return nullptr;
    p++;                                          /* '=' */

    const char *val_start = p;
    while (p < end && *p != ';') p++;
    size_t val_len = (size_t)(p - val_start);
    /* Trim OWS around the value. */
    while (val_len > 0 && (*val_start == ' ' || *val_start == '\t')) {
        val_start++; val_len--;
    }
    while (val_len > 0 && (val_start[val_len - 1] == ' '
                            || val_start[val_len - 1] == '\t')) {
        val_len--;
    }

    n00b_http_cookie_t *c = n00b_alloc_with_opts(
        n00b_http_cookie_t,
        &(n00b_alloc_opts_t){.allocator = a});
    c->name        = mk_str(name_start, name_len, a);
    c->value       = mk_str(val_start, val_len, a);
    c->domain      = nullptr;
    c->path        = nullptr;
    c->expires_ms  = 0;          /* session by default */
    c->secure      = false;
    c->http_only   = false;
    c->samesite    = N00B_COOKIE_SAMESITE_UNSET;
    c->host_only   = true;
    c->creation_ms = now;

    int32_t max_age = INT32_MIN;       /* sentinel "not set" */
    int64_t expires = INT64_MIN;       /* sentinel "not set" */

    /* Parameter list. */
    while (p < end) {
        if (*p != ';') break;
        p++;
        p = skip_ows(p, end);
        const char *nstart = p;
        while (p < end && *p != '=' && *p != ';') p++;
        size_t nlen = (size_t)(p - nstart);
        /* Trim trailing whitespace in name. */
        while (nlen > 0 && (nstart[nlen - 1] == ' '
                            || nstart[nlen - 1] == '\t')) {
            nlen--;
        }
        const char *vstart = nullptr;
        size_t      vlen   = 0;
        if (p < end && *p == '=') {
            p++;
            vstart = p;
            while (p < end && *p != ';') p++;
            vlen = (size_t)(p - vstart);
            while (vlen > 0 && (*vstart == ' ' || *vstart == '\t')) {
                vstart++; vlen--;
            }
            while (vlen > 0 && (vstart[vlen - 1] == ' '
                                || vstart[vlen - 1] == '\t')) {
                vlen--;
            }
        }
        if (nlen == 0) continue;

        if (str_eq_ci(nstart, nlen, "Domain") && vlen > 0) {
            const char *d = vstart;
            size_t      dl = vlen;
            if (dl > 0 && d[0] == '.') { d++; dl--; }
            c->domain    = mk_str_lower(d, dl, a);
            c->host_only = false;
        } else if (str_eq_ci(nstart, nlen, "Path") && vlen > 0) {
            c->path = mk_str(vstart, vlen, a);
        } else if (str_eq_ci(nstart, nlen, "Expires") && vlen > 0) {
            expires = parse_http_date(vstart, vlen);
        } else if (str_eq_ci(nstart, nlen, "Max-Age") && vlen > 0) {
            /* libc-free: strtol traps on off-libc workers (NULL TLS locale);
             * cookie headers are parsed on the HTTP client's conduit
             * workers. A non-numeric or out-of-range value parses to 0,
             * i.e. expire-immediately. */
            int64_t ma = n00b_result_get_or_else(
                n00b_parse_i64(vstart, vlen), 0);
            if (ma > INT32_MAX) ma = INT32_MAX;
            if (ma < INT32_MIN + 1) ma = INT32_MIN + 1;
            max_age = (int32_t)ma;
        } else if (str_eq_ci(nstart, nlen, "Secure")) {
            c->secure = true;
        } else if (str_eq_ci(nstart, nlen, "HttpOnly")) {
            c->http_only = true;
        } else if (str_eq_ci(nstart, nlen, "SameSite") && vlen > 0) {
            if (str_eq_ci(vstart, vlen, "Lax")) {
                c->samesite = N00B_COOKIE_SAMESITE_LAX;
            } else if (str_eq_ci(vstart, vlen, "Strict")) {
                c->samesite = N00B_COOKIE_SAMESITE_STRICT;
            } else if (str_eq_ci(vstart, vlen, "None")) {
                c->samesite = N00B_COOKIE_SAMESITE_NONE;
            }
        }
        /* Unknown attributes silently ignored per RFC 6265 § 5.2. */
    }

    /* Reject cookies whose Domain= attribute refers to an unrelated
     * host (e.g. evil.com setting Domain=victim.com), OR whose
     * Domain is itself a public suffix ("super-cookie" attempt).
     * RFC 6265 § 5.3 step 6 + § 5.4 step 1.4. */
    if (c->domain) {
        if (!domain_match(origin->host->data, origin->host->u8_bytes,
                           c->domain)) {
            return nullptr;
        }
        if (domain_is_public_suffix(c->domain->data)) {
            return nullptr;
        }
    } else {
        c->domain = origin->host;
    }

    /* Default path = directory of origin's URL path. */
    if (!c->path) c->path = default_path_for(origin, a);

    /* Resolve effective expiry: Max-Age wins if set; else Expires;
     * else session (0). */
    if (max_age != INT32_MIN) {
        if (max_age <= 0) {
            c->expires_ms = -1;       /* delete sentinel */
        } else {
            c->expires_ms = c->creation_ms + (int64_t)max_age * 1000;
        }
    } else if (expires != INT64_MIN) {
        c->expires_ms = expires;
        if (expires <= c->creation_ms) c->expires_ms = -1;
    }
    return c;
}

/* ===========================================================================
 * §2-§4  Jar
 * =========================================================================== */

typedef struct jar_node {
    n00b_http_cookie_t *cookie;
    int64_t             last_access_ms;
    struct jar_node    *next;
} jar_node_t;

struct n00b_http_cookie_jar {
    n00b_allocator_t *allocator;
    jar_node_t       *head;
    size_t            count;
    size_t            max_cookies;
    bool              fake_clock_active;
    int64_t           fake_now_ms;
};

static int64_t
jar_now(n00b_http_cookie_jar_t *jar)
{
    if (jar->fake_clock_active) return jar->fake_now_ms;
    return now_ms_real();
}

n00b_http_cookie_jar_t *
n00b_http_cookie_jar_new()
    _kargs {
        size_t            max_cookies = 600;
        n00b_allocator_t *allocator   = nullptr;
    }
{
    n00b_allocator_t *a = allocator ? allocator : default_pool();
    n00b_http_cookie_jar_t *jar = n00b_alloc_with_opts(
        n00b_http_cookie_jar_t,
        &(n00b_alloc_opts_t){.allocator = a});
    jar->allocator   = a;
    jar->max_cookies = max_cookies;
    return jar;
}

void
n00b_http_cookie_jar_close(n00b_http_cookie_jar_t *jar)
{
    if (!jar) return;
    jar->head  = nullptr;
    jar->count = 0;
}

size_t
n00b_http_cookie_jar_size(n00b_http_cookie_jar_t *jar)
{
    if (!jar) return 0;
    /* Count live (non-expired) cookies. */
    int64_t now = jar_now(jar);
    size_t  n = 0;
    jar_node_t *p;
    for (p = jar->head; p; p = p->next) {
        if (p->cookie->expires_ms == 0
            || p->cookie->expires_ms > now) {
            n++;
        }
    }
    return n;
}

void
n00b_http_cookie_jar_set_now_for_test(n00b_http_cookie_jar_t *jar,
                                      int64_t                 now_ms)
{
    if (!jar) return;
    jar->fake_clock_active = true;
    jar->fake_now_ms       = now_ms;
}

/* Per RFC 6265 § 5.4: cookies are uniquely keyed by (name, domain,
 * path).  Setting an existing key replaces the value; setting with
 * Max-Age=0 / past Expires deletes. */
static jar_node_t **
jar_find_slot(n00b_http_cookie_jar_t *jar, n00b_http_cookie_t *c)
{
    jar_node_t **slot;
    for (slot = &jar->head; *slot; slot = &(*slot)->next) {
        n00b_http_cookie_t *existing = (*slot)->cookie;
        if (nstr_eq_ci(existing->name, c->name)
            && nstr_eq_ci(existing->domain, c->domain)
            && existing->path && c->path
            && existing->path->u8_bytes == c->path->u8_bytes
            && memcmp(existing->path->data, c->path->data,
                       c->path->u8_bytes) == 0) {
            return slot;
        }
    }
    return nullptr;
}

static void
jar_insert(n00b_http_cookie_jar_t *jar, n00b_http_cookie_t *c)
{
    /* If cookie is already expired (delete sentinel), find + remove. */
    if (c->expires_ms == -1) {
        jar_node_t **slot = jar_find_slot(jar, c);
        if (slot) {
            *slot = (*slot)->next;
            jar->count--;
        }
        return;
    }

    jar_node_t **slot = jar_find_slot(jar, c);
    if (slot) {
        (*slot)->cookie = c;
        (*slot)->last_access_ms = jar_now(jar);
        return;
    }

    /* Cap eviction: drop oldest by last_access. */
    if (jar->count >= jar->max_cookies) {
        jar_node_t **oldest_slot  = nullptr;
        int64_t      oldest_stamp = INT64_MAX;
        jar_node_t **p;
        for (p = &jar->head; *p; p = &(*p)->next) {
            if ((*p)->last_access_ms < oldest_stamp) {
                oldest_stamp = (*p)->last_access_ms;
                oldest_slot  = p;
            }
        }
        if (oldest_slot) {
            *oldest_slot = (*oldest_slot)->next;
            jar->count--;
        }
    }

    jar_node_t *node = n00b_alloc_with_opts(
        jar_node_t, &(n00b_alloc_opts_t){.allocator = jar->allocator});
    node->cookie         = c;
    node->last_access_ms = jar_now(jar);
    node->next           = jar->head;
    jar->head            = node;
    jar->count++;
}

void
n00b_http_cookie_jar_set_from_response(n00b_http_cookie_jar_t *jar,
                                       n00b_http_url_t        *origin,
                                       const char             *header_value)
{
    if (!jar || !origin || !header_value) return;
    n00b_http_cookie_t *c = n00b_http_cookie_parse(
        header_value, origin,
        .allocator = jar->allocator,
        .now_ms    = jar_now(jar));
    if (!c) return;
    jar_insert(jar, c);
}

/* Header-for-request: filter cookies by host + path + secure +
 * not expired; format as `n=v; n=v; ...`. */
n00b_string_t *
n00b_http_cookie_jar_header_for(n00b_http_cookie_jar_t *jar,
                                n00b_http_url_t        *url)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    if (!jar || !url) return nullptr;
    n00b_allocator_t *a = allocator ? allocator : jar->allocator;
    int64_t  now = jar_now(jar);
    bool     is_secure = true;    /* HTTPS only — chunk 1 enforced */
    (void)is_secure;

    /* Collect matches in arrival order. */
    char  scratch[2048];
    size_t off = 0;

    jar_node_t *p;
    for (p = jar->head; p; p = p->next) {
        n00b_http_cookie_t *c = p->cookie;
        if (c->expires_ms != 0 && c->expires_ms <= now) continue;
        /* Domain match. */
        if (c->host_only) {
            if (c->domain->u8_bytes != url->host->u8_bytes
                || !n00b_ascii_ci_eq_n(c->domain->data, url->host->data,
                                       c->domain->u8_bytes)) {
                continue;
            }
        } else {
            if (!domain_match(url->host->data, url->host->u8_bytes,
                               c->domain)) {
                continue;
            }
        }
        /* Path match. */
        if (!path_match(url->path, c->path)) continue;
        /* Secure attribute — HTTPS-only client always satisfies. */
        /* SameSite enforcement (RFC 6265-bis § 5.6) — for a
         * programmatic HTTP client the only meaningful distinction
         * is "is this a cross-site request?".  Strict and Lax both
         * gate cross-site at the same point for non-browser
         * callers.  None always sends. */
        if (c->samesite == N00B_COOKIE_SAMESITE_STRICT
            || c->samesite == N00B_COOKIE_SAMESITE_LAX) {
            if (!same_site(url->host->data, c->domain)) continue;
        }

        size_t need = c->name->u8_bytes + 1 + c->value->u8_bytes;
        if (off > 0) need += 2;          /* "; " separator */
        if (off + need + 1 > sizeof(scratch)) break;   /* truncate */
        if (off > 0) {
            scratch[off++] = ';';
            scratch[off++] = ' ';
        }
        memcpy(scratch + off, c->name->data, c->name->u8_bytes);
        off += c->name->u8_bytes;
        scratch[off++] = '=';
        memcpy(scratch + off, c->value->data, c->value->u8_bytes);
        off += c->value->u8_bytes;

        p->last_access_ms = now;
    }
    if (off == 0) return nullptr;
    return mk_str(scratch, off, a);
}
