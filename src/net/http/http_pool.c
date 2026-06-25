/*
 * http_pool.c — Per-runtime HTTP connection pool.
 *
 * Phase 6 chunk 4.  Plain doubly-linked-list implementation: each
 * (origin, transport) gets its own LRU list with the head being the
 * most-recently-used.  Global LRU is maintained as a separate list
 * threaded through the same nodes so we can evict-LRU-globally in
 * O(1).
 *
 * Internally locked: every public entry point acquires the pool's
 * recursive rwlock for the duration of its work, so a per-runtime
 * pool is safe to share across HTTP-using threads (the dispatcher
 * thread block, ACME's many-call serial path, plus arbitrary
 * caller threads that pass the same pool kwarg).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/time.h"
#include "core/data_lock.h"
#include "adt/list.h"
#include "internal/net/http/http_pool.h"

/* ----------------------------------------------------------------- */
/* Internal types                                                    */
/* ----------------------------------------------------------------- */

typedef struct pool_entry {
    /* Bucket linkage. */
    struct pool_entry          *bucket_prev;
    struct pool_entry          *bucket_next;

    /* Global-LRU linkage. */
    struct pool_entry          *lru_prev;
    struct pool_entry          *lru_next;

    /* Pointer back to bucket (avoids extra dict lookups on eviction). */
    struct pool_bucket         *bucket;

    void                       *user_data;
    n00b_http_connection_pool_close_fn     close_fn;
    n00b_http_connection_pool_transport_t  transport;
    uint64_t                    admitted_at_ms; /* lifetime cap base. */
    uint64_t                    last_used_at_ms;
} pool_entry_t;

typedef struct pool_bucket {
    /* Composite key: <transport>|<origin> — identical strings for
     * "same origin via same transport"; different transports keep
     * separate buckets so an h1 fd doesn't satisfy an h3 acquire. */
    n00b_string_t              *key;        /* "h1|origin" or "h3|origin" */
    pool_entry_t               *head;       /* MRU */
    pool_entry_t               *tail;       /* LRU */
    size_t                      count;
    struct pool_bucket         *map_next;   /* hash collision chain */
} pool_bucket_t;

#define POOL_BUCKETS 64

struct n00b_http_connection_pool {
    n00b_allocator_t      *allocator;
    /* Recursive rwlock guarding the buckets / LRU / idle_count /
     * stats fields below.  May be null in single-threaded test
     * fixtures (the lock helpers are null-safe no-ops). */
    n00b_rwlock_t         *lock;
    pool_bucket_t         *buckets[POOL_BUCKETS];
    pool_entry_t          *lru_head;        /* MRU */
    pool_entry_t          *lru_tail;        /* LRU */
    size_t                 idle_count;

    size_t                 max_total_idle;
    size_t                 max_per_origin;
    uint64_t               idle_timeout_ms;
    uint64_t               lifetime_ms;

    bool                   fake_now_active; /* tests inject a clock. */
    uint64_t               fake_now_ms;

    n00b_http_connection_pool_stats_t stats;
};

/* ----------------------------------------------------------------- */
/* Helpers                                                           */
/* ----------------------------------------------------------------- */

static n00b_allocator_t *
default_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static uint64_t
now_ms(n00b_http_connection_pool_t *p)
{
    if (p->fake_now_active) return p->fake_now_ms;
    return n00b_ns_timestamp() / 1000000ULL;
}

static const char *
transport_prefix(n00b_http_connection_pool_transport_t t)
{
    switch (t) {
    case N00B_HTTP_CONNECTION_POOL_TRANSPORT_H1: return "h1|";
    case N00B_HTTP_CONNECTION_POOL_TRANSPORT_H3: return "h3|";
    }
    return "??|";
}

/* FNV-1a 32-bit on the bucket key. */
static uint32_t
hash_str(const char *s, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619u;
    }
    return h;
}

static n00b_string_t *
build_key(n00b_http_connection_pool_t           *p,
          n00b_string_t              *origin,
          n00b_http_connection_pool_transport_t  transport)
{
    const char *pref     = transport_prefix(transport);
    size_t      pref_len = strlen(pref);
    size_t      total    = pref_len + origin->u8_bytes;
    char       *buf      = n00b_alloc_array_with_opts(
        char,
        total + 1,
        &(n00b_alloc_opts_t){.allocator = p->allocator, .no_scan = true});
    memcpy(buf, pref, pref_len);
    memcpy(buf + pref_len, origin->data, origin->u8_bytes);
    buf[total] = '\0';
    n00b_string_t *key = n00b_alloc_with_opts(
        n00b_string_t,
        &(n00b_alloc_opts_t){.allocator = p->allocator});
    key->data       = buf;
    key->u8_bytes   = total;
    key->codepoints = total;
    key->styling    = nullptr;
    return key;
}

static void
free_key(n00b_http_connection_pool_t *p, n00b_string_t *key)
{
    if (!p || !key) return;
    if (key->data) {
        n00b_free_with_allocator_hint(p->allocator, key->data);
        key->data = nullptr;
    }
    n00b_free_with_allocator_hint(p->allocator, key);
}

static pool_bucket_t *
find_or_create_bucket(n00b_http_connection_pool_t *p, n00b_string_t *key, bool create)
{
    uint32_t        idx = hash_str(key->data, key->u8_bytes) & (POOL_BUCKETS - 1);
    pool_bucket_t **slot = &p->buckets[idx];
    pool_bucket_t  *b;
    for (b = *slot; b; b = b->map_next) {
        if (b->key->u8_bytes == key->u8_bytes
            && memcmp(b->key->data, key->data, key->u8_bytes) == 0) {
            return b;
        }
    }
    if (!create) return nullptr;
    b = n00b_alloc_with_opts(
        pool_bucket_t,
        &(n00b_alloc_opts_t){.allocator = p->allocator});
    b->key      = key;
    b->head     = nullptr;
    b->tail     = nullptr;
    b->count    = 0;
    b->map_next = *slot;
    *slot       = b;
    return b;
}

/* Bucket linkage maintenance. */
static void
bucket_push_mru(pool_bucket_t *b, pool_entry_t *e)
{
    e->bucket_prev = nullptr;
    e->bucket_next = b->head;
    if (b->head) b->head->bucket_prev = e;
    b->head = e;
    if (!b->tail) b->tail = e;
    b->count++;
}

static void
bucket_unlink(pool_bucket_t *b, pool_entry_t *e)
{
    if (e->bucket_prev) e->bucket_prev->bucket_next = e->bucket_next;
    else                b->head = e->bucket_next;
    if (e->bucket_next) e->bucket_next->bucket_prev = e->bucket_prev;
    else                b->tail = e->bucket_prev;
    b->count--;
}

/* Global-LRU linkage. */
static void
lru_push_head(n00b_http_connection_pool_t *p, pool_entry_t *e)
{
    e->lru_prev = nullptr;
    e->lru_next = p->lru_head;
    if (p->lru_head) p->lru_head->lru_prev = e;
    p->lru_head = e;
    if (!p->lru_tail) p->lru_tail = e;
}

static void
lru_unlink(n00b_http_connection_pool_t *p, pool_entry_t *e)
{
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             p->lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             p->lru_tail = e->lru_prev;
}

/* Remove an entry, invoke close_fn, and update counters. */
static void
drop_entry(n00b_http_connection_pool_t *p, pool_entry_t *e)
{
    bucket_unlink(e->bucket, e);
    lru_unlink(p, e);
    p->idle_count--;
    if (e->close_fn) e->close_fn(e->user_data);
    n00b_free_with_allocator_hint(p->allocator, e);
}

/* ----------------------------------------------------------------- */
/* Lifecycle                                                         */
/* ----------------------------------------------------------------- */

n00b_http_connection_pool_t *
n00b_http_connection_pool_new()
    _kargs {
        size_t            max_total_idle  = 16;
        size_t            max_per_origin  = 4;
        int32_t           idle_timeout_ms = 30000;
        int32_t           lifetime_ms     = 600000;
        n00b_allocator_t *allocator       = nullptr;
    }
{
    n00b_allocator_t *a = allocator ? allocator : default_pool();
    n00b_http_connection_pool_t *p = n00b_alloc_with_opts(
        n00b_http_connection_pool_t,
        &(n00b_alloc_opts_t){.allocator = a});
    p->allocator       = a;
    p->lock            = n00b_data_lock_new();
    p->max_total_idle  = max_total_idle;
    p->max_per_origin  = max_per_origin;
    p->idle_timeout_ms = idle_timeout_ms < 0 ? 0 : (uint64_t)idle_timeout_ms;
    p->lifetime_ms     = lifetime_ms < 0 ? 0 : (uint64_t)lifetime_ms;
    return p;
}

void
n00b_http_connection_pool_close(n00b_http_connection_pool_t *pool)
{
    if (!pool) return;
    n00b_data_write_lock(pool->lock);
    /* Drop everything via close-fns. */
    while (pool->lru_head) {
        drop_entry(pool, pool->lru_head);
    }
    /* Bucket structs themselves live in the pool's allocator and
     * get reaped by the GC once `pool` is unreachable. */
    n00b_data_unlock(pool->lock);
}

/* ----------------------------------------------------------------- */
/* Acquire / release                                                 */
/* ----------------------------------------------------------------- */

void *
n00b_http_connection_pool_acquire(n00b_http_connection_pool_t           *pool,
                       n00b_string_t              *origin,
                       n00b_http_connection_pool_transport_t  transport)
{
    if (!pool || !origin) return nullptr;
    n00b_data_write_lock(pool->lock);
    n00b_string_t *key = build_key(pool, origin, transport);
    pool_bucket_t *b   = find_or_create_bucket(pool, key, false);
    if (!b || !b->head) {
        free_key(pool, key);
        pool->stats.acquire_misses++;
        n00b_data_unlock(pool->lock);
        return nullptr;
    }
    free_key(pool, key);
    pool_entry_t *e = b->head;
    void         *u = e->user_data;
    bucket_unlink(b, e);
    lru_unlink(pool, e);
    pool->idle_count--;
    pool->stats.acquire_hits++;
    n00b_free_with_allocator_hint(pool->allocator, e);
    n00b_data_unlock(pool->lock);
    return u;
}

static void
admit_evict_for_caps(n00b_http_connection_pool_t *p, pool_bucket_t *b)
{
    /* Per-origin cap. */
    if (p->max_per_origin > 0 && b->count >= p->max_per_origin) {
        pool_entry_t *victim = b->tail;
        if (victim) {
            drop_entry(p, victim);
            p->stats.evict_cap_per_origin++;
        }
    }
    /* Global cap. */
    if (p->max_total_idle > 0 && p->idle_count >= p->max_total_idle) {
        pool_entry_t *victim = p->lru_tail;
        if (victim) {
            drop_entry(p, victim);
            p->stats.evict_cap_total++;
        }
    }
}

void
n00b_http_connection_pool_release(n00b_http_connection_pool_t           *pool,
                       n00b_string_t              *origin,
                       n00b_http_connection_pool_transport_t  transport,
                       void                       *user_data,
                       n00b_http_connection_pool_close_fn     close_fn)
{
    if (!pool || !origin || !close_fn) {
        if (close_fn) close_fn(user_data);
        return;
    }
    n00b_data_write_lock(pool->lock);
    n00b_string_t *key = build_key(pool, origin, transport);
    pool_bucket_t *b   = find_or_create_bucket(pool, key, true);
    if (b && b->key != key) {
        free_key(pool, key);
    }

    admit_evict_for_caps(pool, b);

    pool_entry_t *e = n00b_alloc_with_opts(
        pool_entry_t,
        &(n00b_alloc_opts_t){.allocator = pool->allocator});
    e->bucket           = b;
    e->user_data        = user_data;
    e->close_fn         = close_fn;
    e->transport        = transport;
    e->admitted_at_ms   = now_ms(pool);
    e->last_used_at_ms  = e->admitted_at_ms;

    bucket_push_mru(b, e);
    lru_push_head(pool, e);
    pool->idle_count++;
    n00b_data_unlock(pool->lock);
}

/* ----------------------------------------------------------------- */
/* Reap                                                              */
/* ----------------------------------------------------------------- */

void
n00b_http_connection_pool_reap(n00b_http_connection_pool_t *pool, uint64_t now)
{
    if (!pool) return;
    n00b_data_write_lock(pool->lock);
    pool_entry_t *e = pool->lru_tail;
    while (e) {
        pool_entry_t *prev = e->lru_prev;
        bool         drop  = false;
        if (pool->idle_timeout_ms
            && now > e->last_used_at_ms
            && (now - e->last_used_at_ms) >= pool->idle_timeout_ms) {
            pool->stats.evict_idle_timeout++;
            drop = true;
        } else if (pool->lifetime_ms
            && now > e->admitted_at_ms
            && (now - e->admitted_at_ms) >= pool->lifetime_ms) {
            pool->stats.evict_lifetime++;
            drop = true;
        }
        if (drop) drop_entry(pool, e);
        e = prev;
    }
    n00b_data_unlock(pool->lock);
}

/* ----------------------------------------------------------------- */
/* Stats                                                             */
/* ----------------------------------------------------------------- */

n00b_http_connection_pool_stats_t
n00b_http_connection_pool_stats(n00b_http_connection_pool_t *pool)
{
    if (!pool) return (n00b_http_connection_pool_stats_t){0};
    n00b_data_read_lock(pool->lock);
    n00b_http_connection_pool_stats_t s = pool->stats;
    s.idle_count = pool->idle_count;
    n00b_data_unlock(pool->lock);
    return s;
}

void
n00b_http_connection_pool_set_now_for_test(n00b_http_connection_pool_t *pool, uint64_t now)
{
    if (!pool) return;
    n00b_data_write_lock(pool->lock);
    pool->fake_now_active = true;
    pool->fake_now_ms     = now;
    n00b_data_unlock(pool->lock);
}

/* ----------------------------------------------------------------- */
/* Per-runtime singleton                                             */
/* ----------------------------------------------------------------- */

n00b_http_connection_pool_t *
n00b_http_get_connection_pool(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) return nullptr;
    n00b_http_connection_pool_t *cur =
        atomic_load_explicit(&rt->http_connection_pool,
                              memory_order_acquire);
    if (cur) return cur;
    n00b_http_connection_pool_t *fresh = n00b_http_connection_pool_new();
    n00b_http_connection_pool_t *expected = nullptr;
    if (!atomic_compare_exchange_strong_explicit(
            &rt->http_connection_pool, &expected, fresh,
            memory_order_acq_rel, memory_order_acquire)) {
        /* Lost the race; the winner's pool is now in @p expected. */
        return expected;
    }
    return fresh;
}
