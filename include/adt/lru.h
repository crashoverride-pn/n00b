/**
 * @file lru.h
 * @brief Bounded LRU cache: O(1) keyed lookup + recency eviction + TTL aging.
 *
 * A reusable cache for state that is keyed by a string, accessed by
 * recency, and must not grow without bound — e.g. per-file or per-entity
 * records that are not tied to any owner's lifetime and would otherwise
 * accumulate for the life of a long-running process.
 *
 * Backed by a typed @ref n00b_dict (content-hashed string keys, O(1)
 * lookup) plus an intrusive doubly-linked recency list whose head is the
 * most-recently-used entry. Two independent bounds:
 *   - @c max_entries — hard cap; `put` past the cap evicts the LRU tail.
 *   - @c ttl_ns      — staleness; `age()` evicts entries untouched within
 *                      the window. `get` of an expired entry misses + evicts.
 *
 * Values are opaque (`void *`) and owned by the caller. By default an
 * evicted entry simply drops the cache's reference (the GC reclaims a
 * GC-allocated value once unreachable); supply @c value_dtor when values
 * live in a pool or otherwise need explicit teardown on eviction.
 *
 * Not internally synchronized; callers that share an instance across
 * threads must serialize (the wax lifecycle contracts drive it from a
 * single consumer thread).
 */
#pragma once

#include "n00b.h"
#include "adt/dict.h"
#include "core/alloc.h"

typedef void (*n00b_lru_value_dtor_t)(void *value);

/**
 * @brief One cache entry; also a node in the intrusive recency list.
 */
typedef struct n00b_lru_entry_t {
    struct n00b_lru_entry_t *recency_prev; /**< Toward MRU (head). */
    struct n00b_lru_entry_t *recency_next; /**< Toward LRU (tail). */
    n00b_string_t           *key;
    void                    *value;
    uint64_t                 last_touch_ns;
} n00b_lru_entry_t;

/**
 * @brief Bounded LRU cache instance. Zero-initialize, then n00b_lru_init().
 */
typedef struct n00b_lru_t {
    n00b_dict_t(n00b_string_t *, n00b_lru_entry_t *) *index;
    n00b_lru_entry_t      *mru;          /**< Most-recently-used (list head). */
    n00b_lru_entry_t      *lru;          /**< Least-recently-used (list tail). */
    uint32_t               count;
    uint32_t               max_entries;  /**< 0 == unbounded. */
    uint64_t               ttl_ns;       /**< 0 == no TTL aging. */
    n00b_allocator_t      *allocator;
    n00b_lru_value_dtor_t  value_dtor;   /**< Optional; called on evict/invalidate. */
} n00b_lru_t;

/**
 * @brief Initialize a bounded LRU cache.
 * @param lru Zero-initialized cache to set up.
 * @return    @p lru, ready for use.
 *
 * @kw max_entries Hard cap on live entries; 0 leaves the cache unbounded
 *                 (TTL aging may still bound it). Default 0.
 * @kw ttl_ns      Idle time-to-live in nanoseconds; entries untouched for
 *                 longer are evicted by `age()` / missed by `get()`. 0
 *                 disables TTL. Default 0.
 * @kw allocator   Allocator for the index, entries, and recency list.
 *                 Default: the runtime default allocator.
 * @kw value_dtor  Called on a value when its entry is evicted or
 *                 invalidated. Default nullptr (drop reference only).
 *
 * @pre @p lru points to zeroed memory.
 */
extern n00b_lru_t *
n00b_lru_init(n00b_lru_t *lru) _kargs
{
    uint32_t              max_entries = 0;
    uint64_t              ttl_ns      = 0;
    n00b_allocator_t     *allocator   = nullptr;
    n00b_lru_value_dtor_t value_dtor  = nullptr;
};

/**
 * @brief Look up @p key, promoting it to most-recently-used on a hit.
 * @param lru    Cache.
 * @param key    Lookup key (content-compared).
 * @param now_ns Current time; an entry older than @c ttl_ns is treated as a
 *               miss and evicted. Pass 0 to skip the TTL check on this call.
 * @return The stored value, or nullptr if absent or expired.
 */
extern void *
n00b_lru_get(n00b_lru_t *lru, n00b_string_t *key, uint64_t now_ns);

/**
 * @brief Look up @p key WITHOUT promoting recency or applying TTL.
 * @param lru Cache.
 * @param key Lookup key (content-compared).
 * @return The stored value, or nullptr if absent.
 *
 * @details A read-only peek: it does not touch the recency list, does not
 *          update last-touch, and does not evict expired entries. Use it
 *          when you need the value but must not perturb the cache's recency
 *          or aging state (e.g. a const lookup helper).
 */
extern void *
n00b_lru_peek(n00b_lru_t *lru, n00b_string_t *key);

/**
 * @brief Insert or update @p key, promoting it to most-recently-used.
 * @param lru    Cache.
 * @param key    Key to store under.
 * @param value  Value to associate.
 * @param now_ns Current time, recorded as the entry's last-touch.
 *
 * @post If a hard cap is set and exceeded, the least-recently-used entry is
 *       evicted first (its @c value_dtor, if any, runs).
 */
extern void
n00b_lru_put(n00b_lru_t *lru, n00b_string_t *key, void *value, uint64_t now_ns);

/**
 * @brief Remove @p key if present (running @c value_dtor on its value).
 * @return true if an entry was removed.
 */
extern bool
n00b_lru_invalidate(n00b_lru_t *lru, n00b_string_t *key);

/**
 * @brief Evict every entry whose last-touch is older than @c ttl_ns.
 * @param lru    Cache.
 * @param now_ns Current time.
 * @return Number of entries evicted. No-op (returns 0) when @c ttl_ns is 0.
 *
 * @details Intended to be called periodically (e.g. from a heartbeat) so a
 *          cache of entries that are no longer referenced shrinks back down.
 */
extern uint32_t
n00b_lru_age(n00b_lru_t *lru, uint64_t now_ns);

/**
 * @brief Current number of live entries.
 */
extern uint32_t
n00b_lru_len(n00b_lru_t *lru);
