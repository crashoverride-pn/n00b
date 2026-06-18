#define N00B_USE_INTERNAL_API

#include "n00b.h"
#include "adt/lru.h"
#include "adt/dict.h"
#include "core/alloc.h"
#include "core/data_lock.h"
#include "core/runtime.h"

// Opt-in synchronization (lru->lock != nullptr). get/put/invalidate/age all
// mutate the recency list, so they take the write lock; peek/len are read-only.
// The internal helpers (recency_*, lru_evict) assume the lock is already held.
static inline void
lru_wlock(n00b_lru_t *lru)
{
    if (lru->lock != nullptr) {
        n00b_data_write_lock(lru->lock);
    }
}

static inline void
lru_rlock(n00b_lru_t *lru)
{
    if (lru->lock != nullptr) {
        n00b_data_read_lock(lru->lock);
    }
}

static inline void
lru_unlock(n00b_lru_t *lru)
{
    if (lru->lock != nullptr) {
        n00b_data_unlock(lru->lock);
    }
}

// Recency list: head (mru) is most-recently-touched, tail (lru) is least.
// Both get and put promote the touched entry to the head, so the list is
// ordered by last-touch — which is what lets age() stop at the first
// non-expired entry walking from the tail.

static inline void
recency_unlink(n00b_lru_t *lru, n00b_lru_entry_t *e)
{
    if (e->recency_prev != nullptr) {
        e->recency_prev->recency_next = e->recency_next;
    }
    else {
        lru->mru = e->recency_next;
    }

    if (e->recency_next != nullptr) {
        e->recency_next->recency_prev = e->recency_prev;
    }
    else {
        lru->lru = e->recency_prev;
    }

    e->recency_prev = nullptr;
    e->recency_next = nullptr;
}

static inline void
recency_push_front(n00b_lru_t *lru, n00b_lru_entry_t *e)
{
    e->recency_prev = nullptr;
    e->recency_next = lru->mru;

    if (lru->mru != nullptr) {
        lru->mru->recency_prev = e;
    }
    lru->mru = e;

    if (lru->lru == nullptr) {
        lru->lru = e;
    }
}

// Remove an entry from both the recency list and the index, run the
// value destructor if configured, and clear its references so the GC can
// reclaim the entry (and a GC-owned value) once it is unreachable.
static void
lru_evict(n00b_lru_t *lru, n00b_lru_entry_t *e)
{
    recency_unlink(lru, e);
    n00b_dict_remove(lru->index, e->key);
    lru->count--;

    if (lru->value_dtor != nullptr && e->value != nullptr) {
        lru->value_dtor(e->value);
    }
    e->value = nullptr;
    e->key   = nullptr;
}

static inline bool
lru_expired(n00b_lru_t *lru, n00b_lru_entry_t *e, uint64_t now_ns)
{
    if (lru->ttl_ns == 0 || now_ns == 0) {
        return false;
    }
    if (now_ns <= e->last_touch_ns) {
        return false;
    }
    return (now_ns - e->last_touch_ns) > lru->ttl_ns;
}

// clang-format off
n00b_lru_t *
n00b_lru_init(n00b_lru_t *lru) _kargs
{
    uint32_t              max_entries = 0;
    uint64_t              ttl_ns      = 0;
    n00b_allocator_t     *allocator   = nullptr;
    n00b_lru_value_dtor_t value_dtor  = nullptr;
    bool                  locked      = false;
}
// clang-format on
{
    if (allocator == nullptr) {
        allocator = n00b_default_allocator();
    }

    lru->index = n00b_dict_new_private(n00b_string_t *,
                                       n00b_lru_entry_t *,
                                       .allocator = allocator);
    lru->mru         = nullptr;
    lru->lru         = nullptr;
    lru->count       = 0;
    lru->max_entries = max_entries;
    lru->ttl_ns      = ttl_ns;
    lru->allocator   = allocator;
    lru->value_dtor  = value_dtor;
    lru->lock        = locked ? n00b_data_lock_new(.allocator = allocator)
                              : nullptr;

    return lru;
}

void *
n00b_lru_get(n00b_lru_t *lru, n00b_string_t *key, uint64_t now_ns)
{
    // Write lock: a hit mutates the recency list (and an expired hit evicts).
    lru_wlock(lru);

    bool              found = false;
    n00b_lru_entry_t *e     = n00b_dict_get(lru->index, key, &found);

    if (!found || e == nullptr) {
        lru_unlock(lru);
        return nullptr;
    }

    if (lru_expired(lru, e, now_ns)) {
        lru_evict(lru, e);
        lru_unlock(lru);
        return nullptr;
    }

    recency_unlink(lru, e);
    recency_push_front(lru, e);
    if (now_ns != 0) {
        e->last_touch_ns = now_ns;
    }

    void *value = e->value;
    lru_unlock(lru);
    return value;
}

void *
n00b_lru_peek(n00b_lru_t *lru, n00b_string_t *key)
{
    lru_rlock(lru);

    bool              found = false;
    n00b_lru_entry_t *e     = n00b_dict_get(lru->index, key, &found);

    void *value = (found && e != nullptr) ? e->value : nullptr;
    lru_unlock(lru);
    return value;
}

void
n00b_lru_put(n00b_lru_t *lru, n00b_string_t *key, void *value, uint64_t now_ns)
{
    lru_wlock(lru);

    bool              found = false;
    n00b_lru_entry_t *e     = n00b_dict_get(lru->index, key, &found);

    if (found && e != nullptr) {
        if (lru->value_dtor != nullptr && e->value != nullptr
            && e->value != value) {
            lru->value_dtor(e->value);
        }
        e->value         = value;
        e->last_touch_ns = now_ns;
        recency_unlink(lru, e);
        recency_push_front(lru, e);
        lru_unlock(lru);
        return;
    }

    e = n00b_alloc(n00b_lru_entry_t, .allocator = lru->allocator);
    e->key           = key;
    e->value         = value;
    e->last_touch_ns = now_ns;
    e->recency_prev  = nullptr;
    e->recency_next  = nullptr;

    n00b_dict_put(lru->index, key, e);
    recency_push_front(lru, e);
    lru->count++;

    if (lru->max_entries != 0) {
        while (lru->count > lru->max_entries && lru->lru != nullptr) {
            lru_evict(lru, lru->lru);
        }
    }
    lru_unlock(lru);
}

bool
n00b_lru_invalidate(n00b_lru_t *lru, n00b_string_t *key)
{
    lru_wlock(lru);

    bool              found = false;
    n00b_lru_entry_t *e     = n00b_dict_get(lru->index, key, &found);

    if (!found || e == nullptr) {
        lru_unlock(lru);
        return false;
    }

    lru_evict(lru, e);
    lru_unlock(lru);
    return true;
}

uint32_t
n00b_lru_age(n00b_lru_t *lru, uint64_t now_ns)
{
    if (lru->ttl_ns == 0) {
        return 0;
    }

    lru_wlock(lru);

    uint32_t          evicted = 0;
    n00b_lru_entry_t *e       = lru->lru; // oldest last-touch first

    while (e != nullptr) {
        n00b_lru_entry_t *toward_mru = e->recency_prev;
        if (!lru_expired(lru, e, now_ns)) {
            // The tail is the oldest; everything nearer the head is newer,
            // so once one entry is fresh the rest are too.
            break;
        }
        lru_evict(lru, e);
        evicted++;
        e = toward_mru;
    }

    lru_unlock(lru);
    return evicted;
}

uint32_t
n00b_lru_len(n00b_lru_t *lru)
{
    lru_rlock(lru);
    uint32_t count = lru->count;
    lru_unlock(lru);
    return count;
}
