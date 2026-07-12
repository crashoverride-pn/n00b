#pragma once

#include "core/atomic.h"
#include "adt/result.h"

#define n00b_pinref(T)                                                                         \
    _Atomic(struct {                                                                           \
        T        raw;                                                                          \
        uint32_t pins;                                                                         \
        uint32_t lock : 1;                                                                     \
    })

typedef struct {
    void    *raw;
    uint32_t pins;
    uint32_t lock : 1;
} n00b_raw_pinref_t;

typedef _Atomic n00b_raw_pinref_t n00b_pinref_t;

static inline void
n00b_pinref_init(n00b_pinref_t *pref, void *raw)
{
    n00b_raw_pinref_t init = {
        .raw  = raw,
        .pins = 0,
        .lock = 0,
    };

    n00b_atomic_store(pref, init);
}

// Pin, and return the reference.
static inline void *
n00b_pinref_pin(n00b_pinref_t *pref)
{
    n00b_raw_pinref_t pinfo;
    n00b_raw_pinref_t prequest;

    while (true) {
        pinfo = n00b_atomic_load(pref);

        if (pinfo.lock) {
            continue;
        }

        prequest = pinfo;
        prequest.pins += 1;

        if (n00b_cas(pref, &pinfo, prequest)) {
            return prequest.raw;
        }
    }
}

static inline void
n00b_pinref_unpin(n00b_pinref_t *pref)
{
    n00b_raw_pinref_t pinfo;
    n00b_raw_pinref_t prequest;

    do {
        pinfo = n00b_atomic_load(pref);

        prequest = pinfo;
        prequest.pins -= 1;
    } while (!n00b_cas(pref, &pinfo, prequest));
}

// The pin lock allows a thread to clear readers so that a backing store
// can be immediately coppied out once the pin lock is acquired.
//
// But if multiple threads try to lock at once, we return none(void *) so
// that losing threads know to re-acquire the pin.

static inline n00b_result_t(void *) __n00b_pinref_lock(n00b_pinref_t *pref)
{
    n00b_raw_pinref_t pinfo;
    n00b_raw_pinref_t prequest;

    do {
        pinfo = n00b_atomic_load(pref);

        if (pinfo.lock) {
            return n00b_result_err(void *, 0);
        }

        prequest      = pinfo;
        prequest.lock = 1;
    } while (!n00b_cas(pref, &pinfo, prequest));

    // We have the lock, but might need to wait for pins to drain.
    pinfo = prequest;

    while (pinfo.pins) {
        pinfo = n00b_atomic_load(pref);
    }

    return n00b_result_ok(void *, pinfo.raw);
}

static inline void *
__n00b_pinref_unlock(n00b_pinref_t *pref) _kargs
{
    bool finish_pinned = false;
}
{
    n00b_raw_pinref_t pinfo  = n00b_atomic_load(pref);
    void             *result = finish_pinned ? pinfo.raw : nullptr;

    pinfo.lock = 0;
    pinfo.pins = finish_pinned;
    n00b_atomic_store(pref, pinfo);

    return result;
}

static inline void *
n00b_pinref_lock(n00b_pinref_t *pref)
{
    auto res = __n00b_pinref_lock(pref);

    return n00b_result_is_ok(res) ? n00b_result_value(res) : nullptr;
}

static inline void
n00b_pinref_unlock(n00b_pinref_t *pref)
{
    __n00b_pinref_unlock(pref);
}

// WARNING: Cannot hold the pin when updating.
static inline bool
n00b_pinref_update(n00b_pinref_t *pref, void *expected, void *desired)
{
    auto res = __n00b_pinref_lock(pref);

    if (n00b_result_is_err(res)) {
        return false;
    }

    void *actual = n00b_result_value(res);

    if (actual != expected) {
        __n00b_pinref_unlock(pref);
        return false;
    }

    n00b_raw_pinref_t pinfo = {
        .raw  = desired,
        .pins = 0,
        .lock = 0,
    };

    n00b_atomic_store(pref, pinfo);

    return true;
}
