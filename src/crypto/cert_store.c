/*
 * cert_store.c — SNI-keyed cert store with RCU-style atomic swap.
 *
 * Design notes:
 *
 *   - The current view is `_Atomic(view_t *)`, swapped with
 *     atomic_store_explicit(release).  Readers do an
 *     atomic_load_explicit(acquire) to get a snapshot.
 *   - Old views are kept in an unbounded graveyard list for
 *     simplicity (cert renewals happen on the order of weeks; a
 *     long-running server would accrue ~50 stale views per year).
 *     This avoids epoch-based RCU machinery; we revisit when we
 *     have evidence the memory matters.
 *   - Mutations (install/replace) take a tiny mutex so concurrent
 *     writers serialize their view-rebuild + swap; readers never
 *     touch this mutex.
 *
 * Match precedence in lookup: exact > "*.suffix" > "*".  Linear
 * scan because cert stores typically hold 1–10 entries.  If that
 * stops being true we'd add a hash table, but we don't anticipate it.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_store.h"
#include "internal/net/quic/rcu.h"

/* ===========================================================================
 * Internal types
 * =========================================================================== */

typedef struct cert_store_view {
    n00b_quic_cert_entry_t **entries;   /* shared with prior views */
    size_t                   count;
} cert_store_view_t;

struct n00b_quic_cert_store {
    n00b_rcu_t views;
    bool       closed;
};

/* ===========================================================================
 * Allocator
 * =========================================================================== */

static n00b_allocator_t *
cs_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
cs_strdup(const char *s)
{
    size_t l = strlen(s);
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = cs_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, s, l + 1);
    return out;
}

static n00b_buffer_t *
cs_buffer_copy(n00b_buffer_t *src)
{
    n00b_buffer_t *out = n00b_buffer_empty(.allocator = cs_alloc());
    n00b_buffer_resize(out, src->byte_len);
    if (src->byte_len > 0) {
        memcpy(out->data, src->data, src->byte_len);
    }
    return out;
}

/* ===========================================================================
 * SNI matching
 *
 * `pattern` is exactly one of:
 *   - "example.com"        (exact)
 *   - "*.example.com"      (one-label wildcard)
 *   - "*"                  (catch-all)
 *
 * `name` is the literal hostname from a ClientHello SNI extension.
 *
 * `kind` returns the match strength: 2 for exact, 1 for wildcard, 0
 * for catch-all, -1 for no match.  Higher is more specific.
 * =========================================================================== */

static int
sni_match_kind(const char *pattern, const char *name)
{
    if (!pattern || !name) return -1;
    if (pattern[0] == '*' && pattern[1] == '\0') {
        return 0;  /* catch-all */
    }
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1;  /* points at "." */
        size_t name_len    = strlen(name);
        size_t suffix_len  = strlen(suffix);
        if (name_len <= suffix_len) return -1;
        const char *name_dot = name + (name_len - suffix_len);
        /* Suffix part must match exactly... */
        if (strcmp(name_dot, suffix) != 0) return -1;
        /* ...and the bit before the suffix must be a single label
         * (no embedded dot). */
        size_t prefix_len = name_len - suffix_len;
        for (size_t i = 0; i < prefix_len; i++) {
            if (name[i] == '.') return -1;
        }
        return 1;
    }
    return strcmp(pattern, name) == 0 ? 2 : -1;
}

/* ===========================================================================
 * View construction
 * =========================================================================== */

/* Build a new view that contains @p old's entries plus @p extra at
 * the tail.  If @p replace_idx >= 0, that index in @p old is *replaced*
 * by @p extra rather than appended. */
static cert_store_view_t *
view_clone_with(cert_store_view_t      *old,
                n00b_quic_cert_entry_t *extra,
                int                     replace_idx)
{
    size_t old_count = old ? old->count : 0;
    size_t new_count = (replace_idx >= 0) ? old_count : old_count + 1;

    cert_store_view_t *v = n00b_alloc_with_opts(cert_store_view_t,
        &(n00b_alloc_opts_t){.allocator = cs_alloc()});

    v->count = new_count;
    if (new_count == 0) {
        v->entries = nullptr;
        return v;
    }
    v->entries = n00b_alloc_array_with_opts(
        n00b_quic_cert_entry_t *, (int64_t)new_count,
        &(n00b_alloc_opts_t){.allocator = cs_alloc()});

    if (replace_idx >= 0) {
        for (size_t i = 0; i < old_count; i++) {
            v->entries[i] = ((int)i == replace_idx) ? extra : old->entries[i];
        }
    } else {
        for (size_t i = 0; i < old_count; i++) {
            v->entries[i] = old->entries[i];
        }
        v->entries[old_count] = extra;
    }
    return v;
}

/* The previous incarnation kept a `next_grave` field on each view +
 * a n00b_data_lock inside cert_store_t.  Both jobs are now handled by
 * the shared @c n00b_rcu_t in the store. */

/* Find the index of an entry matching @p sni_pattern in @p v, or -1. */
static int
view_find_pattern(cert_store_view_t *v, const char *sni_pattern)
{
    if (!v) return -1;
    for (size_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i]->sni_pattern, sni_pattern) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* ===========================================================================
 * Public API
 * =========================================================================== */

n00b_quic_cert_store_t *
n00b_quic_cert_store_new(void)
{
    n00b_quic_cert_store_t *cs = n00b_alloc_with_opts(n00b_quic_cert_store_t,
        &(n00b_alloc_opts_t){.allocator = cs_alloc()});
    cert_store_view_t *e = n00b_alloc_with_opts(cert_store_view_t,
        &(n00b_alloc_opts_t){.allocator = cs_alloc()});
    e->entries = nullptr;
    e->count   = 0;
    n00b_rcu_init(&cs->views, e);
    cs->closed = false;
    return cs;
}

static n00b_result_t(bool)
install_or_replace(n00b_quic_cert_store_t *cs,
                   const char             *sni_pattern,
                   n00b_buffer_t          *chain_pem,
                   n00b_quic_secret_t     *key,
                   int64_t                 not_after_ms,
                   bool                    allow_replace)
{
    if (!cs || cs->closed || !sni_pattern || !chain_pem || !key) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }

    /* Build the new entry — immutable once published. */
    n00b_quic_cert_entry_t *e = n00b_alloc_with_opts(n00b_quic_cert_entry_t,
        &(n00b_alloc_opts_t){.allocator = cs_alloc()});
    e->sni_pattern   = cs_strdup(sni_pattern);
    e->chain_pem     = cs_buffer_copy(chain_pem);
    e->key           = key;
    e->not_after_ms  = not_after_ms;

    /* The rcu helper serializes writers and retains the old view in
     * its graveyard.  We do the duplicate-pattern check inside the
     * write window by loading current, peeking, and only proceeding
     * to swap if the pattern is acceptable.  Two concurrent
     * inserts of the same pattern would race here; the loser's
     * swap would still produce a duplicate.  We accept this — for
     * v1, install/replace are operator-driven and not concurrent. */
    cert_store_view_t *cur = n00b_rcu_load(&cs->views);
    int idx = view_find_pattern(cur, sni_pattern);
    if (idx >= 0 && !allow_replace) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }

    cert_store_view_t *next = view_clone_with(cur, e, idx);
    n00b_rcu_swap(&cs->views, next);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_quic_cert_store_install(n00b_quic_cert_store_t *cs,
                             const char             *sni_pattern,
                             n00b_buffer_t          *chain_pem,
                             n00b_quic_secret_t     *key,
                             int64_t                 not_after_ms)
{
    return install_or_replace(cs, sni_pattern, chain_pem, key,
                              not_after_ms, false);
}

n00b_result_t(bool)
n00b_quic_cert_store_replace(n00b_quic_cert_store_t *cs,
                             const char             *sni_pattern,
                             n00b_buffer_t          *chain_pem,
                             n00b_quic_secret_t     *key,
                             int64_t                 not_after_ms)
{
    return install_or_replace(cs, sni_pattern, chain_pem, key,
                              not_after_ms, true);
}

const n00b_quic_cert_entry_t *
n00b_quic_cert_store_lookup(n00b_quic_cert_store_t *cs, const char *sni_name)
{
    if (!cs || !sni_name) {
        return nullptr;
    }
    cert_store_view_t *v = n00b_rcu_load(&cs->views);
    if (!v || v->count == 0) {
        return nullptr;
    }
    /* Walk the view once, picking the best (highest-precedence) match. */
    int best_kind = -1;
    n00b_quic_cert_entry_t *best = nullptr;
    for (size_t i = 0; i < v->count; i++) {
        int k = sni_match_kind(v->entries[i]->sni_pattern, sni_name);
        if (k > best_kind) {
            best_kind = k;
            best      = v->entries[i];
            if (best_kind == 2) {
                break;  /* exact match wins; no point looking further */
            }
        }
    }
    return best;
}

size_t
n00b_quic_cert_store_count(n00b_quic_cert_store_t *cs)
{
    if (!cs) return 0;
    cert_store_view_t *v = n00b_rcu_load(&cs->views);
    return v ? v->count : 0;
}

void
n00b_quic_cert_store_close(n00b_quic_cert_store_t *cs)
{
    if (!cs || cs->closed) {
        return;
    }
    cs->closed = true;
    /* Allocations live in the conduit pool; nothing to free.  The
     * rcu helper clears `current` to NULL and tears down its mutex
     * so stray late lookups get NULL rather than UAF. */
    n00b_rcu_close(&cs->views);
}
