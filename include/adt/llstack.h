/**
 * @file llstack.h
 * @brief Lock-free (Treiber) stack.
 *
 * A compare-and-swap based stack with ABA protection via a per-thread
 * monotonic guard word (_n00b_aba_tag).  Used internally by the pool
 * allocator's free lists.  The guard was formerly n00b_rand64(), which
 * routed through arc4random_buf -> libcorecrypto and intermittently
 * SIGSEGV'd on raw n00b workers (its ___chkstk_darwin probe reads the
 * pthread TSD a raw worker lacks); see _n00b_aba_tag in thread.c.
 */
#pragma once

// TODO: make this a typed interface.

#include "core/atomic.h"
#include "core/align.h"

/**
 * @brief Lock-free-stack ABA guard tag (replaces the former n00b_rand64()).
 *
 * Returns a value unique per (live thread, operation): high 16 bits = the
 * caller's thread slot (live-unique, so two threads never collide), low 48
 * bits = a per-thread monotonic counter (advances every op).  An ABA guard
 * needs uniqueness/monotonicity, not cryptographic randomness; the old
 * n00b_rand64() routed through arc4random_buf -> libcorecrypto, whose
 * large-frame ___chkstk_darwin probe reads the pthread TSD a raw n00b worker
 * lacks -> intermittent SIGSEGV on any allocating worker.  Per-thread (NOT
 * per-CPU): avoids the userspace thread-migration race that retired the
 * per-processor STW plan (D-003 / D-037).
 *
 * Internal (`_n00b_` prefix): the only caller is this header's push/pop.
 * Defined in core/thread.c (it needs n00b_thread_self()); declared here to
 * keep this low-level adt header out of the thread/runtime include graph.
 */
extern uint64_t _n00b_aba_tag(void);

typedef struct n00b_llstack_node_t n00b_llstack_node_t;
typedef struct n00b_head_t         n00b_head_t;

struct n00b_llstack_node_t {
    n00b_llstack_node_t *next;
};

struct n00b_head_t {
    alignas(N00B_ALIGN) n00b_llstack_node_t *head;
    uint64_t aba_guard;
};

typedef _Atomic(n00b_head_t) n00b_llstack_t;

/**
 * @brief Initialize a lock-free stack to empty.
 * @param llstack Stack to initialize.
 */
static inline void
n00b_llstack_init(n00b_llstack_t *llstack)
{
    n00b_atomic_store(llstack, ((n00b_head_t){.head = nullptr, .aba_guard = 0}));
}

/**
 * @brief Push a node onto the lock-free stack.
 * @param llstack Stack to push onto.
 * @param item    Node to push (caller-owned, not allocated by stack).
 */
static inline void
n00b_llstack_push_node(n00b_llstack_t *llstack, n00b_llstack_node_t *item)
{
    // Tag is taken ONCE here, not refreshed on CAS-retry: push has no ABA
    // hazard (desired.head is always `item`, never a re-dereferenced old
    // pointer), so retrying with the same tag is safe — a failed CAS only
    // refreshes `expected` and re-links `item->next` below.
    n00b_head_t expected = {.head = nullptr, .aba_guard = 0};
    n00b_head_t desired  = {.head = item, .aba_guard = _n00b_aba_tag()};

    do {
        item->next = expected.head;
    } while (!n00b_atomic_cas(llstack, &expected, desired));
}

/**
 * @brief Pop a node from the lock-free stack.
 *
 * @param llstack Stack to pop from.
 *
 * @kw found  Optional pointer to bool. If supplied, written `true` when
 *            a node was popped and `false` when the stack was empty.
 *            The `found` out-parameter — NOT the return value — is the
 *            authoritative presence signal (per §5.4: no
 *            nullptr-as-absent sentinel). Defaults to `nullptr` (the
 *            caller doesn't care about empty-vs-nonempty disambiguation).
 *
 * @return    The popped node when `*found` was set to true (or when the
 *            caller did not pass `.found` and the stack was non-empty).
 *            Returns `nullptr` when the stack was empty. Callers MAY
 *            rely on the `nullptr` return alone if they know the
 *            stack's nodes are never themselves `nullptr` (the typical
 *            case for caller-owned pool nodes); callers who store
 *            `nullptr` as a legitimate node value MUST use the
 *            `.found` kwarg to disambiguate.
 */
static inline void *
n00b_llstack_pop_node(n00b_llstack_t *llstack) _kargs
{
    bool *found = nullptr;
}
{
    n00b_head_t          expected = n00b_atomic_load(llstack);
    n00b_head_t          desired;
    n00b_llstack_node_t *node;

    // Tag taken once (not per-retry): desired.head is recomputed from the
    // refreshed `expected` inside the loop, and the guard's only job is to
    // differ from the guard in `expected` — which a monotonic per-thread tag
    // does by construction.
    desired.aba_guard = _n00b_aba_tag();

    do {
        node = expected.head;

        if (!node) {
            if (found) {
                *found = false;
            }
            return nullptr;
        }

        desired.head = node->next;
    } while (!n00b_atomic_cas(llstack, &expected, desired));

    /* pool_free zeroes the entire entry before pushing; the push then
     * stamps the first sizeof(void*) bytes with the freelist link.
     * Restore the all-zero payload by clearing the link slot before
     * handing the node back, so callers can rely on the contract that
     * a freshly-popped entry's bytes are all zero. */
    node->next = nullptr;
    return node;
}
