/**
 * @file timer.h
 * @brief Timer support for the conduit system.
 *
 * Timers are topics that fire events after a delay or on an interval.
 * They use integer URIs with the @c N00B_CONDUIT_TAG_TIMER tag.
 *
 * Usage:
 * @code
 *     n00b_conduit_topic_base_t *t =
 *         n00b_result_get(n00b_conduit_timer_repeat(c, 1000));
 *     n00b_conduit_timer_inbox_t *inbox =
 *         n00b_conduit_timer_inbox_new(c);
 *     n00b_conduit_timer_subscribe(t, inbox,
 *         .operations = N00B_CONDUIT_OP_ALL);
 * @endcode
 */
#pragma once

#include "conduit/conduit.h"
#include "conduit/io.h"
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Timer Operations
// ============================================================================

/**
 * @brief Timer event operations.
 */
typedef enum {
    N00B_CONDUIT_TIMER_FIRED     = (1 << 0),
    N00B_CONDUIT_TIMER_CANCELLED = (1 << 1),
    N00B_CONDUIT_TIMER_ALL       = 0x03,
} n00b_conduit_timer_op_t;

// ============================================================================
// Timer Payload
// ============================================================================

/**
 * @brief Timer event payload.
 */
typedef struct {
    uint64_t timer_id;      /**< Timer identifier (from URI) */
    uint64_t fire_count;    /**< Number of times fired */
    uint32_t interval_ms;   /**< Interval (0 for one-shot) */
    bool     repeating;     /**< Is this a repeating timer? */
} n00b_conduit_timer_payload_t;

// ============================================================================
// Timer type instantiation
// ============================================================================

N00B_CONDUIT_FULL_IMPL(n00b_conduit_timer_payload_t);

typedef n00b_conduit_message_t(n00b_conduit_timer_payload_t)
    n00b_conduit_timer_msg_t;
typedef n00b_conduit_inbox_t(n00b_conduit_timer_payload_t)
    n00b_conduit_timer_inbox_t;

// ============================================================================
// Timer API
// ============================================================================

/**
 * @brief Create a one-shot timer.
 * @param c        Conduit instance.
 * @param delay_ms Delay in milliseconds.
 * @return Ok(topic) that will fire once after delay_ms milliseconds.
 */
extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_timer_once(n00b_conduit_t *c, uint32_t delay_ms);

/**
 * @brief Create a repeating timer.
 * @param c           Conduit instance.
 * @param interval_ms Interval in milliseconds.
 * @return Ok(topic) that fires every interval_ms milliseconds.
 */
extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_timer_repeat(n00b_conduit_t *c, uint32_t interval_ms);

/**
 * @brief Cancel a timer.
 * @param timer_topic Timer topic to cancel.
 */
extern void
n00b_conduit_timer_cancel(n00b_conduit_topic_base_t *timer_topic);

/**
 * @brief Get timer ID from topic.
 * @param topic Timer topic.
 * @return Timer ID, or 0 if not a timer topic.
 */
static inline uint64_t
n00b_conduit_timer_id(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        if (N00B_CONDUIT_URI_IS_TIMER(v)) {
            return N00B_CONDUIT_URI_ID(v);
        }
    }

    return 0;
}

/**
 * @brief Check if topic is a timer.
 */
static inline bool
n00b_conduit_topic_is_timer(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        return N00B_CONDUIT_URI_IS_TIMER(v);
    }

    return false;
}

// ============================================================================
// Timer Subscription Macros
// ============================================================================

/** @brief Create a timer inbox.
 *
 * Allocated from the conduit's own allocator, which must be
 * non-moving: the inbox struct has an embedded n00b_condition_t whose
 * underlying lock is registered with the lock-accounting registry by
 * *address*. If the inbox were allocated from a relocating arena (the
 * default that `n00b_alloc` uses), the first GC pass would move the
 * struct and the next acquire-accounting check on the now-stale lock
 * would abort with "Lock at address ... was not initialized before
 * use." Mirrors the inbox pinning in conduit/rw.h's
 * `n00b_conduit_read`.
 *
 * Uses `(c)->allocator` rather than hardcoding the runtime's
 * conduit_pool so a conduit created with an explicit allocator gets
 * ALL of its inboxes from that allocator. The two coincide by default
 * (n00b_conduit_new falls back to conduit_pool), but a caller that
 * passes e.g. the GC-visible user_pool — so in-flight message pointers
 * are traced — previously got every inbox from that pool except this
 * one. test/unit/test_conduit_inbox_pinning.c gates the non-moving
 * requirement for every inbox constructor. */
#define n00b_conduit_timer_inbox_new(c)                                        \
    ({                                                                         \
        n00b_conduit_timer_inbox_t *_inbox =                                   \
            n00b_alloc_with_opts(n00b_conduit_timer_inbox_t,                   \
                &(n00b_alloc_opts_t){.allocator = (c)->allocator});            \
        n00b_conduit_inbox_init(n00b_conduit_timer_payload_t,                  \
                                _inbox, c, N00B_CONDUIT_BP_UNBOUNDED, 0);      \
        _inbox;                                                                \
    })

/** @brief Subscribe to timer events. */
#define n00b_conduit_timer_subscribe(topic, inbox, ...)                        \
    n00b_conduit_subscribe(n00b_conduit_timer_payload_t,                       \
                           (n00b_conduit_topic_t(n00b_conduit_timer_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/** @brief Pop a timer message from inbox. */
#define n00b_conduit_timer_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_conduit_timer_payload_t, inbox)

/** @brief Check if timer inbox has messages. */
#define n00b_conduit_timer_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_conduit_timer_payload_t, inbox)

// ============================================================================
// Internal: Timer Backend Interface
// ============================================================================

/**
 * @brief Timer entry for backend tracking.
 */
struct n00b_conduit_timer {
    uint64_t                   id;
    n00b_conduit_topic_base_t *topic;
    uint32_t                   interval_ms;
    _Atomic(uint64_t)          fire_count;
    bool                       repeating;
    bool                       cancelled;
    struct n00b_conduit_timer *next;
};

/**
 * @internal Register timer with I/O backend.
 */
extern bool
n00b_conduit_timer_register(n00b_conduit_t *c, n00b_conduit_timer_t *timer);

/**
 * @internal Unregister timer from I/O backend.
 */
extern void
n00b_conduit_timer_unregister(n00b_conduit_t *c, n00b_conduit_timer_t *timer);

/**
 * @internal Fire a timer (called by I/O backend).
 */
extern void
n00b_conduit_timer_fire(n00b_conduit_timer_t *timer);
