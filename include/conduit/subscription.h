/**
 * @file subscription.h
 * @brief Type-safe topic subscription management for the conduit system.
 *
 * Subscriptions register consumer interest in topic events.
 * Everything is parameterized by payload type T — no type erasure.
 *
 * @c N00B_CONDUIT_SUBSCRIPTION_IMPL(T) generates:
 * - @c n00b_conduit_subscription_t(T) — fully typed subscription struct
 * - Per-type inline accessors and delivery helpers
 *
 * Subscriptions are stored in a typed list inside the parameterized topic.
 */
#pragma once

#include "conduit/inbox.h"
#include "adt/list.h"

// ============================================================================
// Subscription handle
// ============================================================================

typedef uint64_t n00b_conduit_sub_handle_t;

#define N00B_CONDUIT_INVALID_SUB_HANDLE 0

// ============================================================================
// Subscription state
// ============================================================================

typedef enum {
    N00B_CONDUIT_SUB_PENDING,   /**< Waiting for publisher to accept */
    N00B_CONDUIT_SUB_ACTIVE,    /**< Actively receiving events */
    N00B_CONDUIT_SUB_SUSPENDED, /**< Temporarily paused */
    N00B_CONDUIT_SUB_CANCELING, /**< Cancel requested, waiting for ack */
    N00B_CONDUIT_SUB_REMOVED,   /**< No longer active */
} n00b_conduit_sub_state_t;

// ============================================================================
// Subscription flags (packed boolean fields)
// ============================================================================

typedef enum {
    N00B_CONDUIT_SUB_F_ONE_SHOT           = 0x01,
    N00B_CONDUIT_SUB_F_NOTIFY_ON_DELIVERY = 0x02,
    N00B_CONDUIT_SUB_F_CONFIRM_CANCEL     = 0x04,
    N00B_CONDUIT_SUB_F_NOTIFY_UNSUB       = 0x08,
    N00B_CONDUIT_SUB_F_TIMEOUT_RELATIVE   = 0x10,
} n00b_conduit_sub_flags_t;

// ============================================================================
// Subscription configuration
// ============================================================================

typedef struct {
    uint32_t                     operations;
    uint32_t                     flags;
    uint32_t                     timeout_ms;
    n00b_conduit_backpressure_t  backpressure;
    uint32_t                     inbox_limit;
} n00b_conduit_sub_config_t;

// ============================================================================
// Typed subscription
// ============================================================================

#define n00b_conduit_subscription_t(T) struct typeid("n00b_conduit_sub", T)

#define _N00B_SUB_FN(fn, T) typeid("n00b_conduit_sub_" #fn, T)

/**
 * @brief Instantiate a fully-typed subscription for payload T.
 *
 * All fields are typed — no void pointers. The inbox field is
 * @c n00b_conduit_inbox_t(T) *, and delivery goes directly through
 * the typed inbox push function.
 *
 * Also declares the list type for storing subscription pointers and
 * generates typed delivery/accessor inlines.
 *
 * @pre N00B_CONDUIT_INBOX_IMPL(T) must have been called first.
 */
#define N00B_CONDUIT_SUBSCRIPTION_IMPL(T)                                                      \
    n00b_conduit_subscription_t(T) {                                                           \
        n00b_conduit_sub_handle_t    handle;                                                   \
        n00b_conduit_inbox_t(T)     *inbox;                                                    \
        n00b_conduit_sys_queue_t    *sys_queue;                                                \
        uint32_t                     operations;                                               \
        uint64_t                     generation;                                               \
        uint64_t                     epoch;                                                    \
        _Atomic(int)                 state;                                                    \
        bool                         one_shot;                                                 \
        bool                         dedicated_inbox;                                          \
        bool                         notify_on_delivery;                                       \
        bool                         confirm_cancel;                                           \
        bool                         notify_unsub;                                             \
        bool                         timeout_relative;                                         \
        uint32_t                     timeout_ms;                                               \
        n00b_conduit_backpressure_t  backpressure;                                             \
        uint32_t                     inbox_limit;                                              \
        n00b_conduit_topic_base_t   *topic;                                                    \
        void                        *next_for_topic;                                           \
    };                                                                                         \
                                                                                               \
                                                                                               \
    /** @brief Deliver a typed message to a subscription's inbox. */                           \
    static inline bool                                                                         \
    _N00B_SUB_FN(deliver, T)(n00b_conduit_subscription_t(T) *sub,                              \
                             n00b_conduit_message_t(T)      *msg)                              \
    {                                                                                          \
        if (!sub || !sub->inbox) return false;                                                 \
        bool ok = n00b_conduit_inbox_push_msg(T, sub->inbox, msg);                             \
        if (ok && sub->one_shot) {                                                             \
            n00b_atomic_store(&sub->state, N00B_CONDUIT_SUB_REMOVED);                          \
        }                                                                                      \
        return ok;                                                                             \
    }                                                                                          \
                                                                                               \
    /** @brief Get the typed inbox from a subscription. */                                     \
    static inline n00b_conduit_inbox_t(T) *                                                    \
    _N00B_SUB_FN(inbox, T)(n00b_conduit_subscription_t(T) *sub)                                \
    {                                                                                          \
        return sub->inbox;                                                                     \
    }

// ============================================================================
// Typed subscription operation macros
// ============================================================================

/** @brief Deliver a typed message to a subscription. */
#define n00b_conduit_sub_deliver(T, sub, msg) \
    _N00B_SUB_FN(deliver, T)(sub, msg)

/** @brief Get the typed inbox from a subscription. */
#define n00b_conduit_sub_get_inbox(T, sub) \
    _N00B_SUB_FN(inbox, T)(sub)

// ============================================================================
// Instantiate system subscription type
// ============================================================================

N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_conduit_empty_payload_t);
typedef n00b_conduit_subscription_t(n00b_conduit_empty_payload_t)
    n00b_conduit_subscription_sys_t;

// ============================================================================
// Subscription management (typed per-T in the topic; declared in topic.h)
//
// These operate on handles or typed subscription pointers.  The actual
// implementations are generated by N00B_CONDUIT_TOPIC_IMPL(T) which has
// access to the subscription list.
// ============================================================================

/** @brief Cancel a subscription by handle (extern, implemented per topic). */
extern void n00b_conduit_sub_cancel(n00b_conduit_sub_handle_t handle);

/** @brief Allocate a process-wide unique subscription handle. */
extern n00b_conduit_sub_handle_t n00b_conduit_sub_next_handle(void);

/** @brief Suspend a subscription by handle. */
extern void n00b_conduit_sub_suspend(n00b_conduit_sub_handle_t handle);

/** @brief Resume a suspended subscription by handle. */
extern void n00b_conduit_sub_resume(n00b_conduit_sub_handle_t handle);

/** @brief Check if a subscription handle is active. */
extern bool n00b_conduit_sub_is_active(n00b_conduit_sub_handle_t handle);

/** @brief Get the state of a subscription by handle. */
extern n00b_conduit_sub_state_t
n00b_conduit_sub_state(n00b_conduit_sub_handle_t handle);
