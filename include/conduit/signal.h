/**
 * @file signal.h
 * @brief Signal handling for the conduit system.
 *
 * Signals are topics that fire when a platform signal is raised.
 * They use integer URIs with the @c N00B_CONDUIT_TAG_SIGNAL tag.
 *
 * Usage:
 * @code
 *     n00b_conduit_topic_base_t *t =
 *         n00b_result_get(n00b_conduit_signal_topic(c, SIGINT));
 *     n00b_conduit_signal_inbox_t *inbox =
 *         n00b_conduit_signal_inbox_new(c);
 *     n00b_conduit_signal_subscribe(t, inbox,
 *         .operations = N00B_CONDUIT_OP_ALL);
 * @endcode
 */
#pragma once

#include "conduit/conduit.h"
#include "conduit/io.h"
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

// ============================================================================
// Signal Operations
// ============================================================================

/**
 * @brief Signal event operations.
 */
typedef enum {
    N00B_CONDUIT_SIGNAL_RAISED = (1 << 0),
    N00B_CONDUIT_SIGNAL_ALL    = 0x01,
} n00b_conduit_signal_op_t;

// ============================================================================
// Signal Payload
// ============================================================================

/**
 * @brief Signal event payload.
 */
typedef struct {
    int      signum;       /**< Signal number (SIGINT, SIGTERM, etc.) */
    uint64_t raise_count;  /**< Number of times raised */
} n00b_conduit_signal_payload_t;

// ============================================================================
// Signal type instantiation
// ============================================================================

N00B_CONDUIT_FULL_IMPL(n00b_conduit_signal_payload_t);

typedef n00b_conduit_message_t(n00b_conduit_signal_payload_t)
    n00b_conduit_signal_msg_t;
typedef n00b_conduit_inbox_t(n00b_conduit_signal_payload_t)
    n00b_conduit_signal_inbox_t;

// ============================================================================
// Signal API
// ============================================================================

/**
 * @brief Get the topic for a platform signal.
 * @param c      Conduit instance.
 * @param signum Signal number.
 * @return Ok(topic) that will fire when the signal is raised.
 */
extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_signal_topic(n00b_conduit_t *c, int signum);

/**
 * @brief Stop monitoring a signal.
 * @param c      Conduit instance.
 * @param signum Signal number.
 */
extern void
n00b_conduit_signal_unwatch(n00b_conduit_t *c, int signum);

/**
 * @brief Get signal number from topic.
 * @param topic Signal topic.
 * @return Signal number, or 0 if not a signal topic.
 */
static inline int
n00b_conduit_signal_num(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        if (N00B_CONDUIT_URI_IS_SIGNAL(v)) {
            return (int)N00B_CONDUIT_URI_ID(v);
        }
    }

    return 0;
}

/**
 * @brief Check if topic is a signal.
 */
static inline bool
n00b_conduit_topic_is_signal(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        return N00B_CONDUIT_URI_IS_SIGNAL(v);
    }

    return false;
}

// ============================================================================
// Signal Subscription Macros
// ============================================================================

/** @brief Create a signal inbox. */
#define n00b_conduit_signal_inbox_new(c)                                       \
    ({                                                                         \
        n00b_conduit_signal_inbox_t *_inbox =                                  \
            n00b_alloc_with_opts(n00b_conduit_signal_inbox_t,                  \
                &(n00b_alloc_opts_t){.allocator = (c)->allocator});            \
        n00b_conduit_inbox_init(n00b_conduit_signal_payload_t,                 \
                                _inbox, c, N00B_CONDUIT_BP_UNBOUNDED, 0);      \
        _inbox;                                                                \
    })

/** @brief Subscribe to signal events. */
#define n00b_conduit_signal_subscribe(topic, inbox, ...)                       \
    n00b_conduit_subscribe(n00b_conduit_signal_payload_t,                      \
                           (n00b_conduit_topic_t(n00b_conduit_signal_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/** @brief Pop a signal message from inbox. */
#define n00b_conduit_signal_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_conduit_signal_payload_t, inbox)

/** @brief Check if signal inbox has messages. */
#define n00b_conduit_signal_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_conduit_signal_payload_t, inbox)

// ============================================================================
// Internal: Signal Backend Interface
// ============================================================================

/**
 * @brief Signal entry for backend tracking.
 */
struct n00b_conduit_signal_watch {
    int                              signum;
    n00b_conduit_topic_base_t       *topic;
    n00b_conduit_io_backend_t       *io;
    bool                             mask_was_blocked;
    _Atomic(uint64_t)                raise_count;
    struct n00b_conduit_signal_watch *next;
};

/**
 * @internal Register signal with I/O backend.
 */
extern bool
n00b_conduit_signal_register(n00b_conduit_t *c,
                             n00b_conduit_signal_watch_t *watch);

/**
 * @internal Unregister signal from I/O backend.
 */
extern void
n00b_conduit_signal_unregister(n00b_conduit_t *c,
                               n00b_conduit_signal_watch_t *watch);

/**
 * @internal Fire a signal (called by I/O backend).
 */
extern void
n00b_conduit_signal_fire(n00b_conduit_signal_watch_t *watch);

/**
 * @internal Release all signal watches registered on a conduit.
 */
extern void
n00b_conduit_signal_cleanup(n00b_conduit_t *c);
