/**
 * @file proc_lifecycle.h
 * @brief Process lifecycle monitoring for the conduit system.
 *
 * Process topics fire when a watched process exits, forks, execs, or
 * receives a signal. They use integer URIs with the @c N00B_CONDUIT_TAG_PROC
 * tag.
 *
 * Supported on kqueue (macOS/BSD), Linux (pidfd), and Windows process waits.
 *
 * Usage:
 * @code
 *     n00b_conduit_topic_base_t *t =
 *         n00b_result_get(
 *             n00b_conduit_proc_topic(c, child_pid, N00B_CONDUIT_PROC_EXIT));
 *     n00b_conduit_proc_inbox_t *inbox =
 *         n00b_conduit_proc_inbox_new(c);
 *     n00b_conduit_proc_subscribe(t, inbox,
 *         .operations = N00B_CONDUIT_OP_ALL);
 * @endcode
 */
#pragma once

#include "conduit/conduit.h"
#include "conduit/io.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// ============================================================================
// Process Payload
// ============================================================================

/**
 * @brief Process event payload.
 */
typedef struct {
    pid_t    pid;         /**< Process ID that triggered the event. */
    uint32_t events;      /**< Bitmask of n00b_conduit_proc_op_t that fired. */
    int      exit_status; /**< Valid when N00B_CONDUIT_PROC_EXIT is set. */
    /**
     * True when the exit event's producer reaped the child itself, so
     * `exit_status` is the wait(2) status. False means the child could not be
     * reaped at fire time (on macOS, kqueue posts NOTE_EXIT before the child
     * is reapable) and `exit_status` is whatever the I/O backend supplied --
     * the real status when the backend can report it, otherwise 0. A consumer
     * that owns the child should reap it itself in that case rather than trust
     * the value. Always true on Windows.
     */
    bool     reaped;
} n00b_conduit_proc_payload_t;

// ============================================================================
// Process type instantiation
// ============================================================================

N00B_CONDUIT_FULL_IMPL(n00b_conduit_proc_payload_t);

typedef n00b_conduit_message_t(n00b_conduit_proc_payload_t)
    n00b_conduit_proc_msg_t;
typedef n00b_conduit_inbox_t(n00b_conduit_proc_payload_t)
    n00b_conduit_proc_inbox_t;

// ============================================================================
// Process API
// ============================================================================

/**
 * @brief Watch a process for lifecycle events.
 * @param c      Conduit instance.
 * @param pid    Process ID to watch.
 * @param events Bitmask of n00b_conduit_proc_op_t events to monitor.
 * @return Ok(topic) that will fire when the specified events occur.
 */
extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_proc_topic(n00b_conduit_t *c, pid_t pid, uint32_t events);

/**
 * @brief Stop watching a process.
 * @param c   Conduit instance.
 * @param pid Process ID to unwatch.
 */
extern void
n00b_conduit_proc_unwatch(n00b_conduit_t *c, pid_t pid);

/**
 * @brief Get process ID from topic.
 * @param topic Process topic.
 * @return Process ID, or 0 if not a process topic.
 */
static inline pid_t
n00b_conduit_proc_pid(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        if (N00B_CONDUIT_URI_IS_PROC(v)) {
            return (pid_t)N00B_CONDUIT_URI_ID(v);
        }
    }

    return 0;
}

/**
 * @brief Check if topic is a process watch.
 */
static inline bool
n00b_conduit_topic_is_proc(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        return N00B_CONDUIT_URI_IS_PROC(v);
    }

    return false;
}

// ============================================================================
// Process Subscription Macros
// ============================================================================

/** @brief Create a process inbox. */
#define n00b_conduit_proc_inbox_new(c)                                          \
    ({                                                                          \
        n00b_conduit_proc_inbox_t *_inbox =                                     \
            n00b_alloc_with_opts(n00b_conduit_proc_inbox_t,                      \
                &(n00b_alloc_opts_t){.allocator = (c)->allocator});             \
        n00b_conduit_inbox_init(n00b_conduit_proc_payload_t,                    \
                                _inbox, c, N00B_CONDUIT_BP_UNBOUNDED, 0);       \
        _inbox;                                                                 \
    })

/** @brief Subscribe to process events. */
#define n00b_conduit_proc_subscribe(topic, inbox, ...)                          \
    n00b_conduit_subscribe(n00b_conduit_proc_payload_t,                         \
                           (n00b_conduit_topic_t(n00b_conduit_proc_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/** @brief Pop a process message from inbox. */
#define n00b_conduit_proc_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_conduit_proc_payload_t, inbox)

/** @brief Check if process inbox has messages. */
#define n00b_conduit_proc_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_conduit_proc_payload_t, inbox)

// ============================================================================
// Internal: Process Backend Interface
// ============================================================================

/**
 * @internal Register process watch with I/O backend.
 */
extern bool
n00b_conduit_proc_register(n00b_conduit_t *c,
                            n00b_conduit_proc_watch_t *watch);

/**
 * @internal Unregister process watch from I/O backend.
 */
extern void
n00b_conduit_proc_unregister(n00b_conduit_t *c,
                              n00b_conduit_proc_watch_t *watch);
