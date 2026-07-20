/**
 * @file file_change.h
 * @brief Filesystem change monitoring for the conduit system.
 *
 * File change topics fire when a watched file or directory is modified,
 * deleted, renamed, etc. They use integer URIs with the @c N00B_CONDUIT_TAG_VNODE
 * tag.
 *
 * Supported on kqueue (macOS/BSD), Linux (inotify), and Windows directory
 * notifications.
 *
 * Usage:
 * @code
 *     int fd = open("/path/to/watch", O_RDONLY);
 *     n00b_conduit_topic_base_t *t =
 *         n00b_result_get(
 *             n00b_conduit_file_change_topic(c, fd,
 *                 N00B_CONDUIT_VNODE_WRITE | N00B_CONDUIT_VNODE_DELETE));
 *     n00b_conduit_file_change_inbox_t *inbox =
 *         n00b_conduit_file_change_inbox_new(c);
 *     n00b_conduit_file_change_subscribe(t, inbox,
 *         .operations = N00B_CONDUIT_OP_ALL);
 * @endcode
 */
#pragma once

#include "conduit/conduit.h"
#include "conduit/io.h"
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// File Change Payload
// ============================================================================

/**
 * @brief File change event payload.
 */
typedef struct {
    int      fd;     /**< The watched file descriptor. */
    uint32_t events; /**< Bitmask of n00b_conduit_vnode_op_t that fired. */
} n00b_conduit_file_change_payload_t;

// ============================================================================
// File change type instantiation
// ============================================================================

N00B_CONDUIT_FULL_IMPL(n00b_conduit_file_change_payload_t);

typedef n00b_conduit_message_t(n00b_conduit_file_change_payload_t)
    n00b_conduit_file_change_msg_t;
typedef n00b_conduit_inbox_t(n00b_conduit_file_change_payload_t)
    n00b_conduit_file_change_inbox_t;

// ============================================================================
// File Change API
// ============================================================================

/**
 * @brief Watch a file descriptor for filesystem changes.
 * @param c      Conduit instance.
 * @param fd     Open file descriptor to watch.
 * @param events Bitmask of n00b_conduit_vnode_op_t events to monitor.
 * @return Ok(topic) that will fire when the specified events occur.
 * @pre @p fd must be an open file descriptor.
 */
extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_file_change_topic(n00b_conduit_t *c, int fd, uint32_t events);

/**
 * @brief Stop watching a file descriptor for changes.
 * @param c  Conduit instance.
 * @param fd File descriptor to unwatch.
 */
extern void
n00b_conduit_file_change_unwatch(n00b_conduit_t *c, int fd);

/**
 * @brief A path-based filesystem-change watch: owns the fd + vnode topic.
 *
 * Produced by @ref n00b_conduit_file_change_watch_path. Correlate delivered
 * @ref n00b_conduit_file_change_payload_t events back to a watch by matching
 * @c fd.
 */
typedef struct {
    n00b_conduit_t            *conduit;
    n00b_conduit_topic_base_t *topic;
    int                        fd;
} n00b_conduit_file_change_watch_t;

/**
 * @brief Watch a file/directory *by path* for filesystem changes.
 *
 * Opens @p path read-only and registers a vnode watch for @p events, WITHOUT
 * activating managed read I/O on the fd. This is the correct primitive for
 * pure change-notification: @ref n00b_conduit_file_open arms EVFILT_READ
 * (stream-readiness), which for a regular file reports "readable to EOF"
 * rather than "changed" and pumps the file into an unsubscribed read topic.
 * Change notification is EVFILT_VNODE (NOTE_WRITE/NOTE_EXTEND). Cross-platform:
 * dispatches to the platform vnode backend (kqueue on macOS/BSD, inotify on
 * Linux, directory notifications on Windows).
 *
 * The returned handle owns the fd and the topic. Subscribe to @c handle->topic
 * for events, then release everything with
 * @ref n00b_conduit_file_change_watch_close.
 *
 * @param c      Conduit instance whose default backend services the watch.
 * @param path   Filesystem path to watch.
 * @param events Bitmask of n00b_conduit_vnode_op_t events to monitor.
 * @return Ok(handle) on success, or Err(errno / conduit error) on failure.
 */
extern n00b_result_t(n00b_conduit_file_change_watch_t *)
n00b_conduit_file_change_watch_path(n00b_conduit_t *c,
                                    n00b_string_t  *path,
                                    uint32_t        events);

/**
 * @brief Release a path-based watch: unregisters the vnode watch and closes
 *        the owned fd. Safe on nullptr.
 */
extern void
n00b_conduit_file_change_watch_close(n00b_conduit_file_change_watch_t *w);

/**
 * @brief Get file descriptor from a file change topic.
 * @param topic File change topic.
 * @return File descriptor, or -1 if not a file change topic.
 */
static inline int
n00b_conduit_file_change_fd(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        if (N00B_CONDUIT_URI_IS_VNODE(v)) {
            return (int)N00B_CONDUIT_URI_ID(v);
        }
    }

    return -1;
}

/**
 * @brief Check if topic is a file change watch.
 */
static inline bool
n00b_conduit_topic_is_file_change(n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_uri_t uri = n00b_conduit_topic_uri(topic);

    if (n00b_variant_is_type(uri, uint64_t)) {
        uint64_t v = n00b_variant_get(uri, uint64_t);
        return N00B_CONDUIT_URI_IS_VNODE(v);
    }

    return false;
}

// ============================================================================
// File Change Subscription Macros
// ============================================================================

/** @brief Create a file change inbox. */
#define n00b_conduit_file_change_inbox_new(c)                                   \
    ({                                                                          \
        n00b_conduit_file_change_inbox_t *_inbox =                              \
            n00b_alloc(n00b_conduit_file_change_inbox_t);                       \
        n00b_conduit_inbox_init(n00b_conduit_file_change_payload_t,             \
                                _inbox, c, N00B_CONDUIT_BP_UNBOUNDED, 0);       \
        _inbox;                                                                 \
    })

/** @brief Subscribe to file change events. */
#define n00b_conduit_file_change_subscribe(topic, inbox, ...)                   \
    n00b_conduit_subscribe(n00b_conduit_file_change_payload_t,                  \
                           (n00b_conduit_topic_t(n00b_conduit_file_change_payload_t) *)(topic), \
                           inbox, __VA_ARGS__)

/** @brief Pop a file change message from inbox. */
#define n00b_conduit_file_change_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_conduit_file_change_payload_t, inbox)

/** @brief Check if file change inbox has messages. */
#define n00b_conduit_file_change_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_conduit_file_change_payload_t, inbox)

// ============================================================================
// Internal: File Change Backend Interface
// ============================================================================

/**
 * @internal Register file change watch with I/O backend.
 */
extern bool
n00b_conduit_file_change_register(n00b_conduit_t *c,
                                   n00b_conduit_vnode_watch_t *watch);

/**
 * @internal Unregister file change watch from I/O backend.
 */
extern void
n00b_conduit_file_change_unregister(n00b_conduit_t *c,
                                     n00b_conduit_vnode_watch_t *watch);
