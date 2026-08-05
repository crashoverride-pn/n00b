/**
 * @file message.h
 * @brief Type-safe messages for the conduit event system.
 *
 * Messages are delivered to inboxes when events occur on topics.
 * @c n00b_conduit_message_t(T) provides type-safe payloads via
 * @c N00B_CONDUIT_MESSAGE_IMPL(T).
 *
 * Usage:
 * @code
 *     N00B_CONDUIT_MESSAGE_IMPL(my_payload_t);
 *     n00b_conduit_message_t(my_payload_t) *msg = ...;
 *     n00b_conduit_msg_type(msg);       // message type enum
 *     n00b_conduit_msg_payload(msg);    // typed payload
 * @endcode
 */
#pragma once

#include "conduit/conduit_types.h"
#include "core/string.h"

// ============================================================================
// Message types
// ============================================================================

typedef enum {
    // Subscription lifecycle
    N00B_CONDUIT_MSG_SUB_ACCEPTED,     /**< Subscription confirmed */
    N00B_CONDUIT_MSG_SUB_REJECTED,     /**< Subscription rejected */
    N00B_CONDUIT_MSG_SUB_REMOVED,      /**< Subscription removed (by publisher) */
    N00B_CONDUIT_MSG_CANCEL_ACK,       /**< Cancel request acknowledged */
    N00B_CONDUIT_MSG_SUSPEND_ACK,      /**< Suspend request acknowledged */
    N00B_CONDUIT_MSG_RESUME_ACK,       /**< Resume request acknowledged */

    // Topic events
    N00B_CONDUIT_MSG_TOPIC_CLOSED,     /**< Topic was closed */
    N00B_CONDUIT_MSG_PUBLISHER_LOST,   /**< Publisher went away unexpectedly */

    // I/O events (for FD topics)
    N00B_CONDUIT_MSG_READABLE,         /**< FD is readable */
    N00B_CONDUIT_MSG_WRITABLE,         /**< FD is writable */
    N00B_CONDUIT_MSG_ERROR,            /**< Error on FD */
    N00B_CONDUIT_MSG_HUP,              /**< Hangup on FD */
    N00B_CONDUIT_MSG_EOF,              /**< End of file */

    // Timer events
    N00B_CONDUIT_MSG_TIMEOUT,          /**< Subscription timeout fired */
    N00B_CONDUIT_MSG_TIMER,            /**< Timer event */

    // Backpressure
    N00B_CONDUIT_MSG_OVERFLOW,         /**< Inbox overflow (backpressure signal) */

    // User-defined events start here
    N00B_CONDUIT_MSG_USER = 0x1000,    /**< First user-defined message type */
} n00b_conduit_msg_type_t;

// ============================================================================
// Operation flags for subscriptions
// ============================================================================

typedef enum {
    N00B_CONDUIT_OP_NONE     = 0,
    N00B_CONDUIT_OP_READABLE = 1 << 0,
    N00B_CONDUIT_OP_WRITABLE = 1 << 1,
    N00B_CONDUIT_OP_ERROR    = 1 << 2,
    N00B_CONDUIT_OP_HUP      = 1 << 3,
    N00B_CONDUIT_OP_TIMEOUT  = 1 << 4,
    N00B_CONDUIT_OP_ALL      = 0xFFFF,
} n00b_conduit_op_t;

// ============================================================================
// Message header (common to all messages)
// ============================================================================

typedef struct n00b_conduit_msg_hdr {
    n00b_conduit_msg_type_t      type;
    n00b_conduit_topic_base_t   *topic;
    uint64_t                     generation;
    uint64_t                     epoch;
    uint64_t                     timestamp;
    struct n00b_conduit_msg_hdr *next;
} n00b_conduit_msg_hdr_t;

// ============================================================================
// Type-safe message macro
// ============================================================================

#define n00b_conduit_message_t(T) struct typeid("n00b_conduit_message", T)

#define N00B_CONDUIT_MESSAGE_IMPL(T)                                                           \
    n00b_conduit_message_t(T) {                                                                \
        n00b_conduit_msg_hdr_t header;                                                         \
        T                      payload;                                                        \
    }

// ============================================================================
// Accessor macros
// ============================================================================

#define n00b_conduit_msg_type(msg)       ((msg)->header.type)
#define n00b_conduit_msg_topic(msg)      ((msg)->header.topic)
#define n00b_conduit_msg_generation(msg) ((msg)->header.generation)
#define n00b_conduit_msg_epoch(msg)      ((msg)->header.epoch)
#define n00b_conduit_msg_timestamp(msg)  ((msg)->header.timestamp)
#define n00b_conduit_msg_payload(msg)    ((msg)->payload)

// ============================================================================
// System payload types
// ============================================================================

typedef struct {
    base_socket_t              fd;
    uint32_t                   ops;
    n00b_conduit_io_target_t  *target;
} n00b_conduit_io_payload_t;

typedef struct {
    int            error_code;
    n00b_string_t *error_msg;
} n00b_conduit_error_payload_t;

typedef struct {
    char _unused;
} n00b_conduit_empty_payload_t;

// ============================================================================
// Instantiate system message types
// ============================================================================

N00B_CONDUIT_MESSAGE_IMPL(n00b_conduit_io_payload_t);
N00B_CONDUIT_MESSAGE_IMPL(n00b_conduit_error_payload_t);

typedef n00b_conduit_message_t(n00b_conduit_io_payload_t)    n00b_conduit_io_msg_t;
typedef n00b_conduit_message_t(n00b_conduit_error_payload_t) n00b_conduit_error_msg_t;

// ============================================================================
// Message type name helper
// ============================================================================

static inline const char *
n00b_conduit_msg_type_name(n00b_conduit_msg_type_t type)
{
    switch (type) {
    case N00B_CONDUIT_MSG_SUB_ACCEPTED:   return "SUB_ACCEPTED";
    case N00B_CONDUIT_MSG_SUB_REJECTED:   return "SUB_REJECTED";
    case N00B_CONDUIT_MSG_SUB_REMOVED:    return "SUB_REMOVED";
    case N00B_CONDUIT_MSG_CANCEL_ACK:     return "CANCEL_ACK";
    case N00B_CONDUIT_MSG_SUSPEND_ACK:    return "SUSPEND_ACK";
    case N00B_CONDUIT_MSG_RESUME_ACK:     return "RESUME_ACK";
    case N00B_CONDUIT_MSG_TOPIC_CLOSED:   return "TOPIC_CLOSED";
    case N00B_CONDUIT_MSG_PUBLISHER_LOST: return "PUBLISHER_LOST";
    case N00B_CONDUIT_MSG_READABLE:       return "READABLE";
    case N00B_CONDUIT_MSG_WRITABLE:       return "WRITABLE";
    case N00B_CONDUIT_MSG_ERROR:          return "ERROR";
    case N00B_CONDUIT_MSG_HUP:            return "HUP";
    case N00B_CONDUIT_MSG_EOF:            return "EOF";
    case N00B_CONDUIT_MSG_TIMEOUT:        return "TIMEOUT";
    case N00B_CONDUIT_MSG_TIMER:          return "TIMER";
    case N00B_CONDUIT_MSG_OVERFLOW:       return "OVERFLOW";
    default:
        if (type >= N00B_CONDUIT_MSG_USER) return "USER";
        return "UNKNOWN";
    }
}
