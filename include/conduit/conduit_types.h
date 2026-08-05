/**
 * @file conduit_types.h
 * @brief Common types, error codes, and result aliases for the conduit system.
 *
 * This is the leaf header in the conduit dependency graph -- it has no
 * conduit-internal dependencies and can be included from any other
 * conduit header.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "adt/result.h"
#include "adt/variant.h"
#include "core/platform.h"

// ============================================================================
// Forward declarations
// ============================================================================

typedef struct n00b_conduit            n00b_conduit_t;
typedef struct n00b_conduit_publisher  n00b_conduit_publisher_t;
typedef struct n00b_conduit_topic_base n00b_conduit_topic_base_t;

/** @brief Typed topic name mangling (usable as incomplete struct pointer). */
#define n00b_conduit_topic_t(T) struct typeid("n00b_conduit_topic", T)
typedef struct n00b_conduit_fd_owner n00b_conduit_fd_owner_t;
typedef struct n00b_conduit_listener n00b_conduit_listener_t;
typedef struct n00b_conduit_udp      n00b_conduit_udp_t;

// ============================================================================
// IO watch target -- variant discriminating fd_owner vs listener vs UDP socket
// ============================================================================

typedef n00b_variant_t(n00b_conduit_fd_owner_t *,
                       n00b_conduit_listener_t *,
                       n00b_conduit_udp_t *) n00b_conduit_io_target_t;

// ============================================================================
// Error codes (offset to avoid collision with core n00b_err_t values)
// ============================================================================

enum {
    N00B_CONDUIT_ERR_NONE     = 0,
    N00B_CONDUIT_ERR_NULL_ARG = 1000,
    N00B_CONDUIT_ERR_ALLOC,
    N00B_CONDUIT_ERR_SHUTDOWN,
    N00B_CONDUIT_ERR_CLOSED,
    N00B_CONDUIT_ERR_NOT_OWNER,
    N00B_CONDUIT_ERR_ALREADY_CLAIMED,
    N00B_CONDUIT_ERR_INVALID_STATE,
    N00B_CONDUIT_ERR_EOF,
    N00B_CONDUIT_ERR_EPIPE,
    N00B_CONDUIT_ERR_IO,
    N00B_CONDUIT_ERR_FD_CLOSED,
    N00B_CONDUIT_ERR_NOT_MANAGED,
    N00B_CONDUIT_ERR_CONNECT,
    N00B_CONDUIT_ERR_SOCKET,
    N00B_CONDUIT_ERR_BIND,
    N00B_CONDUIT_ERR_LISTEN,
    N00B_CONDUIT_ERR_PROC_FORK,
    N00B_CONDUIT_ERR_PROC_EXEC,
    N00B_CONDUIT_ERR_PROC_PIPE,
    N00B_CONDUIT_ERR_PROC_PTY,
    N00B_CONDUIT_ERR_PROC_TIMEOUT,
    N00B_CONDUIT_ERR_TIMEOUT,
    N00B_CONDUIT_ERR_REGISTRY_FULL,
    N00B_CONDUIT_ERR_NOT_SUPPORTED,
    N00B_CONDUIT_ERR_NOT_FOUND,
};

// ============================================================================
// Common result type declarations
// ============================================================================

