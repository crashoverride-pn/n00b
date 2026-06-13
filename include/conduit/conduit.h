/**
 * @file conduit.h
 * @brief Low-level IO subsystem
 *
 * Includes all public conduit headers and defines the core
 * @c n00b_conduit_t instance, topic registry, and top-level API.
 *
 * Additional conduit headers (not auto-included due to dependency order):
 *   - `conduit/service.h` — Service thread pool
 *   - `conduit/rw.h`      — High-level read/write API
 *   - `conduit/xform.h`   — Transform/pipeline framework
 */
#pragma once

#include "conduit/conduit_types.h"
#include "conduit/message.h"
#include "conduit/inbox.h"
#include "conduit/subscription.h"
#include "conduit/publisher.h"
#include "conduit/topic.h"
#include "adt/dict_untyped.h"
#include "adt/list.h"
#include "core/alloc.h"

// Forward declarations
typedef struct n00b_conduit_io_backend n00b_conduit_io_backend_t;
typedef struct n00b_conduit_service    n00b_conduit_service_t;
struct n00b_conduit {
    n00b_allocator_t   *allocator;
    n00b_dict_untyped_t int_topics; /**< URI int -> topic base ptr */
    n00b_dict_untyped_t str_topics; /**< URI string -> topic base ptr */
    n00b_dict_untyped_t signal_watches; /**< signum -> n00b_conduit_signal_watch_t * */
    n00b_dict_untyped_t fd_owners;  /**< fd (int) -> n00b_conduit_fd_owner_t * */
    n00b_dict_untyped_t listeners;  /**< fd (int) -> n00b_conduit_listener_t * */
    n00b_list_t(n00b_conduit_io_backend_t *) io_backends; /**< Registered IO backends */
    _Atomic(uint64_t)       next_generation;
    _Atomic(uint64_t)       next_claim_id;
    _Atomic(uint64_t)       next_timer_id;
    _Atomic(uint64_t)       next_user_event_id;
    _Atomic(uint64_t)       next_listener_id;
    _Atomic(uint64_t)       next_local_id;
    _Atomic(uint64_t)       next_xform_id;
    _Atomic(bool)           shutdown;
    n00b_conduit_service_t *service;
};

// ============================================================================
// Conduit API
// ============================================================================

extern n00b_result_t(n00b_conduit_t *) n00b_conduit_new(void);

/**
 * @brief Destroy a conduit and release all resources.
 *
 * All registered topics are closed.  Subscribers that still hold
 * inbox references will see the topics go inactive (no new messages),
 * but existing queued messages remain valid.
 *
 * @pre  All I/O backends and services associated with this conduit
 *       should be stopped/destroyed **before** calling this function.
 * @post @p c is invalid after return — do not dereference.
 */
extern void n00b_conduit_destroy(n00b_conduit_t *c);

static inline bool
n00b_conduit_is_shutdown(n00b_conduit_t *c)
{
    return n00b_atomic_load(&c->shutdown);
}

// ============================================================================
// Backend registry
// ============================================================================

/**
 * @brief Register an IO backend with the conduit.
 *
 * Called automatically by `n00b_conduit_io_new`. The first registered
 * backend becomes the default for user events, signals, and timers.
 *
 * @return Ok(true) on success, or an error code if null arg or registry full.
 */
extern n00b_result_t(bool) n00b_conduit_register_backend(n00b_conduit_t            *c,
                                                                n00b_conduit_io_backend_t *io);

/**
 * @brief Unregister an IO backend from the conduit.
 */
extern void n00b_conduit_unregister_backend(n00b_conduit_t *c, n00b_conduit_io_backend_t *io);

/**
 * @brief Get the first registered backend (for user event/signal/timer routing).
 * @return Some(backend) if at least one backend is registered, None otherwise.
 */
static inline n00b_option_t(n00b_conduit_io_backend_t *)
    n00b_conduit_default_backend(n00b_conduit_t *c)
{
    if (!c || n00b_list_len(c->io_backends) == 0)
        return n00b_option_none(n00b_conduit_io_backend_t *);
    n00b_conduit_io_backend_t *io = n00b_list_get(c->io_backends, 0);
    return n00b_option_from_nullable(n00b_conduit_io_backend_t *, io);
}

/**
 * @brief Find a backend by its ops name string.
 * @return Some(backend) if found, None otherwise.
 */
extern n00b_option_t(n00b_conduit_io_backend_t *)
    n00b_conduit_backend_by_name(n00b_conduit_t *c, n00b_string_t *name);

extern n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_topic_get(n00b_conduit_t *c, n00b_conduit_uri_t uri, size_t topic_size);

static inline n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_topic_for_fd(n00b_conduit_t *c, int fd)
{
    return n00b_conduit_topic_get(c, N00B_CONDUIT_URI_FD(fd), 0);
}

extern uint64_t n00b_conduit_topic_close(n00b_conduit_topic_base_t *topic);

extern n00b_result_t(bool) n00b_conduit_topic_set_name(n00b_conduit_topic_base_t *topic,
                                                              const char                *name);

extern void n00b_conduit_topic_set_policy(n00b_conduit_topic_base_t *topic,
                                          n00b_conduit_policy_t      policy);

extern uint64_t n00b_conduit_epoch_current(n00b_conduit_topic_base_t *topic);

extern n00b_result_t(n00b_conduit_publisher_t *)
n00b_conduit_publish_claim(n00b_conduit_topic_base_t *topic);

extern n00b_result_t(n00b_conduit_publisher_t *)
n00b_conduit_publish_try_claim(n00b_conduit_topic_base_t *topic);

extern void n00b_conduit_publish_yield(n00b_conduit_publisher_t *pub);

extern bool n00b_conduit_publish_is_owner(n00b_conduit_topic_base_t *topic);

extern n00b_result_t(n00b_conduit_topic_base_t *)
    n00b_conduit_publish_topic(n00b_conduit_publisher_t *pub);

extern void n00b_conduit_publish_finishing(n00b_conduit_publisher_t *pub);

extern n00b_conduit_pub_state_t n00b_conduit_publish_state(n00b_conduit_publisher_t *pub);

extern bool n00b_conduit_publish_check_liveness(n00b_conduit_topic_base_t *topic);

// Done topic payload type: all done topics carry n00b_conduit_topic_base_t *.
// Must be after n00b_conduit_topic_get is declared (used by topic init).
N00B_CONDUIT_FULL_IMPL(n00b_conduit_topic_base_t *);

/**
 * @brief Lazily create and return a topic's done-topic.
 *
 * The done-topic fires when the owning topic is closed via
 * `n00b_conduit_topic_close()`.  The payload is a pointer to the
 * owning topic (`n00b_conduit_topic_base_t *`).
 *
 * If the done-topic already exists, returns the existing one.
 * Thread-safe (uses CAS on `topic->done_topic`).
 *
 * @param topic  The topic to get a done-topic for.
 * @return The done-topic, or nullptr on allocation failure.
 */
extern n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *
n00b_conduit_topic_ensure_done(n00b_conduit_topic_base_t *topic);
