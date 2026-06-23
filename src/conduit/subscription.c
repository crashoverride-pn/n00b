/*
 * subscription.c — Subscription management implementation.
 *
 * Manages subscription create, cancel, suspend, resume, and system
 * message delivery.  Uses n00b_dict_untyped_t for handle→subscription
 * lookup, and n00b_list_t for per-topic subscription storage.
 */

#include "conduit/conduit.h"
#include "core/runtime.h"
#include "core/time.h"
#include "core/condition.h"
#include <string.h>

// ============================================================================
// Internal subscription base — type-erased for the global handle map.
//
// Every typed subscription (n00b_conduit_subscription_t(T)) has fields
// at the same offsets as this struct.
// ============================================================================

typedef struct _n00b_conduit_sub_base {
    n00b_conduit_sub_handle_t    handle;
    void                        *inbox;        // typed inbox pointer
    n00b_conduit_sys_queue_t    *sys_queue;
    uint32_t                     operations;
    uint64_t                     generation;
    uint64_t                     epoch;
    _Atomic(int)                 state;
    bool                         one_shot;
    bool                         dedicated_inbox;
    bool                         notify_on_delivery;
    bool                         confirm_cancel;
    bool                         notify_unsub;
    bool                         timeout_relative;
    uint32_t                     timeout_ms;
    n00b_conduit_backpressure_t  backpressure;
    uint32_t                     inbox_limit;
    n00b_conduit_topic_base_t   *topic;
    void                        *next_for_topic;
} _n00b_conduit_sub_base_t;

typedef struct _n00b_conduit_inbox_base {
    _Atomic(void *)                 head;
    _Atomic(void *)                 tail;
    n00b_conduit_backpressure_t     backpressure;
    uint32_t                        limit;
    _Atomic(uint32_t)               count;
    _Atomic(uint32_t)               drop_credits;
    _Atomic(uint32_t)               flags;
    n00b_conduit_sys_queue_t        sys_queue;
    n00b_condition_t                cv;
    n00b_conduit_t                 *conduit;
    const char                     *name;
} _n00b_conduit_inbox_base_t;

// ============================================================================
// Global handle → subscription map
//
// Stored in n00b_runtime_t.sub_map (system-pool-backed) so the GC
// cannot collect the dict's internal store.  A BSS-resident dict
// would have its store pointer invisible to the collector.
// ============================================================================

static inline n00b_dict_untyped_t *
sub_map(void)
{
    return n00b_get_runtime()->sub_map;
}

static inline void
sub_map_insert(n00b_conduit_sub_handle_t handle, _n00b_conduit_sub_base_t *sub)
{
    _n00b_dict_untyped_put(sub_map(), (void *)(uintptr_t)handle, (void *)sub);
}

static inline _n00b_conduit_sub_base_t *
sub_map_lookup(n00b_conduit_sub_handle_t handle)
{
    bool found = false;
    void *val  = _n00b_dict_untyped_get(sub_map(), (void *)(uintptr_t)handle,
                                        &found);
    return found ? (_n00b_conduit_sub_base_t *)val : nullptr;
}

static inline void
sub_map_remove(n00b_conduit_sub_handle_t handle)
{
    _n00b_dict_untyped_remove(sub_map(), (void *)(uintptr_t)handle);
}

// ============================================================================
// System message delivery
// ============================================================================

static void
sub_send_sys_message(_n00b_conduit_sub_base_t *sub, n00b_conduit_msg_type_t type)
{
    if (!sub || !sub->sys_queue) return;

    n00b_allocator_t *msg_alloc = sub->topic && sub->topic->conduit ?
        sub->topic->conduit->allocator :
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    n00b_conduit_sys_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_sys_msg_t,
        &(n00b_alloc_opts_t){.allocator = msg_alloc});
    if (!msg) return;

    msg->header.type       = type;
    msg->header.topic      = sub->topic;
    msg->header.generation = sub->topic
                                 ? n00b_conduit_topic_generation(sub->topic)
                                 : 0;
    msg->header.epoch      = sub->topic
                                 ? n00b_conduit_topic_epoch(sub->topic)
                                 : 0;
    msg->header.timestamp  = n00b_ns_timestamp();
    msg->header.next       = nullptr;

    n00b_conduit_sys_queue_push(sub->sys_queue, msg);

    if (sub->inbox) {
        _n00b_conduit_inbox_base_t *inbox = sub->inbox;

        if ((n00b_atomic_load(&inbox->flags) & N00B_CONDUIT_INBOX_F_NO_NOTIFY) == 0) {
            n00b_condition_notify(&inbox->cv, .auto_unlock = true);
        }
    }
}

// ============================================================================
// Subscription management API
// ============================================================================

static void
sub_unlink_from_topic(_n00b_conduit_sub_base_t *sub)
{
    n00b_conduit_topic_base_t *topic = sub->topic;
    if (!topic) return;

    bool unlinked = false;

    // Walk the per-topic chain and CAS-unlink this sub.
    // Simple approach: try to remove from head, else linear scan.
    void *head = n00b_atomic_load(&topic->sub_list_head);
    if (head == sub) {
        // We're the head — CAS remove.
        if (n00b_atomic_cas(&topic->sub_list_head, &head, sub->next_for_topic)) {
            sub->next_for_topic = nullptr;
            unlinked = true;
        }
        else {
            // CAS failed — head changed, fall through to linear scan.
            head = n00b_atomic_load(&topic->sub_list_head);
        }
    }

    if (!unlinked) {
        // Linear scan for our predecessor.
        _n00b_conduit_sub_base_t *prev = (_n00b_conduit_sub_base_t *)head;
        while (prev) {
            if (prev->next_for_topic == sub) {
                prev->next_for_topic = sub->next_for_topic;
                sub->next_for_topic = nullptr;
                unlinked = true;
                break;
            }
            prev = (_n00b_conduit_sub_base_t *)prev->next_for_topic;
        }
    }

    // Edge trigger: fire on_last_unsubscribe when list becomes empty.
    if (unlinked && n00b_atomic_load(&topic->sub_list_head) == nullptr) {
        if (topic->on_last_unsubscribe) {
            topic->on_last_unsubscribe(topic, topic->on_last_unsubscribe_ctx);
        }
    }
}

void
n00b_conduit_sub_cancel(n00b_conduit_sub_handle_t handle)
{
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) return;

    _n00b_conduit_sub_base_t *sub = sub_map_lookup(handle);
    if (!sub) return;

    if (n00b_atomic_load(&sub->state) == N00B_CONDUIT_SUB_REMOVED) {
        sub_unlink_from_topic(sub);
        sub_map_remove(handle);
        return;
    }

    int expected = N00B_CONDUIT_SUB_ACTIVE;
    if (!n00b_atomic_cas(&sub->state, &expected, N00B_CONDUIT_SUB_CANCELING)) {
        expected = N00B_CONDUIT_SUB_SUSPENDED;
        if (!n00b_atomic_cas(&sub->state, &expected,
                             N00B_CONDUIT_SUB_CANCELING)) {
            return;
        }
    }

    sub_unlink_from_topic(sub);
    sub_map_remove(handle);
    n00b_atomic_store(&sub->state, N00B_CONDUIT_SUB_REMOVED);

    if (sub->confirm_cancel) {
        sub_send_sys_message(sub, N00B_CONDUIT_MSG_CANCEL_ACK);
    }
}

void
n00b_conduit_sub_suspend(n00b_conduit_sub_handle_t handle)
{
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) return;

    _n00b_conduit_sub_base_t *sub = sub_map_lookup(handle);
    if (!sub) return;

    int expected = N00B_CONDUIT_SUB_ACTIVE;
    n00b_atomic_cas(&sub->state, &expected, N00B_CONDUIT_SUB_SUSPENDED);
}

void
n00b_conduit_sub_resume(n00b_conduit_sub_handle_t handle)
{
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) return;

    _n00b_conduit_sub_base_t *sub = sub_map_lookup(handle);
    if (!sub) return;

    int expected = N00B_CONDUIT_SUB_SUSPENDED;
    n00b_atomic_cas(&sub->state, &expected, N00B_CONDUIT_SUB_ACTIVE);
}

bool
n00b_conduit_sub_is_active(n00b_conduit_sub_handle_t handle)
{
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) return false;

    _n00b_conduit_sub_base_t *sub = sub_map_lookup(handle);
    if (!sub) return false;

    return n00b_atomic_load(&sub->state) == N00B_CONDUIT_SUB_ACTIVE;
}

n00b_conduit_sub_state_t
n00b_conduit_sub_state(n00b_conduit_sub_handle_t handle)
{
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return N00B_CONDUIT_SUB_REMOVED;
    }

    _n00b_conduit_sub_base_t *sub = sub_map_lookup(handle);
    if (!sub) return N00B_CONDUIT_SUB_REMOVED;

    return (n00b_conduit_sub_state_t)n00b_atomic_load(&sub->state);
}

// ============================================================================
// Internal: topic-level subscription notification
// ============================================================================

/*
 * Register a subscription in the global handle map.
 * Called by the typed subscribe() functions generated in topic.h.
 */
void
_n00b_conduit_sub_register(n00b_conduit_sub_handle_t handle, void *sub_ptr,
                           n00b_conduit_topic_base_t *topic)
{
    _n00b_conduit_sub_base_t *sub = (_n00b_conduit_sub_base_t *)sub_ptr;
    sub->topic = topic;
    sub_map_insert(handle, sub);

    // Link into per-topic subscription chain (lock-free push to head).
    void *old_head;
    do {
        old_head = n00b_atomic_load(&topic->sub_list_head);
        sub->next_for_topic = old_head;
    } while (!n00b_atomic_cas(&topic->sub_list_head, &old_head, sub));

    // Fire on_first_subscribe callback when this is the first subscriber.
    if (old_head == nullptr && topic->on_first_subscribe) {
        topic->on_first_subscribe(topic, topic->on_first_subscribe_ctx);
    }
}

/*
 * Walk the per-topic subscription chain and deliver a system message
 * to each subscriber's sys_queue.  This is untyped — works via the
 * type-erased sub base layout and the type-agnostic sys_queue.
 */
static void
topic_notify_all(n00b_conduit_topic_base_t *topic, n00b_conduit_msg_type_t type)
{
    if (!topic) return;

    _n00b_conduit_sub_base_t *sub =
        (_n00b_conduit_sub_base_t *)n00b_atomic_load(&topic->sub_list_head);

    while (sub) {
        _n00b_conduit_sub_base_t *next =
            (_n00b_conduit_sub_base_t *)sub->next_for_topic;
        sub_send_sys_message(sub, type);
        sub = next;
    }
}

/*
 * Notify all subscribers that topic is closing, then cancel them.
 */
void
_n00b_conduit_topic_notify_close(n00b_conduit_topic_base_t *topic)
{
    topic_notify_all(topic, N00B_CONDUIT_MSG_TOPIC_CLOSED);

    // Cancel all subscriptions so they're removed from the global map.
    _n00b_conduit_sub_base_t *sub =
        (_n00b_conduit_sub_base_t *)n00b_atomic_load(&topic->sub_list_head);

    while (sub) {
        _n00b_conduit_sub_base_t *next =
            (_n00b_conduit_sub_base_t *)sub->next_for_topic;
        sub_map_remove(sub->handle);
        n00b_atomic_store(&sub->state, N00B_CONDUIT_SUB_REMOVED);
        sub = next;
    }

    n00b_atomic_store(&topic->sub_list_head, (void *)nullptr);
}

/*
 * Notify all subscribers that the publisher was lost.
 */
void
_n00b_conduit_topic_notify_publisher_lost(n00b_conduit_topic_base_t *topic)
{
    topic_notify_all(topic, N00B_CONDUIT_MSG_PUBLISHER_LOST);
}
