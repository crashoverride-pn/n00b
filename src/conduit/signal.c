/*
 * signal.c - signal handling implementation for conduit
 */

#define N00B_USE_INTERNAL_API

#include "conduit/conduit.h"
#include "conduit/signal.h"
#include "conduit/io.h"
#include "conduit/service.h"

// ============================================================================
// Signal Watch Creation
// ============================================================================

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_signal_topic(n00b_conduit_t *c, int signum)
{
    if (!c) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (signum <= 0) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    bool found = false;
    n00b_conduit_signal_watch_t *existing =
        _n00b_dict_untyped_get(&c->signal_watches,
                               (void *)(uintptr_t)signum,
                               &found);
    if (found && existing && existing->topic) {
        return n00b_result_ok(n00b_conduit_topic_base_t *, existing->topic);
    }

    // Allocate and initialize signal watch
    n00b_conduit_signal_watch_t *watch =
        n00b_alloc_with_opts(n00b_conduit_signal_watch_t,
            &(n00b_alloc_opts_t){.allocator = c->allocator});

    watch->signum = signum;
    n00b_atomic_store(&watch->raise_count, (uint64_t)0);
    watch->io               = nullptr;
    watch->mask_was_blocked = false;
    watch->next             = nullptr;

    // Create and initialize the typed topic for this signal.  Using
    // topic_get() directly leaves the typed subscription list uninitialized,
    // so subscriptions can appear to succeed while delivery sees no readers.
    n00b_conduit_topic_t(n00b_conduit_signal_payload_t) *topic =
        n00b_conduit_topic_init(n00b_conduit_signal_payload_t,
                                c,
                                N00B_CONDUIT_URI_SIGNAL(signum));
    if (topic == nullptr) {
        n00b_free(watch);
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }
    watch->topic = (n00b_conduit_topic_base_t *)topic;

    // Register with I/O backend
    if (!n00b_conduit_signal_register(c, watch)) {
        n00b_free(watch);
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    _n00b_dict_untyped_put(&c->signal_watches,
                           (void *)(uintptr_t)signum,
                           watch);

    return n00b_result_ok(n00b_conduit_topic_base_t *, watch->topic);
}

void
n00b_conduit_signal_unwatch(n00b_conduit_t *c, int signum)
{
    if (!c || signum <= 0) {
        return;
    }

    bool found = false;
    n00b_conduit_signal_watch_t *watch =
        _n00b_dict_untyped_get(&c->signal_watches,
                               (void *)(uintptr_t)signum,
                               &found);
    if (found && watch) {
        n00b_conduit_signal_unregister(c, watch);
        _n00b_dict_untyped_remove(&c->signal_watches,
                                  (void *)(uintptr_t)signum);
        n00b_free(watch);
    }

    // Close the topic so subscribers get TOPIC_CLOSED
    n00b_result_t(n00b_conduit_topic_base_t *) topic_res =
        n00b_conduit_topic_get(c, N00B_CONDUIT_URI_SIGNAL(signum), 0);
    if (n00b_result_is_ok(topic_res)) {
        n00b_conduit_topic_close(n00b_result_get(topic_res));
    }
}

// ============================================================================
// Signal Registration (with I/O backend)
// ============================================================================

bool
n00b_conduit_signal_register(n00b_conduit_t *c,
                             n00b_conduit_signal_watch_t *watch)
{
    if (!c || !watch) {
        return false;
    }

    n00b_option_t(n00b_conduit_io_backend_t *) opt =
        n00b_option_none(n00b_conduit_io_backend_t *);
    if (c->service) {
        n00b_option_t(n00b_conduit_svc_thread_t *) st_opt =
            n00b_conduit_service_signal_io(c->service);
        if (n00b_option_is_set(st_opt)) {
            n00b_conduit_svc_thread_t *st = n00b_option_get(st_opt);
            opt = n00b_conduit_svc_thread_io(st);
        }
    }
    if (!n00b_option_is_set(opt)) {
        opt = n00b_conduit_default_backend(c);
    }
    if (!n00b_option_is_set(opt)) {
        return false;
    }
    n00b_conduit_io_backend_t *io = n00b_option_get(opt);
    if (!io->ops->signal_add) {
        return false;
    }

    if (!io->ops->signal_add(io->ctx, watch)) {
        return false;
    }
    watch->io = io;
    return true;
}

void
n00b_conduit_signal_unregister(n00b_conduit_t *c,
                               n00b_conduit_signal_watch_t *watch)
{
    if (!c || !watch) {
        return;
    }

    n00b_conduit_io_backend_t *io = watch->io;
    if (!io) {
        return;
    }
    if (!io->ops->signal_remove) {
        return;
    }

    io->ops->signal_remove(io->ctx, watch);
    watch->io = nullptr;
}

void
n00b_conduit_signal_cleanup(n00b_conduit_t *c)
{
    if (!c) {
        return;
    }

    n00b_dict_untyped_store_t *store = n00b_atomic_load(&c->signal_watches.store);
    if (!store) {
        return;
    }

    for (uint32_t i = 0; i <= store->last_slot; i++) {
        n00b_dict_untyped_bucket_t *b = &store->buckets[i];
        uint32_t flags = n00b_atomic_load(&b->flags);
        if ((flags & N00B_HT_FLAG_DELETED) || !b->value) {
            continue;
        }

        n00b_conduit_signal_watch_t *watch =
            (n00b_conduit_signal_watch_t *)b->value;
        n00b_conduit_signal_unregister(c, watch);
        b->value = nullptr;
        n00b_free(watch);
    }
}

// ============================================================================
// Signal Firing
// ============================================================================

void
n00b_conduit_signal_fire(n00b_conduit_signal_watch_t *watch)
{
    if (!watch || !watch->topic) {
        return;
    }

    n00b_conduit_t *c = watch->topic->conduit;
    if (!c || n00b_conduit_is_shutdown(c)) {
        return;
    }

    n00b_atomic_add(&watch->raise_count, 1);

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(watch->topic);
    if (n00b_result_is_err(pub_res)) {
        // Bump epoch so subscribers can detect the missed signal.
        n00b_atomic_add(&watch->topic->epoch, 1);
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_signal_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_signal_msg_t,
        &(n00b_alloc_opts_t){.allocator = c->allocator});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = watch->topic;
    msg->header.generation = n00b_conduit_topic_generation(watch->topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(watch->topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.signum      = watch->signum;
    msg->payload.raise_count = n00b_atomic_load(&watch->raise_count);

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_signal_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_signal_payload_t) *)watch->topic,
        msg,
        N00B_CONDUIT_SIGNAL_RAISED);

    n00b_conduit_publish_yield(pub);
}
