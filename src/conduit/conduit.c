/*
 * conduit.c — Core conduit implementation.
 *
 * Manages the conduit lifecycle, topic registry (get-or-create via
 * n00b_dict_untyped_t), generation/claim-ID allocation, and the publisher
 * claim/yield/liveness protocol.
 */

#define N00B_USE_INTERNAL_API
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/service.h"
#include "conduit/signal.h"
#include "core/hash.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/time.h"
#include "text/strings/string_ops.h"
#ifndef _WIN32
#include <signal.h>
#include <pthread.h>
#endif
#include <string.h>

// ============================================================================
// Conduit lifecycle
// ============================================================================

n00b_result_t(n00b_conduit_t *)
n00b_conduit_new(void)
{
    n00b_allocator_t *cpool = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    n00b_conduit_t   *c     = n00b_alloc_with_opts(n00b_conduit_t,
                                  &(n00b_alloc_opts_t){.allocator = cpool});
    if (!c) {
        return n00b_result_err(n00b_conduit_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    c->allocator = cpool;

    n00b_dict_untyped_init(&c->int_topics,
                           .allocator     = cpool,
                           .skip_obj_hash = true,
                           .hash          = n00b_hash_word);
    n00b_dict_untyped_init(&c->str_topics,
                           .allocator     = cpool);
    n00b_dict_untyped_init(&c->signal_watches,
                           .allocator     = cpool,
                           .skip_obj_hash = true,
                           .hash          = n00b_hash_word);
    n00b_dict_untyped_init(&c->fd_owners,
                           .allocator     = cpool,
                           .skip_obj_hash = true,
                           .hash          = n00b_hash_word);
    n00b_dict_untyped_init(&c->listeners,
                           .allocator     = cpool,
                           .skip_obj_hash = true,
                           .hash          = n00b_hash_word);

    c->io_backends = n00b_list_new(n00b_conduit_io_backend_t *, .allocator = cpool);

    n00b_atomic_store(&c->next_generation, 1);
    n00b_atomic_store(&c->next_claim_id, 1);
    n00b_atomic_store(&c->next_timer_id, 1);
    n00b_atomic_store(&c->next_user_event_id, 1);
    n00b_atomic_store(&c->next_local_id, 1);
    n00b_atomic_store(&c->next_xform_id, 1);
    n00b_atomic_store(&c->shutdown, false);
    c->service = nullptr;

    return n00b_result_ok(n00b_conduit_t *, c);
}

static void
close_topics_in_dict(n00b_dict_untyped_t *dict, bool free_topics)
{
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&dict->store);
    if (!store) return;

    for (uint32_t i = 0; i <= store->last_slot; i++) {
        n00b_dict_untyped_bucket_t *b = &store->buckets[i];
        uint32_t flags = n00b_atomic_load(&b->flags);
        if ((flags & N00B_HT_FLAG_DELETED) || !b->value) {
            continue;
        }
        n00b_conduit_topic_base_t *topic = (n00b_conduit_topic_base_t *)b->value;
        n00b_conduit_topic_state_t state = n00b_atomic_load(&topic->state);
        if (state == N00B_CONDUIT_TOPIC_ACTIVE) {
            n00b_conduit_topic_close(topic);
        }
        // Teardown: free the topic struct allocated in n00b_conduit_topic_get.
        // n00b_free is allocator-agnostic — it no-ops on default GC-arena
        // pointers (so GC-backed conduits are unaffected) and reclaims the
        // slab for pool-backed conduits, where the topic would otherwise
        // persist for the process lifetime.
        b->value = nullptr;
        if (free_topics) {
            n00b_free(topic);
        }
    }
}

void
n00b_conduit_destroy(n00b_conduit_t *c)
{
    if (!c) {
        return;
    }

    n00b_atomic_store(&c->shutdown, true);

    // Stop service threads before mutating backend watch lists.
    if (c->service) {
        n00b_conduit_service_stop(c->service);
    }
    n00b_conduit_signal_cleanup(c);
    if (c->service) {
        n00b_conduit_service_destroy(c->service);
    }

    // Close all topics, which notifies subscribers.
    n00b_runtime_t *rt = n00b_get_runtime();
    bool free_topics = rt == nullptr
                    || !n00b_atomic_load(&rt->shutdown_started);
    close_topics_in_dict(&c->int_topics, free_topics);
    close_topics_in_dict(&c->str_topics, free_topics);
}

// ============================================================================
// Topic registry — get-or-create
//
// TODO(vtable): Replace the `topic_size` parameter with a URI-tag → type
// registration table.  Each URI tag (e.g. FD, timer, signal, socket)
// should map to a registered struct { size_t size; init_fn init; } so
// that topic_get() can allocate the right typed topic and call its init
// function automatically.  This is blocked on the generalized object
// vtable system.  Until then, callers pass sizeof(their_typed_topic_t)
// and initialize the typed extension fields themselves.
// ============================================================================

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_topic_get(n00b_conduit_t *c, n00b_conduit_uri_t uri,
                        size_t topic_size)
{
    if (!c) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (n00b_conduit_is_shutdown(c)) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_SHUTDOWN);
    }

    if (topic_size < sizeof(n00b_conduit_topic_base_t)) {
        topic_size = sizeof(n00b_conduit_topic_base_t);
    }

    n00b_dict_untyped_t *dict;
    void                *key;

    if (n00b_variant_is_type(uri, uint64_t)) {
        dict = &c->int_topics;
        uint64_t int_key = n00b_variant_get(uri, uint64_t);
        key  = (void *)(uintptr_t)int_key;
    }
    else {
        dict = &c->str_topics;
        n00b_string_t *s = n00b_variant_get(uri, n00b_string_t *);
        key  = (void *)s->data;
    }

    // Look up existing topic.
    bool   found = false;
    void  *val   = _n00b_dict_untyped_get(dict, key, &found);

    if (found) {
        n00b_conduit_topic_base_t *topic = (n00b_conduit_topic_base_t *)val;

        // If topic was closed (e.g. FD recycled), reactivate with new generation.
        // Clear stale publisher, subscriber chain, and waiters from the
        // previous generation.  Typed fields beyond the base struct are
        // the caller's responsibility to reinitialize.
        n00b_conduit_topic_state_t state = n00b_atomic_load(&topic->state);
        if (state == N00B_CONDUIT_TOPIC_CLOSED) {
            uint64_t gen = n00b_atomic_add(&c->next_generation, 1);
            n00b_atomic_store(&topic->generation, gen);
            n00b_atomic_store(&topic->epoch, (uint64_t)0);
            n00b_atomic_store(&topic->publisher, (n00b_conduit_publisher_t *)nullptr);
            n00b_atomic_store(&topic->pub_claim_id, (uint64_t)0);
            n00b_atomic_store(&topic->pub_waiters, (uint32_t)0);
            n00b_atomic_store(&topic->sub_list_head, (void *)nullptr);
            n00b_atomic_store(&topic->done_topic, (void *)nullptr);
            n00b_atomic_store(&topic->timer_owner, (void *)nullptr);
            n00b_atomic_store(&topic->state, N00B_CONDUIT_TOPIC_ACTIVE);
        }
        return n00b_result_ok(n00b_conduit_topic_base_t *, topic);
    }

    // Create new topic, sized for the caller's typed topic struct.
    n00b_conduit_topic_base_t *topic = (n00b_conduit_topic_base_t *)
        n00b_alloc_array_with_opts(uint8_t, topic_size,
            &(n00b_alloc_opts_t){.allocator = c->allocator});
    if (!topic) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    // Zero the WHOLE typed struct: the conduit pool does not guarantee zeroed
    // allocations, and the typed topic's lazy initializers key off null (the
    // typed `init` does `if (!topic->subscriptions.data) subscriptions = list_new`).
    // Without this, a fresh topic whose uninitialized `subscriptions.data` holds
    // non-null pool garbage skips list creation, and the typed deliver then reads
    // a garbage backing array (observed: SIGSEGV in the sock_status deliver
    // during conn_close, reading topic->subscriptions.data).
    memset(topic, 0, topic_size);

    topic->uri     = uri;
    topic->conduit = c;
    n00b_atomic_store(&topic->policy, (int)N00B_CONDUIT_POLICY_OPEN);
    n00b_atomic_store(&topic->generation, n00b_atomic_add(&c->next_generation, 1));
    n00b_atomic_store(&topic->epoch, (uint64_t)0);
    n00b_atomic_store(&topic->state, N00B_CONDUIT_TOPIC_ACTIVE);
    n00b_atomic_store(&topic->publisher, (n00b_conduit_publisher_t *)nullptr);
    n00b_atomic_store(&topic->pub_claim_id, (uint64_t)0);
    n00b_futex_init(&topic->pub_futex);
    n00b_atomic_store(&topic->pub_waiters, (uint32_t)0);
    n00b_atomic_store(&topic->debug_name, (const char *)nullptr);
    n00b_atomic_store(&topic->sub_list_head, (void *)nullptr);
    n00b_atomic_store(&topic->done_topic, (void *)nullptr);
    n00b_atomic_store(&topic->timer_owner, (void *)nullptr);
    topic->on_first_subscribe      = nullptr;
    topic->on_first_subscribe_ctx  = nullptr;
    topic->on_last_unsubscribe     = nullptr;
    topic->on_last_unsubscribe_ctx = nullptr;

    _n00b_dict_untyped_put(dict, key, (void *)topic);

    return n00b_result_ok(n00b_conduit_topic_base_t *, topic);
}

uint64_t
n00b_conduit_topic_close(n00b_conduit_topic_base_t *topic)
{
    if (!topic) {
        return 0;
    }

    n00b_conduit_topic_state_t expected = N00B_CONDUIT_TOPIC_ACTIVE;
    if (!n00b_atomic_cas(&topic->state, &expected, N00B_CONDUIT_TOPIC_CLOSING)) {
        return n00b_atomic_load(&topic->generation);
    }

    // Fire the done_topic if one exists.  This tells "topic is done
    // producing" subscribers that no more messages will arrive.
    n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *done =
        (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)
            n00b_atomic_load(&topic->done_topic);

    if (done) {
        n00b_conduit_message_t(n00b_conduit_topic_base_t *) *dm =
            n00b_alloc_with_opts(
                n00b_conduit_message_t(n00b_conduit_topic_base_t *),
                &(n00b_alloc_opts_t){.allocator = topic->conduit->allocator});
        dm->header.type  = N00B_CONDUIT_MSG_USER;
        dm->header.topic = (n00b_conduit_topic_base_t *)done;
        dm->payload      = topic;
        n00b_conduit_topic_deliver_msg(
            n00b_conduit_topic_base_t *,
            done, dm, N00B_CONDUIT_OP_ALL);
    }

    // Notify subscribers of close (implemented in subscription.c).
    extern void _n00b_conduit_topic_notify_close(n00b_conduit_topic_base_t *);
    _n00b_conduit_topic_notify_close(topic);

    uint64_t new_gen = n00b_atomic_add(&topic->generation, 1) + 1;
    n00b_atomic_store(&topic->state, N00B_CONDUIT_TOPIC_CLOSED);

    return new_gen;
}

n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *
n00b_conduit_topic_ensure_done(n00b_conduit_topic_base_t *topic)
{
    if (!topic || !topic->conduit) {
        return nullptr;
    }

    // Fast path: already exists.
    n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *existing =
        (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)
            n00b_atomic_load(&topic->done_topic);
    if (existing) {
        return existing;
    }

    // Slow path: create one.
    n00b_conduit_t *c = topic->conduit;

    static _Atomic(uint64_t) done_id = 1;
    uint64_t id = n00b_atomic_add(&done_id, 1);

    n00b_result_t(n00b_conduit_topic_base_t *) r =
        n00b_conduit_topic_get(
            c, N00B_CONDUIT_URI_DONE(id),
            sizeof(n00b_conduit_topic_t(n00b_conduit_topic_base_t *)));

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *done =
        (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)
            n00b_result_get(r);

    done->subscriptions = n00b_list_new(
        n00b_conduit_subscription_t(n00b_conduit_topic_base_t *) *, .allocator = c->allocator);
    done->inbox = nullptr;

    // Done topics don't get their own done topics.
    n00b_atomic_store(
        &((n00b_conduit_topic_base_t *)done)->done_topic, nullptr);

    // CAS to install — if someone raced us, use theirs.
    void *expected = nullptr;
    if (n00b_atomic_cas(&topic->done_topic, &expected, done)) {
        return done;
    }

    // Lost the race; return the winner.
    return (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)expected;
}

n00b_result_t(bool)
n00b_conduit_topic_set_name(n00b_conduit_topic_base_t *topic, const char *name)
{
    if (!topic) {
        return n00b_result_err(bool, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_atomic_store(&topic->debug_name, name);

    return n00b_result_ok(bool, true);
}

void
n00b_conduit_topic_set_policy(n00b_conduit_topic_base_t *topic,
                              n00b_conduit_policy_t      policy)
{
    if (topic) {
        n00b_atomic_store(&topic->policy, (int)policy);
    }
}

uint64_t
n00b_conduit_epoch_current(n00b_conduit_topic_base_t *topic)
{
    if (!topic) {
        return 0;
    }
    return n00b_conduit_topic_epoch(topic);
}

// ============================================================================
// Backend registry
// ============================================================================

n00b_result_t(bool)
n00b_conduit_register_backend(n00b_conduit_t *c, n00b_conduit_io_backend_t *io)
{
    if (!c || !io) {
        return n00b_result_err(bool, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_list_push(c->io_backends, io);
    return n00b_result_ok(bool, true);
}

void
n00b_conduit_unregister_backend(n00b_conduit_t *c, n00b_conduit_io_backend_t *io)
{
    if (!c || !io) return;

    (void)n00b_list_remove_all(c->io_backends, io);
}

n00b_option_t(n00b_conduit_io_backend_t *)
n00b_conduit_backend_by_name(n00b_conduit_t *c, n00b_string_t *name)
{
    if (!c || !name) {
        return n00b_option_none(n00b_conduit_io_backend_t *);
    }

    n00b_list_foreach(c->io_backends, p) {
        n00b_conduit_io_backend_t *io = *p;
        if (io && io->ops && io->ops->name) {
            n00b_string_t *io_name = io->ops->name();
            if (n00b_unicode_str_eq(io_name, name)) {
                return n00b_option_set(n00b_conduit_io_backend_t *, io);
            }
        }
    }
    return n00b_option_none(n00b_conduit_io_backend_t *);
}

// ============================================================================
// Publisher implementation
// ============================================================================

static n00b_result_t(n00b_conduit_publisher_t *)
publisher_alloc(n00b_conduit_t *c, n00b_conduit_topic_base_t *topic)
{
    n00b_conduit_publisher_t *pub = n00b_alloc_with_opts(n00b_conduit_publisher_t,
                                       &(n00b_alloc_opts_t){.allocator = c->allocator});
    if (!pub) {
        return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    pub->topic             = topic;
    pub->thread            = base_current_thread_id();
    pub->claim_id          = n00b_atomic_add(&c->next_claim_id, 1);
    pub->thread_slot       = (uint32_t)n00b_thread_id();
    n00b_runtime_t *rt     = n00b_get_runtime();
    pub->thread_generation = rt->threads[pub->thread_slot].generation;
    n00b_atomic_store(&pub->state, (int)N00B_CONDUIT_PUB_ACTIVE);
    n00b_futex_init(&pub->waiters);
    n00b_atomic_store(&pub->waiter_count, (uint32_t)0);

    return n00b_result_ok(n00b_conduit_publisher_t *, pub);
}

static bool
publisher_is_dead(n00b_conduit_topic_base_t *topic, n00b_conduit_publisher_t *pub)
{
    (void)topic;

    n00b_runtime_t       *rt  = n00b_get_runtime();
    n00b_thread_record_t *rec = &rt->threads[pub->thread_slot];

    // If the slot's thread pointer is null the thread has exited.
    n00b_thread_t *t = n00b_atomic_load(&rec->thread);
    if (!t) {
        return true;
    }

    // If the generation has changed the slot was reused by another thread.
    if (rec->generation != pub->thread_generation) {
        return true;
    }

    return false;
}

static void
handle_publisher_lost(n00b_conduit_topic_base_t *topic,
                      n00b_conduit_publisher_t  *dead_pub)
{
    n00b_conduit_publisher_t *expected = dead_pub;
    if (!n00b_atomic_cas(&topic->publisher, &expected,
                         (n00b_conduit_publisher_t *)nullptr)) {
        return;
    }

    extern void _n00b_conduit_topic_notify_publisher_lost(
        n00b_conduit_topic_base_t *);
    _n00b_conduit_topic_notify_publisher_lost(topic);

    n00b_atomic_add(&topic->pub_futex, 1);
    n00b_futex_wake(&topic->pub_futex, true);
}

n00b_result_t(n00b_conduit_publisher_t *)
n00b_conduit_publish_try_claim(n00b_conduit_topic_base_t *topic)
{
    if (!topic || !topic->conduit) {
        return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_conduit_t *c = topic->conduit;

    if (n00b_conduit_is_shutdown(c)) {
        return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_SHUTDOWN);
    }
    if (!n00b_conduit_topic_is_active(topic)) {
        return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_CLOSED);
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_res = publisher_alloc(c, topic);
    if (n00b_result_is_err(pub_res)) {
        return pub_res;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_publisher_t *expected = nullptr;
    if (n00b_atomic_cas(&topic->publisher, &expected, pub)) {
        n00b_atomic_store(&topic->pub_claim_id, pub->claim_id);
        return n00b_result_ok(n00b_conduit_publisher_t *, pub);
    }

    // Re-entrant claim check.
    if (expected &&
        n00b_conduit_thread_equal(expected->thread, base_current_thread_id())) {
        // The same thread already owns the publisher slot, so the
        // publisher we speculatively allocated above was never
        // installed. Free it — otherwise every re-publish to an
        // already-claimed topic (e.g. a high-rate single-publisher
        // payload or timer topic) leaks one publisher. n00b_free is
        // allocator-agnostic: it frees pool/metadata allocations and
        // no-ops on plain GC-arena pointers, so this is safe whatever
        // c->allocator is.
        n00b_free(pub);
        return n00b_result_ok(n00b_conduit_publisher_t *, expected);
    }

    // Dead publisher recovery.
    if (expected && publisher_is_dead(topic, expected)) {
        handle_publisher_lost(topic, expected);

        for (int retries = 0; retries < 5; retries++) {
            expected = nullptr;
            if (n00b_atomic_cas(&topic->publisher, &expected, pub)) {
                n00b_atomic_store(&topic->pub_claim_id, pub->claim_id);
                return n00b_result_ok(n00b_conduit_publisher_t *, pub);
            }
            if (expected && publisher_is_dead(topic, expected)) {
                handle_publisher_lost(topic, expected);
                continue;
            }
            break;
        }
    }

    // Another live publisher owns the slot and pub was never
    // installed (no CAS above succeeded). Free the speculative
    // allocation so repeated contended claims don't leak.
    n00b_free(pub);
    return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_ALREADY_CLAIMED);
}

n00b_result_t(n00b_conduit_publisher_t *)
n00b_conduit_publish_claim(n00b_conduit_topic_base_t *topic)
{
    if (!topic || !topic->conduit) {
        return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(topic);
    if (n00b_result_is_ok(pub_res)) {
        return pub_res;
    }

    n00b_err_t err = n00b_result_get_err(pub_res);
    if (err != N00B_CONDUIT_ERR_ALREADY_CLAIMED) {
        return pub_res;
    }

    n00b_conduit_t *c = topic->conduit;
    n00b_atomic_add(&topic->pub_waiters, 1);

    while (1) {
        if (n00b_conduit_is_shutdown(c)) {
            n00b_atomic_add(&topic->pub_waiters, (uint32_t)-1);
            return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_SHUTDOWN);
        }
        if (!n00b_conduit_topic_is_active(topic)) {
            n00b_atomic_add(&topic->pub_waiters, (uint32_t)-1);
            return n00b_result_err(n00b_conduit_publisher_t *, N00B_CONDUIT_ERR_CLOSED);
        }

        pub_res = n00b_conduit_publish_try_claim(topic);
        if (n00b_result_is_ok(pub_res)) {
            n00b_atomic_add(&topic->pub_waiters, (uint32_t)-1);
            return pub_res;
        }

        uint32_t cur = n00b_atomic_load(&topic->pub_futex);
        n00b_futex_wait(&topic->pub_futex, cur, 100000000); // 100ms
    }
}

void
n00b_conduit_publish_yield(n00b_conduit_publisher_t *pub)
{
    if (!pub || !pub->topic) {
        return;
    }

    n00b_conduit_topic_base_t *topic = pub->topic;

    if (!n00b_conduit_thread_equal(pub->thread, base_current_thread_id())) {
        return;
    }

    n00b_atomic_store(&pub->state, (int)N00B_CONDUIT_PUB_YIELDED);

    n00b_conduit_publisher_t *expected = pub;
    bool released = n00b_atomic_cas(&topic->publisher, &expected,
                                    (n00b_conduit_publisher_t *)nullptr);

    if (n00b_atomic_load(&topic->pub_waiters) > 0) {
        n00b_atomic_add(&topic->pub_futex, 1);
        n00b_futex_wake(&topic->pub_futex, true);
    }

    // This publisher was allocated in n00b_conduit_publish_try_claim and
    // has just been removed from the topic slot. Nothing else references
    // a yielded single-publisher object — waiters woken above re-claim a
    // freshly allocated publisher — so free it to close the claim/yield
    // cycle. Without this, every claim->publish->yield caller (a
    // repeating timer fire, or any per-message publish) leaks one
    // publisher per publish. Free only on a clean release (we won the
    // CAS); if the slot changed underneath us (dead-publisher recovery
    // on another thread), that path owns the object.
    if (released) {
        n00b_free(pub);
    }
}

bool
n00b_conduit_publish_is_owner(n00b_conduit_topic_base_t *topic)
{
    if (!topic) return false;

    n00b_conduit_publisher_t *pub = n00b_atomic_load(&topic->publisher);
    if (!pub) return false;

    return n00b_conduit_thread_equal(pub->thread, base_current_thread_id());
}

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_publish_topic(n00b_conduit_publisher_t *pub)
{
    if (!pub) return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    return n00b_result_ok(n00b_conduit_topic_base_t *, pub->topic);
}

void
n00b_conduit_publish_finishing(n00b_conduit_publisher_t *pub)
{
    if (!pub) return;

    if (!n00b_conduit_thread_equal(pub->thread, base_current_thread_id())) {
        return;
    }

    n00b_atomic_store(&pub->state, (int)N00B_CONDUIT_PUB_FINISHING);
}

n00b_conduit_pub_state_t
n00b_conduit_publish_state(n00b_conduit_publisher_t *pub)
{
    if (!pub) return N00B_CONDUIT_PUB_YIELDED;
    return n00b_atomic_load(&pub->state);
}

bool
n00b_conduit_publish_check_liveness(n00b_conduit_topic_base_t *topic)
{
    if (!topic) return true;

    n00b_conduit_publisher_t *pub = n00b_atomic_load(&topic->publisher);
    if (!pub) return true;

    if (publisher_is_dead(topic, pub)) {
        handle_publisher_lost(topic, pub);
        return false;
    }
    return true;
}
