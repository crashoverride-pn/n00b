/*
 * timer.c - Timer implementation for conduit
 */

#include "conduit/conduit.h"
#include "conduit/timer.h"
#include "conduit/io.h"

// ============================================================================
// Timer Creation
// ============================================================================

static n00b_conduit_timer_t *
timer_alloc(n00b_conduit_t *c, uint32_t interval_ms, bool repeating)
{
    n00b_conduit_timer_t *timer = n00b_alloc_with_opts(n00b_conduit_timer_t,
                                      &(n00b_alloc_opts_t){.allocator = c->allocator});

    timer->id          = n00b_atomic_add(&c->next_timer_id, 1);
    timer->interval_ms = interval_ms;
    n00b_atomic_store(&timer->fire_count, (uint64_t)0);
    timer->repeating   = repeating;
    timer->cancelled   = false;
    timer->next        = nullptr;

    /* Create + fully initialize the topic for this timer. We have to
     * go through n00b_conduit_topic_init (the typed init macro)
     * rather than just n00b_conduit_topic_get, because topic_get only
     * sets up the base struct — it explicitly leaves
     * `topic->subscriptions` uninitialized for the caller (see the
     * comment block in conduit.c above n00b_conduit_topic_get).
     * Without the typed init, topic->subscriptions.data is null and
     * the first subscribe push / first deliver walk dereferences
     * garbage (crashes EXC_BAD_ACCESS in
     * _N00B_TOPIC_FN(deliver, n00b_conduit_timer_payload_t) under
     * load — observed in wax raw-gateway crash report
     * 2026-05-28-162937). */
    n00b_conduit_topic_t(n00b_conduit_timer_payload_t) *typed_topic =
        n00b_conduit_topic_init(n00b_conduit_timer_payload_t, c,
                                N00B_CONDUIT_URI_TIMER(timer->id));
    if (typed_topic == nullptr) {
        n00b_free(timer);
        return nullptr;
    }
    timer->topic = (n00b_conduit_topic_base_t *)typed_topic;
    n00b_atomic_store(&timer->topic->timer_owner, timer);

    return timer;
}

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_timer_once(n00b_conduit_t *c, uint32_t delay_ms)
{
    if (!c) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (delay_ms == 0) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_conduit_timer_t *timer = timer_alloc(c, delay_ms, false);
    if (!timer) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    if (!n00b_conduit_timer_register(c, timer)) {
        n00b_atomic_store(&timer->topic->timer_owner, (void *)nullptr);
        n00b_conduit_topic_close(timer->topic);
        n00b_free(timer);
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    return n00b_result_ok(n00b_conduit_topic_base_t *, timer->topic);
}

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_timer_repeat(n00b_conduit_t *c, uint32_t interval_ms)
{
    if (!c) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (interval_ms == 0) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    n00b_conduit_timer_t *timer = timer_alloc(c, interval_ms, true);
    if (!timer) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    if (!n00b_conduit_timer_register(c, timer)) {
        n00b_atomic_store(&timer->topic->timer_owner, (void *)nullptr);
        n00b_conduit_topic_close(timer->topic);
        n00b_free(timer);
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    return n00b_result_ok(n00b_conduit_topic_base_t *, timer->topic);
}

void
n00b_conduit_timer_cancel(n00b_conduit_topic_base_t *timer_topic)
{
    if (!timer_topic || !n00b_conduit_topic_is_timer(timer_topic)) {
        return;
    }

    n00b_conduit_timer_t *timer =
        n00b_atomic_read_then_set(&timer_topic->timer_owner, (void *)nullptr);
    if (timer != nullptr) {
        timer->cancelled = true;
        n00b_conduit_timer_unregister(timer_topic->conduit, timer);
        n00b_free(timer);
    }

    n00b_conduit_topic_close(timer_topic);
}

// ============================================================================
// Timer Registration (with I/O backend)
// ============================================================================

bool
n00b_conduit_timer_register(n00b_conduit_t *c, n00b_conduit_timer_t *timer)
{
    if (!c || !timer) {
        return false;
    }

    n00b_option_t(n00b_conduit_io_backend_t *) opt = n00b_conduit_default_backend(c);
    if (!n00b_option_is_set(opt)) {
        return false;
    }
    n00b_conduit_io_backend_t *io = n00b_option_get(opt);
    if (!io->ops->timer_add) {
        return false;
    }

    return io->ops->timer_add(io->ctx, timer);
}

void
n00b_conduit_timer_unregister(n00b_conduit_t *c, n00b_conduit_timer_t *timer)
{
    if (!c || !timer) {
        return;
    }

    n00b_option_t(n00b_conduit_io_backend_t *) opt = n00b_conduit_default_backend(c);
    if (!n00b_option_is_set(opt)) {
        return;
    }
    n00b_conduit_io_backend_t *io = n00b_option_get(opt);
    if (!io->ops->timer_remove) {
        return;
    }

    io->ops->timer_remove(io->ctx, timer);
}

// ============================================================================
// Timer Firing
// ============================================================================

void
n00b_conduit_timer_fire(n00b_conduit_timer_t *timer)
{
    if (!timer || !timer->topic || timer->cancelled) {
        return;
    }

    n00b_conduit_t *c = timer->topic->conduit;
    if (!c || n00b_conduit_is_shutdown(c)) {
        return;
    }

    n00b_atomic_add(&timer->fire_count, 1);

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(timer->topic);
    if (n00b_result_is_err(pub_res)) {
        // Bump epoch so subscribers can detect the missed event.
        n00b_atomic_add(&timer->topic->epoch, 1);
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_timer_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_timer_msg_t,
        &(n00b_alloc_opts_t){.allocator = c->allocator});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = timer->topic;
    msg->header.generation = n00b_conduit_topic_generation(timer->topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(timer->topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.timer_id    = timer->id;
    msg->payload.fire_count  = n00b_atomic_load(&timer->fire_count);
    msg->payload.interval_ms = timer->interval_ms;
    msg->payload.repeating   = timer->repeating;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_timer_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_timer_payload_t) *)timer->topic,
        msg,
        N00B_CONDUIT_TIMER_FIRED);

    n00b_conduit_publish_yield(pub);

    // Close topic if one-shot timer
    if (!timer->repeating) {
        timer->cancelled = true;
        n00b_conduit_topic_close(timer->topic);
    }
}
