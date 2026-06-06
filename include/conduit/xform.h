/**
 * @file xform.h
 * @brief Parameterized pipeline transform for the conduit system.
 *
 * A transform subscribes to a typed input topic, processes each message
 * through a user-provided callback, and publishes results on a typed
 * output topic. Transforms run their own thread.
 *
 * Supports:
 * - Heterogeneous transforms: `N00B_CONDUIT_XFORM_IMPL(T_in, T_out)`
 * - Homogeneous filters: `N00B_CONDUIT_FILTER_IMPL(T)` (T_in == T_out)
 * - Dropping messages: return `n00b_option_none(T_out)` from the callback
 * - Multi-output: call `n00b_conduit_xform_emit()` N times, return none
 * - Flush on upstream close: `flush()` fires before downstream TOPIC_CLOSED
 * - Chain API: compose transforms from spec arrays
 *
 * Usage:
 * @code
 *     N00B_CONDUIT_XFORM_IMPL(input_t, output_t);
 *     auto r = n00b_conduit_xform_new(input_t, output_t,
 *         conduit, upstream_topic, &my_ops, sizeof(my_state_t));
 *     auto xf = n00b_result_get(r);
 * @endcode
 */
#pragma once

#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "core/thread.h"
#include "core/atomic.h"
#include "core/alloc.h"
#include "core/gc.h"
#include "adt/option.h"
#include "adt/result.h"

// ============================================================================
// Parameterized transform types and IMPL macro
// ============================================================================

#define n00b_conduit_xform_t(T_in, T_out) \
    struct typeid("n00b_conduit_xform", T_in, T_out)
#define n00b_conduit_xform_ops_t(T_in, T_out) \
    struct typeid("n00b_conduit_xform_ops", T_in, T_out)

#define _N00B_XFORM_FN(fn, T_in, T_out) \
    typeid("n00b_conduit_xform_" #fn, T_in, T_out)

/**
 * @brief Instantiate a fully parameterized transform for T_in -> T_out.
 *
 * Generates the ops vtable, xform struct, thread loop, and creation function.
 * The `_new` function returns `n00b_result_t` for proper error propagation.
 *
 * @pre N00B_CONDUIT_TOPIC_IMPL(T_in) and N00B_CONDUIT_TOPIC_IMPL(T_out)
 *      must have been called. n00b_option_t(T_out) must be usable.
 */
#define N00B_CONDUIT_XFORM_IMPL(T_in, T_out)                                  \
    /* Forward declarations at file scope */                                   \
    n00b_conduit_xform_t(T_in, T_out);                                         \
    n00b_conduit_xform_ops_t(T_in, T_out);                                     \
                                                                               \
    n00b_conduit_xform_ops_t(T_in, T_out) {                                   \
        /** Transform one input into an optional output.                      \
         *  Return n00b_option_set(T_out, val) to emit, or                    \
         *  n00b_option_none(T_out) to drop.                                  \
         *  For multi-output, call n00b_conduit_xform_emit() N times          \
         *  and return n00b_option_none(T_out). */                            \
        n00b_option_t(T_out)                                                   \
            (*transform)(n00b_conduit_xform_t(T_in, T_out) *xform,            \
                         T_in input);                                          \
        void (*flush)(n00b_conduit_xform_t(T_in, T_out) *xform);              \
        void (*teardown)(n00b_conduit_xform_t(T_in, T_out) *xform);           \
        /** Initialize transform state from a chain spec.                     \
         *  Called by the chain API after _new(). */                           \
        void (*init_from_spec)(n00b_conduit_xform_t(T_in, T_out) *xform,      \
                               const void *spec);                              \
        n00b_string_t *kind;                                                    \
    };                                                                         \
                                                                               \
    n00b_conduit_xform_t(T_in, T_out) {                                        \
        n00b_conduit_t                              *conduit;                  \
        n00b_conduit_topic_t(T_out)                 *topic;                    \
        n00b_conduit_topic_t(T_in)                  *upstream;                 \
        n00b_conduit_sub_handle_t                    upstream_sub;             \
        const n00b_conduit_xform_ops_t(T_in, T_out) *ops;                     \
        void                                        *cookie;                   \
        size_t                                       cookie_size;              \
        n00b_conduit_uri_t                           uri;                      \
        n00b_thread_t                               *thread;                   \
        _Atomic(bool)                                running;                  \
        _Atomic(bool)                                stop_requested;           \
        n00b_conduit_inbox_t(T_in)                  *inbox;                    \
        n00b_condition_t                            *inbox_cv;                 \
        n00b_conduit_backpressure_t                  backpressure;             \
        uint32_t                                     inbox_limit;              \
        bool                                         passthrough_sys;          \
    };                                                                         \
                                                                               \
    /* Process one typed input message; returns true if a message was found. */ \
    static inline bool                                                         \
    _N00B_XFORM_FN(process_one, T_in, T_out)(                                 \
        n00b_conduit_xform_t(T_in, T_out) *xf)                                \
    {                                                                          \
        n00b_conduit_message_t(T_in) *in_msg =                                 \
            n00b_conduit_inbox_pop_msg(T_in, xf->inbox);                       \
        if (!in_msg) return false;                                             \
        n00b_option_t(T_out) out =                                             \
            xf->ops->transform(xf, in_msg->payload);                          \
        if (n00b_option_is_set(out)) {                                         \
            n00b_conduit_message_t(T_out) *om =                                \
                n00b_alloc_with_opts(                                          \
                    n00b_conduit_message_t(T_out),                             \
                    &(n00b_alloc_opts_t){.allocator = xf->conduit->allocator});\
            om->header.type       = N00B_CONDUIT_MSG_USER;                     \
            om->header.topic      =                                            \
                (n00b_conduit_topic_base_t *)xf->topic;                        \
            om->header.generation =                                            \
                n00b_atomic_load(&xf->topic->generation);                     \
            om->header.epoch      =                                            \
                n00b_atomic_load(&xf->topic->epoch);                          \
            om->payload = n00b_option_get(out);                                \
            n00b_conduit_topic_deliver_msg(T_out,                              \
                xf->topic, om, N00B_CONDUIT_OP_ALL);                           \
        }                                                                      \
        /* Signal upstream's done_topic so sync writers unblock. */            \
        {                                                                      \
            n00b_conduit_topic_base_t *_up_base =                              \
                (n00b_conduit_topic_base_t *)xf->upstream;                     \
            n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *_done_tp =      \
                (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)          \
                    n00b_atomic_load(&_up_base->done_topic);                   \
            if (_done_tp) {                                                    \
                n00b_conduit_message_t(n00b_conduit_topic_base_t *) *_dm =     \
                    n00b_alloc_with_opts(                                      \
                        n00b_conduit_message_t(n00b_conduit_topic_base_t *),   \
                        &(n00b_alloc_opts_t){.allocator = xf->conduit->allocator});\
                _dm->header.type  = N00B_CONDUIT_MSG_USER;                     \
                _dm->header.topic =                                            \
                    (n00b_conduit_topic_base_t *)_done_tp;                     \
                _dm->payload      = _up_base;                                  \
                n00b_conduit_topic_deliver_msg(                                \
                    n00b_conduit_topic_base_t *,                               \
                    _done_tp, _dm, N00B_CONDUIT_OP_ALL);                       \
            }                                                                  \
        }                                                                      \
        return true;                                                           \
    }                                                                          \
                                                                               \
    /* Thread loop */                                                          \
    static void *                                                              \
    _N00B_XFORM_FN(loop, T_in, T_out)(void *raw)                              \
    {                                                                          \
        n00b_conduit_xform_t(T_in, T_out) *xf = raw;                          \
        n00b_conduit_publish_claim(                                            \
            (n00b_conduit_topic_base_t *)xf->topic);                           \
        n00b_atomic_store(&xf->running, true);                                \
                                                                               \
        while (!n00b_atomic_load(&xf->stop_requested) &&                      \
               !n00b_conduit_is_shutdown(xf->conduit)) {                      \
            /* 1. Drain user messages first */                                 \
            if (_N00B_XFORM_FN(process_one, T_in, T_out)(xf))                 \
                continue;                                                      \
            /* 2. Check system queue only when user queue is empty */           \
            n00b_conduit_sys_msg_t *sys =                                      \
                n00b_conduit_inbox_pop_sys(xf->inbox);                         \
            if (sys) {                                                         \
                n00b_conduit_msg_type_t mt = sys->header.type;                 \
                if (mt == N00B_CONDUIT_MSG_TOPIC_CLOSED ||                     \
                    mt == N00B_CONDUIT_MSG_PUBLISHER_LOST) {                   \
                    /* Drain any remaining user messages */                     \
                    while (_N00B_XFORM_FN(process_one, T_in, T_out)(xf))      \
                        ;                                                      \
                    if (xf->ops->flush) xf->ops->flush(xf);                   \
                    /* Close our output topic — fires done_topic and           \
                     * notifies downstream subscribers, propagating            \
                     * close through chained transforms. */                    \
                    n00b_conduit_topic_close(                                  \
                        (n00b_conduit_topic_base_t *)xf->topic);              \
                    break;                                                     \
                }                                                              \
                if (xf->passthrough_sys)                                       \
                    n00b_conduit_topic_deliver_sys(T_out,                      \
                        xf->topic, mt, N00B_CONDUIT_OP_ALL);                   \
                continue;                                                      \
            }                                                                  \
            /* 3. Nothing: arm the wait while holding the inbox CV lock. */     \
            n00b_condition_lock(&xf->inbox->cv);                                \
            if (!n00b_atomic_load(&xf->stop_requested) &&                       \
                !n00b_conduit_is_shutdown(xf->conduit) &&                       \
                !n00b_conduit_inbox_has_msg(T_in, xf->inbox) &&                 \
                !n00b_conduit_inbox_has_sys(xf->inbox)) {                       \
                n00b_condition_wait(&xf->inbox->cv,                             \
                                    .timeout_ms = 500,                          \
                                    .auto_unlock = true);                       \
            }                                                                  \
            else {                                                              \
                n00b_condition_unlock(&xf->inbox->cv);                          \
            }                                                                  \
        }                                                                      \
        n00b_atomic_store(&xf->running, false);                               \
        if (xf->ops->teardown) xf->ops->teardown(xf);                         \
        if (xf->cookie_size > 0)                                               \
            _n00b_gc_unregister_root(&xf->cookie);                             \
        n00b_conduit_sub_cancel(xf->upstream_sub);                             \
        n00b_conduit_publish_yield(                                            \
            n00b_atomic_load(&xf->topic->publisher));                         \
        return nullptr;                                                        \
    }                                                                          \
                                                                               \
    /* Get the typed output topic. */                                           \
    static inline n00b_conduit_topic_t(T_out) *                                \
    _N00B_XFORM_FN(topic, T_in, T_out)(                                       \
        n00b_conduit_xform_t(T_in, T_out) *xf)                                \
    { return xf->topic; }                                                      \
                                                                               \
    /* Get the cookie pointer. */                                               \
    static inline void *                                                       \
    _N00B_XFORM_FN(cookie, T_in, T_out)(                                      \
        n00b_conduit_xform_t(T_in, T_out) *xf)                                \
    { return xf->cookie; }                                                     \
                                                                               \
    /** Create and start a transform.                                          \
     *  Returns n00b_result_t with the xform pointer on success,               \
     *  or an error code on failure. */                                        \
    static inline n00b_result_t(n00b_conduit_xform_t(T_in, T_out) *)          \
    _N00B_XFORM_FN(new, T_in, T_out)(                                         \
        n00b_conduit_t                              *c,                        \
        n00b_conduit_topic_t(T_in)                  *upstream,                 \
        const n00b_conduit_xform_ops_t(T_in, T_out) *ops,                     \
        size_t                                       cookie_size)               \
    {                                                                          \
        if (!c || !upstream || !ops || !ops->transform)                        \
            return n00b_result_err(                                            \
                n00b_conduit_xform_t(T_in, T_out) *,                           \
                N00B_CONDUIT_ERR_NULL_ARG);                                    \
        /* Allocate xf from the conduit's pool (hidden from GC) so the     \
         * worker thread's parameter pointer stays valid across collections. \
         * The default arena would relocate xf and the worker's              \
         * function-arg slot — held only in stack at worst — could miss      \
         * forwarding, leaving a stale heap pointer. */                       \
        n00b_conduit_xform_t(T_in, T_out) *xf =                               \
            n00b_alloc_with_opts(n00b_conduit_xform_t(T_in, T_out),           \
                &(n00b_alloc_opts_t){.allocator = (c)->allocator});           \
        if (!xf)                                                               \
            return n00b_result_err(                                            \
                n00b_conduit_xform_t(T_in, T_out) *,                           \
                N00B_CONDUIT_ERR_ALLOC);                                       \
        xf->conduit     = c;                                                   \
        xf->upstream    = upstream;                                            \
        xf->ops         = ops;                                                 \
        xf->cookie_size = cookie_size;                                         \
        xf->passthrough_sys = true;                                            \
        if (cookie_size > 0) {                                                 \
            xf->cookie = n00b_alloc_array(uint8_t, cookie_size);               \
            _n00b_gc_register_root(&xf->cookie, 1);                            \
        }                                                                      \
        else {                                                                 \
            xf->cookie = nullptr;                                              \
        }                                                                      \
        uint64_t id = n00b_atomic_add(&c->next_xform_id, 1);                  \
        xf->uri = N00B_CONDUIT_URI_XFORM(id);                                 \
        /* Create output topic */                                              \
        n00b_result_t(n00b_conduit_topic_base_t *) tr =                                       \
            n00b_conduit_topic_get(                                            \
                c, xf->uri,                                                    \
                sizeof(n00b_conduit_topic_t(T_out)));                          \
        if (n00b_result_is_err(tr)) {                                          \
            if (xf->cookie_size > 0)                                           \
                _n00b_gc_unregister_root(&xf->cookie);                         \
            return n00b_result_err(                                            \
                n00b_conduit_xform_t(T_in, T_out) *,                           \
                n00b_result_get_err(tr));                                      \
        }                                                                      \
        xf->topic =                                                            \
            (n00b_conduit_topic_t(T_out) *)                                    \
                n00b_result_get(tr);                                 \
        /* Init output topic typed fields so downstream can subscribe. */      \
        xf->topic->subscriptions =                                             \
            n00b_list_new(n00b_conduit_subscription_t(T_out) *, .allocator = c->allocator); \
        xf->topic->inbox = nullptr;                                            \
        /* Create input inbox */                                               \
        xf->inbox = n00b_alloc_with_opts(n00b_conduit_inbox_t(T_in),           \
            &(n00b_alloc_opts_t){.allocator = (c)->allocator});                \
        n00b_conduit_inbox_init(T_in, xf->inbox, c,                           \
            xf->backpressure, xf->inbox_limit);                                \
        xf->inbox_cv = &xf->inbox->cv;                                        \
        /* Subscribe to upstream */                                            \
        xf->upstream_sub =                                                     \
            n00b_conduit_subscribe(T_in, upstream, xf->inbox,                  \
                .operations = N00B_CONDUIT_OP_ALL);                            \
        n00b_atomic_store(&xf->running, false);                               \
        n00b_atomic_store(&xf->stop_requested, false);                        \
        auto _spawn_r = n00b_thread_spawn(                                      \
            _N00B_XFORM_FN(loop, T_in, T_out), xf);                           \
        if (n00b_result_is_err(_spawn_r)) {                                    \
            if (xf->cookie_size > 0)                                           \
                _n00b_gc_unregister_root(&xf->cookie);                         \
            return n00b_result_err(                                            \
                n00b_conduit_xform_t(T_in, T_out) *,                           \
                N00B_CONDUIT_ERR_ALLOC);                                       \
        }                                                                      \
        xf->thread = n00b_result_get(_spawn_r);                               \
        return n00b_result_ok(                                                 \
            n00b_conduit_xform_t(T_in, T_out) *, xf);                         \
    }

// ============================================================================
// Typed operation macros
// ============================================================================

#define n00b_conduit_xform_new(T_in, T_out, c, upstream, ops, cookie_size) \
    _N00B_XFORM_FN(new, T_in, T_out)((c), (upstream), (ops), (cookie_size))

#define n00b_conduit_xform_topic(T_in, T_out, xf) \
    _N00B_XFORM_FN(topic, T_in, T_out)(xf)

#define n00b_conduit_xform_cookie(T_in, T_out, xf) \
    _N00B_XFORM_FN(cookie, T_in, T_out)(xf)

// ============================================================================
// Multi-output emit helper
// ============================================================================

/**
 * @brief Emit one output message from a multi-output transform.
 *
 * For transforms that produce multiple outputs per input, call this
 * for each output value, then return `n00b_option_none(T_out)` from
 * the transform callback.
 *
 * @param T_in   Input payload type.
 * @param T_out  Output payload type.
 * @param xf     Transform pointer.
 * @param value  Output payload value.
 */
#define n00b_conduit_xform_emit(T_in, T_out, xf, value)                       \
    do {                                                                       \
        n00b_conduit_message_t(T_out) *_em =                                   \
            n00b_alloc_with_opts(                                              \
                n00b_conduit_message_t(T_out),                                 \
                &(n00b_alloc_opts_t){.allocator = (xf)->conduit->allocator});  \
        _em->header.type       = N00B_CONDUIT_MSG_USER;                        \
        _em->header.topic      =                                               \
            (n00b_conduit_topic_base_t *)(xf)->topic;                          \
        _em->header.generation =                                               \
            n00b_atomic_load(&(xf)->topic->generation);                       \
        _em->header.epoch      =                                               \
            n00b_atomic_load(&(xf)->topic->epoch);                            \
        _em->payload           = (value);                                      \
        n00b_conduit_topic_deliver_msg(T_out, (xf)->topic, _em,               \
            N00B_CONDUIT_OP_ALL);                                              \
    } while (0)

/**
 * @brief Homogeneous filter emit helper (T_in == T_out).
 */
#define n00b_conduit_filter_emit(T, xf, value) \
    n00b_conduit_xform_emit(T, T, xf, value)

// ============================================================================
// Xform base for lifecycle ops
// ============================================================================

/**
 * @brief Non-parameterized base struct for transform lifecycle operations.
 *
 * Field layout matches the parameterized struct up through `inbox_cv`,
 * allowing safe casting for stop/join/destroy.
 */
typedef struct n00b_conduit_xform_base {
    n00b_conduit_t            *conduit;
    n00b_conduit_topic_base_t *topic;
    n00b_conduit_topic_base_t *upstream;
    n00b_conduit_sub_handle_t  upstream_sub;
    const void                *ops;
    void                      *cookie;
    size_t                     cookie_size;
    n00b_conduit_uri_t         uri;
    n00b_thread_t             *thread;
    _Atomic(bool)              running;
    _Atomic(bool)              stop_requested;
    void                      *inbox;      /* opaque inbox ptr */
    n00b_condition_t          *inbox_cv;
} n00b_conduit_xform_base_t;

extern void n00b_conduit_xform_stop(n00b_conduit_xform_base_t *xf);
extern void n00b_conduit_xform_join(n00b_conduit_xform_base_t *xf);
extern void n00b_conduit_xform_destroy(n00b_conduit_xform_base_t *xf);

// ============================================================================
// Chain/pipeline API
// ============================================================================

/**
 * @brief Base struct for transform specifications in a chain.
 *
 * Each concrete transform provides a typed `create` function that
 * calls its own `_new()` with the right types and optionally
 * `init_from_spec` for configuration.
 */
typedef struct n00b_conduit_xform_spec_base {
    n00b_conduit_xform_base_t *(*create)(
        n00b_conduit_t            *c,
        n00b_conduit_topic_base_t *upstream,
        const void                *spec);
    size_t cookie_size;
} n00b_conduit_xform_spec_base_t;

/**
 * @brief Build a transform chain from an array of specs.
 *
 * Iterates specs, calling `spec->create(c, upstream, spec)` for each.
 * Each transform's output topic feeds as the next upstream.
 *
 * @param c       Conduit instance.
 * @param source  Source topic (first transform subscribes to this).
 * @param specs   Array of spec pointers.
 * @param count   Number of specs.
 * @return        Output topic of the final transform, or nullptr on error.
 */
extern n00b_conduit_topic_base_t *
n00b_conduit_chain_from_specs(n00b_conduit_t                     *c,
                              n00b_conduit_topic_base_t          *source,
                              const n00b_conduit_xform_spec_base_t **specs,
                              size_t                              count);

/**
 * @brief Build a transform chain from inline spec pointers.
 *
 * Usage:
 * @code
 *     auto out = n00b_conduit_chain(c, source,
 *         &linebuf_spec, &ansi_strip_spec);
 * @endcode
 */
#define n00b_conduit_chain(c, source, ...)                                     \
    ({                                                                         \
        const n00b_conduit_xform_spec_base_t *_specs[] =                       \
            { __VA_ARGS__ };                                                   \
        n00b_conduit_chain_from_specs((c), (source), _specs,                   \
            sizeof(_specs) / sizeof(_specs[0]));                               \
    })

// ============================================================================
// Homogeneous filter shorthand (T_in == T_out)
// ============================================================================

#define n00b_conduit_filter_t(T)         n00b_conduit_xform_t(T, T)
#define n00b_conduit_filter_ops_t(T)     n00b_conduit_xform_ops_t(T, T)
#define N00B_CONDUIT_FILTER_IMPL(T)      N00B_CONDUIT_XFORM_IMPL(T, T)
#define n00b_conduit_filter_new(T, c, upstream, ops, cookie_size) \
    n00b_conduit_xform_new(T, T, c, upstream, ops, cookie_size)
