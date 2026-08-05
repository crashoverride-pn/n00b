/*
 * fd_writer.c — FD-writer conduit filter implementation.
 *
 * Subscribes to a buffer topic and writes each buffer to a managed file
 * descriptor owner.  This is a terminal sink in the conduit
 * pipeline for observation/tapping — subscribers that want to see
 * what was written to a topic.
 *
 * After each managed owner write, publishes the originating topic pointer to the
 * upstream topic's done_topic so synchronous callers can unblock.
 */

#include "conduit/fd_writer.h"
#include "conduit/fd_managed.h"
#include "conduit/rw.h"
#include "conduit/topic.h"
#include "core/alloc.h"

// ============================================================================
// Transform callback
// ============================================================================

static n00b_option_t(n00b_buffer_t *)
fd_writer_transform(n00b_conduit_filter_t(n00b_buffer_t *) *xf,
                    n00b_buffer_t *input)
{
    n00b_fd_writer_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_buffer_t *, xf);

    if (!input) {
        return n00b_option_none(n00b_buffer_t *);
    }

    int64_t len  = 0;
    char   *data = n00b_buffer_to_c(input, &len);

    if (data && len > 0 && st->owner != nullptr) {
        (void)n00b_fd_owner_write(st->owner, data, (size_t)len);
    }

    if (st->consume) {
        n00b_buffer_free_with_allocator_hint(input, xf->conduit->allocator);
    }

    return n00b_option_none(n00b_buffer_t *);
}

static void
fd_writer_flush(n00b_conduit_filter_t(n00b_buffer_t *) *xf)
{
    n00b_fd_writer_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_buffer_t *, xf);

    if (st != nullptr && st->close_on_upstream_close && st->owner != nullptr) {
        n00b_conduit_fd_owner_close(st->owner);
    }
}

// ============================================================================
// Ops vtable
// ============================================================================

static n00b_string_t _kind_fd_writer = {
    .data = "fd_writer", .u8_bytes = 9, .codepoints = 9, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_filter_ops_t(n00b_buffer_t *) fd_writer_ops = {
    .transform = fd_writer_transform,
    .flush     = fd_writer_flush,
    .kind      = &_kind_fd_writer,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_conduit_filter_t(n00b_buffer_t *) *)
n00b_conduit_fd_writer_new(n00b_conduit_t                       *c,
                            n00b_conduit_topic_t(n00b_buffer_t *) *upstream,
                            base_socket_t                          fd) _kargs
{
    bool consume = false;
    bool close_on_upstream_close = false;
}
{
    auto owner_opt = n00b_conduit_fd_get_owner(c, fd);
    if (!n00b_option_is_set(owner_opt)) {
        return n00b_result_err(n00b_conduit_filter_t(n00b_buffer_t *) *,
                               N00B_CONDUIT_ERR_NOT_MANAGED);
    }

    auto r = n00b_conduit_filter_new(n00b_buffer_t *, c, upstream,
                                     &fd_writer_ops,
                                     0);

    if (n00b_result_is_ok(r)) {
        n00b_conduit_filter_t(n00b_buffer_t *) *xf = n00b_result_get(r);
        n00b_fd_writer_state_t *st = n00b_alloc_with_opts(
            n00b_fd_writer_state_t,
            &(n00b_alloc_opts_t){.allocator = c->allocator});
        if (st == nullptr) {
            n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
            return n00b_result_err(n00b_conduit_filter_t(n00b_buffer_t *) *,
                                   N00B_CONDUIT_ERR_ALLOC);
        }
        xf->cookie = st;
        st->fd            = fd;
        st->owner         = n00b_option_get(owner_opt);
        st->upstream_base = (n00b_conduit_topic_base_t *)upstream;
        st->consume       = consume;
        st->close_on_upstream_close = close_on_upstream_close;

        /* fd_writer is a terminal sink. It normally has no downstream
         * subscriber, so it must subscribe to its upstream eagerly even
         * though ordinary transforms start on their first output subscriber. */
        n00b_conduit_topic_base_t *topic =
            (n00b_conduit_topic_base_t *)xf->topic;
        if (topic != nullptr && topic->on_first_subscribe != nullptr) {
            topic->on_first_subscribe(topic, topic->on_first_subscribe_ctx);
        }
    }

    return r;
}
