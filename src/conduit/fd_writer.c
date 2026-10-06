/*
 * fd_writer.c — FD-writer conduit filter implementation.
 *
 * Subscribes to a buffer topic and writes each buffer to a managed file
 * descriptor owner.  This is a terminal sink in the conduit
 * pipeline for observation/tapping — subscribers that want to see
 * what was written to a topic.
 *
 * The transform framework signals the upstream topic's done_topic after each
 * buffer this sink handles, so synchronous callers can unblock.
 */

#include "conduit/fd_writer.h"
#include "conduit/fd_managed.h"
#include "conduit/rw.h"
#include "conduit/topic.h"
#include "core/alloc.h"
#include "core/syscall.h" // n00b_raw_write_all -- last-resort fd write
#include <stdatomic.h>

// ============================================================================
// Transform callback
// ============================================================================

#ifdef N00B_DEBUG
static _Atomic(bool) fd_writer_fail_next = false;

void
n00b_conduit_fd_writer_force_next_failure(void)
{
    atomic_store_explicit(&fd_writer_fail_next, true, memory_order_relaxed);
}
#endif

// n00b#490 (second site): the managed write can fail after the topic write
// has already reported success.
//
// print.c's fallback only sees what `n00b_write` returns, and that is Ok as
// soon as the message is published and delivered here -- the actual kernel
// write happens afterwards, inside this sink. So a failure here is invisible
// upstream, and discarding it (as `(void)n00b_fd_owner_write(...)` did) drops
// the line with no error, no partial output, and no trace. That is the same
// defect #491 fixed one layer up, and it is why the drop survived #491.
//
// n00b_fd_owner_write_attempt can report an error *after* bytes have been
// accepted (notably its ~5s completion wait, 500 x 10ms, expiring with the
// entry still queued), so take the attempt variant rather than
// n00b_fd_owner_write: it preserves bytes_written, and resuming from that
// offset is what keeps the fallback from duplicating an already-written
// prefix.
//
// Only fds 1 and 2 fall back. For them an out-of-order line is plainly better
// than a lost one, and they are the only descriptors n00b_raw_write_all can
// resolve on Windows anyway. For any other sink a direct write is the wrong
// repair: those carry protocol streams where injecting bytes outside the
// managed queue's ordering could corrupt the peer's view rather than inform
// anyone.
static void
fd_writer_deliver(n00b_fd_writer_state_t *st, const char *data, size_t len)
{
    size_t written = 0;
    bool   failed  = true;
    bool   forced  = false;

#ifdef N00B_DEBUG
    // Only SETS the failure state; the recovery below is the real one, so a
    // test exercises the shipped path rather than a stand-in for it.
    forced = atomic_exchange_explicit(&fd_writer_fail_next, false,
                                      memory_order_relaxed);
#endif

    if (!forced) {
        auto attempt_r = n00b_fd_owner_write_attempt(st->owner, data, len);
        if (n00b_result_is_ok(attempt_r)) {
            n00b_fd_owner_write_attempt_t a = n00b_result_get(attempt_r);
            written                         = a.bytes_written;
            failed                          = a.error;
        }
    }

    if (!failed || written >= len) {
        return;
    }

    int fd = (int)st->fd;
    if (fd != 1 && fd != 2) {
        return;
    }

    n00b_raw_write_all(fd, data + written, (unsigned long)(len - written));
}

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
        fd_writer_deliver(st, data, (size_t)len);
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
