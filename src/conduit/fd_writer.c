/*
 * fd_writer.c — FD-writer conduit filter implementation.
 *
 * Subscribes to a buffer topic and writes each buffer to a raw file
 * descriptor via write(2).  This is a terminal sink in the conduit
 * pipeline for observation/tapping — subscribers that want to see
 * what was written to a topic.
 *
 * After each write(), publishes the originating topic pointer to the
 * upstream topic's done_topic so synchronous callers can unblock.
 */

#include "conduit/fd_writer.h"
#include "conduit/rw.h"
#include "conduit/topic.h"
#include "core/alloc.h"

#ifdef _WIN32
#include <io.h>
#define posix_write _write
#else
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#define posix_write write
#endif

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

    if (data && len > 0) {
        const char *p   = data;
        size_t      rem = (size_t)len;

        while (rem > 0) {
            ssize_t n = posix_write(st->fd, p, rem);
            if (n < 0) {
#ifndef _WIN32
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd = { .fd = st->fd, .events = POLLOUT };
                    poll(&pfd, 1, 1000);
                    continue;
                }
                if (errno == EINTR) {
                    continue;
                }
#endif
                break;
            }
            p   += n;
            rem -= (size_t)n;
        }
    }

    if (st->consume) {
        n00b_free(input);
    }

    return n00b_option_none(n00b_buffer_t *);
}

// ============================================================================
// Ops vtable
// ============================================================================

static n00b_string_t _kind_fd_writer = {
    .data = "fd_writer", .u8_bytes = 9, .codepoints = 9, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(n00b_buffer_t *) fd_writer_ops = {
    .transform = fd_writer_transform,
    .kind      = &_kind_fd_writer,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_conduit_filter_t(n00b_buffer_t *) *)
n00b_conduit_fd_writer_new(n00b_conduit_t                       *c,
                            n00b_conduit_topic_t(n00b_buffer_t *) *upstream,
                            int                                    fd) _kargs
{
    bool consume = false;
}
{
    auto r = n00b_conduit_filter_new(n00b_buffer_t *, c, upstream,
                                     &fd_writer_ops,
                                     sizeof(n00b_fd_writer_state_t));

    if (n00b_result_is_ok(r)) {
        n00b_conduit_filter_t(n00b_buffer_t *) *xf = n00b_result_get(r);
        n00b_fd_writer_state_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_buffer_t *, xf);
        st->fd            = fd;
        st->upstream_base = (n00b_conduit_topic_base_t *)upstream;
        st->consume       = consume;
    }

    return r;
}
