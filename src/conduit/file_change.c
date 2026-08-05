/*
 * file_change.c - Filesystem change monitoring implementation for conduit
 */

#include "conduit/conduit.h"
#include "conduit/file_change.h"
#include "conduit/io.h"

#include <fcntl.h>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

// ============================================================================
// File Change Watch Creation
// ============================================================================

n00b_result_t(n00b_conduit_topic_base_t *)
n00b_conduit_file_change_topic(n00b_conduit_t *c, int fd, uint32_t events)
{
    if (!c) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }
    if (fd < 0) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_NULL_ARG);
    }

    // Allocate and initialize the watch struct.
    n00b_conduit_vnode_watch_t *watch =
        n00b_alloc_with_opts(n00b_conduit_vnode_watch_t,
            &(n00b_alloc_opts_t){.allocator = c->allocator});

    watch->fd   = fd;
    watch->ops  = events;
    watch->next = nullptr;

    // Create or retrieve the topic for this fd.
    n00b_result_t(n00b_conduit_topic_base_t *) topic_res =
        n00b_conduit_topic_get(c, N00B_CONDUIT_URI_VNODE(fd),
                                sizeof(n00b_conduit_topic_t(n00b_conduit_file_change_payload_t)));
    if (n00b_result_is_err(topic_res)) {
        return topic_res;
    }
    watch->topic = n00b_result_get(topic_res);

    // Register with I/O backend.
    if (!n00b_conduit_file_change_register(c, watch)) {
        return n00b_result_err(n00b_conduit_topic_base_t *, N00B_CONDUIT_ERR_ALLOC);
    }

    return n00b_result_ok(n00b_conduit_topic_base_t *, watch->topic);
}

void
n00b_conduit_file_change_unwatch(n00b_conduit_t *c, int fd)
{
    if (!c || fd < 0) {
        return;
    }

    n00b_result_t(n00b_conduit_topic_base_t *) topic_res =
        n00b_conduit_topic_get(c, N00B_CONDUIT_URI_VNODE(fd), 0);
    if (n00b_result_is_ok(topic_res)) {
        n00b_conduit_topic_close(n00b_result_get(topic_res));
    }
}

static int
n00b_fc_open_ro(const char *path)
{
#if defined(_WIN32)
    return _open(path, _O_RDONLY | _O_BINARY);
#else
    return open(path, O_RDONLY);
#endif
}

static void
n00b_fc_close(int fd)
{
#if defined(_WIN32)
    _close(fd);
#else
    close(fd);
#endif
}

n00b_result_t(n00b_conduit_file_change_watch_t *)
n00b_conduit_file_change_watch_path(n00b_conduit_t *c,
                                    n00b_string_t  *path,
                                    uint32_t        events)
{
    if (!c || !path) {
        return n00b_result_err(n00b_conduit_file_change_watch_t *,
                               N00B_CONDUIT_ERR_NULL_ARG);
    }

    // Open the path read-only for change notification only. We deliberately do
    // NOT route through n00b_conduit_fd_manage / activate_reads: this fd is a
    // vnode watch handle, never a managed read stream. Managed reads arm
    // EVFILT_READ (stream-readiness), which is the wrong signal for a regular
    // file -- it reports "readable to EOF" rather than "changed", and would
    // pump the file's bytes into a read topic nobody consumes. Change
    // notification is EVFILT_VNODE (NOTE_WRITE/NOTE_EXTEND), which is what
    // n00b_conduit_file_change_topic registers below.
    // n00b_string_t data is NUL-terminated UTF-8 (same contract socket.c relies
    // on for unlink/chmod paths), so it is a valid C path string as-is.
    const char *cpath = (const char *)path->data;
    if (cpath == nullptr) {
        return n00b_result_err(n00b_conduit_file_change_watch_t *,
                               N00B_CONDUIT_ERR_NULL_ARG);
    }
    int fd = n00b_fc_open_ro(cpath);
    if (fd < 0) {
        return n00b_result_err(n00b_conduit_file_change_watch_t *,
                               N00B_CONDUIT_ERR_ALLOC);
    }

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_file_change_topic(c, fd, events);
    if (n00b_result_is_err(tr)) {
        n00b_fc_close(fd);
        return n00b_result_err(n00b_conduit_file_change_watch_t *,
                               n00b_result_get_err(tr));
    }

    n00b_conduit_file_change_watch_t *w = n00b_alloc_with_opts(
        n00b_conduit_file_change_watch_t,
        &(n00b_alloc_opts_t){.allocator = c->allocator});
    w->conduit = c;
    w->topic   = n00b_result_get(tr);
    w->fd      = fd;

    return n00b_result_ok(n00b_conduit_file_change_watch_t *, w);
}

void
n00b_conduit_file_change_watch_close(n00b_conduit_file_change_watch_t *w)
{
    if (!w) {
        return;
    }
    if (w->fd >= 0) {
        n00b_conduit_file_change_unwatch(w->conduit, w->fd);
        n00b_fc_close(w->fd);
        w->fd = -1;
    }
    w->topic = nullptr;
}

// ============================================================================
// File Change Registration (with I/O backend)
// ============================================================================

bool
n00b_conduit_file_change_register(n00b_conduit_t *c,
                                   n00b_conduit_vnode_watch_t *watch)
{
    if (!c || !watch) {
        return false;
    }

    n00b_option_t(n00b_conduit_io_backend_t *) opt = n00b_conduit_default_backend(c);
    if (!n00b_option_is_set(opt)) {
        return false;
    }
    n00b_conduit_io_backend_t *io = n00b_option_get(opt);
    if (!io->ops->vnode_add) {
        return false;
    }

    return io->ops->vnode_add(io->ctx, watch);
}

void
n00b_conduit_file_change_unregister(n00b_conduit_t *c,
                                     n00b_conduit_vnode_watch_t *watch)
{
    if (!c || !watch) {
        return;
    }

    n00b_option_t(n00b_conduit_io_backend_t *) opt = n00b_conduit_default_backend(c);
    if (!n00b_option_is_set(opt)) {
        return;
    }
    n00b_conduit_io_backend_t *io = n00b_option_get(opt);
    if (!io->ops->vnode_remove) {
        return;
    }

    io->ops->vnode_remove(io->ctx, watch);
}

// ============================================================================
// File Change Firing
// ============================================================================

void
n00b_conduit_vnode_fire(n00b_conduit_vnode_watch_t *watch, uint32_t ops)
{
    if (!watch || !watch->topic) {
        return;
    }

    n00b_conduit_t *c = watch->topic->conduit;
    if (!c || n00b_conduit_is_shutdown(c)) {
        return;
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_res =
        n00b_conduit_publish_try_claim(watch->topic);
    if (n00b_result_is_err(pub_res)) {
        n00b_atomic_add(&watch->topic->epoch, 1);
        return;
    }
    n00b_conduit_publisher_t *pub = n00b_result_get(pub_res);

    n00b_conduit_file_change_msg_t *msg = n00b_alloc_with_opts(
        n00b_conduit_file_change_msg_t,
        &(n00b_alloc_opts_t){.allocator = c->allocator});

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = watch->topic;
    msg->header.generation = n00b_conduit_topic_generation(watch->topic);
    msg->header.epoch      = n00b_conduit_topic_epoch(watch->topic);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;

    msg->payload.fd     = watch->fd;
    msg->payload.events = ops;

    n00b_conduit_topic_deliver_msg(
        n00b_conduit_file_change_payload_t,
        (n00b_conduit_topic_t(n00b_conduit_file_change_payload_t) *)watch->topic,
        msg,
        ops);

    n00b_conduit_publish_yield(pub);

    // DELETE and REVOKE are terminal — the watched resource is gone.
    if (ops & (N00B_CONDUIT_VNODE_DELETE | N00B_CONDUIT_VNODE_REVOKE)) {
        n00b_conduit_topic_close(watch->topic);
    }
}
