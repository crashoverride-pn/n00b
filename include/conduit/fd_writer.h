/**
 * @file fd_writer.h
 * @brief FD-writer conduit filter: subscribes to a buffer topic and
 *        writes buffers to a managed file descriptor owner.
 *
 * This is the terminal sink for the conduit pipeline.  Created by
 * `n00b_init()` for stdout (fd 1) and stderr (fd 2), and available for
 * user code to wire up additional managed fd outputs.
 *
 * After each successful managed owner write, the transform framework
 * publishes the originating topic pointer (`n00b_conduit_topic_base_t *`)
 * to the upstream topic's `done_topic`.  Synchronous writers subscribe
 * one-shot to that done topic and wait on the inbox CV.
 *
 * ### Usage
 *
 * ```c
 * auto r = n00b_conduit_fd_writer_new(conduit, topic, 1);
 * // The filter runs its own thread; buffers published to `topic`
 * // are written to fd 1 (stdout) automatically.
 * ```
 */
#pragma once

#include "conduit/xform_types.h"

/**
 * @brief Internal state for the fd-writer transform.
 */
typedef struct {
    int                       fd;
    n00b_conduit_fd_owner_t  *owner;
    n00b_conduit_topic_base_t *upstream_base;
    bool                      consume;
} n00b_fd_writer_state_t;

/**
 * @brief Create an fd-writer filter that writes buffers to a managed fd.
 *
 * The filter subscribes to @p upstream and, for each
 * `n00b_buffer_t *` it receives, writes through the fd owner.
 * It never emits downstream output (pure sink).
 *
 * After each write, a completion signal is published to
 * `upstream->done_topic` so synchronous callers can unblock.
 *
 * @param c        Conduit instance.
 * @param upstream Upstream topic producing `n00b_buffer_t *` payloads.
 * @param fd       File descriptor to write to.
 * @return Result with filter pointer on success, error code on failure.
 */
extern n00b_result_t(n00b_conduit_filter_t(n00b_buffer_t *) *)
n00b_conduit_fd_writer_new(n00b_conduit_t                       *c,
                            n00b_conduit_topic_t(n00b_buffer_t *) *upstream,
                            int                                    fd) _kargs
{
    bool consume = false;
};
