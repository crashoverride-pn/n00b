/*
 * local_internal.h - Private local IPC backend boundary.
 *
 * This header is private to libn00b implementation files. It exposes the
 * shared local resource layout needed by backend dispatch code, but it does
 * not expose native backend handles or platform-specific types.
 */
#pragma once

#include "conduit/local.h"
#include "conduit/socket.h"
#include "core/atomic.h"
#include "core/condition.h"
#include "core/mutex.h"
#include "core/thread.h"
#include "local_xpc_native.h"

struct n00b_conduit_local_listener {
    n00b_conduit_t                  *conduit;
    n00b_allocator_t                *allocator;
    uint64_t                         local_id;
    n00b_conduit_local_backend_t     backend;
    n00b_conduit_topic_base_t       *accept_topic;
    n00b_conduit_topic_base_t       *status_topic;
    void                            *backend_listener;
    n00b_conduit_sock_accept_inbox_t *backend_accept_inbox;
    n00b_conduit_sub_handle_t        backend_accept_sub;
    n00b_thread_t                   *accept_thread;
    n00b_condition_t                 accept_cv;
    n00b_mutex_t                     publish_lock;
    _Atomic(bool)                    accept_started;
    _Atomic(bool)                    accept_running;
    _Atomic(bool)                    accept_stop;
    _Atomic(bool)                    closed;
    _Atomic(bool)                    native_released;
    _Atomic(uint64_t)                close_generation;
};

struct n00b_conduit_local_conn {
    n00b_conduit_t                  *conduit;
    n00b_allocator_t                *allocator;
    uint64_t                         local_id;
    n00b_conduit_local_backend_t     backend;
    n00b_conduit_topic_base_t       *read_topic;
    n00b_conduit_topic_base_t       *write_topic;
    n00b_conduit_topic_base_t       *status_topic;
    void                            *backend_conn;
    n00b_conduit_inbox_t(n00b_buffer_t *) *read_inbox;
    n00b_conduit_inbox_t(n00b_buffer_t *) *write_inbox;
    n00b_conduit_sock_status_inbox_t *status_inbox;
    n00b_conduit_sub_handle_t        read_sub;
    n00b_conduit_sub_handle_t        write_sub;
    n00b_conduit_sub_handle_t        status_sub;
    n00b_thread_t                   *bridge_thread;
    _Atomic(bool)                    bridge_started;
    _Atomic(bool)                    bridge_running;
    _Atomic(bool)                    bridge_stop;
    _Atomic(bool)                    closed;
    _Atomic(bool)                    native_released;
    _Atomic(uint64_t)                close_generation;
    _Atomic(uint64_t)                terminal_status_count;
};
