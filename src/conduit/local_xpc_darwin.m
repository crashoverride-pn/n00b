/*
 * local_xpc_darwin.m - macOS XPC native backend.
 *
 * This file is compiled only on Darwin through the system Objective-C
 * compiler. It deliberately does not include n00b headers: public n00b
 * headers use ncc extensions that the Objective-C frontend must not parse.
 * The n00b-facing local backend dispatch remains in local.c and crosses this
 * native boundary only through private, flat C functions.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <os/lock.h>
#include <xpc/xpc.h>

#include "local_xpc_native.h"

#if !__has_feature(objc_arc)
#error "local_xpc_darwin.m must be compiled with Objective-C ARC."
#endif

/*
 * XPC / dispatch / n00b ownership contract for the future behavioral backend:
 *
 * - This ARC-compiled file treats XPC and dispatch objects as Objective-C
 *   managed OS objects. It must not call xpc_retain, xpc_release,
 *   dispatch_retain, or dispatch_release while ARC is enabled.
 * - If this file is ever compiled without ARC, or with OS_OBJECT_USE_OBJC=0,
 *   the backend must be amended before behavior lands so every asynchronous
 *   block capture manually retains native objects before capture and releases
 *   them after the block finishes.
 * - XPC event-handler arguments are borrowed for the handler invocation. A
 *   handler must not store a raw event object or an interior pointer obtained
 *   from an XPC getter unless the owning object is held strongly for the whole
 *   copy. Data, strings, UUIDs, and peer facts must be copied into n00b-owned
 *   storage before they are published or stored in local connection state.
 * - Outbound writes must copy n00b buffer bytes into XPC-owned payloads using
 *   copying APIs such as xpc_dictionary_set_data or xpc_data_create. The first
 *   XPC implementation must not use xpc_data_create_with_dispatch_data for
 *   n00b buffers.
 * - Native callbacks run on XPC/dispatch-managed threads. They may copy
 *   primitive bytes or facts and enqueue work into the approved n00b conduit
 *   service path. They must not publish complex n00b graph state directly
 *   unless the callback has entered the approved n00b thread discipline.
 * - Native callbacks must not publish after local close. The only exception is
 *   the intended terminal-status path, which is guarded to publish at most one
 *   terminal event and then close topics through the common local close path.
 * - Close owns cycle breaking: cancel native connections, clear handlers or
 *   contexts where needed, and end the n00b-owned backend state exactly once.
 * - Native finalizers may observe copied primitive state, but must not
 *   dereference or mutate the XPC connection object being finalized.
 */

typedef enum {
    LOCAL_XPC_OWNER_LISTENER = 1,
    LOCAL_XPC_OWNER_CONN,
} local_xpc_owner_kind_t;

@interface N00BLocalXPCState : NSObject {
@public
    local_xpc_owner_kind_t kind;
    void                  *n00b_owner_token;
    NSString              *name;
    xpc_connection_t       connection;
    xpc_endpoint_t         listener_endpoint;
    dispatch_queue_t       target_queue;
    NSMutableArray         *pending_accepts;
    os_unfair_lock          pending_lock;

    _Atomic bool handler_installed;
    _Atomic bool activated;
    _Atomic bool local_closed;
    _Atomic bool native_cancelled;
    _Atomic bool terminal_status_published;
}
@end

@implementation N00BLocalXPCState
@end

static bool local_xpc_callback_may_publish(N00BLocalXPCState *state,
                                           bool terminal_status);
static void local_xpc_mark_closed(N00BLocalXPCState *state);

static os_unfair_lock local_xpc_registry_lock = OS_UNFAIR_LOCK_INIT;

static NSMutableDictionary *
local_xpc_registry(void)
{
    static NSMutableDictionary *registry = nil;
    static dispatch_once_t      once;

    dispatch_once(&once, ^{
        registry = [[NSMutableDictionary alloc] init];
    });

    return registry;
}

static NSString *
local_xpc_name_from_bytes(const void *name_data, uint64_t name_len)
{
    if (name_data == nullptr || name_len == 0) {
        return nil;
    }

    return [[NSString alloc] initWithBytes:name_data
                                    length:(NSUInteger)name_len
                                  encoding:NSUTF8StringEncoding];
}

static void
local_xpc_state_init(N00BLocalXPCState *state, local_xpc_owner_kind_t owner_kind,
                     void *owner_token)
{
    state->kind             = owner_kind;
    state->n00b_owner_token = owner_token;
    atomic_store_explicit(&state->handler_installed, false, memory_order_release);
    atomic_store_explicit(&state->activated, false, memory_order_release);
    atomic_store_explicit(&state->local_closed, false, memory_order_release);
    atomic_store_explicit(&state->native_cancelled, false, memory_order_release);
    atomic_store_explicit(&state->terminal_status_published, false,
                          memory_order_release);
}

static void
local_xpc_accept_peer(N00BLocalXPCState *listener, xpc_connection_t peer)
{
    if (listener == nil || peer == nullptr ||
        atomic_load_explicit(&listener->local_closed, memory_order_acquire)) {
        if (peer != nullptr) {
            xpc_connection_cancel(peer);
        }
        return;
    }

    N00BLocalXPCState *conn = [[N00BLocalXPCState alloc] init];
    if (conn == nil) {
        xpc_connection_cancel(peer);
        return;
    }

    local_xpc_state_init(conn, LOCAL_XPC_OWNER_CONN, nullptr);
    conn->connection = peer;
    __weak N00BLocalXPCState *weak_conn = conn;
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        N00BLocalXPCState *strong_conn = weak_conn;
        if (strong_conn == nil) {
            return;
        }
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            (void)local_xpc_callback_may_publish(strong_conn, true);
            local_xpc_mark_closed(strong_conn);
        }
    });
    atomic_store_explicit(&conn->handler_installed, true, memory_order_release);
    xpc_connection_activate(peer);
    atomic_store_explicit(&conn->activated, true, memory_order_release);

    os_unfair_lock_lock(&listener->pending_lock);
    bool closed = atomic_load_explicit(&listener->local_closed,
                                       memory_order_acquire);
    if (!closed) {
        [listener->pending_accepts addObject:conn];
    }
    os_unfair_lock_unlock(&listener->pending_lock);
    if (closed) {
        local_xpc_mark_closed(conn);
    }
}

static bool
local_xpc_callback_may_publish(N00BLocalXPCState *state,
                               bool               terminal_status)
{
    if (state == nullptr) {
        return false;
    }

    if (atomic_load_explicit(&state->local_closed, memory_order_acquire) == false) {
        return true;
    }

    if (terminal_status == false) {
        return false;
    }

    bool expected = false;
    return atomic_compare_exchange_strong_explicit(
        &state->terminal_status_published,
        &expected,
        true,
        memory_order_acq_rel,
        memory_order_acquire);
}

static void
local_xpc_mark_closed(N00BLocalXPCState *state)
{
    if (state == nullptr) {
        return;
    }

    bool already_cancelled = atomic_exchange_explicit(
        &state->native_cancelled, true, memory_order_acq_rel);
    atomic_store_explicit(&state->local_closed, true, memory_order_release);
    if (already_cancelled) {
        return;
    }

    if (state->connection != nullptr) {
        xpc_connection_cancel(state->connection);
    }
}

int
_n00b_conduit_local_xpc_native_backend_present(void)
{
    return 1;
}

int
_n00b_conduit_local_xpc_native_listen(void       *owner_token,
                                      const void *name_data,
                                      uint64_t    name_len,
                                      void      **out_state)
{
    if (out_state == nullptr) {
        return N00B_LOCAL_XPC_NATIVE_INVALID;
    }
    *out_state = nullptr;

    NSString *name = local_xpc_name_from_bytes(name_data, name_len);
    if (name == nil) {
        return N00B_LOCAL_XPC_NATIVE_INVALID;
    }

    NSMutableDictionary *registry = local_xpc_registry();
    os_unfair_lock_lock(&local_xpc_registry_lock);
    bool name_in_use = [registry objectForKey:name] != nil;
    os_unfair_lock_unlock(&local_xpc_registry_lock);
    if (name_in_use) {
        return N00B_LOCAL_XPC_NATIVE_INVALID;
    }

    N00BLocalXPCState *state = [[N00BLocalXPCState alloc] init];
    if (state == nil) {
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }

    local_xpc_state_init(state, LOCAL_XPC_OWNER_LISTENER, owner_token);
    state->pending_lock    = OS_UNFAIR_LOCK_INIT;
    state->name            = name;
    state->pending_accepts = [[NSMutableArray alloc] init];
    state->target_queue    = dispatch_queue_create("n00b.local.xpc", DISPATCH_QUEUE_SERIAL);
    if (state->pending_accepts == nil || state->target_queue == nullptr) {
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }
    state->connection = xpc_connection_create(nullptr, state->target_queue);
    if (state->connection == nullptr) {
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }

    __weak N00BLocalXPCState *weak_state = state;
    xpc_connection_set_event_handler(state->connection, ^(xpc_object_t event) {
        N00BLocalXPCState *strong_state = weak_state;
        if (strong_state == nil) {
            return;
        }

        xpc_type_t event_type = xpc_get_type(event);
        if (event_type == XPC_TYPE_CONNECTION) {
            local_xpc_accept_peer(strong_state, (xpc_connection_t)event);
        }
        else if (event_type == XPC_TYPE_ERROR) {
            (void)local_xpc_callback_may_publish(strong_state, true);
            local_xpc_mark_closed(strong_state);
        }
    });
    atomic_store_explicit(&state->handler_installed, true, memory_order_release);

    xpc_connection_activate(state->connection);
    atomic_store_explicit(&state->activated, true, memory_order_release);

    state->listener_endpoint = xpc_endpoint_create(state->connection);
    if (state->listener_endpoint == nullptr) {
        local_xpc_mark_closed(state);
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }

    os_unfair_lock_lock(&local_xpc_registry_lock);
    name_in_use = [registry objectForKey:name] != nil;
    if (!name_in_use) {
        [registry setObject:state forKey:name];
    }
    os_unfair_lock_unlock(&local_xpc_registry_lock);
    if (name_in_use) {
        local_xpc_mark_closed(state);
        return N00B_LOCAL_XPC_NATIVE_INVALID;
    }

    *out_state = (__bridge_retained void *)state;
    return N00B_LOCAL_XPC_NATIVE_OK;
}

int
_n00b_conduit_local_xpc_native_connect(void       *owner_token,
                                       const void *name_data,
                                       uint64_t    name_len,
                                       void      **out_state)
{
    if (out_state == nullptr) {
        return N00B_LOCAL_XPC_NATIVE_INVALID;
    }
    *out_state = nullptr;

    NSString *name = local_xpc_name_from_bytes(name_data, name_len);
    if (name == nil) {
        return N00B_LOCAL_XPC_NATIVE_INVALID;
    }

    N00BLocalXPCState *listener = nil;
    NSMutableDictionary *registry = local_xpc_registry();
    os_unfair_lock_lock(&local_xpc_registry_lock);
    listener = [registry objectForKey:name];
    os_unfair_lock_unlock(&local_xpc_registry_lock);
    if (listener == nil || listener->listener_endpoint == nullptr ||
        atomic_load_explicit(&listener->local_closed, memory_order_acquire)) {
        return N00B_LOCAL_XPC_NATIVE_NOT_FOUND;
    }

    N00BLocalXPCState *state = [[N00BLocalXPCState alloc] init];
    if (state == nil) {
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }

    local_xpc_state_init(state, LOCAL_XPC_OWNER_CONN, owner_token);
    state->target_queue = dispatch_queue_create("n00b.local.xpc.conn",
                                                DISPATCH_QUEUE_SERIAL);
    if (state->target_queue == nullptr) {
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }
    state->connection = xpc_connection_create_from_endpoint(listener->listener_endpoint);
    if (state->connection == nullptr) {
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }

    xpc_connection_set_target_queue(state->connection, state->target_queue);
    __weak N00BLocalXPCState *weak_state = state;
    xpc_connection_set_event_handler(state->connection, ^(xpc_object_t event) {
        N00BLocalXPCState *strong_state = weak_state;
        if (strong_state == nil) {
            return;
        }
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            (void)local_xpc_callback_may_publish(strong_state, true);
            local_xpc_mark_closed(strong_state);
        }
    });
    atomic_store_explicit(&state->handler_installed, true, memory_order_release);
    xpc_connection_activate(state->connection);
    atomic_store_explicit(&state->activated, true, memory_order_release);

    xpc_object_t hello = xpc_dictionary_create(nullptr, nullptr, 0);
    if (hello == nullptr) {
        local_xpc_mark_closed(state);
        return N00B_LOCAL_XPC_NATIVE_ALLOC;
    }
    xpc_dictionary_set_string(hello, "n00b.local.xpc", "connect");
    xpc_connection_send_message(state->connection, hello);

    *out_state = (__bridge_retained void *)state;
    return N00B_LOCAL_XPC_NATIVE_OK;
}

void *
_n00b_conduit_local_xpc_native_listener_pop_accept(void *raw_state)
{
    N00BLocalXPCState *state = (__bridge N00BLocalXPCState *)raw_state;
    if (state == nil || state->kind != LOCAL_XPC_OWNER_LISTENER) {
        return nullptr;
    }

    os_unfair_lock_lock(&state->pending_lock);
    if ([state->pending_accepts count] == 0) {
        os_unfair_lock_unlock(&state->pending_lock);
        return nullptr;
    }

    N00BLocalXPCState *conn = [state->pending_accepts objectAtIndex:0];
    [state->pending_accepts removeObjectAtIndex:0];
    os_unfair_lock_unlock(&state->pending_lock);
    return (__bridge_retained void *)conn;
}

void
_n00b_conduit_local_xpc_native_peer_facts(void     *raw_state,
                                          uint64_t *pid,
                                          bool     *has_pid,
                                          uint64_t *uid,
                                          bool     *has_uid,
                                          uint64_t *gid,
                                          bool     *has_gid)
{
    if (has_pid != nullptr) {
        *has_pid = false;
    }
    if (has_uid != nullptr) {
        *has_uid = false;
    }
    if (has_gid != nullptr) {
        *has_gid = false;
    }

    N00BLocalXPCState *state = (__bridge N00BLocalXPCState *)raw_state;
    if (state == nil || state->connection == nullptr) {
        return;
    }

    pid_t peer_pid = xpc_connection_get_pid(state->connection);
    if (peer_pid > 0 && pid != nullptr && has_pid != nullptr) {
        *pid     = (uint64_t)peer_pid;
        *has_pid = true;
    }

    if (uid != nullptr && has_uid != nullptr) {
        *uid     = (uint64_t)xpc_connection_get_euid(state->connection);
        *has_uid = true;
    }

    if (gid != nullptr && has_gid != nullptr) {
        *gid     = (uint64_t)xpc_connection_get_egid(state->connection);
        *has_gid = true;
    }
}

void
_n00b_conduit_local_xpc_native_cancel_listener(void *raw_state)
{
    N00BLocalXPCState *state = (__bridge N00BLocalXPCState *)raw_state;
    if (state == nil) {
        return;
    }

    NSMutableDictionary *registry = local_xpc_registry();
    os_unfair_lock_lock(&local_xpc_registry_lock);
    if (state->name != nil && [registry objectForKey:state->name] == state) {
        [registry removeObjectForKey:state->name];
    }
    os_unfair_lock_unlock(&local_xpc_registry_lock);

    os_unfair_lock_lock(&state->pending_lock);
    NSArray *pending = [state->pending_accepts copy];
    [state->pending_accepts removeAllObjects];
    os_unfair_lock_unlock(&state->pending_lock);
    for (N00BLocalXPCState *conn in pending) {
        local_xpc_mark_closed(conn);
    }

    local_xpc_mark_closed(state);
}

void
_n00b_conduit_local_xpc_native_release_listener(void *raw_state)
{
    N00BLocalXPCState *state = (__bridge_transfer N00BLocalXPCState *)raw_state;
    (void)state;
}

void
_n00b_conduit_local_xpc_native_cancel_conn(void *raw_state)
{
    N00BLocalXPCState *state = (__bridge_transfer N00BLocalXPCState *)raw_state;
    local_xpc_mark_closed(state);
}

/*
 * Kept non-static so tests and audits have a direct guard for the native
 * "no publish after close except terminal status" rule.
 */
bool
_n00b_conduit_local_xpc_native_callback_may_publish_for_test(void *raw_state,
                                                             bool terminal_status)
{
    return local_xpc_callback_may_publish(
        (__bridge N00BLocalXPCState *)raw_state, terminal_status);
}
