/*
 * local_xpc_darwin.m - macOS XPC native backend skeleton.
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
#include <xpc/xpc.h>

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

typedef struct local_xpc_native_state {
    local_xpc_owner_kind_t kind;

    /*
     * Borrowed n00b owner token. The local listener/connection owns this
     * state and ends its lifetime through local close. Native callbacks must
     * check local_closed before using this token and may only use it to enqueue
     * work onto the n00b-owned path.
     */
    void *n00b_owner_token;

    /*
     * Native ARC-owned state. These fields are private to this file; no XPC or
     * dispatch type crosses into public headers or portable local payloads.
     */
    xpc_connection_t connection;
    xpc_object_t     listener_endpoint;
    dispatch_queue_t target_queue;

    _Atomic bool handler_installed;
    _Atomic bool activated;
    _Atomic bool local_closed;
    _Atomic bool native_cancelled;
    _Atomic bool terminal_status_published;
} local_xpc_native_state_t;

static bool
local_xpc_callback_may_publish(local_xpc_native_state_t *state,
                               bool                      terminal_status)
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
local_xpc_mark_closed(local_xpc_native_state_t *state)
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

void
_n00b_conduit_local_xpc_native_cancel_listener(void *raw_state)
{
    local_xpc_mark_closed((local_xpc_native_state_t *)raw_state);
}

void
_n00b_conduit_local_xpc_native_cancel_conn(void *raw_state)
{
    local_xpc_mark_closed((local_xpc_native_state_t *)raw_state);
}

/*
 * Kept non-static so Phase 1 has an assertion/audit-visible guard for the
 * "no publish after close except terminal status" rule before native event
 * handlers land in later phases.
 */
bool
_n00b_conduit_local_xpc_native_callback_may_publish_for_test(void *raw_state,
                                                             bool terminal_status)
{
    return local_xpc_callback_may_publish(
        (local_xpc_native_state_t *)raw_state, terminal_status);
}
