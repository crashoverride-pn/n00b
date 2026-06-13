/*
 * local_xpc_native.h - Flat private C boundary for Darwin XPC backend.
 *
 * This header is intentionally n00b-free so the Objective-C frontend can
 * include it. Portable n00b types and native XPC/dispatch types stay on their
 * respective sides of this file.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    N00B_LOCAL_XPC_NATIVE_OK = 0,
    N00B_LOCAL_XPC_NATIVE_ALLOC,
    N00B_LOCAL_XPC_NATIVE_INVALID,
    N00B_LOCAL_XPC_NATIVE_NOT_FOUND,
    N00B_LOCAL_XPC_NATIVE_NOT_SUPPORTED,
} n00b_local_xpc_native_status_t;

extern int _n00b_conduit_local_xpc_native_backend_present(void);

extern int _n00b_conduit_local_xpc_native_listen(void       *owner_token,
                                                 const void *name_data,
                                                 uint64_t    name_len,
                                                 void      **out_state);

extern int _n00b_conduit_local_xpc_native_connect(void       *owner_token,
                                                  const void *name_data,
                                                  uint64_t    name_len,
                                                  void      **out_state);

extern void *_n00b_conduit_local_xpc_native_listener_pop_accept(void *state);

extern void _n00b_conduit_local_xpc_native_peer_facts(void     *state,
                                                      uint64_t *pid,
                                                      bool     *has_pid,
                                                      uint64_t *uid,
                                                      bool     *has_uid,
                                                      uint64_t *gid,
                                                      bool     *has_gid);

extern void _n00b_conduit_local_xpc_native_cancel_listener(void *state);
extern void _n00b_conduit_local_xpc_native_release_listener(void *state);
extern void _n00b_conduit_local_xpc_native_cancel_conn(void *state);
