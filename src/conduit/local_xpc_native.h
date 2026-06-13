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
                                                 void      **out_state,
                                                 void       *allocator);

extern int _n00b_conduit_local_xpc_native_connect(void       *owner_token,
                                                  const void *name_data,
                                                  uint64_t    name_len,
                                                  void      **out_state,
                                                  void       *allocator);

extern void *_n00b_conduit_local_xpc_native_listener_pop_accept(void *state);

extern void _n00b_conduit_local_xpc_native_peer_facts(void     *state,
                                                      uint64_t *pid,
                                                      bool     *has_pid,
                                                      uint64_t *uid,
                                                      bool     *has_uid,
                                                      uint64_t *gid,
                                                      bool     *has_gid);

extern int _n00b_conduit_local_xpc_native_send(void       *state,
                                               const void *data,
                                               uint64_t    len);

extern void *_n00b_conduit_local_xpc_native_pop_read(void *state);

extern uint64_t _n00b_conduit_local_xpc_native_read_len(void *read_obj);

extern const void *_n00b_conduit_local_xpc_native_read_bytes(void *read_obj);

extern void _n00b_conduit_local_xpc_native_release_read(void *read_obj);

extern int _n00b_conduit_local_xpc_native_conn_closed(void *state);

extern void _n00b_conduit_local_xpc_listener_closed(void *owner_token);

extern void _n00b_conduit_local_xpc_attach_foreign(void *stack_low,
                                                   void *stack_high);
extern void _n00b_conduit_local_xpc_detach_foreign(void);

extern void *_n00b_conduit_local_xpc_stage_new(const void *data,
                                               uint64_t    len,
                                               void       *allocator);
extern uint64_t _n00b_conduit_local_xpc_stage_len(void *stage);
extern const void *_n00b_conduit_local_xpc_stage_bytes(void *stage);
extern void _n00b_conduit_local_xpc_stage_release(void *stage);

extern void *_n00b_conduit_local_xpc_stage_queue_new(void *allocator);
extern int _n00b_conduit_local_xpc_stage_queue_push(void *queue, void *stage);
extern void *_n00b_conduit_local_xpc_stage_queue_pop(void *queue);
extern void _n00b_conduit_local_xpc_stage_queue_drop(void *queue);
extern void _n00b_conduit_local_xpc_stage_queue_destroy(void *queue);

extern void _n00b_conduit_local_xpc_native_cancel_listener(void *state);
extern void _n00b_conduit_local_xpc_native_release_listener(void *state);
extern void _n00b_conduit_local_xpc_native_cancel_conn(void *state);
