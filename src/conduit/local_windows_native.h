/*
 * local_windows_native.h - Flat private C boundary for Windows named backend.
 *
 * This header is intentionally n00b-free so the Windows-native implementation
 * boundary does not expose portable n00b objects or native named-pipe details.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    N00B_LOCAL_WINDOWS_NATIVE_OK = 0,
    N00B_LOCAL_WINDOWS_NATIVE_ALLOC,
    N00B_LOCAL_WINDOWS_NATIVE_INVALID,
    N00B_LOCAL_WINDOWS_NATIVE_NOT_FOUND,
    N00B_LOCAL_WINDOWS_NATIVE_CONNECT,
    N00B_LOCAL_WINDOWS_NATIVE_IO,
    N00B_LOCAL_WINDOWS_NATIVE_NOT_SUPPORTED,
} n00b_local_windows_native_status_t;

extern int _n00b_conduit_local_windows_native_backend_present(void);

extern int _n00b_conduit_local_windows_native_listen(void       *owner_token,
                                                     const void *name_data,
                                                     uint64_t    name_len,
                                                     int         backlog,
                                                     void      **out_state,
                                                     void       *allocator);

extern int _n00b_conduit_local_windows_native_connect(void       *owner_token,
                                                      const void *name_data,
                                                      uint64_t    name_len,
                                                      void      **out_state,
                                                      void       *allocator);

extern void *_n00b_conduit_local_windows_native_listener_pop_accept(
    void *state);

extern void _n00b_conduit_local_windows_native_peer_facts(void     *state,
                                                          uint64_t *pid,
                                                          bool     *has_pid,
                                                          uint64_t *uid,
                                                          bool     *has_uid,
                                                          uint64_t *gid,
                                                          bool     *has_gid);

extern int _n00b_conduit_local_windows_native_send(void       *state,
                                                   const void *data,
                                                   uint64_t    len);

extern void *_n00b_conduit_local_windows_native_pop_read(void *state);
extern uint64_t _n00b_conduit_local_windows_native_read_len(void *read_obj);
extern const void *_n00b_conduit_local_windows_native_read_bytes(
    void *read_obj);
extern void _n00b_conduit_local_windows_native_release_read(void *read_obj);
extern int _n00b_conduit_local_windows_native_conn_closed(void *state);

extern void _n00b_conduit_local_windows_native_cancel_listener(void *state);
extern void _n00b_conduit_local_windows_native_release_listener(void *state);
extern void _n00b_conduit_local_windows_native_cancel_conn(void *state);
