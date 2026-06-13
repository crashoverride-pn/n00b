/*
 * local_windows.c - Windows named local IPC backend skeleton.
 *
 * Phase 1 establishes the private native boundary and ownership model only.
 * Named-pipe listener/connect/accept/read/write behavior lands in later
 * phases; entry points may report NOT_SUPPORTED until then.
 */

#include "internal/win32_sockets.h"
#include "local_windows_native.h"

typedef enum {
    LOCAL_WINDOWS_OP_CONNECT,
    LOCAL_WINDOWS_OP_READ,
    LOCAL_WINDOWS_OP_WRITE,
    LOCAL_WINDOWS_OP_ACCEPT,
} local_windows_op_kind_t;

typedef struct local_windows_op {
    OVERLAPPED              overlapped;
    HANDLE                  event;
    local_windows_op_kind_t kind;
    uint8_t                *buffer;
    uint64_t                buffer_len;
    uint64_t                bytes_done;
    void                   *owner;
    bool                    pending;
    bool                    completed;
} local_windows_op_t;

typedef struct local_windows_listener_state local_windows_listener_state_t;
typedef struct local_windows_conn_state     local_windows_conn_state_t;

/*
 * D-008 ownership skeleton:
 *
 * Every future pending ConnectNamedPipe, ReadFile, or WriteFile operation
 * must be represented by a backend-owned local_windows_op_t, or by a stricter
 * operation record with the same owned facts. The operation record owns its
 * OVERLAPPED, event handle, staged byte buffer, kind, byte count, completion
 * flags, and owner token until completion or a CancelIoEx result is observed.
 *
 * Outbound n00b buffers must be copied into the operation buffer before
 * WriteFile is issued. Inbound bytes remain backend-owned until copied or
 * transferred into a fresh n00b_buffer_t before local read publication.
 * Stack-allocated OVERLAPPED records are not permitted for pending I/O.
 * Safe same-user local IPC defaults are also backend policy; Phase 1 adds no
 * public security kwargs.
 *
 * Phase 2/3 will add the queues and completion handling that retain these
 * records across close/cancel. Phase 1 deliberately performs no named-pipe I/O.
 */
struct local_windows_listener_state {
    HANDLE              pipe;
    void               *owner_token;
    void               *allocator;
    int                 backlog;
    bool                closing;
    bool                released;
    local_windows_op_t *accept_op;
};

struct local_windows_conn_state {
    HANDLE              pipe;
    void               *owner_token;
    void               *allocator;
    bool                closing;
    bool                released;
    bool                peer_closed;
    local_windows_op_t *connect_op;
    local_windows_op_t *read_op;
    local_windows_op_t *write_op;
};

int
_n00b_conduit_local_windows_native_backend_present(void)
{
    return 1;
}

int
_n00b_conduit_local_windows_native_listen(void       *owner_token,
                                          const void *name_data,
                                          uint64_t    name_len,
                                          int         backlog,
                                          void      **out_state,
                                          void       *allocator)
{
    (void)owner_token;
    (void)name_data;
    (void)name_len;
    (void)backlog;
    (void)allocator;

    if (out_state == nullptr) {
        return N00B_LOCAL_WINDOWS_NATIVE_INVALID;
    }

    *out_state = nullptr;
    return N00B_LOCAL_WINDOWS_NATIVE_NOT_SUPPORTED;
}

int
_n00b_conduit_local_windows_native_connect(void       *owner_token,
                                           const void *name_data,
                                           uint64_t    name_len,
                                           void      **out_state,
                                           void       *allocator)
{
    (void)owner_token;
    (void)name_data;
    (void)name_len;
    (void)allocator;

    if (out_state == nullptr) {
        return N00B_LOCAL_WINDOWS_NATIVE_INVALID;
    }

    *out_state = nullptr;
    return N00B_LOCAL_WINDOWS_NATIVE_NOT_SUPPORTED;
}

void *
_n00b_conduit_local_windows_native_listener_pop_accept(void *state)
{
    (void)state;
    return nullptr;
}

void
_n00b_conduit_local_windows_native_peer_facts(void     *state,
                                              uint64_t *pid,
                                              bool     *has_pid,
                                              uint64_t *uid,
                                              bool     *has_uid,
                                              uint64_t *gid,
                                              bool     *has_gid)
{
    (void)state;

    if (pid != nullptr) {
        *pid = 0;
    }
    if (uid != nullptr) {
        *uid = 0;
    }
    if (gid != nullptr) {
        *gid = 0;
    }
    if (has_pid != nullptr) {
        *has_pid = false;
    }
    if (has_uid != nullptr) {
        *has_uid = false;
    }
    if (has_gid != nullptr) {
        *has_gid = false;
    }
}

int
_n00b_conduit_local_windows_native_send(void       *state,
                                        const void *data,
                                        uint64_t    len)
{
    (void)state;
    (void)data;
    (void)len;
    return N00B_LOCAL_WINDOWS_NATIVE_NOT_SUPPORTED;
}

void *
_n00b_conduit_local_windows_native_pop_read(void *state)
{
    (void)state;
    return nullptr;
}

uint64_t
_n00b_conduit_local_windows_native_read_len(void *read_obj)
{
    (void)read_obj;
    return 0;
}

const void *
_n00b_conduit_local_windows_native_read_bytes(void *read_obj)
{
    (void)read_obj;
    return nullptr;
}

void
_n00b_conduit_local_windows_native_release_read(void *read_obj)
{
    (void)read_obj;
}

int
_n00b_conduit_local_windows_native_conn_closed(void *state)
{
    (void)state;
    return 1;
}

void
_n00b_conduit_local_windows_native_cancel_listener(void *state)
{
    (void)state;
}

void
_n00b_conduit_local_windows_native_release_listener(void *state)
{
    (void)state;
}

void
_n00b_conduit_local_windows_native_cancel_conn(void *state)
{
    (void)state;
}
