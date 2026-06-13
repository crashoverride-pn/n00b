/*
 * local_windows.c - Windows named local IPC backend.
 *
 * Phase 2 implements named-pipe listener, connect, and accept lifecycle only.
 * Message read/write, bridge data handling, and terminal status mapping remain
 * Phase 3 work. A listener keeps one overlapped ConnectNamedPipe instance
 * armed at a time; concurrent clients may wait for the accept loop to promote
 * the current instance and arm the next one. The public backlog kwarg is
 * retained for API consistency, but Phase 2 does not pre-arm N instances.
 *
 * Same-user default: the pipe is created with the process default DACL and
 * PIPE_REJECT_REMOTE_CLIENTS. Listeners verify every accepted client with
 * GetNamedPipeClientProcessId plus token user SID comparison before
 * publishing. Clients verify the server with GetNamedPipeServerProcessId plus
 * the same SID check before returning a connected local handle. If the peer
 * identity cannot be verified as the current user, the native pipe is closed.
 */

#include "adt/list.h"
#include "core/alloc.h"
#include "core/mutex.h"
#include "internal/win32_sockets.h"
#include "local_windows_native.h"

#define LOCAL_WINDOWS_PIPE_PREFIX L"\\\\.\\pipe\\n00b-local-"
#define LOCAL_WINDOWS_PIPE_PREFIX_LEN \
    ((uint64_t)((sizeof(LOCAL_WINDOWS_PIPE_PREFIX) / sizeof(wchar_t)) - 1))
#define LOCAL_WINDOWS_PIPE_BUFFER_SIZE 65536UL
#define LOCAL_WINDOWS_CONNECT_WAIT_MS 5000UL

#define GENERIC_WRITE 0x40000000UL

#define PIPE_ACCESS_DUPLEX       0x00000003UL
#define PIPE_TYPE_MESSAGE        0x00000004UL
#define PIPE_READMODE_MESSAGE    0x00000002UL
#define PIPE_WAIT                0x00000000UL
#define PIPE_UNLIMITED_INSTANCES 255UL
#define PIPE_REJECT_REMOTE_CLIENTS 0x00000008UL

#define ERROR_FILE_NOT_FOUND 2UL
#define ERROR_ACCESS_DENIED 5UL
#define ERROR_PIPE_BUSY 231UL
#define ERROR_IO_PENDING 997UL
#define ERROR_PIPE_CONNECTED 535UL

#define TOKEN_QUERY 0x0008UL

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
} TOKEN_INFORMATION_CLASS;

typedef struct _SID_AND_ATTRIBUTES {
    void  *Sid;
    DWORD  Attributes;
} SID_AND_ATTRIBUTES;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER;

[[gnu::stdcall]] HANDLE CreateNamedPipeW(
    const wchar_t *name,
    DWORD open_mode,
    DWORD pipe_mode,
    DWORD max_instances,
    DWORD out_buffer_size,
    DWORD in_buffer_size,
    DWORD default_timeout,
    SECURITY_ATTRIBUTES *security_attributes);
[[gnu::stdcall]] BOOL ConnectNamedPipe(HANDLE pipe,
                                       OVERLAPPED *overlapped);
[[gnu::stdcall]] BOOL DisconnectNamedPipe(HANDLE pipe);
[[gnu::stdcall]] BOOL CancelIoEx(HANDLE file,
                                 OVERLAPPED *overlapped);
[[gnu::stdcall]] BOOL WaitNamedPipeW(const wchar_t *name,
                                     DWORD timeout);
[[gnu::stdcall]] BOOL GetNamedPipeClientProcessId(
    HANDLE pipe,
    ULONG *client_process_id);
[[gnu::stdcall]] BOOL GetNamedPipeServerProcessId(
    HANDLE pipe,
    ULONG *server_process_id);
[[gnu::stdcall]] BOOL OpenProcessToken(HANDLE process,
                                       DWORD desired_access,
                                       HANDLE *token);
[[gnu::stdcall]] BOOL GetTokenInformation(
    HANDLE token,
    TOKEN_INFORMATION_CLASS token_information_class,
    void *token_information,
    DWORD token_information_len,
    DWORD *return_len);
[[gnu::stdcall]] BOOL EqualSid(void *sid1, void *sid2);

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

typedef n00b_list_t(void *) local_windows_accept_queue_t;

typedef struct local_windows_listener_state local_windows_listener_state_t;
typedef struct local_windows_conn_state     local_windows_conn_state_t;

struct local_windows_listener_state {
    HANDLE                         pipe;
    void                          *owner_token;
    n00b_allocator_t              *allocator;
    int                            backlog;
    bool                           closing;
    bool                           released;
    wchar_t                       *pipe_name;
    n00b_mutex_t                   lock;
    local_windows_op_t            *accept_op;
    local_windows_accept_queue_t  *accepted;
};

struct local_windows_conn_state {
    HANDLE              pipe;
    void               *owner_token;
    n00b_allocator_t   *allocator;
    bool                closing;
    bool                released;
    bool                peer_closed;
    uint64_t            peer_pid;
    bool                has_peer_pid;
    local_windows_op_t *connect_op;
    local_windows_op_t *read_op;
    local_windows_op_t *write_op;
};

static void
local_windows_close_handle(HANDLE *handle)
{
    if (handle != nullptr && *handle != nullptr &&
        *handle != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(*handle);
        *handle = nullptr;
    }
}

static wchar_t
local_windows_hex_nibble(uint8_t v)
{
    return v < 10 ? (wchar_t)(L'0' + v) : (wchar_t)(L'a' + (v - 10));
}

static wchar_t *
local_windows_pipe_name(const void       *name_data,
                        uint64_t          name_len,
                        n00b_allocator_t *allocator)
{
    if (name_data == nullptr || name_len == 0) {
        return nullptr;
    }

    uint64_t encoded_len = name_len * 2;
    uint64_t total_len   = LOCAL_WINDOWS_PIPE_PREFIX_LEN + encoded_len;
    wchar_t *result = n00b_alloc_array(wchar_t, total_len + 1,
                                       .allocator = allocator);
    if (result == nullptr) {
        return nullptr;
    }

    for (uint64_t i = 0; i < LOCAL_WINDOWS_PIPE_PREFIX_LEN; i++) {
        result[i] = LOCAL_WINDOWS_PIPE_PREFIX[i];
    }
    const uint8_t *src = name_data;
    for (uint64_t i = 0; i < name_len; i++) {
        uint8_t b = src[i];
        uint64_t out_ix = LOCAL_WINDOWS_PIPE_PREFIX_LEN + (i * 2);
        result[out_ix]     = local_windows_hex_nibble((uint8_t)(b >> 4));
        result[out_ix + 1] = local_windows_hex_nibble((uint8_t)(b & 0x0f));
    }
    result[total_len] = L'\0';
    return result;
}

static local_windows_op_t *
local_windows_op_new(local_windows_op_kind_t kind,
                     void                   *owner,
                     n00b_allocator_t       *allocator)
{
    local_windows_op_t *op = n00b_alloc_with_opts(
        local_windows_op_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    if (op == nullptr) {
        return nullptr;
    }

    op->kind  = kind;
    op->owner = owner;
    op->event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (op->event == nullptr) {
        n00b_free(op);
        return nullptr;
    }
    op->overlapped.hEvent = op->event;
    return op;
}

static void
local_windows_op_release(local_windows_op_t **op)
{
    if (op == nullptr || *op == nullptr) {
        return;
    }

    local_windows_close_handle(&(*op)->event);
    if ((*op)->buffer != nullptr) {
        n00b_free((*op)->buffer);
        (*op)->buffer = nullptr;
    }
    n00b_free(*op);
    *op = nullptr;
}

static void
local_windows_op_observe_cancel(HANDLE pipe, local_windows_op_t *op)
{
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE || op == nullptr ||
        op->pending == false) {
        return;
    }

    (void)CancelIoEx(pipe, &op->overlapped);
    DWORD bytes = 0;
    (void)GetOverlappedResult(pipe, &op->overlapped, &bytes, TRUE);
    op->bytes_done = bytes;
    op->pending    = false;
    op->completed  = true;
}

static local_windows_conn_state_t *
local_windows_conn_state_new(HANDLE            pipe,
                             void             *owner_token,
                             n00b_allocator_t *allocator)
{
    local_windows_conn_state_t *state = n00b_alloc_with_opts(
        local_windows_conn_state_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    if (state == nullptr) {
        return nullptr;
    }

    state->pipe        = pipe;
    state->owner_token = owner_token;
    state->allocator   = allocator;
    state->peer_pid    = 0;
    state->has_peer_pid = false;
    return state;
}

static void
local_windows_accept_queue_free(local_windows_accept_queue_t *queue)
{
    if (queue == nullptr) {
        return;
    }

    n00b_rwlock_t *lock = queue->lock;
    n00b_list_free(*queue);
    if (lock != nullptr) {
        n00b_free(lock);
    }
    n00b_free(queue);
}

static void
local_windows_conn_cancel(local_windows_conn_state_t *state)
{
    if (state == nullptr || state->released) {
        return;
    }

    state->closing = true;
    if (state->pipe != nullptr && state->pipe != INVALID_HANDLE_VALUE) {
        local_windows_op_observe_cancel(state->pipe, state->connect_op);
        local_windows_op_observe_cancel(state->pipe, state->read_op);
        local_windows_op_observe_cancel(state->pipe, state->write_op);
        (void)DisconnectNamedPipe(state->pipe);
    }
    local_windows_op_release(&state->connect_op);
    local_windows_op_release(&state->read_op);
    local_windows_op_release(&state->write_op);
    local_windows_close_handle(&state->pipe);
    state->released = true;
}

static bool
local_windows_token_user_equal(HANDLE lhs_token, HANDLE rhs_token)
{
    uint8_t lhs_buf[512] = {};
    uint8_t rhs_buf[512] = {};
    DWORD lhs_len = 0;
    DWORD rhs_len = 0;

    if (!GetTokenInformation(lhs_token, TokenUser, lhs_buf,
                             (DWORD)sizeof(lhs_buf), &lhs_len)) {
        return false;
    }
    if (!GetTokenInformation(rhs_token, TokenUser, rhs_buf,
                             (DWORD)sizeof(rhs_buf), &rhs_len)) {
        return false;
    }

    TOKEN_USER *lhs = (TOKEN_USER *)lhs_buf;
    TOKEN_USER *rhs = (TOKEN_USER *)rhs_buf;
    return EqualSid(lhs->User.Sid, rhs->User.Sid) ? true : false;
}

static bool
local_windows_pid_is_same_user(ULONG pid)
{
    HANDLE current_token = nullptr;
    HANDLE peer_process  = nullptr;
    HANDLE peer_token    = nullptr;
    bool   result        = false;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY,
                          &current_token)) {
        goto done;
    }

    peer_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               (DWORD)pid);
    if (peer_process == nullptr) {
        goto done;
    }
    if (!OpenProcessToken(peer_process, TOKEN_QUERY, &peer_token)) {
        goto done;
    }

    result = local_windows_token_user_equal(current_token, peer_token);

done:
    local_windows_close_handle(&peer_token);
    local_windows_close_handle(&peer_process);
    local_windows_close_handle(&current_token);
    return result;
}

static bool
local_windows_pipe_peer_allowed(HANDLE pipe, uint64_t *peer_pid)
{
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) {
        return false;
    }
    if (peer_pid != nullptr) {
        *peer_pid = (uint64_t)pid;
    }
    return local_windows_pid_is_same_user(pid);
}

static bool
local_windows_pipe_server_allowed(HANDLE pipe, uint64_t *peer_pid)
{
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) {
        return false;
    }
    if (peer_pid != nullptr) {
        *peer_pid = (uint64_t)pid;
    }
    return local_windows_pid_is_same_user(pid);
}

static void
local_windows_listener_drop_pending(local_windows_listener_state_t *state)
{
    if (state == nullptr) {
        return;
    }

    if (state->pipe != nullptr && state->pipe != INVALID_HANDLE_VALUE) {
        local_windows_op_observe_cancel(state->pipe, state->accept_op);
        (void)DisconnectNamedPipe(state->pipe);
    }
    local_windows_op_release(&state->accept_op);
    local_windows_close_handle(&state->pipe);
}

static int
local_windows_listener_arm(local_windows_listener_state_t *state)
{
    if (state == nullptr || state->closing || state->released ||
        state->pipe_name == nullptr) {
        return N00B_LOCAL_WINDOWS_NATIVE_INVALID;
    }
    if (state->accept_op != nullptr ||
        (state->pipe != nullptr && state->pipe != INVALID_HANDLE_VALUE)) {
        return N00B_LOCAL_WINDOWS_NATIVE_OK;
    }

    state->pipe = CreateNamedPipeW(
        state->pipe_name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        LOCAL_WINDOWS_PIPE_BUFFER_SIZE,
        LOCAL_WINDOWS_PIPE_BUFFER_SIZE,
        0,
        nullptr);
    if (state->pipe == INVALID_HANDLE_VALUE) {
        state->pipe = nullptr;
        return N00B_LOCAL_WINDOWS_NATIVE_IO;
    }

    state->accept_op = local_windows_op_new(LOCAL_WINDOWS_OP_ACCEPT, state,
                                            state->allocator);
    if (state->accept_op == nullptr) {
        local_windows_close_handle(&state->pipe);
        return N00B_LOCAL_WINDOWS_NATIVE_ALLOC;
    }

    BOOL ok = ConnectNamedPipe(state->pipe,
                               &state->accept_op->overlapped);
    if (ok) {
        state->accept_op->completed = true;
        return N00B_LOCAL_WINDOWS_NATIVE_OK;
    }

    DWORD err = GetLastError();
    if (err == ERROR_IO_PENDING) {
        state->accept_op->pending = true;
        return N00B_LOCAL_WINDOWS_NATIVE_OK;
    }
    if (err == ERROR_PIPE_CONNECTED) {
        state->accept_op->completed = true;
        (void)SetEvent(state->accept_op->event);
        return N00B_LOCAL_WINDOWS_NATIVE_OK;
    }

    local_windows_listener_drop_pending(state);
    return N00B_LOCAL_WINDOWS_NATIVE_IO;
}

static local_windows_conn_state_t *
local_windows_listener_complete_accept(local_windows_listener_state_t *state)
{
    if (state == nullptr || state->accept_op == nullptr ||
        state->pipe == nullptr || state->pipe == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    local_windows_op_t *op = state->accept_op;
    if (op->pending) {
        if (WaitForSingleObject(op->event, 0) != WAIT_OBJECT_0) {
            return nullptr;
        }
        DWORD bytes = 0;
        if (!GetOverlappedResult(state->pipe, &op->overlapped, &bytes,
                                 FALSE)) {
            local_windows_listener_drop_pending(state);
            (void)local_windows_listener_arm(state);
            return nullptr;
        }
        op->bytes_done = bytes;
        op->pending    = false;
        op->completed  = true;
    }

    if (!op->completed) {
        return nullptr;
    }

    HANDLE accepted_pipe = state->pipe;
    state->pipe = nullptr;
    local_windows_op_release(&state->accept_op);

    uint64_t peer_pid = 0;
    if (!local_windows_pipe_peer_allowed(accepted_pipe, &peer_pid)) {
        (void)DisconnectNamedPipe(accepted_pipe);
        local_windows_close_handle(&accepted_pipe);
        (void)local_windows_listener_arm(state);
        return nullptr;
    }

    local_windows_conn_state_t *conn = local_windows_conn_state_new(
        accepted_pipe, nullptr, state->allocator);
    if (conn == nullptr) {
        (void)DisconnectNamedPipe(accepted_pipe);
        local_windows_close_handle(&accepted_pipe);
        (void)local_windows_listener_arm(state);
        return nullptr;
    }

    conn->peer_pid     = peer_pid;
    conn->has_peer_pid = true;
    (void)local_windows_listener_arm(state);
    return conn;
}

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
    if (out_state == nullptr) {
        return N00B_LOCAL_WINDOWS_NATIVE_INVALID;
    }
    *out_state = nullptr;

    n00b_allocator_t *alloc = allocator;
    wchar_t *pipe_name = local_windows_pipe_name(name_data, name_len, alloc);
    if (pipe_name == nullptr) {
        return name_data == nullptr || name_len == 0
            ? N00B_LOCAL_WINDOWS_NATIVE_INVALID
            : N00B_LOCAL_WINDOWS_NATIVE_ALLOC;
    }

    local_windows_listener_state_t *state = n00b_alloc_with_opts(
        local_windows_listener_state_t,
        &(n00b_alloc_opts_t){.allocator = alloc});
    if (state == nullptr) {
        n00b_free(pipe_name);
        return N00B_LOCAL_WINDOWS_NATIVE_ALLOC;
    }

    state->pipe        = nullptr;
    state->owner_token = owner_token;
    state->allocator   = alloc;
    state->backlog     = backlog;
    state->pipe_name   = pipe_name;
    state->accepted = n00b_alloc_with_opts(
        local_windows_accept_queue_t,
        &(n00b_alloc_opts_t){.allocator = alloc,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});
    if (state->accepted == nullptr) {
        n00b_free(pipe_name);
        n00b_free(state);
        return N00B_LOCAL_WINDOWS_NATIVE_ALLOC;
    }
    *state->accepted = n00b_list_new(void *, .allocator = alloc,
                                     .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_mutex_init(&state->lock);

    int arm_status = local_windows_listener_arm(state);
    if (arm_status != N00B_LOCAL_WINDOWS_NATIVE_OK) {
        local_windows_accept_queue_free(state->accepted);
        n00b_free(pipe_name);
        n00b_free(state);
        return arm_status;
    }

    *out_state = state;
    return N00B_LOCAL_WINDOWS_NATIVE_OK;
}

int
_n00b_conduit_local_windows_native_connect(void       *owner_token,
                                           const void *name_data,
                                           uint64_t    name_len,
                                           void      **out_state,
                                           void       *allocator)
{
    if (out_state == nullptr) {
        return N00B_LOCAL_WINDOWS_NATIVE_INVALID;
    }
    *out_state = nullptr;

    n00b_allocator_t *alloc = allocator;
    wchar_t *pipe_name = local_windows_pipe_name(name_data, name_len, alloc);
    if (pipe_name == nullptr) {
        return name_data == nullptr || name_len == 0
            ? N00B_LOCAL_WINDOWS_NATIVE_INVALID
            : N00B_LOCAL_WINDOWS_NATIVE_ALLOC;
    }

    HANDLE pipe = CreateFileW(pipe_name,
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY &&
            WaitNamedPipeW(pipe_name, LOCAL_WINDOWS_CONNECT_WAIT_MS)) {
            pipe = CreateFileW(pipe_name,
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED,
                               nullptr);
            err = pipe == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        }

        if (pipe == INVALID_HANDLE_VALUE) {
            n00b_free(pipe_name);
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY) {
                return N00B_LOCAL_WINDOWS_NATIVE_NOT_FOUND;
            }
            if (err == ERROR_ACCESS_DENIED) {
                return N00B_LOCAL_WINDOWS_NATIVE_CONNECT;
            }
            return N00B_LOCAL_WINDOWS_NATIVE_IO;
        }
    }

    uint64_t peer_pid = 0;
    if (!local_windows_pipe_server_allowed(pipe, &peer_pid)) {
        local_windows_close_handle(&pipe);
        n00b_free(pipe_name);
        return N00B_LOCAL_WINDOWS_NATIVE_CONNECT;
    }

    local_windows_conn_state_t *state = local_windows_conn_state_new(
        pipe, owner_token, alloc);
    if (state == nullptr) {
        local_windows_close_handle(&pipe);
        n00b_free(pipe_name);
        return N00B_LOCAL_WINDOWS_NATIVE_ALLOC;
    }

    state->peer_pid     = peer_pid;
    state->has_peer_pid = true;
    n00b_free(pipe_name);
    *out_state = state;
    return N00B_LOCAL_WINDOWS_NATIVE_OK;
}

void *
_n00b_conduit_local_windows_native_listener_pop_accept(void *raw_state)
{
    local_windows_listener_state_t *state = raw_state;
    if (state == nullptr || state->released) {
        return nullptr;
    }

    n00b_mutex_lock(&state->lock);
    if (state->closing) {
        n00b_mutex_unlock(&state->lock);
        return nullptr;
    }

    if (state->accepted != nullptr) {
        auto queued = n00b_list_pop_front(void *, *state->accepted);
        if (n00b_option_is_set(queued)) {
            n00b_mutex_unlock(&state->lock);
            return n00b_option_get(queued);
        }
    }

    local_windows_conn_state_t *conn =
        local_windows_listener_complete_accept(state);
    n00b_mutex_unlock(&state->lock);
    return conn;
}

void
_n00b_conduit_local_windows_native_peer_facts(void     *raw_state,
                                              uint64_t *pid,
                                              bool     *has_pid,
                                              uint64_t *uid,
                                              bool     *has_uid,
                                              uint64_t *gid,
                                              bool     *has_gid)
{
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

    local_windows_conn_state_t *state = raw_state;
    if (state == nullptr || pid == nullptr || has_pid == nullptr) {
        return;
    }

    if (state->has_peer_pid) {
        *pid     = state->peer_pid;
        *has_pid = true;
        return;
    }

    ULONG client_pid = 0;
    if (state->pipe != nullptr && state->pipe != INVALID_HANDLE_VALUE &&
        GetNamedPipeClientProcessId(state->pipe, &client_pid)) {
        state->peer_pid     = (uint64_t)client_pid;
        state->has_peer_pid = true;
        *pid                = state->peer_pid;
        *has_pid            = true;
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
_n00b_conduit_local_windows_native_conn_closed(void *raw_state)
{
    local_windows_conn_state_t *state = raw_state;
    return state == nullptr || state->closing || state->released ||
        state->peer_closed;
}

void
_n00b_conduit_local_windows_native_cancel_listener(void *raw_state)
{
    local_windows_listener_state_t *state = raw_state;
    if (state == nullptr || state->released) {
        return;
    }

    n00b_mutex_lock(&state->lock);
    state->closing = true;
    local_windows_listener_drop_pending(state);
    n00b_mutex_unlock(&state->lock);
}

void
_n00b_conduit_local_windows_native_release_listener(void *raw_state)
{
    local_windows_listener_state_t *state = raw_state;
    if (state == nullptr || state->released) {
        return;
    }

    _n00b_conduit_local_windows_native_cancel_listener(raw_state);
    n00b_mutex_lock(&state->lock);
    if (state->accepted != nullptr) {
        void *raw_conn;
        while ((raw_conn = n00b_option_get_or_else(
                    n00b_list_pop_front(void *, *state->accepted),
                    nullptr)) != nullptr) {
            local_windows_conn_cancel(raw_conn);
            n00b_free(raw_conn);
        }
        local_windows_accept_queue_free(state->accepted);
        state->accepted = nullptr;
    }
    if (state->pipe_name != nullptr) {
        n00b_free(state->pipe_name);
        state->pipe_name = nullptr;
    }
    state->released = true;
    n00b_mutex_unlock(&state->lock);
    n00b_free(state);
}

void
_n00b_conduit_local_windows_native_cancel_conn(void *raw_state)
{
    local_windows_conn_state_t *state = raw_state;
    if (state == nullptr) {
        return;
    }

    local_windows_conn_cancel(state);
    n00b_free(state);
}
