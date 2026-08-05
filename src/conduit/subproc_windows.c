/*
 * subproc_windows.c - Windows subprocess management.
 */

#ifdef _WIN32

#include "n00b.h"
#include "conduit/fd_writer.h"
#include "conduit/subproc.h"
#include "core/buffer.h"
#include "internal/subproc_policy.h"
#include "internal/win32_sockets.h"
#include "text/strings/string_convert.h"

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PROC_THREAD_ATTRIBUTE_HANDLE_LIST
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002UL
#endif
#ifndef GENERIC_WRITE
#define GENERIC_WRITE 0x40000000UL
#endif
#ifndef ERROR_FILE_NOT_FOUND
#define ERROR_FILE_NOT_FOUND 2UL
#endif
#ifndef ERROR_PATH_NOT_FOUND
#define ERROR_PATH_NOT_FOUND 3UL
#endif
#ifndef ERROR_TOO_MANY_OPEN_FILES
#define ERROR_TOO_MANY_OPEN_FILES 4UL
#endif
#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED 5UL
#endif
#ifndef ERROR_NOT_ENOUGH_MEMORY
#define ERROR_NOT_ENOUGH_MEMORY 8UL
#endif
#ifndef ERROR_BAD_ENVIRONMENT
#define ERROR_BAD_ENVIRONMENT 10UL
#endif
#ifndef ERROR_OUTOFMEMORY
#define ERROR_OUTOFMEMORY 14UL
#endif
#ifndef ERROR_INVALID_DRIVE
#define ERROR_INVALID_DRIVE 15UL
#endif
#ifndef ERROR_BAD_EXE_FORMAT
#define ERROR_BAD_EXE_FORMAT 193UL
#endif
#ifndef ERROR_DIRECTORY
#define ERROR_DIRECTORY 267UL
#endif

DWORD __attribute__((__stdcall__))
SearchPathA(const char *path,
            const char *file_name,
            const char *extension,
            DWORD       buffer_len,
            char       *buffer,
            char      **file_part);

DWORD __attribute__((__stdcall__))
GetFileAttributesA(const char *path);

static n00b_buffer_t empty_buf_sentinel = {};

struct n00b_subproc_win_state {
    n00b_conduit_topic_base_t *stdout_topic;
    n00b_conduit_topic_base_t *stderr_topic;
    n00b_conduit_topic_base_t *stdin_raw_topic;
    n00b_conduit_inbox_t(n00b_buffer_t *) *stdin_xform_inbox;
    n00b_conduit_sub_handle_t stdin_xform_sub;
    HANDLE process;
    HANDLE thread;
    HANDLE stdin_write;
    HANDLE stdout_read;
    HANDLE stderr_read;
    HANDLE pseudoconsole;
    bool stdout_eof;
    bool stderr_eof;
};

static n00b_subproc_win_state_t *
win_state(n00b_subproc_t *sp)
{
    if (!sp) {
        return nullptr;
    }
    if (!sp->win) {
        sp->win = n00b_alloc_with_opts(
            n00b_subproc_win_state_t,
            &(n00b_alloc_opts_t){.allocator = sp->conduit->allocator});
        memset(sp->win, 0, sizeof(*sp->win));
        sp->win->stdin_xform_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    return sp->win;
}

static char *
win_quote_arg(const char *arg)
{
    if (!arg) {
        arg = "";
    }

    bool quote = *arg == '\0';
    const char *p;
    for (p = arg; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '"') {
            quote = true;
            break;
        }
    }

    if (!quote) {
        size_t len = strlen(arg);
        char  *out = n00b_alloc_array(char, len + 1);
        if (out) {
            memcpy(out, arg, len + 1);
        }
        return out;
    }

    size_t len = strlen(arg);
    char  *out = n00b_alloc_array(char, len * 2 + 3);
    if (!out) {
        return nullptr;
    }

    char  *dst = out;
    size_t backslashes = 0;
    *dst++ = '"';

    for (size_t i = 0; i < len; i++) {
        char ch = arg[i];
        if (ch == '\\') {
            backslashes++;
            continue;
        }
        if (ch == '"') {
            while (backslashes--) {
                *dst++ = '\\';
                *dst++ = '\\';
            }
            *dst++ = '\\';
            *dst++ = '"';
            backslashes = 0;
            continue;
        }
        while (backslashes--) {
            *dst++ = '\\';
        }
        backslashes = 0;
        *dst++ = ch;
    }

    while (backslashes--) {
        *dst++ = '\\';
        *dst++ = '\\';
    }
    *dst++ = '"';
    *dst = '\0';
    return out;
}

static char *
win_build_cmdline(n00b_subproc_t *sp)
{
    size_t n_args = sp->args ? sp->args->len : 0;
    size_t total_parts = ((sp->flags & N00B_SUBPROC_RAW_ARGV) ? 0 : 1) + n_args;

    if (total_parts == 0) {
        return nullptr;
    }

    char **parts = n00b_alloc_array(char *, total_parts);
    if (!parts) {
        return nullptr;
    }

    size_t ix = 0;
    if (!(sp->flags & N00B_SUBPROC_RAW_ARGV)) {
        parts[ix++] = win_quote_arg(n00b_unicode_str_to_cstr(sp->cmd));
    }
    for (size_t i = 0; i < n_args; i++) {
        parts[ix++] = win_quote_arg(n00b_unicode_str_to_cstr(sp->args->data[i]));
    }

    size_t len = 1;
    for (size_t i = 0; i < total_parts; i++) {
        if (!parts[i]) {
            for (size_t j = 0; j < total_parts; j++) {
                n00b_free(parts[j]);
            }
            n00b_free(parts);
            return nullptr;
        }
        len += strlen(parts[i]) + 1;
    }

    char *cmdline = n00b_alloc_array(char, len);
    if (!cmdline) {
        for (size_t i = 0; i < total_parts; i++) {
            n00b_free(parts[i]);
        }
        n00b_free(parts);
        return nullptr;
    }

    cmdline[0] = '\0';
    for (size_t i = 0; i < total_parts; i++) {
        if (i) {
            strcat(cmdline, " ");
        }
        strcat(cmdline, parts[i]);
        n00b_free(parts[i]);
    }
    n00b_free(parts);
    return cmdline;
}

static bool
win_env_key_matches(const char *entry, const char *key)
{
    if (!entry || !key) {
        return false;
    }

    while (*key && *entry && *entry != '=') {
        char a = *entry++;
        char b = *key++;
        if (a >= 'a' && a <= 'z') {
            a = (char)(a - 'a' + 'A');
        }
        if (b >= 'a' && b <= 'z') {
            b = (char)(b - 'a' + 'A');
        }
        if (a != b) {
            return false;
        }
    }

    return *key == '\0' && *entry == '=';
}

static bool
win_env_has_key(n00b_array_t(n00b_string_t *) *env, const char *key)
{
    for (size_t i = 0; i < env->len; i++) {
        if (win_env_key_matches(n00b_unicode_str_to_cstr(env->data[i]), key)) {
            return true;
        }
    }
    return false;
}

static char *
win_parent_env_entry(const char *key)
{
    const char *value = getenv(key);
    if (!value || !*value) {
        return nullptr;
    }

    size_t key_len   = strlen(key);
    size_t value_len = strlen(value);
    char  *entry     = n00b_alloc_array(char, key_len + value_len + 2);
    if (!entry) {
        return nullptr;
    }

    memcpy(entry, key, key_len);
    entry[key_len] = '=';
    memcpy(entry + key_len + 1, value, value_len + 1);
    return entry;
}

static char *
win_build_env_block(n00b_array_t(n00b_string_t *) *env)
{
    if (!env) {
        return nullptr;
    }

    char *system_root = win_env_has_key(env, "SystemRoot")
                            ? nullptr
                            : win_parent_env_entry("SystemRoot");
    char *windir = win_env_has_key(env, "WINDIR")
                       ? nullptr
                       : win_parent_env_entry("WINDIR");

    size_t len = 1;
    for (size_t i = 0; i < env->len; i++) {
        len += strlen(n00b_unicode_str_to_cstr(env->data[i])) + 1;
    }
    if (system_root) {
        len += strlen(system_root) + 1;
    }
    if (windir) {
        len += strlen(windir) + 1;
    }

    char *block = n00b_alloc_array(char, len);
    if (!block) {
        n00b_free(system_root);
        n00b_free(windir);
        return nullptr;
    }

    char *p = block;
    for (size_t i = 0; i < env->len; i++) {
        const char *entry = n00b_unicode_str_to_cstr(env->data[i]);
        size_t entry_len = strlen(entry);
        memcpy(p, entry, entry_len + 1);
        p += entry_len + 1;
    }
    if (system_root) {
        size_t entry_len = strlen(system_root);
        memcpy(p, system_root, entry_len + 1);
        p += entry_len + 1;
        n00b_free(system_root);
    }
    if (windir) {
        size_t entry_len = strlen(windir);
        memcpy(p, windir, entry_len + 1);
        p += entry_len + 1;
        n00b_free(windir);
    }
    *p = '\0';
    return block;
}

static bool
win_cmd_has_path_component(const char *cmd)
{
    return cmd && (strchr(cmd, '\\') || strchr(cmd, '/') || strchr(cmd, ':'));
}

static bool
win_cwd_is_valid(const char *cwd)
{
    if (!cwd) {
        return true;
    }

    DWORD attrs = GetFileAttributesA(cwd);
    return attrs != INVALID_FILE_ATTRIBUTES
           && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static char *
win_resolve_parent_search_cmd(const char *cmd)
{
    if (!cmd || !*cmd || win_cmd_has_path_component(cmd)) {
        return nullptr;
    }

    char  path[MAX_PATH];
    DWORD n = SearchPathA(nullptr, cmd, ".exe", MAX_PATH, path, nullptr);
    if (n == 0 || n >= MAX_PATH) {
        return nullptr;
    }

    char *out = n00b_alloc_array(char, (size_t)n + 1);
    if (!out) {
        return nullptr;
    }
    memcpy(out, path, (size_t)n + 1);
    return out;
}

static const char *
win_application_name(n00b_subproc_t *sp, char **owned)
{
    *owned = nullptr;
    const char *cmd = n00b_unicode_str_to_cstr(sp->cmd);

    if (sp->env) {
        return cmd;
    }
    if (!(sp->flags & N00B_SUBPROC_RAW_ARGV)) {
        return nullptr;
    }

    *owned = win_resolve_parent_search_cmd(cmd);
    return *owned ? *owned : cmd;
}

static void
win_drain_captures(n00b_subproc_t *sp)
{
    if (!sp) {
        return;
    }

    n00b_subproc_drain_capture(sp->cap_stdout, sp->buf_stdout);
    if (sp->cap_stderr && sp->cap_stderr != sp->cap_stdout) {
        n00b_subproc_drain_capture(sp->cap_stderr, sp->buf_stderr);
    }
    n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);
}

static n00b_conduit_topic_t(n00b_buffer_t *) *
win_new_buffer_topic(n00b_conduit_t *c)
{
    if (!c) {
        return nullptr;
    }

    uint64_t id = n00b_atomic_add(&c->next_user_event_id, 1) + 1;
    return n00b_conduit_topic_init(n00b_buffer_t *, c,
                                   N00B_CONDUIT_URI_USER_EVENT(id));
}

static void
win_publish_buffer(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
                   n00b_buffer_t *payload)
{
    if (!topic || !payload || payload->byte_len == 0) {
        return;
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    n00b_allocator_t *alloc = base->conduit ? base->conduit->allocator : nullptr;
    n00b_conduit_message_t(n00b_buffer_t *) *msg = n00b_alloc_with_opts(
        n00b_conduit_message_t(n00b_buffer_t *),
        &(n00b_alloc_opts_t){.allocator = alloc});
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload           = payload;
    n00b_conduit_topic_deliver_msg(n00b_buffer_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static void
win_publish_bytes(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
                  char *data,
                  DWORD n)
{
    if (!topic || !data || n == 0) {
        return;
    }
    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    n00b_allocator_t *alloc = base->conduit ? base->conduit->allocator : nullptr;
    win_publish_buffer(topic, n00b_buffer_from_bytes(data, (int64_t)n,
                                                     .allocator = alloc));
}

static bool
win_pipe_error_is_eof(DWORD err)
{
    return err == ERROR_BROKEN_PIPE
        || err == ERROR_HANDLE_EOF
        || err == ERROR_INVALID_HANDLE
        || err == ERROR_NO_DATA
        || err == ERROR_PIPE_NOT_CONNECTED;
}

static int
win_errno_from_error(DWORD err)
{
    switch (err) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
        return ENOENT;
    case ERROR_DIRECTORY:
        return ENOTDIR;
    case ERROR_ACCESS_DENIED:
        return EACCES;
    case ERROR_TOO_MANY_OPEN_FILES:
        return EMFILE;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return ENOMEM;
    case ERROR_BAD_ENVIRONMENT:
        return E2BIG;
    case ERROR_BAD_EXE_FORMAT:
        return ENOEXEC;
    default:
        return EINVAL;
    }
}

static int
win_last_errno(void)
{
    return win_errno_from_error(GetLastError());
}

static bool
win_drain_pipe(HANDLE pipe, n00b_conduit_topic_t(n00b_buffer_t *) *topic)
{
    if (!pipe) {
        return true;
    }

    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr)) {
            return win_pipe_error_is_eof(GetLastError());
        }
        if (avail == 0) {
            return false;
        }

        char  buf[4096];
        DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
        DWORD got = 0;
        if (!ReadFile(pipe, buf, want, &got, nullptr)) {
            return win_pipe_error_is_eof(GetLastError());
        }
        if (got == 0) {
            return false;
        }
        win_publish_bytes(topic, buf, got);
    }
}

static void win_mark_stdout_eof(n00b_subproc_t *sp);
static void win_mark_stderr_eof(n00b_subproc_t *sp);

static void
win_drain_output_pipes(n00b_subproc_t *sp)
{
    if (!sp) {
        return;
    }
    if (!win_state(sp)->stdout_eof
        && win_drain_pipe(win_state(sp)->stdout_read,
                          (n00b_conduit_topic_t(n00b_buffer_t *) *)
                              win_state(sp)->stdout_topic)) {
        win_mark_stdout_eof(sp);
    }
    if (!win_state(sp)->stderr_eof
        && win_drain_pipe(win_state(sp)->stderr_read,
                          (n00b_conduit_topic_t(n00b_buffer_t *) *)
                              win_state(sp)->stderr_topic)) {
        win_mark_stderr_eof(sp);
    }
    win_drain_captures(sp);
}

static bool
win_pipe_has_pending_bytes(HANDLE pipe)
{
    if (!pipe) {
        return false;
    }

    DWORD avail = 0;
    if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr)) {
        return false;
    }
    return avail > 0;
}

static bool
win_output_has_pending_bytes(n00b_subproc_t *sp)
{
    if (!sp) {
        return false;
    }
    return win_pipe_has_pending_bytes(win_state(sp)->stdout_read)
           || win_pipe_has_pending_bytes(win_state(sp)->stderr_read);
}

static bool
win_output_readers_closed(n00b_subproc_t *sp)
{
    if (!sp) {
        return true;
    }

    bool stdout_closed = win_state(sp)->stdout_eof || !win_state(sp)->stdout_read;
    bool stderr_closed = win_state(sp)->stderr_eof || !win_state(sp)->stderr_read;
    return stdout_closed && stderr_closed;
}

static void
win_drain_output_until_quiet(n00b_subproc_t *sp, uint64_t quiet_ms, uint64_t max_ms)
{
    uint64_t deadline = base_monotonic_ms() + max_ms;
    uint64_t quiet_since = 0;
    bool saw_pending = false;

    for (;;) {
        bool pending_before = win_output_has_pending_bytes(sp);
        saw_pending = saw_pending || pending_before;
        win_drain_output_pipes(sp);
        bool pending_after = win_output_has_pending_bytes(sp);
        saw_pending = saw_pending || pending_after;

        if (win_output_readers_closed(sp)) {
            break;
        }

        uint64_t now = base_monotonic_ms();
        if (!pending_before && !pending_after) {
            if (!saw_pending || quiet_ms == 0) {
                break;
            }
            if (quiet_since == 0) {
                quiet_since = now;
            }
            if (now - quiet_since >= quiet_ms) {
                break;
            }
        }
        else {
            quiet_since = 0;
        }

        if (now >= deadline) {
            break;
        }
        base_nanosleep_ns(10000000ULL);
    }

    win_drain_output_pipes(sp);
}

static void
win_close_pseudoconsole_after_drain(n00b_subproc_t *sp)
{
    if (!sp || !win_state(sp)->pseudoconsole) {
        return;
    }
    win_drain_output_until_quiet(sp, 0, 100);
    ClosePseudoConsole((HPCON)win_state(sp)->pseudoconsole);
    win_state(sp)->pseudoconsole = nullptr;
    win_drain_output_until_quiet(sp, 25, 250);
}

static void
win_close_handle(HANDLE *handle)
{
    if (handle && *handle) {
        CloseHandle(*handle);
        *handle = nullptr;
    }
}

static void
win_add_unique_inherited_handle(HANDLE handles[3], DWORD *count, HANDLE handle)
{
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    for (DWORD i = 0; i < *count; i++) {
        if (handles[i] == handle) {
            return;
        }
    }

    if (*count < 3) {
        handles[(*count)++] = handle;
    }
}

static bool
win_prepare_handle_list_attribute(HANDLE handles[3],
                                  DWORD  count,
                                  LPPROC_THREAD_ATTRIBUTE_LIST *attrs)
{
    *attrs = nullptr;
    if (count == 0) {
        return true;
    }

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    if (attr_size == 0) {
        return false;
    }

    *attrs = n00b_alloc_array(uint8_t, attr_size);
    if (!*attrs) {
        return false;
    }

    if (!InitializeProcThreadAttributeList(*attrs, 1, 0, &attr_size)
        || !UpdateProcThreadAttribute(*attrs,
                                      0,
                                      PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                      handles,
                                      count * sizeof(HANDLE),
                                      nullptr,
                                      nullptr)) {
        DeleteProcThreadAttributeList(*attrs);
        n00b_free(*attrs);
        *attrs = nullptr;
        return false;
    }

    return true;
}

static bool
win_topic_closed(n00b_conduit_topic_base_t *topic)
{
    return !topic || n00b_atomic_load(&topic->state) == N00B_CONDUIT_TOPIC_CLOSED;
}

static void
win_close_topic_if_open(n00b_conduit_topic_base_t *topic)
{
    if (!win_topic_closed(topic)) {
        n00b_conduit_topic_close(topic);
    }
}

static void
win_mark_stdout_eof(n00b_subproc_t *sp)
{
    if (!sp || win_state(sp)->stdout_eof) {
        return;
    }

    win_state(sp)->stdout_eof = true;
    n00b_subproc_note_stdout_done(sp);
    if (win_state(sp)->stdout_topic) {
        win_close_topic_if_open(win_state(sp)->stdout_topic);
    }
    else {
        win_close_topic_if_open(sp->eff_stdout_topic);
    }
    win_close_handle(&win_state(sp)->stdout_read);
}

static void
win_mark_stderr_eof(n00b_subproc_t *sp)
{
    if (!sp || win_state(sp)->stderr_eof) {
        return;
    }

    win_state(sp)->stderr_eof = true;
    n00b_subproc_note_stderr_done(sp);
    if (win_state(sp)->stderr_topic && win_state(sp)->stderr_topic != win_state(sp)->stdout_topic) {
        win_close_topic_if_open(win_state(sp)->stderr_topic);
    }
    else if (sp->eff_stderr_topic && sp->eff_stderr_topic != sp->eff_stdout_topic) {
        win_close_topic_if_open(sp->eff_stderr_topic);
    }
    win_close_handle(&win_state(sp)->stderr_read);
}

static void
win_wait_output_topics(n00b_subproc_t *sp)
{
    uint64_t deadline = base_monotonic_ms() + 500;
    do {
        win_drain_captures(sp);
        if (win_topic_closed(sp->eff_stdout_topic)
            && win_topic_closed(sp->eff_stderr_topic)) {
            break;
        }
        base_nanosleep_ns(10000000ULL);
    } while (base_monotonic_ms() < deadline);
    win_drain_captures(sp);
}

static void
win_mark_remaining_output_done(n00b_subproc_t *sp)
{
    if (!sp) {
        return;
    }
    if (!win_state(sp)->stdout_eof
        && (win_state(sp)->stdout_read
            || win_state(sp)->stdout_topic
            || sp->eff_stdout_topic)) {
        win_mark_stdout_eof(sp);
    }
    if (!win_state(sp)->stderr_eof
        && (win_state(sp)->stderr_read
            || (win_state(sp)->stderr_topic
                && win_state(sp)->stderr_topic != win_state(sp)->stdout_topic)
            || (sp->eff_stderr_topic
                && sp->eff_stderr_topic != sp->eff_stdout_topic))) {
        win_mark_stderr_eof(sp);
    }
}

static uint64_t
win_write_stdin_buffer(n00b_subproc_t *sp, n00b_buffer_t *data)
{
    if (!sp || !win_state(sp)->stdin_write || !data || data->byte_len == 0) {
        return 0;
    }

    DWORD written = 0;
    if (!WriteFile(win_state(sp)->stdin_write, data->data, (DWORD)data->byte_len,
                   &written, nullptr)) {
        return UINT64_MAX;
    }
    return (uint64_t)written;
}

static uint64_t
win_drain_stdin_xform_outputs(n00b_subproc_t *sp, bool wait)
{
    if (!sp || !win_state(sp)->stdin_xform_inbox) {
        return 0;
    }

    uint64_t total    = 0;
    uint64_t deadline = base_monotonic_ms() + 500;

    do {
        bool saw_message = false;
        n00b_conduit_message_t(n00b_buffer_t *) *msg;

        while ((msg = n00b_conduit_inbox_pop_msg(
                    n00b_buffer_t *, win_state(sp)->stdin_xform_inbox)) != nullptr) {
            saw_message = true;
            uint64_t n = win_write_stdin_buffer(sp, msg->payload);
            if (n == UINT64_MAX) {
                return UINT64_MAX;
            }
            total += n;
        }

        n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);
        if (!wait || saw_message
            || win_topic_closed((n00b_conduit_topic_base_t *)sp->stdin_obs_topic)) {
            break;
        }
        base_nanosleep_ns(10000000ULL);
    } while (base_monotonic_ms() < deadline);

    return total;
}

static void
win_finish_stdin(n00b_subproc_t *sp)
{
    if (!sp) {
        return;
    }
    if (win_state(sp)->stdin_raw_topic) {
        n00b_conduit_topic_close(win_state(sp)->stdin_raw_topic);
        win_drain_stdin_xform_outputs(sp, true);
    }
    else if (sp->stdin_obs_topic) {
        n00b_conduit_topic_close((n00b_conduit_topic_base_t *)sp->stdin_obs_topic);
    }
    n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);
    sp->done_flags |= N00B_SUBPROC_DONE_F_STDIN_DONE;
}

static void
win_send_stdin_bytes(n00b_subproc_t *sp, char *data, DWORD n)
{
    if (!sp || !data || n == 0) {
        return;
    }

    n00b_allocator_t *alloc = sp->conduit ? sp->conduit->allocator : nullptr;
    n00b_buffer_t *buf = n00b_buffer_from_bytes(data, (int64_t)n,
                                                .allocator = alloc);
    if (n00b_subproc_xforms_requested(sp->stdin_xforms)) {
        win_publish_buffer(
            (n00b_conduit_topic_t(n00b_buffer_t *) *)win_state(sp)->stdin_raw_topic,
            buf);
        win_drain_stdin_xform_outputs(sp, true);
    }
    else {
        uint64_t written = win_write_stdin_buffer(sp, buf);
        if (written != UINT64_MAX && sp->stdin_obs_topic) {
            n00b_buffer_t *observed = n00b_buffer_from_bytes(
                data, (int64_t)written, .allocator = alloc);
            win_publish_buffer(sp->stdin_obs_topic, observed);
        }
    }
    n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);
}

static void
win_proxy_parent_stdin(n00b_subproc_t *sp)
{
    if (!sp || !(sp->flags & N00B_SUBPROC_PROXY_STDIN) || !win_state(sp)->stdin_write) {
        return;
    }

    HANDLE parent_stdin = GetStdHandle(STD_INPUT_HANDLE);
    if (!parent_stdin || parent_stdin == INVALID_HANDLE_VALUE) {
        return;
    }

    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(parent_stdin, nullptr, 0, nullptr, &avail, nullptr)
            || avail == 0) {
            return;
        }

        char  buf[4096];
        DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
        DWORD got  = 0;
        if (!ReadFile(parent_stdin, buf, want, &got, nullptr) || got == 0) {
            return;
        }
        win_send_stdin_bytes(sp, buf, got);
    }
}

static COORD
win_pty_size(n00b_subproc_t *sp)
{
    COORD size;
    size.X = (short)((sp && sp->dimensions.ws_col) ? sp->dimensions.ws_col : 80);
    size.Y = (short)((sp && sp->dimensions.ws_row) ? sp->dimensions.ws_row : 24);
    return size;
}

static bool
win_create_pseudoconsole(n00b_subproc_t *sp,
                         HANDLE *pty_input_read,
                         HANDLE *pty_output_write)
{
    SECURITY_ATTRIBUTES sa = {
        .nLength              = sizeof(sa),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle       = FALSE,
    };

    if (!CreatePipe(pty_input_read, &win_state(sp)->stdin_write, &sa, 0)
        || !CreatePipe(&win_state(sp)->stdout_read, pty_output_write, &sa, 0)) {
        return false;
    }

    HPCON pc = nullptr;
    HRESULT hr = CreatePseudoConsole(win_pty_size(sp),
                                     *pty_input_read,
                                     *pty_output_write,
                                     0,
                                     &pc);
    if (hr < 0 || !pc) {
        return false;
    }

    win_state(sp)->pseudoconsole = pc;
    win_state(sp)->stderr_read   = nullptr;
    return true;
}

static bool
win_stdin_pipe_requested(n00b_subproc_t *sp)
{
    uint32_t f = sp->flags;
    return (f & (N00B_SUBPROC_CAP_STDIN
                 | N00B_SUBPROC_PROXY_STDIN
                 | N00B_SUBPROC_CLOSE_STDIN))
           || sp->stdin_inject
           || n00b_subproc_subs_requested(sp->stdin_subs)
           || n00b_subproc_xforms_requested(sp->stdin_xforms);
}

static bool
win_prepare_child_stdin(n00b_subproc_t     *sp,
                        SECURITY_ATTRIBUTES *sa,
                        HANDLE             *child_stdin_read)
{
    if (win_stdin_pipe_requested(sp)) {
        return CreatePipe(child_stdin_read, &win_state(sp)->stdin_write, sa, 0)
               && SetHandleInformation(win_state(sp)->stdin_write, HANDLE_FLAG_INHERIT, 0);
    }

    HANDLE parent_stdin = GetStdHandle(STD_INPUT_HANDLE);
    if (parent_stdin && parent_stdin != INVALID_HANDLE_VALUE) {
        HANDLE current_process = GetCurrentProcess();
        if (DuplicateHandle(current_process,
                            parent_stdin,
                            current_process,
                            child_stdin_read,
                            0,
                            TRUE,
                            DUPLICATE_SAME_ACCESS)) {
            return true;
        }
    }

    // STARTF_USESTDHANDLES still needs a valid stdin handle when only
    // stdout/stderr are redirected.
    HANDLE null_stdin = CreateFileW(L"NUL",
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    sa,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (null_stdin == INVALID_HANDLE_VALUE) {
        *child_stdin_read = nullptr;
        return false;
    }

    *child_stdin_read = null_stdin;
    return true;
}

static bool
win_stdout_pipe_requested(n00b_subproc_t *sp)
{
    uint32_t f = sp->flags;
    bool merge = (f & (N00B_SUBPROC_MERGE_OUTPUT | N00B_SUBPROC_USE_PTY)) != 0;

    return (f & N00B_SUBPROC_CAP_STDOUT)
           || (merge && (f & N00B_SUBPROC_CAP_STDERR))
           || (f & N00B_SUBPROC_PROXY_STDOUT)
           || (merge && (f & N00B_SUBPROC_PROXY_STDERR))
           || n00b_subproc_subs_requested(sp->stdout_subs)
           || n00b_subproc_xforms_requested(sp->stdout_xforms);
}

static bool
win_stderr_pipe_requested(n00b_subproc_t *sp)
{
    uint32_t f = sp->flags;
    bool merge = (f & (N00B_SUBPROC_MERGE_OUTPUT | N00B_SUBPROC_USE_PTY)) != 0;

    return !merge
           && ((f & N00B_SUBPROC_CAP_STDERR)
               || (f & N00B_SUBPROC_PROXY_STDERR)
               || n00b_subproc_subs_requested(sp->stderr_subs)
               || n00b_subproc_xforms_requested(sp->stderr_xforms));
}

static bool
win_duplicate_std_handle(DWORD                std_id,
                         DWORD                null_access,
                         SECURITY_ATTRIBUTES *sa,
                         HANDLE              *child_handle)
{
    HANDLE parent_handle = GetStdHandle(std_id);
    if (parent_handle && parent_handle != INVALID_HANDLE_VALUE) {
        HANDLE current_process = GetCurrentProcess();
        if (DuplicateHandle(current_process,
                            parent_handle,
                            current_process,
                            child_handle,
                            0,
                            TRUE,
                            DUPLICATE_SAME_ACCESS)) {
            return true;
        }
    }

    HANDLE null_handle = CreateFileW(L"NUL",
                                     null_access,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     sa,
                                     OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL,
                                     nullptr);
    if (null_handle == INVALID_HANDLE_VALUE) {
        *child_handle = nullptr;
        return false;
    }

    *child_handle = null_handle;
    return true;
}

static void
win_wire_io(n00b_subproc_t *sp)
{
    uint32_t f     = sp->flags;
    bool     merge = (f & (N00B_SUBPROC_MERGE_OUTPUT | N00B_SUBPROC_USE_PTY)) != 0;

    bool need_stdout = win_stdout_pipe_requested(sp);
    bool need_stderr = win_stderr_pipe_requested(sp);
    bool need_stdin = (f & N00B_SUBPROC_CAP_STDIN)
                      || (f & N00B_SUBPROC_PROXY_STDIN)
                      || n00b_subproc_subs_requested(sp->stdin_subs)
                      || n00b_subproc_xforms_requested(sp->stdin_xforms);

    if (need_stdout) {
        n00b_conduit_topic_t(n00b_buffer_t *) *stdout_raw =
            win_new_buffer_topic(sp->conduit);
        n00b_conduit_topic_t(n00b_buffer_t *) *stdout_topic =
            n00b_subproc_apply_xform_chain(sp->conduit, stdout_raw, sp->stdout_xforms);
        win_state(sp)->stdout_topic = (n00b_conduit_topic_base_t *)stdout_raw;
        sp->eff_stdout_topic = (n00b_conduit_topic_base_t *)stdout_topic;

        if (f & N00B_SUBPROC_CAP_STDOUT) {
            sp->cap_stdout = n00b_subproc_wire_capture(sp->conduit, stdout_topic,
                                              &sp->buf_stdout,
                                              &sp->cap_stdout_sub);
        }
        if (merge && (f & N00B_SUBPROC_CAP_STDERR)) {
            if (!(f & N00B_SUBPROC_CAP_STDOUT)) {
                sp->cap_stdout = n00b_subproc_wire_capture(sp->conduit, stdout_topic,
                                                  &sp->buf_stdout,
                                                  &sp->cap_stdout_sub);
            }
            sp->cap_stderr = sp->cap_stdout;
            sp->buf_stderr = sp->buf_stdout;
        }

        n00b_subproc_wire_user_subs(sp->conduit, stdout_topic, sp->stdout_subs);

        if (f & N00B_SUBPROC_PROXY_STDOUT) {
            n00b_conduit_topic_t(n00b_buffer_t *) *proxy_src =
                n00b_subproc_apply_xform_chain(sp->conduit, stdout_topic, sp->proxy_xforms);
            auto r = n00b_conduit_fd_writer_new(sp->conduit, proxy_src, 1);
            if (n00b_result_is_ok(r)) {
                sp->proxy_stdout = n00b_result_get(r);
            }
        }

        if (merge && (f & N00B_SUBPROC_PROXY_STDERR)) {
            n00b_conduit_topic_t(n00b_buffer_t *) *proxy_src =
                n00b_subproc_apply_xform_chain(sp->conduit, stdout_topic, sp->proxy_xforms);
            auto r = n00b_conduit_fd_writer_new(sp->conduit, proxy_src, 2);
            if (n00b_result_is_ok(r)) {
                sp->proxy_stderr = n00b_result_get(r);
            }
        }
    }

    if (need_stderr) {
        n00b_conduit_topic_t(n00b_buffer_t *) *stderr_raw =
            win_new_buffer_topic(sp->conduit);
        n00b_conduit_topic_t(n00b_buffer_t *) *stderr_topic =
            n00b_subproc_apply_xform_chain(sp->conduit, stderr_raw, sp->stderr_xforms);
        win_state(sp)->stderr_topic = (n00b_conduit_topic_base_t *)stderr_raw;
        sp->eff_stderr_topic = (n00b_conduit_topic_base_t *)stderr_topic;

        if (f & N00B_SUBPROC_CAP_STDERR) {
            sp->cap_stderr = n00b_subproc_wire_capture(sp->conduit, stderr_topic,
                                              &sp->buf_stderr,
                                              &sp->cap_stderr_sub);
        }

        n00b_subproc_wire_user_subs(sp->conduit, stderr_topic, sp->stderr_subs);

        if (f & N00B_SUBPROC_PROXY_STDERR) {
            n00b_conduit_topic_t(n00b_buffer_t *) *proxy_src =
                n00b_subproc_apply_xform_chain(sp->conduit, stderr_topic, sp->proxy_xforms);
            auto r = n00b_conduit_fd_writer_new(sp->conduit, proxy_src, 2);
            if (n00b_result_is_ok(r)) {
                sp->proxy_stderr = n00b_result_get(r);
            }
        }
    }

    if (need_stdin) {
        n00b_conduit_topic_t(n00b_buffer_t *) *stdin_raw =
            win_new_buffer_topic(sp->conduit);
        n00b_conduit_topic_t(n00b_buffer_t *) *stdin_topic =
            n00b_subproc_apply_xform_chain(sp->conduit, stdin_raw, sp->stdin_xforms);
        win_state(sp)->stdin_raw_topic = (n00b_conduit_topic_base_t *)stdin_raw;
        sp->stdin_obs_topic     = stdin_topic;

        if (n00b_subproc_xforms_requested(sp->stdin_xforms)) {
            win_state(sp)->stdin_xform_inbox =
                n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                    &(n00b_alloc_opts_t){.allocator = sp->conduit->allocator});
            n00b_conduit_inbox_init(n00b_buffer_t *,
                                    win_state(sp)->stdin_xform_inbox,
                                    sp->conduit,
                                    N00B_CONDUIT_BP_UNBOUNDED,
                                    0);
            win_state(sp)->stdin_xform_sub = n00b_conduit_subscribe(
                n00b_buffer_t *, stdin_topic, win_state(sp)->stdin_xform_inbox,
                .operations = N00B_CONDUIT_OP_ALL);
        }

        if (f & N00B_SUBPROC_CAP_STDIN) {
            sp->cap_stdin = n00b_subproc_wire_capture(sp->conduit, sp->stdin_obs_topic,
                                             &sp->buf_stdin,
                                             &sp->cap_stdin_sub);
        }
        n00b_subproc_wire_user_subs(sp->conduit,
                                    sp->stdin_obs_topic,
                                    sp->stdin_subs);
    }
}

static void
win_close_topics(n00b_subproc_t *sp)
{
    if (!sp) {
        return;
    }
    if (win_state(sp)->stdout_topic) {
        win_close_topic_if_open(win_state(sp)->stdout_topic);
    }
    else if (sp->eff_stdout_topic) {
        win_close_topic_if_open(sp->eff_stdout_topic);
    }
    if (win_state(sp)->stderr_topic && win_state(sp)->stderr_topic != win_state(sp)->stdout_topic) {
        win_close_topic_if_open(win_state(sp)->stderr_topic);
    }
    else if (sp->eff_stderr_topic && sp->eff_stderr_topic != sp->eff_stdout_topic) {
        win_close_topic_if_open(sp->eff_stderr_topic);
    }
    if (sp->stdin_obs_topic) {
        win_finish_stdin(sp);
    }
}

void
n00b_subproc_init(n00b_subproc_t *sp) _kargs
{
    n00b_string_t                             *cmd;
    n00b_conduit_t                            *conduit         = nullptr;
    n00b_conduit_io_backend_t                 *io              = nullptr;
    n00b_array_t(n00b_string_t *)              *args            = nullptr;
    n00b_array_t(n00b_string_t *)              *env             = nullptr;
    bool                                       capture         = false;
    bool                                       capture_stdin   = false;
    bool                                       capture_stdout  = false;
    bool                                       capture_stderr  = false;
    bool                                       proxy           = false;
    bool                                       proxy_stdin     = false;
    bool                                       proxy_stdout    = false;
    bool                                       proxy_stderr    = false;
    bool                                       merge           = true;
    bool                                       pty             = false;
    bool                                       raw_argv        = false;
    bool                                       err_pty         = false;
    bool                                       handle_win_size = true;
    n00b_buffer_t                             *stdin_inject    = nullptr;
    bool                                       close_stdin     = false;
    n00b_string_t                             *cwd;
    struct termios                            *termcap         = nullptr;
    n00b_duration_t                           *timeout         = nullptr;
    n00b_subproc_timeout_t                     timeout_policy  = N00B_SUBPROC_TIMEOUT_SIGTERM;
    n00b_subproc_done_t                        done_condition  = N00B_SUBPROC_DONE_IO_DRAINED;
    n00b_subproc_done_fn_t                     done_fn         = nullptr;
    void                                      *done_fn_ctx    = nullptr;
    n00b_pre_exec_hook_t                       pre_exec_hook   = nullptr;
    void                                      *hook_param     = nullptr;
    n00b_array_t(void *)                      *stdout_xforms  = nullptr;
    n00b_array_t(void *)                      *stderr_xforms  = nullptr;
    n00b_array_t(void *)                      *proxy_xforms   = nullptr;
    n00b_array_t(void *)                      *stdin_xforms   = nullptr;
    n00b_array_t(n00b_subproc_buf_inbox_t *)   *stdout_subs    = nullptr;
    n00b_array_t(n00b_subproc_buf_inbox_t *)   *stderr_subs    = nullptr;
    n00b_array_t(n00b_subproc_buf_inbox_t *)   *stdin_subs     = nullptr;
}
{
    sp->cmd            = cmd;
    sp->conduit        = conduit;
    sp->io             = io;
    sp->args           = args;
    sp->env            = env;
    sp->stdin_inject   = stdin_inject;
    sp->cwd            = cwd;
    sp->termcap        = termcap;
    sp->timeout        = timeout;
    sp->timeout_policy = timeout_policy;
    sp->done_condition = done_condition;
    sp->done_fn        = done_fn;
    sp->done_fn_ctx    = done_fn_ctx;
    sp->pre_exec_hook  = pre_exec_hook;
    sp->hook_param     = hook_param;
    sp->stdout_xforms  = stdout_xforms;
    sp->stderr_xforms  = stderr_xforms;
    sp->proxy_xforms   = proxy_xforms;
    sp->stdin_xforms   = stdin_xforms;
    sp->stdout_subs    = stdout_subs;
    sp->stderr_subs    = stderr_subs;
    sp->stdin_subs     = stdin_subs;

    uint32_t f = 0;
    if (capture)        f |= N00B_SUBPROC_CAP_ALL;
    if (capture_stdin)  f |= N00B_SUBPROC_CAP_STDIN;
    if (capture_stdout) f |= N00B_SUBPROC_CAP_STDOUT;
    if (capture_stderr) f |= N00B_SUBPROC_CAP_STDERR;
    if (proxy)          f |= N00B_SUBPROC_PROXY_ALL;
    if (proxy_stdin)    f |= N00B_SUBPROC_PROXY_STDIN;
    if (proxy_stdout)   f |= N00B_SUBPROC_PROXY_STDOUT;
    if (proxy_stderr)   f |= N00B_SUBPROC_PROXY_STDERR;
    if (merge)          f |= N00B_SUBPROC_MERGE_OUTPUT;
    if (pty)            f |= N00B_SUBPROC_USE_PTY;
    if (raw_argv)       f |= N00B_SUBPROC_RAW_ARGV;
    if (err_pty)        f |= N00B_SUBPROC_PTY_STDERR;
    if (handle_win_size) f |= N00B_SUBPROC_HANDLE_WINSIZE;
    if (close_stdin)    f |= N00B_SUBPROC_CLOSE_STDIN;
    sp->flags = f;

    sp->pid                = n00b_option_none(pid_t);
    sp->gate               = n00b_option_none(int);
    sp->exit_status        = n00b_option_none(int);
    sp->term_signal        = n00b_option_none(int);
    sp->stdin_owner        = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->stdout_owner       = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->stderr_owner       = n00b_option_none(n00b_conduit_fd_owner_t *);
    sp->parent_stdin_owner = n00b_option_none(n00b_conduit_fd_owner_t *);

    sp->buf_stdin  = &empty_buf_sentinel;
    sp->buf_stdout = &empty_buf_sentinel;
    sp->buf_stderr = &empty_buf_sentinel;

    atomic_store(&sp->spawned, false);
    atomic_store(&sp->exited, false);
    sp->cap_stdout      = nullptr;
    sp->cap_stderr      = nullptr;
    sp->cap_stdin       = nullptr;
    sp->stdin_obs_topic = nullptr;
    win_state(sp)->stdout_topic = nullptr;
    win_state(sp)->stderr_topic = nullptr;
    win_state(sp)->stdin_raw_topic = nullptr;
    win_state(sp)->stdin_xform_inbox = nullptr;
    win_state(sp)->stdin_xform_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    sp->eff_stdout_topic = nullptr;
    sp->eff_stderr_topic = nullptr;
    sp->closed          = false;
    sp->errored         = false;
    sp->timed_out       = false;
    sp->termcap_saved   = false;
    win_state(sp)->process     = nullptr;
    win_state(sp)->thread      = nullptr;
    win_state(sp)->stdin_write = nullptr;
    win_state(sp)->stdout_read = nullptr;
    win_state(sp)->stderr_read = nullptr;
    win_state(sp)->pseudoconsole = nullptr;
    win_state(sp)->stdout_eof = false;
    win_state(sp)->stderr_eof = false;
    sp->done_flags     = 0;
    sp->required_mask  = 0;
}

n00b_result_t(bool)
n00b_subproc_spawn(n00b_subproc_t *sp)
{
    if (!sp || !sp->cmd || !sp->conduit) {
        return n00b_result_err(bool, EINVAL);
    }
    if (atomic_load(&sp->spawned)) {
        return n00b_result_err(bool, EALREADY);
    }
    SECURITY_ATTRIBUTES sa = {
        .nLength              = sizeof(sa),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle       = TRUE,
    };

    bool use_pty = (sp->flags & N00B_SUBPROC_USE_PTY) != 0;
    HANDLE child_stdin_read = nullptr;
    HANDLE child_stdout_write = nullptr;
    HANDLE child_stderr_write = nullptr;

    STARTUPINFOA si;
    STARTUPINFOEXA si_ex;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&si_ex, 0, sizeof(si_ex));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    LPPROC_THREAD_ATTRIBUTE_LIST attrs = nullptr;
    SIZE_T attr_size = 0;
    DWORD creation_flags = 0;
    BOOL inherit_handles = TRUE;
    bool use_startup_ex = false;
    int spawn_errno = ENOENT;
    char *cmdline = nullptr;
    char *env_block = nullptr;
    char *app_name_alloc = nullptr;

#define WIN_SPAWN_FAIL(e) \
    do {                  \
        spawn_errno = (e);\
        goto spawn_fail;  \
    } while (0)

    if (use_pty) {
        if (!win_create_pseudoconsole(sp, &child_stdin_read, &child_stdout_write)) {
            WIN_SPAWN_FAIL(win_last_errno());
        }

        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        attrs = n00b_alloc_array(uint8_t, attr_size);
        if (!attrs) {
            WIN_SPAWN_FAIL(ENOMEM);
        }
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)
            || !UpdateProcThreadAttribute(attrs, 0,
                                          PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                          win_state(sp)->pseudoconsole,
                                          sizeof(HPCON),
                                          nullptr,
                                          nullptr)) {
            WIN_SPAWN_FAIL(win_last_errno());
        }

        si_ex.StartupInfo.cb = sizeof(si_ex);
        si_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si_ex.lpAttributeList = attrs;
        creation_flags = EXTENDED_STARTUPINFO_PRESENT;
        inherit_handles = FALSE;
        use_startup_ex = true;
    }
    else {
        bool need_stdout_pipe = win_stdout_pipe_requested(sp);
        bool need_stderr_pipe = win_stderr_pipe_requested(sp);

        if (!win_prepare_child_stdin(sp, &sa, &child_stdin_read)
            || (need_stdout_pipe
                    ? (!CreatePipe(&win_state(sp)->stdout_read,
                                   &child_stdout_write,
                                   &sa,
                                   0)
                       || !SetHandleInformation(win_state(sp)->stdout_read,
                                                HANDLE_FLAG_INHERIT,
                                                0))
                    : !win_duplicate_std_handle(STD_OUTPUT_HANDLE,
                                                GENERIC_WRITE,
                                                &sa,
                                                &child_stdout_write))) {
            WIN_SPAWN_FAIL(win_last_errno());
        }

        if ((sp->flags & N00B_SUBPROC_MERGE_OUTPUT) && need_stdout_pipe) {
            child_stderr_write = child_stdout_write;
        }
        else if (need_stderr_pipe
                 ? (!CreatePipe(&win_state(sp)->stderr_read,
                                &child_stderr_write,
                                &sa,
                                0)
                    || !SetHandleInformation(win_state(sp)->stderr_read,
                                             HANDLE_FLAG_INHERIT,
                                             0))
                 : !win_duplicate_std_handle(STD_ERROR_HANDLE,
                                             GENERIC_WRITE,
                                             &sa,
                                             &child_stderr_write)) {
            WIN_SPAWN_FAIL(win_last_errno());
        }

        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = child_stdin_read;
        si.hStdOutput = child_stdout_write;
        si.hStdError = child_stderr_write;

        HANDLE inherited_handles[3];
        DWORD inherited_handle_count = 0;
        win_add_unique_inherited_handle(inherited_handles,
                                        &inherited_handle_count,
                                        child_stdin_read);
        win_add_unique_inherited_handle(inherited_handles,
                                        &inherited_handle_count,
                                        child_stdout_write);
        win_add_unique_inherited_handle(inherited_handles,
                                        &inherited_handle_count,
                                        child_stderr_write);
        if (!win_prepare_handle_list_attribute(inherited_handles,
                                               inherited_handle_count,
                                               &attrs)) {
            WIN_SPAWN_FAIL(win_last_errno());
        }
        si_ex.StartupInfo = si;
        si_ex.StartupInfo.cb = sizeof(si_ex);
        si_ex.lpAttributeList = attrs;
        creation_flags = EXTENDED_STARTUPINFO_PRESENT;
        inherit_handles = TRUE;
        use_startup_ex = true;
    }

    cmdline = win_build_cmdline(sp);
    env_block = win_build_env_block(sp->env);
    const char *cwd = sp->cwd ? n00b_unicode_str_to_cstr(sp->cwd) : nullptr;
    if (!cmdline) {
        WIN_SPAWN_FAIL((sp->flags & N00B_SUBPROC_RAW_ARGV)
                       && (!sp->args || sp->args->len == 0)
                           ? EINVAL
                           : ENOMEM);
    }
    if (sp->env && !env_block) {
        WIN_SPAWN_FAIL(ENOMEM);
    }
    if (!win_cwd_is_valid(cwd)) {
        WIN_SPAWN_FAIL(ENOTDIR);
    }
    const char *app_name = win_application_name(sp, &app_name_alloc);

    if (sp->pre_exec_hook) {
        sp->pre_exec_hook(sp->hook_param);
    }

    BOOL ok = CreateProcessA(app_name,
                             cmdline,
                             nullptr,
                             nullptr,
                             inherit_handles,
                             creation_flags,
                             env_block,
                             cwd,
                             use_startup_ex ? &si_ex.StartupInfo : &si,
                             &pi);
    int create_errno = win_last_errno();
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        n00b_free(attrs);
        attrs = nullptr;
    }
    n00b_free(cmdline);
    n00b_free(env_block);
    n00b_free(app_name_alloc);
    cmdline = nullptr;
    env_block = nullptr;
    app_name_alloc = nullptr;
    if (!ok) {
        WIN_SPAWN_FAIL(create_errno);
    }

    CloseHandle(child_stdin_read);
    CloseHandle(child_stdout_write);
    if (!use_pty && child_stderr_write && child_stderr_write != child_stdout_write) {
        CloseHandle(child_stderr_write);
    }

    win_state(sp)->process = pi.hProcess;
    win_state(sp)->thread  = pi.hThread;
    sp->pid         = n00b_option_set(pid_t, (pid_t)pi.dwProcessId);

    win_wire_io(sp);
    // Windows does not subscribe a POSIX done-inbox; it drives the same
    // completion mask from pipe EOF markers and WaitForSingleObject.
    bool wait_stderr = sp->eff_stderr_topic
                       && sp->eff_stderr_topic != sp->eff_stdout_topic;
    sp->required_mask = n00b_subproc_completion_mask(sp->eff_stdout_topic != nullptr,
                                                     wait_stderr,
                                                     sp->stdin_inject != nullptr);
    atomic_store(&sp->spawned, true);

    if (sp->stdin_inject && sp->stdin_inject->byte_len) {
        n00b_subproc_write_stdin(sp, sp->stdin_inject);
    }
    if ((sp->flags & N00B_SUBPROC_CLOSE_STDIN) || sp->stdin_inject) {
        win_proxy_parent_stdin(sp);
        win_finish_stdin(sp);
        win_close_handle(&win_state(sp)->stdin_write);
    }

    return n00b_result_ok(bool, true);

spawn_fail:
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        n00b_free(attrs);
    }
    n00b_free(cmdline);
    n00b_free(env_block);
    n00b_free(app_name_alloc);
    sp->errored = true;
    sp->saved_errno = spawn_errno;
    win_close_handle(&child_stdin_read);
    win_close_handle(&child_stdout_write);
    if (child_stderr_write && child_stderr_write != child_stdout_write) {
        win_close_handle(&child_stderr_write);
    }
    if (win_state(sp)->pseudoconsole) {
        ClosePseudoConsole((HPCON)win_state(sp)->pseudoconsole);
        win_state(sp)->pseudoconsole = nullptr;
    }
    win_close_handle(&win_state(sp)->stdin_write);
    win_close_handle(&win_state(sp)->stdout_read);
    win_close_handle(&win_state(sp)->stderr_read);
#undef WIN_SPAWN_FAIL
    return n00b_result_err(bool, sp->saved_errno);
}

n00b_result_t(bool)
n00b_subproc_run(n00b_subproc_t *sp)
{
    n00b_result_t(bool) r = n00b_subproc_spawn(sp);
    if (n00b_result_is_err(r)) {
        return r;
    }
    r = n00b_subproc_wait(sp);
    if (!sp->timed_out || sp->timeout_policy != N00B_SUBPROC_TIMEOUT_DETACH) {
        n00b_subproc_close(sp);
    }
    return r;
}

n00b_result_t(bool)
n00b_subproc_wait(n00b_subproc_t *sp) _kargs
{
    n00b_duration_t *timeout = nullptr;
}
{
    if (!sp || !atomic_load(&sp->spawned) || !win_state(sp)->process) {
        return n00b_result_err(bool, ECHILD);
    }

    n00b_duration_t *to = timeout ? timeout : sp->timeout;
    uint64_t deadline = 0;
    if (to) {
        deadline = base_monotonic_ms()
                 + (uint64_t)to->tv_sec * 1000ULL
                 + (uint64_t)to->tv_nsec / 1000000ULL;
    }

    for (;;) {
        win_drain_output_pipes(sp);
        win_proxy_parent_stdin(sp);

        if (n00b_subproc_done_condition_met(sp)) {
            break;
        }

        DWORD wait_rc = WaitForSingleObject(win_state(sp)->process, 10);
        if (wait_rc == WAIT_OBJECT_0) {
            DWORD exit_code = 0;
            GetExitCodeProcess(win_state(sp)->process, &exit_code);
            sp->exit_status = n00b_option_set(int, (int)exit_code);
            atomic_store(&sp->exited, true);
            n00b_subproc_note_proc_done(sp);
            win_drain_output_pipes(sp);
            win_proxy_parent_stdin(sp);
            win_close_pseudoconsole_after_drain(sp);
            win_mark_remaining_output_done(sp);
            win_close_topics(sp);
            win_wait_output_topics(sp);
            if (n00b_subproc_done_condition_met(sp)) {
                break;
            }
        }

        if (to && base_monotonic_ms() >= deadline) {
            sp->timed_out = true;
            if (sp->timeout_policy == N00B_SUBPROC_TIMEOUT_DETACH) {
                return n00b_result_ok(bool, false);
            }
            TerminateProcess(win_state(sp)->process, 124);
            sp->term_signal = n00b_option_set(int, SIGTERM);
        }
    }

    return n00b_result_ok(bool, true);
}

void
n00b_subproc_close(n00b_subproc_t *sp)
{
    if (!sp || sp->closed) {
        return;
    }
    sp->closed = true;
    win_finish_stdin(sp);
    win_close_pseudoconsole_after_drain(sp);
    win_close_topics(sp);
    win_wait_output_topics(sp);
    win_close_handle(&win_state(sp)->stdin_write);
    win_close_handle(&win_state(sp)->stdout_read);
    win_close_handle(&win_state(sp)->stderr_read);
    win_close_handle(&win_state(sp)->thread);
    win_close_handle(&win_state(sp)->process);
}

n00b_result_t(uint64_t)
n00b_subproc_write_stdin(n00b_subproc_t *sp, n00b_buffer_t *data)
{
    if (!sp || !atomic_load(&sp->spawned) || !win_state(sp)->stdin_write) {
        return n00b_result_err(uint64_t, EBADF);
    }
    if (!data || data->byte_len == 0) {
        return n00b_result_ok(uint64_t, 0);
    }

    uint64_t written;
    if (n00b_subproc_xforms_requested(sp->stdin_xforms)) {
        win_publish_buffer(
            (n00b_conduit_topic_t(n00b_buffer_t *) *)win_state(sp)->stdin_raw_topic,
            data);
        written = win_drain_stdin_xform_outputs(sp, true);
    }
    else {
        written = win_write_stdin_buffer(sp, data);
        if (written != UINT64_MAX && sp->stdin_obs_topic) {
            n00b_buffer_t *observed = n00b_buffer_from_bytes(
                data->data, (int64_t)written,
                .allocator = sp->conduit ? sp->conduit->allocator : nullptr);
            win_publish_buffer(sp->stdin_obs_topic, observed);
        }
    }
    if (written == UINT64_MAX) {
        return n00b_result_err(uint64_t, EIO);
    }
    if (sp->flags & N00B_SUBPROC_CAP_STDIN) {
        n00b_subproc_drain_capture(sp->cap_stdin, sp->buf_stdin);
    }
    return n00b_result_ok(uint64_t, (uint64_t)written);
}

n00b_result_t(bool)
n00b_subproc_kill(n00b_subproc_t *sp) _kargs
{
    int signal = SIGTERM;
}
{
    if (!sp || !atomic_load(&sp->spawned) || atomic_load(&sp->exited)
        || !win_state(sp)->process) {
        return n00b_result_err(bool, ECHILD);
    }
    if (!TerminateProcess(win_state(sp)->process, 128 + signal)) {
        return n00b_result_err(bool, EINVAL);
    }
    sp->term_signal = n00b_option_set(int, signal);
    return n00b_result_ok(bool, true);
}

void
n00b_subproc_proxy_winsize(n00b_subproc_t *sp)
{
    if (sp && win_state(sp)->pseudoconsole) {
        ResizePseudoConsole((HPCON)win_state(sp)->pseudoconsole, win_pty_size(sp));
    }
}

void
n00b_subproc_restore_terminal(n00b_subproc_t *sp)
{
    // Windows ConPTY does not mutate the parent process terminal mode.
    (void)sp;
}

n00b_buffer_t *
n00b_subproc_stdout(n00b_subproc_t *sp)
{
    if (sp && !win_state(sp)->stdout_eof
        && win_drain_pipe(win_state(sp)->stdout_read,
                          (n00b_conduit_topic_t(n00b_buffer_t *) *)
                              win_state(sp)->stdout_topic)) {
        win_mark_stdout_eof(sp);
    }
    win_drain_captures(sp);
    return sp && sp->buf_stdout ? sp->buf_stdout : &empty_buf_sentinel;
}

n00b_buffer_t *
n00b_subproc_stderr(n00b_subproc_t *sp)
{
    if (sp && !win_state(sp)->stderr_eof
        && win_drain_pipe(win_state(sp)->stderr_read,
                          (n00b_conduit_topic_t(n00b_buffer_t *) *)
                              win_state(sp)->stderr_topic)) {
        win_mark_stderr_eof(sp);
    }
    win_drain_captures(sp);
    return sp && sp->buf_stderr ? sp->buf_stderr : &empty_buf_sentinel;
}

n00b_buffer_t *
n00b_subproc_stdin_capture(n00b_subproc_t *sp)
{
    n00b_subproc_drain_capture(sp ? sp->cap_stdin : nullptr, sp ? sp->buf_stdin : nullptr);
    return sp && sp->buf_stdin ? sp->buf_stdin : &empty_buf_sentinel;
}

n00b_result_t(int)
n00b_subproc_exit_code(n00b_subproc_t *sp)
{
    if (!sp || !atomic_load(&sp->exited) || !n00b_option_is_set(sp->exit_status)) {
        return n00b_result_err(int, ECHILD);
    }
    return n00b_result_ok(int, n00b_option_get(sp->exit_status));
}

n00b_result_t(int)
n00b_subproc_term_signal(n00b_subproc_t *sp)
{
    if (!sp || !atomic_load(&sp->exited) || !n00b_option_is_set(sp->term_signal)) {
        return n00b_result_err(int, ECHILD);
    }
    return n00b_result_ok(int, n00b_option_get(sp->term_signal));
}

n00b_option_t(n00b_conduit_topic_t(n00b_buffer_t *) *)
    n00b_subproc_stdout_topic(n00b_subproc_t *sp)
{
    return n00b_option_from_nullable(
        n00b_conduit_topic_t(n00b_buffer_t *) *,
        sp ? (n00b_conduit_topic_t(n00b_buffer_t *) *)sp->eff_stdout_topic
           : nullptr);
}

n00b_option_t(n00b_conduit_topic_t(n00b_buffer_t *) *)
    n00b_subproc_stderr_topic(n00b_subproc_t *sp)
{
    return n00b_option_from_nullable(
        n00b_conduit_topic_t(n00b_buffer_t *) *,
        sp ? (n00b_conduit_topic_t(n00b_buffer_t *) *)sp->eff_stderr_topic
           : nullptr);
}

n00b_option_t(n00b_conduit_topic_t(n00b_buffer_t *) *)
    n00b_subproc_stdin_topic(n00b_subproc_t *sp)
{
    return n00b_option_from_nullable(
        n00b_conduit_topic_t(n00b_buffer_t *) *,
        sp ? sp->stdin_obs_topic : nullptr);
}

#endif
