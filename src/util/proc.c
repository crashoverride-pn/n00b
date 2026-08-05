// Cross-platform process utilities: liveness, and introspection
// (pid / ppid / ancestry).
//
// The public API in util/proc.h is platform-neutral. All OS-specific
// machinery is confined to the two static helpers `proc_raw_ppid` and
// `proc_fill_exe` below (plus `kill(pid, 0)` for liveness); every other
// function is shared across platforms.
//
// Only the direct OS calls (getpid, kill, proc_pidinfo/proc_pidpath on macOS,
// /proc on Linux) are libc/syscall surface — libn00b has no wrapper for
// process ancestry or liveness, mirroring the existing proc_pidpath use in
// src/util/path.c. Per n00b-api-guidelines §11, consumers call the n00b
// primitives here instead of libc.

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/result.h"
#include "util/parse_num.h"
#include "util/proc.h"

#include <errno.h>
#include <unistd.h>
#if defined(_WIN32)
#include "internal/win32_sockets.h"
#include <tlhelp32.h>
#else
#include <signal.h>
#endif

#if defined(__MACH__)
#include <libproc.h>
#include <sys/proc_info.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <limits.h>
#endif

// ----------------------------------------------------------------------------
// Shared helpers (platform-neutral).
// ----------------------------------------------------------------------------

// Basename of a NUL-terminated path, allocated in `allocator`. Computed
// directly from the OS-provided C buffer so it honors the caller's arena and
// avoids n00b_filename_from_path's filesystem-resolving n00b_resolve_path
// (we want the exact exe path the kernel reported, not a re-resolved one).
[[maybe_unused]] static n00b_string_t *
proc_basename(const char *path, n00b_allocator_t *allocator)
{
    const char *base = path;
    const char *p    = path;

    while (*p) {
        if (*p == '/' || *p == '\\') {
            base = p + 1;
        }
        p++;
    }

    return n00b_string_from_cstr(base, .allocator = allocator);
}

// ----------------------------------------------------------------------------
// Platform-specific helpers.
// ----------------------------------------------------------------------------

#if defined(_WIN32)

static n00b_result_t(int64_t)
proc_raw_ppid(int64_t pid)
{
    if (pid <= 0 || pid > 0xffffffffLL) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_NO_SUCH_PID);
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_LOOKUP_FAILED);
    }

    PROCESSENTRY32W entry = {.dwSize = sizeof(entry)};
    BOOL found = Process32FirstW(snapshot, &entry);

    while (found && entry.th32ProcessID != (DWORD)pid) {
        found = Process32NextW(snapshot, &entry);
    }

    CloseHandle(snapshot);
    if (!found) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_NO_SUCH_PID);
    }

    return n00b_result_ok(int64_t, (int64_t)entry.th32ParentProcessID);
}

static void
proc_fill_meta(int64_t pid, n00b_proc_info_t *info, n00b_allocator_t *allocator)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 (DWORD)pid);
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return;
    }

    char  path[32768];
    DWORD path_len = (DWORD)sizeof(path);

    if (QueryFullProcessImageNameA(process, 0, path, &path_len)
        && path_len < sizeof(path)) {
        path[path_len] = '\0';
        info->exe_path = n00b_string_from_cstr(path, .allocator = allocator);
        info->exe_name = proc_basename(path, allocator);
        info->proc_name = proc_basename(path, allocator);
    }

    CloseHandle(process);
}

#elif defined(__MACH__)

static n00b_result_t(int64_t)
proc_raw_ppid(int64_t pid)
{
    struct proc_bsdinfo info = {};
    int                 n    = proc_pidinfo((int)pid,
                            PROC_PIDTBSDINFO,
                            0,
                            &info,
                            sizeof(info));

    if (n != (int)sizeof(info)) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_NO_SUCH_PID);
    }

    return n00b_result_ok(int64_t, (int64_t)info.pbi_ppid);
}

// Copy a possibly-not-NUL-terminated fixed kernel char array into a string.
static n00b_string_t *
proc_fixed_name(const char *field, size_t field_sz, n00b_allocator_t *allocator)
{
    char   tmp[64];
    size_t cap = (field_sz < sizeof(tmp) - 1) ? field_sz : sizeof(tmp) - 1;
    size_t i   = 0;

    while (i < cap && field[i] != '\0') {
        tmp[i] = field[i];
        i++;
    }
    tmp[i] = '\0';

    if (i == 0) {
        return nullptr;
    }

    return n00b_string_from_cstr(tmp, .allocator = allocator);
}

static void
proc_fill_meta(int64_t pid, n00b_proc_info_t *info, n00b_allocator_t *allocator)
{
    char buf[PROC_PIDPATHINFO_MAXSIZE];

    if (proc_pidpath((int)pid, buf, sizeof(buf)) > 0) {
        info->exe_path = n00b_string_from_cstr(buf, .allocator = allocator);
        info->exe_name = proc_basename(buf, allocator);
    }

    // Kernel process name (comm). Prefer the longer pbi_name; fall back to
    // pbi_comm. This is what callers usually want to match on — it can differ
    // from the executable's on-disk filename.
    struct proc_bsdinfo bi = {};

    if (proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi))
        == (int)sizeof(bi)) {
        info->proc_name = proc_fixed_name(bi.pbi_name,
                                          sizeof(bi.pbi_name),
                                          allocator);
        if (info->proc_name == nullptr) {
            info->proc_name = proc_fixed_name(bi.pbi_comm,
                                              sizeof(bi.pbi_comm),
                                              allocator);
        }
    }
}

#elif defined(__linux__)

// Build "/proc/<pid>/<leaf>" into `buf` without libc string formatting
// (no snprintf): render the decimal pid by hand and append the literals.
// Returns false if `buf` is too small.
static bool
proc_path_build(char *buf, size_t cap, int64_t pid, const char *leaf)
{
    static const char prefix[] = "/proc/";

    char     digits[24];
    size_t   dn = 0;
    uint64_t v  = (uint64_t)pid;

    if (v == 0) {
        digits[dn++] = '0';
    }
    while (v > 0) {
        digits[dn++] = (char)('0' + (int)(v % 10));
        v /= 10;
    }

    size_t i = 0;
    size_t k = 0;

    while (prefix[k] != '\0') {
        if (i + 1 >= cap) {
            return false;
        }
        buf[i++] = prefix[k++];
    }
    while (dn > 0) {
        if (i + 1 >= cap) {
            return false;
        }
        buf[i++] = digits[--dn];
    }
    if (i + 1 >= cap) {
        return false;
    }
    buf[i++] = '/';

    k = 0;
    while (leaf[k] != '\0') {
        if (i + 1 >= cap) {
            return false;
        }
        buf[i++] = leaf[k++];
    }
    buf[i] = '\0';

    return true;
}

// Read a /proc file with an EOF-driven loop. /proc files report st_size == 0,
// so n00b_unicode_str_from_file (which trusts fstat's size) returns empty for
// them; a direct read is the only option. This mirrors the direct /proc access
// already used in src/util/path.c (n00b_app_path readlinks /proc/<pid>/exe).
// Returns the byte count (NUL-terminated), or -1 on failure.
static ssize_t
proc_slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        return -1;
    }

    size_t total = 0;

    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }

    close(fd);
    buf[total] = '\0';

    return (ssize_t)total;
}

static n00b_result_t(int64_t)
proc_raw_ppid(int64_t pid)
{
    char path[64];
    char buf[512];

    if (!proc_path_build(path, sizeof(path), pid, "stat")) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_LOOKUP_FAILED);
    }

    if (proc_slurp(path, buf, sizeof(buf)) < 0) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_NO_SUCH_PID);
    }

    // /proc/<pid>/stat is "pid (comm) state ppid ...". The comm field can
    // contain spaces and ')', so parse the fields AFTER the final ')':
    // field[0] = state, field[1] = ppid.
    char  *rparen = nullptr;
    char  *p      = buf;

    while (*p) {
        if (*p == ')') {
            rparen = p;
        }
        p++;
    }
    if (rparen == nullptr) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_LOOKUP_FAILED);
    }

    char *q = rparen + 1;

    while (*q == ' ') {
        q++; // skip to the state field
    }
    while (*q && *q != ' ') {
        q++; // skip over the state field
    }
    while (*q == ' ') {
        q++; // skip to the ppid field
    }

    size_t dlen = 0;

    while (q[dlen] >= '0' && q[dlen] <= '9') {
        dlen++;
    }
    if (dlen == 0) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_LOOKUP_FAILED);
    }

    auto pr = n00b_parse_i64_span(q, dlen);

    if (n00b_result_is_err(pr)) {
        return n00b_result_err(int64_t, N00B_PROC_ERR_LOOKUP_FAILED);
    }

    return n00b_result_ok(int64_t, n00b_result_get(pr));
}

static void
proc_fill_meta(int64_t pid, n00b_proc_info_t *info, n00b_allocator_t *allocator)
{
    char path[64];
    char buf[PATH_MAX];

    // The real executable path via /proc/<pid>/exe.
    if (proc_path_build(path, sizeof(path), pid, "exe")) {
        ssize_t n = readlink(path, buf, sizeof(buf) - 1);

        if (n > 0) {
            buf[n]         = '\0';
            info->exe_path = n00b_string_from_cstr(buf, .allocator = allocator);
            info->exe_name = proc_basename(buf, allocator);
        }
    }

    // Kernel process name (comm), newline-terminated and capped at 15 bytes by
    // the kernel. This is what callers usually want to match on, and it is
    // available even when /proc/<pid>/exe is unreadable.
    if (proc_path_build(path, sizeof(path), pid, "comm")) {
        ssize_t c = proc_slurp(path, buf, sizeof(buf));

        if (c > 0) {
            if (buf[c - 1] == '\n') {
                buf[c - 1] = '\0';
            }
            info->proc_name = n00b_string_from_cstr(buf, .allocator = allocator);
        }
    }
}

#else // unsupported platform

static n00b_result_t(int64_t)
proc_raw_ppid([[maybe_unused]] int64_t pid)
{
    return n00b_result_err(int64_t, N00B_PROC_ERR_UNSUPPORTED);
}

static void
proc_fill_meta([[maybe_unused]] int64_t           pid,
               [[maybe_unused]] n00b_proc_info_t *info,
               [[maybe_unused]] n00b_allocator_t *allocator)
{
    return; // exe_path / exe_name / proc_name stay nullptr
}

#endif

// ----------------------------------------------------------------------------
// Public API (platform-neutral).
// ----------------------------------------------------------------------------

bool
n00b_proc_is_alive(int64_t pid)
{
    if (pid <= 0) {
        return false;
    }

#if defined(_WIN32)
    if (pid > 0xffffffffLL) {
        return false;
    }

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                              (DWORD)pid);
    if (proc == nullptr || proc == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD exit_code = 0;
    bool  alive = GetExitCodeProcess(proc, &exit_code)
               && exit_code == STILL_ACTIVE;
    CloseHandle(proc);
    return alive;
#else
    if (kill((pid_t)pid, 0) == 0) {
        return true;
    }
    /* EPERM => the process exists but is owned by another user. */
    return errno == EPERM;
#endif
}

n00b_string_t *
n00b_proc_err_str(n00b_err_t code)
{
    switch (code) {
    case 0:
        return r"ok";
    case N00B_PROC_ERR_NO_SUCH_PID:
        return r"no such pid";
    case N00B_PROC_ERR_LOOKUP_FAILED:
        return r"process lookup failed";
    case N00B_PROC_ERR_UNSUPPORTED:
        return r"process introspection unsupported on this platform";
    default:
        return r"unknown process error";
    }
}

int64_t
n00b_proc_self_pid(void)
{
    return (int64_t)getpid();
}

n00b_string_t *
n00b_get_hostname(void)
{
    char buf[256] = {0};
#if defined(_WIN32)
    DWORD n = (DWORD)(sizeof(buf) - 1);
    if (!GetComputerNameExA(ComputerNameDnsHostname, buf, &n)) {
        return n00b_string_from_cstr("");
    }
#else
    // gethostname is a thin syscall wrapper (no locale/TLS), so it is safe on
    // n00b off-libc worker threads, unlike libc's locale-aware converters.
    if (gethostname(buf, sizeof(buf) - 1) != 0) {
        return n00b_string_from_cstr("");
    }
#endif
    buf[sizeof(buf) - 1] = '\0';
    return n00b_string_from_cstr(buf);
}

n00b_result_t(n00b_proc_info_t *)
n00b_proc_get_info(int64_t pid) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    // Advisory precondition (D-031 style): body-guard, never trap.
    if (pid <= 0) {
        return n00b_result_err(n00b_proc_info_t *, N00B_PROC_ERR_NO_SUCH_PID);
    }

    auto pr = proc_raw_ppid(pid);

    if (n00b_result_is_err(pr)) {
        return n00b_result_err(n00b_proc_info_t *, n00b_result_get_err(pr));
    }

    n00b_proc_info_t *info = n00b_alloc(n00b_proc_info_t, .allocator = allocator);

    info->pid  = pid;
    info->ppid = n00b_result_get(pr);
    proc_fill_meta(pid, info, allocator);

    return n00b_result_ok(n00b_proc_info_t *, info);
}

n00b_result_t(n00b_list_t(n00b_proc_info_t *) *)
n00b_proc_ancestry(int64_t pid) _kargs {
    n00b_allocator_t *allocator    = nullptr;
    int64_t           max_depth    = 64;
    bool              include_self = true;
}
{
    if (max_depth < 1) {
        max_depth = 1;
    }

    int64_t start = (pid <= 0) ? n00b_proc_self_pid() : pid;

    // If even the starting process can't be queried, there is no chain.
    auto first = n00b_proc_get_info(start, .allocator = allocator);

    if (n00b_result_is_err(first)) {
        return n00b_result_err(n00b_list_t(n00b_proc_info_t *) *,
                               n00b_result_get_err(first));
    }

    n00b_proc_info_t *cur = n00b_result_get(first);

    n00b_list_t(n00b_proc_info_t *) chain =
        n00b_list_new(n00b_proc_info_t *, .allocator = allocator);
    n00b_list_t(n00b_proc_info_t *) *result =
        n00b_alloc(n00b_list_t(n00b_proc_info_t *), .allocator = allocator);
    *result = chain;

    if (include_self) {
        n00b_list_push(*result, cur);
    }

    // Climb parents until init/no-parent, an unresolvable parent, or the
    // depth cap (cycle guard).
    while ((int64_t)n00b_list_len(*result) < max_depth) {
        int64_t ppid = cur->ppid;

        if (ppid <= 0) {
            break; // reached the top of the tree
        }

        auto pr = n00b_proc_get_info(ppid, .allocator = allocator);

        if (n00b_result_is_err(pr)) {
            break; // first unresolvable parent stops the walk
        }

        cur = n00b_result_get(pr);
        n00b_list_push(*result, cur);
    }

    return n00b_result_ok(n00b_list_t(n00b_proc_info_t *) *, result);
}
