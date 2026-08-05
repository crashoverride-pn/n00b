/* src/util/dynamic_lib.c — n00b dynamic-linker boundary.
 *
 * This is the ONLY n00b translation unit that includes `<dlfcn.h>`.
 * Everything else in n00b (and every consumer that doesn't have a
 * specific reason to bypass) routes dynamic-library work through the
 * primitive declared in <util/dynamic_lib.h>. See the audit notes in
 * [[feedback_no_libc_rationalization]] for why the boundary lives
 * here.
 */

#include "n00b.h"
#include "util/dynamic_lib.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/thread.h"
#include "core/runtime.h" // n00b_thread_self() macro dereferences rt->threads[]

#include <stdio.h>
#ifdef _WIN32
#include "core/platform.h"
#include <tlhelp32.h>
#else
#include <dlfcn.h>
#endif

struct n00b_dynamic_lib_t {
    void *handle;
};

/* Per-thread last-error slot.  Folded out of a thread_local into
 * n00b_thread_t::dl_last_error (D-012), reached via n00b_thread_self()
 * so a raw worker thread needs zero TLS.  The string still lives in the
 * n00b GC heap so callers can stash references across stop-the-world
 * cycles.  Before the runtime / calling thread is registered, self() is
 * nullptr and the slot is treated as empty (startup-window guard,
 * matching src/core/data_lock.c). */
static void
set_last_error_cstr(const char *msg)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return;
    }
    self->dl_last_error = n00b_string_from_cstr(msg ? msg : "");
}

static void
record_dl_error(void)
{
#ifdef _WIN32
    char buf[128];
    snprintf(buf, sizeof(buf), "Win32 dynamic library error: %lu",
             (unsigned long)GetLastError());
    set_last_error_cstr(buf);
#else
    const char *e = dlerror();
    set_last_error_cstr(e ? e : "");
#endif
}

n00b_string_t *
n00b_dynamic_lib_last_error(void)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        // No registered thread yet: report an empty (non-null) string
        // without caching, since there is nowhere per-thread to stash it.
        return n00b_string_empty();
    }
    if (self->dl_last_error == nullptr) {
        self->dl_last_error = n00b_string_empty();
    }
    return self->dl_last_error;
}

/* Finalizer wired up by n00b_dynamic_lib_open. Runs when the handle
 * becomes unreachable; closes the underlying `dlopen` handle so the
 * platform reclaims the shared library mapping. Idempotent — calling
 * `n00b_dynamic_lib_close` explicitly first nulls out the handle so
 * the finalizer becomes a no-op. */
static void
finalize_dynamic_lib(void *p)
{
    n00b_dynamic_lib_t *lib = p;
    if (lib && lib->handle) {
#ifdef _WIN32
        FreeLibrary((HMODULE)lib->handle);
#else
        dlclose(lib->handle);
#endif
        lib->handle = nullptr;
    }
}

n00b_result_t(n00b_dynamic_lib_t *)
n00b_dynamic_lib_open(n00b_string_t *path)
{
    if (!path || path->u8_bytes == 0) {
        set_last_error_cstr("n00b_dynamic_lib_open: empty path");
        return n00b_result_err(n00b_dynamic_lib_t *,
                               N00B_DYNLIB_ERR_INVALID_ARG);
    }

    /* The platform loader wants a NUL-terminated string. n00b_string_t.data
     * is always NUL-terminated per core/string.h, so passing it straight is
     * safe. */
#ifdef _WIN32
    void *raw = LoadLibraryA(path->data);
#else
    void *raw = dlopen(path->data, RTLD_NOW | RTLD_LOCAL);
#endif
    if (!raw) {
        record_dl_error();
        return n00b_result_err(n00b_dynamic_lib_t *,
                               N00B_DYNLIB_ERR_LOAD_FAILED);
    }

    n00b_dynamic_lib_t *lib = n00b_alloc(n00b_dynamic_lib_t);
    lib->handle = raw;
    n00b_add_finalizer(lib, finalize_dynamic_lib, lib);
    return n00b_result_ok(n00b_dynamic_lib_t *, lib);
}

n00b_result_t(void *)
n00b_dynamic_lib_symbol(n00b_dynamic_lib_t *lib, n00b_string_t *name)
{
    if (!lib || !lib->handle || !name || name->u8_bytes == 0) {
        set_last_error_cstr("n00b_dynamic_lib_symbol: invalid argument");
        return n00b_result_err(void *, N00B_DYNLIB_ERR_INVALID_ARG);
    }
#ifdef _WIN32
    void *sym = (void *)GetProcAddress((HMODULE)lib->handle, name->data);
    if (!sym) {
        record_dl_error();
        return n00b_result_err(void *, N00B_DYNLIB_ERR_NO_SYMBOL);
    }
#else
    /* Clear dlerror before lookup so a NULL return that *is* the symbol's real
     * value (e.g., for data symbols) is distinguishable from "symbol not
     * found". */
    (void)dlerror();
    void *sym = dlsym(lib->handle, name->data);
    const char *err = dlerror();
    if (err) {
        set_last_error_cstr(err);
        return n00b_result_err(void *, N00B_DYNLIB_ERR_NO_SYMBOL);
    }
#endif
    return n00b_result_ok(void *, sym);
}

void
n00b_dynamic_lib_close(n00b_dynamic_lib_t *lib)
{
    if (lib && lib->handle) {
#ifdef _WIN32
        FreeLibrary((HMODULE)lib->handle);
#else
        dlclose(lib->handle);
#endif
        lib->handle = nullptr;
    }
}

/* ------------------------------------------------------------------
 * C-string boundary — drop-in shape match for dlopen/dlsym/dlclose so
 * demangle's generated headers can substitute these without rewriting
 * their wrappers. The pointee returned by `_open_cstr` is the same
 * `n00b_dynamic_lib_t` the typed API exposes; we just hand the caller
 * a `void *` view for boundary compatibility.
 * ------------------------------------------------------------------ */

void *
n00b_dynamic_lib_open_cstr(const char *path)
{
    n00b_string_t *p = n00b_string_from_cstr(path ? path : "");
    n00b_result_t(n00b_dynamic_lib_t *) r = n00b_dynamic_lib_open(p);
    if (n00b_result_is_err(r)) {
        return nullptr;
    }
    return n00b_result_get(r);
}

void *
n00b_dynamic_lib_symbol_cstr(void *lib, const char *name)
{
    if (!lib || !name) {
        set_last_error_cstr("n00b_dynamic_lib_symbol_cstr: invalid argument");
        return nullptr;
    }
    n00b_string_t *n = n00b_string_from_cstr(name);
    n00b_result_t(void *) r = n00b_dynamic_lib_symbol(
        (n00b_dynamic_lib_t *)lib, n);
    if (n00b_result_is_err(r)) {
        return nullptr;
    }
    return n00b_result_get(r);
}

void
n00b_dynamic_lib_close_cstr(void *lib)
{
    n00b_dynamic_lib_close((n00b_dynamic_lib_t *)lib);
}

void *
n00b_dynamic_lib_current_symbol_cstr(const char *name)
{
    if (name == nullptr || name[0] == '\0') {
        set_last_error_cstr(
            "n00b_dynamic_lib_current_symbol_cstr: invalid argument");
        return nullptr;
    }

#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        record_dl_error();
        return nullptr;
    }

    MODULEENTRY32 entry = {.dwSize = sizeof(entry)};
    FARPROC       sym   = nullptr;
    if (Module32First(snapshot, &entry)) {
        do {
            sym = GetProcAddress(entry.hModule, name);
            if (sym != nullptr) {
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (sym == nullptr) {
        set_last_error_cstr(
            "n00b_dynamic_lib_current_symbol_cstr: symbol not found");
        return nullptr;
    }
    return (void *)sym;
#else
    (void)dlerror();
    void       *sym = dlsym(RTLD_DEFAULT, name);
    const char *err = dlerror();
    if (err != nullptr) {
        set_last_error_cstr(err);
        return nullptr;
    }
    return sym;
#endif
}

const char *
n00b_dynamic_lib_addr_symbol_cstr(void *addr)
{
    if (addr == nullptr) {
        set_last_error_cstr(
            "n00b_dynamic_lib_addr_symbol_cstr: invalid argument");
        return nullptr;
    }

#ifdef _WIN32
    HMODULE module = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                                | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (const char *)addr,
                            &module)) {
        record_dl_error();
        return nullptr;
    }

    uint8_t          *base = (uint8_t *)module;
    IMAGE_DOS_HEADER *dos  = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    IMAGE_DATA_DIRECTORY exports =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports.VirtualAddress == 0 || exports.Size == 0) {
        return nullptr;
    }

    IMAGE_EXPORT_DIRECTORY *table =
        (IMAGE_EXPORT_DIRECTORY *)(base + exports.VirtualAddress);
    DWORD *names = (DWORD *)(base + table->AddressOfNames);

    for (DWORD i = 0; i < table->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if ((void *)GetProcAddress(module, name) == addr) {
            return name;
        }
    }

    set_last_error_cstr(
        "n00b_dynamic_lib_addr_symbol_cstr: exact symbol not found");
    return nullptr;
#else
    Dl_info info;
    if (dladdr(addr, &info) == 0 || info.dli_sname == nullptr
        || info.dli_saddr != addr) {
        set_last_error_cstr(
            "n00b_dynamic_lib_addr_symbol_cstr: exact symbol not found");
        return nullptr;
    }
    (void)dlerror();
    void *resolved = dlsym(RTLD_DEFAULT, info.dli_sname);
    const char *err = dlerror();
    if (err != nullptr || resolved != addr) {
        set_last_error_cstr("n00b_dynamic_lib_addr_symbol_cstr: symbol is not exported");
        return nullptr;
    }
    return info.dli_sname;
#endif
}

const char *
n00b_dynamic_lib_err_str(n00b_dynamic_lib_err_t err)
{
    switch (err) {
    case N00B_DYNLIB_OK:              return "OK";
    case N00B_DYNLIB_ERR_INVALID_ARG: return "INVALID_ARG";
    case N00B_DYNLIB_ERR_NOT_FOUND:   return "NOT_FOUND";
    case N00B_DYNLIB_ERR_LOAD_FAILED: return "LOAD_FAILED";
    case N00B_DYNLIB_ERR_NO_SYMBOL:   return "NO_SYMBOL";
    case N00B_DYNLIB_ERR_PLATFORM:    return "PLATFORM";
    }
    return "UNKNOWN";
}
