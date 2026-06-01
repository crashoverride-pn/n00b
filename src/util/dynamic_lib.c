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

#include <dlfcn.h>

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
    const char *e = dlerror();
    set_last_error_cstr(e ? e : "");
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
        dlclose(lib->handle);
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

    /* dlopen wants a NUL-terminated string. n00b_string_t.data is
     * always NUL-terminated per core/string.h, so passing it
     * straight is safe. */
    void *raw = dlopen(path->data, RTLD_NOW | RTLD_LOCAL);
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
    /* Clear dlerror before lookup so a NULL return that *is* the
     * symbol's real value (e.g., for data symbols) is distinguishable
     * from "symbol not found". */
    (void)dlerror();
    void *sym = dlsym(lib->handle, name->data);
    const char *err = dlerror();
    if (err) {
        set_last_error_cstr(err);
        return n00b_result_err(void *, N00B_DYNLIB_ERR_NO_SYMBOL);
    }
    return n00b_result_ok(void *, sym);
}

void
n00b_dynamic_lib_close(n00b_dynamic_lib_t *lib)
{
    if (lib && lib->handle) {
        dlclose(lib->handle);
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
