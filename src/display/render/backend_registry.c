/*
 * Backend registry: static registration, name lookup, dynamic loading.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/list.h"
#include "text/strings/string_ops.h"
#include "display/render/backend_registry.h"

// -------------------------------------------------------------------
// Registry storage
// -------------------------------------------------------------------

#define MAX_BACKENDS 32

typedef struct {
    n00b_string_t                *name;
    const n00b_renderer_vtable_t *vtable;
} registry_entry_t;

static registry_entry_t registry[MAX_BACKENDS];
static n00b_isize_t      registry_count = 0;
static bool              registry_initialized = false;
static const char       *backend_override_env = "N00B_RENDERER_BACKEND";

static const char *const auto_candidates[] = {
    "ansi",
    "gui",
    "notcurses",
    "stream",
    "dumb",
};

static const char *
renderer_getenv(const char *name)
{
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    return secure_getenv(name);
#else
    return getenv(name);
#endif
}

static bool
renderer_plugin_dir_trusted(const char *dir)
{
    if (!dir || !dir[0]) {
        return false;
    }

#ifdef _WIN32
    return true;
#else
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return false;
    }

    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }

    uid_t uid = getuid();
    return st.st_uid == 0 || st.st_uid == uid;
#endif
}

// -------------------------------------------------------------------
// Selection helpers
// -------------------------------------------------------------------

static n00b_string_t *
normalize_backend_name(n00b_string_t *name)
{
    if (!name || n00b_unicode_str_eq(name, r"", .case_sensitive = false)) {
        return r"auto";
    }

    if (n00b_unicode_str_eq(name, r"tui", .case_sensitive = false)) {
        return r"ansi";
    }

    if (n00b_unicode_str_eq(name, r"nc", .case_sensitive = false)) {
        return r"notcurses";
    }

    return name;
}

static bool
candidate_list_contains(n00b_list_t(n00b_string_t *) *candidates,
                        n00b_string_t               *name)
{
    for (size_t i = 0; i < candidates->len; i++) {
        n00b_string_t *existing = n00b_list_get(*candidates, i);
        if (n00b_unicode_str_eq(existing, name, .case_sensitive = false)) {
            return true;
        }
    }
    return false;
}

static void
candidate_list_push_unique(n00b_list_t(n00b_string_t *) *candidates,
                           n00b_string_t               *name)
{
    if (!name) {
        return;
    }

    n00b_string_t *normalized = normalize_backend_name(name);
    if (!candidate_list_contains(candidates, normalized)) {
        n00b_list_push(*candidates, normalized);
    }
}

static void
candidate_list_append_auto(n00b_list_t(n00b_string_t *) *candidates)
{
    // tty-aware `auto`: when stdout is NOT a terminal (pipe / file / redirect),
    // prefer the plain `stream` backend so we never emit ANSI escapes into
    // non-tty output.  On a real tty we keep the normal rich-first order
    // (ansi, gui, ...).  This only affects `auto`; an explicit `--backend ansi`
    // bypasses this candidate list and can still write escapes to a file.
    //
    // Historically `auto`->`stream` on a non-tty happened only incidentally,
    // because `ansi_init` failed when the conduit SIGWINCH infra wasn't ready
    // yet; once that infra became reliably available, `auto` started selecting
    // `ansi` and leaking color into pipes. This makes the contract explicit.
#ifndef _WIN32
    if (!isatty(STDOUT_FILENO)) {
        candidate_list_push_unique(candidates, r"stream");
    }
#endif
    for (size_t i = 0; i < (sizeof(auto_candidates) / sizeof(auto_candidates[0])); i++) {
        candidate_list_push_unique(candidates, n00b_string_from_cstr(auto_candidates[i]));
    }
}

// -------------------------------------------------------------------
// Registration
// -------------------------------------------------------------------

void
n00b_renderer_register(n00b_string_t                *name,
                        const n00b_renderer_vtable_t *vtable)
{
    if (!name || !vtable) {
        return;
    }

    // Check for duplicate.
    for (n00b_isize_t i = 0; i < registry_count; i++) {
        if (n00b_unicode_str_eq(registry[i].name, name)) {
            // Update existing.
            registry[i].vtable = vtable;
            return;
        }
    }

    if (registry_count >= MAX_BACKENDS) {
        fprintf(stderr, "n00b: renderer registry full (max %d)\n", MAX_BACKENDS);
        return;
    }

    registry[registry_count].name   = name;
    registry[registry_count].vtable = vtable;
    registry_count++;
}

n00b_option_t(n00b_renderer_vtable_ptr_t)
n00b_renderer_find(n00b_string_t *name)
{
    if (!name) {
        return n00b_option_none(n00b_renderer_vtable_ptr_t);
    }

    for (n00b_isize_t i = 0; i < registry_count; i++) {
        if (n00b_unicode_str_eq(registry[i].name, name)) {
            return n00b_option_set(n00b_renderer_vtable_ptr_t,
                                    registry[i].vtable);
        }
    }

    return n00b_option_none(n00b_renderer_vtable_ptr_t);
}

n00b_list_t(n00b_string_t *)
n00b_renderer_list(void)
{
    n00b_list_t(n00b_string_t *) result = n00b_list_new(n00b_string_t *);

    for (n00b_isize_t i = 0; i < registry_count; i++) {
        n00b_list_push(result, registry[i].name);
    }

    return result;
}

n00b_list_t(n00b_string_t *)
n00b_renderer_candidate_names(n00b_string_t *requested) _kargs
{
    bool allow_fallback     = true;
    bool allow_env_override = false;
}
{
    n00b_list_t(n00b_string_t *) result = n00b_list_new(n00b_string_t *);
    n00b_string_t *normalized_request = normalize_backend_name(requested);
    bool is_auto = n00b_unicode_str_eq(normalized_request, r"auto",
                                       .case_sensitive = false);

    if (allow_env_override && is_auto) {
        const char *env_value = renderer_getenv(backend_override_env);
        if (env_value && env_value[0]) {
            candidate_list_push_unique(&result, n00b_string_from_cstr(env_value));
        }
    }

    if (is_auto) {
        candidate_list_append_auto(&result);
        return result;
    }

    candidate_list_push_unique(&result, normalized_request);

    if (allow_fallback) {
        candidate_list_append_auto(&result);
    }

    return result;
}

bool
n00b_renderer_selection_uses_fallback(n00b_string_t                *requested,
                                      const n00b_renderer_vtable_t *selected) _kargs
{
    bool allow_fallback     = true;
    bool allow_dynamic_load = false;
    bool allow_env_override = false;
}
{
    if (!selected) {
        return false;
    }

    n00b_list_t(n00b_string_t *) candidates =
        n00b_renderer_candidate_names(requested,
                                      .allow_fallback     = allow_fallback,
                                      .allow_env_override = allow_env_override);

    for (size_t i = 0; i < candidates.len; i++) {
        n00b_string_t *candidate_name = n00b_list_get(candidates, i);
        n00b_result_t(n00b_renderer_vtable_ptr_t) resolved =
            n00b_renderer_resolve_exact(candidate_name,
                                        .allow_dynamic_load = allow_dynamic_load);
        if (!n00b_result_is_ok(resolved)) {
            continue;
        }

        if (n00b_result_get(resolved) == selected) {
            return i != 0;
        }
    }

    return false;
}

n00b_result_t(n00b_renderer_vtable_ptr_t)
n00b_renderer_resolve_exact(n00b_string_t *name) _kargs
{
    bool allow_dynamic_load = false;
}
{
    if (!name || n00b_unicode_str_eq(name, r"", .case_sensitive = false)) {
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EINVAL);
    }

    n00b_string_t *normalized = normalize_backend_name(name);
    n00b_renderer_registry_init();

    n00b_option_t(n00b_renderer_vtable_ptr_t) found =
        n00b_renderer_find(normalized);

    if (n00b_option_is_set(found)) {
        return n00b_result_ok(n00b_renderer_vtable_ptr_t,
                               n00b_option_get(found));
    }

    if (!allow_dynamic_load) {
        return n00b_result_err(n00b_renderer_vtable_ptr_t, ENOENT);
    }

    return n00b_renderer_load_by_name(normalized);
}

// -------------------------------------------------------------------
// Dynamic loading
// -------------------------------------------------------------------

n00b_result_t(n00b_renderer_vtable_ptr_t)
n00b_renderer_load(n00b_string_t *path)
{
    if (!path) {
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EINVAL);
    }

#ifdef _WIN32
    HMODULE handle = LoadLibraryA(path->data);
    if (!handle) {
        fprintf(stderr, "n00b: failed to load renderer '%s'\n", path->data);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, ENOENT);
    }

    const n00b_renderer_plugin_t *plugin =
        (const n00b_renderer_plugin_t *)GetProcAddress(handle,
                                                       "n00b_renderer_plugin");

    if (!plugin) {
        fprintf(stderr, "n00b: no n00b_renderer_plugin symbol in '%s'\n",
                path->data);
        FreeLibrary(handle);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, ENOENT);
    }

    if (plugin->abi_version != N00B_RENDERER_ABI_VERSION) {
        fprintf(stderr,
                "n00b: ABI version mismatch in '%s': expected %u, got %u\n",
                path->data, N00B_RENDERER_ABI_VERSION, plugin->abi_version);
        FreeLibrary(handle);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EPROTO);
    }

    if (!plugin->vtable || !plugin->name) {
        fprintf(stderr, "n00b: invalid plugin in '%s'\n", path->data);
        FreeLibrary(handle);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EINVAL);
    }

    n00b_renderer_register(n00b_string_from_cstr(plugin->name),
                            plugin->vtable);

    return n00b_result_ok(n00b_renderer_vtable_ptr_t, plugin->vtable);
#else
    void *handle = dlopen(path->data, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "n00b: failed to load renderer '%s': %s\n",
                path->data, dlerror());
        return n00b_result_err(n00b_renderer_vtable_ptr_t, ENOENT);
    }

    const n00b_renderer_plugin_t *plugin =
        (const n00b_renderer_plugin_t *)dlsym(handle, "n00b_renderer_plugin");

    if (!plugin) {
        fprintf(stderr, "n00b: no n00b_renderer_plugin symbol in '%s': %s\n",
                path->data, dlerror());
        dlclose(handle);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, ENOENT);
    }

    if (plugin->abi_version != N00B_RENDERER_ABI_VERSION) {
        fprintf(stderr,
                "n00b: ABI version mismatch in '%s': expected %u, got %u\n",
                path->data, N00B_RENDERER_ABI_VERSION, plugin->abi_version);
        dlclose(handle);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EPROTO);
    }

    if (!plugin->vtable || !plugin->name) {
        fprintf(stderr, "n00b: invalid plugin in '%s'\n", path->data);
        dlclose(handle);
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EINVAL);
    }

    n00b_renderer_register(n00b_string_from_cstr(plugin->name),
                            plugin->vtable);

    // Don't dlclose — the vtable is still in use.
    return n00b_result_ok(n00b_renderer_vtable_ptr_t, plugin->vtable);
#endif
}

n00b_result_t(n00b_renderer_vtable_ptr_t)
n00b_renderer_load_by_name(n00b_string_t *name)
{
    if (!name) {
        return n00b_result_err(n00b_renderer_vtable_ptr_t, EINVAL);
    }

    n00b_renderer_registry_init();

    // First check if already registered.
    n00b_option_t(n00b_renderer_vtable_ptr_t) found =
        n00b_renderer_find(name);

    if (n00b_option_is_set(found)) {
        return n00b_result_ok(n00b_renderer_vtable_ptr_t,
                               n00b_option_get(found));
    }

#if defined(__APPLE__)
    const char *ext = "dylib";
#elif defined(_WIN32)
    const char *ext = "dll";
#else
    const char *ext = "so";
#endif

    char path_buf[1024];

    // Search 1: $N00B_RENDERER_PATH.
    const char *search_path = renderer_getenv("N00B_RENDERER_PATH");
    if (search_path) {
        char buf[4096];
        strncpy(buf, search_path, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char *saveptr = nullptr;
#ifdef _WIN32
        char *dir     = strtok_r(buf, ";", &saveptr);
#else
        char *dir     = strtok_r(buf, ":", &saveptr);
#endif

        while (dir) {
            if (renderer_plugin_dir_trusted(dir)) {
                snprintf(path_buf, sizeof(path_buf),
                         "%s/libn00b_render_%s.%s", dir, name->data, ext);

                n00b_result_t(n00b_renderer_vtable_ptr_t) res =
                    n00b_renderer_load(n00b_string_from_cstr(path_buf));

                if (n00b_result_is_ok(res)) {
                    return res;
                }
            }
#ifdef _WIN32
            dir = strtok_r(nullptr, ";", &saveptr);
#else
            dir = strtok_r(nullptr, ":", &saveptr);
#endif
        }
    }

    // Search 2: $HOME/.n00b/renderers/.
    const char *home = renderer_getenv("HOME");
    if (home) {
        char dir_buf[1024];
        snprintf(dir_buf, sizeof(dir_buf),
                 "%s/.n00b/renderers", home);

        if (renderer_plugin_dir_trusted(dir_buf)) {
            snprintf(path_buf, sizeof(path_buf),
                     "%s/libn00b_render_%s.%s", dir_buf, name->data, ext);

            n00b_result_t(n00b_renderer_vtable_ptr_t) res =
                n00b_renderer_load(n00b_string_from_cstr(path_buf));

            if (n00b_result_is_ok(res)) {
                return res;
            }
        }
    }

    // Search 3: /usr/local/lib/n00b/renderers/.
    if (renderer_plugin_dir_trusted("/usr/local/lib/n00b/renderers")) {
        snprintf(path_buf, sizeof(path_buf),
                 "/usr/local/lib/n00b/renderers/libn00b_render_%s.%s", name->data, ext);

        n00b_result_t(n00b_renderer_vtable_ptr_t) res =
            n00b_renderer_load(n00b_string_from_cstr(path_buf));

        if (n00b_result_is_ok(res)) {
            return res;
        }
    }

    return n00b_result_err(n00b_renderer_vtable_ptr_t, ENOENT);
}

// -------------------------------------------------------------------
// Initialization
// -------------------------------------------------------------------

void
n00b_renderer_registry_init(void)
{
    if (registry_initialized) {
        return;
    }
    registry_initialized = true;

    n00b_renderer_register(r"stream", &n00b_renderer_stream);
    n00b_renderer_register(r"ansi",   &n00b_renderer_ansi);
    n00b_renderer_register(r"dumb",   &n00b_renderer_dumb);

    const n00b_renderer_vtable_t *gui_vtable = nullptr;

#if defined(__APPLE__)
    n00b_renderer_register(r"cocoa", &n00b_renderer_cocoa);
    gui_vtable = &n00b_renderer_cocoa;
#endif

#if defined(N00B_HAVE_X11)
    n00b_renderer_register(r"x11", &n00b_renderer_x11);
    if (!gui_vtable) {
        gui_vtable = &n00b_renderer_x11;
    }
#endif

#if defined(N00B_HAVE_NOTCURSES)
    n00b_renderer_register(r"notcurses", &n00b_renderer_notcurses);
#endif

    if (gui_vtable) {
        // Portable GUI alias (actual window backend):
        //   macOS -> cocoa
        //   Linux/Unix -> x11
        n00b_renderer_register(r"gui", gui_vtable);
    }
}
