/**
 * @file path.h
 * @brief Filesystem path utilities — resolution, joining, walking, temp files.
 */

#pragma once

#include "core/alloc.h"
#include "adt/list.h"
#include "adt/array.h"
#include "adt/option.h"
#include "adt/result.h"
#include "text/strings/string_ops.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef S_IFIFO
#ifdef _S_IFIFO
#define S_IFIFO _S_IFIFO
#else
#define S_IFIFO 0x1000
#endif
#endif

#ifndef S_IFBLK
#define S_IFBLK 0x6000
#endif

#ifndef S_IFLNK
#define S_IFLNK 0xA000
#endif

#ifndef S_IFSOCK
#define S_IFSOCK 0xC000
#endif
#else
#include <unistd.h>
#include <pwd.h>
#endif

typedef enum {
    N00B_FK_NOT_FOUND       = 0,
    N00B_FK_IS_REG_FILE     = S_IFREG,
    N00B_FK_IS_DIR          = S_IFDIR,
    N00B_FK_IS_FLINK        = S_IFLNK,
    N00B_FK_IS_DLINK        = S_IFLNK | S_IFDIR,
    N00B_FK_IS_SOCK         = S_IFSOCK,
    N00B_FK_IS_CHR_DEVICE   = S_IFCHR,
    N00B_FK_IS_BLOCK_DEVICE = S_IFBLK,
    N00B_FK_IS_FIFO         = S_IFIFO,
    N00B_FK_OTHER           = ~0,
} n00b_file_kind;

#ifndef N00B_FILE_T_DECLARED
#define N00B_FILE_T_DECLARED
typedef struct n00b_file n00b_file_t;
#endif

/** @brief Exact destination commit policy. */
typedef enum {
    /** Fail with `EEXIST` if the destination already exists. */
    N00B_PATH_COMMIT_REJECT_EXISTING,
    /** Replace an existing destination with the source path. */
    N00B_PATH_COMMIT_REPLACE_EXISTING,
} n00b_path_commit_policy_t;

/** @brief Open sibling temp file returned by @ref n00b_new_sibling_temp_file. */
typedef struct {
    /** Created temp path in the destination directory. */
    n00b_string_t *path;
    /** Open temp file handle; caller closes it. */
    n00b_file_t   *file;
} n00b_sibling_temp_file_t;

extern n00b_string_t *n00b_resolve_path(n00b_string_t *s);
/**
 * @brief Resolve @p path using caller-owned scratch allocation.
 *
 * Equivalent to @ref n00b_resolve_path for supported filesystem paths, but all
 * strings created during normalization are allocated with @p allocator. This is
 * intended for allocator-threaded helpers that must not hide default-allocator
 * path construction.
 *
 * @param path Path to resolve. `nullptr` or empty resolves to the current
 *             user's home directory.
 *
 * @kw allocator Allocator for the returned string and scratch path pieces.
 *
 * @return Normalized absolute path, or `nullptr` when normalization would
 *         escape above filesystem root or the current directory cannot be read.
 */
extern n00b_string_t *
_n00b_resolve_path_alloc(n00b_string_t *path) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

#define n00b_resolve_path_alloc(p, ...) \
    _n00b_resolve_path_alloc((p) __VA_OPT__(, ) __VA_ARGS__)

extern n00b_string_t *n00b_path_tilde_expand(n00b_string_t *in);
extern n00b_string_t *n00b_get_user_dir(n00b_string_t *user);
extern n00b_string_t *n00b_get_current_directory(void);
extern bool           n00b_set_current_directory(n00b_string_t *s);
extern n00b_string_t *n00b_path_join(n00b_list_t(n00b_string_t *) *items);

/**
 * @brief One directory entry returned by @c n00b_path_list_dir.
 *
 * @c size / @c mtime_ns are best-effort: 0 if the per-entry stat failed.
 */
typedef struct {
    n00b_string_t *name;     /**< Entry name (no path prefix). */
    bool           is_dir;   /**< True if a directory. */
    uint64_t       size;     /**< File size in bytes (0 if unknown). */
    uint64_t       mtime_ns; /**< Modify time, ns since epoch (0 if unknown). */
} n00b_dirent_t;

/**
 * @brief List a directory's entries WITHOUT libc (no opendir/readdir/stat).
 *
 * Uses raw syscalls (getdirentries64 + fstatat64 on Darwin, getdents64 +
 * newfstatat on Linux), so it is safe to call from an n00b worker thread —
 * libc's opendir() allocates via libsystem_malloc, which traps on a worker.
 * The "." and ".." entries are skipped.
 *
 * @param path Directory path (NUL-terminated via @c ->data).
 * @param ok   Out: set true on a successful open+read; false if the directory
 *             could not be opened (consult @c errno). May be NULL.
 *
 * @kw allocator Pool for the returned list, entries, and names.
 *
 * @return A list of @c n00b_dirent_t* (empty on failure).
 */
extern n00b_list_t(n00b_dirent_t *)
n00b_path_list_dir(n00b_string_t *path, bool *ok)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Join a path from a typed-variadic argument tail.
 *
 * Ergonomic variadic builder over @c n00b_path_join. Accepts a
 * required leading component @p first followed by zero or more
 * additional `n00b_string_t *` pieces. Pieces are joined with `/`
 * separators per the same semantics as @c n00b_path_simple_join:
 * an absolute piece (one whose first byte is `/`) re-roots the
 * result.
 *
 * @param first  First path component (required; must be non-null).
 * @param ...    Additional `n00b_string_t *` pieces.
 *
 * @return A newly-allocated string carrying the joined path. Empty
 *         pieces are skipped; an absolute piece anywhere in the tail
 *         re-roots the join. With only @p first and no variadic
 *         tail, returns @p first verbatim.
 */
extern n00b_string_t *
n00b_path_join_v(n00b_string_t *first, n00b_string_t * +);

/**
 * @brief Resolve the XDG Base Directory `XDG_CONFIG_HOME` per the
 *        freedesktop.org spec.
 *
 * Returns the value of `$XDG_CONFIG_HOME` if set and non-empty;
 * otherwise returns `$HOME/.config`. Per the spec, an empty
 * `$XDG_CONFIG_HOME` is treated identically to unset.
 *
 * @return Spec-compliant config home (no trailing slash). Falls
 *         back to `/.config` if both `$XDG_CONFIG_HOME` and `$HOME`
 *         are unset/empty (an edge case the spec does not address).
 */
extern n00b_string_t *n00b_xdg_config_home(void);

/**
 * @brief Resolve the XDG Base Directory `XDG_DATA_HOME` per spec.
 *
 * Returns `$XDG_DATA_HOME` if set and non-empty; otherwise
 * `$HOME/.local/share`. Empty `$XDG_DATA_HOME` is treated as unset.
 *
 * @return Spec-compliant data home (no trailing slash).
 */
extern n00b_string_t *n00b_xdg_data_home(void);

/**
 * @brief Resolve the XDG Base Directory `XDG_CACHE_HOME` per spec.
 *
 * Returns `$XDG_CACHE_HOME` if set and non-empty; otherwise
 * `$HOME/.cache`. Empty `$XDG_CACHE_HOME` is treated as unset.
 *
 * @return Spec-compliant cache home (no trailing slash).
 */
extern n00b_string_t *n00b_xdg_cache_home(void);

/**
 * @brief Resolve the XDG Base Directory `XDG_STATE_HOME` per spec.
 *
 * Returns `$XDG_STATE_HOME` if set and non-empty; otherwise
 * `$HOME/.local/state`. Empty `$XDG_STATE_HOME` is treated as
 * unset.
 *
 * @return Spec-compliant state home (no trailing slash).
 */
extern n00b_string_t *n00b_xdg_state_home(void);

/**
 * @brief Resolve `XDG_RUNTIME_DIR` per spec.
 *
 * Unlike the `*_HOME` variants the spec defines no fallback for
 * runtime dir. Callers decide how to handle absence.
 *
 * @return The value of `$XDG_RUNTIME_DIR` if set and non-empty,
 *         else `nullptr`.
 */
extern n00b_string_t *n00b_xdg_runtime_dir(void);

/**
 * @brief Build a path under `$XDG_CONFIG_HOME/<app>/...`.
 *
 * Composes the XDG config base with @p app and the variadic
 * trailing pieces. Equivalent to
 * `n00b_path_join_v(n00b_xdg_config_home(), app, ...)`.
 *
 * @param app  Application namespace (required; must be non-null
 *             and non-empty).
 * @param ...  Additional `n00b_string_t *` path pieces.
 *
 * @return Joined path (no trailing slash).
 */
extern n00b_string_t *
n00b_xdg_config_path(n00b_string_t *app, n00b_string_t * +);

/**
 * @brief Build a path under `$XDG_DATA_HOME/<app>/...`.
 *
 * @param app  Application namespace.
 * @param ...  Additional `n00b_string_t *` path pieces.
 */
extern n00b_string_t *
n00b_xdg_data_path(n00b_string_t *app, n00b_string_t * +);

/**
 * @brief Build a path under `$XDG_CACHE_HOME/<app>/...`.
 *
 * @param app  Application namespace.
 * @param ...  Additional `n00b_string_t *` path pieces.
 */
extern n00b_string_t *
n00b_xdg_cache_path(n00b_string_t *app, n00b_string_t * +);

/**
 * @brief Build a path under `$XDG_STATE_HOME/<app>/...`.
 *
 * @param app  Application namespace.
 * @param ...  Additional `n00b_string_t *` path pieces.
 */
extern n00b_string_t *
n00b_xdg_state_path(n00b_string_t *app, n00b_string_t * +);

/**
 * @brief Build a path under `$XDG_RUNTIME_DIR/<app>/...`.
 *
 * Returns `nullptr` when `$XDG_RUNTIME_DIR` is unset/empty (the
 * spec mandates no fallback).
 *
 * @param app  Application namespace.
 * @param ...  Additional `n00b_string_t *` path pieces.
 *
 * @return Joined path, or `nullptr` if no runtime dir is defined.
 */
extern n00b_string_t *
n00b_xdg_runtime_path(n00b_string_t *app, n00b_string_t * +);

/**
 * @brief Combined path-canonicalization with composable steps.
 *
 * Applies the following transformations in order:
 *   1. `$VAR` / `${VAR}` environment-variable expansion
 *      (controlled by @p expand_env_vars).
 *   2. Leading `~` / `~user` home-directory expansion
 *      (controlled by @p expand_tilde).
 *   3. Absolute-path rooting via the current working directory
 *      (controlled by @p make_absolute).
 *   4. Optional `realpath()` symlink resolution
 *      (controlled by @p resolve_symlinks).
 *
 * @param p  Input path. May contain env-var references, a leading
 *           tilde, and `.`/`..` components.
 *
 * @kw expand_env_vars   Expand `$VAR` / `${VAR}` (default: true).
 *                       Unknown variables expand to the empty
 *                       string.
 * @kw expand_tilde      Expand a leading `~` / `~user` to the
 *                       associated home directory (default: true).
 * @kw make_absolute     If the path is not yet absolute after
 *                       earlier steps, prefix the cwd (default:
 *                       true).
 * @kw resolve_symlinks  Run `realpath()` on the result, collapsing
 *                       symlinks and `.`/`..` (default: false).
 *
 * @return A new string carrying the canonicalized path. With
 *         @p resolve_symlinks = true and the path missing on disk,
 *         returns the pre-realpath value.
 */
extern n00b_string_t *
_n00b_path_canonical(n00b_string_t *p) _kargs {
    bool expand_env_vars  = true;
    bool expand_tilde     = true;
    bool make_absolute    = true;
    bool resolve_symlinks = false;
};

#define n00b_path_canonical(p, ...) \
    _n00b_path_canonical(p __VA_OPT__(,) __VA_ARGS__)

extern n00b_file_kind n00b_get_file_kind(n00b_string_t *p);

extern n00b_list_t(n00b_string_t *) *
_n00b_path_walk(n00b_string_t *dir) _kargs {
    bool recurse        = true;
    bool yield_links    = false;
    bool yield_dirs     = false;
    bool ignore_special = true;
    bool follow_links   = false;
};

extern n00b_string_t *n00b_app_path(void);
extern n00b_string_t *n00b_path_trim_trailing_slashes(n00b_string_t *s);
extern n00b_result_t(n00b_string_t *) n00b_new_temp_dir(n00b_string_t *prefix,
                                                        n00b_string_t *suffix);
/**
 * @brief Build a fresh path under the temp root without creating anything.
 *
 * Returns a path of the form `<TMPDIR>/<prefix><hex><suffix>` where the
 * hex component is a 64-bit random value. The path is *not* checked for
 * existence or created on disk — callers that need a created file or
 * directory should use `n00b_new_temp_dir` or follow this with their own
 * `open(O_CREAT|O_EXCL)` / `bind`. Useful for tests, AF_UNIX socket
 * paths, scratch sidecar files, etc.
 *
 * @param prefix Optional prefix; may be `nullptr` to omit.
 * @param suffix Optional suffix; may be `nullptr` to omit.
 *
 * @kw allocator Allocator for the returned string. `nullptr` uses the
 *               default heap allocator.
 *
 * @return Fresh path string under the temp root. The filesystem entry
 *         is not created.
 */
extern n00b_string_t *
_n00b_new_temp_path(n00b_string_t *prefix, n00b_string_t *suffix) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

#define n00b_new_temp_path(p, s, ...) \
    _n00b_new_temp_path((p), (s) __VA_OPT__(, ) __VA_ARGS__)

/**
 * @brief Build an uncreated sibling temp path for a destination.
 *
 * The returned path is in the same directory as @p destination_path and has a
 * hidden filename derived from the destination basename plus random suffix
 * bytes. It is only a candidate path: callers that need collision safety must
 * create it with an exclusive-create helper such as
 * @ref n00b_file_open_exclusive or use @ref n00b_new_sibling_temp_file.
 *
 * @param destination_path Destination whose parent directory should hold the
 *                         temp file.
 *
 * @kw allocator Allocator for strings directly created by this helper.
 *
 * @return `Ok(path)` on success, `Err(EINVAL)` for null, empty, or
 *         directory-shaped destinations.
 */
extern n00b_result_t(n00b_string_t *)
_n00b_new_sibling_temp_path(n00b_string_t *destination_path) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

#define n00b_new_sibling_temp_path(p, ...) \
    _n00b_new_sibling_temp_path((p) __VA_OPT__(, ) __VA_ARGS__)

/**
 * @brief Create a collision-safe same-directory sibling temp file.
 *
 * Tries random sibling temp names under the destination directory and creates
 * the first available one with exclusive-create semantics. The destination
 * path itself is never opened or overwritten by this helper.
 *
 * @param destination_path Destination whose parent directory should hold the
 *                         temp file.
 *
 * @kw file_mode    Requested creation mode bits (default: `0600`; subject to
 *                  host create-mode behavior such as umask).
 * @kw max_attempts Maximum random candidates to try before reporting
 *                  `EEXIST` (default: 64).
 * @kw allocator    Allocator for the returned record, temp path, and open
 *                  file handle.
 *
 * @return `Ok(temp)` with an open file handle and path. Caller closes
 *         `temp->file` and removes `temp->path` when appropriate.
 */
extern n00b_result_t(n00b_sibling_temp_file_t *)
_n00b_new_sibling_temp_file(n00b_string_t *destination_path) _kargs {
    uint32_t          file_mode    = 0600;
    uint32_t          max_attempts = 64;
    n00b_allocator_t *allocator    = nullptr;
};

#define n00b_new_sibling_temp_file(p, ...) \
    _n00b_new_sibling_temp_file((p) __VA_OPT__(, ) __VA_ARGS__)

/**
 * @brief Create a collision-safe same-directory sibling temp directory.
 *
 * Tries random sibling temp names under the destination directory and creates
 * the first available one with exclusive directory-create semantics. The
 * destination path itself is never created or overwritten by this helper.
 *
 * @param destination_path Destination whose parent directory should hold the
 *                         temp directory.
 *
 * @kw directory_mode Requested creation mode bits (default: `0775`; subject
 *                    to host create-mode behavior such as umask).
 * @kw max_attempts   Maximum random candidates to try before reporting
 *                    `EEXIST` (default: 64).
 * @kw allocator      Allocator for the returned temp path and scratch strings.
 *
 * @return `Ok(path)` with a newly-created temp directory path, or
 *         `Err(errno)` on validation or create failure.
 */
extern n00b_result_t(n00b_string_t *)
_n00b_new_sibling_temp_dir(n00b_string_t *destination_path) _kargs {
    uint32_t          directory_mode = 0775;
    uint32_t          max_attempts   = 64;
    n00b_allocator_t *allocator      = nullptr;
};

#define n00b_new_sibling_temp_dir(p, ...) \
    _n00b_new_sibling_temp_dir((p) __VA_OPT__(, ) __VA_ARGS__)

/**
 * @brief Return the POSIX permission bits (mode & 07777) of @p path.
 *
 * Thin libn00b wrapper around `stat(2)` for the case where the caller
 * needs to inspect mode bits without doing the syscall directly.
 *
 * @param path Path to inspect.
 *
 * @return `Ok(mode)` where @c mode is the low twelve bits of
 *         @c st.st_mode (suid/sgid/sticky + permissions).
 *         `Err(<errno>)` if @c stat fails.
 */
extern n00b_result_t(uint32_t)
n00b_path_get_mode(n00b_string_t *path);

/**
 * @brief File metadata for a path (a libn00b wrapper around stat(2)).
 */
typedef struct {
    bool     exists;    /**< true if the path exists. */
    bool     is_dir;    /**< true if it is a directory. */
    int64_t  size;      /**< size in bytes (0 if !exists). */
    uint64_t mtime_ns;  /**< last-modified wall-clock ns since epoch (0 if !exists). */
} n00b_path_info_t;

/**
 * @brief Stat @p path and report existence, type, size, and mtime.
 *
 * A libn00b wrapper around `stat(2)` so callers can inspect file metadata
 * without doing the syscall directly — the n00b ↔ POSIX boundary for file
 * metadata (n00b-api-guidelines §11); the `stat(2)` call is intentional and
 * confined to `n00b_path_stat`. A missing path is NOT an error: it returns
 * `Ok({.exists = false})`. Other `stat` failures return `Err(errno)`.
 *
 * @param path Path to inspect.
 *
 * @return `Ok(n00b_path_info_t)` on success, including the not-found case
 *         (`.exists == false`). `Err(EINVAL)` if @p path is null;
 *         `Err(<errno>)` on any other `stat` failure.
 */
extern n00b_result_t(n00b_path_info_t)
n00b_path_stat(n00b_string_t *path);

/**
 * @brief Apply POSIX permission bits to a path and report observed bits.
 *
 * @param path Path to update.
 * @param mode Requested low twelve POSIX mode bits.
 *
 * @return `Ok(mode)` with the observed `stat(2)` low twelve mode bits after
 *         application. `Err(ENOSYS)` on hosts without mode support, or
 *         `Err(errno)` on failure.
 */
extern n00b_result_t(uint32_t)
n00b_path_set_mode(n00b_string_t *path, uint32_t mode);

/**
 * @brief Create a directory and any missing parent directories.
 *
 * Existing parent directories are accepted. If @p path already exists as a
 * directory, the result is controlled by @p allow_existing; any non-directory
 * entry at @p path or an intermediate component is reported as `EEXIST`.
 *
 * @param path Directory path to materialize.
 *
 * @kw mode Directory creation mode bits; default `0775`.
 * @kw allow_existing Treat an existing final directory as success; default
 *      `true`.
 * @kw allocator Optional allocator for scratch path strings; default
 *      `nullptr`.
 *
 * @return `Ok(true)` when at least one directory was created, `Ok(false)` when
 *         @p path already existed and @p allow_existing was true, or
 *         `Err(errno)` on failure.
 */
extern n00b_result_t(bool)
_n00b_path_mkdir_p(n00b_string_t *path) _kargs {
    uint32_t          mode           = 0775;
    bool              allow_existing = true;
    n00b_allocator_t *allocator      = nullptr;
};

#define n00b_path_mkdir_p(p, ...) \
    _n00b_path_mkdir_p((p) __VA_OPT__(, ) __VA_ARGS__)

extern n00b_string_t *n00b_get_temp_root(void);
extern n00b_string_t *n00b_filename_from_path(n00b_string_t *s);

extern n00b_list_t(n00b_string_t *) *
n00b_find_file_in_program_path(n00b_string_t *cmd,
                                n00b_list_t(n00b_string_t *) *path_list);

extern n00b_list_t(n00b_string_t *) *
n00b_find_command_paths(n00b_string_t *cmd,
                         n00b_list_t(n00b_string_t *) *path_list,
                         bool self_ok);

extern n00b_result_t(n00b_string_t *) n00b_rename(n00b_string_t *from,
                                                   n00b_string_t *to);

/**
 * @brief Commit one path to an exact destination.
 *
 * Unlike @ref n00b_rename, this helper never chooses a different destination
 * name. With `N00B_PATH_COMMIT_REPLACE_EXISTING`, the destination may be
 * replaced atomically by the host rename primitive. With
 * `N00B_PATH_COMMIT_REJECT_EXISTING`, an existing destination is rejected
 * without replacing it.
 *
 * @param source_path      Existing source/temp path to commit.
 * @param destination_path Exact destination path.
 *
 * @kw policy Existing-destination policy (default:
 *            `N00B_PATH_COMMIT_REJECT_EXISTING`).
 *
 * @return `Ok(destination_path)` on commit success. `Err(EEXIST)` for a
 *         no-replace collision, `Err(ENOSYS)` when the host lacks an exact
 *         no-replace rename primitive, or `Err(errno)` for other failures.
 *         On failure, @p source_path remains available for caller-observable
 *         cleanup.
 */
extern n00b_result_t(n00b_string_t *)
_n00b_path_commit_exact(n00b_string_t *source_path,
                        n00b_string_t *destination_path) _kargs {
    n00b_path_commit_policy_t policy = N00B_PATH_COMMIT_REJECT_EXISTING;
};

#define n00b_path_commit_exact(s, d, ...) \
    _n00b_path_commit_exact((s), (d) __VA_OPT__(, ) __VA_ARGS__)

/**
 * @brief Remove a filesystem entry (libc `unlink` wrapper).
 *
 * Thin allocator-aware libn00b wrapper around POSIX `unlink(2)`.
 * Centralizes the `unlink + errno` pattern so consumer code never has
 * to reach for `<unistd.h>` / `<errno.h>` directly (cf. §11 — the
 * `n00b<->POSIX` line is contained here).
 *
 * @param path  Path to remove. Must be non-null.
 *
 * @kw ignore_missing  If `true`, an `ENOENT` from the underlying
 *                     `unlink` is reported as `Ok(false)` rather than
 *                     an error. Use this for idempotent delete
 *                     semantics (e.g. a sidecar that may already be
 *                     absent). Default: `false`.
 *
 * @return `Ok(true)` on a successful removal. `Ok(false)` when the
 *         target was absent and `ignore_missing` was `true`.
 *         `Err(<errno>)` carrying the POSIX errno on any other
 *         failure.
 */
extern n00b_result_t(bool)
_n00b_file_unlink(n00b_string_t *path) _kargs {
    bool ignore_missing = false;
};

#define n00b_file_unlink(p, ...) \
    _n00b_file_unlink(p __VA_OPT__(,) __VA_ARGS__)

/**
 * @brief Remove a filesystem tree without following directory symlinks.
 *
 * Deletes regular files and symlinks with unlink semantics, then recursively
 * deletes directory contents before removing each directory. This helper is
 * intended for cleanup of temporary trees created by higher-level atomic
 * operations.
 *
 * @param path File or directory tree root to remove.
 *
 * @kw ignore_missing Report a missing @p path as `Ok(false)` rather than an
 *                    error; default `false`.
 * @kw allocator      Allocator for scratch path strings; default `nullptr`.
 *
 * @return `Ok(true)` when an entry was removed, `Ok(false)` when @p path was
 *         missing and @p ignore_missing was true, or `Err(errno)` on failure.
 */
extern n00b_result_t(bool)
_n00b_path_remove_tree(n00b_string_t *path) _kargs {
    bool              ignore_missing = false;
    n00b_allocator_t *allocator      = nullptr;
};

#define n00b_path_remove_tree(p, ...) \
    _n00b_path_remove_tree((p) __VA_OPT__(, ) __VA_ARGS__)

extern n00b_list_t(n00b_string_t *) *n00b_path_parts(n00b_string_t *p);

extern n00b_list_t(n00b_string_t *) *
_n00b_list_directory(n00b_string_t *dir) _kargs {
    n00b_string_t *extension   = nullptr;
    bool           files       = true;
    bool           directories = true;
    bool           links       = true;
    bool           specials    = true;
    bool           full_path   = false;
    bool           dot_files   = true;
};

extern n00b_string_t *n00b_path_get_extension(n00b_string_t *s);
extern n00b_string_t *n00b_path_remove_extension(n00b_string_t *s);
extern void           n00b_path_strip_slashes_both_ends(n00b_string_t *s);
extern n00b_string_t *n00b_path_chop_extension(n00b_string_t *s);

#define n00b_path_walk(x, ...) \
    _n00b_path_walk(x __VA_OPT__(,) __VA_ARGS__)
#define n00b_list_directory(x, ...) \
    _n00b_list_directory(x __VA_OPT__(,) __VA_ARGS__)

static inline bool
n00b_path_exists(n00b_string_t *s)
{
    return n00b_get_file_kind(s) != N00B_FK_NOT_FOUND;
}

static inline bool
n00b_path_is_file(n00b_string_t *s)
{
    switch (n00b_get_file_kind(s)) {
    case N00B_FK_IS_REG_FILE:
    case N00B_FK_IS_FLINK:
        return true;
    default:
        return false;
    }
}

static inline bool
n00b_path_is_directory(n00b_string_t *s)
{
    switch (n00b_get_file_kind(s)) {
    case N00B_FK_IS_DIR:
    case N00B_FK_IS_DLINK:
        return true;
    default:
        return false;
    }
}

static inline bool
n00b_path_is_link(n00b_string_t *s)
{
    switch (n00b_get_file_kind(s)) {
    case N00B_FK_IS_FLINK:
    case N00B_FK_IS_DLINK:
        return true;
    default:
        return false;
    }
}

static inline n00b_string_t *
n00b_get_home_directory(void)
{
    return n00b_get_user_dir(nullptr);
}

static inline bool
n00b_file_exists(n00b_string_t *filename)
{
    struct stat info;
    return stat(filename->data, &info) == 0;
}

static inline n00b_string_t *
n00b_path_simple_join(n00b_string_t *p1, n00b_string_t *p2)
{
    if (p2->u8_bytes && p2->data[0] == '/') {
        return p2;
    }

    if (!p1 || !p1->codepoints) {
        p1 = r"/";
    }

    n00b_list_t(n00b_string_t *) parts =
        n00b_list_new_private(n00b_string_t *);
    n00b_list_push(parts, p1);
    n00b_list_push(parts, p2);

    return n00b_path_join(&parts);
}

static inline n00b_string_t *
n00b_get_user_name(void)
{
#ifdef _WIN32
    const char *name = getenv("USERNAME");
    if (name == nullptr || name[0] == '\0') {
        name = getenv("USER");
    }
    return n00b_string_from_cstr(name == nullptr ? "" : name);
#else
    struct passwd *pw = getpwuid(getuid());
    return n00b_string_from_cstr(pw->pw_name);
#endif
}

static inline n00b_list_t(n00b_string_t *) *
n00b_get_program_search_path(void)
{
    const char *path = getenv("PATH");

    // Canonical idiom: build a fully scan-info-threaded list as an
    // lvalue first, then struct-copy into a heap-allocated result so
    // the GC sees the threaded scan_kind / scan_cb / scan_user /
    // allocator fields on the heap struct. See list.h _n00b_list_new_sel.
    n00b_list_t(n00b_string_t *) lst = n00b_list_new(n00b_string_t *);

    if (path) {
        const char *separator = ":";
#ifdef _WIN32
        separator = ";";
        if (strchr(path, ';') == nullptr && path[0] == '/') {
            separator = ":";
        }
#endif
        n00b_string_t *ps = n00b_string_from_cstr(path);
        n00b_array_t(n00b_string_t *) parts =
            n00b_unicode_str_split(ps, n00b_string_from_cstr(separator));

        for (size_t i = 0; i < n00b_array_len(parts); i++) {
            n00b_list_push(lst, n00b_array_get(parts, i));
        }
    }

    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *result = lst;
    return result;
}

static inline n00b_option_t(n00b_string_t *)
n00b_find_first_command_path(n00b_string_t *s,
                              n00b_list_t(n00b_string_t *) *l,
                              bool self)
{
    n00b_list_t(n00b_string_t *) *resolved =
        n00b_find_command_paths(s, l, self);

    if (!n00b_list_len(*resolved)) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_set(n00b_string_t *, n00b_list_get(*resolved, 0));
}
