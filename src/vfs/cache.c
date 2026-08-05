#include "vfs/cache.h"
#include "core/alloc.h"
#include "core/hash.h"

#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>

#ifdef _WIN32
#define N00B_CACHE_OPEN(path, flags, mode) _open((path), (flags), (mode))
#define N00B_CACHE_READ(fd, buf, len) _read((fd), (buf), (unsigned int)(len))
#define N00B_CACHE_WRITE(fd, buf, len) _write((fd), (buf), (unsigned int)(len))
#define N00B_CACHE_CLOSE(fd) _close(fd)
#define N00B_CACHE_UNLINK(path) _unlink(path)
#define N00B_CACHE_MKDIR(path, mode) _mkdir(path)
#else
#define N00B_CACHE_OPEN(path, flags, mode) open((path), (flags), (mode))
#define N00B_CACHE_READ(fd, buf, len) read((fd), (buf), (len))
#define N00B_CACHE_WRITE(fd, buf, len) write((fd), (buf), (len))
#define N00B_CACHE_CLOSE(fd) close(fd)
#define N00B_CACHE_UNLINK(path) unlink(path)
#define N00B_CACHE_MKDIR(path, mode) mkdir(path, mode)
#endif

#define INITIAL_ENTRIES 16

// ============================================================================
// Helpers
// ============================================================================

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Build a cache-side file path from a backend path.
 * Uses a hex-encoded hash to avoid path length / character issues.
 */
static n00b_string_t *
cache_file_path(n00b_vfs_cache_t *cache, n00b_string_t *backend_path)
{
    n00b_uint128_t hash = n00b_string_hash(backend_path);
    char hex[33];
    snprintf(hex, sizeof(hex), "%016llx%016llx",
             (unsigned long long)(hash >> 64),
             (unsigned long long)(hash & 0xFFFFFFFFFFFFFFFFULL));

    size_t clen = cache->cache_dir->u8_bytes;
    // cache_dir + '/' + hex + '\0'
    size_t total = clen + 1 + 32 + 1;
    char *buf = n00b_alloc_array(char, total);
    memcpy(buf, cache->cache_dir->data, clen);
    buf[clen] = '/';
    memcpy(buf + clen + 1, hex, 32);
    buf[clen + 33] = '\0';

    return n00b_string_from_raw(buf, (int64_t)(clen + 33));
}

static n00b_vfs_cache_entry_t *
find_entry(n00b_vfs_cache_t *cache, n00b_string_t *path)
{
    for (uint32_t i = 0; i < cache->nentries; i++) {
        n00b_vfs_cache_entry_t *e = cache->entries[i];
        if (e != nullptr
            && e->backend_path->u8_bytes == path->u8_bytes
            && memcmp(e->backend_path->data, path->data,
                      path->u8_bytes) == 0) {
            return e;
        }
    }
    return nullptr;
}

static void
ensure_entries_cap(n00b_vfs_cache_t *cache, uint32_t needed)
{
    if (needed <= cache->entries_cap) {
        return;
    }
    uint32_t new_cap = cache->entries_cap;
    while (new_cap < needed) {
        new_cap *= 2;
    }
    n00b_vfs_cache_entry_t **new_arr =
        n00b_alloc_array(n00b_vfs_cache_entry_t *, new_cap);
    if (cache->nentries > 0) {
        memcpy(new_arr, cache->entries,
               cache->nentries * sizeof(n00b_vfs_cache_entry_t *));
    }
    cache->entries     = new_arr;
    cache->entries_cap = new_cap;
}

static n00b_vfs_cache_entry_t *
add_entry(n00b_vfs_cache_t *cache, n00b_string_t *path)
{
    n00b_vfs_cache_entry_t *e = n00b_alloc(n00b_vfs_cache_entry_t);
    e->backend_path     = path;
    e->cache_path       = cache_file_path(cache, path);
    e->state            = N00B_VFS_CACHE_INVALID;
    e->last_access_ns   = now_ns();

    ensure_entries_cap(cache, cache->nentries + 1);
    cache->entries[cache->nentries++] = e;
    return e;
}

/**
 * Write a buffer to a file at the given path (NUL-terminated C string).
 */
static bool
write_file(const char *path, n00b_buffer_t *data)
{
    int fd = N00B_CACHE_OPEN(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return false;
    }

    int64_t len;
    char *src = n00b_buffer_to_c(data, &len);
    size_t total = 0;
    while (total < (size_t)len) {
        ssize_t w = N00B_CACHE_WRITE(fd, src + total, (size_t)len - total);
        if (w < 0) {
            N00B_CACHE_CLOSE(fd);
            return false;
        }
        total += (size_t)w;
    }
    N00B_CACHE_CLOSE(fd);
    return true;
}

/**
 * Read a whole file into a buffer.
 */
static n00b_buffer_t *
read_file(const char *path)
{
    int fd = N00B_CACHE_OPEN(path, O_RDONLY, 0);
    if (fd < 0) {
        return nullptr;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        N00B_CACHE_CLOSE(fd);
        return nullptr;
    }

    size_t size = (size_t)st.st_size;
    n00b_buffer_t *buf = n00b_buffer_new((int64_t)size);
    if (size > 0) {
        n00b_buffer_resize(buf, size);
        char *dst = n00b_buffer_to_c(buf, nullptr);
        size_t total = 0;
        while (total < size) {
            ssize_t r = N00B_CACHE_READ(fd, dst + total, size - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
    }
    N00B_CACHE_CLOSE(fd);
    return buf;
}

/**
 * NUL-terminated C string from n00b_string_t.
 */
static const char *
str_cstr(n00b_string_t *s)
{
    // n00b_string_t data is NUL-terminated after init.
    return s->data;
}

// ============================================================================
// Lifecycle
// ============================================================================

n00b_result_t(n00b_vfs_cache_t *)
n00b_vfs_cache_new(n00b_string_t *cache_dir, n00b_vfs_backend_t *backend,
                   n00b_vfs_cache_policy_t policy)
{
    if (cache_dir == nullptr || backend == nullptr) {
        return n00b_result_err(n00b_vfs_cache_t *, N00B_VFS_ERR_NULL_ARG);
    }

    // Ensure cache directory exists.
    const char *cdir = str_cstr(cache_dir);
    struct stat st;
    if (stat(cdir, &st) < 0) {
        if (N00B_CACHE_MKDIR(cdir, 0755) < 0) {
            return n00b_result_err(n00b_vfs_cache_t *, N00B_VFS_ERR_IO);
        }
    }

    n00b_vfs_cache_t *c = n00b_alloc(n00b_vfs_cache_t);
    c->cache_dir    = cache_dir;
    c->policy       = policy;
    c->backend      = backend;
    c->entries      = n00b_alloc_array(n00b_vfs_cache_entry_t *, INITIAL_ENTRIES);
    c->entries_cap  = INITIAL_ENTRIES;
    c->nentries     = 0;
    c->total_size   = 0;
    c->lock         = n00b_data_lock_new();

    return n00b_result_ok(n00b_vfs_cache_t *, c);
}

void
n00b_vfs_cache_destroy(n00b_vfs_cache_t *cache)
{
    if (cache == nullptr) return;

    // Flush all dirty entries.
    for (uint32_t i = 0; i < cache->nentries; i++) {
        n00b_vfs_cache_entry_t *e = cache->entries[i];
        if (e != nullptr && e->state == N00B_VFS_CACHE_DIRTY) {
            (void)n00b_vfs_cache_flush(cache, e->backend_path);
        }
    }

    // Remove cache files.
    for (uint32_t i = 0; i < cache->nentries; i++) {
        n00b_vfs_cache_entry_t *e = cache->entries[i];
        if (e != nullptr && e->cache_path != nullptr) {
            N00B_CACHE_UNLINK(str_cstr(e->cache_path));
        }
    }
}

// ============================================================================
// Get
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_vfs_cache_get(n00b_vfs_cache_t *cache, n00b_string_t *path,
                   uint64_t offset, uint64_t length)
{
    n00b_data_read_lock(cache->lock);
    n00b_vfs_cache_entry_t *e = find_entry(cache, path);
    n00b_data_unlock(cache->lock);

    if (e != nullptr
        && (e->state == N00B_VFS_CACHE_CLEAN
            || e->state == N00B_VFS_CACHE_LINKED
            || e->state == N00B_VFS_CACHE_DIRTY)) {

        // Check staleness.
        if (cache->policy.max_entry_age_ns > 0
            && e->state != N00B_VFS_CACHE_DIRTY) {
            uint64_t age = now_ns() - e->last_validated_ns;
            if (age > cache->policy.max_entry_age_ns) {
                e->state = N00B_VFS_CACHE_STALE;
            }
        }

        if (e->state != N00B_VFS_CACHE_STALE) {
            e->last_access_ns = now_ns();

            // Read from cache file.
            n00b_buffer_t *buf = read_file(str_cstr(e->cache_path));
            if (buf != nullptr) {
                size_t blen = n00b_buffer_len(buf);
                if (offset >= blen) {
                    return n00b_result_ok(n00b_buffer_t *, n00b_buffer_empty());
                }
                uint64_t avail = blen - offset;
                if (length > avail) length = avail;
                if (offset == 0 && length == blen) {
                    return n00b_result_ok(n00b_buffer_t *, buf);
                }
                return n00b_result_ok(n00b_buffer_t *,
                    n00b_buffer_get_slice(buf, (int64_t)offset,
                                          (int64_t)(offset + length)));
            }
        }
    }

    // Cache miss or stale — fetch from backend.
    n00b_result_t(n00b_buffer_t *) br =
        cache->backend->ops->get(cache->backend->ctx, path);

    if (n00b_result_is_err(br)) {
        return br;
    }

    n00b_buffer_t *full = n00b_result_get(br);

    // Evict if needed before adding.
    if (cache->policy.max_entries > 0
        && cache->nentries >= cache->policy.max_entries) {
        n00b_vfs_cache_evict_lru(cache);
    }

    // Store in cache.
    n00b_data_write_lock(cache->lock);
    e = find_entry(cache, path);
    if (e == nullptr) {
        e = add_entry(cache, path);
    }
    n00b_data_unlock(cache->lock);

    write_file(str_cstr(e->cache_path), full);
    e->state             = N00B_VFS_CACHE_CLEAN;
    uint64_t new_size    = n00b_buffer_len(full);
    e->size              = new_size;
    e->last_validated_ns = now_ns();
    e->last_access_ns    = now_ns();
    atomic_fetch_add(&cache->total_size, new_size);

    // Return requested range.
    size_t blen = n00b_buffer_len(full);
    if (offset >= blen) {
        return n00b_result_ok(n00b_buffer_t *, n00b_buffer_empty());
    }
    uint64_t avail = blen - offset;
    if (length > avail) length = avail;
    if (offset == 0 && length == blen) {
        return n00b_result_ok(n00b_buffer_t *, full);
    }
    return n00b_result_ok(n00b_buffer_t *,
        n00b_buffer_get_slice(full, (int64_t)offset,
                              (int64_t)(offset + length)));
}

// ============================================================================
// Put
// ============================================================================

n00b_result_t(bool)
n00b_vfs_cache_put(n00b_vfs_cache_t *cache, n00b_string_t *path,
                   n00b_buffer_t *data)
{
    n00b_data_write_lock(cache->lock);
    n00b_vfs_cache_entry_t *e = find_entry(cache, path);
    if (e == nullptr) {
        e = add_entry(cache, path);
    }
    n00b_data_unlock(cache->lock);

    if (!write_file(str_cstr(e->cache_path), data)) {
        return n00b_result_err(bool, N00B_VFS_ERR_CACHE);
    }

    uint64_t old_size = atomic_load(&e->size);
    uint64_t new_size = n00b_buffer_len(data);
    atomic_fetch_sub(&cache->total_size, old_size);
    e->size = new_size;
    atomic_fetch_add(&cache->total_size, new_size);
    e->state          = N00B_VFS_CACHE_DIRTY;
    e->last_access_ns = now_ns();

    if (cache->policy.write_through) {
        return n00b_vfs_cache_flush(cache, path);
    }

    return n00b_result_ok(bool, true);
}

// ============================================================================
// Invalidate
// ============================================================================

n00b_result_t(bool)
n00b_vfs_cache_invalidate(n00b_vfs_cache_t *cache, n00b_string_t *path)
{
    n00b_data_write_lock(cache->lock);
    n00b_vfs_cache_entry_t *e = find_entry(cache, path);
    n00b_data_unlock(cache->lock);

    if (e == nullptr) {
        return n00b_result_ok(bool, true);  // Nothing to invalidate.
    }

    // Remove cache file.
    N00B_CACHE_UNLINK(str_cstr(e->cache_path));
    atomic_fetch_sub(&cache->total_size, atomic_load(&e->size));
    e->state = N00B_VFS_CACHE_INVALID;
    e->size  = 0;

    return n00b_result_ok(bool, true);
}

// ============================================================================
// Flush
// ============================================================================

n00b_result_t(bool)
n00b_vfs_cache_flush(n00b_vfs_cache_t *cache, n00b_string_t *path)
{
    n00b_data_read_lock(cache->lock);
    n00b_vfs_cache_entry_t *e = find_entry(cache, path);
    n00b_data_unlock(cache->lock);

    if (e == nullptr || e->state != N00B_VFS_CACHE_DIRTY) {
        return n00b_result_ok(bool, true);
    }

    // Read from cache file and push to backend.
    n00b_buffer_t *data = read_file(str_cstr(e->cache_path));
    if (data == nullptr) {
        return n00b_result_err(bool, N00B_VFS_ERR_CACHE);
    }

    n00b_result_t(bool) r =
        cache->backend->ops->put(cache->backend->ctx, path, data);

    if (n00b_result_is_ok(r)) {
        e->state             = N00B_VFS_CACHE_CLEAN;
        e->last_validated_ns = now_ns();
    }

    return r;
}

// ============================================================================
// Evict LRU
// ============================================================================

void
n00b_vfs_cache_evict_lru(n00b_vfs_cache_t *cache)
{
    if (cache->nentries == 0) return;

    // Find LRU entry that isn't currently open.
    uint32_t victim = UINT32_MAX;
    uint64_t oldest = UINT64_MAX;

    for (uint32_t i = 0; i < cache->nentries; i++) {
        n00b_vfs_cache_entry_t *e = cache->entries[i];
        if (e == nullptr || e->open_count > 0) continue;
        if (e->last_access_ns < oldest) {
            oldest = e->last_access_ns;
            victim = i;
        }
    }

    if (victim == UINT32_MAX) return;

    n00b_vfs_cache_entry_t *e = cache->entries[victim];

    // Flush dirty entries before eviction.
    if (e->state == N00B_VFS_CACHE_DIRTY) {
        (void)n00b_vfs_cache_flush(cache, e->backend_path);
    }

    // Remove cache file.
    N00B_CACHE_UNLINK(str_cstr(e->cache_path));
    atomic_fetch_sub(&cache->total_size, atomic_load(&e->size));

    // Remove from array by swapping with last.
    cache->entries[victim] = cache->entries[cache->nentries - 1];
    cache->entries[cache->nentries - 1] = nullptr;
    cache->nentries--;
}

// ============================================================================
// Open / Close notifications
// ============================================================================

n00b_result_t(n00b_vfs_cache_entry_t *)
n00b_vfs_cache_open(n00b_vfs_cache_t *cache, n00b_string_t *path,
                    bool for_write)
{
    n00b_data_write_lock(cache->lock);
    n00b_vfs_cache_entry_t *e = find_entry(cache, path);
    if (e == nullptr) {
        e = add_entry(cache, path);
    }
    n00b_data_unlock(cache->lock);

    e->open_count++;
    e->last_access_ns = now_ns();

    if (for_write) {
        e->write_count++;

        // Break hard link if linked (COW).
        if (e->state == N00B_VFS_CACHE_LINKED) {
            // Read data through the link.
            n00b_buffer_t *data = read_file(str_cstr(e->cache_path));
            // Remove the link.
            N00B_CACHE_UNLINK(str_cstr(e->cache_path));
            // Write an independent copy.
            if (data != nullptr) {
                write_file(str_cstr(e->cache_path), data);
            }
            e->state = N00B_VFS_CACHE_DIRTY;
        }
    }
    else if (e->state == N00B_VFS_CACHE_INVALID && cache->policy.use_hard_links
             && cache->backend->ops->supports_link != nullptr
             && cache->backend->ops->supports_link(cache->backend->ctx)) {
        // Try to create a hard link for read-only access.
        n00b_result_t(bool) lr =
            cache->backend->ops->link(cache->backend->ctx, path,
                                       e->cache_path);
        if (n00b_result_is_ok(lr)) {
            e->state             = N00B_VFS_CACHE_LINKED;
            e->last_validated_ns = now_ns();

            // Get size from stat.
            n00b_result_t(n00b_vfs_obj_stat_t) sr =
                cache->backend->ops->stat(cache->backend->ctx, path);
            if (n00b_result_is_ok(sr)) {
                uint64_t sz = n00b_result_get(sr).size;
                e->size = sz;
                atomic_fetch_add(&cache->total_size, sz);
            }
        }
    }

    return n00b_result_ok(n00b_vfs_cache_entry_t *, e);
}

void
n00b_vfs_cache_close(n00b_vfs_cache_t *cache, n00b_string_t *path,
                     bool was_write)
{
    n00b_data_read_lock(cache->lock);
    n00b_vfs_cache_entry_t *e = find_entry(cache, path);
    n00b_data_unlock(cache->lock);

    if (e == nullptr) return;

    e->open_count--;
    if (was_write) {
        e->write_count--;
    }

    // If dirty and write-through, flush on close.
    if (e->state == N00B_VFS_CACHE_DIRTY && cache->policy.write_through) {
        (void)n00b_vfs_cache_flush(cache, e->backend_path);
    }
}
