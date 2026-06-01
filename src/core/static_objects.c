#define N00B_MEM_INTERNAL_API

#include "n00b.h"
#include "core/static_objects.h"
#include "core/mmaps.h"
#include "core/rwlock.h"
#include "core/atomic.h"
#include "core/thread.h"
#include "util/assert.h"

#if defined(_WIN32)
#include "core/platform.h"
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#endif

// WP-018 / WP-016 D2: serialize the cached_hash adoption path below so
// two concurrent `n00b_static_object_register_desc` calls cannot both
// observe `range->cached_hash == 0` and race past the consistency check.
// We use a TID-keyed spinlock (mirroring `mmap_lock` in mmaps.c) rather
// than an `atomic_compare_exchange_strong` on `range->cached_hash`
// because the field is `unsigned _BitInt(128)` and 16-byte atomic CAS is
// not lock-free on every supported toolchain/target combination (x86_64
// without `-mcx16` falls back to libatomic, and `_BitInt(128)` is not
// part of any stdatomic.h guarantee). The critical section is a few
// loads/stores so a spinlock is fine; descriptor registration is rare
// and uncontested in practice.
static _Atomic int64_t static_cached_hash_lock = -1;

static inline void
static_cached_hash_lock_acquire(void)
{
    int64_t tid      = n00b_thread_unique_id();
    int64_t expected = -1;

    do {
        if (expected == tid) {
            break;
        }
        expected = -1;
    } while (!n00b_cas(&static_cached_hash_lock, &expected, tid));
}

static inline void
static_cached_hash_lock_release(void)
{
    n00b_atomic_store(&static_cached_hash_lock, (int64_t)-1);
}

static size_t
n00b_static_objects_enumerate_entries(n00b_static_object_entry_t const *start,
                                      n00b_static_object_entry_t const *stop,
                                      n00b_static_object_iter_cb cb,
                                      void *user)
{
    if (!start || !stop || stop < start) {
        return 0;
    }

    size_t count = 0;

    n00b_static_object_entry_t const *entry;
    for (entry = start; entry < stop; entry++) {
        const n00b_static_object_desc_t *desc = *entry;
        if (!desc || !desc->start || desc->len == 0) {
            continue;
        }
        if (cb) {
            cb(desc, user);
        }
        count++;
    }

    return count;
}

#if defined(__APPLE__)
static size_t
n00b_static_objects_enumerate_macho_image(const struct mach_header *hdr,
                                          intptr_t slide,
                                          n00b_static_object_iter_cb cb,
                                          void *user)
{
    if (!hdr || hdr->magic != MH_MAGIC_64) {
        return 0;
    }

    const struct mach_header_64 *header = (const struct mach_header_64 *)hdr;
    const uint8_t *cursor       = (const uint8_t *)&header[1];
    // WP-018 / WP-016 D3: the load_command table is bounded by
    // `header->sizeofcmds`. Validate every record sits inside this
    // window and is itself well-formed (cmdsize covers at least the
    // load_command header) before dereferencing past `lc->cmd`. The
    // bytes come from the OS dynamic loader so this is defense-in-depth
    // rather than untrusted-input parsing, but it costs nothing and
    // turns a malformed image into a graceful early-out instead of an
    // out-of-bounds read.
    const uint8_t *const cmds_end = cursor + header->sizeofcmds;
    size_t               count    = 0;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        // Need at least a full load_command header to read cmd/cmdsize.
        if ((size_t)(cmds_end - cursor) < sizeof(struct load_command)) {
            return count;
        }

        const struct load_command *lc = (const struct load_command *)cursor;
        // `cmdsize` must cover the load_command header itself and must
        // not run past the end of the load-command table.
        if (lc->cmdsize < sizeof(struct load_command)
            || lc->cmdsize > (uint32_t)(cmds_end - cursor)) {
            return count;
        }

        if (lc->cmd == LC_SEGMENT_64) {
            // For an LC_SEGMENT_64 command the cmdsize must also cover the
            // segment header and the nsects section_64 records that follow.
            if (lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)cursor;
                size_t sections_bytes =
                    (size_t)seg->nsects * sizeof(struct section_64);
                if (sections_bytes
                    <= (size_t)(lc->cmdsize - sizeof(struct segment_command_64))) {
                    const struct section_64 *section =
                        (const struct section_64 *)(seg + 1);

                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (strncmp(section[j].segname, "__DATA", 16) != 0
                            || strncmp(section[j].sectname, "n00b_stobj", 16) != 0) {
                            continue;
                        }

                        uintptr_t start_addr = (uintptr_t)section[j].addr + (uintptr_t)slide;
                        uintptr_t stop_addr  = start_addr + (uintptr_t)section[j].size;
                        count += n00b_static_objects_enumerate_entries(
                            (n00b_static_object_entry_t const *)start_addr,
                            (n00b_static_object_entry_t const *)stop_addr,
                            cb,
                            user);
                    }
                }
            }
        }

        cursor += lc->cmdsize;
    }

    return count;
}
#elif defined(_WIN32)
N00B_STATIC_OBJECT_SECTION_PRE(".n00bs$a")
n00b_static_object_entry_t const __n00b_static_object_section_start
    N00B_STATIC_OBJECT_SECTION_POST(".n00bs$a") = nullptr;

N00B_STATIC_OBJECT_SECTION_PRE(".n00bs$z")
n00b_static_object_entry_t const __n00b_static_object_section_end
    N00B_STATIC_OBJECT_SECTION_POST(".n00bs$z") = nullptr;
#else
extern n00b_static_object_entry_t const __start_n00b_stobj[] __attribute__((weak));
extern n00b_static_object_entry_t const __stop_n00b_stobj[] __attribute__((weak));
#endif

#if defined(_WIN32)
static n00b_mmap_perms_t
n00b_static_object_perms_from_pe_protect(DWORD protect)
{
    if (protect & (PAGE_READWRITE | PAGE_WRITECOPY
                   | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        return n00b_mmap_perms_rw;
    }
    if (protect & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE)) {
        return n00b_mmap_perms_ro;
    }
    return n00b_mmap_perms_no_access;
}

static void
n00b_static_object_register_pe_mapping(const n00b_static_object_desc_t *desc)
{
    const char *cursor = (const char *)desc->start;
    const char *limit  = cursor + desc->len;

    while (cursor < limit) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(cursor, &mbi, sizeof(mbi))) {
            return;
        }
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) {
            return;
        }

        char *start = (char *)mbi.BaseAddress;
        char *end   = start + mbi.RegionSize;
        if (end <= cursor) {
            return;
        }

        (void)n00b_mmap_register(start,
                                 end,
                                 n00b_mmap_static,
                                 .file              = desc->file,
                                 .perms             = n00b_static_object_perms_from_pe_protect(mbi.Protect),
                                 .definitely_unique = false);
        cursor = end;
    }
}
#endif

n00b_alloc_range_t *
n00b_static_object_register_desc(const n00b_static_object_desc_t *desc)
{
    if (!desc || !desc->start || desc->len == 0) {
        return nullptr;
    }

    auto existing = n00b_mmap_range_by_address((void *)desc->start);
    if (n00b_option_is_set(existing)) {
        n00b_alloc_range_t *range = n00b_option_get(existing);
        if (range->start == desc->start && range->len == desc->len
            && range->object_id == desc->object_id) {
            if (range->identity == nullptr && desc->identity != nullptr) {
                (void)n00b_static_identity_register(desc->identity, range);
            }
            // Propagate the descriptor's build-time cached hash into the
            // existing range record. If the range already has a nonzero
            // cached hash, prefer the existing value (descriptor lookup
            // is idempotent and matching descriptors should agree on the
            // hash); otherwise adopt the descriptor's value, which may
            // itself be zero (uncached). Defense-in-depth: if both the
            // existing range and the new descriptor carry nonzero cached
            // hashes, they must agree -- a mismatch would silently drop
            // the second descriptor's value, which is a build-time
            // correctness bug we want to surface loudly (WP-011 Phase 3a
            // audit W1 carry-forward).
            //
            // WP-018 / WP-016 D2: hold the static-cached-hash spinlock
            // across the load + consistency check + conditional store so
            // two concurrent registrations of the same range cannot both
            // observe `range->cached_hash == 0` and race past
            // `n00b_require`. See the lock comment above for why we use
            // a spinlock instead of `atomic_compare_exchange` on the
            // `_BitInt(128)` slot.
            static_cached_hash_lock_acquire();
            n00b_uint128_t current = range->cached_hash;
            n00b_require(current == (n00b_uint128_t)0
                             || desc->cached_hash == (n00b_uint128_t)0
                             || current == desc->cached_hash,
                         "build-time hash conflict: two static descriptors "
                         "map to the same range with disagreeing cached_hash "
                         "values");
            if (current == (n00b_uint128_t)0) {
                range->cached_hash = desc->cached_hash;
            }
            static_cached_hash_lock_release();
            if (desc->flags & N00B_STATIC_OBJECT_F_INIT_RWLOCK) {
                n00b_rwlock_t *lock = (n00b_rwlock_t *)desc->start;
                if (!lock->inited) {
                    n00b_rw_init(lock);
                }
            }
            return range;
        }
    }

#if defined(_WIN32)
    n00b_static_object_register_pe_mapping(desc);
#endif

    n00b_alloc_range_t *range =
        _n00b_static_object_register((void *)desc->start,
                                     (size_t)desc->len,
                                     desc->tinfo,
                                     desc->file,
                                     .scan_kind = desc->scan_kind,
                                     .scan_cb   = desc->scan_cb,
                                     .scan_user = desc->scan_user,
                                     .object_id = desc->object_id,
                                     .identity  = desc->identity,
                                     .flags     = desc->flags);
    if (range) {
        // Copy the descriptor's build-time cached hash into the runtime
        // range record. Zero remains the "uncached" sentinel.
        range->cached_hash = desc->cached_hash;
        if (desc->flags & N00B_STATIC_OBJECT_F_INIT_RWLOCK) {
            n00b_rw_init((n00b_rwlock_t *)desc->start);
        }
    }

    return range;
}

static void
n00b_static_object_register_cb(const n00b_static_object_desc_t *desc, void *user)
{
    size_t *count = (size_t *)user;
    if (n00b_static_object_register_desc(desc)) {
        (*count)++;
    }
}

size_t
n00b_static_objects_enumerate(n00b_static_object_iter_cb cb, void *user)
{
#if defined(__APPLE__)
    uint32_t image_count = _dyld_image_count();
    size_t count = 0;

    for (uint32_t i = 0; i < image_count; i++) {
        count += n00b_static_objects_enumerate_macho_image(
            _dyld_get_image_header(i),
            _dyld_get_image_vmaddr_slide(i),
            cb,
            user);
    }

    return count;
#elif defined(_WIN32)
    return n00b_static_objects_enumerate_entries(
        &__n00b_static_object_section_start + 1,
        &__n00b_static_object_section_end,
        cb,
        user);
#else
    if (!__start_n00b_stobj || !__stop_n00b_stobj) {
        return 0;
    }
    return n00b_static_objects_enumerate_entries(__start_n00b_stobj,
                                                __stop_n00b_stobj,
                                                cb,
                                                user);
#endif
}

size_t
n00b_static_objects_register_all(void)
{
    size_t count = 0;
    (void)n00b_static_objects_enumerate(n00b_static_object_register_cb, &count);
    return count;
}

#if defined(__APPLE__)
size_t
n00b_static_objects_register_macho_image(const struct mach_header *hdr,
                                         intptr_t slide)
{
    size_t count = 0;
    (void)n00b_static_objects_enumerate_macho_image(
        hdr,
        slide,
        n00b_static_object_register_cb,
        &count);
    return count;
}
#endif
