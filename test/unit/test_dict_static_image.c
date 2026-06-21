/*
 * test_dict_static_image.c — WP-011 Phase 3b
 *
 * Manually constructed static dict images mirror what the build-time
 * helper's `container_kind dict` path emits.  The fixtures exercise:
 *
 *   - scalar-keyed dict (int -> int) at the minimum capacity (3 entries);
 *   - scalar-keyed dict that forces a larger pow2 capacity (32 entries);
 *   - pointer-keyed dict (n00b_string_t * -> int) with cached_hash slots
 *     emitted on each key's static-object descriptor (D-066);
 *   - lock model: static dict images are LOCKABLE but NOT locked by
 *     default (per D-070, superseding D-068). The dict's `lock` slot is
 *     a `n00b_rwlock_t *`, emitted as nullptr; the legacy `futex` field
 *     has been renamed to `_migration_state` (the lock-free table-resize
 *     coordination word, NOT a user-facing mutex) and is zero at build
 *     time, which is the protocol's "no migration in progress" state.
 *
 * The test does NOT spawn the helper subprocess; it hand-writes the
 * same dict layout the helper would emit and validates that the dict
 * is queryable through the normal runtime lookup path
 * (`_n00b_dict_internal_get`).  The Phase 3c integration tests will
 * verify that ncc + the helper agree on the encoded shape.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "adt/dict.h"
#include "core/alloc.h"
#include "core/hash.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/static_objects.h"

#define N00B_USE_INTERNAL_API

// Capacity formula: max(pow2_ceil(N), N00B_DICT_MIN_SIZE).
#define SCALAR_SMALL_CAP   16u
#define SCALAR_LARGE_CAP   32u

#define STATIC_DICT_KEY_TINFO    UINT64_C(0x4469637453746B31)
#define STATIC_DICT_VAL_TINFO    UINT64_C(0x4469637453746331)
#define STATIC_DICT_STORE_TINFO  UINT64_C(0x4469637453746F31)

static uint64_t
pow2_ceil_u64_test(uint64_t v)
{
    if (v <= 1) return 1;
    uint64_t r = 1;
    while (r < v) r <<= 1;
    return r;
}

static uint32_t
threshold_for(uint32_t cap)
{
    return cap - (cap >> 2) - 1u;
}

// Slot-assigns each pair by linear probing starting at hash & mask.
// Mirrors the algorithm in n00b-static-init-helper.c::emit_dict_image.
static void
slot_assign(uint64_t cap,
            const n00b_uint128_t *hashes,
            uint64_t n_entries,
            int64_t *slot_to_pair)
{
    uint64_t mask = cap - 1u;
    for (uint64_t i = 0; i < cap; i++) {
        slot_to_pair[i] = -1;
    }
    for (uint64_t i = 0; i < n_entries; i++) {
        uint64_t bix = (uint64_t)hashes[i] & mask;
        for (uint64_t probe = 0; probe < cap; probe++) {
            uint64_t s = (bix + probe) & mask;
            if (slot_to_pair[s] == -1) {
                slot_to_pair[s] = (int64_t)i;
                break;
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Scalar-keyed dict (small): int -> int, 3 entries, capacity 16.
// ----------------------------------------------------------------------------

static int                                 scalar_small_keys_input[3] = {10, 20, 30};
static int                                 scalar_small_vals_input[3] = {100, 200, 300};
static n00b_dict_bucket_t                  scalar_small_buckets[SCALAR_SMALL_CAP];
static int                                 scalar_small_keys[SCALAR_SMALL_CAP];
static int                                 scalar_small_values[SCALAR_SMALL_CAP];
static __n00b_internal_type_erased_store_t scalar_small_store;
static _n00b_dict_internal_t               scalar_small_dict;

static void
build_scalar_small_image(void)
{
    n00b_uint128_t hashes[3];
    for (uint64_t i = 0; i < 3; i++) {
        // Scalar keys use skip_obj_hash=true; the runtime path is
        // n00b_hash_raw(&key_bytes, sizeof(int)).
        hashes[i] = n00b_hash_raw(&scalar_small_keys_input[i], sizeof(int));
    }

    int64_t slot_to_pair[SCALAR_SMALL_CAP];
    slot_assign(SCALAR_SMALL_CAP, hashes, 3, slot_to_pair);

    for (uint32_t s = 0; s < SCALAR_SMALL_CAP; s++) {
        int64_t pi = slot_to_pair[s];
        if (pi < 0) {
            scalar_small_buckets[s] = (n00b_dict_bucket_t){};
            scalar_small_keys[s]    = 0;
            scalar_small_values[s]  = 0;
        }
        else {
            scalar_small_buckets[s] = (n00b_dict_bucket_t){
                .hv           = hashes[pi],
                .insert_order = (uint32_t)(pi + 1),
                .flags        = 0,
            };
            scalar_small_keys[s]   = scalar_small_keys_input[pi];
            scalar_small_values[s] = scalar_small_vals_input[pi];
        }
    }

    scalar_small_store = (__n00b_internal_type_erased_store_t){
        .last_slot  = SCALAR_SMALL_CAP - 1u,
        .threshold  = threshold_for(SCALAR_SMALL_CAP),
        .used_count = 3,
        .buckets    = scalar_small_buckets,
        .keys       = (void **)scalar_small_keys,
        .values     = (void **)scalar_small_values,
    };

    scalar_small_dict = (_n00b_dict_internal_t){
        .store           = (void **)&scalar_small_store,
        .fn              = nullptr,
        .allocator       = nullptr,
        .insertion_epoch = 0,
        .wait_ct         = 0,
        .length          = 3,
        ._migration_state = 0,
        .lock            = 0,
        .cache           = 0,
        .skip_obj_hash   = 1,
        .scan_kind       = N00B_GC_SCAN_KIND_NONE,
        .scan_cb         = nullptr,
        .scan_user       = nullptr,
    };
}

// ----------------------------------------------------------------------------
// Scalar-keyed dict (large): int -> int, 20 entries (forces pow2 = 32).
// ----------------------------------------------------------------------------

#define SCALAR_LARGE_N 20

static int                                 scalar_large_keys_input[SCALAR_LARGE_N];
static int                                 scalar_large_vals_input[SCALAR_LARGE_N];
static n00b_dict_bucket_t                  scalar_large_buckets[SCALAR_LARGE_CAP];
static int                                 scalar_large_keys[SCALAR_LARGE_CAP];
static int                                 scalar_large_values[SCALAR_LARGE_CAP];
static __n00b_internal_type_erased_store_t scalar_large_store;
static _n00b_dict_internal_t               scalar_large_dict;

static void
build_scalar_large_image(void)
{
    n00b_uint128_t hashes[SCALAR_LARGE_N];
    for (uint64_t i = 0; i < SCALAR_LARGE_N; i++) {
        scalar_large_keys_input[i] = (int)(i * 7 + 1);
        scalar_large_vals_input[i] = (int)(i * 11 + 5);
        hashes[i] = n00b_hash_raw(&scalar_large_keys_input[i], sizeof(int));
    }

    int64_t slot_to_pair[SCALAR_LARGE_CAP];
    slot_assign(SCALAR_LARGE_CAP, hashes, SCALAR_LARGE_N, slot_to_pair);

    for (uint32_t s = 0; s < SCALAR_LARGE_CAP; s++) {
        int64_t pi = slot_to_pair[s];
        if (pi < 0) {
            scalar_large_buckets[s] = (n00b_dict_bucket_t){};
            scalar_large_keys[s]    = 0;
            scalar_large_values[s]  = 0;
        }
        else {
            scalar_large_buckets[s] = (n00b_dict_bucket_t){
                .hv           = hashes[pi],
                .insert_order = (uint32_t)(pi + 1),
                .flags        = 0,
            };
            scalar_large_keys[s]   = scalar_large_keys_input[pi];
            scalar_large_values[s] = scalar_large_vals_input[pi];
        }
    }

    scalar_large_store = (__n00b_internal_type_erased_store_t){
        .last_slot  = SCALAR_LARGE_CAP - 1u,
        .threshold  = threshold_for(SCALAR_LARGE_CAP),
        .used_count = SCALAR_LARGE_N,
        .buckets    = scalar_large_buckets,
        .keys       = (void **)scalar_large_keys,
        .values     = (void **)scalar_large_values,
    };

    scalar_large_dict = (_n00b_dict_internal_t){
        .store           = (void **)&scalar_large_store,
        .fn              = nullptr,
        .allocator       = nullptr,
        .insertion_epoch = 0,
        .wait_ct         = 0,
        .length          = SCALAR_LARGE_N,
        ._migration_state = 0,
        .lock            = 0,
        .cache           = 0,
        .skip_obj_hash   = 1,
        .scan_kind       = N00B_GC_SCAN_KIND_NONE,
        .scan_cb         = nullptr,
        .scan_user       = nullptr,
    };
}

// ----------------------------------------------------------------------------
// Pointer-keyed dict: n00b_string_t * -> int, 2 entries.
//
// Each key is a static-storage n00b_string_t whose descriptor is
// registered with N00B_STATIC_OBJECT_DESCRIPTOR_WITH_HASH so its
// cached_hash slot is populated at registration time (D-066).
// ----------------------------------------------------------------------------

#define POINTER_DICT_CAP 16u

// The strings are constructed at runtime (n00b_string_from_cstr) so we
// can register the static-region descriptors for them. The descriptors
// point at static-storage struct buffers, and the cached_hash is
// computed at runtime from the actual string contents before
// registration.
static n00b_string_t pointer_dict_key_storage_a;
static n00b_string_t pointer_dict_key_storage_b;
static char          pointer_dict_key_data_a[8];
static char          pointer_dict_key_data_b[8];

#define POINTER_KEY_A_TINFO  UINT64_C(0x504b41737472)
#define POINTER_KEY_B_TINFO  UINT64_C(0x504b42737472)
#define POINTER_KEY_A_ID     UINT64_C(0x4453492100000001)
#define POINTER_KEY_B_ID     UINT64_C(0x4453492100000002)

// The cached_hash values are filled in by `setup_pointer_dict()` before
// register_all is called. They live in distinct globals so the
// descriptor can reference them; the runtime range registration copies
// the descriptor's `cached_hash` value into n00b_alloc_range_t.
// We cannot use N00B_STATIC_OBJECT_DESCRIPTOR_WITH_HASH directly here
// because the hash is not a compile-time constant (it depends on string
// bytes). Instead we register descriptors via
// n00b_static_object_register_desc() at runtime with a hand-built desc.

static n00b_uint128_t              pointer_key_a_hash;
static n00b_uint128_t              pointer_key_b_hash;
static n00b_static_object_desc_t   pointer_key_a_desc;
static n00b_static_object_desc_t   pointer_key_b_desc;

static n00b_dict_bucket_t                  pointer_dict_buckets[POINTER_DICT_CAP];
static n00b_string_t                      *pointer_dict_keys[POINTER_DICT_CAP];
static int                                 pointer_dict_values[POINTER_DICT_CAP];
static __n00b_internal_type_erased_store_t pointer_dict_store;
static _n00b_dict_internal_t               pointer_dict_dict;

static void
init_static_string(n00b_string_t *s, char *backing,
                   const char *src, size_t len)
{
    memcpy(backing, src, len);
    backing[len] = '\0';
    *s = (n00b_string_t){
        .data       = backing,
        .u8_bytes   = len,
        .codepoints = len,
        .styling    = nullptr,
    };
}

static void
build_pointer_dict_image(void)
{
    init_static_string(&pointer_dict_key_storage_a,
                       pointer_dict_key_data_a, "alpha", 5);
    init_static_string(&pointer_dict_key_storage_b,
                       pointer_dict_key_data_b, "bravo", 5);

    pointer_key_a_hash = n00b_string_hash(&pointer_dict_key_storage_a);
    pointer_key_b_hash = n00b_string_hash(&pointer_dict_key_storage_b);

    // Hand-build descriptors with the cached_hash slot populated. The
    // helper's `container_kind dict` path emits an equivalent
    // N00B_STATIC_OBJECT_DESCRIPTOR_WITH_HASH entry per key.
    pointer_key_a_desc = (n00b_static_object_desc_t){
        .start       = &pointer_dict_key_storage_a,
        .len         = sizeof(pointer_dict_key_storage_a),
        .tinfo       = POINTER_KEY_A_TINFO,
        .scan_kind   = N00B_GC_SCAN_KIND_NONE,
        .scan_cb     = nullptr,
        .scan_user   = nullptr,
        .object_id   = POINTER_KEY_A_ID,
        .file        = __FILE__,
        .identity    = nullptr,
        .flags       = N00B_STATIC_OBJECT_F_MUTABLE,
        .cached_hash = pointer_key_a_hash,
    };
    pointer_key_b_desc = (n00b_static_object_desc_t){
        .start       = &pointer_dict_key_storage_b,
        .len         = sizeof(pointer_dict_key_storage_b),
        .tinfo       = POINTER_KEY_B_TINFO,
        .scan_kind   = N00B_GC_SCAN_KIND_NONE,
        .scan_cb     = nullptr,
        .scan_user   = nullptr,
        .object_id   = POINTER_KEY_B_ID,
        .file        = __FILE__,
        .identity    = nullptr,
        .flags       = N00B_STATIC_OBJECT_F_MUTABLE,
        .cached_hash = pointer_key_b_hash,
    };

    // The dict's compute_hash for pointer keys is `n00b_hash(*(void **)key, fn)`.
    // For our static string keys, n00b_hash() reads cached_hash from the
    // range record on static-range hits, so it matches the values above.
    n00b_uint128_t hashes[2] = {pointer_key_a_hash, pointer_key_b_hash};
    n00b_string_t *keys[2]   = {&pointer_dict_key_storage_a,
                                &pointer_dict_key_storage_b};
    int            vals[2]   = {111, 222};

    int64_t slot_to_pair[POINTER_DICT_CAP];
    slot_assign(POINTER_DICT_CAP, hashes, 2, slot_to_pair);

    for (uint32_t s = 0; s < POINTER_DICT_CAP; s++) {
        int64_t pi = slot_to_pair[s];
        if (pi < 0) {
            pointer_dict_buckets[s] = (n00b_dict_bucket_t){};
            pointer_dict_keys[s]    = nullptr;
            pointer_dict_values[s]  = 0;
        }
        else {
            pointer_dict_buckets[s] = (n00b_dict_bucket_t){
                .hv           = hashes[pi],
                .insert_order = (uint32_t)(pi + 1),
                .flags        = 0,
            };
            pointer_dict_keys[s]   = keys[pi];
            pointer_dict_values[s] = vals[pi];
        }
    }

    pointer_dict_store = (__n00b_internal_type_erased_store_t){
        .last_slot  = POINTER_DICT_CAP - 1u,
        .threshold  = threshold_for(POINTER_DICT_CAP),
        .used_count = 2,
        .buckets    = pointer_dict_buckets,
        .keys       = (void **)pointer_dict_keys,
        .values     = (void **)pointer_dict_values,
    };

    pointer_dict_dict = (_n00b_dict_internal_t){
        .store           = (void **)&pointer_dict_store,
        .fn              = nullptr,
        .allocator       = nullptr,
        .insertion_epoch = 0,
        .wait_ct         = 0,
        .length          = 2,
        ._migration_state = 0,
        .lock            = 0,
        .cache           = 0,
        .skip_obj_hash   = 0,  // pointer-keyed: hash via n00b_hash().
        .scan_kind       = N00B_GC_SCAN_KIND_NONE,
        .scan_cb         = nullptr,
        .scan_user       = nullptr,
    };
}

static n00b_alloc_range_t *
register_static_region(const void *addr, uint64_t len, uint64_t tinfo)
{
    return n00b_static_object_register((void *)addr, (size_t)len,
                                       tinfo,
                                       .scan_kind = N00B_GC_SCAN_KIND_NONE);
}

// ----------------------------------------------------------------------------
// Verifications.
// ----------------------------------------------------------------------------

static void
verify_scalar_small(void)
{
    // Layout invariants.
    assert(scalar_small_store.last_slot == SCALAR_SMALL_CAP - 1u);
    assert(scalar_small_store.threshold == threshold_for(SCALAR_SMALL_CAP));
    assert(atomic_load_explicit(&scalar_small_store.used_count,
                                memory_order_relaxed)
           == 3u);
    assert(scalar_small_dict.length == 3);
    assert(scalar_small_dict.skip_obj_hash == 1);
    assert(scalar_small_dict._migration_state == 0);  // no migration pending.
    assert(scalar_small_dict.lock == 0);        // static default: unlocked.

    // Lookup each key.
    for (int i = 0; i < 3; i++) {
        int key = scalar_small_keys_input[i];
        bool found = false;
        void *vp = _n00b_dict_internal_get(&scalar_small_dict,
                                           sizeof(int), sizeof(int),
                                           &key, nullptr, &found);
        assert(found);
        assert(vp != nullptr);
        assert(*(int *)vp == scalar_small_vals_input[i]);
    }

    // Missing-key lookup.
    int missing = 9999;
    bool found_missing = true;
    void *vp = _n00b_dict_internal_get(&scalar_small_dict,
                                       sizeof(int), sizeof(int),
                                       &missing, nullptr, &found_missing);
    assert(!found_missing);
    assert(vp == nullptr);

    printf("  [PASS] scalar_small dict (cap=16, 3 entries)\n");
}

static void
verify_scalar_large(void)
{
    assert(scalar_large_store.last_slot == SCALAR_LARGE_CAP - 1u);
    assert(scalar_large_store.threshold == threshold_for(SCALAR_LARGE_CAP));
    assert(SCALAR_LARGE_CAP == pow2_ceil_u64_test(SCALAR_LARGE_N));
    assert(SCALAR_LARGE_CAP >= N00B_DICT_MIN_SIZE);
    assert(atomic_load_explicit(&scalar_large_store.used_count,
                                memory_order_relaxed)
           == SCALAR_LARGE_N);
    assert(scalar_large_dict.length == SCALAR_LARGE_N);
    assert(scalar_large_dict._migration_state == 0);
    assert(scalar_large_dict.lock == 0);

    for (int i = 0; i < SCALAR_LARGE_N; i++) {
        int key = scalar_large_keys_input[i];
        bool found = false;
        void *vp = _n00b_dict_internal_get(&scalar_large_dict,
                                           sizeof(int), sizeof(int),
                                           &key, nullptr, &found);
        assert(found);
        assert(vp != nullptr);
        assert(*(int *)vp == scalar_large_vals_input[i]);
    }

    printf("  [PASS] scalar_large dict (cap=32, 20 entries)\n");
}

static void
verify_pointer_dict(void)
{
    assert(pointer_dict_store.last_slot == POINTER_DICT_CAP - 1u);
    assert(atomic_load_explicit(&pointer_dict_store.used_count,
                                memory_order_relaxed)
           == 2u);
    assert(pointer_dict_dict.length == 2);
    assert(pointer_dict_dict.skip_obj_hash == 0);
    assert(pointer_dict_dict._migration_state == 0);
    assert(pointer_dict_dict.lock == 0);

    // The pointer-key descriptors must have populated cached_hash slots
    // on their runtime range records (Phase 3a D-066 + Phase 3b's
    // helper-side cached_hash emission).
    auto opt_a = n00b_mmap_range_by_address(&pointer_dict_key_storage_a);
    auto opt_b = n00b_mmap_range_by_address(&pointer_dict_key_storage_b);
    assert(n00b_option_is_set(opt_a));
    assert(n00b_option_is_set(opt_b));
    n00b_alloc_range_t *range_a = n00b_option_get(opt_a);
    n00b_alloc_range_t *range_b = n00b_option_get(opt_b);
    assert(range_a->cached_hash == pointer_key_a_hash);
    assert(range_b->cached_hash == pointer_key_b_hash);
    assert(range_a->cached_hash != (n00b_uint128_t)0);
    assert(range_b->cached_hash != (n00b_uint128_t)0);

    // n00b_hash() against the static keys must return the cached value
    // verbatim, matching what compute_hash() would call into during
    // dict lookup.
    assert(n00b_hash(&pointer_dict_key_storage_a, nullptr)
           == pointer_key_a_hash);
    assert(n00b_hash(&pointer_dict_key_storage_b, nullptr)
           == pointer_key_b_hash);

    // Lookup via the dict's normal path. We pass &key_ptr because
    // _n00b_dict_internal_get expects `void *key` to dereference at
    // `*(void **)key` for pointer keys.
    n00b_string_t *key_a = &pointer_dict_key_storage_a;
    n00b_string_t *key_b = &pointer_dict_key_storage_b;

    bool found = false;
    void *vp = _n00b_dict_internal_get(&pointer_dict_dict,
                                       sizeof(n00b_string_t *), sizeof(int),
                                       &key_a, nullptr, &found);
    assert(found);
    assert(vp != nullptr);
    assert(*(int *)vp == 111);

    found = false;
    vp = _n00b_dict_internal_get(&pointer_dict_dict,
                                 sizeof(n00b_string_t *), sizeof(int),
                                 &key_b, nullptr, &found);
    assert(found);
    assert(vp != nullptr);
    assert(*(int *)vp == 222);

    printf("  [PASS] pointer dict (n00b_string_t * keys, cached_hash)\n");
}

static void
verify_lock_model(void)
{
    // Lock model per D-070 (superseding D-068): static dict images are
    // LOCKABLE but NOT locked by default. The dict's `lock` slot is a
    // `n00b_rwlock_t *`, emitted as nullptr; heap dict constructors opt
    // in via `n00b_dict_new` (locked) vs `n00b_dict_new_private`.
    //
    // The `_migration_state` word (renamed from the legacy `futex`
    // field) is the lock-free table-resize coordination word, NOT a
    // user-facing mutex; static images emit it as zero, which is the
    // protocol's "no migration in progress" state. The dict store's
    // bucket flags are also zero (no copying/moving/mutex bits set), so
    // the dict is queryable immediately without any runtime
    // initialisation step.
    assert(scalar_small_dict._migration_state == 0);
    assert(scalar_large_dict._migration_state == 0);
    assert(pointer_dict_dict._migration_state == 0);
    assert(scalar_small_dict.lock == 0);
    assert(scalar_large_dict.lock == 0);
    assert(pointer_dict_dict.lock == 0);

    for (uint32_t s = 0; s < SCALAR_SMALL_CAP; s++) {
        uint32_t flags = atomic_load_explicit(&scalar_small_buckets[s].flags,
                                              memory_order_relaxed);
        assert((flags & (N00B_HT_FLAG_MUTEX | N00B_HT_FLAG_COPYING
                         | N00B_HT_FLAG_MOVING)) == 0);
    }

    printf("  [PASS] lock model (lockable, default unlocked; "
           "_migration_state zero)\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    build_scalar_small_image();
    build_scalar_large_image();
    build_pointer_dict_image();

    // Register the dict's backing static regions so n00b_find_alloc_info
    // can locate them as static_range hits. Without this, GC scanning of
    // a real static dict literal would still work (mmap section iteration
    // discovers the descriptors); the test fixture registers them by
    // hand to mirror what the section-iteration path produces for a
    // helper-emitted dict image.
    register_static_region(scalar_small_buckets,
                           sizeof(scalar_small_buckets),
                           STATIC_DICT_STORE_TINFO);
    register_static_region(scalar_small_keys,
                           sizeof(scalar_small_keys),
                           STATIC_DICT_KEY_TINFO);
    register_static_region(scalar_small_values,
                           sizeof(scalar_small_values),
                           STATIC_DICT_VAL_TINFO);
    register_static_region(&scalar_small_store,
                           sizeof(scalar_small_store),
                           STATIC_DICT_STORE_TINFO);
    register_static_region(&scalar_small_dict,
                           sizeof(scalar_small_dict),
                           STATIC_DICT_STORE_TINFO);

    register_static_region(scalar_large_buckets,
                           sizeof(scalar_large_buckets),
                           STATIC_DICT_STORE_TINFO);
    register_static_region(scalar_large_keys,
                           sizeof(scalar_large_keys),
                           STATIC_DICT_KEY_TINFO);
    register_static_region(scalar_large_values,
                           sizeof(scalar_large_values),
                           STATIC_DICT_VAL_TINFO);
    register_static_region(&scalar_large_store,
                           sizeof(scalar_large_store),
                           STATIC_DICT_STORE_TINFO);
    register_static_region(&scalar_large_dict,
                           sizeof(scalar_large_dict),
                           STATIC_DICT_STORE_TINFO);

    // For the pointer dict, register the per-key static-object
    // descriptors (which carry the cached_hash slot) via the descriptor
    // registration path -- that path copies cached_hash into the runtime
    // range record. The dict's own backing arrays are also registered
    // for completeness.
    n00b_alloc_range_t *range_a =
        n00b_static_object_register_desc(&pointer_key_a_desc);
    n00b_alloc_range_t *range_b =
        n00b_static_object_register_desc(&pointer_key_b_desc);
    assert(range_a != nullptr);
    assert(range_b != nullptr);
    assert(range_a->cached_hash == pointer_key_a_hash);
    assert(range_b->cached_hash == pointer_key_b_hash);

    register_static_region(pointer_dict_buckets,
                           sizeof(pointer_dict_buckets),
                           STATIC_DICT_STORE_TINFO);
    register_static_region(pointer_dict_keys,
                           sizeof(pointer_dict_keys),
                           STATIC_DICT_KEY_TINFO);
    register_static_region(pointer_dict_values,
                           sizeof(pointer_dict_values),
                           STATIC_DICT_VAL_TINFO);
    register_static_region(&pointer_dict_store,
                           sizeof(pointer_dict_store),
                           STATIC_DICT_STORE_TINFO);
    register_static_region(&pointer_dict_dict,
                           sizeof(pointer_dict_dict),
                           STATIC_DICT_STORE_TINFO);

    printf("Running static dict image tests...\n");
    verify_scalar_small();
    verify_scalar_large();
    verify_pointer_dict();
    verify_lock_model();
    printf("All static dict image tests passed.\n");

    n00b_shutdown();
    return 0;
}
