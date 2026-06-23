#include <stdio.h>
#include <assert.h>
#include <string.h>

#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/atomic.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "adt/dict.h"

typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
} big_value_t;

typedef n00b_dict_t(uint64_t, uint64_t) u64_dict_t;
typedef n00b_dict_t(uint64_t, big_value_t) big_dict_t;
typedef n00b_dict_t(char *, uint64_t) str_dict_t;
typedef n00b_dict_t(n00b_string_t *, uint64_t) n00b_str_dict_t;

// ============================================================================
// 1. Init empty — length 0
// ============================================================================

static void
test_init_empty(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 0);

    printf("  [PASS] init_empty\n");
}

// ============================================================================
// 2. Put / get — put key/value, get returns correct value
// ============================================================================

static void
test_put_get(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 42, v = 100;
    n00b_dict_put(&dict, k, v);

    bool     found;
    uint64_t val = n00b_dict_get(&dict, k, &found);
    assert(found);
    assert(val == 100);
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 1);

    printf("  [PASS] put_get\n");
}

// ============================================================================
// 3. Overwrite — put same key twice; old value returned via pointer
// ============================================================================

static void
test_overwrite(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 1, v1 = 10, v2 = 20;

    void *prev = n00b_dict_put(&dict, k, v1);
    assert(prev == nullptr);

    prev = n00b_dict_put(&dict, k, v2);
    assert(prev != nullptr);
    assert(*(uint64_t *)prev == 20);

    bool     found;
    uint64_t val = n00b_dict_get(&dict, k, &found);
    assert(found);
    assert(val == 20);

    printf("  [PASS] overwrite\n");
}

// ============================================================================
// 4. Not found — get missing key returns found=false
// ============================================================================

static void
test_not_found(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k1 = 1, v1 = 10, k999 = 999;
    n00b_dict_put(&dict, k1, v1);

    bool     found;
    uint64_t val = n00b_dict_get(&dict, k999, &found);
    assert(!found);
    (void)val;

    printf("  [PASS] not_found\n");
}

// ============================================================================
// 5. Remove — put then remove; get returns found=false after removal
// ============================================================================

static void
test_remove(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 1, v = 10;
    n00b_dict_put(&dict, k, v);

    bool found;
    (void)n00b_dict_get(&dict, k, &found);
    assert(found);

    bool removed = n00b_dict_remove(&dict, k);
    assert(removed);
    (void)n00b_dict_get(&dict, k, &found);
    assert(!found);
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 0);

    printf("  [PASS] remove\n");
}

// ============================================================================
// 6. Add existing — returns false when key exists
// ============================================================================

static void
test_add_existing(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 1, v1 = 10, v2 = 20;

    bool added = n00b_dict_add(&dict, k, v1);
    assert(added);

    added = n00b_dict_add(&dict, k, v2);
    assert(!added);

    // Value should still be the original.
    bool     found;
    uint64_t val = n00b_dict_get(&dict, k, &found);
    assert(found);
    assert(val == 10);

    printf("  [PASS] add_existing\n");
}

// ============================================================================
// 7. Contains — true/false for present/absent keys
// ============================================================================

static void
test_contains(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k42 = 42, k99 = 99, v = 100;

    assert(!n00b_dict_contains(&dict, k42));

    n00b_dict_put(&dict, k42, v);

    assert(n00b_dict_contains(&dict, k42));
    assert(!n00b_dict_contains(&dict, k99));

    printf("  [PASS] contains\n");
}

// ============================================================================
// 8. Growth — insert 200+ entries forcing resize; verify all
// ============================================================================

static void
test_growth(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    for (uint64_t i = 1; i <= 200; i++) {
        uint64_t v = i * 10;
        n00b_dict_put(&dict, i, v);
    }

    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 200);

    for (uint64_t i = 1; i <= 200; i++) {
        bool     found;
        uint64_t val = n00b_dict_get(&dict, i, &found);
        assert(found);
        assert(val == i * 10);
    }

    printf("  [PASS] growth\n");
}

// ============================================================================
// 9. String pointer keys — using n00b_hash_cstring
// ============================================================================

static void
test_string_keys(void)
{
    str_dict_t dict;
    n00b_dict_init(&dict, .hash = n00b_hash_cstring, .skip_obj_hash = true);

    char    *key1 = "hello", *key2 = "world", *key3 = "test";
    uint64_t v1 = 1, v2 = 2, v3 = 3;

    n00b_dict_put(&dict, key1, v1);
    n00b_dict_put(&dict, key2, v2);
    n00b_dict_put(&dict, key3, v3);

    bool     found;
    uint64_t val;

    val = n00b_dict_get(&dict, key1, &found);
    assert(found);
    assert(val == 1);

    val = n00b_dict_get(&dict, key2, &found);
    assert(found);
    assert(val == 2);

    val = n00b_dict_get(&dict, key3, &found);
    assert(found);
    assert(val == 3);

    char *missing = "missing";
    val = n00b_dict_get(&dict, missing, &found);
    assert(!found);

    printf("  [PASS] string_keys\n");
}

static void
test_static_string_custom_hash_keys(void)
{
    n00b_str_dict_t dict;
    n00b_dict_init(&dict, .hash = n00b_string_hash);

    char           runtime_bytes[] = "prefetch";
    char           lookup_bytes[]  = "prefetch";
    n00b_string_t *runtime_key     = n00b_string_from_cstr(runtime_bytes);
    n00b_string_t *runtime_lookup  = n00b_string_from_cstr(lookup_bytes);
    n00b_string_t *static_key  = r"prefetch";
    uint64_t       value       = 42;

    (void)n00b_hash(runtime_key, nullptr);
    n00b_dict_put(&dict, runtime_key, value);

    bool     found;
    uint64_t got = n00b_dict_get(&dict, static_key, &found);
    assert(found);
    assert(got == value);

    got = n00b_dict_get(&dict, runtime_lookup, &found);
    assert(found);
    assert(got == value);

    value = 84;
    n00b_dict_put(&dict, static_key, value);
    got = n00b_dict_get(&dict, runtime_key, &found);
    assert(found);
    assert(got == value);

    n00b_str_dict_t value_hash_dict;
    n00b_dict_init(&value_hash_dict,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true);

    value = 126;
    n00b_dict_put(&value_hash_dict, runtime_key, value);
    got = n00b_dict_get(&value_hash_dict, static_key, &found);
    assert(found);
    assert(got == value);

    printf("  [PASS] static_string_custom_hash_keys\n");
}

// ============================================================================
// 10. Large value types — struct values larger than 8 bytes
// ============================================================================

static void
test_large_values(void)
{
    big_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    for (uint64_t i = 1; i <= 50; i++) {
        big_value_t bv = { .a = i, .b = i * 2, .c = i * 3, .d = i * 4 };
        n00b_dict_put(&dict, i, bv);
    }

    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 50);

    for (uint64_t i = 1; i <= 50; i++) {
        bool        found;
        big_value_t bv = n00b_dict_get(&dict, i, &found);
        assert(found);
        assert(bv.a == i);
        assert(bv.b == i * 2);
        assert(bv.c == i * 3);
        assert(bv.d == i * 4);
    }

    printf("  [PASS] large_values\n");
}

// ============================================================================
// 11. Mixed operations — interleave put/get/remove/add
// ============================================================================

static void
test_mixed_operations(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    for (uint64_t i = 1; i <= 10; i++) {
        uint64_t v = i * 100;
        n00b_dict_put(&dict, i, v);
    }
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 10);

    for (uint64_t i = 2; i <= 10; i += 2) {
        assert(n00b_dict_remove(&dict, i));
    }
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 5);

    for (uint64_t i = 1; i <= 10; i++) {
        bool     found;
        uint64_t val = n00b_dict_get(&dict, i, &found);
        if (i % 2 == 1) {
            assert(found);
            assert(val == i * 100);
        }
        else {
            assert(!found);
        }
    }

    for (uint64_t i = 2; i <= 10; i += 2) {
        uint64_t v = i * 200;
        assert(n00b_dict_add(&dict, i, v));
    }
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 10);

    for (uint64_t i = 1; i <= 10; i++) {
        bool     found;
        uint64_t val = n00b_dict_get(&dict, i, &found);
        assert(found);
        if (i % 2 == 1) {
            assert(val == i * 100);
        }
        else {
            assert(val == i * 200);
        }
    }

    printf("  [PASS] mixed_operations\n");
}

// ============================================================================
// 12. Remove then reinsert — deleted slots are reusable
// ============================================================================

static void
test_remove_reinsert(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 42, v1 = 100, v2 = 200;
    n00b_dict_put(&dict, k, v1);
    assert(n00b_dict_remove(&dict, k));
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 0);

    n00b_dict_put(&dict, k, v2);
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 1);

    bool     found;
    uint64_t val = n00b_dict_get(&dict, k, &found);
    assert(found);
    assert(val == 200);

    printf("  [PASS] remove_reinsert\n");
}

// ============================================================================
// 13. CAS — basic success/failure paths
// ============================================================================

static void
test_cas_insert(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t key     = 42;
    uint64_t new_val = 100;
    bool     ok      = n00b_dict_cas(&dict, key, nullptr, &new_val,
                                     .null_old_means_absence = true);
    assert(ok);

    bool     found;
    uint64_t val = n00b_dict_get(&dict, key, &found);
    assert(found);
    assert(val == 100);

    uint64_t new_val2 = 200;
    ok = n00b_dict_cas(&dict, key, nullptr, &new_val2,
                       .null_old_means_absence = true);
    assert(!ok);

    val = n00b_dict_get(&dict, key, &found);
    assert(found);
    assert(val == 100);

    printf("  [PASS] cas_insert\n");
}

static void
test_cas_update(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 42, v = 100;
    n00b_dict_put(&dict, k, v);

    uint64_t old_val = 100;
    uint64_t new_val = 200;
    void    *old_ptr = &old_val;
    bool     ok      = n00b_dict_cas(&dict, k, &old_ptr, &new_val);
    assert(ok);

    bool     found;
    uint64_t val = n00b_dict_get(&dict, k, &found);
    assert(found);
    assert(val == 200);

    uint64_t wrong_old = 100;
    old_ptr            = &wrong_old;
    uint64_t new_val2  = 300;
    ok = n00b_dict_cas(&dict, k, &old_ptr, &new_val2);
    assert(!ok);

    val = n00b_dict_get(&dict, k, &found);
    assert(found);
    assert(val == 200);

    printf("  [PASS] cas_update\n");
}

// ============================================================================
// 14. Remove missing — removing a non-existent key returns false
// ============================================================================

static void
test_remove_missing(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    uint64_t k = 999;
    bool removed = n00b_dict_remove(&dict, k);
    assert(!removed);

    printf("  [PASS] remove_missing\n");
}

// ============================================================================
// 15. Multiple removes and length tracking
// ============================================================================

static void
test_length_tracking(void)
{
    u64_dict_t dict;
    n00b_dict_init(&dict, .skip_obj_hash = true);

    for (uint64_t i = 1; i <= 5; i++) {
        n00b_dict_put(&dict, i, i);
    }
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 5);

    uint64_t k3 = 3, k1 = 1;
    n00b_dict_remove(&dict, k3);
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 4);

    n00b_dict_remove(&dict, k1);
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 3);

    uint64_t v33 = 33;
    n00b_dict_put(&dict, k3, v33);
    assert(n00b_dict_internal_len((_n00b_dict_internal_t *)&dict) == 4);

    printf("  [PASS] length_tracking\n");
}

// ============================================================================
// 16. Locked dict allocator — rwlock follows the dict allocator
// ============================================================================

static void
test_locked_dict_lock_allocator(void)
{
    n00b_arena_t     *arena = n00b_new_arena(.size   = 1 << 20,
                                             .use_gc = false,
                                             .name   = "dict-lock-test");
    n00b_allocator_t *alloc = (n00b_allocator_t *)arena;

    u64_dict_t private_dict;
    n00b_dict_init(&private_dict,
                   .locked        = false,
                   .allocator     = alloc,
                   .skip_obj_hash = true);
    assert(private_dict.lock == 0);

    u64_dict_t locked_dict;
    n00b_dict_init(&locked_dict,
                   .locked        = true,
                   .allocator     = alloc,
                   .skip_obj_hash = true);
    assert(locked_dict.lock != 0);

    // NOTE: the dict `lock` field is now a uint8_t bitfield (a locked-mode flag),
    // not an n00b_rwlock_t* — a locked dict no longer allocates a separate rwlock
    // object; migration is coordinated via the inline `_migration_state` futex.
    // The former checks here (the dict's lock is an mmap'd rwlock owned by `alloc`,
    // and read-lock/unlock the dict's lock object) tested a removed feature and
    // were dropped. The standalone n00b_data_lock_new() rwlock below is unrelated
    // and still exercises the rwlock API directly.

    n00b_rwlock_t *scoped_lock = n00b_data_lock_new(.allocator = alloc);
    assert(scoped_lock != nullptr);

    auto scoped_map_opt = n00b_mmap_by_address(scoped_lock);
    assert(n00b_option_is_set(scoped_map_opt));

    n00b_mmap_info_t *scoped_map = n00b_option_get(scoped_map_opt);
    assert(n00b_atomic_load(&scoped_map->allocator) == alloc);

    n00b_data_write_lock(scoped_lock);
    n00b_data_unlock(scoped_lock);

    printf("  [PASS] locked_dict_lock_allocator\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running typed dict tests...\n");

    test_init_empty();
    test_put_get();
    test_overwrite();
    test_not_found();
    test_remove();
    test_add_existing();
    test_contains();
    test_growth();
    test_string_keys();
    test_static_string_custom_hash_keys();
    test_large_values();
    test_mixed_operations();
    test_remove_reinsert();
    test_cas_insert();
    test_cas_update();
    test_remove_missing();
    test_length_tracking();
    test_locked_dict_lock_allocator();

    printf("All typed dict tests passed.\n");
    return 0;
}
