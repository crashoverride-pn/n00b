#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/dict_untyped.h"

extern n00b_size_t n00b_dict_untyped_len(n00b_dict_untyped_t *d);

// ============================================================================
// 1. Init empty — new dict has length 0
// ============================================================================

static void
test_init_empty(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    assert(n00b_dict_untyped_len(&dict) == 0);

    printf("  [PASS] init_empty\n");
}

// ============================================================================
// 2. Put / get — put key/value, get returns correct value
// ============================================================================

static void
test_put_get(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    n00b_dict_untyped_put(&dict, 42, 100);

    bool  found;
    void *val = n00b_dict_untyped_get(&dict, 42, &found);
    assert(found);
    assert((int64_t)val == 100);
    assert(n00b_dict_untyped_len(&dict) == 1);

    printf("  [PASS] put_get\n");
}

// ============================================================================
// 3. Overwrite — put same key twice; returns previous value
// ============================================================================

static void
test_overwrite(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    n00b_dict_untyped_put(&dict, 1, 10);
    void *prev = n00b_dict_untyped_put(&dict, 1, 20);

    assert((int64_t)prev == 10);

    bool  found;
    void *val = n00b_dict_untyped_get(&dict, 1, &found);
    assert(found);
    assert((int64_t)val == 20);

    printf("  [PASS] overwrite\n");
}

// ============================================================================
// 4. Not found — get missing key returns found=false
// ============================================================================

static void
test_not_found(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    n00b_dict_untyped_put(&dict, 1, 10);

    bool  found;
    void *val = n00b_dict_untyped_get(&dict, 999, &found);
    assert(!found);
    assert(val == nullptr);

    printf("  [PASS] not_found\n");
}

// ============================================================================
// 5. Remove — put then remove; contains returns false after removal
// ============================================================================

static void
test_remove(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    n00b_dict_untyped_put(&dict, 1, 10);
    assert(n00b_dict_untyped_contains(&dict, (void *)1));

    bool removed = n00b_dict_untyped_remove(&dict, 1);
    assert(removed);
    assert(!n00b_dict_untyped_contains(&dict, (void *)1));

    printf("  [PASS] remove\n");
}

// ============================================================================
// 6. Add existing — add returns false when key exists
// ============================================================================

static void
test_add_existing(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    bool added = n00b_dict_untyped_add(&dict, 1, 10);
    assert(added);

    added = n00b_dict_untyped_add(&dict, 1, 20);
    assert(!added);

    // Value should still be the original
    bool  found;
    void *val = n00b_dict_untyped_get(&dict, 1, &found);
    assert(found);
    assert((int64_t)val == 10);

    printf("  [PASS] add_existing\n");
}

// ============================================================================
// 7. Replace missing — replace returns false when key absent
// ============================================================================

static void
test_replace_missing(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    bool replaced = n00b_dict_untyped_replace(&dict, 1, 10);
    assert(!replaced);

    // Put a value then replace should work
    n00b_dict_untyped_put(&dict, 1, 10);
    replaced = n00b_dict_untyped_replace(&dict, 1, 20);
    assert(replaced);

    bool  found;
    void *val = n00b_dict_untyped_get(&dict, 1, &found);
    assert(found);
    assert((int64_t)val == 20);

    printf("  [PASS] replace_missing\n");
}

// ============================================================================
// 8. Contains — true/false for present/absent keys
// ============================================================================

static void
test_contains(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    assert(!n00b_dict_untyped_contains(&dict, (void *)42));

    n00b_dict_untyped_put(&dict, 42, 100);
    assert(n00b_dict_untyped_contains(&dict, (void *)42));
    assert(!n00b_dict_untyped_contains(&dict, (void *)99));

    printf("  [PASS] contains\n");
}

// ============================================================================
// 9. Growth — insert 200 entries (forces resize); verify all retrievable
// ============================================================================

static void
test_growth(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_word, .skip_obj_hash = true);

    for (int64_t i = 1; i <= 200; i++) {
        n00b_dict_untyped_put(&dict, i, (i * 10));
    }

    assert(n00b_dict_untyped_len(&dict) == 200);

    for (int64_t i = 1; i <= 200; i++) {
        bool  found;
        void *val = n00b_dict_untyped_get(&dict, i, &found);
        assert(found);
        assert((int64_t)val == i * 10);
    }

    printf("  [PASS] growth\n");
}

// ============================================================================
// 10. String keys — use n00b_hash_cstring; put/get with C string keys
// ============================================================================

static void
test_string_keys(void)
{
    n00b_dict_untyped_t dict;
    n00b_dict_untyped_init(&dict, .hash = n00b_hash_cstring, .skip_obj_hash = true);

    char *key1 = "hello";
    char *key2 = "world";
    char *key3 = "test";

    _n00b_dict_untyped_put(&dict, key1, (void *)1);
    _n00b_dict_untyped_put(&dict, key2, (void *)2);
    _n00b_dict_untyped_put(&dict, key3, (void *)3);

    bool  found;
    void *val;

    val = _n00b_dict_untyped_get(&dict, key1, &found);
    assert(found);
    assert((int64_t)val == 1);

    val = _n00b_dict_untyped_get(&dict, key2, &found);
    assert(found);
    assert((int64_t)val == 2);

    val = _n00b_dict_untyped_get(&dict, key3, &found);
    assert(found);
    assert((int64_t)val == 3);

    val = _n00b_dict_untyped_get(&dict, "missing", &found);
    assert(!found);

    printf("  [PASS] string_keys\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running dict_untyped tests...\n");

    test_init_empty();
    test_put_get();
    test_overwrite();
    test_not_found();
    test_remove();
    test_add_existing();
    test_replace_missing();
    test_contains();
    test_growth();
    test_string_keys();

    printf("All dict_untyped tests passed.\n");
    n00b_shutdown();
    return 0;
}
