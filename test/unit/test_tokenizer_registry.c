// test_tokenizer_registry.c — Unit tests for the tokenizer registry.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "parsers/tokenizer_registry.h"

// ============================================================================
// Test 1: Lookup returns found=true for registered names
// ============================================================================

static void
test_lookup_builtin(void)
{
    bool found = false;
    n00b_scan_cb_t cb = n00b_tokenizer_lookup("text", &found);

    assert(found);
    assert(cb != nullptr);  // "text" has a real callback.

    printf("  [PASS] lookup_builtin\n");
}

// ============================================================================
// Test 2: Lookup returns found=false for unknown names
// ============================================================================

static void
test_lookup_unknown(void)
{
    bool found = false;
    n00b_scan_cb_t cb = n00b_tokenizer_lookup("nonexistent_tokenizer", &found);

    assert(!found);
    assert(cb == nullptr);

    printf("  [PASS] lookup_unknown\n");
}

// ============================================================================
// Test 3: "character" is registered with nullptr callback
// ============================================================================

static void
test_character_is_null(void)
{
    bool found = false;
    n00b_scan_cb_t cb = n00b_tokenizer_lookup("character", &found);

    assert(found);        // Name IS registered.
    assert(cb == nullptr); // But callback is nullptr (character-level mode).

    printf("  [PASS] character_is_null\n");
}

// ============================================================================
// Test 4: All built-in names resolve
// ============================================================================

static void
test_all_builtins(void)
{
    static const char *names[] = {
        "text", "character", "shell", "lisp", "json", "c", "n00b",
    };

    for (int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        bool found = false;
        n00b_tokenizer_lookup(names[i], &found);
        assert(found);
    }

    printf("  [PASS] all_builtins\n");
}

// ============================================================================
// Test 5: Custom registration
// ============================================================================

static bool
dummy_tokenizer(n00b_scanner_t *s)
{
    (void)s;
    return false;
}

static void
test_custom_register(void)
{
    n00b_tokenizer_register("my_custom", dummy_tokenizer);

    bool found = false;
    n00b_scan_cb_t cb = n00b_tokenizer_lookup("my_custom", &found);

    assert(found);
    assert(cb == dummy_tokenizer);

    printf("  [PASS] custom_register\n");
}

// ============================================================================
// Test 6: Null name returns not found
// ============================================================================

static void
test_null_name(void)
{
    bool found = false;
    n00b_scan_cb_t cb = n00b_tokenizer_lookup(nullptr, &found);

    assert(!found);
    assert(cb == nullptr);

    printf("  [PASS] null_name\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    printf("Running tokenizer registry tests...\n");

    test_lookup_builtin();
    test_lookup_unknown();
    test_character_is_null();
    test_all_builtins();
    test_custom_register();
    test_null_name();

    printf("All tokenizer registry tests passed.\n");
    n00b_shutdown();
    return 0;
}
