#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "typecheck/types.h"
#include "typecheck/context.h"
#include "typecheck/hash.h"
#include "typecheck/construct.h"
#include "adt/any.h"

// ============================================================================
// 1. Primitive hash matches typehash()
// ============================================================================

static void
test_prim_hash_int(void)
{
    // n00b "int" maps to C "int64_t".
    uint64_t expected = typehash(int64_t);
    uint64_t got      = n00b_type_hash_cname("int64_t");

    assert(expected == got);
    printf("  [PASS] prim_hash_int\n");
}

static void
test_prim_hash_bool(void)
{
    uint64_t expected = typehash(bool);
    uint64_t got      = n00b_type_hash_cname("bool");

    assert(expected == got);
    printf("  [PASS] prim_hash_bool\n");
}

static void
test_prim_hash_double(void)
{
    uint64_t expected = typehash(double);
    uint64_t got      = n00b_type_hash_cname("double");

    assert(expected == got);
    printf("  [PASS] prim_hash_double\n");
}

static void
test_prim_hash_string(void)
{
    uint64_t expected = typehash(n00b_string_t);
    uint64_t got      = n00b_type_hash_cname("n00b_string_t");

    assert(expected == got);
    printf("  [PASS] prim_hash_string\n");
}

// ============================================================================
// 2. tc_type_to_hash for primitives
// ============================================================================

static void
test_tc_int_hash(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();
    uint64_t expected   = typehash(int64_t);
    uint64_t got        = n00b_tc_type_to_hash(ctx->t_int);

    assert(got == expected);
    printf("  [PASS] tc_int_hash\n");
}

static void
test_tc_i32_hash(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();
    uint64_t expected   = typehash(int32_t);
    uint64_t got        = n00b_tc_type_to_hash(ctx->t_i32);

    assert(got == expected);
    printf("  [PASS] tc_i32_hash\n");
}

static void
test_tc_u64_hash(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();
    uint64_t expected   = typehash(uint64_t);
    uint64_t got        = n00b_tc_type_to_hash(ctx->t_u64);

    assert(got == expected);
    printf("  [PASS] tc_u64_hash\n");
}

static void
test_tc_bool_hash(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();
    uint64_t expected   = typehash(bool);
    uint64_t got        = n00b_tc_type_to_hash(ctx->t_bool);

    assert(got == expected);
    printf("  [PASS] tc_bool_hash\n");
}

static void
test_tc_f64_hash(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();
    uint64_t expected   = typehash(double);
    uint64_t got        = n00b_tc_type_to_hash(ctx->t_f64);

    assert(got == expected);
    printf("  [PASS] tc_f64_hash\n");
}

static void
test_tc_string_hash(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();
    uint64_t expected   = typehash(n00b_string_t);
    uint64_t got        = n00b_tc_type_to_hash(ctx->t_string);

    assert(got == expected);
    printf("  [PASS] tc_string_hash\n");
}

// ============================================================================
// 3. Unresolved var → n00b_any_t hash
// ============================================================================

static void
test_tc_var_hash(void)
{
    n00b_tc_ctx_t  *ctx = n00b_tc_ctx_new();
    n00b_tc_type_t *var = n00b_tc_fresh_var(ctx);

    uint64_t expected = typehash(n00b_any_t);
    uint64_t got      = n00b_tc_type_to_hash(var);

    assert(got == expected);
    printf("  [PASS] tc_var_hash\n");
}

// ============================================================================
// 4. any_t boxing round-trip
// ============================================================================

static void
test_any_box_int(void)
{
    uint64_t  hash = typehash(int64_t);
    n00b_any_t a   = n00b_any_box_int(hash, 42);

    assert(a.type_hash == hash);
    assert(n00b_any_unbox_int(a) == 42);
    printf("  [PASS] any_box_int\n");
}

static void
test_any_box_ref(void)
{
    int        dummy = 99;
    uint64_t   hash  = typehash(void *);
    n00b_any_t a     = n00b_any_box_ref(hash, &dummy);

    assert(a.type_hash == hash);
    assert(n00b_any_unbox_ref(a) == &dummy);
    printf("  [PASS] any_box_ref\n");
}

// ============================================================================
// 5. Hash is non-zero and distinct
// ============================================================================

static void
test_hashes_distinct(void)
{
    n00b_tc_ctx_t *ctx = n00b_tc_ctx_new();

    uint64_t h_int    = n00b_tc_type_to_hash(ctx->t_int);
    uint64_t h_bool   = n00b_tc_type_to_hash(ctx->t_bool);
    uint64_t h_string = n00b_tc_type_to_hash(ctx->t_string);
    uint64_t h_f64    = n00b_tc_type_to_hash(ctx->t_f64);

    assert(h_int != 0);
    assert(h_bool != 0);
    assert(h_string != 0);
    assert(h_f64 != 0);

    assert(h_int != h_bool);
    assert(h_int != h_string);
    assert(h_int != h_f64);
    assert(h_bool != h_string);

    printf("  [PASS] hashes_distinct\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("test_type_hash:\n");

    // Section 1: raw cname hashing matches typehash()
    test_prim_hash_int();
    test_prim_hash_bool();
    test_prim_hash_double();
    test_prim_hash_string();

    // Section 2: tc_type → hash
    test_tc_int_hash();
    test_tc_i32_hash();
    test_tc_u64_hash();
    test_tc_bool_hash();
    test_tc_f64_hash();
    test_tc_string_hash();

    // Section 3: Var → n00b_any_t
    test_tc_var_hash();

    // Section 4: boxing
    test_any_box_int();
    test_any_box_ref();

    // Section 5: distinct hashes
    test_hashes_distinct();

    printf("\nAll type_hash tests passed.\n");
    n00b_shutdown();
    return 0;
}
