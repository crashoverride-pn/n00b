/*
 * test_dict_literal_real_headers.c — WP-011 Phase 5a regression
 *
 * Locks in the typeid-alignment fix (Phase 5a finding 1): the
 * canonical `n00b_dict_t(K, V)` macro in `include/adt/dict.h` now
 * uses `typeid("n00b_dict", k, v)` (was `typeid("dict", k, v)`),
 * matching the WP-010 list precedent (`n00b_list_t(T)` →
 * `typeid("n00b_list", T)`) and what ncc's `tag_is_dict_type` looks
 * for.
 *
 * This fixture uses the REAL `n00b_dict_t(K, V)` from
 * `include/adt/dict.h` — no private re-declaration — together with
 * the REAL n00b meson r-string config (the test executable is built
 * with `exe_c_args + n00b_static_init_helper_flags`, so dict literal
 * lowering goes through ncc's full xform pipeline and the
 * static-init helper).
 *
 * It also exercises Phase 5a finding 2 — `is_rstr_element_type`
 * widening to accept the `<rstr_string_type> + "*"` form (the
 * key type extracted from a `typeid("n00b_dict", n00b_string_t *, int)`
 * is `n00b_string_t *`, which the matcher previously rejected since
 * the configured `rstr_string_type` is `n00b_string_t` (no `*`)).
 *
 * If either gap reopens, this fixture fails at the ncc xform stage
 * (no canonical-tag match → dict literal lowering doesn't run) or
 * at the helper stage (r-string keys aren't recognized as static
 * pointer-key elements → bad image emission).
 */

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>

#include "n00b.h"
#include "adt/dict.h"
#include "core/runtime.h"

// Use the REAL n00b_dict_t from include/adt/dict.h. No private
// re-declaration: the whole point of this regression test is that
// the canonical macro's typeid matches what ncc looks for.
static n00b_dict_t(n00b_string_t *, int) test_dict = d{
    r"foo": 1,
    r"bar": 2,
    r"baz": 3,
};

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    // Layout invariants — the static dict image must report 3 live
    // entries at the floor capacity (N00B_DICT_MIN_SIZE == 16).
    assert(atomic_load_explicit(&test_dict.length,
                                memory_order_relaxed)
           == 3);
    assert(test_dict.skip_obj_hash == 0);
    assert(test_dict.lock == 0);

    auto store = test_dict.store;
    assert(store != nullptr);
    assert(store->last_slot == 15u);
    assert(atomic_load_explicit(&store->used_count,
                                memory_order_relaxed)
           == 3u);

    // Lookup configuration. WP-011 Phase 5d landed the cached_hash
    // population on every r-string emission (not just dict keys), so
    // standalone `r"foo"` lvalues and the dict-key descriptors now
    // share the same content-XXH3 in their `cached_hash` slot. With
    // both sides matching, the default lookup path
    // (`n00b_hash(*key, nullptr)` -> short-circuits on `cached_hash`)
    // works without the prior `.skip_obj_hash + .fn` workaround. The
    // dict literal helper emits `.fn=nullptr, .skip_obj_hash=0`, which
    // is exactly what we want; no runtime mutation needed.
    //
    // Content-based lookup via the canonical n00b_dict_get macro.
    // The macro takes `&(key)`, so the query key must be an lvalue.
    // Bind each r-string literal to a local pointer first.
    bool           found;
    n00b_string_t *q_foo  = r"foo";
    n00b_string_t *q_bar  = r"bar";
    n00b_string_t *q_baz  = r"baz";
    n00b_string_t *q_miss = r"quux";

    int v_foo = n00b_dict_get(&test_dict, q_foo, &found);
    assert(found);
    assert(v_foo == 1);

    int v_bar = n00b_dict_get(&test_dict, q_bar, &found);
    assert(found);
    assert(v_bar == 2);

    int v_baz = n00b_dict_get(&test_dict, q_baz, &found);
    assert(found);
    assert(v_baz == 3);

    // Missing key — must report not found.
    found = true;
    (void)n00b_dict_get(&test_dict, q_miss, &found);
    assert(!found);

    printf("test_dict_literal_real_headers: PASS\n");

    n00b_shutdown();
    return 0;
}
