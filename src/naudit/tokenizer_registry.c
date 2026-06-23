/*
 * WP-009 Phase 1 — tokenizer registry.
 *
 * Pairs each registered tokenizer name with the slay scan-cb,
 * state-new factory, and optional reset hook. The registry is
 * read-only after init; lookups are linear scans (one row at
 * Phase 1, growing to <10 rows in foreseeable future). New
 * languages register their tokenizer triple here as part of the
 * code change that adds the language to `languages.c`.
 *
 * The C row wraps `n00b_c_tokenize` + `n00b_c_tokenizer_state_new`
 * + `n00b_c_tokenizer_reset` from libn00b's `slay/c_tokenizer.h`.
 * The `state_new` factory pointer needs a void * return type for
 * language-agnostic dispatch; we wrap the concrete C factory in a
 * thin shim rather than casting through a function-pointer
 * incompatibility (the C-standard rule is fuzzy about
 * function-pointer return-type casts; a real shim is portable).
 *
 * Per project DECISIONS.md D-005 / D-017 (the standing
 * compromise), the public lookup carries no `_kargs` block.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/gc.h"
#include "core/string.h"
#include "adt/list.h"
#include "text/strings/string_ops.h"
#include "slay/c_tokenizer.h"

#include "naudit/tokenizer_registry.h"

/* ---------------------------------------------------------------- */
/* Registry state                                                   */
/* ---------------------------------------------------------------- */

static bool registry_initialized = false;
static n00b_list_t(n00b_naudit_tokenizer_info_t *) *all_tokenizers
    = nullptr;

/* ---------------------------------------------------------------- */
/* State-factory shims                                              */
/* ---------------------------------------------------------------- */

/*
 * Wraps `n00b_c_tokenizer_state_new` so its return type matches
 * the registry's `void *(*)(void)` factory signature. A direct
 * function-pointer cast across return-type-incompatible
 * signatures is undefined in C; the shim is the portable
 * alternative.
 */
static void *
c_state_new_shim(void)
{
    return n00b_c_tokenizer_state_new();
}

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

static n00b_naudit_tokenizer_info_t *
build_c_row(void)
{
    n00b_naudit_tokenizer_info_t *row =
        n00b_alloc(n00b_naudit_tokenizer_info_t);
    row->name      = r"c";
    row->scan_cb   = n00b_c_tokenize;
    row->state_new = c_state_new_shim;
    row->reset_cb  = n00b_c_tokenizer_reset;
    return row;
}

static void
init_registry(void)
{
    if (registry_initialized) {
        return;
    }

    n00b_gc_register_root(all_tokenizers);
    all_tokenizers = n00b_alloc(
        n00b_list_t(n00b_naudit_tokenizer_info_t *));
    *all_tokenizers = n00b_list_new_private(n00b_naudit_tokenizer_info_t *);

    n00b_list_push(*all_tokenizers, build_c_row());

    registry_initialized = true;
}

/* ---------------------------------------------------------------- */
/* Public surface                                                   */
/* ---------------------------------------------------------------- */

n00b_naudit_tokenizer_info_t *
n00b_naudit_lookup_tokenizer(n00b_string_t *name)
{
    if (!name) {
        return nullptr;
    }
    init_registry();
    int64_t n = n00b_list_len(*all_tokenizers);
    for (int64_t i = 0; i < n; i++) {
        n00b_naudit_tokenizer_info_t *row = n00b_list_get(*all_tokenizers,
                                                          i);
        if (row && row->name && n00b_unicode_str_eq(row->name, name)) {
            return row;
        }
    }
    return nullptr;
}
