/**
 * @file static_image.h
 * @brief Linked static grammar image lookup.
 */
#pragma once

#include "n00b.h"
#include "adt/option.h"

// Forward declaration: the static-grammar API traffics only in
// `n00b_grammar_t *`, so the full slay grammar header is not pulled in
// here (it is not part of the `n00b.h` umbrella).
typedef struct n00b_grammar_t n00b_grammar_t;

/**
 * @brief Look up a linked baked grammar by name.
 *
 * Discovers linked `n00b_gimage` section records once, relocates each
 * offset-image in place with grammar repair, registers the ranges as baked GC
 * allocations, and returns the direct baked root for @p name. Subsequent
 * lookups return the same pointer and do not materialize or unmarshal a new
 * grammar.
 *
 * @param name  Grammar lookup name (`n00b_string_t *`; linked records store
 *              UTF-8 name bytes).
 * @return `n00b_option_set` wrapping the direct baked grammar when @p name is
 *         registered, or `n00b_option_none` when @p name is unknown (a normal,
 *         non-error outcome: the static image is a fast path, not a hard
 *         dependency).
 */
extern n00b_option_t(n00b_grammar_t *)
n00b_static_grammar_lookup(n00b_string_t *name);
