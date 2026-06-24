#pragma once

/**
 * @file pwz_internal.h
 * @internal
 * @brief Private types for the PWZ parser engine.
 *
 * Faithful port of the ncc bootstrap PWZ (`~/ncc/src/parse/pwz.c`): the
 * same algorithm and data model — memo reference counting with a recycle
 * free list, the `in_progress` flag packed into bit 31 of `end_pos`, and
 * single-memo left-recursion seed growing — implemented with n00b
 * primitives.
 *
 * Memory model (the n00b analog of ncc's `ncc_alloc` heap + `parse_arena`):
 *   - The grammar exp graph lives in a dedicated non-moving, GC-hidden
 *     n00b pool (`grammar_pool`).  Nonterm names are interned into it and
 *     ALT alternative lists are allocated from it, so nothing in the graph
 *     points into the moving GC arena — the pool never needs to be scanned.
 *   - Per-parse state (memos, contexts, cxt-nodes, result exps, child
 *     arrays) lives in a second non-moving, GC-hidden pool (`parse_pool`),
 *     reset between parses.  Its only outbound pointers are into itself or
 *     the (non-moving) grammar graph, so it too is never scanned.
 *
 * The parser struct itself is allocated from the runtime's non-moving
 * `runtime_obj_pool` so the embedded pool structs (and the allocator
 * pointers into them) stay valid across collections.
 */

#include "slay/pwz.h"
#include "slay/annotation.h"
#include "parsers/token_stream.h"
#include "core/pool.h"

// ============================================================================
// Memo records
// ============================================================================

// Bit 31 of end_pos doubles as the in_progress flag.
#define PWZ_MEM_IN_PROGRESS_BIT ((int32_t)(1u << 31))

// Sentinel for "no position yet". Must not have bit 31 set.
#define PWZ_POS_BOTTOM ((int32_t)0x7FFFFFFE)

typedef struct pwz_exp_t  pwz_exp_t;
typedef struct pwz_cxt_t  pwz_cxt_t;
typedef pwz_exp_t        *pwz_exp_ptr_t;

typedef struct pwz_cxt_node_t {
    pwz_cxt_t             *cxt;
    struct pwz_cxt_node_t *next;
} pwz_cxt_node_t;

typedef struct pwz_mem_t {
    pwz_cxt_node_t *parents;
    pwz_exp_t      *result;
    int32_t         start_pos;
    int32_t         end_pos;   // bit 31 = in_progress flag
    uint32_t        refcount;
} pwz_mem_t;

static inline bool
pwz_mem_in_progress(const pwz_mem_t *m)
{
    return (m->end_pos & PWZ_MEM_IN_PROGRESS_BIT) != 0;
}

static inline void
pwz_mem_set_in_progress(pwz_mem_t *m, bool v)
{
    if (v) {
        m->end_pos |= PWZ_MEM_IN_PROGRESS_BIT;
    }
    else {
        m->end_pos &= ~PWZ_MEM_IN_PROGRESS_BIT;
    }
}

static inline int32_t
pwz_mem_end_pos(const pwz_mem_t *m)
{
    return m->end_pos & ~PWZ_MEM_IN_PROGRESS_BIT;
}

// ============================================================================
// Contexts (per-parse, parse_pool-allocated)
// ============================================================================

typedef enum : uint8_t {
    PWZ_CXT_TOP,
    PWZ_CXT_SEQ,
    PWZ_CXT_ALT,
} pwz_cxt_kind_t;

struct pwz_cxt_t {
    pwz_cxt_kind_t kind;
    int64_t        nt_id;
    int32_t        rule_ix;
    int32_t        nleft;
    union [[n00b::raw_union]] {
        struct {
            pwz_mem_t     *mem;    // parent memo to propagate completion to
            pwz_exp_ptr_t *left;
            pwz_exp_ptr_t *right;
            int32_t        nright;
        } seq;
        struct {
            pwz_mem_t *mem;
        } alt;
    };
};

// ============================================================================
// PWZ expression graph (built once from grammar, grammar_pool-allocated)
// ============================================================================

typedef enum {
    PWZ_TOK,
    PWZ_SEQ,
    PWZ_ALT,
    PWZ_CLASS,
    PWZ_ANY,
} pwz_exp_kind_t;

struct pwz_exp_t {
    pwz_mem_t *mem;            // per-position memo (parse_pool; reset per parse)
    union [[n00b::raw_union]] {
        int64_t           tid;    // PWZ_TOK: terminal ID (n00b ids are int64)
        int64_t           nt_id;  // PWZ_SEQ, PWZ_ALT: nonterminal ID
        n00b_char_class_t cc;     // PWZ_CLASS: character class
    };
    pwz_exp_kind_t kind;
    int32_t        rule_ix;    // PWZ_SEQ: rule index
    int32_t        nchildren;  // PWZ_SEQ: child count
    union [[n00b::raw_union]] {
        struct {
            const char    *name;       // interned in grammar_pool
            pwz_exp_ptr_t *children;
        } seq;
        struct {
            n00b_list_t(pwz_exp_ptr_t) alts;
        } alt;
    };
};

// ============================================================================
// Zippers & worklist
// ============================================================================

typedef struct {
    pwz_exp_t *result;
    pwz_mem_t *mem;
} pwz_zipper_t;

typedef n00b_parse_tree_t *n00b_parse_tree_ptr_t;

// ============================================================================
// Parser state (full definition)
// ============================================================================

struct n00b_pwz_parser_t {
    n00b_grammar_t              *grammar;
    pwz_exp_t                   *start_exp;
    pwz_exp_ptr_t               *nt_exps;   // grammar_pool array, indexed by NT id
    const char                 **nt_names;  // interned names, indexed by NT id
    n00b_list_t(pwz_exp_ptr_t)   all_exps;

    /* Grammar exp graph pool: non-moving, hidden. Persists for the
     * parser's lifetime. */
    n00b_pool_t                  grammar_pool;
    n00b_allocator_t            *grammar_allocator;

    /* Per-parse pool (the ncc parse_arena analog): non-moving, hidden,
     * destroyed + recreated on each reset. Holds result exps, child
     * arrays, memos, contexts, cxt-nodes. */
    n00b_pool_t                  parse_pool;
    n00b_allocator_t            *parse_allocator;
    bool                         parse_pool_initialized;
    pwz_mem_t                   *free_mems;   // recycled-memo free list

    n00b_list_t(pwz_zipper_t)    worklist;
    n00b_list_t(pwz_zipper_t)    worklist_swap;
    n00b_list_t(pwz_exp_ptr_t)   tops;

    n00b_token_stream_t         *stream;

    n00b_parse_tree_t           *result_tree;
    n00b_parse_tree_array_t      result_trees;

    pwz_mem_t                   *mem_bottom;
    pwz_exp_t                   *exp_bottom;
};
