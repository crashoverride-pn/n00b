#include "logic/asp_engine.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define ENGINE_INIT_REL_CAP 16
#define BIND_CAP            64

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

void
n00b_dl_engine_init(n00b_dl_engine_t *eng)
{
    *eng = (typeof(*eng)){};
    n00b_dl_intern_init(&eng->intern);
    eng->relations = n00b_list_new_cap_private(n00b_dl_relation_ptr_t,
                                                ENGINE_INIT_REL_CAP);
    eng->rules     = (n00b_dl_rule_list_t){};
}

void
n00b_dl_engine_free(n00b_dl_engine_t *eng)
{
    n00b_dl_intern_free(&eng->intern);
    size_t rel_n = n00b_list_len(eng->relations);
    for (size_t i = 0; i < rel_n; i++) {
        n00b_dl_relation_t *r = n00b_list_get(eng->relations, i);
        n00b_dl_relation_free(r);
        n00b_free(r);
    }
    n00b_list_free(eng->relations);

    size_t rule_n = n00b_list_len(eng->rules);
    for (size_t i = 0; i < rule_n; i++) {
        n00b_dl_rule_t *rule = &eng->rules.data[i];
        n00b_dl_rule_free(rule);
    }
    n00b_list_free(eng->rules);

    *eng = (typeof(*eng)){};
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

n00b_dl_rel_id_t
n00b_dl_engine_relation(n00b_dl_engine_t *eng, n00b_string_t *name,
                         int32_t arity)
{
    size_t n = n00b_list_len(eng->relations);
    for (size_t i = 0; i < n; i++) {
        n00b_dl_relation_t *r = n00b_list_get(eng->relations, i);
        if (n00b_unicode_str_eq(r->name, name)) {
            return r->id;
        }
    }

    n00b_dl_rel_id_t id = (n00b_dl_rel_id_t)n;

    n00b_dl_relation_t *rel = n00b_alloc(n00b_dl_relation_t);
    n00b_dl_relation_init(rel, id, name, arity);
    n00b_list_push(eng->relations, rel);

    return id;
}

// ---------------------------------------------------------------------------
// Symbol shortcuts
// ---------------------------------------------------------------------------

n00b_dl_sym_t
n00b_dl_const(n00b_dl_engine_t *eng, n00b_string_t *name)
{
    return n00b_dl_intern(&eng->intern, name);
}

n00b_dl_sym_t
n00b_dl_int(n00b_dl_engine_t *eng, int64_t value)
{
    return n00b_dl_intern_int(&eng->intern, value);
}

n00b_dl_sym_t
n00b_dl_var(n00b_dl_engine_t *eng, n00b_string_t *name)
{
    return n00b_dl_intern_var(&eng->intern, name);
}

// ---------------------------------------------------------------------------
// Expression constructors
// ---------------------------------------------------------------------------

n00b_dl_expr_t *
n00b_dl_expr_sym(n00b_dl_sym_t sym)
{
    n00b_dl_expr_t *e = n00b_alloc(n00b_dl_expr_t);
    e->kind           = N00B_DL_EXPR_SYM;
    e->sym            = sym;
    return e;
}

n00b_dl_expr_t *
n00b_dl_expr_int_lit(int64_t val)
{
    n00b_dl_expr_t *e = n00b_alloc(n00b_dl_expr_t);
    e->kind           = N00B_DL_EXPR_INT;
    e->int_val        = val;
    return e;
}

n00b_dl_expr_t *
n00b_dl_expr_binop(n00b_dl_expr_kind_t op, n00b_dl_expr_t *l,
                    n00b_dl_expr_t *r)
{
    n00b_dl_expr_t *e = n00b_alloc(n00b_dl_expr_t);
    e->kind           = op;
    e->bin.left       = l;
    e->bin.right      = r;
    return e;
}

n00b_dl_expr_t *
n00b_dl_expr_neg(n00b_dl_expr_t *operand)
{
    n00b_dl_expr_t *e = n00b_alloc(n00b_dl_expr_t);
    e->kind           = N00B_DL_EXPR_NEG;
    e->operand        = operand;
    return e;
}

void
n00b_dl_expr_free(n00b_dl_expr_t *expr)
{
    if (!expr) return;

    switch (expr->kind) {
    case N00B_DL_EXPR_SYM:
    case N00B_DL_EXPR_INT:
        break;
    case N00B_DL_EXPR_ADD:
    case N00B_DL_EXPR_SUB:
    case N00B_DL_EXPR_MUL:
    case N00B_DL_EXPR_DIV:
    case N00B_DL_EXPR_MOD:
        n00b_dl_expr_free(expr->bin.left);
        n00b_dl_expr_free(expr->bin.right);
        break;
    case N00B_DL_EXPR_NEG:
        n00b_dl_expr_free(expr->operand);
        break;
    }

    n00b_free(expr);
}

n00b_result_t(int64_t)
n00b_dl_sym_to_int64(n00b_dl_engine_t *eng, n00b_dl_sym_t sym)
{
    n00b_string_t *name = n00b_dl_intern_name(&eng->intern, sym);
    if (!name || name->u8_bytes == 0 || name->data[0] != '#') {
        return n00b_result_err(int64_t, EINVAL);
    }
    return n00b_result_ok(int64_t, strtoll(name->data + 1, nullptr, 10));
}

// ---------------------------------------------------------------------------
// Facts and rules
// ---------------------------------------------------------------------------

void
n00b_dl_add_fact(n00b_dl_engine_t *eng, n00b_dl_rel_id_t rel,
                  int32_t arity, const n00b_dl_sym_t *args)
{
    n00b_dl_relation_t *r = n00b_list_get(eng->relations, rel);
    assert(arity == r->arity && "n00b_dl_add_fact: arity mismatch");
    n00b_dl_relation_insert(r, args);
}

void
n00b_dl_add_rule(n00b_dl_engine_t *eng, n00b_dl_rule_t rule)
{
    n00b_list_push(eng->rules, rule);
}

// ---------------------------------------------------------------------------
// Stratification (Tarjan's SCC + topological sort)
// ---------------------------------------------------------------------------

typedef struct {
    int32_t index;
    int32_t lowlink;
    bool    on_stack;
    int32_t scc_id;
} tarjan_node_t;

typedef struct {
    n00b_dl_i32_edges_map_t adj;
    tarjan_node_t           *nodes;
    int32_t                 *stack;
    int32_t                  stack_top;
    int32_t                  counter;
    int32_t                  scc_count;
    int32_t                  num_nodes;
} tarjan_state_t;

static void
tarjan_strongconnect(tarjan_state_t *st, int32_t v)
{
    tarjan_node_t *nv = &st->nodes[v];
    nv->index   = st->counter;
    nv->lowlink = st->counter;
    st->counter++;
    st->stack[st->stack_top++] = v;
    nv->on_stack = true;

    n00b_dl_dep_edge_list_t *edges =
        n00b_dl_i32_edges_map_get(&st->adj, v);
    if (edges) {
        for (int32_t i = 0; i < edges->len; i++) {
            int32_t        w  = edges->data[i].target;
            tarjan_node_t *nw = &st->nodes[w];
            if (nw->index == -1) {
                tarjan_strongconnect(st, w);
                if (nw->lowlink < nv->lowlink) {
                    nv->lowlink = nw->lowlink;
                }
            } else if (nw->on_stack) {
                if (nw->index < nv->lowlink) {
                    nv->lowlink = nw->index;
                }
            }
        }
    }

    if (nv->lowlink == nv->index) {
        int32_t scc_id = st->scc_count++;
        while (true) {
            int32_t w = st->stack[--st->stack_top];
            st->nodes[w].on_stack = false;
            st->nodes[w].scc_id   = scc_id;
            if (w == v) break;
        }
    }
}

static void
cleanup_adj(n00b_dl_i32_edges_map_t *adj)
{
    for (int32_t i = 0; i < adj->capacity; i++) {
        n00b_dl_i32_edges_entry_t *e = &adj->entries[i];
        if (e->occupied && !e->deleted) {
            n00b_free(e->value.data);
        }
    }
    n00b_free(adj->entries);
    adj->entries  = nullptr;
    adj->capacity = 0;
    adj->count    = 0;
}

static bool
stratify(n00b_dl_engine_t *eng)
{
    int32_t n = (int32_t)n00b_list_len(eng->relations);
    if (n == 0) {
        eng->num_strata = 1;
        eng->stratified = true;
        return true;
    }

    tarjan_state_t st = {};
    n00b_dl_i32_edges_map_init(&st.adj);
    st.nodes     = n00b_alloc_array(tarjan_node_t, n);
    st.stack     = n00b_alloc_array(int32_t, n);
    st.stack_top = 0;
    st.counter   = 0;
    st.scc_count = 0;
    st.num_nodes = n;

    for (int32_t i = 0; i < n; i++) {
        st.nodes[i].index  = -1;
        st.nodes[i].scc_id = -1;
    }

    // Build dependency graph
    for (size_t r = 0; r < n00b_list_len(eng->rules); r++) {
        n00b_dl_rule_t *rule     = &eng->rules.data[r];
        int32_t         head_rel = rule->head.rel;

        for (int32_t b = 0; b < rule->body_len; b++) {
            if (!n00b_variant_is_type(rule->body[b], n00b_dl_literal_t))
                continue;
            n00b_dl_literal_t body_lit =
                n00b_variant_get(rule->body[b], n00b_dl_literal_t);
            int32_t body_rel = body_lit.rel;
            bool    negated  = body_lit.negated;

            n00b_dl_dep_edge_list_t *edges =
                n00b_dl_i32_edges_map_get(&st.adj, head_rel);
            if (edges) {
                if (edges->len >= edges->cap) {
                    int32_t            old_cap  = edges->cap;
                    int32_t            new_cap  = old_cap ? old_cap * 2 : 4;
                    n00b_dl_dep_edge_t *new_data =
                        n00b_alloc_array(n00b_dl_dep_edge_t, new_cap);
                    memcpy(new_data, edges->data,
                           old_cap * sizeof(n00b_dl_dep_edge_t));
                    n00b_free(edges->data);
                    edges->data = new_data;
                    edges->cap  = new_cap;
                }
                edges->data[edges->len++] = (n00b_dl_dep_edge_t){
                    .target  = body_rel,
                    .negated = negated,
                };
            } else {
                n00b_dl_dep_edge_list_t new_list = {};
                new_list.data    = n00b_alloc_array(n00b_dl_dep_edge_t, 4);
                new_list.cap     = 4;
                new_list.len     = 1;
                new_list.data[0] = (n00b_dl_dep_edge_t){
                    .target  = body_rel,
                    .negated = negated,
                };
                n00b_dl_i32_edges_map_put(&st.adj, head_rel, new_list);
            }
        }
    }

    // Run Tarjan's
    for (int32_t i = 0; i < n; i++) {
        if (st.nodes[i].index == -1) {
            tarjan_strongconnect(&st, i);
        }
    }

    // Check for negation within an SCC (unstratifiable)
    for (int32_t ci = 0; ci < st.adj.capacity; ci++) {
        n00b_dl_i32_edges_entry_t *entry = &st.adj.entries[ci];
        if (!entry->occupied || entry->deleted) continue;
        int32_t                  src_rel     = entry->key;
        n00b_dl_dep_edge_list_t *edges_check = &entry->value;
        int32_t                  scc_src     = st.nodes[src_rel].scc_id;
        for (int32_t i = 0; i < edges_check->len; i++) {
            if (edges_check->data[i].negated &&
                st.nodes[edges_check->data[i].target].scc_id == scc_src) {
                cleanup_adj(&st.adj);
                n00b_free(st.nodes);
                n00b_free(st.stack);
                return false;
            }
        }
    }

    eng->num_strata = st.scc_count;

    // Assign strata to relations and rules
    int32_t *rel_stratum = n00b_alloc_array(int32_t, n);
    for (int32_t i = 0; i < n; i++) {
        rel_stratum[i] = st.nodes[i].scc_id;
    }

    for (size_t r = 0; r < n00b_list_len(eng->rules); r++) {
        eng->rules.data[r].stratum =
            rel_stratum[eng->rules.data[r].head.rel];
    }

    cleanup_adj(&st.adj);
    n00b_free(st.nodes);
    n00b_free(st.stack);
    n00b_free(rel_stratum);

    eng->stratified = true;
    return true;
}

// ---------------------------------------------------------------------------
// Join evaluation for a single rule
// ---------------------------------------------------------------------------

typedef struct {
    n00b_dl_sym_t var_id;
    n00b_dl_sym_t bound_value;
} binding_t;

typedef struct {
    binding_t entries[BIND_CAP];
    int32_t   count;
} bind_env_t;

static n00b_dl_sym_t
env_lookup(bind_env_t *env, n00b_dl_sym_t var)
{
    for (int32_t i = 0; i < env->count; i++) {
        if (env->entries[i].var_id == var) {
            return env->entries[i].bound_value;
        }
    }
    return N00B_DL_SYM_INVALID;
}

static void
env_bind(bind_env_t *env, n00b_dl_sym_t var, n00b_dl_sym_t val)
{
    for (int32_t i = 0; i < env->count; i++) {
        if (env->entries[i].var_id == var) {
            env->entries[i].bound_value = val;
            return;
        }
    }
    assert(env->count < BIND_CAP && "too many variable bindings in rule");
    env->entries[env->count++] = (binding_t){
        .var_id      = var,
        .bound_value = val,
    };
}

static bool
match_tuple(const n00b_dl_sym_t *tuple, const n00b_dl_literal_t *lit,
            bind_env_t *env, bind_env_t *snapshot)
{
    *snapshot = *env;

    for (int32_t i = 0; i < lit->arity; i++) {
        n00b_dl_sym_t arg = lit->args[i];
        if (n00b_dl_is_var(arg)) {
            n00b_dl_sym_t bound = env_lookup(env, arg);
            if (bound != N00B_DL_SYM_INVALID) {
                if (bound != tuple[i]) {
                    *env = *snapshot;
                    return false;
                }
            } else {
                env_bind(env, arg, tuple[i]);
            }
        } else {
            if (arg != tuple[i]) {
                *env = *snapshot;
                return false;
            }
        }
    }
    return true;
}

static const n00b_dl_sym_t *
get_tuple(n00b_dl_relation_t *rel, size_t idx)
{
    if (idx < rel->stable_count) {
        return rel->stable_data + idx * rel->arity;
    }
    return rel->recent_data + (idx - rel->stable_count) * rel->arity;
}

static int64_t
eval_expr(n00b_dl_engine_t *eng, n00b_dl_expr_t *expr, bind_env_t *env,
          bool *ok)
{
    switch (expr->kind) {
    case N00B_DL_EXPR_INT:
        return expr->int_val;

    case N00B_DL_EXPR_SYM: {
        n00b_dl_sym_t sym = expr->sym;
        if (n00b_dl_is_var(sym)) {
            n00b_dl_sym_t bound = env_lookup(env, sym);
            if (bound == N00B_DL_SYM_INVALID) {
                *ok = false;
                return 0;
            }
            sym = bound;
        }
        auto conv_r = n00b_dl_sym_to_int64(eng, sym);
        if (n00b_result_is_err(conv_r)) {
            *ok = false;
            return 0;
        }
        return n00b_result_get(conv_r);
    }

    case N00B_DL_EXPR_ADD: {
        int64_t l = eval_expr(eng, expr->bin.left, env, ok);
        if (!*ok) return 0;
        int64_t r = eval_expr(eng, expr->bin.right, env, ok);
        if (!*ok) return 0;
        return l + r;
    }
    case N00B_DL_EXPR_SUB: {
        int64_t l = eval_expr(eng, expr->bin.left, env, ok);
        if (!*ok) return 0;
        int64_t r = eval_expr(eng, expr->bin.right, env, ok);
        if (!*ok) return 0;
        return l - r;
    }
    case N00B_DL_EXPR_MUL: {
        int64_t l = eval_expr(eng, expr->bin.left, env, ok);
        if (!*ok) return 0;
        int64_t r = eval_expr(eng, expr->bin.right, env, ok);
        if (!*ok) return 0;
        return l * r;
    }
    case N00B_DL_EXPR_DIV: {
        int64_t l = eval_expr(eng, expr->bin.left, env, ok);
        if (!*ok) return 0;
        int64_t r = eval_expr(eng, expr->bin.right, env, ok);
        if (!*ok) return 0;
        if (r == 0) {
            *ok = false;
            return 0;
        }
        return l / r;
    }
    case N00B_DL_EXPR_MOD: {
        int64_t l = eval_expr(eng, expr->bin.left, env, ok);
        if (!*ok) return 0;
        int64_t r = eval_expr(eng, expr->bin.right, env, ok);
        if (!*ok) return 0;
        if (r == 0) {
            *ok = false;
            return 0;
        }
        return l % r;
    }
    case N00B_DL_EXPR_NEG: {
        int64_t v = eval_expr(eng, expr->operand, env, ok);
        if (!*ok) return 0;
        return -v;
    }
    }
    *ok = false;
    return 0;
}

// ---------------------------------------------------------------------------
// Body evaluation with column-index optimisation for bound variables
// ---------------------------------------------------------------------------

static void
evaluate_body(n00b_dl_engine_t *eng, n00b_dl_rule_t *rule,
              int32_t lit_idx, bind_env_t *env, bool has_recent,
              n00b_dl_relation_t *head_rel)
{
    if (lit_idx >= rule->body_len) {
        if (!has_recent) return;

        // Build the head tuple dynamically — arity is only known at runtime.
        n00b_dl_sym_t *head_tuple =
            n00b_alloc_array(n00b_dl_sym_t, head_rel->arity);
        for (int32_t i = 0; i < rule->head.arity; i++) {
            n00b_dl_sym_t arg = rule->head.args[i];
            if (n00b_dl_is_var(arg)) {
                head_tuple[i] = env_lookup(env, arg);
            } else {
                head_tuple[i] = arg;
            }
        }
        n00b_dl_relation_insert(head_rel, head_tuple);
        n00b_free(head_tuple);
        return;
    }

    n00b_dl_body_goal_t *goal = &rule->body[lit_idx];

    if (n00b_variant_is_type(*goal, n00b_dl_builtin_t)) {
        n00b_dl_builtin_t  builtin = n00b_variant_get(*goal, n00b_dl_builtin_t);
        n00b_dl_builtin_t *bi      = &builtin;
        bool ok = true;

        if (bi->kind == N00B_DL_BUILTIN_IS) {
            int64_t val = eval_expr(eng, bi->rhs, env, &ok);
            if (!ok) return;

            n00b_dl_sym_t result_sym = n00b_dl_int(eng, val);

            assert(bi->lhs->kind == N00B_DL_EXPR_SYM
                   && n00b_dl_is_var(bi->lhs->sym));
            n00b_dl_sym_t target_var = bi->lhs->sym;

            n00b_dl_sym_t existing = env_lookup(env, target_var);
            if (existing != N00B_DL_SYM_INVALID) {
                if (existing != result_sym) return;
            } else {
                bind_env_t snapshot = *env;
                env_bind(env, target_var, result_sym);
                evaluate_body(eng, rule, lit_idx + 1, env,
                              has_recent, head_rel);
                *env = snapshot;
                return;
            }
        } else {
            int64_t lval = eval_expr(eng, bi->lhs, env, &ok);
            if (!ok) return;
            int64_t rval = eval_expr(eng, bi->rhs, env, &ok);
            if (!ok) return;

            bool pass = false;
            switch (bi->kind) {
            case N00B_DL_BUILTIN_LT: pass = (lval <  rval); break;
            case N00B_DL_BUILTIN_GT: pass = (lval >  rval); break;
            case N00B_DL_BUILTIN_LE: pass = (lval <= rval); break;
            case N00B_DL_BUILTIN_GE: pass = (lval >= rval); break;
            case N00B_DL_BUILTIN_EQ: pass = (lval == rval); break;
            case N00B_DL_BUILTIN_NE: pass = (lval != rval); break;
            default: return;
            }

            if (!pass) return;
        }

        evaluate_body(eng, rule, lit_idx + 1, env, has_recent, head_rel);
        return;
    }

    // literal goal
    n00b_dl_literal_t   literal = n00b_variant_get(*goal, n00b_dl_literal_t);
    n00b_dl_literal_t  *lit     = &literal;
    n00b_dl_relation_t *rel = n00b_list_get(eng->relations, lit->rel);

    if (lit->negated) {
        size_t total = rel->stable_count + rel->recent_count;
        for (size_t i = 0; i < total; i++) {
            const n00b_dl_sym_t *tuple = get_tuple(rel, i);
            bind_env_t           snapshot;
            if (match_tuple(tuple, lit, env, &snapshot)) {
                *env = snapshot;
                return;
            }
        }
        evaluate_body(eng, rule, lit_idx + 1, env, has_recent, head_rel);
        return;
    }

    // Use column indexes when a bound variable or constant argument exists.
    // For each argument position, check if it's already bound in env.
    // If found, rebuild the index (lazily) and iterate only matching tuples.
    int32_t bound_col = -1;
    int64_t bound_val = 0;

    for (int32_t a = 0; a < lit->arity; a++) {
        n00b_dl_sym_t arg = lit->args[a];
        if (n00b_dl_is_var(arg)) {
            n00b_dl_sym_t bv = env_lookup(env, arg);
            if (bv != N00B_DL_SYM_INVALID) {
                bound_col = a;
                bound_val = (int64_t)bv;
                break;
            }
        } else {
            bound_col = a;
            bound_val = (int64_t)arg;
            break;
        }
    }

    if (bound_col >= 0) {
        n00b_dl_relation_rebuild_index(rel);

        n00b_dl_offset_list_t *offsets =
            n00b_dl_i64_offsets_map_get(&rel->col_index[bound_col],
                                         bound_val);
        if (!offsets) {
            return;
        }

        for (int32_t oi = 0; oi < offsets->len; oi++) {
            size_t               idx       = offsets->data[oi];
            const n00b_dl_sym_t *tuple     = get_tuple(rel, idx);
            bind_env_t           snapshot;
            bool                 is_recent = (idx >= rel->stable_count);

            if (match_tuple(tuple, lit, env, &snapshot)) {
                evaluate_body(eng, rule, lit_idx + 1, env,
                              has_recent || is_recent, head_rel);
                *env = snapshot;
            }
        }
    } else {
        // No bound arguments — full scan
        size_t total = rel->stable_count + rel->recent_count;

        for (size_t i = 0; i < total; i++) {
            const n00b_dl_sym_t *tuple     = get_tuple(rel, i);
            bind_env_t           snapshot;
            bool                 is_recent = (i >= rel->stable_count);

            if (match_tuple(tuple, lit, env, &snapshot)) {
                evaluate_body(eng, rule, lit_idx + 1, env,
                              has_recent || is_recent, head_rel);
                *env = snapshot;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Semi-naive evaluation
// ---------------------------------------------------------------------------

static void
evaluate_stratum(n00b_dl_engine_t *eng, int32_t stratum)
{
    size_t rel_n = n00b_list_len(eng->relations);
    for (size_t r = 0; r < rel_n; r++) {
        n00b_dl_relation_swap(n00b_list_get(eng->relations, r));
    }

    bool first_iteration = true;

    while (true) {
        eng->iterations++;

        for (size_t r = 0; r < n00b_list_len(eng->rules); r++) {
            n00b_dl_rule_t *rule = &eng->rules.data[r];
            if (rule->stratum != stratum) continue;

            n00b_dl_relation_t *head_rel =
                n00b_list_get(eng->relations, rule->head.rel);
            bind_env_t          env      = {};
            evaluate_body(eng, rule, 0, &env, first_iteration, head_rel);
        }

        first_iteration = false;

        bool changed = false;
        for (size_t r = 0; r < rel_n; r++) {
            if (n00b_dl_relation_swap(n00b_list_get(eng->relations, r))) {
                changed = true;
            }
        }

        if (!changed) break;
    }
}

// ---------------------------------------------------------------------------
// Public API: run
// ---------------------------------------------------------------------------

bool
n00b_dl_run(n00b_dl_engine_t *eng)
{
    if (!stratify(eng)) {
        return false;
    }

    for (int32_t s = 0; s < eng->num_strata; s++) {
        evaluate_stratum(eng, s);
    }

    eng->facts_derived = 0;
    size_t rn = n00b_list_len(eng->relations);
    for (size_t r = 0; r < rn; r++) {
        eng->facts_derived +=
            (int64_t)n00b_dl_relation_count(n00b_list_get(eng->relations, r));
    }

    return true;
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

void
n00b_dl_query(n00b_dl_engine_t *eng, n00b_dl_rel_id_t rel,
               n00b_dl_query_cb cb, void *ctx)
{
    n00b_dl_relation_t *r     = n00b_list_get(eng->relations, rel);
    size_t              total = r->stable_count + r->recent_count;

    for (size_t i = 0; i < total; i++) {
        const n00b_dl_sym_t *tuple = get_tuple(r, i);
        if (!cb(tuple, r->arity, ctx)) {
            return;
        }
    }
}

size_t
n00b_dl_count(n00b_dl_engine_t *eng, n00b_dl_rel_id_t rel)
{
    return n00b_dl_relation_count(n00b_list_get(eng->relations, rel));
}

// ---------------------------------------------------------------------------
// Introspection & query-by-name
// ---------------------------------------------------------------------------

n00b_option_t(n00b_dl_rel_id_t)
n00b_dl_find_relation(n00b_dl_engine_t *eng, n00b_string_t *name)
{
    size_t n = n00b_list_len(eng->relations);
    for (size_t i = 0; i < n; i++) {
        n00b_dl_relation_t *r = n00b_list_get(eng->relations, i);
        if (n00b_unicode_str_eq(r->name, name)) {
            return n00b_option_set(n00b_dl_rel_id_t, r->id);
        }
    }
    return n00b_option_none(n00b_dl_rel_id_t);
}

n00b_string_t *
n00b_dl_relation_name(n00b_dl_engine_t *eng, n00b_dl_rel_id_t id)
{
    if (id < 0 || (size_t)id >= n00b_list_len(eng->relations)) {
        return n00b_string_empty();
    }
    return n00b_list_get(eng->relations, id)->name;
}

n00b_option_t(int32_t)
n00b_dl_relation_arity(n00b_dl_engine_t *eng, n00b_dl_rel_id_t id)
{
    if (id < 0 || (size_t)id >= n00b_list_len(eng->relations)) {
        return n00b_option_none(int32_t);
    }
    return n00b_option_set(int32_t, n00b_list_get(eng->relations, id)->arity);
}

size_t
n00b_dl_count_by_name(n00b_dl_engine_t *eng, n00b_string_t *name)
{
    auto opt = n00b_dl_find_relation(eng, name);
    if (!n00b_option_is_set(opt)) return 0;
    return n00b_dl_relation_count(
        n00b_list_get(eng->relations, n00b_option_get(opt)));
}

int64_t
n00b_dl_iterations(n00b_dl_engine_t *eng)
{
    return eng->iterations;
}

int64_t
n00b_dl_total_facts(n00b_dl_engine_t *eng)
{
    return eng->facts_derived;
}

int32_t
n00b_dl_num_relations(n00b_dl_engine_t *eng)
{
    return (int32_t)n00b_list_len(eng->relations);
}

n00b_string_t *
n00b_dl_sym_to_str(n00b_dl_engine_t *eng, n00b_dl_sym_t sym)
{
    n00b_string_t *name = n00b_dl_intern_name(&eng->intern, sym);
    if (!name || name->u8_bytes == 0) {
        return r"?";
    }
    if (name->data[0] == '#') {
        return n00b_string_from_raw(name->data + 1,
                                    (int64_t)name->u8_bytes - 1);
    }
    return name;
}
