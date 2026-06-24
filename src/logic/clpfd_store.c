#include "logic/clpfd_store.h"
#include "n00b.h"
#include "core/alloc.h"
#include "text/strings/string_ops.h"

#include <errno.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------

typedef struct {
    int32_t *indices;
    int32_t  count;
    int32_t  cap;
} csp_index_list_t;

typedef struct {
    n00b_csp_var_id_t  var;
    n00b_csp_domain_t  old_domain;
} csp_trail_entry_t;

// Choice point: records both trail and constraint positions.
typedef struct {
    int32_t trail_mark;
    int32_t con_mark;
} csp_choice_point_t;

struct n00b_csp_store {
    // Variables
    n00b_csp_var_t *vars;
    int32_t         var_count;
    int32_t         var_cap;

    // Constraints
    n00b_csp_constraint_t *constraints;
    int32_t                con_count;
    int32_t                con_cap;

    // Watchlist: var_id -> list of constraint indices
    csp_index_list_t *watchlist;
    int32_t           watchlist_cap;

    // AC-3 propagation queue (circular buffer)
    int32_t *queue;
    int32_t  queue_head;
    int32_t  queue_tail;
    int32_t  queue_cap;
    bool    *in_queue;
    int32_t  in_queue_cap;

    // Trail for backtracking
    csp_trail_entry_t *trail;
    int32_t            trail_len;
    int32_t            trail_cap;

    // Choice point stack
    csp_choice_point_t *choice_points;
    int32_t             cp_count;
    int32_t             cp_cap;

    bool failed;
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void
watchlist_add(n00b_csp_store_t *s, n00b_csp_var_id_t var, int32_t con_idx)
{
    if (var < 0 || var >= s->watchlist_cap) {
        return;
    }

    csp_index_list_t *wl = &s->watchlist[var];

    if (wl->count >= wl->cap) {
        int32_t  new_cap     = wl->cap ? wl->cap * 2 : 4;
        int32_t *new_indices = n00b_alloc_array(int32_t, new_cap);
        if (wl->count > 0) {
            memcpy(new_indices, wl->indices, wl->count * sizeof(int32_t));
        }
        n00b_free(wl->indices);
        wl->indices = new_indices;
        wl->cap     = new_cap;
    }

    wl->indices[wl->count++] = con_idx;
}

// Remove all watchlist entries for constraint con_idx.
static void
watchlist_remove(n00b_csp_store_t *s, int32_t con_idx)
{
    n00b_csp_constraint_t *con = &s->constraints[con_idx];

    for (int32_t v = 0; v < con->var_count; v++) {
        n00b_csp_var_id_t var = con->vars[v];

        if (var < 0 || var >= s->watchlist_cap) {
            continue;
        }

        csp_index_list_t *wl = &s->watchlist[var];

        for (int32_t i = 0; i < wl->count; i++) {
            if (wl->indices[i] == con_idx) {
                wl->indices[i] = wl->indices[--wl->count];
                break;
            }
        }
    }
}

static void
ensure_watchlist(n00b_csp_store_t *s, int32_t var_count)
{
    if (var_count <= s->watchlist_cap) {
        return;
    }

    int32_t           old_cap = s->watchlist_cap;
    int32_t           new_cap = var_count;
    csp_index_list_t *new_wl  = n00b_alloc_array(csp_index_list_t, new_cap);
    if (old_cap > 0) {
        memcpy(new_wl, s->watchlist, old_cap * sizeof(csp_index_list_t));
    }
    n00b_free(s->watchlist);
    s->watchlist     = new_wl;
    s->watchlist_cap = new_cap;
    memset(&s->watchlist[old_cap], 0,
           (new_cap - old_cap) * sizeof(csp_index_list_t));
}

static void
enqueue_constraint(n00b_csp_store_t *s, int32_t con_idx)
{
    if (con_idx < 0 || con_idx >= s->in_queue_cap) {
        int32_t new_cap      = con_idx + 16;
        bool   *new_in_queue = n00b_alloc_array(bool, new_cap);
        if (s->in_queue_cap > 0) {
            memcpy(new_in_queue, s->in_queue, s->in_queue_cap * sizeof(bool));
        }
        n00b_free(s->in_queue);
        s->in_queue     = new_in_queue;
        s->in_queue_cap = new_cap;
    }

    if (s->in_queue[con_idx]) {
        return;
    }

    // Grow queue if needed.
    int32_t next_tail = (s->queue_tail + 1) % s->queue_cap;

    if (next_tail == s->queue_head) {
        int32_t  new_cap = s->queue_cap * 2;
        int32_t *new_q   = n00b_alloc_array(int32_t, new_cap);
        int32_t  count   = 0;
        int32_t  i       = s->queue_head;

        while (i != s->queue_tail) {
            new_q[count++] = s->queue[i];
            i              = (i + 1) % s->queue_cap;
        }

        n00b_free(s->queue);
        s->queue      = new_q;
        s->queue_head = 0;
        s->queue_tail = count;
        s->queue_cap  = new_cap;
    }

    s->queue[s->queue_tail] = con_idx;
    s->queue_tail           = (s->queue_tail + 1) % s->queue_cap;
    s->in_queue[con_idx]    = true;
}

static int32_t
dequeue_constraint(n00b_csp_store_t *s)
{
    if (s->queue_head == s->queue_tail) {
        return -1;
    }

    int32_t idx   = s->queue[s->queue_head];
    s->queue_head = (s->queue_head + 1) % s->queue_cap;
    s->in_queue[idx] = false;

    return idx;
}

static void
enqueue_watching(n00b_csp_store_t *s, n00b_csp_var_id_t var)
{
    if (var < 0 || var >= s->watchlist_cap) {
        return;
    }

    csp_index_list_t *wl = &s->watchlist[var];

    for (int32_t i = 0; i < wl->count; i++) {
        int32_t ci = wl->indices[i];

        if (!s->constraints[ci].entailed && !s->constraints[ci].failed) {
            enqueue_constraint(s, ci);
        }
    }
}

static void
trail_save(n00b_csp_store_t *s, n00b_csp_var_id_t var)
{
    if (s->trail_len >= s->trail_cap) {
        int32_t            new_cap   = s->trail_cap ? s->trail_cap * 2 : 64;
        csp_trail_entry_t *new_trail = n00b_alloc_array(csp_trail_entry_t,
                                                         new_cap);
        if (s->trail_len > 0) {
            memcpy(new_trail, s->trail,
                   s->trail_len * sizeof(csp_trail_entry_t));
        }
        n00b_free(s->trail);
        s->trail     = new_trail;
        s->trail_cap = new_cap;
    }

    s->trail[s->trail_len].var        = var;
    s->trail[s->trail_len].old_domain = n00b_csp_dom_clone(&s->vars[var].domain);
    s->trail_len++;
}

static void
update_ground(n00b_csp_store_t *s, n00b_csp_var_id_t var)
{
    n00b_csp_var_t *v = &s->vars[var];

    if (n00b_csp_dom_is_singleton(&v->domain)) {
        v->ground = true;
        v->value  = n00b_csp_dom_min(&v->domain);
    }
    else {
        v->ground = false;
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

n00b_csp_store_t *
n00b_csp_store_new(void)
{
    n00b_csp_store_t *s = n00b_alloc(n00b_csp_store_t);
    s->queue_cap        = 64;
    s->queue            = n00b_alloc_array(int32_t, s->queue_cap);

    return s;
}

void
n00b_csp_store_free(n00b_csp_store_t *s)
{
    if (!s) {
        return;
    }

    // Free variables (n00b_string_t name pointers are GC-managed).
    for (int32_t i = 0; i < s->var_count; i++) {
        n00b_csp_dom_free(&s->vars[i].domain);
    }

    n00b_free(s->vars);

    // Free constraints.
    for (int32_t i = 0; i < s->con_count; i++) {
        n00b_free(s->constraints[i].vars);
        n00b_free(s->constraints[i].coeffs);
        n00b_csp_dom_free(&s->constraints[i].in_domain);
    }

    n00b_free(s->constraints);

    // Free watchlists.
    for (int32_t i = 0; i < s->watchlist_cap; i++) {
        n00b_free(s->watchlist[i].indices);
    }

    n00b_free(s->watchlist);

    // Free queue.
    n00b_free(s->queue);
    n00b_free(s->in_queue);

    // Free trail.
    for (int32_t i = 0; i < s->trail_len; i++) {
        n00b_csp_dom_free(&s->trail[i].old_domain);
    }

    n00b_free(s->trail);
    n00b_free(s->choice_points);
    n00b_free(s);
}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

n00b_csp_var_id_t
n00b_csp_new_var(n00b_csp_store_t *s, n00b_string_t *name, n00b_csp_domain_t dom)
{
    if (s->var_count >= s->var_cap) {
        int32_t         new_cap  = s->var_cap ? s->var_cap * 2 : 16;
        n00b_csp_var_t *new_vars = n00b_alloc_array(n00b_csp_var_t, new_cap);
        if (s->var_count > 0) {
            memcpy(new_vars, s->vars, s->var_count * sizeof(n00b_csp_var_t));
        }
        n00b_free(s->vars);
        s->vars    = new_vars;
        s->var_cap = new_cap;
    }

    n00b_csp_var_id_t id = s->var_count;
    n00b_csp_var_t   *v  = &s->vars[s->var_count++];
    v->id                = id;
    v->name              = name;
    v->domain            = dom;
    v->ground            = false;
    v->value             = 0;

    update_ground(s, id);
    ensure_watchlist(s, s->var_count);

    return id;
}

n00b_option_t(n00b_csp_var_id_t)
n00b_csp_find_var(n00b_csp_store_t *s, n00b_string_t *name)
{
    for (int32_t i = 0; i < s->var_count; i++) {
        if (n00b_unicode_str_eq(s->vars[i].name, name)) {
            return n00b_option_set(n00b_csp_var_id_t, i);
        }
    }

    return n00b_option_none(n00b_csp_var_id_t);
}

n00b_result_t(const n00b_csp_domain_t *)
n00b_csp_var_domain(n00b_csp_store_t *s, n00b_csp_var_id_t v)
{
    if (v < 0 || v >= s->var_count) {
        return n00b_result_err(const n00b_csp_domain_t *, EINVAL);
    }

    return n00b_result_ok(const n00b_csp_domain_t *, &s->vars[v].domain);
}

n00b_result_t(bool)
n00b_csp_var_is_ground(n00b_csp_store_t *s, n00b_csp_var_id_t v)
{
    if (v < 0 || v >= s->var_count) {
        return n00b_result_err(bool, EINVAL);
    }

    return n00b_result_ok(bool, s->vars[v].ground);
}

n00b_result_t(int64_t)
n00b_csp_var_value(n00b_csp_store_t *s, n00b_csp_var_id_t v)
{
    if (v < 0 || v >= s->var_count) {
        return n00b_result_err(int64_t, EINVAL);
    }

    return n00b_result_ok(int64_t, s->vars[v].value);
}

// ---------------------------------------------------------------------------
// Variable queries
// ---------------------------------------------------------------------------

int32_t
n00b_csp_var_count(const n00b_csp_store_t *s)
{
    return s->var_count;
}

int32_t
n00b_csp_dom_iterate(n00b_csp_store_t *s, n00b_csp_var_id_t v,
                      n00b_csp_dom_iter_cb cb, void *ctx)
{
    if (v < 0 || v >= s->var_count) {
        return -1;
    }

    const n00b_csp_domain_t *d = &s->vars[v].domain;
    int32_t count = 0;

    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        for (int64_t val = iv.lo; val <= iv.hi; val++) {
            count++;
            if (!cb(val, ctx)) {
                return count;
            }
        }
        break;
    }
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs = n00b_variant_get(*d, n00b_csp_dom_bitset_t);
        for (uint64_t bits = bs.bits; bits;) {
            int     bit = __builtin_ctzll(bits);
            int64_t val = bs.base + bit;
            count++;
            if (!cb(val, ctx)) {
                return count;
            }
            bits &= bits - 1;
        }
        break;
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        for (int32_t i = 0; i < sp.count; i++) {
            count++;
            if (!cb(sp.values[i], ctx)) {
                return count;
            }
        }
        break;
    }
    default: // empty
        break;
    }

    return count;
}

// ---------------------------------------------------------------------------
// Constraint posting
// ---------------------------------------------------------------------------

static int32_t
add_constraint(n00b_csp_store_t *s, n00b_csp_constraint_t con)
{
    if (s->con_count >= s->con_cap) {
        int32_t                new_cap  = s->con_cap ? s->con_cap * 2 : 16;
        n00b_csp_constraint_t *new_cons = n00b_alloc_array(n00b_csp_constraint_t,
                                                            new_cap);
        if (s->con_count > 0) {
            memcpy(new_cons, s->constraints,
                   s->con_count * sizeof(n00b_csp_constraint_t));
        }
        n00b_free(s->constraints);
        s->constraints = new_cons;
        s->con_cap     = new_cap;
    }

    int32_t idx                    = s->con_count;
    s->constraints[s->con_count++] = con;

    // Add to watchlists.
    for (int32_t i = 0; i < con.var_count; i++) {
        watchlist_add(s, con.vars[i], idx);
    }

    // Enqueue for initial propagation.
    enqueue_constraint(s, idx);

    return idx;
}

bool
n00b_csp_post_eq(n00b_csp_store_t *s, n00b_csp_var_id_t x,
                  n00b_csp_var_id_t y)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_EQ;
    con.var_count = 2;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, 2);
    con.vars[0]   = x;
    con.vars[1]   = y;

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_eq_const(n00b_csp_store_t *s, n00b_csp_var_id_t x, int64_t c)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_EQ_CONST;
    con.var_count = 1;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, 1);
    con.vars[0]   = x;
    con.constant  = c;

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_ne(n00b_csp_store_t *s, n00b_csp_var_id_t x,
                  n00b_csp_var_id_t y)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_NE;
    con.var_count = 2;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, 2);
    con.vars[0]   = x;
    con.vars[1]   = y;

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_lt(n00b_csp_store_t *s, n00b_csp_var_id_t x,
                  n00b_csp_var_id_t y)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_LT;
    con.var_count = 2;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, 2);
    con.vars[0]   = x;
    con.vars[1]   = y;

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_le(n00b_csp_store_t *s, n00b_csp_var_id_t x,
                  n00b_csp_var_id_t y)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_LE;
    con.var_count = 2;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, 2);
    con.vars[0]   = x;
    con.vars[1]   = y;

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_in(n00b_csp_store_t *s, n00b_csp_var_id_t x,
                  n00b_csp_domain_t dom)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_IN;
    con.var_count = 1;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, 1);
    con.vars[0]   = x;
    con.in_domain = dom; // Takes ownership.

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_linear(n00b_csp_store_t *s, const n00b_csp_var_id_t *vars,
                      const int64_t *coeffs, int32_t n, int64_t rhs)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_LINEAR;
    con.var_count = n;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, n);
    con.coeffs    = n00b_alloc_array(int64_t, n);
    memcpy(con.vars, vars, n * sizeof(n00b_csp_var_id_t));
    memcpy(con.coeffs, coeffs, n * sizeof(int64_t));
    con.constant = rhs;

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

bool
n00b_csp_post_alldiff(n00b_csp_store_t *s, const n00b_csp_var_id_t *vars,
                       int32_t n)
{
    n00b_csp_constraint_t con = {};
    con.kind      = N00B_CSP_CON_ALLDIFF;
    con.var_count = n;
    con.vars      = n00b_alloc_array(n00b_csp_var_id_t, n);
    memcpy(con.vars, vars, n * sizeof(n00b_csp_var_id_t));

    add_constraint(s, con);

    return n00b_csp_propagate(s);
}

// ---------------------------------------------------------------------------
// Backtracking
// ---------------------------------------------------------------------------

void
n00b_csp_push_state(n00b_csp_store_t *s)
{
    if (s->cp_count >= s->cp_cap) {
        int32_t             new_cap = s->cp_cap ? s->cp_cap * 2 : 16;
        csp_choice_point_t *new_cps = n00b_alloc_array(csp_choice_point_t,
                                                        new_cap);
        if (s->cp_count > 0) {
            memcpy(new_cps, s->choice_points,
                   s->cp_count * sizeof(csp_choice_point_t));
        }
        n00b_free(s->choice_points);
        s->choice_points = new_cps;
        s->cp_cap        = new_cap;
    }

    s->choice_points[s->cp_count].trail_mark = s->trail_len;
    s->choice_points[s->cp_count].con_mark   = s->con_count;
    s->cp_count++;
}

void
n00b_csp_pop_state(n00b_csp_store_t *s)
{
    if (s->cp_count == 0) {
        return;
    }

    csp_choice_point_t cp = s->choice_points[--s->cp_count];

    // Undo trail entries in reverse order.
    for (int32_t i = s->trail_len - 1; i >= cp.trail_mark; i--) {
        n00b_csp_var_id_t var = s->trail[i].var;
        n00b_csp_dom_free(&s->vars[var].domain);
        s->vars[var].domain = s->trail[i].old_domain;
        // Don't free trail entry's domain — it was moved into the variable.
        update_ground(s, var);
    }

    s->trail_len = cp.trail_mark;

    // Remove constraints added since the choice point.
    for (int32_t i = s->con_count - 1; i >= cp.con_mark; i--) {
        watchlist_remove(s, i);
        n00b_free(s->constraints[i].vars);
        n00b_free(s->constraints[i].coeffs);
        n00b_csp_dom_free(&s->constraints[i].in_domain);
    }

    s->con_count = cp.con_mark;
    s->failed    = false;

    // Clear the propagation queue.
    s->queue_head = 0;
    s->queue_tail = 0;

    if (s->in_queue) {
        memset(s->in_queue, 0, s->in_queue_cap * sizeof(bool));
    }

    // Reset entailment and failed flags for all surviving constraints.
    for (int32_t i = 0; i < s->con_count; i++) {
        s->constraints[i].entailed = false;
        s->constraints[i].failed   = false;
    }
}

// ---------------------------------------------------------------------------
// Propagation
// ---------------------------------------------------------------------------

static bool
propagate_eq(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    n00b_csp_var_id_t x = con->vars[0];
    n00b_csp_var_id_t y = con->vars[1];

    // Intersect X with Y's domain.
    n00b_csp_domain_t y_clone = n00b_csp_dom_clone(&s->vars[y].domain);
    trail_save(s, x);

    if (n00b_csp_dom_intersect(&s->vars[x].domain, &y_clone)) {
        update_ground(s, x);
        enqueue_watching(s, x);
    }

    n00b_csp_dom_free(&y_clone);

    // Intersect Y with X's domain.
    n00b_csp_domain_t x_clone = n00b_csp_dom_clone(&s->vars[x].domain);
    trail_save(s, y);

    if (n00b_csp_dom_intersect(&s->vars[y].domain, &x_clone)) {
        update_ground(s, y);
        enqueue_watching(s, y);
    }

    n00b_csp_dom_free(&x_clone);

    if (n00b_csp_dom_is_empty(&s->vars[x].domain)
        || n00b_csp_dom_is_empty(&s->vars[y].domain)) {
        con->failed = true;
        s->failed   = true;
        return false;
    }

    // Check entailment: both ground and equal.
    if (s->vars[x].ground && s->vars[y].ground
        && s->vars[x].value == s->vars[y].value) {
        con->entailed = true;
    }

    return true;
}

static bool
propagate_eq_const(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    n00b_csp_var_id_t x = con->vars[0];
    int64_t           c = con->constant;

    if (!n00b_csp_dom_contains(&s->vars[x].domain, c)) {
        con->failed = true;
        s->failed   = true;
        return false;
    }

    if (s->vars[x].ground && s->vars[x].value == c) {
        con->entailed = true;
        return true;
    }

    trail_save(s, x);
    n00b_csp_domain_t singleton = n00b_csp_dom_singleton(c);
    n00b_csp_dom_intersect(&s->vars[x].domain, &singleton);
    update_ground(s, x);
    enqueue_watching(s, x);

    return true;
}

static bool
propagate_ne(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    n00b_csp_var_id_t x = con->vars[0];
    n00b_csp_var_id_t y = con->vars[1];

    // If X is ground, remove X's value from Y.
    if (s->vars[x].ground) {
        if (n00b_csp_dom_contains(&s->vars[y].domain, s->vars[x].value)) {
            trail_save(s, y);
            n00b_csp_dom_remove_value(&s->vars[y].domain, s->vars[x].value);
            update_ground(s, y);
            enqueue_watching(s, y);

            if (n00b_csp_dom_is_empty(&s->vars[y].domain)) {
                con->failed = true;
                s->failed   = true;
                return false;
            }
        }
    }

    // If Y is ground, remove Y's value from X.
    if (s->vars[y].ground) {
        if (n00b_csp_dom_contains(&s->vars[x].domain, s->vars[y].value)) {
            trail_save(s, x);
            n00b_csp_dom_remove_value(&s->vars[x].domain, s->vars[y].value);
            update_ground(s, x);
            enqueue_watching(s, x);

            if (n00b_csp_dom_is_empty(&s->vars[x].domain)) {
                con->failed = true;
                s->failed   = true;
                return false;
            }
        }
    }

    // Entailed if both ground and not equal.
    if (s->vars[x].ground && s->vars[y].ground
        && s->vars[x].value != s->vars[y].value) {
        con->entailed = true;
    }

    return true;
}

static bool
propagate_lt(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    n00b_csp_var_id_t x = con->vars[0];
    n00b_csp_var_id_t y = con->vars[1];

    // X.max < Y.max (so X.max <= Y.max - 1)
    int64_t y_max = n00b_csp_dom_max(&s->vars[y].domain);
    trail_save(s, x);

    if (n00b_csp_dom_restrict_max(&s->vars[x].domain, y_max - 1)) {
        update_ground(s, x);
        enqueue_watching(s, x);
    }

    // Y.min > X.min (so Y.min >= X.min + 1)
    int64_t x_min = n00b_csp_dom_min(&s->vars[x].domain);
    trail_save(s, y);

    if (n00b_csp_dom_restrict_min(&s->vars[y].domain, x_min + 1)) {
        update_ground(s, y);
        enqueue_watching(s, y);
    }

    if (n00b_csp_dom_is_empty(&s->vars[x].domain)
        || n00b_csp_dom_is_empty(&s->vars[y].domain)) {
        con->failed = true;
        s->failed   = true;
        return false;
    }

    // Entailed if X.max < Y.min.
    if (n00b_csp_dom_max(&s->vars[x].domain)
        < n00b_csp_dom_min(&s->vars[y].domain)) {
        con->entailed = true;
    }

    return true;
}

static bool
propagate_le(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    n00b_csp_var_id_t x = con->vars[0];
    n00b_csp_var_id_t y = con->vars[1];

    // X.max <= Y.max
    int64_t y_max = n00b_csp_dom_max(&s->vars[y].domain);
    trail_save(s, x);

    if (n00b_csp_dom_restrict_max(&s->vars[x].domain, y_max)) {
        update_ground(s, x);
        enqueue_watching(s, x);
    }

    // Y.min >= X.min
    int64_t x_min = n00b_csp_dom_min(&s->vars[x].domain);
    trail_save(s, y);

    if (n00b_csp_dom_restrict_min(&s->vars[y].domain, x_min)) {
        update_ground(s, y);
        enqueue_watching(s, y);
    }

    if (n00b_csp_dom_is_empty(&s->vars[x].domain)
        || n00b_csp_dom_is_empty(&s->vars[y].domain)) {
        con->failed = true;
        s->failed   = true;
        return false;
    }

    if (n00b_csp_dom_max(&s->vars[x].domain)
        <= n00b_csp_dom_min(&s->vars[y].domain)) {
        con->entailed = true;
    }

    return true;
}

static bool
propagate_in(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    n00b_csp_var_id_t x = con->vars[0];

    trail_save(s, x);

    if (n00b_csp_dom_intersect(&s->vars[x].domain, &con->in_domain)) {
        update_ground(s, x);
        enqueue_watching(s, x);
    }

    if (n00b_csp_dom_is_empty(&s->vars[x].domain)) {
        con->failed = true;
        s->failed   = true;
        return false;
    }

    con->entailed = true; // IN constraint only needs to fire once.

    return true;
}

// ---------------------------------------------------------------------------
// LINEAR propagator: a1*X1 + a2*X2 + ... = c
//
// Bounds propagation: for each Xi, compute the feasible range of Xi
// from the bounds of all other variables, then narrow Xi's domain.
// ---------------------------------------------------------------------------

static bool
propagate_linear(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    int32_t  n      = con->var_count;
    int64_t *coeffs = con->coeffs;
    int64_t  rhs    = con->constant;

    // Compute the sum range for the entire LHS: [sum_lo, sum_hi].
    // For each term aᵢ*Xᵢ, the contribution range depends on sign of aᵢ.
    int64_t sum_lo = 0;
    int64_t sum_hi = 0;

    for (int32_t i = 0; i < n; i++) {
        int64_t lo = n00b_csp_dom_min(&s->vars[con->vars[i]].domain);
        int64_t hi = n00b_csp_dom_max(&s->vars[con->vars[i]].domain);

        if (coeffs[i] > 0) {
            sum_lo += coeffs[i] * lo;
            sum_hi += coeffs[i] * hi;
        }
        else {
            sum_lo += coeffs[i] * hi;
            sum_hi += coeffs[i] * lo;
        }
    }

    // If rhs is outside [sum_lo, sum_hi], no solution.
    if (rhs < sum_lo || rhs > sum_hi) {
        con->failed = true;
        s->failed   = true;
        return false;
    }

    // For each variable Xi, narrow its domain.
    // aᵢ*Xᵢ = rhs - (sum of other terms)
    // Let rest_lo, rest_hi = bounds of sum excluding term i.
    bool all_ground = true;

    for (int32_t i = 0; i < n; i++) {
        n00b_csp_var_id_t vi = con->vars[i];
        int64_t           ai = coeffs[i];

        if (ai == 0) {
            if (!s->vars[vi].ground) {
                all_ground = false;
            }
            continue;
        }

        int64_t vi_lo = n00b_csp_dom_min(&s->vars[vi].domain);
        int64_t vi_hi = n00b_csp_dom_max(&s->vars[vi].domain);

        // rest = sum - ai*Xi
        // rest_lo = sum_lo - contribution_hi_of_i
        // rest_hi = sum_hi - contribution_lo_of_i
        int64_t rest_lo, rest_hi;

        if (ai > 0) {
            rest_lo = sum_lo - ai * vi_lo;
            rest_hi = sum_hi - ai * vi_hi;
        }
        else {
            rest_lo = sum_lo - ai * vi_hi;
            rest_hi = sum_hi - ai * vi_lo;
        }

        // We need: ai*Xi = rhs - rest
        // So ai*Xi ∈ [rhs - rest_hi, rhs - rest_lo]
        int64_t prod_lo = rhs - rest_hi;
        int64_t prod_hi = rhs - rest_lo;

        // Xi ∈ [prod_lo/ai, prod_hi/ai], adjusting for integer division.
        //
        // We need:  Xi >= ceil(prod_lo / ai)   (lower bound)
        //           Xi <= floor(prod_hi / ai)  (upper bound)
        //
        // C integer division truncates toward zero, so:
        //   ceil(a/b)  for b>0: a>=0 → (a + b - 1) / b,  a<0 → a / b
        //   floor(a/b) for b>0: a>=0 → a / b,             a<0 → (a - b + 1) / b
        //
        // When ai<0, dividing flips the inequality: divide by |ai| and negate.

        int64_t new_lo, new_hi;

        if (ai > 0) {
            // ceil(prod_lo / ai)
            if (prod_lo >= 0) {
                new_lo = (prod_lo + ai - 1) / ai;
            }
            else {
                new_lo = prod_lo / ai;
            }
            // floor(prod_hi / ai)
            if (prod_hi >= 0) {
                new_hi = prod_hi / ai;
            }
            else {
                new_hi = (prod_hi - ai + 1) / ai;
            }
        }
        else {
            // ai < 0: Xi >= ceil(prod_hi / ai), Xi <= floor(prod_lo / ai)
            // Equivalent to dividing by |ai| and negating, which flips bounds.
            int64_t neg_ai = -ai;

            // new_lo = ceil(prod_hi / ai) = -floor(prod_hi / neg_ai)
            if (prod_hi >= 0) {
                new_lo = -(prod_hi / neg_ai);
            }
            else {
                new_lo = -((prod_hi - neg_ai + 1) / neg_ai);
            }

            // new_hi = floor(prod_lo / ai) = -ceil(prod_lo / neg_ai)
            if (prod_lo >= 0) {
                new_hi = -((prod_lo + neg_ai - 1) / neg_ai);
            }
            else {
                new_hi = -(prod_lo / neg_ai);
            }
        }

        // Narrow Xi's domain
        trail_save(s, vi);
        bool changed = false;

        if (n00b_csp_dom_restrict_min(&s->vars[vi].domain, new_lo)) {
            changed = true;
        }
        if (n00b_csp_dom_restrict_max(&s->vars[vi].domain, new_hi)) {
            changed = true;
        }

        if (n00b_csp_dom_is_empty(&s->vars[vi].domain)) {
            con->failed = true;
            s->failed   = true;
            return false;
        }

        if (changed) {
            update_ground(s, vi);
            enqueue_watching(s, vi);

            // Recompute contribution of this var for future iterations.
            int64_t new_vi_lo = n00b_csp_dom_min(&s->vars[vi].domain);
            int64_t new_vi_hi = n00b_csp_dom_max(&s->vars[vi].domain);

            if (ai > 0) {
                sum_lo = sum_lo - ai * vi_lo + ai * new_vi_lo;
                sum_hi = sum_hi - ai * vi_hi + ai * new_vi_hi;
            }
            else {
                sum_lo = sum_lo - ai * vi_hi + ai * new_vi_hi;
                sum_hi = sum_hi - ai * vi_lo + ai * new_vi_lo;
            }
        }

        if (!s->vars[vi].ground) {
            all_ground = false;
        }
    }

    if (all_ground) {
        // Verify the constraint holds.
        int64_t total = 0;
        for (int32_t i = 0; i < n; i++) {
            total += coeffs[i] * s->vars[con->vars[i]].value;
        }
        if (total == rhs) {
            con->entailed = true;
        }
        else {
            con->failed = true;
            s->failed   = true;
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// ALLDIFF propagator: Régin's algorithm
//
// Uses maximum bipartite matching to achieve domain consistency.
// 1. Build bipartite graph: variables ↔ values
// 2. Find maximum matching via augmenting paths
// 3. Identify edges that cannot participate in any maximum matching
// 4. Remove those values from domains
// ---------------------------------------------------------------------------

// Value node indexing: values in the union of all domains are mapped
// to indices 0..num_values-1 via a sorted unique array.

typedef struct {
    // Value mapping
    int64_t *vals;       // Sorted unique values from all domains
    int32_t  num_vals;

    // Matching: match_var[i] = value index matched to var i, or -1
    //           match_val[j] = var index matched to value j, or -1
    int32_t *match_var;
    int32_t *match_val;

    // Adjacency: for each variable, which value indices are in its domain
    int32_t **adj;       // adj[i] = array of value indices
    int32_t  *adj_count;

    int32_t num_vars;
} alldiff_graph_t;

static int
cmp_int64(const void *a, const void *b)
{
    int64_t va = *(const int64_t *)a;
    int64_t vb = *(const int64_t *)b;
    return (va > vb) - (va < vb);
}

static int32_t
val_index(const int64_t *vals, int32_t num_vals, int64_t v)
{
    // Binary search in sorted vals array.
    int32_t lo = 0, hi = num_vals - 1;

    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        if (vals[mid] == v) {
            return mid;
        }
        if (vals[mid] < v) {
            lo = mid + 1;
        }
        else {
            hi = mid - 1;
        }
    }

    return -1;
}

// Augmenting path search from an unmatched variable.
// Returns true if an augmenting path was found (and matching updated).
static bool
augment(alldiff_graph_t *g, int32_t var, bool *visited)
{
    for (int32_t k = 0; k < g->adj_count[var]; k++) {
        int32_t val_idx = g->adj[var][k];

        if (visited[val_idx]) {
            continue;
        }
        visited[val_idx] = true;

        // If this value is unmatched, or its current match can be rerouted
        if (g->match_val[val_idx] < 0
            || augment(g, g->match_val[val_idx], visited)) {
            g->match_var[var]     = val_idx;
            g->match_val[val_idx] = var;
            return true;
        }
    }

    return false;
}

// Find maximum matching via Kuhn's algorithm (augmenting paths).
static int32_t
max_matching(alldiff_graph_t *g)
{
    int32_t matched = 0;

    for (int32_t i = 0; i < g->num_vars; i++) {
        g->match_var[i] = -1;
    }
    for (int32_t j = 0; j < g->num_vals; j++) {
        g->match_val[j] = -1;
    }

    for (int32_t i = 0; i < g->num_vars; i++) {
        bool *visited = n00b_alloc_array(bool, g->num_vals);
        if (augment(g, i, visited)) {
            matched++;
        }
        n00b_free(visited);
    }

    return matched;
}

// Tarjan's SCC on the residual graph to find prunable edges.
// In the residual graph:
//   - Matched edges go from value → variable
//   - Unmatched edges go from variable → value
//   - Free (unmatched) values are roots for DFS
// An edge (var, val) can be pruned if it's not in the matching AND
// var and val are in different SCCs of the residual graph.

typedef struct {
    int32_t *stack;
    bool    *on_stack;
    int32_t *index;
    int32_t *lowlink;
    int32_t *scc_id;
    int32_t  stack_top;
    int32_t  next_index;
    int32_t  next_scc;
    int32_t  total_nodes; // num_vars + num_vals
} scc_state_t;

// Node numbering: variables are 0..num_vars-1, values are num_vars..num_vars+num_vals-1
#define VAR_NODE(i) (i)
#define VAL_NODE(j, nv) ((nv) + (j))

static void
scc_strongconnect(alldiff_graph_t *g, scc_state_t *st, int32_t node)
{
    st->index[node]   = st->next_index;
    st->lowlink[node] = st->next_index;
    st->next_index++;
    st->stack[st->stack_top++] = node;
    st->on_stack[node]         = true;

    int32_t nv = g->num_vars;

    if (node < nv) {
        // Variable node: edges to unmatched values
        int32_t var = node;
        for (int32_t k = 0; k < g->adj_count[var]; k++) {
            int32_t val_idx = g->adj[var][k];
            if (val_idx == g->match_var[var]) {
                continue; // Skip matched edge (goes other direction)
            }
            int32_t target = VAL_NODE(val_idx, nv);
            if (st->index[target] < 0) {
                scc_strongconnect(g, st, target);
                if (st->lowlink[target] < st->lowlink[node]) {
                    st->lowlink[node] = st->lowlink[target];
                }
            }
            else if (st->on_stack[target]) {
                if (st->index[target] < st->lowlink[node]) {
                    st->lowlink[node] = st->index[target];
                }
            }
        }
    }
    else {
        // Value node: edge to matched variable (if any)
        int32_t val_idx = node - nv;
        int32_t matched_var = g->match_val[val_idx];
        if (matched_var >= 0) {
            int32_t target = VAR_NODE(matched_var);
            if (st->index[target] < 0) {
                scc_strongconnect(g, st, target);
                if (st->lowlink[target] < st->lowlink[node]) {
                    st->lowlink[node] = st->lowlink[target];
                }
            }
            else if (st->on_stack[target]) {
                if (st->index[target] < st->lowlink[node]) {
                    st->lowlink[node] = st->index[target];
                }
            }
        }
    }

    // Root of SCC?
    if (st->lowlink[node] == st->index[node]) {
        int32_t scc = st->next_scc++;
        int32_t w;
        do {
            w                  = st->stack[--st->stack_top];
            st->on_stack[w]    = false;
            st->scc_id[w]      = scc;
        } while (w != node);
    }
}

static bool
propagate_alldiff(n00b_csp_store_t *s, n00b_csp_constraint_t *con)
{
    int32_t n = con->var_count;

    if (n <= 1) {
        con->entailed = true;
        return true;
    }

    // Collect all values from all variable domains.
    int32_t  total_vals_cap = 0;

    for (int32_t i = 0; i < n; i++) {
        total_vals_cap += (int32_t)n00b_csp_dom_size(
            &s->vars[con->vars[i]].domain);
    }

    int64_t *all_vals = n00b_alloc_array(int64_t, total_vals_cap + 1);
    int32_t  all_count = 0;

    // Collect callback
    for (int32_t i = 0; i < n; i++) {
        n00b_csp_domain_t *dom = &s->vars[con->vars[i]].domain;

        switch (dom->selector) {
        case typehash(n00b_csp_dom_interval_t): {
            n00b_csp_dom_interval_t iv =
                n00b_variant_get(*dom, n00b_csp_dom_interval_t);
            for (int64_t v = iv.lo; v <= iv.hi; v++) {
                all_vals[all_count++] = v;
            }
            break;
        }
        case typehash(n00b_csp_dom_bitset_t): {
            n00b_csp_dom_bitset_t bs =
                n00b_variant_get(*dom, n00b_csp_dom_bitset_t);
            for (uint64_t bits = bs.bits; bits;) {
                int bit = __builtin_ctzll(bits);
                all_vals[all_count++] = bs.base + bit;
                bits &= bits - 1;
            }
            break;
        }
        case typehash(n00b_csp_dom_sparse_t): {
            n00b_csp_dom_sparse_t sp =
                n00b_variant_get(*dom, n00b_csp_dom_sparse_t);
            for (int32_t j = 0; j < sp.count; j++) {
                all_vals[all_count++] = sp.values[j];
            }
            break;
        }
        default: // empty
            con->failed = true;
            s->failed   = true;
            n00b_free(all_vals);
            return false;
        }
    }

    // Sort and deduplicate
    qsort(all_vals, all_count, sizeof(int64_t), cmp_int64);
    int32_t unique_count = 0;
    for (int32_t i = 0; i < all_count; i++) {
        if (i == 0 || all_vals[i] != all_vals[i - 1]) {
            all_vals[unique_count++] = all_vals[i];
        }
    }

    // Build graph
    alldiff_graph_t g;
    g.num_vars  = n;
    g.num_vals  = unique_count;
    g.vals      = all_vals;
    g.match_var = n00b_alloc_array(int32_t, n);
    g.match_val = n00b_alloc_array(int32_t, unique_count);
    g.adj       = n00b_alloc_array(int32_t *, n);
    g.adj_count = n00b_alloc_array(int32_t, n);

    for (int32_t i = 0; i < n; i++) {
        n00b_csp_domain_t *dom = &s->vars[con->vars[i]].domain;
        int64_t sz = n00b_csp_dom_size(dom);
        g.adj[i]       = n00b_alloc_array(int32_t, sz);
        g.adj_count[i] = 0;

        switch (dom->selector) {
        case typehash(n00b_csp_dom_interval_t): {
            n00b_csp_dom_interval_t iv =
                n00b_variant_get(*dom, n00b_csp_dom_interval_t);
            for (int64_t v = iv.lo; v <= iv.hi; v++) {
                g.adj[i][g.adj_count[i]++] =
                    val_index(all_vals, unique_count, v);
            }
            break;
        }
        case typehash(n00b_csp_dom_bitset_t): {
            n00b_csp_dom_bitset_t bs =
                n00b_variant_get(*dom, n00b_csp_dom_bitset_t);
            for (uint64_t bits = bs.bits; bits;) {
                int bit = __builtin_ctzll(bits);
                g.adj[i][g.adj_count[i]++] =
                    val_index(all_vals, unique_count,
                              bs.base + bit);
                bits &= bits - 1;
            }
            break;
        }
        case typehash(n00b_csp_dom_sparse_t): {
            n00b_csp_dom_sparse_t sp =
                n00b_variant_get(*dom, n00b_csp_dom_sparse_t);
            for (int32_t j = 0; j < sp.count; j++) {
                g.adj[i][g.adj_count[i]++] =
                    val_index(all_vals, unique_count,
                              sp.values[j]);
            }
            break;
        }
        default:
            break;
        }
    }

    // Find maximum matching
    int32_t matched = max_matching(&g);

    if (matched < n) {
        // Not enough values to satisfy alldiff → fail
        con->failed = true;
        s->failed   = true;
        goto cleanup;
    }

    // Run Tarjan's SCC on residual graph to find prunable edges.
    int32_t total_nodes = n + unique_count;

    scc_state_t st;
    st.stack      = n00b_alloc_array(int32_t, total_nodes);
    st.on_stack   = n00b_alloc_array(bool, total_nodes);
    st.index      = n00b_alloc_array(int32_t, total_nodes);
    st.lowlink    = n00b_alloc_array(int32_t, total_nodes);
    st.scc_id     = n00b_alloc_array(int32_t, total_nodes);
    st.stack_top  = 0;
    st.next_index = 0;
    st.next_scc   = 0;

    for (int32_t i = 0; i < total_nodes; i++) {
        st.index[i] = -1;
    }

    // Start DFS from free (unmatched) value nodes, then remaining.
    for (int32_t j = 0; j < unique_count; j++) {
        if (g.match_val[j] < 0 && st.index[VAL_NODE(j, n)] < 0) {
            scc_strongconnect(&g, &st, VAL_NODE(j, n));
        }
    }
    for (int32_t i = 0; i < total_nodes; i++) {
        if (st.index[i] < 0) {
            scc_strongconnect(&g, &st, i);
        }
    }

    // Prune: remove (var, val) edges where:
    //   - The edge is NOT in the matching, AND
    //   - var and val are in different SCCs
    for (int32_t i = 0; i < n; i++) {
        n00b_csp_var_id_t vi = con->vars[i];
        int32_t var_scc = st.scc_id[VAR_NODE(i)];

        for (int32_t k = 0; k < g.adj_count[i]; k++) {
            int32_t val_idx = g.adj[i][k];

            // Skip matched edge
            if (g.match_var[i] == val_idx) {
                continue;
            }

            int32_t val_scc = st.scc_id[VAL_NODE(val_idx, n)];

            if (var_scc != val_scc) {
                // This value can be pruned from this variable's domain.
                trail_save(s, vi);
                n00b_csp_dom_remove_value(&s->vars[vi].domain,
                                           all_vals[val_idx]);

                if (n00b_csp_dom_is_empty(&s->vars[vi].domain)) {
                    con->failed = true;
                    s->failed   = true;
                    // Free SCC state
                    n00b_free(st.stack);
                    n00b_free(st.on_stack);
                    n00b_free(st.index);
                    n00b_free(st.lowlink);
                    n00b_free(st.scc_id);
                    goto cleanup;
                }

                update_ground(s, vi);
                enqueue_watching(s, vi);
            }
        }
    }

    // Check entailment: all vars ground with distinct values
    bool all_ground = true;
    for (int32_t i = 0; i < n; i++) {
        if (!s->vars[con->vars[i]].ground) {
            all_ground = false;
            break;
        }
    }
    if (all_ground) {
        con->entailed = true;
    }

    n00b_free(st.stack);
    n00b_free(st.on_stack);
    n00b_free(st.index);
    n00b_free(st.lowlink);
    n00b_free(st.scc_id);

cleanup:
    for (int32_t i = 0; i < n; i++) {
        n00b_free(g.adj[i]);
    }
    n00b_free(g.adj);
    n00b_free(g.adj_count);
    n00b_free(g.match_var);
    n00b_free(g.match_val);
    n00b_free(all_vals);

    return !s->failed;
}

bool
n00b_csp_propagate(n00b_csp_store_t *s)
{
    if (s->failed) {
        return false;
    }

    int32_t con_idx;

    while ((con_idx = dequeue_constraint(s)) >= 0) {
        n00b_csp_constraint_t *con = &s->constraints[con_idx];

        if (con->entailed || con->failed) {
            continue;
        }

        bool ok;

        switch (con->kind) {
        case N00B_CSP_CON_EQ:
            ok = propagate_eq(s, con);
            break;
        case N00B_CSP_CON_EQ_CONST:
            ok = propagate_eq_const(s, con);
            break;
        case N00B_CSP_CON_NE:
            ok = propagate_ne(s, con);
            break;
        case N00B_CSP_CON_LT:
            ok = propagate_lt(s, con);
            break;
        case N00B_CSP_CON_LE:
            ok = propagate_le(s, con);
            break;
        case N00B_CSP_CON_IN:
            ok = propagate_in(s, con);
            break;
        case N00B_CSP_CON_LINEAR:
            ok = propagate_linear(s, con);
            break;
        case N00B_CSP_CON_ALLDIFF:
            ok = propagate_alldiff(s, con);
            break;
        default:
            ok = true;
            break;
        }

        if (!ok) {
            return false;
        }
    }

    return true;
}
