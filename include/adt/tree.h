/**
 * @file tree.h
 * @brief Type-safe n-ary tree — pure macros.
 *
 * @c n00b_tree_t(N, L) represents an n-ary tree where internal nodes have
 * type @p N and leaves have type @p L. Children are stored in a dynamic array.
 *
 * Usage:
 * @code
 *     n00b_tree_t(int, char *) *root = n00b_tree_node(int, char *, 42);
 *     n00b_tree_add_leaf(root, int, char *, "hello");
 *     n00b_tree_add_leaf(root, int, char *, "world");
 * @endcode
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/gc_map.h"
#include <string.h>

/** @brief Default initial capacity for a node's children array. */
#ifndef N00B_TREE_INITIAL_CAPACITY
#define N00B_TREE_INITIAL_CAPACITY 4
#endif

#define n00b_tree_tid(N, L) typeid("tree", N, "_", L)
// ============================================================================
// Type definition
// ============================================================================

/**
 * @brief Tree type with node type @p N and leaf type @p L.
 *
 * @param N  Internal node value type.
 * @param L  Leaf value type.
 */
#define n00b_tree_t(N, L)                                                                      \
    _generic_struct n00b_tree_tid(N, L) {                                                      \
        bool is_leaf;                                                                          \
        union {                                                                                \
            struct {                                                                           \
                N value;                                                                       \
                struct n00b_tree_tid(N, L) **children;                                         \
                size_t num_children;                                                           \
                size_t capacity;                                                               \
                n00b_gc_scan_kind_t scan_kind;                                                 \
                n00b_gc_scan_cb_t   scan_cb;                                                   \
                void               *scan_user;                                                 \
            } node;                                                                            \
            L leaf;                                                                            \
        };                                                                                     \
    }

// ============================================================================
// Construction
// ============================================================================

/**
 * @brief Create a new internal node with value @p val.
 * @param N    Node type.
 * @param L    Leaf type.
 * @param val  Value for the internal node.
 * @return Pointer to the new node, or @c nullptr on failure.
 */
#define n00b_tree_node(N, L, val, ...)                                                         \
    ({                                                                                         \
        n00b_alloc_opts_t _bt_o = (n00b_alloc_opts_t){__VA_ARGS__};                            \
        n00b_tree_t(N, L) *_bt = n00b_alloc(n00b_tree_t(N, L));                                \
        if (_bt) {                                                                             \
            _bt->is_leaf    = false;                                                           \
            _bt->node.value = (val);                                                           \
            _bt->node.children                                                                 \
                = n00b_alloc_array_with_opts(n00b_tree_t(N, L) *,                              \
                                             N00B_TREE_INITIAL_CAPACITY,                       \
                                             &_bt_o);                                          \
            _bt->node.num_children = 0;                                                        \
            _bt->node.capacity     = N00B_TREE_INITIAL_CAPACITY;                               \
            _bt->node.scan_kind    = _bt_o.scan_kind;                                          \
            _bt->node.scan_cb      = _bt_o.scan_cb;                                            \
            _bt->node.scan_user    = _bt_o.scan_user;                                          \
        }                                                                                      \
        _bt;                                                                                   \
    })

/**
 * @brief Create a new leaf with value @p val.
 * @param N    Node type.
 * @param L    Leaf type.
 * @param val  Value for the leaf.
 * @return Pointer to the new leaf, or @c nullptr on failure.
 */
#define n00b_tree_leaf(N, L, val)                                                              \
    ({                                                                                         \
        n00b_tree_t(N, L) *_bt = n00b_alloc(n00b_tree_t(N, L));                                  \
        if (_bt) {                                                                             \
            _bt->is_leaf = true;                                                               \
            _bt->leaf    = (val);                                                              \
        }                                                                                      \
        _bt;                                                                                   \
    })

// ============================================================================
// Internal: grow children array
// ============================================================================

/** @internal Grow a node's children array to @p new_cap entries.
 *  Re-applies the node's stored scan_kind / cb / user to the new array. */
#define _n00b_tree_grow_children(_ptr, _new_cap)                                               \
    do {                                                                                       \
        size_t _old_n   = (_ptr)->node.num_children;                                           \
        size_t _elem_sz = sizeof(*(_ptr)->node.children);                                      \
        void  *_new_buf = n00b_alloc_array_with_opts(typeof(*(_ptr)->node.children), (_new_cap), \
                              &(n00b_alloc_opts_t){                                            \
                                  .scan_kind = (_ptr)->node.scan_kind,                         \
                                  .scan_cb   = (_ptr)->node.scan_cb,                           \
                                  .scan_user = (_ptr)->node.scan_user,                         \
                              });                                                              \
        if (_old_n > 0) {                                                                      \
            memcpy(_new_buf, (_ptr)->node.children, _old_n * _elem_sz);                        \
        }                                                                                      \
        n00b_free((_ptr)->node.children);                                                      \
        (_ptr)->node.children = _new_buf;                                                      \
        (_ptr)->node.capacity = (_new_cap);                                                    \
    } while (0)

// ============================================================================
// Child addition
// ============================================================================

/**
 * @brief Add a pre-created child to the end of a parent's children.
 *
 * Uses @c auto to infer types — no type parameters needed.
 *
 * @param parent  Parent node (must not be a leaf).
 * @param child   Child node or leaf to add.
 * @return @c true on success, @c false if parent is a leaf or null.
 */
#define n00b_tree_add_child(parent, child)                                                     \
    ({                                                                                         \
        auto _p  = (parent);                                                                   \
        auto _c  = (child);                                                                    \
        bool _ok = false;                                                                      \
        if (_p && !_p->is_leaf && _c) {                                                        \
            if (_p->node.num_children >= _p->node.capacity) {                                  \
                size_t _nc                                                                     \
                    = _p->node.capacity ? _p->node.capacity * 2 : N00B_TREE_INITIAL_CAPACITY;  \
                _n00b_tree_grow_children(_p, _nc);                                             \
            }                                                                                  \
            _p->node.children[_p->node.num_children++] = _c;                                   \
            _ok                                        = true;                                 \
        }                                                                                      \
        _ok;                                                                                   \
    })

/**
 * @brief Create a new internal node and add it as a child.
 * @param parent  Parent node.
 * @param N       Node type.
 * @param L       Leaf type.
 * @param val     Value for the new child node.
 * @return Pointer to the new child, or @c nullptr on failure.
 */
#define n00b_tree_add_node(parent, N, L, val)                                                  \
    ({                                                                                         \
        n00b_tree_t(N, L) *_an = n00b_tree_node(N, L, val);                                    \
        if (_an && !n00b_tree_add_child(parent, _an)) {                                        \
            n00b_free(_an->node.children);                                                     \
            n00b_free(_an);                                                                    \
            _an = nullptr;                                                                     \
        }                                                                                      \
        _an;                                                                                   \
    })

/**
 * @brief Create a new leaf and add it as a child.
 * @param parent  Parent node.
 * @param N       Node type.
 * @param L       Leaf type.
 * @param val     Value for the new leaf.
 * @return Pointer to the new leaf, or @c nullptr on failure.
 */
#define n00b_tree_add_leaf(parent, N, L, val)                                                  \
    ({                                                                                         \
        n00b_tree_t(N, L) *_al = n00b_tree_leaf(N, L, val);                                    \
        if (_al && !n00b_tree_add_child(parent, _al)) {                                        \
            n00b_free(_al);                                                                    \
            _al = nullptr;                                                                     \
        }                                                                                      \
        _al;                                                                                   \
    })

// ============================================================================
// Child mutation
// ============================================================================

/**
 * @brief Replace the child at index @p i.
 *
 * Does not free the old child — the caller is responsible for it.
 *
 * @param t      Pointer to the parent node.
 * @param i      Zero-based child index.
 * @param child  New child to place at index @p i.
 * @return @c true on success, @c false if @p t is null/leaf or index is out of bounds.
 */
#define n00b_tree_set_child(t, i, child)                                                       \
    ({                                                                                         \
        auto   _sc_p  = (t);                                                                   \
        size_t _sc_i  = (i);                                                                   \
        bool   _sc_ok = false;                                                                 \
        if (_sc_p && !_sc_p->is_leaf && _sc_i < _sc_p->node.num_children) {                    \
            _sc_p->node.children[_sc_i] = (child);                                             \
            _sc_ok                      = true;                                                \
        }                                                                                      \
        _sc_ok;                                                                                \
    })

/**
 * @brief Remove the child at index @p i, shifting remaining children left.
 *
 * Does not free the removed child — the caller owns it.
 *
 * @param t  Pointer to the parent node.
 * @param i  Zero-based child index.
 * @return Pointer to the removed child, or @c nullptr if invalid.
 */
#define n00b_tree_remove_child(t, i)                                                           \
    ({                                                                                         \
        auto          _rc_p       = (t);                                                       \
        size_t        _rc_i       = (i);                                                       \
        typeof(_rc_p) _rc_removed = nullptr;                                                   \
        if (_rc_p && !_rc_p->is_leaf && _rc_i < _rc_p->node.num_children) {                    \
            _rc_removed    = _rc_p->node.children[_rc_i];                                      \
            size_t _rc_rem = _rc_p->node.num_children - _rc_i - 1;                             \
            if (_rc_rem > 0) {                                                                 \
                memmove(&_rc_p->node.children[_rc_i],                                          \
                        &_rc_p->node.children[_rc_i + 1],                                      \
                        _rc_rem * sizeof(*_rc_p->node.children));                              \
            }                                                                                  \
            _rc_p->node.num_children--;                                                        \
        }                                                                                      \
        _rc_removed;                                                                           \
    })

/**
 * @brief Insert a child at index @p i, shifting existing children right.
 *
 * Grows the children array if needed.
 *
 * @param t      Pointer to the parent node.
 * @param i      Insertion index (0 .. num_children).
 * @param child  Child to insert.
 * @return @c true on success.
 */
#define n00b_tree_insert_child_at(t, i, child)                                                 \
    ({                                                                                         \
        auto   _ic_p  = (t);                                                                   \
        auto   _ic_c  = (child);                                                               \
        size_t _ic_i  = (i);                                                                   \
        bool   _ic_ok = false;                                                                 \
        if (_ic_p && !_ic_p->is_leaf && _ic_c && _ic_i <= _ic_p->node.num_children) {          \
            if (_ic_p->node.num_children >= _ic_p->node.capacity) {                            \
                size_t _ic_nc = _ic_p->node.capacity ? _ic_p->node.capacity * 2                \
                                                     : N00B_TREE_INITIAL_CAPACITY;             \
                _n00b_tree_grow_children(_ic_p, _ic_nc);                                       \
            }                                                                                  \
            size_t _ic_shift = _ic_p->node.num_children - _ic_i;                               \
            if (_ic_shift > 0) {                                                               \
                memmove(&_ic_p->node.children[_ic_i + 1],                                      \
                        &_ic_p->node.children[_ic_i],                                          \
                        _ic_shift * sizeof(*_ic_p->node.children));                            \
            }                                                                                  \
            _ic_p->node.children[_ic_i] = _ic_c;                                               \
            _ic_p->node.num_children++;                                                        \
            _ic_ok = true;                                                                     \
        }                                                                                      \
        _ic_ok;                                                                                \
    })

/**
 * @brief Replace the entire children array wholesale.
 *
 * Does not free the old children array or any child nodes.
 *
 * @param t      Pointer to the parent node.
 * @param arr    New children array (the tree takes ownership).
 * @param count  Number of elements in @p arr.
 */
#define n00b_tree_replace_children(t, arr, count)                                              \
    do {                                                                                       \
        auto _rpl_p = (t);                                                                     \
        if (_rpl_p && !_rpl_p->is_leaf) {                                                      \
            _rpl_p->node.children     = (arr);                                                 \
            _rpl_p->node.num_children = (count);                                               \
            _rpl_p->node.capacity     = (count);                                               \
        }                                                                                      \
    } while (0)

// ============================================================================
// Accessors
// ============================================================================

/**
 * @brief Check if a tree node is a leaf.
 * @param t  Pointer to a tree node.
 * @return @c true if @p t is a leaf.
 */
#define n00b_tree_is_leaf(t) ((t)->is_leaf)

/**
 * @brief Check if a tree node is an internal node.
 * @param t  Pointer to a tree node.
 * @return @c true if @p t is an internal node.
 */
#define n00b_tree_is_node(t) (!(t)->is_leaf)

/**
 * @brief Get the value of a leaf node.
 * @param t  Pointer to a leaf node.
 * @return The leaf value.
 */
#define n00b_tree_leaf_value(t) ((t)->leaf)

/**
 * @brief Get the value of an internal node.
 * @param t  Pointer to an internal node.
 * @return The node value.
 */
#define n00b_tree_node_value(t) ((t)->node.value)

/**
 * @brief Get the number of children of a node.
 * @param t  Pointer to a tree node.
 * @return Number of children (0 for leaves).
 */
#define n00b_tree_num_children(t) ((t)->is_leaf ? 0 : (t)->node.num_children)

/**
 * @brief Get the child at index @p i.
 * @param t  Pointer to an internal node.
 * @param i  Zero-based child index.
 * @return Pointer to the child node.
 */
#define n00b_tree_child(t, i) ((t)->node.children[i])

/**
 * @brief Iterate over all children of an internal node.
 * @param t    Pointer to an internal node.
 * @param var  Name of the loop variable (pointer to each child).
 */
#define n00b_tree_foreach_child(t, var)                                                        \
    for (size_t _i = 0, _n = n00b_tree_num_children(t); _i < _n; ++_i)                         \
        for (int _once = 1; _once;)                                                            \
            for (typeof((t)->node.children[0]) var = (t)->node.children[_i]; _once;            \
                 _once = 0)

/**
 * @brief Free a single tree node (does not recurse into children).
 *
 * If @p t is an internal node, frees the children array.
 * Does not free children themselves — the caller must walk the tree.
 *
 * @param t  Pointer to the tree node to free.
 */
#define n00b_tree_free_node(t)                                                                 \
    do {                                                                                       \
        if ((t) && !(t)->is_leaf) {                                                            \
            n00b_free((t)->node.children);                                                     \
        }                                                                                      \
        n00b_free(t);                                                                          \
    } while (0)
