/**
 * @file ntree.h
 * @brief Type-safe node-only n-ary tree / forest.
 *
 * @c n00b_ntree_t(T) stores pointer-stable heap nodes whose values are
 * statically typed as @p T. Unlike the legacy @c tree.h API, every entry is a
 * node: there is no separate leaf value type. Nodes carry direct parent
 * pointers and typed child lists, and the tree object tracks forest roots.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "adt/list.h"

#define n00b_ntree_node_tid(T) typeid("n00b_ntree_node", T)
#define n00b_ntree_tid(T)      typeid("n00b_ntree", T)

/** @brief A pointer-stable ntree node with value type @p T. */
#define n00b_ntree_node_t(T)                                                                 \
    _generic_struct n00b_ntree_node_tid(T) {                                                 \
        T                                value;                                               \
        struct n00b_ntree_node_tid(T)   *parent;                                              \
        n00b_list_t(struct n00b_ntree_node_tid(T) *) children;                                \
        n00b_allocator_t                *allocator;                                           \
    }

/** @brief A forest of ntree roots with value type @p T. */
#define n00b_ntree_t(T)                                                                      \
    _generic_struct n00b_ntree_tid(T) {                                                      \
        n00b_list_t(n00b_ntree_node_t(T) *) roots;                                           \
        size_t                         count;                                                \
        n00b_allocator_t              *allocator;                                            \
    }

/** @brief Allocate an empty ntree forest. */
#define n00b_ntree_new(T, ...)                                                               \
    ({                                                                                       \
        n00b_alloc_opts_t _nt_o = (n00b_alloc_opts_t){__VA_ARGS__};                          \
        n00b_ntree_t(T) *_nt = n00b_alloc_with_opts(n00b_ntree_t(T), &_nt_o);                \
        if (_nt != nullptr) {                                                                \
            *_nt = (n00b_ntree_t(T)){                                                        \
                .roots = n00b_list_new_private(n00b_ntree_node_t(T) *,                      \
                                               .allocator = _nt_o.allocator),                \
                .count = 0,                                                                  \
                .allocator = _nt_o.allocator,                                                \
            };                                                                               \
        }                                                                                    \
        _nt;                                                                                 \
    })

/** @brief Allocate a pointer-stable node with value @p val. */
#define n00b_ntree_node_new(T, val, ...)                                                     \
    ({                                                                                       \
        n00b_alloc_opts_t _nn_o = (n00b_alloc_opts_t){__VA_ARGS__};                          \
        n00b_ntree_node_t(T) *_nn = n00b_alloc_with_opts(n00b_ntree_node_t(T), &_nn_o);      \
        if (_nn != nullptr) {                                                                \
            *_nn = (n00b_ntree_node_t(T)){                                                   \
                .value = (val),                                                              \
                .parent = nullptr,                                                           \
                .children = n00b_list_new_private(n00b_ntree_node_t(T) *,                   \
                                                  .allocator = _nn_o.allocator),             \
                .allocator = _nn_o.allocator,                                                \
            };                                                                               \
        }                                                                                    \
        _nn;                                                                                 \
    })

/** @brief Number of roots in @p tree. */
#define n00b_ntree_root_count(tree)                                                          \
    ({                                                                                       \
        auto _nt_t = (tree);                                                                 \
        _nt_t == nullptr ? (size_t)0 : n00b_list_len(_nt_t->roots);                          \
    })

/** @brief Total number of nodes tracked by @p tree. */
#define n00b_ntree_count(tree)                                                               \
    ({                                                                                       \
        auto _nt_t = (tree);                                                                 \
        _nt_t == nullptr ? (size_t)0 : _nt_t->count;                                         \
    })

/** @brief Number of direct children on @p node. */
#define n00b_ntree_child_count(node)                                                         \
    ({                                                                                       \
        auto _nt_n = (node);                                                                 \
        _nt_n == nullptr ? (size_t)0 : n00b_list_len(_nt_n->children);                       \
    })

/** @brief Return root at index @p i. */
#define n00b_ntree_root(tree, i)                                                             \
    ({                                                                                       \
        auto _nt_t = (tree);                                                                 \
        _nt_t == nullptr ? nullptr : n00b_list_get(_nt_t->roots, i);                         \
    })

/** @brief Return child at index @p i. */
#define n00b_ntree_child(node, i)                                                            \
    ({                                                                                       \
        auto _nt_n = (node);                                                                 \
        _nt_n == nullptr ? nullptr : n00b_list_get(_nt_n->children, i);                      \
    })

#define _n00b_ntree_list_index(list_expr, needle_expr)                                       \
    ({                                                                                       \
        auto _nt_l = &(list_expr);                                                           \
        auto _nt_needle = (needle_expr);                                                     \
        size_t _nt_found = SIZE_MAX;                                                         \
        for (size_t _nt_i = 0; _nt_i < n00b_list_len(*_nt_l); _nt_i++) {                     \
            if (n00b_list_get(*_nt_l, _nt_i) == _nt_needle) {                                \
                _nt_found = _nt_i;                                                           \
                break;                                                                       \
            }                                                                                \
        }                                                                                    \
        _nt_found;                                                                           \
    })

#define _n00b_ntree_stack_pop(stack_expr)                                                      \
    ({                                                                                         \
        auto   _nt_s = &(stack_expr);                                                          \
        size_t _nt_i = n00b_list_len(*_nt_s) - 1;                                              \
        n00b_list_delete(*_nt_s, _nt_i);                                                       \
    })

#define _n00b_ntree_subtree_count(node_expr)                                                   \
    ({                                                                                         \
        auto   _nt_start = (node_expr);                                                        \
        size_t _nt_total = 0;                                                                  \
        if (_nt_start != nullptr) {                                                           \
            n00b_list_t(void *) _nt_stack =                                                   \
                n00b_list_new_private(void *, .allocator = _nt_start->allocator);              \
            n00b_list_push(_nt_stack, _nt_start);                                             \
            while (n00b_list_len(_nt_stack) > 0) {                                            \
                typeof(_nt_start) _nt_cur = _n00b_ntree_stack_pop(_nt_stack);                 \
                _nt_total++;                                                                  \
                for (size_t _nt_i = 0; _nt_i < n00b_list_len(_nt_cur->children); _nt_i++) {   \
                    n00b_list_push(_nt_stack, n00b_list_get(_nt_cur->children, _nt_i));       \
                }                                                                              \
            }                                                                                  \
        }                                                                                      \
        _nt_total;                                                                             \
    })

#define _n00b_ntree_contains(tree_expr, node_expr)                                             \
    ({                                                                                         \
        auto _ntc_t      = (tree_expr);                                                        \
        auto _ntc_needle = (node_expr);                                                        \
        bool _ntc_found  = false;                                                             \
        if (_ntc_t != nullptr && _ntc_needle != nullptr) {                                    \
            n00b_list_t(void *) _nt_stack =                                                   \
                n00b_list_new_private(void *, .allocator = _ntc_t->allocator);                \
            for (size_t _nt_i = 0; _nt_i < n00b_list_len(_ntc_t->roots); _nt_i++) {           \
                n00b_list_push(_nt_stack, n00b_list_get(_ntc_t->roots, _nt_i));               \
            }                                                                                  \
            while (!_ntc_found && n00b_list_len(_nt_stack) > 0) {                             \
                typeof(_ntc_needle) _nt_cur = _n00b_ntree_stack_pop(_nt_stack);               \
                if (_nt_cur == _ntc_needle) {                                                 \
                    _ntc_found = true;                                                        \
                }                                                                              \
                else {                                                                         \
                    for (size_t _nt_i = 0;                                                     \
                         _nt_i < n00b_list_len(_nt_cur->children);                            \
                         _nt_i++) {                                                           \
                        n00b_list_push(_nt_stack, n00b_list_get(_nt_cur->children, _nt_i));   \
                    }                                                                          \
                }                                                                              \
            }                                                                                  \
        }                                                                                      \
        _ntc_found;                                                                            \
    })

/**
 * @brief Add detached @p node as a forest root.
 *
 * Fails if @p node already has a parent or is already present as a root.
 */
#define n00b_ntree_add_root(tree, node)                                                       \
    ({                                                                                       \
        auto _nt_t = (tree);                                                                 \
        auto _nt_n = (node);                                                                 \
        bool _nt_ok = false;                                                                 \
        if (_nt_t != nullptr && _nt_n != nullptr && _nt_n->parent == nullptr &&              \
            _n00b_ntree_list_index(_nt_t->roots, _nt_n) == SIZE_MAX) {                       \
            n00b_list_push(_nt_t->roots, _nt_n);                                             \
            _nt_t->count += _n00b_ntree_subtree_count(_nt_n);                                \
            _nt_ok = true;                                                                   \
        }                                                                                    \
        _nt_ok;                                                                              \
    })

/**
 * @brief Add detached @p child under @p parent.
 *
 * This is intentionally strict: already-parented nodes are rejected. Callers
 * that need a move must make the detach step explicit first.
 */
#define n00b_ntree_add_child(tree_expr, parent_expr, child_expr)                              \
    ({                                                                                       \
        auto _nt_t = (tree_expr);                                                            \
        auto _nt_p = (parent_expr);                                                          \
        auto _nt_c = (child_expr);                                                           \
        bool _nt_ok = false;                                                                 \
        if (_nt_t != nullptr && _nt_p != nullptr && _nt_c != nullptr &&                      \
            _nt_c->parent == nullptr && _n00b_ntree_contains(_nt_t, _nt_p)) {                \
            size_t _nt_ri = _n00b_ntree_list_index(_nt_t->roots, _nt_c);                     \
            if (_nt_ri != SIZE_MAX) {                                                        \
                (void)n00b_list_delete(_nt_t->roots, _nt_ri);                                \
            }                                                                                \
            _nt_c->parent = _nt_p;                                                           \
            n00b_list_push(_nt_p->children, _nt_c);                                          \
            if (_nt_ri == SIZE_MAX) {                                                        \
                _nt_t->count += _n00b_ntree_subtree_count(_nt_c);                            \
            }                                                                                \
            _nt_ok = true;                                                                   \
        }                                                                                    \
        _nt_ok;                                                                              \
    })

/**
 * @brief Detach @p node from its parent or root list.
 *
 * Detached nodes preserve their child subtree. If the node had a parent, it is
 * promoted to a root of @p tree. If it was already a root, the call succeeds
 * without changing the tree.
 */
#define n00b_ntree_detach(tree, node)                                                         \
    ({                                                                                       \
        auto _nt_t = (tree);                                                                 \
        auto _nt_n = (node);                                                                 \
        bool _nt_ok = false;                                                                 \
        if (_nt_t != nullptr && _nt_n != nullptr && _n00b_ntree_contains(_nt_t, _nt_n)) {    \
            if (_nt_n->parent != nullptr) {                                                  \
                auto _nt_p = _nt_n->parent;                                                  \
                size_t _nt_i = _n00b_ntree_list_index(_nt_p->children, _nt_n);               \
                if (_nt_i != SIZE_MAX) {                                                     \
                    (void)n00b_list_delete(_nt_p->children, _nt_i);                          \
                    _nt_n->parent = nullptr;                                                 \
                    if (_n00b_ntree_list_index(_nt_t->roots, _nt_n) == SIZE_MAX) {           \
                        n00b_list_push(_nt_t->roots, _nt_n);                                 \
                    }                                                                        \
                    _nt_ok = true;                                                           \
                }                                                                            \
            }                                                                                \
            else {                                                                           \
                _nt_ok = _n00b_ntree_list_index(_nt_t->roots, _nt_n) != SIZE_MAX;            \
            }                                                                                \
        }                                                                                    \
        _nt_ok;                                                                              \
    })

/** @brief Remove @p node and its descendants from @p tree membership. */
#define n00b_ntree_remove_subtree(tree, node)                                                 \
    ({                                                                                       \
        auto _nt_t = (tree);                                                                 \
        auto _nt_n = (node);                                                                 \
        bool _nt_ok = false;                                                                 \
        if (_nt_t != nullptr && _nt_n != nullptr && _n00b_ntree_contains(_nt_t, _nt_n)) {    \
            size_t _nt_removed = _n00b_ntree_subtree_count(_nt_n);                           \
            if (_nt_n->parent != nullptr) {                                                  \
                auto _nt_p = _nt_n->parent;                                                  \
                size_t _nt_i = _n00b_ntree_list_index(_nt_p->children, _nt_n);               \
                if (_nt_i != SIZE_MAX) {                                                     \
                    (void)n00b_list_delete(_nt_p->children, _nt_i);                          \
                    _nt_n->parent = nullptr;                                                 \
                    _nt_ok = true;                                                           \
                }                                                                            \
            }                                                                                \
            else {                                                                           \
                size_t _nt_i = _n00b_ntree_list_index(_nt_t->roots, _nt_n);                  \
                if (_nt_i != SIZE_MAX) {                                                     \
                    (void)n00b_list_delete(_nt_t->roots, _nt_i);                             \
                    _nt_ok = true;                                                           \
                }                                                                            \
            }                                                                                \
            if (_nt_ok) {                                                                    \
                _nt_t->count = _nt_removed > _nt_t->count ? 0 : _nt_t->count - _nt_removed;  \
            }                                                                                \
        }                                                                                    \
        _nt_ok;                                                                              \
    })

/** @brief Pre-order walk over @p node's subtree. */
#define n00b_ntree_foreach_pre(node, var, body)                                               \
    do {                                                                                       \
        auto _nt_start = (node);                                                               \
        if (_nt_start != nullptr) {                                                           \
            n00b_list_t(void *) _nt_stack =                                                   \
                n00b_list_new_private(void *, .allocator = _nt_start->allocator);              \
            n00b_list_push(_nt_stack, _nt_start);                                             \
            while (n00b_list_len(_nt_stack) > 0) {                                            \
                typeof(_nt_start) var = _n00b_ntree_stack_pop(_nt_stack);                     \
                body;                                                                          \
                size_t _nt_n_children = n00b_list_len(var->children);                         \
                while (_nt_n_children > 0) {                                                   \
                    _nt_n_children--;                                                          \
                    n00b_list_push(_nt_stack, n00b_list_get(var->children, _nt_n_children));  \
                }                                                                              \
            }                                                                                  \
        }                                                                                      \
    } while (0)

/** @brief Post-order walk over @p node's subtree. */
#define n00b_ntree_foreach_post(node, var, body)                                              \
    do {                                                                                       \
        auto _nt_start = (node);                                                               \
        if (_nt_start != nullptr) {                                                           \
            n00b_list_t(void *) _nt_stack =                                                   \
                n00b_list_new_private(void *, .allocator = _nt_start->allocator);              \
            n00b_list_t(void *) _nt_post =                                                    \
                n00b_list_new_private(void *, .allocator = _nt_start->allocator);              \
            n00b_list_push(_nt_stack, _nt_start);                                             \
            while (n00b_list_len(_nt_stack) > 0) {                                            \
                typeof(_nt_start) _nt_cur = _n00b_ntree_stack_pop(_nt_stack);                 \
                n00b_list_push(_nt_post, _nt_cur);                                            \
                for (size_t _nt_i = 0; _nt_i < n00b_list_len(_nt_cur->children); _nt_i++) {   \
                    n00b_list_push(_nt_stack, n00b_list_get(_nt_cur->children, _nt_i));       \
                }                                                                              \
            }                                                                                  \
            while (n00b_list_len(_nt_post) > 0) {                                             \
                typeof(_nt_start) var = _n00b_ntree_stack_pop(_nt_post);                      \
                body;                                                                          \
            }                                                                                  \
        }                                                                                      \
    } while (0)
