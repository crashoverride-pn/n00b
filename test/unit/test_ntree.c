#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "adt/ntree.h"
#include "core/arena.h"
#include "core/runtime.h"

typedef struct test_node_t {
    int id;
} test_node_t;

static test_node_t
node_value(int id)
{
    return (test_node_t){.id = id};
}

static void
test_construct_empty(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    assert(tree != nullptr);
    assert(n00b_ntree_count(tree) == 0);
    assert(n00b_ntree_root_count(tree) == 0);
    printf("  [PASS] construct empty\n");
}

static void
test_allocator_propagation(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    assert(arena != nullptr);
    n00b_allocator_t *allocator = (n00b_allocator_t *)arena;

    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t,
                                                    .allocator = allocator);
    n00b_ntree_node_t(test_node_t) *root =
        n00b_ntree_node_new(test_node_t, node_value(1), .allocator = allocator);
    assert(tree != nullptr);
    assert(root != nullptr);
    assert(tree->allocator == allocator);
    assert(tree->roots.allocator == allocator);
    assert(root->allocator == allocator);
    assert(root->children.allocator == allocator);
    assert(n00b_ntree_add_root(tree, root));
    assert(n00b_ntree_count(tree) == 1);
    printf("  [PASS] allocator propagation\n");
}

static void
test_add_root_and_child(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root =
        n00b_ntree_node_new(test_node_t, node_value(1));
    n00b_ntree_node_t(test_node_t) *child =
        n00b_ntree_node_new(test_node_t, node_value(2));

    assert(n00b_ntree_add_root(tree, root));
    assert(n00b_ntree_add_child(tree, root, child));
    assert(child->parent == root);
    assert(n00b_ntree_child_count(root) == 1);
    assert(n00b_ntree_child(root, 0) == child);
    assert(n00b_ntree_count(tree) == 2);
    printf("  [PASS] add root and child\n");
}

static void
test_strict_attach_rejects_parented_node(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root_a =
        n00b_ntree_node_new(test_node_t, node_value(1));
    n00b_ntree_node_t(test_node_t) *root_b =
        n00b_ntree_node_new(test_node_t, node_value(2));
    n00b_ntree_node_t(test_node_t) *child =
        n00b_ntree_node_new(test_node_t, node_value(3));

    assert(n00b_ntree_add_root(tree, root_a));
    assert(n00b_ntree_add_root(tree, root_b));
    assert(n00b_ntree_add_child(tree, root_a, child));
    assert(!n00b_ntree_add_child(tree, root_b, child));
    assert(child->parent == root_a);
    assert(n00b_ntree_child_count(root_a) == 1);
    assert(n00b_ntree_child_count(root_b) == 0);
    printf("  [PASS] strict attach rejects parented node\n");
}

static void
test_cross_tree_attach_rejected(void)
{
    n00b_ntree_t(test_node_t) *tree_a = n00b_ntree_new(test_node_t);
    n00b_ntree_t(test_node_t) *tree_b = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root_a =
        n00b_ntree_node_new(test_node_t, node_value(1));
    n00b_ntree_node_t(test_node_t) *root_b =
        n00b_ntree_node_new(test_node_t, node_value(2));
    n00b_ntree_node_t(test_node_t) *child =
        n00b_ntree_node_new(test_node_t, node_value(3));

    assert(n00b_ntree_add_root(tree_a, root_a));
    assert(n00b_ntree_add_root(tree_b, root_b));
    assert(!n00b_ntree_add_child(tree_a, root_b, child));
    assert(child->parent == nullptr);
    assert(n00b_ntree_count(tree_a) == 1);
    assert(n00b_ntree_count(tree_b) == 1);
    printf("  [PASS] cross-tree attach rejected\n");
}

static void
test_detach_promotes_to_root(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root =
        n00b_ntree_node_new(test_node_t, node_value(1));
    n00b_ntree_node_t(test_node_t) *child =
        n00b_ntree_node_new(test_node_t, node_value(2));
    n00b_ntree_node_t(test_node_t) *grandchild =
        n00b_ntree_node_new(test_node_t, node_value(3));

    assert(n00b_ntree_add_root(tree, root));
    assert(n00b_ntree_add_child(tree, root, child));
    assert(n00b_ntree_add_child(tree, child, grandchild));
    assert(n00b_ntree_detach(tree, child));
    assert(child->parent == nullptr);
    assert(grandchild->parent == child);
    assert(n00b_ntree_child_count(root) == 0);
    assert(n00b_ntree_root_count(tree) == 2);
    assert(n00b_ntree_count(tree) == 3);
    printf("  [PASS] detach promotes to root\n");
}

static void
test_remove_subtree_updates_membership(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root =
        n00b_ntree_node_new(test_node_t, node_value(1));
    n00b_ntree_node_t(test_node_t) *child =
        n00b_ntree_node_new(test_node_t, node_value(2));
    n00b_ntree_node_t(test_node_t) *grandchild =
        n00b_ntree_node_new(test_node_t, node_value(3));

    assert(n00b_ntree_add_root(tree, root));
    assert(n00b_ntree_add_child(tree, root, child));
    assert(n00b_ntree_add_child(tree, child, grandchild));
    assert(n00b_ntree_remove_subtree(tree, child));
    assert(child->parent == nullptr);
    assert(n00b_ntree_child_count(root) == 0);
    assert(n00b_ntree_root_count(tree) == 1);
    assert(n00b_ntree_count(tree) == 1);
    printf("  [PASS] remove subtree updates membership\n");
}

static void
test_pointer_stability(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root =
        n00b_ntree_node_new(test_node_t, node_value(0));
    assert(n00b_ntree_add_root(tree, root));

    n00b_ntree_node_t(test_node_t) *first = nullptr;
    for (int i = 1; i <= 64; i++) {
        n00b_ntree_node_t(test_node_t) *child =
            n00b_ntree_node_new(test_node_t, node_value(i));
        if (i == 1) {
            first = child;
        }
        assert(n00b_ntree_add_child(tree, root, child));
    }

    assert(n00b_ntree_child(root, 0) == first);
    assert(first->value.id == 1);
    assert(first->parent == root);
    printf("  [PASS] pointer stability\n");
}

static void
test_traversal_order(void)
{
    n00b_ntree_t(test_node_t) *tree = n00b_ntree_new(test_node_t);
    n00b_ntree_node_t(test_node_t) *root =
        n00b_ntree_node_new(test_node_t, node_value(1));
    n00b_ntree_node_t(test_node_t) *left =
        n00b_ntree_node_new(test_node_t, node_value(2));
    n00b_ntree_node_t(test_node_t) *right =
        n00b_ntree_node_new(test_node_t, node_value(3));
    n00b_ntree_node_t(test_node_t) *leaf =
        n00b_ntree_node_new(test_node_t, node_value(4));

    assert(n00b_ntree_add_root(tree, root));
    assert(n00b_ntree_add_child(tree, root, left));
    assert(n00b_ntree_add_child(tree, root, right));
    assert(n00b_ntree_add_child(tree, left, leaf));

    int pre[4] = {};
    int post[4] = {};
    int pre_i = 0;
    int post_i = 0;

    n00b_ntree_foreach_pre(root, node, {
        pre[pre_i++] = node->value.id;
    });
    n00b_ntree_foreach_post(root, node, {
        post[post_i++] = node->value.id;
    });

    assert(pre_i == 4);
    assert(pre[0] == 1 && pre[1] == 2 && pre[2] == 4 && pre[3] == 3);
    assert(post_i == 4);
    assert(post[0] == 4 && post[1] == 2 && post[2] == 3 && post[3] == 1);
    printf("  [PASS] traversal order\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);
    printf("Running ntree tests...\n");
    test_construct_empty();
    test_allocator_propagation();
    test_add_root_and_child();
    test_strict_attach_rejects_parented_node();
    test_cross_tree_attach_rejected();
    test_detach_promotes_to_root();
    test_remove_subtree_updates_membership();
    test_pointer_stability();
    test_traversal_order();
    printf("All ntree tests passed.\n");
    return 0;
}
