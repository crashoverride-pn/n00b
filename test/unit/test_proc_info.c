// Unit tests for the cross-platform process-introspection API (util/proc.h).
//
// Phase 1 verifies the macOS implementation: self/parent lookup, ancestry
// shape and child-to-ancestor ordering, and error handling for bad pids.

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/result.h"
#include "adt/list.h"
#include "text/strings/string_ops.h"
#include "util/proc.h"

// self pid is sane, and get_info(self) reports our own identity.
static void
test_self_info(void)
{
    int64_t self = n00b_proc_self_pid();
    assert(self > 0);

    auto r = n00b_proc_get_info(self);
    assert(n00b_result_is_ok(r));

    n00b_proc_info_t *info = n00b_result_get(r);
    assert(info != nullptr);
    assert(info->pid == self);
    assert(info->ppid > 0); // a unit test always has a launching parent

    // The running binary's path resolves; its basename and kernel process
    // name are both this test (short enough not to be truncated).
    assert(info->exe_path != nullptr);
    assert(info->exe_name != nullptr);
#ifdef _WIN32
    assert(n00b_unicode_str_eq(info->exe_name, r"test_proc_info.exe"));
#else
    assert(n00b_unicode_str_eq(info->exe_name, r"test_proc_info"));
#endif
    assert(info->proc_name != nullptr);
    assert(n00b_unicode_str_eq(info->proc_name, info->exe_name));

    printf("  [PASS] self_info\n");
}

// get_info(parent) succeeds and its pid matches self's reported ppid.
static void
test_parent_info(void)
{
    auto sr = n00b_proc_get_info(n00b_proc_self_pid());
    assert(n00b_result_is_ok(sr));
    n00b_proc_info_t *self = n00b_result_get(sr);

    auto pr = n00b_proc_get_info(self->ppid);
    assert(n00b_result_is_ok(pr));
    n00b_proc_info_t *parent = n00b_result_get(pr);

    assert(parent->pid == self->ppid);

    printf("  [PASS] parent_info\n");
}

// Bad pids are reported as errors, not silently mishandled.
static void
test_bad_pid(void)
{
    auto neg = n00b_proc_get_info(-1);
    assert(n00b_result_is_err(neg));
    assert(n00b_result_get_err(neg) == N00B_PROC_ERR_NO_SUCH_PID);

    auto zero = n00b_proc_get_info(0);
    assert(n00b_result_is_err(zero));

    // A pid that is extremely unlikely to exist.
    auto missing = n00b_proc_get_info(0x7ffffff0);
    assert(n00b_result_is_err(missing));

    printf("  [PASS] bad_pid\n");
}

// ancestry(self) begins at self and is correctly chained child->ancestor.
static void
test_ancestry_shape(void)
{
    int64_t self = n00b_proc_self_pid();

    auto r = n00b_proc_ancestry(self);
    assert(n00b_result_is_ok(r));

    n00b_list_t(n00b_proc_info_t *) *chain = n00b_result_get(r);
    assert(chain != nullptr);

    int64_t len = (int64_t)n00b_list_len(*chain);
    assert(len >= 1);

    n00b_proc_info_t *first = n00b_list_get(*chain, 0);
    assert(first->pid == self);

    // Each element's ppid must equal the next element's pid.
    for (int64_t i = 0; i + 1 < len; i++) {
        n00b_proc_info_t *child  = n00b_list_get(*chain, i);
        n00b_proc_info_t *parent = n00b_list_get(*chain, i + 1);
        assert(child->ppid == parent->pid);
    }

    printf("  [PASS] ancestry_shape\n");
}

// include_self = false starts the chain at the parent; max_depth caps length.
static void
test_ancestry_options(void)
{
    int64_t self = n00b_proc_self_pid();

    auto sr = n00b_proc_get_info(self);
    assert(n00b_result_is_ok(sr));
    int64_t self_ppid = n00b_result_get(sr)->ppid;

    auto r = n00b_proc_ancestry(self, .include_self = false);
    assert(n00b_result_is_ok(r));
    n00b_list_t(n00b_proc_info_t *) *chain = n00b_result_get(r);
    assert((int64_t)n00b_list_len(*chain) >= 1);
    assert(n00b_list_get(*chain, 0)->pid == self_ppid);

    auto capped = n00b_proc_ancestry(self, .max_depth = 1);
    assert(n00b_result_is_ok(capped));
    assert((int64_t)n00b_list_len(*n00b_result_get(capped)) == 1);

    printf("  [PASS] ancestry_options\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running proc_info tests...\n");

    test_self_info();
    test_parent_info();
    test_bad_pid();
    test_ancestry_shape();
    test_ancestry_options();

    printf("All proc_info tests passed.\n");
    n00b_shutdown();
    return 0;
}
