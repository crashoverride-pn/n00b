#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/gc_map.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/type_info.h"
#include "adt/dict_untyped.h"
#include "n00b/embed_ffi.h"
#include "text/strings/string_ops.h"

typedef struct test_default_static_policy_t {
    int value;
} test_default_static_policy_t;

#ifndef _WIN32
typedef struct n00b_subproc n00b_subproc_t;
#endif

typedef struct test_plain_static_policy_t {
    uint64_t value;
} test_plain_static_policy_t;

typedef struct test_forbidden_static_policy_t {
    uint64_t value;
} test_forbidden_static_policy_t;

typedef struct test_fixup_static_policy_t {
    void *ptr;
} test_fixup_static_policy_t;

typedef struct test_constructor_static_policy_t {
    void *ptr;
} test_constructor_static_policy_t;

static n00b_static_layout_info_t *
require_layout(uint64_t type_hash)
{
    auto layout_opt = n00b_type_static_layout(type_hash);
    assert(n00b_option_is_set(layout_opt));
    return n00b_option_get(layout_opt);
}

static void
test_builtin_static_layout_policies(void)
{
    n00b_static_layout_info_t *layout = require_layout(typehash(uint64_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_PLAIN);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(layout->reason == nullptr);
    assert(n00b_type_static_layout_allowed(typehash(uint64_t *)));

    layout = require_layout(typehash(n00b_string_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_PLAIN);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_ALL);
    assert(n00b_type_static_layout_allowed(typehash(n00b_string_t *)));

    layout = require_layout(typehash(n00b_buffer_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_CONSTRUCTOR_IMAGE);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(layout->reason != nullptr);
    assert(n00b_unicode_str_contains(layout->reason, r"buffer"));
    assert(n00b_type_static_layout_allowed(typehash(n00b_buffer_t *)));

    // WP-011 Phase 3b: dict policy changed from default-deny to
    // constructor-image. ncc's migrated dict literal static-init path
    // builds the static dict image; the type-registered initializer stub
    // catches mistakenly-routed direct calls.
    layout = require_layout(typehash(n00b_dict_untyped_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_CONSTRUCTOR_IMAGE);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(layout->reason != nullptr);
    assert(n00b_unicode_str_contains(layout->reason, r"dict"));
    assert(n00b_type_static_layout_allowed(typehash(n00b_dict_untyped_t *)));

    layout = require_layout(typehash(n00b_ffi_module_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_TRANSIENT);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(layout->reason != nullptr);
    assert(n00b_unicode_str_contains(layout->reason, r"ffi"));
    assert(!n00b_type_static_layout_allowed(typehash(n00b_ffi_module_t *)));

#ifndef _WIN32
    layout = require_layout(typehash(n00b_subproc_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_TRANSIENT);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(layout->reason != nullptr);
    assert(n00b_unicode_str_contains(layout->reason, r"subprocess"));
    assert(!n00b_type_static_layout_allowed(typehash(n00b_subproc_t *)));
#endif

    printf("  [PASS] builtin static layout policies\n");
}

static void
test_default_deny_for_unannotated_registration(void)
{
    bool ok = N00B_TYPE_REGISTER(test_default_static_policy_t);
    assert(ok);

    n00b_static_layout_info_t *layout = require_layout(typehash(test_default_static_policy_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_DEFAULT_DENY);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_DEFAULT);
    assert(layout->reason == nullptr);
    assert(!n00b_type_static_layout_allowed(typehash(test_default_static_policy_t *)));

    printf("  [PASS] unannotated registration defaults to deny\n");
}

static void
test_explicit_allowed_policy_macros(void)
{
    bool ok = N00B_TYPE_REGISTER(test_plain_static_policy_t,
        N00B_TYPE_STATIC_PLAIN(N00B_GC_SCAN_KIND_NONE),
    );
    assert(ok);

    n00b_static_layout_info_t *layout = require_layout(typehash(test_plain_static_policy_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_PLAIN);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_NONE);
    assert(n00b_type_static_layout_allowed(typehash(test_plain_static_policy_t *)));

    ok = N00B_TYPE_REGISTER(test_fixup_static_policy_t,
        N00B_TYPE_STATIC_FIXUP(N00B_GC_SCAN_KIND_CALLBACK, r"runtime pointer fixup required"),
    );
    assert(ok);

    layout = require_layout(typehash(test_fixup_static_policy_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_FIXUP);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(n00b_unicode_str_eq(layout->reason, r"runtime pointer fixup required"));
    assert(n00b_type_static_layout_allowed(typehash(test_fixup_static_policy_t *)));

    ok = N00B_TYPE_REGISTER(test_constructor_static_policy_t,
        N00B_TYPE_STATIC_CONSTRUCTOR_IMAGE(N00B_GC_SCAN_KIND_ALL, r"constructor image available"),
    );
    assert(ok);

    layout = require_layout(typehash(test_constructor_static_policy_t *));
    assert(layout->policy == N00B_STATIC_LAYOUT_CONSTRUCTOR_IMAGE);
    assert(layout->scan_kind == N00B_GC_SCAN_KIND_ALL);
    assert(n00b_unicode_str_eq(layout->reason, r"constructor image available"));
    assert(n00b_type_static_layout_allowed(typehash(test_constructor_static_policy_t *)));

    printf("  [PASS] explicit allowed policy macros\n");
}

static void
test_denial_reason_is_deep_copied(void)
{
    // After WP-018, .reason is an n00b_string_t * (immutable by
    // convention).  The registry no longer needs to deep-copy a raw
    // C-string buffer; instead, the caller must construct an
    // n00b_string_t whose contents are independent of any local C
    // buffer they might mutate later.  This test confirms that
    // mutating the original C buffer used to build the n00b string
    // does not leak through to the stored reason.
    char reason[64] = "capability state cannot be static";

    n00b_string_t *reason_str = n00b_string_from_cstr(reason);

    bool ok = n00b_type_register(
        typehash(test_forbidden_static_policy_t *),
        &(n00b_type_info_t){
            .name          = r"test_forbidden_static_policy_t",
            .alloc_len     = sizeof(test_forbidden_static_policy_t),
            .static_layout = {
                .policy    = N00B_STATIC_LAYOUT_FORBIDDEN,
                .scan_kind = N00B_GC_SCAN_KIND_NONE,
                .reason    = reason_str,
            },
        });
    assert(ok);

    n00b_static_layout_info_t *layout = require_layout(typehash(test_forbidden_static_policy_t *));
    n00b_string_t *stored_reason = layout->reason;
    assert(stored_reason != nullptr);
    assert(n00b_unicode_str_eq(stored_reason, r"capability state cannot be static"));

    strcpy(reason, "mutated local reason");
    assert(n00b_unicode_str_eq(stored_reason, r"capability state cannot be static"));
    assert(!n00b_type_static_layout_allowed(typehash(test_forbidden_static_policy_t *)));

    printf("  [PASS] denial reason isolation from caller buffer\n");
}

static void
test_unregistered_and_policy_names(void)
{
    uint64_t missing_hash = UINT64_C(0xF00DD00DCAFE1234);
    assert(!n00b_option_is_set(n00b_type_static_layout(missing_hash)));
    assert(!n00b_type_static_layout_allowed(missing_hash));

    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name(N00B_STATIC_LAYOUT_DEFAULT_DENY), r"default-deny"));
    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name(N00B_STATIC_LAYOUT_FORBIDDEN), r"forbidden"));
    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name(N00B_STATIC_LAYOUT_TRANSIENT), r"transient"));
    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name(N00B_STATIC_LAYOUT_PLAIN), r"plain"));
    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name(N00B_STATIC_LAYOUT_FIXUP), r"fixup"));
    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name(N00B_STATIC_LAYOUT_CONSTRUCTOR_IMAGE), r"constructor-image"));
    assert(n00b_unicode_str_eq(n00b_static_layout_policy_name((n00b_static_layout_policy_t)255), r"unknown"));

    printf("  [PASS] unregistered lookup and policy names\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running type static-layout policy tests...\n");

    test_builtin_static_layout_policies();
    test_default_deny_for_unannotated_registration();
    test_explicit_allowed_policy_macros();
    test_denial_reason_is_deep_copied();
    test_unregistered_and_policy_names();

    printf("All type static-layout policy tests passed.\n");
    n00b_shutdown();
    return 0;
}
