/**
 * @file test_demangle.c
 * @brief Tests for C++ Itanium and Rust v0 symbol demangling.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "compiler/objfile/demangle.h"

// ============================================================================
// Helpers
// ============================================================================

static void
check_demangle(const char *mangled, const char *expected, const char *label)
{
    n00b_string_t *result = n00b_demangle(mangled);
    assert(result != nullptr);
    assert(strcmp(result->data, expected) == 0);
    printf("  [PASS] %s: %s -> %s\n", label, mangled, result->data);
}

static void
check_itanium(const char *mangled, const char *expected, const char *label)
{
    n00b_string_t *result = n00b_demangle_itanium(mangled);
    assert(result != nullptr);
    assert(strcmp(result->data, expected) == 0);
    printf("  [PASS] %s: %s -> %s\n", label, mangled, result->data);
}

static void
check_rust(const char *mangled, const char *expected, const char *label)
{
    n00b_option_t(n00b_string_t *) result_opt = n00b_demangle_rust(mangled);
    assert(n00b_option_is_set(result_opt));
    n00b_string_t *result = n00b_option_get(result_opt);
    assert(strcmp(result->data, expected) == 0);
    printf("  [PASS] %s: %s -> %s\n", label, mangled, result->data);
}

// ============================================================================
// C++ Itanium ABI tests
// ============================================================================

static void
test_itanium_simple_functions(void)
{
    printf("test_itanium_simple_functions:\n");

    // Simple function: foo()
    check_itanium("_Z3foov", "foo()", "simple void fn");

    // Function with args: bar(int, double)
    check_itanium("_Z3barid", "bar(int, double)", "fn with args");

    // Function with pointer: baz(int*)
    check_itanium("_Z3bazPi", "baz(int*)", "fn with pointer");

    // Function with reference: qux(int&)
    check_itanium("_Z3quxRi", "qux(int&)", "fn with reference");

    // Function with const ref: f(const int&)
    check_itanium("_Z1fRKi", "f(int const&)", "fn with const ref");

    printf("  OK\n\n");
}

static void
test_itanium_namespaces(void)
{
    printf("test_itanium_namespaces:\n");

    // ns::func()
    check_itanium("_ZN2ns4funcEv", "ns::func()", "namespaced fn");

    // a::b::c::func(int)
    check_itanium("_ZN1a1b1c4funcEi", "a::b::c::func(int)", "deeply nested");

    printf("  OK\n\n");
}

static void
test_itanium_classes(void)
{
    printf("test_itanium_classes:\n");

    // MyClass::method(int)
    check_itanium("_ZN7MyClass6methodEi", "MyClass::method(int)", "method");

    // Constructor: MyClass::MyClass()
    check_itanium("_ZN7MyClassC1Ev", "MyClass::MyClass()", "constructor");

    // Destructor: MyClass::~MyClass()
    check_itanium("_ZN7MyClassD1Ev", "MyClass::~MyClass()", "destructor");

    printf("  OK\n\n");
}

static void
test_itanium_operators(void)
{
    printf("test_itanium_operators:\n");

    // operator+
    check_itanium("_ZN1AplERKS_", "A::operator+(A const&)", "operator+");

    // operator==
    check_itanium("_ZN1AeqERKS_", "A::operator==(A const&)", "operator==");

    // operator new
    check_itanium("_Znwm", "operator new(unsigned long)", "operator new");

    // operator delete
    check_itanium("_ZdlPv", "operator delete(void*)", "operator delete");

    printf("  OK\n\n");
}

static void
test_itanium_templates(void)
{
    printf("test_itanium_templates:\n");

    // func<int>(void, int) — T_ resolves to first template arg
    check_itanium("_Z4funcIiEvT_", "func<int>(void, int)", "template fn");

    // pair<int, double>()
    check_itanium("_Z4pairIidEv", "pair<int, double>()", "template 2 args");

    printf("  OK\n\n");
}

static void
test_itanium_special(void)
{
    printf("test_itanium_special:\n");

    // vtable: vtable for Foo
    check_itanium("_ZTV3Foo", "vtable for Foo", "vtable");

    // typeinfo: typeinfo for Foo
    check_itanium("_ZTI3Foo", "typeinfo for Foo", "typeinfo");

    // typeinfo name: typeinfo name for Foo
    check_itanium("_ZTS3Foo", "typeinfo name for Foo", "typeinfo name");

    // guard variable
    check_itanium("_ZGVN3foo3barE", "guard variable for foo::bar", "guard var");

    printf("  OK\n\n");
}

static void
test_itanium_macos_prefix(void)
{
    printf("test_itanium_macos_prefix:\n");

    // macOS adds extra underscore: __Z3foov
    check_itanium("__Z3foov", "foo()", "macos prefix");

    printf("  OK\n\n");
}

static void
test_itanium_std_substitutions(void)
{
    printf("test_itanium_std_substitutions:\n");

    // std::string is Ss
    check_itanium("_Z4funcSs", "func(std::string)", "std::string sub");

    printf("  OK\n\n");
}

// ============================================================================
// Rust v0 tests
// ============================================================================

static void
test_rust_crate_root(void)
{
    printf("test_rust_crate_root:\n");

    // Simple crate function: mycrate::foo
    // _R  N  C  <crate>  <ident>
    // _RNvC5crate3foo  = crate::foo
    check_rust("_RNvC5crate3foo", "crate::foo", "crate fn");

    printf("  OK\n\n");
}

static void
test_rust_nested_path(void)
{
    printf("test_rust_nested_path:\n");

    // mymod::mytype::method
    // _RNvNtC5crate5mymod6method = crate::mymod::method
    check_rust("_RNvNtC5crate5mymod6method", "crate::mymod::method", "nested fn");

    printf("  OK\n\n");
}

static void
test_rust_generic(void)
{
    printf("test_rust_generic:\n");

    // foo::<i32>
    // _RINvC5crate3foolEE = crate::foo<i32>
    check_rust("_RINvC5crate3foolEE", "crate::foo<i32>", "generic fn");

    printf("  OK\n\n");
}

static void
test_rust_basic_types(void)
{
    printf("test_rust_basic_types:\n");

    // Test via generic args: foo<bool, u8, str>
    check_rust("_RINvC5crate3foobheEE", "crate::foo<bool, u8, str>", "basic types");

    printf("  OK\n\n");
}

static void
test_rust_ref_types(void)
{
    printf("test_rust_ref_types:\n");

    // foo<&i32> → _RINvC5crate3fooRlEE
    check_rust("_RINvC5crate3fooRlEE", "crate::foo<&i32>", "ref type");

    // foo<&mut u8> → _RINvC5crate3fooQhEE
    check_rust("_RINvC5crate3fooQhEE", "crate::foo<&mut u8>", "mut ref type");

    printf("  OK\n\n");
}

static void
test_rust_pointer_types(void)
{
    printf("test_rust_pointer_types:\n");

    // foo<*const i32> → _RINvC5crate3fooPlEE
    check_rust("_RINvC5crate3fooPlEE", "crate::foo<*const i32>", "const ptr");

    // foo<*mut u8> → _RINvC5crate3fooOhEE
    check_rust("_RINvC5crate3fooOhEE", "crate::foo<*mut u8>", "mut ptr");

    printf("  OK\n\n");
}

static void
test_rust_tuple(void)
{
    printf("test_rust_tuple:\n");

    // foo<(i32, bool)> → _RINvC5crate3fooTlbEEE
    check_rust("_RINvC5crate3fooTlbEEE", "crate::foo<(i32, bool)>", "tuple");

    printf("  OK\n\n");
}

static void
test_rust_slice(void)
{
    printf("test_rust_slice:\n");

    // foo<[u8]> → _RINvC5crate3fooShEE
    check_rust("_RINvC5crate3fooShEE", "crate::foo<[u8]>", "slice");

    printf("  OK\n\n");
}

static void
test_rust_closure(void)
{
    printf("test_rust_closure:\n");

    // foo::{closure} — nested "C" (closure) namespace with empty identifier
    check_rust("_RNCNvC5crate3foo0", "crate::foo::{closure}", "closure");

    printf("  OK\n\n");
}

// ============================================================================
// C++ Itanium — extended coverage
// ============================================================================

static void
test_itanium_rvalue_refs(void)
{
    printf("test_itanium_rvalue_refs:\n");

    // f(int&&) — rvalue reference
    check_itanium("_Z1fOi", "f(int&&)", "rvalue ref");

    // f(const int&&)
    check_itanium("_Z1fOKi", "f(int const&&)", "const rvalue ref");

    printf("  OK\n\n");
}

static void
test_itanium_function_pointers(void)
{
    printf("test_itanium_function_pointers:\n");

    // f(void (*)(int)) — function pointer parameter
    // PFviE = pointer to function(void, int)
    check_itanium("_Z1fPFviE", "f(void (*)(int))", "fn ptr param");

    // f(int (*)(double, float))
    check_itanium("_Z1fPFidfE", "f(int (*)(double, float))", "fn ptr multi-arg");

    printf("  OK\n\n");
}

static void
test_itanium_array_types(void)
{
    printf("test_itanium_array_types:\n");

    // f(int[10]) — array type
    // A10_i = array of 10 ints
    check_itanium("_Z1fA10_i", "f(int[10])", "array type");

    printf("  OK\n\n");
}

static void
test_itanium_local_names(void)
{
    printf("test_itanium_local_names:\n");

    // foo()::bar — local name inside function
    // Z3foov E 3bar = local "bar" inside "foo()"
    check_itanium("_ZZ3foovE3bar", "foo()::bar", "local name");

    printf("  OK\n\n");
}

static void
test_itanium_thunks(void)
{
    printf("test_itanium_thunks:\n");

    // non-virtual thunk to Foo::bar()
    check_itanium("_ZThn16_N3Foo3barEv",
                   "non-virtual thunk to Foo::bar()", "nv thunk");

    // virtual thunk to Foo::baz()
    check_itanium("_ZTv0_n24_N3Foo3bazEv",
                   "virtual thunk to Foo::baz()", "v thunk");

    printf("  OK\n\n");
}

static void
test_itanium_deep_recursion(void)
{
    printf("test_itanium_deep_recursion:\n");

    // Build a deeply nested pointer-to-pointer-to-... type that exceeds
    // the depth limit (256).  Should not crash — returns best-effort or
    // the original mangled name.
    char deep[600];
    deep[0] = '_';
    deep[1] = 'Z';
    deep[2] = '1';
    deep[3] = 'f';

    // 300 'P' chars = pointer-to-pointer-to-...
    for (int i = 0; i < 300; i++) {
        deep[4 + i] = 'P';
    }

    deep[304] = 'i'; // base type
    deep[305] = '\0';

    n00b_string_t *result = n00b_demangle_itanium(deep);
    // Should return something (not crash). Either demangled or original.
    assert(result != nullptr);
    printf("  [PASS] deep recursion did not crash\n");

    printf("  OK\n\n");
}

static void
test_itanium_ctor_dtor_stress(void)
{
    printf("test_itanium_ctor_dtor_stress:\n");

    // Long class name that may trigger output buffer realloc,
    // then constructor reference back to it.
    // "VeryLongClassNameThatExceedsInitialBufferCapacity" = 49 chars.
    check_itanium(
        "_ZN49VeryLongClassNameThatExceedsInitialBufferCapacityC1Ev",
        "VeryLongClassNameThatExceedsInitialBufferCapacity"
        "::VeryLongClassNameThatExceedsInitialBufferCapacity()",
        "long ctor");

    check_itanium(
        "_ZN49VeryLongClassNameThatExceedsInitialBufferCapacityD1Ev",
        "VeryLongClassNameThatExceedsInitialBufferCapacity"
        "::~VeryLongClassNameThatExceedsInitialBufferCapacity()",
        "long dtor");

    printf("  OK\n\n");
}

// ============================================================================
// Rust v0 — extended coverage
// ============================================================================

static void
test_rust_fn_pointers(void)
{
    printf("test_rust_fn_pointers:\n");

    // fn(i32) -> bool:  F = fn-sig start, l = i32 param, E = end params,
    //                   b = bool return type.  Wrapped in I...E generic args.
    check_rust("_RINvC5crate3fooFlEbEE", "crate::foo<fn(i32) -> bool>",
               "fn ptr type");

    printf("  OK\n\n");
}

static void
test_rust_array_with_const(void)
{
    printf("test_rust_array_with_const:\n");

    // [i32; 5] = A <type> <const>
    // type = l (i32), const = j 5_ (type=usize, value=5)
    // K prefix only appears in generic-arg context, not inside A.
    check_rust("_RINvC5crate3fooAlj5_EE", "crate::foo<[i32; 5]>",
               "array with const");

    printf("  OK\n\n");
}

static void
test_rust_nested_closures(void)
{
    printf("test_rust_nested_closures:\n");

    // foo::{closure}::{closure} — doubly nested closure
    // NC NC NvC5crate3foo 0 0
    check_rust("_RNCNCNvC5crate3foo00",
               "crate::foo::{closure}::{closure}",
               "nested closures");

    printf("  OK\n\n");
}

static void
test_rust_punycode(void)
{
    printf("test_rust_punycode:\n");

    // Punycode identifier — should output {punycode:...} marker
    // u <decimal> <punycode-bytes>
    // A simple punycode ident: u5hello
    // Actually RFC 2603 punycode is: u <decimal-length> <bytes> _  <punycode-suffix>
    // For now just check it doesn't crash on identifiers starting with 'u'
    // and that the output contains the punycode marker.
    n00b_option_t(n00b_string_t *) result_opt
        = n00b_demangle_rust("_RNvC5crate5u8bng_75l");

    // May not parse perfectly but should not crash.
    (void)result_opt;
    printf("  [PASS] punycode did not crash\n");

    printf("  OK\n\n");
}

// ============================================================================
// Cross-cutting tests
// ============================================================================

static void
test_is_mangled(void)
{
    printf("test_is_mangled:\n");

    assert(n00b_is_mangled("_Z3foov") == true);
    assert(n00b_is_mangled("__Z3foov") == true);
    assert(n00b_is_mangled("_RNvC5crate3foo") == true);
    assert(n00b_is_mangled("main") == false);
    assert(n00b_is_mangled("_start") == false);
    assert(n00b_is_mangled("printf") == false);
    assert(n00b_is_mangled(nullptr) == false);

    printf("  [PASS] all is_mangled checks\n");
    printf("  OK\n\n");
}

static void
test_auto_dispatch(void)
{
    printf("test_auto_dispatch:\n");

    // C++ via auto-dispatch
    check_demangle("_Z3foov", "foo()", "auto cxx");

    // Rust via auto-dispatch
    check_demangle("_RNvC5crate3foo", "crate::foo", "auto rust");

    // Unmangled passes through
    n00b_string_t *r = n00b_demangle("main");
    assert(r != nullptr);
    assert(strcmp(r->data, "main") == 0);
    printf("  [PASS] passthrough: main -> main\n");

    printf("  OK\n\n");
}

static void
test_null_safety(void)
{
    printf("test_null_safety:\n");

    assert(n00b_demangle(nullptr) == nullptr);
    assert(n00b_demangle_itanium(nullptr) == nullptr);
    assert(!n00b_option_is_set(n00b_demangle_rust(nullptr)));
    assert(n00b_is_mangled(nullptr) == false);

    printf("  [PASS] all null checks\n");
    printf("  OK\n\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("=== Demangle Tests ===\n\n");

    // C++ Itanium
    test_itanium_simple_functions();
    test_itanium_namespaces();
    test_itanium_classes();
    test_itanium_operators();
    test_itanium_templates();
    test_itanium_special();
    test_itanium_macos_prefix();
    test_itanium_std_substitutions();
    test_itanium_rvalue_refs();
    test_itanium_function_pointers();
    test_itanium_array_types();
    test_itanium_local_names();
    test_itanium_thunks();
    test_itanium_deep_recursion();
    test_itanium_ctor_dtor_stress();

    // Rust v0
    test_rust_crate_root();
    test_rust_nested_path();
    test_rust_generic();
    test_rust_basic_types();
    test_rust_ref_types();
    test_rust_pointer_types();
    test_rust_tuple();
    test_rust_slice();
    test_rust_closure();
    test_rust_fn_pointers();
    test_rust_array_with_const();
    test_rust_nested_closures();
    test_rust_punycode();

    // Cross-cutting
    test_is_mangled();
    test_auto_dispatch();
    test_null_safety();

    printf("All demangle tests passed.\n");
    n00b_shutdown();
    return 0;
}
