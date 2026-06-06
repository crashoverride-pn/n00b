# n00b Best Practices

A practical guide for contributors working on libn00b and ncc.  Covers the
build workflow, ncc language extensions, C23 idioms, memory ownership,
API design, error handling, and testing.

---

## Building

**Never run `meson setup` directly on the top-level project.**  The build
script performs a two-phase build (bootstrap compiler, then the main library)
and passes options that `meson setup` alone will not have.

```bash
# Normal build:
bash build.sh

# Build and run the default test set:
N00B_TEST=1 bash build.sh

# Clean rebuild with the default test set:
N00B_CLEAN=1 N00B_TEST=1 bash build.sh

# Include tests tagged long:
bash build.sh --all-tests

# After an initial build, rebuild individual targets:
meson compile -C build_debug test_buffer

# Run a specific test (after initial build):
meson test -C build_debug --print-errorlogs buffer
```

The default `N00B_TEST=1` path skips Meson tests tagged `long`.
Use `bash build.sh --all-tests` or `N00B_TEST_ALL=1 N00B_TEST=1 bash build.sh`
before merging broad changes, release candidates, or changes that touch a
long-test area directly.  Targeted test runs are not filtered, so
`N00B_TEST=1 N00B_TESTS=regex_engine bash build.sh` still runs that test.

If you change anything under `bootstrap/`, you must force a bootstrap
rebuild:

```bash
N00B_BUILD_BOOTSTRAP=1 bash build.sh
```

### Build options (`meson.options`)

| Option | Type | Default | Purpose |
|--------|------|---------|---------|
| `dev_mode` | boolean | false | Enables `N00B_DEV` define for diagnostic routines |
| `enable_debug` | boolean | false | Enables `N00B_DEBUG` for debug logging |
| `use_memcheck` | combo | `off` | Lightweight heap checks (`off` / `on` / `strict`) |
| `use_asan` | boolean | false | Address sanitizer |
| `use_ubsan` | boolean | false | Undefined behavior sanitizer |
| `show_gc_stats` | boolean | false | GC statistics output |
| `enable_lto` | boolean | false | Link-time optimization |

### Bootstrap compiler only

```bash
cd bootstrap
meson setup builddir      # first time only
meson compile -C builddir
```

See `docs/ncc.md` for bootstrap diagnostic flags (`NCC_PARSER_STATS`, etc.)
and the full compilation pipeline.

---

## NCC language extensions

ncc is a source-to-source C compiler that adds several extensions via AST
transforms.  The two you will use most often are **keyword arguments** and
**checked variadics**.

### Keyword arguments (`_kargs`)

#### What they are

Keyword arguments let a function declare optional, named parameters with
default values.  Callers pass them using designated-initializer syntax.
ncc rewrites both the declaration and every call site so that the defaults
are filled in automatically.

#### Declaring a function with keyword arguments

Place a `_kargs` block after the closing parenthesis of the parameter list.
The block declares variables with their default values.  End the block with
a semicolon in header declarations, or follow it with the function body in
implementations:

```c
// Header (declaration):
n00b_string_t n00b_unicode_str_pad(n00b_string_t s, int32_t width)
    _kargs {
        int              align     = N00B_STR_ALIGN_LEFT;
        n00b_allocator_t *allocator = nullptr;
        n00b_codepoint_t  fill      = ' ';
    };

// Implementation:
n00b_string_t
n00b_unicode_str_pad(n00b_string_t s, int32_t width)
    _kargs {
        int              align     = N00B_STR_ALIGN_LEFT;
        n00b_allocator_t *allocator = nullptr;
        n00b_codepoint_t  fill      = ' ';
    }
{
    // `align`, `allocator`, and `fill` are in scope as local variables.
    // If the caller didn't pass them, they have their default values.
    if (!allocator) {
        allocator = n00b_get_default_allocator();
    }
    // ...
}
```

#### Calling a function with keyword arguments

Pass keyword arguments after the positional arguments using
`.name = value` syntax.  Omit any keywords you don't need &mdash; the
defaults apply:

```c
// All defaults (left-aligned):
n00b_unicode_str_pad(s, 40);

// Override fill character:
n00b_unicode_str_pad(s, 40, .fill = '.');

// Override alignment and allocator:
n00b_unicode_str_pad(s, 40, .align = N00B_STR_ALIGN_CENTER, .allocator = arena);
```

#### When to use keyword arguments

Use `_kargs` when a function has **optional parameters with sensible
defaults** that most callers will not need to change.  The canonical
example is `.allocator` &mdash; nearly every allocating function accepts
one, but most callers are happy with the default.

Good candidates for keyword arguments:

- **Allocator selection** (`.allocator`)
- **Behavioral options** (`.locale`, `.no_hard_wrap`, `.ellipsis`)
- **Numeric defaults** (`.width = 80`, `.hang = 0`)
- **Configuration flags** that are usually false

Avoid keyword arguments for **required** parameters that have no meaningful
default.  If the caller must always provide a value, make it a positional
parameter.

#### Documenting keyword arguments

In Doxygen comments, use `@kw` instead of `@param`:

```c
/** @brief Pad a string on the right.
 *  @param s      The string to pad.
 *  @param width  Target display width in columns.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @kw fill       Fill codepoint (default: space U+0020).
 */
```

### Checked variadics (`+`)

#### What they are

ncc's `+` replaces C's `...` with a type-safe, countable variadic
mechanism.  When ncc sees `+` in a parameter list, it:

1. Rewrites the declaration to take `n00b_vargs_t *vargs` as the last
   parameter.
2. At each call site, packs the variadic arguments into a compound
   literal `n00b_vargs_t` and passes a pointer to it.

The result is that the callee can iterate over arguments with a known
count, rather than relying on sentinels or format strings.

#### Declaring a variadic function

```c
// Header:
n00b_string_t n00b_format(n00b_string_t desc, +);

// Implementation:
n00b_string_t
n00b_format(n00b_string_t desc, +)
{
    // `vargs` is implicitly in scope as `n00b_vargs_t *`.
    // ncc provides it automatically.
    for (unsigned int i = 0; i < vargs->nargs; i++) {
        void *arg = vargs->args[i];
        // ...
    }
}
```

#### Calling a variadic function

Pass extra arguments after the positional ones.  ncc packs them
automatically:

```c
int64_t count = 42;
n00b_string_t name = STR("world");

n00b_string_t s = n00b_cformat("[|b|]Hello[|/b|] [|#|], count = [|#:,d|]",
                                &name, &count);
```

If there are no variadic arguments, just call with the positional ones:

```c
n00b_string_t s = n00b_cformat("no substitutions here");
```

#### Accessing variadic arguments

Inside the implementation, use the `n00b_vargs_t` API:

```c
// Number of remaining arguments:
unsigned int remaining = n00b_remaining_vargs(vargs);

// Get next argument (advances cursor):
void *arg = n00b_vargs_next(vargs);

// Peek without advancing:
void *arg = n00b_vargs_peek(vargs);

// Rewind to re-iterate:
n00b_vargs_rewind(vargs);
```

All arguments arrive as `void *`.  Cast to the expected type:

```c
int64_t n = (int64_t)n00b_vargs_next(vargs);           // integer
n00b_string_t *sp = (n00b_string_t *)n00b_vargs_next(vargs);  // pointer
double *dp = (double *)n00b_vargs_next(vargs);          // double by pointer
```

#### Passing vargs to helpers

ncc only treats functions declared with `+` as variadic.  An explicit
`n00b_vargs_t *` parameter is **not** auto-detected — you can safely
pass vargs through to internal helpers:

```c
// This is fine — ncc sees no `+`, so it doesn't transform calls.
static n00b_string_t
do_format_inner(const char *desc, n00b_vargs_t *vargs)
{
    // work with vargs directly
}

n00b_string_t
n00b_format(n00b_string_t desc, +)
{
    return do_format_inner(desc.data, vargs);  // safe
}
```

Only the outermost user-facing function should use `+`.

#### When to use checked variadics

Use `+` when a function genuinely needs a **variable number of same-typed
arguments** that are processed uniformly.  Good examples:

- `n00b_format()` &mdash; N substitution arguments
- `n00b_cp_query()` &mdash; N filter predicates

Do **not** use `+` as a substitute for keyword arguments.  If the extra
parameters are named options with defaults, use `_kargs` instead.  If the
parameters are a fixed set with different types, use normal positional
parameters.

### Other extensions (brief reference)

| Extension | Syntax | Use |
|-----------|--------|-----|
| `typeid()` | `typeid("prefix", T, ...)` | Generates unique struct names for generic types |
| `typestr()` | `typestr(T)` | String literal of the encoded type ID |
| `r"..."` | `r"«b»bold«/b»"` | Compile-time rich text literals (see `docs/strings.md`) |
| `!` (postfix) | `expr!` | Early return on error (like Rust's `?`) |
| `constexpr_eval()` | `constexpr_eval(N + 1)` | Compile-time integer arithmetic |
| `constexpr_paste()` | `constexpr_paste("prefix_", N)` | Compile-time identifier concatenation |

---

## C23 and GCC extensions

n00b targets **C23** (`-std=c23`) and relies on several GCC/Clang
extensions.  This section covers the idioms you should use and the
old-C patterns they replace.

### `nullptr` (not `NULL`)

Always use `nullptr` for null pointers.  Never use `NULL`, `0`, or
`(void *)0`:

```c
// Good:
n00b_allocator_t *allocator = nullptr;
if (ptr == nullptr) { ... }

// Bad:
n00b_allocator_t *allocator = NULL;
if (ptr == 0) { ... }
```

`nullptr` has type `nullptr_t` and converts to any pointer type without a
cast.  Unlike `NULL` (which is `(void *)0` or just `0` depending on the
implementation), it cannot accidentally be used as an integer.

### `auto` for type inference

C23's `auto` deduces the type from the initializer.  Use it when the
type is obvious from the right-hand side or when the full type is
excessively verbose:

```c
// Result types — the full type is long and redundant:
auto r = n00b_check_mmap(nullptr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANON, -1, 0);
if (n00b_result_is_err(r)) { ... }
void *ptr = n00b_result_get(r);

// Option types:
auto pos = n00b_unicode_str_find(haystack, needle);
if (n00b_option_is_set(pos)) { ... }

// Tree operations (the generic type is very long):
auto child = n00b_tree_add_node(parent, n00b_md_node_t, n00b_md_node_t, node);
```

Do **not** use `auto` when the type is not obvious from context:

```c
// Bad — what type is this?
auto x = compute_something();

// Good — be explicit when the initializer doesn't make the type clear:
int32_t offset = compute_something();
```

### `typeof` in macros

`typeof` (standardized in C23, long available as a GCC extension) is
essential for writing type-safe generic macros:

```c
// Clone any array without naming the type:
#define n00b_array_clone(x)              \
    ({                                   \
        typeof(x) _bl_copy = ...;        \
        memcpy(_bl_copy.data, ...);      \
        _bl_copy;                        \
    })

// Zero-initialize any container:
*_bl_lp = (typeof(x)){};
```

### Empty initializers `{}`

C23 allows `{}` as a universal zero-initializer for any type.  Use it
instead of `{0}` or `memset`:

```c
// Good:
line_ctx_t lc = {};
n00b_option_t(size_t) none = {};

// Older style (still works, but {} is cleaner):
line_ctx_t lc = {0};
```

### Compound literals

Compound literals create anonymous, temporary values inline.  They are
heavily used throughout the codebase for struct initialization, passing
temporaries to functions, and in macros:

```c
// Inline struct creation:
n00b_layout_dim_t dim = (n00b_layout_dim_t){
    .value.i = 20,
    .pct     = false,
};

// Passing a temporary to a function:
n00b_ansi_parse(ctx, &(n00b_buffer_t){ .data = raw, .len = len });

// In option/result constructors (these are compound-literal macros):
return n00b_option_set(int32_t, 42);
// expands to: ((n00b_option_t(int32_t)){ .has_value = true, .value = 42 })
```

Compound literals declared inside a function have automatic storage
duration (they live on the stack for the enclosing block).  Don't return
pointers to them.

### Statement expressions `({ ... })` (GCC extension)

Statement expressions allow a block of statements to produce a value.
Nearly all n00b macros use them:

```c
#define n00b_array_get(x, i)      \
    (*(({                          \
        size_t _bl_i = (i);        \
        if (_bl_i >= (x).len) {    \
            abort();               \
        }                          \
        &(x).data[_bl_i];         \
    })))
```

Key rules for statement expressions in n00b macros:

- Use `_bl_` prefix for all local variables to avoid shadowing.
- The last expression in the block is the value of the whole expression.
- Evaluate macro arguments exactly once by capturing them in locals.

### `_BitInt(N)`

C23 introduces arbitrary-width integers.  n00b uses `_BitInt(128)` for
wide hash values:

```c
typedef unsigned _BitInt(128) n00b_uint128_t;
```

### `_Atomic`

C23 standardizes atomic types.  Use `_Atomic` for any field accessed from
multiple threads:

```c
typedef _Atomic(uint32_t) n00b_futex_t;
typedef _Atomic(uint32_t) n00b_spin_lock_t;

// In struct definitions:
_Atomic(n00b_allocator_t *) default_allocator;
_Atomic int64_t             tid_lock;
```

### `_Alignas`

Use `_Alignas` when a field or buffer requires specific alignment:

```c
typedef struct {
    _Alignas(N00B_ALIGN) char mem[];   // Aligned flexible array
} n00b_arena_segment_t;

typedef struct {
    _Alignas(max_align_t) char _data[...];  // Maximally aligned storage
} n00b_variant_t;
```

### `[[attribute]]` syntax (not `__attribute__`)

C23 standardizes the `[[...]]` attribute syntax.  Always prefer it over
the legacy GCC `__attribute__((...))` form:

```c
// C23 standard attributes:
[[nodiscard]] n00b_alloc_t *n00b_arena_alloc(...);
[[noreturn]] void compiler_passthrough(int argc, char **argv);
[[maybe_unused]] char *envp[];
[[fallthrough]];   // in switch cases
[[deprecated("use n00b_foo_v2 instead")]] void n00b_foo(void);
```

GNU-specific attributes use the `[[gnu::name]]` prefix:

```c
[[gnu::constructor]]            // module initializer (runs before main)
static void setup_extensions(void) { ... }

[[gnu::noinline]]               // prevent inlining
static void *node_alloc(size_t sz) { ... }

[[gnu::packed]]                 // packed struct layout
typedef struct { ... } wire_msg_t;
```

**Gotcha:** Some attributes (like `constructor` and `destructor`) are not
part of the C23 standard and *must* have the `gnu::` prefix.  Writing
`[[constructor]]` is a compilation error &mdash; you need
`[[gnu::constructor]]`.

ncc includes an automatic modernization pass that rewrites common
`__attribute__` forms to `[[...]]` syntax during preprocessing, but new
code should use the modern syntax directly.

### `__VA_OPT__` in variadic macros

C23's `__VA_OPT__` replaces the old `##__VA_ARGS__` trick for
conditionally including tokens when variadic arguments are present:

```c
// Thread an optional allocator through to n00b_alloc:
#define n00b_array_new(T, N, ...)                              \
    ({                                                         \
        (n00b_array_t(T)){                                     \
            .len  = 0,                                         \
            .cap  = N,                                         \
            .data = n00b_alloc(N * sizeof(T)                   \
                        __VA_OPT__(, .allocator = __VA_ARGS__)), \
            __VA_OPT__(.allocator = __VA_ARGS__,)              \
        };                                                     \
    })
```

### `[[gnu::cleanup(fn)]]` (GCC extension)

The `cleanup` attribute calls a function when a variable goes out of
scope &mdash; C's closest analog to RAII.  Used in the iteration macros
to ensure iterators are freed even on `break` or early `return`:

```c
// From unicode/iter.h:
#define n00b_unicode_foreach_grapheme(s, var)                          \
    for ([[gnu::cleanup(n00b_unicode_seg_iter_cleanup)]]                \
         n00b_unicode_break_iter_t *_it = n00b_unicode_grapheme_iter(*(s)); \
         /* ... */ )
```

This is a GCC extension (not C23 standard), but is supported by both
GCC and Clang.  Use `[[gnu::cleanup(fn)]]`, not
`__attribute__((cleanup(fn)))`.

### `__builtin_unreachable()` (GCC built-in)

Mark branches that should never be reached.  The compiler uses this for
optimization and warnings:

```c
switch (spec->type) {
case 'd': ...
case 'x': ...
default:
    __builtin_unreachable();
}
```

### Quick reference: old idioms to avoid

| Old idiom | Preferred n00b idiom |
|-----------|---------------------|
| `NULL` | `nullptr` |
| `{0}` for zero-init | `{}` |
| `##__VA_ARGS__` | `__VA_OPT__(, __VA_ARGS__)` |
| `__typeof__` | `typeof` |
| `__attribute__((noreturn))` | `[[noreturn]]` |
| `__attribute__((unused))` | `[[maybe_unused]]` |
| `__attribute__((constructor))` | `[[gnu::constructor]]` |
| `__attribute__((cleanup(fn)))` | `[[gnu::cleanup(fn)]]` |
| Explicit type on obvious initializations | `auto` |
| `memset(x, 0, sizeof(*x))` | `*x = (typeof(*x)){}` |

---

## Memory ownership

### The golden rule: code as if there is no GC

n00b has a garbage collector, and it is the default memory management
strategy.  **But you should always write code as if the GC does not
exist.**

This means:

1. **Every allocation has a clear owner.**  At any point in the program,
   exactly one entity &mdash; a struct, a function, a module &mdash; is
   responsible for each allocation.

2. **Owners free what they own.**  When a module is done with memory it
   allocated, it calls `n00b_free()`.  Don't rely on the GC to clean up
   after you.

3. **Ownership transfers are explicit.**  If a function takes ownership of
   a pointer, document it.  If a function borrows a pointer, document that
   the caller retains ownership.

4. **Avoid shared ownership.**  If two things need the same data, prefer
   copying over sharing.  When sharing is necessary, document the lifetime
   constraints.

The GC exists as a safety net for cycles and for situations where precise
ownership is impractical (e.g., complex graph structures).  It is not an
excuse to stop thinking about lifetimes.

### Why this matters

n00b is designed to work in environments with and without a GC.  Users may
disable the GC, use custom allocators, embed libn00b in a larger system
with its own memory strategy, or run in constrained environments where
non-deterministic collection is unacceptable.  If the library only works
correctly with the GC on, it is broken.

### Practical ownership patterns

#### Pattern 1: The function owns what it allocates

The simplest case.  A function allocates memory, uses it, and frees it
before returning:

```c
n00b_string_t
format_greeting(n00b_string_t name)
{
    n00b_text_style_t *bold = n00b_str_style_new();
    bold->bold = N00B_TRI_YES;

    n00b_string_t result = n00b_str_add_style(name, bold, 0,
                                                n00b_option_none(size_t));
    n00b_free(bold);
    return result;
}
```

#### Pattern 2: Caller owns the return value

Functions that return newly allocated memory transfer ownership to the
caller.  Document this in the header:

```c
/** @return Heap-allocated style.
 *  @post Caller must free with `n00b_free()`.
 */
n00b_text_style_t *n00b_str_style_new(...);
```

#### Pattern 3: Container takes ownership of contents

When you push a value into a container (list, tree, etc.), the container
may reallocate or free the underlying storage.  **Never assume a pointer
you handed to a container is still valid after a mutating operation.**

This is a critical case.  Consider:

```c
n00b_list_t(int) list = n00b_list_new(int);
n00b_list_push(list, 42);
n00b_list_push(list, 43);  // May reallocate — old .data pointer is invalid!
```

If you give a function both an `n00b_array_t` and an `n00b_list_t` that
share the same backing pointer, and the function resizes the list, it will
free the array's data out from under it.  **Don't alias backing pointers
across containers.**

For APIs that convert between container types (e.g., `n00b_list_to_array`),
document the ownership transfer:

```c
/** @brief Move list contents into an array.
 *  @post The source list is zeroed (data pointer moved, not copied).
 */
#define n00b_list_to_array(T, x) ...
```

#### Pattern 4: Borrowed pointers

When a function takes a pointer it does not own, document the borrowing
relationship:

```c
/** @brief Feed a buffer of bytes to the parser.
 *  @param buf  Input buffer (not modified; data must remain valid
 *              until `n00b_ansi_parser_results()` is called).
 */
void n00b_ansi_parse(n00b_ansi_ctx *ctx, n00b_buffer_t *buf);
```

#### Pattern 5: Static data (no ownership)

Rich text literals (`r"..."`) return pointers to static data.  Never free
them:

```c
n00b_string_t *msg = r"«b»Hello«/b»";  // Static — do not free.
```

### Providing allocator flexibility

Most allocating functions should accept an optional `.allocator` keyword
argument so that callers can direct allocations to a specific arena, pool,
or custom allocator:

```c
n00b_string_t n00b_unicode_str_cat(n00b_string_t a, n00b_string_t b)
    _kargs { n00b_allocator_t *allocator = nullptr; };
```

When `allocator` is `nullptr`, use the default runtime allocator.  This
pattern gives non-GC users the ability to manage memory precisely without
changing the API surface.

For modules that allocate multiple internal structures, thread the
allocator through to all internal allocations:

```c
n00b_buffer_t *buf = n00b_alloc(n00b_buffer_t, .allocator = allocator);
buf->data = n00b_alloc_array(char, capacity, .allocator = allocator);
```

When a different lifetime strategy is needed &mdash; for example, a caller
who wants to free a returned container but keep the elements alive &mdash;
consider providing an alternate API or a keyword that controls the
behavior, rather than forcing one policy.

### Allocation API

Always use the highest-level allocation macro available:

| Macro | Purpose |
|-------|---------|
| `n00b_alloc(T, ...)` | Allocate a single `T` |
| `n00b_alloc_array(T, n, ...)` | Allocate an array of `n` `T`s |
| `n00b_alloc_flex(T1, T2, n, ...)` | Allocate `T1` with trailing `T2[n]` |
| `n00b_alloc_size(n, sz, ...)` | Raw size allocation (avoid if possible) |
| `n00b_free(ptr)` | Free any allocation |

All allocation macros accept `.allocator` and `.no_scan` as keyword
arguments.  Every call automatically embeds `__FILE__:__LINE__` for
debugging.

**Never call `_n00b_alloc_raw()` or any `_n00b_`-prefixed function
directly.**  The underscore prefix signals an internal implementation
detail; the public macros provide type safety, source locations, and
correct argument marshaling.

---

## Public API design

### Pointers are references, not wrappers

Bare pointers are allowed in the public API, but **only to denote
references** &mdash; borrowing or ownership of a single object.  A `T *`
in a function signature means "a reference to a `T`", not "a `T` that
might be absent" or "an array of `T`s of unknown length."

Each type should be **consistently** passed one way:

- **Small structs** (like `n00b_string_t`, `n00b_option_t`, style records)
  are passed and returned **by value**.
- **Large structs** or opaque handles (like `n00b_ansi_ctx`,
  `n00b_text_style_t`, tree nodes) are passed **by reference** (`T *`).

Pick one convention per type and stick with it across the entire API.

When a pointer would be overloaded to mean something beyond "reference to
one `T`", use the appropriate type-safe wrapper instead:

| Instead of... | Use... |
|--------------|--------|
| `T *` that might be NULL on error | `n00b_result_t(T)` |
| `T *` that might be NULL for "absent" | `n00b_option_t(T)` |
| `T *` + separate `int count` pair | `n00b_array_t(T)` |
| Bare `char *` for string data | `n00b_string_t` |

This applies to all new and migrated code.

### Type-safe containers

All generic containers follow the same pattern:

```c
// 1. Declare the type (once, in a header):
n00b_list_decl(int);

// 2. Create an instance:
n00b_list_t(int) list = n00b_list_new(int);

// 3. Use it:
n00b_list_push(list, 42);
int x = n00b_list_get(list, 0);

// 4. Free it:
n00b_list_free(list);
```

The `*_decl()` macro expands a struct with a `typeid()`-based name.  Each
unique type combination gets its own struct &mdash; this is how type safety
is enforced at compile time without true generics.

Available containers:

| Type | Purpose |
|------|---------|
| `n00b_list_t(T)` | Growable list with spinlock |
| `n00b_stack_t(T)` | LIFO stack |
| `n00b_array_t(T)` | Fixed-capacity array |
| `n00b_tree_t(N, L)` | N-ary tree (node type, leaf type) |
| `n00b_variant_t(T1, T2, ...)` | Tagged union |
| `n00b_tuple_decl(T1, T2, ...)` | Heterogeneous tuple |
| `n00b_option_t(T)` | Optional value |
| `n00b_result_t(T)` | Success or error |

---

## Error handling

### `n00b_result_t(T)` for fallible operations

Use `n00b_result_t(T)` when a function can fail.  The result is either an
`ok` value of type `T` or an error carrier. Most APIs should use integer
code errors (`n00b_err_t`, which is `int`, typically `errno`) for simple,
portable failures:

```c
// Returning success:
return n00b_result_ok(n00b_string_t, my_string);

// Returning failure:
return n00b_result_err(n00b_string_t, ENOMEM);

// Checking at the call site:
n00b_result_t(n00b_string_t) r = n00b_unicode_str_from_file(path);

if (n00b_result_is_ok(r)) {
    n00b_string_t contents = n00b_result_get(r);
    // ...
}
else {
    n00b_err_t err = n00b_result_get_err(r);
    // handle error
}

// Or use get_or_else for a default:
n00b_string_t contents = n00b_result_get_or_else(r, empty_string);
```

Use structured payload errors when callers need more than an integer code:
for example, several fields of diagnostic context, a parse failure object, or
an error produced by a lower layer that should propagate intact. Structured
payload helpers carry pointer payloads only; the pointer is tagged with
`typehash(E)`.

```c
typedef struct parse_error parse_error_t;
typedef struct ast_node ast_node_t;

return n00b_result_err_payload(ast_node_t *, parse_error_t *, err);

if (n00b_result_is_err_payload(parse_error_t *, r)) {
    parse_error_t *err = n00b_result_get_err_payload(parse_error_t *, r);
    // handle structured error
}
```

`n00b_result_get_error(r)` returns the raw carrier for forwarding or generic
inspection and asserts if the result is ok. `n00b_result_get_err(r)` is only
for integer-code errors and asserts if the result is ok or carries a
structured payload. Likewise, `n00b_result_get_err_payload(E, r)` asserts if
the result is ok, is not a payload error, or the stored payload tag does not
match `typehash(E)`.

POSIX wrappers produce results automatically:

```c
n00b_result_t(void *) r = n00b_check_mmap(NULL, size, PROT, FLAGS, -1, 0);
n00b_result_t(int)    r = n00b_check_posix(getrlimit(RLIMIT_NOFILE, &rl));
```

### `n00b_option_t(T)` for optional values

Use `n00b_option_t(T)` when a value may be absent (but absence is not an
error):

```c
// Returning a present value:
return n00b_option_set(int32_t, byte_offset);

// Returning absence:
return n00b_option_none(int32_t);

// Checking at the call site:
n00b_unicode_opt_i32_t pos = n00b_unicode_str_find(haystack, needle);

if (n00b_option_is_set(pos)) {
    int32_t offset = n00b_option_get(pos);
    // ...
}

// Or with a default:
int32_t offset = n00b_option_get_or_else(pos, -1);
```

### Error propagation (`!`)

ncc's postfix `!` operator works like Rust's `?` &mdash; it unwraps a
result on success or returns early with the error carrier:

```c
n00b_result_t(n00b_string_t)
read_and_process(const char *path)
{
    // If from_file fails, this function returns its error immediately.
    n00b_string_t contents = n00b_unicode_str_from_file(path)!;

    // Only reached on success.
    return n00b_result_ok(n00b_string_t, process(contents));
}
```

The propagated carrier is unchanged, so integer-code errors and structured
payload errors can cross result ok types without caller-side conversion.

---

## Documentation

### Where to document

- **Headers only.**  Doxygen comments go in header files.  Source files
  should have comments where the logic is non-obvious, but not Doxygen
  annotations.
- **`@file` block** at the top of every header with `@brief`, a description
  of the module's purpose, and a "Related modules" section linking to
  collaborating headers.
- **Omit trivial descriptions.**  If a function's purpose is obvious from
  its name and parameters, don't add a redundant `@brief`.

### Keyword argument documentation

Use `@kw`, not `@param`, for keyword arguments:

```c
/** @brief Pad a string on the right.
 *  @param s      The string to pad.
 *  @param width  Target display width in columns.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @kw fill       Fill codepoint (default: space U+0020).
 *  @return A new left-aligned string padded to @p width columns.
 */
```

### Preconditions and postconditions

Add `@pre` and `@post` wherever they are meaningful:

```c
/** @brief Merge two styles.
 *  @pre @p base and @p overlay are non-NULL.
 *  @post Returned style is independent of both inputs.
 */
```

### Ownership documentation

Always document who owns returned memory and borrowed pointers:

```c
/** @return Parsed descriptor (owned by cache; do not free). */
/** @post Caller must free with `n00b_free()`. */
/** @param buf  Input buffer (borrowed; must remain valid until ...). */
```

---

## Testing

### Test file template

Each test is a standalone executable using `assert()` + `printf`.  No
external test framework at this point (Claude likes writing tests for you):

```c
#include "test_helpers.h"  // or appropriate test header

TEST(test_something)
{
    // setup
    n00b_string_t s = STR("hello");

    // assert
    ASSERT_EQ(s.u8_bytes, 5);
    ASSERT_STR_EQ(s.data, "hello");

    // teardown (if needed)
}

static void
run_tests(void)
{
    RUN_TEST(test_something);
}

TEST_MAIN()
```

### Adding a test

1. Create `test/unit/test_<name>.c`
2. Add to `meson.build`:
   ```meson
   <name>_test = executable('test_<name>',
       ['test/unit/test_<name>.c'],
       kwargs: test_common_kwargs,
   )
   test('<name>', <name>_test, suite: 'unit')
   ```
3. Verify: `N00B_TEST=1 bash build.sh`

### What to test

- Every public API function should have at least basic coverage.
- Edge cases: empty strings, zero-length arrays, NULL inputs (where
  applicable), boundary values.
- Error paths: verify that fallible functions return proper
  `n00b_result_err` on failure.
- Ownership: if a function transfers ownership, verify the caller can
  free the result without double-free.

---

## Code style quick reference

| Rule | Example |
|------|---------|
| 4-space indent, no tabs | `    if (x) {` |
| Column limit: 96 | |
| Return type on own line (definitions) | `static void`<br>`my_function(...)` |
| K&R braces (functions on new line) | `{` on next line for functions |
| Pointer alignment: right | `char *x`, not `char* x` |
| `n00b_` prefix for public API | `n00b_list_push()` |
| `_n00b_` prefix for internals | `_n00b_alloc_raw()` |
| `N00B_` for constants/macros | `N00B_THREADS_MAX` |
| `_bl_` for block-local temporaries | `_bl_r`, `_bl_nc` |
| `#pragma once` (never include guards) | |

---

## Other key notes

- The bootstrap compiler, if it fails to parse code with its extended
  grammar, will not currently give a useful error message. If it's not
  yet using extensions, run w/ the regular C compiler. Or else, bisect
  the function to isolate the compile issue.

  Generally, since the parser backtracks, the failure to parse is in
  the non-terminal unit that STARTS where the failure is imported.

- **`typeid()` produces base-64 encoded SHA256 hashes.**  Struct names in error messages
  will be long hex strings &mdash; this is expected.
  - **Warnings should be fixed, not suppressed.**  Don't add `-Wno-*` flags
  to the build; fix the underlying code.
