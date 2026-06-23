# ncc &mdash; The n00b C Compiler

## Overview

ncc is a **source-to-source C compiler** that wraps an underlying C compiler
(typically clang) and adds language extensions via AST transformations. It
targets **C23** and is designed to make C code safer and more ergonomic without
leaving the language.

The compiler lives in `bootstrap/` and is built first during the project build
as `ncc-bootstrap`. The main library (`libn00b`) is then compiled using
ncc-bootstrap as its C compiler, so that headers and source files can freely
use ncc extensions.

### Design philosophy

- **Zero runtime cost at the call site.** Every extension compiles down to
  standard C23 &mdash; no interpreter, no bytecode, no hidden allocations
  at call sites beyond what the generated code explicitly shows.
- **Transparent output.** Run with `-E` to see exactly what ncc produces
  before handing it to clang. There is no magic.
- **Incremental adoption.** Files without ncc extensions pass through
  unchanged. The `--no-ncc` flag bypasses the entire pipeline for files
  that need maximum compile speed (e.g., large generated tables).

---

## Compilation Pipeline

```
Source file (.c)
    │
    ▼
┌──────────────────────┐
│ 1. Rich string scan  │  r"«b»text«/b»" → __ncc_rstr("«b»text«/b»")
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 2. C preprocessor    │  clang -E (via pipe)
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 3. Lexer             │  ~170 keywords, all C23 + ncc extensions
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 4. Packrat parser    │  Full C23 grammar + ncc productions
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 5. Tree flattening   │  Collapse recursive-descent chains
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 6. Semantic xforms   │  11 ordered transform passes (see below)
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 7. Emit              │  Reconstruct C source from transformed AST
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 8. Compile           │  Pipe to clang (or $NCC_COMPILER)
└──────────────────────┘
```

**Early-exit modes:**

| Flag | Exits after | Output |
|------|-------------|--------|
| `-E -E` | Step 2 | Raw preprocessor output |
| `--dump-tokens` | Step 3 | Token list |
| `-E` | Step 7 | NCC-transformed C source |
| `--no-ncc` | &mdash; | Bypasses pipeline entirely; raw `execvp` to compiler |

---

## Language Extensions

### `typeid()` &mdash; Type-Based Identifiers

**Status: Complete, heavily used throughout the codebase.**

```c
typeid("n00b_list", int)          // → n00b_list_a1b2c3d4e5f6...
typeid("n00b_tree", node_t, int)  // → n00b_tree_f7e8d9c0b1a2...
```

Generates a unique C identifier from a prefix and one or more type arguments.
The identifier is deterministic (SHA256-based), so the same type combination
always produces the same name. This is the foundation of the generic container
system &mdash; each instantiation of `n00b_list_t(T)` expands to a struct whose
name includes a `typeid()`.

**How it works:** Type arguments are normalized to a canonical string form,
concatenated, hashed, and truncated to produce a valid C identifier. The
normalization preserves source-level type names (i.e., `int` stays `int`, not
`int32_t`; typedefs are not resolved).

### `typestr()` &mdash; Type-to-String

**Status: Complete.**

```c
typestr(int)                      // → "int"
typestr(n00b_list_t(int))         // → "n00b_list_t(int)"
```

Produces a string literal encoding the type. Mirrors `typeid()` but returns a
`const char *` instead of an identifier. Useful for runtime type introspection
and error messages.

### `typehash()` GC Type Maps

**Status: Complete for supported n00b allocation layouts.**

ncc lowers `typehash(T *)` to a stable integer literal. In n00b-integrated
builds, eligible `typehash(T *)` sites also cause ncc to emit link-time GC
layout metadata for `T`. n00b allocation macros use that same hash, so
`n00b_alloc(T)` and `n00b_alloc_array(T, N)` can be upgraded from conservative
default scanning to exact callback scanning after the final binary is indexed.

The post-link command is `n00b-gcmap-index`. See
[`docs/gc_type_maps.md`](gc_type_maps.md) for the n00b build and runtime
contract, and `docs/gc_typemaps.md` in the ncc repository for ncc's eligibility
rules.

### `constexpr_eval()` / `constexpr_max()` / `constexpr_min()`

**Status: Complete.**

```c
constexpr_eval(sizeof(foo_t) + 7)          // → integer literal
constexpr_max(sizeof(a_t), sizeof(b_t))    // → larger of the two
constexpr_min(4, constexpr_eval(N * 2))    // → nesting supported
```

Compile-time integer expression evaluation. ncc extracts the expression, emits
a tiny C program that prints its value, compiles and runs it with the
underlying compiler, and splices the result back as an integer literal.

**Implementation note:** Each evaluation forks a subprocess. There is no
cross-expression caching, so heavy use in hot headers can add compile time.
The parenthesized counter expressions from `N00B_MAP_COUNT` (e.g., `((0) + 1)`)
are handled correctly via nested evaluation.

### `constexpr_paste()`

**Status: Complete.**

```c
constexpr_paste("field_", 3)     // → field_3
constexpr_paste("n00b_", "list") // → n00b_list
```

Compile-time identifier concatenation. Evaluates its arguments and pastes them
into a single identifier token. Often appears inside `typeid()`-generated code.

### `_kargs` &mdash; Keyword Arguments

**Status: Complete, heavily used throughout the codebase.**

```c
// Definition:
void
n00b_list_push(n00b_list_t(void *) list, void *item)
    _kargs { bool thread_safe = true; };

// Call sites:
n00b_list_push(my_list, ptr);                        // default: thread_safe=true
n00b_list_push(my_list, ptr, .thread_safe = false);  // override
```

Type-safe named optional parameters with defaults. The transform generates:

1. A **struct** (`_funcname__kargs`) containing each keyword parameter plus a
   bitfield indicating which fields were explicitly provided.
2. A **modified function signature** that takes a pointer to this struct as an
   additional parameter.
3. **Compound literals** at each call site, initialized with the provided
   keyword arguments.

This replaces the older `keywords { ... }` block syntax found in some ported
code. During migration, `keywords` blocks should be converted to `_kargs`.

#### Type Safety with `_kargs: opaque` and Generic APIs

`_kargs: opaque` declares a function that receives `void *kargs` &mdash; the
compiler does not generate a struct on the declaration side. The call site
still generates a `_<funcname>__kargs` struct, but the callee has no way to
know which concrete type was passed.

**This means opaque kargs cannot carry type-dependent fields.** If a generic
API (like conduit's read/write) must dispatch differently based on a payload
type `T`, use the **macro dispatch pattern** instead:

```c
// 1. Generate per-type functions via a macro:
#define MY_API_IMPL(T)                                      \
    static inline n00b_result_t(T)                          \
    _MY_API_FN(read, T)(my_topic_t(T) *topic)               \
        _kargs { int timeout_ms = 0; }                      \
    { /* type-safe implementation using T */ }

// 2. User-facing macro dispatches by type:
#define my_api_read(T, topic, ...) \
    _MY_API_FN(read, T)(topic, ##__VA_ARGS__)
```

Each `MY_API_IMPL(T)` instantiation gets its own `_kargs` struct (named by
the mangled function name), so the compiler sees the full type. The user
writes `my_api_read(my_payload_t, topic, .timeout_ms = 100)` and gets
compile-time type checking on both the topic and the keyword arguments.

This pattern is used throughout conduit: `N00B_CONDUIT_INBOX_IMPL(T)`,
`N00B_CONDUIT_SUBSCRIPTION_IMPL(T)`, `N00B_CONDUIT_TOPIC_IMPL(T)`,
`N00B_CONDUIT_RW_IMPL(T)`.

### Variadic `+` &mdash; Checked Variadics

**Status: Complete, heavily used throughout the codebase.**

```c
// Untyped variadics:
void log_msg(const char *fmt, +);

// Typed variadics (compile-time checked):
void sum_ints(int first, int +);

// Call sites:
log_msg("hello %s %d", name, count);
sum_ints(1, 2, 3, 4, 5);
```

Replaces C's `...` with a safer mechanism. The `+` parameter becomes a
`n00b_vargs_t *` containing an array of `void *` pointers and a count.
For **typed** variadics, `_Static_assert` checks are emitted at each call
site to verify that every argument is assignment-compatible with the declared
type.

> **Note:** ncc only transforms functions explicitly declared with `+`.
> A plain `n00b_vargs_t *` parameter is *not* auto-detected, so you can
> safely pass vargs through to internal helpers without double-wrapping.

### `!` &mdash; Error Propagation

**Status: Complete.**

```c
n00b_result_t(int) parse_number(const char *s);

n00b_result_t(int)
do_work(const char *input)
{
    int n = parse_number(input)!;  // early-return on error
    return n00b_result_ok(int, n * 2);
}
```

Postfix `!` on an expression returning `n00b_result_t(T)`. If the result
is an error, the enclosing function immediately returns with that result
error carrier. Otherwise, the `.ok` value is yielded. Analogous to Rust's
`?` operator.

The transform expands to a statement expression (`({ ... })`) that tests
`.is_ok` and either returns the error carrier or yields the success value.
Because the carrier is propagated unchanged, integer-code errors and
structured payload errors can cross result ok types without caller-side
conversion.

### `r"..."` &mdash; Rich String Literals

**Status: Complete. Will be used heavily throughout libn00b for styled text.**

```c
r"«b»bold text«/b» and «i»italic«/i»"
r"«@code»monospace via role«/»"
r"plain string, no markup"
```

Rich text strings with inline styling markup using guillemet delimiters
(`«` and `»`). The transform converts these into static `n00b_string_t`
compound literals with pre-parsed style information, so there is no
runtime parsing cost.

Generated static objects that need GC visibility should follow the stack-map
and static-descriptor runtime contract in
[`docs/gc_stack_maps.md`](gc_stack_maps.md). n00b builds pass descriptor
templates to ncc so r-string literals are emitted as descriptor-backed static
objects with matching scan metadata.

Descriptor-backed r-strings carry portable static identity for marshaled
static pointers. See [`docs/marshal.md`](marshal.md) for the source-semantic
identity model and `.namespace.toml` metadata file format.

**Supported markup:**

| Tag | Meaning |
|-----|---------|
| `«b»` | Bold |
| `«i»` | Italic |
| `«u»` | Underline |
| `«s»` | Strikethrough |
| `«em»` | Emphasis (resolved at render time) |
| `«strong»` | Strong (resolved at render time) |
| `«@name»` | Named role (resolved at render time) |
| `«/tag»` or `«/»` | Close tag |

Tags can nest. Roles (prefixed with `@`) and named styles like `«em»` are
**deferred** &mdash; they store a tag name that the rendering system resolves
at display time, enabling theme-aware styling.

### `b"..."` &mdash; Static Buffer Images

**Status: Supported through generalized static-init lowering.**

```c
const n00b_buffer_t *lit = b"payload";
```

The transform materializes the object as C declarations. For buffers, ncc emits
descriptor-backed static payload bytes, a readonly `n00b_buffer_t`, scan
metadata, dependency metadata, response metadata, and portable static identities
for both the object and payload ranges. No runtime constructor is called for the
generated static object, and no build-time helper subprocess is invoked.

Mutable block-scope targets are rejected; block-scope uses should target
`const` objects. The retired constructor-backed static-image surface has been
replaced by the literal route.

Generated static-image identities use the same `.namespace.toml` namespace
metadata as r-strings and array literals. Projects that exchange marshal
streams across compatible binaries should commit a project-specific
`.namespace.toml` rather than relying on the fallback `ncc.default` namespace.

### Static Container Literals

**Status: Arrays, lists, and dictionaries supported through generalized
static-init lowering.**

```c
n00b_array_t(int) numbers = a{1, 2, 3};
n00b_array_t(int) legacy = [4, 5, 6];
n00b_list_t(int)  values = l{7, 8, 9};
n00b_list_t(int) *ptr    = l{10, 11};
n00b_dict_t(int, int) counts = d{1: 10, 2: 20};
```

`a{...}` and bare `[...]` both initialize compatible array values. `l{...}`
initializes `n00b_list_t(T)` values or pointers to generated static list
objects. `d{...}` initializes compatible dictionary values. Arrays, lists, and
dictionaries are distinct literal targets; mismatched targets are compile-time
errors.

Nonempty array/list/dict literals are materialized by generalized static-init
lowering. ncc carries typed C initializer records, element type metadata,
target ABI facts, scan policy, descriptor attributes, and portable identity keys
into descriptor-backed static storage and returns the initializer expression.

Static list literals are locked by default. Generated code emits
descriptor-backed static lock storage, and static-object registration
initializes those lock ranges before mutation. List backing capacity follows the
normal list default: `max(pow2(len), N00B_DEFAULT_LIST_SZ)`.

Supported element values are static-initialization-safe scalars, pointers,
rich strings, `b"..."` buffer pointers where the element type is a compatible
buffer pointer, aggregate values with static layout, and nested supported
arrays, lists, and dictionaries. Arbitrary constructor-image object graphs
remain future work.

Block-scope mutable generated statics are rejected. Use `const` for local
array/list literal declarations or move mutable declarations to file scope.

### `once` &mdash; Single Initialization

**Status: Complete (prototype). Available but not used in this codebase.**

```c
once void
init_subsystem(void)
{
    // Runs exactly once, thread-safe via futex
}
```

Wraps a function so it executes at most once across all threads, using
futex-based synchronization. Subsequent calls are no-ops.

> **Why it is not used internally:** The n00b runtime centralizes all global
> state in `n00b_runtime_t`, and should not preclude multiple independent
> runtime instances within a single process. `once` functions create true
> process-global singletons, which conflicts with this design. The transform
> is retained for user code that genuinely needs single-init semantics.

### `@rpc("svc/method")` &mdash; QUIC RPC Annotation

**Status: Complete (Phase 4 § 4.5).  Used by the QUIC RPC layer.**

```c
extern n00b_result_t(GreetReply *)
greet_hello(GreetRequest *req, n00b_rpc_ctx_t *ctx)
    @rpc("greet.v1.Greeter/Hello");
```

Marks a C function as an RPC method.  ncc generates three sibling
external declarations per annotated function:

1. **Dispatcher** &mdash; decodes a CBOR request buffer, invokes the
   user handler, encodes the response.  `static`-scope helper named
   `_n00b_rpc_dispatch__<svc>__<method>`.  Emitted at the **definition**
   site only.
2. **Constructor** &mdash; runs at process start (via
   `__attribute__((constructor))`) and registers the dispatcher in
   the runtime registry via `n00b_rpc_register(...)`.  Emitted at
   the **definition** site only.
3. **Client stub** &mdash; the public callable.  Encodes the request
   to CBOR, dispatches via `n00b_rpc_call_unary` / `_server_stream`
   / `_client_stream` / `_bidi`, and decodes the reply.  Named
   `n00b_rpc_call_<svc>__<method>` (no leading underscore).
   Declarations (the header path) emit only an `extern` prototype for
   this symbol; the body is emitted at the definition site &mdash; so a
   single header may be included by many TUs without duplicate-symbol
   errors at link.

The annotation's quoted string is `<package>.<service>/<method>`:
package and service are dotted lower-case-style identifiers; method
is a single identifier.  The package + service component is mangled
into the C symbol by replacing dots with `_` and the slash with
`__`.  See `docs/quic/rpc.md` § "Generated symbols" for the full
naming reference.

#### Stream shapes

ncc inspects the user's return type and first parameter to pick one
of four templates:

| Return                                    | First param                  | Shape         |
|-------------------------------------------|------------------------------|---------------|
| `n00b_result_t(T *)`                       | `U *`                        | unary         |
| `n00b_result_t(n00b_rpc_stream_t(T) *)`    | `U *`                        | server-stream |
| `n00b_result_t(T *)`                       | `n00b_rpc_stream_t(U) *`     | client-stream |
| `n00b_result_t(n00b_rpc_stream_t(T) *)`    | `n00b_rpc_stream_t(U) *`     | bidi          |

#### Restrictions (v0)

- The function must take a `n00b_rpc_ctx_t *` parameter.
- The return type must be `n00b_result_t(...)`.
- `static` functions cannot be `@rpc`-annotated.
- `_kargs` + `@rpc` on the same function is rejected at parse time.
- The method string must be `<package>.<service>/<method>` with
  exactly one `/`; each component must be a valid C identifier
  (the package may be dotted).

The `@rpc` transform runs **first** in the pipeline so the
synthesized dispatcher / stub bodies flow through `generic_struct`,
`typeid`, `option`, and `kargs_vargs` lowering naturally.

### `package` &mdash; Namespace Prefixing

**Status: Implementation exists but is deferred. Do not use.**

```c
package mylib;

void helper(void);  // → mylib_helper()
```

Rewrites all local identifiers with a package prefix. The implementation works
but the design needs to be rethought before it can be used in production
&mdash; the current approach is too coarse-grained for the project's needs.

---

## Modernize Mode

```bash
ncc --modernize file.c > file_modernized.c
```

A separate pipeline that upgrades C11/C17 code to C23 idioms. Runs in two
phases:

1. **Token-level** (pre-CPP): keyword replacements, pragma updates, include
   normalization.
2. **Tree-level** (post-parse): AST-based rewrites for patterns that require
   structural understanding.

### Transforms applied

| Transform | Example |
|-----------|---------|
| `NULL` → `nullptr` | `return NULL;` → `return nullptr;` |
| `= {0}` → `= {}` | `struct s x = {0};` → `struct s x = {};` |
| `__attribute__((...))` → `[[...]]` | Standard C23 attribute syntax |
| `_Alignas` → `alignas` | C23 keyword |
| `_Bool` → `bool` | C23 keyword |
| Include path updates | Normalized paths |

Individual transforms can be skipped via the `NCC_MODERNIZE_SKIP` environment
variable (comma-separated list of: `keywords`, `includes`, `elifdef`,
`attributes`, `builtins`, `empty-init`, `va-paste`, `va-start`, `overflow`,
`nullptr`, `pragma-once`).

---

## Command-Line Reference

### Compiler flags (passed through to clang)

All standard compiler flags (`-c`, `-o`, `-I`, `-D`, `-W`, `-O`, `-g`, etc.)
are passed through to the underlying compiler. ncc intercepts only what it
needs.

### NCC-specific flags

| Flag | Purpose |
|------|---------|
| `--no-ncc` | Pure compiler passthrough &mdash; skip entire ncc pipeline |
| `--dump-tokens` | Print token list after lexing, then exit |
| `--modernize` | Run C11/C17 → C23 upgrade pipeline |
| `--modernize-overflow` | Like `--modernize` but emit comments for overflow checks |
| `--ncc-help` | Show ncc help |
| `-E` | Output ncc-transformed C (after all transforms) |
| `-E -E` | Output raw preprocessor output (before ncc) |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `NCC_COMPILER` | Override C compiler (checked before `$CC`) |
| `NCC_COMPILER_PATH` | Explicit compiler path |
| `NCC_EXTENSIONS` | Comma-separated file extensions to process (default: `.c`) |
| `NCC_PACKAGE_MAP` | Remap package prefixes (e.g., `conduit=n00b`) |
| `NCC_MODERNIZE_SKIP` | Skip specific modernize transforms |
| `NCC_CLANG_FORMAT_STYLE` | clang-format style for modernize output |

### Diagnostic environment variables

| Variable | Purpose |
|----------|---------|
| `NCC_DEBUG` | Enable parse tree logging (0/1) |
| `NCC_DUMP_TREE_PRE` | Write pre-transform AST to file |
| `NCC_DUMP_TREE_POST` | Write post-transform AST to file |
| `NCC_VERBOSE` | Print transform statistics |

---

## Parser Architecture

ncc uses a **packrat parser** &mdash; a top-down parser with memoization that
guarantees linear-time parsing for unambiguous grammars. The grammar covers
the full C23 language plus ncc's extension productions.

### Key characteristics

- **~150 non-terminals** covering all of C23 plus ncc extensions.
- **Declarative rule definitions** using `declare_nt(name, N)` for N
  alternative branches, matched in order.
- **Left recursion** handled via `declare_recursive(name, N)` with an
  iterative loop (no deep call stacks).
- **Arena allocator** for parse tree nodes during parsing, with
  mark/reset for backtracking on failed branches.

### Memoization and performance

The memo table is `(num_tokens + 1) × NT_COUNT` entries. For files with
hundreds of thousands of tokens (e.g., generated lookup tables), this can
consume gigabytes of memory.

The `no_memo` bitfield in `parser_t` (configured in `parse.c`) skips
memoization for non-terminals with near-zero hit rates. Profiling on a
672K-token file showed:

- **Before:** 6.2M memo stores, 895K hits, 36M heap-copied nodes (~3.5 GB)
- **After:** 924K stores, 895K hits, 15.3M heap-copied nodes (~1.5 GB)
- **Reduction:** 85% fewer stores, 57% fewer heap copies

The `NCC_PARSER_STATS` compile flag enables per-NT profiling to identify
additional candidates for `no_memo`. Enable with:
```bash
meson configure bootstrap/builddir -Dc_args="-DNCC_PARSER_STATS"
```

For files that contain no ncc extensions at all (e.g., generated data tables),
use `--no-ncc` to bypass the parser entirely.

### Compiler extension support

The parser handles common GCC/Clang extensions:

- `__attribute__((...))`, `__asm__("label")`
- Statement expressions: `({ ... })`
- `__extension__`, `__typeof__`, `__builtin_va_list`
- Alternative keywords: `__inline`, `__volatile__`, `__const`, `__restrict`
- Nullability qualifiers: `_Nullable`, `_Nonnull`, `_Null_unspecified`

---

## Transform Infrastructure

Transforms register callbacks on specific non-terminal types. During tree
traversal, callbacks fire in either **pre-order** (before children) or
**post-order** (after children). A transform can:

- Replace a node (return a new subtree).
- Modify the node in place (mutate children, add/remove kids).
- Leave it unchanged (return `nullptr`).

### Semantic transform ordering

Transforms run in a fixed order after tree flattening:

1. **package** &mdash; rewrites identifiers (must be first)
2. **typeid** &mdash; generates type-based identifiers
3. **typestr** &mdash; generates type string literals
4. **once** &mdash; wraps single-init functions
5. **vargs** &mdash; rewrites variadic parameters and call sites
6. **keyword** &mdash; generates keyword argument structs (after vargs)
7. **kw_call** &mdash; rewrites call sites with `.arg=val` syntax
8. **bang** &mdash; expands `!` error propagation
9. **rstr** &mdash; expands rich string literals
10. **constexpr** &mdash; evaluates compile-time expressions
11. **constexpr_paste** &mdash; evaluates compile-time identifier pasting

The ordering matters: `vargs` must run before `keyword` (both rewrite
parameters), `keyword` before `kw_call` (call sites reference generated
structs), and `constexpr` variants run last because earlier transforms
may generate code containing them.

### AST construction

Synthetic nodes are built with `synth_terminal()` and `synth_nonterminal()`.
Synthetic tokens carry replacement text in an `ncc_buf_t` and are
distinguished from source tokens by high node IDs (1,000,000+). The emit
phase handles both seamlessly.

---

## Building ncc

### Bootstrap build (standalone)

```bash
cd bootstrap
meson setup builddir      # first time
meson compile -C builddir
```

### As part of the full project

```bash
bash build.sh                        # builds ncc-bootstrap, then libn00b
N00B_BUILD_BOOTSTRAP=1 bash build.sh # force bootstrap rebuild
```

After bootstrap changes, the bootstrap **must** be rebuilt and reinstalled
before the main build will pick up the changes.

### Running bootstrap tests

```bash
cd bootstrap
meson test -C builddir --print-errorlogs
```

Tests cover: `constexpr`, `typeid`, `kw_args`, `rstr`, `error` propagation,
`passthrough`, `no-ncc`, and `preprocess` modes.

---

## Extension Status Summary

| Extension | Syntax | Status | Used in codebase |
|-----------|--------|--------|------------------|
| `typeid()` | `typeid("pfx", T, ...)` | **Complete** | Yes &mdash; all generic containers |
| `typestr()` | `typestr(T)` | **Complete** | Yes &mdash; runtime introspection |
| `constexpr_eval/max/min` | `constexpr_eval(expr)` | **Complete** | Yes &mdash; sizing, alignment |
| `constexpr_paste()` | `constexpr_paste("a", "b")` | **Complete** | Yes &mdash; typeid-generated code |
| `_kargs` | `f(x) _kargs { opt = 0; };` | **Complete** | Yes &mdash; most public APIs |
| `+` (variadics) | `void f(int, +)` | **Complete** | Yes &mdash; variadic functions |
| `!` (bang) | `expr!` | **Complete** | Yes &mdash; result types |
| `r"..."` | `r"«b»bold«/b»"` | **Complete** | Yes &mdash; all styled text |
| `once` | `once void f() { }` | **Complete** | No &mdash; conflicts with multi-runtime |
| `@rpc(...)` | `f(...) @rpc("svc/m");` | **Complete** | Yes &mdash; QUIC RPC layer (Phase 4 § 4.5) |
| `package` | `package name;` | **Deferred** | No &mdash; design needs rework |
| `--modernize` | CLI flag | **Complete** | Tooling only |

---

## Adding a New Extension

Step-by-step checklist for adding a new ncc language extension:

1. **Register keyword** in `bootstrap/src/parse_support.c` (add to the
   `str_list(...)` in `register_keywords()`).
2. **Declare extern** for the keyword in `bootstrap/include/parse_internal.h`.
3. **Add branch symbol** in `bootstrap/include/branch_symbols.h` (if the
   extension introduces new grammar branches).
4. **Add parser rule** in `bootstrap/src/parse.c` — update the `declare_nt`
   count for any affected non-terminal, add `nt_branch` entries for new
   alternatives.
5. **Create transform** in `bootstrap/src/xform_<name>.c` — register
   pre-order and/or post-order callbacks on the target non-terminal(s).
   See existing `xform_*.c` files for the pattern.
6. **Register transform** in `bootstrap/src/compile_packrat.c` — add an
   `extern` declaration and call the registration function during init,
   respecting the [transform ordering](#semantic-transform-ordering).
7. **Add to build** in `bootstrap/meson.build` — append the new source file
   to the `bootstrap_files` list.

After making changes, rebuild the bootstrap:

```bash
N00B_BUILD_BOOTSTRAP=1 bash build.sh
```
