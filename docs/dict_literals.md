# Static Dictionary Literals

Static dictionary literals are a compile-time syntactic feature
provided by ncc for initializing `n00b_dict_t(K, V)` objects with
known-at-compile-time key/value pairs. ncc's generalized static-init
lowering constructs the dict image during compilation; the resulting
object is a registered static range that behaves like any other
heap-built dict at runtime, with one performance advantage — pointer-key
lookups short-circuit through a precomputed `cached_hash` slot on the
key's static-object descriptor.

This document is the user-facing reference. The implementation lives
in WP-011 (decisions D-063 through D-077; see `.agents/DECISIONS.md`
in the project root for design rationale).

## Syntax

Two equivalent forms exist:

```c
// Explicit form: 'd' prefix before the brace.
n00b_dict_t(int, int) x = d{1: 10, 2: 20, 3: 30};

// Bare form: no prefix. Recognized as a dict literal because the
// element stream uses ':' key/value separators.
n00b_dict_t(int, int) y = {1: 10, 2: 20, 3: 30};
```

Both forms produce identical lowerings.

### Recognition rules

| Spelling | Treated as |
|----------|------------|
| `{}` (empty) | C zero-initialization (unchanged from C semantics). |
| `{1, 2, 3}` | C compound initializer (array / struct). |
| `{.x = 5}` | C designated initializer. |
| `{1: 2}` | Dict literal (because of the `:`). |
| `d{}` | Empty static dict literal. |
| `d{1: 2}` | Dict literal (explicit). |

The `:` separator is what disambiguates the bare form from a C
compound initializer.

### Empty dict

`d{}` produces an empty dict with `used_count == 0` and capacity
`N00B_DICT_MIN_SIZE` (16). It supports lookups (they return
not-found) but contains no entries. The bare form `{}` is NOT an
empty dict — it's C zero-init. Use `d{}` for an explicit empty
static dict.

## Supported key categories

Phase 3c.i through 3c.ii.b ship with three key categories:

1. **Scalar / enum keys** — `int`, `uint8_t`, enum types, etc. The
   hash is `XXH3_128bits` over the raw bytes of the stored key.
2. **r-string keys** — `n00b_string_t *` pointing at a static
   r-string literal (`r"foo"`). The hash is `XXH3_128bits` over the
   string's UTF-8 content.
3. **b-buffer keys** — `n00b_buffer_t *` pointing at a static buffer
   literal (`b"abc"`). The hash is `XXH3_128bits` over the buffer's
   byte payload.

Other pointer key types (struct pointers, function pointers,
generic `void *`) currently route to a permanent compile-time
diagnostic. Future workplans may extend the supported set.

## Supported value categories

- Scalar / enum values.
- Compatible pointers (including pointers to user-defined static
  structs).
- r-strings (`r"..."`).
- b-buffers (`b"..."`).
- Aggregate types with static layout.
- Nested supported arrays, lists, or dicts (`l{...}`, `a{...}`,
  `d{...}`).

## Lookup patterns

Static dicts behave like heap dicts at lookup time. Use the standard
dict API:

```c
n00b_dict_t(int, int) m = d{1: 100, 2: 200, 3: 300};

bool found;
int  v = n00b_dict_get_value(&m, 1, &found, int, 0);  // v == 100, found == true
int  z = n00b_dict_get_value(&m, 99, &found, int, 0); // z == 0,  found == false
```

For r-string keyed dicts, content-based lookup works automatically
because every r-string descriptor carries its content hash in
`cached_hash` (D-077). Two content-equal r-strings produced by
different call sites hash to the same value:

```c
static const n00b_dict_t(n00b_string_t *, int) cache = d{
    r"foo": 1,
    r"bar": 2,
};

// Lookup with an r-string at a different call site than the literal
// the dict was constructed from — both hash to the same value.
bool found;
int  v = n00b_dict_get_value(&cache, r"foo", &found, int, 0);
// v == 1, found == true.
```

For buffer-keyed dicts, the same content-hashing rule applies via
`n00b_buffer_hash`.

## Pointer-target lowering

A dict literal can initialize a pointer target as well as a value
target. The pointer-target form generates a static top-level dict
object and assigns its address:

```c
// Value target: store the dict inline.
n00b_dict_t(int, int) m = d{1: 100};

// Pointer target: generate a static top-level dict, assign address.
n00b_dict_t(int, int) *mp = d{1: 100};
```

Pointer-target lowering follows the WP-010 list-pointer pattern
(D-067). The generated object's mutability follows the **pointee**
constness, not the pointer-variable constness.

## Lock model

Static dict literals default to `.lock = nullptr` — they are
**lockable but not locked by default** (D-070, superseding D-068).
The dict store layout includes a `n00b_rwlock_t *lock` slot mirroring
the WP-010 list precedent. Heap dicts have two constructor variants:

- `n00b_dict_new(K, V)` — locked by default (allocates a rwlock).
- `n00b_dict_new_private(K, V)` — private/unlocked (`.lock = nullptr`).

Static dict literals are typically not concurrently mutated (their
content is fixed at compile time), so the unlocked default is the
common case. If you need a locked static dict, add `.lock = ...`
post-init or convert to a heap dict.

The dict's embedded `n00b_futex_t _migration_state` (D-072,
formerly named `futex`) is the lock-free table-resize coordination
word, NOT a user-facing lock. Its semantics are preserved exactly
from pre-WP-011.

## Duplicate keys

Duplicate keys at compile time are a hard error (D-065):

```c
n00b_dict_t(int, int) bad = d{1: 10, 1: 20};
// Error: duplicate dict literal key '1' at <line>:<col> and <line>:<col>
```

The duplicate-key check compares 128-bit hash values; identical keys
produce identical hashes and are rejected.

## cached_hash performance path

For pointer-keyed lookups (r-string, buffer), `n00b_hash()` reads the
key's `cached_hash` slot on the registered static range before
falling through to the type's vtable hash function. After D-077,
EVERY r-string emission populates `cached_hash` with the content
XXH3 hash, so static-key lookups return immediately without recomputing
the hash from the content bytes.

This is transparent — you do not need to enable or configure
anything. The cached_hash field is populated by ncc at compile time
for all r-string emissions (`r"..."`) and for buffer emissions
appearing as dict keys.

Edge case: empty r-strings (`r""`) emit `cached_hash = 0` (the
runtime's `n00b_string_hash` returns `n00b_hash_word(0ULL)` for
empty inputs, a non-zero constant ncc cannot reproduce at compile
time). The recompute-then-vtable path handles this correctly; no
functional gap.

## Diagnostics

The compile-time diagnostics dict literals can produce:

| Diagnostic | Cause |
|------------|-------|
| `dict literal initializer for 'n00b_dict_t(K, V)' requires a file-scope static-init target with external linkage` | The literal is routed outside the supported generalized static-init path. File-scope static-init roots must be externally visible so ncc can marshal and register them. |
| `dict literal target type 'X' is not a dict type` | Target isn't a `n00b_dict_t(K, V)` or alias. |
| `dict literal key type 'X' is not supported for static initialization yet` | Key type isn't scalar/enum, r-string, or b-buffer. |
| `dict literal value type 'X' is not supported for static initialization yet` | Value type isn't in the supported set. |
| `duplicate dict literal key '<key>' at <line>:<col> and <line>:<col>` | D-065 hard error. |
| `dict pointer-key lowering not yet implemented for this pointer type` | Permanent fixture for unsupported pointer key types. |
| `dict literal block-scope mutable lifetime is not allowed` | Block-scope mutable dict literal targets are rejected (matching list literal precedent). |

## Migrating a libn00b translation unit to use dict literals

A libn00b file that wants to use static dict literals now uses the
same generalized ncc static-init route as other migrated static
objects. There is no separate helper subprocess and no legacy helper build
flag. The important build constraint is
that file-scope static-init roots need external linkage, and translation
units compiled into both bootstrap and final libraries must not introduce
duplicate definitions.

The style registry is the worked example: the old bootstrap stub split
has been retired, and the defaults implementation is compiled through the
normal full-library source list. When migrating another translation unit:

1. Keep ordinary runtime helpers in the package's normal source list.
2. Put static dict literal roots at file scope with external linkage when
   ncc must marshal or register the object.
3. Avoid block-scope mutable static dict targets; ncc rejects those for
   lifetime reasons.
4. Wire the source through the package's existing Meson source list rather
   than adding legacy helper ordering targets or helper-only source lists.
5. Verify with `N00B_NATIVE=1 NCC_PATH=<path-to-ncc> bash build.sh <build-dir>`
   and focused tests for the migrated subsystem.

Example:

```c
#include "n00b.h"
#include "text/strings/<name>.h"

const n00b_text_style_t style_em = {.italic = N00B_TRI_YES};
const n00b_text_style_t style_em2 = {.bold = N00B_TRI_YES};

n00b_dict_t(n00b_string_t *, const n00b_text_style_t *) builtin = d{
    r"em":  &style_em,
    r"em2": &style_em2,
};

void
n00b_str_registry_install_defaults(void) {
    n00b_dict_foreach(&builtin, key, value, {
        n00b_str_style_register((const char *)key->data, value);
    });
}
```

### Build invocation pitfalls

n00b's `meson.build:15` guards against direct `meson setup` invocation
because `build.sh` is what resolves `NCC_PATH` to the freshly-built
workspace ncc (see `build.sh`'s `ensure_ncc` function) and invokes
meson with `CC=$NCC_PATH`.

The guard checks `get_option('using_build_script')` and aborts when
unset. The option can be bypassed with `-Dusing_build_script=true`,
but doing so **loses the NCC_PATH resolution** — meson auto-detects
whatever `clang` happens to be on `PATH`, which then receives
`--ncc-*` flags it does not understand and fails the
`gen_unicode_lib` and vendor library compilations. This trap bit
WP-011 Phase 5d's validation (a subagent had set up
`build_wp011_phase3b` with `-Dusing_build_script=true` and the
build silently used plain clang).

The fix: **always use `bash build.sh <build-dir>`**. The script
sets `using_build_script=true` AND sets `CC=$NCC_PATH` AND tracks
NCC_PATH resolution so cold-start environments work. Bypassing it
should be a deliberate, one-off override — not a default for fresh
build directories.

If you absolutely must bypass `build.sh` (e.g., to set up an IDE
project that meson can read), explicitly pass `CC=<path-to-ncc>` to
`meson setup` alongside `-Dusing_build_script=true`. Don't rely on
`PATH` to resolve the right compiler.

### What CAN'T be migrated

Unsupported pointer key/value categories, block-scope mutable targets,
and static-init roots without the required file-scope visibility still
produce diagnostics. The retired helper no longer creates a separate
source-set constraint.

## See also

- **r-string literals** (`r"..."`): the content-hashed string type
  used as dict keys. See `strings.md`.
- **Static list literals** (`l{...}`): WP-010, the precedent for the
  dict literal lowering pipeline.
- **Static array literals** (`a{...}` or bare `[...]`): also WP-010.
- **Buffer literals** (`b"..."`): WP-007.
- **Descriptor-backed static ranges**: WP-003 / WP-009. The runtime
  metadata structure (`n00b_alloc_range_t`) that carries the
  `cached_hash` slot used by D-066.
- **Decisions** D-063 through D-077 in `.agents/DECISIONS.md` for
  design rationale.
