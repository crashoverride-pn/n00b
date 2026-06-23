# ncc Static Objects in n00b

This document covers ncc's static-object pipeline as it manifests in
libn00b — every compile-time literal, generalized static-init image, and
descriptor-backed runtime structure that you'll encounter when writing
n00b source.

Scope: just the ncc-static-objects work delivered by WP-003 through
WP-012. For the full n00b library API (strings, conduit, marshal,
render, GC, etc.), see the topic-specific docs in this same directory.

Audience split:
- **Part 1 (User Guide)** — for developers writing n00b source.
- **Part 2 (Contributor Notes)** — for libn00b maintainers and people
  migrating existing libn00b code to use static literals.

For the corresponding ncc compiler manual (language extensions, build
invocation, and static-init pipeline), see `docs/static_objects_pipeline.md` in
the ncc repository.

For heap allocation type maps emitted from `typehash(T *)` and the post-link
`n00b-gcmap-index` command, see [`docs/gc_type_maps.md`](gc_type_maps.md).

---

# Part 1 — User Guide

## What's a static object in n00b?

A static object is a piece of memory whose lifetime starts at program
load (or earlier — descriptor-section enumeration happens during
`n00b_init`) and persists for the entire process. n00b tracks every
such region as a registered **static range** with metadata:

- **Type info** (`n00b_alloc_type_info_t`) — what type the object is.
- **Scan kind / callback** — how the GC should treat it.
- **Identity** (optional, per WP-008) — portable identifier for
  marshal/unmarshal across binary instances.
- **Cached hash** (per WP-011 D-066) — precomputed hash for
  short-circuiting `n00b_hash(ptr)` lookups.

You almost never construct these by hand. ncc emits them automatically for
compile-time literals and migrated static-init roots.

## Compile-time literal forms

n00b supports the following compile-time literal forms via ncc:

### r-strings — `r"..."`

```c
n00b_string_t *greeting = r"«b»Hello«/b» world";
```

A static `n00b_string_t` with rich-text markup parsed at compile time.
See `strings.md` § Rich text for the markup grammar.

### b-strings — `b"..."`

```c
n00b_buffer_t *blob = b"\x00\x01\x02\x03";
```

A static `n00b_buffer_t` carrying the raw byte payload.

### Array literals — `[...]` / `a{...}`

```c
n00b_array_t(int) ints = [1, 2, 3, 4];
n00b_array_t(int) ints2 = a{1, 2, 3, 4};   // equivalent
```

### List literals — `l{...}`

```c
n00b_list_t(int) values = l{10, 20, 30};
```

Lists differ from arrays: lists are dynamic, lockable, and have
mutability semantics that differ from arrays.

### Dict literals — `d{...}` or bare `{key:value}`

```c
n00b_dict_t(int, int) counts = d{1: 10, 2: 20};
n00b_dict_t(n00b_string_t *, int) ids = d{r"alice": 1};
```

See `docs/dict_literals.md` for the full reference.

## Why static objects?

Compile-time literals avoid runtime allocation and parsing overhead.
For long-lived program data — defaults, lookup tables, registries —
this is a significant win:

- **No runtime allocation cost.** The object's storage is fixed at
  link time.
- **No GC overhead.** Static ranges are excluded from the heap
  collection set (the GC scans them but never moves or frees them).
- **Marshal-portable.** Per WP-008, descriptor-backed static objects
  carry portable identities that survive serialization across binary
  instances.
- **Pre-hashed.** Per WP-011 D-066/D-077/D-078, pointer-key lookups
  short-circuit through the cached_hash slot.

## Hash semantics for static objects

Every static object descriptor (rich-string and buffer; future:
cstrings) carries its content hash in the `cached_hash` slot.
`n00b_hash(ptr)` reads this value before falling through to the
vtable hash function:

```c
n00b_string_t *foo = r"hello";        // cached_hash = XXH3(content)
n00b_string_t *bar = r"hello";        // same content, same cached_hash
n00b_buffer_t *blob = b"world";       // cached_hash = XXH3(content)

assert(n00b_hash(foo) == n00b_hash(bar));   // content-equal → hash-equal
```

This guarantees that content-equal literals at different call sites
hash identically — making them work as dict keys, set members, and
hash-table keys without further configuration.

Empty literals (`r""`, `b""`) have `cached_hash = 0` (an "uncached"
sentinel). `n00b_hash()` falls through to the vtable in that case;
the value returned is the same as for any other empty input.

## Lock model for static container literals

| Container | Default | How to opt out |
|-----------|---------|----------------|
| Static `l{...}` list | Locked (embedded rwlock) | n/a — static lists are always locked |
| Static `d{...}` dict | Lockable, NOT locked-by-default (`lock = nullptr`) | Use as-is; set `.lock = ...` post-init if needed |
| Static `a{...}` array | n/a (arrays don't have a lock field) | — |

For heap containers, use `n00b_list_new` / `n00b_dict_new` (locked)
vs `n00b_list_new_private` / `n00b_dict_new_private` (unlocked).

## Lookup patterns

### Scalar-keyed dicts

```c
n00b_dict_t(int, int) m = d{1: 10, 2: 20};
bool found;
int v = n00b_dict_get_value(&m, 1, &found, int, 0);   // 10, true
int z = n00b_dict_get_value(&m, 99, &found, int, 0);  // 0,  false
```

### Pointer-keyed (r-string / buffer) dicts

```c
static const n00b_dict_t(n00b_string_t *, int) cache = d{
    r"foo": 1,
    r"bar": 2,
};

// Lookup via the canonical n00b_dict_get macro.
n00b_string_t *q = r"foo";
bool found;
int v = n00b_dict_get(&cache, q, &found);   // 1, true
```

Content-based lookup works without configuration — the static r-string
descriptor carries the precomputed cached_hash matching what the dict
literal computed at compile time.

## Diagnostics

If you write a dict literal incorrectly, ncc emits user-spelled
diagnostics. Common cases:

| Diagnostic | Cause |
|------------|-------|
| `... requires a file-scope static-init target with external linkage` | The literal is routed outside the supported generalized static-init path. File-scope static-init roots must be externally visible so ncc can marshal and register them. |
| `dict literal key type 'X' is not supported for static initialization yet` | Key type isn't scalar/enum, r-string, or b-buffer. |
| `dict literal value type 'X' is not supported for static initialization yet` | Value type isn't in the supported set. |
| `duplicate dict literal key '<key>' at <line> and <line>` | Same key appears twice. |
| `dict pointer-key lowering not yet implemented for this pointer type` | Non-r-string, non-buffer pointer keys aren't supported yet. |
| `dict literal block-scope mutable lifetime is not allowed` | Block-scope mutable dict literals are rejected (matches list literal precedent). |

---

# Part 2 — Contributor Notes

## Runtime substrate (WP-003, WP-009)

### `n00b_alloc_range_t`

The runtime metadata record for a registered static range, declared in
`include/core/alloc_base.h`. Fields (relevant subset):

```c
struct n00b_alloc_range_t {
    void                          *start;
    void                          *tree_node;
    n00b_alloc_type_info_t         tinfo;
    n00b_gc_scan_cb_t              scan_cb;
    void                          *scan_user;
    n00b_allocator_t              *allocator;
    const char                    *file;
    const n00b_static_identity_t  *identity;
    uint64_t                       object_id;
    uint64_t                       len;
    n00b_mmap_rec_kind_t           kind;
    n00b_gc_scan_kind_t            scan_kind;
    uint32_t                       flags;
    n00b_uint128_t                 cached_hash;  // WP-011 Phase 3a (D-066)
};
```

`n00b_find_alloc_info(ptr)` returns this metadata for any registered
range. `n00b_hash(ptr, fn)` consults the `cached_hash` field first;
non-zero means "use this value", zero means "recompute via vtable".

### `n00b_static_object_desc_t`

The compile-time descriptor template, declared in `include/n00b.h`.
Section-enumerated at runtime to populate `n00b_alloc_range_t` records.
Includes a `cached_hash` field that ncc-generated static-init code populates.

### Descriptor template macros

`include/core/static_objects.h` declares:

- `N00B_STATIC_OBJECT_DESCRIPTOR(...)` — base macro.
- `N00B_STATIC_OBJECT_DESCRIPTOR_WITH_IDENTITY(...)` — WP-008
  identity-aware variant.
- `N00B_STATIC_OBJECT_DESCRIPTOR_WITH_HASH(...)` — WP-011 cached_hash
  variant.
- `N00B_STATIC_OBJECT_DESCRIPTOR_WITH_IDENTITY_AND_HASH(...)` — both.

Code that wants cached_hash uses `_WITH_HASH` or
`_WITH_IDENTITY_AND_HASH`. The base macros default the slot to zero.

## Generalized static-init lowering

The retired helper subprocess and legacy helper flag are no longer part of
the build. ncc now handles
migrated static images through generalized static-init lowering: it marshals
file-scope roots during compilation, emits descriptor-backed storage, and
returns normal initializer expressions in the generated C.

### Container kinds supported

- `list` — n00b_list_t static image (locked by default).
- `array` — n00b_array_t static image.
- `buffer` — n00b_buffer_t static image via `b"..."`.
- `dict` — n00b_dict_t static image (lockable, not locked-by-default
  per D-070).

Static-init roots that ncc must marshal need file-scope visibility and, for the
current generalized route, external linkage. Unsupported pointer categories,
mutable block-scope targets, and roots that cannot be described with correct
scan metadata are rejected with ncc diagnostics.

## libn00b build shape

`n00b_bootstrap` remains as a bootstrap/static-library variant for tests that
need to compare early and final runtime behavior, but it no longer exists to
link a helper subprocess. Static-literal-aware sources are compiled through the
normal source lists; do not add legacy helper ordering targets or helper-only
source splits for new migrations.

## Migration recipe for libn00b TUs

When migrating an existing libn00b TU to use static dict literals, use the
recipe in `docs/dict_literals.md` (this same directory). Quick summary:

1. Keep runtime helpers in the package's normal source list.
2. Put static literal roots at file scope with the visibility ncc requires.
3. Wire the source through existing Meson source lists.
4. Verify the library build and focused tests through `build.sh`.

The worked example is `src/text/strings/style_registry_defaults.c`.

## Cached_hash perf path (D-066, D-077, D-078)

`n00b_hash(ptr, fn)`'s pseudocode:

```c
n00b_uint128_t n00b_hash(void *obj, n00b_hash_fn fn) {
    n00b_alloc_info_t ainfo = n00b_find_alloc_info(obj);

    if (n00b_alloc_info_is_heap(ainfo)) {
        // Heap path: cache via inline/oob header.
        if (ainfo.hdr->cached_hash != 0) return ainfo.hdr->cached_hash;
        ainfo.hdr->cached_hash = (*fn_or_vtable)(obj);
        return ainfo.hdr->cached_hash;
    }

    if (n00b_alloc_info_is_static_range(ainfo)) {
        // Static-range path (WP-011 Phase 3a).
        if (ainfo.hdr.range->cached_hash != 0)
            return ainfo.hdr.range->cached_hash;
        // No write-back for static ranges; fall through.
    }

    // Vtable / fn lookup, return.
}
```

For r-strings, buffers, and (per WP-011) some dict keys, the
descriptor's `cached_hash` slot is populated at build time so the
static-range path returns immediately.

## Dict store layout (WP-011 D-070)

```c
struct n00b_dict_store_t(k, v) {
    n00b_futex_t          _migration_state;  // lock-free table-resize coordination word (D-072)
    uint32_t              last_slot;
    uint32_t              threshold;          // 75% resize trigger
    _Atomic uint32_t      used_count;
    n00b_dict_bucket_t   *buckets;            // hash-keyed bucket array
    k                    *keys;               // type-erased key array
    v                    *values;             // type-erased value array
    n00b_rwlock_t        *lock;               // WP-011 D-070: lockable, nullptr by default
    // ... plus scan_kind, scan_cb, scan_user, etc.
};
```

The `_migration_state` field (renamed from `futex` in Phase 3b.fix) is
**not** a user-facing mutex — it's the lock-free table-resize
coordination word, semantics unchanged from pre-WP-011. The
user-facing locking is via the new `lock` slot.

## Vendored hash code

`include/vendor/xxhash.h` (upstream xxHash) is the source of truth for
`XXH3_128bits`. ncc and libn00b both link against it. Bit-identity
between the ncc tree and the n00b tree is required for static-key
lookups to work; build-time checks verify the xxhash header is
byte-identical where needed.

## Project workplans (handoff context)

The static-objects pipeline was built across WP-003 → WP-012 in the
n00b workspace. Audit documents live in
`.agents/work-plans/wp-NNN-*/` in the ncc repo (workplans are managed
there). Design decisions are recorded as D-001 through D-078 in
`.agents/DECISIONS.md`.

Known deferrals carried forward past the project end:

- **PE/COFF runtime validation** — needs a Windows runner.
- **D-072: dict migration coordination protocol retirement** — needs
  a concurrency-design WP. The `_migration_state` field's lock-free
  protocol is functional; retirement is a refactor.
- **D-077/D-078: empty r/b-string `cached_hash = 0`** — functional,
  not blocking.
- **cstring static descriptors + cached_hash** — future work. Plain C
  string literals don't currently get descriptors.
- **Bootstrap-stub pattern with non-empty defaults** — D-076 assumes
  empty defaults are functionally correct at bootstrap. Files needing
  non-empty defaults would require a different pattern.
- **Arbitrary constructor-image object literals** — generalize beyond
  list/array/dict/buffer/r-string. Substantial future work.
