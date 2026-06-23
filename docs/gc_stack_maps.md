# GC Stack Maps and Static Object Descriptors

This document is the runtime/compiler contract for accurate GC roots emitted by
ncc and consumed by n00b. It describes the WP-001 runtime substrate; production
ncc emission is expected to follow this contract in a later workplan.

The default collector behavior remains conservative. Exact stack maps and static
object descriptors are opt-in runtime metadata that make generated code more
precise without removing the conservative fallback path.

For heap allocation type maps keyed by `typehash(T *)`, including the
post-link `n00b-gcmap-index` command, see
[`docs/gc_type_maps.md`](gc_type_maps.md). This page covers stack roots and
static object descriptors.

## Root Sources

The collector scans these roots for every collection:

1. User-registered roots from `n00b_gc_register_root()`.
2. Runtime roots such as `argv` and `envp`.
3. Per-thread state records owned by the runtime.
4. Thread stacks, either exact stack frames or conservative stack ranges,
   depending on the thread's `n00b_gc_stack_policy_t`.

Generated exact stack maps do not replace user-registered roots or runtime
roots. They only control how ordinary thread stacks are scanned.

## Stack Map Model

Generated code publishes a per-thread linked list of active frame records:

```c
static const n00b_gc_stack_slot_t slots[] = {
    {.root_index = 0, .num_words = 1},
};

static const n00b_gc_stack_map_t map = {
    .num_roots     = 1,
    .num_slots     = 1,
    .slots         = slots,
    .function_name = "example",
    .file_name     = __FILE__,
    .line          = __LINE__,
};

void *roots[] = {&local_pointer};
n00b_gc_stack_frame_t frame;

n00b_gc_stack_push(&frame, &map, roots);
/* body containing GC safepoints */
n00b_gc_stack_pop(&frame);
```

`n00b_gc_stack_frame_t` and the `roots` array must have a lifetime that covers
every safepoint where the frame is published. Frames are strictly LIFO: every
successful `n00b_gc_stack_push()` must be paired with `n00b_gc_stack_pop()` for
the same frame before the enclosing C scope exits.

Each `roots[root_index]` entry is the address of a stack slot or stack range,
not the pointer value stored in that slot. `num_words` is the number of
pointer-sized words starting at that address that the collector should scan.
For ordinary local pointer variables, `num_words` is `1`.

The compiler must update the underlying stack slot before any operation that can
reach a GC safepoint. If a local root's value changes, the stack storage scanned
through `roots[]` must contain the new value before the next allocation,
blocking operation, explicit STW checkin, or call into n00b code that can do any
of those things.

## Safepoints

n00b already has cooperative safepoints. Generated stack maps are meaningful at
those same points:

- Allocation through `_n00b_alloc_raw()` checks in with STW for normal runtime
  allocators.
- Futex waits and synchronization paths call `n00b_thread_checkin()`.
- Blocking regions use `n00b_thread_suspend()` / `n00b_thread_resume()` or
  `n00b_run_blocking()`.
- An explicit `n00b_stop_the_world()` caller scans the published state of the
  other runtime threads.

When generated code enters a blocking region, all roots that can be observed by
the collector must already be stored in the published stack slots. The suspend
path captures the stack top before marking the thread suspended, and the STW
owner uses `N00B_SUSPEND` / `N00B_BLOCKING` to decide when the thread is safe to
scan.

## Stack Policies

The per-thread stack policy is controlled with `n00b_gc_stack_set_policy()`:

| Policy | Behavior |
|--------|----------|
| `N00B_GC_STACK_CONSERVATIVE` | Ignore published exact frames and scan the conservative stack range. This is the default. |
| `N00B_GC_STACK_EXACT_WITH_FALLBACK` | Scan published frames when at least one frame is active; otherwise scan the conservative stack range. |
| `N00B_GC_STACK_EXACT_ONLY` | Scan only published frames and skip the conservative stack range. Runtime thread records are still scanned. |

ncc-generated code should publish frames but should not force an exact-only
policy by itself. Policy selection belongs to the runtime, tests, or an explicit
program-level configuration. Code that calls into uninstrumented C should keep a
fallback policy unless the boundary is proven not to hide live GC pointers.

## Static Object Descriptors

Generated static objects that need GC visibility should publish a
`n00b_static_object_desc_t` and place a pointer to that descriptor in the
runtime static-object linker section. `n00b_static_objects_register_all()`
enumerates the section and registers each descriptor with the mmap/range tree.

Manual registration is still available for tests and hand-written runtime
objects:

```c
n00b_alloc_range_t *range = n00b_static_object_register(
    &generated_object,
    sizeof(generated_object),
    typehash(generated_type *),
    .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
    .scan_cb   = generated_scan_callback,
    .scan_user = generated_scan_data,
    .object_id = generated_stable_id,
    .flags     = 0);
```

The object must live inside a registered `n00b_mmap_static` range. The runtime
asserts that the object address is registered as static and that the descriptor
fits inside the containing static mapping.

`n00b_alloc_range_t` records descriptor metadata used by the GC and future
memory-test APIs:

| Field | Meaning |
|-------|---------|
| `start`, `len` | Object byte range. |
| `tinfo` | Runtime type hash, usually `typehash(T *)`. |
| `object_id` | Stable generated-object identity for diagnostics. |
| `file` | Source location captured by `N00B_LOC_STRING()`. |
| `identity` | Optional portable relocation identity for marshaled static pointers. |
| `scan_kind`, `scan_cb`, `scan_user` | GC scan shape for object contents. |
| `flags` | Static object policy bits, including readonly versus mutable. |

Descriptor lookup uses `n00b_mmap_range_by_address()`. The collector scans a
descriptor-backed static object when a root or another scanned object points
into that object's range. A per-collection memo prevents repeated scans of the
same descriptor.

Descriptor identities are also used by the marshaler for portable static
pointer relocation. See [`docs/marshal.md`](marshal.md) for the difference
between same-runtime `SPATCH` relocation and cross-binary `PSPATCH`
relocation.

## Static Scan Policy

The compiler must choose a scan policy from type information:

| Static payload | Required scan policy |
|----------------|----------------------|
| Scalar data with no GC pointers | `N00B_GC_SCAN_KIND_NONE`. |
| Pointer-only arrays or simple reference arrays | `N00B_GC_SCAN_KIND_ALL`. |
| Alternating pointer/scalar words | `N00B_GC_SCAN_KIND_EVERY_OTHER`. |
| Mixed structs, nested arrays, or any layout with sparse pointer fields | `N00B_GC_SCAN_KIND_CALLBACK`. |

`N00B_GC_SCAN_KIND_DEFAULT` currently scans every pointer-sized word for range
descriptors. Generated code should avoid `DEFAULT` when type information is
available, especially for mixed scalar/pointer objects where scalar words might
look like heap pointers.

Rich string literals and other generated static structs should use descriptor
scan policies that match their actual pointer fields. For example,
`n00b_string_t` is a mixed struct, so a descriptor-based string object should
not be registered with `ALL` unless every scalar word is known not to contain
pointer-shaped data.

## Static Image Initializers

Static images are built before the final C compile, not at runtime startup. ncc
now uses its generalized static-init lowering to marshal file-scope roots and
emit ordinary C declarations plus initializer expressions. There is no
separate helper subprocess in this path.

`b"..."` is the supported buffer literal spelling:

```c
const n00b_buffer_t *literal = b"payload";
```

`b"..."` produces a readonly static `n00b_buffer_t` byte payload. It supports
ordinary C string escapes and adjacent ordinary string literal concatenation.
The generated buffer image is readonly, descriptor-backed, and borrowed from
static payload bytes.

The same generalized route owns migrated static container literal images for
nonempty arrays, lists, and dictionaries. `a{...}` and bare `[...]` initialize
compatible array values. `l{...}` initializes `n00b_list_t(T)` values or
pointers to generated static list objects. `d{...}` initializes compatible dict
values. ncc carries typed C initializer records and scan metadata into the
static image; generated storage remains descriptor-backed and carries dependency
metadata and portable identities where available.

ncc-generated rich strings, array/list literal storage, and static images carry
portable static identities when descriptors are emitted. Unsupported registered
types, unsupported container element types, mutable block-scope targets, bad
literal argument kinds, ABI mismatches, and missing static initializer vtable
slots are rejected at build time with ncc source-positioned diagnostics.

## Unsupported Generated Statics

If ncc cannot describe a static object with a correct scan policy, it should not
emit descriptor registration for that object. The compiler should either keep an
existing supported representation or issue a diagnostic at the literal site.

The runtime descriptor model does not yet construct static dictionaries or
choose dictionary hash policy. Those are follow-up migrations after the
stack-map and descriptor contract is stable.

## Testing Requirements

Runtime tests should cover these behaviors before production ncc emission is
enabled:

- Exact mapped stack roots survive collection in exact-only mode.
- Unmapped locals do not keep objects live in exact-only mode.
- Nested exact frames are scanned from the per-thread frame chain.
- `N00B_SUSPEND` and `N00B_BLOCKING` lifecycles clear after STW release.
- Descriptor-backed static objects are discoverable by address.
- Nested descriptor-backed static objects can rewrite a moving heap pointer.

Compiler tests for WP-002 should add transformed-source checks showing that ncc
emits stable descriptors, LIFO frame publication, and helpful diagnostics for
literal types whose static layout is not yet supported.
