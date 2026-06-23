# Marshaling

n00b marshaling copies a managed object graph into a byte stream and restores
it later into a target arena. The stream acts like a compacted virtual heap:
heap objects are copied into stream records, pointer fields are rewritten as
virtual addresses, and unmarshal patches those fields to the addresses of the
newly allocated receiver-side objects.

Pointers stay pointers semantically. The marshaler does not turn a pointer into
an application-level id or ask the pointee's constructor to run during
unmarshal.

Heap objects whose GC shape is `CALLBACK` can be marshaled only when the
callback is one of n00b's built-in layout callbacks and the stream can preserve
or rederive the layout metadata. For ordinary `n00b_alloc(T)` and
`n00b_alloc_array(T, N)` objects, that metadata comes from the linked
`typehash(T *)` GC type map. Build or run those binaries through
[`n00b-gcmap-index`](gc_type_maps.md) before relying on marshal round-trips of
typed heap objects.

## Static Pointers

Pointers may also refer to registered static objects, such as ncc-generated
rich strings, array backing storage, and static buffer images. Static objects
are not copied into the stream. Instead, the stream carries a relocation record
that tells the receiver how to find the matching static object in its own
loaded image and how to patch the pointer slot.

There are two static relocation forms:

| Record | Use | Portability |
|--------|-----|-------------|
| `SPATCH` | Registered static object without stable identity. | Same runtime/image only. It records the original address plus validation bytes. |
| `PSPATCH` | Registered static object with `n00b_static_identity_t`. | Cross-binary capable when the receiver has a matching registered identity. |

`PSPATCH` records carry:

- identity version and kind;
- namespace id and object key;
- target object offset;
- object length, type hash, scan kind, and readonly/mutable flags;
- validation bytes at the target offset.

Unmarshal looks up the identity in the current process static-object registry.
It patches the pointer to `receiver_static_start + offset` only if exactly one
registered range matches and all requested metadata checks pass. Missing,
duplicate, type, scan-kind, length, mutability, and check-byte failures have
distinct marshal statuses.

## Static Identity

Stable static relocation identity is carried by `n00b_static_identity_t`:

```c
typedef struct n00b_static_identity_t {
    uint32_t                    version;
    n00b_static_identity_kind_t kind;
    uint8_t                     reserved[3];
    const char                 *namespace_id;
    const char                 *object_key;
} n00b_static_identity_t;
```

The namespace says who owns the identity space. The object key identifies one
source-semantic static object inside that namespace. These are not linker
symbols and must not depend on loaded addresses.

Descriptor-backed static objects store the identity on
`n00b_static_object_desc_t`; registration copies the identity pointer onto the
`n00b_alloc_range_t` used by GC and marshal lookup. Manual statics can opt into
portable relocation by providing their own identity. If two live static ranges
register the same identity, lookup fails closed instead of choosing one.

## ncc-Generated Identity

ncc-generated static objects emit identities for:

- `r"..."` rich string objects;
- `n00b_array_t(T)` literal backing storage;
- generalized static-init objects and payloads;
- `b"..."` static `n00b_buffer_t` literals.

ncc uses source-semantic identity. The generated object key includes the static
kind, source path, source line/column, type hash, payload length, and a hash of
the literal source text. Moving a literal or changing its semantic source
changes the key.

Namespace metadata comes from the nearest `.namespace.toml` found by walking up
from the source file directory:

```toml
namespace = "com.example.project"

[[exceptions]]
path = "third_party/"
namespace = "com.example.third_party"

[[exceptions]]
path = "generated/special.c"
namespace = "com.example.generated"
```

`default = "..."` is accepted as an alias for the top-level `namespace = "..."`
entry. Exception paths are relative to the directory containing
`.namespace.toml`; the longest matching exception wins.

If no metadata file exists, ncc uses a conservative fallback namespace of
`ncc.default` and the source basename. Builds that need stable cross-binary
relocation should commit a project-specific `.namespace.toml`. The ncc flag
`--ncc-static-identity-generate-namespace` can create an initial metadata file
beside the source file when stable generated static identity is first required.

## Important Limits

Portable relocation is strict by design:

- no weak or fuzzy matching is attempted;
- a missing or ambiguous identity rejects the stream;
- metadata or validation-byte mismatches reject the stream;
- static objects are not reconstructed by replaying arbitrary constructors;
- pointers into unregistered static memory remain unsupported.

Readonly and mutable statics both carry flags. Portable relocation checks those
flags so a stream expecting readonly data cannot silently bind to a mutable
range, or the reverse.
