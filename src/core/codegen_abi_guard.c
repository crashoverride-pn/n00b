/**
 * @file core/codegen_abi_guard.c
 * @brief Single layout tripwire for the type-name-free codegen ABI.
 *
 * ncc emits the GC/marshal descriptors (static-object descriptor + identity,
 * GC root table + section entry, GC stack slot/map/frame, transient
 * layout/entry/index) as ANONYMOUS structs with primitive-spelled fields, so no
 * translation unit needs to include core/codegen_abi_inject.h anymore (the build
 * no longer force-includes it). That decoupling is only safe if the anonymous
 * layouts ncc emits are byte-for-byte identical to the real structs the runtime
 * reads out of the linker sections. A divergence would silently mis-scan the GC
 * heap = corruption.
 *
 * This TU is the ONE place that re-establishes the check: it includes the real
 * header and _Static_asserts that every real struct's size and every field
 * offset match a reference struct that mirrors EXACTLY what ncc emits (see the
 * emitters in the ncc worktree: xform_static_object.c, xform_array_literal.c,
 * xform_gc_globals.c, xform_gc_stack_maps.c, xform_gc_typemap.c, and the
 * r-string templates in meson.build). If the header layout ever drifts from the
 * emitted layout, THIS build fails here — not the runtime. It is intentionally
 * the only hand-written TU (besides the genuine API users) that must rebuild
 * when codegen_abi_inject.h changes.
 */
#include "core/codegen_abi_inject.h"

// ── Reference layouts: must mirror the ncc-emitted anonymous structs EXACTLY.
// Keep field order/types/widths in sync with the emitters cited above.

struct n00b_ref_sodesc {
    const void           *start;
    uint64_t              len;
    uint64_t              tinfo;
    unsigned char         scan_kind;
    void                (*scan_cb)(void *, void *);
    void                 *scan_user;
    uint64_t              object_id;
    const char           *file;
    const void           *identity;
    uint32_t              flags;
    unsigned _BitInt(128) cached_hash;
};

struct n00b_ref_sid {
    uint32_t      version;
    unsigned char kind;
    unsigned char reserved[3];
    const char   *namespace_id;
    const char   *object_key;
};

struct n00b_ref_root {
    void    *addr;
    uint64_t num_words;
};

struct n00b_ref_root_sec {
    const void *roots;
    uint64_t    count;
};

struct n00b_ref_slot {
    uint32_t root_index;
    uint32_t num_words;
};

struct n00b_ref_map {
    uint32_t    num_roots;
    uint32_t    num_slots;
    uint32_t    flags;
    const void *slots;
    const char *function_name;
    const char *file_name;
    uint32_t    line;
};

struct n00b_ref_frame {
    void  *prev;
    const void *map;
    void **roots;
};

struct n00b_ref_trlay {
    uint64_t        field_count;
    const uint64_t *byte_offsets;
    const uint64_t *byte_sizes;
};

struct n00b_ref_trent {
    uint64_t    type_hash;
    const void *layout;
};

struct n00b_ref_tridx {
    uint64_t type_hash;
    uint64_t entry_index;
};

// ── Assertions: size + every field offset, real struct vs reference.

#define N00B_ABI_SAME_SIZE(real, ref)                                          \
    _Static_assert(sizeof(real) == sizeof(struct ref),                         \
                   #real " size drifted from the ncc-emitted layout")
#define N00B_ABI_SAME_OFF(real, ref, field)                                    \
    _Static_assert(offsetof(real, field) == offsetof(struct ref, field),       \
                   #real "." #field " offset drifted from the ncc-emitted layout")

// static-object descriptor
N00B_ABI_SAME_SIZE(n00b_static_object_desc_t, n00b_ref_sodesc);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, start);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, len);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, tinfo);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, scan_kind);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, scan_cb);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, scan_user);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, object_id);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, file);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, identity);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, flags);
N00B_ABI_SAME_OFF(n00b_static_object_desc_t, n00b_ref_sodesc, cached_hash);

// static identity
N00B_ABI_SAME_SIZE(n00b_static_identity_t, n00b_ref_sid);
N00B_ABI_SAME_OFF(n00b_static_identity_t, n00b_ref_sid, version);
N00B_ABI_SAME_OFF(n00b_static_identity_t, n00b_ref_sid, kind);
N00B_ABI_SAME_OFF(n00b_static_identity_t, n00b_ref_sid, reserved);
N00B_ABI_SAME_OFF(n00b_static_identity_t, n00b_ref_sid, namespace_id);
N00B_ABI_SAME_OFF(n00b_static_identity_t, n00b_ref_sid, object_key);
// the kind enum must remain a 1-byte type for the `unsigned char kind` mirror.
_Static_assert(sizeof(n00b_static_identity_kind_t) == 1,
               "n00b_static_identity_kind_t must stay 1 byte (uint8_t enum)");

// GC roots
N00B_ABI_SAME_SIZE(n00b_gc_root_t, n00b_ref_root);
N00B_ABI_SAME_OFF(n00b_gc_root_t, n00b_ref_root, addr);
N00B_ABI_SAME_OFF(n00b_gc_root_t, n00b_ref_root, num_words);
N00B_ABI_SAME_SIZE(n00b_gc_root_section_entry_t, n00b_ref_root_sec);
N00B_ABI_SAME_OFF(n00b_gc_root_section_entry_t, n00b_ref_root_sec, roots);
N00B_ABI_SAME_OFF(n00b_gc_root_section_entry_t, n00b_ref_root_sec, count);

// GC stack maps
N00B_ABI_SAME_SIZE(n00b_gc_stack_slot_t, n00b_ref_slot);
N00B_ABI_SAME_OFF(n00b_gc_stack_slot_t, n00b_ref_slot, root_index);
N00B_ABI_SAME_OFF(n00b_gc_stack_slot_t, n00b_ref_slot, num_words);
N00B_ABI_SAME_SIZE(n00b_gc_stack_map_t, n00b_ref_map);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, num_roots);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, num_slots);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, flags);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, slots);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, function_name);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, file_name);
N00B_ABI_SAME_OFF(n00b_gc_stack_map_t, n00b_ref_map, line);
N00B_ABI_SAME_SIZE(n00b_gc_stack_frame_t, n00b_ref_frame);
N00B_ABI_SAME_OFF(n00b_gc_stack_frame_t, n00b_ref_frame, prev);
N00B_ABI_SAME_OFF(n00b_gc_stack_frame_t, n00b_ref_frame, map);
N00B_ABI_SAME_OFF(n00b_gc_stack_frame_t, n00b_ref_frame, roots);

// transient
N00B_ABI_SAME_SIZE(n00b_transient_layout_t, n00b_ref_trlay);
N00B_ABI_SAME_OFF(n00b_transient_layout_t, n00b_ref_trlay, field_count);
N00B_ABI_SAME_OFF(n00b_transient_layout_t, n00b_ref_trlay, byte_offsets);
N00B_ABI_SAME_OFF(n00b_transient_layout_t, n00b_ref_trlay, byte_sizes);
N00B_ABI_SAME_SIZE(n00b_transient_map_entry_t, n00b_ref_trent);
N00B_ABI_SAME_OFF(n00b_transient_map_entry_t, n00b_ref_trent, type_hash);
N00B_ABI_SAME_OFF(n00b_transient_map_entry_t, n00b_ref_trent, layout);
N00B_ABI_SAME_SIZE(n00b_transient_map_index_entry_t, n00b_ref_tridx);
N00B_ABI_SAME_OFF(n00b_transient_map_index_entry_t, n00b_ref_tridx, type_hash);
N00B_ABI_SAME_OFF(n00b_transient_map_index_entry_t, n00b_ref_tridx, entry_index);
