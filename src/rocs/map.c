#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "adt/dict.h"
#include "adt/list.h"
#include "core/align.h"
#include "core/file.h"
#include "core/mmaps.h"
#include "rocs/n00b_rocs.h"
#include "util/marshal.h"

#define N00B_MARSHAL_OP_ALLOC   UINT32_C(0xe11cbab0)
#define N00B_MARSHAL_OP_CPATCH  UINT32_C(0xe31cbab0)
#define N00B_MARSHAL_OP_SPATCH  UINT32_C(0xe41cbab0)
#define N00B_MARSHAL_OP_STOP    UINT32_C(0xe51cbab0)
#define N00B_MARSHAL_OP_PSPATCH UINT32_C(0xe61cbab0)
#define N00B_MARSHAL_OP_CBSCAN  UINT32_C(0xe71cbab0)
#define N00B_MARSHAL_OP_FNPATCH UINT32_C(0xe81cbab0)

#define N00B_MARSHAL_PAYLOAD_FRONT_VERSION 4u
#define N00B_MARSHAL_STATIC_CHECK_MAX      16u
#define N00B_MARSHAL_FN_NAME_MAX           1024u
#define N00B_MARSHAL_SCAN_CB_TAG_LIMIT     6u

#define N00B_MARSHAL_ALLOC_F_SOURCE_INLINE     (1u << 0)
#define N00B_MARSHAL_ALLOC_F_SOURCE_OOB        (1u << 1)
#define N00B_MARSHAL_ALLOC_F_SOURCE_HEADERLESS (1u << 2)
#define N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN   (1u << 3)
#define N00B_MARSHAL_ALLOC_F_KNOWN             \
    (N00B_MARSHAL_ALLOC_F_SOURCE_INLINE        \
     | N00B_MARSHAL_ALLOC_F_SOURCE_OOB         \
     | N00B_MARSHAL_ALLOC_F_SOURCE_HEADERLESS  \
     | N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN)

#define ROCS_MAP_REGION_LABEL "rocs sealed shard image"

/*
 * CONTRACT: These marshal structs mirror util/marshal.c's v4 wire records.
 * They are used only to validate trailing metadata. rocs resident-image reads
 * resolve vaddrs into payload-front bytes and never apply trailing
 * CPATCH/SPATCH/PSPATCH/CBSCAN/FNPATCH records at read time.
 *
 * CONTRACT: Payload-front slots are not globally cleared. Ordinary pointer,
 * static-data, and persistent-static patch slots remain whatever the payload
 * contains; only FNPATCH slots are intentionally zero because code pointers are
 * not meaningful inside a read-only resident image. The shared marshal module
 * still preserves ordinary n00b_unmarshal behavior for non-rocs callers, but
 * rocs sealed-shard readers never unmarshal shard images.
 */

typedef struct {
    uint64_t marshal_magic;
    uint32_t version;
    uint32_t base_address;
    uint32_t root_offset;
    uint32_t payload_front_len;
} rocs_marshal_stream_header_t;

typedef struct {
    uint32_t op;
    uint32_t flags;
    uint64_t vaddr;
    uint64_t user_len;
    uint64_t payload_len;
    uint64_t tinfo;
    uint32_t ptr_words;
    uint32_t scan_kind;
    uint32_t no_scan;
    uint32_t is_array;
} rocs_marshal_alloc_record_t;

typedef struct {
    uint32_t op;
    uint32_t reserved;
    uint64_t vaddr;
    uint64_t value;
} rocs_marshal_cpatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t check_len;
    uint64_t vaddr;
    uint64_t static_addr;
    uint64_t static_start;
    uint64_t static_len;
    uint64_t object_id;
    uint8_t  check[16];
} rocs_marshal_spatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t record_len;
    uint64_t vaddr;
    uint64_t object_offset;
    uint64_t object_len;
    uint64_t tinfo;
    uint32_t flags_mask;
    uint32_t flags_value;
    uint32_t scan_kind;
    uint32_t identity_version;
    uint32_t identity_kind;
    uint32_t namespace_len;
    uint32_t key_len;
    uint32_t check_len;
    uint32_t reserved;
} rocs_marshal_pspatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t record_len;
    uint64_t vaddr;
    uint32_t scan_cb_tag;
    uint32_t has_identity;
    uint64_t object_offset;
    uint64_t object_len;
    uint64_t tinfo;
    uint32_t flags_mask;
    uint32_t flags_value;
    uint32_t scan_kind;
    uint32_t identity_version;
    uint32_t identity_kind;
    uint32_t namespace_len;
    uint32_t key_len;
    uint32_t check_len;
    uint32_t reserved;
} rocs_marshal_cbscan_record_t;

typedef struct {
    uint32_t op;
    uint32_t record_len;
    uint64_t vaddr;
    uint32_t name_len;
    uint32_t reserved;
} rocs_marshal_fnpatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t end_of_stream;
} rocs_marshal_stop_record_t;

typedef struct {
    uint64_t records;
    uint64_t columns;
    uint64_t retain_raw;
    uint32_t state;
    uint32_t reserved;
    uint64_t record_count;
    uint64_t byte_estimate;
    uint64_t open_ts;
    uint64_t seal_ts;
    uint64_t shard_id;
} rocs_mapped_shard_wire_t;

/*
 * CONTRACT: Phase 3 reads this stable shard-root prefix directly from the
 * mapped marshal payload. WP-003's hot n00b_store_shard_t must preserve this
 * prefix or intentionally update this wire view and its tests in the same
 * change.
 */
static_assert(sizeof(rocs_mapped_shard_wire_t) == 72);

typedef struct {
    uint64_t            data;
    size_t              len;
    size_t              cap;
    uint64_t            lock;
    uint64_t            allocator;
    n00b_gc_scan_kind_t scan_kind;
    uint64_t            scan_cb;
    uint64_t            scan_user;
} rocs_mapped_list_wire_t;

/*
 * CONTRACT: Mapped list access uses only data/len/cap plus resolver range
 * checks. The lock, allocator, and scan fields are layout-checked so drift is
 * caught, but mapped readers never dereference them or call hot list APIs.
 */
typedef struct {
    uint32_t         last_slot;
    uint32_t         threshold;
    _Atomic uint32_t used_count;
    uint64_t         buckets;
    uint64_t         keys;
    uint64_t         values;
} rocs_mapped_dict_store_wire_t;

/*
 * CONTRACT: This is the typed dict store prefix from include/adt/dict.h, with
 * pointer fields represented as stored marshal vaddrs. The erased store does
 * not include key/value widths, so every mapped dict view must carry explicit
 * key_stride/value_stride from its schema-level constructor.
 */
static_assert(sizeof(uint64_t) == sizeof(void *));
static_assert(sizeof(rocs_mapped_list_wire_t) == sizeof(n00b_list_t(void *)));
static_assert(offsetof(rocs_mapped_list_wire_t, data)
              == offsetof(n00b_list_t(void *), data));
static_assert(offsetof(rocs_mapped_list_wire_t, len)
              == offsetof(n00b_list_t(void *), len));
static_assert(offsetof(rocs_mapped_list_wire_t, cap)
              == offsetof(n00b_list_t(void *), cap));
static_assert(offsetof(rocs_mapped_list_wire_t, lock)
              == offsetof(n00b_list_t(void *), lock));
static_assert(offsetof(rocs_mapped_dict_store_wire_t, buckets)
              == offsetof(__n00b_internal_type_erased_store_t, buckets));
static_assert(offsetof(rocs_mapped_dict_store_wire_t, keys)
              == offsetof(__n00b_internal_type_erased_store_t, keys));
static_assert(offsetof(rocs_mapped_dict_store_wire_t, values)
              == offsetof(__n00b_internal_type_erased_store_t, values));
static_assert(sizeof(rocs_mapped_dict_store_wire_t)
              == sizeof(__n00b_internal_type_erased_store_t));
static_assert(offsetof(_n00b_dict_internal_t, store) == 0);

typedef enum {
    N00B_STORE_MAP_BACKING_NONE,
    N00B_STORE_MAP_BACKING_COPY,
    N00B_STORE_MAP_BACKING_LOCAL_FILE,
} n00b_store_map_backing_kind_t;

struct n00b_store_map_t {
    uint8_t                         *bytes;
    size_t                           byte_len;
    uint8_t                         *image_base;
    uint32_t                         payload_len;
    uint32_t                         base_address;
    uint32_t                         root_offset;
    bool                             closed;
    n00b_allocator_t                *allocator;
    n00b_store_map_backing_kind_t    backing_kind;
    bool                             region_registered;
    size_t                           mmap_len;
    void                            *owned_mmap;
    n00b_file_t                     *file;
    n00b_buffer_t                   *file_buffer;
};

struct n00b_store_map_shard_t {
    n00b_store_map_t          *map;
    rocs_mapped_shard_wire_t  *wire;
};

struct n00b_store_map_list_t {
    n00b_store_map_t         *map;
    rocs_mapped_list_wire_t  *wire;
};

struct n00b_store_map_dict_t {
    n00b_store_map_t *map;
    uint8_t          *dict;
    size_t            key_stride;
    size_t            value_stride;
};

struct n00b_store_map_slot_t {
    n00b_store_map_t *map;
    uint8_t          *addr;
    size_t            width;
    uint64_t          vaddr;
};

struct n00b_store_map_ref_t {
    n00b_store_map_t *map;
    uint8_t          *addr;
    uint64_t          vaddr;
};

static uint64_t
rocs_align8(uint64_t n)
{
    return (n + 7u) & ~UINT64_C(7);
}

static bool
rocs_mul_overflow_size(size_t a, size_t b, size_t *out)
{
    if (a != 0 && b > SIZE_MAX / a) {
        return true;
    }
    *out = a * b;
    return false;
}

static bool
rocs_add_overflow_uintptr(uintptr_t base, size_t len, uintptr_t *out)
{
    if ((uintptr_t)len > UINTPTR_MAX - base) {
        return true;
    }
    *out = base + (uintptr_t)len;
    return false;
}

static bool
rocs_page_align_size(size_t n, size_t *out)
{
    uint64_t aligned = n00b_page_align((uint64_t)n);
    if (aligned > SIZE_MAX) {
        return false;
    }
    *out = (size_t)aligned;
    return true;
}

static bool
rocs_u32_power_mask(uint32_t last_slot)
{
    return (last_slot & (last_slot + 1u)) == 0;
}

static bool
rocs_vaddr_span_ok(uint32_t base_address,
                   uint32_t payload_len,
                   uint64_t vaddr,
                   uint64_t len)
{
    if ((uint32_t)(vaddr >> 32) != base_address) {
        return false;
    }
    uint64_t offset = vaddr & UINT32_MAX;
    if (offset > payload_len) {
        return false;
    }
    return len <= (uint64_t)payload_len - offset;
}

static bool
rocs_var_record_len_ok(uint32_t fixed_len,
                       uint32_t a,
                       uint32_t b,
                       uint32_t c,
                       uint32_t record_len)
{
    uint64_t len = fixed_len;
    len += a;
    len += b;
    len += c;
    len = rocs_align8(len);
    return len <= UINT32_MAX && record_len == (uint32_t)len;
}

static n00b_store_map_err_t
rocs_validate_records(uint8_t *bytes,
                      size_t   byte_len,
                      uint32_t base_address,
                      uint32_t payload_len,
                      size_t   ix)
{
    uint32_t expected_offset   = 0;
    bool     expect_cbscan     = false;
    uint64_t expected_cbscan_v = 0;

    while (ix < byte_len) {
        if (byte_len - ix < sizeof(uint32_t)) {
            return N00B_STORE_MAP_ERR_BAD_LAYOUT;
        }

        uint32_t op = *(uint32_t *)(bytes + ix);
        if (expect_cbscan && op != N00B_MARSHAL_OP_CBSCAN) {
            return N00B_STORE_MAP_ERR_BAD_LAYOUT;
        }

        switch (op) {
        case N00B_MARSHAL_OP_ALLOC: {
            if (byte_len - ix < sizeof(rocs_marshal_alloc_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_alloc_record_t *rec = (void *)(bytes + ix);
            if ((rec->vaddr >> 32) != base_address
                || (uint32_t)(rec->vaddr & UINT32_MAX) != expected_offset
                || rec->payload_len != rocs_align8(rec->user_len)
                || rec->payload_len < rec->user_len
                || rec->ptr_words > (rec->user_len / sizeof(uint64_t))
                || rec->scan_kind > N00B_GC_SCAN_KIND_CALLBACK
                || (rec->flags & ~N00B_MARSHAL_ALLOC_F_KNOWN) != 0
                || rec->payload_len > UINT32_MAX
                || expected_offset > UINT32_MAX - (uint32_t)rec->payload_len
                || !rocs_vaddr_span_ok(base_address,
                                       payload_len,
                                       rec->vaddr,
                                       rec->payload_len)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            if (rec->scan_kind == N00B_GC_SCAN_KIND_CALLBACK) {
                expect_cbscan     = true;
                expected_cbscan_v = rec->vaddr;
            }
            expected_offset += (uint32_t)rec->payload_len;
            ix += sizeof(*rec);
            break;
        }
        case N00B_MARSHAL_OP_CPATCH: {
            if (byte_len - ix < sizeof(rocs_marshal_cpatch_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_cpatch_record_t *rec = (void *)(bytes + ix);
            if (rec->reserved != 0
                || !rocs_vaddr_span_ok(base_address,
                                       payload_len,
                                       rec->vaddr,
                                       sizeof(uint64_t))) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            ix += sizeof(*rec);
            break;
        }
        case N00B_MARSHAL_OP_SPATCH: {
            if (byte_len - ix < sizeof(rocs_marshal_spatch_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_spatch_record_t *rec = (void *)(bytes + ix);
            if (rec->check_len == 0
                || rec->check_len > sizeof(rec->check)
                || !rocs_vaddr_span_ok(base_address,
                                       payload_len,
                                       rec->vaddr,
                                       sizeof(uint64_t))
                || rec->static_addr < rec->static_start
                || rec->static_addr - rec->static_start >= rec->static_len
                || rec->check_len > rec->static_len
                    - (rec->static_addr - rec->static_start)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            ix += sizeof(*rec);
            break;
        }
        case N00B_MARSHAL_OP_PSPATCH: {
            if (byte_len - ix < sizeof(rocs_marshal_pspatch_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_pspatch_record_t *rec = (void *)(bytes + ix);
            uint32_t flags_mask = N00B_STATIC_OBJECT_F_READONLY
                                | N00B_STATIC_OBJECT_F_MUTABLE;
            if (byte_len - ix < rec->record_len
                || !rocs_vaddr_span_ok(base_address,
                                       payload_len,
                                       rec->vaddr,
                                       sizeof(uint64_t))
                || rec->object_len == 0
                || rec->object_offset >= rec->object_len
                || rec->check_len == 0
                || rec->check_len > N00B_MARSHAL_STATIC_CHECK_MAX
                || rec->check_len > rec->object_len - rec->object_offset
                || rec->identity_version != N00B_STATIC_IDENTITY_VERSION
                || rec->identity_kind == N00B_STATIC_IDENTITY_NONE
                || rec->identity_kind > N00B_STATIC_IDENTITY_MANUAL
                || rec->flags_mask != flags_mask
                || (rec->flags_value & ~rec->flags_mask) != 0
                || rec->scan_kind > N00B_GC_SCAN_KIND_CALLBACK
                || rec->reserved != 0
                || !rocs_var_record_len_ok(sizeof(*rec),
                                           rec->namespace_len,
                                           rec->key_len,
                                           rec->check_len,
                                           rec->record_len)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            ix += rec->record_len;
            break;
        }
        case N00B_MARSHAL_OP_FNPATCH: {
            if (byte_len - ix < sizeof(rocs_marshal_fnpatch_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_fnpatch_record_t *rec = (void *)(bytes + ix);
            if (byte_len - ix < rec->record_len
                || rec->reserved != 0
                || rec->name_len == 0
                || rec->name_len > N00B_MARSHAL_FN_NAME_MAX
                || !rocs_vaddr_span_ok(base_address,
                                       payload_len,
                                       rec->vaddr,
                                       sizeof(uint64_t))
                || !rocs_var_record_len_ok(sizeof(*rec),
                                           rec->name_len,
                                           0,
                                           0,
                                           rec->record_len)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            ix += rec->record_len;
            break;
        }
        case N00B_MARSHAL_OP_CBSCAN: {
            if (byte_len - ix < sizeof(rocs_marshal_cbscan_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_cbscan_record_t *rec = (void *)(bytes + ix);
            if (!expect_cbscan
                || rec->vaddr != expected_cbscan_v
                || rec->scan_cb_tag >= N00B_MARSHAL_SCAN_CB_TAG_LIMIT
                || rec->has_identity > 1
                || byte_len - ix < rec->record_len
                || rec->reserved != 0) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            if (rec->has_identity == 0) {
                if (rec->record_len != rocs_align8(sizeof(*rec))
                    || rec->namespace_len != 0
                    || rec->key_len != 0
                    || rec->check_len != 0
                    || rec->object_offset != 0
                    || rec->object_len != 0
                    || rec->tinfo != 0
                    || rec->flags_mask != 0
                    || rec->flags_value != 0
                    || rec->scan_kind != 0
                    || rec->identity_version != 0
                    || rec->identity_kind != 0) {
                    return N00B_STORE_MAP_ERR_BAD_LAYOUT;
                }
            }
            else {
                uint32_t flags_mask = N00B_STATIC_OBJECT_F_READONLY
                                    | N00B_STATIC_OBJECT_F_MUTABLE;
                if (rec->object_len == 0
                    || rec->object_offset >= rec->object_len
                    || rec->check_len == 0
                    || rec->check_len > N00B_MARSHAL_STATIC_CHECK_MAX
                    || rec->check_len > rec->object_len - rec->object_offset
                    || rec->identity_version != N00B_STATIC_IDENTITY_VERSION
                    || rec->identity_kind == N00B_STATIC_IDENTITY_NONE
                    || rec->identity_kind > N00B_STATIC_IDENTITY_MANUAL
                    || rec->flags_mask != flags_mask
                    || (rec->flags_value & ~rec->flags_mask) != 0
                    || rec->scan_kind > N00B_GC_SCAN_KIND_CALLBACK
                    || !rocs_var_record_len_ok(sizeof(*rec),
                                               rec->namespace_len,
                                               rec->key_len,
                                               rec->check_len,
                                               rec->record_len)) {
                    return N00B_STORE_MAP_ERR_BAD_LAYOUT;
                }
            }
            expect_cbscan = false;
            ix += rec->record_len;
            break;
        }
        case N00B_MARSHAL_OP_STOP: {
            if (byte_len - ix < sizeof(rocs_marshal_stop_record_t)) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            rocs_marshal_stop_record_t *rec = (void *)(bytes + ix);
            if (rec->end_of_stream != 1
                || ix + sizeof(*rec) != byte_len
                || expected_offset != payload_len
                || expect_cbscan) {
                return N00B_STORE_MAP_ERR_BAD_LAYOUT;
            }
            return N00B_STORE_MAP_OK;
        }
        default:
            return N00B_STORE_MAP_ERR_BAD_LAYOUT;
        }
    }

    return N00B_STORE_MAP_ERR_BAD_LAYOUT;
}

static n00b_store_map_err_t
rocs_validate_image(uint8_t *bytes, size_t byte_len)
{
    if (bytes == nullptr) {
        return N00B_STORE_MAP_ERR_ARG;
    }
    if (byte_len < sizeof(rocs_marshal_stream_header_t)) {
        return N00B_STORE_MAP_ERR_BAD_LAYOUT;
    }

    rocs_marshal_stream_header_t *hdr = (void *)bytes;
    if (hdr->marshal_magic != N00B_MARSHAL_MAGIC) {
        return N00B_STORE_MAP_ERR_BAD_MAGIC;
    }
    if (hdr->version < N00B_MARSHAL_PAYLOAD_FRONT_VERSION
        || hdr->version > N00B_MARSHAL_VERSION) {
        return N00B_STORE_MAP_ERR_BAD_VERSION;
    }
    if (hdr->payload_front_len == 0
        || hdr->root_offset >= hdr->payload_front_len
        || (size_t)hdr->payload_front_len > byte_len - sizeof(*hdr)) {
        return N00B_STORE_MAP_ERR_BAD_LAYOUT;
    }

    size_t metadata_ix = sizeof(*hdr) + (size_t)hdr->payload_front_len;
    return rocs_validate_records(bytes,
                                 byte_len,
                                 hdr->base_address,
                                 hdr->payload_front_len,
                                 metadata_ix);
}

static n00b_store_map_t *
rocs_map_alloc(n00b_allocator_t *allocator)
{
    n00b_store_map_t *map = n00b_alloc_with_opts(
        n00b_store_map_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    map->allocator = allocator;
    return map;
}

#define ROCS_VIEW_ALLOC(map, T)                                                               \
    n00b_alloc_with_opts(T, &(n00b_alloc_opts_t){.allocator = (map)->allocator})

static void *
rocs_map_resolve_span(n00b_store_map_t *map, uint64_t vaddr, size_t len)
{
    if (map == nullptr || map->closed) {
        return nullptr;
    }
    if (!rocs_vaddr_span_ok(map->base_address, map->payload_len, vaddr, len)) {
        return nullptr;
    }
    uint32_t offset = (uint32_t)(vaddr & UINT32_MAX);
    return map->image_base + offset;
}

static n00b_result_t(void *)
rocs_map_resolve_required(n00b_store_map_t *map, uint64_t vaddr, size_t len)
{
    void *ptr = rocs_map_resolve_span(map, vaddr, len);
    if (ptr == nullptr) {
        return n00b_result_err(void *, N00B_STORE_MAP_ERR_RANGE);
    }
    return n00b_result_ok(void *, ptr);
}

static void
rocs_map_init_from_bytes(n00b_store_map_t *map, uint8_t *bytes, size_t byte_len)
{
    rocs_marshal_stream_header_t *hdr = (void *)bytes;
    map->bytes        = bytes;
    map->byte_len     = byte_len;
    map->image_base   = bytes + sizeof(*hdr);
    map->payload_len  = hdr->payload_front_len;
    map->base_address = hdr->base_address;
    map->root_offset  = hdr->root_offset;
}

static n00b_store_map_err_t
rocs_map_register_region(n00b_store_map_t *map,
                         size_t            mmap_len,
                         n00b_mmap_perms_t perms)
{
    if (map == nullptr
        || map->bytes == nullptr
        || map->byte_len == 0
        || mmap_len < map->byte_len
        || map->region_registered) {
        return N00B_STORE_MAP_ERR_BACKING;
    }

    uintptr_t start      = (uintptr_t)map->bytes;
    uintptr_t mmap_end   = 0;
    uintptr_t image_end  = 0;
    if (rocs_add_overflow_uintptr(start, mmap_len, &mmap_end)
        || rocs_add_overflow_uintptr(start, map->byte_len, &image_end)
        || mmap_end <= start
        || image_end <= start) {
        return N00B_STORE_MAP_ERR_BACKING;
    }

    /*
     * CONTRACT: rocs sealed shard bytes are resident, non-moving, and
     * immutable for rocs callers, but they are not ordinary n00b heap objects
     * and do not contain registered static objects. Register the backing only
     * so runtime address classification can find it. The GC's api-mmap case is
     * opaque and returns without tracing or rewriting shard contents.
     */
    auto mmap_opt = n00b_mmap_register(map->bytes,
                                       (void *)mmap_end,
                                       n00b_mmap_api_mmap,
                                       .file  = ROCS_MAP_REGION_LABEL,
                                       .perms = perms);
    if (!n00b_option_is_set(mmap_opt)) {
        return N00B_STORE_MAP_ERR_BACKING;
    }

    (void)image_end;
    map->region_registered = true;
    map->mmap_len          = mmap_len;
    return N00B_STORE_MAP_OK;
}

static void
rocs_map_unregister_region(n00b_store_map_t *map)
{
    if (map != nullptr && map->region_registered && map->bytes != nullptr) {
        n00b_mmap_unregister(map->bytes);
        map->region_registered = false;
    }
}

void
n00b_rocs_module_init(void)
{
}

void
n00b_rocs_module_shutdown(void)
{
}

n00b_string_t *
n00b_store_map_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_MAP_OK:              return r"OK";
    case N00B_STORE_MAP_ERR_ARG:         return r"ARG";
    case N00B_STORE_MAP_ERR_IO:          return r"IO";
    case N00B_STORE_MAP_ERR_BAD_MAGIC:   return r"BAD_MAGIC";
    case N00B_STORE_MAP_ERR_BAD_VERSION: return r"BAD_VERSION";
    case N00B_STORE_MAP_ERR_BAD_LAYOUT:  return r"BAD_LAYOUT";
    case N00B_STORE_MAP_ERR_RANGE:       return r"RANGE";
    case N00B_STORE_MAP_ERR_SCHEMA:      return r"SCHEMA";
    case N00B_STORE_MAP_ERR_BACKING:     return r"BACKING";
    case N00B_STORE_MAP_ERR_CACHE:       return r"CACHE";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_store_map_t *)
n00b_store_map_open_buffer(n00b_buffer_t *image) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (image == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_ARG);
    }

    _n00b_buffer_rlock(image);
    size_t byte_len = image->byte_len;
    if (byte_len == 0 || image->data == nullptr) {
        _n00b_buffer_unlock(image);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    size_t mmap_len = 0;
    if (!rocs_page_align_size(byte_len, &mmap_len)) {
        _n00b_buffer_unlock(image);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_BACKING);
    }

    auto mmap_r = n00b_mmap(byte_len,
                            .kind = n00b_mmap_api_mmap,
                            .skip_register = true);
    if (n00b_result_is_err(mmap_r)) {
        _n00b_buffer_unlock(image);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_BACKING);
    }

    uint8_t *copy = n00b_result_get(mmap_r);
    memcpy(copy, image->data, byte_len);
    _n00b_buffer_unlock(image);

    n00b_store_map_err_t valid = rocs_validate_image(copy, byte_len);
    if (valid != N00B_STORE_MAP_OK) {
        n00b_safe_munmap(copy, mmap_len);
        return n00b_result_err(n00b_store_map_t *, valid);
    }

    n00b_store_map_t *map = rocs_map_alloc(allocator);
    rocs_map_init_from_bytes(map, copy, byte_len);
    map->backing_kind = N00B_STORE_MAP_BACKING_COPY;
    map->owned_mmap   = copy;

    n00b_store_map_err_t reg = rocs_map_register_region(map,
                                                        mmap_len,
                                                        n00b_mmap_perms_rw);
    if (reg != N00B_STORE_MAP_OK) {
        n00b_safe_munmap(copy, mmap_len);
        return n00b_result_err(n00b_store_map_t *, reg);
    }

    return n00b_result_ok(n00b_store_map_t *, map);
}

n00b_result_t(n00b_store_map_t *)
n00b_store_map_open_local_file(n00b_string_t *path) _kargs
{
    bool              populate  = false;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (path == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_ARG);
    }

    auto file_r = n00b_file_open(path,
                                 .kind     = N00B_FILE_KIND_MMAP,
                                 .populate = populate);
    if (n00b_result_is_err(file_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_IO);
    }

    n00b_file_t *file = n00b_result_get(file_r);
    auto         buf_r = n00b_file_as_buffer(file);
    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(file);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_BACKING);
    }

    n00b_buffer_t *buf = n00b_result_get(buf_r);
    if (buf == nullptr || buf->data == nullptr || buf->byte_len == 0) {
        n00b_file_close(file);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    _n00b_buffer_rlock(buf);
    n00b_store_map_err_t valid = rocs_validate_image((uint8_t *)buf->data,
                                                     buf->byte_len);
    _n00b_buffer_unlock(buf);
    if (valid != N00B_STORE_MAP_OK) {
        n00b_buffer_free(buf);
        n00b_file_close(file);
        return n00b_result_err(n00b_store_map_t *, valid);
    }

    n00b_store_map_t *map = rocs_map_alloc(allocator);
    rocs_map_init_from_bytes(map, (uint8_t *)buf->data, buf->byte_len);
    map->backing_kind = N00B_STORE_MAP_BACKING_LOCAL_FILE;
    map->file         = file;
    map->file_buffer  = buf;

    n00b_store_map_err_t reg = rocs_map_register_region(map,
                                                        buf->byte_len,
                                                        n00b_mmap_perms_ro);
    if (reg != N00B_STORE_MAP_OK) {
        n00b_buffer_free(buf);
        n00b_file_close(file);
        return n00b_result_err(n00b_store_map_t *, reg);
    }

    return n00b_result_ok(n00b_store_map_t *, map);
}

n00b_result_t(n00b_store_map_t *)
n00b_store_map_open_vfs(n00b_vfs_t *vfs, n00b_string_t *path) _kargs
{
    n00b_vfs_cache_t              *cache     = nullptr;
    n00b_store_residency_policy_t *policy    = nullptr;
}
{
    /*
     * CONTRACT: VFS/S3-backed residency belongs to WP-005. Keep the public
     * entry point stable in WP-001, but fail predictably instead of silently
     * falling back to local mmap semantics for remote paths.
     */
    (void)vfs;
    (void)path;
    (void)cache;
    (void)policy;
    return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_CACHE);
}

n00b_result_t(bool)
n00b_store_map_close(n00b_store_map_t *map)
{
    if (map == nullptr || map->closed) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_ARG);
    }

    n00b_store_map_err_t err = N00B_STORE_MAP_OK;
    if (map->owned_mmap != nullptr) {
        auto munmap_r = n00b_munmap(map->owned_mmap);
        if (n00b_result_is_err(munmap_r)) {
            n00b_safe_munmap(map->owned_mmap, map->mmap_len);
            map->region_registered = false;
            err = N00B_STORE_MAP_ERR_BACKING;
        }
        else {
            map->region_registered = false;
        }
        map->owned_mmap = nullptr;
    }
    if (map->backing_kind == N00B_STORE_MAP_BACKING_LOCAL_FILE) {
        rocs_map_unregister_region(map);
    }
    if (map->file_buffer != nullptr) {
        n00b_buffer_free(map->file_buffer);
        map->file_buffer = nullptr;
    }
    if (map->file != nullptr) {
        auto close_r = n00b_file_close_result(map->file);
        if (err == N00B_STORE_MAP_OK && n00b_result_is_err(close_r)) {
            err = N00B_STORE_MAP_ERR_IO;
        }
        map->file = nullptr;
    }

    map->bytes       = nullptr;
    map->byte_len    = 0;
    map->mmap_len    = 0;
    map->image_base  = nullptr;
    map->payload_len = 0;
    map->backing_kind = N00B_STORE_MAP_BACKING_NONE;
    map->closed      = true;

    if (err != N00B_STORE_MAP_OK) {
        return n00b_result_err(bool, err);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_map_resident_base_for_test(n00b_store_map_t *map)
{
    if (map == nullptr || map->closed || map->bytes == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, (uint64_t)(uintptr_t)map->bytes);
}

n00b_result_t(uint64_t)
n00b_store_map_resident_len_for_test(n00b_store_map_t *map)
{
    if (map == nullptr || map->closed || map->byte_len == 0) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, (uint64_t)map->byte_len);
}

n00b_result_t(n00b_store_map_shard_t *)
n00b_store_map_root(n00b_store_map_t *map)
{
    if (map == nullptr || map->closed) {
        return n00b_result_err(n00b_store_map_shard_t *, N00B_STORE_MAP_ERR_ARG);
    }

    uint64_t root_vaddr = ((uint64_t)map->base_address << 32) | map->root_offset;
    auto     root_r     = rocs_map_resolve_required(map,
                                                    root_vaddr,
                                                    sizeof(rocs_mapped_shard_wire_t));
    if (n00b_result_is_err(root_r)) {
        return n00b_result_err(n00b_store_map_shard_t *, n00b_result_get_err(root_r));
    }

    n00b_store_map_shard_t *shard = ROCS_VIEW_ALLOC(map, n00b_store_map_shard_t);
    shard->map  = map;
    shard->wire = n00b_result_get(root_r);
    return n00b_result_ok(n00b_store_map_shard_t *, shard);
}

n00b_result_t(uint64_t)
n00b_store_map_shard_id(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, shard->wire->shard_id);
}

n00b_result_t(uint64_t)
n00b_store_map_shard_records_len(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, shard->wire->record_count);
}

n00b_result_t(n00b_store_map_list_t *)
n00b_store_map_shard_records(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(n00b_store_map_list_t *, N00B_STORE_MAP_ERR_ARG);
    }

    auto list_r = rocs_map_resolve_required(shard->map,
                                            shard->wire->records,
                                            sizeof(rocs_mapped_list_wire_t));
    if (n00b_result_is_err(list_r)) {
        return n00b_result_err(n00b_store_map_list_t *, n00b_result_get_err(list_r));
    }

    n00b_store_map_list_t *list = ROCS_VIEW_ALLOC(shard->map, n00b_store_map_list_t);
    list->map  = shard->map;
    list->wire = n00b_result_get(list_r);
    return n00b_result_ok(n00b_store_map_list_t *, list);
}

n00b_result_t(n00b_store_map_dict_t *)
n00b_store_map_shard_columns(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(n00b_store_map_dict_t *, N00B_STORE_MAP_ERR_ARG);
    }

    auto dict_r = rocs_map_resolve_required(shard->map,
                                            shard->wire->columns,
                                            sizeof(uint64_t));
    if (n00b_result_is_err(dict_r)) {
        return n00b_result_err(n00b_store_map_dict_t *, n00b_result_get_err(dict_r));
    }

    n00b_store_map_dict_t *dict = ROCS_VIEW_ALLOC(shard->map, n00b_store_map_dict_t);
    dict->map          = shard->map;
    dict->dict         = n00b_result_get(dict_r);
    /*
     * CONTRACT: Phase 3 shard-columns fixtures are pointer-key/pointer-value
     * typed dicts. Future mapped dict constructors for hash keys, postings, or
     * packed scalar values must set schema-appropriate strides here instead of
     * inferring widths from the erased dict store.
     */
    dict->key_stride   = sizeof(uint64_t);
    dict->value_stride = sizeof(uint64_t);
    return n00b_result_ok(n00b_store_map_dict_t *, dict);
}

n00b_result_t(uint64_t)
n00b_store_map_list_len(n00b_store_map_list_t *list)
{
    if (list == nullptr || list->map == nullptr || list->map->closed) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, list->wire->len);
}

n00b_result_t(n00b_option_t(n00b_store_map_slot_t *))
n00b_store_map_list_slot(n00b_store_map_list_t *list, uint64_t ordinal)
{
    if (list == nullptr || list->map == nullptr || list->map->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_map_slot_t *),
                               N00B_STORE_MAP_ERR_ARG);
    }
    if (ordinal >= list->wire->len) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_slot_t *),
                              n00b_option_none(n00b_store_map_slot_t *));
    }

    size_t span;
    if (rocs_mul_overflow_size((size_t)list->wire->len, sizeof(uint64_t), &span)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_slot_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }
    uint8_t *data = rocs_map_resolve_span(list->map, list->wire->data, span);
    if (data == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_map_slot_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }

    n00b_store_map_slot_t *slot = ROCS_VIEW_ALLOC(list->map, n00b_store_map_slot_t);
    slot->map   = list->map;
    slot->addr  = data + ordinal * sizeof(uint64_t);
    slot->width = sizeof(uint64_t);
    slot->vaddr = list->wire->data + ordinal * sizeof(uint64_t);
    return n00b_result_ok(n00b_option_t(n00b_store_map_slot_t *),
                          n00b_option_set(n00b_store_map_slot_t *, slot));
}

n00b_result_t(n00b_option_t(n00b_store_map_ref_t *))
n00b_store_map_slot_ref(n00b_store_map_slot_t *slot)
{
    if (slot == nullptr || slot->map == nullptr || slot->map->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_map_ref_t *),
                               N00B_STORE_MAP_ERR_ARG);
    }
    if (slot->width < sizeof(uint64_t)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_ref_t *),
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    uint64_t raw = *(uint64_t *)slot->addr;
    if (raw == 0) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_ref_t *),
                              n00b_option_none(n00b_store_map_ref_t *));
    }

    uint8_t *addr = rocs_map_resolve_span(slot->map, raw, 1);
    if (addr == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_map_ref_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }

    n00b_store_map_ref_t *ref = ROCS_VIEW_ALLOC(slot->map, n00b_store_map_ref_t);
    ref->map   = slot->map;
    ref->addr  = addr;
    ref->vaddr = raw;
    return n00b_result_ok(n00b_option_t(n00b_store_map_ref_t *),
                          n00b_option_set(n00b_store_map_ref_t *, ref));
}

n00b_result_t(n00b_option_t(n00b_store_map_dict_entry_t *))
n00b_store_map_dict_find_hv(n00b_store_map_dict_t *dict, n00b_uint128_t hv)
{
    if (dict == nullptr || dict->map == nullptr || dict->map->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_map_dict_entry_t *),
                               N00B_STORE_MAP_ERR_ARG);
    }
    if (hv == (n00b_uint128_t)0) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_dict_entry_t *),
                              n00b_option_none(n00b_store_map_dict_entry_t *));
    }

    /*
     * CONTRACT: Mapped dict lookup is a read-only probe over sealed bytes. It
     * never calls _n00b_dict_internal_get/n00b_dict_get, never obtains the dict
     * rwlock, and never mutates bucket flags. Bucket synchronization flags
     * (MUTEX/COPYING/MOVING) are ignored because sealed images are immutable;
     * only DELETED has lookup semantics.
     */
    uint64_t store_vaddr = *(uint64_t *)dict->dict;
    rocs_mapped_dict_store_wire_t *store = rocs_map_resolve_span(
        dict->map,
        store_vaddr,
        sizeof(rocs_mapped_dict_store_wire_t));
    if (store == nullptr || !rocs_u32_power_mask(store->last_slot)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_dict_entry_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }

    size_t bucket_count = (size_t)store->last_slot + 1u;
    size_t bucket_span;
    size_t key_span;
    size_t value_span;
    if (rocs_mul_overflow_size(bucket_count, sizeof(n00b_dict_bucket_t), &bucket_span)
        || rocs_mul_overflow_size(bucket_count, dict->key_stride, &key_span)
        || rocs_mul_overflow_size(bucket_count, dict->value_stride, &value_span)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_dict_entry_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }

    n00b_dict_bucket_t *buckets = rocs_map_resolve_span(dict->map,
                                                        store->buckets,
                                                        bucket_span);
    uint8_t *keys = rocs_map_resolve_span(dict->map, store->keys, key_span);
    uint8_t *vals = rocs_map_resolve_span(dict->map, store->values, value_span);
    if (buckets == nullptr || keys == nullptr || vals == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_map_dict_entry_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }

    uint32_t bix = (uint32_t)(hv & store->last_slot);
    for (uint32_t i = 0; i <= store->last_slot; i++) {
        n00b_dict_bucket_t *bucket = &buckets[bix];
        n00b_uint128_t      bhv    = bucket->hv;
        uint32_t            flags  = atomic_load_explicit(&bucket->flags,
                                                          memory_order_relaxed);

        if (bhv == hv) {
            if ((flags & N00B_HT_FLAG_DELETED) != 0) {
                return n00b_result_ok(
                    n00b_option_t(n00b_store_map_dict_entry_t *),
                    n00b_option_none(n00b_store_map_dict_entry_t *));
            }

            n00b_store_map_slot_t *key = ROCS_VIEW_ALLOC(dict->map,
                                                         n00b_store_map_slot_t);
            key->map   = dict->map;
            key->addr  = keys + (size_t)bix * dict->key_stride;
            key->width = dict->key_stride;
            key->vaddr = store->keys + (size_t)bix * dict->key_stride;

            n00b_store_map_slot_t *value = ROCS_VIEW_ALLOC(dict->map,
                                                           n00b_store_map_slot_t);
            value->map   = dict->map;
            value->addr  = vals + (size_t)bix * dict->value_stride;
            value->width = dict->value_stride;
            value->vaddr = store->values + (size_t)bix * dict->value_stride;

            n00b_store_map_dict_entry_t *entry = ROCS_VIEW_ALLOC(
                dict->map,
                n00b_store_map_dict_entry_t);
            entry->key          = key;
            entry->value        = value;
            entry->hv           = hv;
            entry->bucket_index = bix;

            return n00b_result_ok(
                n00b_option_t(n00b_store_map_dict_entry_t *),
                n00b_option_set(n00b_store_map_dict_entry_t *, entry));
        }

        if (bhv == (n00b_uint128_t)0) {
            return n00b_result_ok(n00b_option_t(n00b_store_map_dict_entry_t *),
                                  n00b_option_none(n00b_store_map_dict_entry_t *));
        }

        bix = (bix + 1u) & store->last_slot;
    }

    return n00b_result_ok(n00b_option_t(n00b_store_map_dict_entry_t *),
                          n00b_option_none(n00b_store_map_dict_entry_t *));
}
