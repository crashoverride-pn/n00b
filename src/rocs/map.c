#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "adt/dict.h"
#include "adt/list.h"
#include "core/align.h"
#include "core/file.h"
#include "core/hash.h"
#include "core/mmaps.h"
#include "internal/rocs/map.h"
#include "rocs/n00b_rocs.h"
#include "rocs/shard.h"
#include "util/marshal.h"
#include "vfs/cache.h"
#include "vfs/vfs.h"

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
    uint64_t raw_bytes;
    uint32_t state;
    uint32_t reserved;
    uint64_t record_count;
    uint64_t byte_estimate;
    uint64_t open_ts;
    uint64_t seal_ts;
    uint64_t shard_id;
} rocs_mapped_shard_wire_t;

typedef struct {
    uint64_t data;
    uint64_t byte_len;
} rocs_mapped_raw_blob_wire_t;

typedef struct {
    uint64_t offset;
    uint64_t byte_len;
} rocs_mapped_raw_span_wire_t;

/*
 * CONTRACT: Phase 3 reads this stable shard-root prefix directly from the
 * mapped marshal payload. WP-003's hot n00b_store_shard_t must preserve this
 * prefix or intentionally update this wire view and its tests in the same
 * change.
 */
static_assert(sizeof(rocs_mapped_raw_blob_wire_t) == sizeof(n00b_store_raw_blob_t));
static_assert(offsetof(rocs_mapped_raw_blob_wire_t, data)
              == offsetof(n00b_store_raw_blob_t, data));
static_assert(offsetof(rocs_mapped_raw_blob_wire_t, byte_len)
              == offsetof(n00b_store_raw_blob_t, byte_len));
static_assert(sizeof(rocs_mapped_raw_span_wire_t) == sizeof(n00b_store_raw_span_t));
static_assert(offsetof(rocs_mapped_raw_span_wire_t, offset)
              == offsetof(n00b_store_raw_span_t, offset));
static_assert(offsetof(rocs_mapped_raw_span_wire_t, byte_len)
              == offsetof(n00b_store_raw_span_t, byte_len));

static_assert(sizeof(rocs_mapped_shard_wire_t) == 80);
static_assert(sizeof(rocs_mapped_shard_wire_t) == sizeof(n00b_store_shard_t));
static_assert(offsetof(rocs_mapped_shard_wire_t, records)
              == offsetof(n00b_store_shard_t, records));
static_assert(offsetof(rocs_mapped_shard_wire_t, columns)
              == offsetof(n00b_store_shard_t, columns));
static_assert(offsetof(rocs_mapped_shard_wire_t, retain_raw)
              == offsetof(n00b_store_shard_t, retain_raw));
static_assert(offsetof(rocs_mapped_shard_wire_t, raw_bytes)
              == offsetof(n00b_store_shard_t, raw_bytes));
static_assert(offsetof(rocs_mapped_shard_wire_t, state)
              == offsetof(n00b_store_shard_t, state));
static_assert(offsetof(rocs_mapped_shard_wire_t, record_count)
              == offsetof(n00b_store_shard_t, record_count));
static_assert(offsetof(rocs_mapped_shard_wire_t, byte_estimate)
              == offsetof(n00b_store_shard_t, byte_estimate));
static_assert(offsetof(rocs_mapped_shard_wire_t, open_ts)
              == offsetof(n00b_store_shard_t, open_ts));
static_assert(offsetof(rocs_mapped_shard_wire_t, seal_ts)
              == offsetof(n00b_store_shard_t, seal_ts));
static_assert(offsetof(rocs_mapped_shard_wire_t, shard_id)
              == offsetof(n00b_store_shard_t, shard_id));

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

typedef struct {
    uint32_t kind;
    uint32_t reserved;
    uint64_t count;
    uint64_t ordinals;
    uint64_t flags;
} rocs_mapped_posting_list_wire_t;

typedef struct {
    uint64_t contents;
    uint64_t num_flags;
    uint64_t alloc_wordlen;
    uint64_t allocator;
} rocs_mapped_flagset_wire_t;

static_assert(sizeof(rocs_mapped_posting_list_wire_t)
              == sizeof(n00b_store_posting_list_t));
static_assert(offsetof(rocs_mapped_posting_list_wire_t, kind)
              == offsetof(n00b_store_posting_list_t, kind));
static_assert(offsetof(rocs_mapped_posting_list_wire_t, count)
              == offsetof(n00b_store_posting_list_t, count));
static_assert(offsetof(rocs_mapped_posting_list_wire_t, ordinals)
              == offsetof(n00b_store_posting_list_t, ordinals));
static_assert(offsetof(rocs_mapped_posting_list_wire_t, flags)
              == offsetof(n00b_store_posting_list_t, flags));
static_assert(sizeof(rocs_mapped_flagset_wire_t) == sizeof(n00b_flagset_t));
static_assert(offsetof(rocs_mapped_flagset_wire_t, contents)
              == offsetof(n00b_flagset_t, contents));
static_assert(offsetof(rocs_mapped_flagset_wire_t, num_flags)
              == offsetof(n00b_flagset_t, num_flags));
static_assert(offsetof(rocs_mapped_flagset_wire_t, alloc_wordlen)
              == offsetof(n00b_flagset_t, alloc_wordlen));

typedef struct {
    uint64_t data;
    size_t   u8_bytes;
    size_t   codepoints;
    uint64_t styling;
} rocs_mapped_string_wire_t;

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
static_assert(sizeof(rocs_mapped_string_wire_t) == sizeof(n00b_string_t));
static_assert(offsetof(rocs_mapped_string_wire_t, data)
              == offsetof(n00b_string_t, data));
static_assert(offsetof(rocs_mapped_string_wire_t, u8_bytes)
              == offsetof(n00b_string_t, u8_bytes));
static_assert(offsetof(rocs_mapped_string_wire_t, codepoints)
              == offsetof(n00b_string_t, codepoints));
static_assert(offsetof(rocs_mapped_string_wire_t, styling)
              == offsetof(n00b_string_t, styling));
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

struct n00b_store_map_posting_list_t {
    n00b_store_map_t                  *map;
    rocs_mapped_posting_list_wire_t   *wire;
    n00b_store_map_list_t             *ordinals;
    rocs_mapped_flagset_wire_t        *flags;
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

struct n00b_store_map_buffer_t {
    n00b_store_map_t *map;
    uint8_t          *data;
    uint64_t          byte_len;
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

static const n00b_gc_struct_array_t _rocs_map_json_node_pointer_shape = {
    .stride = 1,
    .offset = 1,
    .count  = 1,
};

static n00b_json_node_t *
_rocs_map_json_scalar_alloc(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_json_node_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
}

static n00b_json_node_t *
_rocs_map_json_pointer_alloc(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_json_node_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = n00b_gc_scan_cb_struct_field,
            .scan_user = (void *)&_rocs_map_json_node_pointer_shape,
        });
}

static n00b_result_t(n00b_string_t *)
_rocs_map_string_copy_from_vaddr(n00b_store_map_t  *map,
                                 uint64_t           vaddr,
                                 n00b_allocator_t  *allocator)
{
    auto string_r = rocs_map_resolve_required(map,
                                              vaddr,
                                              sizeof(rocs_mapped_string_wire_t));
    if (n00b_result_is_err(string_r)) {
        auto range_opt = n00b_mmap_range_by_address((void *)(uintptr_t)vaddr);
        if (!n00b_option_is_set(range_opt)) {
            return n00b_result_err(n00b_string_t *, n00b_result_get_err(string_r));
        }

        n00b_alloc_range_t *range = n00b_option_get(range_opt);
        if (range->kind != n00b_mmap_static
            || range->start != (void *)(uintptr_t)vaddr
            || range->len < sizeof(n00b_string_t)) {
            return n00b_result_err(n00b_string_t *, n00b_result_get_err(string_r));
        }

        n00b_string_t *s = (n00b_string_t *)(uintptr_t)vaddr;
        if (s->u8_bytes > (size_t)INT64_MAX
            || (s->u8_bytes != 0 && s->data == nullptr)) {
            return n00b_result_err(n00b_string_t *, N00B_STORE_MAP_ERR_RANGE);
        }
        if (s->u8_bytes == 0) {
            return n00b_result_ok(n00b_string_t *,
                                  n00b_string_from_raw("",
                                                       0,
                                                       .allocator = allocator));
        }
        return n00b_result_ok(n00b_string_t *,
                              n00b_string_from_raw(s->data,
                                                   (int64_t)s->u8_bytes,
                                                   .allocator = allocator));
    }

    rocs_mapped_string_wire_t *mapped = n00b_result_get(string_r);
    if (mapped->u8_bytes > (size_t)INT64_MAX) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_MAP_ERR_RANGE);
    }
    if (mapped->u8_bytes == 0) {
        return n00b_result_ok(n00b_string_t *,
                              n00b_string_from_raw("",
                                                   0,
                                                   .allocator = allocator));
    }
    if (mapped->data == 0) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    uint8_t *bytes = rocs_map_resolve_span(map, mapped->data, mapped->u8_bytes);
    if (bytes == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    return n00b_result_ok(n00b_string_t *,
                          n00b_string_from_raw((char *)bytes,
                                               (int64_t)mapped->u8_bytes,
                                               .allocator = allocator));
}

static n00b_result_t(n00b_json_node_t *)
_rocs_map_json_copy_from_vaddr(n00b_store_map_t  *map,
                               uint64_t           vaddr,
                               n00b_allocator_t  *allocator);

static n00b_result_t(n00b_json_node_t *)
_rocs_map_json_copy_array(n00b_store_map_t        *map,
                          rocs_mapped_list_wire_t *wire,
                          n00b_allocator_t        *allocator)
{
    if (wire == nullptr || wire->len > wire->cap) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    n00b_json_node_t  *node = _rocs_map_json_pointer_alloc(allocator);
    n00b_json_array_t  arr =
        n00b_list_new_private(n00b_json_node_t *,
                              .allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_ALL);

    if (wire->len != 0) {
        if (wire->data == 0) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }

        size_t span = 0;
        if (rocs_mul_overflow_size(wire->len, sizeof(uint64_t), &span)) {
            return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
        }

        uint64_t *items = rocs_map_resolve_span(map, wire->data, span);
        if (items == nullptr) {
            return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
        }

        for (size_t i = 0; i < wire->len; i++) {
            uint64_t child_vaddr = items[i];
            if (child_vaddr == 0) {
                return n00b_result_err(n00b_json_node_t *,
                                       N00B_STORE_MAP_ERR_BAD_LAYOUT);
            }

            auto child_r =
                _rocs_map_json_copy_from_vaddr(map, child_vaddr, allocator);
            if (n00b_result_is_err(child_r)) {
                return child_r;
            }

            n00b_list_push(arr, n00b_result_get(child_r));
        }
    }

    node->value = n00b_variant_set(n00b_json_value_t, n00b_json_array_t, arr);
    return n00b_result_ok(n00b_json_node_t *, node);
}

static n00b_result_t(n00b_json_node_t *)
_rocs_map_json_copy_object(n00b_store_map_t  *map,
                           uint64_t           dict_vaddr,
                           n00b_allocator_t  *allocator)
{
    uint8_t *dict = rocs_map_resolve_span(map, dict_vaddr, sizeof(uint64_t));
    if (dict == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    uint64_t store_vaddr = *(uint64_t *)dict;
    if (store_vaddr == 0) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    rocs_mapped_dict_store_wire_t *store = rocs_map_resolve_span(
        map,
        store_vaddr,
        sizeof(rocs_mapped_dict_store_wire_t));
    if (store == nullptr || !rocs_u32_power_mask(store->last_slot)) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    size_t bucket_count = (size_t)store->last_slot + 1u;
    size_t bucket_span  = 0;
    size_t key_span     = 0;
    size_t value_span   = 0;
    if (rocs_mul_overflow_size(bucket_count,
                               sizeof(n00b_dict_bucket_t),
                               &bucket_span)
        || rocs_mul_overflow_size(bucket_count, sizeof(uint64_t), &key_span)
        || rocs_mul_overflow_size(bucket_count, sizeof(uint64_t), &value_span)) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    n00b_dict_bucket_t *buckets = rocs_map_resolve_span(map,
                                                        store->buckets,
                                                        bucket_span);
    uint8_t            *keys    = rocs_map_resolve_span(map,
                                                        store->keys,
                                                        key_span);
    uint8_t            *values  = rocs_map_resolve_span(map,
                                                        store->values,
                                                        value_span);
    if (buckets == nullptr || keys == nullptr || values == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    n00b_json_node_t   *node = _rocs_map_json_pointer_alloc(allocator);
    n00b_json_object_t *obj  = n00b_alloc_with_opts(
        n00b_json_object_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    n00b_dict_init(obj,
                   .allocator       = allocator,
                   .locked          = false,
                   .hash            = n00b_string_hash,
                   .skip_obj_hash   = true,
                   .key_scan_kind   = N00B_GC_SCAN_KIND_ALL,
                   .value_scan_kind = N00B_GC_SCAN_KIND_ALL);

    for (uint32_t i = 0; i <= store->last_slot; i++) {
        n00b_dict_bucket_t *bucket = &buckets[i];
        n00b_uint128_t      hv     = bucket->hv;
        uint32_t            flags  = atomic_load_explicit(&bucket->flags,
                                                          memory_order_relaxed);

        if (hv == (n00b_uint128_t)0 || (flags & N00B_HT_FLAG_DELETED) != 0) {
            continue;
        }

        uint64_t key_vaddr = *(uint64_t *)(keys + (size_t)i * sizeof(uint64_t));
        uint64_t val_vaddr = *(uint64_t *)(values + (size_t)i * sizeof(uint64_t));
        if (key_vaddr == 0 || val_vaddr == 0) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }

        auto key_r = _rocs_map_string_copy_from_vaddr(map,
                                                      key_vaddr,
                                                      allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(n00b_json_node_t *,
                                   n00b_result_get_err(key_r));
        }

        auto value_r = _rocs_map_json_copy_from_vaddr(map,
                                                      val_vaddr,
                                                      allocator);
        if (n00b_result_is_err(value_r)) {
            return value_r;
        }

        n00b_string_t    *key   = n00b_result_get(key_r);
        n00b_json_node_t *value = n00b_result_get(value_r);
        n00b_dict_put(obj, key, value);
    }

    node->value = n00b_variant_set(n00b_json_value_t,
                                   n00b_json_object_t *,
                                   obj);
    return n00b_result_ok(n00b_json_node_t *, node);
}

static n00b_result_t(n00b_json_node_t *)
_rocs_map_json_copy_node(n00b_store_map_t  *map,
                         n00b_json_node_t  *mapped,
                         n00b_allocator_t  *allocator)
{
    if (map == nullptr || mapped == nullptr) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_ARG);
    }

    if (n00b_variant_is_type(mapped->value, n00b_json_null_t)) {
        n00b_json_node_t *node = _rocs_map_json_scalar_alloc(allocator);
        node->value = n00b_variant_set(n00b_json_value_t,
                                       n00b_json_null_t,
                                       ((n00b_json_null_t){}));
        return n00b_result_ok(n00b_json_node_t *, node);
    }
    if (n00b_variant_is_type(mapped->value, bool)) {
        n00b_json_node_t *node = _rocs_map_json_scalar_alloc(allocator);
        node->value = n00b_variant_set(n00b_json_value_t,
                                       bool,
                                       n00b_variant_get(mapped->value, bool));
        return n00b_result_ok(n00b_json_node_t *, node);
    }
    if (n00b_variant_is_type(mapped->value, int64_t)) {
        n00b_json_node_t *node = _rocs_map_json_scalar_alloc(allocator);
        node->value = n00b_variant_set(n00b_json_value_t,
                                       int64_t,
                                       n00b_variant_get(mapped->value, int64_t));
        return n00b_result_ok(n00b_json_node_t *, node);
    }
    if (n00b_variant_is_type(mapped->value, double)) {
        n00b_json_node_t *node = _rocs_map_json_scalar_alloc(allocator);
        node->value = n00b_variant_set(n00b_json_value_t,
                                       double,
                                       n00b_variant_get(mapped->value, double));
        return n00b_result_ok(n00b_json_node_t *, node);
    }
    if (n00b_variant_is_type(mapped->value, n00b_string_t *)) {
        uint64_t string_vaddr =
            (uint64_t)(uintptr_t)n00b_variant_get(mapped->value,
                                                  n00b_string_t *);
        if (string_vaddr == 0) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }

        auto string_r =
            _rocs_map_string_copy_from_vaddr(map, string_vaddr, allocator);
        if (n00b_result_is_err(string_r)) {
            return n00b_result_err(n00b_json_node_t *,
                                   n00b_result_get_err(string_r));
        }

        n00b_json_node_t *node = _rocs_map_json_pointer_alloc(allocator);
        node->value = n00b_variant_set(n00b_json_value_t,
                                       n00b_string_t *,
                                       n00b_result_get(string_r));
        return n00b_result_ok(n00b_json_node_t *, node);
    }
    if (n00b_variant_is_type(mapped->value, n00b_json_array_t)) {
        rocs_mapped_list_wire_t *wire =
            (rocs_mapped_list_wire_t *)
                &mapped->value.value.N00B_VARIANT_FIELD(n00b_json_array_t);
        return _rocs_map_json_copy_array(map, wire, allocator);
    }
    if (n00b_variant_is_type(mapped->value, n00b_json_object_t *)) {
        uint64_t dict_vaddr =
            (uint64_t)(uintptr_t)n00b_variant_get(mapped->value,
                                                  n00b_json_object_t *);
        if (dict_vaddr == 0) {
            return n00b_result_err(n00b_json_node_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }

        return _rocs_map_json_copy_object(map, dict_vaddr, allocator);
    }

    return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
}

static n00b_result_t(n00b_json_node_t *)
_rocs_map_json_copy_from_vaddr(n00b_store_map_t  *map,
                               uint64_t           vaddr,
                               n00b_allocator_t  *allocator)
{
    auto node_r = rocs_map_resolve_required(map, vaddr, sizeof(n00b_json_node_t));
    if (n00b_result_is_err(node_r)) {
        return n00b_result_err(n00b_json_node_t *, n00b_result_get_err(node_r));
    }

    return _rocs_map_json_copy_node(map,
                                    n00b_result_get(node_r),
                                    allocator);
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
    n00b_allocator_t              *allocator = nullptr;
}
{
    if (vfs == nullptr || path == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_ARG);
    }

    n00b_store_residency_policy_t effective =
        policy == nullptr ? n00b_store_residency_policy_get_default()
                          : *policy;

    switch (effective.preferred_backing) {
    case N00B_STORE_IMAGE_AUTO:
    case N00B_STORE_IMAGE_PINNED_BUFFER:
        break;
    case N00B_STORE_IMAGE_LOCAL_MMAP:
        return n00b_result_err(n00b_store_map_t *,
                               N00B_STORE_MAP_ERR_BACKING);
    case N00B_STORE_IMAGE_CACHE_MMAP:
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_CACHE);
    default:
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_ARG);
    }

    auto stat_r = n00b_vfs_stat(vfs, path);
    if (n00b_result_is_err(stat_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_IO);
    }
    n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
    if (stat.kind != N00B_VFS_OBJ_FILE || stat.size == 0
        || stat.size > (uint64_t)SIZE_MAX
        || stat.size > (uint64_t)INT64_MAX) {
        return n00b_result_err(n00b_store_map_t *,
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    if (cache != nullptr) {
        auto cache_r = n00b_vfs_cache_get(cache, path, 0, stat.size);
        if (n00b_result_is_err(cache_r)) {
            return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_IO);
        }
        n00b_buffer_t *image = n00b_result_get(cache_r);
        if (image == nullptr || (uint64_t)n00b_buffer_len(image) != stat.size) {
            return n00b_result_err(n00b_store_map_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }
        return n00b_store_map_open_buffer(image, .allocator = allocator);
    }

    auto open_r = n00b_vfs_open(vfs, path, N00B_VFS_O_R);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_IO);
    }

    n00b_vfs_fh_t fh = n00b_result_get(open_r);
    auto read_r = n00b_vfs_read(vfs, fh, stat.size, .allocator = allocator);
    auto close_r = n00b_vfs_close(vfs, fh);
    if (n00b_result_is_err(read_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_IO);
    }
    if (n00b_result_is_err(close_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_MAP_ERR_IO);
    }

    n00b_buffer_t *image = n00b_result_get(read_r);
    if (image == nullptr || (uint64_t)n00b_buffer_len(image) != stat.size) {
        return n00b_result_err(n00b_store_map_t *,
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    return n00b_store_map_open_buffer(image, .allocator = allocator);
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

n00b_result_t(n00b_json_node_t *)
n00b_store_map_shard_record_json_copy(n00b_store_map_shard_t *shard,
                                      uint64_t                ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_ARG);
    }
    if ((n00b_shard_state_t)shard->wire->state != N00B_SHARD_STATE_SEALED) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    auto records_r = n00b_store_map_shard_records(shard);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(n00b_json_node_t *, n00b_result_get_err(records_r));
    }
    n00b_store_map_list_t *records = n00b_result_get(records_r);
    if (records->wire->len != shard->wire->record_count) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }
    if (ordinal >= records->wire->len) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    auto slot_r = n00b_store_map_list_slot(records, ordinal);
    if (n00b_result_is_err(slot_r)) {
        return n00b_result_err(n00b_json_node_t *, n00b_result_get_err(slot_r));
    }
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    if (!n00b_option_is_set(slot_opt)) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    auto ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    if (n00b_result_is_err(ref_r)) {
        return n00b_result_err(n00b_json_node_t *, n00b_result_get_err(ref_r));
    }
    n00b_option_t(n00b_store_map_ref_t *) ref_opt = n00b_result_get(ref_r);
    if (!n00b_option_is_set(ref_opt)) {
        return n00b_result_err(n00b_json_node_t *, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    return _rocs_map_json_copy_from_vaddr(shard->map,
                                          n00b_option_get(ref_opt)->vaddr,
                                          allocator);
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

n00b_result_t(n00b_shard_state_t)
n00b_store_map_shard_state(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(n00b_shard_state_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(n00b_shard_state_t, (n00b_shard_state_t)shard->wire->state);
}

n00b_result_t(uint64_t)
n00b_store_map_shard_seal_ts(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, shard->wire->seal_ts);
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

n00b_result_t(n00b_option_t(n00b_store_map_list_t *))
n00b_store_map_shard_retain_raw(n00b_store_map_shard_t *shard)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_map_list_t *),
                               N00B_STORE_MAP_ERR_ARG);
    }
    if (shard->wire->retain_raw == 0) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_list_t *),
                              n00b_option_none(n00b_store_map_list_t *));
    }

    auto list_r = rocs_map_resolve_required(shard->map,
                                            shard->wire->retain_raw,
                                            sizeof(rocs_mapped_list_wire_t));
    if (n00b_result_is_err(list_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_list_t *),
                               n00b_result_get_err(list_r));
    }

    n00b_store_map_list_t *list = ROCS_VIEW_ALLOC(shard->map, n00b_store_map_list_t);
    list->map  = shard->map;
    list->wire = n00b_result_get(list_r);
    return n00b_result_ok(n00b_option_t(n00b_store_map_list_t *),
                          n00b_option_set(n00b_store_map_list_t *, list));
}

n00b_result_t(n00b_option_t(n00b_store_map_buffer_t *))
n00b_store_map_shard_raw_buffer(n00b_store_map_shard_t *shard,
                                uint64_t                ordinal)
{
    if (shard == nullptr || shard->map == nullptr || shard->map->closed) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               N00B_STORE_MAP_ERR_ARG);
    }
    if (shard->wire->retain_raw == 0) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_buffer_t *),
                              n00b_option_none(n00b_store_map_buffer_t *));
    }

    auto list_r = n00b_store_map_shard_retain_raw(shard);
    if (n00b_result_is_err(list_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               n00b_result_get_err(list_r));
    }
    n00b_option_t(n00b_store_map_list_t *) list_opt = n00b_result_get(list_r);
    if (!n00b_option_is_set(list_opt)) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_buffer_t *),
                              n00b_option_none(n00b_store_map_buffer_t *));
    }

    auto slot_r = n00b_store_map_list_slot(n00b_option_get(list_opt), ordinal);
    if (n00b_result_is_err(slot_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               n00b_result_get_err(slot_r));
    }
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    if (!n00b_option_is_set(slot_opt)) {
        return n00b_result_ok(n00b_option_t(n00b_store_map_buffer_t *),
                              n00b_option_none(n00b_store_map_buffer_t *));
    }

    auto span_ref_r = n00b_store_map_slot_ref(n00b_option_get(slot_opt));
    if (n00b_result_is_err(span_ref_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               n00b_result_get_err(span_ref_r));
    }
    n00b_option_t(n00b_store_map_ref_t *) span_ref_opt = n00b_result_get(span_ref_r);
    if (!n00b_option_is_set(span_ref_opt)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    n00b_store_map_ref_t *span_ref = n00b_option_get(span_ref_opt);
    rocs_mapped_raw_span_wire_t *span =
        rocs_map_resolve_span(shard->map,
                              span_ref->vaddr,
                              sizeof(rocs_mapped_raw_span_wire_t));
    if (span == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }
    if (shard->wire->raw_bytes == 0) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               N00B_STORE_MAP_ERR_BACKING);
    }

    auto blob_r = rocs_map_resolve_required(shard->map,
                                            shard->wire->raw_bytes,
                                            sizeof(rocs_mapped_raw_blob_wire_t));
    if (n00b_result_is_err(blob_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               n00b_result_get_err(blob_r));
    }
    rocs_mapped_raw_blob_wire_t *blob = n00b_result_get(blob_r);
    if (span->offset > blob->byte_len
        || span->byte_len > blob->byte_len - span->offset
        || (blob->data == 0 && span->byte_len != 0)
        || span->offset > UINT64_MAX - blob->data) {
        return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                               N00B_STORE_MAP_ERR_RANGE);
    }

    uint64_t data_vaddr = blob->data + span->offset;
    uint8_t *data       = nullptr;
    if (span->byte_len != 0) {
        if (span->byte_len > SIZE_MAX) {
            return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                                   N00B_STORE_MAP_ERR_RANGE);
        }
        data = rocs_map_resolve_span(shard->map,
                                     data_vaddr,
                                     (size_t)span->byte_len);
        if (data == nullptr) {
            return n00b_result_err(n00b_option_t(n00b_store_map_buffer_t *),
                                   N00B_STORE_MAP_ERR_RANGE);
        }
    }

    n00b_store_map_buffer_t *buffer =
        ROCS_VIEW_ALLOC(shard->map, n00b_store_map_buffer_t);
    buffer->map      = shard->map;
    buffer->data     = data;
    buffer->byte_len = span->byte_len;
    buffer->vaddr    = data_vaddr;

    return n00b_result_ok(n00b_option_t(n00b_store_map_buffer_t *),
                          n00b_option_set(n00b_store_map_buffer_t *, buffer));
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

n00b_result_t(uint64_t)
n00b_store_map_slot_u64(n00b_store_map_slot_t *slot)
{
    if (slot == nullptr || slot->map == nullptr || slot->map->closed) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    if (slot->width < sizeof(uint64_t)) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    uint64_t value;
    memcpy(&value, slot->addr, sizeof(value));
    return n00b_result_ok(uint64_t, value);
}

n00b_result_t(n00b_uint128_t)
n00b_store_map_slot_u128(n00b_store_map_slot_t *slot)
{
    if (slot == nullptr || slot->map == nullptr || slot->map->closed) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_MAP_ERR_ARG);
    }
    if (slot->width < sizeof(n00b_uint128_t)) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    n00b_uint128_t value;
    memcpy(&value, slot->addr, sizeof(value));
    return n00b_result_ok(n00b_uint128_t, value);
}

n00b_result_t(n00b_store_map_dict_t *)
n00b_store_map_slot_column(n00b_store_map_slot_t *slot)
{
    auto raw_r = n00b_store_map_slot_u64(slot);
    if (n00b_result_is_err(raw_r)) {
        return n00b_result_err(n00b_store_map_dict_t *,
                               n00b_result_get_err(raw_r));
    }

    uint64_t raw = n00b_result_get(raw_r);
    if (raw == 0) {
        return n00b_result_err(n00b_store_map_dict_t *,
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    auto dict_r = rocs_map_resolve_required(slot->map, raw, sizeof(uint64_t));
    if (n00b_result_is_err(dict_r)) {
        return n00b_result_err(n00b_store_map_dict_t *,
                               n00b_result_get_err(dict_r));
    }

    n00b_store_map_dict_t *dict = ROCS_VIEW_ALLOC(slot->map,
                                                  n00b_store_map_dict_t);
    dict->map          = slot->map;
    dict->dict         = n00b_result_get(dict_r);
    dict->key_stride   = sizeof(n00b_uint128_t);
    dict->value_stride = sizeof(uint64_t);
    return n00b_result_ok(n00b_store_map_dict_t *, dict);
}

n00b_result_t(n00b_store_map_list_t *)
n00b_store_map_slot_list(n00b_store_map_slot_t *slot)
{
    auto raw_r = n00b_store_map_slot_u64(slot);
    if (n00b_result_is_err(raw_r)) {
        return n00b_result_err(n00b_store_map_list_t *,
                               n00b_result_get_err(raw_r));
    }

    uint64_t raw = n00b_result_get(raw_r);
    if (raw == 0) {
        return n00b_result_err(n00b_store_map_list_t *,
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    auto list_r = rocs_map_resolve_required(slot->map,
                                            raw,
                                            sizeof(rocs_mapped_list_wire_t));
    if (n00b_result_is_err(list_r)) {
        return n00b_result_err(n00b_store_map_list_t *,
                               n00b_result_get_err(list_r));
    }

    n00b_store_map_list_t *list = ROCS_VIEW_ALLOC(slot->map,
                                                  n00b_store_map_list_t);
    list->map  = slot->map;
    list->wire = n00b_result_get(list_r);
    return n00b_result_ok(n00b_store_map_list_t *, list);
}

static bool
rocs_map_posting_kind_valid(uint32_t kind)
{
    return kind == (uint32_t)N00B_STORE_POSTINGS_SPARSE
        || kind == (uint32_t)N00B_STORE_POSTINGS_DENSE;
}

n00b_result_t(n00b_store_map_posting_list_t *)
n00b_store_map_slot_posting_list(n00b_store_map_slot_t *slot)
{
    auto raw_r = n00b_store_map_slot_u64(slot);
    if (n00b_result_is_err(raw_r)) {
        return n00b_result_err(n00b_store_map_posting_list_t *,
                               n00b_result_get_err(raw_r));
    }

    uint64_t raw = n00b_result_get(raw_r);
    if (raw == 0) {
        return n00b_result_err(n00b_store_map_posting_list_t *,
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    auto wire_r = rocs_map_resolve_required(slot->map,
                                            raw,
                                            sizeof(rocs_mapped_posting_list_wire_t));
    if (n00b_result_is_err(wire_r)) {
        return n00b_result_err(n00b_store_map_posting_list_t *,
                               n00b_result_get_err(wire_r));
    }

    rocs_mapped_posting_list_wire_t *wire = n00b_result_get(wire_r);
    if (!rocs_map_posting_kind_valid(wire->kind)) {
        return n00b_result_err(n00b_store_map_posting_list_t *,
                               N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    n00b_store_map_posting_list_t *postings = ROCS_VIEW_ALLOC(
        slot->map,
        n00b_store_map_posting_list_t);
    postings->map      = slot->map;
    postings->wire     = wire;
    postings->ordinals = nullptr;
    postings->flags    = nullptr;

    if (wire->kind == (uint32_t)N00B_STORE_POSTINGS_SPARSE) {
        if (wire->ordinals == 0) {
            return n00b_result_err(n00b_store_map_posting_list_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }
        auto ord_r = rocs_map_resolve_required(slot->map,
                                               wire->ordinals,
                                               sizeof(rocs_mapped_list_wire_t));
        if (n00b_result_is_err(ord_r)) {
            return n00b_result_err(n00b_store_map_posting_list_t *,
                                   n00b_result_get_err(ord_r));
        }
        postings->ordinals       = ROCS_VIEW_ALLOC(slot->map,
                                                   n00b_store_map_list_t);
        postings->ordinals->map  = slot->map;
        postings->ordinals->wire = n00b_result_get(ord_r);
    }
    else {
        if (wire->flags == 0) {
            return n00b_result_err(n00b_store_map_posting_list_t *,
                                   N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }
        auto flags_r = rocs_map_resolve_required(slot->map,
                                                 wire->flags,
                                                 sizeof(rocs_mapped_flagset_wire_t));
        if (n00b_result_is_err(flags_r)) {
            return n00b_result_err(n00b_store_map_posting_list_t *,
                                   n00b_result_get_err(flags_r));
        }
        postings->flags = n00b_result_get(flags_r);
    }

    return n00b_result_ok(n00b_store_map_posting_list_t *, postings);
}

n00b_result_t(n00b_store_postings_kind_t)
n00b_store_map_posting_list_kind(n00b_store_map_posting_list_t *postings)
{
    if (postings == nullptr || postings->map == nullptr
        || postings->map->closed || postings->wire == nullptr) {
        return n00b_result_err(n00b_store_postings_kind_t,
                               N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_postings_kind_t,
                          (n00b_store_postings_kind_t)postings->wire->kind);
}

n00b_result_t(uint64_t)
n00b_store_map_posting_list_len(n00b_store_map_posting_list_t *postings)
{
    if (postings == nullptr || postings->map == nullptr
        || postings->map->closed || postings->wire == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    if (postings->wire->kind == (uint32_t)N00B_STORE_POSTINGS_SPARSE) {
        if (postings->ordinals == nullptr) {
            return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_BAD_LAYOUT);
        }
        return n00b_store_map_list_len(postings->ordinals);
    }
    return n00b_result_ok(uint64_t, postings->wire->count);
}

static n00b_result_t(uint64_t)
rocs_map_posting_sparse_ordinal_at(n00b_store_map_posting_list_t *postings,
                                   uint64_t                       index)
{
    if (postings->ordinals == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    auto slot_r = n00b_store_map_list_slot(postings->ordinals, index);
    if (n00b_result_is_err(slot_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(slot_r));
    }
    n00b_option_t(n00b_store_map_slot_t *) slot_opt = n00b_result_get(slot_r);
    if (!n00b_option_is_set(slot_opt)) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_RANGE);
    }

    return n00b_store_map_slot_u64(n00b_option_get(slot_opt));
}

static n00b_result_t(uint64_t)
rocs_map_posting_dense_ordinal_at(n00b_store_map_posting_list_t *postings,
                                  uint64_t                       index)
{
    if (postings->flags == nullptr || index >= postings->wire->count) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_RANGE);
    }

    size_t span;
    if (rocs_mul_overflow_size((size_t)postings->flags->alloc_wordlen,
                               sizeof(uint64_t),
                               &span)) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_RANGE);
    }
    uint64_t *words = rocs_map_resolve_span(postings->map,
                                            postings->flags->contents,
                                            span);
    if (words == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_RANGE);
    }

    uint64_t seen = 0;
    for (uint64_t word_ix = 0; word_ix < postings->flags->alloc_wordlen;
         word_ix++) {
        uint64_t word = words[word_ix];
        while (word != 0) {
            uint64_t bit     = (uint64_t)__builtin_ctzll(word);
            uint64_t ordinal = (word_ix << 6) + bit;
            if (ordinal >= postings->flags->num_flags) {
                return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_RANGE);
            }
            if (seen == index) {
                return n00b_result_ok(uint64_t, ordinal);
            }
            seen++;
            word &= word - 1;
        }
    }

    return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_BAD_LAYOUT);
}

n00b_result_t(uint64_t)
n00b_store_map_posting_list_ordinal_at(n00b_store_map_posting_list_t *postings,
                                       uint64_t                       index)
{
    if (postings == nullptr || postings->map == nullptr
        || postings->map->closed || postings->wire == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    if (postings->wire->kind == (uint32_t)N00B_STORE_POSTINGS_SPARSE) {
        return rocs_map_posting_sparse_ordinal_at(postings, index);
    }
    return rocs_map_posting_dense_ordinal_at(postings, index);
}

n00b_result_t(bool)
n00b_store_map_posting_list_contains(n00b_store_map_posting_list_t *postings,
                                     uint64_t                       ordinal)
{
    if (postings == nullptr || postings->map == nullptr
        || postings->map->closed || postings->wire == nullptr) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_ARG);
    }

    if (postings->wire->kind == (uint32_t)N00B_STORE_POSTINGS_SPARSE) {
        auto len_r = n00b_store_map_posting_list_len(postings);
        if (n00b_result_is_err(len_r)) {
            return n00b_result_err(bool, n00b_result_get_err(len_r));
        }
        uint64_t len = n00b_result_get(len_r);
        for (uint64_t i = 0; i < len; i++) {
            auto value_r = rocs_map_posting_sparse_ordinal_at(postings, i);
            if (n00b_result_is_err(value_r)) {
                return n00b_result_err(bool, n00b_result_get_err(value_r));
            }
            if (n00b_result_get(value_r) == ordinal) {
                return n00b_result_ok(bool, true);
            }
        }
        return n00b_result_ok(bool, false);
    }

    if (postings->flags == nullptr || ordinal >= postings->flags->num_flags) {
        return n00b_result_ok(bool, false);
    }
    size_t span;
    if (rocs_mul_overflow_size((size_t)postings->flags->alloc_wordlen,
                               sizeof(uint64_t),
                               &span)) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_RANGE);
    }
    uint64_t *words = rocs_map_resolve_span(postings->map,
                                            postings->flags->contents,
                                            span);
    if (words == nullptr) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_RANGE);
    }
    bool found = (words[ordinal >> 6] & (1ull << (ordinal & 63u))) != 0;
    return n00b_result_ok(bool, found);
}

n00b_result_t(bool)
n00b_store_map_slot_string_eq(n00b_store_map_slot_t *slot,
                              n00b_string_t         *value)
{
    if (value == nullptr || slot == nullptr || slot->map == nullptr
        || slot->map->closed) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_ARG);
    }
    if (value->u8_bytes != 0 && value->data == nullptr) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_ARG);
    }

    auto raw_r = n00b_store_map_slot_u64(slot);
    if (n00b_result_is_err(raw_r)) {
        return n00b_result_err(bool, n00b_result_get_err(raw_r));
    }

    uint64_t raw = n00b_result_get(raw_r);
    if (raw == 0) {
        return n00b_result_ok(bool, false);
    }

    auto string_r = rocs_map_resolve_required(slot->map,
                                              raw,
                                              sizeof(rocs_mapped_string_wire_t));
    if (n00b_result_is_err(string_r)) {
        return n00b_result_err(bool, n00b_result_get_err(string_r));
    }

    rocs_mapped_string_wire_t *mapped = n00b_result_get(string_r);
    if (mapped->u8_bytes != value->u8_bytes) {
        return n00b_result_ok(bool, false);
    }
    if (mapped->u8_bytes == 0) {
        return n00b_result_ok(bool, true);
    }
    if (mapped->data == 0) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_BAD_LAYOUT);
    }

    uint8_t *bytes = rocs_map_resolve_span(slot->map,
                                           mapped->data,
                                           mapped->u8_bytes);
    if (bytes == nullptr) {
        return n00b_result_err(bool, N00B_STORE_MAP_ERR_RANGE);
    }

    return n00b_result_ok(bool,
                          memcmp(bytes, value->data, mapped->u8_bytes) == 0);
}

n00b_result_t(uint64_t)
n00b_store_map_buffer_len(n00b_store_map_buffer_t *buffer)
{
    if (buffer == nullptr || buffer->map == nullptr || buffer->map->closed) {
        return n00b_result_err(uint64_t, N00B_STORE_MAP_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, buffer->byte_len);
}

n00b_result_t(uint8_t)
n00b_store_map_buffer_byte(n00b_store_map_buffer_t *buffer, uint64_t index)
{
    if (buffer == nullptr || buffer->map == nullptr || buffer->map->closed) {
        return n00b_result_err(uint8_t, N00B_STORE_MAP_ERR_ARG);
    }
    if (index >= buffer->byte_len || index > SIZE_MAX) {
        return n00b_result_err(uint8_t, N00B_STORE_MAP_ERR_RANGE);
    }
    return n00b_result_ok(uint8_t, buffer->data[(size_t)index]);
}

n00b_result_t(n00b_buffer_t *)
n00b_store_map_buffer_copy(n00b_store_map_buffer_t *buffer) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (buffer == nullptr || buffer->map == nullptr || buffer->map->closed) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_MAP_ERR_ARG);
    }
    if (buffer->byte_len > (uint64_t)INT64_MAX) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_MAP_ERR_RANGE);
    }

    n00b_buffer_t *copy = n00b_buffer_from_bytes((char *)buffer->data,
                                                 (int64_t)buffer->byte_len,
                                                 .allocator = allocator);
    return n00b_result_ok(n00b_buffer_t *, copy);
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
