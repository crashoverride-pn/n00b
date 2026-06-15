#define N00B_USE_INTERNAL_API

#include "n00b.h"
#include "util/marshal.h"

#include "adt/dict_untyped.h"
#include "adt/dict.h"
#include "core/alloc.h"
#include "core/alloc_mdata.h"
#include "core/align.h"
#include "core/buffer.h"
#include "core/gc_map.h"
#include "core/hash.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "core/static_objects.h"
#include "core/stw.h"

#include <stdint.h>
#ifndef _WIN32
// dladdr (marshal: address->symbol) / dlsym (unmarshal: symbol->address)
// for N00B_MARSHAL_OP_FNPATCH. Same mechanism FFI uses (embed_ffi.c).
#include <dlfcn.h>
#endif

#define N00B_MARSHAL_OP_ALLOC  UINT32_C(0xe11cbab0)
#define N00B_MARSHAL_OP_CPATCH UINT32_C(0xe31cbab0)
#define N00B_MARSHAL_OP_SPATCH UINT32_C(0xe41cbab0)
#define N00B_MARSHAL_OP_STOP   UINT32_C(0xe51cbab0)
#define N00B_MARSHAL_OP_PSPATCH UINT32_C(0xe61cbab0)
#define N00B_MARSHAL_OP_CBSCAN UINT32_C(0xe71cbab0)
// Static *function* pointer, identified+rebound by exported symbol name
// (dladdr on marshal, dlsym on unmarshal) — the FFI mechanism. Only
// emitted for exact-match exported symbols; never bumps the stream
// version (objects holding fn pointers were previously unmarshalable).
#define N00B_MARSHAL_OP_FNPATCH UINT32_C(0xe81cbab0)

// scan_cb round-trips as a small enum tag over the closed set of
// built-in scan callbacks (D-039: custom callbacks are an explicit
// error, never a marshaled code pointer). A CBSCAN ext record always
// carries one of these tags; STRUCT_FIELD / STRUCT_LAYOUT additionally
// carry a PSPATCH-style scan_user identity payload (the descriptor),
// while ALL / NONE / EVERY_OTHER carry no identity payload.
typedef enum : uint32_t {
    N00B_MARSHAL_SCAN_CB_TAG_ALL          = 0,
    N00B_MARSHAL_SCAN_CB_TAG_NONE         = 1,
    N00B_MARSHAL_SCAN_CB_TAG_EVERY_OTHER  = 2,
    N00B_MARSHAL_SCAN_CB_TAG_STRUCT_FIELD = 3,
    N00B_MARSHAL_SCAN_CB_TAG_STRUCT_LAYOUT = 4,
    // D-049: the link-time type->GC-map callback. Its scan_user descriptor is
    // NOT serialized (uses_user stays false) — it is re-derived on unmarshal
    // from the object's tinfo via n00b_gc_type_map_lookup, so no identity
    // payload is needed.
    N00B_MARSHAL_SCAN_CB_TAG_TYPE_LAYOUT  = 5,
    N00B_MARSHAL_SCAN_CB_TAG_LIMIT,
} n00b_marshal_scan_cb_tag_t;

#define N00B_MARSHAL_MIN_VERSION 1u
#define N00B_MARSHAL_PAYLOAD_FRONT_VERSION 4u
#define N00B_MARSHAL_STATIC_CHECK_MAX 16u

#define N00B_MARSHAL_ALLOC_F_SOURCE_INLINE     (1u << 0)
#define N00B_MARSHAL_ALLOC_F_SOURCE_OOB        (1u << 1)
#define N00B_MARSHAL_ALLOC_F_SOURCE_HEADERLESS (1u << 2)
#define N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN   (1u << 3)
#define N00B_MARSHAL_ALLOC_F_KNOWN             \
    (N00B_MARSHAL_ALLOC_F_SOURCE_INLINE        \
     | N00B_MARSHAL_ALLOC_F_SOURCE_OOB         \
     | N00B_MARSHAL_ALLOC_F_SOURCE_HEADERLESS  \
     | N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN)

typedef struct {
    uint64_t marshal_magic;
    uint32_t version;
    uint32_t base_address;
    uint32_t root_offset;
    uint32_t flags;
} n00b_marshal_stream_header_t;

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
} n00b_marshal_alloc_record_t;

typedef struct {
    uint32_t op;
    uint32_t reserved;
    uint64_t vaddr;
    uint64_t value;
} n00b_marshal_cpatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t check_len;
    uint64_t vaddr;
    uint64_t static_addr;
    uint64_t static_start;
    uint64_t static_len;
    uint64_t object_id;
    uint8_t  check[16];
} n00b_marshal_spatch_record_t;

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
} n00b_marshal_pspatch_record_t;

// CALLBACK-scan extension record. In legacy v3 streams it follows the
// ALLOC payload; in v4+ streams it follows the ALLOC metadata in the
// trailing metadata section. record_len covers the fixed struct plus the
// variable-length identity payload (namespace/key/check bytes, PSPATCH-
// style), 8-byte aligned. When has_identity == 0 (scan_user is null:
// all/none/every_other), the identity fields are all zero and no payload
// bytes follow the fixed struct.
typedef struct {
    uint32_t op;
    uint32_t record_len;
    uint64_t vaddr;          // ALLOC record's vaddr; binds the ext to its object.
    uint32_t scan_cb_tag;    // n00b_marshal_scan_cb_tag_t
    uint32_t has_identity;   // 0 (null scan_user) or 1 (descriptor present)
    // Identity payload (mirrors n00b_marshal_pspatch_record_t), only
    // meaningful when has_identity != 0.
    uint64_t object_offset;
    uint64_t object_len;
    uint64_t tinfo;
    uint32_t flags_mask;
    uint32_t flags_value;
    uint32_t scan_kind;      // scan_kind of the scan_user descriptor object
    uint32_t identity_version;
    uint32_t identity_kind;
    uint32_t namespace_len;
    uint32_t key_len;
    uint32_t check_len;
    uint32_t reserved;
} n00b_marshal_cbscan_record_t;

typedef struct {
    uint32_t op;
    uint32_t end_of_stream;
} n00b_marshal_stop_record_t;

// FNPATCH: a static function pointer serialized by exported-symbol name.
// The fixed struct is followed by name_len bytes of the symbol name (no
// terminating NUL on the wire), zero-padded out to record_len (8-byte
// aligned). On unmarshal the name is resolved with dlsym(RTLD_DEFAULT).
typedef struct {
    uint32_t op;         // N00B_MARSHAL_OP_FNPATCH
    uint32_t record_len; // align8(sizeof(struct) + name_len)
    uint64_t vaddr;      // word slot to patch with the resolved address
    uint32_t name_len;   // symbol name length (no NUL)
    uint32_t reserved;
} n00b_marshal_fnpatch_record_t;

#define N00B_MARSHAL_FN_NAME_MAX 1024u

static inline const char *
fnpatch_name_bytes(const n00b_marshal_fnpatch_record_t *rec)
{
    return (const char *)rec + sizeof(*rec);
}

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} marshal_bytes_t;

typedef struct n00b_marshal_node_t {
    void                         *user_ptr;
    uint64_t                      vaddr;
    n00b_marshal_alloc_record_t   rec;
    char                         *payload;
    bool                          scanned;
    // CALLBACK-scan support. is_callback is set when the source object
    // was allocated SCAN_KIND_CALLBACK; scan_cb_tag/scan_user capture the
    // resolved built-in tag and the (static) scan_user descriptor; bitmap
    // is the precise per-word pointer oracle computed once at scan time
    // (D-040 OQ-3: stored, not re-derived) and drives scan_node instead
    // of scan_word_for_policy. bitmap_words is its length in uint64_t.
    bool                          is_callback;
    n00b_marshal_scan_cb_tag_t    scan_cb_tag;
    void                         *scan_user;
    uint64_t                     *bitmap;
    uint64_t                      bitmap_words;
} n00b_marshal_node_t;

typedef struct {
    uint64_t                    vaddr;
    uint64_t                    user_len;
    void                       *user_ptr;
    n00b_marshal_alloc_record_t rec;
    // CALLBACK-scan support: the stored pointer bitmap drives relink for
    // CALLBACK segments (scan_word_for_policy returns false for CALLBACK).
    bool                        is_callback;
    uint64_t                   *bitmap;
    uint64_t                    bitmap_words;
} n00b_unmarshal_segment_t;

typedef struct {
    uint64_t                       start;
    uint64_t                       len;
    uint64_t                       object_id;
    n00b_alloc_type_info_t         tinfo;
    n00b_gc_scan_kind_t            scan_kind;
    uint32_t                       flags;
    const n00b_static_identity_t  *identity;
} n00b_marshal_static_ref_t;

struct n00b_marshal_ctx_t {
    n00b_pool_t             scratch;
    n00b_allocator_t       *scratch_alloc;
    // 1-entry adaptive cache of the allocator the graph walk is currently in.
    // Most pointers in a marshal walk are clustered in the same pool, so trying
    // this allocator's OOB index first (n00b_try_alloc_info_in_allocator) turns
    // the per-pointer global mmap interval-tree search into an O(1) dict hit —
    // the GC's "addr is in the arena I manage" fast path, generalized to pools.
    n00b_allocator_t       *home_allocator;
    // Private (unlocked) typed memo map: user_ptr -> marshal node.  Typed
    // n00b_dict has no STW lockless-scan path, so building it during the
    // marshal (which triggers GC collects that flip stw_active) stays O(1)
    // amortized instead of degrading to the dict_untyped O(N) stw_scan probe.
    n00b_dict_t(void *, n00b_marshal_node_t *) *memos;
    n00b_marshal_node_t   **worklist;
    size_t                  work_len;
    size_t                  work_ix;
    size_t                  work_cap;
    marshal_bytes_t         out;
    marshal_bytes_t         metadata;
    marshal_bytes_t         patches;
    uint32_t                base_address;
    uint32_t                flags;
    uint32_t                next_offset;
    n00b_marshal_status_t   status;
    n00b_string_t          *error;
    bool                    used;
};

struct n00b_unmarshal_ctx_t {
    n00b_pool_t               scratch;
    n00b_allocator_t         *scratch_alloc;
    marshal_bytes_t           in;
    n00b_unmarshal_segment_t **segments;
    size_t                    segment_len;
    size_t                    segment_cap;
    n00b_arena_t             *target_arena;
    n00b_marshal_status_t     status;
    n00b_string_t            *error;
    bool                      closed;
};

static uint64_t
align8(uint64_t n)
{
    return (n + 7u) & ~UINT64_C(7);
}

static void
marshal_set_error(n00b_marshal_status_t *status,
                  n00b_string_t        **error,
                  n00b_marshal_status_t  code,
                  n00b_string_t         *msg)
{
    if (*status == N00B_MARSHAL_OK) {
        *status = code;
        *error  = msg;
    }
}

static void
marshal_init_scratch(n00b_pool_t       *pool,
                     n00b_allocator_t **alloc,
                     const char        *name)
{
    *alloc = n00b_pool_init(pool,
                            .__system = true,
                            .hidden   = true,
                            .scrub_locks_on_destroy = false,
                            .name     = name);
}

static void *
marshal_scratch_alloc(n00b_allocator_t *alloc, size_t n)
{
    if (!n) {
        n = 1;
    }
    // Scratch holds serialized bytes only (no live pointers); type it as a
    // char array so it carries a precise typehash while staying unscanned.
    return n00b_alloc_array_with_opts(char,
                                      n00b_align(n),
                                      &(n00b_alloc_opts_t){
                                          .allocator = alloc,
                                          .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                      });
}

static void
bytes_reserve(marshal_bytes_t   *b,
              n00b_allocator_t *alloc,
              size_t            needed)
{
    if (needed <= b->cap) {
        return;
    }

    size_t new_cap = b->cap ? b->cap : 256;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = needed;
            break;
        }
        new_cap <<= 1;
    }

    char *new_data = marshal_scratch_alloc(alloc, new_cap);
    if (b->len) {
        memcpy(new_data, b->data, b->len);
    }
    b->data = new_data;
    b->cap  = new_cap;
}

static void
bytes_append(marshal_bytes_t   *b,
             n00b_allocator_t *alloc,
             const void       *data,
             size_t            len)
{
    bytes_reserve(b, alloc, b->len + len);
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

static void
bytes_append_zero(marshal_bytes_t   *b,
                  n00b_allocator_t *alloc,
                  size_t            len)
{
    bytes_reserve(b, alloc, b->len + len);
    memset(b->data + b->len, 0, len);
    b->len += len;
}

static void
work_push(n00b_marshal_ctx_t *ctx, n00b_marshal_node_t *node)
{
    if (ctx->work_len == ctx->work_cap) {
        size_t new_cap = ctx->work_cap ? ctx->work_cap << 1 : 32;
        n00b_marshal_node_t **new_items = marshal_scratch_alloc(
            ctx->scratch_alloc, new_cap * sizeof(*new_items));
        if (ctx->work_len) {
            memcpy(new_items, ctx->worklist, ctx->work_len * sizeof(*new_items));
        }
        ctx->worklist = new_items;
        ctx->work_cap = new_cap;
    }
    ctx->worklist[ctx->work_len++] = node;
}

static bool
scan_word_for_policy(n00b_marshal_alloc_record_t *rec, uint64_t i)
{
    switch ((n00b_gc_scan_kind_t)rec->scan_kind) {
    case N00B_GC_SCAN_KIND_NONE:
        return false;
    case N00B_GC_SCAN_KIND_ALL:
        return true;
    case N00B_GC_SCAN_KIND_EVERY_OTHER:
        return (i & 1u) == 0;
    case N00B_GC_SCAN_KIND_DEFAULT:
        return !rec->no_scan;
    case N00B_GC_SCAN_KIND_CALLBACK:
    default:
        return false;
    }
}

// Resolve a scan callback function pointer to its built-in tag.
// Returns false for a custom (non-built-in) callback (D-039): the caller
// raises N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK. The address->tag
// table lives here (D-040 OQ-1); the built-in set is closed.
static bool
marshal_scan_cb_to_tag(n00b_gc_scan_cb_t cb, n00b_marshal_scan_cb_tag_t *out)
{
    static const struct {
        n00b_gc_scan_cb_t          cb;
        n00b_marshal_scan_cb_tag_t tag;
    } table[] = {
        {n00b_gc_scan_cb_all, N00B_MARSHAL_SCAN_CB_TAG_ALL},
        {n00b_gc_scan_cb_none, N00B_MARSHAL_SCAN_CB_TAG_NONE},
        {n00b_gc_scan_cb_every_other, N00B_MARSHAL_SCAN_CB_TAG_EVERY_OTHER},
        {n00b_gc_scan_cb_struct_field, N00B_MARSHAL_SCAN_CB_TAG_STRUCT_FIELD},
        {n00b_gc_scan_cb_struct_layout, N00B_MARSHAL_SCAN_CB_TAG_STRUCT_LAYOUT},
        {n00b_gc_scan_cb_type_layout, N00B_MARSHAL_SCAN_CB_TAG_TYPE_LAYOUT},
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i].cb == cb) {
            *out = table[i].tag;
            return true;
        }
    }
    return false;
}

// Reverse of marshal_scan_cb_to_tag: tag -> built-in callback address.
static bool
marshal_tag_to_scan_cb(n00b_marshal_scan_cb_tag_t tag, n00b_gc_scan_cb_t *out)
{
    switch (tag) {
    case N00B_MARSHAL_SCAN_CB_TAG_ALL:
        *out = n00b_gc_scan_cb_all;
        return true;
    case N00B_MARSHAL_SCAN_CB_TAG_NONE:
        *out = n00b_gc_scan_cb_none;
        return true;
    case N00B_MARSHAL_SCAN_CB_TAG_EVERY_OTHER:
        *out = n00b_gc_scan_cb_every_other;
        return true;
    case N00B_MARSHAL_SCAN_CB_TAG_STRUCT_FIELD:
        *out = n00b_gc_scan_cb_struct_field;
        return true;
    case N00B_MARSHAL_SCAN_CB_TAG_STRUCT_LAYOUT:
        *out = n00b_gc_scan_cb_struct_layout;
        return true;
    case N00B_MARSHAL_SCAN_CB_TAG_TYPE_LAYOUT:
        *out = n00b_gc_scan_cb_type_layout;
        return true;
    case N00B_MARSHAL_SCAN_CB_TAG_LIMIT:
    default:
        return false;
    }
}

// A scan_cb_tag carries a scan_user descriptor (and thus an identity
// payload) only for the struct-field / struct-layout callbacks
// (D-040 OQ-5). all/none/every_other take no user data; TYPE_LAYOUT
// re-derives scan_user from the allocation's tinfo on unmarshal.
static bool
marshal_scan_cb_tag_uses_user(n00b_marshal_scan_cb_tag_t tag)
{
    return tag == N00B_MARSHAL_SCAN_CB_TAG_STRUCT_FIELD
        || tag == N00B_MARSHAL_SCAN_CB_TAG_STRUCT_LAYOUT;
}

static uint64_t
marshal_scan_word_count(n00b_marshal_alloc_record_t *rec)
{
    uint64_t user_words = rec->user_len / sizeof(uint64_t);

    if ((rec->flags & N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN) != 0
        && rec->ptr_words < user_words) {
        return rec->ptr_words;
    }

    return user_words;
}

static n00b_marshal_status_t
marshal_status_from_static_identity(n00b_static_identity_status_t status)
{
    switch (status) {
    case N00B_STATIC_IDENTITY_OK:
        return N00B_MARSHAL_OK;
    case N00B_STATIC_IDENTITY_ERR_MISSING:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_MISSING;
    case N00B_STATIC_IDENTITY_ERR_DUPLICATE:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_DUPLICATE;
    case N00B_STATIC_IDENTITY_ERR_MUTABILITY:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_MUTABILITY;
    case N00B_STATIC_IDENTITY_ERR_TYPE:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_TYPE;
    case N00B_STATIC_IDENTITY_ERR_SCAN:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_SCAN;
    case N00B_STATIC_IDENTITY_ERR_LENGTH:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_LENGTH;
    case N00B_STATIC_IDENTITY_ERR_CHECK_BYTES:
        return N00B_MARSHAL_ERR_STATIC_IDENTITY_CHECK_BYTES;
    case N00B_STATIC_IDENTITY_ERR_NULL:
    case N00B_STATIC_IDENTITY_ERR_INVALID:
    default:
        return N00B_MARSHAL_ERR_BAD_STREAM;
    }
}

static bool
marshal_static_identity_valid(const n00b_static_identity_t *identity)
{
    return identity != nullptr
        && identity->version == N00B_STATIC_IDENTITY_VERSION
        && identity->kind != N00B_STATIC_IDENTITY_NONE
        && identity->kind <= N00B_STATIC_IDENTITY_MANUAL
        && identity->namespace_id != nullptr
        && identity->namespace_id[0] != '\0'
        && identity->object_key != nullptr
        && identity->object_key[0] != '\0';
}

static bool
pspatch_expected_len(uint32_t namespace_len,
                     uint32_t key_len,
                     uint32_t check_len,
                     uint32_t *out_len)
{
    if (namespace_len == 0 || key_len == 0
        || check_len == 0 || check_len > N00B_MARSHAL_STATIC_CHECK_MAX) {
        return false;
    }

    uint64_t len = sizeof(n00b_marshal_pspatch_record_t);
    len += namespace_len;
    len += key_len;
    len += check_len;
    len = align8(len);

    if (len > UINT32_MAX) {
        return false;
    }

    *out_len = (uint32_t)len;
    return true;
}

static bool
pspatch_lengths_for_identity(const n00b_static_identity_t *identity,
                             uint32_t check_len,
                             uint32_t *namespace_len,
                             uint32_t *key_len,
                             uint32_t *record_len)
{
    if (!marshal_static_identity_valid(identity)) {
        return false;
    }

    size_t ns_len = strlen(identity->namespace_id);
    size_t obj_len = strlen(identity->object_key);

    if (ns_len > UINT32_MAX || obj_len > UINT32_MAX) {
        return false;
    }

    *namespace_len = (uint32_t)ns_len;
    *key_len       = (uint32_t)obj_len;
    return pspatch_expected_len(*namespace_len, *key_len, check_len, record_len);
}

static const unsigned char *
pspatch_namespace_bytes(const n00b_marshal_pspatch_record_t *rec)
{
    return (const unsigned char *)rec + sizeof(*rec);
}

static const unsigned char *
pspatch_key_bytes(const n00b_marshal_pspatch_record_t *rec)
{
    return pspatch_namespace_bytes(rec) + rec->namespace_len;
}

static const unsigned char *
pspatch_check_bytes(const n00b_marshal_pspatch_record_t *rec)
{
    return pspatch_key_bytes(rec) + rec->key_len;
}

static bool
pspatch_payload_has_nul(const n00b_marshal_pspatch_record_t *rec)
{
    return memchr(pspatch_namespace_bytes(rec), '\0', rec->namespace_len) != nullptr
        || memchr(pspatch_key_bytes(rec), '\0', rec->key_len) != nullptr;
}

// CBSCAN identity-payload accessors and length helper. The identity
// payload bytes follow the fixed n00b_marshal_cbscan_record_t in the
// same order as PSPATCH (namespace, key, check), but only when
// has_identity != 0.
static const unsigned char *
cbscan_namespace_bytes(const n00b_marshal_cbscan_record_t *rec)
{
    return (const unsigned char *)rec + sizeof(*rec);
}

static const unsigned char *
cbscan_key_bytes(const n00b_marshal_cbscan_record_t *rec)
{
    return cbscan_namespace_bytes(rec) + rec->namespace_len;
}

static const unsigned char *
cbscan_check_bytes(const n00b_marshal_cbscan_record_t *rec)
{
    return cbscan_key_bytes(rec) + rec->key_len;
}

static bool
cbscan_payload_has_nul(const n00b_marshal_cbscan_record_t *rec)
{
    return memchr(cbscan_namespace_bytes(rec), '\0', rec->namespace_len) != nullptr
        || memchr(cbscan_key_bytes(rec), '\0', rec->key_len) != nullptr;
}

// Expected total CBSCAN record length (fixed struct + identity payload).
// When has_identity == 0, the identity fields must all be zero and the
// record is exactly the fixed struct, 8-byte aligned.
static bool
cbscan_expected_len(uint32_t has_identity,
                    uint32_t namespace_len,
                    uint32_t key_len,
                    uint32_t check_len,
                    uint32_t *out_len)
{
    if (!has_identity) {
        if (namespace_len != 0 || key_len != 0 || check_len != 0) {
            return false;
        }
        uint64_t len = align8(sizeof(n00b_marshal_cbscan_record_t));
        if (len > UINT32_MAX) {
            return false;
        }
        *out_len = (uint32_t)len;
        return true;
    }

    if (namespace_len == 0 || key_len == 0
        || check_len == 0 || check_len > N00B_MARSHAL_STATIC_CHECK_MAX) {
        return false;
    }

    uint64_t len = sizeof(n00b_marshal_cbscan_record_t);
    len += namespace_len;
    len += key_len;
    len += check_len;
    len = align8(len);

    if (len > UINT32_MAX) {
        return false;
    }

    *out_len = (uint32_t)len;
    return true;
}

static bool
alloc_view(n00b_alloc_info_t              info,
           void                         **user_ptr,
           uint64_t                      *user_len,
           n00b_marshal_alloc_record_t   *rec,
           n00b_gc_scan_cb_t             *scan_cb,
           void                         **scan_user)
{
    *rec       = (typeof(*rec)){};
    rec->op    = N00B_MARSHAL_OP_ALLOC;
    *scan_cb   = nullptr;
    *scan_user = nullptr;

    if (info.kind == n00b_alloc_oob) {
        n00b_oob_hdr_t *oob = info.hdr.oob;
        *user_ptr           = oob->user_ptr;
        *user_len           = oob->hcur ? oob->alloc_len - N00B_ALLOC_HDR_SZ
                                        : oob->alloc_len;
        rec->flags          = N00B_MARSHAL_ALLOC_F_SOURCE_OOB;
        if (oob->hcur) {
            rec->flags |= N00B_MARSHAL_ALLOC_F_SOURCE_INLINE;
        }
        else {
            rec->flags |= N00B_MARSHAL_ALLOC_F_SOURCE_HEADERLESS;
        }
        rec->tinfo     = oob->tinfo;
        rec->ptr_words = oob->ptr_words;
        if (oob->ptr_words_known) {
            rec->flags |= N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN;
        }
        rec->scan_kind = oob->scan_kind;
        rec->no_scan   = oob->no_scan;
        rec->is_array  = oob->is_array;
        // The OOB header is the authoritative carrier for CALLBACK
        // scan_cb / scan_user (W-1); CALLBACK allocations are runtime-
        // forced onto this path (alloc.c:113-120).
        *scan_cb   = oob->scan_cb;
        *scan_user = oob->scan_user;
        return true;
    }

    if (info.kind == n00b_alloc_inline) {
        n00b_inline_hdr_t *hdr = info.hdr.in_line;
        *user_ptr             = ((char *)hdr) + N00B_ALLOC_HDR_SZ;
        *user_len             = hdr->alloc_len - N00B_ALLOC_HDR_SZ;
        rec->flags            = N00B_MARSHAL_ALLOC_F_SOURCE_INLINE;
        rec->tinfo            = hdr->tinfo;
        rec->ptr_words        = hdr->ptr_words;
        if (hdr->ptr_words_known) {
            rec->flags |= N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN;
        }
        rec->scan_kind        = hdr->scan_kind;
        rec->no_scan          = hdr->no_scan;
        rec->is_array         = hdr->is_array;
        *scan_cb              = hdr->scan_cb;
        *scan_user            = hdr->scan_user;
        return true;
    }

    return false;
}

static n00b_marshal_node_t *
marshal_add_alloc(n00b_marshal_ctx_t *ctx, n00b_alloc_info_t info)
{
    void                       *user_ptr = nullptr;
    uint64_t                    user_len = 0;
    n00b_marshal_alloc_record_t rec;
    n00b_gc_scan_cb_t           scan_cb   = nullptr;
    void                       *scan_user = nullptr;

    if (!alloc_view(info, &user_ptr, &user_len, &rec, &scan_cb, &scan_user)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION,
                          r"unsupported or missing allocation metadata");
        return nullptr;
    }

    // CALLBACK objects round-trip via a built-in scan_cb tag plus, for
    // struct_field / struct_layout, a static-identity scan_user payload
    // (D-038/D-039). A custom (non-built-in) scan_cb is an explicit error.
    bool                       is_callback = false;
    n00b_marshal_scan_cb_tag_t scan_cb_tag = N00B_MARSHAL_SCAN_CB_TAG_LIMIT;

    if (rec.scan_kind == N00B_GC_SCAN_KIND_CALLBACK) {
        if (!marshal_scan_cb_to_tag(scan_cb, &scan_cb_tag)) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                              r"callback scan policy uses a non-built-in scan_cb");
            return nullptr;
        }
        if (marshal_scan_cb_tag_uses_user(scan_cb_tag) && scan_user == nullptr) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                              r"struct-layout scan callback is missing its scan_user descriptor");
            return nullptr;
        }
        if (scan_cb_tag == N00B_MARSHAL_SCAN_CB_TAG_TYPE_LAYOUT && rec.tinfo == 0) {
            rec.tinfo = n00b_gc_type_map_hash_for_layout(scan_user);
            if (rec.tinfo == 0) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                                  r"type-layout scan callback is missing its type hash");
                return nullptr;
            }
        }
        is_callback = true;
    }

    if (rec.ptr_words > (user_len / sizeof(uint64_t))) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION,
                          r"allocation pointer-word metadata exceeds object size");
        return nullptr;
    }

    bool                 found = false;
    n00b_marshal_node_t *node  = n00b_dict_get(ctx->memos, user_ptr, &found);
    if (found) {
        return node;
    }

    uint64_t payload_len = align8(user_len);
    if (ctx->next_offset > UINT32_MAX || payload_len > UINT32_MAX
        || ctx->next_offset + payload_len > UINT32_MAX) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_LIMIT,
                          r"marshaled graph exceeds 32-bit virtual heap limit");
        return nullptr;
    }

    node              = marshal_scratch_alloc(ctx->scratch_alloc, sizeof(*node));
    node->user_ptr    = user_ptr;
    node->vaddr       = ((uint64_t)ctx->base_address << 32) | ctx->next_offset;
    node->rec         = rec;
    node->payload     = marshal_scratch_alloc(ctx->scratch_alloc, payload_len);
    node->scanned     = false;
    node->is_callback = is_callback;
    node->scan_cb_tag = scan_cb_tag;
    node->scan_user   = scan_user;
    node->bitmap      = nullptr;
    node->bitmap_words = 0;

    node->rec.vaddr       = node->vaddr;
    node->rec.user_len    = user_len;
    node->rec.payload_len = payload_len;

    memcpy(node->payload, user_ptr, user_len);
    if (payload_len > user_len) {
        memset(node->payload + user_len, 0, payload_len - user_len);
    }

    ctx->next_offset += (uint32_t)payload_len;
    n00b_dict_put(ctx->memos, user_ptr, node);
    work_push(ctx, node);

    return node;
}

static void
emit_cpatch(n00b_marshal_ctx_t *ctx, uint64_t vaddr, uint64_t value)
{
    n00b_marshal_cpatch_record_t rec = {
        .op       = N00B_MARSHAL_OP_CPATCH,
        .reserved = 0,
        .vaddr    = vaddr,
        .value    = value,
    };

    bytes_append(&ctx->patches, ctx->scratch_alloc, &rec, sizeof(rec));
}

static bool
static_ref_view(void *addr, n00b_marshal_static_ref_t *out)
{
    *out = (typeof(*out)){};

    auto range_opt = n00b_mmap_range_by_address(addr);
    if (n00b_option_is_set(range_opt)) {
        n00b_alloc_range_t *range = n00b_option_get(range_opt);
        uint64_t            base  = (uint64_t)(uintptr_t)range->start;
        uint64_t            end   = base + range->len;

        if (range->kind == n00b_mmap_static
            && (uint64_t)(uintptr_t)addr >= base
            && (uint64_t)(uintptr_t)addr < end) {
            *out = (n00b_marshal_static_ref_t){
                .start     = base,
                .len       = range->len,
                .object_id = range->object_id,
                .tinfo     = range->tinfo,
                .scan_kind = range->scan_kind,
                .flags     = range->flags,
                .identity  = range->identity,
            };
            return true;
        }
    }

    return false;
}

static bool
emit_spatch(n00b_marshal_ctx_t *ctx,
            uint64_t vaddr,
            uint64_t value,
            const n00b_marshal_static_ref_t *ref)
{
    uint64_t offset = value - ref->start;
    if (offset >= ref->len) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer lies outside its registered object");
        return false;
    }

    uint64_t remain    = ref->len - offset;
    uint32_t check_len = (uint32_t)(remain < sizeof(((n00b_marshal_spatch_record_t *)0)->check)
                                       ? remain
                                       : sizeof(((n00b_marshal_spatch_record_t *)0)->check));
    if (!check_len) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer has no bytes available for validation");
        return false;
    }

    n00b_marshal_spatch_record_t rec = {
        .op           = N00B_MARSHAL_OP_SPATCH,
        .check_len    = check_len,
        .vaddr        = vaddr,
        .static_addr  = value,
        .static_start = ref->start,
        .static_len   = ref->len,
        .object_id    = ref->object_id,
    };
    memcpy(rec.check, (void *)(uintptr_t)value, check_len);

    bytes_append(&ctx->patches, ctx->scratch_alloc, &rec, sizeof(rec));
    return true;
}

static bool
emit_pspatch(n00b_marshal_ctx_t *ctx,
             uint64_t vaddr,
             uint64_t value,
             const n00b_marshal_static_ref_t *ref)
{
    const n00b_static_identity_t *identity = ref->identity;
    if (!marshal_static_identity_valid(identity)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer identity is malformed");
        return false;
    }

    uint64_t offset = value - ref->start;
    if (offset >= ref->len) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer lies outside its registered object");
        return false;
    }

    uint64_t remain    = ref->len - offset;
    uint32_t check_len = (uint32_t)(remain < N00B_MARSHAL_STATIC_CHECK_MAX
                                       ? remain
                                       : N00B_MARSHAL_STATIC_CHECK_MAX);
    if (!check_len) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer has no bytes available for validation");
        return false;
    }

    uint32_t namespace_len;
    uint32_t key_len;
    uint32_t record_len;
    if (!pspatch_lengths_for_identity(identity,
                                      check_len,
                                      &namespace_len,
                                      &key_len,
                                      &record_len)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer identity cannot be encoded");
        return false;
    }

    const uint32_t flags_mask = N00B_STATIC_OBJECT_F_READONLY
                              | N00B_STATIC_OBJECT_F_MUTABLE;
    const uint32_t flags_value = ref->flags & flags_mask;
    const unsigned char *check = (const unsigned char *)(uintptr_t)value;

    n00b_static_identity_query_t query = {
        .checks = N00B_STATIC_IDENTITY_CHECK_LEN
                | N00B_STATIC_IDENTITY_CHECK_TINFO
                | N00B_STATIC_IDENTITY_CHECK_SCAN_KIND
                | N00B_STATIC_IDENTITY_CHECK_FLAGS
                | N00B_STATIC_IDENTITY_CHECK_BYTES,
        .len          = ref->len,
        .tinfo        = ref->tinfo,
        .scan_kind    = ref->scan_kind,
        .flags_mask   = flags_mask,
        .flags_value  = flags_value,
        .check_offset = offset,
        .check_len    = check_len,
        .check_bytes  = check,
    };

    n00b_alloc_range_t *range = nullptr;
    n00b_static_identity_status_t lookup = n00b_static_identity_lookup(identity,
                                                                       &query,
                                                                       &range);
    if (lookup != N00B_STATIC_IDENTITY_OK) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          marshal_status_from_static_identity(lookup),
                          r"portable static pointer identity failed validation");
        return false;
    }
    if (range == nullptr || (uint64_t)(uintptr_t)range->start != ref->start) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_STATIC_IDENTITY_DUPLICATE,
                          r"portable static pointer identity resolved to a different object");
        return false;
    }

    n00b_marshal_pspatch_record_t rec = {
        .op               = N00B_MARSHAL_OP_PSPATCH,
        .record_len       = record_len,
        .vaddr            = vaddr,
        .object_offset    = offset,
        .object_len       = ref->len,
        .tinfo            = ref->tinfo,
        .flags_mask       = flags_mask,
        .flags_value      = flags_value,
        .scan_kind        = ref->scan_kind,
        .identity_version = identity->version,
        .identity_kind    = identity->kind,
        .namespace_len    = namespace_len,
        .key_len          = key_len,
        .check_len        = check_len,
        .reserved         = 0,
    };

    bytes_append(&ctx->patches, ctx->scratch_alloc, &rec, sizeof(rec));
    bytes_append(&ctx->patches,
                 ctx->scratch_alloc,
                 identity->namespace_id,
                 namespace_len);
    bytes_append(&ctx->patches,
                 ctx->scratch_alloc,
                 identity->object_key,
                 key_len);
    bytes_append(&ctx->patches, ctx->scratch_alloc, check, check_len);

    size_t used = sizeof(rec) + namespace_len + key_len + check_len;
    bytes_append_zero(&ctx->patches, ctx->scratch_alloc, record_len - used);
    return true;
}

// A static *code* pointer (function) is not in any n00b_mmap_static data
// range, so static_ref_view misses it. Identify it by exported symbol via
// dladdr and emit it by name (rebound with dlsym on unmarshal), mirroring
// how FFI binds C symbols. Returns false (without setting an error) if the
// address is not an exact-match exported symbol, so the caller falls back
// to the generic unsupported-static-pointer error.
static bool
emit_fnpatch(n00b_marshal_ctx_t *ctx, uint64_t vaddr, uint64_t value)
{
#ifndef _WIN32
    Dl_info info;
    if (dladdr((void *)(uintptr_t)value, &info) == 0
        || info.dli_sname == nullptr
        || (uint64_t)(uintptr_t)info.dli_saddr != value) {
        // No symbol, or only a *nearest* symbol (not an exact entry point):
        // never guess — let the caller reject it.
        return false;
    }

    const char *sym  = info.dli_sname;
    uint32_t    nlen = 0;
    while (sym[nlen] != '\0') {
        if (nlen >= N00B_MARSHAL_FN_NAME_MAX) {
            return false;
        }
        nlen++;
    }
    if (nlen == 0) {
        return false;
    }

    uint32_t record_len = (uint32_t)align8(sizeof(n00b_marshal_fnpatch_record_t)
                                           + nlen);
    n00b_marshal_fnpatch_record_t rec = {
        .op         = N00B_MARSHAL_OP_FNPATCH,
        .record_len = record_len,
        .vaddr      = vaddr,
        .name_len   = nlen,
        .reserved   = 0,
    };
    bytes_append(&ctx->patches, ctx->scratch_alloc, &rec, sizeof(rec));
    bytes_append(&ctx->patches, ctx->scratch_alloc, sym, nlen);
    bytes_append_zero(&ctx->patches,
                      ctx->scratch_alloc,
                      record_len - sizeof(rec) - nlen);
    return true;
#else
    (void)ctx;
    (void)vaddr;
    (void)value;
    return false;
#endif
}

static bool
emit_static_patch(n00b_marshal_ctx_t *ctx,
                  uint64_t            vaddr,
                  uint64_t            value,
                  bool               *zero_slot)
{
    *zero_slot = false;

    n00b_marshal_static_ref_t ref;
    if (!static_ref_view((void *)(uintptr_t)value, &ref)) {
        // Not a registered static data object — but it may be an exported
        // function pointer we can round-trip by symbol name.
        if (emit_fnpatch(ctx, vaddr, value)) {
            *zero_slot = true;
            return true;
        }
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                          r"static pointer is not a registered static object");
        return false;
    }

    if (ref.identity != nullptr) {
        return emit_pspatch(ctx, vaddr, value, &ref);
    }

    return emit_spatch(ctx, vaddr, value, &ref);
}

static void
emit_alloc(n00b_marshal_ctx_t *ctx, n00b_marshal_node_t *node)
{
    bytes_append(&ctx->metadata,
                 ctx->scratch_alloc,
                 &node->rec,
                 sizeof(node->rec));
    bytes_append(&ctx->out,
                 ctx->scratch_alloc,
                 node->payload,
                 (size_t)node->rec.payload_len);
}

static bool
marshal_interior_in_bounds(uint64_t interior, uint64_t user_len)
{
    if (user_len == 0) {
        return interior == 0;
    }
    return interior < user_len;
}

// Build the precise per-word pointer bitmap for a CALLBACK node by
// invoking its built-in scan_cb into a private scratch n00b_gc_map_t
// (D-040 OQ-3: the bitmap is computed once and stored on the node).
// The map's user_ptr is the LIVE source object: the built-in callbacks
// only READ num_words/user to set bits and never mutate the object
// (W-6), so this is side-effect-free on the live graph. The bitmap and
// the map's backing storage are private scratch allocations.
static bool
compute_callback_bitmap(n00b_marshal_ctx_t *ctx, n00b_marshal_node_t *node)
{
    n00b_gc_scan_cb_t cb = nullptr;
    if (!marshal_tag_to_scan_cb(node->scan_cb_tag, &cb)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback scan policy uses a non-built-in scan_cb");
        return false;
    }

    uint64_t num_words = marshal_scan_word_count(&node->rec);
    uint64_t map_words = n00b_gc_map_word_count(num_words);
    if (map_words == 0) {
        map_words = 1;
    }

    uint64_t *bitmap = marshal_scratch_alloc(ctx->scratch_alloc,
                                             map_words * sizeof(uint64_t));
    memset(bitmap, 0, map_words * sizeof(uint64_t));

    n00b_gc_map_t map = {
        .user_ptr  = node->user_ptr,
        .num_words = num_words,
        .bitmap    = bitmap,
    };
    cb(&map, node->scan_user);

    node->bitmap       = bitmap;
    node->bitmap_words = map_words;
    return true;
}

// Emit the CALLBACK-scan extension record for a node into the trailing
// metadata section, immediately after its ALLOC metadata. Carries the
// built-in scan_cb tag and, for struct_field / struct_layout, the
// scan_user descriptor as a PSPATCH-style static identity
// (resolved/validated exactly like emit_pspatch).
static bool
emit_cbscan(n00b_marshal_ctx_t *ctx, n00b_marshal_node_t *node)
{
    if (!marshal_scan_cb_tag_uses_user(node->scan_cb_tag)) {
        // all / none / every_other: no scan_user, no identity payload.
        uint32_t record_len;
        if (!cbscan_expected_len(0, 0, 0, 0, &record_len)) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                              r"callback-scan record cannot be encoded");
            return false;
        }
        n00b_marshal_cbscan_record_t rec = {
            .op          = N00B_MARSHAL_OP_CBSCAN,
            .record_len  = record_len,
            .vaddr       = node->vaddr,
            .scan_cb_tag = node->scan_cb_tag,
        };
        bytes_append(&ctx->metadata, ctx->scratch_alloc, &rec, sizeof(rec));
        bytes_append_zero(&ctx->metadata,
                          ctx->scratch_alloc,
                          record_len - sizeof(rec));
        return true;
    }

    // struct_field / struct_layout: the scan_user descriptor must be a
    // registered static object with an identity (W-2 / D-040 OQ-2).
    n00b_marshal_static_ref_t ref;
    if (!static_ref_view(node->scan_user, &ref) || ref.identity == nullptr) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback scan_user descriptor is not a registered static identity");
        return false;
    }

    const n00b_static_identity_t *identity = ref.identity;
    if (!marshal_static_identity_valid(identity)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback scan_user identity is malformed");
        return false;
    }

    uint64_t offset = (uint64_t)(uintptr_t)node->scan_user - ref.start;
    if (offset >= ref.len) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback scan_user lies outside its registered object");
        return false;
    }

    uint64_t remain    = ref.len - offset;
    uint32_t check_len = (uint32_t)(remain < N00B_MARSHAL_STATIC_CHECK_MAX
                                       ? remain
                                       : N00B_MARSHAL_STATIC_CHECK_MAX);
    if (!check_len) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback scan_user has no bytes available for validation");
        return false;
    }

    uint32_t namespace_len;
    uint32_t key_len;
    uint32_t identity_len;
    if (!pspatch_lengths_for_identity(identity,
                                      check_len,
                                      &namespace_len,
                                      &key_len,
                                      &identity_len)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback scan_user identity cannot be encoded");
        return false;
    }

    const uint32_t flags_mask  = N00B_STATIC_OBJECT_F_READONLY
                               | N00B_STATIC_OBJECT_F_MUTABLE;
    const uint32_t flags_value = ref.flags & flags_mask;
    const unsigned char *check = (const unsigned char *)(uintptr_t)node->scan_user;

    n00b_static_identity_query_t query = {
        .checks = N00B_STATIC_IDENTITY_CHECK_LEN
                | N00B_STATIC_IDENTITY_CHECK_TINFO
                | N00B_STATIC_IDENTITY_CHECK_SCAN_KIND
                | N00B_STATIC_IDENTITY_CHECK_FLAGS
                | N00B_STATIC_IDENTITY_CHECK_BYTES,
        .len          = ref.len,
        .tinfo        = ref.tinfo,
        .scan_kind    = ref.scan_kind,
        .flags_mask   = flags_mask,
        .flags_value  = flags_value,
        .check_offset = offset,
        .check_len    = check_len,
        .check_bytes  = check,
    };

    n00b_alloc_range_t *range = nullptr;
    n00b_static_identity_status_t lookup = n00b_static_identity_lookup(identity,
                                                                       &query,
                                                                       &range);
    if (lookup != N00B_STATIC_IDENTITY_OK) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          marshal_status_from_static_identity(lookup),
                          r"callback scan_user identity failed validation");
        return false;
    }
    if (range == nullptr || (uint64_t)(uintptr_t)range->start != ref.start) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_STATIC_IDENTITY_DUPLICATE,
                          r"callback scan_user identity resolved to a different object");
        return false;
    }

    uint32_t record_len;
    if (!cbscan_expected_len(1, namespace_len, key_len, check_len, &record_len)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                          r"callback-scan record cannot be encoded");
        return false;
    }

    n00b_marshal_cbscan_record_t rec = {
        .op               = N00B_MARSHAL_OP_CBSCAN,
        .record_len       = record_len,
        .vaddr            = node->vaddr,
        .scan_cb_tag      = node->scan_cb_tag,
        .has_identity     = 1,
        .object_offset    = offset,
        .object_len       = ref.len,
        .tinfo            = ref.tinfo,
        .flags_mask       = flags_mask,
        .flags_value      = flags_value,
        .scan_kind        = ref.scan_kind,
        .identity_version = identity->version,
        .identity_kind    = identity->kind,
        .namespace_len    = namespace_len,
        .key_len          = key_len,
        .check_len        = check_len,
        .reserved         = 0,
    };

    bytes_append(&ctx->metadata, ctx->scratch_alloc, &rec, sizeof(rec));
    bytes_append(&ctx->metadata,
                 ctx->scratch_alloc,
                 identity->namespace_id,
                 namespace_len);
    bytes_append(&ctx->metadata, ctx->scratch_alloc, identity->object_key, key_len);
    bytes_append(&ctx->metadata, ctx->scratch_alloc, check, check_len);

    size_t used = sizeof(rec) + namespace_len + key_len + check_len;
    bytes_append_zero(&ctx->metadata, ctx->scratch_alloc, record_len - used);
    return true;
}

// Add the resolved target allocation to the marshal graph and rewrite the
// pointer word in `words[i]` to its virtual address.  Returns false on error
// (the caller must propagate by returning).  Shared by the home-allocator fast
// path and the global slow path in scan_node.
static inline bool
marshal_resolve_and_rewrite(n00b_marshal_ctx_t *ctx,
                            uint64_t           *words,
                            uint64_t            i,
                            uint64_t            word,
                            n00b_alloc_info_t   info)
{
    n00b_marshal_node_t *target = marshal_add_alloc(ctx, info);
    if (!target) {
        return false;
    }
    uint64_t interior = word - (uint64_t)(uintptr_t)target->user_ptr;
    if (!marshal_interior_in_bounds(interior, target->rec.user_len)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION,
                          r"pointer does not resolve inside target allocation");
        return false;
    }
    words[i] = target->vaddr + interior;
    return true;
}

static void
scan_node(n00b_marshal_ctx_t *ctx, n00b_marshal_node_t *node)
{
    if (node->scanned || ctx->status != N00B_MARSHAL_OK) {
        return;
    }

    node->scanned = true;

    // For CALLBACK nodes the bitmap (not scan_word_for_policy) is the
    // per-word pointer oracle (D-040 OQ-3); compute it once before the
    // scan loop and walk every user word so the bitmap decides each.
    uint64_t nwords;
    if (node->is_callback) {
        if (!compute_callback_bitmap(ctx, node)) {
            return;
        }
        nwords = marshal_scan_word_count(&node->rec);
    }
    else {
        nwords = marshal_scan_word_count(&node->rec);
    }
    uint64_t *words = (uint64_t *)node->payload;

    for (uint64_t i = 0; i < nwords; i++) {
        uint64_t word      = words[i];
        bool     rewritten = false;

        bool is_ptr;
        if (node->is_callback) {
            is_ptr = (i < node->bitmap_words * 64)
                  && n00b_gc_map_is_set(&(n00b_gc_map_t){.bitmap = node->bitmap}, i);
        }
        else {
            is_ptr = scan_word_for_policy(&node->rec, i);
        }

        if (is_ptr && word) {
            // Fast path (GC-style "already managed"): try the allocator the
            // walk is currently in before the global mmap interval-tree search.
            // Most pointers in a graph cluster in one pool, so this turns the
            // per-pointer tree search into an O(1) OOB-index hit.
            n00b_alloc_info_t home_info = n00b_try_alloc_info_in_allocator(
                (void *)(uintptr_t)word,
                ctx->home_allocator);
            if (home_info.kind == n00b_alloc_oob) {
                if (!marshal_resolve_and_rewrite(ctx, words, i, word, home_info)) {
                    return;
                }
                rewritten = true;
            }
            else {
                auto mmap_opt = n00b_mmap_by_address((void *)(uintptr_t)word);
                if (n00b_option_is_set(mmap_opt)) {
                    n00b_mmap_info_t *map = n00b_option_get(mmap_opt);
                    switch (map->kind) {
                    case n00b_mmap_managed_segment:
                    case n00b_mmap_pool:
                    case n00b_mmap_sys_segment: {
                        // Adopt this allocator as the walk's home so subsequent
                        // clustered pointers take the fast path above.
                        ctx->home_allocator = map->allocator;
                        n00b_alloc_info_t info = n00b_find_alloc_info(
                            (void *)(uintptr_t)word, .scan_for_header = true);
                        if (!marshal_resolve_and_rewrite(ctx, words, i, word, info)) {
                            return;
                        }
                        rewritten = true;
                        break;
                    }
                    case n00b_mmap_static:
                        bool zero_static_slot = false;
                        if (!emit_static_patch(ctx,
                                               node->vaddr + i * sizeof(uint64_t),
                                               word,
                                               &zero_static_slot)) {
                            return;
                        }
                        if (zero_static_slot) {
                            words[i] = 0;
                        }
                        rewritten = true;
                        break;
                    default:
                        break;
                    }
                }
            }
        }

        if (!rewritten && (word >> 32) == ctx->base_address) {
            uint64_t vaddr = node->vaddr + i * sizeof(uint64_t);
            emit_cpatch(ctx, vaddr, word);
        }
    }

    emit_alloc(ctx, node);

    if (node->is_callback) {
        // In v4+ the CBSCAN ext record is metadata, immediately after
        // this node's ALLOC metadata record.
        if (!emit_cbscan(ctx, node)) {
            return;
        }
    }
}

static bool
marshal_process(n00b_marshal_ctx_t *ctx, void *addr)
{
    if (!addr) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_NULL_ARG,
                          r"cannot marshal a null root");
        return false;
    }

    n00b_alloc_info_t info = n00b_find_alloc_info(addr, .scan_for_header = true);
    n00b_marshal_node_t *root = marshal_add_alloc(ctx, info);
    if (!root) {
        return false;
    }

    uint64_t interior = (uint64_t)(uintptr_t)addr - (uint64_t)(uintptr_t)root->user_ptr;
    if (!marshal_interior_in_bounds(interior, root->rec.user_len)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION,
                          r"root pointer does not resolve inside allocation");
        return false;
    }

    n00b_marshal_stream_header_t hdr = {
        .marshal_magic = N00B_MARSHAL_MAGIC,
        .version       = N00B_MARSHAL_VERSION,
        .base_address  = ctx->base_address,
        .root_offset   = (uint32_t)((root->vaddr + interior) & UINT32_MAX),
        .flags         = 0,
    };

    bytes_append(&ctx->out, ctx->scratch_alloc, &hdr, sizeof(hdr));

    while (ctx->work_ix < ctx->work_len) {
        scan_node(ctx, ctx->worklist[ctx->work_ix++]);
        if (ctx->status != N00B_MARSHAL_OK) {
            return false;
        }
    }

    if (ctx->out.len - sizeof(hdr) > UINT32_MAX) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_LIMIT,
                          r"marshaled payload front exceeds 32-bit limit");
        return false;
    }

    ((n00b_marshal_stream_header_t *)ctx->out.data)->flags =
        (uint32_t)(ctx->out.len - sizeof(hdr));

    if (ctx->metadata.len) {
        bytes_append(&ctx->out, ctx->scratch_alloc, ctx->metadata.data, ctx->metadata.len);
    }

    if (ctx->patches.len) {
        bytes_append(&ctx->out, ctx->scratch_alloc, ctx->patches.data, ctx->patches.len);
    }

    n00b_marshal_stop_record_t stop = {
        .op            = N00B_MARSHAL_OP_STOP,
        .end_of_stream = 1,
    };
    bytes_append(&ctx->out, ctx->scratch_alloc, &stop, sizeof(stop));

    return true;
}

n00b_marshal_ctx_t *
n00b_marshal_ctx_new() _kargs
{
    uint32_t flags        = N00B_MARSHAL_F_NONE;
    uint32_t base_address = 0;
}
{
    n00b_marshal_ctx_t *ctx = n00b_alloc(n00b_marshal_ctx_t);
    *ctx                    = (typeof(*ctx)){};
    marshal_init_scratch(&ctx->scratch, &ctx->scratch_alloc, "marshal_scratch");
    ctx->memos = n00b_alloc_with_opts(
        n00b_dict_t(void *, n00b_marshal_node_t *),
        &(n00b_alloc_opts_t){.allocator = ctx->scratch_alloc,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});
    n00b_dict_init(ctx->memos,
                   .locked        = false,
                   .allocator     = ctx->scratch_alloc,
                   .hash          = n00b_hash_word,
                   .skip_obj_hash = true,
                   .scan_kind     = N00B_GC_SCAN_KIND_NONE);

    ctx->base_address = base_address ? base_address
                                     : (0x4d000000u
                                        | ((uint32_t)(uintptr_t)ctx & 0x00ffffffu));
    if (!ctx->base_address) {
        ctx->base_address = 0x4d1cbab0u;
    }
    ctx->flags  = flags;
    ctx->status = N00B_MARSHAL_OK;
    return ctx;
}

void
n00b_marshal_ctx_destroy(n00b_marshal_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    n00b_allocator_destroy((n00b_allocator_t *)&ctx->scratch);
    n00b_free(ctx);
}

n00b_marshal_status_t
n00b_marshal_ctx_status(n00b_marshal_ctx_t *ctx)
{
    return ctx ? ctx->status : N00B_MARSHAL_ERR_NULL_ARG;
}

n00b_string_t *
n00b_marshal_status_name(n00b_marshal_status_t code)
{
    switch (code) {
    case N00B_MARSHAL_OK:
        return r"ok";
    case N00B_MARSHAL_ERR_NULL_ARG:
        return r"null-arg";
    case N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION:
        return r"unsupported-allocation";
    case N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_POLICY:
        return r"unsupported-scan-policy";
    case N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK:
        return r"unsupported-scan-callback";
    case N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER:
        return r"unsupported-static-pointer";
    case N00B_MARSHAL_ERR_BAD_STREAM:
        return r"bad-stream";
    case N00B_MARSHAL_ERR_INCOMPLETE_STREAM:
        return r"incomplete-stream";
    case N00B_MARSHAL_ERR_CONTEXT_CLOSED:
        return r"context-closed";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_MISSING:
        return r"static-identity-missing";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_DUPLICATE:
        return r"static-identity-duplicate";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_MUTABILITY:
        return r"static-identity-mutability";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_TYPE:
        return r"static-identity-type";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_SCAN:
        return r"static-identity-scan";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_LENGTH:
        return r"static-identity-length";
    case N00B_MARSHAL_ERR_STATIC_IDENTITY_CHECK_BYTES:
        return r"static-identity-check-bytes";
    case N00B_MARSHAL_ERR_LIMIT:
        return r"limit";
    }
    return r"unknown";
}

n00b_string_t *
n00b_marshal_ctx_error(n00b_marshal_ctx_t *ctx)
{
    if (!ctx) {
        return r"null marshal context";
    }
    return ctx->error;
}

n00b_buffer_t *
n00b_marshal_incremental(n00b_marshal_ctx_t *ctx, void *addr) _kargs
{
    bool close = true;
}
{
    (void)close;
    if (!ctx) {
        return nullptr;
    }
    if (ctx->used) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_CONTEXT_CLOSED,
                          r"marshal context already emitted a root");
        return nullptr;
    }
    ctx->used = true;

    bool hold_stw = (ctx->flags & N00B_MARSHAL_F_STW) != 0;
    if (hold_stw) {
        n00b_stop_the_world();
    }
    bool ok = marshal_process(ctx, addr);
    if (hold_stw) {
        n00b_restart_the_world();
    }
    if (!ok) {
        return nullptr;
    }

    return n00b_buffer_from_bytes(ctx->out.data, (int64_t)ctx->out.len);
}

n00b_buffer_t *
n00b_marshal(void *addr) _kargs
{
    uint32_t          flags        = N00B_MARSHAL_F_NONE;
    uint32_t          base_address = 0;
}
{
    n00b_marshal_ctx_t *ctx = n00b_marshal_ctx_new(.flags        = flags,
                                                   .base_address = base_address);
    n00b_buffer_t *result = n00b_marshal_incremental(ctx,
                                                     addr,
                                                     .close = true);
    n00b_marshal_ctx_destroy(ctx);
    return result;
}

static void
segments_push(n00b_unmarshal_ctx_t *ctx, n00b_unmarshal_segment_t *seg)
{
    if (ctx->segment_len == ctx->segment_cap) {
        size_t new_cap = ctx->segment_cap ? ctx->segment_cap << 1 : 32;
        n00b_unmarshal_segment_t **new_items = marshal_scratch_alloc(
            ctx->scratch_alloc, new_cap * sizeof(*new_items));
        if (ctx->segment_len) {
            memcpy(new_items, ctx->segments, ctx->segment_len * sizeof(*new_items));
        }
        ctx->segments    = new_items;
        ctx->segment_cap = new_cap;
    }
    ctx->segments[ctx->segment_len++] = seg;
}

static n00b_unmarshal_segment_t *
segment_for_vaddr(n00b_unmarshal_ctx_t *ctx, uint64_t vaddr)
{
    for (size_t i = 0; i < ctx->segment_len; i++) {
        n00b_unmarshal_segment_t *seg = ctx->segments[i];
        if (vaddr >= seg->vaddr
            && marshal_interior_in_bounds(vaddr - seg->vaddr, seg->user_len)) {
            return seg;
        }
    }
    return nullptr;
}

static void *
addr_for_vaddr_span(n00b_unmarshal_ctx_t *ctx, uint64_t vaddr, uint64_t len)
{
    n00b_unmarshal_segment_t *seg = segment_for_vaddr(ctx, vaddr);
    if (!seg) {
        return nullptr;
    }

    uint64_t offset = vaddr - seg->vaddr;
    if (len > seg->user_len || offset > seg->user_len - len) {
        return nullptr;
    }

    return ((char *)seg->user_ptr) + offset;
}

static void *
addr_for_vaddr(n00b_unmarshal_ctx_t *ctx, uint64_t vaddr)
{
    return addr_for_vaddr_span(ctx, vaddr, 0);
}

static uint64_t *
word_slot_for_vaddr(n00b_unmarshal_ctx_t *ctx, uint64_t vaddr)
{
    if (vaddr & (sizeof(uint64_t) - 1)) {
        return nullptr;
    }

    return addr_for_vaddr_span(ctx, vaddr, sizeof(uint64_t));
}

static bool
stream_complete_records(n00b_unmarshal_ctx_t        *ctx,
                        n00b_marshal_stream_header_t *hdr,
                        size_t                        ix,
                        bool                          payload_front,
                        uint32_t                      payload_front_len)
{
    uint32_t expected_offset = 0;
    // When a CALLBACK ALLOC record is parsed, the very next record must
    // be its CBSCAN extension: after the payload in v3, after the ALLOC
    // metadata in v4+.
    bool     expect_cbscan       = false;
    uint64_t expect_cbscan_vaddr = 0;

    while (ix < ctx->in.len) {
        if (ctx->in.len - ix < sizeof(uint32_t)) {
            return false;
        }

        uint32_t op = *(uint32_t *)(ctx->in.data + ix);
        if (expect_cbscan && op != N00B_MARSHAL_OP_CBSCAN) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_BAD_STREAM,
                              r"callback allocation record missing its scan extension");
            return false;
        }

        switch (op) {
        case N00B_MARSHAL_OP_ALLOC: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_alloc_record_t)) {
                return false;
            }

            n00b_marshal_alloc_record_t *rec = (void *)(ctx->in.data + ix);
            if ((rec->vaddr >> 32) != hdr->base_address
                || (uint32_t)(rec->vaddr & UINT32_MAX) != expected_offset
                || rec->payload_len != align8(rec->user_len)
                || rec->payload_len < rec->user_len
                || rec->ptr_words > (rec->user_len / sizeof(uint64_t))
                || rec->scan_kind > N00B_GC_SCAN_KIND_CALLBACK
                || (rec->flags & ~N00B_MARSHAL_ALLOC_F_KNOWN) != 0) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid allocation record shape");
                return false;
            }

            if (rec->scan_kind == N00B_GC_SCAN_KIND_CALLBACK) {
                if (hdr->version < 3) {
                    marshal_set_error(&ctx->status,
                                      &ctx->error,
                                      N00B_MARSHAL_ERR_BAD_STREAM,
                                      r"callback allocation record requires marshal stream version 3");
                    return false;
                }
                expect_cbscan       = true;
                expect_cbscan_vaddr = rec->vaddr;
            }

            ix += sizeof(*rec);

            if (rec->payload_len > UINT32_MAX
                || expected_offset > UINT32_MAX - (uint32_t)rec->payload_len) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_LIMIT,
                                  r"marshal stream exceeds 32-bit virtual heap limit");
                return false;
            }

            uint32_t payload_len = (uint32_t)rec->payload_len;
            if (payload_front) {
                if (payload_len > payload_front_len
                    || expected_offset > payload_front_len - payload_len) {
                    marshal_set_error(&ctx->status,
                                      &ctx->error,
                                      N00B_MARSHAL_ERR_BAD_STREAM,
                                      r"allocation payload exceeds marshal payload front");
                    return false;
                }
            }
            else {
                if (ctx->in.len - ix < rec->payload_len) {
                    return false;
                }
                ix += (size_t)rec->payload_len;
            }

            expected_offset += payload_len;
            break;
        }
        case N00B_MARSHAL_OP_CPATCH: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_cpatch_record_t)) {
                return false;
            }
            n00b_marshal_cpatch_record_t *rec = (void *)(ctx->in.data + ix);
            if (rec->reserved != 0 || (rec->vaddr >> 32) != hdr->base_address) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid collision patch record");
                return false;
            }
            ix += sizeof(*rec);
            break;
        }
        case N00B_MARSHAL_OP_SPATCH: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_spatch_record_t)) {
                return false;
            }
            n00b_marshal_spatch_record_t *rec = (void *)(ctx->in.data + ix);
            if (rec->check_len == 0 || rec->check_len > sizeof(rec->check)
                || (rec->vaddr >> 32) != hdr->base_address
                || rec->static_addr < rec->static_start
                || rec->static_addr - rec->static_start >= rec->static_len
                || rec->check_len > rec->static_len - (rec->static_addr - rec->static_start)) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid static patch record");
                return false;
            }
            ix += sizeof(*rec);
            break;
        }
        case N00B_MARSHAL_OP_PSPATCH: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_pspatch_record_t)) {
                return false;
            }
            n00b_marshal_pspatch_record_t *rec = (void *)(ctx->in.data + ix);
            uint32_t expected_len;
            const uint32_t flags_mask = N00B_STATIC_OBJECT_F_READONLY
                                      | N00B_STATIC_OBJECT_F_MUTABLE;
            if (hdr->version < 2
                || !pspatch_expected_len(rec->namespace_len,
                                          rec->key_len,
                                          rec->check_len,
                                          &expected_len)
                || rec->record_len != expected_len
                || rec->reserved != 0
                || (rec->vaddr >> 32) != hdr->base_address
                || rec->object_len == 0
                || rec->object_offset >= rec->object_len
                || rec->check_len > rec->object_len - rec->object_offset
                || rec->identity_version != N00B_STATIC_IDENTITY_VERSION
                || rec->identity_kind == N00B_STATIC_IDENTITY_NONE
                || rec->identity_kind > N00B_STATIC_IDENTITY_MANUAL
                || rec->flags_mask != flags_mask
                || (rec->flags_value & ~rec->flags_mask) != 0
                || rec->scan_kind > N00B_GC_SCAN_KIND_CALLBACK) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid portable static patch record");
                return false;
            }
            if (ctx->in.len - ix < rec->record_len) {
                return false;
            }
            if (pspatch_payload_has_nul(rec)) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"portable static patch identity contains nul bytes");
                return false;
            }
            ix += rec->record_len;
            break;
        }
        case N00B_MARSHAL_OP_FNPATCH: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_fnpatch_record_t)) {
                return false;
            }
            n00b_marshal_fnpatch_record_t *rec = (void *)(ctx->in.data + ix);
            uint64_t expected = align8(sizeof(*rec) + rec->name_len);
            if (rec->reserved != 0
                || rec->name_len == 0
                || rec->name_len > N00B_MARSHAL_FN_NAME_MAX
                || (uint64_t)rec->record_len != expected
                || (rec->vaddr >> 32) != hdr->base_address) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid function patch record");
                return false;
            }
            if (ctx->in.len - ix < rec->record_len) {
                return false;
            }
            const char *nm = fnpatch_name_bytes(rec);
            for (uint32_t i = 0; i < rec->name_len; i++) {
                if (nm[i] == '\0') {
                    marshal_set_error(&ctx->status,
                                      &ctx->error,
                                      N00B_MARSHAL_ERR_BAD_STREAM,
                                      r"function patch symbol contains nul bytes");
                    return false;
                }
            }
            ix += rec->record_len;
            break;
        }
        case N00B_MARSHAL_OP_CBSCAN: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_cbscan_record_t)) {
                return false;
            }
            n00b_marshal_cbscan_record_t *rec = (void *)(ctx->in.data + ix);
            if (!expect_cbscan
                || hdr->version < 3
                || rec->vaddr != expect_cbscan_vaddr
                || rec->scan_cb_tag >= N00B_MARSHAL_SCAN_CB_TAG_LIMIT
                || rec->has_identity > 1) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid callback-scan record placement");
                return false;
            }

            bool tag_uses_user = (rec->scan_cb_tag
                                  == N00B_MARSHAL_SCAN_CB_TAG_STRUCT_FIELD)
                              || (rec->scan_cb_tag
                                  == N00B_MARSHAL_SCAN_CB_TAG_STRUCT_LAYOUT);
            if ((bool)rec->has_identity != tag_uses_user) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"callback-scan identity presence disagrees with scan_cb tag");
                return false;
            }

            uint32_t expected_len;
            if (!cbscan_expected_len(rec->has_identity,
                                     rec->namespace_len,
                                     rec->key_len,
                                     rec->check_len,
                                     &expected_len)
                || rec->record_len != expected_len
                || rec->reserved != 0) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid callback-scan record shape");
                return false;
            }

            if (rec->has_identity) {
                const uint32_t flags_mask = N00B_STATIC_OBJECT_F_READONLY
                                          | N00B_STATIC_OBJECT_F_MUTABLE;
                if (rec->object_len == 0
                    || rec->object_offset >= rec->object_len
                    || rec->check_len > rec->object_len - rec->object_offset
                    || rec->identity_version != N00B_STATIC_IDENTITY_VERSION
                    || rec->identity_kind == N00B_STATIC_IDENTITY_NONE
                    || rec->identity_kind > N00B_STATIC_IDENTITY_MANUAL
                    || rec->flags_mask != flags_mask
                    || (rec->flags_value & ~rec->flags_mask) != 0
                    || rec->scan_kind > N00B_GC_SCAN_KIND_CALLBACK) {
                    marshal_set_error(&ctx->status,
                                      &ctx->error,
                                      N00B_MARSHAL_ERR_BAD_STREAM,
                                      r"invalid callback-scan identity payload");
                    return false;
                }
            }
            else {
                if (rec->object_offset != 0 || rec->object_len != 0
                    || rec->tinfo != 0 || rec->flags_mask != 0
                    || rec->flags_value != 0 || rec->scan_kind != 0
                    || rec->identity_version != 0 || rec->identity_kind != 0) {
                    marshal_set_error(&ctx->status,
                                      &ctx->error,
                                      N00B_MARSHAL_ERR_BAD_STREAM,
                                      r"callback-scan record carries unexpected identity payload");
                    return false;
                }
            }

            if (ctx->in.len - ix < rec->record_len) {
                return false;
            }
            if (rec->has_identity && cbscan_payload_has_nul(rec)) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"callback-scan identity contains nul bytes");
                return false;
            }
            expect_cbscan = false;
            ix += rec->record_len;
            break;
        }
        case N00B_MARSHAL_OP_STOP: {
            if (ctx->in.len - ix < sizeof(n00b_marshal_stop_record_t)) {
                return false;
            }
            n00b_marshal_stop_record_t *rec = (void *)(ctx->in.data + ix);
            if (rec->end_of_stream != 1 || ix + sizeof(*rec) != ctx->in.len) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"invalid marshal stream terminator");
                return false;
            }
            if (payload_front && expected_offset != payload_front_len) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"marshal payload front length disagrees with allocation metadata");
                return false;
            }
            return true;
        }
        default:
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_BAD_STREAM,
                              r"unknown marshal stream record");
            return false;
        }
    }

    return false;
}

static bool
stream_complete(n00b_unmarshal_ctx_t *ctx)
{
    if (ctx->in.len < sizeof(n00b_marshal_stream_header_t)) {
        return false;
    }

    n00b_marshal_stream_header_t *hdr = (void *)ctx->in.data;
    if (hdr->marshal_magic != N00B_MARSHAL_MAGIC
        || hdr->version < N00B_MARSHAL_MIN_VERSION
        || hdr->version > N00B_MARSHAL_VERSION) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_BAD_STREAM,
                          r"invalid marshal stream header");
        return false;
    }

    if (hdr->version >= N00B_MARSHAL_PAYLOAD_FRONT_VERSION) {
        if ((size_t)hdr->flags > SIZE_MAX - sizeof(*hdr)) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_LIMIT,
                              r"marshal payload front exceeds host size limit");
            return false;
        }
        size_t metadata_ix = sizeof(*hdr) + (size_t)hdr->flags;
        if (ctx->in.len < metadata_ix) {
            return false;
        }
        return stream_complete_records(ctx, hdr, metadata_ix, true, hdr->flags);
    }

    return stream_complete_records(ctx, hdr, sizeof(*hdr), false, 0);
}

// Resolve a validated CBSCAN ext record into the built-in scan_cb and
// (for struct_field / struct_layout) the scan_user descriptor address,
// using the same static-identity lookup the PSPATCH relink uses. On a
// successful return, *out_scan_cb / *out_scan_user are the values to
// restore on the reconstructed object.
static bool
cbscan_resolve(n00b_unmarshal_ctx_t                *ctx,
               const n00b_marshal_cbscan_record_t  *rec,
               uint64_t                             owner_tinfo,
               n00b_gc_scan_cb_t                   *out_scan_cb,
               void                               **out_scan_user)
{
    n00b_gc_scan_cb_t cb = nullptr;
    if (!marshal_tag_to_scan_cb((n00b_marshal_scan_cb_tag_t)rec->scan_cb_tag, &cb)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_BAD_STREAM,
                          r"callback-scan record carries an unknown scan_cb tag");
        return false;
    }

    *out_scan_cb   = cb;
    *out_scan_user = nullptr;

    if (!rec->has_identity) {
        if (rec->scan_cb_tag == N00B_MARSHAL_SCAN_CB_TAG_TYPE_LAYOUT) {
            const n00b_gc_struct_layout_t *layout =
                n00b_gc_type_map_lookup(owner_tinfo);
            if (layout == nullptr) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
                                  r"callback-scan TYPE_LAYOUT descriptor is missing for allocation tinfo");
                return false;
            }
            *out_scan_user = (void *)layout;
        }
        return true;
    }

    char *namespace_id = marshal_scratch_alloc(ctx->scratch_alloc,
                                               rec->namespace_len + 1);
    memcpy(namespace_id, cbscan_namespace_bytes(rec), rec->namespace_len);
    namespace_id[rec->namespace_len] = '\0';

    char *object_key = marshal_scratch_alloc(ctx->scratch_alloc,
                                             rec->key_len + 1);
    memcpy(object_key, cbscan_key_bytes(rec), rec->key_len);
    object_key[rec->key_len] = '\0';

    n00b_static_identity_t identity = {
        .version      = rec->identity_version,
        .kind         = (n00b_static_identity_kind_t)rec->identity_kind,
        .namespace_id = namespace_id,
        .object_key   = object_key,
    };
    n00b_static_identity_query_t query = {
        .checks = N00B_STATIC_IDENTITY_CHECK_LEN
                | N00B_STATIC_IDENTITY_CHECK_TINFO
                | N00B_STATIC_IDENTITY_CHECK_SCAN_KIND
                | N00B_STATIC_IDENTITY_CHECK_FLAGS
                | N00B_STATIC_IDENTITY_CHECK_BYTES,
        .len          = rec->object_len,
        .tinfo        = rec->tinfo,
        .scan_kind    = (n00b_gc_scan_kind_t)rec->scan_kind,
        .flags_mask   = rec->flags_mask,
        .flags_value  = rec->flags_value,
        .check_offset = rec->object_offset,
        .check_len    = rec->check_len,
        .check_bytes  = cbscan_check_bytes(rec),
    };

    n00b_alloc_range_t *range = nullptr;
    n00b_static_identity_status_t lookup = n00b_static_identity_lookup(&identity,
                                                                       &query,
                                                                       &range);
    if (lookup != N00B_STATIC_IDENTITY_OK) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          marshal_status_from_static_identity(lookup),
                          r"callback scan_user identity failed validation");
        return false;
    }
    if (range == nullptr) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_STATIC_IDENTITY_MISSING,
                          r"callback scan_user identity resolved to no object");
        return false;
    }

    *out_scan_user = (void *)((char *)range->start + rec->object_offset);
    return true;
}

// Reconstruct the per-word pointer bitmap for an unmarshaled CALLBACK
// segment by invoking the resolved built-in scan_cb over the (already
// allocated, not-yet-relinked) object. Stored on the segment so relink
// reads it instead of re-invoking scan_cb (D-040 OQ-3). The bitmap and
// the map storage are private scratch allocations.
static bool
unmarshal_store_callback_bitmap(n00b_unmarshal_ctx_t     *ctx,
                                n00b_unmarshal_segment_t *seg,
                                n00b_gc_scan_cb_t         scan_cb,
                                void                     *scan_user)
{
    uint64_t num_words = marshal_scan_word_count(&seg->rec);
    uint64_t map_words = n00b_gc_map_word_count(num_words);
    if (map_words == 0) {
        map_words = 1;
    }

    uint64_t *bitmap = marshal_scratch_alloc(ctx->scratch_alloc,
                                             map_words * sizeof(uint64_t));
    memset(bitmap, 0, map_words * sizeof(uint64_t));

    n00b_gc_map_t map = {
        .user_ptr  = seg->user_ptr,
        .num_words = num_words,
        .bitmap    = bitmap,
    };
    scan_cb(&map, scan_user);

    seg->is_callback  = true;
    seg->bitmap       = bitmap;
    seg->bitmap_words = map_words;
    return true;
}

typedef struct {
    uint64_t *slots;
    size_t    len;
} n00b_marshal_patch_slots_t;

static bool
stream_uses_payload_front(n00b_marshal_stream_header_t *hdr);

static bool
unmarshal_patch_slot_record(n00b_unmarshal_ctx_t *ctx,
                            bool                  payload_front,
                            size_t               *ix,
                            uint64_t             *slots,
                            size_t               *slot_ix,
                            bool                 *done)
{
    if (ctx->in.len - *ix < sizeof(uint32_t)) {
        return false;
    }

    uint32_t op = *(uint32_t *)(ctx->in.data + *ix);

    switch (op) {
    case N00B_MARSHAL_OP_ALLOC: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_alloc_record_t)) {
            return false;
        }
        n00b_marshal_alloc_record_t *rec = (void *)(ctx->in.data + *ix);
        *ix += sizeof(*rec);
        if (!payload_front) {
            if (ctx->in.len - *ix < rec->payload_len) {
                return false;
            }
            *ix += (size_t)rec->payload_len;
        }
        return true;
    }
    case N00B_MARSHAL_OP_CPATCH: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_cpatch_record_t)) {
            return false;
        }
        n00b_marshal_cpatch_record_t *rec = (void *)(ctx->in.data + *ix);
        if (slots != nullptr) {
            slots[*slot_ix] = rec->vaddr;
        }
        *slot_ix += 1;
        *ix += sizeof(*rec);
        return true;
    }
    case N00B_MARSHAL_OP_SPATCH: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_spatch_record_t)) {
            return false;
        }
        n00b_marshal_spatch_record_t *rec = (void *)(ctx->in.data + *ix);
        if (slots != nullptr) {
            slots[*slot_ix] = rec->vaddr;
        }
        *slot_ix += 1;
        *ix += sizeof(*rec);
        return true;
    }
    case N00B_MARSHAL_OP_PSPATCH: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_pspatch_record_t)) {
            return false;
        }
        n00b_marshal_pspatch_record_t *rec = (void *)(ctx->in.data + *ix);
        if (ctx->in.len - *ix < rec->record_len) {
            return false;
        }
        if (slots != nullptr) {
            slots[*slot_ix] = rec->vaddr;
        }
        *slot_ix += 1;
        *ix += rec->record_len;
        return true;
    }
    case N00B_MARSHAL_OP_FNPATCH: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_fnpatch_record_t)) {
            return false;
        }
        n00b_marshal_fnpatch_record_t *rec = (void *)(ctx->in.data + *ix);
        if (ctx->in.len - *ix < rec->record_len) {
            return false;
        }
        if (slots != nullptr) {
            slots[*slot_ix] = rec->vaddr;
        }
        *slot_ix += 1;
        *ix += rec->record_len;
        return true;
    }
    case N00B_MARSHAL_OP_CBSCAN: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_cbscan_record_t)) {
            return false;
        }
        n00b_marshal_cbscan_record_t *rec = (void *)(ctx->in.data + *ix);
        if (ctx->in.len - *ix < rec->record_len) {
            return false;
        }
        *ix += rec->record_len;
        return true;
    }
    case N00B_MARSHAL_OP_STOP: {
        if (ctx->in.len - *ix < sizeof(n00b_marshal_stop_record_t)) {
            return false;
        }
        n00b_marshal_stop_record_t *rec = (void *)(ctx->in.data + *ix);
        if (rec->end_of_stream != 1 || *ix + sizeof(*rec) != ctx->in.len) {
            return false;
        }
        *done = true;
        *ix += sizeof(*rec);
        return true;
    }
    default:
        return false;
    }
}

static bool
unmarshal_collect_patch_slots(n00b_unmarshal_ctx_t        *ctx,
                              n00b_marshal_stream_header_t *hdr,
                              n00b_marshal_patch_slots_t  *out)
{
    bool   payload_front = stream_uses_payload_front(hdr);
    size_t start         = sizeof(*hdr);
    if (payload_front) {
        start += hdr->flags;
    }

    size_t count = 0;
    size_t ix    = start;
    bool   done  = false;
    while (!done && ix < ctx->in.len) {
        if (!unmarshal_patch_slot_record(ctx,
                                         payload_front,
                                         &ix,
                                         nullptr,
                                         &count,
                                         &done)) {
            return false;
        }
    }
    if (!done) {
        return false;
    }

    *out = (n00b_marshal_patch_slots_t){};
    if (count == 0) {
        return true;
    }

    out->slots = marshal_scratch_alloc(ctx->scratch_alloc,
                                       count * sizeof(*out->slots));
    out->len   = count;

    ix          = start;
    done        = false;
    size_t used = 0;
    while (!done && ix < ctx->in.len) {
        if (!unmarshal_patch_slot_record(ctx,
                                         payload_front,
                                         &ix,
                                         out->slots,
                                         &used,
                                         &done)) {
            return false;
        }
    }

    return done && used == count;
}

static bool
unmarshal_slot_is_patched(n00b_marshal_patch_slots_t *slots, uint64_t vaddr)
{
    for (size_t i = 0; i < slots->len; i++) {
        if (slots->slots[i] == vaddr) {
            return true;
        }
    }
    return false;
}

static void
patch_alloc_metadata(void              *user_ptr,
                     n00b_marshal_alloc_record_t *rec,
                     n00b_gc_scan_cb_t  scan_cb,
                     void              *scan_user)
{
    // For CALLBACK records, scan_cb / scan_user are restored from the
    // CBSCAN ext (resolved tag + identity); for all other records they
    // are null, matching the pre-v3 behavior.
    n00b_alloc_info_t info = n00b_find_alloc_info(user_ptr);
    if (info.kind == n00b_alloc_oob) {
        n00b_oob_hdr_t *oob = info.hdr.oob;
        bool            ptr_words_known =
            (rec->flags & N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN) != 0;
        oob->tinfo          = rec->tinfo;
        oob->ptr_words      = rec->ptr_words;
        oob->ptr_words_known = ptr_words_known;
        oob->is_array       = rec->is_array != 0;
        oob->no_scan        = rec->no_scan != 0;
        oob->scan_kind      = rec->scan_kind;
        oob->scan_cb        = scan_cb;
        oob->scan_user      = scan_user;
        if (oob->hcur) {
            oob->hcur->tinfo           = rec->tinfo;
            oob->hcur->ptr_words       = rec->ptr_words;
            oob->hcur->ptr_words_known = ptr_words_known;
            oob->hcur->is_array        = rec->is_array != 0;
            oob->hcur->no_scan         = rec->no_scan != 0;
            oob->hcur->scan_kind       = rec->scan_kind;
            oob->hcur->scan_cb         = scan_cb;
            oob->hcur->scan_user       = scan_user;
        }
        return;
    }
    if (info.kind == n00b_alloc_inline) {
        n00b_inline_hdr_t *hdr = info.hdr.in_line;
        hdr->tinfo           = rec->tinfo;
        hdr->ptr_words       = rec->ptr_words;
        hdr->ptr_words_known =
            (rec->flags & N00B_MARSHAL_ALLOC_F_PTR_WORDS_KNOWN) != 0;
        hdr->is_array        = rec->is_array != 0;
        hdr->no_scan         = rec->no_scan != 0;
        hdr->scan_kind       = rec->scan_kind;
        hdr->scan_cb         = scan_cb;
        hdr->scan_user       = scan_user;
    }
}

static bool
stream_uses_payload_front(n00b_marshal_stream_header_t *hdr)
{
    return hdr->version >= N00B_MARSHAL_PAYLOAD_FRONT_VERSION;
}

static bool
unmarshal_allocate_records(n00b_unmarshal_ctx_t *ctx)
{
    n00b_marshal_stream_header_t *hdr = (void *)ctx->in.data;
    bool payload_front = stream_uses_payload_front(hdr);
    size_t ix = sizeof(*hdr);
    if (payload_front) {
        ix += hdr->flags;
    }

    while (ix < ctx->in.len) {
        uint32_t op = *(uint32_t *)(ctx->in.data + ix);
        if (op == N00B_MARSHAL_OP_STOP) {
            return true;
        }
        if (op == N00B_MARSHAL_OP_CPATCH) {
            ix += sizeof(n00b_marshal_cpatch_record_t);
            continue;
        }
        if (op == N00B_MARSHAL_OP_SPATCH) {
            ix += sizeof(n00b_marshal_spatch_record_t);
            continue;
        }
        if (op == N00B_MARSHAL_OP_PSPATCH) {
            n00b_marshal_pspatch_record_t *rec = (void *)(ctx->in.data + ix);
            ix += rec->record_len;
            continue;
        }
        if (op == N00B_MARSHAL_OP_FNPATCH) {
            // Patch-only record: no object to allocate; applied later.
            n00b_marshal_fnpatch_record_t *rec = (void *)(ctx->in.data + ix);
            ix += rec->record_len;
            continue;
        }
        if (op == N00B_MARSHAL_OP_CBSCAN) {
            // Consumed alongside its preceding CALLBACK ALLOC record below.
            n00b_marshal_cbscan_record_t *rec = (void *)(ctx->in.data + ix);
            ix += rec->record_len;
            continue;
        }

        n00b_marshal_alloc_record_t *rec = (void *)(ctx->in.data + ix);
        ix += sizeof(*rec);
        char *payload = payload_front
                      ? ctx->in.data + sizeof(*hdr)
                            + (size_t)(uint32_t)(rec->vaddr & UINT32_MAX)
                      : ctx->in.data + ix;

        // For a CALLBACK record, resolve scan_cb / scan_user from the
        // CBSCAN ext. Legacy v3 places it after the payload; v4+ places
        // it immediately after the ALLOC metadata in the trailing section.
        bool                          is_callback = false;
        n00b_gc_scan_cb_t             scan_cb     = nullptr;
        void                         *scan_user   = nullptr;
        n00b_marshal_cbscan_record_t *cbscan      = nullptr;
        if (rec->scan_kind == N00B_GC_SCAN_KIND_CALLBACK) {
            is_callback = true;
            cbscan      = (void *)(ctx->in.data + ix
                                   + (payload_front ? 0 : (size_t)rec->payload_len));
            if (!cbscan_resolve(ctx, cbscan, rec->tinfo, &scan_cb, &scan_user)) {
                return false;
            }
            // W-4: the CALLBACK => OOB path asserts inside the alloc
            // primitive (alloc.c:118) when the allocator has no metadata
            // pool. Pre-check here and surface a clean marshal error.
            n00b_allocator_t *allocator = (n00b_allocator_t *)ctx->target_arena;
            if (allocator->metadata_pool == nullptr) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION,
                                  r"callback-scanned object requires a target arena with out-of-band metadata");
                return false;
            }
        }

        // W-5: extend the EXISTING unmarshal opts feeding the EXISTING
        // _n00b_alloc_raw call; no new raw-alloc site is introduced.
        n00b_alloc_opts_t opts = {
            .allocator = (n00b_allocator_t *)ctx->target_arena,
            .no_scan   = rec->no_scan != 0,
            .scan_kind = rec->scan_kind,
            .scan_cb   = scan_cb,
            .scan_user = scan_user,
        };
        void *obj = _n00b_alloc_raw(1,
                                    rec->user_len ? rec->user_len : 1,
                                    0,
                                    "*unmarshal*",
                                    &opts);
        memcpy(obj, payload, (size_t)rec->user_len);
        patch_alloc_metadata(obj, rec, scan_cb, scan_user);

        n00b_unmarshal_segment_t *seg = marshal_scratch_alloc(ctx->scratch_alloc,
                                                              sizeof(*seg));
        *seg = (n00b_unmarshal_segment_t){
            .vaddr    = rec->vaddr,
            .user_len = rec->user_len,
            .user_ptr = obj,
            .rec      = *rec,
        };
        if (is_callback) {
            unmarshal_store_callback_bitmap(ctx, seg, scan_cb, scan_user);
        }
        segments_push(ctx, seg);

        if (!payload_front) {
            ix += (size_t)rec->payload_len;
        }
    }

    return false;
}

static bool
unmarshal_relink_records(n00b_unmarshal_ctx_t *ctx)
{
    n00b_marshal_stream_header_t *hdr = (void *)ctx->in.data;
    n00b_marshal_patch_slots_t patch_slots;
    if (!unmarshal_collect_patch_slots(ctx, hdr, &patch_slots)) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_BAD_STREAM,
                          r"invalid marshal patch-slot index");
        return false;
    }

    bool payload_front = stream_uses_payload_front(hdr);
    size_t ix = sizeof(*hdr);
    if (payload_front) {
        ix += hdr->flags;
    }

    while (ix < ctx->in.len) {
        uint32_t op = *(uint32_t *)(ctx->in.data + ix);
        if (op == N00B_MARSHAL_OP_STOP) {
            return true;
        }
        if (op == N00B_MARSHAL_OP_CPATCH) {
            n00b_marshal_cpatch_record_t *patch = (void *)(ctx->in.data + ix);
            uint64_t *slot = word_slot_for_vaddr(ctx, patch->vaddr);
            if (!slot) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"collision patch points outside a marshaled word slot");
                return false;
            }
            *slot = patch->value;
            ix += sizeof(*patch);
            continue;
        }
        if (op == N00B_MARSHAL_OP_SPATCH) {
            n00b_marshal_spatch_record_t *patch = (void *)(ctx->in.data + ix);
            uint64_t *slot = word_slot_for_vaddr(ctx, patch->vaddr);
            if (!slot) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"static patch points outside a marshaled word slot");
                return false;
            }

            auto mmap_opt = n00b_mmap_by_address((void *)(uintptr_t)patch->static_addr);
            if (!n00b_option_is_set(mmap_opt)
                || n00b_option_get(mmap_opt)->kind != n00b_mmap_static) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"static patch target is not mapped static memory");
                return false;
            }

            n00b_marshal_static_ref_t ref;
            if (!static_ref_view((void *)(uintptr_t)patch->static_addr, &ref)
                || ref.start != patch->static_start
                || ref.len != patch->static_len
                || (patch->object_id && ref.object_id != patch->object_id)
                || patch->check_len > ref.len - (patch->static_addr - ref.start)
                || memcmp((void *)(uintptr_t)patch->static_addr,
                          patch->check,
                          patch->check_len) != 0) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"static patch target failed validation");
                return false;
            }

            *slot = patch->static_addr;
            ix += sizeof(*patch);
            continue;
        }
        if (op == N00B_MARSHAL_OP_PSPATCH) {
            n00b_marshal_pspatch_record_t *patch = (void *)(ctx->in.data + ix);
            uint64_t *slot = word_slot_for_vaddr(ctx, patch->vaddr);
            if (!slot) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"portable static patch points outside a marshaled word slot");
                return false;
            }

            char *namespace_id = marshal_scratch_alloc(ctx->scratch_alloc,
                                                       patch->namespace_len + 1);
            memcpy(namespace_id, pspatch_namespace_bytes(patch), patch->namespace_len);
            namespace_id[patch->namespace_len] = '\0';

            char *object_key = marshal_scratch_alloc(ctx->scratch_alloc,
                                                     patch->key_len + 1);
            memcpy(object_key, pspatch_key_bytes(patch), patch->key_len);
            object_key[patch->key_len] = '\0';

            n00b_static_identity_t identity = {
                .version      = patch->identity_version,
                .kind         = (n00b_static_identity_kind_t)patch->identity_kind,
                .namespace_id = namespace_id,
                .object_key   = object_key,
            };
            n00b_static_identity_query_t query = {
                .checks = N00B_STATIC_IDENTITY_CHECK_LEN
                        | N00B_STATIC_IDENTITY_CHECK_TINFO
                        | N00B_STATIC_IDENTITY_CHECK_SCAN_KIND
                        | N00B_STATIC_IDENTITY_CHECK_FLAGS
                        | N00B_STATIC_IDENTITY_CHECK_BYTES,
                .len          = patch->object_len,
                .tinfo        = patch->tinfo,
                .scan_kind    = (n00b_gc_scan_kind_t)patch->scan_kind,
                .flags_mask   = patch->flags_mask,
                .flags_value  = patch->flags_value,
                .check_offset = patch->object_offset,
                .check_len    = patch->check_len,
                .check_bytes  = pspatch_check_bytes(patch),
            };

            n00b_alloc_range_t *range = nullptr;
            n00b_static_identity_status_t lookup = n00b_static_identity_lookup(&identity,
                                                                               &query,
                                                                               &range);
            if (lookup != N00B_STATIC_IDENTITY_OK) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  marshal_status_from_static_identity(lookup),
                                  r"portable static patch target failed validation");
                return false;
            }
            if (range == nullptr) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_STATIC_IDENTITY_MISSING,
                                  r"portable static patch target resolved to no object");
                return false;
            }

            *slot = (uint64_t)(uintptr_t)range->start + patch->object_offset;
            ix += patch->record_len;
            continue;
        }
        if (op == N00B_MARSHAL_OP_FNPATCH) {
            n00b_marshal_fnpatch_record_t *patch = (void *)(ctx->in.data + ix);
            uint64_t *slot = word_slot_for_vaddr(ctx, patch->vaddr);
            if (!slot) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"function patch points outside a marshaled word slot");
                return false;
            }

            char *name = marshal_scratch_alloc(ctx->scratch_alloc,
                                               patch->name_len + 1);
            memcpy(name, fnpatch_name_bytes(patch), patch->name_len);
            name[patch->name_len] = '\0';

#ifndef _WIN32
            // Rebind by exported symbol in THIS process (FFI's mechanism).
            void *addr = dlsym(RTLD_DEFAULT, name);
#else
            void *addr = nullptr;
#endif
            if (addr == nullptr) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
                                  r"marshaled function symbol could not be resolved");
                return false;
            }

            *slot = (uint64_t)(uintptr_t)addr;
            ix += patch->record_len;
            continue;
        }
        if (op == N00B_MARSHAL_OP_CBSCAN) {
            n00b_marshal_cbscan_record_t *patch = (void *)(ctx->in.data + ix);
            ix += patch->record_len;
            continue;
        }

        n00b_marshal_alloc_record_t *rec = (void *)(ctx->in.data + ix);
        n00b_unmarshal_segment_t *seg = segment_for_vaddr(ctx, rec->vaddr);
        if (!seg) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_BAD_STREAM,
                              r"allocation record missing virtual segment");
            return false;
        }

        // CALLBACK segments relink off the stored bitmap (D-040 OQ-3);
        // scan_word_for_policy returns false for CALLBACK, so for those
        // segments the bitmap is the sole per-word pointer oracle.
        uint64_t nwords;
        if (seg->is_callback) {
            nwords = seg->user_len / sizeof(uint64_t);
        }
        else {
            nwords = marshal_scan_word_count(rec);
        }
        uint64_t *words = (uint64_t *)seg->user_ptr;
        for (uint64_t i = 0; i < nwords; i++) {
            bool is_ptr;
            if (seg->is_callback) {
                is_ptr = (i < seg->bitmap_words * 64)
                      && n00b_gc_map_is_set(&(n00b_gc_map_t){.bitmap = seg->bitmap}, i);
            }
            else {
                is_ptr = scan_word_for_policy(rec, i);
            }
            if (!is_ptr) {
                continue;
            }
            uint64_t slot_vaddr = seg->vaddr + i * sizeof(uint64_t);
            if (unmarshal_slot_is_patched(&patch_slots, slot_vaddr)) {
                continue;
            }
            uint64_t word = words[i];
            if ((word >> 32) != hdr->base_address) {
                continue;
            }
            void *target = addr_for_vaddr(ctx, word);
            if (!target) {
                marshal_set_error(&ctx->status,
                                  &ctx->error,
                                  N00B_MARSHAL_ERR_BAD_STREAM,
                                  r"virtual pointer target missing");
                return false;
            }
            words[i] = (uint64_t)(uintptr_t)target;
        }

        ix += sizeof(*rec);
        if (!payload_front) {
            ix += (size_t)rec->payload_len;
        }
    }

    return false;
}

static bool
unmarshal_process(n00b_unmarshal_ctx_t *ctx, n00b_list_t(void *) *roots)
{
    n00b_marshal_stream_header_t *hdr = (void *)ctx->in.data;

    n00b_stop_the_world();
    bool saved_collection = ctx->target_arena->collection_enabled;
    ctx->target_arena->collection_enabled = false;

    bool ok = unmarshal_allocate_records(ctx) && unmarshal_relink_records(ctx);

    if (ok) {
        uint64_t root_vaddr = ((uint64_t)hdr->base_address << 32) | hdr->root_offset;
        void *root = addr_for_vaddr(ctx, root_vaddr);
        if (!root) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_BAD_STREAM,
                              r"root virtual address missing");
            ok = false;
        }
        else {
            n00b_list_push(*roots, root);
        }
    }

    ctx->target_arena->collection_enabled = saved_collection;
    n00b_restart_the_world();
    return ok;
}

n00b_unmarshal_ctx_t *
n00b_unmarshal_ctx_new() _kargs
{
    n00b_arena_t *target_arena = nullptr;
}
{
    n00b_unmarshal_ctx_t *ctx = n00b_alloc(n00b_unmarshal_ctx_t);
    *ctx                      = (typeof(*ctx)){};
    marshal_init_scratch(&ctx->scratch, &ctx->scratch_alloc, "unmarshal_scratch");
    ctx->target_arena = target_arena ? target_arena : n00b_get_runtime()->default_arena;
    ctx->status       = N00B_MARSHAL_OK;
    return ctx;
}

void
n00b_unmarshal_ctx_destroy(n00b_unmarshal_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    n00b_allocator_destroy((n00b_allocator_t *)&ctx->scratch);
    n00b_free(ctx);
}

n00b_marshal_status_t
n00b_unmarshal_ctx_status(n00b_unmarshal_ctx_t *ctx)
{
    return ctx ? ctx->status : N00B_MARSHAL_ERR_NULL_ARG;
}

n00b_string_t *
n00b_unmarshal_ctx_error(n00b_unmarshal_ctx_t *ctx)
{
    if (!ctx) {
        return r"null unmarshal context";
    }
    return ctx->error;
}

n00b_list_t(void *)
n00b_unmarshal_incremental(n00b_unmarshal_ctx_t *ctx, n00b_buffer_t *chunk)
{
    n00b_list_t(void *) roots = n00b_list_new(void *);
    if (!ctx || !chunk) {
        if (ctx) {
            marshal_set_error(&ctx->status,
                              &ctx->error,
                              N00B_MARSHAL_ERR_NULL_ARG,
                              r"null unmarshal argument");
        }
        return roots;
    }
    if (ctx->closed) {
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_CONTEXT_CLOSED,
                          r"unmarshal context already closed");
        return roots;
    }

    _n00b_buffer_rlock(chunk);
    if (chunk->byte_len > SIZE_MAX - ctx->in.len) {
        _n00b_buffer_unlock(chunk);
        marshal_set_error(&ctx->status,
                          &ctx->error,
                          N00B_MARSHAL_ERR_LIMIT,
                          r"marshal stream input exceeds host size limit");
        return roots;
    }
    bytes_append(&ctx->in, ctx->scratch_alloc, chunk->data, chunk->byte_len);
    _n00b_buffer_unlock(chunk);

    if (ctx->status == N00B_MARSHAL_ERR_INCOMPLETE_STREAM) {
        ctx->status = N00B_MARSHAL_OK;
        ctx->error  = nullptr;
    }

    if (!stream_complete(ctx)) {
        if (ctx->status == N00B_MARSHAL_OK) {
            ctx->status = N00B_MARSHAL_ERR_INCOMPLETE_STREAM;
        }
        return roots;
    }

    ctx->status = N00B_MARSHAL_OK;
    if (unmarshal_process(ctx, &roots)) {
        ctx->closed = true;
    }
    return roots;
}

n00b_list_t(void *)
n00b_unmarshal(n00b_buffer_t *buf) _kargs
{
    n00b_arena_t *target_arena = nullptr;
}
{
    n00b_unmarshal_ctx_t *ctx = n00b_unmarshal_ctx_new(.target_arena = target_arena);
    n00b_list_t(void *) roots = n00b_unmarshal_incremental(ctx, buf);
    n00b_unmarshal_ctx_destroy(ctx);
    return roots;
}

void *
n00b_unmarshal_one(n00b_buffer_t *buf) _kargs
{
    n00b_arena_t *target_arena = nullptr;
}
{
    n00b_list_t(void *) roots = n00b_unmarshal(buf, .target_arena = target_arena);
    if (n00b_list_len(roots) == 0) {
        return nullptr;
    }
    return n00b_list_get(roots, 0);
}
