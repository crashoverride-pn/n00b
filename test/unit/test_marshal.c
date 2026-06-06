#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_mdata.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/gc_map.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"
#include "util/assert.h"
#include "util/marshal.h"

#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}
#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

typedef struct marshal_node_t {
    uint64_t               tag;
    uint64_t               scalar;
    struct marshal_node_t *next;
    struct marshal_node_t *alias;
} marshal_node_t;

typedef struct {
    uint64_t  tag;
    uint64_t *static_ref;
} marshal_static_ref_t;

typedef struct {
    uint64_t  tag;
    uint64_t *ptr;
} marshal_callback_ref_t;

typedef struct {
    uint64_t          tag;
    n00b_gc_scan_cb_t fn;
} marshal_fn_ref_t;

typedef struct {
    struct marshal_node_t *real_ptr;
    uint64_t               scalar_tail;
} marshal_limited_scan_t;

#define TEST_MARSHAL_OP_ALLOC  UINT32_C(0xe11cbab0)
#define TEST_MARSHAL_OP_CPATCH UINT32_C(0xe31cbab0)
#define TEST_MARSHAL_OP_SPATCH UINT32_C(0xe41cbab0)
#define TEST_MARSHAL_OP_STOP   UINT32_C(0xe51cbab0)
#define TEST_MARSHAL_OP_PSPATCH UINT32_C(0xe61cbab0)
#define TEST_MARSHAL_OP_CBSCAN UINT32_C(0xe71cbab0)
#define TEST_MARSHAL_OP_FNPATCH UINT32_C(0xe81cbab0)

#define TEST_MARSHAL_PAYLOAD_FRONT_VERSION 4u

typedef struct {
    uint64_t marshal_magic;
    uint32_t version;
    uint32_t base_address;
    uint32_t root_offset;
    uint32_t flags;
} test_marshal_stream_header_t;

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
} test_marshal_alloc_record_t;

typedef struct {
    uint32_t op;
    uint32_t reserved;
    uint64_t vaddr;
    uint64_t value;
} test_marshal_cpatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t check_len;
    uint64_t vaddr;
    uint64_t static_addr;
    uint64_t static_start;
    uint64_t static_len;
    uint64_t object_id;
    uint8_t  check[16];
} test_marshal_spatch_record_t;

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
} test_marshal_pspatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t record_len;
} test_marshal_sized_record_t;

typedef struct {
    uint32_t op;
    uint32_t record_len;
    uint64_t vaddr;
    uint32_t name_len;
    uint32_t reserved;
} test_marshal_fnpatch_record_t;

typedef struct {
    uint32_t op;
    uint32_t end_of_stream;
} test_marshal_stop_record_t;

#define TEST_PORTABLE_STATIC_TINFO UINT64_C(0x7073746174696301)

static uint64_t portable_success_src[3] = {
    UINT64_C(0x1000000000000001),
    UINT64_C(0x1000000000000002),
    UINT64_C(0x1000000000000003),
};
static uint64_t portable_success_dst[3] = {
    UINT64_C(0x1000000000000001),
    UINT64_C(0x1000000000000002),
    UINT64_C(0x1000000000000003),
};
static const n00b_static_identity_t portable_success_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "success",
};

static uint64_t portable_missing_src[3] = {
    UINT64_C(0x2000000000000001),
    UINT64_C(0x2000000000000002),
    UINT64_C(0x2000000000000003),
};
static const n00b_static_identity_t portable_missing_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "missing",
};

static uint64_t portable_mutability_src[3] = {
    UINT64_C(0x3000000000000001),
    UINT64_C(0x3000000000000002),
    UINT64_C(0x3000000000000003),
};
static uint64_t portable_mutability_dst[3] = {
    UINT64_C(0x3000000000000001),
    UINT64_C(0x3000000000000002),
    UINT64_C(0x3000000000000003),
};
static const n00b_static_identity_t portable_mutability_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "mutability",
};

static uint64_t portable_duplicate_src[3] = {
    UINT64_C(0x4000000000000001),
    UINT64_C(0x4000000000000002),
    UINT64_C(0x4000000000000003),
};
static uint64_t portable_duplicate_dst_a[3] = {
    UINT64_C(0x4000000000000001),
    UINT64_C(0x4000000000000002),
    UINT64_C(0x4000000000000003),
};
static uint64_t portable_duplicate_dst_b[3] = {
    UINT64_C(0x4000000000000001),
    UINT64_C(0x4000000000000002),
    UINT64_C(0x4000000000000003),
};
static const n00b_static_identity_t portable_duplicate_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "duplicate",
};

static uint64_t portable_check_src[3] = {
    UINT64_C(0x5000000000000001),
    UINT64_C(0x5000000000000002),
    UINT64_C(0x5000000000000003),
};
static uint64_t portable_check_dst[3] = {
    UINT64_C(0x5000000000000001),
    UINT64_C(0x50000000000000ff),
    UINT64_C(0x5000000000000003),
};
static const n00b_static_identity_t portable_check_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "check-bytes",
};

static uint64_t portable_type_src[3] = {
    UINT64_C(0x5100000000000001),
    UINT64_C(0x5100000000000002),
    UINT64_C(0x5100000000000003),
};
static uint64_t portable_type_dst[3] = {
    UINT64_C(0x5100000000000001),
    UINT64_C(0x5100000000000002),
    UINT64_C(0x5100000000000003),
};
static const n00b_static_identity_t portable_type_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "type",
};

static uint64_t portable_scan_src[3] = {
    UINT64_C(0x5200000000000001),
    UINT64_C(0x5200000000000002),
    UINT64_C(0x5200000000000003),
};
static uint64_t portable_scan_dst[3] = {
    UINT64_C(0x5200000000000001),
    UINT64_C(0x5200000000000002),
    UINT64_C(0x5200000000000003),
};
static const n00b_static_identity_t portable_scan_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "scan",
};

static uint64_t portable_length_src[3] = {
    UINT64_C(0x5300000000000001),
    UINT64_C(0x5300000000000002),
    UINT64_C(0x5300000000000003),
};
static uint64_t portable_length_dst[2] = {
    UINT64_C(0x5300000000000001),
    UINT64_C(0x5300000000000002),
};
static const n00b_static_identity_t portable_length_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "length",
};

static uint64_t portable_malformed_words[3] = {
    UINT64_C(0x6000000000000001),
    UINT64_C(0x6000000000000002),
    UINT64_C(0x6000000000000003),
};
static const n00b_static_identity_t portable_malformed_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.portable",
    .object_key   = "malformed",
};

static uint64_t unsupported_static_words[2] = {
    UINT64_C(0x7000000000000001),
    UINT64_C(0x7000000000000002),
};

// Synthetic mixed pointer/scalar struct for the CALLBACK struct_layout
// round-trip test. Word layout (one element, stride 4):
//   word 0: packed-int scalar equal to 0x100000000 (aliases the static
//           address range) -- must NOT be treated as a pointer.
//   word 1: a real heap pointer -- relinked.
//   word 2: scalar tail.
//   word 3: scalar/padding.
typedef struct {
    uint64_t        packed_alias; // 0x100000000
    marshal_node_t *real_ptr;
    uint64_t        scalar_tail;
    uint64_t        pad;
} marshal_struct_layout_t;

// struct_layout descriptor: the single pointer word sits at offset 1.
// Both the offsets array and the descriptor are file-scope statics so
// they can be registered as static objects (the descriptor additionally
// gets a static identity, which marshal round-trips for scan_user).
static const uint64_t cbscan_layout_offsets[1] = {1};
static const n00b_gc_struct_layout_t cbscan_layout_desc = {
    .stride       = 4,
    .count        = 1,
    .offset_count = 1,
    .offsets      = cbscan_layout_offsets,
};
#define CBSCAN_LAYOUT_TINFO UINT64_C(0x6362736361746e01)
static const n00b_static_identity_t cbscan_layout_identity = {
    .version      = N00B_STATIC_IDENTITY_VERSION,
    .kind         = N00B_STATIC_IDENTITY_MANUAL,
    .namespace_id = "test.marshal.cbscan",
    .object_key   = "struct-layout-desc",
};

typedef struct {
    n00b_arena_t    *arena;
    _Atomic uint32_t run;
    _Atomic uint32_t done;
    _Atomic uint32_t collections;
    uint32_t         delay_iters;
} gc_request_t;

static uint64_t
stress_value(size_t i)
{
    return UINT64_C(0x0f0e0d0c00000000) | (uint64_t)i;
}

static void *
gc_request_worker(void *arg)
{
    gc_request_t *request = arg;

    while (!atomic_load(&request->run)) {
    }

    for (uint32_t i = 0; i < request->delay_iters; i++) {
        __asm__ __volatile__("" ::: "memory");
    }

    n00b_stop_the_world();
    n00b_collect(request->arena);
    n00b_restart_the_world();
    atomic_fetch_add(&request->collections, 1);
    atomic_store(&request->done, 1);

    return nullptr;
}

static n00b_thread_t *
start_gc_request(gc_request_t *request, n00b_arena_t *arena, uint32_t delay_iters)
{
    *request = (gc_request_t){.arena = arena, .delay_iters = delay_iters};

    auto result = n00b_thread_spawn(gc_request_worker, request);
    assert(n00b_result_is_ok(result));

    return n00b_result_get(result);
}

static n00b_buffer_t *
buffer_slice(n00b_buffer_t *buf, int64_t start, int64_t len)
{
    _n00b_buffer_rlock(buf);
    n00b_buffer_t *result = n00b_buffer_from_bytes(buf->data + start, len);
    _n00b_buffer_unlock(buf);

    return result;
}

static n00b_buffer_t *
buffer_copy_with_extra(n00b_buffer_t *buf, int64_t extra)
{
    _n00b_buffer_rlock(buf);
    int64_t len   = (int64_t)buf->byte_len;
    char   *bytes = n00b_alloc_array(char, (size_t)(len + extra));
    memcpy(bytes, buf->data, (size_t)len);
    memset(bytes + len, 0x5a, (size_t)extra);
    _n00b_buffer_unlock(buf);

    return n00b_buffer_from_bytes(bytes, len + extra);
}

static size_t
marshal_first_record_ix(char *bytes, size_t len)
{
    test_marshal_stream_header_t *hdr = (void *)bytes;
    size_t ix = sizeof(*hdr);
    if (hdr->version >= TEST_MARSHAL_PAYLOAD_FRONT_VERSION) {
        CHECK(hdr->flags <= len - ix);
        ix += hdr->flags;
    }
    return ix;
}

static size_t
marshal_alloc_wire_len(test_marshal_stream_header_t *hdr,
                       test_marshal_alloc_record_t  *rec)
{
    if (hdr->version >= TEST_MARSHAL_PAYLOAD_FRONT_VERSION) {
        return sizeof(*rec);
    }
    return sizeof(*rec) + (size_t)rec->payload_len;
}

static n00b_buffer_t *
buffer_copy_mutating_alloc(n00b_buffer_t *buf,
                           void (*mutate)(test_marshal_alloc_record_t *rec))
{
    _n00b_buffer_rlock(buf);
    int64_t len   = (int64_t)buf->byte_len;
    char   *bytes = n00b_alloc_array(char, (size_t)len);
    memcpy(bytes, buf->data, (size_t)len);
    _n00b_buffer_unlock(buf);

    size_t ix = marshal_first_record_ix(bytes, (size_t)len);
    test_marshal_alloc_record_t *rec = (void *)(bytes + ix);
    CHECK(rec->op == TEST_MARSHAL_OP_ALLOC);
    mutate(rec);

    return n00b_buffer_from_bytes(bytes, len);
}

static n00b_buffer_t *
buffer_copy_mutating_record(n00b_buffer_t *buf,
                            uint32_t       wanted_op,
                            void (*mutate)(void *rec))
{
    _n00b_buffer_rlock(buf);
    int64_t len   = (int64_t)buf->byte_len;
    char   *bytes = n00b_alloc_array(char, (size_t)len);
    memcpy(bytes, buf->data, (size_t)len);
    _n00b_buffer_unlock(buf);

    test_marshal_stream_header_t *hdr = (void *)bytes;
    size_t ix = marshal_first_record_ix(bytes, (size_t)len);
    while (ix + sizeof(uint32_t) <= (size_t)len) {
        uint32_t op = *(uint32_t *)(bytes + ix);
        if (op == wanted_op) {
            mutate(bytes + ix);
            return n00b_buffer_from_bytes(bytes, len);
        }

        if (op == TEST_MARSHAL_OP_ALLOC) {
            test_marshal_alloc_record_t *rec = (void *)(bytes + ix);
            ix += marshal_alloc_wire_len(hdr, rec);
            continue;
        }
        if (op == TEST_MARSHAL_OP_CPATCH) {
            ix += sizeof(test_marshal_cpatch_record_t);
            continue;
        }
        if (op == TEST_MARSHAL_OP_SPATCH) {
            ix += sizeof(test_marshal_spatch_record_t);
            continue;
        }
        if (op == TEST_MARSHAL_OP_PSPATCH) {
            test_marshal_pspatch_record_t *rec = (void *)(bytes + ix);
            ix += rec->record_len;
            continue;
        }
        if (op == TEST_MARSHAL_OP_CBSCAN || op == TEST_MARSHAL_OP_FNPATCH) {
            test_marshal_sized_record_t *rec = (void *)(bytes + ix);
            ix += rec->record_len;
            continue;
        }
        break;
    }

    n00b_require(false, "requested marshal record not found");
    return nullptr;
}

static n00b_buffer_t *
buffer_copy_as_legacy_inline(n00b_buffer_t *buf, uint32_t version)
{
    _n00b_buffer_rlock(buf);
    size_t len = buf->byte_len;
    char  *out = n00b_alloc_array(char, len);

    test_marshal_stream_header_t *src_hdr = (void *)buf->data;
    CHECK(src_hdr->version >= TEST_MARSHAL_PAYLOAD_FRONT_VERSION);

    test_marshal_stream_header_t hdr = *src_hdr;
    hdr.version = version;
    hdr.flags   = 0;
    memcpy(out, &hdr, sizeof(hdr));

    size_t payload_ix  = sizeof(hdr);
    size_t metadata_ix = payload_ix + src_hdr->flags;
    size_t ix          = metadata_ix;
    size_t out_ix      = sizeof(hdr);

    while (ix + sizeof(uint32_t) <= len) {
        uint32_t op = *(uint32_t *)(buf->data + ix);

        if (op == TEST_MARSHAL_OP_ALLOC) {
            test_marshal_alloc_record_t *rec = (void *)(buf->data + ix);
            uint32_t offset = (uint32_t)(rec->vaddr & UINT32_MAX);
            CHECK((uint64_t)offset + rec->payload_len <= src_hdr->flags);

            memcpy(out + out_ix, rec, sizeof(*rec));
            out_ix += sizeof(*rec);
            memcpy(out + out_ix,
                   buf->data + payload_ix + offset,
                   (size_t)rec->payload_len);
            out_ix += (size_t)rec->payload_len;
            ix += sizeof(*rec);
            continue;
        }

        if (op == TEST_MARSHAL_OP_CPATCH) {
            memcpy(out + out_ix,
                   buf->data + ix,
                   sizeof(test_marshal_cpatch_record_t));
            out_ix += sizeof(test_marshal_cpatch_record_t);
            ix += sizeof(test_marshal_cpatch_record_t);
            continue;
        }

        if (op == TEST_MARSHAL_OP_SPATCH) {
            memcpy(out + out_ix,
                   buf->data + ix,
                   sizeof(test_marshal_spatch_record_t));
            out_ix += sizeof(test_marshal_spatch_record_t);
            ix += sizeof(test_marshal_spatch_record_t);
            continue;
        }

        if (op == TEST_MARSHAL_OP_STOP) {
            memcpy(out + out_ix,
                   buf->data + ix,
                   sizeof(test_marshal_stop_record_t));
            out_ix += sizeof(test_marshal_stop_record_t);
            ix += sizeof(test_marshal_stop_record_t);
            CHECK(ix == len);
            break;
        }

        if (op == TEST_MARSHAL_OP_CBSCAN || op == TEST_MARSHAL_OP_FNPATCH
            || op == TEST_MARSHAL_OP_PSPATCH) {
            test_marshal_sized_record_t *rec = (void *)(buf->data + ix);
            memcpy(out + out_ix, buf->data + ix, rec->record_len);
            out_ix += rec->record_len;
            ix += rec->record_len;
            continue;
        }

        n00b_require(false, "legacy conversion saw an unsupported record");
    }

    _n00b_buffer_unlock(buf);
    return n00b_buffer_from_bytes(out, (int64_t)out_ix);
}

static void
mark_all_cb(n00b_gc_map_t *m, void *user)
{
    (void)user;
    n00b_gc_map_mark_all(m);
}

static void
mutate_unknown_op(test_marshal_alloc_record_t *rec)
{
    rec->op = UINT32_C(0xdeadbeef);
}

static void
mutate_short_payload(test_marshal_alloc_record_t *rec)
{
    assert(rec->payload_len >= sizeof(uint64_t));
    rec->payload_len -= sizeof(uint64_t);
}

static void
mutate_callback_scan(test_marshal_alloc_record_t *rec)
{
    rec->scan_kind = N00B_GC_SCAN_KIND_CALLBACK;
}

static void
mutate_bad_scan_kind(test_marshal_alloc_record_t *rec)
{
    rec->scan_kind = N00B_GC_SCAN_KIND_CALLBACK + 1;
}

static void
mutate_bad_alloc_flags(test_marshal_alloc_record_t *rec)
{
    rec->flags |= UINT32_C(0x80000000);
}

static void
assert_unmarshal_status(n00b_buffer_t *buf, n00b_marshal_status_t status)
{
    n00b_unmarshal_ctx_t *ctx   = n00b_unmarshal_ctx_new();
    n00b_list_t(void *)   roots = n00b_unmarshal_incremental(ctx, buf);
    assert(n00b_list_len(roots) == 0);
    assert(n00b_unmarshal_ctx_status(ctx) == status);
    n00b_unmarshal_ctx_destroy(ctx);
}

static void
set_ptr_words(void *obj, uint32_t ptr_words)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(obj);

    if (info.kind == n00b_alloc_oob) {
        info.hdr.oob->ptr_words = ptr_words;
        if (info.hdr.oob->hcur) {
            info.hdr.oob->hcur->ptr_words = ptr_words;
        }
        return;
    }

    assert(info.kind == n00b_alloc_inline);
    info.hdr.in_line->ptr_words = ptr_words;
}

static n00b_alloc_range_t *
register_portable_words_ex(uint64_t *words,
                           size_t count,
                           const n00b_static_identity_t *identity,
                           uint32_t flags,
                           uint64_t object_id,
                           n00b_alloc_type_info_t tinfo,
                           n00b_gc_scan_kind_t scan_kind)
{
    (void)n00b_mmap_register(words,
                             words + count,
                             n00b_mmap_static,
                             .file              = identity->object_key,
                             .order_id          = object_id,
                             .definitely_unique = false);
    return n00b_static_object_register(words,
                                       count * sizeof(*words),
                                       tinfo,
                                       .scan_kind = scan_kind,
                                       .object_id = object_id,
                                       .identity  = identity,
                                       .flags     = flags);
}

static n00b_alloc_range_t *
register_portable_words(uint64_t *words,
                        size_t count,
                        const n00b_static_identity_t *identity,
                        uint32_t flags,
                        uint64_t object_id)
{
    return register_portable_words_ex(words,
                                      count,
                                      identity,
                                      flags,
                                      object_id,
                                      TEST_PORTABLE_STATIC_TINFO,
                                      N00B_GC_SCAN_KIND_NONE);
}

static void
unregister_portable_words(uint64_t *words, size_t count)
{
    n00b_mmap_delete_ranges(n00b_global_mem_map(n00b_get_runtime()),
                            (uint64_t)(uintptr_t)words,
                            (uint64_t)(uintptr_t)(words + count));
}

static void
test_cycle_shared_and_collision(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    marshal_node_t *a = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    marshal_node_t *b = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));

    a->tag    = 0xa0a0;
    a->scalar = (UINT64_C(0x12345678) << 32) | UINT64_C(0x00000042);
    a->next   = b;
    a->alias  = b;

    b->tag    = 0xb0b0;
    b->scalar = 99;
    b->next   = a;
    b->alias  = b;

    n00b_buffer_t *buf = n00b_marshal(a, .base_address = 0x12345678u);
    assert(buf != nullptr);
    assert(n00b_buffer_len(buf) > 0);

    marshal_node_t *root = n00b_unmarshal_one(buf, .target_arena = arena);
    assert(root != nullptr);
    assert(root != a);
    assert(root->tag == 0xa0a0);
    assert(root->scalar == ((UINT64_C(0x12345678) << 32) | UINT64_C(0x00000042)));
    assert(root->next != nullptr);
    assert(root->next == root->alias);
    assert(root->next->tag == 0xb0b0);
    assert(root->next->next == root);
    assert(root->next->alias == root->next);

    n00b_gc_register_root(root);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    assert(root->tag == 0xa0a0);
    assert(root->next->next == root);
    assert(root->next == root->alias);
    n00b_gc_unregister_root(root);

    printf("  [PASS] cycle_shared_and_collision\n");
}

static void
test_static_pointer_patch(void)
{
    static uint64_t static_words[4] = {
        UINT64_C(0x0102030405060708),
        UINT64_C(0x1112131415161718),
        UINT64_C(0x2122232425262728),
        UINT64_C(0x3132333435363738),
    };

    (void)n00b_mmap_register(static_words,
                             static_words + 4,
                             n00b_mmap_static,
                             .file              = "test_marshal_static_words",
                             .order_id          = UINT64_C(0x6006),
                             .definitely_unique = false);
    (void)n00b_static_object_register(static_words,
                                      sizeof(static_words),
                                      0,
                                      .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                      .object_id = UINT64_C(0x60060001));

    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    marshal_static_ref_t *src = n00b_alloc_with_opts(marshal_static_ref_t,
                                                     ARENA_OPTS(arena));
    src->tag        = 0xcafe;
    src->static_ref = &static_words[1];

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x3456789au);
    assert(buf != nullptr);

    marshal_static_ref_t *copy = n00b_unmarshal_one(buf, .target_arena = arena);
    assert(copy != nullptr);
    assert(copy != src);
    assert(copy->tag == 0xcafe);
    assert(copy->static_ref == &static_words[1]);
    assert(*copy->static_ref == static_words[1]);

    n00b_buffer_t *v1_buf = buffer_copy_as_legacy_inline(buf, 1);
    marshal_static_ref_t *v1_copy = n00b_unmarshal_one(v1_buf,
                                                       .target_arena = arena);
    assert(v1_copy != nullptr);
    assert(v1_copy->static_ref == &static_words[1]);

    n00b_gc_register_root(copy);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    assert(copy->static_ref == &static_words[1]);
    n00b_gc_unregister_root(copy);

    printf("  [PASS] static_pointer_patch\n");
}

static void
assert_fnpatch_record(n00b_buffer_t *buf, uint32_t base_address)
{
    _n00b_buffer_rlock(buf);
    char  *bytes = buf->data;
    size_t len   = buf->byte_len;

    CHECK(len >= sizeof(test_marshal_stream_header_t));
    test_marshal_stream_header_t *hdr = (void *)bytes;
    CHECK(hdr->version >= TEST_MARSHAL_PAYLOAD_FRONT_VERSION);
    CHECK(hdr->base_address == base_address);
    CHECK(hdr->root_offset == 0);
    CHECK(hdr->flags <= len - sizeof(*hdr));

    size_t ix  = marshal_first_record_ix(bytes, len);
    bool   saw = false;
    while (ix + sizeof(uint32_t) <= len) {
        uint32_t op = *(uint32_t *)(bytes + ix);
        if (op == TEST_MARSHAL_OP_ALLOC) {
            test_marshal_alloc_record_t *rec = (void *)(bytes + ix);
            ix += marshal_alloc_wire_len(hdr, rec);
            continue;
        }
        if (op == TEST_MARSHAL_OP_CPATCH) {
            ix += sizeof(test_marshal_cpatch_record_t);
            continue;
        }
        if (op == TEST_MARSHAL_OP_SPATCH) {
            ix += sizeof(test_marshal_spatch_record_t);
            continue;
        }
        if (op == TEST_MARSHAL_OP_PSPATCH) {
            test_marshal_pspatch_record_t *rec = (void *)(bytes + ix);
            CHECK(rec->record_len <= len - ix);
            ix += rec->record_len;
            continue;
        }
        if (op == TEST_MARSHAL_OP_CBSCAN) {
            test_marshal_sized_record_t *rec = (void *)(bytes + ix);
            CHECK(rec->record_len <= len - ix);
            ix += rec->record_len;
            continue;
        }
        if (op == TEST_MARSHAL_OP_FNPATCH) {
            test_marshal_fnpatch_record_t *rec = (void *)(bytes + ix);
            CHECK(rec->record_len >= sizeof(*rec));
            CHECK(rec->record_len <= len - ix);
            CHECK((rec->vaddr >> 32) == base_address);
            CHECK((uint32_t)(rec->vaddr & UINT32_MAX) == sizeof(uint64_t));
            CHECK(rec->name_len > 0);
            CHECK(rec->name_len <= rec->record_len - sizeof(*rec));

            uint64_t *payload_slot = (void *)(bytes + sizeof(*hdr)
                                              + (uint32_t)(rec->vaddr
                                                           & UINT32_MAX));
            CHECK(*payload_slot == 0);
            saw = true;
            ix += rec->record_len;
            continue;
        }

        CHECK(op == TEST_MARSHAL_OP_STOP);
        ix += sizeof(test_marshal_stop_record_t);
        CHECK(ix == len);
        break;
    }

    CHECK(saw);
    _n00b_buffer_unlock(buf);
}

static void
test_function_pointer_patch_round_trip(void)
{
#ifdef _WIN32
    return;
#else
    enum {
        BASE = 0x42424242u,
    };

    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    marshal_fn_ref_t *src = n00b_alloc_size_with_opts(
        1,
        sizeof(marshal_fn_ref_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    src->tag = 0;
    src->fn  = n00b_gc_scan_cb_all;

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = BASE);
    CHECK(buf != nullptr);
    assert_fnpatch_record(buf, BASE);

    marshal_fn_ref_t *copy = n00b_unmarshal_one(buf, .target_arena = arena);
    CHECK(copy != nullptr);
    CHECK(copy != src);
    CHECK(copy->tag == 0);
    CHECK(copy->fn == n00b_gc_scan_cb_all);

    uint64_t      bitmap = 0;
    n00b_gc_map_t map    = {
        .user_ptr  = copy,
        .num_words = 1,
        .bitmap    = &bitmap,
    };
    copy->fn(&map, nullptr);
    CHECK(n00b_gc_map_is_set(&map, 0));
#endif
}

static n00b_buffer_t *
marshal_portable_ref(n00b_arena_t *arena,
                     uint64_t *words,
                     const n00b_static_identity_t *identity,
                     uint32_t flags,
                     uint64_t object_id,
                     uint32_t base_address)
{
    n00b_alloc_range_t *range = register_portable_words(words, 3, identity, flags, object_id);
    auto range_opt = n00b_mmap_range_by_address(&words[1]);
    if (!n00b_option_is_set(range_opt)) {
        fprintf(stderr, "portable range lookup failed after registration\n");
    }
    assert(n00b_option_is_set(range_opt));
    assert(n00b_option_get(range_opt) == range);

    marshal_static_ref_t *src = n00b_alloc_with_opts(marshal_static_ref_t,
                                                     ARENA_OPTS(arena));
    src->tag        = UINT64_C(0xcafe);
    src->static_ref = &words[1];

    n00b_marshal_ctx_t *ctx = n00b_marshal_ctx_new(.base_address = base_address);
    n00b_buffer_t *buf = n00b_marshal_incremental(ctx, src);
    if (buf == nullptr) {
        n00b_string_t *err = n00b_marshal_ctx_error(ctx);
        fprintf(stderr,
                "portable marshal failed: status=%d error=%s\n",
                n00b_marshal_ctx_status(ctx),
                err ? err->data : "(null)");
    }
    assert(buf != nullptr);
    n00b_marshal_ctx_destroy(ctx);
    return buf;
}

static void
test_portable_static_pointer_relocation(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    n00b_buffer_t *success = marshal_portable_ref(arena,
                                                  portable_success_src,
                                                  &portable_success_identity,
                                                  N00B_STATIC_OBJECT_F_READONLY,
                                                  UINT64_C(0x70010001),
                                                  0x13572468u);
    unregister_portable_words(portable_success_src, 3);
    (void)register_portable_words(portable_success_dst,
                                  3,
                                  &portable_success_identity,
                                  N00B_STATIC_OBJECT_F_READONLY,
                                  UINT64_C(0x70010002));
    marshal_static_ref_t *copy = n00b_unmarshal_one(success, .target_arena = arena);
    assert(copy != nullptr);
    assert(copy->static_ref == &portable_success_dst[1]);
    assert(*copy->static_ref == portable_success_dst[1]);

    n00b_buffer_t *missing = marshal_portable_ref(arena,
                                                  portable_missing_src,
                                                  &portable_missing_identity,
                                                  N00B_STATIC_OBJECT_F_READONLY,
                                                  UINT64_C(0x70020001),
                                                  0x13572469u);
    unregister_portable_words(portable_missing_src, 3);
    assert_unmarshal_status(missing, N00B_MARSHAL_ERR_STATIC_IDENTITY_MISSING);

    n00b_buffer_t *mutability = marshal_portable_ref(arena,
                                                     portable_mutability_src,
                                                     &portable_mutability_identity,
                                                     N00B_STATIC_OBJECT_F_READONLY,
                                                     UINT64_C(0x70030001),
                                                     0x1357246au);
    unregister_portable_words(portable_mutability_src, 3);
    (void)register_portable_words(portable_mutability_dst,
                                  3,
                                  &portable_mutability_identity,
                                  N00B_STATIC_OBJECT_F_MUTABLE,
                                  UINT64_C(0x70030002));
    assert_unmarshal_status(mutability, N00B_MARSHAL_ERR_STATIC_IDENTITY_MUTABILITY);

    n00b_buffer_t *duplicate = marshal_portable_ref(arena,
                                                    portable_duplicate_src,
                                                    &portable_duplicate_identity,
                                                    N00B_STATIC_OBJECT_F_READONLY,
                                                    UINT64_C(0x70040001),
                                                    0x1357246bu);
    unregister_portable_words(portable_duplicate_src, 3);
    (void)register_portable_words(portable_duplicate_dst_a,
                                  3,
                                  &portable_duplicate_identity,
                                  N00B_STATIC_OBJECT_F_READONLY,
                                  UINT64_C(0x70040002));
    (void)register_portable_words(portable_duplicate_dst_b,
                                  3,
                                  &portable_duplicate_identity,
                                  N00B_STATIC_OBJECT_F_READONLY,
                                  UINT64_C(0x70040003));
    assert_unmarshal_status(duplicate, N00B_MARSHAL_ERR_STATIC_IDENTITY_DUPLICATE);

    n00b_buffer_t *check_bytes = marshal_portable_ref(arena,
                                                      portable_check_src,
                                                      &portable_check_identity,
                                                      N00B_STATIC_OBJECT_F_READONLY,
                                                      UINT64_C(0x70050001),
                                                      0x1357246cu);
    unregister_portable_words(portable_check_src, 3);
    (void)register_portable_words(portable_check_dst,
                                  3,
                                  &portable_check_identity,
                                  N00B_STATIC_OBJECT_F_READONLY,
                                  UINT64_C(0x70050002));
    assert_unmarshal_status(check_bytes, N00B_MARSHAL_ERR_STATIC_IDENTITY_CHECK_BYTES);

    n00b_buffer_t *type = marshal_portable_ref(arena,
                                               portable_type_src,
                                               &portable_type_identity,
                                               N00B_STATIC_OBJECT_F_READONLY,
                                               UINT64_C(0x70080001),
                                               0x1357246eu);
    unregister_portable_words(portable_type_src, 3);
    (void)register_portable_words_ex(portable_type_dst,
                                     3,
                                     &portable_type_identity,
                                     N00B_STATIC_OBJECT_F_READONLY,
                                     UINT64_C(0x70080002),
                                     TEST_PORTABLE_STATIC_TINFO ^ UINT64_C(1),
                                     N00B_GC_SCAN_KIND_NONE);
    assert_unmarshal_status(type, N00B_MARSHAL_ERR_STATIC_IDENTITY_TYPE);

    n00b_buffer_t *scan = marshal_portable_ref(arena,
                                               portable_scan_src,
                                               &portable_scan_identity,
                                               N00B_STATIC_OBJECT_F_READONLY,
                                               UINT64_C(0x70090001),
                                               0x1357246fu);
    unregister_portable_words(portable_scan_src, 3);
    (void)register_portable_words_ex(portable_scan_dst,
                                     3,
                                     &portable_scan_identity,
                                     N00B_STATIC_OBJECT_F_READONLY,
                                     UINT64_C(0x70090002),
                                     TEST_PORTABLE_STATIC_TINFO,
                                     N00B_GC_SCAN_KIND_ALL);
    assert_unmarshal_status(scan, N00B_MARSHAL_ERR_STATIC_IDENTITY_SCAN);

    n00b_buffer_t *length = marshal_portable_ref(arena,
                                                 portable_length_src,
                                                 &portable_length_identity,
                                                 N00B_STATIC_OBJECT_F_READONLY,
                                                 UINT64_C(0x700a0001),
                                                 0x13572470u);
    unregister_portable_words(portable_length_src, 3);
    (void)register_portable_words(portable_length_dst,
                                  2,
                                  &portable_length_identity,
                                  N00B_STATIC_OBJECT_F_READONLY,
                                  UINT64_C(0x700a0002));
    assert_unmarshal_status(length, N00B_MARSHAL_ERR_STATIC_IDENTITY_LENGTH);

    (void)n00b_mmap_register(unsupported_static_words,
                             unsupported_static_words + 2,
                             n00b_mmap_static,
                             .file              = "unsupported-static-words",
                             .order_id          = UINT64_C(0x70060001),
                             .definitely_unique = false);
    marshal_static_ref_t *unsupported = n00b_alloc_with_opts(marshal_static_ref_t,
                                                             ARENA_OPTS(arena));
    unsupported->tag        = UINT64_C(0x70060002);
    unsupported->static_ref = &unsupported_static_words[0];
    n00b_marshal_ctx_t *mctx = n00b_marshal_ctx_new(.base_address = 0x1357246du);
    assert(n00b_marshal_incremental(mctx, unsupported) == nullptr);
    assert(n00b_marshal_ctx_status(mctx)
           == N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER);
    n00b_marshal_ctx_destroy(mctx);

    printf("  [PASS] portable_static_pointer_relocation\n");
}

static void
test_ptr_words_limits_scan_extent(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    marshal_node_t *decoy = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    decoy->tag            = 0xd0d0;
    decoy->scalar         = 88;
    decoy->next           = nullptr;
    decoy->alias          = nullptr;

    marshal_limited_scan_t *src = n00b_alloc_with_opts(marshal_limited_scan_t,
                                                       ARENA_OPTS(arena));
    src->real_ptr    = decoy;
    src->scalar_tail = (uint64_t)(uintptr_t)decoy;
    set_ptr_words(src, 1);

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x65432110u);
    assert(buf != nullptr);

    marshal_limited_scan_t *copy = n00b_unmarshal_one(buf, .target_arena = arena);
    assert(copy != nullptr);
    assert(copy != src);
    assert(copy->real_ptr != nullptr);
    assert(copy->real_ptr != decoy);
    assert(copy->real_ptr->tag == decoy->tag);
    assert(copy->scalar_tail == (uint64_t)(uintptr_t)decoy);
    assert(copy->scalar_tail != (uint64_t)(uintptr_t)copy->real_ptr);

    n00b_alloc_info_t copy_info = n00b_find_alloc_info(copy);
    if (copy_info.kind == n00b_alloc_oob) {
        assert(copy_info.hdr.oob->ptr_words == 1);
    }
    else {
        assert(copy_info.kind == n00b_alloc_inline);
        assert(copy_info.hdr.in_line->ptr_words == 1);
    }

    printf("  [PASS] ptr_words_limits_scan_extent\n");
}

static void
mutate_ptr_words_too_large(test_marshal_alloc_record_t *rec)
{
    rec->ptr_words = (uint32_t)(rec->user_len / sizeof(uint64_t)) + 1;
}

static void
mutate_cpatch_unaligned(void *rec)
{
    ((test_marshal_cpatch_record_t *)rec)->vaddr += 1;
}

static void
mutate_spatch_unaligned(void *rec)
{
    ((test_marshal_spatch_record_t *)rec)->vaddr += 1;
}

static void
mutate_pspatch_unaligned(void *rec)
{
    ((test_marshal_pspatch_record_t *)rec)->vaddr += 1;
}

static void
test_bad_ptr_words_rejected(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    marshal_node_t *node = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    node->tag            = 0xf00d;
    node->scalar         = 5;
    node->next           = nullptr;
    node->alias          = nullptr;

    n00b_buffer_t *buf = n00b_marshal(node, .base_address = 0x76543210u);
    assert(buf != nullptr);
    n00b_buffer_t *bad = buffer_copy_mutating_alloc(buf, mutate_ptr_words_too_large);
    assert_unmarshal_status(bad, N00B_MARSHAL_ERR_BAD_STREAM);

    printf("  [PASS] bad_ptr_words_rejected\n");
}

static void
test_callback_scan_boundary(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    marshal_callback_ref_t *src = n00b_alloc_size_with_opts(
        1,
        sizeof(marshal_callback_ref_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = mark_all_cb,
        });
    src->tag = 0xcbcb;
    src->ptr = nullptr;

    // D-039 guard (V-1): a CUSTOM (non-built-in) scan_cb is never
    // marshalable. This MUST remain an error; under WP-022 the code is
    // the dedicated N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK.
    n00b_marshal_ctx_t *mctx = n00b_marshal_ctx_new();
    assert(n00b_marshal_incremental(mctx, src) == nullptr);
    assert(n00b_marshal_ctx_status(mctx) == N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK);
    n00b_marshal_ctx_destroy(mctx);

    // A built-in scan_cb (every_other, no scan_user) now marshals
    // successfully and round-trips (success case added alongside the
    // retained custom-cb error case).
    // every_other marks word 0 (the tag word) as a pointer candidate;
    // keep it null so it is left verbatim, and carry a real pointer in
    // the unmarked ptr slot to confirm unmarked words round-trip too.
    marshal_node_t *cb_target = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    cb_target->tag = 0x9e9e;

    marshal_callback_ref_t *builtin = n00b_alloc_size_with_opts(
        1,
        sizeof(marshal_callback_ref_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = n00b_gc_scan_cb_every_other,
        });
    builtin->tag = 0;
    builtin->ptr = (uint64_t *)cb_target;

    n00b_buffer_t *ok = n00b_marshal(builtin, .base_address = 0x5a5a5a5au);
    assert(ok != nullptr);
    marshal_callback_ref_t *builtin_copy = n00b_unmarshal_one(ok, .target_arena = arena);
    assert(builtin_copy != nullptr);
    assert(builtin_copy != builtin);
    assert(builtin_copy->tag == 0);
    // ptr is at word 1, which every_other does NOT mark, so it stays a
    // verbatim scalar (not relinked) -- it equals the original address.
    assert(builtin_copy->ptr == (uint64_t *)cb_target);
    n00b_alloc_info_t bc_info = n00b_find_alloc_info(builtin_copy);
    assert(bc_info.kind == n00b_alloc_oob);
    assert(bc_info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(bc_info.hdr.oob->scan_cb == n00b_gc_scan_cb_every_other);
    assert(bc_info.hdr.oob->scan_user == nullptr);

    // A plain node whose ALLOC record is mutated to scan_kind=CALLBACK
    // carries no CBSCAN extension; unmarshal rejects the orphaned
    // CALLBACK record cleanly.
    marshal_node_t *plain = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    plain->tag            = 0xeeee;
    plain->scalar         = 7;
    plain->next           = nullptr;
    plain->alias          = nullptr;

    n00b_buffer_t *buf = n00b_marshal(plain, .base_address = 0x456789abu);
    assert(buf != nullptr);
    n00b_buffer_t *bad = buffer_copy_mutating_alloc(buf, mutate_callback_scan);
    assert_unmarshal_status(bad, N00B_MARSHAL_ERR_BAD_STREAM);

    printf("  [PASS] callback_scan_boundary\n");
}

// Register the synthetic struct_layout descriptor as a static object
// with an identity so marshal can round-trip it as scan_user (mirrors
// register_portable_words). The descriptor and its offsets array are
// file-scope statics.
static void
register_cbscan_layout_desc(void)
{
    (void)n00b_mmap_register((void *)&cbscan_layout_desc,
                             (void *)((char *)&cbscan_layout_desc
                                      + sizeof(cbscan_layout_desc)),
                             n00b_mmap_static,
                             .file              = "test_marshal_cbscan_layout_desc",
                             .order_id          = UINT64_C(0x80010001),
                             .definitely_unique = false);
    // Surface a failed static-object registration as a clear setup error
    // (it returns the descriptor range, non-null on success) rather than
    // letting a later cbscan_resolve fail with an opaque identity-missing
    // error.
    n00b_alloc_range_t *desc_range = n00b_static_object_register(
        (void *)&cbscan_layout_desc,
        sizeof(cbscan_layout_desc),
        CBSCAN_LAYOUT_TINFO,
        .scan_kind = N00B_GC_SCAN_KIND_NONE,
        .object_id = UINT64_C(0x80010002),
        .identity  = &cbscan_layout_identity,
        .flags     = N00B_STATIC_OBJECT_F_READONLY);
    assert(desc_range != nullptr);
}

// Mirror register_cbscan_layout_desc's teardown (cf. unregister_portable_words):
// drop the registered static mmap range so the synthetic identity does not
// leak into later tests sharing the identity namespace.
static void
unregister_cbscan_layout_desc(void)
{
    n00b_mmap_delete_ranges(
        n00b_global_mem_map(n00b_get_runtime()),
        (uint64_t)(uintptr_t)&cbscan_layout_desc,
        (uint64_t)(uintptr_t)((char *)&cbscan_layout_desc
                              + sizeof(cbscan_layout_desc)));
}

static void
test_callback_struct_layout_round_trip(void)
{
    register_cbscan_layout_desc();

    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    marshal_node_t *target = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    target->tag    = 0x7a7a;
    target->scalar = 0x1234;
    target->next   = nullptr;
    target->alias  = nullptr;

    marshal_struct_layout_t *src = n00b_alloc_size_with_opts(
        1,
        sizeof(marshal_struct_layout_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = n00b_gc_scan_cb_struct_layout,
            .scan_user = (void *)&cbscan_layout_desc,
        });
    src->packed_alias = UINT64_C(0x100000000);
    src->real_ptr     = target;
    src->scalar_tail  = UINT64_C(0xfeedface);
    src->pad          = 0;

    // Snapshot the live source bytes; emit must not mutate them (W-6).
    marshal_struct_layout_t snapshot = *src;

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x11223344u);
    assert(buf != nullptr);
    assert(memcmp(&snapshot, src, sizeof(snapshot)) == 0);
    assert(src->packed_alias == UINT64_C(0x100000000));
    assert(src->real_ptr == target);

    marshal_struct_layout_t *copy = n00b_unmarshal_one(buf, .target_arena = arena);
    assert(copy != nullptr);
    assert(copy != src);
    // The packed-int word aliases the static range but is a scalar; it
    // must survive verbatim (not relinked).
    assert(copy->packed_alias == UINT64_C(0x100000000));
    assert(copy->scalar_tail == UINT64_C(0xfeedface));
    // The real pointer is relocated to the unmarshaled copy of target.
    assert(copy->real_ptr != nullptr);
    assert(copy->real_ptr != target);
    assert(copy->real_ptr->tag == 0x7a7a);
    assert(copy->real_ptr->scalar == 0x1234);

    n00b_alloc_info_t info = n00b_find_alloc_info(copy);
    assert(info.kind == n00b_alloc_oob);
    assert(info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    assert(info.hdr.oob->scan_cb == n00b_gc_scan_cb_struct_layout);
    assert(info.hdr.oob->scan_user == (void *)&cbscan_layout_desc);

    // The restored object survives a collection with its pointer intact.
    n00b_gc_register_root(copy);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    assert(copy->packed_alias == UINT64_C(0x100000000));
    assert(copy->real_ptr->tag == 0x7a7a);
    n00b_gc_unregister_root(copy);

    unregister_cbscan_layout_desc();
    printf("  [PASS] callback_struct_layout_round_trip\n");
}

static void
round_trip_null_scan_user(n00b_arena_t      *arena,
                          n00b_gc_scan_cb_t  cb,
                          uint32_t           base_address)
{
    marshal_callback_ref_t *src = n00b_alloc_size_with_opts(
        1,
        sizeof(marshal_callback_ref_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = cb,
        });
    // Keep both words null so that whichever the callback marks is left
    // verbatim (the focus here is round-tripping the scan policy, not
    // pointer relink); all/every_other mark word 0, none marks nothing.
    src->tag = 0;
    src->ptr = nullptr;

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = base_address);
    CHECK(buf != nullptr);

    marshal_callback_ref_t *copy = n00b_unmarshal_one(buf, .target_arena = arena);
    CHECK(copy != nullptr);
    CHECK(copy != src);
    CHECK(copy->tag == 0);

    n00b_alloc_info_t info = n00b_find_alloc_info(copy);
    CHECK(info.kind == n00b_alloc_oob);
    CHECK(info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    CHECK(info.hdr.oob->scan_cb == cb);
    CHECK(info.hdr.oob->scan_user == nullptr);

    n00b_buffer_t *legacy = buffer_copy_as_legacy_inline(buf, 3);
    marshal_callback_ref_t *legacy_copy = n00b_unmarshal_one(legacy,
                                                             .target_arena = arena);
    CHECK(legacy_copy != nullptr);
    CHECK(legacy_copy != src);
    CHECK(legacy_copy->tag == 0);

    n00b_alloc_info_t legacy_info = n00b_find_alloc_info(legacy_copy);
    CHECK(legacy_info.kind == n00b_alloc_oob);
    CHECK(legacy_info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_CALLBACK);
    CHECK(legacy_info.hdr.oob->scan_cb == cb);
    CHECK(legacy_info.hdr.oob->scan_user == nullptr);
}

static void
test_callback_null_scan_user_round_trip(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    round_trip_null_scan_user(arena, n00b_gc_scan_cb_all, 0x21212121u);
    round_trip_null_scan_user(arena, n00b_gc_scan_cb_none, 0x22222222u);
    round_trip_null_scan_user(arena, n00b_gc_scan_cb_every_other, 0x23232323u);

    printf("  [PASS] callback_null_scan_user_round_trip\n");
}

static void
mutate_header_version_v2(void *bytes)
{
    ((test_marshal_stream_header_t *)bytes)->version = 2;
}

static void
mutate_header_version_v5(void *bytes)
{
    ((test_marshal_stream_header_t *)bytes)->version = 5;
}

static n00b_buffer_t *
buffer_copy_mutating_header(n00b_buffer_t *buf, void (*mutate)(void *bytes))
{
    _n00b_buffer_rlock(buf);
    int64_t len   = (int64_t)buf->byte_len;
    char   *bytes = n00b_alloc_array(char, (size_t)len);
    memcpy(bytes, buf->data, (size_t)len);
    _n00b_buffer_unlock(buf);
    mutate(bytes);
    return n00b_buffer_from_bytes(bytes, len);
}

static void
test_callback_version_mismatch(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    marshal_callback_ref_t *src = n00b_alloc_size_with_opts(
        1,
        sizeof(marshal_callback_ref_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = n00b_gc_scan_cb_none,
        });
    src->tag = 0x5151;
    src->ptr = nullptr;

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x31313131u);
    assert(buf != nullptr);

    // A current CALLBACK stream presented as version 2 is rejected:
    // CALLBACK records are illegal below v3, and v4 payload-front
    // streams are not legacy inline streams.
    n00b_buffer_t *as_v2 = buffer_copy_mutating_header(buf, mutate_header_version_v2);
    assert_unmarshal_status(as_v2, N00B_MARSHAL_ERR_BAD_STREAM);

    // A version above the supported maximum is rejected by the header gate.
    n00b_buffer_t *as_v5 = buffer_copy_mutating_header(buf, mutate_header_version_v5);
    assert_unmarshal_status(as_v5, N00B_MARSHAL_ERR_BAD_STREAM);

    printf("  [PASS] callback_version_mismatch\n");
}

static void
test_malformed_stream_hardening(void)
{
    static uint64_t static_words[2] = {
        UINT64_C(0x4142434445464748),
        UINT64_C(0x5152535455565758),
    };

    (void)n00b_mmap_register(static_words,
                             static_words + 2,
                             n00b_mmap_static,
                             .file              = "test_marshal_bad_spatch_words",
                             .order_id          = UINT64_C(0x6007),
                             .definitely_unique = false);
    (void)n00b_static_object_register(static_words,
                                      sizeof(static_words),
                                      0,
                                      .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                      .object_id = UINT64_C(0x60070001));

    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    marshal_node_t *node = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    node->tag            = 0xabab;
    node->scalar         = (UINT64_C(0x56789abc) << 32) | UINT64_C(5);
    node->next           = nullptr;
    node->alias          = nullptr;

    marshal_static_ref_t *static_ref = n00b_alloc_with_opts(marshal_static_ref_t,
                                                            ARENA_OPTS(arena));
    static_ref->tag        = 0xfefe;
    static_ref->static_ref = &static_words[0];

    n00b_buffer_t *buf = n00b_marshal(node, .base_address = 0x56789abcu);
    assert(buf != nullptr);

    n00b_buffer_t *trailing = buffer_copy_with_extra(buf, 1);
    assert_unmarshal_status(trailing, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *unknown_op = buffer_copy_mutating_alloc(buf, mutate_unknown_op);
    assert_unmarshal_status(unknown_op, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *short_payload = buffer_copy_mutating_alloc(buf, mutate_short_payload);
    assert_unmarshal_status(short_payload, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *bad_kind = buffer_copy_mutating_alloc(buf, mutate_bad_scan_kind);
    assert_unmarshal_status(bad_kind, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *bad_flags = buffer_copy_mutating_alloc(buf, mutate_bad_alloc_flags);
    assert_unmarshal_status(bad_flags, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *bad_cpatch = buffer_copy_mutating_record(buf,
                                                            TEST_MARSHAL_OP_CPATCH,
                                                            mutate_cpatch_unaligned);
    assert_unmarshal_status(bad_cpatch, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *spatch_stream = n00b_marshal(static_ref,
                                                .base_address = 0x56789abcu);
    assert(spatch_stream != nullptr);
    n00b_buffer_t *bad_spatch = buffer_copy_mutating_record(spatch_stream,
                                                            TEST_MARSHAL_OP_SPATCH,
                                                            mutate_spatch_unaligned);
    assert_unmarshal_status(bad_spatch, N00B_MARSHAL_ERR_BAD_STREAM);

    n00b_buffer_t *pspatch_stream = marshal_portable_ref(arena,
                                                         portable_malformed_words,
                                                         &portable_malformed_identity,
                                                         N00B_STATIC_OBJECT_F_READONLY,
                                                         UINT64_C(0x70070001),
                                                         0x56789abcu);
    n00b_buffer_t *bad_pspatch = buffer_copy_mutating_record(pspatch_stream,
                                                             TEST_MARSHAL_OP_PSPATCH,
                                                             mutate_pspatch_unaligned);
    assert_unmarshal_status(bad_pspatch, N00B_MARSHAL_ERR_BAD_STREAM);

    _n00b_buffer_rlock(buf);
    int64_t len   = (int64_t)buf->byte_len;
    char   *bytes = n00b_alloc_array(char, (size_t)len);
    memcpy(bytes, buf->data, (size_t)len);
    _n00b_buffer_unlock(buf);
    ((test_marshal_stream_header_t *)bytes)->marshal_magic ^= UINT64_C(0x55);

    n00b_unmarshal_ctx_t *ctx = n00b_unmarshal_ctx_new();
    n00b_buffer_t        *c1  = n00b_buffer_from_bytes(bytes, 4);
    n00b_list_t(void *) roots = n00b_unmarshal_incremental(ctx, c1);
    assert(n00b_list_len(roots) == 0);
    assert(n00b_unmarshal_ctx_status(ctx) == N00B_MARSHAL_ERR_INCOMPLETE_STREAM);

    n00b_buffer_t *c2 = n00b_buffer_from_bytes(bytes + 4, len - 4);
    roots = n00b_unmarshal_incremental(ctx, c2);
    assert(n00b_list_len(roots) == 0);
    assert(n00b_unmarshal_ctx_status(ctx) == N00B_MARSHAL_ERR_BAD_STREAM);
    n00b_unmarshal_ctx_destroy(ctx);

    printf("  [PASS] malformed_stream_hardening\n");
}

static void
test_single_root_context_boundary(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    marshal_node_t *a = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));
    marshal_node_t *b = n00b_alloc_with_opts(marshal_node_t, ARENA_OPTS(arena));

    a->tag = 1;
    b->tag = 2;

    n00b_marshal_ctx_t *ctx = n00b_marshal_ctx_new();
    assert(n00b_marshal_incremental(ctx, a, .close = false) != nullptr);
    assert(n00b_marshal_incremental(ctx, b, .close = true) == nullptr);
    assert(n00b_marshal_ctx_status(ctx) == N00B_MARSHAL_ERR_CONTEXT_CLOSED);
    n00b_marshal_ctx_destroy(ctx);

    printf("  [PASS] single_root_context_boundary\n");
}

static void
test_gc_pressure_during_round_trip(void)
{
    enum { STRESS_WORDS = 64 * 1024 };

    n00b_arena_t *source = n00b_new_arena(.size = 4096, .use_gc = true);
    uint64_t     *blob   = n00b_alloc_size_with_opts(
        STRESS_WORDS,
        sizeof(uint64_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)source,
            .no_scan   = true,
        });

    for (size_t i = 0; i < STRESS_WORDS; i++) {
        blob[i] = stress_value(i);
    }

    n00b_gc_register_root(blob);

    gc_request_t   marshal_gc;
    n00b_thread_t *marshal_thread = start_gc_request(&marshal_gc, source, 1000000);
    atomic_store(&marshal_gc.run, 1);
    n00b_buffer_t *buf = n00b_marshal(blob, .base_address = 0x23456789u);
    while (!atomic_load(&marshal_gc.done)) {
    }
    n00b_thread_join(marshal_thread);
    assert(atomic_load(&marshal_gc.collections) == 1);

    assert(buf != nullptr);
    assert(n00b_buffer_len(buf) > (int64_t)(STRESS_WORDS * sizeof(uint64_t)));
    assert(blob[12345] == stress_value(12345));

    n00b_arena_t *target     = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_segment_t *old_head = target->current_segment;

    n00b_unmarshal_ctx_t *uctx = n00b_unmarshal_ctx_new(.target_arena = target);
    int64_t               len  = n00b_buffer_len(buf);
    int64_t               c1   = 17;
    int64_t               c2   = 4093;

    n00b_buffer_t *chunk = buffer_slice(buf, 0, c1);
    n00b_list_t(void *) roots = n00b_unmarshal_incremental(uctx, chunk);
    assert(n00b_list_len(roots) == 0);
    assert(n00b_unmarshal_ctx_status(uctx) == N00B_MARSHAL_ERR_INCOMPLETE_STREAM);

    chunk = buffer_slice(buf, c1, c2);
    roots = n00b_unmarshal_incremental(uctx, chunk);
    assert(n00b_list_len(roots) == 0);
    assert(n00b_unmarshal_ctx_status(uctx) == N00B_MARSHAL_ERR_INCOMPLETE_STREAM);

    gc_request_t   unmarshal_gc;
    n00b_thread_t *unmarshal_thread = start_gc_request(&unmarshal_gc, target, 1000000);
    atomic_store(&unmarshal_gc.run, 1);
    chunk = buffer_slice(buf, c1 + c2, len - c1 - c2);
    roots = n00b_unmarshal_incremental(uctx, chunk);
    while (!atomic_load(&unmarshal_gc.done)) {
    }
    n00b_thread_join(unmarshal_thread);
    assert(atomic_load(&unmarshal_gc.collections) == 1);

    assert(n00b_unmarshal_ctx_status(uctx) == N00B_MARSHAL_OK);
    assert(n00b_list_len(roots) == 1);

    uint64_t *copy = n00b_list_get(roots, 0);
    n00b_gc_register_root(copy);

    assert(copy != nullptr);
    assert(copy != blob);
    assert(copy[0] == stress_value(0));
    assert(copy[12345] == stress_value(12345));
    assert(copy[STRESS_WORDS - 1] == stress_value(STRESS_WORDS - 1));
    assert(target->current_segment != old_head);
    assert(target->collection_enabled);

    n00b_stop_the_world();
    n00b_collect(target);
    n00b_restart_the_world();
    assert(copy[12345] == stress_value(12345));

    n00b_gc_unregister_root(copy);
    n00b_gc_unregister_root(blob);
    n00b_unmarshal_ctx_destroy(uctx);

    printf("  [PASS] gc_pressure_during_round_trip\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running marshal tests...\n");
    test_cycle_shared_and_collision();
    test_static_pointer_patch();
    test_function_pointer_patch_round_trip();
    test_portable_static_pointer_relocation();
    test_ptr_words_limits_scan_extent();
    test_bad_ptr_words_rejected();
    test_callback_scan_boundary();
    test_callback_struct_layout_round_trip();
    test_callback_null_scan_user_round_trip();
    test_callback_version_mismatch();
    test_malformed_stream_hardening();
    test_single_root_context_boundary();
    test_gc_pressure_during_round_trip();
    printf("All marshal tests passed.\n");

    n00b_shutdown();
    return 0;
}
