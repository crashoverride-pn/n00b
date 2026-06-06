#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "util/assert.h"
#include "util/marshal.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

#define TEST_MARSHAL_OP_ALLOC  UINT32_C(0xe11cbab0)
#define TEST_MARSHAL_OP_CPATCH UINT32_C(0xe31cbab0)
#define TEST_MARSHAL_OP_STOP   UINT32_C(0xe51cbab0)
#define TEST_MARSHAL_OP_CBSCAN UINT32_C(0xe71cbab0)

typedef struct {
    uint64_t marshal_magic;
    uint32_t version;
    uint32_t base_address;
    uint32_t root_offset;
    uint32_t payload_front_len;
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
} test_marshal_cbscan_record_t;

typedef struct {
    uint32_t op;
    uint32_t end_of_stream;
} test_marshal_stop_record_t;

typedef struct layout_leaf_t {
    uint64_t magic;
    uint64_t scalar;
} layout_leaf_t;

typedef struct layout_callback_t {
    layout_leaf_t *target;
    uint64_t       zero;
} layout_callback_t;

typedef struct layout_root_t {
    uint64_t           tag;
    layout_leaf_t     *child;
    layout_callback_t *callback;
    uint64_t           collision;
} layout_root_t;

static uint64_t
align8(uint64_t n)
{
    return (n + 7u) & ~UINT64_C(7);
}

static void
test_payload_front_layout(void)
{
    enum {
        BASE = 0x2c0ffeeu,
    };

    uint64_t collision = ((uint64_t)BASE << 32) | UINT64_C(0x12345678);
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    layout_leaf_t *leaf = n00b_alloc_size_with_opts(
        1,
        sizeof(layout_leaf_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    leaf->magic  = UINT64_C(0x5152535455565758);
    leaf->scalar = UINT64_C(0x6162636465666768);

    layout_callback_t *callback = n00b_alloc_size_with_opts(
        1,
        sizeof(layout_callback_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_CALLBACK,
            .scan_cb   = n00b_gc_scan_cb_all,
        });
    callback->target = leaf;
    callback->zero   = 0;

    layout_root_t *root = n00b_alloc_size_with_opts(
        1,
        sizeof(layout_root_t),
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    root->tag       = UINT64_C(0xa0a1a2a3a4a5a6a7);
    root->child     = leaf;
    root->callback  = callback;
    root->collision = collision;

    n00b_buffer_t *buf = n00b_marshal(root, .base_address = BASE);
    CHECK(buf != nullptr);

    _n00b_buffer_rlock(buf);
    char *bytes = buf->data;
    size_t len  = buf->byte_len;
    CHECK(len >= sizeof(test_marshal_stream_header_t));

    test_marshal_stream_header_t *hdr = (void *)bytes;
    CHECK(hdr->marshal_magic == N00B_MARSHAL_MAGIC);
    CHECK(hdr->version == N00B_MARSHAL_VERSION);
    CHECK(hdr->base_address == BASE);
    CHECK(hdr->root_offset == 0);
    CHECK(hdr->payload_front_len > 0);

    size_t payload_ix  = sizeof(*hdr);
    size_t metadata_ix = payload_ix + hdr->payload_front_len;
    CHECK(metadata_ix < len);

    uint32_t first_op = *(uint32_t *)(bytes + metadata_ix);
    CHECK(first_op == TEST_MARSHAL_OP_ALLOC);

    char    *image_base      = bytes + payload_ix;
    size_t   ix              = metadata_ix;
    uint32_t expected_offset = 0;
    uint32_t alloc_count     = 0;
    bool     saw_cbscan      = false;
    bool     saw_cpatch      = false;
    uint64_t cpatch_vaddr    = 0;

    while (ix < len) {
        uint32_t op = *(uint32_t *)(bytes + ix);
        if (op == TEST_MARSHAL_OP_ALLOC) {
            test_marshal_alloc_record_t *rec = (void *)(bytes + ix);
            CHECK((rec->vaddr >> 32) == BASE);
            CHECK((uint32_t)(rec->vaddr & UINT32_MAX) == expected_offset);
            CHECK(rec->payload_len == align8(rec->user_len));
            CHECK(rec->payload_len <= UINT32_MAX);
            CHECK((uint64_t)expected_offset + rec->payload_len
                  <= hdr->payload_front_len);

            char *payload = image_base + (uint32_t)(rec->vaddr & UINT32_MAX);
            CHECK(payload >= image_base);
            CHECK(payload + rec->payload_len <= bytes + metadata_ix);

            if (rec->scan_kind == N00B_GC_SCAN_KIND_CALLBACK) {
                uint32_t next_op = *(uint32_t *)(bytes + ix + sizeof(*rec));
                CHECK(next_op == TEST_MARSHAL_OP_CBSCAN);
            }

            expected_offset += (uint32_t)rec->payload_len;
            alloc_count++;
            ix += sizeof(*rec);
            continue;
        }

        if (op == TEST_MARSHAL_OP_CBSCAN) {
            test_marshal_cbscan_record_t *rec = (void *)(bytes + ix);
            CHECK((rec->vaddr >> 32) == BASE);
            CHECK(rec->record_len >= sizeof(*rec));
            CHECK(rec->scan_cb_tag == 0);
            CHECK(rec->has_identity == 0);
            saw_cbscan = true;
            ix += rec->record_len;
            continue;
        }

        if (op == TEST_MARSHAL_OP_CPATCH) {
            test_marshal_cpatch_record_t *rec = (void *)(bytes + ix);
            CHECK(rec->reserved == 0);
            CHECK((rec->vaddr >> 32) == BASE);
            CHECK(rec->value == collision);
            cpatch_vaddr = rec->vaddr;
            saw_cpatch = true;
            ix += sizeof(*rec);
            continue;
        }

        CHECK(op == TEST_MARSHAL_OP_STOP);
        test_marshal_stop_record_t *rec = (void *)(bytes + ix);
        CHECK(rec->end_of_stream == 1);
        ix += sizeof(*rec);
        CHECK(ix == len);
        break;
    }

    CHECK(alloc_count == 3);
    CHECK(saw_cbscan);
    CHECK(saw_cpatch);
    CHECK(expected_offset == hdr->payload_front_len);

    uint64_t *patched_slot = (void *)(image_base
                                      + (uint32_t)(cpatch_vaddr & UINT32_MAX));
    CHECK(*patched_slot == collision);
    _n00b_buffer_unlock(buf);

    /*
     * This is shared marshal API compatibility coverage only. rocs shard
     * readers must use mapped resident views and must never unmarshal shards.
     */
    layout_root_t *copy = n00b_unmarshal_one(buf, .target_arena = arena);
    CHECK(copy != nullptr);
    CHECK(copy != root);
    CHECK(copy->tag == root->tag);
    CHECK(copy->collision == collision);
    CHECK(copy->child != nullptr);
    CHECK(copy->child != leaf);
    CHECK(copy->child->magic == leaf->magic);
    CHECK(copy->callback != nullptr);
    CHECK(copy->callback != callback);
    CHECK(copy->callback->target == copy->child);
    CHECK(copy->callback->zero == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_payload_front_layout();
    n00b_shutdown();
    return 0;
}
