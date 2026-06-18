#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/fd_managed.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/runtime.h"

static bool
buffer_has_literal(n00b_buffer_t *buf, const char *needle, uint64_t needle_len)
{
    assert(buf != nullptr);
    assert(needle != nullptr);

    if (needle_len == 0) {
        return true;
    }
    if (buf->byte_len < needle_len) {
        return false;
    }

    uint64_t last = (uint64_t)buf->byte_len - needle_len;

    for (uint64_t i = 0; i <= last; i++) {
        uint64_t j = 0;

        while (j < needle_len && buf->data[i + j] == needle[j]) {
            j++;
        }
        if (j == needle_len) {
            return true;
        }
    }

    return false;
}

#define BUFFER_HAS_LITERAL(buf, lit) \
    buffer_has_literal((buf), (lit), (uint64_t)(sizeof(lit) - 1))

static n00b_conduit_message_t(n00b_buffer_t *) *
wait_for_census_msg(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    for (uint32_t i = 0; i < 1000; i++) {
        n00b_conduit_message_t(n00b_buffer_t *) *msg =
            n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);

        if (msg != nullptr) {
            return msg;
        }

        usleep(1000);
    }

    return nullptr;
}

// nogc: the debug-census stats struct carries fixed-size arrays of *static*
// site-name pointers; ncc cannot describe a pointer-array as a precise stack
// root, and this test only reads scalar stat fields (the GC objects it does
// touch -- the conduit topic/inbox -- are rooted via rt->default_conduit, not
// only this frame), so opting the frame out of stack-map generation is safe.
[[n00b::nogc]] static void
test_debug_census_publishes_typed_buffer(n00b_runtime_t *rt)
{
    assert(rt != nullptr);
    assert(rt->default_conduit != nullptr);

    n00b_conduit_topic_t(n00b_buffer_t *) *topic =
        n00b_conduit_topic_init(n00b_buffer_t *,
                                rt->default_conduit,
                                n00b_conduit_str_uri(r"test/gc-census"));
    assert(topic != nullptr);

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                             &(n00b_alloc_opts_t){
                                 .allocator = rt->default_conduit->allocator,
                             });
    n00b_conduit_inbox_init(n00b_buffer_t *,
                            inbox,
                            rt->default_conduit,
                            N00B_CONDUIT_BP_UNBOUNDED,
                            0);

    n00b_conduit_sub_handle_t handle =
        n00b_conduit_subscribe(n00b_buffer_t *,
                               topic,
                               inbox,
                               .operations = N00B_CONDUIT_OP_ALL);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);

    uint8_t *user_bytes = n00b_alloc_array_with_opts(
        uint8_t,
        64,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)&rt->user_pool,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    assert(user_bytes != nullptr);
    user_bytes[0] = 0xa5;

    n00b_debug_find_leaks_to_conduit(topic);
    assert(!n00b_atomic_load(&rt->debug_leak_detect));

    n00b_debug_census_stats_t stats = n00b_debug_census_stats();
    assert(stats.enabled);
    assert(!stats.active);
    assert(stats.runs >= 1);
    assert(stats.last_started_ns > 0);
    assert(stats.last_finished_ns >= stats.last_started_ns);
    assert(stats.last_duration_ns > 0);
    assert(stats.gc_total_pause_ns > 0);
    assert(stats.gc_root_count > 0);
    assert(stats.gc_scan_range_count > 0);
    assert(stats.pool_live_allocs > 0);
    assert(stats.pool_live_bytes > 0);
    assert(stats.metadata_pool_count > 0);

    n00b_conduit_message_t(n00b_buffer_t *) *msg = wait_for_census_msg(inbox);
    assert(msg != nullptr);
    assert(msg->payload != nullptr);
    assert(n00b_buffer_len(msg->payload) > 0);
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b census: collection complete\n"));
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b gc-timing: total_pause_ns="));
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b gc-timing phases: internal_ns="));
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b gc-roots: count="));
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b gc-scan: ranges="));
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b gc-worklist-origin: ranges="));
    assert(BUFFER_HAS_LITERAL(msg->payload, "n00b pool-census: LIVE "));

    n00b_conduit_sub_cancel(handle);
    printf("  [PASS] debug census publishes typed buffer\n");
}

static void
test_user_pool_metadata_compaction_preserves_live_records(n00b_runtime_t *rt)
{
    assert(rt != nullptr);

    n00b_allocator_t *allocator = (n00b_allocator_t *)&rt->user_pool;
    assert(allocator->metadata_pool != nullptr);

    void *keep[16] = {};
    void *drop[16] = {};
    n00b_allocator_t *old_metadata_pool = allocator->metadata_pool;

    for (uint32_t i = 0; i < 16; i++) {
        keep[i] = n00b_alloc_array_with_opts(
            uint8_t,
            32,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
                .scan_kind = N00B_GC_SCAN_KIND_NONE,
            });
        drop[i] = n00b_alloc_array_with_opts(
            uint8_t,
            32,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
                .scan_kind = N00B_GC_SCAN_KIND_NONE,
            });
        assert(keep[i] != nullptr);
        assert(drop[i] != nullptr);
    }

    for (uint32_t i = 0; i < 16; i++) {
        n00b_free(drop[i]);
    }

    n00b_allocator_compact_metadata(allocator);
    assert(allocator->metadata_pool != nullptr);
    assert(allocator->metadata_pool != old_metadata_pool);

    for (uint32_t i = 0; i < 16; i++) {
        n00b_alloc_info_t info = n00b_find_alloc_info(keep[i]);
        assert(info.kind == n00b_alloc_oob);
        assert(info.hdr.oob != nullptr);
        assert(info.hdr.oob->user_ptr == keep[i]);
        assert(info.hdr.oob->alive);
        n00b_free(keep[i]);
    }

    printf("  [PASS] user_pool metadata compaction preserves live records\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_gc_census:\n");
#if defined(N00B_DEBUG)
    test_debug_census_publishes_typed_buffer(&rt);
#else
    printf("  [SKIP] debug census publish requires N00B_DEBUG\n");
#endif
    test_user_pool_metadata_compaction_preserves_live_records(&rt);
    printf("All GC census tests passed.\n");

    n00b_shutdown();
    return 0;
}
