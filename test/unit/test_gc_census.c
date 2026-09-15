#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/fd_managed.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/pool.h"
#include "core/runtime.h"

[[n00b::nomap]] static n00b_debug_census_stats_t g_census_stats;

// The pool census (n00b_debug_pool_census) walks rt->metadata_pools plus
// rt->user_pool, and can only classify allocations that carry an OOB
// metadata record (it reads oob->gc_epoch / alive / alloc_len). Nothing
// registers into rt->metadata_pools by default, and since user_pool moved to
// inline headers (init.c: `.external_metadata = false`) it has no OOB dict
// either, so with a stock runtime the census sees zero pools. n00b#281. This
// test therefore brings its own OOB-metadata pool and opts it into the list,
// which is the documented way for a pool to get census/root semantics.
[[n00b::nomap]] static n00b_pool_t g_census_pool;

// Registered as a GC root below: this function is [[n00b::nogc]] (no stack
// map), so a local would not be a real root and the census would classify
// the allocation as a leak rather than LIVE.
[[n00b::nomap]] static uint8_t *g_census_bytes;

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

    n00b_pool_init(&g_census_pool,
                   .hidden            = false,
                   .external_metadata = true,
                   .name              = "test_gc_census");
    n00b_list_push(rt->metadata_pools, (n00b_allocator_t *)&g_census_pool);

    g_census_bytes = n00b_alloc_array_with_opts(
        uint8_t,
        64,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)&g_census_pool,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    assert(g_census_bytes != nullptr);
    g_census_bytes[0] = 0xa5;
    n00b_gc_register_root(g_census_bytes);

    n00b_debug_find_leaks_to_conduit(topic);
    assert(!n00b_atomic_load(&rt->debug_leak_detect));

    g_census_stats = n00b_debug_census_stats();
    assert(g_census_stats.enabled);
    assert(!g_census_stats.active);
    assert(g_census_stats.runs >= 1);
    assert(g_census_stats.last_started_ns > 0);
    assert(g_census_stats.last_finished_ns >= g_census_stats.last_started_ns);
    assert(g_census_stats.last_duration_ns > 0);
    assert(g_census_stats.gc_total_pause_ns > 0);
    assert(g_census_stats.gc_root_count > 0);
    assert(g_census_stats.gc_scan_range_count > 0);
    assert(g_census_stats.pool_live_allocs > 0);
    assert(g_census_stats.pool_live_bytes > 0);
    assert(g_census_stats.metadata_pool_count > 0);

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
    n00b_gc_unregister_root(g_census_bytes);
    printf("  [PASS] debug census publishes typed buffer\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_gc_census:\n");
#if defined(N00B_DEBUG)
    // The runtime the process actually uses, not the init local: on Linux the
    // local is not the live runtime (its pools and conduit are garbage there),
    // which is the SIGSEGV this test showed on ubuntu before and after the
    // census fix. Same rule as n00b#366's dict_gc_scan lesson.
    test_debug_census_publishes_typed_buffer(n00b_get_runtime());
#else
    printf("  [SKIP] debug census publish requires N00B_DEBUG\n");
#endif
    printf("All GC census tests passed.\n");

    n00b_shutdown();
    return 0;
}
