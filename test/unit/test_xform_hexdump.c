/*
 * test_xform_hexdump.c — Tests for the hexdump conduit transform.
 */

#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/xform_hexdump.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/atomic.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_topic_t(n00b_buffer_t *) *
make_buf_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 5000;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri =
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, id);
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_buffer_t *)));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_buffer_t *) *topic =
        (n00b_conduit_topic_t(n00b_buffer_t *) *)
            n00b_result_get(tr);
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    topic->inbox = nullptr;
    return topic;
}

static void
push_buf(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
         const uint8_t *data, size_t len)
{
    // Conduit contract: delivered messages must come from conduit->allocator.
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(n00b_buffer_t *),
            &(n00b_alloc_opts_t){.allocator =
                ((n00b_conduit_topic_base_t *)topic)->conduit->allocator});
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = n00b_buffer_from_bytes((char *)data, (int64_t)len);
    n00b_conduit_topic_deliver_msg(n00b_buffer_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static n00b_plane_t *
pop_plane(n00b_conduit_inbox_t(n00b_plane_t *) *inbox)
{
    n00b_conduit_message_t(n00b_plane_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_plane_t *, inbox);
    if (!msg) return nullptr;
    return msg->payload;
}

typedef struct {
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *)  *xf;
    n00b_conduit_inbox_t(n00b_plane_t *)                    *inbox;
} hexdump_ctx_t;

static hexdump_ctx_t
setup_hexdump(n00b_conduit_t *c,
              n00b_conduit_topic_t(n00b_buffer_t *) *src,
              uint32_t width)
{
    auto r = n00b_conduit_hexdump_new(c, src, .width = width);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(n00b_buffer_t *, n00b_plane_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_plane_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_plane_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_plane_t *));
    n00b_conduit_inbox_init(n00b_plane_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_plane_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    return (hexdump_ctx_t){ .xf = xf, .inbox = inbox };
}

// ============================================================================
// Tests
// ============================================================================

static void
test_hexdump_xform_basic(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    hexdump_ctx_t ctx = setup_hexdump(c, src, 80);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // 32 bytes: at 80 col width, cpl=16, so 2 complete lines.
    uint8_t data[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8_t)i;

    push_buf(src, data, 32);
    usleep(150000);

    n00b_plane_t *plane = pop_plane(ctx.inbox);
    assert(plane != nullptr);
    assert(plane->height > 0);
    assert(plane->width > 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] hexdump xform basic\n");
}

static void
test_hexdump_xform_partial(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    hexdump_ctx_t ctx = setup_hexdump(c, src, 80);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Push 5 bytes (less than cpl) — should show a partial line.
    uint8_t data[5] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };
    push_buf(src, data, 5);
    usleep(150000);

    n00b_plane_t *plane = pop_plane(ctx.inbox);
    assert(plane != nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] hexdump xform partial\n");
}

static void
test_hexdump_xform_streaming(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    // width=80 -> cpl=16
    hexdump_ctx_t ctx = setup_hexdump(c, src, 80);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // First push: 5 bytes (partial line).
    uint8_t data1[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    push_buf(src, data1, 5);
    usleep(150000);

    n00b_plane_t *plane1 = pop_plane(ctx.inbox);
    assert(plane1 != nullptr);

    // Second push: 20 more bytes.
    // Total = 25. With cpl=16: 1 complete line (16 bytes) + partial (9 bytes).
    uint8_t data2[20];
    for (int i = 0; i < 20; i++) data2[i] = (uint8_t)(0x06 + i);
    push_buf(src, data2, 20);
    usleep(150000);

    n00b_plane_t *plane2 = pop_plane(ctx.inbox);
    assert(plane2 != nullptr);

    // After 25 bytes with cpl=16: 1 complete line, 1 partial (9 bytes).
    n00b_hexdump_xform_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_plane_t *, ctx.xf);
    assert(st->current_row == 1);
    assert(st->has_partial == true);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] hexdump xform streaming\n");
}

static void
test_hexdump_xform_empty(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    hexdump_ctx_t ctx = setup_hexdump(c, src, 80);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Push empty buffer — should produce no output.
    push_buf(src, (const uint8_t *)"", 0);
    usleep(150000);

    n00b_plane_t *plane = pop_plane(ctx.inbox);
    assert(plane == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] hexdump xform empty\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform_hexdump:\n");
    fflush(stdout);

    test_hexdump_xform_basic();      fflush(stdout);
    test_hexdump_xform_partial();    fflush(stdout);
    test_hexdump_xform_empty();      fflush(stdout);
    test_hexdump_xform_streaming();  fflush(stdout);

    printf("All hexdump transform tests passed.\n");
    n00b_shutdown();
    return 0;
}
