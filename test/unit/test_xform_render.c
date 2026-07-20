/*
 * test_xform_render.c — Tests for the render pipeline transforms.
 *
 * render_out: n00b_plane_t * -> n00b_buffer_t *
 * render_in:  n00b_buffer_t * -> n00b_plane_t *
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/xform_render.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/atomic.h"
#include "core/thread.h"

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
    static _Atomic(uint64_t) next_id = 1;
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

static n00b_conduit_topic_t(n00b_plane_t *) *
make_plane_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 1000;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri =
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, id);
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_plane_t *)));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_plane_t *) *topic =
        (n00b_conduit_topic_t(n00b_plane_t *) *)
            n00b_result_get(tr);
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_plane_t *) *);
    topic->inbox = nullptr;
    return topic;
}

static void
push_buf(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
         const char *data, size_t len)
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

static void
push_plane(n00b_conduit_topic_t(n00b_plane_t *) *topic,
           n00b_plane_t *plane)
{
    n00b_conduit_message_t(n00b_plane_t *) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(n00b_plane_t *),
            &(n00b_alloc_opts_t){.allocator =
                ((n00b_conduit_topic_base_t *)topic)->conduit->allocator});
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = plane;
    n00b_conduit_topic_deliver_msg(n00b_plane_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static char *
pop_buf_str(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    if (!msg) return nullptr;
    int64_t len = 0;
    char *data = n00b_buffer_to_c(msg->payload, &len);
    char *out = n00b_alloc_array(char, (size_t)len + 1);
    memcpy(out, data, (size_t)len);
    out[len] = '\0';
    return out;
}

static n00b_plane_t *
pop_plane(n00b_conduit_inbox_t(n00b_plane_t *) *inbox)
{
    n00b_conduit_message_t(n00b_plane_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_plane_t *, inbox);
    if (!msg) return nullptr;
    return msg->payload;
}

// Setup helpers returning the xform and a subscribed inbox.

typedef struct {
    n00b_conduit_xform_t(n00b_plane_t *, n00b_buffer_t *)  *xf;
    n00b_conduit_inbox_t(n00b_buffer_t *)                  *inbox;
} render_out_ctx_t;

static render_out_ctx_t
setup_render_out(n00b_conduit_t *c,
                 n00b_conduit_topic_t(n00b_plane_t *) *src)
{
    auto r = n00b_conduit_render_out_new(c, src,
        .width = 80, .height = 25);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(n00b_plane_t *, n00b_buffer_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_buffer_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    return (render_out_ctx_t){ .xf = xf, .inbox = inbox };
}

typedef struct {
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_plane_t *)  *xf;
    n00b_conduit_inbox_t(n00b_plane_t *)                   *inbox;
} render_in_ctx_t;

static render_in_ctx_t
setup_render_in(n00b_conduit_t *c,
                n00b_conduit_topic_t(n00b_buffer_t *) *src)
{
    auto r = n00b_conduit_render_in_new(c, src,
        .width = 80, .height = 25);
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

    return (render_in_ctx_t){ .xf = xf, .inbox = inbox };
}

// ============================================================================
// Tests
// ============================================================================

static void
test_render_out_basic(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_plane_t *) *src = make_plane_topic(c);
    render_out_ctx_t ctx = setup_render_out(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t, plane);
    plane->width = 80;
    plane->height = 25;
    n00b_string_t *str = n00b_string_from_raw("Hello", 5);
    n00b_plane_draw_text(plane, 0, 0, str);

    push_plane(src, plane);
    usleep(100000);

    char *out = pop_buf_str(ctx.inbox);
    assert(out != nullptr);
    assert(strstr(out, "Hello") != nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] render_out basic\n");
}

static void
test_render_out_multiline(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_plane_t *) *src = make_plane_topic(c);
    render_out_ctx_t ctx = setup_render_out(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    n00b_plane_t *plane = n00b_new_kargs(n00b_plane_t, plane);
    plane->width = 80;
    plane->height = 25;
    n00b_string_t *line1 = n00b_string_from_raw("Line1", 5);
    n00b_plane_draw_text(plane, 0, 0, line1);
    int32_t lh = n00b_plane_line_height(plane, nullptr);
    n00b_string_t *line2 = n00b_string_from_raw("Line2", 5);
    n00b_plane_draw_text(plane, 0, lh, line2);

    push_plane(src, plane);
    usleep(100000);

    char *out = pop_buf_str(ctx.inbox);
    assert(out != nullptr);
    assert(strstr(out, "Line1") != nullptr);
    assert(strstr(out, "Line2") != nullptr);
    // Stream backend separates rows with newlines.
    assert(strstr(out, "\n") != nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] render_out multiline\n");
}

static void
test_render_out_null_plane(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_plane_t *) *src = make_plane_topic(c);
    render_out_ctx_t ctx = setup_render_out(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    push_plane(src, nullptr);
    usleep(100000);

    // Null plane => option_none => no output message.
    assert(pop_buf_str(ctx.inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] render_out null plane\n");
}

static void
test_render_in_basic(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    render_in_ctx_t ctx = setup_render_in(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    push_buf(src, "Hello", 5);
    usleep(100000);

    n00b_plane_t *plane = pop_plane(ctx.inbox);
    assert(plane != nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] render_in basic\n");
}

static void
test_render_in_empty(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    render_in_ctx_t ctx = setup_render_in(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    push_buf(src, "", 0);
    usleep(100000);

    // Empty buffer => option_none => no output.
    assert(pop_plane(ctx.inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] render_in empty\n");
}

static void
test_round_trip(void)
{
    n00b_conduit_t *c = make_conduit();

    // Stage 1: buffer -> render_in -> plane
    n00b_conduit_topic_t(n00b_buffer_t *) *buf_src = make_buf_topic(c);
    render_in_ctx_t in_ctx = setup_render_in(c, buf_src);

    // Stage 2: plane -> render_out -> buffer
    auto plane_topic = n00b_conduit_xform_topic(
        n00b_buffer_t *, n00b_plane_t *, in_ctx.xf);

    auto r = n00b_conduit_render_out_new(c, plane_topic,
        .width = 80, .height = 25);
    assert(n00b_result_is_ok(r));
    auto out_xf = n00b_result_get(r);

    auto buf_out = n00b_conduit_xform_topic(
        n00b_plane_t *, n00b_buffer_t *, out_xf);
    buf_out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    buf_out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_buffer_t *) *final_inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, final_inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_buffer_t *, buf_out, final_inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)buf_src);

    push_buf(buf_src, "RoundTrip", 9);
    usleep(200000);

    char *out = pop_buf_str(final_inbox);
    assert(out != nullptr);
    assert(strstr(out, "RoundTrip") != nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)out_xf);
    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)in_ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] round trip (buf->plane->buf)\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform_render:\n");
    fflush(stdout);

    test_render_out_basic();       fflush(stdout);
    test_render_out_multiline();   fflush(stdout);
    test_render_out_null_plane();  fflush(stdout);
    test_render_in_basic();        fflush(stdout);
    test_render_in_empty();        fflush(stdout);
    test_round_trip();             fflush(stdout);

    printf("All render transform tests passed.\n");
    n00b_shutdown();
    return 0;
}
