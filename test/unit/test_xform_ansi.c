/*
 * test_xform_ansi.c — Tests for the ANSI strip transform.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/xform_ansi_strip.h"
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

static char *
pop_str(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
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

// Helper to set up output subscription.
typedef struct {
    n00b_conduit_filter_t(n00b_buffer_t *)  *xf;
    n00b_conduit_inbox_t(n00b_buffer_t *)   *inbox;
} ansi_test_ctx_t;

static ansi_test_ctx_t
setup_ansi_strip(n00b_conduit_t *c, n00b_conduit_topic_t(n00b_buffer_t *) *src)
{
    auto r = n00b_conduit_ansi_strip_new(c, src);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(n00b_buffer_t *, n00b_buffer_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_buffer_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    return (ansi_test_ctx_t){ .xf = xf, .inbox = inbox };
}

// ============================================================================
// Tests
// ============================================================================

static void
test_plain_text_passthrough(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    ansi_test_ctx_t ctx = setup_ansi_strip(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "hello world", 11);
    usleep(50000);

    char *out = pop_str(ctx.inbox);
    assert(out != nullptr);
    assert(strcmp(out, "hello world") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] plain text passthrough\n");
}

static void
test_strip_sgr(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    ansi_test_ctx_t ctx = setup_ansi_strip(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    // Bold "hi" then reset.
    push_buf(src, "\033[1mhi\033[0m", 10);
    usleep(50000);

    char *out = pop_str(ctx.inbox);
    assert(out != nullptr);
    assert(strcmp(out, "hi") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] strip SGR sequences\n");
}

static void
test_strip_csi_cursor(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    ansi_test_ctx_t ctx = setup_ansi_strip(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    // Cursor up 2 + text.
    push_buf(src, "\033[2Ahello", 9);
    usleep(50000);

    char *out = pop_str(ctx.inbox);
    assert(out != nullptr);
    assert(strcmp(out, "hello") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] strip CSI cursor sequences\n");
}

static void
test_preserve_newlines(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    ansi_test_ctx_t ctx = setup_ansi_strip(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "\033[31mhello\n\033[32mworld\t!\033[0m", 26);
    usleep(50000);

    char *out = pop_str(ctx.inbox);
    assert(out != nullptr);
    assert(strcmp(out, "hello\nworld\t!") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] preserve newlines and tabs\n");
}

static void
test_empty_input(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);
    ansi_test_ctx_t ctx = setup_ansi_strip(c, src);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "", 0);
    usleep(30000);

    assert(pop_str(ctx.inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)ctx.xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] empty input\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform_ansi:\n");
    fflush(stdout);

    test_plain_text_passthrough(); fflush(stdout);
    test_strip_sgr();              fflush(stdout);
    test_strip_csi_cursor();       fflush(stdout);
    test_preserve_newlines();      fflush(stdout);
    test_empty_input();            fflush(stdout);

    printf("All ANSI strip tests passed.\n");
    n00b_shutdown();
    return 0;
}
