/*
 * test_xform_linebuf.c — Tests for the line-buffering transform.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/xform_linebuf.h"
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

/*
 * Push a single buffer to a topic.  Caller must have claimed publisher.
 */
static void
push_buf(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
         const char *data, size_t len)
{
    // Conduit contract: a delivered message must be allocated from the
    // conduit's allocator (the conduit copies/drops/frees it with that
    // allocator as the free hint); plain n00b_alloc is a cross-pool free.
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
push_close(n00b_conduit_topic_t(n00b_buffer_t *) *topic)
{
    n00b_conduit_topic_deliver_sys(n00b_buffer_t *, topic,
        N00B_CONDUIT_MSG_TOPIC_CLOSED, N00B_CONDUIT_OP_ALL);
}

/*
 * Pop a buffer from an inbox, return data as a C string (null-terminated).
 * Returns nullptr if no message.
 */
static char *
pop_line(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    if (!msg) return nullptr;
    int64_t len = 0;
    char *data = n00b_buffer_to_c(msg->payload, &len);
    // Make a null-terminated copy.
    char *out = n00b_alloc_array(char, (size_t)len + 1);
    memcpy(out, data, (size_t)len);
    out[len] = '\0';
    return out;
}

// ============================================================================
// Tests
// ============================================================================

static void
test_single_line(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "hello\n", 6);
    usleep(50000);

    char *line = pop_line(inbox);
    assert(line != nullptr);
    assert(strcmp(line, "hello") == 0);

    // No more lines.
    assert(pop_line(inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] single line\n");
}

static void
test_multi_line(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "aaa\nbbb\nccc\n", 12);
    usleep(50000);

    assert(strcmp(pop_line(inbox), "aaa") == 0);
    assert(strcmp(pop_line(inbox), "bbb") == 0);
    assert(strcmp(pop_line(inbox), "ccc") == 0);
    assert(pop_line(inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] multi-line per input\n");
}

static void
test_split_across_inputs(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // First chunk: partial line.
    push_buf(src, "hel", 3);
    usleep(30000);
    assert(pop_line(inbox) == nullptr); // no complete line yet

    // Second chunk: completes the line.
    push_buf(src, "lo\n", 3);
    usleep(30000);
    assert(strcmp(pop_line(inbox), "hello") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] split across inputs\n");
}

static void
test_flush_partial(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Push partial data with no delimiter, then close.
    push_buf(src, "no-newline", 10);
    push_close(src);

    // Wait for xform to flush.
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    char *line = pop_line(inbox);
    assert(line != nullptr);
    assert(strcmp(line, "no-newline") == 0);

    n00b_conduit_destroy(c);
    printf("  [PASS] flush partial on close\n");
}

static void
test_max_line_len(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src, .max_line_len = 5);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "longline123\n", 12);
    usleep(50000);

    char *line = pop_line(inbox);
    assert(line != nullptr);
    assert(strlen(line) == 5);
    assert(strncmp(line, "longl", 5) == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] max_line_len truncation\n");
}

static void
test_custom_delimiter(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src, .delimiter = '|');
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "one|two|three|", 14);
    usleep(50000);

    assert(strcmp(pop_line(inbox), "one") == 0);
    assert(strcmp(pop_line(inbox), "two") == 0);
    assert(strcmp(pop_line(inbox), "three") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] custom delimiter\n");
}

static void
test_empty_input(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "", 0);
    usleep(30000);

    assert(pop_line(inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] empty input\n");
}

static void
test_include_delimiter(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_linebuf_new(c, src, .include_delimiter = true);
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

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    push_buf(src, "hello\n", 6);
    usleep(50000);

    char *line = pop_line(inbox);
    assert(line != nullptr);
    assert(strcmp(line, "hello\n") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] include delimiter\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform_linebuf:\n");
    fflush(stdout);

    test_single_line();       fflush(stdout);
    test_multi_line();        fflush(stdout);
    test_split_across_inputs(); fflush(stdout);
    test_flush_partial();     fflush(stdout);
    test_max_line_len();      fflush(stdout);
    test_custom_delimiter();  fflush(stdout);
    test_empty_input();       fflush(stdout);
    test_include_delimiter(); fflush(stdout);

    printf("All linebuf tests passed.\n");
    n00b_shutdown();
    return 0;
}
