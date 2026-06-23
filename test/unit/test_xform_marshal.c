#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/xform_marshal.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"
#include "util/marshal.h"

#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}

typedef struct xmarshal_node_t {
    uint64_t                tag;
    uint64_t                scalar;
    struct xmarshal_node_t *next;
    struct xmarshal_node_t *alias;
} xmarshal_node_t;

typedef struct {
    n00b_arena_t    *arena;
    _Atomic uint32_t run;
    _Atomic uint32_t done;
    _Atomic uint32_t collections;
    uint32_t         delay_iters;
} gc_request_t;

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static xmarshal_node_t *
make_pair(n00b_arena_t *arena)
{
    xmarshal_node_t *a = n00b_alloc_with_opts(xmarshal_node_t, ARENA_OPTS(arena));
    xmarshal_node_t *b = n00b_alloc_with_opts(xmarshal_node_t, ARENA_OPTS(arena));

    a->tag    = 1;
    a->scalar = 10;
    a->next   = b;
    a->alias  = b;

    b->tag    = 2;
    b->scalar = 20;
    b->next   = a;
    b->alias  = b;

    return a;
}

static xmarshal_node_t *
make_chain(n00b_arena_t *arena, uint32_t count)
{
    xmarshal_node_t *head = nullptr;
    xmarshal_node_t *prev = nullptr;

    for (uint32_t i = 0; i < count; i++) {
        xmarshal_node_t *node = n00b_alloc_with_opts(xmarshal_node_t,
                                                     ARENA_OPTS(arena));
        node->tag    = 100 + i;
        node->scalar = 100000 + (count - i);
        node->next   = nullptr;
        node->alias  = head;

        if (!head) head = node;
        if (prev) prev->next = node;
        prev = node;
    }

    if (head && prev) prev->alias = head;
    return head;
}

static void
assert_pair_copy(xmarshal_node_t *copy)
{
    assert(copy != nullptr);
    assert(copy->tag == 1);
    assert(copy->scalar == 10);
    assert(copy->next != nullptr);
    assert(copy->next == copy->alias);
    assert(copy->next->tag == 2);
    assert(copy->next->scalar == 20);
    assert(copy->next->next == copy);
    assert(copy->next->alias == copy->next);
}

static void
init_object_topic(n00b_conduit_topic_t(n00b_marshal_object_t) *topic)
{
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_marshal_object_t) *,
                      .allocator = topic->conduit->allocator);
    topic->inbox = nullptr;
}

static void
init_buffer_topic(n00b_conduit_topic_t(n00b_buffer_t *) *topic)
{
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *,
                      .allocator = topic->conduit->allocator);
    topic->inbox = nullptr;
}

static n00b_conduit_topic_t(n00b_marshal_object_t) *
make_object_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 1;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri = N00B_CONDUIT_URI_USER_EVENT(id);

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_marshal_object_t)));
    assert(n00b_result_is_ok(tr));

    n00b_conduit_topic_t(n00b_marshal_object_t) *topic =
        (n00b_conduit_topic_t(n00b_marshal_object_t) *)n00b_result_get(tr);
    init_object_topic(topic);
    return topic;
}

static n00b_conduit_topic_t(n00b_buffer_t *) *
make_buffer_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 1000;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri = N00B_CONDUIT_URI_USER_EVENT(id);

    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_buffer_t *)));
    assert(n00b_result_is_ok(tr));

    n00b_conduit_topic_t(n00b_buffer_t *) *topic =
        (n00b_conduit_topic_t(n00b_buffer_t *) *)n00b_result_get(tr);
    init_buffer_topic(topic);
    return topic;
}

static n00b_conduit_inbox_t(n00b_buffer_t *) *
subscribe_buffer(n00b_conduit_t *c,
                 n00b_conduit_topic_t(n00b_buffer_t *) *topic)
{
    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                             ARENA_OPTS(c->allocator));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_buffer_t *, topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);
    return inbox;
}

static n00b_conduit_inbox_t(n00b_marshal_object_t) *
subscribe_object(n00b_conduit_t *c,
                 n00b_conduit_topic_t(n00b_marshal_object_t) *topic)
{
    n00b_conduit_inbox_t(n00b_marshal_object_t) *inbox =
        n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_marshal_object_t),
                             ARENA_OPTS(c->allocator));
    n00b_conduit_inbox_init(n00b_marshal_object_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_marshal_object_t, topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);
    return inbox;
}

static void
wait_marshal_running(
    n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *xf)
{
    while (!n00b_atomic_load(&xf->running)) {
        usleep(100);
    }
}

static void
wait_unmarshal_running(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf)
{
    while (!n00b_atomic_load(&xf->running)) {
        usleep(100);
    }
}

static void
wait_unmarshal_incomplete(
    n00b_conduit_xform_t(n00b_buffer_t *, n00b_marshal_object_t) *xf)
{
    for (uint32_t i = 0; i < 100000; i++) {
        n00b_marshal_status_t status = n00b_conduit_unmarshal_status(xf);
        if (status == N00B_MARSHAL_ERR_INCOMPLETE_STREAM) return;
        if (status != N00B_MARSHAL_OK) break;

        usleep(100);
    }

    n00b_string_t *err = n00b_conduit_unmarshal_error(xf);
    fprintf(stderr,
            "unmarshal transform did not reach incomplete status: status=%d "
            "error=%s inbox=%u running=%d\n",
            n00b_conduit_unmarshal_status(xf),
            err ? err->data : "(null)",
            n00b_conduit_inbox_msg_count(n00b_buffer_t *, xf->inbox),
            n00b_atomic_load(&xf->running));
    assert(false);
}

static void
publish_object(n00b_conduit_topic_t(n00b_marshal_object_t) *topic,
               n00b_marshal_object_t object)
{
    n00b_conduit_message_t(n00b_marshal_object_t) *msg =
        n00b_alloc(n00b_conduit_message_t(n00b_marshal_object_t));
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = object;
    n00b_conduit_topic_deliver_msg(n00b_marshal_object_t, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static void
publish_buffer(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
               n00b_buffer_t *buffer)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_alloc(n00b_conduit_message_t(n00b_buffer_t *));
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = buffer;
    n00b_conduit_topic_deliver_msg(n00b_buffer_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static void
close_object_topic(n00b_conduit_topic_t(n00b_marshal_object_t) *topic)
{
    n00b_conduit_topic_deliver_sys(n00b_marshal_object_t, topic,
        N00B_CONDUIT_MSG_TOPIC_CLOSED, N00B_CONDUIT_OP_ALL);
}

static void
close_buffer_topic(n00b_conduit_topic_t(n00b_buffer_t *) *topic)
{
    n00b_conduit_topic_deliver_sys(n00b_buffer_t *, topic,
        N00B_CONDUIT_MSG_TOPIC_CLOSED, N00B_CONDUIT_OP_ALL);
}

static n00b_buffer_t *
buffer_slice(n00b_buffer_t *buf, int64_t start, int64_t len)
{
    _n00b_buffer_rlock(buf);
    n00b_buffer_t *result = n00b_buffer_from_bytes(buf->data + start, len);
    _n00b_buffer_unlock(buf);
    return result;
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

static void
wait_gc_done(gc_request_t *request, n00b_thread_t *thread)
{
    for (uint32_t i = 0; i < 300000 && !atomic_load(&request->done); i++) {
        usleep(100);
    }

    if (!atomic_load(&request->done)) {
        fprintf(stderr,
                "gc request did not complete: run=%u done=%u collections=%u\n",
                atomic_load(&request->run),
                atomic_load(&request->done),
                atomic_load(&request->collections));
        assert(false);
    }

    n00b_thread_join(thread);
    assert(atomic_load(&request->collections) == 1);
}

static void
wait_marshal_inbox_empty(
    n00b_conduit_xform_t(n00b_marshal_object_t, n00b_buffer_t *) *xf)
{
    for (uint32_t i = 0;
         i < 300000
         && n00b_conduit_inbox_msg_count(n00b_marshal_object_t, xf->inbox) > 0;
         i++) {
        usleep(100);
    }

    uint32_t remaining = n00b_conduit_inbox_msg_count(n00b_marshal_object_t,
                                                      xf->inbox);
    if (remaining > 0) {
        fprintf(stderr,
                "marshal transform did not drain input: remaining=%u running=%d\n",
                remaining,
                n00b_atomic_load(&xf->running));
        assert(false);
    }
}

static void
test_one_shot_wrappers(void)
{
    n00b_arena_t *source = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_arena_t *target = n00b_new_arena(.size = 4096, .use_gc = true);
    xmarshal_node_t *src = make_pair(source);

    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x13572468u);
    if (!buf) {
        n00b_marshal_ctx_t *ctx = n00b_marshal_ctx_new(.base_address = 0x13572468u);
        (void)n00b_marshal_incremental(ctx, src);
        n00b_string_t *err = n00b_marshal_ctx_error(ctx);
        fprintf(stderr,
                "n00b_marshal wrapper failed: status=%d error=%s\n",
                n00b_marshal_ctx_status(ctx),
                err ? err->data : "(null)");
        n00b_marshal_ctx_destroy(ctx);
    }
    assert(buf != nullptr);
    assert(n00b_buffer_len(buf) > 0);

    n00b_list_t(void *) roots = n00b_unmarshal(buf, .target_arena = target);
    assert(n00b_list_len(roots) == 1);
    assert_pair_copy(n00b_list_get(roots, 0));

    xmarshal_node_t *one = n00b_unmarshal_one(buf, .target_arena = target);
    assert_pair_copy(one);

    printf("  [PASS] one_shot_wrappers\n");
}

static void
test_marshal_transform(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_arena_t  *source = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_arena_t  *target = n00b_new_arena(.size = 4096, .use_gc = true);
    xmarshal_node_t *src = make_pair(source);

    n00b_conduit_topic_t(n00b_marshal_object_t) *topic = make_object_topic(c);
    auto r = n00b_conduit_marshal_new(c, topic, .base_address = 0x24681357u);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    n00b_conduit_inbox_t(n00b_buffer_t *) *out = subscribe_buffer(
        c, n00b_conduit_xform_topic(n00b_marshal_object_t, n00b_buffer_t *, xf));

    wait_marshal_running(xf);
    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)topic);
    publish_object(topic, src);
    close_object_topic(topic);
    n00b_conduit_publish_yield(n00b_atomic_load(&topic->publisher));

    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);
    assert(n00b_conduit_marshal_status(xf) == N00B_MARSHAL_OK);

    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, out);
    assert(msg != nullptr);
    assert_pair_copy(n00b_unmarshal_one(msg->payload, .target_arena = target));

    n00b_conduit_destroy(c);
    printf("  [PASS] marshal_transform\n");
}

static void
test_unmarshal_transform_split(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_arena_t  *source = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_arena_t  *target = n00b_new_arena(.size = 4096, .use_gc = true);
    xmarshal_node_t *src = make_pair(source);
    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x11223344u);
    assert(buf != nullptr);

    int64_t len = n00b_buffer_len(buf);
    n00b_buffer_t *chunk1 = buffer_slice(buf, 0, 13);
    n00b_buffer_t *chunk2 = buffer_slice(buf, 13, len - 13);

    n00b_conduit_topic_t(n00b_buffer_t *) *topic = make_buffer_topic(c);
    auto r = n00b_conduit_unmarshal_new(c, topic, .target_arena = target);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    n00b_conduit_inbox_t(n00b_marshal_object_t) *out = subscribe_object(
        c, n00b_conduit_xform_topic(n00b_buffer_t *, n00b_marshal_object_t, xf));

    wait_unmarshal_running(xf);
    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)topic);
    publish_buffer(topic, chunk1);

    wait_unmarshal_incomplete(xf);

    publish_buffer(topic, chunk2);
    close_buffer_topic(topic);
    n00b_conduit_publish_yield(n00b_atomic_load(&topic->publisher));

    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);
    assert(n00b_conduit_unmarshal_status(xf) == N00B_MARSHAL_OK);

    n00b_conduit_message_t(n00b_marshal_object_t) *msg =
        n00b_conduit_inbox_pop_msg(n00b_marshal_object_t, out);
    assert(msg != nullptr);
    assert_pair_copy(msg->payload);

    n00b_conduit_destroy(c);
    printf("  [PASS] unmarshal_transform_split\n");
}

static void
test_marshal_unmarshal_chain(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_arena_t  *source = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_arena_t  *target = n00b_new_arena(.size = 4096, .use_gc = true);
    xmarshal_node_t *src = make_pair(source);

    n00b_conduit_topic_t(n00b_marshal_object_t) *topic = make_object_topic(c);
    auto mr = n00b_conduit_marshal_new(c, topic, .base_address = 0x55667788u);
    assert(n00b_result_is_ok(mr));
    auto mxf = n00b_result_get(mr);

    auto ur = n00b_conduit_unmarshal_new(
        c,
        n00b_conduit_xform_topic(n00b_marshal_object_t, n00b_buffer_t *, mxf),
        .target_arena = target);
    assert(n00b_result_is_ok(ur));
    auto uxf = n00b_result_get(ur);

    n00b_conduit_inbox_t(n00b_marshal_object_t) *out = subscribe_object(
        c, n00b_conduit_xform_topic(n00b_buffer_t *, n00b_marshal_object_t, uxf));

    wait_marshal_running(mxf);
    wait_unmarshal_running(uxf);
    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)topic);
    publish_object(topic, src);
    close_object_topic(topic);
    n00b_conduit_publish_yield(n00b_atomic_load(&topic->publisher));

    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)mxf);
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)uxf);
    assert(n00b_conduit_marshal_status(mxf) == N00B_MARSHAL_OK);
    assert(n00b_conduit_unmarshal_status(uxf) == N00B_MARSHAL_OK);

    n00b_conduit_message_t(n00b_marshal_object_t) *msg =
        n00b_conduit_inbox_pop_msg(n00b_marshal_object_t, out);
    assert(msg != nullptr);
    assert_pair_copy(msg->payload);

    n00b_conduit_destroy(c);
    printf("  [PASS] marshal_unmarshal_chain\n");
}

static void
test_marshal_transform_gc_pressure(void)
{
    enum { NODE_COUNT = 5000 };

    n00b_conduit_t *c = make_conduit();
    n00b_arena_t  *source = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_arena_t  *target = n00b_new_arena(.size = 4096, .use_gc = true);
    xmarshal_node_t *src = make_chain(source, NODE_COUNT);
    n00b_gc_register_root(src);

    n00b_conduit_topic_t(n00b_marshal_object_t) *topic = make_object_topic(c);
    auto r = n00b_conduit_marshal_new(c,
                                      topic,
                                      .flags        = N00B_MARSHAL_F_STW,
                                      .base_address = 0x31415926u);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);
    n00b_conduit_inbox_t(n00b_buffer_t *) *out = subscribe_buffer(
        c, n00b_conduit_xform_topic(n00b_marshal_object_t, n00b_buffer_t *, xf));

    wait_marshal_running(xf);

    gc_request_t   request;
    n00b_thread_t *gc_thread = start_gc_request(&request, source, 0);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)topic);
    publish_object(topic, src);
    wait_marshal_inbox_empty(xf);
    atomic_store(&request.run, 1);
    close_object_topic(topic);
    n00b_conduit_publish_yield(n00b_atomic_load(&topic->publisher));

    wait_gc_done(&request, gc_thread);
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);
    assert(n00b_conduit_marshal_status(xf) == N00B_MARSHAL_OK);

    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, out);
    assert(msg != nullptr);

    xmarshal_node_t *copy = n00b_unmarshal_one(msg->payload, .target_arena = target);
    assert(copy != nullptr);
    assert(copy->tag == 100);
    assert(copy->next != nullptr);
    assert(copy->next->tag == 101);

    n00b_gc_unregister_root(src);
    n00b_conduit_destroy(c);
    printf("  [PASS] marshal_transform_gc_pressure\n");
}

static void
test_unmarshal_transform_gc_pressure(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_arena_t  *source = n00b_new_arena(.size = 4096, .use_gc = true);
    n00b_arena_t  *target = n00b_get_runtime()->default_arena;
    xmarshal_node_t *src = make_pair(source);
    n00b_buffer_t *buf = n00b_marshal(src, .base_address = 0x27182818u);
    assert(buf != nullptr);

    int64_t len = n00b_buffer_len(buf);
    n00b_buffer_t *chunk1 = buffer_slice(buf, 0, 29);
    n00b_buffer_t *chunk2 = buffer_slice(buf, 29, len - 29);

    n00b_conduit_topic_t(n00b_buffer_t *) *topic = make_buffer_topic(c);
    auto r = n00b_conduit_unmarshal_new(c, topic, .target_arena = target);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);
    n00b_conduit_inbox_t(n00b_marshal_object_t) *out = subscribe_object(
        c, n00b_conduit_xform_topic(n00b_buffer_t *, n00b_marshal_object_t, xf));

    wait_unmarshal_running(xf);
    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)topic);
    publish_buffer(topic, chunk1);

    wait_unmarshal_incomplete(xf);

    gc_request_t   request;
    n00b_thread_t *gc_thread = start_gc_request(&request, target, 0);
    atomic_store(&request.run, 1);
    wait_gc_done(&request, gc_thread);

    publish_buffer(topic, chunk2);
    close_buffer_topic(topic);
    n00b_conduit_publish_yield(n00b_atomic_load(&topic->publisher));

    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);
    assert(n00b_conduit_unmarshal_status(xf) == N00B_MARSHAL_OK);

    n00b_conduit_message_t(n00b_marshal_object_t) *msg =
        n00b_conduit_inbox_pop_msg(n00b_marshal_object_t, out);
    assert(msg != nullptr);
    assert_pair_copy(msg->payload);

    n00b_conduit_destroy(c);
    printf("  [PASS] unmarshal_transform_gc_pressure\n");
}

int
main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running marshal conduit transform tests...\n");
    test_one_shot_wrappers();
    test_marshal_transform();
    test_unmarshal_transform_split();
    test_marshal_unmarshal_chain();
    test_marshal_transform_gc_pressure();
    test_unmarshal_transform_gc_pressure();
    printf("All marshal conduit transform tests passed.\n");

    n00b_shutdown();
    return 0;
}
