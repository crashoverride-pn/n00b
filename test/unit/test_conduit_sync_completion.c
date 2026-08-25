#include <assert.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/rw.h"
#include "conduit/xform_types.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "core/thread.h"

enum {
    WRITER_COUNT      = 12,
    WRITES_PER_WRITER = 3000,
    MAX_CHURN_ROUNDS  = 8,
};

typedef struct {
    n00b_conduit_topic_t(n00b_buffer_t *) * topic;
    n00b_buffer_t     *payload;
    _Atomic(uint32_t) *failures;
} writer_args_t;

static void *
write_sync(void *raw)
{
    writer_args_t *args = raw;

    for (int i = 0; i < WRITES_PER_WRITER; i++) {
        auto result = n00b_conduit_write(n00b_buffer_t *,
                                         args->topic,
                                         args->payload,
                                         .timeout_ms = 5000);
        if (n00b_result_is_err(result)) {
            n00b_atomic_add(args->failures, 1);
        }
    }

    return nullptr;
}

static n00b_option_t(n00b_buffer_t *)
    drop_buffer(n00b_conduit_filter_t(n00b_buffer_t *) * filter, n00b_buffer_t *input)
{
    (void)filter;
    (void)input;
    return n00b_option_none(n00b_buffer_t *);
}

static n00b_string_t drop_kind = {
    .data       = "drop",
    .u8_bytes   = 4,
    .codepoints = 4,
    .styling    = nullptr,
};

static const n00b_conduit_filter_ops_t(n00b_buffer_t *) drop_ops = {
    .transform = drop_buffer,
    .kind      = &drop_kind,
};

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    auto conduit_result = n00b_conduit_new();
    assert(n00b_result_is_ok(conduit_result));
    n00b_conduit_t *conduit = n00b_result_get(conduit_result);

    n00b_conduit_topic_t(n00b_buffer_t *) *source
        = n00b_conduit_topic_init(n00b_buffer_t *,
                                  conduit,
                                  n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 1));
    assert(source != nullptr);

    auto filter_result
        = n00b_conduit_filter_new(n00b_buffer_t *, conduit, source, &drop_ops, 0);
    assert(n00b_result_is_ok(filter_result));
    n00b_conduit_filter_t(n00b_buffer_t *) *filter = n00b_result_get(filter_result);
    n00b_conduit_topic_t(n00b_buffer_t *) *output
        = n00b_conduit_xform_topic(n00b_buffer_t *, n00b_buffer_t *, filter);

    n00b_conduit_inbox_t(n00b_buffer_t *) *output_inbox
        = n00b_alloc_with_opts(n00b_conduit_inbox_t(n00b_buffer_t *),
                               &(n00b_alloc_opts_t){.allocator = conduit->allocator});
    n00b_conduit_inbox_init(n00b_buffer_t *,
                            output_inbox,
                            conduit,
                            N00B_CONDUIT_BP_UNBOUNDED,
                            0);
    n00b_conduit_inbox_set_no_notify(output_inbox, true);
    n00b_conduit_sub_handle_t output_sub
        = n00b_conduit_subscribe(n00b_buffer_t *, output, output_inbox);
    assert(output_sub != N00B_CONDUIT_INVALID_SUB_HANDLE);

    while (!n00b_atomic_load(&filter->running)) {
        usleep(100);
    }

    _Atomic(uint32_t) failures = 0;
    n00b_buffer_t    *payload  = n00b_buffer_from_bytes("x\n", 2);
    writer_args_t     args[WRITER_COUNT];
    n00b_thread_t    *writers[WRITER_COUNT];
    n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *done_topic = (n00b_conduit_topic_t(
        n00b_conduit_topic_base_t *) *)n00b_atomic_load(&source->done_topic);
    assert(done_topic != nullptr);

    for (int round = 0;
         round < MAX_CHURN_ROUNDS && n00b_atomic_load(&done_topic->sub_list_head) == nullptr;
         round++) {
        for (int i = 0; i < WRITER_COUNT; i++) {
            args[i] = (writer_args_t){
                .topic    = source,
                .payload  = payload,
                .failures = &failures,
            };
            auto spawn_result = n00b_thread_spawn(write_sync, &args[i]);
            assert(n00b_result_is_ok(spawn_result));
            writers[i] = n00b_result_get(spawn_result);
        }

        for (int i = 0; i < WRITER_COUNT; i++) {
            n00b_thread_join(writers[i]);
        }
    }

    assert(n00b_atomic_load(&failures) == 0);
    assert(n00b_atomic_load(&done_topic->sub_list_head) == nullptr);

    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)done_topic);
    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)filter);
    n00b_conduit_sub_cancel(output_sub);
    n00b_conduit_inbox_destroy(n00b_buffer_t *, output_inbox);
    n00b_free_with_allocator_hint(conduit->allocator, output_inbox);
    n00b_conduit_destroy(conduit);
    n00b_shutdown();

    return 0;
}
