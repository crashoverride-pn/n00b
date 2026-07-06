/* src/util/queue.c — broker-neutral queue + fake (in-process FIFO)
 * backend.
 *
 * The vtable indirection keeps consumers backend-agnostic while
 * letting downstream substrate libraries (libn00b_aws) drop in real
 * SQS / SNS-into-SQS backends through the same surface.
 *
 * Fake backend semantics:
 *   - One mutex guards the pending-entries list.
 *   - Each receive marks the entries it returns as "in-flight" by
 *     setting `visible_at_ms = now + visibility_seconds * 1000`.
 *     Subsequent receives skip not-yet-visible entries.
 *   - Long-poll is approximated: when the visible set is empty the
 *     call polls every 50 ms until either a message becomes visible
 *     or @p wait_seconds elapses.
 *   - `delete` removes by receipt handle; `change_visibility` resets
 *     the deadline.
 */

#include "n00b.h"
#include "util/queue.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/atomic.h"
#include "core/mutex.h"
#include "core/platform.h"
#include "core/string.h"
#include "adt/list.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"

struct n00b_queue_t {
    const n00b_queue_vtable_t *vtable;
    void                      *self;
};

n00b_queue_t *
n00b_queue_new_backend(const n00b_queue_vtable_t *vtable, void *self) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!vtable) {
        return nullptr;
    }
    n00b_queue_t *q = n00b_alloc(n00b_queue_t, N00B_ALLOC_OPTS(allocator));
    q->vtable = vtable;
    q->self   = self;
    return q;
}

int
n00b_queue_receive_batch(n00b_queue_t         *q,
                         int                   max_messages,
                         int                   wait_seconds,
                         int                   visibility_seconds,
                         n00b_queue_message_t *out,
                         int                  *out_count)
{
    if (out_count) { *out_count = 0; }
    if (!q || !q->vtable || !q->vtable->receive_batch) {
        return -1;
    }
    return q->vtable->receive_batch(q->self,
                                    max_messages,
                                    wait_seconds,
                                    visibility_seconds,
                                    out,
                                    out_count);
}

int
n00b_queue_delete(n00b_queue_t *q, n00b_string_t *receipt_handle)
{
    if (!q || !q->vtable || !q->vtable->delete_one) {
        return -1;
    }
    return q->vtable->delete_one(q->self, receipt_handle);
}

int
n00b_queue_change_visibility(n00b_queue_t  *q,
                             n00b_string_t *receipt_handle,
                             int            seconds)
{
    if (!q || !q->vtable || !q->vtable->change_visibility) {
        return -1;
    }
    return q->vtable->change_visibility(q->self, receipt_handle, seconds);
}

int
n00b_queue_send(n00b_queue_t *q, n00b_string_t *body)
{
    if (!q || !q->vtable || !q->vtable->send) {
        return -1;
    }
    return q->vtable->send(q->self, body);
}

int
n00b_queue_enqueue_fake(n00b_queue_t *q, n00b_string_t *body)
{
    if (!q || !q->vtable || !q->vtable->enqueue_fake) {
        return -1;
    }
    return q->vtable->enqueue_fake(q->self, body);
}

size_t
n00b_queue_pending_count(n00b_queue_t *q)
{
    if (!q || !q->vtable || !q->vtable->pending_count) {
        return 0;
    }
    return q->vtable->pending_count(q->self);
}

/* =========================================================================
 * Fake backend
 * ========================================================================= */

typedef struct fake_entry {
    n00b_string_t *receipt_handle;
    n00b_string_t *body;
    uint32_t       receive_count;
    uint64_t       visible_at_ms;
} fake_entry_t;

typedef struct {
    n00b_mutex_t                lock;
    n00b_list_t(fake_entry_t *) pending;
    _Atomic uint64_t            next_id;
} fake_state_t;

static n00b_string_t *
fake_new_receipt(fake_state_t *s)
{
    uint64_t id = n00b_atomic_add(&s->next_id, 1) + 1;
    return n00b_cformat("fake-[|#|]", (int64_t)id);
}

static int
fake_send(void *self, n00b_string_t *body);

static int
fake_enqueue(void *self, n00b_string_t *body)
{
    fake_state_t *s = self;
    n00b_mutex_lock(&s->lock);
    fake_entry_t *e   = n00b_alloc(fake_entry_t);
    e->receipt_handle = fake_new_receipt(s);
    e->body           = body;
    e->receive_count  = 0;
    e->visible_at_ms  = 0;
    n00b_list_push(s->pending, e);
    n00b_mutex_unlock(&s->lock);
    return 0;
}

static size_t
fake_pending_count(void *self)
{
    fake_state_t *s = self;
    n00b_mutex_lock(&s->lock);
    size_t n = (size_t)n00b_list_len(s->pending);
    n00b_mutex_unlock(&s->lock);
    return n;
}

static int
fake_receive_batch(void                 *self,
                   int                   max_messages,
                   int                   wait_seconds,
                   int                   visibility_seconds,
                   n00b_queue_message_t *out,
                   int                  *out_count)
{
    if (out_count) { *out_count = 0; }
    if (!out || max_messages <= 0) {
        return 0;
    }
    fake_state_t *s = self;
    uint64_t deadline_ms = base_monotonic_ms()
                         + (uint64_t)(wait_seconds > 0 ? wait_seconds : 0) * 1000;

    for (;;) {
        n00b_mutex_lock(&s->lock);
        uint64_t now_ms = base_monotonic_ms();
        int      taken  = 0;
        size_t   n      = (size_t)n00b_list_len(s->pending);
        for (size_t i = 0; i < n && taken < max_messages; i++) {
            fake_entry_t *e = n00b_list_get(s->pending, i);
            if (!e || e->visible_at_ms > now_ms) {
                continue;
            }
            e->receive_count += 1;
            e->visible_at_ms  = now_ms
                              + (uint64_t)(visibility_seconds > 0
                                              ? visibility_seconds
                                              : 0) * 1000;
            out[taken].body           = e->body;
            out[taken].receipt_handle = e->receipt_handle;
            out[taken].receive_count  = e->receive_count;
            taken += 1;
        }
        n00b_mutex_unlock(&s->lock);

        if (taken > 0 || wait_seconds <= 0) {
            if (out_count) { *out_count = taken; }
            return 0;
        }
        if (base_monotonic_ms() >= deadline_ms) {
            return 0;
        }
        base_nanosleep_ns(50ULL * 1000ULL * 1000ULL);
    }
}

static int
fake_find_locked(fake_state_t *s, n00b_string_t *receipt)
{
    size_t n = (size_t)n00b_list_len(s->pending);
    for (size_t i = 0; i < n; i++) {
        fake_entry_t *e = n00b_list_get(s->pending, i);
        if (e && n00b_unicode_str_eq(e->receipt_handle, receipt)) {
            return (int)i;
        }
    }
    return -1;
}

static int
fake_delete_one(void *self, n00b_string_t *receipt)
{
    if (!receipt) { return -1; }
    fake_state_t *s = self;
    n00b_mutex_lock(&s->lock);
    int idx = fake_find_locked(s, receipt);
    if (idx >= 0) {
        (void)n00b_list_delete(s->pending, (size_t)idx);
    }
    n00b_mutex_unlock(&s->lock);
    return idx >= 0 ? 0 : 1;
}

static int
fake_change_visibility(void *self, n00b_string_t *receipt, int seconds)
{
    if (!receipt) { return -1; }
    fake_state_t *s = self;
    n00b_mutex_lock(&s->lock);
    int idx = fake_find_locked(s, receipt);
    if (idx >= 0) {
        fake_entry_t *e = n00b_list_get(s->pending, (size_t)idx);
        e->visible_at_ms = base_monotonic_ms()
                         + (uint64_t)(seconds > 0 ? seconds : 0) * 1000;
    }
    n00b_mutex_unlock(&s->lock);
    return idx >= 0 ? 0 : 1;
}

static int
fake_send(void *self, n00b_string_t *body)
{
    return fake_enqueue(self, body);
}

static const n00b_queue_vtable_t fake_vtable = {
    .receive_batch     = fake_receive_batch,
    .delete_one        = fake_delete_one,
    .change_visibility = fake_change_visibility,
    .send              = fake_send,
    .enqueue_fake      = fake_enqueue,
    .pending_count     = fake_pending_count,
};

n00b_queue_t *
n00b_queue_new_fake() _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    fake_state_t *s = n00b_alloc(fake_state_t, N00B_ALLOC_OPTS(allocator));
    n00b_mutex_init(&s->lock);
    s->pending  = n00b_list_new_private(fake_entry_t *);
    atomic_init(&s->next_id, 1);
    return n00b_queue_new_backend(&fake_vtable, s, .allocator = allocator);
}
