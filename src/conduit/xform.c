/*
 * xform.c — Transform lifecycle functions and chain API.
 */

#include "conduit/xform.h"
#include "core/thread.h"
#include "core/atomic.h"
#include "core/gc.h"
#include "core/runtime.h"

#include <unistd.h>

void
n00b_conduit_xform_stop(n00b_conduit_xform_base_t *xf)
{
    if (!xf) return;
    n00b_atomic_store(&xf->stop_requested, true);
}

void
n00b_conduit_xform_join(n00b_conduit_xform_base_t *xf)
{
    if (!xf || !xf->thread) return;
    n00b_thread_join(xf->thread);
}

void
n00b_conduit_xform_destroy(n00b_conduit_xform_base_t *xf)
{
    if (!xf) return;

    // Always stop+join, even if running hasn't been set yet (race window).
    n00b_conduit_xform_stop(xf);
    n00b_conduit_xform_join(xf);
    if (xf->thread != nullptr) {
        n00b_gc_unregister_root(xf->thread);
        xf->thread = nullptr;
    }

    if (xf->upstream_sub) {
        n00b_conduit_sub_cancel(xf->upstream_sub);
    }

    if (xf->topic) {
        n00b_conduit_topic_close(xf->topic);
    }

    if (xf->cookie_size > 0 && xf->cookie != nullptr) {
        n00b_runtime_t *rt = n00b_get_runtime();
        if (rt == nullptr || !n00b_atomic_load(&rt->shutdown_started)) {
            _n00b_gc_unregister_root(&xf->cookie);
        }
        xf->cookie = nullptr;
    }
}

n00b_conduit_topic_base_t *
n00b_conduit_chain_from_specs(n00b_conduit_t                        *c,
                              n00b_conduit_topic_base_t             *source,
                              const n00b_conduit_xform_spec_base_t **specs,
                              size_t                                 count)
{
    if (!c || !source || !specs || count == 0) return nullptr;

    n00b_conduit_topic_base_t *upstream = source;

    for (size_t i = 0; i < count; i++) {
        if (!specs[i] || !specs[i]->create) return nullptr;

        n00b_conduit_xform_base_t *xf =
            specs[i]->create(c, upstream, specs[i]);
        if (!xf) return nullptr;

        upstream = xf->topic;
    }

    return upstream;
}
