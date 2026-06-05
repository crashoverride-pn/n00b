/*
 * rpc.c — n00b RPC runtime (Phase 4 § 4.6).
 *
 * Replaces the 4.5 abort-stubs with a real implementation:
 *
 *   - Process-wide service registry: a string-keyed dict mapping
 *     "service/method" to a (pattern, dispatcher fn) tuple.  Lazily
 *     initialized at first use (atomic-flag-guarded); populated by the
 *     constructors emitted by the @rpc-annotated TUs.
 *
 *   - Client side: `n00b_rpc_call_unary` opens a POST H3 request to
 *     /<full_method>, ships the CBOR body, awaits the response with
 *     a deadline derived from the ctx, decodes :status +
 *     n00b-rpc-status, and returns the response body buffer.
 *     Cancellation is wired via a watcher thread that blocks on the
 *     ctx's cancel futex and STOP_SENDINGs the request stream when
 *     the ctx flips.
 *
 *   - Server side: `n00b_rpc_attach_server` wraps an H3 server +
 *     conduit + an existing rpc_server_t handle and spins a worker
 *     thread that drains the H3 request topic, looks up the path in
 *     the registry, builds a per-call ctx (honoring the
 *     n00b-rpc-deadline-ms header), invokes the dispatcher, and
 *     emits the response (HEADERS + DATA + FIN with the right
 *     :status + n00b-rpc-status mapping).
 *
 *   - The streaming variants (server-stream, client-stream, bidi)
 *     remain abort-stubs in 4.6.  Those land in 4.7.
 *
 * Allocator discipline: every long-lived allocation goes through
 * `n00b_rpc_alloc()` (the runtime's conduit_pool, mirroring
 * n00b_h3_alloc).  Per-call scratch lives on the stack or in
 * tiny pool buffers freed implicitly by GC.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/hash.h"
#include "core/time.h"
#include "core/data_lock.h"
#include "core/mutex.h"
#include "core/futex.h"
#include "adt/dict_untyped.h"
#include "adt/llist.h"
#include "adt/result.h"
#include "conduit/conduit.h"
#include "conduit/inbox.h"
#include "conduit/topic.h"
#include "conduit/subscription.h"
#include "conduit/print.h"
#include "net/quic/quic_types.h"
#include "net/quic/conn.h"
#include "net/quic/chan.h"
#include "net/quic/endpoint.h"
#include "net/quic/h3.h"
#include "net/quic/h3_types.h"
#include "net/quic/cbor.h"
#include "net/quic/jwt.h"
#include "net/quic/auth_policy.h"
#include "net/quic/audit.h"
#include "net/quic/manifest.h"
#include "net/quic/rpc.h"
#include "net/quic/rpc_ctx.h"
#include "net/quic/rpc_status.h"
#include "internal/net/quic/h3_internal.h"

/* ===========================================================================
 * Allocator
 * =========================================================================== */

n00b_allocator_t *
n00b_rpc_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
rpc_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t n = strlen(s);
    char  *p = n00b_alloc_array_with_opts(char, (int64_t)(n + 1),
                    &(n00b_alloc_opts_t){
                        .allocator = n00b_rpc_alloc(),
                        .no_scan   = true,
                    });
    memcpy(p, s, n + 1);
    return p;
}

/* ===========================================================================
 * Service registry
 *
 * Single global dict, lazy-init.  Keys are conduit-pool-owned C
 * strings (so their lifetime exceeds the call site that registered
 * them).  Values are `rpc_entry_t *` (also conduit-pool-owned).
 * =========================================================================== */

typedef enum : uint8_t {
    RPC_PATTERN_UNARY         = 0,
    RPC_PATTERN_SERVER_STREAM = 1,
    RPC_PATTERN_CLIENT_STREAM = 2,
    RPC_PATTERN_BIDI          = 3,
} rpc_pattern_t;

typedef struct {
    rpc_pattern_t           pattern;
    /* Stored as opaque; callers cast to the per-pattern signature. */
    void                   *fn;
    n00b_string_t          *full_method;   /* conduit-pool-owned. */
} rpc_entry_t;

/* Typed registry: keys are `n00b_string_t *` (full method id),
 * values are `rpc_entry_t *`.  Converted from `n00b_dict_untyped_t`
 * to match the project's preferred typed-dict idiom (see
 * `src/slay/grammar.c`). */
/* Registry: dict-untyped (typed-dict tripped ncc parser when used \
 * with n00b_alloc_with_opts in a static global). Keys n00b_string_t *. */
static n00b_dict_untyped_t *rpc_registry = nullptr;

/* The registry mutex is `n00b_mutex_t` — futex-backed, integrates
 * with the per-thread lock chain.  It cannot be initialized before
 * `n00b_init` (the lock primitives read the runtime startup flag),
 * so we lazy-init on first use, guarded by an atomic flag.  All
 * actual `n00b_mutex_lock` sites are gated on `runtime_ready()`. */
static n00b_mutex_t         rpc_registry_mu;
static _Atomic uint32_t     rpc_registry_mu_inited;
static _Atomic uint32_t     rpc_registry_built;

/* Deferred registrations: ncc emits `__attribute__((constructor))`
 * registrars for every `@rpc(...)` annotation, which fire at process
 * load time — BEFORE `n00b_init()` builds the runtime that the
 * conduit_pool allocator depends on.  We park such registrations in a
 * `calloc`'d list (the n00b runtime allocator is not yet usable) and
 * replay them on first registry access from runtime context.
 *
 * No mutex covers `deferred_head`: linker-defined `__attribute__
 * ((constructor))` chains run sequentially on the main thread before
 * `main()`, so constructor-time appends are single-threaded.  After
 * runtime is up, the drain runs from a single thread (the first
 * registry caller); subsequent registrations bypass deferred and
 * go through the runtime registry directly. */
typedef struct deferred_reg {
    const char         *full_method;  /* Caller-owned string literal. */
    rpc_pattern_t       pattern;
    void               *fn;
    struct deferred_reg *next;
} deferred_reg_t;

static deferred_reg_t  *deferred_head = nullptr;

static void
ensure_registry_mu(void)
{
    /* States: 0 = uninit, 1 = initing, 2 = ready.  Only the CAS
     * winner runs the init, then bumps to 2 with release semantics
     * so peers that observe 2 see the fully-initialized mutex. */
    uint32_t state = atomic_load(&rpc_registry_mu_inited);
    if (state == 2) return;
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong(&rpc_registry_mu_inited,
                                       &expected, 1)) {
        n00b_mutex_init(&rpc_registry_mu);
        atomic_store(&rpc_registry_mu_inited, 2);
        return;
    }
    /* Lost the race: spin until the winner publishes 2. */
    while (atomic_load(&rpc_registry_mu_inited) != 2) {
        /* Tight spin; the init is microseconds. */
    }
}

static bool
runtime_ready(void)
{
    return n00b_option_is_set(n00b_default_runtime);
}

static void
defer_register(const char *full_method, rpc_pattern_t pattern, void *fn)
{
    /* Constructor phase, single-threaded: no lock required.
     * `calloc` rather than the n00b allocator because the runtime
     * is not yet up. */
    deferred_reg_t *d = (deferred_reg_t *)calloc(1, sizeof(*d));
    if (!d) return;
    d->full_method = full_method;  /* annotation strings are literals */
    d->pattern     = pattern;
    d->fn          = fn;
    d->next        = deferred_head;
    deferred_head  = d;
}

static void
register_method(const char    *full_method,
                rpc_pattern_t  pattern,
                void          *fn);

static void
drain_deferred_locked(void)
{
    /* Caller has the registry mutex held.  Constructor-time adds to
     * `deferred_head` are done before `main()` (single-threaded);
     * runtime-time adds go through the registry path directly.  So
     * we can detach the list with a plain pointer swap. */
    deferred_reg_t *d = deferred_head;
    deferred_head     = nullptr;

    while (d) {
        deferred_reg_t *next = d->next;
        register_method(d->full_method, d->pattern, d->fn);
        free(d);
        d = next;
    }
}

static void
rpc_registry_init(void)
{
    n00b_dict_untyped_t *dd = n00b_alloc_with_opts(
        n00b_dict_untyped_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    n00b_dict_untyped_init(dd,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .allocator     = n00b_rpc_alloc());
    rpc_registry = dd;
}

static n00b_dict_untyped_t *
registry(void)
{
    /* Lazy first-build of the registry dict + its mutex.  Both
     * require the n00b runtime/allocator; constructor-time callers
     * have already been parked in `deferred_head` by the
     * `runtime_ready()` gate in `register_method`. */
    if (atomic_load(&rpc_registry_built) == 0 && runtime_ready()) {
        ensure_registry_mu();
        n00b_mutex_lock(&rpc_registry_mu);
        if (atomic_load(&rpc_registry_built) == 0) {
            rpc_registry_init();
            atomic_store(&rpc_registry_built, 1);
            /* Replay constructor-parked registrations before any
             * runtime caller can race with the dict. */
            if (deferred_head) drain_deferred_locked();
        }
        n00b_mutex_unlock(&rpc_registry_mu);
    }
    return rpc_registry;
}

static void
register_method(const char    *full_method,
                rpc_pattern_t  pattern,
                void          *fn)
{
    if (!full_method || !fn) return;

    /* Pre-runtime: park the registration; replay after init. */
    if (!runtime_ready()) {
        defer_register(full_method, pattern, fn);
        return;
    }
    n00b_dict_untyped_t *d = registry();

    n00b_mutex_lock(&rpc_registry_mu);

    rpc_entry_t *e = n00b_alloc_with_opts(rpc_entry_t,
                        &(n00b_alloc_opts_t){
                            .allocator = n00b_rpc_alloc(),
                        });
    e->pattern     = pattern;
    e->fn          = fn;
    e->full_method = n00b_string_from_cstr(full_method);

    n00b_dict_untyped_put(d, e->full_method, e);

    n00b_mutex_unlock(&rpc_registry_mu);
}

static rpc_entry_t *
lookup_method(const char *full_method)
{
    if (!full_method) return nullptr;
    n00b_dict_untyped_t *d = registry();
    if (!d) return nullptr;

    n00b_string_t *key = n00b_string_from_cstr(full_method);
    n00b_mutex_lock(&rpc_registry_mu);
    bool         found = false;
    rpc_entry_t *v     = n00b_dict_untyped_get(d, key, &found);
    n00b_mutex_unlock(&rpc_registry_mu);

    return found ? v : nullptr;
}

/**
 * @brief Test-only registry reset.  Drops all registered methods so
 * a single process can re-register fresh handlers across sub-tests.
 * Not exposed in the public header; tests reach it via an extern
 * forward decl.
 */
void n00b_rpc_registry_reset_for_testing(void);

void
n00b_rpc_registry_reset_for_testing(void)
{
    ensure_registry_mu();
    n00b_mutex_lock(&rpc_registry_mu);
    /* Re-init the underlying dict in place: drop the old one (GC
     * will reclaim) and build a fresh one. */
    if (rpc_registry) {
        rpc_registry_init();
    }
    n00b_mutex_unlock(&rpc_registry_mu);
}

void
n00b_rpc_register(const char *full_method, n00b_rpc_dispatch_fn_t fn)
{
    register_method(full_method, RPC_PATTERN_UNARY, (void *)fn);
}

void
n00b_rpc_register_server_stream(const char                           *full_method,
                                n00b_rpc_server_stream_dispatch_fn_t  fn)
{
    register_method(full_method, RPC_PATTERN_SERVER_STREAM, (void *)fn);
}

void
n00b_rpc_register_client_stream(const char                           *full_method,
                                n00b_rpc_client_stream_dispatch_fn_t  fn)
{
    register_method(full_method, RPC_PATTERN_CLIENT_STREAM, (void *)fn);
}

void
n00b_rpc_register_bidi(const char                  *full_method,
                       n00b_rpc_bidi_dispatch_fn_t  fn)
{
    register_method(full_method, RPC_PATTERN_BIDI, (void *)fn);
}

/* ===========================================================================
 * Channel
 * =========================================================================== */

struct n00b_rpc_channel {
    n00b_h3_client_t *h3;          /**< Borrowed; outlives the channel. */
    char             *scheme;      /**< conduit-pool-owned. */
    char             *authority;   /**< conduit-pool-owned. */
    /* Auth (sub-phase 4.9) — all conduit-pool owned, may be null. */
    char             *auth_bearer;     /**< JWT for `authorization: Bearer …` */
    char             *auth_dpop;       /**< DPoP proof header value */
    char             *auth_policy_id;  /**< Value of `n00b-rpc-policy:` */
};

n00b_rpc_channel_t *
n00b_rpc_channel_new(n00b_rpc_channel_spec_t spec)
{
    return n00b_rpc_channel_new_raw(spec.h3,
                                    spec.scheme ? spec.scheme : "https",
                                    spec.authority);
}

n00b_rpc_channel_t *
n00b_rpc_channel_new_raw(n00b_h3_client_t *h3,
                         const char       *scheme,
                         const char       *authority)
{
    if (!h3 || !scheme || !authority) return nullptr;
    n00b_rpc_channel_t *c = n00b_alloc_with_opts(
        n00b_rpc_channel_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    c->h3        = h3;
    c->scheme    = rpc_strdup(scheme);
    c->authority = rpc_strdup(authority);
    return c;
}

n00b_h3_client_t *
n00b_rpc_channel_h3(n00b_rpc_channel_t *chan)
{
    return chan ? chan->h3 : nullptr;
}

void
n00b_rpc_channel_set_auth(n00b_rpc_channel_t                *chan,
                          const n00b_rpc_auth_credentials_t *creds,
                          const char                        *policy_id)
{
    if (!chan) return;
    /* Memset-zero on un-set is fine; conduit pool reclaims older
     * copies via GC.  Re-stamp every field — the call is the
     * setter, and a partial set would be confusing. */
    chan->auth_bearer    = (creds && creds->bearer_token)
                              ? rpc_strdup(creds->bearer_token) : nullptr;
    chan->auth_dpop      = (creds && creds->dpop_proof)
                              ? rpc_strdup(creds->dpop_proof) : nullptr;
    chan->auth_policy_id = policy_id ? rpc_strdup(policy_id) : nullptr;
}

/* ===========================================================================
 * Client unary call
 *
 * Wire shape (rpc_design.md § 2.1 + § 3):
 *   POST /<full_method>
 *   :scheme = chan->scheme
 *   :authority = chan->authority
 *   content-type: application/cbor
 *   n00b-rpc-deadline-ms: <abs ms unix epoch>      (if ctx has deadline)
 *   n00b-rpc-trace-id: <hex>                       (deferred — no ctx field)
 *   <DATA: req_cbor> + FIN
 * =========================================================================== */

/* Cancellation watcher: blocks on the ctx's cancel futex; on signal,
 * STOP_SENDING/RESET the H3 request stream so the response wait
 * returns promptly. */
typedef struct {
    n00b_rpc_ctx_t           *ctx;
    n00b_h3_request_t        *req;
    _Atomic uint32_t          shutdown;   /* 0 = run, 1 = exit */
    n00b_futex_t              shutdown_futex;
    n00b_thread_t            *thread;
    bool                      thread_started;
} cancel_watcher_t;

static void *
cancel_watcher_main(void *arg)
{
    cancel_watcher_t *w = (cancel_watcher_t *)arg;

    /* Wake every 50ms to check shutdown; otherwise block on the
     * ctx's cancel transition. */
    while (atomic_load(&w->shutdown) == 0) {
        if (n00b_rpc_ctx_is_cancelled(w->ctx)) {
            n00b_h3_request_cancel(w->req);
            return nullptr;
        }
        /* Sleep up to 50ms, but wake on shutdown_futex change. */
        (void)n00b_futex_wait(&w->shutdown_futex, 0,
                              (uint64_t)50 * 1000 * 1000);
    }
    /* Final cancel-on-shutdown is unwanted; return cleanly. */
    return nullptr;
}

static cancel_watcher_t *
cancel_watcher_start(n00b_rpc_ctx_t *ctx, n00b_h3_request_t *req)
{
    if (!ctx || !req) return nullptr;
    cancel_watcher_t *w = n00b_alloc_with_opts(
        cancel_watcher_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    w->ctx = ctx;
    w->req = req;
    atomic_store(&w->shutdown, 0);
    n00b_futex_init(&w->shutdown_futex);

    auto tr = n00b_thread_spawn(cancel_watcher_main, w);
    if (n00b_result_is_ok(tr)) {
        w->thread = n00b_result_get(tr);
        w->thread_started = true;
    }
    return w;
}

static void
cancel_watcher_stop(cancel_watcher_t *w)
{
    if (!w) return;
    if (w->thread_started) {
        atomic_store(&w->shutdown, 1);
        n00b_futex_wake_all(&w->shutdown_futex);
        n00b_thread_join(w->thread);
        w->thread_started = false;
    }
}

/* Forward decl: defined down in the streaming section.  Used by all
 * call sites (unary + each streaming variant) so they share the
 * "content-type + deadline + auth headers" assembly path.  The
 * `Bearer <jwt>` value is heap-allocated from the rpc allocator so
 * arbitrarily-large JWTs are supported (no silent truncation).
 *
 * @p creds_override and @p policy_override carry the sub-phase-4.9
 * per-call override (see `docs/quic/rpc_design.md` § 7.3).  When
 * non-NULL, they take precedence over the channel-level fields for
 * THIS request only — the channel state is not mutated. */
static size_t
build_request_headers_full(n00b_rpc_ctx_t                    *ctx,
                           const n00b_rpc_channel_t          *chan,
                           const n00b_rpc_auth_credentials_t *creds_override,
                           const char                        *policy_override,
                           n00b_h3_header_t                  *out,
                           char                              *deadline_buf);

/* Forward decl: defined alongside the streaming call sites.  Shared
 * preflight credential check used by all four call sites. */
static bool
auth_preflight_unauthenticated(const n00b_rpc_channel_t          *chan,
                               const n00b_rpc_auth_credentials_t *creds_override,
                               const char                        *policy_override);

/* Find a header value in an H3 response; case-sensitive, lower-case
 * only per RFC 9114 § 4.2. */
static const char *
find_header_value(const n00b_h3_header_t *headers,
                  size_t                  n_headers,
                  const char             *name,
                  size_t                 *out_len)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i < n_headers; i++) {
        if (headers[i].name_len == name_len
            && memcmp(headers[i].name, name, name_len) == 0) {
            if (out_len) *out_len = headers[i].value_len;
            return (const char *)headers[i].value;
        }
    }
    return nullptr;
}

/* Build "/<full_method>" — caller-allocated, conduit-pool-owned. */
static char *
make_path(const char *full_method)
{
    size_t n = strlen(full_method);
    char  *p = n00b_alloc_array_with_opts(char, (int64_t)(n + 2),
                    &(n00b_alloc_opts_t){
                        .allocator = n00b_rpc_alloc(),
                        .no_scan   = true,
                    });
    p[0] = '/';
    memcpy(p + 1, full_method, n + 1);
    return p;
}

n00b_result_t(n00b_buffer_t *)
n00b_rpc_call_unary(n00b_rpc_ctx_t     *ctx,
                    n00b_rpc_channel_t *chan,
                    const char         *full_method,
                    n00b_buffer_t      *req_cbor) _kargs
{
    const n00b_rpc_auth_credentials_t *creds_override  = nullptr;
    const char                        *policy_override = nullptr;
}
{
    if (!chan || !chan->h3 || !full_method) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    /* Empty body is valid per rpc_design.md § 4. */
    const uint8_t *body     = nullptr;
    size_t         body_len = 0;
    if (req_cbor) {
        body     = (const uint8_t *)req_cbor->data;
        body_len = (size_t)req_cbor->byte_len;
    }

    /* Pre-flight cancellation check: don't issue if already cancelled
     * or the deadline has already passed. */
    if (ctx) {
        if (n00b_rpc_ctx_is_cancelled(ctx)) {
            return n00b_result_err(n00b_buffer_t *, N00B_RPC_CANCELLED);
        }
    }

    /* Pre-flight credential sanity (sub-phase 4.9 per-call override).
     * See `auth_preflight_unauthenticated` (defined alongside the
     * server-stream call site) for the rule. */
    if (auth_preflight_unauthenticated(chan, creds_override, policy_override)) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_UNAUTHENTICATED);
    }

    /* Build the request headers (content-type + optional deadline +
     * effective auth headers — sub-phase 4.9, with per-call
     * override). */
    n00b_h3_header_t extras[5];
    char             deadline_buf[32];
    size_t           n_extras = build_request_headers_full(
        ctx, chan, creds_override, policy_override, extras, deadline_buf);

    char *path = make_path(full_method);

    auto reqr = n00b_h3_client_request(
        chan->h3,
        (n00b_h3_request_spec_t){
            .method    = "POST",
            .scheme    = chan->scheme,
            .authority = chan->authority,
            .path      = path,
            .headers   = { .items = extras, .count = n_extras },
            .body      = body,
            .body_len  = body_len,
        });
    if (n00b_result_is_err(reqr)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(reqr));
    }
    n00b_h3_request_t *h3req = n00b_result_get(reqr);

    /* Spin a watcher to translate ctx-cancel into stream-reset. */
    cancel_watcher_t *watcher = cancel_watcher_start(ctx, h3req);

    /* Compute the await deadline (ms).  If ctx has a deadline use
     * it; else default to 10s (matching n00b_h3_request_await's
     * default).  Cap at INT32_MAX. */
    int32_t deadline_ms = 10000;
    if (ctx) {
        int64_t rem_ns = n00b_rpc_ctx_remaining_ns(ctx);
        if (rem_ns == 0) {
            /* Already past deadline. */
            cancel_watcher_stop(watcher);
            return n00b_result_err(n00b_buffer_t *, N00B_RPC_DEADLINE_EXCEEDED);
        }
        if (rem_ns > 0) {
            int64_t rem_ms = rem_ns / 1000000 + 1;
            if (rem_ms < INT32_MAX) deadline_ms = (int32_t)rem_ms;
        }
    }

    auto rsp = n00b_h3_request_await(h3req, .deadline_ms = deadline_ms);

    cancel_watcher_stop(watcher);

    if (n00b_result_is_err(rsp)) {
        int err = n00b_result_get_err(rsp);
        /* Disambiguate timeout vs ctx-cancel: if ctx is cancelled,
         * surface CANCELLED/DEADLINE_EXCEEDED rather than the raw
         * QUIC-err. */
        if (ctx && n00b_rpc_ctx_is_cancelled(ctx)) {
            int64_t rem = n00b_rpc_ctx_remaining_ns(ctx);
            if (rem == 0 && err == N00B_QUIC_ERR_TIMEOUT) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_RPC_DEADLINE_EXCEEDED);
            }
            return n00b_result_err(n00b_buffer_t *, N00B_RPC_CANCELLED);
        }
        return n00b_result_err(n00b_buffer_t *, err);
    }

    n00b_h3_response_t *resp = n00b_result_get(rsp);

    /* Read n00b-rpc-status header. */
    size_t      sv_len = 0;
    const char *sv     = find_header_value(resp->headers, resp->n_headers,
                                            "n00b-rpc-status", &sv_len);
    int32_t status_code = -1;
    if (sv) {
        char tmp[16];
        if (sv_len < sizeof(tmp)) {
            memcpy(tmp, sv, sv_len);
            tmp[sv_len] = '\0';
            status_code = (int32_t)strtol(tmp, nullptr, 10);
        }
    }

    if (status_code == N00B_RPC_OK
        || (status_code < 0 && resp->status == 200)) {
        /* Success path: return body buffer (may be empty). */
        if (resp->body) {
            return n00b_result_ok(n00b_buffer_t *, resp->body);
        }
        /* Fabricate an empty buffer for "no body" replies. */
        n00b_buffer_t *empty = n00b_alloc_with_opts(
            n00b_buffer_t,
            &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
        n00b_buffer_init(empty, .length = 0,
                         .allocator = n00b_rpc_alloc(), .no_lock = true);
        return n00b_result_ok(n00b_buffer_t *, empty);
    }

    if (status_code >= 0) {
        return n00b_result_err(n00b_buffer_t *, status_code);
    }
    /* No n00b-rpc-status header AND non-200 :status: synthesize. */
    if (resp->status == 404) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_UNIMPLEMENTED);
    }
    if (resp->status == 504) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_DEADLINE_EXCEEDED);
    }
    return n00b_result_err(n00b_buffer_t *, N00B_RPC_UNKNOWN);
}

/* ===========================================================================
 * Server side: dispatcher
 * =========================================================================== */

struct n00b_rpc_server {
    n00b_h3_server_t          *h3;             /**< Borrowed. */
    n00b_conduit_t            *conduit;        /**< Borrowed. */
    n00b_h3_request_inbox_t   *inbox;
    n00b_thread_t             *worker;
    _Atomic uint32_t           shutdown;
    n00b_futex_t               shutdown_futex;
    bool                       worker_started;

    /* Per-request dispatch.  The worker thread pops requests off the
     * inbox; for each, if `in_flight < max_in_flight`, it spawns a
     * fresh `n00b_thread` to run `dispatch_inbound`.  Otherwise it
     * dispatches inline (graceful backpressure).  Handler threads
     * call into `n00b_h3_inbound_request_respond`, which uses
     * `n00b_quic_chan_send_queued` — wire writes are serialized on
     * the endpoint's I/O thread, not on the dispatch thread. */
    _Atomic uint32_t           in_flight;
    uint32_t                   max_in_flight;     /**< Default 64. */

    /* Test instrumentation: peak observed value of `in_flight`.
     * Lets concurrency tests assert that dispatch actually ran
     * handlers in parallel (peak > 1).  Updated on every spawn. */
    _Atomic uint32_t           peak_in_flight;

    /* Sub-phase 4.9: auth wiring.  All optional; auth is unenforced
     * unless `n00b_rpc_server_attach_auth` has been called. */
    n00b_quic_manifest_t          *manifest;          /**< Borrowed. */
    bool                           auth_enabled;      /**< Have manifest? */
    bool                           audit_stderr;      /**< Echo to stderr too. */
    n00b_rpc_verifier_resolver_fn  verifier_resolver;
    void                          *verifier_resolver_ctx;

    /* Phase 5 § 5.1 — optional metrics.  When `metrics_registry` is
     * nullptr, both helpers are no-ops. */
    n00b_quic_metric_registry_t   *metrics_registry;
    n00b_quic_metric_counter_t    *m_calls_total;       /* {service,method,status} */
    n00b_quic_metric_hist_t       *m_call_duration_us;
};


static int64_t
parse_deadline_ms(const n00b_h3_header_t *headers, size_t n_headers)
{
    size_t      vlen = 0;
    const char *v    = find_header_value(headers, n_headers,
                                          "n00b-rpc-deadline-ms", &vlen);
    if (!v || vlen == 0 || vlen >= 32) return -1;
    char tmp[32];
    memcpy(tmp, v, vlen);
    tmp[vlen] = '\0';
    int64_t ms = (int64_t)strtoll(tmp, nullptr, 10);
    return ms <= 0 ? -1 : ms;
}

/* Given an absolute wall-clock deadline (unix-epoch ms), translate to
 * the local monotonic-ns clock for ctx_with_deadline.  If the wall
 * clock already passed the deadline, return 0 (caller treats as
 * already-expired). */
static int64_t
wallclock_ms_to_monotonic_ns(int64_t deadline_unix_ms)
{
    struct timespec wall;
    clock_gettime(CLOCK_REALTIME, &wall);
    int64_t now_unix_ms = (int64_t)wall.tv_sec * 1000
                        + (int64_t)wall.tv_nsec / 1000000;
    int64_t rem_ms = deadline_unix_ms - now_unix_ms;
    if (rem_ms <= 0) return 0;
    return n00b_ns_timestamp() + rem_ms * 1000000;
}

/* Emit an error response: HEADERS (mapped :status + n00b-rpc-status)
 * + empty DATA + FIN. */
static void
respond_with_status(n00b_h3_inbound_request_t *ireq,
                    n00b_rpc_status_t          status)
{
    int  http = n00b_rpc_status_http_class(status);
    char status_str[16];
    int  n = snprintf(status_str, sizeof(status_str), "%d", (int)status);
    if (n <= 0) n = 1;

    n00b_h3_header_t hdrs[2];
    size_t           n_hdrs = 0;
    hdrs[n_hdrs++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"n00b-rpc-status",
        .name_len  = strlen("n00b-rpc-status"),
        .value     = (const uint8_t *)status_str,
        .value_len = (size_t)n,
    };
    hdrs[n_hdrs++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"content-type",
        .name_len  = strlen("content-type"),
        .value     = (const uint8_t *)"application/cbor",
        .value_len = strlen("application/cbor"),
    };

    (void)n00b_h3_inbound_request_respond(
        ireq,
        (n00b_h3_response_spec_t){
            .status  = (uint16_t)http,
            .headers = { .items = hdrs, .count = n_hdrs },
        });
}

static void
respond_with_ok(n00b_h3_inbound_request_t *ireq, n00b_buffer_t *resp_cbor)
{
    n00b_h3_header_t hdrs[2];
    size_t           n_hdrs = 0;
    hdrs[n_hdrs++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"n00b-rpc-status",
        .name_len  = strlen("n00b-rpc-status"),
        .value     = (const uint8_t *)"0",
        .value_len = 1,
    };
    hdrs[n_hdrs++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"content-type",
        .name_len  = strlen("content-type"),
        .value     = (const uint8_t *)"application/cbor",
        .value_len = strlen("application/cbor"),
    };

    const uint8_t *body     = nullptr;
    size_t         body_len = 0;
    if (resp_cbor) {
        body     = (const uint8_t *)resp_cbor->data;
        body_len = (size_t)resp_cbor->byte_len;
    }
    (void)n00b_h3_inbound_request_respond(
        ireq,
        (n00b_h3_response_spec_t){
            .status   = 200,
            .headers  = { .items = hdrs, .count = n_hdrs },
            .body     = body,
            .body_len = body_len,
        });
}

/* Forward decls for the auth-wiring helpers (defined below). */
static n00b_rpc_status_t
authenticate_inbound(n00b_rpc_server_t                *s,
                     const char                       *full_method,
                     const n00b_h3_header_t           *hdrs,
                     size_t                            n_hdrs,
                     const n00b_quic_manifest_policy_t **out_policy);

static void
emit_audit_event(n00b_rpc_server_t                 *s,
                 const char                        *full_method,
                 const n00b_quic_manifest_policy_t *policy,
                 n00b_rpc_status_t                  status,
                 int64_t                            latency_ns,
                 n00b_h3_inbound_request_t         *ireq);

static void
dispatch_inbound(n00b_rpc_server_t        *s,
                 n00b_h3_inbound_request_t *ireq)
{
    int64_t t_start = n00b_ns_timestamp();

    /* Parse method id from path (strip leading '/'). */
    const char *path = n00b_h3_inbound_request_path(ireq);
    if (!path || path[0] != '/' || path[1] == '\0') {
        respond_with_status(ireq, N00B_RPC_UNIMPLEMENTED);
        emit_audit_event(s, "?", nullptr, N00B_RPC_UNIMPLEMENTED,
                         n00b_ns_timestamp() - t_start, ireq);
        return;
    }
    const char *full_method = path + 1;

    rpc_entry_t *e = lookup_method(full_method);
    if (!e) {
        respond_with_status(ireq, N00B_RPC_UNIMPLEMENTED);
        emit_audit_event(s, full_method, nullptr, N00B_RPC_UNIMPLEMENTED,
                         n00b_ns_timestamp() - t_start, ireq);
        return;
    }

    /* Build a server-side ctx with the deadline (if any) propagated
     * from the request header. */
    size_t                  n_h = 0;
    const n00b_h3_header_t *hdrs = n00b_h3_inbound_request_headers(ireq, &n_h);

    /* Sub-phase 4.9: authenticate before doing any handler work.  If
     * auth wiring is not enabled this is a no-op (returns OK).  We
     * always emit one audit event per dispatch — allow OR deny. */
    const n00b_quic_manifest_policy_t *applied_policy = nullptr;
    n00b_rpc_status_t auth_st = authenticate_inbound(s, full_method, hdrs, n_h,
                                                     &applied_policy);
    if (auth_st != N00B_RPC_OK) {
        respond_with_status(ireq, auth_st);
        emit_audit_event(s, full_method, applied_policy, auth_st,
                         n00b_ns_timestamp() - t_start, ireq);
        return;
    }

    int64_t         deadline_unix_ms = parse_deadline_ms(hdrs, n_h);
    n00b_rpc_ctx_t *ctx              = nullptr;

    if (deadline_unix_ms > 0) {
        int64_t mono_ns = wallclock_ms_to_monotonic_ns(deadline_unix_ms);
        if (mono_ns == 0) {
            /* Deadline already passed before we even invoked the
             * handler — short-circuit. */
            respond_with_status(ireq, N00B_RPC_DEADLINE_EXCEEDED);
            emit_audit_event(s, full_method, applied_policy,
                             N00B_RPC_DEADLINE_EXCEEDED,
                             n00b_ns_timestamp() - t_start, ireq);
            return;
        }
        ctx = n00b_rpc_ctx_with_deadline(nullptr, mono_ns);
    }
    else {
        ctx = n00b_rpc_ctx_new();
    }

    /* Get the request body.  Empty body is valid (rpc_design.md § 4). */
    n00b_buffer_t *body = n00b_h3_inbound_request_body(ireq);
    if (!body) {
        body = n00b_alloc_with_opts(
            n00b_buffer_t,
            &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
        n00b_buffer_init(body, .length = 0,
                         .allocator = n00b_rpc_alloc(), .no_lock = true);
    }

    /* Streaming variants are dispatched by `dispatch_inbound_streaming`
     * (forward-declared below). */
    extern void dispatch_streaming_inbound(rpc_entry_t *,
                                            n00b_h3_inbound_request_t *,
                                            n00b_buffer_t *,
                                            n00b_rpc_ctx_t *);
    if (e->pattern != RPC_PATTERN_UNARY) {
        /* Audit BEFORE handing over: streaming dispatch may run
         * arbitrarily long, but the auth decision itself is already
         * settled (allow). */
        emit_audit_event(s, full_method, applied_policy, N00B_RPC_OK,
                         n00b_ns_timestamp() - t_start, ireq);
        dispatch_streaming_inbound(e, ireq, body, ctx);
        return;
    }

    /* Invoke. */
    n00b_rpc_dispatch_fn_t unary_fn = (n00b_rpc_dispatch_fn_t)e->fn;
    n00b_result_t(n00b_buffer_t *) r = unary_fn(body, ctx);

    /* If the handler called ctx_cancel mid-flight, RESET the stream
     * (rpc_design.md § 6.3) — caller's response is discarded. */
    if (n00b_rpc_ctx_is_cancelled(ctx)) {
        n00b_h3_inbound_request_reset(ireq, 1);
        n00b_rpc_ctx_close(ctx);
        emit_audit_event(s, full_method, applied_policy, N00B_RPC_CANCELLED,
                         n00b_ns_timestamp() - t_start, ireq);
        return;
    }

    n00b_rpc_status_t final_st = N00B_RPC_OK;
    if (n00b_result_is_err(r)) {
        int e_code = n00b_result_get_err(r);
        n00b_rpc_status_t st;
        if (e_code >= N00B_RPC_OK && e_code <= N00B_RPC_UNAUTHENTICATED) {
            st = (n00b_rpc_status_t)e_code;
        }
        else {
            st = n00b_rpc_status_from_quic_err(e_code);
        }
        if (st == N00B_RPC_OK) st = N00B_RPC_INTERNAL;
        respond_with_status(ireq, st);
        final_st = st;
    }
    else {
        respond_with_ok(ireq, n00b_result_get(r));
    }

    n00b_rpc_ctx_close(ctx);
    emit_audit_event(s, full_method, applied_policy, final_st,
                     n00b_ns_timestamp() - t_start, ireq);
}

/* Server worker — per-request thread dispatch.
 *
 * picoquic is not thread-safe at the endpoint level: all
 * picoquic_add_to_stream / picoquic_prepare_next_packet calls must
 * happen on the I/O thread that owns the UDP socket.  An earlier
 * attempt at per-request dispatch tripped libmalloc heap-corruption
 * assertions inside `picoquic_format_stream_frame` because handler
 * threads called back into picoquic from
 * `n00b_h3_inbound_request_respond` while the I/O thread was inside
 * `picoquic_prepare_next_packet`.
 *
 * The fix: response wire writes go through
 * `n00b_quic_chan_send_queued`, which publishes onto the endpoint's
 * outbound topic.  The I/O thread drains that topic at the head of
 * every `run_once` and replays the bytes to picoquic itself.
 * Handlers can therefore run on any thread; only the wire I/O is
 * serialized.
 *
 * Concurrency cap: when `in_flight >= max_in_flight` the worker
 * dispatches inline (graceful backpressure).  Handlers usually
 * complete in microseconds; the cap exists only to prevent runaway
 * thread spawning under pathological load. */

typedef struct {
    n00b_rpc_server_t        *server;
    n00b_h3_inbound_request_t *ireq;
} dispatch_thread_arg_t;

static void *
dispatch_thread_main(void *p)
{
    dispatch_thread_arg_t *a = (dispatch_thread_arg_t *)p;
    n00b_rpc_server_t        *s    = a->server;
    n00b_h3_inbound_request_t *ireq = a->ireq;
    /* `a` is conduit-pool-owned; GC reclaims it when this thread
     * exits.  Don't `free()` — it wasn't malloc'd. */

    dispatch_inbound(s, ireq);

    atomic_fetch_sub(&s->in_flight, 1);
    return nullptr;
}

static void *
server_worker_main(void *arg)
{
    n00b_rpc_server_t *s = (n00b_rpc_server_t *)arg;
    while (atomic_load(&s->shutdown) == 0) {
        if (n00b_h3_request_inbox_has_messages(s->inbox)) {
            n00b_h3_request_msg_t *m = n00b_h3_request_inbox_pop(s->inbox);
            if (!m || !m->payload.req) {
                continue;
            }
            n00b_h3_inbound_request_t *ireq = m->payload.req;

            /* Backpressure: when at the in-flight cap, handle inline.
             * Handlers complete quickly in normal load; the cap only
             * matters under storm conditions. */
            uint32_t current = atomic_load(&s->in_flight);
            if (current >= s->max_in_flight) {
                dispatch_inbound(s, ireq);
                continue;
            }

            uint32_t after = atomic_fetch_add(&s->in_flight, 1) + 1;
            uint32_t prev_peak = atomic_load(&s->peak_in_flight);
            while (after > prev_peak) {
                if (atomic_compare_exchange_weak(&s->peak_in_flight,
                                                 &prev_peak, after)) {
                    break;
                }
            }

            dispatch_thread_arg_t *a = n00b_alloc_with_opts(
                dispatch_thread_arg_t,
                &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
            a->server = s;
            a->ireq   = ireq;

            auto tr = n00b_thread_spawn(dispatch_thread_main, a);
            if (n00b_result_is_err(tr)) {
                /* Thread spawn failed — fall back to inline so the
                 * request still gets a response. */
                atomic_fetch_sub(&s->in_flight, 1);
                dispatch_inbound(s, ireq);
            }
            /* Successful spawn: dispatch_thread_main owns the work
             * and decrements `in_flight` on exit.  We deliberately
             * do NOT join here — handler runtimes are unbounded
             * (sleeps, slow upstreams).  shutdown drains pending
             * handlers via the in_flight counter (see _close). */
            continue;
        }
        /* Sleep up to 5ms; shutdown_futex wakes us early on close. */
        (void)n00b_futex_wait(&s->shutdown_futex, 0,
                              (uint64_t)5 * 1000 * 1000);
    }
    return nullptr;
}

n00b_rpc_server_t *
n00b_rpc_attach_server(n00b_h3_server_t *h3, n00b_conduit_t *conduit)
{
    if (!h3 || !conduit) return nullptr;

    n00b_rpc_server_t *s = n00b_alloc_with_opts(
        n00b_rpc_server_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    s->h3      = h3;
    s->conduit = conduit;
    atomic_store(&s->shutdown, 0);
    atomic_store(&s->in_flight, 0);
    atomic_store(&s->peak_in_flight, 0);
    s->max_in_flight = 64;
    n00b_futex_init(&s->shutdown_futex);

    s->inbox = n00b_h3_request_inbox_new(conduit);
    n00b_h3_request_subscribe(n00b_h3_server_request_topic(h3),
                              s->inbox,
                              .operations = N00B_CONDUIT_OP_ALL);

    auto tr = n00b_thread_spawn(server_worker_main, s);
    if (n00b_result_is_ok(tr)) {
        s->worker = n00b_result_get(tr);
        s->worker_started = true;
    }
    return s;
}

uint32_t
n00b_rpc_server_peak_in_flight(n00b_rpc_server_t *s)
{
    if (!s) return 0;
    return atomic_load(&s->peak_in_flight);
}

void
n00b_rpc_server_close(n00b_rpc_server_t *s)
{
    if (!s) return;
    if (s->worker_started) {
        atomic_store(&s->shutdown, 1);
        n00b_futex_wake_all(&s->shutdown_futex);
        n00b_thread_join(s->worker);
        s->worker_started = false;

        /* Drain any in-flight handlers spawned by the worker.  We
         * don't track the handler threads individually; they're
         * detached.  A bounded spin on `in_flight` is sufficient —
         * handlers shouldn't take more than a few seconds even in
         * pathological cases, and this only fires at server close. */
        int budget_ms = 5000;
        while (atomic_load(&s->in_flight) > 0 && budget_ms > 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
            nanosleep(&ts, nullptr);
            budget_ms -= 1;
        }
    }
}

/* ===========================================================================
 * Auth wiring (sub-phase 4.9)
 *
 * Server-side enforcement of `auth.policies[]` + `rpc.services[]`
 * pinned defaults, plus per-call `n00b-rpc-policy` overrides
 * (which must be at-least-as-strict as the pinned default).
 * =========================================================================== */

/* Look up a manifest policy by id (linear search; manifest policies
 * are typically <10 in real deployments).  Returns nullptr if absent. */
static const n00b_quic_manifest_policy_t *
manifest_lookup_policy(n00b_quic_manifest_t *mf, const n00b_buffer_t *id)
{
    if (!mf || n00b_quic_mfbuf_empty(id) || !mf->auth_policies) return nullptr;
    size_t n = (size_t)n00b_list_len(*mf->auth_policies);
    for (size_t i = 0; i < n; i++) {
        n00b_quic_manifest_policy_t *p = n00b_list_get(*mf->auth_policies, i);
        if (p && n00b_quic_mfbuf_eq(p->id, id)) {
            return p;
        }
    }
    return nullptr;
}

/* Look up the `auth_policy` id pinned to a service in the manifest's
 * `rpc.services[]`.  The full method id is `service/method`; we
 * match the service prefix only. */
static const n00b_buffer_t *
manifest_service_policy_id(n00b_quic_manifest_t *mf, const char *full_method)
{
    if (!mf || !full_method) return nullptr;
    /* Service prefix = everything before the last '/' in the method id. */
    const char *slash = strrchr(full_method, '/');
    if (!slash) return nullptr;
    size_t svc_len = (size_t)(slash - full_method);
    if (!mf->rpc_services) return nullptr;
    size_t n = (size_t)n00b_list_len(*mf->rpc_services);
    for (size_t i = 0; i < n; i++) {
        const n00b_quic_manifest_rpc_service_t *svc =
            n00b_list_get(*mf->rpc_services, i);
        if (!svc || !svc->id || !svc->auth_policy) continue;
        if (svc->id->byte_len == svc_len
            && memcmp(svc->id->data, full_method, svc_len) == 0) {
            return svc->auth_policy;
        }
    }
    return nullptr;
}

/* Public: at-least-as-strict comparison.  See header for semantics. */
bool
n00b_rpc_policy_at_least_as_strict(const n00b_quic_manifest_policy_t *base,
                                   const n00b_quic_manifest_policy_t *candidate)
{
    if (!base) return true;            /* No baseline → anything passes. */
    if (!candidate) return false;      /* Have baseline, no candidate. */

    /* DPoP / mTLS bits: candidate must require if base requires. */
    if (base->require_dpop && !candidate->require_dpop) return false;
    if (base->require_mtls && !candidate->require_mtls) return false;

    /* Audience: if base pins one, candidate must pin the same.
     * (A different audience is a parallel constraint, not stricter.) */
    if (!n00b_quic_mfbuf_empty(base->audience)) {
        if (!n00b_quic_mfbuf_eq(base->audience, candidate->audience)) {
            return false;
        }
    }

    /* Issuer override: same logic as audience. */
    if (!n00b_quic_mfbuf_empty(base->issuer_override)) {
        if (!n00b_quic_mfbuf_eq(base->issuer_override,
                                candidate->issuer_override)) {
            return false;
        }
    }

    /* Required claims: every base claim must be matched in candidate. */
    size_t base_n = base->required_claims
                    ? (size_t)n00b_list_len(*base->required_claims) : 0;
    size_t cand_n = candidate->required_claims
                    ? (size_t)n00b_list_len(*candidate->required_claims) : 0;
    for (size_t i = 0; i < base_n; i++) {
        const n00b_quic_manifest_required_claim_t *bc =
            n00b_list_get(*base->required_claims, i);
        if (!bc || !bc->name || !bc->value) continue;
        bool matched = false;
        for (size_t j = 0; j < cand_n; j++) {
            const n00b_quic_manifest_required_claim_t *cc =
                n00b_list_get(*candidate->required_claims, j);
            if (!cc || !cc->name || !cc->value) continue;
            if (cc->op == bc->op
                && n00b_quic_mfbuf_eq(cc->name, bc->name)
                && n00b_quic_mfbuf_eq(cc->value, bc->value)) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    return true;
}

/* Build a runtime policy object from a manifest policy entry.  The
 * caller owns the returned policy (close via
 * `n00b_quic_auth_policy_close`).  Returns nullptr on alloc failure
 * or invalid entries. */
static n00b_quic_auth_policy_t *
build_runtime_policy(const n00b_quic_manifest_policy_t *mp,
                     n00b_quic_manifest_t              *mf)
{
    if (!mp) return nullptr;
    n00b_quic_auth_policy_t *p = n00b_quic_auth_policy_new();
    if (!p) return nullptr;
    if (!n00b_quic_mfbuf_empty(mp->audience)) {
        n00b_quic_auth_policy_require_audience(p, mp->audience->data);
    }
    /* Issuer: prefer override; else look up the IdP. */
    n00b_buffer_t *iss = !n00b_quic_mfbuf_empty(mp->issuer_override)
                            ? mp->issuer_override : nullptr;
    if (!iss && mp->idp && mf && mf->auth_idps) {
        size_t idp_n = (size_t)n00b_list_len(*mf->auth_idps);
        for (size_t i = 0; i < idp_n; i++) {
            n00b_quic_manifest_idp_t *idp = n00b_list_get(*mf->auth_idps, i);
            if (idp && n00b_quic_mfbuf_eq(idp->id, mp->idp)) {
                iss = idp->issuer;
                break;
            }
        }
    }
    if (!n00b_quic_mfbuf_empty(iss)) {
        n00b_quic_auth_policy_require_issuer(p, iss->data);
    }
    if (mp->require_dpop) n00b_quic_auth_policy_require_dpop(p);
    if (mp->require_mtls) n00b_quic_auth_policy_require_mtls(p);
    size_t rc_n = mp->required_claims
                  ? (size_t)n00b_list_len(*mp->required_claims) : 0;
    for (size_t i = 0; i < rc_n; i++) {
        const n00b_quic_manifest_required_claim_t *rc =
            n00b_list_get(*mp->required_claims, i);
        if (!rc || !rc->name || !rc->value) continue;
        if (rc->op == N00B_QUIC_MANIFEST_CLAIM_CONTAINS) {
            n00b_quic_auth_policy_require_claim_contains(p, rc->name->data,
                                                         rc->value->data);
        } else {
            n00b_quic_auth_policy_require_claim(p, rc->name->data,
                                                rc->value->data);
        }
    }
    return p;
}

/* Strip a `Bearer ` prefix from an authorization header value.
 * Returns a pointer into the original buffer (no copy) or nullptr
 * if the header doesn't start with `Bearer `. */
static const char *
strip_bearer_prefix(const char *auth_value, size_t auth_len, size_t *out_len)
{
    static const char prefix[] = "Bearer ";
    const size_t plen = sizeof(prefix) - 1;
    if (auth_len < plen) return nullptr;
    if (memcmp(auth_value, prefix, plen) != 0) {
        /* Some clients send "bearer " in lower case; tolerate. */
        for (size_t i = 0; i < plen; i++) {
            char c = auth_value[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            char ref = prefix[i];
            if (ref >= 'A' && ref <= 'Z') ref = (char)(ref + 32);
            if (c != ref) return nullptr;
        }
    }
    if (out_len) *out_len = auth_len - plen;
    return auth_value + plen;
}

/* Authenticate one inbound RPC.  Returns N00B_RPC_OK if the request
 * passes (or auth is unconfigured); else the rpc-status to send. */
static n00b_rpc_status_t
authenticate_inbound(n00b_rpc_server_t                  *s,
                     const char                         *full_method,
                     const n00b_h3_header_t             *hdrs,
                     size_t                              n_hdrs,
                     const n00b_quic_manifest_policy_t **out_policy)
{
    if (out_policy) *out_policy = nullptr;
    if (!s || !s->auth_enabled || !s->manifest) {
        return N00B_RPC_OK;
    }

    /* Resolve the service-pinned policy. */
    const n00b_buffer_t *pinned_id = manifest_service_policy_id(s->manifest,
                                                                full_method);
    const n00b_quic_manifest_policy_t *pinned = pinned_id
        ? manifest_lookup_policy(s->manifest, pinned_id) : nullptr;

    /* Honor the per-call override.  An override referencing an
     * unknown policy id is itself a deny.  An override that's WEAKER
     * than the pinned default is rejected with PERMISSION_DENIED. */
    size_t      override_len = 0;
    const char *override_val = find_header_value(hdrs, n_hdrs,
                                                  "n00b-rpc-policy",
                                                  &override_len);
    const n00b_quic_manifest_policy_t *applied = pinned;
    if (override_val && override_len > 0) {
        /* Materialize a buffer view of the override id. */
        n00b_buffer_t over_id_buf = {
            .data     = (char *)override_val,
            .byte_len = override_len,
        };

        const n00b_quic_manifest_policy_t *over =
            manifest_lookup_policy(s->manifest, &over_id_buf);
        if (!over) {
            /* Per-call asks for an unknown policy id. */
            return N00B_RPC_PERMISSION_DENIED;
        }
        if (!n00b_rpc_policy_at_least_as_strict(pinned, over)) {
            /* Weaker than the pinned default. */
            return N00B_RPC_PERMISSION_DENIED;
        }
        applied = over;
    }

    if (out_policy) *out_policy = applied;

    /* No applicable policy → allow.  (Service has no manifest entry
     * AND no per-call override.  Operators can require coverage via
     * preflight; the runtime defaults to permissive when neither
     * side declared a constraint.) */
    if (!applied) return N00B_RPC_OK;

    /* Resolve the JWT verifier.  Our default has no built-in resolver;
     * the application installs one via
     * `n00b_rpc_server_set_verifier_resolver`.  Without a resolver, we
     * cannot verify a token — treat as UNAUTHENTICATED. */
    n00b_jwt_verifier_t *verifier = nullptr;
    if (s->verifier_resolver) {
        verifier = s->verifier_resolver(applied->idp ? applied->idp->data
                                                     : nullptr,
                                        hdrs, n_hdrs,
                                        s->verifier_resolver_ctx);
    }

    /* Pull credentials from headers. */
    size_t      auth_len = 0;
    const char *auth_val = find_header_value(hdrs, n_hdrs, "authorization",
                                              &auth_len);
    size_t      tok_len  = 0;
    const char *bearer   = nullptr;
    if (auth_val) bearer = strip_bearer_prefix(auth_val, auth_len, &tok_len);

    size_t      dpop_len = 0;
    const char *dpop_val = find_header_value(hdrs, n_hdrs, "dpop", &dpop_len);

    /* Materialize NUL-terminated copies of the borrowed header
     * values.  Conduit pool; ephemeral. */
    char *bearer_copy = nullptr;
    if (bearer && tok_len > 0) {
        bearer_copy = n00b_alloc_array_with_opts(char, (int64_t)(tok_len + 1),
                          &(n00b_alloc_opts_t){
                              .allocator = n00b_rpc_alloc(),
                              .no_scan   = true,
                          });
        memcpy(bearer_copy, bearer, tok_len);
        bearer_copy[tok_len] = '\0';
    }
    char *dpop_copy = nullptr;
    if (dpop_val && dpop_len > 0) {
        dpop_copy = n00b_alloc_array_with_opts(char, (int64_t)(dpop_len + 1),
                        &(n00b_alloc_opts_t){
                            .allocator = n00b_rpc_alloc(),
                            .no_scan   = true,
                        });
        memcpy(dpop_copy, dpop_val, dpop_len);
        dpop_copy[dpop_len] = '\0';
    }

    /* Build the htu (full URL) for DPoP.  RFC 9449 § 4.2: htu is
     * the request URL.  We synthesize as `<scheme>://<authority><path>`. */
    /* Note: the manifest policy may not require DPoP; in that case
     * htm/htu are not used by eval, but we still pass them defensively. */
    n00b_quic_auth_policy_t *runtime_policy = build_runtime_policy(applied,
                                                                   s->manifest);
    if (!runtime_policy) {
        return N00B_RPC_INTERNAL;
    }

    /* If the policy needs a token but we have no verifier wired in,
     * treat as UNAUTHENTICATED rather than letting eval surface
     * NULL_ARG (which would map to INVALID_ARGUMENT — wrong shape). */
    if (bearer_copy && !verifier) {
        n00b_quic_auth_policy_close(runtime_policy);
        return N00B_RPC_UNAUTHENTICATED;
    }

    n00b_quic_auth_credentials_t creds = {
        .bearer_token = bearer_copy,
        .jwt_verifier = verifier,
        .dpop_header  = dpop_copy,
        .htm          = "POST",
        .htu          = full_method,
    };

    auto er = n00b_quic_auth_policy_eval(runtime_policy, &creds);
    n00b_quic_auth_policy_close(runtime_policy);
    if (n00b_result_is_ok(er)) {
        return N00B_RPC_OK;
    }
    int qerr = n00b_result_get_err(er);
    return n00b_rpc_status_from_quic_err(qerr);
}

/* Emit one audit event for an inbound RPC dispatch.  Always called
 * exactly once per dispatch; allow OR deny.  Phase 3's audit topic
 * is the fan-out mechanism — subscribers receive each event. */
static void
emit_audit_event(n00b_rpc_server_t                 *s,
                 const char                        *full_method,
                 const n00b_quic_manifest_policy_t *policy,
                 n00b_rpc_status_t                  status,
                 int64_t                            latency_ns,
                 n00b_h3_inbound_request_t         *ireq)
{
    if (!s) return;
    /* Best-effort peer-address render.  ireq → channel → conn →
     * picoquic_get_peer_addr.  Stack-allocated; lifetime ends at
     * the audit emit call below (subscribers must copy if they
     * need persistence). */
    char                     peer_str[INET6_ADDRSTRLEN + 8] = {0};
    struct sockaddr_storage  peer_ss;
    if (ireq && n00b_h3_inbound_request_peer_addr(ireq, &peer_ss)) {
        if (peer_ss.ss_family == AF_INET) {
            char ip[INET_ADDRSTRLEN] = {0};
            const struct sockaddr_in *p = (const struct sockaddr_in *)&peer_ss;
            inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));
            snprintf(peer_str, sizeof(peer_str), "%s:%u",
                     ip, (unsigned)ntohs(p->sin_port));
        } else if (peer_ss.ss_family == AF_INET6) {
            char ip[INET6_ADDRSTRLEN] = {0};
            const struct sockaddr_in6 *p
                = (const struct sockaddr_in6 *)&peer_ss;
            inet_ntop(AF_INET6, &p->sin6_addr, ip, sizeof(ip));
            snprintf(peer_str, sizeof(peer_str), "[%s]:%u",
                     ip, (unsigned)ntohs(p->sin6_port));
        }
    }

    n00b_quic_audit_event_t evt = {
        .timestamp_ms = (int64_t)(n00b_us_timestamp() / 1000),
        .decision     = (status == N00B_RPC_OK)
                          ? N00B_QUIC_AUDIT_ALLOW
                          : N00B_QUIC_AUDIT_DENY,
        .reason_code  = (status == N00B_RPC_OK)
                          ? N00B_QUIC_OK
                          : (n00b_quic_err_t)status,
        .policy_id    = (policy && policy->id) ? policy->id->data : nullptr,
        .htm          = "POST",
        .htu          = full_method,
        .peer_addr    = peer_str[0] ? peer_str : nullptr,
    };
    /* Fan out via the Phase-3 audit topic. */
    n00b_quic_audit_emit(&evt);

    if (s->audit_stderr) {
        /* Route through the n00b conduit's stderr topic so any
         * subscriber tee'd to the audit stream can mirror these
         * events.  Same fan-out shape as `n00b_eprintf`. */
        n00b_eprintf(
            "[rpc-audit] method=«#» policy=«#» decision=«#» "
            "status=«#» latency_us=«#»",
            full_method ? full_method : "?",
            (policy && policy->id) ? (const char *)policy->id->data
                                    : "(none)",
            evt.decision == N00B_QUIC_AUDIT_ALLOW ? "allow" : "deny",
            (int)status,
            latency_ns / 1000);
    }

    /* Phase 5 § 5.1 — RPC metrics.  No-op if no registry attached.
     * service / method are split from full_method on the last '/';
     * status is the n00b_rpc_status_t enum stringified. */
    if (s->m_calls_total || s->m_call_duration_us) {
        const char *slash    = full_method ? strrchr(full_method, '/')
                                           : nullptr;
        const char *svc_str  = "?";
        const char *meth_str = full_method ? full_method : "?";
        char        svc_buf[128];
        if (slash && (size_t)(slash - full_method) < sizeof(svc_buf)) {
            size_t sl = (size_t)(slash - full_method);
            memcpy(svc_buf, full_method, sl);
            svc_buf[sl] = '\0';
            svc_str  = svc_buf;
            meth_str = slash + 1;
        }
        char status_buf[16];
        snprintf(status_buf, sizeof(status_buf), "%d", (int)status);
        if (s->m_calls_total) {
            n00b_list_t(n00b_buffer_t *) *lv = n00b_alloc(
                n00b_list_t(n00b_buffer_t *));
            *lv = n00b_list_new(n00b_buffer_t *);
            n00b_list_push(*lv, n00b_buffer_from_cstr(svc_str));
            n00b_list_push(*lv, n00b_buffer_from_cstr(meth_str));
            n00b_list_push(*lv, n00b_buffer_from_cstr(status_buf));
            n00b_quic_metric_counter_inc(s->m_calls_total, 1,
                .label_values = lv);
        }
        if (s->m_call_duration_us) {
            n00b_quic_metric_hist_observe(s->m_call_duration_us,
                                          (double)(latency_ns / 1000));
        }
    }
}

void
n00b_rpc_server_attach_metrics(n00b_rpc_server_t           *s,
                               n00b_quic_metric_registry_t *r)
{
    if (!s || !r) return;
    s->metrics_registry = r;
    /* Calls counter. */
    n00b_list_t(n00b_buffer_t *) *labels = n00b_alloc(
        n00b_list_t(n00b_buffer_t *));
    *labels = n00b_list_new(n00b_buffer_t *);
    n00b_list_push(*labels, n00b_buffer_from_cstr("service"));
    n00b_list_push(*labels, n00b_buffer_from_cstr("method"));
    n00b_list_push(*labels, n00b_buffer_from_cstr("status"));
    auto cr = n00b_quic_metric_counter(r,
        "n00b_quic_rpc_calls_total",
        "Total RPC calls served by this dispatcher",
        .labels = labels);
    if (n00b_result_is_ok(cr)) s->m_calls_total = n00b_result_get(cr);

    /* Duration histogram (microseconds, default exponential-ish bucket
     * set covering sub-ms through tens of seconds). */
    static const double duration_buckets[] = {
        100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0,
        500000.0, 1000000.0, 5000000.0, 10000000.0
    };
    auto hr = n00b_quic_metric_hist(r,
        "n00b_quic_rpc_call_duration_us",
        "RPC call duration in microseconds",
        duration_buckets,
        sizeof(duration_buckets) / sizeof(duration_buckets[0]));
    if (n00b_result_is_ok(hr)) s->m_call_duration_us = n00b_result_get(hr);
}

n00b_result_t(bool)
n00b_rpc_server_attach_auth(n00b_rpc_server_t    *s,
                            n00b_quic_manifest_t *mf,
                            bool                  stderr_fallback)
{
    if (!s || !mf) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    /* Sanity-check: every `rpc.services[].auth_policy` must resolve
     * to an `auth.policies[].id`.  Mirror of preflight (sub-phase
     * 4.11) but cheap to re-run here so the operator catches it
     * even when they skip preflight. */
    if (mf->rpc_services) {
        size_t svc_n = (size_t)n00b_list_len(*mf->rpc_services);
        for (size_t i = 0; i < svc_n; i++) {
            const n00b_quic_manifest_rpc_service_t *svc =
                n00b_list_get(*mf->rpc_services, i);
            if (!svc || n00b_quic_mfbuf_empty(svc->auth_policy)) continue;
            if (!manifest_lookup_policy(mf, svc->auth_policy)) {
                return n00b_result_err(bool, N00B_QUIC_ERR_PROTOCOL);
            }
        }
    }
    s->manifest      = mf;
    s->auth_enabled  = true;
    s->audit_stderr  = stderr_fallback;
    return n00b_result_ok(bool, true);
}

void
n00b_rpc_server_set_verifier_resolver(n00b_rpc_server_t              *s,
                                      n00b_rpc_verifier_resolver_fn   fn,
                                      void                           *user_ctx)
{
    if (!s) return;
    s->verifier_resolver     = fn;
    s->verifier_resolver_ctx = user_ctx;
}

/* ===========================================================================
 * Streaming RPC (sub-phase 4.7)
 *
 * The runtime exposes a typed FIFO + close-state holder
 * (`n00b_rpc_buffer_stream_t`) that backs `n00b_rpc_stream_t(T)`
 * pointers.  All allocations come from `conduit_pool` per the
 * project's allocator discipline.
 *
 * Wire shape (per `rpc_design.md` § 2.2-2.4):
 *
 *   - Server-stream: client sends one POST + FIN.  Server emits
 *     HEADERS + N DATA frames (one CBOR item per push) + FIN.
 *   - Client-stream: client emits HEADERS + N DATA frames + FIN.
 *     Server replies with HEADERS + DATA + FIN.
 *   - Bidi: both sides emit HEADERS + DATA frames + FIN
 *     independently.
 *
 * H3 doesn't preserve frame boundaries semantically (RFC 9114 § 4.1):
 * a CBOR item may straddle DATA frames or share one with the next.
 * The runtime therefore reassembles bytes into a moving window and
 * attempts strict CBOR decode at the front; on success the decoded
 * item is pushed onto the stream and the window advances by the
 * consumed bytes.
 * =========================================================================== */

/* ---------------------------------------------------------------------------
 * `n00b_rpc_buffer_stream_t` — FIFO + close state.
 *
 * Intrusive FIFO.  We tried `n00b_linked_list_t(n00b_buffer_t *)`
 * here but its `_first` returns the node under a read lock that is
 * released before the caller can `_remove` — leaving a TOCTOU
 * window where two readers race on the same node.  The recv
 * pattern needs an atomic peek-and-remove that the n00b list
 * doesn't expose.  Manual head/tail with a single rwlock around
 * the (read, remove) pair is the simpler, correct shape.
 * --------------------------------------------------------------------------- */

typedef struct rpc_stream_node {
    n00b_buffer_t          *item;
    struct rpc_stream_node *next;
} rpc_stream_node_t;

struct n00b_rpc_buffer_stream {
    /* The first field MUST mirror `n00b_rpc_stream_t(T)` so a
     * `n00b_rpc_stream_t(T) *` and a `n00b_rpc_buffer_stream_t *` are
     * interchangeable: the macro form is just the typed shell.  We
     * never read this field; it exists for ABI compat with the
     * `_generic_struct typeid("rpc_stream", T)` lowering. */
    void                *_opaque_self;
    n00b_rwlock_t       *lock;
    n00b_futex_t         signal;
    rpc_stream_node_t   *head;
    rpc_stream_node_t   *tail;
    size_t               n;
    bool                 closed;
    n00b_rpc_status_t    close_status;
};

n00b_rpc_stream_t(n00b_buffer_t *) *
n00b_rpc_buffer_stream_new(void)
{
    n00b_rpc_buffer_stream_t *s = n00b_alloc_with_opts(
        n00b_rpc_buffer_stream_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    s->_opaque_self = (void *)s;
    s->lock = n00b_data_lock_new();
    n00b_futex_init(&s->signal);
    return (n00b_rpc_stream_t(n00b_buffer_t *) *)s;
}

n00b_result_t(bool)
n00b_rpc_buffer_stream_send(n00b_rpc_stream_t(n00b_buffer_t *) *stream,
                            n00b_buffer_t                       *item)
{
    if (!stream) return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    n00b_rpc_buffer_stream_t *s = (n00b_rpc_buffer_stream_t *)stream;

    n00b_data_write_lock(s->lock);
    if (s->closed) {
        n00b_data_unlock(s->lock);
        return n00b_result_err(bool, N00B_RPC_ABORTED);
    }
    rpc_stream_node_t *n = n00b_alloc_with_opts(
        rpc_stream_node_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    n->item = item;
    n->next = nullptr;
    if (s->tail) s->tail->next = n;
    else         s->head       = n;
    s->tail = n;
    s->n   += 1;
    n00b_data_unlock(s->lock);
    n00b_futex_wake_all(&s->signal);
    return n00b_result_ok(bool, true);
}

void
n00b_rpc_buffer_stream_close(n00b_rpc_stream_t(n00b_buffer_t *) *stream)
{
    if (!stream) return;
    n00b_rpc_buffer_stream_t *s = (n00b_rpc_buffer_stream_t *)stream;
    n00b_data_write_lock(s->lock);
    if (!s->closed) {
        s->closed       = true;
        s->close_status = N00B_RPC_OK;
    }
    n00b_data_unlock(s->lock);
    n00b_futex_wake_all(&s->signal);
}

void
n00b_rpc_buffer_stream_close_err(n00b_rpc_stream_t(n00b_buffer_t *) *stream,
                                 n00b_rpc_status_t                   status)
{
    if (!stream) return;
    n00b_rpc_buffer_stream_t *s = (n00b_rpc_buffer_stream_t *)stream;
    n00b_data_write_lock(s->lock);
    if (!s->closed) {
        s->closed       = true;
        s->close_status = status == N00B_RPC_OK ? N00B_RPC_ABORTED : status;
    }
    n00b_data_unlock(s->lock);
    n00b_futex_wake_all(&s->signal);
}

bool
n00b_rpc_buffer_stream_is_closed(n00b_rpc_stream_t(n00b_buffer_t *) *stream)
{
    if (!stream) return true;
    n00b_rpc_buffer_stream_t *s = (n00b_rpc_buffer_stream_t *)stream;
    n00b_data_write_lock(s->lock);
    bool c = s->closed;
    n00b_data_unlock(s->lock);
    return c;
}

n00b_rpc_status_t
n00b_rpc_buffer_stream_status(n00b_rpc_stream_t(n00b_buffer_t *) *stream)
{
    if (!stream) return N00B_RPC_INTERNAL;
    n00b_rpc_buffer_stream_t *s = (n00b_rpc_buffer_stream_t *)stream;
    n00b_data_write_lock(s->lock);
    n00b_rpc_status_t st = s->close_status;
    n00b_data_unlock(s->lock);
    return st;
}

/* Pop one item from the stream.  Blocks up to 50ms waiting for data;
 * on timeout returns err with NEED_MORE_DATA so callers can re-poll
 * (typically interleaved with other work like ctx-cancel checks).
 *
 * Errors:
 *   - NULL_ARG          : @p stream is null.
 *   - NEED_MORE_DATA    : stream open + empty (caller polls again).
 *   - end-of-stream     : ok(nullptr) when stream is empty + closed
 *                         cleanly.
 *   - non-OK status     : err(close_status) when stream was err-closed. */
n00b_result_t(n00b_buffer_t *)
n00b_rpc_buffer_stream_recv(n00b_rpc_stream_t(n00b_buffer_t *) *stream)
{
    if (!stream) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    n00b_rpc_buffer_stream_t *s = (n00b_rpc_buffer_stream_t *)stream;

    for (int spin = 0; spin < 5; spin++) {
        n00b_data_write_lock(s->lock);
        if (s->head) {
            rpc_stream_node_t *n = s->head;
            s->head = n->next;
            if (!s->head) s->tail = nullptr;
            s->n -= 1;
            n00b_buffer_t *it = n->item;
            n00b_data_unlock(s->lock);
            return n00b_result_ok(n00b_buffer_t *, it);
        }
        if (s->closed) {
            n00b_rpc_status_t st = s->close_status;
            n00b_data_unlock(s->lock);
            if (st == N00B_RPC_OK) {
                /* Clean end-of-stream → ok(nullptr). */
                return n00b_result_ok(n00b_buffer_t *, nullptr);
            }
            return n00b_result_err(n00b_buffer_t *, (int)st);
        }
        n00b_data_unlock(s->lock);
        (void)n00b_futex_wait(&s->signal, 0,
                              (uint64_t)10 * 1000 * 1000); /* 10ms */
    }
    return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NEED_MORE_DATA);
}

/* ---------------------------------------------------------------------------
 * Header builders shared between client + server streaming
 * --------------------------------------------------------------------------- */

/* Build the standard RPC request headers (content-type + optional
 * deadline + optional auth headers).  Returns a pointer to a
 * stack-borrowed array via @p out; @p deadline_buf must be a
 * 32-byte stack scratch buffer.  Output array must be size ≥ 5.
 * The `Bearer <jwt>` header value is heap-allocated via the rpc
 * allocator (GC-managed), so arbitrarily-large JWTs are handled
 * without truncation.
 *
 * Sub-phase 4.9 per-call override: @p creds_override and @p
 * policy_override (each may be nullptr) take precedence over the
 * channel-level credentials for this single request.  When
 * @p creds_override is non-NULL, ALL of its bearer + dpop fields
 * substitute (a NULL field in the override means "do not send that
 * header for this call", NOT "fall back to channel" — overrides
 * are an all-or-nothing replacement of the auth credentials).
 * @p policy_override is independent: a non-NULL value substitutes
 * for the channel policy id; a NULL value falls back. */
static size_t
build_request_headers_full(n00b_rpc_ctx_t                    *ctx,
                           const n00b_rpc_channel_t          *chan,
                           const n00b_rpc_auth_credentials_t *creds_override,
                           const char                        *policy_override,
                           n00b_h3_header_t                  *out,   /* size >= 5 */
                           char                              *deadline_buf)
{
    size_t n = 0;
    out[n++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"content-type",
        .name_len  = strlen("content-type"),
        .value     = (const uint8_t *)"application/cbor",
        .value_len = strlen("application/cbor"),
    };
    if (ctx) {
        int64_t rem_ns = n00b_rpc_ctx_remaining_ns(ctx);
        if (rem_ns >= 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            int64_t now_ms = (int64_t)ts.tv_sec * 1000
                           + (int64_t)ts.tv_nsec / 1000000;
            int64_t abs_ms = now_ms + rem_ns / 1000000;
            int sn = snprintf(deadline_buf, 32, "%" PRId64, abs_ms);
            if (sn > 0 && sn < 32) {
                out[n++] = (n00b_h3_header_t){
                    .name      = (const uint8_t *)"n00b-rpc-deadline-ms",
                    .name_len  = strlen("n00b-rpc-deadline-ms"),
                    .value     = (const uint8_t *)deadline_buf,
                    .value_len = (size_t)sn,
                };
            }
        }
    }
    /* Sub-phase 4.9: auth headers.  Resolve the effective bearer +
     * dpop + policy: per-call override wins when present, else fall
     * back to channel state.  `authorization: Bearer <jwt>` value is
     * heap-allocated (no silent truncation). */
    const char *eff_bearer = nullptr;
    const char *eff_dpop   = nullptr;
    const char *eff_policy = nullptr;
    if (creds_override) {
        eff_bearer = creds_override->bearer_token;
        eff_dpop   = creds_override->dpop_proof;
    }
    else if (chan) {
        eff_bearer = chan->auth_bearer;
        eff_dpop   = chan->auth_dpop;
    }
    if (policy_override) {
        eff_policy = policy_override;
    }
    else if (chan) {
        eff_policy = chan->auth_policy_id;
    }

    if (eff_bearer) {
        size_t blen   = strlen(eff_bearer);
        size_t needed = strlen("Bearer ") + blen + 1;
        char  *bearer_hdr = n00b_alloc_array_with_opts(
            char, (int64_t)needed,
            &(n00b_alloc_opts_t){
                .allocator = n00b_rpc_alloc(),
                .no_scan   = true,
            });
        memcpy(bearer_hdr, "Bearer ", 7);
        memcpy(bearer_hdr + 7, eff_bearer, blen);
        bearer_hdr[7 + blen] = '\0';
        out[n++] = (n00b_h3_header_t){
            .name      = (const uint8_t *)"authorization",
            .name_len  = strlen("authorization"),
            .value     = (const uint8_t *)bearer_hdr,
            .value_len = needed - 1,
        };
    }
    if (eff_dpop) {
        out[n++] = (n00b_h3_header_t){
            .name      = (const uint8_t *)"dpop",
            .name_len  = strlen("dpop"),
            .value     = (const uint8_t *)eff_dpop,
            .value_len = strlen(eff_dpop),
        };
    }
    if (eff_policy) {
        out[n++] = (n00b_h3_header_t){
            .name      = (const uint8_t *)"n00b-rpc-policy",
            .name_len  = strlen("n00b-rpc-policy"),
            .value     = (const uint8_t *)eff_policy,
            .value_len = strlen(eff_policy),
        };
    }
    return n;
}


/* Pull as many complete CBOR items as possible from a moving byte
 * window; for each item, push onto the stream.  Updates *consumed
 * with the total bytes consumed.  Returns ok(true) on success;
 * err(N00B_QUIC_ERR_NEED_MORE_DATA) when no full item is decodable
 * yet (caller should accumulate more bytes); err on a strict-mode
 * decode failure (caller treats as protocol error). */
static n00b_result_t(bool)
push_decoded_items(n00b_rpc_stream_t(n00b_buffer_t *) *stream,
                   const uint8_t                       *data,
                   size_t                               len,
                   size_t                              *consumed)
{
    *consumed = 0;
    while (*consumed < len) {
        const uint8_t *here  = data + *consumed;
        size_t         avail = len - *consumed;
        /* O(N) item segmentation: `n00b_cbor_decode_first_bytes`
         * decodes the head of the window and reports the bytes used;
         * trailing bytes stay in the caller's window for the next
         * pull.  We follow with a strict-mode revalidation pass on
         * the exact slice for the 4.7 hardening (tag allowlist +
         * dup-key rejection).  Replaces an earlier O(N^2)
         * bracket-search. */
        size_t item_len = 0;
        auto   r        = n00b_cbor_decode_first_bytes(here, avail,
                                                       &item_len);
        if (n00b_result_is_err(r)) {
            int e = n00b_result_get_err(r);
            if (e == N00B_QUIC_ERR_NEED_MORE_DATA) {
                /* Wait for more bytes; non-fatal. */
                return n00b_result_err(bool, N00B_QUIC_ERR_NEED_MORE_DATA);
            }
            return n00b_result_err(bool, e);
        }
        auto sr = n00b_cbor_decode_strict_bytes(here, item_len, nullptr);
        if (n00b_result_is_err(sr)) {
            return n00b_result_err(bool, n00b_result_get_err(sr));
        }
        n00b_buffer_t *frame = n00b_alloc_with_opts(
            n00b_buffer_t,
            &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
        n00b_buffer_init(frame, .length = 0,
                         .allocator = n00b_rpc_alloc(),
                         .no_lock   = true);
        n00b_buffer_resize(frame, (uint64_t)item_len);
        memcpy((uint8_t *)frame->data, here, item_len);
        (void)n00b_rpc_buffer_stream_send(stream, frame);
        *consumed += item_len;
    }
    return n00b_result_ok(bool, true);
}

/* ---------------------------------------------------------------------------
 * Client side: pump one direction of a streaming H3 request into a
 * stream.
 * --------------------------------------------------------------------------- */

typedef struct {
    n00b_h3_request_t                    *req;
    n00b_rpc_stream_t(n00b_buffer_t *)   *stream;
    n00b_rpc_ctx_t                       *ctx;
    n00b_quic_endpoint_t                 *ep;
    _Atomic uint32_t                      shutdown;
    n00b_thread_t                        *thread;
    bool                                  started;
} client_recv_pump_t;

/* Drain DATA from the request stream into @p stream.  Continues until
 * peer FIN, ctx cancel, or local shutdown. */
static void *
client_recv_pump_main(void *arg)
{
    client_recv_pump_t *p = (client_recv_pump_t *)arg;
    n00b_buffer_t *acc = n00b_buffer_empty(.allocator = n00b_rpc_alloc());

    while (atomic_load(&p->shutdown) == 0) {
        if (p->ctx && n00b_rpc_ctx_is_cancelled(p->ctx)) {
            n00b_h3_request_cancel(p->req);
            break;
        }
        if (p->ep) n00b_quic_endpoint_run_once(p->ep, 2);
        n00b_h3_client_drive(p->req->client);

        /* Drain currently-buffered body bytes. */
        uint8_t scratch[2048];
        size_t  got;
        while ((got = n00b_h3_request_consume_body(p->req, scratch,
                                                   sizeof(scratch))) > 0) {
            size_t old = acc->byte_len;
            n00b_buffer_resize(acc, old + got);
            memcpy(acc->data + old, scratch, got);

            /* Try to decode as many CBOR items as possible. */
            size_t consumed = 0;
            auto pr = push_decoded_items(p->stream,
                                         (uint8_t *)acc->data,
                                         acc->byte_len, &consumed);
            if (n00b_result_is_err(pr)) {
                int e = n00b_result_get_err(pr);
                if (e == N00B_QUIC_ERR_NEED_MORE_DATA) {
                    /* Wait for more bytes. */
                } else {
                    n00b_rpc_buffer_stream_close_err(p->stream,
                        N00B_RPC_INVALID_ARGUMENT);
                    n00b_h3_request_cancel(p->req);
                    return nullptr;
                }
            }
            if (consumed > 0) {
                if (consumed < acc->byte_len) {
                    memmove(acc->data, acc->data + consumed,
                            acc->byte_len - consumed);
                }
                n00b_buffer_resize(acc, acc->byte_len - consumed);
            }
        }

        /* Check for FIN / reset. */
        if (n00b_h3_request_is_reset(p->req)) {
            /* Map to CANCELLED unless we know better. */
            n00b_rpc_status_t st = N00B_RPC_CANCELLED;
            if (n00b_h3_request_headers_received(p->req)) {
                /* Read n00b-rpc-status header if present. */
                size_t hn = 0;
                const n00b_h3_header_t *hh =
                    n00b_h3_request_response_headers(p->req, &hn);
                size_t      vlen = 0;
                const char *vv   = find_header_value(hh, hn,
                                                       "n00b-rpc-status",
                                                       &vlen);
                if (vv && vlen < 16) {
                    char tmp[16];
                    memcpy(tmp, vv, vlen);
                    tmp[vlen] = '\0';
                    int sc = (int)strtol(tmp, nullptr, 10);
                    if (sc > 0) st = (n00b_rpc_status_t)sc;
                }
            }
            n00b_rpc_buffer_stream_close_err(p->stream, st);
            return nullptr;
        }
        if (n00b_h3_request_recv_fin(p->req) && acc->byte_len == 0) {
            /* Check status header for non-OK trailing status. */
            n00b_rpc_status_t st = N00B_RPC_OK;
            size_t hn = 0;
            const n00b_h3_header_t *hh =
                n00b_h3_request_response_headers(p->req, &hn);
            size_t      vlen = 0;
            const char *vv   = find_header_value(hh, hn, "n00b-rpc-status",
                                                   &vlen);
            if (vv && vlen < 16) {
                char tmp[16];
                memcpy(tmp, vv, vlen);
                tmp[vlen] = '\0';
                int sc = (int)strtol(tmp, nullptr, 10);
                if (sc > 0) st = (n00b_rpc_status_t)sc;
            }
            if (st == N00B_RPC_OK) {
                n00b_rpc_buffer_stream_close(p->stream);
            } else {
                n00b_rpc_buffer_stream_close_err(p->stream, st);
            }
            return nullptr;
        }

        /* Brief pause between pump iterations. */
        struct timespec sl = { 0, 1 * 1000 * 1000 };
        nanosleep(&sl, nullptr);
    }
    return nullptr;
}

static client_recv_pump_t *
client_recv_pump_start(n00b_h3_request_t                  *req,
                       n00b_rpc_stream_t(n00b_buffer_t *) *stream,
                       n00b_rpc_ctx_t                     *ctx)
{
    client_recv_pump_t *p = n00b_alloc_with_opts(
        client_recv_pump_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    p->req    = req;
    p->stream = stream;
    p->ctx    = ctx;
    p->ep     = n00b_quic_conn_endpoint(n00b_quic_chan_conn(req->chan));
    atomic_store(&p->shutdown, 0);
    auto tr = n00b_thread_spawn(client_recv_pump_main, p);
    if (n00b_result_is_ok(tr)) {
        p->thread  = n00b_result_get(tr);
        p->started = true;
    }
    return p;
}

static void
client_recv_pump_stop(client_recv_pump_t *p)
{
    if (!p || !p->started) return;
    atomic_store(&p->shutdown, 1);
    n00b_thread_join(p->thread);
    p->started = false;
}

/* ---------------------------------------------------------------------------
 * `n00b_rpc_call_server_stream`
 * --------------------------------------------------------------------------- */

/* Sub-phase 4.9: shared per-call credential sanity check.  Returns
 * true if the call should be refused as UNAUTHENTICATED.  Factors
 * the rule used by all four call sites: a per-call override with
 * an empty bearer is a misconfiguration; if any policy id is in
 * play (per-call OR channel-level) but no bearer is available
 * from any source, refuse rather than send unauthenticated. */
static bool
auth_preflight_unauthenticated(const n00b_rpc_channel_t          *chan,
                               const n00b_rpc_auth_credentials_t *creds_override,
                               const char                        *policy_override)
{
    if (creds_override
        && (!creds_override->bearer_token
            || creds_override->bearer_token[0] == '\0')) {
        return true;
    }
    const char *eff_policy = policy_override ? policy_override
                                              : (chan ? chan->auth_policy_id
                                                      : nullptr);
    const char *eff_bearer = creds_override ? creds_override->bearer_token
                                            : (chan ? chan->auth_bearer
                                                    : nullptr);
    if (eff_policy && (!eff_bearer || eff_bearer[0] == '\0')) {
        return true;
    }
    return false;
}

n00b_result_t(n00b_rpc_stream_t(n00b_buffer_t *) *)
n00b_rpc_call_server_stream(n00b_rpc_ctx_t     *ctx,
                            n00b_rpc_channel_t *chan,
                            const char         *full_method,
                            n00b_buffer_t      *req_cbor) _kargs
{
    const n00b_rpc_auth_credentials_t *creds_override  = nullptr;
    const char                        *policy_override = nullptr;
}
{
    if (!chan || !chan->h3 || !full_method) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    if (ctx && n00b_rpc_ctx_is_cancelled(ctx)) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               N00B_RPC_CANCELLED);
    }
    if (auth_preflight_unauthenticated(chan, creds_override, policy_override)) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               N00B_RPC_UNAUTHENTICATED);
    }

    char             dbuf[32] = {0};
    n00b_h3_header_t extras[5];
    size_t           n_extras = build_request_headers_full(
        ctx, chan, creds_override, policy_override, extras, dbuf);

    char *path = make_path(full_method);

    const uint8_t *body     = req_cbor ? (const uint8_t *)req_cbor->data : nullptr;
    size_t         body_len = req_cbor ? (size_t)req_cbor->byte_len : 0;

    auto reqr = n00b_h3_client_request(
        chan->h3,
        (n00b_h3_request_spec_t){
            .method    = "POST",
            .scheme    = chan->scheme,
            .authority = chan->authority,
            .path      = path,
            .headers   = { .items = extras, .count = n_extras },
            .body      = body,
            .body_len  = body_len,
        });
    if (n00b_result_is_err(reqr)) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               n00b_result_get_err(reqr));
    }
    n00b_h3_request_t *h3req = n00b_result_get(reqr);

    n00b_rpc_stream_t(n00b_buffer_t *) *out = n00b_rpc_buffer_stream_new();
    /* Spin a recv pump that drains DATA → out. */
    (void)client_recv_pump_start(h3req, out, ctx);

    return n00b_result_ok(n00b_rpc_stream_t(n00b_buffer_t *) *, out);
}

/* ---------------------------------------------------------------------------
 * `n00b_rpc_call_client_stream`
 * --------------------------------------------------------------------------- */

typedef struct {
    n00b_h3_request_t                    *req;
    n00b_rpc_stream_t(n00b_buffer_t *)   *in;
    n00b_rpc_ctx_t                       *ctx;
    _Atomic uint32_t                      done;
    n00b_thread_t                        *thread;
    bool                                  started;
    bool                                  send_err;
    int                                   send_err_code;
} client_send_pump_t;

static void *
client_send_pump_main(void *arg)
{
    client_send_pump_t *p = (client_send_pump_t *)arg;
    while (true) {
        if (p->ctx && n00b_rpc_ctx_is_cancelled(p->ctx)) {
            n00b_h3_request_cancel(p->req);
            atomic_store(&p->done, 1);
            return nullptr;
        }
        auto rr = n00b_rpc_buffer_stream_recv(p->in);
        if (n00b_result_is_err(rr)) {
            int e = n00b_result_get_err(rr);
            if (e == N00B_QUIC_ERR_NEED_MORE_DATA) continue;
            /* Stream err-closed.  Cancel the H3 request. */
            n00b_h3_request_cancel(p->req);
            p->send_err      = true;
            p->send_err_code = e;
            atomic_store(&p->done, 1);
            return nullptr;
        }
        n00b_buffer_t *item = n00b_result_get(rr);
        if (!item) {
            /* End-of-stream: FIN. */
            (void)n00b_h3_request_send_data(
                p->req,
                (n00b_h3_data_t){ .fin = true });
            atomic_store(&p->done, 1);
            return nullptr;
        }
        auto sr = n00b_h3_request_send_data(
            p->req,
            (n00b_h3_data_t){
                .body     = (const uint8_t *)item->data,
                .body_len = (size_t)item->byte_len,
            });
        if (n00b_result_is_err(sr)) {
            p->send_err      = true;
            p->send_err_code = n00b_result_get_err(sr);
            atomic_store(&p->done, 1);
            return nullptr;
        }
    }
}

static client_send_pump_t *
client_send_pump_start(n00b_h3_request_t                   *req,
                       n00b_rpc_stream_t(n00b_buffer_t *)  *in,
                       n00b_rpc_ctx_t                      *ctx)
{
    client_send_pump_t *p = n00b_alloc_with_opts(
        client_send_pump_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    p->req = req;
    p->in  = in;
    p->ctx = ctx;
    atomic_store(&p->done, 0);
    auto tr = n00b_thread_spawn(client_send_pump_main, p);
    if (n00b_result_is_ok(tr)) {
        p->thread  = n00b_result_get(tr);
        p->started = true;
    }
    return p;
}

static void
client_send_pump_join(client_send_pump_t *p)
{
    if (!p || !p->started) return;
    n00b_thread_join(p->thread);
    p->started = false;
}

n00b_result_t(n00b_buffer_t *)
n00b_rpc_call_client_stream(n00b_rpc_ctx_t                     *ctx,
                            n00b_rpc_channel_t                 *chan,
                            const char                         *full_method,
                            n00b_rpc_stream_t(n00b_buffer_t *) *in) _kargs
{
    const n00b_rpc_auth_credentials_t *creds_override  = nullptr;
    const char                        *policy_override = nullptr;
}
{
    if (!chan || !chan->h3 || !full_method || !in) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    if (ctx && n00b_rpc_ctx_is_cancelled(ctx)) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_CANCELLED);
    }
    if (auth_preflight_unauthenticated(chan, creds_override, policy_override)) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_UNAUTHENTICATED);
    }

    char             dbuf[32] = {0};
    n00b_h3_header_t extras[5];
    size_t           n_extras = build_request_headers_full(
        ctx, chan, creds_override, policy_override, extras, dbuf);
    char            *path     = make_path(full_method);

    /* Open without FIN; the send-pump drains @p in onto the wire. */
    auto reqr = n00b_h3_client_request(
        chan->h3,
        (n00b_h3_request_spec_t){
            .method    = "POST",
            .scheme    = chan->scheme,
            .authority = chan->authority,
            .path      = path,
            .headers   = { .items = extras, .count = n_extras },
            .keep_open = true,
        });
    if (n00b_result_is_err(reqr)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(reqr));
    }
    n00b_h3_request_t *h3req = n00b_result_get(reqr);

    cancel_watcher_t *watcher = cancel_watcher_start(ctx, h3req);
    client_send_pump_t *sp    = client_send_pump_start(h3req, in, ctx);

    /* Compute deadline. */
    int32_t deadline_ms = 10000;
    if (ctx) {
        int64_t rem_ns = n00b_rpc_ctx_remaining_ns(ctx);
        if (rem_ns == 0) {
            client_send_pump_join(sp);
            cancel_watcher_stop(watcher);
            return n00b_result_err(n00b_buffer_t *, N00B_RPC_DEADLINE_EXCEEDED);
        }
        if (rem_ns > 0) {
            int64_t rem_ms = rem_ns / 1000000 + 1;
            if (rem_ms < INT32_MAX) deadline_ms = (int32_t)rem_ms;
        }
    }

    auto rsp = n00b_h3_request_await(h3req, .deadline_ms = deadline_ms);

    client_send_pump_join(sp);
    cancel_watcher_stop(watcher);

    if (n00b_result_is_err(rsp)) {
        int err = n00b_result_get_err(rsp);
        if (ctx && n00b_rpc_ctx_is_cancelled(ctx)) {
            int64_t rem = n00b_rpc_ctx_remaining_ns(ctx);
            if (rem == 0 && err == N00B_QUIC_ERR_TIMEOUT) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_RPC_DEADLINE_EXCEEDED);
            }
            return n00b_result_err(n00b_buffer_t *, N00B_RPC_CANCELLED);
        }
        return n00b_result_err(n00b_buffer_t *, err);
    }

    n00b_h3_response_t *resp = n00b_result_get(rsp);
    size_t      sv_len = 0;
    const char *sv = find_header_value(resp->headers, resp->n_headers,
                                        "n00b-rpc-status", &sv_len);
    int32_t status_code = -1;
    if (sv) {
        char tmp[16];
        if (sv_len < sizeof(tmp)) {
            memcpy(tmp, sv, sv_len);
            tmp[sv_len] = '\0';
            status_code = (int32_t)strtol(tmp, nullptr, 10);
        }
    }
    if (status_code == N00B_RPC_OK ||
        (status_code < 0 && resp->status == 200)) {
        if (resp->body) {
            return n00b_result_ok(n00b_buffer_t *, resp->body);
        }
        n00b_buffer_t *empty = n00b_alloc_with_opts(
            n00b_buffer_t,
            &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
        n00b_buffer_init(empty, .length = 0,
                         .allocator = n00b_rpc_alloc(), .no_lock = true);
        return n00b_result_ok(n00b_buffer_t *, empty);
    }
    if (status_code >= 0) {
        return n00b_result_err(n00b_buffer_t *, status_code);
    }
    if (resp->status == 404) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_UNIMPLEMENTED);
    }
    if (resp->status == 504) {
        return n00b_result_err(n00b_buffer_t *, N00B_RPC_DEADLINE_EXCEEDED);
    }
    return n00b_result_err(n00b_buffer_t *, N00B_RPC_UNKNOWN);
}

/* ---------------------------------------------------------------------------
 * `n00b_rpc_call_bidi`
 * --------------------------------------------------------------------------- */

n00b_result_t(n00b_rpc_stream_t(n00b_buffer_t *) *)
n00b_rpc_call_bidi(n00b_rpc_ctx_t                     *ctx,
                   n00b_rpc_channel_t                 *chan,
                   const char                         *full_method,
                   n00b_rpc_stream_t(n00b_buffer_t *) *in) _kargs
{
    const n00b_rpc_auth_credentials_t *creds_override  = nullptr;
    const char                        *policy_override = nullptr;
}
{
    if (!chan || !chan->h3 || !full_method || !in) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    if (ctx && n00b_rpc_ctx_is_cancelled(ctx)) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               N00B_RPC_CANCELLED);
    }
    if (auth_preflight_unauthenticated(chan, creds_override, policy_override)) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               N00B_RPC_UNAUTHENTICATED);
    }

    char             dbuf[32] = {0};
    n00b_h3_header_t extras[5];
    size_t           n_extras = build_request_headers_full(
        ctx, chan, creds_override, policy_override, extras, dbuf);
    char            *path     = make_path(full_method);

    auto reqr = n00b_h3_client_request(
        chan->h3,
        (n00b_h3_request_spec_t){
            .method    = "POST",
            .scheme    = chan->scheme,
            .authority = chan->authority,
            .path      = path,
            .headers   = { .items = extras, .count = n_extras },
            .keep_open = true,
        });
    if (n00b_result_is_err(reqr)) {
        return n00b_result_err(n00b_rpc_stream_t(n00b_buffer_t *) *,
                               n00b_result_get_err(reqr));
    }
    n00b_h3_request_t *h3req = n00b_result_get(reqr);

    /* Outbound: drain @p in onto the wire. */
    (void)client_send_pump_start(h3req, in, ctx);

    /* Inbound: pump DATA → out_stream. */
    n00b_rpc_stream_t(n00b_buffer_t *) *out = n00b_rpc_buffer_stream_new();
    (void)client_recv_pump_start(h3req, out, ctx);

    return n00b_result_ok(n00b_rpc_stream_t(n00b_buffer_t *) *, out);
}

/* ===========================================================================
 * Server-side streaming dispatch
 *
 * The server worker (`server_worker_main`) routes streaming patterns
 * to `dispatch_streaming_inbound` (forward-declared up in the unary
 * dispatch path).
 * =========================================================================== */

/* Per-streaming-call state spawned for each inbound streaming RPC.
 * Owns a couple of pump threads + the inbound stream + handler ctx. */
typedef struct {
    rpc_entry_t                          *entry;
    n00b_h3_inbound_request_t            *ireq;
    n00b_rpc_ctx_t                       *ctx;
    /* For client-stream / bidi: stream of inbound CBOR items. */
    n00b_rpc_stream_t(n00b_buffer_t *)   *in_stream;
    /* For server-stream / bidi: stream the handler emits items into. */
    n00b_rpc_stream_t(n00b_buffer_t *)   *out_stream;
    /* Pump threads. */
    n00b_thread_t                        *recv_thread;
    n00b_thread_t                        *send_thread;
    n00b_thread_t                        *worker_thread;
    bool                                  recv_started;
    bool                                  send_started;
    bool                                  worker_started;
    _Atomic uint32_t                      shutdown;
} streaming_call_t;

/* Pump inbound request DATA frames into in_stream. */
static void *
server_recv_pump_main(void *arg)
{
    streaming_call_t *s = (streaming_call_t *)arg;
    n00b_buffer_t *acc = n00b_buffer_empty(.allocator = n00b_rpc_alloc());

    while (atomic_load(&s->shutdown) == 0) {
        if (s->ctx && n00b_rpc_ctx_is_cancelled(s->ctx)) {
            n00b_rpc_buffer_stream_close_err(s->in_stream, N00B_RPC_CANCELLED);
            return nullptr;
        }
        uint8_t scratch[2048];
        size_t  got;
        bool    progressed = false;
        while ((got = n00b_h3_inbound_request_consume_body(s->ireq, scratch,
                                                           sizeof(scratch))) > 0) {
            progressed = true;
            size_t old = acc->byte_len;
            n00b_buffer_resize(acc, old + got);
            memcpy(acc->data + old, scratch, got);

            size_t consumed = 0;
            auto pr = push_decoded_items(s->in_stream,
                                         (uint8_t *)acc->data,
                                         acc->byte_len, &consumed);
            if (n00b_result_is_err(pr)) {
                int e = n00b_result_get_err(pr);
                if (e != N00B_QUIC_ERR_NEED_MORE_DATA) {
                    /* Strict-decode failed → INVALID_ARGUMENT. */
                    n00b_rpc_buffer_stream_close_err(s->in_stream,
                        N00B_RPC_INVALID_ARGUMENT);
                    return nullptr;
                }
            }
            if (consumed > 0) {
                if (consumed < acc->byte_len) {
                    memmove(acc->data, acc->data + consumed,
                            acc->byte_len - consumed);
                }
                n00b_buffer_resize(acc, acc->byte_len - consumed);
            }
        }

        if (n00b_h3_inbound_request_peer_fin(s->ireq) && acc->byte_len == 0) {
            n00b_rpc_buffer_stream_close(s->in_stream);
            return nullptr;
        }
        if (!progressed) {
            struct timespec sl = { 0, 1 * 1000 * 1000 };
            nanosleep(&sl, nullptr);
        }
    }
    n00b_rpc_buffer_stream_close_err(s->in_stream, N00B_RPC_CANCELLED);
    return nullptr;
}

/* Drain handler's out_stream onto the wire as DATA frames; FIN when
 * stream closes.  Sends HEADERS first if needed. */
static void *
server_send_pump_main(void *arg)
{
    streaming_call_t *s = (streaming_call_t *)arg;
    /* Emit response HEADERS up front (status=200, content-type, rpc-status=0). */
    n00b_h3_header_t hdrs[2];
    size_t           n_hdrs = 0;
    hdrs[n_hdrs++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"content-type",
        .name_len  = strlen("content-type"),
        .value     = (const uint8_t *)"application/cbor",
        .value_len = strlen("application/cbor"),
    };
    hdrs[n_hdrs++] = (n00b_h3_header_t){
        .name      = (const uint8_t *)"n00b-rpc-status",
        .name_len  = strlen("n00b-rpc-status"),
        .value     = (const uint8_t *)"0",
        .value_len = 1,
    };
    (void)n00b_h3_inbound_request_send_headers(
        s->ireq,
        (n00b_h3_response_headers_t){
            .status  = 200,
            .headers = { .items = hdrs, .count = n_hdrs },
        });

    while (atomic_load(&s->shutdown) == 0) {
        if (s->ctx && n00b_rpc_ctx_is_cancelled(s->ctx)) {
            n00b_h3_inbound_request_reset(s->ireq, 1);
            return nullptr;
        }
        auto rr = n00b_rpc_buffer_stream_recv(s->out_stream);
        if (n00b_result_is_err(rr)) {
            int e = n00b_result_get_err(rr);
            if (e == N00B_QUIC_ERR_NEED_MORE_DATA) continue;
            /* Err-closed: emit a final empty DATA + FIN, AND surface the
             * status via a RESET_STREAM with a mapped error code so the
             * client's recv pump can read the err. */
            n00b_h3_inbound_request_reset(s->ireq, (uint64_t)e);
            return nullptr;
        }
        n00b_buffer_t *item = n00b_result_get(rr);
        if (!item) {
            /* Clean end of stream: FIN. */
            (void)n00b_h3_inbound_request_send_data(
                s->ireq,
                (n00b_h3_data_t){ .fin = true });
            return nullptr;
        }
        (void)n00b_h3_inbound_request_send_data(
            s->ireq,
            (n00b_h3_data_t){
                .body     = (const uint8_t *)item->data,
                .body_len = (size_t)item->byte_len,
            });
    }
    return nullptr;
}

/* For server-stream + bidi: invoke the handler to obtain the
 * out_stream pointer, then start the send pump. */
static void *
streaming_worker_main(void *arg)
{
    streaming_call_t *s = (streaming_call_t *)arg;
    rpc_entry_t      *e = s->entry;

    if (e->pattern == RPC_PATTERN_SERVER_STREAM) {
        n00b_buffer_t *body = n00b_h3_inbound_request_body(s->ireq);
        if (!body) {
            body = n00b_alloc_with_opts(
                n00b_buffer_t,
                &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
            n00b_buffer_init(body, .length = 0,
                             .allocator = n00b_rpc_alloc(), .no_lock = true);
        }
        n00b_rpc_server_stream_dispatch_fn_t fn =
            (n00b_rpc_server_stream_dispatch_fn_t)e->fn;
        auto r = fn(body, s->ctx);
        if (n00b_result_is_err(r)) {
            int ec = n00b_result_get_err(r);
            n00b_rpc_status_t st;
            if (ec >= N00B_RPC_OK && ec <= N00B_RPC_UNAUTHENTICATED) {
                st = (n00b_rpc_status_t)ec;
            } else {
                st = n00b_rpc_status_from_quic_err(ec);
                if (st == N00B_RPC_OK) st = N00B_RPC_INTERNAL;
            }
            respond_with_status(s->ireq, st);
            return nullptr;
        }
        s->out_stream = n00b_result_get(r);
        /* Start send pump. */
        auto tr = n00b_thread_spawn(server_send_pump_main, s);
        if (n00b_result_is_ok(tr)) {
            s->send_thread  = n00b_result_get(tr);
            s->send_started = true;
            n00b_thread_join(s->send_thread);
        }
    }
    else if (e->pattern == RPC_PATTERN_CLIENT_STREAM) {
        /* recv pump must already be running; invoke handler with
         * in_stream + ctx, await its reply. */
        n00b_rpc_client_stream_dispatch_fn_t fn =
            (n00b_rpc_client_stream_dispatch_fn_t)e->fn;
        auto r = fn(s->in_stream, s->ctx);
        if (n00b_result_is_err(r)) {
            int ec = n00b_result_get_err(r);
            n00b_rpc_status_t st;
            if (ec >= N00B_RPC_OK && ec <= N00B_RPC_UNAUTHENTICATED) {
                st = (n00b_rpc_status_t)ec;
            } else {
                st = n00b_rpc_status_from_quic_err(ec);
                if (st == N00B_RPC_OK) st = N00B_RPC_INTERNAL;
            }
            respond_with_status(s->ireq, st);
            return nullptr;
        }
        respond_with_ok(s->ireq, n00b_result_get(r));
    }
    else { /* RPC_PATTERN_BIDI */
        n00b_rpc_bidi_dispatch_fn_t fn =
            (n00b_rpc_bidi_dispatch_fn_t)e->fn;
        auto r = fn(s->in_stream, s->ctx);
        if (n00b_result_is_err(r)) {
            int ec = n00b_result_get_err(r);
            n00b_rpc_status_t st;
            if (ec >= N00B_RPC_OK && ec <= N00B_RPC_UNAUTHENTICATED) {
                st = (n00b_rpc_status_t)ec;
            } else {
                st = n00b_rpc_status_from_quic_err(ec);
                if (st == N00B_RPC_OK) st = N00B_RPC_INTERNAL;
            }
            respond_with_status(s->ireq, st);
            return nullptr;
        }
        s->out_stream = n00b_result_get(r);
        auto tr = n00b_thread_spawn(server_send_pump_main, s);
        if (n00b_result_is_ok(tr)) {
            s->send_thread  = n00b_result_get(tr);
            s->send_started = true;
            n00b_thread_join(s->send_thread);
        }
    }
    return nullptr;
}

/* Entry point invoked by `dispatch_inbound` when the registered method
 * isn't unary.  Sets up streams + pump threads + invokes the handler.
 *
 * Note: this runs on the server worker thread.  It blocks until the
 * call completes (FIN both ways or reset) — the worker is single
 * threaded by design (mirror of the unary path).  Concurrent inbound
 * streaming calls would require a dispatcher thread pool; v1 serves
 * one streaming call at a time per attached server.  Documented as
 * a known limitation. */
void
dispatch_streaming_inbound(rpc_entry_t              *e,
                           n00b_h3_inbound_request_t *ireq,
                           n00b_buffer_t            *body,
                           n00b_rpc_ctx_t           *ctx)
{
    (void)body;
    streaming_call_t *s = n00b_alloc_with_opts(
        streaming_call_t,
        &(n00b_alloc_opts_t){ .allocator = n00b_rpc_alloc() });
    s->entry = e;
    s->ireq  = ireq;
    s->ctx   = ctx;
    atomic_store(&s->shutdown, 0);

    /* Build inbound stream for client-stream + bidi. */
    if (e->pattern == RPC_PATTERN_CLIENT_STREAM ||
        e->pattern == RPC_PATTERN_BIDI) {
        s->in_stream = n00b_rpc_buffer_stream_new();
        auto tr = n00b_thread_spawn(server_recv_pump_main, s);
        if (n00b_result_is_ok(tr)) {
            s->recv_thread  = n00b_result_get(tr);
            s->recv_started = true;
        }
    }

    /* Invoke handler (synchronously on this worker thread).  Server-
     * stream + bidi handlers return out_stream; the worker_main runs
     * the send pump until close.  Client-stream awaits the reply. */
    streaming_worker_main(s);

    /* Tear down. */
    atomic_store(&s->shutdown, 1);
    if (s->recv_started) {
        n00b_thread_join(s->recv_thread);
    }
    n00b_rpc_ctx_close(ctx);
}
