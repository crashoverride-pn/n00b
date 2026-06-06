#include "internal/core/signals.h"

#include "conduit/signal.h"
#include "internal/display/terminal_lifecycle.h"

#include <signal.h>

#ifndef _WIN32
#include "core/syscall.h"
#else
#include <stdlib.h>
#endif

static n00b_conduit_signal_inbox_t *g_default_signal_inbox = nullptr;
static n00b_conduit_sub_handle_t    g_default_signal_subs[4];
static int                          g_default_signal_count = 0;
static _Atomic(bool)                g_default_signals_active = false;

#if defined(__linux__)
static bool     g_default_mask_prepared = false;
static sigset_t g_default_unblock_mask;
#endif

static int
default_signal_at(int ix)
{
    switch (ix) {
    case 0:
        return SIGINT;
    case 1:
        return SIGTERM;
#ifndef _WIN32
    case 2:
        return SIGQUIT;
    case 3:
        return SIGHUP;
#endif
    default:
        return 0;
    }
}

static bool
is_default_signal(int signum)
{
    for (int i = 0; i < 4; i++) {
        if (default_signal_at(i) == signum) {
            return true;
        }
    }
    return false;
}

void
n00b_runtime_signal_defaults_prepare(void)
{
#if defined(__linux__)
    sigset_t mask;
    sigemptyset(&mask);
    for (int i = 0; i < 4; i++) {
        int signum = default_signal_at(i);
        if (signum > 0) {
            sigaddset(&mask, signum);
        }
    }

    sigset_t old_mask;
    if (sigprocmask(SIG_BLOCK, &mask, &old_mask) != 0) {
        return;
    }

    sigemptyset(&g_default_unblock_mask);
    for (int i = 0; i < 4; i++) {
        int signum = default_signal_at(i);
        if (signum > 0 && sigismember(&old_mask, signum) == 0) {
            sigaddset(&g_default_unblock_mask, signum);
        }
    }
    g_default_mask_prepared = true;
#endif
}

void
n00b_runtime_signal_defaults_install(n00b_runtime_t *rt)
{
    if (!rt || !rt->default_conduit) {
        return;
    }

    g_default_signal_inbox = n00b_conduit_signal_inbox_new(rt->default_conduit);
    if (!g_default_signal_inbox) {
        return;
    }

    g_default_signal_count = 0;
    for (int i = 0; i < 4; i++) {
        int signum = default_signal_at(i);
        if (signum <= 0) {
            continue;
        }

        n00b_result_t(n00b_conduit_topic_base_t *) topic_r =
            n00b_conduit_signal_topic(rt->default_conduit, signum);
        if (n00b_result_is_err(topic_r)) {
            continue;
        }

        n00b_conduit_topic_base_t *topic = n00b_result_get(topic_r);
        n00b_conduit_sub_handle_t handle =
            n00b_conduit_signal_subscribe(topic,
                                          g_default_signal_inbox,
                                          .operations = N00B_CONDUIT_OP_ALL);
        if (handle != N00B_CONDUIT_INVALID_SUB_HANDLE) {
            g_default_signal_subs[g_default_signal_count++] = handle;
        }
    }

    if (g_default_signal_count > 0) {
        n00b_atomic_store(&g_default_signals_active, true);
    }
    else {
        n00b_runtime_signal_defaults_finish_shutdown(rt);
    }
}

void
n00b_runtime_signal_defaults_drain(n00b_runtime_t *rt)
{
    (void)rt;

    if (!n00b_atomic_load(&g_default_signals_active)
        || !g_default_signal_inbox) {
        return;
    }

    while (n00b_conduit_signal_inbox_has_messages(g_default_signal_inbox)) {
        n00b_conduit_signal_msg_t *msg =
            n00b_conduit_signal_inbox_pop(g_default_signal_inbox);
        if (!msg) {
            break;
        }

        int signum = msg->payload.signum;
        if (!is_default_signal(signum)) {
            continue;
        }

        n00b_atomic_store(&g_default_signals_active, false);
        n00b_display_terminal_restore();

#ifndef _WIN32
        n00b_raw_exit(128 + signum);
#else
        _Exit(128 + signum);
#endif
    }
}

void
n00b_runtime_signal_defaults_begin_shutdown(n00b_runtime_t *rt)
{
    (void)rt;

    n00b_atomic_store(&g_default_signals_active, false);
    n00b_display_terminal_restore();
}

void
n00b_runtime_signal_defaults_cancel(n00b_runtime_t *rt)
{
    (void)rt;

    for (int i = 0; i < g_default_signal_count; i++) {
        if (g_default_signal_subs[i] != N00B_CONDUIT_INVALID_SUB_HANDLE) {
            n00b_conduit_sub_cancel(g_default_signal_subs[i]);
            g_default_signal_subs[i] = N00B_CONDUIT_INVALID_SUB_HANDLE;
        }
    }
    g_default_signal_count = 0;
    g_default_signal_inbox = nullptr;
}

void
n00b_runtime_signal_defaults_finish_shutdown(n00b_runtime_t *rt)
{
    (void)rt;

#if defined(__linux__)
    if (g_default_mask_prepared) {
        sigprocmask(SIG_UNBLOCK, &g_default_unblock_mask, nullptr);
        g_default_mask_prepared = false;
    }
#endif
}
