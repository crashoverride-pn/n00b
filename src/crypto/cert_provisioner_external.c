/*
 * cert_provisioner_external.c — provisioner that runs an external
 * command (typically `step-cli` for dev workflows), then loads the
 * resulting PEM files like the static path does.
 *
 * Uses fork+execvp with an argv array — never the shell — so a
 * config-file substitution in the operator's deployment can't sneak
 * shell metacharacters into the executed command.
 *
 * Renewal is operator-driven via `force_refresh` for now.  A future
 * Phase 2 follow-up may add inotify/fsevents watches.
 */

#define N00B_USE_INTERNAL_API
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "conduit/file_change.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_provisioner.h"
#include "internal/crypto/cert_provisioner_common.h"

typedef struct {
    char              **argv;          /* owned, NULL-terminated copy */
    size_t              argc;
    char               *chain_pem_path;
    n00b_quic_secret_t *key_secret;    /* borrowed */
    bool                force_refresh;

    /* Optional filesystem-change watcher.  When attached via
     * n00b_quic_cert_provisioner_external_watch, file edits or
     * rename rotations on chain_pem_path automatically flip
     * force_refresh the next time should_renew runs. */
    n00b_conduit_t                   *watch_conduit;
    int                               watch_fd;
    n00b_conduit_topic_base_t        *watch_topic;
    n00b_conduit_file_change_inbox_t *watch_inbox;
    n00b_conduit_sub_handle_t         watch_sub;
} ext_state_t;

static n00b_allocator_t *
ep_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
ep_strdup(const char *s)
{
    size_t l = strlen(s);
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = ep_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, s, l + 1);
    return out;
}

static int
run_external_argv(char *const *argv)
{
    /* fork + execvp: argv is never interpreted by a shell, so even
     * if the operator's config substitutes attacker-controlled
     * strings into one of the args, no metacharacter can change the
     * command shape. */
    pid_t pid = fork();
    if (pid < 0) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    if (pid == 0) {
        /* Child. */
        execvp(argv[0], argv);
        _exit(127);  /* execvp only returns on failure */
    }
    /* Parent. */
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return N00B_QUIC_ERR_PROTOCOL;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return N00B_QUIC_ERR_PROTOCOL;
    }
    return N00B_QUIC_OK;
}

static n00b_result_t(n00b_quic_cert_t *)
ep_acquire(n00b_quic_cert_provisioner_t *self)
{
    ext_state_t *st = self->ctx;

    int rc = run_external_argv(st->argv);
    if (rc != N00B_QUIC_OK) {
        return n00b_result_err(n00b_quic_cert_t *, rc);
    }

    auto fr = n00b_certp_load_file(st->chain_pem_path);
    if (!n00b_result_is_ok(fr)) {
        return n00b_result_err(n00b_quic_cert_t *,
                               (int)n00b_result_get_err(fr));
    }
    n00b_buffer_t *pem = n00b_result_get(fr);

    auto dr = n00b_certp_pem_first_cert_to_der(pem);
    if (!n00b_result_is_ok(dr)) {
        return n00b_result_err(n00b_quic_cert_t *,
                               (int)n00b_result_get_err(dr));
    }
    n00b_buffer_t *der = n00b_result_get(dr);

    int64_t nb = 0, na = 0;
    if (n00b_certp_parse_validity((const uint8_t *)der->data,
                                  (size_t)der->byte_len, &nb, &na) != 0) {
        return n00b_result_err(n00b_quic_cert_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    n00b_quic_cert_t *cert = n00b_alloc_with_opts(n00b_quic_cert_t,
        &(n00b_alloc_opts_t){.allocator = ep_alloc()});
    cert->chain_pem      = pem;
    cert->key            = st->key_secret;
    cert->not_before_ms  = nb;
    cert->not_after_ms   = na;

    /* Successful acquisition resets the refresh flag. */
    st->force_refresh = false;

    return n00b_result_ok(n00b_quic_cert_t *, cert);
}

/* Re-open the chain_pem_path and re-register the file-change watch.
 * Used after a rename/delete event invalidates the previous fd.
 * Best-effort: a failure here just means the watch goes dormant
 * until the next manual force_refresh — strictly no-worse than the
 * pre-watcher behavior. */
static void
ep_rearm_watch(ext_state_t *st)
{
    if (!st || !st->watch_conduit) return;

    if (st->watch_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(st->watch_sub);
        st->watch_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    if (st->watch_topic) {
        st->watch_topic = nullptr;
    }
    if (st->watch_fd >= 0) {
        n00b_conduit_file_change_unwatch(st->watch_conduit, st->watch_fd);
        close(st->watch_fd);
        st->watch_fd = -1;
    }

    int fd = open(st->chain_pem_path, O_RDONLY);
    if (fd < 0) return;
    auto tr = n00b_conduit_file_change_topic(
        st->watch_conduit, fd,
        N00B_CONDUIT_VNODE_WRITE | N00B_CONDUIT_VNODE_RENAME
            | N00B_CONDUIT_VNODE_DELETE);
    if (n00b_result_is_err(tr)) {
        close(fd);
        return;
    }
    st->watch_fd    = fd;
    st->watch_topic = n00b_result_get(tr);
    st->watch_sub   = n00b_conduit_file_change_subscribe(
        st->watch_topic, st->watch_inbox,
        .operations = N00B_CONDUIT_OP_ALL);
}

static bool
ep_should_renew(n00b_quic_cert_provisioner_t *self,
                const n00b_quic_cert_t       *current)
{
    if (!current) {
        return true;
    }
    ext_state_t *st = self->ctx;

    /* Drain the watch inbox; any event flips force_refresh.  If the
     * event was rename/delete, the underlying fd is now stale so
     * we re-arm on the (new) path. */
    if (st->watch_inbox) {
        bool need_rearm = false;
        n00b_conduit_file_change_msg_t *msg;
        while ((msg = n00b_conduit_file_change_inbox_pop(st->watch_inbox))
               != nullptr) {
            st->force_refresh = true;
            if (msg->payload.events
                & (N00B_CONDUIT_VNODE_RENAME | N00B_CONDUIT_VNODE_DELETE)) {
                need_rearm = true;
            }
        }
        if (need_rearm) {
            ep_rearm_watch(st);
        }
    }

    return st->force_refresh;
}

static void
ep_close(n00b_quic_cert_provisioner_t *self)
{
    if (!self || !self->ctx) return;
    ext_state_t *st = self->ctx;
    if (st->watch_sub != N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_sub_cancel(st->watch_sub);
        st->watch_sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    }
    if (st->watch_fd >= 0 && st->watch_conduit) {
        n00b_conduit_file_change_unwatch(st->watch_conduit, st->watch_fd);
        close(st->watch_fd);
        st->watch_fd = -1;
    }
    st->key_secret = nullptr;
    self->ctx      = nullptr;
}

n00b_result_t(n00b_quic_cert_provisioner_t *)
n00b_quic_cert_provisioner_external(const char *const  *argv,
                                    const char         *chain_pem_path,
                                    n00b_quic_secret_t *key_secret)
{
    if (!argv || !argv[0] || !chain_pem_path || !key_secret) {
        return n00b_result_err(n00b_quic_cert_provisioner_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    /* Count argv entries (must be NULL-terminated). */
    size_t argc = 0;
    while (argv[argc] != nullptr) {
        argc++;
        if (argc > 1024) {
            /* Defense against an obviously broken caller. */
            return n00b_result_err(n00b_quic_cert_provisioner_t *,
                                   N00B_QUIC_ERR_INVALID_ARG);
        }
    }

    ext_state_t *st = n00b_alloc_with_opts(ext_state_t,
        &(n00b_alloc_opts_t){.allocator = ep_alloc()});
    /* +1 for the NULL terminator. */
    st->argv = n00b_alloc_array_with_opts(char *, (int64_t)(argc + 1),
                                          &(n00b_alloc_opts_t){
                                              .allocator = ep_alloc(),
                                          });
    for (size_t i = 0; i < argc; i++) {
        st->argv[i] = ep_strdup(argv[i]);
    }
    st->argv[argc]      = nullptr;
    st->argc            = argc;
    st->chain_pem_path  = ep_strdup(chain_pem_path);
    st->key_secret      = key_secret;
    st->force_refresh   = false;
    st->watch_conduit   = nullptr;
    st->watch_fd        = -1;
    st->watch_topic     = nullptr;
    st->watch_inbox     = nullptr;
    st->watch_sub       = N00B_CONDUIT_INVALID_SUB_HANDLE;

    n00b_quic_cert_provisioner_t *p = n00b_alloc_with_opts(
        n00b_quic_cert_provisioner_t,
        &(n00b_alloc_opts_t){.allocator = ep_alloc()});
    p->name         = "external";
    p->acquire      = ep_acquire;
    p->should_renew = ep_should_renew;
    p->close        = ep_close;
    p->ctx          = st;
    return n00b_result_ok(n00b_quic_cert_provisioner_t *, p);
}

void
n00b_quic_cert_provisioner_external_force_refresh(
    n00b_quic_cert_provisioner_t *self)
{
    if (!self || !self->ctx) return;
    /* Sanity: only valid on an external provisioner. */
    if (!self->name || strcmp(self->name, "external") != 0) return;
    ext_state_t *st = self->ctx;
    st->force_refresh = true;
}

n00b_result_t(bool)
n00b_quic_cert_provisioner_external_watch(
    n00b_quic_cert_provisioner_t *self,
    n00b_conduit_t               *conduit)
{
    if (!self || !self->ctx || !conduit) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }
    if (!self->name || strcmp(self->name, "external") != 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }
    ext_state_t *st = self->ctx;
    if (st->watch_conduit) {
        /* Already attached. */
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }

    int fd = open(st->chain_pem_path, O_RDONLY);
    if (fd < 0) {
        return n00b_result_err(bool, N00B_QUIC_ERR_INVALID_ARG);
    }

    auto tr = n00b_conduit_file_change_topic(
        conduit, fd,
        N00B_CONDUIT_VNODE_WRITE | N00B_CONDUIT_VNODE_RENAME
            | N00B_CONDUIT_VNODE_DELETE);
    if (n00b_result_is_err(tr)) {
        close(fd);
        return n00b_result_err(bool, n00b_result_get_err(tr));
    }
    n00b_conduit_topic_base_t        *topic = n00b_result_get(tr);
    n00b_conduit_file_change_inbox_t *inbox =
        n00b_conduit_file_change_inbox_new(conduit);
    n00b_conduit_sub_handle_t sub = n00b_conduit_file_change_subscribe(
        topic, inbox, .operations = N00B_CONDUIT_OP_ALL);
    if (sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_conduit_file_change_unwatch(conduit, fd);
        close(fd);
        return n00b_result_err(bool, N00B_QUIC_ERR_BIND_FAILED);
    }

    st->watch_conduit = conduit;
    st->watch_fd      = fd;
    st->watch_topic   = topic;
    st->watch_inbox   = inbox;
    st->watch_sub     = sub;
    return n00b_result_ok(bool, true);
}
