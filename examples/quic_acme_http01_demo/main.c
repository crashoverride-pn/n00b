/*
 * quic_acme_http01_demo — Phase 5 § 5.7 (variant B: n00b-direct-ACME).
 *
 * Drives the full ACME flow end-to-end against a configurable
 * directory using an HTTP-01 challenge provider that runs an
 * *embedded* minimal HTTP/1.1 server.  No cert-manager
 * involvement — n00b owns the entire pipeline (account
 * registration → order → authz → HTTP-01 challenge → finalize →
 * cert pickup).
 *
 * Intended use:
 *   - K8s fixture: against in-cluster Pebble.  An ExternalName
 *     Service + Ingress route the challenge GET to the
 *     `--listen-port` exposed by this binary.
 *   - Bare-VM fixture: against an ACME server reachable on the
 *     public internet (or the same Pebble shape via a real DNS
 *     name and port-80 reachability).
 *
 * Usage:
 *   quic_acme_http01_demo --directory <url> --domain <name>
 *                         [--listen-port <int>]    (default: 80)
 *                         [--account-key <uri>]    (default: ephemeral:acme-account)
 *                         [--cert-key <uri>]       (default: ephemeral:acme-cert)
 *                         [--out <path>]           (write PEM chain here; '-' = stdout)
 *
 * On success: prints `ACME OK: cert acquired (<bytes> bytes)` to
 * stdout, writes the PEM chain to @p out, exits 0.
 *
 * The demo deliberately *doesn't* pull in the conduit IO loop or
 * picotls — `acme_http.c` already uses blocking sockets + poll(2)
 * per its module's design (see include/internal/quic/acme_http.h).
 * The embedded HTTP-01 responder follows the same shape: vanilla
 * socket() + accept() + a single worker thread.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#ifndef _WIN32
#include <pthread.h>
#include <fcntl.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/acme.h"

#ifdef _WIN32
typedef SOCKET           http01_socket_t;
typedef HANDLE           http01_thread_t;
typedef CRITICAL_SECTION http01_mutex_t;

#define HTTP01_THREAD_RET DWORD WINAPI
#define HTTP01_THREAD_DONE return 0
#define HTTP01_INVALID_SOCKET(fd) ((fd) == INVALID_SOCKET)
#define HTTP01_CLOSE_SOCKET(fd) closesocket((SOCKET)(fd))
#define HTTP01_SEND_FLAGS 0
#define HTTP01_SOCKOPT_PTR(ptr) ((const char *)(ptr))
#define HTTP01_SOCKET_FMT "%llu"
#define HTTP01_SOCKET_ARG(fd) ((unsigned long long)(uintptr_t)(fd))

#ifndef INFINITE
#define INFINITE 0xffffffffUL
#endif

static void
http01_mutex_init(http01_mutex_t *lock)
{
    InitializeCriticalSection(lock);
}

static void
http01_mutex_destroy(http01_mutex_t *lock)
{
    DeleteCriticalSection(lock);
}

static void
http01_mutex_lock(http01_mutex_t *lock)
{
    EnterCriticalSection(lock);
}

static void
http01_mutex_unlock(http01_mutex_t *lock)
{
    LeaveCriticalSection(lock);
}

static int
http01_make_nonblocking(http01_socket_t fd)
{
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
}

static int
http01_thread_start(http01_thread_t *thread,
                    HTTP01_THREAD_RET (*fn)(void *),
                    void *arg)
{
    *thread = CreateThread(nullptr, 0, fn, arg, 0, nullptr);
    return *thread ? 0 : -1;
}

static void
http01_thread_join(http01_thread_t thread)
{
    if (thread) {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
}
#else
typedef int             http01_socket_t;
typedef pthread_t       http01_thread_t;
typedef pthread_mutex_t http01_mutex_t;

#define HTTP01_THREAD_RET void *
#define HTTP01_THREAD_DONE return nullptr
#define HTTP01_INVALID_SOCKET(fd) ((fd) < 0)
#define HTTP01_CLOSE_SOCKET(fd) close(fd)
#define HTTP01_SEND_FLAGS MSG_NOSIGNAL
#define HTTP01_SOCKOPT_PTR(ptr) (ptr)
#define HTTP01_SOCKET_FMT "%d"
#define HTTP01_SOCKET_ARG(fd) (fd)

static void
http01_mutex_init(http01_mutex_t *lock)
{
    pthread_mutex_init(lock, nullptr);
}

static void
http01_mutex_destroy(http01_mutex_t *lock)
{
    pthread_mutex_destroy(lock);
}

static void
http01_mutex_lock(http01_mutex_t *lock)
{
    pthread_mutex_lock(lock);
}

static void
http01_mutex_unlock(http01_mutex_t *lock)
{
    pthread_mutex_unlock(lock);
}

static int
http01_make_nonblocking(http01_socket_t fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int
http01_thread_start(http01_thread_t *thread,
                    HTTP01_THREAD_RET (*fn)(void *),
                    void *arg)
{
    return pthread_create(thread, nullptr, fn, arg);
}

static void
http01_thread_join(http01_thread_t thread)
{
    pthread_join(thread, nullptr);
}
#endif

/* ---------------------------------------------------------------------------
 * Embedded HTTP-01 responder.
 *
 * State is a single (token, key_authz) pair behind a mutex.  ACME
 * authz flows are sequential, so a single slot is sufficient.
 * provision() sets the slot; deprovision() clears it.  The HTTP
 * server thread reads the slot for each incoming request and
 * returns 200 + key_authz when the GET path's token suffix
 * matches, else 404.
 * --------------------------------------------------------------------------- */

typedef struct {
    http01_mutex_t  lock;
    char           *token;       /* heap; nullptr when unprovisioned */
    char           *key_authz;   /* heap; nullptr when unprovisioned */
    http01_socket_t listen_fd;
    http01_thread_t worker;
    volatile int    stop;        /* set by main; worker polls */
    int             listen_port;
} http01_state_t;

static int
http01_provision(struct n00b_acme_challenge_provider *self,
                 const n00b_acme_challenge_t         *challenge,
                 const char                          *identifier,
                 const char                          *key_authz)
{
    (void)identifier;
    http01_state_t *st = (http01_state_t *)self->ctx;
    http01_mutex_lock(&st->lock);
    free(st->token);
    free(st->key_authz);
    st->token     = strdup(challenge->token);
    st->key_authz = strdup(key_authz);
    http01_mutex_unlock(&st->lock);
    fprintf(stderr,
            "[acme-demo] HTTP-01 provisioned: token=%.16s... "
            "(authz=%zu bytes) on :%d\n",
            challenge->token, strlen(key_authz), st->listen_port);
    return N00B_QUIC_OK;
}

static int
http01_deprovision(struct n00b_acme_challenge_provider *self,
                   const n00b_acme_challenge_t         *challenge,
                   const char                          *identifier)
{
    (void)challenge;
    (void)identifier;
    http01_state_t *st = (http01_state_t *)self->ctx;
    http01_mutex_lock(&st->lock);
    free(st->token);
    free(st->key_authz);
    st->token     = nullptr;
    st->key_authz = nullptr;
    http01_mutex_unlock(&st->lock);
    fprintf(stderr, "[acme-demo] HTTP-01 deprovisioned\n");
    return N00B_QUIC_OK;
}

/* Read a request line + headers (we ignore everything but the
 * request line).  Returns the path on success (heap-allocated, must
 * be freed); nullptr on parse failure / I/O error. */
static char *
read_request_path(http01_socket_t cfd)
{
    char buf[4096];
    size_t off = 0;
    /* Read until we see CRLFCRLF (end of headers) or buf full. */
    while (off < sizeof(buf) - 1) {
        ssize_t n = recv(cfd, buf + off, sizeof(buf) - 1 - off, 0);
        if (n <= 0) return nullptr;
        off += (size_t)n;
        buf[off] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    /* Parse first line: "GET <path> HTTP/1.1\r\n" */
    if (strncmp(buf, "GET ", 4) != 0) return nullptr;
    char *p = buf + 4;
    char *end = strchr(p, ' ');
    if (!end) return nullptr;
    *end = '\0';
    return strdup(p);
}

static void
write_full(http01_socket_t fd, const char *s, size_t n)
{
    while (n > 0) {
        ssize_t w = send(fd, s, n, HTTP01_SEND_FLAGS);
        if (w <= 0) return;
        s += w; n -= (size_t)w;
    }
}

static HTTP01_THREAD_RET
http01_worker(void *arg)
{
    http01_state_t *st = (http01_state_t *)arg;
    fprintf(stderr, "[acme-demo] worker thread started\n");
    /* Make listen_fd non-blocking so we can poll() and notice shutdown. */
    http01_make_nonblocking(st->listen_fd);

    const char prefix[] = "/.well-known/acme-challenge/";

    while (!st->stop) {
        struct pollfd pfd = {.fd = st->listen_fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 250);
        if (pr < 0) {
            fprintf(stderr, "[acme-demo] worker poll: errno=%d %s\n",
                    errno, strerror(errno));
            continue;
        }
        if (pr == 0) continue;
        if (!(pfd.revents & POLLIN)) {
            fprintf(stderr, "[acme-demo] worker poll: revents=0x%x\n",
                    pfd.revents);
            continue;
        }

        struct sockaddr_in raddr;
        socklen_t          rlen = sizeof(raddr);
        http01_socket_t cfd = accept(st->listen_fd,
                                     (struct sockaddr *)&raddr,
                                     &rlen);
        if (HTTP01_INVALID_SOCKET(cfd)) {
            fprintf(stderr, "[acme-demo] worker accept: errno=%d %s\n",
                    errno, strerror(errno));
            continue;
        }
        fprintf(stderr, "[acme-demo] worker accepted cfd=" HTTP01_SOCKET_FMT
                " from %s\n",
                HTTP01_SOCKET_ARG(cfd), inet_ntoa(raddr.sin_addr));

        char *path = read_request_path(cfd);
        if (!path) {
            fprintf(stderr,
                    "[acme-demo] worker read_request_path returned null "
                    "(probe / bad request) - closing cfd=" HTTP01_SOCKET_FMT
                    "\n", HTTP01_SOCKET_ARG(cfd));
            HTTP01_CLOSE_SOCKET(cfd); continue;
        }

        const char *token_part = nullptr;
        if (strncmp(path, prefix, sizeof(prefix) - 1) == 0) {
            token_part = path + sizeof(prefix) - 1;
        }

        char *expected_authz = nullptr;
        bool  matched         = false;
        http01_mutex_lock(&st->lock);
        if (token_part && st->token && st->key_authz
            && strcmp(token_part, st->token) == 0) {
            matched         = true;
            expected_authz  = strdup(st->key_authz);
        }
        http01_mutex_unlock(&st->lock);

        if (matched && expected_authz) {
            char hdr[256];
            int hl = snprintf(hdr, sizeof(hdr),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: application/octet-stream\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n\r\n",
                              strlen(expected_authz));
            write_full(cfd, hdr, (size_t)hl);
            write_full(cfd, expected_authz, strlen(expected_authz));
            free(expected_authz);
            fprintf(stderr,
                    "[acme-demo] HTTP-01 GET %s → 200\n", path);
        } else {
            const char nf[] =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            write_full(cfd, nf, sizeof(nf) - 1);
            fprintf(stderr,
                    "[acme-demo] HTTP-01 GET %s → 404\n", path);
        }
        free(path);
        HTTP01_CLOSE_SOCKET(cfd);
    }
    HTTP01_THREAD_DONE;
}

static int
http01_state_start(http01_state_t *st, int port)
{
    http01_mutex_init(&st->lock);
    st->token       = nullptr;
    st->key_authz   = nullptr;
    st->stop        = 0;
    st->listen_port = port;

    st->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (HTTP01_INVALID_SOCKET(st->listen_fd)) {
        perror("socket"); return -1;
    }
    int yes = 1;
    setsockopt(st->listen_fd, SOL_SOCKET, SO_REUSEADDR,
               HTTP01_SOCKOPT_PTR(&yes), sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)port);
    if (bind(st->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); HTTP01_CLOSE_SOCKET(st->listen_fd); return -1;
    }
    if (listen(st->listen_fd, 8) < 0) {
        perror("listen"); HTTP01_CLOSE_SOCKET(st->listen_fd); return -1;
    }
    if (http01_thread_start(&st->worker, http01_worker, st) != 0) {
        perror("thread_create"); HTTP01_CLOSE_SOCKET(st->listen_fd); return -1;
    }
    fprintf(stderr,
            "[acme-demo] HTTP-01 responder listening on :%d\n", port);
    return 0;
}

static void
http01_state_stop(http01_state_t *st)
{
    st->stop = 1;
    http01_thread_join(st->worker);
    HTTP01_CLOSE_SOCKET(st->listen_fd);
    free(st->token);
    free(st->key_authz);
    http01_mutex_destroy(&st->lock);
}

/* ---------------------------------------------------------------------------
 * Entry.
 * --------------------------------------------------------------------------- */

static void
usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --directory <url> --domain <name>\n"
            "          [--listen-port <int>]   (default 80; 1..65535)\n"
            "          [--account-key <uri>]   (default ephemeral:acme-account)\n"
            "          [--cert-key <uri>]      (default ephemeral:acme-cert)\n"
            "          [--out <path>]          ('-' = stdout)\n"
            "          [--settle-ms <int>]     (default 0; the K8s\n"
            "                                  fixture sets ACME_DEMO_SETTLE_MS=3000\n"
            "                                  to absorb kube-proxy lag)\n",
            argv0);
}

/* Parse a port string into a uint16_t.  Returns -1 on out-of-range
 * or non-numeric input. */
static int
parse_port(const char *s)
{
    char *end = NULL;
    long  v   = strtol(s, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 65535) {
        return -1;
    }
    return (int)v;
}

int
main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    setvbuf(stderr, nullptr, _IOLBF, 0);

    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *directory_url   = nullptr;
    const char *domain          = nullptr;
    const char *account_key_uri = "ephemeral:acme-account";
    const char *cert_key_uri    = "ephemeral:acme-cert";
    const char *out_path        = "-";
    int         listen_port     = 80;
    int         settle_ms       = 0;

    /* Optional `ACME_DEMO_SETTLE_MS=<ms>` env var.  K8s fixture
     * sets this to 3000 to absorb kube-proxy EndpointSlice
     * propagation lag (see Phase 5 § 5.7 progress notes); bare
     * VMs leave it at 0. */
    const char *env_settle = getenv("ACME_DEMO_SETTLE_MS");
    if (env_settle) {
        char *e = NULL;
        long v = strtol(env_settle, &e, 10);
        if (e && *e == '\0' && v >= 0 && v <= 60000) {
            settle_ms = (int)v;
        }
    }

    for (int i = 1; i < argc; i++) {
        if (i + 1 < argc && !strcmp(argv[i], "--directory")) {
            directory_url = argv[++i];
        } else if (i + 1 < argc && !strcmp(argv[i], "--domain")) {
            domain = argv[++i];
        } else if (i + 1 < argc && !strcmp(argv[i], "--listen-port")) {
            listen_port = parse_port(argv[++i]);
            if (listen_port < 0) {
                fprintf(stderr,
                        "[acme-demo] --listen-port out of range "
                        "(expected 1..65535)\n");
                return 2;
            }
        } else if (i + 1 < argc && !strcmp(argv[i], "--settle-ms")) {
            char *e = NULL;
            long v = strtol(argv[++i], &e, 10);
            if (!e || *e != '\0' || v < 0 || v > 60000) {
                fprintf(stderr,
                        "[acme-demo] --settle-ms out of range "
                        "(expected 0..60000)\n");
                return 2;
            }
            settle_ms = (int)v;
        } else if (i + 1 < argc && !strcmp(argv[i], "--account-key")) {
            account_key_uri = argv[++i];
        } else if (i + 1 < argc && !strcmp(argv[i], "--cert-key")) {
            cert_key_uri = argv[++i];
        } else if (i + 1 < argc && !strcmp(argv[i], "--out")) {
            out_path = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!directory_url || !domain) {
        usage(argv[0]);
        return 2;
    }

    /* Open keys via the secret-handle API.  Both are released on
     * any exit path below — even the early-failure ones — so the
     * cert_key open failure doesn't leak the already-open
     * account_key. */
    auto akr = n00b_quic_secret_open(n00b_buffer_from_cstr((char *)account_key_uri));
    if (!n00b_result_is_ok(akr)) {
        fprintf(stderr, "[acme-demo] open account key (%s) failed: %s\n",
                account_key_uri,
                n00b_quic_err_str((n00b_quic_err_t)n00b_result_get_err(akr)));
        return 3;
    }
    n00b_quic_secret_t *account_key = n00b_result_get(akr);

    auto ckr = n00b_quic_secret_open(n00b_buffer_from_cstr((char *)cert_key_uri));
    if (!n00b_result_is_ok(ckr)) {
        fprintf(stderr, "[acme-demo] open cert key (%s) failed: %s\n",
                cert_key_uri,
                n00b_quic_err_str((n00b_quic_err_t)n00b_result_get_err(ckr)));
        n00b_quic_secret_close(account_key);
        return 3;
    }
    n00b_quic_secret_t *cert_key = n00b_result_get(ckr);

    /* Stand up the embedded HTTP-01 responder. */
    http01_state_t state = {0};
    if (http01_state_start(&state, listen_port) != 0) {
        return 4;
    }
    n00b_acme_challenge_provider_t cp = {
        .type        = "http-01",
        .provision   = http01_provision,
        .deprovision = http01_deprovision,
        .ctx         = &state,
    };

    /* Optional settle window before the ACME flow starts.  In
     * K8s, kube-proxy's EndpointSlice → iptables propagation lags
     * Pod-Ready by a second or two.  If we kick off the ACME flow
     * immediately, Pebble's HTTP-01 GET arrives before kube-proxy
     * has installed the forwarding rule, the connection is
     * refused, and Pebble marks the authz invalid.  The fixture
     * sets `ACME_DEMO_SETTLE_MS=3000` (or `--settle-ms 3000`) to
     * absorb the lag.  Bare-VM operators don't need any settle
     * (default 0 = no-op). */
    if (settle_ms > 0) {
        fprintf(stderr,
                "[acme-demo] Listener up; settling %d ms before "
                "signaling ACME ready (set --settle-ms 0 / unset "
                "ACME_DEMO_SETTLE_MS to disable)...\n",
                settle_ms);
        struct timespec ts = {settle_ms / 1000,
                              (long)(settle_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
    }

    fprintf(stderr,
            "[acme-demo] Acquiring cert for '%s' from %s ...\n",
            domain, directory_url);

    const char *names[] = {domain};
    auto r = n00b_acme_acquire_certificate(directory_url,
                                           account_key, cert_key,
                                           names, 1, &cp,
                                           .timeout_ms       = 60000,
                                           .poll_max_wait_ms = 120000);
    int rc = 0;
    if (!n00b_result_is_ok(r)) {
        int err = (int)n00b_result_get_err(r);
        fprintf(stderr,
                "[acme-demo] FAIL: %d (%s)\n",
                err, n00b_quic_err_str((n00b_quic_err_t)err));
        rc = 5;
    } else {
        n00b_buffer_t *chain = n00b_result_get(r);
        printf("ACME OK: cert acquired (%zu bytes)\n",
               (size_t)chain->byte_len);
        if (!strcmp(out_path, "-")) {
            fwrite(chain->data, 1, (size_t)chain->byte_len, stdout);
            fflush(stdout);
        } else {
            FILE *f = fopen(out_path, "wb");
            if (!f) {
                fprintf(stderr, "[acme-demo] FAIL: open %s: %s\n",
                        out_path, strerror(errno));
                rc = 6;
            } else {
                fwrite(chain->data, 1, (size_t)chain->byte_len, f);
                fclose(f);
                fprintf(stderr,
                        "[acme-demo] wrote PEM chain to %s\n", out_path);
            }
        }
    }

    http01_state_stop(&state);
    n00b_quic_secret_close(account_key);
    n00b_quic_secret_close(cert_key);
    n00b_shutdown();
    return rc;
}
