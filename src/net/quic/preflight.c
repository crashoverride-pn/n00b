/*
 * preflight.c — Manifest readiness checks.
 *
 * Each finding is structured (check id, severity, detail,
 * remediation) so an LLM-driven ops loop can read the report,
 * apply fixes, and re-run.  See `~/dd/quic_2.md` § 9.3.
 *
 * Finding strings (`check`, `detail`, `remediation`) are constructed
 * at the callsite via `n00b_cformat` / `n00b_string_from_cstr` and
 * passed as `n00b_string_t *` directly into `fb_push`.  The earlier
 * "snprintf into char[256] then `n00b_string_from_cstr` inside
 * `fb_push`" pattern is gone, which removes silent truncation and
 * lets us speak the project's rich-format vocabulary (incl. `«#»`
 * substitutions of `n00b_errno_str(errno)` etc.) directly.
 */

#define N00B_USE_INTERNAL_API
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>      /* snprintf for libc-bound buffers (port_str, candidate) */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "conduit/print.h"
#include "net/quic/quic_types.h"
#include "net/quic/manifest.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_provisioner.h"
#include "internal/crypto/cert_provisioner_common.h"
#include "util/errno_str.h"

#ifdef _WIN32
#define N00B_PREFLIGHT_CLOSE_SOCKET(fd) closesocket((SOCKET)(fd))
#define N00B_PREFLIGHT_SOCKET_ERRNO() WSAGetLastError()
#define N00B_PREFLIGHT_SOCKOPT_PTR(ptr) ((const char *)(ptr))
#define N00B_PREFLIGHT_REUSE_OPT SO_EXCLUSIVEADDRUSE
#define N00B_PREFLIGHT_EACCES WSAEACCES
#define N00B_PREFLIGHT_EADDRINUSE WSAEADDRINUSE
#define N00B_PREFLIGHT_PATH_DELIM ";"
#define N00B_PREFLIGHT_PATH_SEP "\\"

static bool
pf_has_path_sep(const char *s)
{
    return strchr(s, '/') != nullptr || strchr(s, '\\') != nullptr;
}

static char *
pf_strtok(char *s, const char *delim, char **saveptr)
{
    return strtok_s(s, delim, saveptr);
}
#else
#define N00B_PREFLIGHT_CLOSE_SOCKET(fd) close(fd)
#define N00B_PREFLIGHT_SOCKET_ERRNO() errno
#define N00B_PREFLIGHT_SOCKOPT_PTR(ptr) (ptr)
#define N00B_PREFLIGHT_REUSE_OPT SO_REUSEADDR
#define N00B_PREFLIGHT_EACCES EACCES
#define N00B_PREFLIGHT_EADDRINUSE EADDRINUSE
#define N00B_PREFLIGHT_PATH_DELIM ":"
#define N00B_PREFLIGHT_PATH_SEP "/"

static bool
pf_has_path_sep(const char *s)
{
    return strchr(s, '/') != nullptr;
}

static char *
pf_strtok(char *s, const char *delim, char **saveptr)
{
    return strtok_r(s, delim, saveptr);
}
#endif

/* ===========================================================================
 * Allocator + finding builders
 * =========================================================================== */

static n00b_allocator_t *
pf_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
pf_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t l = strlen(s);
    char  *o = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                          &(n00b_alloc_opts_t){
                                              .allocator = pf_alloc(),
                                              .no_scan   = true,
                                          });
    memcpy(o, s, l + 1);
    return o;
}

/* Findings accumulator: typed `n00b_list_t` head with conduit-pool
 * allocator.  Replaces an earlier hand-rolled growable-array. */
typedef n00b_list_t(n00b_quic_preflight_finding_t *) finding_buf_t;

static void
fb_init(finding_buf_t *fb)
{
    *fb = n00b_list_new(n00b_quic_preflight_finding_t *);
    fb->allocator = pf_alloc();
}

/* Push a new finding into the buffer.
 *
 * Strings (`check`, optional `detail`, optional `remediation`) are
 * `n00b_string_t *` constructed at the callsite via rich-format
 * helpers; this helper just snapshots them into the finding record.
 *
 * `detail` and `remediation` default to `nullptr` per the
 * pointer-as-kwarg-default policy (D-035 part 2 carve-out; see
 * `feedback_n00b_option_t_exception.md`).  `fb_push` is a `static`
 * internal helper rather than a public n00b-attest API, so this
 * usage is by stylistic consistency with the surrounding code, not
 * by direct mandate of the exception's public-API motivation. */
static void
fb_push(finding_buf_t                  *fb,
        n00b_string_t                  *check,
        n00b_quic_preflight_severity_t  severity)
    _kargs {
        n00b_string_t *detail      = nullptr;
        n00b_string_t *remediation = nullptr;
    }
{
    n00b_quic_preflight_finding_t *f = n00b_alloc_with_opts(
        n00b_quic_preflight_finding_t,
        &(n00b_alloc_opts_t){.allocator = pf_alloc()});
    f->check       = check;
    f->severity    = severity;
    f->detail      = detail;
    f->remediation = remediation;
    n00b_list_push(*fb, f);
}

/* ===========================================================================
 * Individual checks
 * =========================================================================== */

static void
check_port_bind(finding_buf_t *fb, const n00b_buffer_t *host_buf, uint16_t port)
{
    n00b_string_t *host = host_buf
        ? n00b_string_from_cstr((const char *)host_buf->data)
        : r"";
    n00b_string_t *check_id =
        n00b_cformat("port-bind:«#»:«#»", host, (int64_t)port);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;  /* QUIC is UDP */
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo *res = nullptr;
    int rc = getaddrinfo(host_buf ? (const char *)host_buf->data : "",
                         port_str, &hints, &res);
    if (rc != 0 || !res) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_cformat("Cannot resolve bind host: «#»",
                                       n00b_gai_str(rc)),
                .remediation = n00b_string_from_cstr(
                    "Check `bind_host` in the manifest; use a literal "
                    "IPv4 (\"0.0.0.0\") or IPv6 (\"::\") wildcard for "
                    "all-interfaces binds."));
        return;
    }

    base_socket_t fd = socket(res->ai_family, res->ai_socktype,
                              res->ai_protocol);
    if (fd == BASE_INVALID_SOCKET) {
        freeaddrinfo(res);
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = r"socket() failed",
                .remediation = n00b_string_from_cstr(
                    "Check process limits (ulimit -n) and kernel-side "
                    "socket creation policies."));
        return;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, N00B_PREFLIGHT_REUSE_OPT,
               N00B_PREFLIGHT_SOCKOPT_PTR(&yes), sizeof(yes));

    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0) {
        int saved_errno = N00B_PREFLIGHT_SOCKET_ERRNO();
        n00b_string_t *detail = n00b_cformat("bind() failed: «#»",
                                             n00b_errno_str(saved_errno));
        n00b_string_t *remediation = (saved_errno == N00B_PREFLIGHT_EACCES)
            ? n00b_string_from_cstr(
                "Privileged port (<1024); run with elevated capabilities "
                "(e.g., setcap cap_net_bind_service=+ep on Linux) or "
                "configure the OS to allow binding.")
            : (saved_errno == N00B_PREFLIGHT_EADDRINUSE)
                  ? n00b_string_from_cstr(
                      "Another process already holds this port; identify "
                      "with `lsof -i :PORT` and resolve.")
                  : r"Inspect kernel networking state.";
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = detail, .remediation = remediation);
        N00B_PREFLIGHT_CLOSE_SOCKET(fd);
        freeaddrinfo(res);
        return;
    }
    N00B_PREFLIGHT_CLOSE_SOCKET(fd);
    freeaddrinfo(res);
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = r"bind() succeeded");
}

/* Phase 5 § 5.2 — TCP-bind sanity for the metrics listener. */
static void
check_metrics_bind(finding_buf_t                      *fb,
                   const n00b_quic_manifest_metrics_t *m)
{
    const char    *host_cstr = m->bind_host ? (const char *)m->bind_host->data
                                            : "::1";
    n00b_string_t *host      = n00b_string_from_cstr(host_cstr);
    n00b_string_t *check_id  =
        n00b_cformat("metrics-bind:«#»:«#»", host, (int64_t)m->bind_port);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)m->bind_port);

    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;
    int rc = getaddrinfo(host_cstr, port_str, &hints, &res);
    if (rc != 0 || !res) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_cformat(
                    "Cannot resolve metrics bind host '«#»': «#»",
                    host, n00b_gai_str(rc)),
                .remediation = n00b_string_from_cstr(
                    "Check `observability.metrics.bind_host`; use a "
                    "literal IPv4/IPv6 wildcard or loopback."));
        return;
    }
    base_socket_t fd = socket(res->ai_family, res->ai_socktype,
                              res->ai_protocol);
    if (fd == BASE_INVALID_SOCKET) {
        freeaddrinfo(res);
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "socket() failed for metrics bind"),
                .remediation = n00b_string_from_cstr(
                    "Check process FD ulimit."));
        return;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, N00B_PREFLIGHT_REUSE_OPT,
               N00B_PREFLIGHT_SOCKOPT_PTR(&yes), sizeof(yes));
    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0) {
        int saved_errno = N00B_PREFLIGHT_SOCKET_ERRNO();
        n00b_string_t *detail = n00b_cformat(
            "metrics bind() failed: «#»", n00b_errno_str(saved_errno));
        n00b_string_t *remediation = (saved_errno == N00B_PREFLIGHT_EACCES)
            ? n00b_string_from_cstr(
                "Pick a non-privileged port (>= 1024) for metrics.")
            : (saved_errno == N00B_PREFLIGHT_EADDRINUSE)
                  ? n00b_string_from_cstr(
                      "Another process holds the metrics port; "
                      "use `lsof -i :PORT` to identify it.")
                  : n00b_string_from_cstr(
                      "Inspect kernel networking state.");
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = detail, .remediation = remediation);
        N00B_PREFLIGHT_CLOSE_SOCKET(fd);
        freeaddrinfo(res);
        return;
    }
    N00B_PREFLIGHT_CLOSE_SOCKET(fd);
    freeaddrinfo(res);
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = r"metrics bind() succeeded");
}

static void
check_static_cert(finding_buf_t                       *fb,
                  const n00b_buffer_t                 *ep_id,
                  const n00b_quic_manifest_cert_t     *cert)
{
    n00b_string_t *ep_id_s = n00b_string_from_cstr(
        ep_id ? (const char *)ep_id->data : "?");
    n00b_string_t *check_id = n00b_cformat("cert-static:«#»", ep_id_s);

    auto fr = n00b_certp_load_file(cert->chain_pem_path
                                   ? cert->chain_pem_path->data : nullptr);
    if (!n00b_result_is_ok(fr)) {
        n00b_string_t *path_s = n00b_string_from_cstr(
            cert->chain_pem_path ? (const char *)cert->chain_pem_path->data
                                 : "?");
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_cformat(
                    "Cannot read chain_pem_path '«#»'", path_s),
                .remediation = n00b_string_from_cstr(
                    "Make the file readable by the n00b-server process; "
                    "check ownership and SELinux/AppArmor labels."));
        return;
    }
    n00b_buffer_t *pem = n00b_result_get(fr);
    auto dr = n00b_certp_pem_first_cert_to_der(pem);
    if (!n00b_result_is_ok(dr)) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "chain_pem_path doesn't contain a parseable PEM "
                    "CERTIFICATE block"),
                .remediation = n00b_string_from_cstr(
                    "Verify with `openssl x509 -in <path> -text -noout`."));
        return;
    }
    n00b_buffer_t *der = n00b_result_get(dr);
    int64_t nb = 0, na = 0;
    if (n00b_certp_parse_validity((const uint8_t *)der->data,
                                  (size_t)der->byte_len,
                                  &nb, &na) != 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "Could not parse Validity period from leaf cert"),
                .remediation = n00b_string_from_cstr(
                    "Verify the cert isn't malformed."));
        return;
    }
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    int64_t now_ms = (int64_t)tv.tv_sec * 1000;
    if (now_ms < nb) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "Cert is not yet valid (notBefore is in the future)"),
                .remediation = n00b_string_from_cstr(
                    "Wait or replace the cert."));
        return;
    }
    if (now_ms > na) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "Cert has already expired"),
                .remediation = n00b_string_from_cstr(
                    "Renew or replace the cert."));
        return;
    }
    /* Soft-warn if the cert expires within 30 days. */
    int64_t margin_ms = (int64_t)30 * 24 * 60 * 60 * 1000;
    if (now_ms > na - margin_ms) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_WARN,
                .detail = n00b_string_from_cstr(
                    "Cert expires within 30 days"),
                .remediation = n00b_string_from_cstr(
                    "Schedule a renewal soon."));
    } else {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
                .detail = r"Cert is valid");
    }
}

static void
check_external_argv(finding_buf_t                          *fb,
                    const n00b_buffer_t                    *ep_id,
                    n00b_list_t(n00b_buffer_t *)           *argv)
{
    n00b_string_t *ep_id_s = n00b_string_from_cstr(
        ep_id ? (const char *)ep_id->data : "?");
    n00b_string_t *check_id = n00b_cformat("cert-external:«#»", ep_id_s);

    if (!argv || n00b_list_len(*argv) == 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "External cert provisioner has no argv[0]"),
                .remediation = n00b_string_from_cstr(
                    "Add the command name to the manifest's argv array."));
        return;
    }
    n00b_buffer_t *cmd_buf = n00b_list_get(*argv, 0);
    if (!cmd_buf || cmd_buf->byte_len == 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "External cert provisioner has no argv[0]"),
                .remediation = n00b_string_from_cstr(
                    "Add the command name to the manifest's argv array."));
        return;
    }
    const char *cmd = cmd_buf->data;

    /* Naïve PATH search: if argv[0] contains '/', treat as absolute /
     * relative; otherwise search PATH. */
    if (pf_has_path_sep(cmd)) {
        if (access(cmd, X_OK) != 0) {
            fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                    .detail = n00b_cformat(
                        "argv[0] '«#»' is not executable",
                        n00b_string_from_cstr(cmd)),
                    .remediation = n00b_string_from_cstr(
                        "Check the file's permission bits (chmod +x)."));
            return;
        }
    } else {
        const char *path_env = getenv("PATH");
        if (!path_env) {
            fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_WARN,
                    .detail = n00b_string_from_cstr(
                        "PATH not set; cannot validate argv[0] location"),
                    .remediation = n00b_string_from_cstr(
                        "Set PATH or use an absolute path in argv[0]."));
            return;
        }
        bool found = false;
        char *path_copy = pf_strdup(path_env);
        char *saveptr   = nullptr;
        char *dir;
        for (dir = pf_strtok(path_copy, N00B_PREFLIGHT_PATH_DELIM, &saveptr);
             dir;
             dir = pf_strtok(nullptr, N00B_PREFLIGHT_PATH_DELIM, &saveptr)) {
            char candidate[1024];
            snprintf(candidate, sizeof(candidate), "%s%s%s",
                     dir, N00B_PREFLIGHT_PATH_SEP, cmd);
            if (access(candidate, X_OK) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                    .detail = n00b_cformat(
                        "argv[0] '«#»' not found in PATH",
                        n00b_string_from_cstr(cmd)),
                    .remediation = n00b_string_from_cstr(
                        "Install the binary, or pass an absolute path "
                        "in argv[0]."));
            return;
        }
    }
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = n00b_string_from_cstr(
                "External cert command is executable"));
}

static void
check_acme_directory(finding_buf_t       *fb,
                     const n00b_buffer_t *ep_id,
                     const n00b_buffer_t *directory_url_buf)
{
    n00b_string_t *ep_id_s = n00b_string_from_cstr(
        ep_id ? (const char *)ep_id->data : "?");
    n00b_string_t *check_id =
        n00b_cformat("cert-acme-directory:«#»", ep_id_s);
    if (!directory_url_buf || directory_url_buf->byte_len < 8
        || memcmp(directory_url_buf->data, "https://", 8) != 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "ACME directory_url must start with https://"),
                .remediation = n00b_string_from_cstr(
                    "Use the canonical URL for your ACME provider."));
        return;
    }
    const char *directory_url = directory_url_buf->data;
    /* DNS resolution of the host portion (best-effort; not network-
     * gated since `getaddrinfo` will hit the system resolver). */
    const char *host_start = directory_url + 8;
    const char *slash      = strchr(host_start, '/');
    size_t      host_len   = slash ? (size_t)(slash - host_start)
                                   : strlen(host_start);
    char host_buf[256];
    if (host_len >= sizeof(host_buf)) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "directory_url host part is implausibly long"));
        return;
    }
    memcpy(host_buf, host_start, host_len);
    host_buf[host_len] = '\0';
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host_buf, "443", &hints, &res);
    if (rc != 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_WARN,
                .detail = n00b_cformat(
                    "Cannot resolve ACME directory host '«#»': «#»",
                    n00b_string_from_cstr(host_buf),
                    n00b_gai_str(rc)),
                .remediation = n00b_string_from_cstr(
                    "Check DNS, or run preflight again with network "
                    "access."));
        return;
    }
    if (res) freeaddrinfo(res);
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = n00b_string_from_cstr(
                "ACME directory host resolves"));
}

static void
check_secret_uri(finding_buf_t       *fb,
                 n00b_string_t       *check_id,
                 const n00b_buffer_t *uri)
{
    if (!uri) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = r"Secret URI is missing",
                .remediation = n00b_string_from_cstr(
                    "Add the URI to the manifest."));
        return;
    }
    auto r = n00b_quic_secret_open((n00b_buffer_t *)uri);
    if (!n00b_result_is_ok(r)) {
        int err = (int)n00b_result_get_err(r);
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_cformat(
                    "Cannot open secret URI '«#»': «#»",
                    n00b_string_from_cstr((const char *)uri->data),
                    n00b_string_from_cstr(
                        n00b_quic_err_str((n00b_quic_err_t)err))),
                .remediation = n00b_string_from_cstr(
                    "Check the secret-provider configuration "
                    "(Keychain ACL / KMS policy / vault token / etc.) "
                    "and that the URI scheme is registered."));
        return;
    }
    n00b_quic_secret_t *sec = n00b_result_get(r);
    n00b_quic_secret_close(sec);
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = r"Secret URI opens cleanly");
}

/* ===========================================================================
 * Phase 3 § 11 — auth checks
 * =========================================================================== */

static void
check_idp(finding_buf_t *fb, const n00b_quic_manifest_idp_t *idp)
{
    n00b_string_t *id_s = n00b_string_from_cstr(
        idp->id ? (const char *)idp->id->data : "?");
    n00b_string_t *check_id = n00b_cformat("auth-idp:«#»", id_s);

    if (!idp->id) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "IdP entry missing 'id'"),
                .remediation = n00b_string_from_cstr(
                    "Add an `id` to the IdP."));
        return;
    }
    if (!idp->issuer || idp->issuer->byte_len < 8
        || memcmp(idp->issuer->data, "https://", 8) != 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "IdP issuer must start with https://"),
                .remediation = n00b_string_from_cstr(
                    "Use the canonical issuer URL for your IdP."));
        return;
    }
    /* DNS resolution of the host portion (same pattern as ACME). */
    const char *host_start = (const char *)idp->issuer->data + 8;
    const char *slash      = strchr(host_start, '/');
    size_t      host_len   = slash ? (size_t)(slash - host_start)
                                   : strlen(host_start);
    if (host_len == 0 || host_len >= 256) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "IdP issuer host is empty or implausibly long"),
                .remediation = n00b_string_from_cstr(
                    "Check the issuer URL."));
        return;
    }
    char host_buf[256];
    memcpy(host_buf, host_start, host_len);
    host_buf[host_len] = '\0';
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host_buf, "443", &hints, &res);
    if (rc != 0) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_WARN,
                .detail = n00b_cformat(
                    "Cannot resolve IdP host '«#»': «#»",
                    n00b_string_from_cstr(host_buf),
                    n00b_gai_str(rc)),
                .remediation = n00b_string_from_cstr(
                    "Check DNS, or run preflight again with network access."));
        return;
    }
    if (res) freeaddrinfo(res);
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = r"IdP issuer host resolves");
}

static void
check_policy(finding_buf_t                       *fb,
             const n00b_quic_manifest_policy_t   *pol,
             const n00b_quic_manifest_t          *m)
{
    n00b_string_t *id_s = n00b_string_from_cstr(
        pol->id ? (const char *)pol->id->data : "?");
    n00b_string_t *check_id = n00b_cformat("auth-policy:«#»", id_s);

    if (!pol->id) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "policy entry missing 'id'"),
                .remediation = n00b_string_from_cstr(
                    "Add a unique `id` to each policy."));
        return;
    }
    if (!pol->idp) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "policy entry missing 'idp'"),
                .remediation = n00b_string_from_cstr(
                    "Reference an IdP from `auth.idps` by id."));
        return;
    }
    /* The referenced idp must be defined. */
    bool found = false;
    size_t idp_n = m->auth_idps ? (size_t)n00b_list_len(*m->auth_idps) : 0;
    for (size_t i = 0; i < idp_n; i++) {
        n00b_quic_manifest_idp_t *idp = n00b_list_get(*m->auth_idps, i);
        if (n00b_quic_mfbuf_eq(idp->id, pol->idp)) {
            found = true;
            break;
        }
    }
    if (!found) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_cformat(
                    "policy '«#»' references undefined idp '«#»'",
                    n00b_string_from_cstr((const char *)pol->id->data),
                    n00b_string_from_cstr((const char *)pol->idp->data)),
                .remediation = n00b_string_from_cstr(
                    "Add the idp to `auth.idps[]` or correct the "
                    "reference."));
        return;
    }
    /* Audience-empty WARN — a policy with no audience will accept
     * any token from the configured IdP regardless of who minted it
     * for whom; that's almost always a misconfiguration. */
    if (n00b_quic_mfbuf_empty(pol->audience)) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_WARN,
                .detail = n00b_string_from_cstr(
                    "policy has no audience requirement"),
                .remediation = n00b_string_from_cstr(
                    "Set `audience` to your service identifier so tokens "
                    "minted for other services aren't accepted."));
    }

    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = n00b_string_from_cstr(
                "policy idp reference resolves"));
}

/* ===========================================================================
 * Phase 4 § 4.11 — RPC service auth-policy reference check
 * =========================================================================== */

static void
check_rpc_service(finding_buf_t                          *fb,
                  const n00b_quic_manifest_rpc_service_t *svc,
                  const n00b_quic_manifest_t             *m)
{
    n00b_string_t *id_s = n00b_string_from_cstr(
        svc->id ? (const char *)svc->id->data : "(unnamed)");
    n00b_string_t *check_id = n00b_cformat("rpc-service:«#»", id_s);

    if (!svc->id) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "rpc.services entry missing 'id'"),
                .remediation = n00b_string_from_cstr(
                    "Set `id` to the gRPC-style service name "
                    "(e.g., `pkg.v1.Service`)."));
        return;
    }
    if (!svc->auth_policy) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_string_from_cstr(
                    "rpc.services entry missing 'auth_policy'"),
                .remediation = n00b_string_from_cstr(
                    "Reference an `auth.policies[].id` so inbound calls "
                    "are gated by a defined policy."));
        return;
    }
    bool found = false;
    size_t pol_n = m->auth_policies ? (size_t)n00b_list_len(*m->auth_policies) : 0;
    for (size_t i = 0; i < pol_n; i++) {
        n00b_quic_manifest_policy_t *pol2 = n00b_list_get(*m->auth_policies, i);
        if (n00b_quic_mfbuf_eq(pol2->id, svc->auth_policy)) {
            found = true;
            break;
        }
    }
    if (!found) {
        fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_ERROR,
                .detail = n00b_cformat(
                    "rpc.service '«#»' references undefined "
                    "auth_policy '«#»'",
                    n00b_string_from_cstr((const char *)svc->id->data),
                    n00b_string_from_cstr(
                        (const char *)svc->auth_policy->data)),
                .remediation = n00b_string_from_cstr(
                    "Add the policy to `auth.policies[]` or correct "
                    "the reference."));
        return;
    }
    fb_push(fb, check_id, N00B_QUIC_PREFLIGHT_INFO,
            .detail = n00b_string_from_cstr(
                "rpc service auth_policy reference resolves"));
}

/* ===========================================================================
 * Top-level walker
 * =========================================================================== */

n00b_result_t(n00b_quic_preflight_report_t *)
n00b_quic_preflight(n00b_quic_manifest_t *m)
{
    if (!m) {
        return n00b_result_err(n00b_quic_preflight_report_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }
    finding_buf_t fb;
    fb_init(&fb);

    size_t ep_n = m->endpoints
                  ? (size_t)n00b_list_len(*m->endpoints) : 0;
    for (size_t i = 0; i < ep_n; i++) {
        const n00b_quic_manifest_endpoint_t *ep =
            n00b_list_get(*m->endpoints, i);

        check_port_bind(&fb, ep->bind_host, ep->bind_port);

        n00b_string_t *ep_id_s = n00b_string_from_cstr(
            ep->id ? (const char *)ep->id->data : "?");

        switch (ep->cert.kind) {
        case N00B_QUIC_MANIFEST_CERT_STATIC: {
            check_static_cert(&fb, ep->id, &ep->cert);
            n00b_string_t *check_id =
                n00b_cformat("cert-static-key:«#»", ep_id_s);
            check_secret_uri(&fb, check_id, ep->cert.key_secret_uri);
            break;
        }
        case N00B_QUIC_MANIFEST_CERT_EXTERNAL: {
            check_external_argv(&fb, ep->id, ep->cert.argv);
            n00b_string_t *check_id =
                n00b_cformat("cert-external-key:«#»", ep_id_s);
            check_secret_uri(&fb, check_id, ep->cert.key_secret_uri);
            break;
        }
        case N00B_QUIC_MANIFEST_CERT_ACME: {
            check_acme_directory(&fb, ep->id, ep->cert.directory_url);
            n00b_string_t *check_id =
                n00b_cformat("cert-acme-key:«#»", ep_id_s);
            check_secret_uri(&fb, check_id, ep->cert.account_key_uri);
            break;
        }
        }
    }

    /* Phase 3 § 11 auth checks. */
    size_t idp_total = m->auth_idps
                       ? (size_t)n00b_list_len(*m->auth_idps)
                       : 0;
    for (size_t i = 0; i < idp_total; i++) {
        check_idp(&fb, n00b_list_get(*m->auth_idps, i));
    }
    size_t pol_total = m->auth_policies
                       ? (size_t)n00b_list_len(*m->auth_policies)
                       : 0;
    for (size_t i = 0; i < pol_total; i++) {
        check_policy(&fb, n00b_list_get(*m->auth_policies, i), m);
    }
    /* Phase 4 § 4.11 rpc service checks. */
    if (m->rpc_services) {
        size_t n = (size_t)n00b_list_len(*m->rpc_services);
        for (size_t i = 0; i < n; i++) {
            check_rpc_service(&fb,
                              n00b_list_get(*m->rpc_services, i),
                              m);
        }
    }
    /* Phase 5 § 5.2 metrics-bind sanity. */
    if (m->metrics) {
        check_metrics_bind(&fb, m->metrics);
    }

    n00b_quic_preflight_report_t *r = n00b_alloc_with_opts(
        n00b_quic_preflight_report_t,
        &(n00b_alloc_opts_t){.allocator = pf_alloc()});
    r->ok       = true;
    r->findings = n00b_alloc_with_opts(
        n00b_list_t(n00b_quic_preflight_finding_t *),
        &(n00b_alloc_opts_t){.allocator = pf_alloc()});
    *r->findings = fb;
    size_t fn = (size_t)n00b_list_len(*r->findings);
    for (size_t i = 0; i < fn; i++) {
        n00b_quic_preflight_finding_t *f = n00b_list_get(*r->findings, i);
        if (f->severity == N00B_QUIC_PREFLIGHT_ERROR) {
            r->ok = false;
            break;
        }
    }
    return n00b_result_ok(n00b_quic_preflight_report_t *, r);
}

/* ===========================================================================
 * Print helper
 * =========================================================================== */

void
n00b_quic_preflight_report_print(n00b_quic_preflight_report_t *r, int fd)
{
    if (!r) return;
    size_t fn = r->findings ? (size_t)n00b_list_len(*r->findings) : 0;
    n00b_printf("Preflight: «#» («#» findings)",
                r->ok ? "OK" : "FAILED", fn, .fd = fd);
    for (size_t i = 0; i < fn; i++) {
        n00b_quic_preflight_finding_t *f = n00b_list_get(*r->findings, i);
        const char *sev = "INFO";
        if (f->severity == N00B_QUIC_PREFLIGHT_WARN)  sev = "WARN";
        if (f->severity == N00B_QUIC_PREFLIGHT_ERROR) sev = "ERROR";
        n00b_printf("  [«#»] «#»: «#»",
                    sev,
                    f->check ? f->check->data : "<no-id>",
                    f->detail ? f->detail->data : "",
                    .fd = fd);
        if (f->remediation && f->severity != N00B_QUIC_PREFLIGHT_INFO) {
            n00b_printf("         remedy: «#»",
                        f->remediation->data, .fd = fd);
        }
    }
}
