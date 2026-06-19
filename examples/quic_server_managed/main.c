/*
 * quic_server_managed — manifest-driven QUIC server.
 *
 * Reads a deployment manifest (JSON) from argv[1], runs preflight,
 * and either:
 *   - exits 0 / 2 with the report on stdout if `--preflight` was
 *     also passed (the second positional arg);
 *   - or, otherwise, builds a server endpoint per the manifest and
 *     drives `n00b_quic_endpoint_run_once` until SIGINT.
 *
 * **Phase 2 v1 scope**: the only fully-wired cert kind is `static`
 * — the existing static cert provisioner reads chain_pem_path off
 * disk and a key_secret_uri (typically `keychain:` or `ephemeral:`)
 * for the signing key.  `external` and `acme` are recognized by
 * the manifest loader but the orchestrator declines to run them
 * here until the deployment playbook lands.  Bind ports < 1024
 * require elevated privileges; preflight surfaces the issue ahead
 * of the actual bind() call.
 *
 * Usage:
 *   quic_server_managed <manifest.json>             # run
 *   quic_server_managed <manifest.json> --preflight # validate only
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/manifest.h"
#include "net/quic/endpoint.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_provisioner.h"

static volatile sig_atomic_t g_stop = 0;

static void
on_sig(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int
do_preflight_only(n00b_quic_manifest_t *m)
{
    auto pr = n00b_quic_preflight(m);
    if (!n00b_result_is_ok(pr)) {
        fprintf(stderr, "preflight call failed\n");
        return 2;
    }
    n00b_quic_preflight_report_t *rep = n00b_result_get(pr);
    n00b_quic_preflight_report_print(rep, 1);  /* stdout fd */
    return rep->ok ? 0 : 2;
}


static n00b_quic_endpoint_t *
bring_up_endpoint(n00b_conduit_t                *c,
                  n00b_conduit_io_backend_t     *io,
                  n00b_quic_manifest_endpoint_t *ep)
{
    const char *ep_id = ep->id ? (const char *)ep->id->data : "?";
    if (ep->cert.kind != N00B_QUIC_MANIFEST_CERT_STATIC) {
        fprintf(stderr,
                "[%s] cert.kind != static is not yet supported "
                "in quic_server_managed; the deployment playbook "
                "wires external + acme later.\n",
                ep_id);
        return NULL;
    }

    /* Open the key secret. */
    auto kr = n00b_quic_secret_open(ep->cert.key_secret_uri);
    if (!n00b_result_is_ok(kr)) {
        fprintf(stderr,
                "[%s] cannot open key_secret_uri '%s'\n",
                ep_id, (const char *)ep->cert.key_secret_uri->data);
        return NULL;
    }
    n00b_quic_secret_t *key = n00b_result_get(kr);

    /* Static provisioner pulls the PEM chain off disk + opens DER. */
    auto pr = n00b_quic_cert_provisioner_static(
        ep->cert.chain_pem_path->data, key);
    if (!n00b_result_is_ok(pr)) {
        fprintf(stderr, "[%s] cert provisioner construction failed\n", ep_id);
        return NULL;
    }
    n00b_quic_cert_provisioner_t *prov = n00b_result_get(pr);
    auto cr = prov->acquire(prov);
    if (!n00b_result_is_ok(cr)) {
        fprintf(stderr, "[%s] cert acquire failed\n", ep_id);
        return NULL;
    }
    n00b_quic_cert_t *cert = n00b_result_get(cr);

    /* The endpoint constructor takes raw DER bytes for the cert; we
     * extract the leaf from the PEM chain.  Multi-cert chains aren't
     * exercised at this seam yet. */
    extern n00b_result_t(n00b_buffer_t *)
        n00b_certp_pem_first_cert_to_der(n00b_buffer_t *pem);
    auto dr = n00b_certp_pem_first_cert_to_der(cert->chain_pem);
    if (!n00b_result_is_ok(dr)) {
        fprintf(stderr, "[%s] PEM→DER conversion failed\n", ep_id);
        return NULL;
    }
    n00b_buffer_t *der = n00b_result_get(dr);

    /* Pick the first ALPN as the default; clients that negotiate a
     * different one in the list will need ALPN-selection wiring,
     * which Phase 2 doesn't yet provide. */
    size_t alpn_n = (ep->alpns ? (size_t)n00b_list_len(*ep->alpns) : 0);
    const char *alpn0 = (alpn_n > 0)
                        ? (const char *)
                              ((n00b_buffer_t *)
                                   n00b_list_get(*ep->alpns, 0))->data
                        : "n00b/1";

    /* The endpoint constructor wants a path to a PEM-PKCS#8 key
     * file.  We round-trip through a tempfile pulled from the
     * secret-handle's `format` if it's an ephemeral; for keychain/
     * KMS the proper path is the picotls sign-callback bridge,
     * which Phase 2 v1 doesn't ship.  Document the limitation. */
    char *key_path = nullptr;
    const char *key_uri = ep->cert.key_secret_uri->data;
    if (strncmp(key_uri, "ephemeral:", 10) == 0) {
        fprintf(stderr,
                "[%s] ephemeral key URIs are stubs; the deployment "
                "playbook uses real key paths (keychain export, "
                "KMS pre-export, etc.).\n", ep_id);
        return NULL;
    } else {
        /* Treat the URI as a literal path for now; deployments using
         * `file:/path/to/key.pem` would benefit from a `file:`
         * provider in the secret module. */
        if (strncmp(key_uri, "file:", 5) == 0) {
            key_path = (char *)key_uri + 5;
        } else {
            fprintf(stderr,
                    "[%s] key_secret_uri scheme not yet wired through "
                    "to picotls; use 'file:/path/to/key.pem' for v1.\n",
                    ep_id);
            return NULL;
        }
    }

    auto er = n00b_quic_endpoint_new(c, io,
                                     .listen         = true,
                                     .bind_host      = ep->bind_host->data,
                                     .bind_port      = ep->bind_port,
                                     .alpn           = alpn0,
                                     .cert_der_bytes = (const uint8_t *)der->data,
                                     .cert_der_len   = (size_t)der->byte_len,
                                     .key_pem_path   = key_path);
    if (!n00b_result_is_ok(er)) {
        fprintf(stderr, "[%s] endpoint construct failed: %s\n",
                ep_id,
                n00b_quic_err_str((n00b_quic_err_t)n00b_result_get_err(er)));
        return NULL;
    }
    return n00b_result_get(er);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <manifest.json> [--preflight]\n",
                argv[0]);
        return 1;
    }
    bool preflight_only = (argc >= 3 &&
                           strcmp(argv[2], "--preflight") == 0);

    auto mr = n00b_quic_manifest_load_path(argv[1]);
    if (!n00b_result_is_ok(mr)) {
        fprintf(stderr, "Failed to load manifest from %s\n", argv[1]);
        return 1;
    }
    n00b_quic_manifest_t *m = n00b_result_get(mr);
    size_t ep_count = m->endpoints
                      ? (size_t)n00b_list_len(*m->endpoints) : 0;
    fprintf(stderr, "Loaded manifest: service_name='%s', %zu endpoint(s)\n",
            m->service_name, ep_count);

    /* Always run preflight before binding. */
    auto pr = n00b_quic_preflight(m);
    n00b_quic_preflight_report_t *rep = n00b_result_get(pr);
    n00b_quic_preflight_report_print(rep, 2);  /* stderr fd */
    if (preflight_only) {
        return rep->ok ? 0 : 2;
    }
    if (!rep->ok) {
        fprintf(stderr,
                "Preflight reported errors; refusing to start.\n"
                "(Re-run with --preflight to see the report only.)\n");
        return 2;
    }

    /* Bring up the conduit. */
    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    /* Bring up each endpoint.  v1 requires kind=static. */
    n00b_quic_endpoint_t **eps = calloc(ep_count,
                                        sizeof(n00b_quic_endpoint_t *));
    int up = 0;
    for (size_t i = 0; i < ep_count; i++) {
        eps[i] = bring_up_endpoint(c, io, n00b_list_get(*m->endpoints, i));
        if (eps[i]) up++;
    }
    if (up == 0) {
        fprintf(stderr, "No endpoints came up; exiting.\n");
        free(eps);
        return 1;
    }
    fprintf(stderr, "%d/%zu endpoints listening; SIGINT to stop.\n",
            up, ep_count);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    while (!g_stop) {
        for (size_t i = 0; i < ep_count; i++) {
            if (eps[i]) {
                n00b_quic_endpoint_run_once(eps[i], 100);
            }
        }
    }

    fprintf(stderr, "Stopping.\n");
    for (size_t i = 0; i < ep_count; i++) {
        if (eps[i]) n00b_quic_endpoint_close(eps[i]);
    }
    free(eps);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    n00b_shutdown();
    return 0;
}
