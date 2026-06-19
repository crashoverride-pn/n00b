/*
 * test_quic_trust_bridge.c — End-to-end verification that the
 * trust→picotls bridge actually fires during the QUIC handshake.
 *
 * Three sub-tests:
 *
 *   1. Pinned trust matching the server's leaf fingerprint → handshake
 *      succeeds.  Proves the bridge is installed and accepts the chain
 *      it's supposed to accept.
 *
 *   2. Pinned trust set to a *different* fingerprint (all-zeros) →
 *      handshake fails before any cnx state advances.  Proves the
 *      bridge actually rejects on a verdict mismatch (i.e., the
 *      fallthrough path is wired).
 *
 *   3. Default trust (system OS-native) → handshake against the
 *      self-signed test fixture fails, because the OS trust store
 *      doesn't trust our synthetic CA.  Proves the
 *      "safe-by-default" choice from § 5.2 is honored — an endpoint
 *      with no `.trust =` does NOT silently accept.
 *
 * The pattern follows test_quic_handshake.c — same loopback shape,
 * same self-signed fixture; the difference is we exercise the
 * verify-cert path instead of bypassing it via
 * picoquic_set_null_verifier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/sha256.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "crypto/trust.h"
#include "internal/net/quic/endpoint_internal.h"
#include "picoquic.h"

#include "../fixtures/quic_test_pki.h"

static void
sha256_be(const void *data, size_t len, uint8_t out[32])
{
    n00b_sha256_digest_t words;
    n00b_sha256_hash(data, len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i * 4]   = (uint8_t)(w >> 24);
        out[i*4 + 1] = (uint8_t)(w >> 16);
        out[i*4 + 2] = (uint8_t)(w >> 8);
        out[i*4 + 3] = (uint8_t)(w);
    }
}

/* Run the loopback handshake until a terminal event happens.  Returns
 * the final client-side cnx state.  Bounded at 200 ticks (~1 s). */
static n00b_quic_conn_state_t
drive_handshake(n00b_quic_endpoint_t *client,
                n00b_quic_endpoint_t *server,
                n00b_quic_conn_t     *conn)
{
    for (int i = 0; i < 200; i++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);

        n00b_quic_conn_state_t st = n00b_quic_conn_state(conn);
        if (st == N00B_QUIC_CONN_STATE_CONNECTED
            || st == N00B_QUIC_CONN_STATE_CLOSED
            || st == N00B_QUIC_CONN_STATE_FAILED) {
            return st;
        }
    }
    return n00b_quic_conn_state(conn);
}

typedef struct {
    n00b_conduit_t            *c;
    n00b_conduit_io_backend_t *io;
    n00b_quic_endpoint_t      *server;
    n00b_quic_endpoint_t      *client;
    char                      *key_path;
    uint16_t                   sport;
} bridge_setup_t;

/* Common setup: server endpoint + UDP bound on 127.0.0.1.  Client is
 * created here too with whatever `client_trust` the caller passed; if
 * NULL the endpoint defaults to system trust per § 5.2.
 *
 * Returns false on setup failure (test should SKIP). */
static bool
setup(bridge_setup_t *s, n00b_quic_trust_t *client_trust)
{
    memset(s, 0, sizeof(*s));
    s->key_path = n00b_quic_test_write_key_pem();
    if (!s->key_path) {
        return false;
    }

    auto cr = n00b_conduit_new();
    s->c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(s->c);
    s->io = n00b_result_get(ir);

    auto sr = n00b_quic_endpoint_new(s->c, s->io,
                                     .listen         = true,
                                     .bind_host      = "127.0.0.1",
                                     .alpn           = "n00b-trust-bridge/1",
                                     .cert_der_bytes = n00b_quic_test_cert_der,
                                     .cert_der_len   = n00b_quic_test_cert_der_len,
                                     .key_pem_path   = s->key_path);
    if (n00b_result_is_err(sr)) {
        return false;
    }
    s->server = n00b_result_get(sr);
    s->sport  = n00b_quic_endpoint_local_port(s->server);

    auto cur = n00b_quic_endpoint_new(s->c, s->io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = "n00b-trust-bridge/1",
                                      .trust     = client_trust);
    if (n00b_result_is_err(cur)) {
        return false;
    }
    s->client = n00b_result_get(cur);
    return true;
}

static void
teardown(bridge_setup_t *s)
{
    if (s->client) {
        n00b_quic_endpoint_close(s->client);
    }
    if (s->server) {
        n00b_quic_endpoint_close(s->server);
    }
    if (s->io) {
        n00b_conduit_io_destroy(s->io);
    }
    if (s->c) {
        n00b_conduit_destroy(s->c);
    }
    if (s->key_path) {
        unlink(s->key_path);
        free(s->key_path);
    }
}

static n00b_quic_conn_t *
do_connect(bridge_setup_t *s)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(s->sport);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    auto rr = n00b_quic_connect(s->client,
                                (const struct sockaddr *)&dst,
                                n00b_string_from_cstr("quic-test.n00b.local"));
    return n00b_result_is_ok(rr) ? n00b_result_get(rr) : nullptr;
}

/* ---- 1. Pinned trust accepts the matching cert. ---------------- */

static void
test_pinned_accept(void)
{
    uint8_t fp[32];
    sha256_be(n00b_quic_test_cert_der, n00b_quic_test_cert_der_len, fp);
    n00b_quic_trust_t *pinned = n00b_quic_trust_pinned(fp);

    bridge_setup_t s;
    if (!setup(&s, pinned)) {
        printf("  [SKIP] pinned-accept (setup failed)\n");
        teardown(&s);
        return;
    }
    n00b_quic_conn_t *conn = do_connect(&s);
    assert(conn);
    n00b_quic_conn_state_t st = drive_handshake(s.client, s.server, conn);
    assert(st == N00B_QUIC_CONN_STATE_CONNECTED);
    printf("  [PASS] pinned trust matching server fp → handshake CONNECTED\n");

    teardown(&s);
    n00b_quic_trust_close(pinned);
}

/* ---- 2. Pinned trust set to wrong fp → handshake rejected. ----- */

static void
test_pinned_reject(void)
{
    uint8_t bogus[32] = {0};  /* deliberately not the server fp */
    n00b_quic_trust_t *pinned = n00b_quic_trust_pinned(bogus);

    bridge_setup_t s;
    if (!setup(&s, pinned)) {
        printf("  [SKIP] pinned-reject (setup failed)\n");
        teardown(&s);
        return;
    }
    n00b_quic_conn_t *conn = do_connect(&s);
    assert(conn);
    n00b_quic_conn_state_t st = drive_handshake(s.client, s.server, conn);
    /* Verify-cert callback returns BAD_CERTIFICATE → handshake never
     * reaches CONNECTED.  picoquic settles into CLOSED on the clean
     * close-on-alert path; FAILED is the abrupt-fail variant.  Both
     * are acceptable terminal states; CONNECTING is *not* (would mean
     * we never ran out of time on the cert verdict). */
    assert(st == N00B_QUIC_CONN_STATE_CLOSED
           || st == N00B_QUIC_CONN_STATE_FAILED);
    printf("  [PASS] pinned trust mismatch → handshake refused (state=%d)\n",
           (int)st);

    teardown(&s);
    n00b_quic_trust_close(pinned);
}

/* ---- 3. Default (system) trust → self-signed test cert rejected. */

static void
test_default_system_rejects_selfsigned(void)
{
    bridge_setup_t s;
    /* No trust= → endpoint defaults to n00b_quic_trust_system(). */
    if (!setup(&s, nullptr)) {
        printf("  [SKIP] default-system (setup failed)\n");
        teardown(&s);
        return;
    }
    n00b_quic_conn_t *conn = do_connect(&s);
    assert(conn);
    n00b_quic_conn_state_t st = drive_handshake(s.client, s.server, conn);
    /* The OS trust store does not trust our self-signed test CA, so
     * verification must fail.  This is the safe-by-default property
     * § 5.2 commits to.  Same terminal-state set as test 2. */
    assert(st == N00B_QUIC_CONN_STATE_CLOSED
           || st == N00B_QUIC_CONN_STATE_FAILED);
    printf("  [PASS] default system trust rejects self-signed (state=%d)\n",
           (int)st);

    teardown(&s);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_trust_bridge:\n");
    test_pinned_accept();
    test_pinned_reject();
    test_default_system_rejects_selfsigned();
    printf("All quic_trust_bridge tests passed.\n");

    n00b_shutdown();
    return 0;
}
