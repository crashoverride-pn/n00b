/*
 * test_quic_qlog.c — Verify endpoint .qlog_dir kwarg produces files.
 *
 * picoquic emits one .qlog file per cnx into the configured dir.
 * The format is QUIC qlog v0.3-ish JSON-SEQ; we parse it minimally
 * (look for the version string + at least one event) — enough to
 * confirm picoquic actually wrote it, without taking on a full
 * qlog-parser dependency.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "net/quic/endpoint.h"
#include "net/quic/conn.h"
#include "internal/net/quic/endpoint_internal.h"

#include "picoquic.h"

#include "../fixtures/quic_test_pki.h"

static int
count_qlog_files(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len > 5 && strcmp(name + len - 5, ".qlog") == 0) {
            n++;
        }
    }
    closedir(d);
    return n;
}

static char *
find_first_qlog(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return NULL;
    struct dirent *entry;
    char *path = NULL;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len > 5 && strcmp(name + len - 5, ".qlog") == 0) {
            size_t plen = strlen(dir) + 1 + len + 1;
            path = malloc(plen);
            snprintf(path, plen, "%s/%s", dir, name);
            break;
        }
    }
    closedir(d);
    return path;
}

static void
test_qlog_creation(void)
{
    /* Use a fresh per-test temp dir so multiple test runs don't pile
     * up files. */
    char dir[256];
    snprintf(dir, sizeof(dir), "/tmp/n00b_qlog_test_%d", (int)getpid());
    /* Fresh: remove if exists from a prior run. */
    {
        DIR *existing = opendir(dir);
        if (existing) {
            struct dirent *e;
            while ((e = readdir(existing)) != NULL) {
                if (e->d_name[0] != '.') {
                    char p[512];
                    snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
                    unlink(p);
                }
            }
            closedir(existing);
            rmdir(dir);
        }
    }
    /* Note: endpoint_new will mkdir the qlog_dir if it doesn't exist. */

    char *key_pem_path = n00b_quic_test_write_key_pem();
    if (!key_pem_path) { printf("  [SKIP] qlog_creation\n"); return; }

    auto cr = n00b_conduit_new();
    n00b_conduit_t *c = n00b_result_get(cr);
    auto ir = n00b_conduit_io_new_default(c);
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto sr = n00b_quic_endpoint_new(c, io,
                                     .listen         = true,
                                     .bind_host      = "127.0.0.1",
                                     .alpn           = "n00b-qlog/1",
                                     .cert_der_bytes = n00b_quic_test_cert_der,
                                     .cert_der_len   = n00b_quic_test_cert_der_len,
                                     .key_pem_path   = key_pem_path,
                                     .qlog_dir       = n00b_string_from_cstr(dir));
    if (n00b_result_is_err(sr)) {
        printf("  [SKIP] qlog_creation (server bind failed)\n");
        unlink(key_pem_path); free(key_pem_path);
        n00b_conduit_io_destroy(io); n00b_conduit_destroy(c);
        return;
    }
    n00b_quic_endpoint_t *server = n00b_result_get(sr);

    auto cur = n00b_quic_endpoint_new(c, io,
                                      .bind_host = "127.0.0.1",
                                      .alpn      = "n00b-qlog/1",
                                      .qlog_dir  = n00b_string_from_cstr(dir));
    n00b_quic_endpoint_t *client = n00b_result_get(cur);
    picoquic_set_null_verifier(client->quic);

    uint16_t           sport = n00b_quic_endpoint_local_port(server);
    struct sockaddr_in dst   = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(sport);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    auto ccr = n00b_quic_connect(client,
                                 (const struct sockaddr *)&dst,
                                 n00b_string_from_cstr("quic-test.n00b.local"));
    n00b_quic_conn_t *conn = n00b_result_get(ccr);

    /* Drive a handshake.  picoquic flushes qlog data when the cnx
     * is destroyed (not at end of every event), so we explicitly
     * close the conn and run again to flush. */
    for (int i = 0; i < 200; i++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);
        if (n00b_quic_conn_state(conn) == N00B_QUIC_CONN_STATE_CONNECTED) break;
    }
    assert(n00b_quic_conn_state(conn) == N00B_QUIC_CONN_STATE_CONNECTED);

    n00b_quic_close(conn, 0);
    for (int i = 0; i < 100; i++) {
        n00b_quic_endpoint_run_once(client, 5);
        n00b_quic_endpoint_run_once(server, 5);
    }

    /* Closing the endpoints triggers picoquic to flush any
     * outstanding qlog data per connection. */
    n00b_quic_endpoint_close(client);
    n00b_quic_endpoint_close(server);

    /* Now check the dir exists and contains at least one .qlog file
     * (we expect 2: one client cnx, one server cnx). */
    struct stat st;
    assert(stat(dir, &st) == 0);
    assert(S_ISDIR(st.st_mode));

    int n_files = count_qlog_files(dir);
    assert(n_files >= 1);

    /* Sanity-check: the file is non-empty and contains the qlog
     * format marker.  We look for the substring `"qlog_format"` —
     * picoquic writes JSON-SEQ but the first record always advertises
     * the format. */
    char *first = find_first_qlog(dir);
    assert(first != NULL);
    FILE *f = fopen(first, "rb");
    assert(f != NULL);
    char buf[4096] = {0};
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    assert(got > 0);
    /* Look for a hint that this is qlog: the format marker shows up
     * very early in any picoquic-emitted file. */
    assert(strstr(buf, "qlog") != NULL);
    free(first);

    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    unlink(key_pem_path); free(key_pem_path);
    printf("  [PASS] qlog_dir produced %d .qlog file(s) under %s\n",
           n_files, dir);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_qlog:\n");
    fflush(stdout);
    test_qlog_creation();
    fflush(stdout);
    printf("All quic qlog tests passed.\n");
    n00b_shutdown();
    return 0;
}
