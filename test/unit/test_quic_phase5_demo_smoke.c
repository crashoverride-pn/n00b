/*
 * test_quic_phase5_demo_smoke.c — Smoke for `examples/quic_phase5_demo`.
 *
 * Phase 5 § 5.3.  Spawns the demo's `--loopback` mode and asserts:
 *   - Exit status 0.
 *   - stdout contains "Hello reply" (Greeter/Hello).
 *   - stdout contains "Stream item: i=3" (last server-stream item).
 *   - stdout contains "Vault.Read reply" (DPoP-required call).
 *   - stdout contains "Vault.Write reply" (DPoP + role=admin).
 *   - stdout contains "MTls.Echo reply" (beta-tenant routing).
 *   - stdout contains "metrics surface OK" (Prom scrape verified).
 *
 * The demo binary path is passed via N00B_QUIC_PHASE5_DEMO_BIN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#endif
#include <errno.h>

#include "n00b.h"
#include "core/runtime.h"

#ifndef _WIN32
static ssize_t
read_all(int fd, char *buf, size_t cap)
{
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t r = read(fd, buf + total, cap - 1 - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    buf[total] = '\0';
    return (ssize_t)total;
}
#endif

#ifdef _WIN32
static int
run_demo_loopback(const char *bin, char *out, size_t cap)
{
    if (strchr(bin, '"') != nullptr) {
        return -1;
    }

    char cmd[4096];
    int  n = snprintf(cmd, sizeof(cmd), "\"%s\" --loopback 2>&1", bin);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return -1;
    }

    FILE *fp = _popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    size_t total = 0;
    while (total + 1 < cap) {
        size_t r = fread(out + total, 1, cap - 1 - total, fp);
        total += r;
        if (r == 0) {
            if (ferror(fp)) {
                (void)_pclose(fp);
                return -1;
            }
            break;
        }
    }
    out[total] = '\0';

    return _pclose(fp);
}
#else
static int
run_demo_loopback(const char *bin, char *out, size_t cap)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execl(bin, bin, "--loopback", (char *)nullptr);
        _exit(127);
    }
    close(pipefd[1]);
    ssize_t n = read_all(pipefd[0], out, cap);
    close(pipefd[0]);
    if (n < 0) { kill(pid, SIGTERM); waitpid(pid, nullptr, 0); return -1; }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}
#endif

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *bin = getenv("N00B_QUIC_PHASE5_DEMO_BIN");
    if (!bin) {
        printf("test_quic_phase5_demo_smoke:\n"
               "  [SKIP] N00B_QUIC_PHASE5_DEMO_BIN not set\n");
        n00b_shutdown();
        return 77;  /* meson skip */
    }

    char out[16384] = {0};
    int rc = run_demo_loopback(bin, out, sizeof(out));

    printf("test_quic_phase5_demo_smoke:\n");
    if (rc != 0) {
        fprintf(stderr, "  demo exited with status %d\n", rc);
        fprintf(stderr, "----- stdout -----\n%s\n----- end stdout -----\n", out);
        n00b_shutdown();
        return 1;
    }

    static const char *needles[] = {
        "Hello reply",
        "Stream item: i=3",
        "Vault.Read reply",
        "Vault.Write reply",
        "MTls.Echo reply",
        "metrics surface OK",
    };
    int missing = 0;
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
        if (!strstr(out, needles[i])) {
            fprintf(stderr, "  [FAIL] missing %s\n", needles[i]);
            missing++;
        }
    }
    if (missing) {
        fprintf(stderr, "----- stdout -----\n%s\n----- end stdout -----\n", out);
        n00b_shutdown();
        return 1;
    }
    printf("  [PASS] loopback exercises all 5 RPCs + metrics surface\n");
    n00b_shutdown();
    return 0;
}
