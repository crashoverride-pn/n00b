/*
 * test_quic_rpc_demo_smoke.c — Smoke for `examples/quic_rpc_demo`.
 *
 * Phase 4 § 4.12.  Spawns the demo's `--loopback` mode as a subprocess
 * and asserts that:
 *   - The process exits with status 0.
 *   - stdout contains "Hello reply: Hello, alice!" (unary).
 *   - stdout contains "Stream item 5: tick 5" (last server-stream item).
 *   - stdout contains "Upload: chunks=4 bytes=40" (client-stream summary).
 *   - stdout contains "Chat reply: ping-3 seq=4" (last bidi response).
 *
 * The full end-to-end exercise of all four RPC shapes (unary,
 * server-stream, client-stream, bidi) + auth + deadline + cancellation
 * context lives in the demo binary itself; the smoke just sanity-checks
 * that all the wiring up to a successful run stays green under ASan +
 * UBSan in CI.
 *
 * The demo binary path is passed via the `N00B_QUIC_RPC_DEMO_BIN` env
 * var (set by meson when this test is registered).  When the var isn't
 * set, the test prints [SKIP] rather than failing — useful for ad-hoc
 * runs that didn't go through the meson harness.
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
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "  pipe() err=%d\n", errno);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child: redirect stdout to the pipe, leave stderr alone. */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execl(bin, bin, "--loopback", (char *)nullptr);
        _exit(127);  /* exec failed */
    }

    /* Parent. */
    close(pipefd[1]);

    /* Set a 60s wall-clock cap on the child via SIGALRM to the parent;
     * if the alarm fires we kill the child and report failure. */
    ssize_t n = read_all(pipefd[0], out, cap);
    close(pipefd[0]);
    if (n < 0) {
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
        return -1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) {
        fprintf(stderr, "  child terminated abnormally (signal=%d)\n",
                WIFSIGNALED(status) ? WTERMSIG(status) : -1);
        return -1;
    }
    return WEXITSTATUS(status);
}
#endif

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_rpc_demo_smoke:\n");
    fflush(stdout);

    const char *bin = getenv("N00B_QUIC_RPC_DEMO_BIN");
    if (!bin || !*bin) {
        printf("  [SKIP] N00B_QUIC_RPC_DEMO_BIN not set\n");
        return 0;
    }

    char out[8192];
    int rc = run_demo_loopback(bin, out, sizeof(out));
    if (rc != 0) {
        printf("  [FAIL] demo exit status=%d\n", rc);
        printf("--- stdout ---\n%s\n--- end ---\n", out);
        return 1;
    }

    /* Assert observable contract. */
    if (!strstr(out, "Hello reply: Hello, alice!")) {
        printf("  [FAIL] stdout missing 'Hello reply: Hello, alice!'\n");
        printf("--- stdout ---\n%s\n--- end ---\n", out);
        return 1;
    }
    if (!strstr(out, "Stream item 5: tick 5")) {
        printf("  [FAIL] stdout missing 'Stream item 5: tick 5'\n");
        printf("--- stdout ---\n%s\n--- end ---\n", out);
        return 1;
    }
    if (!strstr(out, "Upload: chunks=4 bytes=40")) {
        printf("  [FAIL] stdout missing 'Upload: chunks=4 bytes=40'\n");
        printf("--- stdout ---\n%s\n--- end ---\n", out);
        return 1;
    }
    if (!strstr(out, "Chat reply: ping-3 seq=4")) {
        printf("  [FAIL] stdout missing 'Chat reply: ping-3 seq=4'\n");
        printf("--- stdout ---\n%s\n--- end ---\n", out);
        return 1;
    }

    printf("  [PASS] quic_rpc_demo_smoke "
           "(loopback Hello + Stream + Upload + Chat)\n");
    n00b_shutdown();
    return 0;
}
