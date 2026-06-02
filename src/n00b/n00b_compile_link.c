/**
 * @file n00b_compile_link.c
 * @brief Link .o files into an executable via a compiler driver.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "n00b/n00b_compile_binary.h"
#include "util/errno_str.h"
#include "core/string.h"
#include "conduit/print.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

static bool
file_readable(const char *path)
{
    if (!path || !*path) {
        return false;
    }

    FILE *f = fopen(path, "rb");

    if (!f) {
        return false;
    }

    fclose(f);
    return true;
}

static bool
join_path(char *buf, size_t buf_len, const char *dir, const char *leaf)
{
    if (!buf || buf_len == 0 || !dir || !leaf) {
        return false;
    }

    size_t      dir_len = strlen(dir);
    const char *sep     = "";

    if (dir_len > 0) {
        char last = dir[dir_len - 1];

        if (last != '/' && last != '\\') {
            sep = "/";
        }
    }

    int n = snprintf(buf, buf_len, "%s%s%s", dir, sep, leaf);

    return n > 0 && (size_t)n < buf_len;
}

static const char *
find_lib_dir(const char *hint)
{
    static char lib_path[1024];

    if (hint && join_path(lib_path, sizeof(lib_path), hint, "libn00b.a")
        && file_readable(lib_path)) {
        return hint;
    }

    const char *env = getenv("N00B_LIB_DIR");

    if (env && join_path(lib_path, sizeof(lib_path), env, "libn00b.a")
        && file_readable(lib_path)) {
        return env;
    }

    if (file_readable("../lib/libn00b.a")) {
        return "../lib";
    }

    if (file_readable("build_debug/libn00b.a")) {
        return "build_debug";
    }

    if (file_readable("build_cross_windows-x86_64/libn00b.a")) {
        return "build_cross_windows-x86_64";
    }

    return NULL;
}

static const char *
find_compiler(void)
{
    const char *env = getenv("N00B_COMPILER");

    if (env && *env) {
        return env;
    }

    return "clang";
}

static int
run_linker(const char *compiler, const char **argv)
{
#ifdef _WIN32
    int argc = 0;

    while (argv[argc]) {
        argc++;
    }

    const char **spawn_argv = n00b_alloc_array(const char *, (size_t)argc + 1);

    if (!spawn_argv) {
        fprintf(stderr, "n00b compile: cannot allocate linker argument list\n");
        return 1;
    }

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        bool        q   = false;

        if (!arg || !*arg) {
            q = true;
        }
        else {
            const char *p;
            for (p = arg; *p; p++) {
                if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'
                    || *p == '"') {
                    q = true;
                    break;
                }
            }
        }

        if (!q) {
            size_t len = strlen(arg);
            char  *dup = n00b_alloc_array(char, len + 1);

            if (!dup) {
                fprintf(stderr, "n00b compile: cannot allocate linker argument\n");
                for (int j = 0; j < i; j++) {
                    n00b_free((void *)spawn_argv[j]);
                }
                n00b_free(spawn_argv);
                return 1;
            }

            memcpy(dup, arg, len + 1);
            spawn_argv[i] = dup;
            continue;
        }

        size_t len = arg ? strlen(arg) : 0;
        char  *out = n00b_alloc_array(char, len * 2 + 3);

        if (!out) {
            fprintf(stderr, "n00b compile: cannot allocate linker argument\n");
            for (int j = 0; j < i; j++) {
                n00b_free((void *)spawn_argv[j]);
            }
            n00b_free(spawn_argv);
            return 1;
        }

        char  *dst         = out;
        size_t backslashes = 0;

        *dst++ = '"';

        for (size_t j = 0; j < len; j++) {
            char ch = arg[j];

            if (ch == '\\') {
                backslashes++;
                continue;
            }

            if (ch == '"') {
                while (backslashes--) {
                    *dst++ = '\\';
                    *dst++ = '\\';
                }
                *dst++ = '\\';
                *dst++ = '"';
                backslashes = 0;
                continue;
            }

            while (backslashes--) {
                *dst++ = '\\';
            }
            backslashes = 0;
            *dst++      = ch;
        }

        while (backslashes--) {
            *dst++ = '\\';
            *dst++ = '\\';
        }

        *dst++ = '"';
        *dst   = '\0';

        spawn_argv[i] = out;
    }

    spawn_argv[argc] = NULL;

    intptr_t rc = _spawnvp(_P_WAIT, compiler, spawn_argv);

    for (int i = 0; i < argc; i++) {
        n00b_free((void *)spawn_argv[i]);
    }
    n00b_free(spawn_argv);

    if (rc == -1) {
        n00b_eprintf("n00b compile: spawn(«#») failed: «#»",
                     n00b_string_from_cstr(compiler),
                     n00b_errno_str(errno));
        return 127;
    }

    return (int)rc;
#else
    pid_t pid = fork();

    if (pid < 0) {
        n00b_eprintf("n00b compile: fork() failed: «#»",
                     n00b_errno_str(errno));
        return 1;
    }

    if (pid == 0) {
        execvp(compiler, (char *const *)argv);
        n00b_eprintf("n00b compile: execvp(«#») failed: «#»",
                     n00b_string_from_cstr(compiler),
                     n00b_errno_str(errno));
        _exit(127);
    }

    int status;

    if (waitpid(pid, &status, 0) < 0) {
        n00b_eprintf("n00b compile: waitpid() failed: «#»",
                     n00b_errno_str(errno));
        return 1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return 1;
#endif
}

int
n00b_link_binary(const char **obj_paths, int n_objs, const char *output, const char *lib_dir)
{
#ifdef _WIN32
    (void)obj_paths;
    (void)n_objs;
    (void)output;
    (void)lib_dir;
    fprintf(stderr, "n00b compile: Windows linking is not supported in this build\n");
    return 1;
#endif

    const char *resolved_lib_dir = find_lib_dir(lib_dir);
    const char *compiler         = find_compiler();

    if (!resolved_lib_dir) {
        fprintf(stderr, "n00b compile: cannot find libn00b.a; set N00B_LIB_DIR or --lib-dir\n");
        return 1;
    }

    int          max_args = n_objs + 40;
    const char **argv     = n00b_alloc_array(const char *, (size_t)(max_args + 1));
    int          ai       = 0;

    argv[ai++] = compiler;
#ifdef _WIN32
    argv[ai++] = "--target=x86_64-w64-windows-gnu";
    argv[ai++] = "-static";
    argv[ai++] = "-Wl,--stack,16777216";
    argv[ai++] = "-Wl,--subsystem,console";
#endif
    argv[ai++] = "-o";
    argv[ai++] = output;

    for (int i = 0; i < n_objs; i++) {
        argv[ai++] = obj_paths[i];
    }

    char lib_flag[1024];

    snprintf(lib_flag, sizeof(lib_flag), "-L%s", resolved_lib_dir);
    argv[ai++] = lib_flag;

    argv[ai++] = "-ln00b";
    argv[ai++] = "-lpthread";
    argv[ai++] = "-lm";

#if defined(_WIN32)
    argv[ai++] = "-lws2_32";
    argv[ai++] = "-lsynchronization";
    argv[ai++] = "-ladvapi32";
#elif defined(__APPLE__)
    argv[ai++] = "-framework";
    argv[ai++] = "CoreFoundation";
    argv[ai++] = "-framework";
    argv[ai++] = "AppKit";
#else
    argv[ai++] = "-latomic";
    argv[ai++] = "-ldl";
#endif

    argv[ai] = NULL;

    int rc = run_linker(compiler, argv);
    n00b_free(argv);
    return rc;
}
