#ifdef _WIN32

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <shellapi.h>

#include "n00b_crt.h"

static HANDLE
n00b_crt_heap(void)
{
    HANDLE heap = GetProcessHeap();

    if (heap == nullptr) {
        ExitProcess(127);
    }

    return heap;
}

static void *
n00b_crt_alloc(size_t size)
{
    void *result = HeapAlloc(n00b_crt_heap(), HEAP_ZERO_MEMORY, size);

    if (result == nullptr) {
        ExitProcess(127);
    }

    return result;
}

static size_t
n00b_crt_wide_len(const wchar_t *wide)
{
    size_t result = 0;

    while (wide[result] != L'\0') {
        result++;
    }

    return result;
}

static char *
n00b_crt_wide_to_utf8(const wchar_t *wide)
{
    int bytes = WideCharToMultiByte(CP_UTF8,
                                    0,
                                    wide,
                                    -1,
                                    nullptr,
                                    0,
                                    nullptr,
                                    nullptr);
    if (bytes <= 0) {
        ExitProcess(127);
    }

    char *result = n00b_crt_alloc((size_t)bytes);
    int   wrote  = WideCharToMultiByte(CP_UTF8,
                                      0,
                                      wide,
                                      -1,
                                      result,
                                      bytes,
                                      nullptr,
                                      nullptr);
    if (wrote != bytes) {
        ExitProcess(127);
    }

    return result;
}

static char **
n00b_crt_build_argv(int *argc_out)
{
    int      argc      = 0;
    wchar_t *cmd_line  = GetCommandLineW();
    wchar_t **wide_argv = CommandLineToArgvW(cmd_line, &argc);

    if (wide_argv == nullptr || argc < 0) {
        ExitProcess(127);
    }

    char **argv = n00b_crt_alloc(((size_t)argc + 1) * sizeof(char *));

    for (int i = 0; i < argc; i++) {
        argv[i] = n00b_crt_wide_to_utf8(wide_argv[i]);
    }

    LocalFree(wide_argv);

    *argc_out = argc;
    return argv;
}

static char **
n00b_crt_build_envp(void)
{
    wchar_t *env_block = GetEnvironmentStringsW();

    if (env_block == nullptr) {
        ExitProcess(127);
    }

    size_t   count = 0;
    wchar_t *cur   = env_block;

    for (; *cur != L'\0'; cur += n00b_crt_wide_len(cur) + 1) {
        count++;
    }

    char **envp = n00b_crt_alloc((count + 1) * sizeof(char *));
    size_t ix   = 0;

    cur = env_block;
    for (; *cur != L'\0'; cur += n00b_crt_wide_len(cur) + 1) {
        envp[ix++] = n00b_crt_wide_to_utf8(cur);
    }

    FreeEnvironmentStringsW(env_block);

    return envp;
}

[[noreturn]] void
n00b_crt_windows_main(void)
{
    _set_error_mode(_OUT_TO_STDERR);

    int    argc = 0;
    char **argv = n00b_crt_build_argv(&argc);
    char **envp = n00b_crt_build_envp();

    n00b_crt_main(argc, argv, envp);
    __builtin_unreachable();
}

#endif
