#include <string.h>
#include <unistd.h>

#include "n00b_crt.h"

static int
env_has_expected_marker(char **envp)
{
    if (envp == nullptr) {
        return 0;
    }

    for (char **cur = envp; *cur != nullptr; cur++) {
        if (strcmp(*cur, "N00B_CRT_STUB_EXPECT=present") == 0) {
            return 1;
        }
    }

    return 0;
}

[[noreturn]] void
n00b_crt_main(int argc, char **argv, char **envp)
{
    if (argc != 3) {
        _exit(10);
    }

    if (argv == nullptr || argv[0] == nullptr || argv[argc] != nullptr) {
        _exit(11);
    }

    if (strcmp(argv[1], "crt_arg_one") != 0
        || strcmp(argv[2], "crt_arg_two") != 0) {
        _exit(13);
    }

    if (!env_has_expected_marker(envp)) {
        _exit(12);
    }

    _exit(0);
}

void
n00b_crt_run_init_array(void)
{
}
