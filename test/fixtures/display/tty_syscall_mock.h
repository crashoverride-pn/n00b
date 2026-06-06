#pragma once

#include <stdbool.h>

typedef struct {
    bool enabled;
    bool stdin_isatty;
    bool stdout_isatty;
    bool tcgetattr_ok;
    bool tcsetattr_fails;
    int  tcsetattr_errno;
    int  tcgetattr_calls;
    int  tcsetattr_calls;
    int  stdout_write_calls;
    int  mouse_enable_writes;
} n00b_test_tty_faults_t;

extern void                     n00b_test_tty_faults_reset(void);
extern n00b_test_tty_faults_t   n00b_test_tty_faults_get(void);
extern void                     n00b_test_tty_faults_set(n00b_test_tty_faults_t faults);
