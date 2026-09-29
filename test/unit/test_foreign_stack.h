#ifndef N00B_TEST_FOREIGN_STACK_H
#define N00B_TEST_FOREIGN_STACK_H

// Stack bounds of the calling pthread, for n00b_thread_init's
// .foreign_stack_low / .foreign_stack_high. The runtime does not discover a
// foreign thread's stack; the embedding app, here the test, supplies it.
// macOS reports the stack top and size, glibc the base and size (which needs
// _GNU_SOURCE, set by the build).

#include <pthread.h>
#include <stddef.h>

static inline void
n00b_test_pthread_stack_bounds(char **lo, char **hi)
{
#if defined(__APPLE__)
    *hi = (char *)pthread_get_stackaddr_np(pthread_self());
    *lo = *hi - pthread_get_stacksize_np(pthread_self());
#else
    pthread_attr_t attr;
    void          *base;
    size_t         sz;
    pthread_getattr_np(pthread_self(), &attr);
    pthread_attr_getstack(&attr, &base, &sz);
    pthread_attr_destroy(&attr);
    *lo = (char *)base;
    *hi = *lo + sz;
#endif
}

#endif
