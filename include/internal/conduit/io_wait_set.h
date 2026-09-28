#pragma once

/**
 * @file io_wait_set.h
 * @brief Interest-mask policy shared by the poll, epoll, io_uring, and WSAPoll
 * backends.
 */

#include "conduit/io.h"

#if defined(_WIN32)
#include "internal/win32_sockets.h"
#else
#include <poll.h>
#endif

/**
 * The poll events a backend asks the kernel to wait on for @p ops: POLLIN for
 * READ and POLLOUT for WRITE.
 *
 * Zero means the fd must stay out of the kernel wait set. poll, epoll,
 * io_uring poll, and WSAPoll all report POLLHUP and POLLERR whatever mask is
 * requested, so a registered idle fd whose peer is gone (stdin fed by a closed
 * pipe) would make every level-triggered wait return at once. The backend puts
 * the fd back in the set when read or write interest returns.
 *
 * ERROR and HUP are therefore reported only alongside READ or WRITE interest.
 * A mask of ERROR or HUP alone waits on nothing, as it does on kqueue, which
 * has no filter for either.
 */
static inline short
n00b_conduit_io_wait_events(n00b_conduit_io_op_t ops)
{
    short events = 0;
    if (ops & N00B_CONDUIT_IO_READ) {
        events |= POLLIN;
    }
    if (ops & N00B_CONDUIT_IO_WRITE) {
        events |= POLLOUT;
    }
    return events;
}
