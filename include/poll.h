#pragma once

#ifdef _WIN32
#include "internal/win32_sockets.h"

#ifndef poll
#define poll(fds, nfds, timeout) WSAPoll((WSAPOLLFD *)(fds), (ULONG)(nfds), (timeout))
#endif

#else
#include_next <poll.h>
#endif
