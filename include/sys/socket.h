#pragma once

#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include_next <sys/socket.h>
#endif
