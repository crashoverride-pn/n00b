#pragma once

/**
 * @file n00b/alloc_interpose.h
 * @brief (Compatibility no-op.) libc malloc-family interposition is automatic.
 *
 * Earlier designs required an application to include this header from its
 * main translation unit to install a macOS `__DATA,__interpose` table.  That
 * is no longer necessary: the interpose table (macOS) and the strong malloc
 * symbols (Linux) live inside libn00b itself, so simply linking libn00b
 * installs interposition.  Because libn00b is statically linked into n00b
 * executables, its macOS interpose table lands in the main-executable image
 * and interposes the picoquic/picotls dylibs (built shared on macOS).
 *
 * This header is kept as a no-op so existing
 * `#include <n00b/alloc_interpose.h>` lines keep compiling.  See
 * core/alloc_interpose.h for the runtime API (probe / require) and the
 * rationale.
 */
