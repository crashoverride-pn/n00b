#pragma once

/**
 * @file n00b/alloc_interpose.h
 * @brief Compatibility no-op for the old allocator-interpose installer.
 *
 * Earlier designs required an application to include this header from its
 * main translation unit to install a macOS `__DATA,__interpose` table. That
 * model is no longer used: dyld interpose tables do not interpose the image
 * that contains the table, and n00b currently links libn00b statically into
 * executables. Vendored QUIC/picotls code is redirected by the force-included
 * compile-time shim in `core/alloc_interpose_shim.h`; Linux also gets
 * process-wide coverage from strong malloc-family symbols in libn00b.
 *
 * This header is kept as a no-op so existing
 * `#include <n00b/alloc_interpose.h>` lines keep compiling.  See
 * core/alloc_interpose.h for the runtime API (probe / require) and the
 * rationale.
 */
