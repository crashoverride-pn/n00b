/**
 * @file backend_memory.h
 * @brief In-memory storage backend for testing and ephemeral use.
 *
 * All data is stored in a hash map keyed by path string.  No
 * persistence — everything is lost when the backend is cleaned up.
 */
#pragma once

#include "vfs/backend.h"

/**
 * @brief Create an in-memory storage backend.
 *
 * The returned backend has an empty store.  All operations are
 * immediate and consistent (no eventual consistency delay).
 *
 * @kw allocator Allocator for backend state and memory objects.
 *
 * @return Initialized backend, or error on allocation failure.
 */
extern n00b_result_t(n00b_vfs_backend_t *)
n00b_vfs_backend_memory_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief The vtable for the in-memory backend.
 *
 * Exposed for testing; callers normally use @c n00b_vfs_backend_memory_new.
 */
extern const n00b_vfs_backend_ops_t n00b_vfs_backend_memory_ops;
