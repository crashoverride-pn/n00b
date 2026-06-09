/**
 * @file backend_local.h
 * @brief Local directory storage backend.
 *
 * Maps backend paths to files under a root directory on the local
 * filesystem.  Supports hard links for the cache layer.
 */
#pragma once

#include "vfs/backend.h"

/**
 * @brief Create a local directory backend.
 *
 * @param root_dir  Absolute path to the root directory.  Must exist.
 * @kw allocator Allocator for backend state and local path scratch.
 * @return Initialized backend, or error on failure.
 */
extern n00b_result_t(n00b_vfs_backend_t *)
n00b_vfs_backend_local_new(n00b_string_t *root_dir) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief The vtable for the local directory backend.
 */
extern const n00b_vfs_backend_ops_t n00b_vfs_backend_local_ops;
