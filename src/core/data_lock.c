/*
 * Data lock allocation: creates initialized rwlock for data structures.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/thread.h"
#include "core/runtime.h"
#include "core/rwlock.h"
#include "core/data_lock.h"

n00b_rwlock_t *
n00b_data_lock_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!n00b_default_runtime_is_set()
        || !n00b_get_runtime()->startup_complete) {
        return nullptr;
    }

    n00b_allocator_t *lock_allocator =
        allocator != nullptr ?
            allocator :
            (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    n00b_rwlock_t *lock =
        n00b_alloc_with_opts(
            n00b_rwlock_t,
            &(n00b_alloc_opts_t){
                .allocator = lock_allocator,
            });

    n00b_rw_init(lock);
    return lock;
}

void
n00b_finalize_data_lock(void *lock_ptr)
{
    n00b_rwlock_t *lock = (n00b_rwlock_t *)lock_ptr;
    if (lock != nullptr) {
        n00b_free(lock);
    }
}
