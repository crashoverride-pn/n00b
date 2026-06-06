# n00b Core Library

## Overview

The n00b core library provides the foundational runtime infrastructure:
memory allocation with garbage collection, type-safe generic containers,
threading and synchronization primitives, algebraic data types, and a
runtime type registry.

The library is organized into seven layers:

1. **Platform** &mdash; cross-platform types, TLS, atomics, futex.
2. **Memory** &mdash; allocation hierarchy (raw &rarr; arena &rarr;
   pool), mmap registry, GC, finalizers, stop-the-world synchronization.
3. **Containers** &mdash; type-safe generic list, stack, array, linked
   list, dictionary, tree, and interval tree.
4. **Algebraic types** &mdash; option, result, variant, tuple.
5. **Synchronization** &mdash; mutex, reader-writer lock, condition
   variable, data-structure locking, lock accounting.
6. **Type system** &mdash; type registry, vtable, per-type metadata.
7. **Runtime** &mdash; initialization, thread management, per-thread
   state, utilities.

### Design principles

- **Type safety via `typeid()`.** Every generic container is uniquely
  tagged at compile time by its element type(s).  No casts needed at
  call sites.
- **Allocation hierarchy.** Public macros (`n00b_alloc`, etc.) hide the
  internal allocation pipeline.  Never call `_n00b_alloc_raw()` directly.
- **Public APIs never return bare pointers.** Fallible operations return
  `n00b_result_t(T)`, optional values return `n00b_option_t(T)`, arrays
  return `n00b_array_t(T)`.
- **Error propagation via `!`.** ncc's postfix `!` operator unwraps a
  `n00b_result_t` on success or returns early with the error carrier &mdash;
  like Rust's `?`.
- **Minimal locking.** Reader-writer locks for containers, futex for
  thread synchronization, lock-free reads on dictionaries.
- **Keyword arguments.** Functions that allocate accept `.allocator` and
  other options via ncc's `_kargs` extension.

---

## Platform &mdash; `core/platform.h`

Cross-platform abstractions for threading, TLS, timing, and system
queries.  Automatically detects the platform and architecture:

| Macro | Platforms |
|-------|-----------|
| `BASE_PLATFORM_MACOS` / `_LINUX` / `_WINDOWS` | OS detection |
| `BASE_ARCH_ARM64` / `_X86_64` | Architecture detection |
| `BASE_ALIGN` | 16-byte alignment |

Key inline functions:

```c
void      *base_tls_get(base_tls_key_t key);
void       base_tls_set(base_tls_key_t key, void *value);
void       base_nanosleep_ns(uint64_t ns);
uint64_t   base_monotonic_ms(void);
uint64_t   base_monotonic_ns(void);
size_t     base_page_size(void);
```

### Atomics &mdash; `core/atomic.h`

Wrappers with explicit memory ordering:

```c
n00b_atomic_load(x)              // acquire
n00b_atomic_store(x, y)          // release
n00b_atomic_add(x, y)            // acq_rel
n00b_atomic_cas(x, y, z)         // acq_rel
n00b_atomic_or(x, y)             // acq_rel
n00b_atomic_read_then_set(x, y)  // exchange
n00b_atomic_fence()              // acq_rel barrier
```

### Futex &mdash; `core/futex.h`

Cross-platform fast userspace mutex:

```c
void n00b_futex_init(n00b_futex_t *futex);
int  n00b_futex_wait(n00b_futex_t *futex, uint32_t expected, uint64_t nsec);
int  n00b_futex_wake(n00b_futex_t *futex, bool all);
void n00b_futex_wait_for_value(volatile n00b_futex_t *futex, uint32_t value);
void n00b_futex_wait_on_mask(n00b_futex_t *futex, uint32_t mask);
```

Linux uses `SYS_futex`; macOS uses `__ulock_wait2()` / `__ulock_wake()`.

---

## Memory allocation

For allocator choice and lifetime guidance, see
[`docs/allocation.md`](allocation.md).

### Public API &mdash; `core/alloc.h`

Always use these macros &mdash; never call `_n00b_alloc_raw()` directly:

```c
n00b_alloc(T, ...)                  // Single object of type T
n00b_alloc_array(T, N, ...)         // Array of N elements
n00b_alloc_flex(T1, T2, N, ...)     // Struct T1 + trailing array of N T2
n00b_alloc_size(n, sz, ...)         // Raw byte allocation (when no type available)

n00b_free(ptr)                      // Deallocation
```

All allocation macros accept keyword arguments:

| Keyword | Default | Purpose |
|---------|---------|---------|
| `.allocator` | `nullptr` | Use specific allocator (nullptr = runtime default) |
| `.no_scan` | `false` | Don't scan this allocation for GC pointers |
| `.finalizer` | `nullptr` | Finalizer callback registered at alloc time |
| `.finalizer_data` | `nullptr` | Opaque pointer passed to the finalizer |
| `.mem_debug` | `false` | Enable memory debug tracking |
| `.debug_taint` | `false` | Enable taint tracking |

Every allocation embeds `__FILE__:__LINE__` via `N00B_LOC_STRING()`.
Typed allocations also pass `typehash(T *)` to the allocator. When ncc emits a
matching GC type map and the executable has been processed with
[`n00b-gcmap-index`](gc_type_maps.md), default-scanned allocations are upgraded
to exact callback scans automatically.

**Example:**

```c
// Allocate a single struct:
my_struct_t *s = n00b_alloc(my_struct_t);

// Allocate an array of 100 ints:
int *arr = n00b_alloc_array(int, 100);

// Allocate with a specific allocator:
char *buf = n00b_alloc_array(char, 4096, .allocator = my_arena);

// Flexible array member:
my_flex_t *f = n00b_alloc_flex(my_flex_t, int, 50);

// Allocate with a finalizer:
resource_t *r = n00b_alloc(resource_t,
                           .finalizer      = my_cleanup,
                           .finalizer_data = extra_info);
```

### Thread-local scoped allocator fallback

`n00b_with_allocator(allocator) { ... }` installs a thread-local
allocator fallback for the current block.  `n00b_ensure_allocator()`
resolves allocators in this order:

1. Explicit `.allocator` kwargs.
2. The current thread's scoped allocator.
3. The runtime default allocator.

Use this for bounded scratch work where all objects allocated in the
scope are temporary:

```c
n00b_with_allocator((n00b_allocator_t *)scratch_arena) {
    n00b_string_t *tmp = n00b_cformat("decoded [|#|]", field_name);
    // Use tmp only inside the scope, or make sure scratch_arena outlives it.
}
```

The override is thread-local: n00b worker threads and the main thread
have independent current allocators.  Restore the previous allocator
before resetting or destroying a scratch arena/pool.  Objects allocated
from the scoped allocator must not escape the block unless that
allocator outlives every escaped object.

GC visibility still follows the allocator's normal mmap and scan
metadata.  A scoped allocator pointer to an arena header does not by
itself make the collector descend into the whole arena, but any pointer
to a visible scratch allocation found in scanned roots, thread stacks, or
thread records can cause that scratch allocation to be scanned.  Pointers
stored inside it can therefore keep other GC objects live until the
scratch references are gone or the scratch allocator is reset/destroyed.
Use hidden/no-scan allocator settings only when the caller also accounts
for the resulting tracing and pointer-rewrite behavior.

### Allocator interface &mdash; `core/alloc_base.h`

```c
typedef struct n00b_allocator_t {
    n00b_calloc_fn          zero_alloc;      // (self, size, params) -> void*
    n00b_free_fn            free;
    n00b_allocator_destroy_fn destroy;
    const char             *debug_name;
    uint8_t                 add_inline_header : 1;
    uint8_t                 __system : 1;    // Skip STW checks
    uint8_t                 __md_pool : 1;   // Is metadata pool
    uint8_t                 hidden : 1;      // Not in mmap tree
    n00b_allocator_t       *metadata_pool;
    n00b_dict_untyped_t    *metadata;
    void                   *opaque[];        // Allocator-specific data
} n00b_allocator_t;
```

### Allocation metadata &mdash; `core/alloc_mdata.h`

Each allocation carries metadata for GC scanning:

| Field | Purpose |
|-------|---------|
| `guard` | Magic value (`n00b_gc_guard`) for validation |
| `tinfo` | Type information string |
| `alloc_len` | Allocation size |
| `ptr_words` | Pointer count for GC scanning |
| `no_scan` | Skip this allocation during GC |
| `moved` | Set during GC relocation |

Metadata can be stored inline (prepended to data) or out-of-band
(in a separate metadata pool), depending on the allocator.

### Arena allocator &mdash; `core/arena.h`

Bump-pointer allocator with linked-list segment management:

```c
typedef struct n00b_arena_t {
    n00b_base_allocator_t   vtable;
    _Atomic(char *)         next_alloc;         // Bump pointer
    _Atomic(n00b_segment_t *) current_segment;
    uint32_t                collection_enabled : 1;
    // ...
} n00b_arena_t;
```

Allocation is a simple `next_alloc += size`.  When the current segment
is exhausted, a new segment is linked in &mdash; or, if
`collection_enabled`, a GC cycle is triggered.

### Pool allocator &mdash; `core/pool.h`

Fixed-size slab allocator with lock-free free lists (Treiber stacks):

```c
typedef struct n00b_pool_t {
    n00b_base_allocator_t vtable;
    n00b_llstack_t        free_lists[4];    // 4 size classes (power-of-2)
    n00b_pool_page_t     *page_table;
    _Atomic uint32_t      lock;
} n00b_pool_t;
```

Used internally for metadata pools, GC root lists, and other
system-level allocations that must not participate in GC.

### Memory mapping registry &mdash; `core/mmaps.h`

Global interval-tree tracking all mapped memory regions:

```c
n00b_mmap_info_t *n00b_mmap_register(n00b_mmap_ctx_t *ctx, uint64_t start,
                                       uint64_t end, n00b_mmap_rec_kind_t kind, +);

void n00b_mmap_unregister(n00b_mmap_ctx_t *ctx, n00b_mmap_info_t *info);

n00b_mmap_info_t *n00b_mmap_by_address(n00b_mmap_ctx_t *ctx, void *addr);

n00b_allocator_t *n00b_mem_get_allocator(void *ptr);
```

Region kinds:

| Kind | Purpose |
|------|---------|
| `n00b_mmap_static` | Static data segments |
| `n00b_mmap_arena` | Arena allocation regions |
| `n00b_mmap_managed_segment` | GC-managed arena segments |
| `n00b_mmap_sys_segment` | System allocator segments |
| `n00b_mmap_stack` | Thread stacks |
| `n00b_mmap_pool` | Pool allocator pages |

---

## Garbage collection &mdash; `core/gc.h`

Copying/compacting collector for arena allocators:

```c
void n00b_collect(n00b_arena_t *arena);

#define n00b_gc_register_root(var) \
    _n00b_gc_register_root(&(var), sizeof(var) / sizeof(void *))

void _n00b_gc_unregister_root(void *addr);
```

### Collection algorithm

1. **Setup** &mdash; allocate a to-space arena (at least the size of
   the from-space; doubled if many segments exist).
2. **Root scanning** &mdash; scan registered roots, thread stacks, and
   argv/envp for pointers into the from-space.
3. **Worklist** &mdash; copy marked allocations to the to-space, update
   all pointer fields.  A memo table (old&rarr;new) prevents
   double-copying.
4. **Swap** &mdash; replace the from-space segments with to-space.
5. **Finalizers** &mdash; process the global finalizer list; run
   callbacks for objects not found in the memo table (i.e., dead).
6. **Cleanup** &mdash; unmap old segments.

### Root sources

1. User-registered roots (`n00b_gc_register_root()`)
2. All registered thread stacks
3. `n00b_runtime_t::argv` and `envp`

Exact stack maps and descriptor-backed static objects are documented in
[`docs/gc_stack_maps.md`](gc_stack_maps.md). The default runtime path remains
conservative unless a thread opts into an exact stack policy.

### Finalizers

Objects that hold external resources (locks, file descriptors, etc.)
register finalizers that run when the object is collected or freed:

```c
// Post-allocation registration:
n00b_add_finalizer(obj, my_cleanup_fn, user_data);

// At allocation time (avoids a lookup):
my_type_t *obj = n00b_alloc(my_type_t,
                            .finalizer      = my_cleanup_fn,
                            .finalizer_data = user_data);
```

`n00b_free()` calls `n00b_run_and_remove_finalizers()` before
deallocation.  The GC calls `n00b_process_finalizers()` during
collection for objects that did not survive.

Finalizer info is stored in `n00b_runtime_t::finalizers`, a list
backed by the system pool (not GC-managed).

---

## Stop-the-world &mdash; `core/stw.h`

Thread suspension for safe GC:

```c
#define n00b_stop_the_world()    _n00b_stop_the_world(N00B_LOC_STRING())
#define n00b_restart_the_world() _n00b_restart_the_world(N00B_LOC_STRING())

void n00b_thread_checkin(void);
```

How it works:
1. Caller acquires STW lock (CAS on `runtime->stw`).
2. Sets the STW flag in each thread's futex.
3. Each thread calls `n00b_thread_checkin()` at safe points; if the STW
   flag is set, the thread blocks.
4. Once all threads are suspended, GC runs.
5. Caller resets futexes; threads wake and check in.

### Blocking operations

```c
n00b_run_blocking(...) {
    // Saves stack state via setjmp
    // Suspends thread (safe for GC to scan stack)
    // Runs blocking operation
    // Resumes thread
}
```

This macro wraps blocking system calls so the thread is marked as
suspended (GC-safe) while blocked.

---

## Synchronization

### Lock infrastructure &mdash; `core/lock_common.h`

All lock types (mutex, rwlock, condition variable) share a common base
via the `N00B_COMMON_LOCK_BASE` macro:

```c
struct n00b_lock_base_t {
    _Atomic(n00b_lock_base_t *) next_thread_lock;   // Per-thread chain
    _Atomic(n00b_lock_base_t *) prev_thread_lock;
    char                       *debug_name;
    _Atomic n00b_core_lock_info_t data;              // Owner, nesting, type
    n00b_alloc_info_t            allocation;
    n00b_lock_log_t             *logs;               // Debug log
    char                        *creation_loc;
    uint32_t                     inited : 1;
    uint32_t                     no_log : 1;
};
```

Every lock operation records source location (`N00B_LOC_STRING()`) for
crash debugging.  The per-thread lock chain (threaded through
`n00b_thread_record_t::exclusive_locks`) allows inspecting held locks
on crash or thread-exit cleanup:

```c
n00b_debug_thread_locks(thread, stderr);   // Dump one thread's locks
n00b_debug_all_locks("lockdump.txt");      // Dump all threads' locks
```

### Mutex &mdash; `core/mutex.h`

Futex-based mutex with spin-then-block, recursive locking, and lock
accounting:

```c
n00b_mutex_t lock;
n00b_mutex_init(&lock);

n00b_mutex_lock(&lock);    // Blocks if contended
n00b_mutex_unlock(&lock);  // Returns true if fully unlocked

// System mutexes skip lock logging (for internal infrastructure):
n00b_sys_mutex_init(&lock);
```

### Reader-writer lock &mdash; `core/rwlock.h`

Futex-based reader-writer lock supporting multiple concurrent readers,
exclusive writers, reader-to-writer upgrade, and nesting:

```c
n00b_rwlock_t rw;
n00b_rw_init(&rw);

n00b_rw_read_lock(&rw);     // Shared access
// ... read data ...
n00b_rw_unlock(&rw);

n00b_rw_write_lock(&rw);    // Exclusive access
// ... modify data ...
n00b_rw_unlock(&rw);
```

### Condition variable &mdash; `core/condition.h`

Enhanced condition variable with built-in mutex, epoch-based
synchronization, selective wake via predicates, and value passing from
notifier to waiters:

```c
n00b_condition_t cv;
n00b_condition_init(&cv);

// Waiter:
n00b_condition_lock(&cv);
void *result = n00b_condition_wait(&cv, .timeout = 5000000000);  // 5s
n00b_condition_unlock(&cv);

// Notifier:
n00b_condition_lock(&cv);
n00b_condition_notify(&cv, .value = my_data, .all = true);
n00b_condition_unlock(&cv);
```

**Selective wake** &mdash; waiters specify a predicate value; the
notifier sets a predicate and only matching waiters are woken:

```c
// Waiter: only wake for predicate 42
void *r = n00b_condition_wait(&cv, .predicate = 42);

// Notifier: wake waiters matching predicate 42
n00b_condition_notify(&cv, .predicate = 42, .value = payload);
```

A custom predicate callback can be installed for complex matching:

```c
n00b_condition_set_callback(&cv, my_predicate_fn, cv_param);
```

**Epoch handshake** ensures the notify operation is atomic from the
caller's perspective: notifier wakes waiters, all waiters process
their predicates, then a two-phase epoch bump ensures consistent
completion before anyone proceeds.

**Keyword arguments for `n00b_condition_wait`:**

| Keyword | Default | Purpose |
|---------|---------|---------|
| `.predicate` | `~0LL` (match any) | Predicate value to match |
| `.timeout` | `0` (forever) | Timeout in nanoseconds |
| `.auto_unlock` | `false` | Unlock CV after waking |
| `.wake_param` | `nullptr` | Per-thread parameter for predicate callback |

**Keyword arguments for `n00b_condition_notify`:**

| Keyword | Default | Purpose |
|---------|---------|---------|
| `.predicate` | `0` | Predicate value for selective wake |
| `.max` | `1` | Maximum waiters to wake |
| `.value` | `nullptr` | Output value passed to woken waiters |
| `.all` | `false` | Wake all matching waiters |
| `.auto_unlock` | `false` | Unlock CV after notify completes |

Convenience macros:

```c
n00b_condition_notify_one(cv)    // Wake one waiter
n00b_condition_notify_all(cv)    // Wake all waiters
```

### Data-structure locking &mdash; `core/data_lock.h`

Every mutable container stores an `n00b_rwlock_t *lock` field.  The
data-lock helpers provide null-safe wrappers &mdash; when the lock
pointer is non-null they acquire/release the rwlock; when null (for
private or single-threaded use) they are no-ops:

```c
n00b_rwlock_t *lock = n00b_data_lock_new();  // nullptr during early init

n00b_data_read_lock(lock);     // Shared access (no-op if lock is null)
// ... read data ...
n00b_data_unlock(lock);

n00b_data_write_lock(lock);    // Exclusive access (no-op if lock is null)
// ... modify data ...
n00b_data_unlock(lock);
```

Default container constructors (`n00b_list_new`, `n00b_stack_new`) call
`n00b_data_lock_new()` automatically.  Pass `false` as the locked
parameter (e.g. `n00b_list_new(int, false)`) to create an unlocked
container for single-threaded use.  Deprecated `_new_private` compat
macros are still available.

`n00b_finalize_data_lock()` is the finalizer callback that frees
data-structure rwlocks when their owner is collected.

---

## Type system

### Type registry &mdash; `core/type_info.h`

The type registry maps `typehash(T)` (a compile-time 64-bit hash of
the normalized type) to `n00b_type_info_t` metadata.  It is
initialized during `n00b_init()` and stored on the runtime.

```c
typedef struct n00b_type_info_t {
    n00b_string_t           *name;
    n00b_vtable_entry        core_vtable[N00B_BI_NUM_FUNCS];
    n00b_ext_vtable_opt_t    ext_vtable;      // option: extension methods
    uint32_t                 alloc_len;
    n00b_option_t(uint32_t)  lock_offset;     // byte offset of rwlock field
    n00b_literal_kind_t      literal_kind;
    n00b_string_t           *literal_modifier;
} n00b_type_info_t;
```

**Registry API:**

```c
// Register a type:
bool n00b_type_register(uint64_t type_hash, const n00b_type_info_t *info);

// Look up by typehash:
n00b_option_t(n00b_type_info_t *) n00b_type_lookup(uint64_t type_hash);

// Look up by object pointer (reads typehash from allocation header):
n00b_option_t(n00b_type_info_t *) n00b_type_info_for(void *obj);

// Add an extension method to a registered type:
bool n00b_type_add_method(uint64_t type_hash, const n00b_method_t *method);
```

Both lookup functions return `n00b_option_t` &mdash; absent means the
type is not registered:

```c
auto info_opt = n00b_type_lookup(typehash(my_type_t));

if (n00b_option_is_set(info_opt)) {
    n00b_type_info_t *info = n00b_option_get(info_opt);
    printf("Type: %s, size: %u\n", info->name, info->alloc_len);
}
```

**Registration macros** simplify declaring built-in types:

```c
N00B_TYPE_REGISTER(my_type_t,
    N00B_CORE_METHOD(N00B_BI_CONSTRUCTOR, my_ctor),
    N00B_CORE_METHOD(N00B_BI_FINALIZER,   my_dtor),
    N00B_LOCK_FIELD(my_type_t, lock),          // auto-finalize rwlock
);
```

`N00B_LOCK_FIELD` sets `lock_offset` so the central finalizer can free
the type's rwlock without per-object finalizer registration.

### Vtable &mdash; `core/vtable.h`

Defines the core vtable slot enumeration and extension method types.

**Core vtable** &mdash; a fixed-size array of bare function pointers
indexed by `n00b_builtin_type_fn`:

| Slot | Purpose |
|------|---------|
| `N00B_BI_CONSTRUCTOR` | Object constructor |
| `N00B_BI_FINALIZER` | Object finalizer |
| `N00B_BI_TO_STRING` | Convert to string |
| `N00B_BI_FORMAT` | Format for display |
| `N00B_BI_COPY` / `N00B_BI_SHALLOW_COPY` | Deep/shallow copy |
| `N00B_BI_EQ` / `N00B_BI_LT` / `N00B_BI_GT` | Comparison |
| `N00B_BI_ADD` / `N00B_BI_SUB` / `N00B_BI_MUL` / `N00B_BI_DIV` / `N00B_BI_MOD` | Arithmetic |
| `N00B_BI_LEN` | Length |
| `N00B_BI_INDEX_GET` / `N00B_BI_INDEX_SET` | Indexing |
| `N00B_BI_SLICE_GET` / `N00B_BI_SLICE_SET` | Slicing |
| `N00B_BI_HASH` | Hashing |
| `N00B_BI_RENDER` | Render to canvas |
| `N00B_BI_GC_MAP` | GC pointer map |

**Extension vtable** &mdash; an optional array of `n00b_method_t`,
where each method carries full signature metadata:

```c
typedef struct n00b_method_t {
    n00b_vtable_entry                  fn;          // Function pointer
    const char                        *name;        // Method name
    n00b_method_param_t                return_type; // Return type info
    n00b_array_t(n00b_method_param_t)  params;      // Parameter type info
} n00b_method_t;
```

To look up a core vtable entry for a managed object:

```c
n00b_vtable_entry fn = n00b_obj_core_method(obj, N00B_BI_TO_STRING);
if (fn) {
    // Call the to_string method
}
```

---

## Thread management &mdash; `core/thread.h`

### Per-thread state

```c
struct n00b_thread_t {
    union {
        struct { int32_t id; int32_t generation; } parts;
        uint64_t unique_id;
    } id_info;

    void                 *stack_base;
    void                 *stack_top;
    n00b_mmap_info_t     *stack_map;
    pthread_t             pthread_id;
    n00b_futex_t          self_lock;
    n00b_futex_t          cv_wake;          // Per-thread futex for CV notification
    n00b_thread_record_t *record;           // Pointer into rt->threads[slot]
    n00b_option_t(pthread_attr_t) pthread_attrs;
};

extern thread_local n00b_thread_t __n00b_thread_self;
```

The `n00b_thread_record_t` (in `rt->threads[]`) holds state visible
to other threads: lock chains, condition-variable wait info, and
generation counters for slot reuse.

### Thread-local access

```c
n00b_thread_t *n00b_thread_self(void);
int64_t        n00b_thread_unique_id(void);   // (slot << 32) | generation
int32_t        n00b_thread_id(void);           // Slot index
int32_t        n00b_thread_generation(void);   // Generation counter
```

### Spawning threads

`n00b_thread_spawn` returns `n00b_result_t` &mdash; the spawned
thread on success, or an error code on failure:

```c
n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(my_fn, my_arg);

if (n00b_result_is_ok(r)) {
    n00b_thread_t *thread = n00b_result_get(r);
    void *retval = n00b_thread_join(thread);
}

// Or with the ! operator for automatic error propagation:
n00b_thread_t *thread = n00b_thread_spawn(my_fn, my_arg)!;
```

Possible error codes: `ENXIO` (runtime not initialized), `ENOMEM`
(no thread slot available), or the `pthread_create` failure code.

Spawned threads automatically participate in GC stop-the-world,
register their stacks for scanning, and clean up locks on exit.

### Stack tracking

```c
void n00b_capture_stack_base(n00b_thread_t *thread, n00b_runtime_t *rt);
void n00b_capture_stack_top(n00b_thread_t *thread);
```

Stack base is captured once at thread registration.  Stack top is
updated at GC safe points to bound the region the collector must scan.

---

## Generic containers

All containers follow the same pattern:

```c
n00b_<container>_decl(T);                // Declare the struct type
n00b_<container>_t(T) x = n00b_<container>_new(T);  // Instantiate
n00b_<container>_<op>(x, ...);           // Use
n00b_<container>_free(x);                // Free
```

Type safety is enforced by `typeid()` &mdash; each unique type
combination gets its own struct definition.

### List &mdash; `core/list.h`

Growable dynamic array with reader-writer lock:

```c
n00b_list_t(T)   x  = n00b_list_new(T);
n00b_list_t(T)   x  = n00b_list_new_cap(T, 64);

n00b_list_push(x, val);
T val = n00b_list_pop(x);
n00b_list_push_front(x, val);
T val = n00b_list_pop_front(x);

n00b_list_insert(x, i, val);
n00b_list_delete(x, i);
T val = n00b_list_get(x, i);          // Bounds-checked
n00b_list_set(x, i, val);             // Bounds-checked

n00b_list_find(x, val);               // Linear search, returns index
n00b_list_sort(x, cmp);               // qsort
n00b_list_remove_all(x, val);
n00b_list_clear(x);

n00b_list_foreach(x, var) { ... }     // Lock-aware iteration (no-op when unlocked)

n00b_array_t(T) a = n00b_list_to_array(T, x);  // Move to fixed array
```

All mutating operations acquire the write lock; reads acquire the
read lock.  `foreach` is explicitly unlocked &mdash; the caller must
ensure exclusive access.

**Example:**

```c
n00b_list_decl(int);
n00b_list_t(int) nums = n00b_list_new(int);

n00b_list_push(nums, 42);
n00b_list_push(nums, 17);
n00b_list_push(nums, 99);

n00b_list_sort(nums, int_cmp);

n00b_list_foreach(nums, n) {
    printf("%d\n", n);
}

n00b_list_free(nums);
```

### Stack &mdash; `core/stack.h`

LIFO stack (same backing as list):

```c
n00b_stack_t(T) s = n00b_stack_new(T);

n00b_stack_push(s, val);
T val = n00b_stack_pop(s);
T val = n00b_stack_peek(s);
bool empty = n00b_stack_is_empty(s);
n00b_stack_clear(s);
n00b_stack_foreach(s, var) { ... }
```

### Array &mdash; `core/array.h`

Fixed-capacity, no lock by default (pass `true` as third arg to
`n00b_array_new` for thread-safe access):

```c
n00b_array_t(T) a = n00b_array_new(T, 100);

T val = n00b_array_get(a, i);
n00b_array_set(a, i, val);         // Extends len if i >= len
n00b_array_t(T) b = n00b_array_clone(a);
n00b_array_foreach(a, var) { ... }
```

### Linked list &mdash; `core/llist.h`

Intrusive doubly-linked list (not thread-safe):

```c
n00b_linked_list_decl(T);

n00b_linked_list_append(lptr, item);
T first = n00b_linked_list_first(lptr);
node = n00b_linked_list_next(nptr);
T val = n00b_linked_list_node_contents(nptr);
```

### Lock-free stack &mdash; `core/llstack.h`

Treiber stack with ABA protection (used internally for pool free lists):

```c
n00b_llstack_push_node(n00b_llstack_t *llstack, n00b_llstack_node_t *item);
void *n00b_llstack_pop_node(n00b_llstack_t *llstack);
```

### Dictionary &mdash; `core/dict.h`, `core/dict_untyped.h`

Open-addressing hash table with robin-hood probing.  Lock-free reads,
single-writer migration:

```c
n00b_dict_untyped_t *d = n00b_dict_untyped_new(hash_fn, allocator);

void *old = _n00b_dict_untyped_put(d, key, value);
void *val = _n00b_dict_untyped_get(d, key, &found);
bool ok   = _n00b_dict_untyped_replace(d, key, value);
bool ok   = _n00b_dict_untyped_add(d, key, value);  // Fails if exists
bool ok   = _n00b_dict_untyped_remove(d, key);
```

The hash table auto-resizes when load exceeds a threshold.  During
migration, readers see a consistent snapshot; a futex gates concurrent
writers.

### Tree &mdash; `core/tree.h`

N-ary tree with typed nodes and leaves:

```c
n00b_tree_decl(NodeType, LeafType);

auto node  = n00b_tree_node(N, L, value);
auto leaf  = n00b_tree_leaf(N, L, value);
n00b_tree_add_child(parent, N, L, child);
```

### Interval tree &mdash; `core/interval_tree.h`

AVL-balanced interval tree (used for the mmap registry):

```c
n00b_interval_tree_t *t = n00b_new_interval_tree(allocator);

n00b_result_t(n00b_interval_node_t *)
n00b_interval_insert(t, low, high, data);

n00b_result_t(int)
n00b_interval_delete(t, target);
```

---

## Algebraic data types

### Option &mdash; `core/option.h`

Represents a value that may or may not be present (absence is not an
error):

```c
n00b_option_t(T)  opt = n00b_option_set(T, value);     // Some(value)
n00b_option_t(T)  opt = n00b_option_none(T);            // None

bool has = n00b_option_is_set(opt);
T    val = n00b_option_get(opt);                         // Crashes if none
T    val = n00b_option_get_or_else(opt, fallback);

n00b_option_match(opt, set_expr, none_expr);

n00b_option_t(T)  opt = n00b_option_from_nullable(T, ptr);  // nullptr → none
```

Each unique `T` requires a prior `n00b_option_decl(T)`.  Common
declarations (primitives, `void *`, `const char *`, and
forward-declared core types) are centralized in `option.h`.

**Example:**

```c
n00b_option_t(n00b_type_info_t *) info_opt = n00b_type_lookup(typehash(my_t));

if (n00b_option_is_set(info_opt)) {
    n00b_type_info_t *info = n00b_option_get(info_opt);
    printf("Found type: %s\n", info->name);
}
else {
    printf("Type not registered\n");
}
```

### Result &mdash; `adt/result.h`

Represents a value on success or an error carrier on failure. Use integer
code errors (`n00b_err_t`, an `int` typically holding `errno`) for simple
failures, and structured payload errors when callers need typed diagnostic
context:

```c
n00b_result_t(T)  r = n00b_result_ok(T, value);
n00b_result_t(T)  r = n00b_result_err(T, errno_val);
n00b_result_t(T)  r = n00b_result_err_payload(T, my_error_t *, error_ptr);

bool ok  = n00b_result_is_ok(r);
bool err = n00b_result_is_err(r);
T    val = n00b_result_get(r);                // Crashes if err
int  e   = n00b_result_get_err(r);            // Integer errors only
T    val = n00b_result_get_or_else(r, fallback);

n00b_result_error_t carrier = n00b_result_get_error(r);
bool has_payload = n00b_result_is_err_payload(my_error_t *, r);
my_error_t *p    = n00b_result_get_err_payload(my_error_t *, r);

n00b_result_match(r, ok_expr, err_expr);
```

Structured payload helpers carry pointer payloads tagged with `typehash(E)`.
`n00b_result_get_error(r)` returns the raw carrier and asserts if `r` is ok.
`n00b_result_get_err_payload(E, r)` asserts if `r` is ok, is not a payload
error, or the stored tag does not match `typehash(E)`. `n00b_result_get_err(r)`
is for integer-code errors only and asserts on structured payload errors.

#### Error propagation (`!`)

ncc's postfix `!` operator works like Rust's `?` &mdash; it unwraps a
result on success or returns early with the error carrier:

```c
n00b_result_t(my_output_t)
process_data(const char *path)
{
    // If thread_spawn fails, this function returns its error immediately.
    n00b_thread_t *t = n00b_thread_spawn(worker_fn, work)!;

    // Only reached on success.
    return n00b_result_ok(my_output_t, do_work(t));
}
```

The `!` operator requires the enclosing function to also return a
`n00b_result_t`. It propagates the result error carrier unchanged, so both
integer-code errors and structured payload errors can cross result ok types
without caller-side conversion. It only works with `n00b_result_t`, not
`n00b_option_t`.

#### POSIX wrappers

```c
n00b_result_t(int)   r = n00b_check_posix(open("/tmp/f", O_RDONLY));
n00b_result_t(void*) r = n00b_check_mmap(mmap(...));
n00b_result_t(long)  r = n00b_check_sysconf(_SC_PAGESIZE);
```

#### When to use option vs result

| Situation | Type |
|-----------|------|
| Value might be absent (lookup miss, not found) | `n00b_option_t(T)` |
| Operation can fail (I/O error, invalid input) | `n00b_result_t(T)` |
| Feature might not be available on this platform | `n00b_result_t` with `ENOTSUP` |
| Bare pointer that is always valid (borrow/ownership) | `T *` |

### Variant &mdash; `core/variant.h`

Tagged union with compile-time type checking.  The selector uses
`typehash(T)` for O(1) integer comparison:

```c
n00b_variant_decl(int, double, char *);

n00b_variant_t(int, double, char *) v = n00b_variant_set(
    n00b_variant_t(int, double, char *), int, 42);

bool is_int  = n00b_variant_is_type(v, int);
int  val     = n00b_variant_get(v, int);          // Asserts correct type
int  val_alt = n00b_variant_get_or_else(v, int, 0);

bool any_set = n00b_variant_is_set(v);            // selector != 0
```

### Tuple &mdash; `core/tuple.h`

Fixed-size heterogeneous record:

```c
n00b_tuple_decl(int, double, char *);

auto t = n00b_tuple(42, 3.14, "hello");

int    a = n00b_tuple_get(t, 0);   // 42
double b = n00b_tuple_get(t, 1);   // 3.14
char  *c = n00b_tuple_get(t, 2);   // "hello"
```

Field access via `constexpr_paste()` generates `item_0`, `item_1`, etc.

---

## String and buffer

### String &mdash; `core/string.h`

Immutable UTF-8 string (by-value struct):

```c
typedef struct n00b_string_t {
    int64_t  u8_bytes;     // UTF-8 byte count
    char    *data;         // UTF-8 data (not NUL-terminated in general)
    int64_t  codepoints;   // Codepoint count
    void    *styling;      // Rich text metadata (opaque)
} n00b_string_t;

n00b_string_t n00b_string_from_raw(n00b_allocator_t *alloc,
                                     const char *src, int64_t byte_len,
                                     int64_t cp_count);
n00b_string_t n00b_string_empty(n00b_allocator_t *alloc);
```

See [docs/strings.md](strings.md) for the full string operations library.

### Buffer &mdash; `core/buffer.h`

Mutable growable byte buffer with reader-writer lock:

```c
n00b_buffer_t *n00b_buffer_empty(void);
n00b_buffer_t *n00b_buffer_from_bytes(const char *data, int64_t len);
void           n00b_buffer_free(n00b_buffer_t *buf);
```

Key operations include hex encode/decode, searching, slicing, and
conversion to `n00b_string_t`.

---

## Hashing &mdash; `core/hash.h`

128-bit hashing via XXH3:

```c
n00b_uint128_t n00b_hash_word(void *value);
n00b_uint128_t n00b_hash_cstring(void *value);
n00b_uint128_t n00b_hash(void *obj, n00b_hash_fn fn);
n00b_uint128_t n00b_string_hash(n00b_string_t s);
n00b_uint128_t n00b_buffer_hash(n00b_buffer_t *b);
```

All hash functions return `n00b_uint128_t` for collision resistance.

---

## Layout solver &mdash; `core/layout.h`

1D constraint-based layout engine used by the table library:

```c
typedef struct {
    n00b_layout_dim_t min, max, pref;
    int64_t priority;
    int64_t flex_multiple;
    int64_t child_gap;
} n00b_layout_t;

typedef struct {
    int64_t computed_min, computed_max, computed_pref;
    int64_t size;                    // Output: final computed size
} n00b_layout_result_t;

void n00b_layout_calculate(n00b_layout_t *items,
                            n00b_layout_result_t *results,
                            size_t count, int64_t available);
```

`n00b_layout_dim_t` supports both absolute (`int64_t`) and percentage
(`double`) dimensions.

### Algorithm

1. Resolve percentage dimensions against available space.
2. Assign each item its minimum (or preferred if larger).
3. Grow items toward their maximum, smallest-first.
4. Distribute remaining space proportionally by `flex_multiple`.
5. If over-constrained: shrink flex items first (largest-first), then
   rigid items.
6. If still over: force-crop by ascending priority (lowest dropped
   first).

---

## Variadic support &mdash; `core/vargs.h`

ncc's `+` variadic transform packs arguments into:

```c
typedef struct n00b_vargs_t {
    unsigned int nargs;
    unsigned int cur_ix;
    void       **args;
} n00b_vargs_t;
```

At call sites, ncc rewrites `f(a, b, c)` to pass a compound literal:
`f(&(n00b_vargs_t){.nargs=3, .cur_ix=0, .args=(void*[]){a, b, c}})`.

See the [ncc documentation](ncc.md) for details on the `+` extension.

---

## Runtime initialization &mdash; `core/runtime.h`

```c
struct n00b_runtime_t {
    n00b_array_t(char *)                argv, envp;
    n00b_mmap_ctx_t                     mmaps;
    _Atomic uint32_t                    next_thread_slot;
    _Atomic uint32_t                    live_threads;
    _Atomic bool                        startup_complete;
    _Atomic(n00b_allocator_t *)         default_allocator;
    n00b_arena_t                       *default_arena;
    n00b_pool_t                         system_pool;
    n00b_list_t(n00b_gc_root_t)         gc_roots;
    n00b_list_t(n00b_finalizer_info_t *) finalizers;
    n00b_dict_untyped_t                *type_registry;
    n00b_thread_record_t                threads[N00B_THREADS_MAX];
    n00b_base_allocator_t               slab_allocator;
    n00b_futex_t                        stw;
    uint32_t                            stw_nesting;
};
```

```c
void n00b_init(n00b_runtime_t *rt, int argc, char *argv[], ...);
```

**Keyword arguments:**

| Keyword | Default | Purpose |
|---------|---------|---------|
| `.allocator` | `nullptr` | Allocator (nullptr = GC'd arena) |
| `.envp` | `nullptr` | Environment pointer (nullptr = inherit) |
| `.numeric_locale` | `""` | Numeric locale string |
| `.fd_limit` | `0` | File descriptor limit (0 = don't change) |
| `.max_threads` | `N00B_THREADS_MAX` | Maximum thread count |

```c
n00b_allocator_t *n00b_default_allocator(void);
n00b_allocator_t *n00b_slab_allocator(void);
```

### Initialization steps

1. Cache page size, generate GC guard value.
2. Initialize mmap registry with interval tree.
3. Set up slab allocator (hidden system pool for metadata).
4. Initialize GC root pool and finalizer list.
5. Register main thread (capture stack base).
6. Create default arena (GC-enabled) or use provided allocator.
7. Initialize the type registry and register built-in types.

**Example:**

```c
int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    // Runtime is now live: allocator, GC, threading, type registry all ready.
    // ...

    return 0;
}
```

---

## Utility modules

### Random &mdash; `core/random.h`

```c
void     n00b_random_bytes(char *buf, size_t len);
uint64_t n00b_rand64(void);
uint32_t n00b_rand32(void);
```

Linux uses `getrandom(2)`; macOS/BSD uses `arc4random_buf()`.

### Time &mdash; `core/time.h`

```c
void    n00b_capture_timestamp(n00b_duration_t *output);
int64_t n00b_ns_from_duration(n00b_duration_t *d);
int64_t n00b_ns_minus(n00b_duration_t *d1, n00b_duration_t *d2);
int64_t n00b_ns_timestamp(void);
```

### Alignment &mdash; `core/align.h`

```c
void    *n00b_align_to_page_start(void *addr);
uint64_t n00b_page_align(uint64_t n);
uint64_t n00b_align(uint64_t n);     // Align to N00B_ALIGN (16)
uint64_t n00b_align_floor(uint64_t n, uint64_t base);
uint64_t n00b_align_ceil(uint64_t n, uint64_t base);
```

### Macros &mdash; `core/macros.h`

```c
N00B_LOC_STRING()               // "__FILE__:__LINE__"
N00B_VA_COUNT(...)              // Count variadic arguments
N00B_MAP(macro, ...)            // Apply macro to each argument
N00B_MAP_COUNT(macro, N, ...)   // MAP with counter
N00B_EVAL(...)                  // Deep recursive macro expansion
```

### Memory introspection &mdash; `core/memory_info.h`

```c
size_t n00b_address_is_probable_cstring(void *addr, size_t *bytelen,
                                         size_t min_len);
```

Heuristically detects probable UTF-8 C strings by scanning for valid
UTF-8 sequences with a NUL terminator within the current page.

---

## Cross-cutting patterns

### Generic container pattern

All containers follow this template:

```c
// Declare the type (typically in a header):
n00b_list_decl(int);

// Create an instance:
n00b_list_t(int) nums = n00b_list_new(int);

// Use it:
n00b_list_push(nums, 42);
int val = n00b_list_pop(nums);

// Free it:
n00b_list_free(nums);
```

The `*_decl()` macro expands a struct with a `typeid()`-based tag.
Each unique type combination gets its own struct &mdash; this is how
type safety is enforced without language-level generics.

### Error handling pattern

Functions follow a strict convention based on their failure mode:

```c
// Fallible (can fail with an error code):
n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(fn, arg);
if (n00b_result_is_err(r)) { /* handle error */ }

// Or propagate with !:
n00b_thread_t *t = n00b_thread_spawn(fn, arg)!;

// Optional (value may be absent, not an error):
n00b_option_t(n00b_type_info_t *) info = n00b_type_lookup(hash);
if (n00b_option_is_set(info)) { /* use it */ }

// Infallible (always succeeds, returns bare pointer):
n00b_thread_t *self = n00b_thread_self();
```

### Keyword arguments

Most functions that allocate accept optional keyword arguments:

```c
n00b_alloc(my_struct_t, .allocator = arena, .no_scan = true)
n00b_list_new_cap(int, 256, .allocator = my_alloc)
n00b_init(&rt, argc, argv, .fd_limit = 1024)
n00b_condition_wait(&cv, .timeout = 5000000000, .predicate = 42)
```

### Thread safety summary

| Component | Mechanism |
|-----------|-----------|
| List, stack | Reader-writer lock (auto-created, null-safe) |
| Array | No lock by default (use `_new_locked` variant) |
| Buffer | Reader-writer lock |
| Linked list | No lock |
| Dictionary | Lock-free reads, futex for migration |
| Interval tree | Reader-writer lock |
| Pool free list | Lock-free Treiber stack |
| Arena | Atomic bump pointer, spinlock for segments |
| Mmap registry | TID-based reentrant spinlock |
| GC | Stop-the-world (futex-based) |
| Type registry | Lock-free reads (dict-backed) |

---

## Quick reference

| Task | API |
|------|-----|
| Initialize runtime | `n00b_init(&rt, argc, argv)` |
| Allocate object | `n00b_alloc(T)` |
| Allocate array | `n00b_alloc_array(T, N)` |
| Free allocation | `n00b_free(ptr)` |
| Register finalizer | `n00b_add_finalizer(obj, fn, data)` |
| Register GC root | `n00b_gc_register_root(var)` |
| Trigger collection | `n00b_collect(arena)` |
| Stop the world | `n00b_stop_the_world()` |
| Spawn thread | `n00b_thread_spawn(fn, arg)` |
| Join thread | `n00b_thread_join(thread)` |
| Get thread self | `n00b_thread_self()` |
| Create list | `n00b_list_new(T)` |
| Push to list | `n00b_list_push(list, val)` |
| Create stack | `n00b_stack_new(T)` |
| Create array | `n00b_array_new(T, N)` |
| Create option | `n00b_option_set(T, val)` / `n00b_option_none(T)` |
| Create result | `n00b_result_ok(T, val)` / `n00b_result_err(T, e)` |
| Propagate error | `val = fallible_call()!` |
| POSIX call check | `n00b_check_posix(syscall())` |
| Look up type | `n00b_type_lookup(typehash(T))` |
| Register type | `N00B_TYPE_REGISTER(T, ...)` |
| Lock mutex | `n00b_mutex_lock(&m)` |
| RW read lock | `n00b_rw_read_lock(&rw)` |
| RW write lock | `n00b_rw_write_lock(&rw)` |
| Wait on CV | `n00b_condition_wait(&cv, ...)` |
| Notify CV | `n00b_condition_notify(&cv, ...)` |
| Hash string | `n00b_string_hash(s)` |
| Hash buffer | `n00b_buffer_hash(b)` |
| Layout solve | `n00b_layout_calculate(items, results, n, avail)` |
| Default allocator | `n00b_default_allocator()` |
