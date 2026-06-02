#define N00B_USE_INTERNAL_API

#include <assert.h>
#include <pthread.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"

// ============================================================================
// Foreign-thread reproducer for the Crayon gateway crash.
//
// A RAW pthread (created with pthread_create, NOT n00b_thread_spawn) calls a
// gc-framed n00b function.  ncc emits a gc-roots prologue that calls
// n00b_gc_stack_push() -> n00b_thread_self().  The worker branch of the
// n00b_thread_self() macro reads the id word at
//
//     (SP & ~(N00B_CALLSTACK_REGION_SIZE-1)) + N00B_CALLSTACK_REGION_SIZE - 8
//
// A foreign pthread's stack is NOT an 8 MiB-aligned n00b callstack region, so
// that address is (usually) unmapped and the read faults -- the documented
// KNOWN LIMITATION in include/core/thread.h.
//
// This is exactly the crash the Crayon raw_gateway hits on libdispatch/XPC
// reply threads (crayon_raw_gateway_fill_es_subscription_bits /
// crayon_raw_gateway_enqueue_payload), which are foreign to n00b.
//
// EXPECTED (post-fix): n00b_thread_self() resolves to nullptr (or a usable
// thread after attach) on a foreign thread, never faults; the gc-framed call
// completes.  PRE-fix: SIGSEGV in the n00b_thread_self() id-word read.
// ============================================================================

static void *
foreign_fn(void *raw)
{
    // An unattached foreign thread brackets no live slot, so n00b_thread_self()
    // must resolve to nullptr WITHOUT faulting (the bounds-scan fix; pre-fix
    // the masked id-word read at base + S - 8 faulted on the foreign stack).
    n00b_thread_t *self = n00b_thread_self();
    assert(self == nullptr);
    printf("  foreign thread_self() = %p (nullptr expected, no fault)\n",
           (void *)self);

    // A gc-framed n00b call still works with a null self: gc_stack_push
    // tolerates the pre-registration window.  (The foreign-thread ATTACH path
    // — n00b_thread_init -> n00b_capture_stack_base's mach_vm stack discovery
    // — is __N00B_THREAD_INTERNAL-gated and is exercised by the gateway, not
    // reachable from a unit test without reaching into thread internals.)
    n00b_string_t *s = n00b_string_from_cstr("hello from a foreign pthread");
    assert(s != nullptr);
    printf("  foreign gc-framed call ok: \"%s\"\n", s->data);

    return raw;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running thread_self_foreign test...\n");

    pthread_t t;
    int       rc = pthread_create(&t, nullptr, foreign_fn, nullptr);
    assert(rc == 0);
    pthread_join(t, nullptr);

    printf("All thread_self_foreign tests passed.\n");
    n00b_shutdown();
    return 0;
}
