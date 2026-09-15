/*
 * test_memperm_probe.c — n00b#399.
 *
 * n00b_check_memory_perms falls back to a kernel probe (write one byte out of
 * the address into a pipe, read it back into the address) when the registry
 * has no record for a page. The probe's verdicts feed the conservative
 * scanner: _find_sentinal stops its backward guard walk on no_access, and a
 * walk that stops early is how a live object's header is missed (n00b#321).
 *
 * n00b#399: the probe used to treat ANY failure as no_access. Only EFAULT is
 * a statement about the address; EINTR, a pipe that could not be created, a
 * poll that never became ready, all describe the probe. Those now come back
 * as perms_unknown ("could not determine") and are counted in
 * n00b_memperm_indeterminate, so they cannot truncate a scan.
 *
 * What can be forced deterministically from a test is the two verdicts the
 * probe must still get right, on pages the registry has never seen (raw
 * mmap, so every call here is a real probe, not a fast-path hit):
 *
 *   readable+writable page  -> rw
 *   PROT_NONE page          -> no_access    (write faults with EFAULT)
 *   unmapped address        -> no_access    (write faults with EFAULT)
 *
 * and that none of those is mistaken for an indeterminate probe. A genuine
 * EINTR cannot be produced on demand without a signal racing the syscall, so
 * the retry path is argued in the source rather than exercised here.
 */

#define N00B_USE_INTERNAL_API
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "n00b.h"
#include "core/memory_info.h"
#include "core/mmaps.h"
#include "core/runtime.h"

static int failures = 0;

static void
expect(const char *what, n00b_mmap_perms_t got, n00b_mmap_perms_t want)
{
    if (got == want) {
        printf("  [PASS] %s -> %d\n", what, (int)got);
    }
    else {
        printf("  [FAIL] %s -> %d, expected %d\n", what, (int)got, (int)want);
        failures++;
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("n00b#399: the memory-perms probe's verdicts\n");

    size_t pg = (size_t)n00b_page_size;

    /* Three raw pages: rw, none, and one we unmap again so the address is
     * genuinely unmapped (and, being freshly released, unlikely to be reused
     * within the microseconds this test takes). None is registered. */
    char *rw = mmap(nullptr, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    char *none = mmap(nullptr, pg, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    char *gone = mmap(nullptr, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (rw == MAP_FAILED || none == MAP_FAILED || gone == MAP_FAILED) {
        printf("  [SKIP] could not map scratch pages\n");
        return 0;
    }
    munmap(gone, pg);

    /* None of these may be in the registry, or the fast path answers and the
     * probe is never reached. */
    assert(!n00b_option_is_set(n00b_mmap_by_address(rw)));
    assert(!n00b_option_is_set(n00b_mmap_by_address(none)));
    assert(!n00b_option_is_set(n00b_mmap_by_address(gone)));

    rw[0] = 0x5a;

    uint64_t indeterminate0 = atomic_load(&n00b_memperm_indeterminate);

    expect("readable, writable page", n00b_check_memory_perms(rw), n00b_mmap_perms_rw);
    expect("PROT_NONE page", n00b_check_memory_perms(none), n00b_mmap_perms_no_access);
    expect("unmapped address", n00b_check_memory_perms(gone), n00b_mmap_perms_no_access);

    /* The probe writes one byte out of the page and reads one back into it;
     * the page's own contents must survive that. */
    if (rw[0] != 0x5a) {
        printf("  [FAIL] the probe altered the byte it probed (0x%02x)\n",
               (unsigned)(unsigned char)rw[0]);
        failures++;
    }
    else {
        printf("  [PASS] the probe leaves the probed byte intact\n");
    }

    /* Repeat many times through the cached per-thread pipe: a stale byte left
     * in the pipe by one probe would corrupt the verdict of the next. */
    for (int i = 0; i < 1000; i++) {
        if (n00b_check_memory_perms(rw) != n00b_mmap_perms_rw
            || n00b_check_memory_perms(none) != n00b_mmap_perms_no_access) {
            printf("  [FAIL] verdict drifted on iteration %d\n", i);
            failures++;
            break;
        }
    }
    if (failures == 0) {
        printf("  [PASS] 1000 alternating probes through the cached pipe agree\n");
    }

    uint64_t indeterminate = atomic_load(&n00b_memperm_indeterminate);
    if (indeterminate != indeterminate0) {
        printf("  [FAIL] %llu probe(s) were reported indeterminate; every one"
               " here had a definite answer\n",
               (unsigned long long)(indeterminate - indeterminate0));
        failures++;
    }
    else {
        printf("  [PASS] no definite probe was reported indeterminate\n");
    }

    munmap(rw, pg);
    munmap(none, pg);

    if (failures) {
        printf("\n%d check(s) failed.\n", failures);
        return 1;
    }
    printf("\nn00b#399: EFAULT is the only failure the probe reads as a verdict.\n");
    return 0;
}
