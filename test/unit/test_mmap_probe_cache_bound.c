/*
 * test_mmap_probe_cache_bound.c — n00b#213.
 *
 * n00b#213 is "the mmap registry grows unbounded". Every registration in the
 * process has a matching unregister on the path that unmaps the memory --
 * except one. n00b_check_kernel_page_map (memory_info.c) caches the answer to
 * "is something mapped at this address?" by REGISTERING the probed page, and
 * nothing in n00b owns that mapping, so nothing ever takes the record back
 * out. A process that keeps asking about foreign addresses therefore
 * accumulated one permanent single-page record per distinct page, for the life
 * of the process, and every registry search in the process got deeper as they
 * piled up -- including the conservative scan's, which n00b#275 measured as
 * the single heaviest leaf in a wedged collector.
 *
 * The cache is still a cache; it is now bounded. This test probes far more
 * distinct foreign pages than the cap and asserts the registry's unmanaged
 * record count does not grow past it.
 *
 * The pages are mapped with a RAW mmap, deliberately bypassing n00b_mmap, so
 * that they are genuinely absent from the registry and each one drives the
 * probe path exactly as a libc-malloc'd buffer or a mapped file would.
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

/* Enough to wrap the ring several times over, so an off-by-a-lot in the
 * eviction bookkeeping still shows up. */
#define PROBE_PAGES (N00B_MMAP_PROBE_CACHE_ENTRIES * 4)

static int failures = 0;

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("n00b#213: the kernel-probe page cache is bounded\n");

    size_t pg    = (size_t)n00b_page_size;
    size_t bytes = (size_t)PROBE_PAGES * pg;

    /* Raw mmap: NOT registered, so every page below is a registry miss that
     * reaches the probe. */
    char *region = mmap(nullptr,
                        bytes,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON,
                        -1,
                        0);

    if (region == MAP_FAILED) {
        printf("  [SKIP] could not map %zu bytes of scratch\n", bytes);
        return 0;
    }

    n00b_mmap_registry_stats_t before = n00b_mmap_registry_stats();

    uint64_t evictions_before = atomic_load(&n00b_mmap_probe_evictions);

    for (size_t i = 0; i < PROBE_PAGES; i++) {
        char *page = region + i * pg;

        /* Touch it first: the probe only caches pages the kernel reports as
         * resident. */
        *page = (char)i;

        /* n00b_value_is_data is the public shape of this path, and it is what
         * a long-running consumer reaches through formatting and pointer
         * classification. */
        (void)n00b_value_is_data(page);
    }

    n00b_mmap_registry_stats_t after     = n00b_mmap_registry_stats();
    uint64_t                   evictions = atomic_load(&n00b_mmap_probe_evictions);

    uint64_t grew = after.unmanaged_count > before.unmanaged_count
                      ? after.unmanaged_count - before.unmanaged_count
                      : 0;

    printf("  ... probed %d distinct foreign pages\n", PROBE_PAGES);
    printf("  ... unmanaged records: %llu -> %llu (+%llu), cap %d\n",
           (unsigned long long)before.unmanaged_count,
           (unsigned long long)after.unmanaged_count,
           (unsigned long long)grew,
           N00B_MMAP_PROBE_CACHE_ENTRIES);
    printf("  ... probe-cache evictions: %llu\n",
           (unsigned long long)(evictions - evictions_before));

    if (grew > (uint64_t)N00B_MMAP_PROBE_CACHE_ENTRIES) {
        printf("  [FAIL] the registry grew by %llu records for %d probes:"
               " probing still grows the registry without bound\n",
               (unsigned long long)grew,
               PROBE_PAGES);
        failures++;
    }
    else {
        printf("  [PASS] %d probes added at most %d records\n",
               PROBE_PAGES,
               N00B_MMAP_PROBE_CACHE_ENTRIES);
    }

    /* If nothing was ever evicted, the bound was never exercised and the
     * check above proves nothing -- either the probe path was not reached at
     * all, or the pages were already registered. Say so rather than passing
     * quietly. */
    if (evictions == evictions_before) {
        printf("  [FAIL] no probe-cache eviction happened, so the cap was"
               " never reached and this test did not exercise the bound\n");
        failures++;
    }
    else {
        printf("  [PASS] the ring wrapped, so the cap was actually reached\n");
    }

    /* The cache must still ANSWER: a bounded cache that started returning
     * "nothing is mapped here" would pass the count check and be wrong. */
    char *recheck = region + (PROBE_PAGES - 1) * pg;

    if (n00b_value_is_data(recheck)) {
        printf("  [FAIL] a freshly probed, resident, mapped page is reported"
               " as not-a-pointer\n");
        failures++;
    }
    else {
        printf("  [PASS] the bounded cache still answers correctly\n");
    }

    munmap(region, bytes);

    if (failures) {
        printf("\n%d check(s) failed.\n", failures);
        return 1;
    }

    printf("\nn00b#213: probing foreign addresses no longer grows the mmap"
           " registry without bound.\n");
    return 0;
}
