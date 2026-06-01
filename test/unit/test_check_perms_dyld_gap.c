/*
 * test_check_perms_dyld_gap.c
 *
 * Test the @ref n00b_check_memory_perms API against three classes of
 * addresses:
 *   - KNOWN-mapped (inside a Mach-O segment's file-backed range)
 *   - KNOWN-unmapped past the segment's filesize but within vmsize
 *     (BSS / zero-fill tail; not file-backed; may or may not be
 *     actually mapped depending on dyld's bookkeeping)
 *   - obviously bogus (very high addresses with no mapping at all)
 *
 * If @c n00b_check_memory_perms reports @c perms_ro or @c perms_rw
 * for an address that's not actually mapped, that's the API lying —
 * which is the proximate cause of GC mark SIGBUSes during gateway
 * burst load, because scan_memory_range trusts the verdict and
 * dereferences.
 *
 * The test prints one line per probe; the human eyeballs which
 * addresses report bogus-readable.  Exits 0 unconditionally — it's
 * a diagnostic, not a pass/fail predicate.
 */

#include <stdio.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/alloc.h"
#include "core/memory_info.h"
#include "core/runtime.h"

// This is a macOS/Mach-O-specific diagnostic (it walks Mach-O segments via
// mach_vm); it has no meaning on other OSes, so compile a trivial skipping main
// there.  Exits 0 unconditionally either way.
#ifdef __APPLE__

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static const char *
perms_str(n00b_mmap_perms_t p)
{
    switch (p) {
    case n00b_mmap_perms_unknown:   return "unknown  ";
    case n00b_mmap_perms_no_access: return "no_access";
    case n00b_mmap_perms_ro:        return "ro       ";
    case n00b_mmap_perms_rw:        return "rw       ";
    default:                        return "????     ";
    }
}

static void
probe(const char *label, void *addr, const char *note)
{
    n00b_mmap_perms_t verdict = n00b_check_memory_perms(addr);
    fprintf(stderr,
            "  %-10s  addr=%p  perms=%s  %s\n",
            label,
            addr,
            perms_str(verdict),
            note ? note : "");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    fprintf(stderr,
            "test_check_perms_dyld_gap: probing n00b_check_memory_perms\n"
            "  KEY: a 'past_file' or 'bogus' line that reports ro/rw is\n"
            "       the API lying and will SIGBUS the GC mark in real use\n");

    /* Probe addresses we KNOW are not in any mapping.  Use
     * mach vm_region_recurse to find a confirmed gap between
     * mapped regions and probe inside the gap. */
    probe("bogus_hi",     (void *)0x7777777700000008ULL,
          "near top of VA: must be no_access");
    probe("null",         (void *)NULL,
          "null: must be no_access");
    probe("stack_a",      (void *)&runtime,
          "on stack: must be ro or rw");

    /* Walk vm regions to find a real gap. */
    {
        mach_port_t            task = mach_task_self();
        mach_vm_address_t      addr = 0;
        mach_vm_size_t         size = 0;
        natural_t              depth;
        vm_region_submap_info_data_64_t info;
        int gaps_probed = 0;
        mach_vm_address_t prev_end = 0;
        for (int i = 0; i < 200 && gaps_probed < 3; i++) {
            depth                 = 0;
            mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t          kr  = mach_vm_region_recurse(
                task,
                &addr,
                &size,
                &depth,
                (vm_region_recurse_info_t)&info,
                &cnt);
            if (kr != KERN_SUCCESS) break;
            if (prev_end && addr > prev_end + 0x10000) {
                mach_vm_address_t mid = prev_end + (addr - prev_end) / 2;
                /* Page-align. */
                mid &= ~((mach_vm_address_t)0xfff);
                char label[32];
                snprintf(label, sizeof(label), "vm_gap_%d", gaps_probed);
                fprintf(stderr,
                        "  -- gap between mapped regions [%llx..%llx], probe at %llx --\n",
                        (unsigned long long)prev_end,
                        (unsigned long long)addr,
                        (unsigned long long)mid);
                probe(label, (void *)(uintptr_t)mid,
                      "INSIDE vm_region gap: must be no_access");
                gaps_probed++;
            }
            prev_end = addr + size;
            addr += size;
        }
    }

    fprintf(stderr, "\n  -- dyld images (first 8 with vmsize > filesize) --\n");

    uint32_t total_images = _dyld_image_count();
    int      checked      = 0;

    for (uint32_t img = 0; img < total_images && checked < 8; img++) {
        const struct mach_header *hdr_any = _dyld_get_image_header(img);
        if (!hdr_any || hdr_any->magic != MH_MAGIC_64) continue;
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)hdr_any;
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        const char *name = _dyld_get_image_name(img);

        const struct load_command *cmd =
            (const struct load_command *)((const char *)hdr + sizeof(*hdr));
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)cmd;
                /* Print EVERY segment with any gap, no minimum. */
                uint64_t gap = (seg->vmsize > seg->filesize)
                               ? seg->vmsize - seg->filesize
                               : 0;
                if (seg->filesize > 0) {
                    void *mapped     = (void *)(seg->vmaddr + slide
                                                + seg->filesize / 2);
                    void *past_vmend = (void *)(seg->vmaddr + slide
                                                + seg->vmsize + 0x10000);
                    fprintf(stderr,
                            "image: %s seg=%s vmsize=0x%llx filesize=0x%llx gap=0x%llx\n",
                            name,
                            seg->segname,
                            (unsigned long long)seg->vmsize,
                            (unsigned long long)seg->filesize,
                            (unsigned long long)gap);
                    probe("mapped",     mapped,     "inside filesize");
                    if (gap > 0) {
                        void *in_gap = (void *)(seg->vmaddr + slide
                                                + seg->filesize + gap / 2);
                        probe("in_gap", in_gap, "[filesize, vmsize) -- bss/zerofill");
                    }
                    probe("past_vmend", past_vmend, "past vmsize -- outside segment");
                    checked++;
                    if (checked >= 16) break;
                }
            }
            cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize);
        }
    }

    fprintf(stderr,
            "\ntest_check_perms_dyld_gap: checked %d segments\n",
            checked);

    n00b_shutdown();
    return 0;
}

#else // !__APPLE__

int
main(void)
{
    fprintf(stderr,
            "[SKIP] check_perms_dyld_gap: macOS/Mach-O-only diagnostic\n");
    return 0;
}

#endif // __APPLE__
