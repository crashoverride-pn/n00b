#include "core/static_init_runtime.h"

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#endif

int
n00b_run_degraded_static_init_range(const n00b_static_init_fn_t *start,
                                    const n00b_static_init_fn_t *end)
{
    if (start == nullptr || end == nullptr || end < start) {
        return 0;
    }

    while (start < end) {
        n00b_static_init_fn_t fn = *start++;
        if (fn == nullptr) {
            continue;
        }

        int rc = fn();
        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}

#if defined(__APPLE__)
static int
n00b_run_degraded_static_inits_macho_image(const struct mach_header *hdr,
                                           intptr_t slide)
{
    if (hdr == nullptr || hdr->magic != MH_MAGIC_64) {
        return 0;
    }

    const struct mach_header_64 *header = (const struct mach_header_64 *)hdr;
    const uint8_t *cursor = (const uint8_t *)&header[1];
    const uint8_t *const cmds_end = cursor + header->sizeofcmds;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if ((size_t)(cmds_end - cursor) < sizeof(struct load_command)) {
            return 0;
        }

        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(struct load_command)
            || lc->cmdsize > (uint32_t)(cmds_end - cursor)) {
            return 0;
        }

        if (lc->cmd == LC_SEGMENT_64
            && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            size_t sections_bytes =
                (size_t)seg->nsects * sizeof(struct section_64);
            if (sections_bytes
                <= (size_t)(lc->cmdsize - sizeof(struct segment_command_64))) {
                const struct section_64 *section =
                    (const struct section_64 *)(seg + 1);

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strncmp(section[j].segname, "__DATA", 16) != 0
                        || strncmp(section[j].sectname, "n00b_sinit", 16) != 0) {
                        continue;
                    }

                    uintptr_t start_addr =
                        (uintptr_t)section[j].addr + (uintptr_t)slide;
                    const n00b_static_init_fn_t *start =
                        (const n00b_static_init_fn_t *)start_addr;
                    const n00b_static_init_fn_t *end =
                        start + (section[j].size / sizeof(*start));
                    int rc = n00b_run_degraded_static_init_range(start, end);
                    if (rc != 0) {
                        return rc;
                    }
                }
            }
        }

        cursor += lc->cmdsize;
    }

    return 0;
}

int
n00b_run_degraded_static_inits(void)
{
    uint32_t image_count = _dyld_image_count();

    for (uint32_t i = 0; i < image_count; i++) {
        int rc = n00b_run_degraded_static_inits_macho_image(
            _dyld_get_image_header(i),
            _dyld_get_image_vmaddr_slide(i));
        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}
#elif defined(_WIN32)
[[gnu::used, gnu::section(".n00bsi$a")]]
n00b_static_init_fn_t __n00b_static_init_section_start[] = { nullptr };

[[gnu::used, gnu::section(".n00bsi$z")]]
n00b_static_init_fn_t __n00b_static_init_section_end[] = { nullptr };

int
n00b_run_degraded_static_inits(void)
{
    return n00b_run_degraded_static_init_range(
        __n00b_static_init_section_start + 1,
        __n00b_static_init_section_end);
}
#else
[[gnu::weak]] extern const n00b_static_init_fn_t __start_n00b_sinit[];
[[gnu::weak]] extern const n00b_static_init_fn_t __stop_n00b_sinit[];

int
n00b_run_degraded_static_inits(void)
{
    if (__start_n00b_sinit == nullptr || __stop_n00b_sinit == nullptr) {
        return 0;
    }

    return n00b_run_degraded_static_init_range(__start_n00b_sinit,
                                              __stop_n00b_sinit);
}
#endif
