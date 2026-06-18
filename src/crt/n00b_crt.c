#include <stddef.h>
#include <stdint.h>

#include "n00b_crt.h"

typedef void (*n00b_crt_init_fn)(void);

void
n00b_crt_run_init_array_range(void (**start)(void), void (**end)(void))
{
    while (start < end) {
        void (*fn)(void) = *start++;

        if (fn != nullptr) {
            fn();
        }
    }
}

#if defined(_WIN32)

[[gnu::used, gnu::section(".CRT$XCA")]]
n00b_crt_init_fn n00b_crt_xca[] = { nullptr };
[[gnu::used, gnu::section(".CRT$XCZ")]]
n00b_crt_init_fn n00b_crt_xcz[] = { nullptr };

void
n00b_crt_run_init_array(void)
{
    n00b_crt_run_init_array_range(n00b_crt_xca + 1, n00b_crt_xcz);
}

#elif defined(__APPLE__) && defined(__MACH__)

#define N00B_CRT_MH_MAGIC_64   UINT32_C(0xfeedfacf)
#define N00B_CRT_LC_SEGMENT_64 UINT32_C(0x19)

typedef struct {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} n00b_crt_mach_header_64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} n00b_crt_load_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} n00b_crt_segment_command_64_t;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} n00b_crt_section_64_t;

extern const n00b_crt_mach_header_64_t *_dyld_get_image_header(uint32_t image_index);
extern intptr_t                         _dyld_get_image_vmaddr_slide(uint32_t image_index);

static int
n00b_crt_macho_name_eq(const char field[16], const char *name)
{
    for (size_t i = 0; i < 16; i++) {
        char want = name[i];

        if (field[i] != want) {
            return 0;
        }

        if (want == '\0') {
            return 1;
        }
    }

    return name[16] == '\0';
}

void
n00b_crt_run_init_array(void)
{
    const n00b_crt_mach_header_64_t *header = _dyld_get_image_header(0);

    if (header == nullptr || header->magic != N00B_CRT_MH_MAGIC_64) {
        return;
    }

    intptr_t  slide  = _dyld_get_image_vmaddr_slide(0);
    uintptr_t cursor = (uintptr_t)(header + 1);

    for (uint32_t cmd_ix = 0; cmd_ix < header->ncmds; cmd_ix++) {
        const n00b_crt_load_command_t *load_cmd = (const void *)cursor;

        if (load_cmd->cmdsize < sizeof(*load_cmd)) {
            return;
        }

        if (load_cmd->cmd == N00B_CRT_LC_SEGMENT_64
            && load_cmd->cmdsize >= sizeof(n00b_crt_segment_command_64_t)) {
            const n00b_crt_segment_command_64_t *segment = (const void *)cursor;
            const n00b_crt_section_64_t         *section = (const void *)(segment + 1);

            for (uint32_t sect_ix = 0; sect_ix < segment->nsects; sect_ix++) {
                if (n00b_crt_macho_name_eq(section[sect_ix].sectname,
                                           "__mod_init_func")) {
                    n00b_crt_init_fn *start = (void *)(uintptr_t)(section[sect_ix].addr
                                                                  + (uint64_t)slide);
                    n00b_crt_init_fn *end   = start + (section[sect_ix].size
                                                       / sizeof(*start));
                    n00b_crt_run_init_array_range(start, end);
                }
                else if (n00b_crt_macho_name_eq(section[sect_ix].sectname,
                                                "__init_offsets")) {
                    const uint32_t *start = (const void *)(uintptr_t)(section[sect_ix].addr
                                                                      + (uint64_t)slide);
                    const uint32_t *end   = start + (section[sect_ix].size
                                                     / sizeof(*start));

                    while (start < end) {
                        uint32_t offset = *start++;

                        if (offset != 0) {
                            n00b_crt_init_fn fn = (void *)((uintptr_t)header + offset);
                            fn();
                        }
                    }
                }
            }
        }

        cursor += load_cmd->cmdsize;
    }
}

#else

[[gnu::weak]] extern n00b_crt_init_fn __init_array_start[];
[[gnu::weak]] extern n00b_crt_init_fn __init_array_end[];

void
n00b_crt_run_init_array(void)
{
    if (__init_array_start == nullptr || __init_array_end == nullptr) {
        return;
    }

    n00b_crt_run_init_array_range(__init_array_start, __init_array_end);
}

#endif
