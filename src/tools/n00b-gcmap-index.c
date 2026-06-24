#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/wait.h>
#endif

#if defined(__ELF__) || defined(__linux__)
#include <elf.h>
#endif

typedef struct {
    uint64_t type_hash;
    uint64_t layout_word;
} gcmap_record_t;

typedef struct {
    uint64_t type_hash;
    uint64_t entry_index;
} gcidx_record_t;

typedef struct {
    size_t offset;
    size_t size;
    bool   found;
} section_span_t;

static int
failf(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "n00b-gcmap-index: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);

    return 1;
}

static int
compare_gcidx(const void *ap, const void *bp)
{
    const gcidx_record_t *a = (const gcidx_record_t *)ap;
    const gcidx_record_t *b = (const gcidx_record_t *)bp;

    if (a->type_hash < b->type_hash) {
        return -1;
    }
    if (a->type_hash > b->type_hash) {
        return 1;
    }
    if (a->entry_index < b->entry_index) {
        return -1;
    }
    if (a->entry_index > b->entry_index) {
        return 1;
    }

    return 0;
}

static bool
span_in_file(uint64_t offset, uint64_t size, size_t file_size)
{
    if (offset > (uint64_t)file_size) {
        return false;
    }
    if (size > (uint64_t)file_size - offset) {
        return false;
    }
    if (offset > (uint64_t)SIZE_MAX || size > (uint64_t)SIZE_MAX) {
        return false;
    }

    return true;
}

// Build a sorted index section from a map section. The map section's records
// need only carry a uint64_t type_hash at offset 0 (gcmap_record_t and the
// transient n00b_trmap entry share that 16-byte shape); the index records are
// {type_hash, entry_index}. Used for both (n00b_gcmap -> n00b_gcidx) and
// (n00b_trmap -> n00b_tridx). Only the index section is written, so the map
// section's relocated pointer words (and any Mach-O chained-fixup metadata)
// are never disturbed.
static int
fill_index(uint8_t        *base,
           size_t          file_size,
           section_span_t  map,
           section_span_t  idx,
           const char     *map_name,
           const char     *idx_name,
           bool           *changed)
{
    if (!map.found && !idx.found) {
        *changed = false;
        return 0;
    }
    if (!map.found || !idx.found) {
        return failf("expected both %s and %s sections", map_name, idx_name);
    }
    if (map.size % sizeof(gcmap_record_t) != 0) {
        return failf("%s size is not a whole number of records", map_name);
    }
    if (idx.size % sizeof(gcidx_record_t) != 0) {
        return failf("%s size is not a whole number of records", idx_name);
    }

    size_t count = map.size / sizeof(gcmap_record_t);
    if (idx.size / sizeof(gcidx_record_t) != count) {
        return failf("%s/%s record counts differ", map_name, idx_name);
    }
    if (count == 0) {
        *changed = false;
        return 0;
    }
    if (count > SIZE_MAX / sizeof(gcidx_record_t)) {
        return failf("too many %s records", map_name);
    }
    if (!span_in_file(map.offset, map.size, file_size)
        || !span_in_file(idx.offset, idx.size, file_size)) {
        return failf("%s/%s section extends past end of file",
                     map_name,
                     idx_name);
    }

    const gcmap_record_t *map_records =
        (const gcmap_record_t *)(const void *)(base + map.offset);
    gcidx_record_t *idx_records =
        (gcidx_record_t *)(void *)(base + idx.offset);
    gcidx_record_t *sorted = (gcidx_record_t *)calloc(count,
                                                      sizeof(gcidx_record_t));
    if (!sorted) {
        return failf("calloc(%zu): %s", count, strerror(errno));
    }

    for (size_t i = 0; i < count; i++) {
        sorted[i].type_hash   = map_records[i].type_hash;
        sorted[i].entry_index = (uint64_t)i;
    }

    qsort(sorted, count, sizeof(gcidx_record_t), compare_gcidx);

    if (memcmp(idx_records, sorted, count * sizeof(gcidx_record_t)) == 0) {
        *changed = false;
    }
    else {
        memcpy(idx_records, sorted, count * sizeof(gcidx_record_t));
        *changed = true;
    }

    free(sorted);
    return 0;
}

#if defined(__APPLE__)
static bool
macho_name_eq(const char name[16], const char *want)
{
    return strncmp(name, want, 16) == 0;
}

static int
set_macho_span(const struct section_64 *sec,
               size_t                   file_size,
               section_span_t          *span)
{
    if (span->found) {
        return failf("duplicate Mach-O section %.*s", 16, sec->sectname);
    }
    if (!span_in_file(sec->offset, sec->size, file_size)) {
        return failf("Mach-O section %.*s extends past end of file",
                     16,
                     sec->sectname);
    }

    span->offset = (size_t)sec->offset;
    span->size   = (size_t)sec->size;
    span->found  = true;
    return 0;
}

static int
find_macho_sections(uint8_t        *base,
                    size_t          file_size,
                    section_span_t *gcmap,
                    section_span_t *gcidx,
                    section_span_t *trmap,
                    section_span_t *tridx)
{
    if (file_size < sizeof(struct mach_header_64)) {
        return failf("file is too small to be a Mach-O executable");
    }

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)(const void *)base;

    if (hdr->magic == FAT_MAGIC || hdr->magic == FAT_CIGAM) {
        return failf("fat Mach-O binaries are not supported");
    }
    if (hdr->magic != MH_MAGIC_64) {
        return failf("only native-endian 64-bit Mach-O binaries are supported");
    }
    if ((uint64_t)hdr->sizeofcmds > (uint64_t)file_size - sizeof(*hdr)) {
        return failf("Mach-O load commands extend past end of file");
    }

    const uint8_t *cmdp = base + sizeof(*hdr);
    const uint8_t *end  = cmdp + hdr->sizeofcmds;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if ((size_t)(end - cmdp) < sizeof(struct load_command)) {
            return failf("truncated Mach-O load command");
        }

        const struct load_command *lc =
            (const struct load_command *)(const void *)cmdp;

        if (lc->cmdsize < sizeof(*lc) || cmdp + lc->cmdsize > end) {
            return failf("invalid Mach-O load command size");
        }

        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                return failf("truncated LC_SEGMENT_64 command");
            }

            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)(const void *)cmdp;
            size_t max_sections =
                (lc->cmdsize - sizeof(*seg)) / sizeof(struct section_64);
            if (seg->nsects > max_sections) {
                return failf("LC_SEGMENT_64 nsects exceeds command size");
            }

            const struct section_64 *sec =
                (const struct section_64 *)(const void *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (macho_name_eq(sec[j].segname, "__DATA")
                    && macho_name_eq(sec[j].sectname, "n00b_gcmap")) {
                    int rc = set_macho_span(&sec[j], file_size, gcmap);
                    if (rc != 0) {
                        return rc;
                    }
                }
                else if (macho_name_eq(sec[j].segname, "__DATA")
                         && macho_name_eq(sec[j].sectname, "n00b_gcidx")) {
                    int rc = set_macho_span(&sec[j], file_size, gcidx);
                    if (rc != 0) {
                        return rc;
                    }
                }
                else if (macho_name_eq(sec[j].segname, "__DATA")
                         && macho_name_eq(sec[j].sectname, "n00b_trmap")) {
                    int rc = set_macho_span(&sec[j], file_size, trmap);
                    if (rc != 0) {
                        return rc;
                    }
                }
                else if (macho_name_eq(sec[j].segname, "__DATA")
                         && macho_name_eq(sec[j].sectname, "n00b_tridx")) {
                    int rc = set_macho_span(&sec[j], file_size, tridx);
                    if (rc != 0) {
                        return rc;
                    }
                }
            }
        }

        cmdp += lc->cmdsize;
    }

    return 0;
}

static int
resign_macho(const char *path)
{
    pid_t pid = fork();

    if (pid < 0) {
        return failf("fork: %s", strerror(errno));
    }
    if (pid == 0) {
        execl("/usr/bin/codesign",
              "/usr/bin/codesign",
              "--force",
              "--sign",
              "-",
              path,
              (char *)NULL);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return failf("waitpid(codesign): %s", strerror(errno));
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return failf("codesign --force --sign - failed for %s", path);
    }

    return 0;
}
#endif

#if defined(__ELF__) || defined(__linux__)
static int
set_elf_span(const Elf64_Shdr *shdr,
             const char       *name,
             size_t            file_size,
             section_span_t   *span)
{
    if (span->found) {
        return failf("duplicate ELF section %s", name);
    }
    if (!span_in_file(shdr->sh_offset, shdr->sh_size, file_size)) {
        return failf("ELF section %s extends past end of file", name);
    }

    span->offset = (size_t)shdr->sh_offset;
    span->size   = (size_t)shdr->sh_size;
    span->found  = true;
    return 0;
}

static int
find_elf_sections(uint8_t        *base,
                  size_t          file_size,
                  section_span_t *gcmap,
                  section_span_t *gcidx,
                  section_span_t *trmap,
                  section_span_t *tridx)
{
    if (file_size < sizeof(Elf64_Ehdr)) {
        return failf("file is too small to be an ELF executable");
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)(const void *)base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return failf("not an ELF executable");
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64
        || ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return failf("only little-endian ELF64 binaries are supported");
    }
    if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        return failf("unexpected ELF section-header size");
    }
    if (ehdr->e_shnum == 0 || ehdr->e_shstrndx == SHN_UNDEF
        || ehdr->e_shstrndx >= ehdr->e_shnum) {
        return failf("ELF section-name table is missing");
    }
    if (!span_in_file(ehdr->e_shoff,
                      (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr),
                      file_size)) {
        return failf("ELF section headers extend past end of file");
    }

    const Elf64_Shdr *sections =
        (const Elf64_Shdr *)(const void *)(base + ehdr->e_shoff);
    const Elf64_Shdr *names_hdr = &sections[ehdr->e_shstrndx];
    if (!span_in_file(names_hdr->sh_offset, names_hdr->sh_size, file_size)) {
        return failf("ELF section-name table extends past end of file");
    }

    const char *names = (const char *)(const void *)(base + names_hdr->sh_offset);

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i].sh_name >= names_hdr->sh_size) {
            return failf("ELF section name offset is out of range");
        }

        const char *name = names + sections[i].sh_name;
        if (strcmp(name, "n00b_gcmap") == 0) {
            int rc = set_elf_span(&sections[i], name, file_size, gcmap);
            if (rc != 0) {
                return rc;
            }
        }
        else if (strcmp(name, "n00b_gcidx") == 0) {
            int rc = set_elf_span(&sections[i], name, file_size, gcidx);
            if (rc != 0) {
                return rc;
            }
        }
        else if (strcmp(name, "n00b_trmap") == 0) {
            int rc = set_elf_span(&sections[i], name, file_size, trmap);
            if (rc != 0) {
                return rc;
            }
        }
        else if (strcmp(name, "n00b_tridx") == 0) {
            int rc = set_elf_span(&sections[i], name, file_size, tridx);
            if (rc != 0) {
                return rc;
            }
        }
    }

    return 0;
}
#endif

static int
index_path(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return failf("open(%s): %s", path, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        return failf("fstat(%s): %s", path, strerror(saved));
    }
    if (st.st_size <= 0) {
        close(fd);
        return failf("%s is empty", path);
    }

    size_t file_size = (size_t)st.st_size;
    uint8_t *base = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd, 0);
    if (base == MAP_FAILED) {
        int saved = errno;
        close(fd);
        return failf("mmap(%s): %s", path, strerror(saved));
    }

    section_span_t gcmap = {0};
    section_span_t gcidx = {0};
    section_span_t trmap = {0};
    section_span_t tridx = {0};
    bool           changed = false;
    int            rc = 0;

#if defined(__APPLE__)
    uint32_t magic = file_size >= sizeof(uint32_t)
                   ? *(const uint32_t *)(const void *)base
                   : 0;
    if (magic == MH_MAGIC_64 || magic == FAT_MAGIC || magic == FAT_CIGAM
        || magic == MH_CIGAM_64 || magic == MH_MAGIC) {
        rc = find_macho_sections(base, file_size, &gcmap, &gcidx, &trmap,
                                 &tridx);
        bool changed_tr = false;
        if (rc == 0) {
            rc = fill_index(base, file_size, gcmap, gcidx, "n00b_gcmap",
                            "n00b_gcidx", &changed);
        }
        if (rc == 0) {
            rc = fill_index(base, file_size, trmap, tridx, "n00b_trmap",
                            "n00b_tridx", &changed_tr);
        }
        changed = changed || changed_tr;
        if (rc == 0 && changed && msync(base, file_size, MS_SYNC) != 0) {
            rc = failf("msync(%s): %s", path, strerror(errno));
        }
        munmap(base, file_size);
        close(fd);
        if (rc == 0 && changed) {
            rc = resign_macho(path);
        }
        return rc;
    }
#endif

#if defined(__ELF__) || defined(__linux__)
    if (file_size >= SELFMAG && memcmp(base, ELFMAG, SELFMAG) == 0) {
        rc = find_elf_sections(base, file_size, &gcmap, &gcidx, &trmap,
                               &tridx);
        bool changed_tr = false;
        if (rc == 0) {
            rc = fill_index(base, file_size, gcmap, gcidx, "n00b_gcmap",
                            "n00b_gcidx", &changed);
        }
        if (rc == 0) {
            rc = fill_index(base, file_size, trmap, tridx, "n00b_trmap",
                            "n00b_tridx", &changed_tr);
        }
        changed = changed || changed_tr;
        if (rc == 0 && changed && msync(base, file_size, MS_SYNC) != 0) {
            rc = failf("msync(%s): %s", path, strerror(errno));
        }
        munmap(base, file_size);
        close(fd);
        return rc;
    }
#endif

    munmap(base, file_size);
    close(fd);
    return failf("unsupported executable format: %s", path);
}

static int
usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [--exec] <executable> [args...]\n", argv0);
    return 2;
}

int
main(int argc, char **argv)
{
    bool exec_mode = false;
    int  path_arg  = 1;

    if (argc < 2) {
        return usage(argv[0]);
    }
    if (strcmp(argv[1], "--help") == 0) {
        return usage(argv[0]);
    }
    if (strcmp(argv[1], "--exec") == 0) {
        exec_mode = true;
        path_arg  = 2;
        if (argc < 3) {
            return usage(argv[0]);
        }
    }

    int rc = index_path(argv[path_arg]);
    if (rc != 0 || !exec_mode) {
        return rc;
    }

    execv(argv[path_arg], &argv[path_arg]);
    return failf("execv(%s): %s", argv[path_arg], strerror(errno));
}
