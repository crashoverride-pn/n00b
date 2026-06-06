/*
 * Thin hosted helper for N00b's optional ELF oracle tests.
 *
 * This binary is built only when the oracle test is explicitly enabled and
 * N00B_ELF_ORACLE_ROOT points at Brandon's packager checkout. It links
 * Brandon's zerocool/read_target_elf.c and provides a small libc-backed shim
 * for the syscall and memory primitives normally supplied by zerocool's Linux
 * assembly runtime.
 */

#include "core.h"
#include "errcode.h"
#include "read_target_elf.h"
#include "phtab_adjustment.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern int open(const char *path, int flags, ...);

static int64_t
host_errno_result(void)
{
    return -(int64_t)((uint64_t)(unsigned)errno << 32);
}

void *
zcl_mem_copy(void *dest, void *src, uint64_t len)
{
    return memcpy(dest, src, (size_t)len);
}

void *
zcl_mem_set(void *dest, char byte, uint64_t len)
{
    return memset(dest, (unsigned char)byte, (size_t)len);
}

uint64_t
zcl_string_len(char *string)
{
    return (uint64_t)strlen(string);
}

int64_t
zcl_syscall_write_stdout(char *buf, unsigned long len)
{
    ssize_t n = write(STDOUT_FILENO, buf, len);
    return n < 0 ? host_errno_result() : (int64_t)n;
}

void *
zcl_syscall_mmap(void     *addr,
                 uint64_t size,
                 int      prot,
                 int      flags,
                 int      fd,
                 uint64_t offset)
{
    void *result = mmap(addr, (size_t)size, prot, flags, fd, (off_t)offset);
    return result == MAP_FAILED ? (void *)0 : result;
}

void *
zcl_mmap_or_null(void     *addr,
                 uint64_t size,
                 int      prot,
                 int      flags,
                 int      fd,
                 uint64_t offset)
{
    return zcl_syscall_mmap(addr, size, prot, flags, fd, offset);
}

void *
zcl_syscall_munmap(void *addr, uint64_t size)
{
    return (void *)(intptr_t)munmap(addr, (size_t)size);
}

int
zcl_syscall_open(char *path, int flags, int mode)
{
    int fd = open(path, flags, mode);
    return fd < 0 ? -errno : fd;
}

int64_t
zcl_syscall_read(int fd, void *buf, uint64_t size)
{
    ssize_t n = read(fd, buf, (size_t)size);
    return n < 0 ? host_errno_result() : (int64_t)n;
}

int64_t
zcl_syscall_write(int fd, void *buf, uint64_t size)
{
    ssize_t n = write(fd, buf, (size_t)size);
    return n < 0 ? host_errno_result() : (int64_t)n;
}

int
zcl_syscall_close(int fd)
{
    return close(fd);
}

int
zcl_syscall_fstat(int fd, struct stat *statbuf)
{
    return fstat(fd, statbuf);
}

int
zcl_syscall_fchmod(int fd, int mode)
{
    return fchmod(fd, (mode_t)mode);
}

int
zcl_syscall_rename(char *oldpath, char *newpath)
{
    return rename(oldpath, newpath);
}

int
zcl_syscall_unlink(char *path)
{
    return unlink(path);
}

void
zcl_syscall_exit(int exit_code)
{
    _exit(exit_code);
}

static int
usage(char *argv0)
{
    fprintf(stderr, "usage: %s --mode read-target|phtab-adjustment <elf>\n",
            argv0);
    printf("verdict=oracle-error\ncode=usage\ndetail=bad-arguments\n");
    return 2;
}

static int
read_target(char *path, zcl_allocator *allocator, zcl_target_elf *elf)
{
    int err = 0;
    int rc  = zcl_read_target_elf(path, allocator, elf, &err);

    if (rc == 0) {
        printf("verdict=valid-target\ncode=0\ndetail=ok\n");
    }
    else {
        printf("verdict=invalid-target\ncode=%d\ndetail=read-target\n", err);
    }

    return 0;
}

static int
phtab_adjustment(char *path, zcl_allocator *allocator, zcl_target_elf *elf)
{
    uint64_t offset = 0;
    uint64_t size   = 0;
    int      err    = 0;
    int      rc     = zcl_read_target_elf(path, allocator, elf, &err);

    if (rc != 0) {
        printf("verdict=phtab-not-adjustable\ncode=%d\ndetail=read-target\n",
               err);
        return 0;
    }

    rc = zcl_is_phtab_adjustable(elf, &offset, &size, &err);
    if (rc == 0) {
        printf("verdict=phtab-adjustable\ncode=0\noffset=%llu\nsize=%llu\n",
               (unsigned long long)offset,
               (unsigned long long)size);
    }
    else {
        printf("verdict=phtab-not-adjustable\ncode=%d\ndetail=adjustment\n",
               err);
    }

    return 0;
}

int
main(int argc, char **argv)
{
    if (argc != 4 || strcmp(argv[1], "--mode") != 0) {
        return usage(argv[0]);
    }

    bool read_target_mode = strcmp(argv[2], "read-target") == 0;
    bool phtab_mode       = strcmp(argv[2], "phtab-adjustment") == 0;

    if (!read_target_mode && !phtab_mode) {
        printf("verdict=unsupported\ncode=unsupported-mode\ndetail=%s\n",
               argv[2]);
        return 0;
    }

    zcl_allocator allocator;
    zcl_mem_set(&allocator, 0, sizeof(allocator));

    if (zcl_init_allocator(&allocator) != 0) {
        printf("verdict=oracle-error\ncode=%d\ndetail=allocator\n",
               ERRCODE_OOM);
        return 0;
    }

    zcl_target_elf elf;
    if (read_target_mode) {
        read_target(argv[3], &allocator, &elf);
    }
    else {
        phtab_adjustment(argv[3], &allocator, &elf);
    }

    zcl_unmap_all_memory(&allocator);
    return 0;
}
