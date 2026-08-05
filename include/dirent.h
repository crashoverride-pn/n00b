#pragma once

#ifdef _WIN32
#include <errno.h>
#include <io.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef ENAMETOOLONG
#define ENAMETOOLONG 36
#endif

#ifndef EBUSY
#define EBUSY 16
#endif

enum { N00B_DIRENT_NAME_MAX = 260 };

struct dirent {
    char d_name[N00B_DIRENT_NAME_MAX];
};

typedef struct {
    intptr_t           handle;
    struct _finddata_t data;
    int                first;
    struct dirent      entry;
} DIR;

// ponytail: one shim DIR per translation unit; allocate slots if nested walks need it.
static DIR n00b_dirent_slot;
static int n00b_dirent_slot_busy;

static inline DIR *
opendir(const char *path)
{
    if (!path) {
        errno = EINVAL;
        return NULL;
    }

    size_t len     = strlen(path);
    int    has_sep = len > 0 && (path[len - 1] == '/' || path[len - 1] == '\\');
    char   pattern[N00B_DIRENT_NAME_MAX + 3];

    if (n00b_dirent_slot_busy) {
        errno = EBUSY;
        return NULL;
    }

    if (len + (has_sep ? 2 : 3) > sizeof(pattern)) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    memcpy(pattern, path, len);
    size_t ix = len;
    if (!has_sep) {
        pattern[ix++] = '/';
    }
    pattern[ix++] = '*';
    pattern[ix]   = '\0';

    DIR *dir    = &n00b_dirent_slot;
    dir->handle = _findfirst(pattern, &dir->data);

    if (dir->handle == -1) {
        return NULL;
    }

    dir->first            = 1;
    n00b_dirent_slot_busy = 1;
    return dir;
}

static inline struct dirent *
readdir(DIR *dir)
{
    if (!dir) {
        errno = EINVAL;
        return NULL;
    }

    if (!dir->first && _findnext(dir->handle, &dir->data) != 0) {
        return NULL;
    }
    dir->first = 0;

    size_t name_len = strlen(dir->data.name);
    if (name_len >= sizeof(dir->entry.d_name)) {
        name_len = sizeof(dir->entry.d_name) - 1;
    }
    memcpy(dir->entry.d_name, dir->data.name, name_len);
    dir->entry.d_name[name_len] = '\0';
    return &dir->entry;
}

static inline int
closedir(DIR *dir)
{
    if (!dir || dir != &n00b_dirent_slot || !n00b_dirent_slot_busy) {
        errno = EINVAL;
        return -1;
    }

    int result = _findclose(dir->handle);
    dir->handle           = -1;
    n00b_dirent_slot_busy = 0;
    return result;
}

#else
#include_next <dirent.h>
#endif
