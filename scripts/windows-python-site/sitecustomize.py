"""Work around Python 3.13+ Windows temp-dir ACLs for Meson.

Python now gives os.mkdir(path, 0o700) Windows-specific ACL handling.
On this machine that can create a directory the same Python process cannot
write into. Meson compiler probes use tempfile.TemporaryDirectory, so make
temporary directories inherit the parent ACL instead.
"""

import errno
import os
import sys
import tempfile


_original_mkdtemp = tempfile.mkdtemp


def _windows_acl_safe_mkdtemp(suffix=None, prefix=None, dir=None):
    if os.name != "nt":
        return _original_mkdtemp(suffix, prefix, dir)

    prefix, suffix, directory, output_type = tempfile._sanitize_params(
        prefix, suffix, dir
    )
    names = tempfile._get_candidate_names()
    if output_type is bytes:
        names = map(os.fsencode, names)

    for _ in range(tempfile.TMP_MAX):
        name = next(names)
        path = os.path.join(directory, prefix + name + suffix)
        sys.audit("tempfile.mkdtemp", path)
        try:
            os.mkdir(path)
        except FileExistsError:
            continue
        return os.path.abspath(path)

    raise FileExistsError(errno.EEXIST, "No usable temporary directory name found")


tempfile.mkdtemp = _windows_acl_safe_mkdtemp
