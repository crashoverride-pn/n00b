#!/usr/bin/env python3
"""Reject single-shot writes to stdout and stderr in the runtime's sources.

A single write(2) can come back short: on a non-blocking descriptor, or on a
pipe when a signal lands partway through a write larger than PIPE_BUF. Code
that issues one write and ignores the count drops the rest of the message,
which for a crash report or an assertion is the part that says what failed.
n00b_raw_write_all and n00b_raw_write_all_brief are the primitives that loop,
so this rejects:

  - any call to n00b_raw_write outside include/core/syscall.h, which defines
    it, whatever the descriptor;
  - libc write() and raw SYS_write syscalls whose descriptor is written as
    1, 2, STDOUT_FILENO, or STDERR_FILENO.

Usage: lint_raw_writes.py <source root>
"""
import os
import re
import sys

SCAN_DIRS = ("src", "include")
SKIP_DIRS = ("src/vendor",)

# Files that may still call n00b_raw_write, with the reason.
RAW_WRITE_ALLOWED = {
    "include/core/syscall.h": "defines it",
}

# Files whose direct writes to fd 1 or 2 are allowed, with the reason.
FD_WRITE_ALLOWED = {
    "include/core/syscall.h": "defines the raw write primitives",
    "src/display/terminal_lifecycle.c": "tty_write_raw loops over short writes",
}

RAW_WRITE = re.compile(r"\bn00b_raw_write\s*\(")
STD_FD = r"(?:1|2|STDOUT_FILENO|STDERR_FILENO)"
FD_WRITE = re.compile(
    r"(?<![\w.>])write\s*\(\s*" + STD_FD + r"\s*,"
    r"|\b_n00b_raw_write_once\s*\(\s*" + STD_FD + r"\s*,"
    r"|\bSYS_write\s*,\s*(?:\(\s*long\s*\)\s*)?" + STD_FD + r"\s*,"
)


def strip_comments_and_literals(text: str) -> str:
    """Blank out comments and string or character literals, keeping newlines
    so match offsets still map to the right line."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + re.sub(r"[^\n]", " ", text[i + 1:j - 1]) + c)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def scan(root: str) -> list[str]:
    problems = []
    for top in SCAN_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(root, top)):
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            dirnames[:] = sorted(
                d for d in dirnames if f"{rel_dir}/{d}" not in SKIP_DIRS
            )
            for name in sorted(filenames):
                if name.startswith(".") or not name.endswith((".c", ".h", ".m")):
                    continue
                rel = f"{rel_dir}/{name}"
                with open(os.path.join(dirpath, name), encoding="utf-8",
                          errors="replace") as f:
                    code = strip_comments_and_literals(f.read())
                checks = []
                if rel not in RAW_WRITE_ALLOWED:
                    checks.append((RAW_WRITE, "single-shot n00b_raw_write; use "
                                   "n00b_raw_write_all or _brief"))
                if rel not in FD_WRITE_ALLOWED:
                    checks.append((FD_WRITE, "single write to fd 1 or 2; use "
                                   "n00b_raw_write_all or _brief"))
                for pattern, why in checks:
                    for m in pattern.finditer(code):
                        line = code.count("\n", 0, m.start()) + 1
                        problems.append(f"{rel}:{line}: {why}")
    return problems


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    problems = scan(sys.argv[1])
    for p in problems:
        print(p)
    if problems:
        print(f"{len(problems)} single-shot write(s) to stdout or stderr",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
