#!/usr/bin/env python3
"""Build optional PE fixtures for Meson tests.

Each command writes its declared output. Missing optional tools or network emit
an empty placeholder so the runtime tests can use their existing SKIP path.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path


SIGCHECK_URL = "https://download.sysinternals.com/files/Sigcheck.zip"
SIGCHECK_ZIP_SHA256 = "e28a0ee282023abefdaa422b9529bc771c2e16d96360d109807ed4c048ddf1c1"
SIGCHECK_EXE_SHA256 = "a2efff8d5bce9db4b899d38afaa706bdfd822711f929616a51b0dbc9f76c6281"


def write_empty(path: Path, reason: str) -> int:
    path.write_bytes(b"")
    print(f"[fixture pe] {reason}; emitting empty placeholder", file=sys.stderr)
    return 0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_hello(args: argparse.Namespace) -> int:
    gcc = shutil.which("x86_64-w64-mingw32-gcc")
    if gcc is None:
        return write_empty(args.output, "x86_64-w64-mingw32-gcc not found")

    subprocess.run([gcc, "-O2", "-s", "-o", str(args.output), str(args.source)],
                   check=True)
    print(f"[fixture pe] built hello.exe ({args.output.stat().st_size} bytes)",
          file=sys.stderr)
    return 0


def sign_hello(args: argparse.Namespace) -> int:
    if not args.input.exists() or args.input.stat().st_size == 0:
        return write_empty(args.output, "input hello.exe is empty (mingw absent)")

    signer = shutil.which("osslsigncode")
    if signer is None:
        return write_empty(args.output, "osslsigncode not found")

    subprocess.run([
        signer,
        "sign",
        "-certs",
        str(args.cert),
        "-key",
        str(args.key),
        "-h",
        "sha256",
        "-n",
        "n00b-attest test fixture",
        "-in",
        str(args.input),
        "-out",
        str(args.output),
    ], check=True)
    print(f"[fixture pe] signed hello.exe.signed ({args.output.stat().st_size} bytes)",
          file=sys.stderr)
    return 0


def fetch_sigcheck(args: argparse.Namespace) -> int:
    try:
        with urllib.request.urlopen(SIGCHECK_URL, timeout=60) as response:
            zip_data = response.read()
    except Exception as exc:
        return write_empty(args.output, f"sigcheck download failed ({exc})")

    if sha256(zip_data) != SIGCHECK_ZIP_SHA256:
        return write_empty(args.output, "Sigcheck.zip SHA-256 mismatch")

    with tempfile.TemporaryDirectory(prefix="n00b-sigcheck-") as tmp:
        zip_path = Path(tmp) / "Sigcheck.zip"
        zip_path.write_bytes(zip_data)
        try:
            with zipfile.ZipFile(zip_path) as zf:
                members = {name.lower(): name for name in zf.namelist()}
                exe_name = members.get("sigcheck64.exe")
                if exe_name is None:
                    return write_empty(args.output, "sigcheck64.exe not found in zip")
                exe_data = zf.read(exe_name)
        except zipfile.BadZipFile as exc:
            return write_empty(args.output, f"Sigcheck.zip is invalid ({exc})")

    if sha256(exe_data) != SIGCHECK_EXE_SHA256:
        return write_empty(args.output, "sigcheck64.exe SHA-256 mismatch")

    args.output.write_bytes(exe_data)
    print(f"[fixture pe] cached sigcheck64.exe ({len(exe_data)} bytes; SHA-256 verified)",
          file=sys.stderr)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build-hello")
    build.add_argument("source", type=Path)
    build.add_argument("output", type=Path)
    build.set_defaults(func=build_hello)

    sign = subparsers.add_parser("sign-hello")
    sign.add_argument("input", type=Path)
    sign.add_argument("cert", type=Path)
    sign.add_argument("key", type=Path)
    sign.add_argument("output", type=Path)
    sign.set_defaults(func=sign_hello)

    fetch = subparsers.add_parser("fetch-sigcheck")
    fetch.add_argument("output", type=Path)
    fetch.set_defaults(func=fetch_sigcheck)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
