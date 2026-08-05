# Windows Builds

## Native Windows

Native Windows builds use PowerShell, Meson, Ninja, and the neighboring native
`ncc.exe`. Do not use POSIX build tools for this path.

From the `n00b` checkout:

```powershell
.\build.ps1
```

The wrapper resolves `NCC_PATH`, or the neighboring
`..\ncc\build-msvc\ncc.exe`, sets `CC`, runs Meson setup or reconfigure, and
then runs Ninja. Set `N00B_JOBS` to pass a Ninja job count.

To run the underlying commands manually:

```powershell
$env:CC = (Resolve-Path ..\ncc\build-msvc\ncc.exe).Path
meson setup build_msvc -Dusing_build_script=true -Dskip_vcs_check=true --buildtype=debug
ninja -C build_msvc
```

## Cross Builds

`n00b` Windows builds are cross builds from Linux or macOS. Meson invokes the
native build-host `ncc` wrapper, and `ncc` delegates code generation and linking
to llvm-mingw Clang for `x86_64-w64-windows-gnu`.

## Requirements

- A native `ncc` executable.
- llvm-mingw with Clang 22.1.0 or newer.
- PowerShell 7 on the Windows machine used for smoke testing.

## Build

From the `n00b` checkout:

```sh
export LLVM_MINGW=/path/to/llvm-mingw
NCC_PATH=/path/to/ncc \
N00B_CROSS=windows-x86_64 \
N00B_CLEAN=1 \
N00B_JOBS=2 \
bash build.sh
```

The build produces Windows PE executables under `build_cross_windows-x86_64`,
including `n00b.exe` and selected test executables.

## Smoke Bundle

Package the Windows smoke artifacts from the `n00b` checkout:

```sh
scripts/package_windows_smoke.sh build_cross_windows-x86_64 /tmp/n00b-windows-smoke
```

The package step regenerates the Unicode C tables into the Windows cross-build
directory, rebuilds the cross tree, and fails if any required UCD cache or
Unicode test-data file is missing or empty. Once `src/text/unicode/.unicode_cache`
is populated, the package step can repopulate `test/data` from that cache
without a network fetch.

Copy the output directory to Windows and run:

```powershell
pwsh -File .\windows_smoke.ps1 -N00b .\n00b.exe
```

The smoke script runs `n00b.exe --help`, selected self-contained test
executables including the Unicode table-backed tests, `n00b.exe run .\hello.n`,
and a negative compile-mode assertion that requires the current unsupported
Windows compile message. It writes a transcript to
`windows-smoke-transcript.txt`.

`n00b.exe compile` is intentionally disabled on Windows. Windows cross-build
parity work covers the runtime, library, parser, conduit, object-file, display,
VFS, Unicode, and test executable surfaces, but not Windows AOT executable
generation through the `compile` subcommand.
