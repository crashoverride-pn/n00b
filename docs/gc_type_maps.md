# GC Type Maps and n00b-gcmap-index

This page documents n00b's post-link GC type-map pipeline. It is for people
building n00b binaries, writing tests that execute n00b-linked programs, or
debugging marshal failures caused by missing exact heap layout metadata.

## What This Solves

n00b allocation macros pass a compile-time type hash into the allocator:

```c
widget_t *one = n00b_alloc(widget_t);
widget_t *many = n00b_alloc_array(widget_t, 16);
```

Both calls carry `typehash(widget_t *)`. ncc can use that type hash to emit a
GC layout descriptor for `widget_t` when it can prove which fields are real
managed pointers. The runtime then uses the descriptor to scan only those
pointer fields.

Without an indexed type map, these allocations keep the conservative
`DEFAULT` scan policy. That fallback is GC-safe, but it scans every word and is
not precise enough for workflows that need exact pointer layout, especially
marshal/unmarshal of callback-scanned heap objects.

## Build Pipeline

The complete pipeline has three stages:

1. ncc sees `typehash(T *)` and emits two linker sections into each object
   file:
   - `n00b_gcmap`: pointer-bearing entries `{type_hash, layout}`.
   - `n00b_gcidx`: no-pointer placeholder entries `{0, entry_index}`.
2. The linker concatenates those sections into the final executable.
3. `n00b-gcmap-index` rewrites `n00b_gcidx` in place so it is sorted by
   `type_hash` and points back into the original `n00b_gcmap` section.

At runtime, `_n00b_alloc_raw()` performs a binary search over `n00b_gcidx`.
When a match exists, it upgrades the allocation from `DEFAULT` scanning to:

```c
.scan_kind = N00B_GC_SCAN_KIND_CALLBACK
.scan_cb   = n00b_gc_scan_cb_type_layout
.scan_user = matched_layout
```

The descriptor's element count is derived from the allocation length, so one
layout serves both `n00b_alloc(T)` and `n00b_alloc_array(T, N)`.

## Running n00b-gcmap-index

Use the command after the final link step:

```sh
path/to/n00b-gcmap-index path/to/executable
```

`n00b-gcmap-index` is a build tool, not a public runtime command installed for
end users by default. Invoke the built executable from the build directory or
from the Meson target that owns it. The command modifies the target executable
in place and exits successfully when:

- the executable has no GC type-map sections;
- the executable is already indexed;
- the index was filled and written successfully.

For test runners and one-shot execution, use `--exec`:

```sh
path/to/n00b-gcmap-index --exec path/to/executable [args...]
```

In `--exec` mode, the command indexes the executable first and then replaces
itself with the executable via `execv()`. The program receives the executable
path as `argv[0]` followed by the remaining arguments.

## Build-Script Integration

Most n00b developers should not need to run this by hand. The n00b build uses
`n00b-gcmap-index` for the helper binaries that need exact type layouts, and
unit tests that depend on indexed maps run through the `--exec` wrapper.

When adding a new executable that marshals typed heap objects or depends on
exact type-layout scanning, make sure the final binary is indexed before it is
run. In Meson tests, the usual pattern is:

```meson
test('my_exact_layout_test', n00b_gcmap_index,
     args: ['--exec', my_exact_layout_test.full_path()],
     depends: [my_exact_layout_test],
     suite: 'unit')
```

For normal local builds, use the repository build script as the entry point so
the ncc path and relevant post-link steps stay aligned:

```sh
bash build.sh build_debug
```

## Supported Executable Formats

`n00b-gcmap-index` currently supports:

| Format | Support |
|--------|---------|
| 64-bit native-endian Mach-O | Supported on macOS. The command ad-hoc re-signs the binary if it changes the file. |
| Little-endian ELF64 | Supported on Linux and other ELF64 hosts. |
| Fat Mach-O | Not supported. |
| Windows PE/COFF | Not built or indexed by this command yet. Runtime lookup currently treats the table as empty on Windows. |

## Failure Modes

The command exits non-zero and prints `n00b-gcmap-index: ...` on failure.

| Message | Meaning |
|---------|---------|
| `expected both n00b_gcmap and n00b_gcidx sections` | The binary has only one of the required sections. Rebuild with matching ncc and n00b headers. |
| `n00b_gcmap/n00b_gcidx record counts differ` | The sections were not emitted as matching pairs. Rebuild cleanly. |
| `... size is not a whole number of records` | The section size does not match the expected record ABI. Check for stale objects or mismatched headers. |
| `unsupported executable format` | The file is not a supported Mach-O or ELF64 executable. |
| `fat Mach-O binaries are not supported` | Index each thin architecture binary before packaging a universal binary. |
| `codesign --force --sign - failed` | macOS changed the file but ad-hoc re-signing failed. Re-run after fixing local codesign availability or permissions. |

If the command is not run, n00b does not fail open into an unsafe under-scan.
The runtime validates the index before use. A missing, empty, unsorted, or
inconsistent index is ignored and allocations keep conservative `DEFAULT`
scanning.

## Debugging Missing Maps

To check the ncc side, inspect transformed source:

```sh
ncc -E module.c
```

Look for generated declarations named `__ncc_gcmap_lay_*`,
`__ncc_gcmap_ent_*`, and `__ncc_gcidx_ent_*`. If they are absent, ncc skipped
the type because it could not prove a safe layout. Common reasons are
block-local type names, incomplete aggregate definitions, pointer arrays, and
mixed pointer/scalar unions.

To check the linked binary, run `n00b-gcmap-index` directly. A zero exit status
means the binary is now in the best state the tool can produce. Runtime code
then validates the section contents again before using them.

For the ncc-side eligibility rules, see the ncc repository's
`docs/gc_typemaps.md`.
