#!/usr/bin/env bash
#
# ObjC compiler/linker wrapper that injects the GC type-map dictionary.
#
# WHY: ncc compiles every n00b C TU with --ncc-gcmap-prelink, emitting raw,
# dependency-free `n00b_gcraw` records (instead of typed codegen-ABI structs —
# that decoupling is what stops minor edits to include/core/codegen_abi.h from
# rebuilding the whole tree). Those raw records must be aggregated, per final
# executable, into one generated object defining the typed n00b_gcmap_table[] /
# n00b_gcmap_count that the runtime binary-searches (src/core/gc_type_map.c).
#
# ncc normally does this at its own link stage, but in this build the executables
# are linked by the ObjC linker (libn00b.a contains the Cocoa ObjC bridge, so
# meson selects the ObjC compiler as the clink driver), NOT by ncc. So we slot
# this wrapper in as the ObjC compiler/linker (via OBJC=...):
#   * ObjC COMPILE step (`-c`, or a .m/.mm input): transparently exec the real
#     Apple clang — we touch nothing.
#   * LINK step: run `ncc --ncc-gcmap-emit` over the link's object/archive inputs
#     (which include every one of this executable's own TUs AND libn00b.a, so the
#     dictionary is complete and per-executable-correct), then exec the real
#     Apple clang link with the original args plus the generated dictionary
#     object appended.
#
# Required environment:
#   NCC_GCMAP_REAL_OBJC   absolute path to the real ObjC compiler (Apple clang)
#   NCC_GCMAP_NCC         absolute path to ncc
#   NCC_GCMAP_INCLUDE     include dir for the generated TU's #include "core/codegen_abi.h"
#
# If any are unset, the wrapper degrades to a transparent passthrough to the real
# compiler (the build still works; typed allocations fall back to conservative
# scanning, which is GC-safe).
set -euo pipefail

# Resolve configuration from the environment when present (set by build.sh), but
# fall back to deriving everything from the wrapper's own location so a direct
# `ninja` run (no build.sh env) still aggregates the dictionary rather than
# silently degrading. This matters because src/core/gc_type_map.c references the
# dictionary symbols directly: if the dict object is not linked, the link FAILS.
self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${self_dir}/.." && pwd)"

real="${NCC_GCMAP_REAL_OBJC:-}"
ncc="${NCC_GCMAP_NCC:-}"
inc="${NCC_GCMAP_INCLUDE:-}"

if [[ -z "$real" ]]; then
    real="$(xcrun --find clang 2>/dev/null || command -v clang)"
fi
if [[ -z "$ncc" ]]; then
    ncc="$(command -v ncc 2>/dev/null || echo "$HOME/.local/bin/ncc")"
fi
if [[ -z "$inc" ]]; then
    inc="${repo_root}/include"
fi

# Determine whether this invocation is a compile or a link.
is_compile=0
for a in "$@"; do
    case "$a" in
        -c|-E|-S|-M|-MM|-fsyntax-only) is_compile=1 ;;
        *.m|*.mm)                      is_compile=1 ;;
    esac
done

# Transparent passthrough for compiles.
if [[ "$is_compile" -eq 1 ]]; then
    exec "$real" "$@"
fi

# ── Link step: collect object/archive inputs from the link command. ──────────
inputs=()
skip_next=0
for a in "$@"; do
    if [[ "$skip_next" -eq 1 ]]; then
        skip_next=0
        continue
    fi
    case "$a" in
        -o) skip_next=1 ;;                       # output path (next arg)
        *.o|*.a)        inputs+=("$a") ;;        # object / archive inputs
    esac
done

if [[ "${#inputs[@]}" -eq 0 ]]; then
    exec "$real" "$@"
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/ncc_gcmap_obj.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT
dict="$tmpdir/n00b_gcmap_generated.o"

# Aggregate raw records from this link's inputs into the typed dictionary object.
# `--ncc-gcmap-emit` always writes a valid object (with count==0 when no records
# were found), so the dictionary symbols that src/core/gc_type_map.c references
# are always defined. If emit genuinely fails, error out — a dict-less link would
# fail anyway on undefined n00b_gcmap_table/_count.
if ! "$ncc" "--ncc-gcmap-emit=$dict" "--ncc-gcmap-include=$inc" "${inputs[@]}"; then
    echo "ncc-gcmap-objc-link-wrapper: gcmap-emit failed (ncc=$ncc inc=$inc)" >&2
    exit 1
fi

# Link the original command plus the generated dictionary object.
exec "$real" "$@" "$dict"
