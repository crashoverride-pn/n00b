# Work plan: decouple the GC/marshal codegen ABI from `n00b.h` (pre-link aggregation)

## Problem

`include/n00b.h` is the base header every other header includes. Anything in it
forces a near-total rebuild. Measured blast radius: ~490 of 537 TUs (90%+) rebuild
when `n00b.h` changes; the whole `core/` memory cluster sits in the same 90%+ band.
That cluster is also the most-churned code in the repo, so routine GC/marshal work
triggers full rebuilds.

Root cause is *not* umbrella-include creep. It is that three unrelated things were
fused into `n00b.h`:

1. **Pervasive typedefs** — `n00b_size_t`, the forward-decl block, `n00b_buffer_t`
   /`string_t`/`list_t`, etc. Genuinely universal. This is what `n00b.h` is for.
2. **The GC scanning/marshal codegen ABI** — root tables, type→layout maps, variant
   arms, transient maps, static-object descriptors, section macros. These are an
   *output contract* for ncc-emitted code, not core types.
3. **The GC-stack-map / `setjmp` runtime API** — used by **4** TUs.

Only ~25 TUs reference a GC-map/scan symbol in hand-written code; only 4 use the
stack API. The 90% coupling is a header-placement artifact: ncc-emitted code
references the bucket-2 structs *by name* (ncc emits no `#include`), and those
structs live in `n00b.h`, so every TU that includes `n00b.h` for bucket 1 inherits
a build dependency on bucket 2.

## Why per-TU `#include` injection is not enough

The type→GC-map dictionary is inherently **whole-program**: one entry per
pointer-bearing aggregate type, looked up at allocation regardless of which TU
allocates. Today ncc emits, per TU, *typed* aggregates into linker sections
(`n00b_gcmap`/`n00b_gcidx`; `xform_gc_typemap.c:1472-1511`), e.g.:

```c
static const uint64_t            __ncc_gcmap_off_N[] = { (__builtin_offsetof(T,f)/sizeof(void*)), ... };
static const n00b_gc_struct_layout_t __ncc_gcmap_lay_N = { .offsets = __ncc_gcmap_off_N, ... };
[[section("n00b_gcmap")]] static const n00b_gc_type_map_entry_t __ncc_gcmap_ent_N =
        { .type_hash = 0x..ULL, .layout = &__ncc_gcmap_lay_N };
```

Because most TUs define pointer-bearing aggregates, most TUs emit these typed
aggregates, so merely moving the structs to a new header that ncc `#include`s
per-TU would keep ~most of the coupling. The dependency has to be *removed*, not
relocated.

## Key observation

Every *value* emitted above is already a compile-time constant: `offsetof`
(resolved by the C compiler where the type is complete), typehash literals, counts.
**The only thing that needs the ABI struct *types* is the typed designated-initializer
wrapper.** The data does not. So the two jobs fused in the per-TU emitter can split:

- **Per-TU, unavoidable:** compute `offsetof` (needs the complete type, only present
  in the defining TU) and drop the resolved numbers as raw words. No ABI type needed.
- **Whole-library, once:** assemble those numbers into the typed, deduped, sorted
  dictionary. This is the only place the ABI structs are needed — the pre-link step.

## Target architecture

### Headers

- **`include/core/codegen_abi.h`** (new) — bucket 2: `n00b_gc_root_t`,
  `n00b_gc_root_section_entry_t`, `n00b_gc_scan_kind_t`/`_cb_t` + scan-cb externs,
  `n00b_gc_struct_array_t`, `n00b_gc_variant_arm_t`, `n00b_gc_variant_field_t`,
  `n00b_gc_struct_layout_t`, `n00b_gc_type_map_entry_t`/`_index_entry_t`, the
  `n00b_transient_*` cluster, `n00b_static_object_desc_t`, `n00b_static_identity_t`
  + kind enum, and the `N00B_*_SECTION` macros. Includes `n00b.h` for the scalar
  typedefs it builds on. Included **only** by: the pre-link-generated TU, the
  GC/marshal runtime readers (`gc_type_map.c`, `transient_map.c`, `gc_map.h`), and
  the pre-link tool. **Not** by `n00b.h`.
- **`include/core/gc.h`** — bucket 3: the `n00b_gc_stack_*` types, `n00b_jmp_buf_t`,
  `n00b_setjmp`/`n00b_longjmp`, policy/push/pop API. Used by ~4 TUs.
- **`include/n00b.h`** — bucket 1 only.

### Per-TU emission (ncc) — raw, untyped

ncc stops emitting typed aggregates. Instead, per eligible type, it emits one
self-describing `uint64_t` record into section **`n00b_gcraw`**:

```
word[0]  record_words      (total words incl. this header; lets the reader walk linearly)
word[1]  kind              (1 = typemap, 2 = root table, 3 = transient — extensible)
word[2]  type_hash
word[3]  stride_words
word[4]  n_fixed_offsets
word[5..]                  fixed pointer offsets (word units, via offsetof)
         n_variants, then per variant: selector_offset, n_arms,
                       per arm: selector, n_ptr_offsets, offsets...
```

`offsetof` stays in the initializer (`(__builtin_offsetof(T,f)/sizeof(void*))`), so
the compiler resolves it where the type is complete. No `n00b_gc_*` type is named,
so **the TU no longer depends on `codegen_abi.h`.** A versioning word in the section
header guards the format.

### Pre-link aggregation — an ncc link-stage pass, typed, once

ncc is already the **link driver** and already does the exact pattern this needs:

- `ncc_link_passthrough` / `maybe_comptime_link_passthrough` (ncc.c) own the link
  step and enumerate all linker-input objects (`ncc_link_inputs_t`).
- `compile_entry_object` (comptime_build.c:387) already *generates a C source,
  compiles it to a temp `.o`, and appends it to the link argv* — generate → compile
  → inject is existing, working machinery.
- `ncc_read_comptime_metadata_inputs` + `&agg` (ncc.c:2153) already *reads per-TU
  metadata from the link inputs and aggregates it at link time* — whole-program
  aggregation is an existing capability.

So the aggregator is **not a separate tool**: it is a link-stage pass in ncc behind
a flag (e.g. `--ncc-gcmap-prelink`). At link, ncc reads every `n00b_gcraw` record
from the input objects (offsets already compiler-resolved per-TU), dedups by
`type_hash`, sorts, generates `n00b_gcmap_generated.c`, compiles it via the existing
`compile_entry_object` path, and links it in:

```c
#include "core/codegen_abi.h"
static const uint64_t __g_off_K[] = { ... };                  // copied resolved ints
static const n00b_gc_struct_layout_t __g_lay_K = { ... };
const n00b_gc_type_map_entry_t n00b_gcmap_table[] = { /* sorted by type_hash */ };
const size_t                    n00b_gcmap_count = K;
```

The runtime binary-searches `n00b_gcmap_table` directly. This **retires the
`n00b_gcidx` linker section and the post-link `n00b-gcmap-index` index-fill** for
the typemap path (dedup/sort now happen once, at generation), though the tool can
stay for external/pre-built binaries during transition.

### Result

Editing a `codegen_abi.h` struct rebuilds the one generated TU + the ~25 GC/marshal
runtime readers — not ~460 TUs. Per-TU `offsetof` correctness is preserved.

## Tradeoff

The `n00b_gcraw` record layout becomes a versioned contract between ncc's emitter and
the aggregator, replacing the compiler's field-name checking of the typed wrappers.
The single generated file is still type-checked against `codegen_abi.h`, so the
contract is checked in the one place layout actually matters; the raw format is
guarded by its version word.

## Phasing (each phase keeps the build green)

- **Phase 1 — n00b-only, safe, independently shippable.** Create `codegen_abi.h`
  with the bucket-2 structs; have `n00b.h` `#include` it at the very end (after the
  scalar typedefs it depends on — circular-include-safe via `#pragma once`). Move
  bucket 3 to `core/gc.h`. **Delete** the dead `n00b_static_image_*` contract (0
  refs tree-wide, orphaned by ncc WP-010 #37), the duplicate `typedef uint64_t
  n00b_size_t`, and the stale `include/core/.#*.h` lock symlinks. Move
  `n00b_static_identity_query_t`/`_status_t` to `core/static_objects.h` (used by 3
  tests + that header). No ncc change; per-TU emission still resolves via
  `n00b.h → codegen_abi.h`. *No blast-radius win yet — this is reorganization +
  dead-code removal that makes the rest tractable.*
- **Phase 2 — ncc PR.** Add raw `n00b_gcraw` emission behind a flag; keep the typed
  path available for rollback. Update ncc `docs/gc_typemaps.md`.
- **Phase 3 — ncc link-stage aggregation.** Add the `--ncc-gcmap-prelink` pass that
  reads `n00b_gcraw` from link inputs, dedups/sorts, and generates+compiles+links
  `n00b_gcmap_generated.c` via the existing `compile_entry_object` path. Switch the
  runtime to read `n00b_gcmap_table`. Meson change is just passing the flag on the
  link step — no `extract_all_objects`, no separate tool target.
- **Phase 4 — cut over and decouple.** Flip ncc to raw-only; remove the
  `#include "core/codegen_abi.h"` line from `n00b.h`; add explicit includes to the
  runtime readers; retire `n00b_gcidx`/post-link index for the typemap path.
- **Phase 5 — roots + transient** through the same raw pipeline; update
  `docs/gc_type_maps.md`.

## CRITICAL CORRECTION (stable vs volatile) — read this first

Phase 1 was too coarse: it moved BOTH the stable allocator scan API AND the volatile
descriptor structs into `codegen_abi.h`. The pervasive headers (`alloc.h`, `list.h`,
`string.h`, `buffer.h`, `dict.h`; ~58 TUs) only use the **stable** API
(`n00b_gc_scan_kind_t`, `n00b_gc_scan_cb_t`, `n00b_gc_map_t` fwd, `N00B_GC_SCAN_KIND_*`),
which never churns. So that API was moved BACK into `n00b.h` (done); `codegen_abi.h`
now holds ONLY the volatile, ncc-emitted descriptor structs (the ones that actually
churn: typemap layout/variant, static-object desc/identity, transient, roots, stack
maps, section macros).

Why the win still isn't deployed: removing `#include "core/codegen_abi.h"` from
`n00b.h` is only safe once NO ncc-emitted code in the ~460 TUs names a volatile struct.
Two emitters are pervasive:
- **Typemap** → emitted into ~most aggregate-defining TUs. SOLVED via raw `n00b_gcraw`.
- **Static-object descriptors** → emitted into **145/537 TUs** (measured: `r"…"`/`b"…"`
  literals; build enables it via `--ncc-rstr-*` + `--ncc-static-object-entry-attr`).
  NOT solved — this is THE remaining pervasive blocker; needs the same raw treatment
  as the typemap.
Narrow emitters (don't block much): roots (~28 TUs with static managed globals; manual
`n00b_gc_register_root` call sites are a SEPARATE GC-efficiency cleanup — they call a
fn declared in core/gc.h, they don't name volatile structs; user says most are
redundant with --ncc-auto-gc-roots), stack-maps (~4-5 files). These can be
include-injected or kept (small blast radius) without blocking the win.

Hand-written volatile-struct users that need an explicit `#include "core/codegen_abi.h"`
once n00b.h drops it: typemap-struct files (gc_map.c, gc_type_map.c, alloc.c, init.c,
marshal.c, slay/codegen.c, + crash_capture.h, gc_map.h, slay/symtab.h) and static-obj
files (~15: static_objects.c, static_image.c, gc_baked.c, mmaps.c, crt, json.c, etc.).

Remaining path to the measurable win: (1) stable/volatile split [DONE]; (2) raw-ify
static-object descriptors like the typemap; (3) handle narrow emitters
(inject/keep) + roots cleanup [needs user input on dynamic roots]; (4) Phase 4 runtime
reads the generated dict for typemap AND static-objects; (5) remove the n00b.h include,
build flip, measure, GC/marshal tests.

## FINISHED + MEASURED (2026-06-24, type-name-free inject slice)

The remaining blocker — `codegen_abi_inject.h` force-included into ~564 TUs — is
resolved. ncc now emits ALL its descriptors **type-name-free** (anonymous structs
with primitive-spelled fields matching the real layouts), so no force-include is
needed and the dependency collapses:

- **`include/core/codegen_abi_inject.h`: 564 → 27 TU dependents** (`ninja -t deps`,
  mtime-independent). The 27 are exactly the genuine users: the GC/marshal/
  static-object runtime (alloc, gc, gc_baked, init, memory_info, mmaps,
  static_image, static_objects, transient_map, crt, json, rocs/map, rocs/shard,
  comptime_image, marshal), the layout-guard TU, and 11 GC/marshal/static-object
  test TUs. **Zero application/tool TUs.** (A `ninja -n` touch test shows 44
  perpetually-dirty tool/example TUs that rebuild on every ninja run regardless —
  a pre-existing build quirk, not header deps.)
- `codegen_abi.h` unchanged at 9.
- The build no longer force-includes any codegen-ABI header (only `n00b.h`).

How (the type-name-free emission):
1. **ncc emitters** (ncc worktree, all `src/xform/`): identity
   (`xform_static_object.c`, anonymous struct + `ncc_static_identity_kind_numeric`
   enum→int map), static-object descriptor (`xform_array_literal.c`, anon struct;
   scan_cb forward-declared inline with the real `(n00b_gc_map_t*, void*)` sig —
   that type is in n00b.h, not the ABI header — and cast to the field's structural
   pointer type), GC roots (`xform_gc_globals.c`), transient
   (`xform_gc_typemap.c`), GC stack maps (`xform_gc_stack_maps.c`, anon slot/map/
   frame + inline `void*` push/pop externs). Section-resident pointers and
   cross-struct pointers are emitted as `const void *` (byte-identical).
2. **stack push/pop signatures → `void*`** in both the header decl and the gc.c
   definitions, so the emitted externs stay compatible with the header in the
   hand-written TUs that include it (meson can't give the monolithic libn00b
   per-source c_args, so per-file `--ncc-no-gc-stack-maps` was not an option).
3. **r-string descriptor templates** in `meson.build` (the pervasive 145-TU path)
   rewritten to the anonymous `n00b_sodesc` struct.
4. **Pointer-only header users** (runtime.h 170×, alloc_base.h, mmaps.h, gc.h,
   comptime_image.h) covered by 3 forward typedefs added to `n00b.h` (zero added
   cost — n00b.h is already universal). Only `gc_baked.h` (enum constant) and
   `static_objects.h` (by-value macro) `#include` the full header; genuine `.c`
   users include it explicitly.
5. **`src/core/codegen_abi_guard.c`** (NEW): the single layout tripwire —
   `_Static_assert`s sizeof + every offsetof of each real struct against reference
   structs mirroring the emitted layout. It is the only TU that *must* rebuild on
   a header edit. Verified: it compiles green (no drift).

VERIFY: full build green (704 targets / 92 link targets). All 17 GC/marshal/
static/transient suites pass: gc, gc_scan_map, gc_selective_scan,
gc_type_map_register, gc_auto_roots_e2e, gc_register_roots_api, marshal_type_layout,
object_marshal, transient_zero, merkle, merkle_transient, static_object_sections,
static_descriptor, ncc_static_objects, ncc_static_images, xform_marshal,
writable_baked_gc. The two PRE-EXISTING failures reproduce identically (verified
failure sites unchanged): `marshal` at
`assert_failed_inplace_relocate_discards_deferred_patch` (test_marshal.c:608);
`rocs_map_gc_region` at the `n00b_file_open(temp).is_ok` requirement
(test_rocs_map_gc_region.c:149, env/temp-dir). Neither is GC under-scan.

## DEPLOYED + MEASURED (2026-06-24, successor session)

The decoupling is shipped end-to-end and measured. Authoritative
dependency-graph result (`ninja -t deps`, mtime-independent):

- **`include/core/codegen_abi.h` (volatile: typemap/variant/transient dictionary
  structs) — 9 TU dependents**, down from **559**. Touching it now rebuilds only
  the GC/marshal runtime readers (alloc.c, gc_map.c, gc_type_map.c,
  transient_map.c, marshal.c, json.c, rocs/map.c, rocs/shard.c, slay/codegen.c),
  not the world.
- `include/core/codegen_abi_inject.h` (NEW, stable: roots / stack-maps /
  static-object descriptors / transient structs + scan-cb externs) — 559 TU
  dependents, but it is force-included (`-include`) and rarely changes.
- `n00b.h` no longer includes any codegen ABI header.

How it was done (differs from the original recipe because in THIS build the
executables are linked by the ObjC compiler, not ncc, so ncc's own link-stage
hook never fires):

1. **Header split.** `codegen_abi.h` keeps only the volatile dictionary structs
   (read by the 9 runtime TUs + the generated dict). The stable slice ncc-emitted
   code references by name in arbitrary TUs (roots, stack-maps, static-object
   descriptors, transient structs, scan-cb externs) moved to the new
   `codegen_abi_inject.h`, which the build force-includes via
   `-include core/codegen_abi_inject.h`. `gc_map.h`/`symtab.h` now forward-declare
   `n00b_gc_struct_layout_t` (tagged) instead of including the volatile header.
2. **ncc raw emission** (`--ncc-gcmap-prelink`, flipped on in `exe_c_args`): per-TU
   raw `n00b_gcraw` records, no typed gcmap structs. (The ncc codegen-abi branch
   was rebased onto ncc `main` to also carry the WP-001 transient-attr emission;
   transient stays TYPED, hence its structs live in the force-included header.)
3. **ncc standalone aggregator** `--ncc-gcmap-emit=OUT INPUTS...` (new): reads
   `n00b_gcraw` from objects/archives, emits the typed `n00b_gcmap_table[]`/
   `_count` object (empty/count==0 when no records). `ncc_gcmap_emit_to_path` in
   comptime_build.c.
4. **Per-executable aggregation at link** via `scripts/ncc-gcmap-objc-link-wrapper.sh`,
   slotted in as `OBJC` by build.sh: passes ObjC compiles through to Apple clang,
   and on link runs `--ncc-gcmap-emit` over the link inputs (the executable's own
   TUs + libn00b.a, so the dict is complete and per-executable correct) and
   appends the dict object. The lone ncc-linked target that links libn00b
   (`test_ncc_static_images`, `link_language:'c'`) instead enables ncc's own
   link-stage hook via `--ncc-gcmap-prelink`/`--ncc-gcmap-include` on its link args.
5. **Phase 4 runtime** (`gc_type_map.c`): binary-searches the generated sorted
   `n00b_gcmap_table` when present (weak), else the legacy section path.

VERIFY: full clean build green (704 targets). GC/marshal/static/transient suites
pass — `gc`, `gc_scan_map`, `gc_selective_scan`, `container_scan_kind`,
`gc_type_map_register`, `gc_auto_roots_e2e`, `gc_register_roots_api`, `gc_census`,
`marshal_type_layout`, `object_marshal`, `type_static_layout`, `transient_zero`,
`merkle`, `merkle_transient`, `static_object_sections`, `static_descriptor`,
`ncc_static_objects`, `ncc_static_images`, `grammar_marshal_roundtrip`,
`xform_marshal`, `writable_baked_gc` all OK. Two failures (`marshal`,
`rocs_map_gc_region`) are PRE-EXISTING — both reproduce identically on pristine
n00b `main` with this ncc (verified): `marshal` aborts in
`assert_failed_inplace_relocate_discards_deferred_patch`; `rocs_map_gc_region`
fails `n00b_file_open(temp).is_ok` (environment/temp-dir). Neither is GC under-scan
and neither is caused by this work.

LEFT FOR THE HUMAN / FUTURE:
- Manual `n00b_gc_register_root` optimization (the 29 call sites, 11 in init.c):
  left untouched as optional future work (redundant root registration is harmless;
  removing a genuinely-dynamic one would under-scan).
- `marshal` / `rocs_map_gc_region` pre-existing failures (ncc-`main`/env, not this
  work) — flagged for separate triage.
- The ncc codegen-abi branch now sits on ncc `main` (rebased, with conflicts in
  `xform_gc_typemap.c` resolved to keep both transient + raw-gcraw emission). The
  installed `~/.local/bin/ncc` is this build.

## Status (live)

- **Phase 1 — DONE, verified.** `core/codegen_abi.h` created; `n00b.h` 488→228 lines;
  duplicate `n00b_size_t` and stale `.#` lock files removed. Full `build.sh
  --no-build-tests` build green (704/704 targets, `libn00b.a` links). Both include
  orders pass clang C23 `-fsyntax-only`.
- **Phase 2 (typemap) — DONE, verified.** `--ncc-gcmap-prelink` flag added (default
  off) in the ncc worktree. `xform_gc_typemap.c` emits flat `n00b_gcraw` `uint64`
  records (variant asserts split into their own buffer; emitted in both paths).
  ncc rebuilds clean. Verified on `test_gc_typemap_variant.c`: raw mode emits
  structurally-correct records (record_words counts check; aggregate-arm offsets
  present; typehashes match the typed path) and **zero `n00b_gc_*` typed references**;
  typed path unchanged with the flag off. Record layout (all words `uint64`):
  `[record_words, kind=1, type_hash, stride_words, n_fixed, <fixed offsets...>,
  n_variants, per-variant{selector_offset, n_arms, per-arm{selector, n_offs,
  <offsets...>}}]`. Offsets are `(__builtin_offsetof(T,f)/sizeof(void*))`.
- **Phase 2 (roots, transient) — TODO.** Still on the typed path (smaller blast
  radius); migrate after the typemap pipeline is proven end-to-end.
- **Phase 3 core — DONE, VERIFIED end-to-end on real bytes.**
  `src/parse/gcmap_prelink.{c,h}` (registered in ncc `meson.build`): `ncc_gcraw_parse`
  (bounded record parser, dedups by type_hash, rejects malformed/truncated sections
  via a per-record `p != end` check) + `ncc_gcraw_generate_c` (typed `n00b_gcmap_table[]`
  + `n00b_gcmap_count`, sorted by hash, integer offset literals,
  `#include "core/codegen_abi.h"`). Verified: `ncc -c --ncc-gcmap-prelink` on the
  variant fixture → 52-word `n00b_gcraw` Mach-O section → `llvm-objcopy --dump-section`
  → harness (links `libncc_internal.a`) parsed 5 unique records → generated dict
  compiles against `codegen_abi.h`; stride/offset/variant values all match the typed
  path's `offsetof`/`sizeof`. Also fixed: `derive_gc_section_attr` fallback now
  Mach-O-correct (`__DATA,<name>`) so the section is valid without a static-object attr.
  Harness at `/tmp/gcraw_harness.c`; reproduce via the commands in this session.
  NOT yet wired into the link (glue is now just automating those proven steps).
- **`--ncc-gcmap-include=DIR` flag — DONE.** Accumulating opt
  (`opts->gcmap_includes`), parsed in ncc.c (mirrors `add_comptime_arg`). The n00b
  build passes this on the LINK command; the glue adds each as `-I` when compiling the
  generated dict. ncc builds green.
- **Phase 3 orchestrator — DONE, VERIFIED end-to-end.**
  `ncc_gcmap_prelink_build_object` (comptime_build.c) + `ncc_ct_read_object_section`
  (comptime_meta.c, public). Verified in isolation (harness `/tmp/glue_harness.c`
  linking `libncc_internal.a`): given the real `variant.o`, it read `n00b_gcraw` →
  parsed → generated → compiled `n00b_gcmap_generated.o`, which exports
  `_n00b_gcmap_table` + `_n00b_gcmap_count` (confirmed via `llvm-nm`). ncc builds green.
- **Phase 3 archive expansion — DONE, VERIFIED.** `ncc_ct_read_input_section`
  (comptime_meta.c, public) handles `.o` and `.a` (extracts members, concatenates each
  member's `n00b_gcraw` — valid because records self-delimit). Orchestrator now calls
  it per input. Verified: built `libvariant.a` from `variant.o`, ran the orchestrator
  harness on the archive → produced `n00b_gcmap_generated.o` exporting
  `n00b_gcmap_table`/`n00b_gcmap_count`. ncc builds green.
- **Phase 3 link hook — DONE, VERIFIED end-to-end through the real link driver.**
  Hooked in `main()` (ncc.c) at the single `!opts.input_file` chokepoint (covers all
  link paths): when `opts.gcmap_prelink`, collect `is_linker_input` args → run
  `ncc_gcmap_prelink_build_object` → append the generated dict `.o` to the link argv.
  Verified: `ncc -c --ncc-gcmap-prelink` then `ncc v.o -o exe --ncc-gcmap-prelink
  --ncc-gcmap-include=<inc>` → the hook auto-generated + linked the dict; the binary
  exports `n00b_gcmap_table`/`n00b_gcmap_count` (llvm-nm) and runs. **PHASE 3 COMPLETE.**
  GC-safe pre-Phase-4: raw mode emits no typed gcmap/gcidx sections, so the current
  section-based runtime lookup finds nothing → conservative scan (safe), while the
  dict symbols sit ready for Phase 4.
- **Phase 3 link glue — original notes (now mostly implemented; see above):** The dict
  is whole-program, so generate it at the **final executable link** (when all `.o` +
  `.a` inputs, incl. `libn00b.a` members, are present), NOT at the static-lib build.
  Steps:
  1. Expose `find_objcopy` / `dump_section` / `extract_archive_members` from
     comptime_meta.c (drop `static`, add prototypes to comptime_meta.h).
  2. New glue (put in comptime_build.c — has `append_compile_target_args` + the
     compile pattern): for each `inputs.user_inputs` ending `.o`/`.a` (expand `.a` via
     `extract_archive_members`), `dump_section(__DATA,n00b_gcraw / n00b_gcraw)` to a
     temp, read bytes, feed all into one `ncc_gcraw_set_t` via `ncc_gcraw_parse`
     (dedups across the whole link). If the set is empty → no dict, return.
  3. `ncc_gcraw_generate_c(set)` → temp `.c` → compile with `opts->compiler` +
     `append_compile_target_args` + `-std=gnu23` + each `opts->gcmap_includes` as
     `-I` + `-c -o` → append the `.o` to the final link argv.
  4. Hook in `maybe_comptime_link_passthrough` gated on `opts->gcmap_prelink`, BUT it
     must also run on the pure-link (non-comptime) path — today `n_metadata_inputs==0`
     early-returns. Add the gcmap object to whatever final link executes.
  - Verified core (this session): `ncc -c --ncc-gcmap-prelink` → 52-word `n00b_gcraw`
    section → objcopy dump → parse (5 records) → generate → compiles. Glue just
    automates this across all link inputs.
- **Phase 4 — TODO** (recipe below).

## Phase 3 recipe (concrete — reuse `comptime_meta.c`)

ncc's comptime-metadata pipeline already does object-section surgery; reuse it:
- `find_objcopy()` / `find_ar()` — locate `llvm-objcopy` / `llvm-ar`.
- `dump_section(objcopy, obj, "n00b_gcraw", ...)` — get the section's raw bytes
  (the compiler has resolved `offsetof`/`sizeof` to integers). `extract_archive_members`
  handles `.a` inputs.
- Parse the byte stream as `uint64` words; walk records by `record_words[0]`; dedup
  by `type_hash` (word 2).
- Generate `n00b_gcmap_generated.c` (`#include "core/codegen_abi.h"`) with the typed
  `n00b_gc_struct_layout_t` + sorted `n00b_gc_type_map_entry_t n00b_gcmap_table[]` +
  `n00b_gcmap_count`. Compile + inject via the `compile_entry_object` path.
- `remove_section` the now-redundant `n00b_gcraw` from the final link (optional).
- Hook this into `maybe_comptime_link_passthrough` when `--ncc-gcmap-prelink` is set.

### Phase 3 link-glue specifics (for the implementer)

- Compile the generated dict by mirroring `compile_entry_object`
  (comptime_build.c:419-468): write the `ncc_gcraw_generate_c` text to a temp `.c`,
  run `opts->compiler` with `append_compile_target_args` + `-std=gnu23 -c -o`, append
  the resulting `.o` to the link argv.
- Reuse comptime_meta's `find_objcopy` / `dump_section` / `extract_archive_members`
  (currently `static`) — expose them via `comptime_meta.h`, or put the glue function
  inside `comptime_meta.c` to keep using them directly.
- **Include-path decision — DECIDED (a).** The generated TU keeps
  `#include "core/codegen_abi.h"` (single source of truth for the ABI layout; option
  (b)'s inline struct defs were rejected because a silent layout drift between the
  generated TU and the runtime's view would mis-scan = heap corruption). The n00b
  build must therefore pass the include dir on the link step: add a
  `--ncc-gcmap-include=DIR` opt (mirror the existing flag plumbing) and append it to
  the generated-dict compile argv; have `meson.build`/`build.sh` pass
  `--ncc-gcmap-include=<n00b>/include` (+ any generated-include dirs) on the link.
  `ncc_gcraw_generate_c` already emits the include, so no generator change needed.
- End-to-end smoke test once glued: `ncc -c file.c --ncc-gcmap-prelink` →
  `llvm-objcopy --dump-section=n00b_gcraw` → feed bytes through parse+generate; the
  generated dict's offsets must match the typed path's `offsetof` values for the
  same types.

## Phase 4 recipe (n00b runtime + decouple)

- `src/core/gc_type_map.c`: read the generated `n00b_gcmap_table`/`n00b_gcmap_count`
  (binary search) instead of the `n00b_gcmap`/`n00b_gcidx` sections + post-link index.
- Drop `#include "core/codegen_abi.h"` from `n00b.h`; add explicit includes to the
  GC/marshal runtime readers (`gc_type_map.c`, `transient_map.c`, `gc_map.h`) and
  anything that instantiates the ABI by hand.
- Flip `--ncc-gcmap-prelink` on in `meson.build`/`build.sh`; retire the post-link
  `n00b-gcmap-index` for the typemap path.
- **Verify:** GC + marshal test suites must pass (guards against under-scan), then
  confirm: editing a `codegen_abi.h` struct rebuilds ~dozens of TUs, not ~460.

## Open risk to settle before Phase 3

Lower than first thought, since the aggregation rides ncc's existing link path.
Remaining unknowns: (1) reading the `n00b_gcraw` section from link-input objects
across Mach-O/ELF/PE — reuse the readers behind `n00b-gcmap-index` /
`compiler/objfile`; (2) confirm the generated TU links into both `libn00b` and the
helper-binary links that currently run the post-link `--exec` indexer, so the two
paths don't double-emit a dictionary during the transition.
