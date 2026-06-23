# Mach-O Object Bundles

This is the Mach-O companion to [Object Bundles](object_bundles.md). The
object-bundle model, manifest format, policy semantics, extraction, and
execution planning are format-neutral and are described there. This document
covers what is Mach-O-specific: how a bundle is carried inside a Mach-O binary,
how the backend rewrites the binary safely, how placement and signing interact,
and what is and is not implemented today.

The public object-bundle API is one cross-format surface in
`include/compiler/objfile/obj_bundle.h`. Callers select Mach-O with
`.format = N00B_FMT_MACHO` (or rely on auto-detection); the Mach-O carrier
mechanics stay behind the same entry points. As with ELF, the public header
Doxygen is the precise call-level contract; this document summarizes the
caller-visible model.

## Overview & Layer Ownership

Mach-O support is a backend under the unchanged format-neutral bundle core. The
core reaches a format backend through exactly two dispatch hooks in
`src/compiler/objfile/obj_bundle.c` — one for `n00b_obj_bundle_read()` and one
for `n00b_obj_bundle_write()`. When the effective format is `N00B_FMT_MACHO`,
those hooks route to the Mach-O carrier backend; everything downstream of a
successful read (extraction, execution planning, policy evaluation) is the same
neutral core used for ELF, with no Mach-O-specific logic past the carrier
boundary.

The Mach-O backend deliberately mirrors the ELF backend's decomposition. Strict
dependency direction is downward only: each layer knows nothing about the layers
above it.

| Layer | Owns | Does not own |
|-------|------|--------------|
| Carrier backend (`obj_bundle_macho`) | Mapping a carrier request to a Mach-O rewrite; carrier descriptor validation; reserved-namespace/guard checks; selected-carrier authority. | Bundle manifest tables, extraction policy, execution selection (all neutral-core). |
| Rewrite (`macho_rewrite`) | Plan + apply: surgical metadata insert/replace/delete; loadable `LC_SEGMENT_64` insert with `__LINKEDIT` relocation and load-command offset patching; arm64 `LC_MAIN` entrypoint redirect. | Bundles, manifests, or signing. |
| Admission (`macho_rewrite_admit`) | Loader-safe admission verdicts plus structured rejection reasons. No bytes, no plan. | Plans or emitted bytes. |
| Layout (`macho_layout`) | File-offset and virtual-address interval/occupancy facts: classification, coverage, gap and EOF-tail search, collision summaries. Facts only. | Whether any rewrite is admissible. |
| Parse (`macho.h`) | Full Mach-O parse (fat, `LC_*`, `LC_MAIN`, `LC_CODE_SIGNATURE`). | Anything above. |

Fat/universal handling layers over the single-slice rewrite engine
(`macho_fat_rewrite`), and signing reconciliation reuses the existing chalk
resign path; both are invoked from the carrier write path, not from the rewrite
layer. The rewrite layer never owns signing.

### Backend layer map

```
neutral bundle core (unchanged)
        │  (2 hooks: read / write)
        ▼
obj_bundle_macho   Mach-O carrier backend  ──► strip → rewrite → resign (chalk)
        │
        ▼
macho_rewrite      plan + apply: surgical / loadable / LC_MAIN redirect
        │                       └── macho_fat_rewrite (per-slice + re-fat)
        ▼
macho_rewrite_admit  loader-safe verdict + structured rejection reasons
        │
        ▼
macho_layout         file-offset + vmaddr interval/occupancy facts
        │
        ▼
macho parse          n00b_macho_binary_t / n00b_macho_fat_t
```

The write path runs admit → plan → (optionally enable entrypoint) → apply, then
hands the rewritten bytes to signing reconciliation. The read path locates the
reserved N00b carrier region, validates it, and decodes the canonical bundle
through the neutral codec.

### Two coordinate spaces: file offset vs. vmaddr

Every Mach-O rewrite reasons about two distinct coordinate spaces, and the
layout model tracks them separately:

- **File offset** — where bytes physically live in the object file. The
  signature must be last, inside `__LINKEDIT`, which must be the last segment,
  and the file must end exactly at `__LINKEDIT`'s end. Load commands grow only
  into the header slack between the end of the load-command region and the first
  section's file offset.
- **Virtual address (vmaddr)** — where a segment is mapped at run time. A
  loadable segment needs a page-aligned vmaddr above the last non-`__LINKEDIT`
  segment, and `__LINKEDIT` slides up in both file and VM order when a loadable
  segment is inserted before it.

The layout model records segment file extents and VM extents as separate
intervals (along with the load-command region, sections, the symtab/strtab and
`__LINKEDIT` sub-regions, the code-signature region, and any trailing overlay).
Keeping the two spaces distinct is what lets admission decide loader safety and
lets the rewrite layer patch the correct `__LINKEDIT`-referencing offsets when a
segment moves. The arm64 `LC_MAIN` `entryoff` is itself a file-offset-style
delta relative to `__TEXT` (the loader computes the entry VM address as
`__TEXT.vmaddr + entryoff`), so the two-space distinction is also what makes the
entrypoint redirect well-defined.

## Carrier Kinds & Reserved Namespace

Mach-O supports the same three carrier kinds as ELF, expressed through the
neutral `n00b_obj_bundle_carrier_t` request (`AUTO` / `METADATA` / `LOADABLE` /
`SPLIT`). `AUTO` and explicit `METADATA` both write the metadata carrier; the
backend never silently upgrades to a loadable or split carrier.

| Carrier | Where the bundle physically lives |
|---------|-----------------------------------|
| Metadata | The complete canonical bundle bytes live non-loaded, appended at the end of `__LINKEDIT` and described by an `LC_NOTE`, before the (re-added) signature. This reuses the exact insert mechanism chalk's marking already ships, so it carries the least feasibility risk. |
| Loadable | The complete canonical bundle bytes live in a new loader-visible `LC_SEGMENT_64`, with a descriptor in the metadata `LC_NOTE` recording the payload's file offset, length, and SHA-256 digest. This is the path that supports execute-from-bundle. |
| Split | A descriptor plus the **excised** executable-compatible payload slices in the new `LC_SEGMENT_64`, with the skeleton and reconstruction records carried in the metadata `LC_NOTE`. See the SPLIT model below. |

The descriptor is a fixed 64-byte little-endian header (its own Mach-O magic,
version, header size, carrier kind, payload file offset, payload length, and a
32-byte SHA-256 payload digest), stored inside the `LC_NOTE` payload — never in
a bare load-command field — so it is covered by the code-signature hash like
every other carrier byte. The metadata carrier needs no descriptor: the reader
discriminates "descriptor present" (LOADABLE/SPLIT) from raw metadata by the
presence of the descriptor magic.

### SPLIT carrier model

The Mach-O split carrier is a true ELF-mirrored *excised* split, not a degenerate
whole-bundle copy. The executable-compatible payload slices are physically
excised from the canonical bundle into the loadable `LC_SEGMENT_64`. What remains
— the canonical bundle minus those slices — is the **skeleton**, stored as a
contiguous blob in the carrier's `LC_NOTE` trailer alongside per-slice
reconstruction records. Each reconstruction record maps a slice's offset and
length in the segment to its offset in the rebuilt canonical bundle, and carries
a fast CRC-32 structural pre-check. On read, the backend interleaves the skeleton
gaps with the segment slices by reconstruct-offset to rebuild the exact canonical
bytes; the CRC-32 is only a cheap pre-check, while the bundle-level SHA-256 over
the reconstructed canonical bytes is the real integrity gate, re-validated by the
neutral core before decode.

A SPLIT request whose bundle has no executable-compatible artifact slice cannot
form a split carrier; the backend rejects it with a structured carrier error
(surfaced through the neutral error channel, see *Structured carrier errors*
below) rather than producing a degenerate carrier.

### Reserved namespace & guard policy

ELF reserves the `.0c001.*` section namespace and an `SHT_GUARD` lock section.
Mach-O has no section-name convention or guard section type, so the analog is
expressed through the carrier identifier:

- **Reserved identifier.** The metadata `LC_NOTE`'s `data_owner` string
  (`n00b.0c001`) is the reserved N00b carrier identifier. Any `LC_NOTE` whose
  owner falls under this root is treated as N00b-owned reserved namespace.
- **Guard marker.** A distinguished reserved marker means "this binary is
  wrapped/locked; do not re-wrap or silently overwrite."
- **Replacement / rejection policy** (mirroring the ELF write post-conditions, and
  reusing the existing neutral `n00b_obj_bundle_error_code_t` values verbatim — no
  new error surface):
  - No reserved occupant present → write the carrier.
  - A unique, valid, N00b-owned bundle carrier present → replace **only** with
    `N00B_OBJ_BUNDLE_REPLACE_EXISTING`; otherwise reject as replacement-required.
  - Reserved-but-foreign occupant → reject; replacement never authorizes
    importing or overwriting foreign or legacy carriers.
  - Guard marker present → reject regardless of `replace`.
  - Malformed or duplicate N00b carriers → reject regardless of `replace`.

This satisfies FR-17 (metadata carrier), FR-18 (loadable carrier), FR-19 (split
carrier), and FR-20 (reserved-namespace/guard), with the two dispatch hooks
wiring `N00B_FMT_MACHO` into the neutral API (FR-21).

## Placement, Fat Binaries & Signing

### `__LINKEDIT`-aware placement

All carrier placement respects the Mach-O loader invariants: the signature is
last, inside `__LINKEDIT`, which is the last segment, and the file ends at
`__LINKEDIT`'s end. The metadata carrier appends its bytes at the end of
`__LINKEDIT` and grows `__LINKEDIT`'s file/VM size to cover them — the
low-risk, chalk-proven mechanism. The loadable and split carriers insert a new
`LC_SEGMENT_64` **before** `__LINKEDIT` in both file and VM order, which slides
`__LINKEDIT` up; the rewrite layer then patches every load command whose offsets
point into `__LINKEDIT` (symtab/strtab, chained fixups, function starts,
data-in-code, and the rest of the `__LINKEDIT`-referencing set that is actually
present) by the same delta. A new load command can only grow into the header
slack between the load-command region and the first section; when that slack is
insufficient, the rewrite performs a `__TEXT` section reflow rather than failing
outright. Admission rejects loader-unsafe requests with a structured reason
before any bytes are emitted.

### Fat / universal binaries

Fat (universal) containers are handled per-slice. The default policy applies the
bundle carrier to the arm64 slice only; every non-arm64 slice is parsed and
passed through byte-identical (arm64-first, D-002). Each rewritten slice is fed
to the thin rewrite engine as a detached thin object so the engine emits
slice-relative bytes, and the slices are then re-assembled (re-fat) into a
loader-valid universal container with correct per-slice page alignment and
strictly increasing `fat_arch` offsets. This satisfies FR-15 (fat parse-aware
rewrite) and FR-16 (re-fat).

#### Fat carrier round-trip

**A fat carrier round-trips through both write and read.**
`n00b_obj_bundle_write()` on a fat input produces a rewritten fat output with the
bundle carrier embedded in the arm64 slice(s) and every non-arm64 slice
byte-identical, re-fat'd, with signing applied per slice (the **production
half**). `n00b_obj_bundle_read()` on a fat carrier parses fat → selects the
carrier-bearing arm64 slice → detaches it as a thin object (`fat_offset == 0`,
D-034) → runs the existing thin carrier read on it; extraction and exec-plan then
work on the recovered bundle unchanged (the **read half**, WP-015).

With both halves present, the **full fat round-trip and the complete fat half of
FR-24 are closed**: a fat input written with a carrier reads back through
`n00b_obj_bundle_read()` / extraction / exec-plan. A fat input with no arm64
(carrier-writable) slice is rejected on both write and read with
`UNSUPPORTED_CARRIER`.

### Signing reconciliation

Mach-O carrier writes reuse the existing chalk signing path; the rewrite layer
never signs. The non-negotiable invariant is **strip → rewrite → re-sign**, in
that order, because the CodeDirectory hashes the rewritten bytes:

1. **Strip** any existing `LC_CODE_SIGNATURE` (a documented no-op when the input
   is unsigned).
2. **Rewrite** the carrier (and, for the loadable/split host-entrypoint path, the
   `LC_MAIN` redirect). After this the file again ends exactly at `__LINKEDIT`'s
   end with no signature.
3. **Re-sign** the persisted bytes.

Signing is write-time only (FR-24). Because `codesign` operates on a file path
rather than a buffer, the resign step lives in the file-persisting API: the
pure-buffer `n00b_obj_bundle_write()` returns rewritten-but-unsigned bytes, and
`n00b_obj_bundle_write_file()` owns persistence and the resign step. The default
signature is **ad-hoc**, which is correct for the unentitled binaries these
bundles produce; a real identity can be supplied via the additive
`signer_identity` keyword argument on `n00b_obj_bundle_write_file()`. For fat
outputs, the standard `codesign` invocation signs every slice of the container in
one call, so once the re-fat is correct, per-slice signing follows with no extra
machinery — provided the re-fat happens before the resign.

On a non-macOS host the resign step can only strip, so a host-entrypoint carrier
can be *produced* but not *validated* or *run* off a macOS host. The signing /
loader oracle proofs (codesign-verify and run-from-bundle) are therefore
macOS-gated; the default test suite is host-neutral and deterministic (D-006).

## Host-Entrypoint Write Boundary

Execute-from-bundle is supported as an **opt-in, write-time mutation**, not as a
process-launch feature. When a caller opts in on a Mach-O `LOADABLE` or `SPLIT`
write on arm64, the backend:

1. asks the neutral core for the selected entrypoint artifact and its offset in
   the loadable payload (the **selection** logic is shared with ELF and is
   unchanged — only the arm64 `entryoff` derivation is Mach-O-specific);
2. builds the loadable insert plan;
3. enables a checked arm64 `LC_MAIN` redirect on the accepted plan, recording the
   original entry as a fact and deriving the new `entryoff` from the plan's final
   segment placement;
4. applies, then hands the result to signing reconciliation.

This is the same boundary the ELF backend draws: write-time host-entrypoint
mutation produces a rewritten object whose `LC_MAIN` points at the embedded
entrypoint, but the object-bundle APIs do **not** fork, exec, create `memfd`
objects, or otherwise launch the rewritten object. The redirect is disabled by
default, is arm64-only, and is rejected with a structured reason for unsupported
architectures or unsupported exec modes before any bytes are emitted. Public
execution *planning* still reports `HOST_ENTRYPOINT` as an unsupported execution
mode — that is a distinct concern from this write-time mutation (CR-11, FR-13,
FR-22).

## Structured Carrier Errors

Carrier-layer failures surface the neutral `n00b_obj_bundle_error_t` (with
format, carrier, and detail context populated), not a bare backend code (CR-12).
A caller sees a single structured error channel regardless of which backend layer
detected the problem: a malformed or duplicate carrier, a replacement-required
state, a guard or reserved-namespace conflict, a digest mismatch, an
out-of-bounds descriptor range, a no-executable-slice SPLIT request, or a rewrite
that admission rejected all reconcile into the neutral error payload. The
internal backend layers (layout, admission, rewrite, fat-rewrite, carrier
descriptor codec) each define their own contiguous error blocks and `*_err_str`
mappers, but those are translated at the carrier boundary into the neutral
result. The per-block error-code reference and the per-function API contract are
documented in the API reference section; this section states only the model: one
structured carrier error channel, surfaced before any silent fall-through to a
different carrier interpretation.

## Implemented vs. Future

The Mach-O object-bundle arc was promoted into versioned docs under **D-046**
(the §3.5 promotion authorization). Status reflects the landed implementation
work plans (WP-001..WP-014):

| Capability | Status | Work plan |
|------------|--------|-----------|
| Foundations, fixtures, signed-arm64 feasibility spike (D-009) | Implemented | WP-001 |
| Public API + ncc-contract design (pinned up front) | Implemented | WP-002 |
| File-offset + vmaddr layout/interval model | Implemented | WP-003 |
| Loader-safe rewrite admission + structured rejection | Implemented | WP-004 |
| Byte-preserving surgical metadata rewrite (insert/replace/delete) | Implemented | WP-005 |
| Loadable `LC_SEGMENT_64` insert + `__LINKEDIT` relocation + offset patching + arm64 `LC_MAIN` redirect + `__TEXT` reflow | Implemented | WP-006 |
| Fat/universal parse-aware per-slice rewrite + re-fat | Implemented | WP-007 |
| Metadata carrier + dispatch-hook wiring + reserved-namespace/guard | Implemented | WP-008 |
| Loadable carrier + descriptor + host-entrypoint redirect | Implemented | WP-009 |
| Split carrier (excised slices + skeleton + reconstruction records, D-040) | Implemented | WP-010 |
| Signing reconciliation (strip→rewrite→resign; ad-hoc default + `signer_identity`) | Implemented | WP-011 |
| End-to-end structural e2e + known-answer tests (loader/codesign oracle gated) | Implemented | WP-012 |
| Fat carrier **write** dispatch (`fat → write`) | Implemented | WP-014 |
| Fat carrier **read** / extract (closes the fat round-trip, FR-24) | Implemented | WP-015 |
| PE object-bundle carriers | Future / separate follow-on project (D-008) | — |
| Broader mutation-oracle expansion; executable-contract lowering | Future / backlog | — |

Scope boundaries that hold today:

- **arm64 first (D-002).** The bundle carrier applies to the arm64 slice; x86_64
  and other non-arm64 slices are passed through byte-identical, and the arm64
  `LC_MAIN` redirect is the only architecture-gated rewrite. x86_64 Mach-O
  rewrite/entrypoint is a non-goal.
- **Default suite is host-neutral and deterministic (D-006).** The codesign-verify
  and run-from-bundle proofs are macOS-gated; the always-run suite does not depend
  on a macOS host.
- **PE is a separate follow-on project (D-008).** It is not implemented here and is
  not promised as part of this arc.
- **Fat support round-trips (write + read).** Both the write half (WP-014) and
  the read half (WP-015) are implemented; FR-24's full fat round-trip is closed.

## Public API & ncc Contracts

This section documents the caller-visible *semantics* of the Mach-O backend
surface, module by module. The precise call-level contract for each function —
its `@brief`, `@param`, `@kw`, `@pre`, `@post`, and `@return` — lives in the
header Doxygen and is authoritative; this section explains the model the headers
encode, not a restatement of every predicate. The public headers are:

| Header | Module | Prefix | Error block |
|--------|--------|--------|-------------|
| `include/compiler/objfile/macho_layout.h` | interval / occupancy model | `n00b_macho_layout_*` | `-42xx` |
| `include/compiler/objfile/macho_rewrite_admit.h` | rewrite admission vocabulary | `n00b_macho_rewrite_admit_*` | `-39xx` |
| `include/compiler/objfile/macho_rewrite.h` | plan / apply rewrite | `n00b_macho_rewrite_*` | `-44xx` |
| `include/compiler/objfile/macho_fat_rewrite.h` | fat / universal rewrite | `n00b_macho_fat_*` | `-43xx` |
| `include/compiler/objfile/macho_carrier.h` | carrier descriptor codec | `n00b_macho_carrier_*` | `-41xx` |
| `include/compiler/objfile/obj_bundle.h` | format-neutral dispatch | `n00b_obj_bundle_*` | `-37xx` |

The Mach-O backend that glues the carrier to the neutral dispatch
(`obj_bundle_macho`) is **internal** (`include/internal/compiler/objfile/`); it
is not part of the public surface and is not documented here. Callers reach
Mach-O only through `obj_bundle.h`.

### Surface discipline (NFR-03 / NFR-04)

Every public function in these headers follows the libn00b surface conventions:

- **No `char *` on the public surface (NFR-03).** Strings are `n00b_string_t *`;
  byte payloads are `n00b_buffer_t *`. Nullable returns are
  `n00b_option_t(T)`; fallible returns are `n00b_result_t(T)` carrying either
  `Ok(value)` or `Err(code)` with a stable `n00b_*_ERR_*` code. Field access on
  a result reads `result.is_ok` / `result.ok`; on an option, `option.has_value`
  / `option.value`.
- **Allocator discipline (NFR-04).** Every allocating function takes an
  `.allocator` keyword argument whose default is `nullptr`, meaning "use the
  current runtime allocator." The owning relationship is documented per function
  in its `@kw allocator` line (e.g. layout-build owns the returned layout and all
  its interval-tree nodes; re-fat owns the returned buffer). Pass an explicit
  allocator only when the caller needs the result to outlive or be isolated from
  the current arena.

### Dual contracts (CR-01) and the `03` §0 conventions

Each public function ships **two** halves of one contract:

1. **Header Doxygen** carries the prose `@pre` / `@post` / `@kw`. ncc forbids
   `requires`/`ensures` on a prototype, so the header expresses preconditions and
   postconditions as documentation only.
2. **The `.c` definition** carries the executable ncc `requires {}` / `ensures
   {}` blocks. Block order is fixed by ncc: positional params → `_kargs {}` →
   `requires {}` → `ensures {}` → body. The mapping is mechanical: `@pre` →
   `requires`, `@post` → `ensures`.

The convention set the headers follow (from `03-api-and-contracts.md` §0):

- **Contracts are debug-only assertions, not input validation.** Each
  expression statement in a `requires`/`ensures` block lowers to an independent,
  unconditional `__builtin_trap()` on a false value under debug builds and is
  stripped entirely under `NDEBUG`. A release build does **not** trap on a
  contract; the function body still returns the documented `Err(...)` for every
  bad-input case. Every "null input → `Err`" case is therefore expressed twice:
  once as a release-path `Err` in the body, once as a debug `requires` assertion.
- **Advisory `@pre` (D-031).** Some functions document `@pre` as **(Advisory;
  D-031)**: their null/zero/mismatch inputs are part of the function's contract
  surface and return a documented `Err`/reject verdict, so a trapping `requires`
  would fire in debug *before* the body could return the documented value. These
  functions enforce the precondition with a body guard, not a `requires`; the
  `@pre` survives as advisory header prose. The admission layer, the fat layer,
  and several rewrite entry points use this pattern.
- **Success-guarded postconditions (D-028).** Because each `ensures` statement
  is an independent unconditional trap, a fallible function's success-state
  postconditions are all written guarded by success —
  `!result.is_ok || (result.ok ... && <postcondition>)` — so a legitimate `Err`
  return never trips the assertion. A fallible `ensures` never contains a bare
  `result.is_ok;` or bare `result.ok != nullptr;`.
- **Pointer-returning functions carry no `ensures` (D-029).** The stable ncc
  miscompiles a pointer-returning function (e.g. the `*_str` / `*_err_str`
  name-mappers, which return `n00b_string_t *`) that carries an `ensures` block.
  These functions therefore have **no `ensures` block at all**; their non-null
  postcondition is expressed as `@return` prose only ("a process-lifetime string
  literal, never null"). Result-/option-returning functions are unaffected and
  keep their guarded `ensures`.
- **No `old(...)` (CR / §0.4).** ncc v1 has no pre-state capture and forbids
  function calls in contracts. The headline guarantees — *every original byte
  outside the planned ranges is preserved* and *the descriptor digest equals
  SHA-256 of the payload* — are inherently relations between input and output (or
  payload and hash) and are **not** expressible as a debug assertion. The headers
  mark these `@post` lines **(no-`old` limit)**: the full guarantee is stated as
  authoritative prose, the executable `ensures` captures only the checkable
  structural shadow (lengths, counts, offsets, monotonicity, non-null-ness), and
  the per-WP regression test is the real oracle that diffs byte ranges and
  recomputes the digest. This is documentation of the implemented dual contract,
  not a claim of new executable contract code.

### Error codes and `*_err_str` (CR-07)

Each module owns a contiguous error-code block (D-022 assigned the ranges so
they never collide) plus an `*_err_str` mapper that turns a code into a stable,
process-lifetime string. The blocks, verified against the headers:

| Module | `OK` | Error range | `*_err_str` |
|--------|------|-------------|-------------|
| layout | `N00B_MACHO_LAYOUT_OK` (0) | `-4201` `ERR_INVALID`, `-4202` `ERR_OVERFLOW`, `-4203` `ERR_INTERVAL` | `n00b_macho_layout_err_str` |
| admit | `N00B_MACHO_REWRITE_ADMIT_OK` (0) | `-3901` `ERR_NULL_BINARY`, `-3902` `ERR_NULL_REQUEST`, `-3903` `ERR_ZERO_PAYLOAD`, `-3904` `ERR_LAYOUT_SUBSTRATE`, `-3905` `ERR_OVERFLOW` | `n00b_macho_rewrite_admit_err_str` |
| rewrite | `N00B_MACHO_REWRITE_OK` (0) | `-4401`..`-4415` (`ERR_NULL_BINARY` … `ERR_TRUSTED_NAME`) | `n00b_macho_rewrite_err_str` |
| fat | `N00B_MACHO_FAT_OK` (0) | `-4301`..`-4307` (`ERR_NULL_INPUT`, `ERR_NOT_FAT`, `ERR_NO_TARGET_SLICE`, `ERR_SLICE_REWRITE`, `ERR_ALIGN_OVERFLOW`, `ERR_SLICE_TOO_LARGE`, `ERR_REFAT`) | `n00b_macho_fat_err_str` |
| carrier | `N00B_MACHO_CARRIER_OK` (0) | `-4101`..`-4109` plus `-4110` `ERR_UNSUPPORTED_CARRIER` (no executable slice for a SPLIT request, D-040) | `n00b_macho_carrier_err_str` |
| neutral dispatch | `N00B_OBJ_BUNDLE_ERR_OK` (0) | `-37xx` incl. `-3717` `MALFORMED_BUNDLE_CARRIER`, `-3723` `UNSUPPORTED_CARRIER`, `-3724` `REWRITE_FAILURE` | `n00b_obj_bundle_err_str` |

Internal backend codes never leak to a neutral caller: the carrier boundary
translates each backend code into the neutral `n00b_obj_bundle_error_t`
(see *Structured carrier errors* above and CR-12 below).

### Public enums and `*_str` (CR-08)

Every public enum carries a stable name mapper (pointer-returning, so per D-029
none of them carry an `ensures`). These are the enum **name** mappers; the
per-module error-code-to-string `*_err_str` mappers are listed separately under
CR-07 above.

- **layout**: interval kind (`n00b_macho_layout_interval_kind_str`), coverage
  kind (`..._coverage_kind_str`), gap kind (`..._gap_kind_str`), plus single-bit
  segment-flag and section-flag mappers (`..._segment_flag_str`,
  `..._section_flag_str`).
- **admit**: policy flag (`n00b_macho_rewrite_admit_policy_flag_str`), outcome
  (`..._outcome_str`), placement kind (`..._placement_kind_str`), rejection
  reason (`..._rejection_reason_str`).
- **rewrite**: plan outcome (`n00b_macho_rewrite_plan_outcome_str`), rejection
  reason (`..._rejection_reason_str`), target-profile reason
  (`..._target_profile_reason_str`), patch kind (`..._patch_kind_str`),
  host-entrypoint rejection reason
  (`..._host_entrypoint_rejection_reason_str`).
- **fat**: slice disposition (`n00b_macho_fat_slice_disposition_str`),
  select policy (`n00b_macho_fat_select_policy_str`).
- **carrier**: carrier kind (`n00b_macho_carrier_kind_str`).

### Layout — `n00b_macho_layout_*`

A read-only structural analysis layer: it records where the mach_header, the
load-command region, each `LC_SEGMENT_64` (file extent and vm extent recorded
**separately**), each section, the `__LINKEDIT` sub-regions, the code-signature
region, and any overlay live. Overlap and collision are *facts*, never admission
verdicts.

- `n00b_macho_layout_build(bin)` returns `Ok(layout)`; the layout borrows facts
  from `bin` but keeps no pointers into its segments, sections, or buffers, and
  does not reflect later mutation. `.allocator` owns the returned layout and all
  interval-tree nodes.
- The query family — `*_file_overlap` / `*_vaddr_overlap` (single),
  `*_file_overlaps` / `*_vaddr_overlaps` (copied list), `*_file_collision` /
  `*_vaddr_collision` (summary), `*_next_file_interval`,
  `*_page_segment_vaddr_collision`, `*_find_file_gap` / `*_find_vaddr_gap`,
  `*_eof_tail_gap` — answers placement questions in the two coordinate spaces.
  Functions that copy an array (overlaps/collisions) take `.allocator`; the
  single-overlap and gap queries do not allocate a list and have no `.allocator`.
- Gap/collision queries take `min_size` (must be nonzero) and `alignment`
  (`0` means byte alignment); on a found gap the result is aligned and at least
  `min_size` wide.

### Admission — `n00b_macho_rewrite_admit_*`

A read-only decision layer that turns a metadata (`LC_NOTE`) or loadable
(`LC_SEGMENT_64`) request into an accept/reject *verdict* with concrete
placement and load-command-slack facts. It never mutates `bin`, never emits
bytes, and never produces a plan.

- `n00b_macho_rewrite_admit_metadata_insert` admits a general `LC_NOTE` insert;
  `..._chalk_mark_insert` and `..._object_bundle_insert` are the two trusted
  reserved-owner twins (chalk's `data_owner = "chalk"` and the bundle's
  `N00B_MACHO_BUNDLE_NOTE_OWNER = "n00b.0c001"`); a non-matching owner is
  rejected with `REJECT_RESERVED_NOTE_NAME`.
- `n00b_macho_rewrite_admit_loadable_insert` admits one new `LC_SEGMENT_64`.
  Load-command-slack exhaustion is an **accepted-but-costly** case (D-021), not a
  rejection: when slack is smaller than the new segment command, the plan path
  becomes a `__TEXT` section reflow rather than `__LINKEDIT`-only relocation
  (the concrete reflow facts live on the loadable *plan*, not the admission
  result).
- `n00b_macho_rewrite_admit_host_entrypoint_target` admits an arm64 `LC_MAIN`
  `entryoff` redirect into a candidate segment payload range; non-arm64,
  non-`MH_EXECUTE`, `LC_UNIXTHREAD`-only, or out-of-range targets reject.
- Verdict shape: an accepted result sets a placement and the relevant facts; a
  rejected result sets `rejection_reason != NONE`. The advisory-`@pre` (D-031)
  pattern applies here — null `bin`/`request` and zero/undersized fields are
  documented `Err`/reject returns, body-guarded, not trapping preconditions.

### Rewrite — `n00b_macho_rewrite_*` (plan-first + convenience, CR-09)

Turns admission facts into explicit patch *plans*, then applies accepted plans
to **new** byte buffers. Planning and apply never mutate the parsed object or
its original stream. Each rewrite operation is offered in **two forms** (CR-09):

| Operation | Plan | Apply | One-call convenience |
|-----------|------|-------|----------------------|
| metadata insert | `n00b_macho_rewrite_plan_metadata_insert` | `n00b_macho_rewrite_apply_metadata_insert_plan` | `n00b_macho_rewrite_apply_metadata_insert` |
| chalk-mark insert | `..._plan_chalk_mark_insert` | `..._apply_chalk_mark_plan` | — |
| chalk-mark delete | `..._plan_chalk_mark_delete` | `..._apply_chalk_mark_plan` | `..._apply_chalk_mark_delete` |
| chalk-mark replace | `..._plan_chalk_mark_replace` | `..._apply_chalk_mark_plan` | `..._apply_chalk_mark_replace` |
| object-bundle insert | `..._plan_object_bundle_insert` | `..._apply_object_bundle_plan` | `..._apply_object_bundle_insert` |
| object-bundle delete | `..._plan_object_bundle_delete` | `..._apply_object_bundle_plan` | `..._apply_object_bundle_delete` |
| object-bundle replace | `..._plan_object_bundle_replace` | `..._apply_object_bundle_plan` | `..._apply_object_bundle_replace` |
| loadable insert | `..._plan_loadable_insert` | `..._apply_loadable_insert_plan` | — |

The plan form lets a caller inspect the patch array, the target profile, and the
admission facts before committing; the convenience form plans-and-applies in one
call and returns the rewritten bytes (or `Err`, including `PLAN_REJECTED`). The
read-only `n00b_macho_rewrite_target_profile` reports whether an object is the
single-slice arm64 shape the rewrite layer requires.

The **opt-in entrypoint-enable** pairing (CR-11) layers over the loadable plan:
`n00b_macho_rewrite_plan_host_entrypoint_target` validates an arm64 `LC_MAIN`
redirect for an accepted loadable plan and derives the replacement `entryoff`;
`n00b_macho_rewrite_loadable_plan_enable_entrypoint` then enables the checked
patch on the plan (recording `replacement_entryoff`, preserving
`original_entryoff`). The redirect is **disabled by default** — a loadable plan
without an enabled entrypoint preserves `LC_MAIN.entryoff` on apply — and apply
verifies the redirect through the reparsed output. Apply never executes the
object and never re-signs (signing reconciliation is the carrier write path).

Byte-preservation `@post` lines on the apply functions are **(no-`old` limit)**:
the prose guarantees "all original ranges outside the planned patches are
preserved" and "the output reparses with `n00b_macho_parse_single`," while the
executable `ensures` carries only the structural shadow (output-length bounds)
because the relational and call-based parts cannot live in a contract.

### Fat / universal — `n00b_macho_fat_*` (WRITE side)

Layers over the single-slice rewrite engine. `n00b_macho_fat_select` classifies
each slice (`REWRITE` / `PASSTHROUGH` / `REJECT`) under a policy
(`ARM64_ONLY` default, `ALL_ARM`, `EXPLICIT_INDEX`); a policy that yields no
`REWRITE` target returns `Err(N00B_MACHO_FAT_ERR_NO_TARGET_SLICE)`.
`n00b_macho_fat_rewrite` orchestrates: select, run the thin rewrite on each
`REWRITE` slice as a **detached** thin object (D-034), pass other slices through
byte-identical (D-035/D-002), then re-fat. `n00b_macho_refat` is the re-assembly
primitive that writes the big-endian `fat_header` + `fat_arch[]` table with
`2^align`-aligned, strictly-increasing offsets; cursor overflow or a slice that
exceeds the `fat_arch` u32 field is a reported error, never a silent truncation.
This is the fat **write** primitive; the matching read path (`n00b_obj_bundle_read`
selecting and detaching the carrier-bearing arm64 slice) closes the round-trip —
see the fat carrier round-trip note above (WP-015).

### Carrier descriptor codec — `n00b_macho_carrier_*`

The descriptor wire-format codec for the LOADABLE and SPLIT carriers (the
METADATA carrier stores raw canonical bytes with no descriptor and is
discriminated by the absence of the 8-byte magic).

- `n00b_macho_carrier_descriptor_encode` writes the fixed 64-byte little-endian
  header and, for SPLIT, the trailer (`skeleton_len` + `record_count` words +
  the excised skeleton blob + the 48-byte slice records, D-040). The caller must
  have computed `payload_digest`; this layer never hashes.
- `n00b_macho_carrier_descriptor_decode` decodes and structurally validates
  (magic, version, header size, kind, bounds, and — for SPLIT — the trailer); it
  does **not** verify the digest (decode is pure structure).
- `n00b_macho_carrier_compute_digest` is the one shared SHA-256-into-canonical-
  byte-order routine used by both the writer and the verifier, so the two never
  diverge on byte order; `n00b_macho_carrier_verify_digest` recomputes the hash
  in its body (a hash call cannot live in a contract) and returns the boolean
  verdict in the result rather than asserting it.

### Neutral dispatch — `n00b_obj_bundle_*` (FR-21)

Callers reach the Mach-O backend only through the format-neutral `obj_bundle.h`
surface. `N00B_FMT_MACHO` is a **supported** carrier format (FR-21): selecting
`.format = N00B_FMT_MACHO` (or relying on auto-detect) routes
`n00b_obj_bundle_read` / `n00b_obj_bundle_write` /
`n00b_obj_bundle_write_file` through the Mach-O carrier backend. The
`N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER (-3723)` code does **not** apply to a
supported Mach-O carrier request; it remains for genuinely unsupported requests.
For Mach-O there are two live cases, both "no rewrite target": a fat input with
no arm64 slice (the fat write path), and a SPLIT request whose payload has no
executable-compatible slice (the carrier layer's `-4110` maps to `-3723`).

Two write entry points exist because code signing needs an on-disk path:

- `n00b_obj_bundle_write` is the pure-buffer path. For Mach-O it returns
  rewritten-but-**UNSIGNED** bytes, which are non-loadable on arm64 until
  re-signed. A caller that needs a runnable arm64 image must use the file path.
- `n00b_obj_bundle_write_file` rewrites exactly as `n00b_obj_bundle_write`
  would, persists through the object-file sink, and re-signs the on-disk file
  (strip → carrier rewrite → persist → re-sign). Its additive
  `signer_identity` keyword (D-041) defaults to `nullptr` = ad-hoc signing,
  which is correct for the unentitled binaries these bundles produce; an explicit
  identity overrides it. Ignored for non-Mach-O inputs.

### Structured carrier errors — `n00b_obj_bundle_error_t` (CR-12)

A carrier-layer failure surfaces the neutral `n00b_obj_bundle_error_t`, not a
bare backend code. The accessor family reads its context: `*_error_code`
(stable `n00b_obj_bundle_error_code_t`), `*_error_message`, `*_error_format`
(the object format when carrier-specific), `*_error_carrier` (the carrier
placement when known), `*_error_logical_path`, `*_error_destination_path`,
`*_error_artifact_id`, `*_error_detail` (a backend-specific detail value), plus
the execution-planning and extraction-facts accessors. Each accessor that can be
absent returns an `n00b_option_t`. The neutral `n00b_obj_bundle_err_str` maps
any `n00b_obj_bundle_error_code_t` to a human-readable string.

## Mach-O Carrier Usage Example

The following worked example builds a bundle, writes it into a Mach-O host as a
metadata carrier, persists + signs it, then reads it back — the CR-10 save/load
round-trip — and shows the CR-12 structured-error path. All calls use the real
public signatures from `obj_bundle.h`; `n00b_string_t *` literals use ncc's
`r"..."` rstring syntax, `_kargs` are passed with direct `.name = value` syntax,
and results are checked with `n00b_result_is_ok` / `.is_ok` and read with
`n00b_result_get` (value) or `n00b_result_get_err_payload` (the structured
`n00b_obj_bundle_error_t *` carried on the neutral API's error path, CR-12).

```c
#include "compiler/objfile/obj_bundle.h"

// `host_bytes` is a parsed-from-disk arm64 Mach-O executable's bytes
// (n00b_buffer_t *). `payload` is one artifact's bytes (n00b_buffer_t *).
// `reload_file` reloads the persisted output through the VFS (caller-supplied).
n00b_result_t(n00b_obj_bundle_t *)
save_round_trip(n00b_buffer_t *host_bytes,
                n00b_buffer_t *payload,
                n00b_string_t *out_path)
{
    // 1. Build a bundle: one executable artifact, marked the default exec.
    n00b_obj_bundle_t *bundle = n00b_result_get(n00b_obj_bundle_new());

    n00b_result_t(bool) ares = n00b_obj_bundle_add_artifact(
        bundle, r"bin/app", payload,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    if (!ares.is_ok) {
        return n00b_result_err(n00b_obj_bundle_t *,
                               N00B_OBJ_BUNDLE_ERR_BUILD);
    }
    (void)n00b_obj_bundle_set_default_exec(bundle, r"bin/app");

    // 2. Write + persist + sign into a Mach-O host. The buffer path
    //    (n00b_obj_bundle_write) would return UNSIGNED bytes; for a runnable
    //    arm64 image we use the file path, which re-signs on disk. The
    //    METADATA carrier is the default (AUTO) carrier; ad-hoc signing is the
    //    default (signer_identity == nullptr).
    n00b_result_t(n00b_objfile_sink_result_t *) wres =
        n00b_obj_bundle_write_file(host_bytes, bundle, out_path,
                                   .format  = N00B_FMT_MACHO,
                                   .carrier = N00B_OBJ_BUNDLE_CARRIER_METADATA);
    if (!wres.is_ok) {
        // write_file errors carry the structured payload (CR-12); forward it.
        n00b_obj_bundle_error_t *werr =
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, wres);
        return n00b_result_err(n00b_obj_bundle_t *,
                               n00b_obj_bundle_error_code(werr));
    }

    // 3. Read the carrier back out of the persisted bytes (round-trip).
    n00b_buffer_t *written_bytes = reload_file(out_path);
    n00b_result_t(n00b_obj_bundle_t *) rres =
        n00b_obj_bundle_read(written_bytes, .format = N00B_FMT_MACHO);
    if (!rres.is_ok) {
        n00b_obj_bundle_error_t *rerr =
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, rres);
        return n00b_result_err(n00b_obj_bundle_t *,
                               n00b_obj_bundle_error_code(rerr));
    }

    // The recovered bundle decodes to the same canonical artifact set.
    return rres;
}
```

Note the boundary behavior: this wrapper collapses each failure to an integer
code via `n00b_result_err(..., n00b_obj_bundle_error_code(err))`, so its caller
sees a code, not the structured `n00b_obj_bundle_error_t`. A wrapper that needs
to preserve the structured payload across its own boundary should forward it with
`n00b_result_err_payload` instead (the structured channel below shows how the
payload is read directly from the underlying call's result).

Structured-error path (CR-12): a guarded or duplicate carrier is rejected with a
neutral `n00b_obj_bundle_error_t`, inspected through the accessors.

```c
// Attempting to write over a binary that already carries an N00b bundle, with
// the default REJECT_EXISTING replace policy, fails with a structured error.
n00b_result_t(n00b_buffer_t *) wres =
    n00b_obj_bundle_write(already_wrapped_bytes, bundle,
                          .format = N00B_FMT_MACHO);

if (!wres.is_ok) {
    // The result error carries the neutral structured payload (extracted by
    // its payload pointer type, set on the Err side with n00b_result_err_payload).
    n00b_obj_bundle_error_t *err =
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, wres);

    n00b_obj_bundle_error_code_t code = n00b_obj_bundle_error_code(err);
    // e.g. N00B_OBJ_BUNDLE_ERR_REPLACE_REQUIRED (-3718) for a present, valid,
    // N00b-owned carrier, or N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER
    // (-3716) / MALFORMED_BUNDLE_CARRIER (-3717) for a malformed/duplicate one.
    n00b_string_t *msg = n00b_obj_bundle_err_str(code);

    // Carrier-specific context is present for a carrier-layer failure:
    n00b_option_t(n00b_format_t) fmt = n00b_obj_bundle_error_format(err);
    if (fmt.has_value) {
        // fmt.value == N00B_FMT_MACHO
    }
    n00b_option_t(n00b_obj_bundle_carrier_t) carrier =
        n00b_obj_bundle_error_carrier(err);
    n00b_option_t(int64_t) detail = n00b_obj_bundle_error_detail(err);
    // Translate or log `msg` / `detail`; never re-interpret the carrier.
}
```

The structured-error channel is the only carrier-failure surface a neutral
caller sees: malformed/duplicate carriers, a replacement-required state, a guard
or reserved-namespace conflict, a digest mismatch, an out-of-bounds descriptor
range, a no-executable-slice SPLIT request, and an admission-rejected rewrite all
reconcile into one `n00b_obj_bundle_error_t` rather than leaking a backend code.
