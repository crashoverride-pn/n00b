# Object Bundles

## Overview

An **object bundle** is a canonical collection of named artifacts, execution
metadata, and policy records that can be embedded into an object file. The
bundle model is carrier-independent: the same canonical bundle bytes can live
in an ELF metadata section, a loadable segment, or a split metadata/loadable
layout when the backend supports that carrier.

The current implementation is ELF-first. The public API is intentionally
format-neutral and centered on `include/compiler/objfile/obj_bundle.h`.
Format-specific rewrite code owns byte placement. Object-bundle code owns
artifact metadata, manifest validation, policy selection, extraction planning,
execution planning, and carrier selection.

## Terminology

| Term | Meaning |
|------|---------|
| Object bundle | The logical collection embedded in an object file: canonical manifest, artifact metadata, policy records, execution metadata, and payload bytes. |
| Bundle | Short form of object bundle. |
| Artifact | One stored item in a bundle. An artifact has a logical path, kind, payload bytes when applicable, mode/flags, digest, and optional execution role. |
| Manifest | The canonical binary metadata record describing bundle version, artifact table, payload table, execution map, policy table, string data, and compatibility fields. |
| Carrier | The object-file storage mechanism that holds bundle bytes or reconstruction state, such as ELF `.0c001.bundle`, a descriptor-backed loadable segment, or a split metadata/loadable layout. |
| Extraction | Materializing bundle artifacts to a filesystem destination after manifest validation, policy evaluation, path checks, and collision checks. |
| Execution plan | A side-effect-free plan that selects an executable-compatible artifact and records argv, environment, policy, and platform-support facts for a later executor. |
| Policy | Bundle-carried extraction or execution rules. Policy records can have different representations and priorities; callers supply per-operation controls that may narrow policy but do not replace it. |
| Carrier replacement | An explicit write operation that replaces a unique valid N00b-owned bundle carrier. Replacement does not authorize foreign, malformed, duplicate, guarded, or previously wrapped inputs. |

## Layer Boundary

Object-bundle packaging sits above low-level object-file rewrite mechanics.
The rewrite layer receives concrete carrier mutations and reports layout
facts. It does not interpret bundle artifacts, extraction policy, execution
selectors, or Brandon embedded-filesystem records.

| Layer | Owns | Does not own |
|-------|------|--------------|
| Object-file layout and rewrite | ELF/Mach-O/PE facts, occupied ranges, gaps, section or segment mutation plans, byte preservation outside planned patch ranges. | Bundle manifest tables, artifact identity, extraction policy, execution target selection. |
| Object-bundle core | Bundle construction, canonical encode/decode, manifest validation, artifact tables, execution map records, policy table records. | Raw ELF gap math, PHTAB relocation policy, architecture-specific entrypoint patch bytes. |
| Carrier backend | Mapping a carrier request to an object-file rewrite, descriptor validation, and selected carrier authority. | Runtime extraction behavior, process execution, embedded policy language semantics. |
| Packaging policy | Selection and evaluation of extraction/execution policy records, including embedded N00b policy when present. | Low-level section/segment rewrite admission. |
| Extraction and execution planning | Filesystem materialization planning, execution target planning, argv/env facts, policy result facts. | Process launch, `memfd` execution, or generic host-entrypoint runtime behavior. |

## Manifest

The manifest is a N00b-owned canonical binary format. It is not JSON and it
is not Brandon's old `.0c001.file` stream.

Canonical bundle bytes are independent of the object-file carrier that stores
them. A metadata carrier stores those bytes directly. Descriptor-backed
carriers validate their descriptor state and then feed the same canonical
bundle bytes to the normal decoder.

The implemented v1 manifest model includes:

| Area | Current behavior |
|------|------------------|
| Header and identity | The manifest has N00b magic/version fields, compatibility flags, bounded table lengths/offsets, and a content ID. Unsupported versions or required features reject. |
| Artifact table | Artifacts have stable IDs, logical paths, kinds, flags, modes, payload ranges, and digests. Logical paths are normalized before duplicate checks. |
| Payload table | Payload ranges are bounded, digest-checked, and tied to artifact records. Payload sharing is not part of v1 behavior. |
| Execution map | The manifest records at most one default executable and selector-to-target mappings. Mapping targets must refer to executable-compatible artifacts. |
| Policy table | Extraction and execution policy records are manifest data, not caller-side options. See [Policy Table](#policy-table). |
| String data | Manifest strings are UTF-8 and participate in canonical validation. |

Canonical ordering is deterministic. Strict decoding rejects non-canonical
manifest structure rather than accepting and rewriting ambiguous input. The
canonical shape is:

1. header;
2. artifact table sorted by artifact ID;
3. payload table sorted by artifact ID;
4. execution map;
5. policy table;
6. extension records when supported;
7. string table;
8. payload bytes.

Validation is deliberately stricter than general ELF parsing because the
manifest is N00b-owned. Decode validates shape, bounds, ordering, alignment,
content ID, payload and policy digests, string-table UTF-8, artifact/payload
cross-references, execution-map references, policy references, and canonical
re-encode equality. Decode either returns a fully valid bundle or fails; no
partially valid decoded bundle escapes.

The v1 writer emits uncompressed payload bytes. Compression, encryption, and
other payload transforms are extension points, not current default behavior.
Unknown required feature bits, compressed artifacts, malformed ranges, digest
mismatches, duplicate logical paths, duplicate selectors, multiple default
executables, and missing execution targets reject during validation.

## Policy Table

Object bundles carry extraction and execution policy in the manifest. Caller
API controls such as extraction overwrite options, execution selector
strictness, or validate-only mode are per-call controls. They may narrow what
the selected bundle policy permits, but they do not widen bundle-carried
policy.

Policy records are selected by scope and priority. Unknown required policy
records for the requested scope are fatal. Optional policy records may be
ignored only when doing so cannot change required behavior. Fallback to a
lower-priority policy is allowed only when the manifest declares a compatible
fallback.

| Policy kind | Current role |
|-------------|--------------|
| `N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT` | The built-in baseline policy for v1 bundles that do not need an explicit payload. |
| `N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1` | A simple declarative v1 policy payload with production schema validation. It is useful as a stable compatibility representation. |
| `N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B` | A canonical v1 embedded-policy payload envelope containing UTF-8 N00b predicate source. It is the long-term policy direction and is evaluated through `n00b_eval_compile_predicate()`, not through a second policy language. |

Policy records include a policy ID, kind, scope, flags, priority, optional
payload bytes, payload digest, and optional fallback policy ID. The public
builder copies caller-provided payload bytes; caller-owned buffers are not
mutated.

| Field | Caller-visible meaning |
|-------|------------------------|
| Scope | Extraction, execution, or both. A policy that does not cover the requested operation is not selected for that operation. |
| Priority | Selection order among supported policies for the same scope. Higher-priority supported policies are preferred over lower-priority fallback records. |
| Required/optional flags | Required unsupported records reject for their scope. Optional records can be skipped only when the manifest permits that compatibility behavior. |
| Fallback ID | Names the compatible lower-priority policy that may be used for supported fallback cases. False policy decisions do not fall back. |
| Payload digest | Protects declarative and embedded policy payload bytes during canonical encode/decode and carrier readback. |

Embedded N00b policy is already integrated into extraction and execution
planning. Extraction evaluates selected embedded policy before validate-only
success, direct writes, or atomic staging. Execution planning evaluates
selected embedded policy after deterministic target selection and before a
successful plan is returned.

## Carriers

The N00b binary section namespace is `.0c001.*`. The baseline object-bundle
carrier is `.0c001.bundle`.

| Carrier request | Current ELF behavior |
|-----------------|----------------------|
| `N00B_OBJ_BUNDLE_CARRIER_AUTO` | Writes raw canonical metadata bytes in non-loadable `.0c001.bundle`. It does not silently choose loadable or split carriers. |
| `N00B_OBJ_BUNDLE_CARRIER_METADATA` | Writes raw canonical object-bundle bytes in non-loadable `.0c001.bundle`. |
| `N00B_OBJ_BUNDLE_CARRIER_LOADABLE` | Writes a descriptor in `.0c001.bundle` and stores the complete canonical bundle bytes in a new `PT_LOAD`. Reads validate descriptor kind, version, bounds, and digest before decoding the canonical bundle. |
| `N00B_OBJ_BUNDLE_CARRIER_SPLIT` | Writes descriptor/skeleton state in `.0c001.bundle` and selected executable-compatible artifact payload slices in a new `PT_LOAD`. Reads validate reconstruction records and rebuild exact canonical bundle bytes before decode. |

Readers follow only the selected `.0c001.bundle` raw metadata or descriptor
state. Stale loadable bytes from an older replaced carrier are not
authoritative.

Descriptor-backed carriers are an ELF carrier envelope, not a change to the
canonical manifest wire format. The descriptor records enough checked facts to
locate and validate the current carrier state. For `LOADABLE`, the selected
range is the complete canonical bundle blob. For `SPLIT`, the selected
descriptor/skeleton and reconstruction records rebuild the exact canonical
bundle blob before decode.

Replacement is explicit. Existing valid N00b-owned metadata, loadable, or
split carriers require `N00B_OBJ_BUNDLE_REPLACE_EXISTING` before a write can
replace them. Replacement updates selected `.0c001.bundle` state but does not
need to erase stale non-selected loadable bytes, because readers never scan
stale loadable bytes as authoritative bundle payloads.

Carrier failures are structured object-bundle errors. Malformed descriptors,
unsupported descriptor versions, out-of-bounds ranges, digest mismatches,
unsupported carriers, malformed canonical bundle bytes, duplicate carriers,
and replacement-required states are reported before silently falling through to
another carrier interpretation.

Mach-O and PE remain part of the format-neutral API intent but do not have
implemented object-bundle carriers in the current state.

## Public API

The public object-bundle API is one cross-format surface in
`include/compiler/objfile/obj_bundle.h`. It uses `n00b_result_t()` return
values with structured `n00b_obj_bundle_error_t` payloads for bundle,
carrier, policy, extraction, and execution failures.

The header Doxygen is the exact call-level contract. This document summarizes
the caller-visible model: required inputs are positional, optional behavior is
selected with `_kargs`, and ELF/Mach-O/PE-specific carrier mechanics stay
behind the same object-bundle entry points. `N00B_FMT_UNKNOWN` means
auto-detect; unsupported formats or carriers fail through the same structured
result path instead of requiring format-specific APIs.

Important public operations include:

| Operation | Purpose |
|-----------|---------|
| `n00b_obj_bundle_new()` | Create an empty mutable bundle. |
| `n00b_obj_bundle_add_artifact()` | Add a file, executable, directory, metadata, or opaque artifact from read-only payload bytes. |
| `n00b_obj_bundle_set_default_exec()` | Set the default executable-compatible artifact. |
| `n00b_obj_bundle_add_exec_mapping()` | Map a selector to an executable-compatible artifact. |
| `n00b_obj_bundle_add_policy()` | Add a bundle-carried policy record. |
| `n00b_obj_bundle_validate()` | Validate bundle invariants without side effects. |
| `n00b_obj_bundle_encode()` / `n00b_obj_bundle_decode()` | Convert between bundle handles and canonical bundle bytes. |
| `n00b_obj_bundle_read()` / `n00b_obj_bundle_write()` | Read or write bundle carriers in object-file bytes. |
| `n00b_obj_bundle_write_file()` | Rewrite object-file bytes and persist them through the object-file sink layer. |
| `n00b_obj_bundle_extract()` | Validate policy/path/collision state and materialize supported artifacts. |
| `n00b_obj_bundle_exec_plan()` | Build a side-effect-free logical execution plan. |

Optional controls use ncc keyword arguments. Examples include `.format`,
`.carrier`, `.replace`, `.strict`, `.allocator`, extraction controls, execution
controls, and opt-in host-entrypoint write controls.

| Control family | Important controls |
|----------------|--------------------|
| Object-file carrier I/O | `.format`, `.carrier`, `.replace`, `.strict`, `.allocator`. |
| Host-entrypoint write planning | `.entrypoint`, `.entrypoint_selector`, `.entrypoint_strict_selector`, `.entrypoint_policy_mode`. |
| File persistence | `.sink_mode`, `.overwrite`, `.file_mode`, `.preserve_existing_mode`. |
| Extraction | `.overwrite`, `.atomic`, `.preserve_modes`, `.create_dirs`, `.allow_absolute_paths`, `.allow_parent_refs`, `.policy_mode`, `.allocator`. |
| Execution planning | `.selector`, `.argv`, `.env`, `.inherit_env`, `.strict_selector`, `.mode`, `.policy_mode`, `.allocator`. |

Ownership and lifetime rules are intentionally conservative:

- artifact and policy payload inputs are read-only copy sources;
- mutation APIs leave the bundle unchanged on error;
- `encode()` and `write()` return independent buffers allocated with the
  selected allocator;
- `read()` and `write()` do not mutate the input object-byte buffer;
- `write_file()` first produces rewritten bytes, then hands them to the
  format-neutral sink layer;
- extraction results, execution plans, and structured error payloads are
  opaque allocator-backed records;
- accessor return values are observation facts and should be treated as
  read-only; execution-plan `argv` and `env` containers are plan-owned copies,
  selected logical paths are borrowed from the bundle, and caller-supplied
  selector facts are borrowed.

Structured object-bundle errors carry a stable code and optional context such
as message, object format, carrier, logical path, destination path, artifact
ID, policy kind/scope, backend detail, requested execution mode, platform
support, and extraction-result facts. `write_file()` can also fail after the
object-bundle rewrite accepts the input; those persistence failures carry the
sink layer's structured `n00b_objfile_sink_error_t` payload instead.

## Extraction

Extraction validates before filesystem side effects. The planner validates the
bundle, selects and evaluates extraction policy, normalizes logical paths,
checks destination containment, rejects unsafe paths by default, detects
collisions and overwrite conflicts, and only then performs direct or atomic
materialization.

Current extraction supports regular files, executable files, zero-length
files, directories, and empty directories. It records planned/written counts,
policy facts, direct/atomic facts, commit facts, rollback facts, and cleanup
facts in `n00b_obj_bundle_extract_result_t`.

Extraction policy can be builtin/default, declarative v1, or embedded N00b.
Embedded policy is evaluated before validate-only success, direct writes, or
atomic staging.

Logical artifact paths are bundle paths, not host paths. By default,
extraction rejects absolute logical paths and parent-directory references, then
joins accepted paths under the destination root. The implementation uses
`include/util/path.h` helpers for canonicalization, joining, same-directory
temporary paths, exact commits, directory creation, and cleanup; callers do
not need a separate public path object.

`policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY` still validates the
bundle, target paths, caller controls, collision state, and selected policy,
including embedded policy predicates. It returns result facts without
filesystem writes. Policy denial still fails in validate-only mode.

With direct extraction, `atomic = false`, the validated plan writes directly
to final destinations. With atomic extraction, `atomic = true`, the validated
plan stages into a sibling temporary tree and commits to the exact
destination root only when exact no-replace root commit semantics are
available. If a failure happens after a visible side effect, result/error
facts report commit, rollback, and cleanup attempts rather than hiding partial
state.

Caller controls cap the operation. `overwrite` allows replacing destination
paths only when bundle policy also permits it. `create_dirs` controls
directory creation. `preserve_modes` requests supported mode-bit application,
subject to host behavior. `allow_absolute_paths` and `allow_parent_refs` are
specialized unsafe controls and remain false by default.

## Execution

Execution planning is a logical, side-effect-free operation. It selects an
executable-compatible target from a selector mapping or the default executable,
records argv and environment intent, evaluates execution-scope policy, and
returns opaque plan facts. It does not fork, exec, create `memfd` objects,
materialize extraction output, mutate the host object, or mutate the process
environment.

Target selection is deterministic:

1. If `.selector` is supplied and a matching selector mapping exists, the
   mapped target is selected.
2. If `.selector` is supplied, no mapping exists, and `.strict_selector` is
   true, planning fails.
3. Otherwise the default executable is selected when present.
4. Data-only bundles or bundles with no matching/default executable fail with
   structured no-target context.

Execution targets must be executable-compatible: either
`N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE`, or
`N00B_OBJ_BUNDLE_ARTIFACT_FILE` with an execute mode bit set. A successful
plan records the selected artifact ID, selected logical path, selection
source, caller selector, requested and resolved mode, platform support state,
extraction dependency, selected policy kind/scope, fallback use, `argv`,
`env`, and environment-inheritance intent.

If caller `argv` is supplied, the plan preserves it. If it is omitted, the
plan synthesizes `argv[0]` from the selected target logical path. The
environment overlay is recorded as plan facts; planning does not read or
mutate the process environment. `inherit_env` records intent for a later
executor.

Execution-scope policy is selected and evaluated after target selection, so
embedded N00b predicates can inspect the selected target, selector source,
requested mode, inheritance, strict-selector, and policy-mode facts.
`policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY` still evaluates policy;
it is not a bypass and does not turn denied execution into success.

`N00B_OBJ_BUNDLE_EXEC_AUTO` and `N00B_OBJ_BUNDLE_EXEC_EXTRACTED` resolve to a
logical extracted-execution dependency without invoking extraction.
`N00B_OBJ_BUNDLE_EXEC_MEMFD` and
`N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT` are recognized future/logical modes,
but public execution planning currently reports them as unsupported. That is
separate from write-time host-entrypoint mutation: `n00b_obj_bundle_write()`
and `n00b_obj_bundle_write_file()` can opt into host-entrypoint rewriting only
for explicit ELF `LOADABLE` or `SPLIT` carriers on supported ELF64
little-endian x86-64 inputs. The write-time path uses
`entrypoint_selector`, `entrypoint_strict_selector`, and
`entrypoint_policy_mode` to select and evaluate the execution target, and
embedded execution predicates observe requested mode
`N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT`. `AUTO` and `METADATA` do not upgrade
carriers for entrypoint mutation; unsupported formats, architectures, unsafe
targets, and policy denials reject before emission. This write feature still
does not launch the rewritten object.

## Reserved And Wrapped Inputs

N00b owns `.0c001.bundle`. Other `.0c001.*` names are reserved or foreign
unless a later design explicitly says otherwise.

Read policy is inspection-friendly: a unique valid selected `.0c001.bundle`
carrier can be read even when neighboring reserved, wrapped, guard, or Chalk
sections are present. Duplicate or malformed selected carriers reject.
Brandon `.0c001.file` alone is not imported as a N00b object-bundle wire
format.

Write policy is conservative. Explicit replacement is required for an existing
valid N00b-owned metadata, loadable, or split carrier. Replacement does not
authorize:

- malformed `.0c001.bundle`;
- duplicate `.0c001.bundle`;
- Brandon `.0c001.file`;
- `.0c001.wrap` or `.0c001.code`;
- unknown `.0c001.*` occupants;
- guard section type `0xc001`;
- reuse of `.chalk.free` as bundle storage.

Non-conflicting `.chalk.mark` and `.chalk.free` sections are preserved.

The current policy is intentionally about selected N00b carrier state, not
about migrating arbitrary wrapped inputs. A valid `.0c001.bundle` can coexist
with neighboring foreign/reserved/Chalk/guard sections for reads. Writes must
reject unsafe carrier environments before emission or sink persistence.

| Input state | Read behavior | Write behavior |
|-------------|---------------|----------------|
| No `.0c001.bundle` | `n00b_obj_bundle_read()` reports bundle not found. | Clean ELF inputs can receive a new selected carrier if rewrite admission succeeds. |
| One valid `.0c001.bundle` raw metadata carrier | Decode the canonical bundle. | Reject by default; replace only with `N00B_OBJ_BUNDLE_REPLACE_EXISTING`. |
| One valid `.0c001.bundle` loadable/split descriptor | Validate descriptor state first, then decode or reconstruct canonical bundle bytes. | Reject by default; replace only with `N00B_OBJ_BUNDLE_REPLACE_EXISTING`. |
| Duplicate `.0c001.bundle` | Reject as duplicate carrier. | Reject; no automatic repair. |
| Malformed `.0c001.bundle` | Reject as malformed selected carrier. | Reject; replacement does not authorize repair. |
| `.0c001.file` | Not imported as a bundle. If it appears beside a valid selected carrier, the selected carrier can still be read. | Reject as foreign legacy or reserved namespace; no Brandon legacy import. |
| `.0c001.wrap` or `.0c001.code` | Does not block reading a unique valid selected carrier. | Reject as already wrapped or reserved. |
| Unknown `.0c001.*` | Does not block reading a unique valid selected carrier. | Reject as reserved namespace occupied. |
| Guard section type `0xc001` | Does not block reading a unique valid selected carrier. | Reject writes that would require ignoring wrapped-input guard semantics. |
| `.chalk.mark` | Not a bundle carrier; can coexist with a valid selected carrier. | Preserve when non-conflicting. |
| `.chalk.free` | Not a bundle carrier or free space for bundles; can coexist with a valid selected carrier. | Preserve when non-conflicting; never reuse as object-bundle storage. |

## Contracts

The public header is the precise call-level API contract. This section
promotes the design contract skeletons into versioned documentation so future
implementation or ncc design-by-contract work has stable inputs.

These are **documentation contracts**. They summarize invariants that the
current implementation and tests are expected to preserve, but WP-018 does not
lower them into compiled ncc contracts, change public declarations, or add
runtime behavior.

| Contract family | Current documentation status |
|-----------------|------------------------------|
| Public API | Header Doxygen carries concrete `@pre`, `@post`, `@kw`, ownership, and result/error wording for public calls. |
| Internal layer boundaries | Versioned docs describe ownership between bundle core, carrier backend, rewrite, policy, extraction, and execution planning. |
| Executable contracts | Not implemented in WP-018. Future lowering must preserve the public API shape and decisions recorded here. |

### Public API Invariants

| Invariant | Contract |
|-----------|----------|
| Single surface | Callers use `include/compiler/objfile/obj_bundle.h`; format-specific ELF/Mach-O/PE carrier mechanics stay behind `_kargs` controls and backend dispatch. |
| Result shape | Fallible object-bundle APIs return `n00b_result_t()` and carry structured payloads for caller-visible errors. |
| Positional vs. optional inputs | Required values are positional. Optional behavior is controlled with `_kargs` and documented with `@kw` in public headers. |
| Allocator ownership | Returned bundles, buffers, extraction results, execution plans, and errors are allocated with the selected allocator where documented. |
| Mutation failure | Public bundle mutation calls leave the bundle unchanged on error. |
| Input immutability | Caller artifact/policy payloads, input object buffers, and input bundles are read-only sources unless a function explicitly documents otherwise. |
| Accessors | Public accessors expose observation facts. Returned lists, dictionaries, strings, plans, results, and errors should be treated as read-only unless the header says otherwise. |

### Internal Boundary Invariants

| Boundary | Contract |
|----------|----------|
| Bundle core to carrier backend | Core passes canonical bundle bytes plus a carrier request. Backend returns a new object-byte buffer or structured error. |
| Carrier backend to object-file rewrite | Backend passes concrete section/segment mutation plans. Rewrite code reports layout facts and preserves non-planned ranges; it does not interpret artifact policy or execution maps. |
| Policy runtime to extraction/execution | Policy selection and evaluation receive stable operation facts. Embedded N00b predicates compile through `n00b_eval_compile_predicate()`, not through a second evaluator. |
| Extraction planner to filesystem helpers | The planner validates policy, paths, collisions, and mode/overwrite controls before using path/sink helpers. Filesystem helpers do not interpret bundle policy. |
| Execution planner to a future executor | The plan records selected target, argv/env intent, policy facts, mode, and platform support. A later executor consumes those facts and must not reselect targets. |
| Entrypoint write path to ELF rewrite | Write-time host-entrypoint mutation uses selected bundle execution facts to enable a checked ELF `e_entry` patch; it does not become process execution. |

### Manifest And Canonical Invariants

| Invariant | Contract |
|-----------|----------|
| Full decode or error | Decode returns a fully valid bundle or fails. No partially decoded invalid bundle escapes. |
| Canonical encode | Encode emits deterministic canonical bytes for the bundle model, independent of carrier. |
| Strict shape | Decode validates magic/version, table bounds, ordering, alignment, content ID, UTF-8 strings, cross-references, digests, and canonical re-encode equality. |
| Logical paths | Logical paths are normalized before insertion and duplicate checks. They are not host filesystem paths. |
| Artifact identity | Artifact IDs are unique within the bundle, payload ranges are bounded, and v1 does not expose payload sharing. |
| Execution map integrity | At most one default executable exists. Selector mappings are unique and reference executable-compatible artifacts. |
| Policy integrity | Policy IDs are unique, policy payload digests are checked, and required policy records for the requested scope must be known and supported. |

### Carrier And Replacement Invariants

| Invariant | Contract |
|-----------|----------|
| Selected carrier authority | Reads follow the selected `.0c001.bundle` state: raw metadata bytes or a descriptor that points to loadable/split reconstruction state. |
| Metadata compatibility | `AUTO` and explicit `METADATA` write raw canonical `.0c001.bundle` bytes for ELF. |
| Descriptor validation | Loadable/split descriptor kind, version, bounds, digest, and reconstruction facts are validated before canonical decode. |
| Stale bytes | Stale non-selected loadable bytes are ignored and are never authoritative bundle payloads. |
| Explicit replacement | Existing valid N00b-owned metadata/loadable/split carriers require `N00B_OBJ_BUNDLE_REPLACE_EXISTING`. |
| Replacement limits | Replacement does not authorize malformed or duplicate carriers, Brandon `.0c001.file`, `.0c001.wrap`, `.0c001.code`, unknown `.0c001.*`, guard sections, or reuse of `.chalk.free`. |
| Byte preservation | Rewrite-backed writes preserve non-planned object-byte ranges according to the selected backend's rewrite contract. |

### Extraction Invariants

| Invariant | Contract |
|-----------|----------|
| Validate before write | Extraction validates bundle, policy, paths, destination containment, collisions, artifact kinds, overwrite, and caller controls before the first filesystem write. |
| Safety floor | In default enforcement mode, extraction does not write outside `destination_root`. Existing symlink destinations and unsafe roots are rejected before writes. |
| Caller controls narrow | `overwrite`, `create_dirs`, path controls, and policy mode do not widen bundle policy. |
| Validate-only still enforces | Validate-only mode still evaluates selected policy and rejects policy denial; it simply avoids materialization on success. |
| Direct facts | Direct extraction records planned/written files and directories and reports visible partial state on failure. |
| Atomic facts | Atomic extraction stages under a sibling temp root, commits only after validation, and reports commit, rollback, and cleanup facts. |

### Execution And Entrypoint Invariants

| Invariant | Contract |
|-----------|----------|
| Side-effect-free planning | Execution planning does not fork, exec, create `memfd`, materialize extraction output, mutate object files, patch host entrypoints, or mutate environment. |
| Deterministic selection | Selector mapping wins when present. Strict missing selectors reject. Otherwise the default executable is used when available. |
| Target validity | Selected targets are executable-compatible artifacts and are reported with artifact ID, logical path, and selection source. |
| Argv/env facts | Caller argv is preserved, absent argv synthesizes `argv[0]`, env overlays are plan-owned facts, and `inherit_env` records intent only. |
| Platform reporting | `AUTO` and `EXTRACTED` resolve to a logical extracted-execution dependency. `MEMFD` and public execution-plan `HOST_ENTRYPOINT` remain unsupported modes. |
| Write-time entrypoint mutation | Host-entrypoint mutation is an opt-in object-bundle write feature for explicit ELF `LOADABLE`/`SPLIT` carriers on supported ELF64 little-endian x86-64 inputs, not a process-launch API. |

### Policy Invariants

| Invariant | Contract |
|-----------|----------|
| Bundle-carried policy | Extraction and execution policy comes from the manifest policy table, not from caller options alone. |
| API controls narrow | Per-call controls may narrow selected policy but cannot widen it. |
| Scope and priority | Policy selection is by requested scope and priority among supported records. |
| Required records | Unknown or unsupported required records for the requested scope reject. |
| Optional fallback | Optional/fallback behavior is allowed only when the manifest declares a compatible lower-priority fallback. |
| Denial is final | A supported policy that evaluates to false denies the operation; denial does not fall back. |
| Embedded N00b | Embedded policy source is carried in a canonical payload envelope and evaluated through the shared N00b eval path with read-only operation context facts. |

### Brandon-Compatibility Invariants

| Invariant | Contract |
|-----------|----------|
| Optional reference only | Brandon remains design/oracle context, not a production dependency or default test dependency. |
| No legacy import | Brandon `.0c001.file` is not imported as a N00b v1 object-bundle wire format. |
| Promoted behavior | Stable Brandon-derived concepts become N00b-owned only when represented in canonical design/docs and Brandon-independent known-answer tests. |
| Runtime divergence | N00b object-bundle APIs do not inherit Brandon's `/proc/self/exe`, `memfd`, `execveat`, or entrypoint-wrapper runtime assumptions. |

Future executable contract lowering should treat these tables as semantic
inputs. It should not change the canonical manifest format, public API shape,
carrier authority, replacement policy, policy semantics, or runtime boundary
without a new reviewed work plan and decision.

## Brandon Compatibility

Brandon's packager is design input and optional oracle context. It is not a
production dependency, not a default test dependency, and not the N00b
object-bundle wire format.

N00b preserves the stable generic concepts:

- embedded file/artifact payloads;
- one default executable;
- selector-to-target execution mappings;
- duplicate rejection;
- meaningful `.0c001.*` namespace handling;
- byte preservation outside planned rewrite ranges.

N00b intentionally diverges by using `.0c001.bundle` for the owned bundle
format, rejecting `.0c001.file` as a legacy import format, keeping policy above
rewrite mechanics, and avoiding Linux-only runtime assumptions in the generic
execution model.

The manifest preserves the useful data-model ideas from Brandon's old embedded
filesystem: embedded payloads, a default executable, selector mappings,
duplicate rejection, and validation that execution targets exist. It
deliberately replaces Brandon's linear record stream with canonical tables,
offsets, lengths, digests, compatibility flags, and strict validation.

The runtime boundary is also different. Brandon's reference path used
Linux-specific mechanisms such as `/proc/self/exe`, `memfd`, and `execveat`.
N00b's generic object-bundle APIs stop at carrier write, extraction planning,
extraction materialization, and side-effect-free execution planning. Static
host-entrypoint mutation is an opt-in ELF write feature for supported
`LOADABLE` and `SPLIT` carriers, not a generic process-launch runtime.

Brandon-derived behavior becomes N00b-owned when it is promoted into
Brandon-independent known-answer tests. Optional Brandon oracle work remains
diagnostic and non-default. WP-019 is reserved for future mutation-oracle
expansion only if later calibration needs it.

## Implementation Status

| Area | Current state | Source trace |
|------|---------------|--------------|
| Packaging design | Approved object-bundle architecture, manifest, carrier, API, extraction, execution, wrapped-input, contract, Brandon-compatibility, and implementation projection design. | WP-007 completion notes |
| Structured results | `n00b_result_t()` supports integer and structured pointer payload errors; object-bundle APIs use structured result payloads. | WP-008 completion notes |
| Bundle core and manifest codec | Public object-bundle API, construction, validation, canonical v1 encode/decode, artifact tables, execution maps, builtin/default and declarative v1 policy records. | WP-009 completion notes |
| ELF metadata carrier | ELF `.0c001.bundle` raw metadata read/write, replacement policy, conservative reserved namespace rejection, and Chalk preservation. | WP-010 completion notes |
| File sinks | `n00b_obj_bundle_write_file()` persists rewritten object bytes through atomic/direct sink behavior after carrier policy accepts the input. | WP-011 completion notes |
| Extraction | `n00b_obj_bundle_extract()` supports policy-aware direct and atomic materialization for v1 file/directory artifacts with structured result facts. | WP-012 completion notes |
| Execution planning | `n00b_obj_bundle_exec_plan()` selects logical executable targets and records argv/env/platform/policy facts without process or filesystem side effects. | WP-013 completion notes |
| Embedded N00b policy | Embedded policy kind, payload envelope, eval context, extraction integration, and execution-plan integration are implemented through `n00b_eval_compile_predicate()`. | WP-014 completion notes |
| Loadable/split carriers | Explicit ELF `LOADABLE` and `SPLIT` carriers are descriptor-backed, validate bounds/digests/reconstruction facts, and preserve stale-byte non-authority. | WP-015 completion notes |
| Entrypoint policy | Opt-in write-time host-entrypoint mutation is implemented for explicit ELF `LOADABLE` and `SPLIT` writes on ELF64 little-endian x86-64. Runtime execution remains out of scope. | WP-016 completion notes |
| Reserved/wrapped input policy | Full default known-answer policy covers reserved `.0c001.*`, Brandon foreign names, guard sections, Chalk coexistence, replacement limits, migration, and stale-byte authority. | WP-017 completion notes |

## Future And Backlog Boundaries

| Topic | Current boundary |
|-------|------------------|
| Mach-O and PE carriers | Public API is format-neutral, but carriers are not implemented yet. |
| Process execution | Execution planning records intent and policy facts; it does not launch processes. |
| Linux `memfd` execution | Recognized as a future execution mode, currently unsupported in public execution planning. |
| Brandon `.0c001.file` import | Not a supported legacy wire format. |
| Brandon oracle expansion | Optional and non-default; projected only if later mutation diagnostics need it. |
| Compression/decompression | Reserved as a manifest extension point; unsupported in default v1 behavior. |
| Executable contracts | Current contracts are documented invariants and Doxygen, not compiled ncc contract lowering. |
