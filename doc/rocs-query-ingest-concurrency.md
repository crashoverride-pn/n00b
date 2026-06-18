# Work Plan: rocs query↔ingest concurrency (lock the shared catalog reads)

Status: SCOPED, IMPLEMENTATION NOT STARTED.
Owner: (rocs / libn00b)
Last updated: 2026-06-18

## Goal
Let a `crayon search` scan run concurrently with live ingest. Today the wax
gateway holds `g_cache_lock` for the ENTIRE scan
(`crayon_rocs_cache_query_stream`), which blocks `crayon_rocs_cache_observe_event`;
a long `--limit` query starves ingest until the queue overflows and events drop.
Dropping that lock must be safe.

## What is ALREADY solved (do not redo)
- The moving-GC register-forwarding crash (`project_async_seal_gc_worker_race`)
  is FIXED by the Bartlett mostly-copying pinning GC — Steps 1–4 of
  `doc/gc-mostly-copying-pinning.md` are implemented in-tree and ALL THREE repros
  pass on the current tree (`rocs_async_seal_stress`, `worker_pool_gc_stress`,
  `gc_worker_trace` = OK in build_debug). That doc's "Step 2 marking-only" status
  is STALE. So the GC relocation hazard for a preempt-suspended thread is handled.
- Query allocations are off the GC heap (wax per-query non-GC arena; commit qkk).
- `--limit` is enforced via a monotonic counter (commit pt).

## The remaining hazard: a data race on the catalog (PROVEN)
Two attempts to drop `g_cache_lock` crashed (crash logs):
1. ingest thread SIGSEGV in `n00b_lru_get` (file-lifecycle LRU);
2. query thread SIGSEGV in `n00b_query_cursor_next` → plan dispatch →
   `n00b_store_catalog_entry_*`.
Root cause of (2): the query scan resolves LIVE catalog entries per boundary —
`rocs_query_validate_boundary_entry` → `n00b_store_catalog_find_shard` →
`rocs_store_catalog_find_raw` — which reads `store->catalog` with NO lock, while
the seal worker appends/mutates the catalog under `store->commit_lock`
(store.c commit phase, ~3072). `g_cache_lock` was the only thing serializing the
two. This is a reader/writer data race, not a GC bug.
Root cause of (1): `n00b_lru_t` has NO locking — `n00b_lru_init` builds its index
with `n00b_dict_new_private` (unlocked) and the struct has no lock field; the
file-lifecycle LRU is mutated by ingest with no guard. (dict/list support a
locked vs `_private` mode per WP-010; the LRU never got it.)

## Plan
P1 — Repro under build_debug: a test that runs a snapshot cursor scan while a
   second thread seals shards into the same store; expect a crash today. This is
   the gate for the rest.
P2 — Lock the rocs catalog reads. The catalog is a PRIVATE (unlocked) n00b_list
   (`n00b_list_new_private`); seal appends under `commit_lock` WRITE (store.c
   commit phase ~3107); prune frees entries via `n00b_list_delete` (store.c:7475
   — must also be under commit_lock write; verify). Take `commit_lock` as a READ
   lock around the QUERY-side catalog walks:
     - `rocs_query_validate_boundary_entry` / the scan's `catalog_find_shard`
       call (query.c ~3149) — commit_lock(read) alone, brief: find + copy the
       entry fields the scan needs, release.
     - `rocs_store_catalog_owns_entry` (store.c:2098) — traverses the catalog
       while the caller holds `residency_lock` (inside resident_shard_acquire),
       so it takes commit_lock(read) WHILE holding residency_lock.
   Do NOT add the lock inside `rocs_store_catalog_find_raw`: seal/rotate paths
   call it WHILE holding commit_lock write (store.c:3165) → self-deadlock. Lock
   only the query-side callers.
   LOCK ORDER (must be global): residency_lock → commit_lock. Established by the
   close path (residency_lock then commit_lock) and owns_entry above. The query
   validate path takes commit_lock alone (released before residency acquire), so
   it never nests the other way. Seal commit takes commit_lock alone. Verify no
   commit_lock-write holder calls a path that now takes commit_lock read.
   Entry lifetime: entries are stable once created; a query holding one across a
   lock release is safe because the residency pin keeps the shard+entry alive
   (prune/trim skip pinned). Confirm prune respects pins before relying on this.
P3 — Give `n00b_lru_t` an optional locked mode: add a `lock` slot + a
   `n00b_lru_new`/`_private` split (mirror dict). Enable locking on the
   file-lifecycle LRU (wax) since ingest mutates it and a concurrent query (or
   future reader) must be safe. (Confirm whether anything besides the single
   ingest thread touches it; if strictly single-threaded, locking it is cheap
   insurance but P2 may be sufficient for the crash — validate.)
P4 — Drop `g_cache_lock` during the scan in wax `crayon_rocs_cache_query_stream`
   (already prototyped + reverted). Keep setup (flush + view/cursor snapshot)
   under the lock; release for the scan loop; cleanup is rocs-internally locked.
P5 — Validate: sustained concurrent query+ingest soak — gw pid stable,
   `rocs_pressure_dropped` flat under query load, footprint bounded, results
   correct. Full build_debug unit suite green. prompt-auditor → n00b-code-auditor
   before push.

## Risks
- Lock ordering commit_lock↔residency_lock — must be consistent or it deadlocks.
- commit_lock as a read lock on the hot query path adds contention with seal;
  measure. The catalog is small; read-lock hold should be brief (find + copy out
  the entry fields the scan needs, then release).
- The boundary snapshot is captured at view creation; the scan re-resolves live
  entries only to acquire residency. An alternative to P2 is to capture the full
  catalog-entry data needed into the (non-GC) boundary snapshot at view creation
  so the scan never touches the live catalog — heavier but lock-free on the scan.

## See also
- `doc/gc-mostly-copying-pinning.md` (the GC half — done).
- auto-memory `project_query_write_oom_root_causes`.
