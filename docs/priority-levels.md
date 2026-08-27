# Priority levels (P0–P3)

**n00b does not maintain its own priority rubric. The authoritative definition is
[`crashappsec/wax` → `docs/priority-levels.md`](https://github.com/crashappsec/wax/blob/main/docs/priority-levels.md).**

This file exists so that the divergence question has a written answer instead of
being inferred from label descriptions. There is one definition of P0 across both
repos; if that ever stops being true it must be recorded here as a deliberate
carve-out, the way crayon_ui's sequencing exception is.

Adopted at wax `main` @ `59d5d9d7`, merged as `418e1df6` (PR#680, "docs: the missing-trailer clause was
vestigial and contradicted the gating rule"), 2026-08-27.

## Why this repo needed the pointer

n00b's `P1` label previously read *"a P0 whose gate is not yet open."* That is the
demote-on-gating rule, which the wax document explicitly reverses:

> Gating does not change an issue's level. A blocked P0 is a P0.

So for a period the two repos meant different things by the same label and nothing
said so. The label descriptions have been rewritten to match the gates.

## The clause that governs most n00b rows

n00b is a library with no users of its own, so **inherited severity** decides most
gradings here. Both halves must hold before a downstream failure becomes n00b's P0:

1. a named downstream consumer is blocked in a shipping path, **and**
2. the defect reproduces inside this library's own boundary — its own tests, its
   own harness, no downstream binary required.

If (1) holds and (2) does not, the row is **blocked-on-reporter**, not n00b's P0.

Note what this is *for*: it is an actionability test, not a paperwork test. The
document names its own purpose — requiring only (1) would have made `#192` a P0
nobody could act on. A defect established from source at a pinned commit, with a
named line and a writable fix, is actionable whether or not a test exists yet; in
that case the correct move is usually **add the repro and keep the level**, not
demote. `#226` is the worked example.
