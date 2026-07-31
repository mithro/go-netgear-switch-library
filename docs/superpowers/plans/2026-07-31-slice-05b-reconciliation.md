# Slice 05b: Reconciliation to 1841111 — Dispatch + Mock Widths

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the merged facade + virtual mock into line with the re-pinned
reference (`main` @ `1841111`) on the two foundational, safety-critical
drifts: (A) **no silent backend fallback** — one explicitly-chosen backend per
op (principle 1); (B) **the mock emits real measured VLAN PortList widths**,
and the SNMP writer preserves the device width on membership RMW (principle 5).

**Architecture:** per the committed dossier
`docs/superpowers/plans/2026-07-31-slice-05b-dossier-reconciliation.md`
(**D-REC**) — read by every implementer first. NORMATIVE SOURCE (wins): frozen
snapshot
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1841111`
(`sync_api.py`, `_dispatch.py`, `virtual/state.py`, `seed.py`, `snmp_write.py`
+ the tests D-REC tabulates). Pin guard: snapshot HEAD starts `1841111`, else
BLOCKED.

**This is reconciliation of ALREADY-MERGED code** — expect to rewrite existing
tests that pinned the old (now-repudiated) behaviour. Every such rewrite is
deliberate and listed in the task report with the old vs new assertion.

## Global Constraints

- Principle 1: an op runs on ONE backend (model default via preference OR an
  explicitly requested one); NO fallback; a chosen backend that can't serve →
  error naming it (+ hint when it was a default). CredentialError still
  propagates immediately.
- Principle 5: seed MEASURED per-model VLAN widths (gsm7252ps=79, gsm7228ps=45,
  m4300-24x=131, m4300-16x=131; Plus models + gs728tpp = unset/formula); the
  mock and the SNMP writer both consult the state/device width, never the
  `VlanBitmapWidth` formula, when a real width exists.
- Honesty/TDD/race/coverage≥90%/gates/no-stash/trailers as prior slices.

---

### Task 1: Facade single-backend dispatch (no fallback) + explicit selection

**Files:** Modify `dispatch.go`, `write_dispatch.go`, `switch.go`,
`switch_write.go`, `backend_snmp.go`, `backend_nsdp.go`; Test
`switch_test.go`, `switch_write_test.go` (rewrite dispatch tests).

Per D-REC Topic A:
- Add `resolveBackend(requested *model.Backend) (model.Backend, error)` mirroring
  `_dispatch.resolve_backend`: requested nil → first of `backendPreference` the
  model declares; explicit backend the model lacks → error (exact message per
  D-REC). Add `Switch.backend *model.Backend` (session default) +
  `WithBackend(model.Backend)` option.
- Rework `readVia`/`writeVia`: resolve ONE backend, build/cache its reader/
  writer, run the op, on UnsupportedCapability call `cannotServe(chosen,
  requested, err)` (the two exact message shapes — explicit-vs-default with the
  "pass backend=..." hint; port Python's `_cannot_serve` text verbatim, Go-cased
  `backend=Backend.<X>` → whatever the Go override spelling is). NO loop.
- Per-op backend override: reads take a variadic `ReadOption`/`WithReadBackend`;
  writes get a `Backend *model.Backend` field on the existing `Write{Force}`
  struct (D-REC-recommended shapes). Wire every read/write method + Snapshot.
- `Identify`/`NSDPDevice` bypasses unchanged. Update EVERY call site D-REC lists.

- [ ] TDD: rewrite the ~21 `TestReadVia_*`/`TestWriteVia_*` per the new
  semantics (skip→error-naming-backend; explicit-backend-lacking→error;
  no-fallback; cache still one-build; credential propagation); new tests for
  WithBackend default + per-op override + the two cannotServe message shapes.
  Commit `feat(facade): single-backend dispatch with explicit selection, no fallback`.

---

### Task 2: Snapshot + facade integration reconciliation

**Files:** Modify `snapshot.go` (re-read per D-REC's flagged follow-up); Tests
`switch_read_test.go`, `facade_integration_test.go`, `facade_nsdp_integration_test.go`,
`facade_write_integration_test.go`.

Per D-REC trap #4 and the call-site list:
- Snapshot degrades an unsupported field to empty on the SINGLE resolved
  backend — it does NOT fall through to a second backend. Fix
  `TestSnapshot_DegradesUnsupportedFieldsToEmptyAndFallsThroughToSecondBackend`
  to assert degrade-to-empty (mirror the current Python snapshot test).
- Audit every facade integration test that relied on fallback (gs305ep/
  gs110emx multi-backend expectations, the "falls through to HTTP for PoE"
  cases): each op now targets one backend; where the old test expected a
  second backend to fill a gap, it must either pass an explicit backend or
  assert the honest per-backend result. List each change in the report.

- [ ] TDD; commit `fix(facade): Snapshot degrades to empty, no second-backend fallthrough`.

---

### Task 3: Real VLAN PortList widths (mock + SNMP writer)

**Files:** Modify `virtual/state.go` (+ `state_oidmap.go`), `virtual/seed.go`,
`snmp/writer_vlan.go`, possibly `snmp/write.go`; Tests
`virtual/state_test.go`/`seed_test.go`, `snmp/writer_vlan_test.go`,
`facade_write_integration_test.go`.

Per D-REC Topic B:
- Add a per-model measured `VLANPortListWidth` (nil-able) to State/seed; seed
  the real values (79/45/131/131; Plus+gs728tpp nil). Mock `oid_map` VLAN
  egress/untagged emission uses the seeded width when set, else the formula
  (`VlanBitmapWidth`) — exactly as Python prefers `vlan_portlist_width`.
- SNMP writer `SetVlanMembership`: fetch the RAW device octet-string bitmaps
  (from the pre-write read) and RMW **preserving their byte width** — do NOT
  re-derive width via `EncodePortBitmap(ports, 8)`/`VlanBitmapWidth`. This is
  the actual slice-04 bug D-REC trap #3 names; fixing the mock alone without
  this breaks `TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts`.
  Confirm `MembershipBitmaps`/`SetPortBit` preserve an already-correct wider
  input width (D-REC open item — verify against `set_port_bit`'s
  `max(8, current, requested)` and adjust the RMW call to pass the device
  width, not 8).
- Update the width-derivation callers; add tests pinning: mock emits 79-byte
  egress for gsm7252ps; writer RMW round-trips a 79-byte bitmap preserving all
  other ports' bits at full width.

- [ ] TDD; commit in two if cleaner: `feat(virtual): seed real per-model VLAN PortList widths` then `fix(snmp): preserve device VLAN bitmap width on membership RMW`.

---

### Task 4: Orchestrator — gates, PR, final review, merge (+ optional live width verify)

- [ ] Gates; push; PR; CI; final whole-branch review (fable) + ledger triage;
  ONE fix wave + scoped re-review; merge; cleanup; memory/divergence update.
- [ ] OPTIONAL live verification (principle 5 grounding): if a managed switch is
  reachable, walk `dot1qVlanStaticEgressPorts` on a real gsm7252ps/m4300 via
  gosnmp and CONFIRM the octet-string width equals the seeded value
  (79/131) — record the host+firmware in the report and, if it differs,
  the SEED is wrong (fix the seed, per principle 5). Read-only walk; no writes.

## Self-review
- Principle 1 ✓ (T1/T2 remove all fallback; explicit selection added). Principle
  5 ✓ (T3 seeds measured widths, writer preserves device width; T4 optionally
  grounds them on hardware). Spec §2.1 revised backend-selection ✓.
- Interfaces: Write{Force,Backend} + ReadOption used across all facade ops
  (T1) consumed by T2/T3 integration tests; State.VLANPortListWidth (T3) read
  by mock + (transitively) proven by the writer RMW test.
- Scope note: this does NOT port the broader NSDP-tag-surface / SNMP-VLAN-
  dialect / HTTP-now-implemented drifts — those belong to their owning slices
  (06 HTTP, a later NSDP/SNMP catch-up, or the completion audit). Only the two
  foundational dispatch + width drifts are in scope here.
