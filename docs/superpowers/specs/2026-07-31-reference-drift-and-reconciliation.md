# Reference Drift & Reconciliation — Re-pin to 1841111

**Date:** 2026-07-31
**Status:** Assessment; reconciliation plan pending user steer

## What happened

The Python reference (actively developed by the repo owner) advanced ~25
commits past the slice-05 pin `1aa1274` to `main` @ `1841111`. Fresh read-only
snapshot worktree:
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1841111`.

The owner also recorded **five non-negotiable design principles** in a
root `CLAUDE.md` (commit `cef13bc`), "after this codebase violated all five."
They align with and sharpen the standing /goal (faithful parity, no
papering-over). Summarised:

1. **Fail fast and loud; never paper over.** *Specifically forbidden:
   switching protocol/backend mid-operation.* A caller who asks for SNMP gets
   SNMP or an error — never a silent retry over HTTP (data loss disguised as
   success; a write hazard when SNMP write access is deliberately locked down).
2. **Backends must have feature parity.** Every backend a model supports must
   offer the same ops; a missing op is a missing implementation to build, not a
   device limitation, until proven with captured device output.
3. **Every model, not just the one in front of you.** Verify per-SKU;
   firmware differs within a family.
4. **A failure is something you did wrong** — debug before blaming hardware;
   record limitations only with quoted device output + firmware version.
5. **The fake must behave like real hardware; when it differs, fix the fake.**
   Seed *measured* device values, never values computed with the same formula
   as the code under test (that proves nothing).

## Drifts into ALREADY-MERGED Go slices

| Area | Merged slice | Reference change | Principle |
|---|---|---|---|
| **Facade dispatch** | 03/04/05 | Silent SNMP→NSDP→HTTP fallback loop REMOVED. Now: ONE backend, chosen by `self.backend` default or an explicit `backend=` arg; op the chosen backend can't serve → error naming the backend + hint. New explicit-backend-selection API surface. | 1 |
| **Mock VLAN PortList width** | 02/04 | Mock emitted egress/untagged bitmaps via `vlan_bitmap_width(model)=max(8,ceil(ports/8))` — the SAME wrong formula as the buggy writer. Real widths are measured (79/131/45 bytes, not port-count-derivable). Mock now seeds real widths. | 5 |
| **SNMP VLAN write** | 04 | Per-model VLAN write dialects (qbridge vs vendor switchport); egress-writable only when no port is access-mode; two-PDU ordering (egress first, untag auto-follows). | 3,4 |
| **HTTP ops** | (06, not yet built) | `set_port_enabled`/`set_mgmt_ip`/`clear_poe_fault`/VLAN membership now IMPLEMENTED over HTTP (were UnsupportedCapability at `1aa1274`); gsm7252ps PoE-over-HTTP works. | 2 |
| **NSDP** | 05 | "measure the real NSDP tag surface; fix 10G reads, add port names, VLAN create/delete." Slice 05 ported the `1aa1274` NSDP behaviour. | 2,3 |
| **CLI write backend** | (07/08) | Full CLI write backend added, live-verified on 4 models. | 2 |
| **MCP** | (09) | Explicit backend selection on every MCP tool. | — |

The Go slices 02–05 faithfully mirror `1aa1274`; several now diverge from
`1841111`. Slices 06+ have not been built, so they naturally port the new
behaviour if we re-pin.

## The fork (user decision)

**Option A (recommended): re-pin to 1841111 now; reconcile before HTTP.**
Adopt the five principles as binding. Insert a **reconciliation slice** before
slice 06 that: (1) reworks the Go facade to single-backend-no-fallback +
explicit backend selection (`WithBackend`, `backend=`-equivalent per-op
option), matching the current `_read`/`_write`; (2) fixes the mock VLAN
PortList real-width fidelity (principle 5). Then slice 06 (HTTP) and all later
slices port against `1841111`. NSDP tag-surface + SNMP VLAN-dialect drifts
become targeted follow-ups folded in where they belong (or into the
completion-audit phase). This keeps the end state a faithful match of the
current library — which the /goal requires.

**Option B: stay on 1aa1274 to the end; reconcile everything at the finish.**
Finish all 12 slices against the frozen old pin, then do one big catch-up pass
to `1841111` (or wherever main is then). Simpler mid-flight, but builds more
on soon-to-change behaviour (esp. the dispatch model that everything routes
through) and delays a write-safety-critical fix (principle 1).

**Option C: something else** (e.g. pin to a specific intermediate commit, or
defer the dispatch rework but adopt the HTTP/NSDP behaviour).
