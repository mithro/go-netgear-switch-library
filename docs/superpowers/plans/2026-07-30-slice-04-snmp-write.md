# Slice 04: SNMP Write + Facade Write Methods — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** `snmp.Writer` (all SNMP write/control ops with verify-after-write,
the PoE cycle state machine, VLAN bitmap RMW), facade write dispatch
(`writeVia`, write-community gate, `Write{Force}` options, protected-port
guards), proven against the slice-02 VirtualSwitch (whose write faces are
already complete).

**Architecture:** per the committed dossier
`docs/superpowers/plans/2026-07-30-slice-04-dossier-snmp-write.md` (**D-WR**)
— read by every implementer first. NORMATIVE SOURCE (wins): frozen snapshot
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274`
(`src/netgear_switch/protocols/snmp/write.py`, `snmp_write.py`,
`sync_api.py` write side + the test files D-WR tabulates). Pin guard:
snapshot HEAD starts `1aa1274`, else BLOCKED.

**Tech Stack:** existing packages; no new dependencies.

## Global Constraints

- Verify-after-write EVERYWHERE per D-WR: re-read, compare,
  `*model.WriteVerificationError{Msg, Before, After}` with Python-equivalent
  payloads; precondition failures (e.g. delete of missing VLAN) are
  `ErrSNMP`-class errors, NOT verification errors — keep the distinction.
- PoE rearm = TWO SEQUENTIAL SETs (never one duplicate-OID SetMany);
  injectable clock+sleep; PoeCycleTimeouts{Off 30s, On 60s, Poll 2s} defaults.
- VLAN membership = read both bitmaps → RMW target port bit only → ONE
  atomic 2-varbind SetMany (`x` type, width max(8,ceil(ports/8))) → verify
  BOTH columns. PVID SET is Gauge32 (`u`).
- Write-community gate is the STRICTER one (rejects nil AND ""; D-WR
  asymmetric-gates trap) wrapping ErrCredential with Python's message shape.
- Facade: protected-ports refuse disruptive writes without Force
  (ErrProtectedPort, exit-code-4 class); delete-VLAN facade-level member
  guard; writeVia mirrors readVia semantics with its own writer cache.
- Honesty rules; TDD; race-clean; coverage ≥90%; gates via make; NO git
  stash; trailers:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` +
  `Claude-Session: https://claude.ai/code/session_01HchhGh659AVsp7J4yyidLc`.

---

### Task 1: `snmp` write encoders (consolidation + net-new)

**Files:** Create `snmp/write.go`; Modify `virtual/state_oidmap.go` (+ any
virtual callers) to consume the snmp-package encoders; Test
`snmp/write_test.go`.

**Produces:**
```go
func EncodePortBitmap(ports []int, widthBytes int) []byte // MSB-first; grows past width when needed
func SetPortBit(bitmap []byte, port int, on bool) []byte  // per D-WR set_port_bit semantics (copy+grow)
func MembershipBitmaps(egress, untagged []byte, port int, mode model.VlanMode, width int) (newEgress, newUntagged []byte) // per D-WR membership_bitmaps table
func VlanBitmapWidth(portCount int) int                   // max(8, ceil(portCount/8))
```
virtual's unexported duplicates (encodePortBitmap/vlanBitmapWidth) are
REPLACED by these (delete duplicates; virtual imports snmp already).

- [ ] TDD per D-WR §1 + test_write_encode.py intents (mode table:
  untagged→both bits set; tagged→egress set, untagged cleared;
  excluded→both cleared; inverse property vs DecodePortBitmap); virtual
  suite must stay green after consolidation. Commit
  `feat(snmp): write encoders (bitmap RMW, membership modes, width)`.

---

### Task 2: `snmp.Writer` — simple sets + verify mechanics

**Files:** Create `snmp/writer.go`; Test `snmp/writer_test.go`.

**Produces:**
```go
type Writer struct{ ... } // NewWriter(c WriteClient, m *model.SwitchModel) (*Writer, error) — same _require_snmp gate as NewReader
func (w *Writer) SetPoE(ctx, port int, on bool) error
func (w *Writer) SetPortEnabled(ctx, port int, enabled bool) error
func (w *Writer) SetPVID(ctx, port, vlan int) error // Gauge32 "u"
// internal verify helper(s) matching D-WR re-read/compare/WriteVerificationError payloads exactly
```

- [ ] TDD with a fake WriteClient (records SetVarbinds; serves canned
  post-write reads): exact varbind (oid/type-letter/value) pins per op;
  verify-success, verify-mismatch (Before/After payloads exact),
  re-read-error propagation. Mirror D-WR's test_snmp_write.py intents for
  these ops. Commit `feat(snmp): writer simple sets with verify-after-write`.

---

### Task 3: `snmp.Writer` — VLAN lifecycle + mgmt-IP

**Files:** Modify `snmp/writer.go`; Test `snmp/writer_vlan_test.go`.

**Produces:**
```go
func (w *Writer) SetVlanMembership(ctx, vlan, port int, mode model.VlanMode) error // RMW + atomic 2-varbind + verify BOTH
func (w *Writer) CreateVlan(ctx, vlan int, name string) error  // RowStatus 4 + name, one SetMany; verify per D-WR
func (w *Writer) DeleteVlan(ctx, vlan int) error               // existence PREcondition (ErrSNMP) then RowStatus 6 + verify-gone
func (w *Writer) SetMgmtIP(ctx, address, netmask, gateway string) error // vendor "a" varbinds; caller enforces Force; verify all 3 fields individually
```

- [ ] TDD per D-WR: RMW preserves other ports' bits (trunk-preservation pin);
  atomic SetMany call-shape pin; delete-missing-VLAN is precondition error
  not verification; mgmt-IP three individual verifies; no-vendor-base model
  → ErrUnsupportedCapability. Commit
  `feat(snmp): VLAN lifecycle and mgmt-IP writes`.

---

### Task 4: `snmp.Writer` — PoE cycle state machine

**Files:** Modify `snmp/writer.go`; Test `snmp/writer_cycle_test.go`.

**Produces:**
```go
type PoeCycleTimeouts struct{ Off, On, Poll time.Duration } // defaults 30s/60s/2s via DefaultPoeCycleTimeouts()
func (w *Writer) CyclePoE(ctx, port int, t PoeCycleTimeouts) error
func (w *Writer) ClearPoEFault(ctx, port int, t PoeCycleTimeouts) error
// injectable clock/sleep seam per D-WR (WithClock writer option or struct fields — follow D-WR's recommended shape)
```

- [ ] TDD with fake clock (no real sleeps in tests): off→poll(detect∈{1,2} AND
  link down, ≤Off)→on→poll(delivering for cycle; delivering-or-searching for
  clear-fault, ≤On); TWO sequential Set calls pinned (never SetMany);
  timeout → error with Python-equivalent message; poll cadence honoured.
  Commit `feat(snmp): PoE cycle and clear-fault state machine`.

---

### Task 5: Facade write dispatch + write methods

**Files:** Create `write_dispatch.go`, write methods in `switch.go` (or
`switch_write.go`); Modify `dispatch.go` minimally if shared plumbing needs
extraction; Test `switch_write_test.go`.

**Produces:**
```go
type Write struct{ Force bool } // spec §5 options struct
type BackendWriter interface{ /* per D-WR: write-op surface */ }
// writer seam parallel to readers: RegisterBackendWriter(...), writeVia(...), writerFor(...)
func (s *Switch) SetPoE(ctx, port int, on bool, o Write) error
func (s *Switch) SetPortEnabled(ctx, port int, enabled bool, o Write) error
func (s *Switch) SetPVID(ctx, port, vlan int, o Write) error
func (s *Switch) SetVlanMembership(ctx, vlan, port int, mode VlanMode, o Write) error
func (s *Switch) CreateVlan(ctx, vlan int, name string, o Write) error
func (s *Switch) DeleteVlan(ctx, vlan int, o Write) error       // facade member-guard per D-WR
func (s *Switch) SetMgmtIP(ctx, address, netmask, gateway string, o Write) error // Force MANDATORY
func (s *Switch) CyclePoE(ctx, port int, o Write, opts ...CycleOption) error
func (s *Switch) ClearPoEFault(ctx, port int, o Write, opts ...CycleOption) error
```
Protected-port guard per D-WR (which ops, message, Force bypass); write
community via stricter gate + resolveOnce cell; SNMP backend-writer shim in
backend_snmp.go.

- [ ] TDD per D-WR facade intents: guard matrix (each disruptive op × 
  protected/unprotected × Force); guard fires BEFORE dispatch/credential
  resolution (mirror Python order — verify in source); write-community gate
  asymmetry; delete-VLAN member guard (needs a read first — mirror source
  mechanics); writeVia skip/reraise parity. Commit
  `feat(facade): write dispatch, safety rails, write methods`.

---

### Task 6: Write integration capstone vs VirtualSwitch

**Files:** Test `facade_write_integration_test.go` (netgearswitch_test).

- [ ] Against VirtualSwitch(gsm7252ps) over real UDP: SetPVID visible in
  subsequent GetPVIDs; SetVlanMembership untagged/tagged/excluded round-trip
  preserving other ports (check vlan 90's other members); CreateVlan
  3999+name then DeleteVlan; SetPoE off→on with fake-coherence
  (detect/link transitions observable via GetPoE/GetPorts); CyclePoE with
  short injected timeouts completes against coherent fake; protected-port
  refusal end-to-end; SetMgmtIP Force-gated round-trip (fake accepts vendor
  writes); write-verification-failure path: SET an is-writable-but-no-op...
  (per D-WR: pick the Python-mirrored scenario — e.g. absent-instance
  ifAdminStatus port → face accepts, state no-ops, verify catches →
  WriteVerificationError). Mirror test_snmp_write_face.py +
  write-equivalence intents. Commit
  `test(facade): write integration capstone against the virtual switch`.

---

### Task 7: Orchestrator — gates, PR, final review, merge

- [ ] make cover ≥90%; push; PR; CI; final whole-branch review (fable) incl.
  D-WR parity spot-checks + ledger triage; ONE fix wave + scoped re-review;
  merge; cleanup; update memory/divergence log; consider opt-in live-hardware
  WRITE smoke per approved policy (link-down port on a designated switch,
  restore after) — EXECUTE only if a clearly-safe target exists, else defer
  to slice 11 with a note.

---

## Self-review
- Spec §2.1 write ops (SNMP-scope) ✓ T2-T5; §6-equivalent write safety ✓
  (verify, rails, cycle machine) T2-T5; §8 fake write behaviour — already
  complete (D-WR §4), exercised by T6. Cert/SCP paths are slices 06/07.
- Types consistent: Writer consumes WriteClient (slice-02); Write{Force}
  matches spec §5; encoders consolidated so virtual + snmp share one
  implementation (T1 before all).
- No placeholders; D-WR carries exact semantics/messages.
