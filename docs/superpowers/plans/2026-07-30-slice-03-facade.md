# Slice 03: Switch Facade + Read APIs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** The root-package `Switch` facade: model-driven read dispatch over
the backend seam (SNMP live now; NSDP/HTTP/CLI plug in via slices 05–07),
lazy once-only credential resolution, `Snapshot` degrade semantics,
`Identify`, `DetectModel`, `FromConfig`, proven against the slice-02
VirtualSwitch.

**Architecture:** per the committed dossier
`docs/superpowers/plans/2026-07-30-slice-03-dossier-facade.md` (**D-FAC**) —
read by every implementer first. NORMATIVE SOURCE (wins over dossier):
frozen snapshot
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274`
(`src/netgear_switch/sync_api.py`, `_dispatch.py` + the test files D-FAC
tabulates). Pin guard: snapshot HEAD must start `1aa1274`, else BLOCKED.

**Tech Stack:** existing repo packages only (model, snmp, virtual for tests);
no new dependencies.

## Global Constraints

- Single ctx-based facade following SyncSwitch semantics (never AsyncSwitch's
  async-only restrictions) — D-FAC is explicit about the deltas.
- Backend preference (SNMP, NSDP, HTTP, SSH) with UnsupportedCapability
  skip-and-reraise-LAST; ErrCredential NEVER swallowed by dispatch.
- Lazy once-only secret resolution (resolve-once, cache result including nil).
- Honesty rules; errors wrap the model sentinels with Python-equivalent
  message content.
- TDD; race-clean; coverage ≥90% library-only; gofmt/vet/golangci-lint clean;
  make targets (jailed); NO git stash; commit trailers:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` +
  `Claude-Session: https://claude.ai/code/session_01HchhGh659AVsp7J4yyidLc`.

---

### Task 1: Backend seam + Switch construction + dispatch core

**Files:** Create `switch.go`, `dispatch.go`; Test `switch_test.go` (root
package `netgearswitch`).

**Interfaces — Produces (exact; details per D-FAC's Go-seam section):**
```go
// dispatch.go
type BackendReader interface { /* per D-FAC: the read-op surface the
    dispatch loop calls; ops it cannot serve return an error wrapping
    model.ErrUnsupportedCapability */ }
type BackendBuilder func(sw *Switch) (BackendReader, error)
func RegisterBackend(b model.Backend, build BackendBuilder) // package-level registry; slices 05-07 call from init()
var backendPreference = []model.Backend{model.BackendSNMP, model.BackendNSDP, model.BackendHTTP, model.BackendSSH}

// switch.go
type Switch struct{ /* model, host, resolved-secret cells, reader cache */ }
type SwitchOption func(*Switch)
func New(m *model.SwitchModel, host string, opts ...SwitchOption) (*Switch, error)
func WithSNMPCommunity(s string) SwitchOption
func WithSNMPWriteCommunityResolver(r func() (*string, error)) SwitchOption
func WithSNMPClient(c snmp.Client) SwitchOption   // test injection
func WithProtectedPorts(ports ...int) SwitchOption
func WithNSDPInterface(s string) SwitchOption      // stored; consumed slice 05
func WithHTTPPasswordResolver(r func() (*string, error)) SwitchOption // stored; slice 06
func FromConfig(cfg SwitchConfig, opts ...SwitchOption) (*Switch, error) // maps SwitchConfig fields per D-FAC
func (s *Switch) Close() error
```
Dispatch core: `readVia(ctx, op string, fn func(BackendReader) error) error`
walking backendPreference ∩ model.Backends; builder-or-op
ErrUnsupportedCapability → skip + remember last; ErrCredential → propagate
immediately; no backend served → last unsupported error (or a fresh one if
none seen). Reader cache per backend. Unregistered-but-model-supported
backend (NSDP/HTTP/SSH today) → treated as unsupported-with-remembered-error
mentioning the backend (D-FAC seam semantics) so gs110emx constructs fine
and reads fail honestly until slice 05.

- [ ] Steps: TDD per D-FAC construction/dispatch test intents (from
  test_sync_api.py): construction never resolves secrets nor does I/O;
  fake-backend registry tests for skip order, reraise-last, credential
  propagation, cache reuse (builder called once); FromConfig field mapping;
  protected-ports stored sorted. Commit
  `feat(facade): Switch construction, backend seam, read dispatch core`.

---

### Task 2: SNMP backend adapter + read methods + Snapshot + Identify

**Files:** Create `backend_snmp.go`, `snapshot.go`; Modify `switch.go`;
Test `switch_read_test.go`.

**Interfaces — Produces:**
```go
// backend_snmp.go: init() RegisterBackend(model.BackendSNMP, buildSNMPReader)
// buildSNMPReader: community default "public"? NO — per D-FAC: community nil => prompt-free error path per Python (document exactly); uses snmp.NewGoSNMPClient + snmp.NewReader
// switch.go read methods (all ctx):
func (s *Switch) GetPorts(ctx) ([]PortStatus, error)   // + GetStats, GetVlans, GetPvids, GetLldp, GetMacs (require_mac_table gate first), GetPoe, GetSensors, GetMgmtIP
func (s *Switch) Identify(ctx) (DetectedModel, error)  // BYPASSES dispatch: direct SNMP client per D-FAC
func (s *Switch) Snapshot(ctx) (SwitchData, error)     // per-field degrade semantics EXACTLY per D-FAC (which errors swallowed per field, which propagate)
```

- [ ] Steps: TDD with injected fake snmp.Client (reuse reader-test fake
  pattern) for unit semantics; require_mac_table gate message parity; snapshot
  degrade matrix (unsupported → empty field; credential/transport errors →
  propagate) exactly as D-FAC tabulates. Commit
  `feat(facade): SNMP-backed reads, Snapshot degrade semantics, Identify`.

---

### Task 3: DetectModel free function + root-package aliases

**Files:** Create `detect.go`; Modify `alias.go` if needed; Test
`detect_test.go`.

```go
func DetectModel(ctx context.Context, host string, opts ...DetectOption) (DetectedModel, error)
type DetectOption func(*detectConfig)
func WithDetectCommunity(s string) DetectOption
func WithDetectClient(c snmp.Client) DetectOption
```
Per D-FAC detect_model(): builds a GoSNMPClient (default community per
Python's default), delegates to snmp.ReadSystemInfo.

- [ ] Steps: TDD (fake client: matched, unmatched, sysObjectID-first);
  ensure public API surface via root import only (test_public_api intent —
  add a Go test asserting the exported surface compiles from a single
  import). Commit `feat(facade): DetectModel entry point`.

---

### Task 4: Facade integration capstone vs VirtualSwitch

**Files:** Test `facade_integration_test.go` (root, `netgearswitch_test`).

- [ ] Steps: against virtual.NewVirtualSwitch("gsm7252ps"): every facade read
  non-vacuous matching the slice-02 capstone pins (reuse the pin values);
  Snapshot returns all fields populated for gsm7252ps; Snapshot on
  m4300-24x has empty PoE (degrade) while GetPoe errors; gs110emx (NSDP
  model, no Go NSDP yet): New succeeds, GetPorts fails wrapping
  ErrUnsupportedCapability mentioning nsdp, Snapshot returns all-empty
  fields honestly; Identify + DetectModel against the live fake (gsm7252ps
  + gsm7228ps sysObjectID case). Commit
  `test(facade): integration capstone against the virtual switch`.

---

### Task 5: Orchestrator — gates, PR, final review, merge

- [ ] make cover ≥90%; push branch; PR; CI green; final whole-branch review
  (most capable model) incl. D-FAC parity spot-checks + ledger triage; ONE
  fix wave + scoped re-review; merge via PR merge commit; cleanup workspace/
  worktree; update roadmap tick + memory + cross-language-divergences.md if
  new adjudications.

---

## Self-review
- Spec §2.1 read-op dispatch semantics ✓ (T1/T2), §5 API sketch ✓ (T1-T3),
  detect ✓ (T3), snapshot ✓ (T2), integration ✓ (T4). Write-side plumbing
  (protected ports storage) present but write METHODS are slice 04 — plan
  scope matches roadmap.
- Types consistent: BackendReader/RegisterBackend (T1) consumed by
  backend_snmp.go (T2); snmp pkg signatures referenced are the real ones
  per D-FAC.
- No placeholders; dossier carries exact semantics; test intents named.
