# Capabilities Oracle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Python's `netgear_switch.capabilities` module — a pure, stateless oracle answering "can model M do operation O over backend B, and why not?" — to a new Go package `capabilities/`, deriving every verdict from the SAME registry/spec objects the real Go dispatch path already reads (never a parallel hand-written table), with a golden-fixture cross-check pinning the Go oracle's full matrix output against the pinned Python `capabilities.py`'s own output.

**Architecture:** New leaf package `capabilities/` (peer to `model/`, `snmp/`, `nsdp/`, `webui/`, `fastpath/`) that imports all five and computes `Capability` verdicts on demand — no precomputed table, exactly like the Python source. A curated subset of its API is re-exported from the root package's existing `alias.go`, deliberately leaving `ReadOperations`/`WriteOperations`/`OperationByName` reachable only via `capabilities.X`, mirroring Python's `__init__.py` re-export asymmetry (§2 of the dossier). Two small, mechanical prerequisite fixes land first: a real registry bug (gsm7228ps wrongly lists an SSH backend it does not have) and exporting a handful of currently-unexported message-constant/helper identifiers the oracle needs to reuse verbatim rather than duplicate.

**Tech Stack:** Go 1.26; stdlib only (`fmt`, `sort`, `strings`, `errors`, `encoding/json`, `reflect` in tests); no new third-party dependencies.

## Source of truth (REQUIRED READING for every task)

- **Dossier** (§1–§6 valid; §7/§8 partly stale — see Authoritative Corrections below): `/tmp/claude-1001/-home-tim-github-mithro-go-netgear-switch-library--claude-worktrees-slice-06-http/5ceed0aa-57a1-4aec-9f06-4caf78b8b75d/scratchpad/capabilities-oracle-dossier.md`
- **Pinned Python source (read-only; the parity target):** `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-a9e0ebc/src/netgear_switch/capabilities.py` (415 lines) and its test file `tests/test_capabilities.py` (339 lines, 13 tests). This snapshot is pinned at commit `a9e0ebc`; the fixture filename in Task 10 encodes this hash so a future re-pin is an explicit, visible diff.
- **This Go worktree (base `bf0f1d6`):** already has `fastpath/` (slice-07, merged) with real SSH/Telnet CLI backends, and `nsdp/writer.go` with real `CreateVlan`/`DeleteVlan` over NSDP.

### Authoritative corrections to the dossier (verified directly against this worktree; supersede dossier §7/§8 wherever they conflict)

- Dossier finding #1 (NSDP create/delete VLAN refused) is **FALSE/OBSOLETE**. `nsdp/writer.go`'s `CreateVlan`/`DeleteVlan` are real, verified-after-write NSDP implementations; `noVLANLifecycleMsg` no longer exists. The oracle asserts NSDP `create_vlan`/`delete_vlan` = **SUPPORTED**, matching Python's `_nsdp_support` refusals dict (which has no entry for either).
- Dossier finding #2 (CLI/SSH/Telnet backend missing) is **FALSE/OBSOLETE**. `fastpath/` exists; `backend_cli.go` registers both `model.BackendSSH` and `model.BackendTelnet` as read AND write backends. This plan ports `_cli_support` faithfully.
- Dossier finding #3 (NSDP message constants unexported) is **real** — resolved in Task 2: export them, don't duplicate the text.
- `upload_certificate`'s `NotImplementedError` case folds into a single `Support.UNSUPPORTED` verdict in Python; Go must **not** invent a distinct verdict for `model.ErrKnownUnimplemented` even though Go (unlike Python) has that sentinel as a first-class, independently-`errors.Is`-matchable concept. There is no fifth `Support` value. See Task 6.
- **NEW finding, not in the dossier** (discovered during this plan's research, verified against the pinned Python `registry.py` and this Go worktree): `model/registry.go`'s `gsm7228ps` entry wrongly lists `model.BackendSSH`. The pinned Python registry explicitly and deliberately has `{Backend.SNMP, Backend.HTTP, Backend.TELNET}` for this model — **no SSH** — with a live-verified comment explaining the real S3300-52X hardware runs no SSH listener at all (confirmed by its own SNMP `tcpConnTable`; CLI is telnet-only on port 60000). A faithful port of the oracle atop the current (wrong) Go registry would assert `gsm7228ps`/SSH/\* = SUPPORTED for every operation — a fabricated capability contradicting both the pinned source and quoted live-hardware evidence, exactly the failure mode principle 5 exists to prevent. This is fixed as **Task 1**, before anything else, because Task 10's golden-fixture cross-check will not even reach parity (row *counts* differ: 526 vs. 525) until it's fixed. See "Task 1" for the full ripple (also touches `model/registry_test.go` and `facade_cli_integration_test.go`).

## Global Constraints

**The five non-negotiable design principles (bind every task):**

1. **Fail fast, never switch backend mid-op** (no silent fallback). The oracle is read-only and dispatches nothing itself, but every verdict it derives must describe the SAME single-backend-only dispatch behavior `dispatch.go`/`write_dispatch.go` actually implement.
2. **Backends have feature PARITY** — a missing op is built, not assumed a device limit unless proven with quoted live device output. Every `Support.UNSUPPORTED` reason this plan writes either reuses an existing, already-evidenced message constant, or is Python's own already-evidenced prose translated to Go's phrasing conventions. No new "assumed" refusals are invented.
3. **Every model per-SKU.** All 10 registered models (`m4300-24x, m4300-16x, gsm7252ps, gsm7228ps, gs110emx, gs305ep, m7300, xs748t, gs728tpp, gs105pe`) are exercised by the oracle's tests, not just a representative subset.
4. **A failure is yours to debug, not the hardware's.** Never fold a real backend gap into a fabricated "device limitation" reason.
5. **The fake seeds MEASURED values and must match hardware.** The gsm7228ps SSH registry bug (Task 1) is exactly this principle violated by the *registry*, not the fake — fixing it is in scope for this reason alone even though it is not, strictly, "the capabilities oracle."

**CI / quality gates — run ALL of these before every task's commit, not just `go test`:**

```
make fmt-check   # gofmt -l . — SEPARATE gate from lint
go vet ./...     # via ./scripts/jail.sh
make lint        # golangci-lint v2.12.2: errcheck, govet, staticcheck, revive, misspell, unconvert, errorlint
make test        # go test -race ./... via ./scripts/jail.sh
make cover       # go test -race -coverprofile ... + scripts/coveragegate -min 90 (library-only aggregate)
```

Prefix any Go command you run directly (not via `make`) with `./scripts/jail.sh` (CPU/mem resource jail).

**Package-comment convention (revive):** every new `.go` file in this plan starts `package capabilities` (or `package netgearswitch_test`), a **blank line**, then a `// filename.go: ...` header comment — never a doc comment attached directly to the `package` line — matching the established convention in e.g. `model/registry.go`, `nsdp/writer.go`, `webui/cert.go` (checked directly: all three do exactly this). A comment attached directly above `package X` with no blank line IS parsed as the package doc and revive will flag it if it doesn't start `// Package X`.

**Verbatim enumerations (copy these into code exactly; do not paraphrase):**

- **Models (10, canonical registry order):** `m4300-24x, m4300-16x, gsm7252ps, gsm7228ps, gs110emx, gs305ep, m7300, xs748t, gs728tpp, gs105pe`.
- **Backends (6):** `snmp, nsdp, http, ssh, telnet, console` (Go's lowercase `model.Backend` string values — `model.BackendSNMP`, `model.BackendNSDP`, `model.BackendHTTP`, `model.BackendSSH`, `model.BackendTelnet`, `model.BackendConsole`).
- **Backend preference/resolution order** (mirrors Python's locally-restated tuple, `capabilities.py:388-395` — deliberately NOT the same variable as `dispatch.go`'s `backendPreference`, see "Deliberate non-fixes" below): `SNMP, NSDP, HTTP, SSH, TELNET, CONSOLE`.
- **Read operations (10, exact `snake_case` names, order matters):** `get_ports, get_stats, get_vlans, get_pvids, get_lldp, get_macs, get_poe, get_sensors, get_mgmt_ip, nsdp_device`.
- **Write operations (11, exact names, order matters):** `set_port_enabled, set_poe, cycle_poe, clear_poe_fault, set_pvid, set_vlan_membership, create_vlan, delete_vlan, set_mgmt_ip, upload_certificate, upload_certificate_scp`.
- **Support values (exact string forms — chosen to equal Python's `Support` enum `.value` byte-for-byte, load-bearing for Task 10's cross-check):** `supported, no-backend, unsupported, unverified`.
- **PoE-gated ops** (`_POE_OPS` in Python, both SNMP and CLI branches): `get_poe, set_poe, cycle_poe, clear_poe_fault`.
- **NSDP unsupported-op -> reason-constant map** (op name -> Go identifier, all in package `nsdp` after Task 2): `get_macs -> nsdp.NoMACsMsg`, `get_lldp -> nsdp.NoLLDPMsg`, `get_sensors -> nsdp.NoSensorsMsg`, `get_poe -> nsdp.NoPoEReadMsg`, `set_poe -> nsdp.NoPoEWriteMsg`, `cycle_poe -> nsdp.NoPoEWriteMsg`, `clear_poe_fault -> nsdp.NoPoEWriteMsg`, `set_port_enabled -> nsdp.NoPortAdminMsg`.
- **`CERT_UPLOAD_KNOWN_UNIMPLEMENTED` models (3, already exported as `webui.CertUploadKnownUnimplemented`):** `m4300-24x, m4300-16x, gsm7252ps`.
- **`SCP_CERT_PROFILES` models (3, already exported as `fastpath.ScpCertProfiles`):** `m4300-24x, m4300-16x, gsm7252ps` (deliberately NOT `gsm7228ps` — it uses HTTP multipart instead).

**Deliberate, documented divergences from a byte-for-byte port (decide once here, do not re-litigate per task):**

1. **`Backend` casing in reason text.** Python's `NO_BACKEND` reason interpolates `backend.name` (uppercase, e.g. `"SNMP"`). This codebase already has an established, deliberate precedent of using Go's own lowercase `Backend` spelling in equivalent dispatch messages (`dispatch.go`'s `resolveBackend`, doc comment cites this exactly as "D-REC A.10.6"). This plan follows that existing precedent, not Python's casing — Go's `%s` formatting of a `model.Backend` already prints the lowercase form, so this requires no special-casing, just not fighting the natural formatting.
2. **Reason text is NOT asserted byte-identical to Python anywhere**, including in Task 10's cross-check. Confirmed by direct comparison: `nsdp.NoPortAdminMsg` (Go) is already byte-identical to Python's `_NO_PORT_ADMIN`, but the shared "evidence" prose each embeds (`nsdpSweepEvidence` in Go vs. `_SWEEP` in Python) already diverges in wording ("an exhaustive NSDP tag sweep... see the nsdp package for the full tag inventory" vs. "an exhaustive tag sweep... see nsdp_read._SWEEP") — a legitimate, expected difference (different repo, different doc pointer), not a bug. Task 10's cross-check therefore pins **verdict** (`Support` value) and **reason-non-emptiness**, never reason bytes. Individual reason *content* is instead pinned by narrower, hand-written unit tests per backend (Tasks 4–7) that assert specific substrings/exact text where the text genuinely is meant to be byte-identical (e.g. `nsdp.NoPortAdminMsg` itself, `webui.CertUploadKnownUnimplemented`'s mechanism strings).
3. **`Operation.Name` uses Python's exact `snake_case` string** (`"get_ports"`, `"upload_certificate_scp"`, ...), NOT a Go-idiomatic `PascalCase` method name. This is deliberate: it keeps Task 10's golden-fixture cross-check a trivial exact-string match, keeps `Operation` a stable doc-table key independent of the Go facade's own naming, and mirrors Python's `Operation.name` being "the exact facade method name" as a *string*, not a language-level binding. The mapping from `Operation.Name` to the actual Go `*netgearswitch.Switch` method (`GetPorts`, `SetVlanMembership`, etc.) is a separate, explicit lookup table in Task 9's test — see that task for the one documented gap (`upload_certificate_scp` has no `*Switch` method yet; `fastpath.DeployCertificateSCP` exists but is not wired into the facade — a pre-existing gap this plan does not close, flagged loudly rather than silently worked around).
4. **`capabilities.Capability` is not `==`-comparable** (it embeds `Operation`, which has a `[]model.Backend` slice field, and Go slices are not comparable). Tests that need to compare two `Capability` values use `reflect.DeepEqual`, never `==`. Documented here so nobody tries `==`, gets a compile error, and "fixes" it by making `Backends` a fixed-size array or similar — don't; `reflect.DeepEqual` is the correct, idiomatic answer.
5. **`SwitchModel.Verified` is never read by the oracle**, in Python or here. `m7300`/`xs748t` (`Verified: false`) still get real SNMP-derived verdicts wherever `_snmp_support`'s actual branches say so — `Verified` gates test-suite trust in the model's *data* (whether a live capture backs its port/PoE counts), not backend/operation support. Do not add a `!m.Verified -> UNVERIFIED` branch; Python has none, and adding one would silently un-port the module.

**Deliberate non-fixes (out of scope for this plan, flagged so nobody "fixes" them mid-task):**

- `dispatch.go`'s package-level `backendPreference = []model.Backend{SNMP, NSDP, HTTP, SSH}` (used for real default-backend *resolution*, shared by `dispatch.go` and `write_dispatch.go`) omits `TELNET`/`CONSOLE`. This is a separate, pre-existing latent gap in real dispatch resolution order, not something `capabilities.BackendsFor` reads or is affected by — Python's own `capabilities.backends_for` also re-states its own local 6-element order tuple rather than importing `sync_api._BACKEND_PREFERENCE` (dossier §4.6 confirms this is deliberate duplication-by-convention in Python too). Fixing `dispatch.go`'s list is real, valuable follow-up work, but unrelated to this plan; do not fold it in here.
- `fastpath.DeployCertificateSCP` is not wired into `*netgearswitch.Switch` as an `UploadCertificateSCP` method. The capability *verdict* for `upload_certificate_scp` is still fully derivable today (`fastpath.ScpProfile(m)` is the real gate, and it works standalone), so this plan ports that operation's oracle logic faithfully — it just cannot assert a matching `*Switch` method exists, and says so explicitly in Task 9 rather than skipping the operation or inventing a stand-in.

---

## File Structure

```
model/registry.go            MODIFY (Task 1) — fix gsm7228ps.Backends
model/registry_test.go       MODIFY (Task 1) — fix stale expected-backends table row
facade_cli_integration_test.go   MODIFY (Task 1) — drop gsm7228ps from the SSH-parity model list
facade_http_integration_test.go  MODIFY (Task 1) — fix one stale comment

nsdp/reader.go                MODIFY (Task 2) — export 4 message constants
nsdp/writer.go                MODIFY (Task 2) — export 1 message constant
webui/reader.go                MODIFY (Task 2) — export 2 helper functions

capabilities/types.go          CREATE (Task 3) — Support, OperationKind, Operation, Capability,
                                                  Operations/ReadOperations/WriteOperations tables,
                                                  OperationByName, ErrUnknownOperation, poeOps, noPSE
capabilities/types_test.go     CREATE (Task 3)

capabilities/support_snmp.go       CREATE (Task 4) — snmpSupport
capabilities/support_snmp_test.go  CREATE (Task 4)

capabilities/support_nsdp.go       CREATE (Task 5) — nsdpSupport, nsdpRefusals map
capabilities/support_nsdp_test.go  CREATE (Task 5)

capabilities/support_http.go       CREATE (Task 6) — httpSupport, httpPathFor
capabilities/support_http_test.go  CREATE (Task 6)

capabilities/support_cli.go        CREATE (Task 7) — cliReadsSupported, cliWritesSupported, cliSupport
capabilities/support_cli_test.go   CREATE (Task 7)

capabilities/support.go        CREATE (Task 8) — BackendsFor, For, ForKey, Matrix, backendOrder
capabilities/support_test.go   CREATE (Task 8)

capabilities_facade_test.go    CREATE (Task 9) — root-package black-box test: op-name -> *Switch
                                                  method parity + OperationByName lookup test
alias.go                       MODIFY (Task 9) — re-export the curated capabilities subset

capabilities/testdata/python_matrix_a9e0ebc.json   CREATE (Task 10) — golden fixture
capabilities/matrix_parity_test.go                 CREATE (Task 10)
```

**Why a new top-level `capabilities/` package, not a file in `model/`:** `model/` is the declarative registry (SKU data + sentinels); it has no notion of "operation" or "backend-specific derivation logic" and importing `webui`/`nsdp`/`fastpath` FROM `model` would invert this codebase's whole dependency direction (every protocol package already imports `model`, never the reverse — confirmed by grep across `snmp/`, `nsdp/`, `webui/`, `fastpath/`, all of which `import ".../model"` and are never imported by it). `capabilities` sits at the SAME layer as the root `netgearswitch` package — a consumer of every protocol package — but is its own package so the root package can choose a *curated* re-export subset (mirroring Python's `__init__.py` re-exporting only `OPERATIONS, Capability, Operation, OperationKind, Support, backends_for, matrix, support` while `READ_OPERATIONS`/`WRITE_OPERATIONS`/`operation` stay reachable only via `netgear_switch.capabilities`). Go has no submodule-visibility concept; a separate package plus a deliberate, incomplete `alias.go` re-export list is the only way to reproduce that curation on purpose rather than by accident (dossier §7.1).

---

### Task 1: Fix `gsm7228ps`'s wrongly-registered SSH backend

**Files:**
- Modify: `model/registry.go:171-179` (the `gsm7228ps` entry)
- Modify: `model/registry_test.go:61-71` (the expected-backends table row)
- Modify: `facade_cli_integration_test.go:25,151` (`cliCapstoneModels`, `startCLICapstoneVSW`)
- Modify: `facade_http_integration_test.go:628` (stale comment only)
- Test: `model/registry_test.go` (new focused test)

**Interfaces:**
- Consumes: nothing new.
- Produces: `model.GetModel("gsm7228ps").Backends` == `[]model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendTelnet}` (no `BackendSSH`) — every later task in this plan (and Task 10's row-count arithmetic: 25 model×backend pairs × 21 ops = 525) depends on this being fixed first.

**Why:** The pinned Python `registry.py:194-227` registers `gsm7228ps` with `{Backend.SNMP, Backend.HTTP, Backend.TELNET}` and a live-verified comment: *"TELNET (not SSH): the S3300-52X's FASTPATH CLI is reachable over telnet on the NON-STANDARD port 60000 (not 23) -- live-verified 2026-07-30 on 10.1.5.11 ... SSH is genuinely ABSENT: the switch runs no ssh listener on any port (its SNMP tcpConnTable shows only 80/443/60000)."* This Go worktree's `model/registry.go:171-179` currently lists `Backends: []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet}` — SSH included, contradicting the pinned source and the quoted live-device evidence. `virtual/server.go:214` already conditions its SSH-listener bind on `v.modelInfo.HasBackend(model.BackendSSH)`, so fixing the registry automatically stops the fake from claiming an SSH face for `gsm7228ps` too — the fake was, until this fix, lying about the same capability the registry was.

- [ ] **Step 1: Write the failing regression test.** Add to `model/registry_test.go` (as a new top-level test function, near the alias tests):

```go
// TestGSM7228PSHasNoSSH pins a real registry-data bug found while building
// the capabilities oracle: the pinned Python registry.py (commit a9e0ebc)
// registers gsm7228ps with {SNMP, HTTP, TELNET} -- explicitly NOT SSH -- with
// a live-verified comment that the real S3300-52X hardware runs no SSH
// listener at all (its own SNMP tcpConnTable shows only ports 80/443/60000;
// CLI is telnet-only on the non-standard port 60000). A Go registry that
// claims SSH here fabricates a capability the device does not have.
func TestGSM7228PSHasNoSSH(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7228ps): %v", err)
	}
	if m.HasBackend(model.BackendSSH) {
		t.Error("gsm7228ps: HasBackend(BackendSSH) = true, want false (real S3300-52X has no SSH listener)")
	}
	if !m.HasBackend(model.BackendTelnet) {
		t.Error("gsm7228ps: HasBackend(BackendTelnet) = false, want true")
	}
	if !m.HasBackend(model.BackendSNMP) || !m.HasBackend(model.BackendHTTP) {
		t.Error("gsm7228ps: expected SNMP and HTTP backends unchanged")
	}
}
```

- [ ] **Step 2: Run it, verify it fails** (the current registry entry still has SSH):

```
./scripts/jail.sh go test ./model/... -run TestGSM7228PSHasNoSSH -v
```
Expected: FAIL — `HasBackend(BackendSSH) = true, want false`.

- [ ] **Step 3: Fix the registry entry.** In `model/registry.go`, change the `gsm7228ps` entry's `Backends` field and extend its existing evidence comment:

```go
		{
			// VERIFIED 2026-07-30 against real hardware: the S3300-52X-PoE+
			// (sw-netgear-s3300-1, sysObjectID 4526.100.10.19). The live
			// capture confirmed the smart-managed-pro (4526.11) vendor family
			// is correct here -- unlike gs728tpp (which had zero 4526 OIDs),
			// this switch's fan/temp/PoE vendor data really does live under
			// 4526.11.43, and all 9 read ops cross-verified SNMP<->mock. Its
			// sysDescr "S3300-52X-PoE+" is deliberately unmatchable text (same
			// shape as the unregistered S3300-28X), so it is auto-detected via
			// the sysObjectID map instead. Registered key is gsm7228ps;
			// "s3300" is an alias (see modelAliases). Note 4526.100.10.19 is
			// the product-ID OID, distinct from the 4526.11 vendor DATA
			// subtree.
			//
			// TELNET, NOT SSH: the S3300-52X's FASTPATH CLI is reachable over
			// telnet on the NON-STANDARD port 60000 (not 23) -- live-verified
			// 2026-07-30 on 10.1.5.11 (login admin+password, prompt
			// "(manage-sw-netgear-s3300-1) >"). SSH is genuinely ABSENT: the
			// switch runs no ssh listener on any port (its own SNMP
			// tcpConnTable shows only 80/443/60000). Mirrors Python
			// registry.py's gsm7228ps _model(...) call exactly -- do not
			// re-add BackendSSH here without a NEW live capture proving it.
			Key:            "gsm7228ps",
			DisplayName:    "GSM7228PS (S3300)",
			Class:          ClassSmartManagedPro,
			PortCount:      52,
			PoEPortCount:   48,
			Backends:       []Backend{BackendSNMP, BackendHTTP, BackendTelnet},
			SNMPVendorBase: vendorBaseSmartManagedPro,
			Verified:       true,
		},
```

- [ ] **Step 4: Run the new test, verify it passes.**

```
./scripts/jail.sh go test ./model/... -run TestGSM7228PSHasNoSSH -v
```

- [ ] **Step 5: Fix the now-stale table-driven test row.** In `model/registry_test.go:61-71`, change the `gsm7228ps` case's `backends` field:

```go
	{
		key:          "gsm7228ps",
		displayName:  "GSM7228PS (S3300)",
		class:        model.ClassSmartManagedPro,
		portCount:    52,
		poePortCount: 48,
		backends:     []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendTelnet},
		vendorBase:   "1.3.6.1.4.1.4526.11",
		verified:     true,
		hasMACTable:  true,
	},
```

- [ ] **Step 6: Fix the ripple in `facade_cli_integration_test.go`.** Remove `"gsm7228ps"` from the SSH-parity model list (it has no SSH to test), and relax `startCLICapstoneVSW`'s bind-check to only require an SSH face for models that actually declare one:

```go
// The three models with a FASTPATH CLI backend reachable over SSH. gsm7228ps
// (S3300) is deliberately excluded here -- it is telnet-only on real hardware
// (see model/registry.go's gsm7228ps comment) -- and is exercised by
// TestCLICapstone_ReadsOverRealTelnet instead, which already uses it
// exclusively for the telnet path.
var cliCapstoneModels = []string{"gsm7252ps", "m4300-24x", "m4300-16x"}
```

```go
func startCLICapstoneVSW(t *testing.T, modelKey string) *virtual.VirtualSwitch {
	t.Helper()
	vsw, err := virtual.NewVirtualSwitch(modelKey)
	if err != nil {
		t.Fatalf("NewVirtualSwitch(%q): %v", modelKey, err)
	}
	if err := vsw.Start(); err != nil {
		t.Fatalf("VirtualSwitch.Start(%q): %v", modelKey, err)
	}
	t.Cleanup(func() { _ = vsw.Stop() })
	m := mustCapstoneModel(t, modelKey)
	if m.HasBackend(model.BackendSSH) && vsw.SSHPort == 0 {
		t.Fatalf("model %q did not bind its SSH face", modelKey)
	}
	if vsw.TelnetPort == 0 {
		t.Fatalf("model %q did not bind its telnet face", modelKey)
	}
	return vsw
}
```

- [ ] **Step 7: Fix the stale comment in `facade_http_integration_test.go:628`.** Change:

```go
// --- gsm7228ps (S3300 dialect, backends {SNMP, HTTP, SSH, Telnet}) ---------
```
to:
```go
// --- gsm7228ps (S3300 dialect, backends {SNMP, HTTP, Telnet} -- no SSH) ----
```

- [ ] **Step 8: Run the full suite, verify everything still passes.**

```
make fmt-check
./scripts/jail.sh go vet ./...
make lint
./scripts/jail.sh go test -race ./...
```
Expected: all green. `TestCLICapstone_ReadsMatchInProcessOverRealSSH` now iterates only 3 models; `TestCLICapstone_ReadsOverRealTelnet` (already gsm7228ps-only) is unaffected.

- [ ] **Step 9: Commit.**

```bash
git add model/registry.go model/registry_test.go facade_cli_integration_test.go facade_http_integration_test.go
git commit -m "$(cat <<'EOF'
fix(model): gsm7228ps has no SSH backend (telnet-only S3300 hardware)

The pinned Python registry.py (a9e0ebc) registers gsm7228ps with
{SNMP, HTTP, TELNET} -- explicitly not SSH -- backed by a live-verified
capture: the real S3300-52X runs no SSH listener at all (SNMP tcpConnTable
shows only 80/443/60000; CLI is telnet-only on the non-standard port 60000).
This Go registry wrongly included BackendSSH, which meant both the registry
and (via virtual/server.go's HasBackend-driven bind) the fake claimed an SSH
capability the real device does not have -- found while building the
capabilities oracle, whose golden-fixture parity check depends on this being
correct (25, not 26, model x backend pairs).

Ripples: model/registry_test.go's expected-backends row, and
facade_cli_integration_test.go's SSH-parity model list (gsm7228ps moves to
telnet-only, already exercised by TestCLICapstone_ReadsOverRealTelnet).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Export NSDP refusal-message constants and two webui helper functions

**Files:**
- Modify: `nsdp/reader.go:40-43,326,334,342,350`
- Modify: `nsdp/writer.go:65,403`
- Modify: `webui/reader.go:159,370,784,800`

**Interfaces:**
- Consumes: nothing new.
- Produces: `nsdp.NoMACsMsg`, `nsdp.NoLLDPMsg`, `nsdp.NoSensorsMsg`, `nsdp.NoPoEReadMsg` (all `string` constants, package `nsdp`, from `reader.go`); `nsdp.NoPortAdminMsg` (`string` constant, package `nsdp`, from `writer.go`) — `nsdp.NoPoEWriteMsg` is already exported (unchanged). `webui.SupportsSensors(spec *webui.HTTPModelSpec) bool` and `webui.MgmtIPPath(spec *webui.HTTPModelSpec) string` (both currently `supportsSensors`/`mgmtIPPath`, unexported).

**Why (the R3 decision the dossier asked for, made explicit):** Python's `_nsdp_support` imports and reuses `nsdp_read._NO_MACS` etc. verbatim so the oracle's refusal reason can never drift from the reader's own; `_http_path_for` calls `http_read._supports_sensors`/`_mgmt_ip_path` for the same reason. The two options were (a) export the Go constants/helpers so `capabilities` calls them directly, or (b) re-derive equivalent text/logic inside `capabilities` with a pinning test. **This plan picks (a)** — export — because: `nsdp.NoPoEWriteMsg` already sets this exact precedent (exported specifically so an out-of-package caller can reuse the identical text without duplicating it, per its own doc comment), the rename is mechanical and low-risk (verified: no test file references any of these 6 identifiers by their unexported names — only their own declaration + call sites within `reader.go`/`writer.go`/`reader.go` do), and it is strictly more faithful to "derives, does not duplicate" than re-deriving equivalent prose with a pinning test would be.

- [ ] **Step 1: Write the failing test.** Add to `nsdp/reader_test.go` (append; package `nsdp`, so this is an internal/white-box test — fine, it's proving the identifiers are now exported and callable with the SAME identifier from a test in the same package, which fails to compile today because the names don't exist yet under these capitalized spellings):

```go
func TestExportedRefusalMessagesNonEmpty(t *testing.T) {
	for name, msg := range map[string]string{
		"NoMACsMsg":    NoMACsMsg,
		"NoLLDPMsg":    NoLLDPMsg,
		"NoSensorsMsg": NoSensorsMsg,
		"NoPoEReadMsg": NoPoEReadMsg,
	} {
		if msg == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
```

And to `nsdp/writer_test.go` (append):

```go
func TestExportedNoPortAdminMsg(t *testing.T) {
	if NoPortAdminMsg == "" {
		t.Error("NoPortAdminMsg is empty")
	}
}
```

And to `webui/reader_test.go` (append; check the actual package name at the top of that file first — it may be `webui` or `webui_test`; if it's the external `webui_test` package, prefix both calls with `webui.`):

```go
func TestExportedSupportsSensorsAndMgmtIPPath(t *testing.T) {
	spec, err := HTTPSpec(mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("HTTPSpec: %v", err)
	}
	if !SupportsSensors(spec) {
		t.Error("SupportsSensors(gsm7252ps spec) = false, want true (FASTPATH dialect with a sysInfo page)")
	}
	if MgmtIPPath(spec) == "" {
		t.Error("MgmtIPPath(gsm7252ps spec) is empty, want a page path")
	}
}
```

(If `webui/reader_test.go` has no `mustModel` test helper already, use whatever existing helper that file already uses elsewhere to resolve a `*model.SwitchModel` by key — check the file first; do not invent a second helper with a different name.)

- [ ] **Step 2: Run, verify all three fail to compile** (undefined: `NoMACsMsg` / `NoPortAdminMsg` / `SupportsSensors`):

```
./scripts/jail.sh go test ./nsdp/... ./webui/... -run TestExported -v
```

- [ ] **Step 3: Rename in `nsdp/reader.go`.** Capitalize the 4 constants and their 4 call sites (`unsupportedRead(noLLDPMsg)` etc. become `unsupportedRead(NoLLDPMsg)` etc.), and give each its own doc comment (revive requires exported identifiers to have one — follow `NoPoEWriteMsg`'s existing doc-comment style exactly):

```go
// NoMACsMsg is the exact message GetMACs wraps in the error it returns,
// mirroring Python nsdp_read.py's _NO_MACS module constant verbatim.
// Exported so callers outside this package -- notably the capabilities
// oracle's NSDP derivation -- can reuse the identical text instead of
// duplicating it (see nsdp.NoPoEWriteMsg's doc comment for the same
// rationale, already established by that constant).
const NoMACsMsg = "NSDP has no MAC/FDB table tag (" + nsdpSweepEvidence + ")"

// NoLLDPMsg is the exact message GetLLDP wraps, mirroring Python's _NO_LLDP.
const NoLLDPMsg = "NSDP has no LLDP neighbour tag (" + nsdpSweepEvidence + ")"

// NoSensorsMsg is the exact message GetSensors wraps, mirroring Python's
// _NO_SENSORS.
const NoSensorsMsg = "NSDP has no environmental-sensor tag (" + nsdpSweepEvidence + ")"

// NoPoEReadMsg is the exact message GetPoE wraps, mirroring Python's _NO_POE
// (the READ-side constant; nsdp.NoPoEWriteMsg is the separate write-side one).
const NoPoEReadMsg = "NSDP has no PoE status tag (" + nsdpSweepEvidence + "); use the HTTP backend for PoE"
```

Update the 4 call sites (`return nil, unsupportedRead(NoLLDPMsg)` etc.) to the capitalized names.

- [ ] **Step 4: Rename in `nsdp/writer.go`.** Capitalize `noPortAdminMsg` -> `NoPortAdminMsg`, update its doc comment (it currently says "Unexported: nothing outside this package needs to reproduce it independently" — that sentence is now false, delete/replace it) and its one call site:

```go
// NoPortAdminMsg is the unsupported-write message for the one remaining
// unsupported per-port write (SetPortEnabled), mirroring Python
// nsdp_write.py's _NO_PORT_ADMIN verbatim. Exported for the same reason as
// NoPoEWriteMsg: the capabilities oracle's NSDP derivation reuses this text
// directly rather than duplicating it.
const NoPortAdminMsg = "per-port admin-enable over NSDP is UNPROVEN on these Plus models: the " +
	"measured tag inventory (GS110EMX fw 1.0.2.8) has two candidate per-port config tags " +
	"(0x0800, 0x9400) whose semantics were never settled -- no write has been attempted " +
	"against either, and a wrong guess can drop the port's link. Use the HTTP backend, " +
	"whose port-settings page IS grounded"
```
```go
	return unsupportedWrite(NoPortAdminMsg)
```

- [ ] **Step 5: Rename in `webui/reader.go`.** Capitalize `supportsSensors` -> `SupportsSensors` and `mgmtIPPath` -> `MgmtIPPath`, update both call sites (lines ~784, ~800), and give each an exported-style doc comment:

```go
// SupportsSensors reports whether spec's dialect has a sysInfo page carrying
// box sensors, mirroring Python's _supports_sensors (http_read.py:178-190).
// Exported so the capabilities oracle's HTTP derivation can reuse this exact
// logic instead of re-deriving "does this model's web UI expose sensors".
func SupportsSensors(spec *HTTPModelSpec) bool {
	return (isM4300Dialect(spec) || isXEFastpathDialect(spec) || isGoAheadDialect(spec)) &&
		spec.SysinfoPath != ""
}
```
```go
// MgmtIPPath is the page GetMgmtIP reads for this model, mirroring Python's
// _mgmt_ip_path: spec.MgmtIPPath if named, else spec.SysinfoPath, else "" (no
// mgmt-IP page at all -- gs305ep). Exported for the same reason as
// SupportsSensors.
func MgmtIPPath(spec *HTTPModelSpec) string {
	if spec.MgmtIPPath != "" {
		return spec.MgmtIPPath
	}
	return spec.SysinfoPath
}
```

- [ ] **Step 6: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./nsdp/... ./webui/... -run TestExported -v
```

- [ ] **Step 7: Run the full gate.**

```
make fmt-check && ./scripts/jail.sh go vet ./... && make lint && ./scripts/jail.sh go test -race ./...
```

- [ ] **Step 8: Commit.**

```bash
git add nsdp/reader.go nsdp/writer.go nsdp/reader_test.go nsdp/writer_test.go webui/reader.go webui/reader_test.go
git commit -m "$(cat <<'EOF'
refactor(nsdp,webui): export refusal-message constants and two dialect helpers

Prerequisite for the capabilities oracle's "derives, does not duplicate"
requirement: NoMACsMsg/NoLLDPMsg/NoSensorsMsg/NoPoEReadMsg (nsdp/reader.go),
NoPortAdminMsg (nsdp/writer.go), and SupportsSensors/MgmtIPPath
(webui/reader.go) were unexported, forcing any external caller (the new
capabilities package) to duplicate their text/logic. NoPoEWriteMsg already
established the export-for-reuse precedent this follows. No behavior change;
pure identifier capitalization + doc comments.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `capabilities` package skeleton — types, operation tables, lookup

**Files:**
- Create: `capabilities/types.go`
- Test: `capabilities/types_test.go`

**Interfaces:**
- Consumes: `model.Backend`, `model.BackendSNMP/NSDP/HTTP/SSH/Telnet/Console` (all already exported, package `model`).
- Produces (used by every later task in this plan):
  - `type Support string` with consts `SupportSupported = "supported"`, `SupportNoBackend = "no-backend"`, `SupportUnsupported = "unsupported"`, `SupportUnverified = "unverified"`.
  - `type OperationKind string` with consts `OperationKindRead = "read"`, `OperationKindWrite = "write"`.
  - `type Operation struct { Name string; Kind OperationKind; Summary string; Backends []model.Backend }` (`Backends == nil` means "any backend the model has").
  - `type Capability struct { ModelKey string; Backend model.Backend; Operation Operation; Support Support; Reason string }` with method `func (c Capability) Supported() bool`.
  - `var ReadOperations []Operation` (10 entries), `var WriteOperations []Operation` (11 entries), `var Operations []Operation` (= `ReadOperations` + `WriteOperations`, 21 entries).
  - `func OperationByName(name string) (Operation, error)` and `var ErrUnknownOperation = errors.New("unknown operation")`.
  - `var poeOps = map[string]bool{...}` and `func noPSE(m *model.SwitchModel) (Support, string)` (unexported; consumed by Tasks 4 and 7's SNMP/CLI derivations).

- [ ] **Step 1: Write the failing tests.** Create `capabilities/types_test.go`:

```go
package capabilities

// types_test.go: pins the Operations table's shape against the pinned
// Python capabilities.py (a9e0ebc) verbatim -- counts, names, kinds, and the
// three backend-restricted operations.

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestOperationTableShape(t *testing.T) {
	if len(ReadOperations) != 10 {
		t.Errorf("len(ReadOperations) = %d, want 10", len(ReadOperations))
	}
	if len(WriteOperations) != 11 {
		t.Errorf("len(WriteOperations) = %d, want 11", len(WriteOperations))
	}
	if len(Operations) != 21 {
		t.Errorf("len(Operations) = %d, want 21", len(Operations))
	}
	for _, op := range ReadOperations {
		if op.Kind != OperationKindRead {
			t.Errorf("ReadOperations: %q has Kind %q, want %q", op.Name, op.Kind, OperationKindRead)
		}
	}
	for _, op := range WriteOperations {
		if op.Kind != OperationKindWrite {
			t.Errorf("WriteOperations: %q has Kind %q, want %q", op.Name, op.Kind, OperationKindWrite)
		}
	}
}

func TestOperationNamesExactAndOrdered(t *testing.T) {
	wantRead := []string{
		"get_ports", "get_stats", "get_vlans", "get_pvids", "get_lldp",
		"get_macs", "get_poe", "get_sensors", "get_mgmt_ip", "nsdp_device",
	}
	wantWrite := []string{
		"set_port_enabled", "set_poe", "cycle_poe", "clear_poe_fault",
		"set_pvid", "set_vlan_membership", "create_vlan", "delete_vlan",
		"set_mgmt_ip", "upload_certificate", "upload_certificate_scp",
	}
	for i, want := range wantRead {
		if ReadOperations[i].Name != want {
			t.Errorf("ReadOperations[%d].Name = %q, want %q", i, ReadOperations[i].Name, want)
		}
	}
	for i, want := range wantWrite {
		if WriteOperations[i].Name != want {
			t.Errorf("WriteOperations[%d].Name = %q, want %q", i, WriteOperations[i].Name, want)
		}
	}
}

func TestBackendRestrictedOperations(t *testing.T) {
	nsdpDevice, err := OperationByName("nsdp_device")
	if err != nil {
		t.Fatalf("OperationByName(nsdp_device): %v", err)
	}
	if len(nsdpDevice.Backends) != 1 || nsdpDevice.Backends[0] != model.BackendNSDP {
		t.Errorf("nsdp_device.Backends = %v, want [NSDP]", nsdpDevice.Backends)
	}

	upCert, err := OperationByName("upload_certificate")
	if err != nil {
		t.Fatalf("OperationByName(upload_certificate): %v", err)
	}
	if len(upCert.Backends) != 1 || upCert.Backends[0] != model.BackendHTTP {
		t.Errorf("upload_certificate.Backends = %v, want [HTTP]", upCert.Backends)
	}

	upScp, err := OperationByName("upload_certificate_scp")
	if err != nil {
		t.Fatalf("OperationByName(upload_certificate_scp): %v", err)
	}
	wantScp := map[model.Backend]bool{model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true}
	if len(upScp.Backends) != 3 {
		t.Errorf("upload_certificate_scp.Backends = %v, want 3 entries (SSH, TELNET, CONSOLE)", upScp.Backends)
	}
	for _, b := range upScp.Backends {
		if !wantScp[b] {
			t.Errorf("upload_certificate_scp.Backends contains unexpected %v", b)
		}
	}

	getPorts, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	if getPorts.Backends != nil {
		t.Errorf("get_ports.Backends = %v, want nil (unrestricted)", getPorts.Backends)
	}
}

func TestOperationByNameUnknown(t *testing.T) {
	_, err := OperationByName("get_nonsense")
	if !errors.Is(err, ErrUnknownOperation) {
		t.Errorf("OperationByName(get_nonsense) error = %v, want wrapping ErrUnknownOperation", err)
	}
}

func TestCapabilitySupported(t *testing.T) {
	c := Capability{Support: SupportSupported}
	if !c.Supported() {
		t.Error("Capability{Support: SupportSupported}.Supported() = false, want true")
	}
	c.Support = SupportUnsupported
	if c.Supported() {
		t.Error("Capability{Support: SupportUnsupported}.Supported() = true, want false")
	}
}
```

- [ ] **Step 2: Run, verify it fails to compile** (nothing in package `capabilities` exists yet):

```
./scripts/jail.sh go test ./capabilities/... -v
```

- [ ] **Step 3: Implement `capabilities/types.go`:**

```go
package capabilities

// types.go: the capability data model -- Support/OperationKind/Operation/
// Capability plus the fixed 21-entry Operations table, ported field-for-
// field from src/netgear_switch/capabilities.py (pinned worktree
// go-port-pin-a9e0ebc), lines 62-180. Any discrepancy between this file and
// that pin is a bug in this file.

import (
	"errors"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Support is how a (model, backend, operation) triple is served -- or
// refused. Values are chosen to equal Python's Support enum's .value
// strings byte-for-byte (load-bearing for the golden-fixture cross-check in
// capabilities/matrix_parity_test.go).
type Support string

const (
	// SupportSupported: the backend implements this operation for this model.
	SupportSupported Support = "supported"
	// SupportNoBackend: the model does not have this backend at all -- what
	// dispatch.go's resolveBackend refuses before any operation is considered.
	SupportNoBackend Support = "no-backend"
	// SupportUnsupported: the model has the backend, but that backend cannot
	// serve this operation -- either the protocol has no such notion (NSDP
	// has no PoE tag) or the device genuinely lacks the hardware (no PSE
	// ports). Never a stand-in for "not implemented yet" (principle 2).
	SupportUnsupported Support = "unsupported"
	// SupportUnverified: implemented, but gated off because the backend's
	// per-model spec is not yet cross-verified against live hardware
	// (HTTPModelSpec.ReadsVerified / CliModelSpec.ReadsVerified/WritesVerified).
	SupportUnverified Support = "unverified"
)

// OperationKind is whether an Operation reads or writes device state.
type OperationKind string

const (
	OperationKindRead  OperationKind = "read"
	OperationKindWrite OperationKind = "write"
)

// Operation is one facade operation, as exposed by *netgearswitch.Switch.
// Name is the operation's Python-derived snake_case identifier (e.g.
// "get_ports"), NOT the Go facade method name (e.g. GetPorts) -- see this
// plan's "Deliberate divergences" note 3 for why: it keeps this table a
// stable doc/lookup key independent of Go naming, and keeps the golden-
// fixture cross-check (capabilities/matrix_parity_test.go) a trivial exact
// string match against the pinned Python's own Operation.name values.
type Operation struct {
	Name    string
	Kind    OperationKind
	Summary string
	// Backends restricts which backends can EVER serve this operation,
	// for the few that bypass normal per-model backend membership
	// (nsdp_device is NSDP-only; certificate upload is HTTP or CLI-over-SCP).
	// nil means "any backend the model has". A non-nil Backends is always
	// non-empty in practice -- treat nil and non-nil-empty as the same
	// "unrestricted" state only via the nil check, never len() == 0, since
	// this codebase never constructs the latter.
	Backends []model.Backend
}

var cliBackends = []model.Backend{model.BackendSSH, model.BackendTelnet, model.BackendConsole}

// ReadOperations are the 10 read-kind operations, in the pinned Python
// source's exact order (capabilities.py:104-122).
var ReadOperations = []Operation{
	{Name: "get_ports", Kind: OperationKindRead, Summary: "Per-port link/admin status"},
	{Name: "get_stats", Kind: OperationKindRead, Summary: "Per-port octet/packet counters"},
	{Name: "get_vlans", Kind: OperationKindRead, Summary: "VLAN list with tagged/untagged members"},
	{Name: "get_pvids", Kind: OperationKindRead, Summary: "Per-port PVID"},
	{Name: "get_lldp", Kind: OperationKindRead, Summary: "LLDP neighbour table"},
	{Name: "get_macs", Kind: OperationKindRead, Summary: "MAC/FDB forwarding table"},
	{Name: "get_poe", Kind: OperationKindRead, Summary: "Per-port PoE status and power draw"},
	{Name: "get_sensors", Kind: OperationKindRead, Summary: "Fan/PSU/temperature sensors"},
	{Name: "get_mgmt_ip", Kind: OperationKindRead, Summary: "Management IP configuration"},
	{Name: "nsdp_device", Kind: OperationKindRead, Summary: "Full NSDP device record", Backends: []model.Backend{model.BackendNSDP}},
}

// WriteOperations are the 11 write-kind operations, in the pinned Python
// source's exact order (capabilities.py:124-150).
var WriteOperations = []Operation{
	{Name: "set_port_enabled", Kind: OperationKindWrite, Summary: "Bring a port up or down"},
	{Name: "set_poe", Kind: OperationKindWrite, Summary: "Enable or disable PoE on a port"},
	{Name: "cycle_poe", Kind: OperationKindWrite, Summary: "Power-cycle a PoE port"},
	{Name: "clear_poe_fault", Kind: OperationKindWrite, Summary: "Clear a latched PoE fault"},
	{Name: "set_pvid", Kind: OperationKindWrite, Summary: "Set a port's PVID"},
	{Name: "set_vlan_membership", Kind: OperationKindWrite, Summary: "Set a port tagged/untagged/excluded on a VLAN"},
	{Name: "create_vlan", Kind: OperationKindWrite, Summary: "Create a VLAN"},
	{Name: "delete_vlan", Kind: OperationKindWrite, Summary: "Delete a VLAN"},
	{Name: "set_mgmt_ip", Kind: OperationKindWrite, Summary: "Set the management IP/mask/gateway"},
	{Name: "upload_certificate", Kind: OperationKindWrite, Summary: "Upload an HTTPS certificate over the web UI", Backends: []model.Backend{model.BackendHTTP}},
	{Name: "upload_certificate_scp", Kind: OperationKindWrite, Summary: "Deploy an HTTPS certificate via FASTPATH copy scp://", Backends: cliBackends},
}

// Operations is ReadOperations followed by WriteOperations, 21 entries
// total, mirroring Python's OPERATIONS = READ_OPERATIONS + WRITE_OPERATIONS.
var Operations = append(append([]Operation{}, ReadOperations...), WriteOperations...)

var byName = func() map[string]Operation {
	m := make(map[string]Operation, len(Operations))
	for _, op := range Operations {
		m[op.Name] = op
	}
	return m
}()

// ErrUnknownOperation is wrapped by OperationByName's error on a miss; match
// with errors.Is.
var ErrUnknownOperation = errors.New("unknown operation")

// OperationByName looks an Operation up by its facade method name (e.g.
// "get_ports"), mirroring Python's operation(name). On a miss it returns an
// error wrapping ErrUnknownOperation, matching model.GetModel's own
// lookup-miss convention (fmt.Errorf("%s: %w", key, Err...)) rather than
// Python's KeyError.
func OperationByName(name string) (Operation, error) {
	op, ok := byName[name]
	if !ok {
		return Operation{}, fmt.Errorf("%s: %w", name, ErrUnknownOperation)
	}
	return op, nil
}

// Capability is the verdict for one (model, backend, operation) triple,
// mirroring Python's frozen Capability dataclass. Not ==-comparable (see
// this plan's "Deliberate divergences" note 4) because Operation.Backends is
// a slice; use reflect.DeepEqual in tests that compare two Capability values.
type Capability struct {
	ModelKey  string
	Backend   model.Backend
	Operation Operation
	Support   Support
	// Reason is empty when Support == SupportSupported; otherwise the
	// reason, phrased the way the corresponding reader/writer phrases its
	// own refusal (see this plan's "Deliberate divergences" note 2 for why
	// this text is NOT byte-identical to Python's).
	Reason string
}

// Supported reports whether c.Support == SupportSupported.
func (c Capability) Supported() bool {
	return c.Support == SupportSupported
}

// poeOps is the set of operations gated by a model having zero PSE ports,
// mirroring Python's _POE_OPS. Shared by the SNMP (Task 4) and CLI (Task 7)
// derivations -- NSDP and HTTP gate PoE differently (NSDP: no tag at all,
// unconditionally; HTTP: a missing page, which already naturally resolves
// to UNSUPPORTED via httpPathFor without needing this set).
var poeOps = map[string]bool{
	"get_poe": true, "set_poe": true, "cycle_poe": true, "clear_poe_fault": true,
}

// noPSE returns the UNSUPPORTED verdict for a PoE op on a model with zero
// PSE ports, mirroring Python's _no_pse.
func noPSE(m *model.SwitchModel) (Support, string) {
	return SupportUnsupported, fmt.Sprintf("%s has no PSE ports, so it has no PoE to report or set", m.DisplayName)
}
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./capabilities/... -v
```

- [ ] **Step 5: Run the fmt/vet/lint gate** (new package, first pass through golangci-lint):

```
make fmt-check && ./scripts/jail.sh go vet ./... && make lint
```

- [ ] **Step 6: Commit.**

```bash
git add capabilities/types.go capabilities/types_test.go
git commit -m "$(cat <<'EOF'
feat(capabilities): package skeleton -- Support/Operation/Capability types

New capabilities/ package (peer to model/snmp/nsdp/webui/fastpath), porting
the data model half of Python's capabilities.py: the 21-entry Operations
table (10 read + 11 write, exact snake_case names/order), Support/
OperationKind string enums (values equal Python's enum .value byte-for-byte),
Capability struct, and OperationByName lookup. No derivation logic yet --
that's Tasks 4-8.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: SNMP support derivation

**Files:**
- Create: `capabilities/support_snmp.go`
- Test: `capabilities/support_snmp_test.go`

**Interfaces:**
- Consumes: `capabilities.Operation`, `capabilities.Support*`, `poeOps`, `noPSE` (Task 3); `snmp.HasVendorOids(m *model.SwitchModel) bool` (already exported, `snmp/oids.go:211`); `model.SwitchModel.HasMACTable() bool` (already exported).
- Produces: `func snmpSupport(m *model.SwitchModel, op Operation) (Support, string)` (unexported; consumed by Task 8's `For`).

- [ ] **Step 1: Write the failing tests.** Create `capabilities/support_snmp_test.go`:

```go
package capabilities

// support_snmp_test.go: pins snmpSupport's 3 branches against Python's
// _snmp_support (capabilities.py:197-219).

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func mustModelSnmp(t *testing.T, key string) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", key, err)
	}
	return m
}

func TestSNMPSupportNoPSE(t *testing.T) {
	// m4300-24x: SNMP model with PoEPortCount == 0.
	m := mustModelSnmp(t, "m4300-24x")
	for _, opName := range []string{"get_poe", "set_poe", "cycle_poe", "clear_poe_fault"} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := snmpSupport(m, op)
		if support != SupportUnsupported {
			t.Errorf("snmpSupport(m4300-24x, %s) = %v, want SupportUnsupported", opName, support)
		}
		if reason == "" {
			t.Errorf("snmpSupport(m4300-24x, %s) reason is empty", opName)
		}
	}
}

func TestSNMPSupportSetMgmtIPNoVendorOIDs(t *testing.T) {
	// gs728tpp: SNMP model with SNMPVendorBase == "" (no 4526 subtree).
	m := mustModelSnmp(t, "gs728tpp")
	op, err := OperationByName("set_mgmt_ip")
	if err != nil {
		t.Fatalf("OperationByName(set_mgmt_ip): %v", err)
	}
	support, reason := snmpSupport(m, op)
	if support != SupportUnsupported {
		t.Errorf("snmpSupport(gs728tpp, set_mgmt_ip) = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("snmpSupport(gs728tpp, set_mgmt_ip) reason is empty")
	}
}

func TestSNMPSupportDefaultSupported(t *testing.T) {
	m := mustModelSnmp(t, "m4300-24x")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, reason := snmpSupport(m, op)
	if support != SupportSupported {
		t.Errorf("snmpSupport(m4300-24x, get_ports) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("snmpSupport(m4300-24x, get_ports) reason = %q, want empty", reason)
	}
}

func TestSNMPSupportUnverifiedFlagIgnored(t *testing.T) {
	// m7300 has Verified == false but IS an SNMP model with real PoE/vendor
	// derivation rules that must still run normally -- see this plan's
	// "Deliberate divergences" note 5: Verified is never read by the oracle.
	m := mustModelSnmp(t, "m7300")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, _ := snmpSupport(m, op)
	if support != SupportSupported {
		t.Errorf("snmpSupport(m7300, get_ports) = %v, want SupportSupported (Verified must not gate this)", support)
	}
}
```

- [ ] **Step 2: Run, verify it fails to compile** (`snmpSupport` undefined):

```
./scripts/jail.sh go test ./capabilities/... -run TestSNMPSupport -v
```

- [ ] **Step 3: Implement `capabilities/support_snmp.go`:**

```go
package capabilities

// support_snmp.go: the SNMP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _snmp_support (pin go-port-pin-a9e0ebc,
// lines 197-219). Any discrepancy between this file and that pin is a bug in
// this file.

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// snmpSupport derives the SNMP-backend verdict for (m, op). SnmpReader/
// SnmpWriter serve almost everything from standard MIBs; the model-dependent
// refusals below are the guards they raise themselves -- this function reads
// the SAME model/snmp package data those guards read, never a parallel rule.
func snmpSupport(m *model.SwitchModel, op Operation) (Support, string) {
	if poeOps[op.Name] && m.PoEPortCount == 0 {
		return noPSE(m)
	}
	if op.Name == "set_mgmt_ip" && !snmp.HasVendorOids(m) {
		// SNMP writer's set_mgmt_ip writes the vendor mgmt-IP columns, so a
		// model whose agent registers no 4526 subtree at all has nothing to
		// write. The READ path has a standard-MIB fallback; the write does
		// not.
		return SupportUnsupported, fmt.Sprintf(
			"model %q registers no Netgear vendor OID subtree, and the management-IP write columns are vendor-only",
			m.Key)
	}
	if op.Name == "get_macs" && !m.HasMACTable() {
		// Unreachable today: HasMACTable() IS "has an SNMP backend", and this
		// function only runs when backend == SNMP. Kept defensively, mirroring
		// Python's own "# pragma: no cover" comment on the identical branch.
		return SupportUnsupported, fmt.Sprintf("model %q has no MAC/FDB table", m.Key)
	}
	return SupportSupported, ""
}
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./capabilities/... -run TestSNMPSupport -v
```

- [ ] **Step 5: Commit.**

```bash
git add capabilities/support_snmp.go capabilities/support_snmp_test.go
git commit -m "$(cat <<'EOF'
feat(capabilities): SNMP-backend support derivation

Ports _snmp_support from the pinned capabilities.py: PoE ops UNSUPPORTED on
0-PSE models, set_mgmt_ip UNSUPPORTED without a vendor OID subtree, get_macs
defensively gated on HasMACTable (unreachable today, mirrors Python's own
pragma-no-cover comment). Confirmed SwitchModel.Verified is never consulted
(m7300/xs748t still get real SNMP verdicts despite Verified=false).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: NSDP support derivation

**Files:**
- Create: `capabilities/support_nsdp.go`
- Test: `capabilities/support_nsdp_test.go`

**Interfaces:**
- Consumes: `capabilities.Operation`, `capabilities.Support*` (Task 3); `nsdp.NoMACsMsg`, `nsdp.NoLLDPMsg`, `nsdp.NoSensorsMsg`, `nsdp.NoPoEReadMsg`, `nsdp.NoPoEWriteMsg`, `nsdp.NoPortAdminMsg` (all exported by Task 2).
- Produces: `func nsdpSupport(m *model.SwitchModel, op Operation) (Support, string)` (unexported; consumed by Task 8's `For`; `m` is accepted but unused today — see comment in Step 3 — kept for signature symmetry with the other three backend-derivation functions and because Python's `_nsdp_support(model, op)` also takes `model` unused).

- [ ] **Step 1: Write the failing tests.** Create `capabilities/support_nsdp_test.go`:

```go
package capabilities

// support_nsdp_test.go: pins nsdpSupport against Python's _nsdp_support
// (capabilities.py:222-240) -- in particular that create_vlan/delete_vlan
// are SUPPORTED (the R1 dossier finding: nsdp/writer.go implements these for
// real over NSDP; there must be no refusal-dict entry for either).

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

func TestNSDPSupportRefusals(t *testing.T) {
	m := mustModelSnmp(t, "gs110emx") // any NSDP model; nsdpSupport ignores m today
	cases := []struct {
		op     string
		reason string
	}{
		{"get_macs", nsdp.NoMACsMsg},
		{"get_lldp", nsdp.NoLLDPMsg},
		{"get_sensors", nsdp.NoSensorsMsg},
		{"get_poe", nsdp.NoPoEReadMsg},
		{"set_poe", nsdp.NoPoEWriteMsg},
		{"cycle_poe", nsdp.NoPoEWriteMsg},
		{"clear_poe_fault", nsdp.NoPoEWriteMsg},
		{"set_port_enabled", nsdp.NoPortAdminMsg},
	}
	for _, c := range cases {
		op, err := OperationByName(c.op)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", c.op, err)
		}
		support, reason := nsdpSupport(m, op)
		if support != SupportUnsupported {
			t.Errorf("nsdpSupport(%s) = %v, want SupportUnsupported", c.op, support)
		}
		if reason != c.reason {
			t.Errorf("nsdpSupport(%s) reason = %q, want %q", c.op, reason, c.reason)
		}
	}
}

func TestNSDPSupportVlanLifecycleIsSupported(t *testing.T) {
	// R1: nsdp/writer.go's CreateVlan/DeleteVlan are real (verified-after-
	// write). The oracle must agree -- neither op appears in the refusal
	// dict, matching the pinned Python source exactly.
	m := mustModelSnmp(t, "gs110emx")
	for _, opName := range []string{"create_vlan", "delete_vlan"} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := nsdpSupport(m, op)
		if support != SupportSupported {
			t.Errorf("nsdpSupport(%s) = %v (%s), want SupportSupported", opName, support, reason)
		}
	}
}

func TestNSDPSupportOtherReadsAndWritesSupported(t *testing.T) {
	m := mustModelSnmp(t, "gs110emx")
	for _, opName := range []string{
		"get_ports", "get_stats", "get_vlans", "get_pvids", "get_mgmt_ip",
		"set_pvid", "set_vlan_membership", "set_mgmt_ip",
	} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := nsdpSupport(m, op)
		if support != SupportSupported {
			t.Errorf("nsdpSupport(%s) = %v (%s), want SupportSupported", opName, support, reason)
		}
	}
}

var _ = model.BackendNSDP // silence unused-import if the above cases change
```

- [ ] **Step 2: Run, verify it fails to compile** (`nsdpSupport` undefined):

```
./scripts/jail.sh go test ./capabilities/... -run TestNSDPSupport -v
```

- [ ] **Step 3: Implement `capabilities/support_nsdp.go`:**

```go
package capabilities

// support_nsdp.go: the NSDP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _nsdp_support (pin go-port-pin-a9e0ebc,
// lines 222-240). Any discrepancy between this file and that pin is a bug in
// this file.
//
// WARNING (R1, dossier): create_vlan/delete_vlan are DELIBERATELY absent
// from nsdpRefusals below -- nsdp/writer.go's CreateVlan/DeleteVlan are real,
// verified-after-write NSDP implementations (see that file's own doc
// comment: "VLAN create/delete ARE implemented here"). Do not add either to
// this map without first confirming nsdp.Writer has regressed.

import (
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// nsdpRefusals maps an operation name to the reader's/writer's own message
// constant, so a change to what NSDP refuses updates this table in the same
// edit as the constant itself -- mirrors Python's _nsdp_support refusals
// dict verbatim (capabilities.py:227-236).
var nsdpRefusals = map[string]string{
	"get_macs":         nsdp.NoMACsMsg,
	"get_lldp":         nsdp.NoLLDPMsg,
	"get_sensors":      nsdp.NoSensorsMsg,
	"get_poe":          nsdp.NoPoEReadMsg,
	"set_poe":          nsdp.NoPoEWriteMsg,
	"cycle_poe":        nsdp.NoPoEWriteMsg,
	"clear_poe_fault":  nsdp.NoPoEWriteMsg,
	"set_port_enabled": nsdp.NoPortAdminMsg,
}

// nsdpSupport derives the NSDP-backend verdict for op. m is unused today
// (kept for signature symmetry with snmpSupport/httpSupport/cliSupport, and
// because Python's _nsdp_support(model, op) also accepts an unused model
// parameter) -- NSDP's refusals are a flat, model-independent lookup by
// operation name.
func nsdpSupport(_ *model.SwitchModel, op Operation) (Support, string) {
	if reason, ok := nsdpRefusals[op.Name]; ok {
		return SupportUnsupported, reason
	}
	return SupportSupported, ""
}
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./capabilities/... -run TestNSDPSupport -v
```

- [ ] **Step 5: Commit.**

```bash
git add capabilities/support_nsdp.go capabilities/support_nsdp_test.go
git commit -m "$(cat <<'EOF'
feat(capabilities): NSDP-backend support derivation

Ports _nsdp_support from the pinned capabilities.py: a flat op-name -> reason
refusal map reusing nsdp package's own exported message constants verbatim
(Task 2). Explicitly pins create_vlan/delete_vlan as SUPPORTED (R1): both are
genuinely implemented over NSDP in this worktree's nsdp/writer.go, and the
Python source's own refusal dict has no entry for either.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: HTTP support derivation

**Files:**
- Create: `capabilities/support_http.go`
- Test: `capabilities/support_http_test.go`

**Interfaces:**
- Consumes: `capabilities.Operation`, `capabilities.Support*` (Task 3); `webui.HTTPModelSpec` (all fields already exported, `webui/endpoints.go`); `webui.CertUploadKnownUnimplemented map[string]string` (already exported, `webui/cert.go:52`); `webui.SupportsSensors`, `webui.MgmtIPPath` (exported by Task 2).
- Produces: `func httpSupport(m *model.SwitchModel, spec *webui.HTTPModelSpec, op Operation) (Support, string)` and `func httpPathFor(spec *webui.HTTPModelSpec, op Operation) string` (both unexported; consumed by Task 8's `For`, which is the one place that calls `webui.HTTPSpec(m)` to obtain `spec`). **Deliberate divergence from Python's structure:** Python's `_http_support(model, op)` calls `http_spec(model)` itself; this Go port instead takes the already-resolved `*webui.HTTPModelSpec` as a parameter. This is necessary because Go has no monkeypatching (Python's `test_unverified_backend_gates_off` mutates the live `endpoints._SPECS` dict in place and restores it in a `finally`) — taking `spec` as a parameter makes the `ReadsVerified`-gate branch trivially unit-testable with a synthetic spec, while `For` (Task 8) still calls the real `webui.HTTPSpec(m)`, so "derives, does not duplicate" holds end-to-end.

- [ ] **Step 1: Write the failing tests.** Create `capabilities/support_http_test.go`:

```go
package capabilities

// support_http_test.go: pins httpSupport against Python's _http_support and
// _http_path_for (capabilities.py:243-311).

import (
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

func mustHTTPSpec(t *testing.T, key string) (*model.SwitchModel, *webui.HTTPModelSpec) {
	t.Helper()
	m := mustModelSnmp(t, key)
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec(%q): %v", key, err)
	}
	return m, spec
}

func TestHTTPSupportUnverifiedGate(t *testing.T) {
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	// Synthesize an UNVERIFIED spec rather than mutating package state --
	// see this task's Interfaces note on why httpSupport takes spec directly.
	unverified := *spec
	unverified.ReadsVerified = false
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, reason := httpSupport(m, &unverified, op)
	if support != SupportUnverified {
		t.Errorf("httpSupport(unverified spec, get_ports) = %v, want SupportUnverified", support)
	}
	if !strings.Contains(reason, "UNVERIFIED") {
		t.Errorf("httpSupport(unverified spec, get_ports) reason = %q, want it to contain UNVERIFIED", reason)
	}
}

func TestHTTPSupportCertUploadKnownUnimplementedFoldsToUnsupported(t *testing.T) {
	// m4300-24x/m4300-16x/gsm7252ps take a cert over SCP, not HTTP. Python's
	// real facade raises NotImplementedError for this case but the ORACLE
	// still reports a single Support.UNSUPPORTED -- no distinct verdict, even
	// though Go has model.ErrKnownUnimplemented as a first-class sentinel.
	for key := range webui.CertUploadKnownUnimplemented {
		m, spec := mustHTTPSpec(t, key)
		op, err := OperationByName("upload_certificate")
		if err != nil {
			t.Fatalf("OperationByName(upload_certificate): %v", err)
		}
		support, reason := httpSupport(m, spec, op)
		if support != SupportUnsupported {
			t.Errorf("httpSupport(%s, upload_certificate) = %v, want SupportUnsupported", key, support)
		}
		if !strings.Contains(reason, "upload_certificate_scp") {
			t.Errorf("httpSupport(%s, upload_certificate) reason = %q, want it to mention upload_certificate_scp", key, reason)
		}
	}
}

func TestHTTPSupportNoPageIsUnsupported(t *testing.T) {
	// gs305ep's HTTPModelSpec has no MgmtIPPath and no SysinfoPath fallback
	// (its dialect has no mgmt-IP page at all).
	m, spec := mustHTTPSpec(t, "gs305ep")
	op, err := OperationByName("get_mgmt_ip")
	if err != nil {
		t.Fatalf("OperationByName(get_mgmt_ip): %v", err)
	}
	support, reason := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gs305ep, get_mgmt_ip) = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("httpSupport(gs305ep, get_mgmt_ip) reason is empty")
	}
}

func TestHTTPSupportSensorsGate(t *testing.T) {
	// gsm7228ps (S3300 dialect) has a SysinfoPath but NO live sensor table
	// (webui.SupportsSensors deliberately excludes the S3300 dialect).
	m, spec := mustHTTPSpec(t, "gsm7228ps")
	op, err := OperationByName("get_sensors")
	if err != nil {
		t.Fatalf("OperationByName(get_sensors): %v", err)
	}
	support, _ := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gsm7228ps, get_sensors) = %v, want SupportUnsupported", support)
	}
}

func TestHTTPSupportSetMgmtIPNeedsBothPageAndFields(t *testing.T) {
	// gs110emx: verify set_mgmt_ip requires BOTH MgmtIPPath and MgmtIPFields.
	m, spec := mustHTTPSpec(t, "gs110emx")
	op, err := OperationByName("set_mgmt_ip")
	if err != nil {
		t.Fatalf("OperationByName(set_mgmt_ip): %v", err)
	}
	support, _ := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gs110emx, set_mgmt_ip) = %v, want SupportUnsupported (no XUI mgmt-IP write page)", support)
	}
}

func TestHTTPSupportDefaultSupported(t *testing.T) {
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, reason := httpSupport(m, spec, op)
	if support != SupportSupported {
		t.Errorf("httpSupport(gsm7252ps, get_ports) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("httpSupport(gsm7252ps, get_ports) reason = %q, want empty", reason)
	}
}
```

- [ ] **Step 2: Run, verify it fails to compile** (`httpSupport`/`httpPathFor` undefined):

```
./scripts/jail.sh go test ./capabilities/... -run TestHTTPSupport -v
```

- [ ] **Step 3: Implement `capabilities/support_http.go`:**

```go
package capabilities

// support_http.go: the HTTP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _http_support and _http_path_for
// (pin go-port-pin-a9e0ebc, lines 243-311). Any discrepancy between this
// file and that pin is a bug in this file.
//
// httpSupport/httpPathFor take an already-resolved *webui.HTTPModelSpec
// rather than calling webui.HTTPSpec(m) themselves -- see this task's
// Interfaces note (Go has no monkeypatching, so the ReadsVerified gate is
// tested with a synthetic spec instead; For, in support.go, is the one place
// that calls the real webui.HTTPSpec).

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// httpSupport derives the HTTP-backend verdict for (m, op) given spec.
func httpSupport(m *model.SwitchModel, spec *webui.HTTPModelSpec, op Operation) (Support, string) {
	if !spec.ReadsVerified {
		// The facade gates BOTH reads and writes on ReadsVerified (see
		// backend_http.go's httpReadsSupported, reused for both directions):
		// output nobody has cross-verified against hardware is not
		// dispatched at all.
		return SupportUnverified, fmt.Sprintf("model %q HTTP reads are UNVERIFIED-pending-capture", m.Key)
	}
	if op.Name == "upload_certificate" {
		// These models CAN take a certificate -- just not over HTTP. The
		// real facade raises model.ErrKnownUnimplemented naming the real
		// mechanism (webui/cert.go's rejectKnownUnimplementedCertUpload)
		// rather than model.ErrUnsupportedCapability -- but the ORACLE folds
		// both into this single Support.UNSUPPORTED verdict, exactly
		// mirroring Python's collapse of UnsupportedCapabilityError and
		// NotImplementedError. Do not add a distinct Support value here.
		if mechanism, ok := webui.CertUploadKnownUnimplemented[m.Key]; ok {
			return SupportUnsupported, fmt.Sprintf(
				"this model takes a certificate by %s, not over the web UI -- use upload_certificate_scp",
				mechanism)
		}
	}
	path := httpPathFor(spec, op)
	if path == "" {
		return SupportUnsupported, fmt.Sprintf("model %q web UI has no page for %s (%s)", m.Key, op.Name, op.Summary)
	}
	return SupportSupported, ""
}

// httpPathFor is the endpoint op needs, or "" if this model's UI has no such
// page (Go's None sentinel, matching every other webui *ModelSpec string
// field). Mirrors http_read.py/http_write.py one line at a time; the three
// ops with composite conditions defer to webui's own exported helpers so
// there is exactly one definition of "this UI can answer that".
func httpPathFor(spec *webui.HTTPModelSpec, op Operation) string {
	switch op.Name {
	case "get_sensors":
		if webui.SupportsSensors(spec) {
			return spec.SysinfoPath
		}
		return ""
	case "get_mgmt_ip":
		return webui.MgmtIPPath(spec)
	case "set_mgmt_ip":
		// The XUI write needs the field map as well as the page.
		if spec.MgmtIPFields != nil {
			return spec.MgmtIPPath
		}
		return ""
	}
	simple := map[string]string{
		"get_ports":            spec.DashboardPath,
		"get_stats":            spec.StatsPath,
		"get_poe":              spec.PoEStatusPath,
		"get_pvids":            spec.PvidPath,
		"get_vlans":            spec.VlanConfigPath,
		"get_macs":             spec.MacTablePath,
		"get_lldp":             spec.LLDPPath,
		"set_poe":              spec.PoEConfigPath,
		"cycle_poe":            spec.PoEConfigPath,
		"clear_poe_fault":      spec.PoEConfigPath,
		"set_pvid":             spec.PvidPath,
		"set_vlan_membership":  spec.VlanMembershipPath,
		"create_vlan":          spec.VlanConfigPath,
		"delete_vlan":          spec.VlanConfigPath,
		"set_port_enabled":     spec.PortConfigPath,
		"upload_certificate":   spec.CertUploadPath,
	}
	return simple[op.Name]
}
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./capabilities/... -run TestHTTPSupport -v
```

- [ ] **Step 5: gofmt the map literal** (the `simple` map above is deliberately hand-aligned in the plan for readability; `gofmt` will re-align it — run it before committing):

```
gofmt -w capabilities/support_http.go
```

- [ ] **Step 6: Commit.**

```bash
git add capabilities/support_http.go capabilities/support_http_test.go
git commit -m "$(cat <<'EOF'
feat(capabilities): HTTP-backend support derivation

Ports _http_support/_http_path_for from the pinned capabilities.py.
Deliberately takes an already-resolved *webui.HTTPModelSpec as a parameter
(rather than calling webui.HTTPSpec itself) so the ReadsVerified gate is
unit-testable with a synthetic spec -- Go has no monkeypatching equivalent to
Python's test_unverified_backend_gates_off. Confirms the cert-upload
NotImplementedError/UnsupportedCapabilityError collapse: both fold into a
single Support.UNSUPPORTED verdict, no new Support value invented even though
Go has a distinct model.ErrKnownUnimplemented sentinel Python lacks.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: CLI (SSH/Telnet/Console) support derivation

**Files:**
- Create: `capabilities/support_cli.go`
- Test: `capabilities/support_cli_test.go`

**Interfaces:**
- Consumes: `capabilities.Operation`, `capabilities.Support*`, `poeOps`, `noPSE` (Task 3); `fastpath.CLISpec(m *model.SwitchModel) (*fastpath.CliModelSpec, error)` and `fastpath.ScpProfile(m *model.SwitchModel) (*fastpath.ScpCertProfile, error)` (both already exported, `fastpath/spec.go`); `fastpath.CliModelSpec.ReadsVerified`, `.WritesVerified` (already exported fields).
- Produces: `func cliReadsSupported(m *model.SwitchModel) (bool, *fastpath.CliModelSpec)`, `func cliWritesSupported(m *model.SwitchModel) bool`, `func cliSupport(m *model.SwitchModel, op Operation) (Support, string)` (all unexported; `cliSupport` consumed by Task 8's `For`).

- [ ] **Step 1: Write the failing tests.** Create `capabilities/support_cli_test.go`:

```go
package capabilities

// support_cli_test.go: pins cliSupport against Python's _cli_support
// (capabilities.py:314-341) and the SCP cert gate
// (protocols/cli/commands.py's scp_cert_profile via fastpath.ScpProfile).

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/fastpath"
)

func TestCLISupportReadsWritesVerifiedToday(t *testing.T) {
	// Every CLI model's spec is ReadsVerified=WritesVerified=true today (see
	// fastpath/spec.go's newCliModelSpec calls) -- so cliSupport must report
	// SUPPORTED (subject to the other branches), never UNVERIFIED, for all 4.
	for _, key := range []string{"gsm7252ps", "m4300-24x", "m4300-16x", "gsm7228ps"} {
		m := mustModelSnmp(t, key)
		op, err := OperationByName("get_ports")
		if err != nil {
			t.Fatalf("OperationByName(get_ports): %v", err)
		}
		support, reason := cliSupport(m, op)
		if support != SupportSupported {
			t.Errorf("cliSupport(%s, get_ports) = %v (%s), want SupportSupported", key, support, reason)
		}
	}
}

func TestCLISupportSCPCertificateGateMatchesFastpath(t *testing.T) {
	// test_scp_certificate_gate's Go equivalent: the oracle's verdict for
	// upload_certificate_scp must equal whether fastpath.ScpProfile(m)
	// itself errors -- the oracle asks the facade's own gate, not a copy.
	for _, key := range []string{"gsm7252ps", "m4300-24x", "m4300-16x", "gsm7228ps"} {
		m := mustModelSnmp(t, key)
		_, profileErr := fastpath.ScpProfile(m)
		wantSupported := profileErr == nil

		op, err := OperationByName("upload_certificate_scp")
		if err != nil {
			t.Fatalf("OperationByName(upload_certificate_scp): %v", err)
		}
		support, _ := cliSupport(m, op)
		gotSupported := support == SupportSupported
		if gotSupported != wantSupported {
			t.Errorf("cliSupport(%s, upload_certificate_scp) supported = %v, want %v (ScpProfile err = %v)",
				key, gotSupported, wantSupported, profileErr)
		}
	}
}

func TestCLISupportPoEGate(t *testing.T) {
	// m4300-24x: CLI model with PoEPortCount == 0.
	m := mustModelSnmp(t, "m4300-24x")
	op, err := OperationByName("get_poe")
	if err != nil {
		t.Fatalf("OperationByName(get_poe): %v", err)
	}
	support, _ := cliSupport(m, op)
	if support != SupportUnsupported {
		t.Errorf("cliSupport(m4300-24x, get_poe) = %v, want SupportUnsupported", support)
	}
}

func TestCLISupportPoESupportedOnPSEModel(t *testing.T) {
	// gsm7252ps: CLI model that DOES have PSE ports.
	m := mustModelSnmp(t, "gsm7252ps")
	op, err := OperationByName("get_poe")
	if err != nil {
		t.Fatalf("OperationByName(get_poe): %v", err)
	}
	support, reason := cliSupport(m, op)
	if support != SupportSupported {
		t.Errorf("cliSupport(gsm7252ps, get_poe) = %v (%s), want SupportSupported", support, reason)
	}
}
```

- [ ] **Step 2: Run, verify it fails to compile** (`cliSupport` undefined):

```
./scripts/jail.sh go test ./capabilities/... -run TestCLISupport -v
```

- [ ] **Step 3: Implement `capabilities/support_cli.go`:**

```go
package capabilities

// support_cli.go: the CLI-backend (SSH/Telnet/Console) derivation, ported
// field-for-field from src/netgear_switch/capabilities.py's _cli_support
// (pin go-port-pin-a9e0ebc, lines 314-341), plus the Python _dispatch
// module's cli_reads_supported/cli_writes_supported (_dispatch.py:202-234),
// which Go has no direct equivalent of yet -- re-derived here directly from
// fastpath.CLISpec rather than duplicated as a separate exported helper,
// since nothing else in this codebase needs it today. Any discrepancy
// between this file and the pin is a bug in this file.

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

// cliReadsSupported reports whether m's CLI reads are dispatchable: it has a
// CLI backend AND that backend's CliModelSpec.ReadsVerified is true.
// Mirrors Python's cli_reads_supported. Returns the resolved spec too (nil
// on failure) so cliWritesSupported/cliSupport need not look it up twice.
func cliReadsSupported(m *model.SwitchModel) (bool, *fastpath.CliModelSpec) {
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		return false, nil
	}
	return spec.ReadsVerified, spec
}

// cliWritesSupported additionally requires cliReadsSupported(m) AND
// WritesVerified -- verification is layered: a write can't be honestly
// verified by reading back through an unverified reader. Mirrors Python's
// cli_writes_supported.
func cliWritesSupported(m *model.SwitchModel) bool {
	ok, spec := cliReadsSupported(m)
	return ok && spec.WritesVerified
}

// cliSupport derives the CLI-backend verdict for (m, op).
func cliSupport(m *model.SwitchModel, op Operation) (Support, string) {
	readsOK, _ := cliReadsSupported(m)
	if op.Kind == OperationKindRead && !readsOK {
		return SupportUnverified, fmt.Sprintf("model %q CLI reads are UNVERIFIED-pending cross-verify", m.Key)
	}
	if op.Kind == OperationKindWrite && !cliWritesSupported(m) {
		return SupportUnverified, fmt.Sprintf("model %q CLI writes are UNVERIFIED-pending a live write run", m.Key)
	}
	if op.Name == "upload_certificate_scp" {
		// The facade's real dispatch gate is fastpath.ScpProfile itself --
		// ask it rather than re-listing which models have a copy-scp
		// profile, mirroring Python's identical comment on this branch.
		if _, err := fastpath.ScpProfile(m); err != nil {
			return SupportUnsupported, err.Error()
		}
		return SupportSupported, ""
	}
	if poeOps[op.Name] && m.PoEPortCount == 0 {
		return noPSE(m)
	}
	if op.Name == "get_macs" && !m.HasMACTable() {
		// Same "currently unreachable" caveat as snmpSupport's identical
		// branch: every model with a CLI backend today also has SNMP.
		return SupportUnsupported, fmt.Sprintf("model %q CLI has no MAC/FDB table", m.Key)
	}
	return SupportSupported, ""
}
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./capabilities/... -run TestCLISupport -v
```

- [ ] **Step 5: Commit.**

```bash
git add capabilities/support_cli.go capabilities/support_cli_test.go
git commit -m "$(cat <<'EOF'
feat(capabilities): CLI-backend (SSH/Telnet/Console) support derivation

Ports _cli_support plus _dispatch.cli_reads_supported/cli_writes_supported
from the pinned capabilities.py. The upload_certificate_scp branch asks
fastpath.ScpProfile(m) directly rather than re-listing which models have a
copy-scp profile -- pinned by TestCLISupportSCPCertificateGateMatchesFastpath,
the Go equivalent of Python's test_scp_certificate_gate. Confirmed all 4 CLI
models are ReadsVerified=WritesVerified=true today (fastpath/spec.go), so the
UNVERIFIED branch is currently unreachable in practice but implemented
faithfully.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Top-level dispatch — `For`, `BackendsFor`, `ForKey`, `Matrix`

**Files:**
- Create: `capabilities/support.go`
- Test: `capabilities/support_test.go`

**Interfaces:**
- Consumes: `snmpSupport`, `nsdpSupport`, `httpSupport`, `cliSupport` (Tasks 4–7); `webui.HTTPSpec(m *model.SwitchModel) (*webui.HTTPModelSpec, error)` (already exported); `model.Models() []*model.SwitchModel`, `model.GetModel(key string) (*model.SwitchModel, error)` (already exported).
- Produces (the package's full public surface, consumed by Task 9's root-package re-exports and Task 10's cross-check):
  - `func BackendsFor(m *model.SwitchModel) []model.Backend`
  - `func For(m *model.SwitchModel, backend model.Backend, op Operation) Capability`
  - `func ForKey(modelKey string, backend model.Backend, opName string) (Capability, error)`
  - `func Matrix(modelKeys []string, operations []Operation) ([]Capability, error)` (`nil` modelKeys = every registered model in canonical order; `nil` operations = `Operations`, all 21)

- [ ] **Step 1: Write the failing tests.** Create `capabilities/support_test.go`:

```go
package capabilities

// support_test.go: pins the top-level dispatcher (For/BackendsFor/ForKey/
// Matrix) against Python's support()/backends_for()/matrix()
// (capabilities.py:344-414) and the 6 remaining test_capabilities.py
// invariants not already covered by Tasks 4-7's per-backend tests:
// test_no_backend_is_reported_before_the_operation,
// test_console_is_named_as_a_transport_not_a_missing_cli,
// test_backend_fixed_operations, test_backends_are_in_facade_preference_order,
// test_matrix_covers_every_model_and_carries_no_absent_backends,
// test_every_refusal_states_a_reason.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestBackendsForOrder(t *testing.T) {
	// Pins two concrete models' order, mirroring Python's
	// test_backends_are_in_facade_preference_order EXACTLY -- plus a third
	// case (gsm7228ps) this plan's Task 1 fix makes newly correct: telnet
	// only, no SSH.
	cases := []struct {
		key  string
		want []model.Backend
	}{
		{"m4300-24x", []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet}},
		{"gs110emx", []model.Backend{model.BackendNSDP, model.BackendHTTP}},
		{"gsm7228ps", []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendTelnet}},
	}
	for _, c := range cases {
		m := mustModelSnmp(t, c.key)
		got := BackendsFor(m)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("BackendsFor(%s) = %v, want %v", c.key, got, c.want)
		}
	}
}

func TestForNoBackendReportedBeforeOperation(t *testing.T) {
	m := mustModelSnmp(t, "gs110emx") // NSDP+HTTP only, no SNMP
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	cap := For(m, model.BackendSNMP, op)
	if cap.Support != SupportNoBackend {
		t.Errorf("For(gs110emx, SNMP, get_ports).Support = %v, want SupportNoBackend", cap.Support)
	}
	if !strings.Contains(cap.Reason, "snmp") {
		t.Errorf("For(gs110emx, SNMP, get_ports).Reason = %q, want it to mention the snmp backend", cap.Reason)
	}
}

func TestForConsoleIsNamedAsTransportNotMissingCLI(t *testing.T) {
	m := mustModelSnmp(t, "gsm7252ps")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	cap := For(m, model.BackendConsole, op)
	if cap.Support != SupportNoBackend {
		t.Errorf("For(gsm7252ps, CONSOLE, get_ports).Support = %v, want SupportNoBackend", cap.Support)
	}
	if !strings.Contains(cap.Reason, "serial transport") {
		t.Errorf("For(gsm7252ps, CONSOLE, get_ports).Reason = %q, want it to mention 'serial transport'", cap.Reason)
	}
	sshCap := For(m, model.BackendSSH, op)
	if !sshCap.Supported() {
		t.Errorf("For(gsm7252ps, SSH, get_ports) = %v, want Supported", sshCap.Support)
	}
}

func TestForBackendFixedOperations(t *testing.T) {
	for _, m := range model.Models() {
		for _, backend := range BackendsFor(m) {
			for _, op := range Operations {
				if op.Backends == nil {
					continue
				}
				restricted := true
				for _, b := range op.Backends {
					if b == backend {
						restricted = false
						break
					}
				}
				if !restricted {
					continue
				}
				cap := For(m, backend, op)
				if cap.Support != SupportUnsupported {
					t.Errorf("For(%s, %s, %s).Support = %v, want SupportUnsupported (backend-restricted op)",
						m.Key, backend, op.Name, cap.Support)
				}
				if !strings.Contains(cap.Reason, op.Name) {
					t.Errorf("For(%s, %s, %s).Reason = %q, want it to mention the op name",
						m.Key, backend, op.Name, cap.Reason)
				}
			}
		}
	}
}

func TestForKeyMatchesForByObject(t *testing.T) {
	byKey, err := ForKey("gsm7252ps", model.BackendSNMP, "get_ports")
	if err != nil {
		t.Fatalf("ForKey: %v", err)
	}
	m := mustModelSnmp(t, "gsm7252ps")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	byObject := For(m, model.BackendSNMP, op)
	// Capability is not ==-comparable (Operation.Backends is a slice) -- see
	// this plan's "Deliberate divergences" note 4.
	if !reflect.DeepEqual(byKey, byObject) {
		t.Errorf("ForKey(...) = %+v, want equal to For(...) = %+v", byKey, byObject)
	}
}

func TestMatrixCoversEveryModelAndCarriesNoAbsentBackends(t *testing.T) {
	caps, err := Matrix(nil, nil)
	if err != nil {
		t.Fatalf("Matrix(nil, nil): %v", err)
	}
	seen := map[string]bool{}
	wantLen := 0
	for _, m := range model.Models() {
		seen[m.Key] = false
		wantLen += len(BackendsFor(m)) * len(Operations)
	}
	for _, c := range caps {
		if c.Support == SupportNoBackend {
			t.Errorf("Matrix() row %+v has Support == SupportNoBackend, want none", c)
		}
		if _, ok := seen[c.ModelKey]; !ok {
			t.Errorf("Matrix() row has unexpected ModelKey %q", c.ModelKey)
		}
		seen[c.ModelKey] = true
	}
	for key, wasSeen := range seen {
		if !wasSeen {
			t.Errorf("Matrix() has no rows for model %q", key)
		}
	}
	if len(caps) != wantLen {
		t.Errorf("len(Matrix()) = %d, want %d", len(caps), wantLen)
	}
}

func TestEveryRefusalStatesAReason(t *testing.T) {
	caps, err := Matrix(nil, nil)
	if err != nil {
		t.Fatalf("Matrix(nil, nil): %v", err)
	}
	for _, c := range caps {
		if c.Supported() {
			if c.Reason != "" {
				t.Errorf("%s/%s/%s: Supported but Reason = %q, want empty", c.ModelKey, c.Backend, c.Operation.Name, c.Reason)
			}
		} else if c.Reason == "" {
			t.Errorf("%s/%s/%s: %v but Reason is empty", c.ModelKey, c.Backend, c.Operation.Name, c.Support)
		}
	}
}
```

- [ ] **Step 2: Run, verify it fails to compile** (`BackendsFor`/`For`/`ForKey`/`Matrix` undefined):

```
./scripts/jail.sh go test ./capabilities/... -run "TestBackendsFor|TestFor|TestMatrix|TestEveryRefusal" -v
```

- [ ] **Step 3: Implement `capabilities/support.go`:**

```go
package capabilities

// support.go: the top-level dispatcher -- For/BackendsFor/ForKey/Matrix --
// ported field-for-field from src/netgear_switch/capabilities.py's
// support()/backends_for()/matrix() (pin go-port-pin-a9e0ebc, lines
// 344-414). Any discrepancy between this file and that pin is a bug in this
// file.
//
// Naming: Python's free function support(model, backend, op) cannot be
// named Support in Go (the type Support already claims that identifier) --
// this port uses For. operation(name) becomes OperationByName (types.go);
// matrix(models=None, operations=OPERATIONS) becomes Matrix with nil-slice
// defaults, since Go has no keyword-default arguments.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// backendOrder is the model's backends in the facade's default-preference
// order, mirroring Python's LOCALLY-restated tuple in backends_for
// (capabilities.py:388-395) -- deliberately NOT dispatch.go's
// backendPreference (which only lists 4 backends and is used for a
// different purpose, real default-backend RESOLUTION). Python re-states its
// own copy rather than importing sync_api._BACKEND_PREFERENCE; this mirrors
// that same deliberate duplication-by-convention.
var backendOrder = []model.Backend{
	model.BackendSNMP, model.BackendNSDP, model.BackendHTTP,
	model.BackendSSH, model.BackendTelnet, model.BackendConsole,
}

// BackendsFor returns m's backends in the facade's default-preference
// order, mirroring Python's backends_for.
func BackendsFor(m *model.SwitchModel) []model.Backend {
	out := make([]model.Backend, 0, len(backendOrder))
	for _, b := range backendOrder {
		if m.HasBackend(b) {
			out = append(out, b)
		}
	}
	return out
}

// backendRestricts reports whether op.Backends is set and does NOT include
// backend.
func backendRestricts(op Operation, backend model.Backend) bool {
	if op.Backends == nil {
		return false
	}
	for _, b := range op.Backends {
		if b == backend {
			return false
		}
	}
	return true
}

// sortedBackendNames renders backends as a sorted, comma-joined string of
// their (Go-lowercase) names, for reason text -- mirrors Python's
// ", ".join(sorted(b.name for b in ...)) shape, but in this codebase's own
// established lowercase Backend spelling (see this plan's "Deliberate
// divergences" note 1).
func sortedBackendNames(backends []model.Backend) string {
	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = string(b)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// For is the verdict for one (model, backend, operation) triple, mirroring
// Python's support(). Never errors: m and op are already-resolved concrete
// values, so there is nothing left to look up that can fail -- unlike
// Python's support(), which accepts raw string keys and can raise. Use
// ForKey for the string-based entry point.
func For(m *model.SwitchModel, backend model.Backend, op Operation) Capability {
	if !m.HasBackend(backend) {
		reason := fmt.Sprintf("model %q has no %s backend (it has: %s)", m.Key, backend, sortedBackendNames(m.Backends))
		if backend == model.BackendConsole {
			// CONSOLE is never a member of any model's Backends (it is a
			// transport for the CLI backend, not a network backend) -- say
			// so explicitly, rather than implying the CLI is absent on a
			// model whose SSH/Telnet works fine.
			reason = "CONSOLE is a serial transport for the CLI backend, not a network backend; a model's CLI support is its SSH/TELNET entry"
		}
		return Capability{ModelKey: m.Key, Backend: backend, Operation: op, Support: SupportNoBackend, Reason: reason}
	}

	if backendRestricts(op, backend) {
		reason := fmt.Sprintf("%s is served only over %s", op.Name, sortedBackendNames(op.Backends))
		return Capability{ModelKey: m.Key, Backend: backend, Operation: op, Support: SupportUnsupported, Reason: reason}
	}

	var support Support
	var reason string
	switch backend {
	case model.BackendSNMP:
		support, reason = snmpSupport(m, op)
	case model.BackendNSDP:
		support, reason = nsdpSupport(m, op)
	case model.BackendHTTP:
		spec, err := webui.HTTPSpec(m)
		if err != nil {
			// Defensive: cannot happen for any of the 10 currently
			// registered models (every one with an HTTP backend has a
			// matching webui.HTTPSpecs entry) -- if it ever does, fold it
			// into UNSUPPORTED with the underlying error's own text rather
			// than panicking or silently claiming SUPPORTED.
			support, reason = SupportUnsupported, err.Error()
		} else {
			support, reason = httpSupport(m, spec, op)
		}
	default: // SSH, Telnet -- Console is always caught by the NO_BACKEND check above
		support, reason = cliSupport(m, op)
	}
	return Capability{ModelKey: m.Key, Backend: backend, Operation: op, Support: support, Reason: reason}
}

// ForKey is For's string-keyed convenience entry point, mirroring Python's
// support() accepting a model key or an Operation name interchangeably.
// Unlike For, ForKey can fail (an unknown model key or operation name).
func ForKey(modelKey string, backend model.Backend, opName string) (Capability, error) {
	m, err := model.GetModel(modelKey)
	if err != nil {
		return Capability{}, err
	}
	op, err := OperationByName(opName)
	if err != nil {
		return Capability{}, err
	}
	return For(m, backend, op), nil
}

// Matrix returns every verdict for modelKeys x their backends x operations.
// modelKeys == nil defaults to every registered model (model.Models()'s
// canonical order); operations == nil defaults to Operations (all 21). Only
// backends a model actually has are included (via BackendsFor), so the
// result never carries a SupportNoBackend row. Mirrors Python's matrix().
func Matrix(modelKeys []string, operations []Operation) ([]Capability, error) {
	keys := modelKeys
	if keys == nil {
		for _, m := range model.Models() {
			keys = append(keys, m.Key)
		}
	}
	ops := operations
	if ops == nil {
		ops = Operations
	}
	var out []Capability
	for _, key := range keys {
		m, err := model.GetModel(key)
		if err != nil {
			return nil, err
		}
		for _, backend := range BackendsFor(m) {
			for _, op := range ops {
				out = append(out, For(m, backend, op))
			}
		}
	}
	return out, nil
}
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race ./capabilities/... -v
```

- [ ] **Step 5: Run the full gate.**

```
make fmt-check && ./scripts/jail.sh go vet ./... && make lint && ./scripts/jail.sh go test -race ./...
```

- [ ] **Step 6: Commit.**

```bash
git add capabilities/support.go capabilities/support_test.go
git commit -m "$(cat <<'EOF'
feat(capabilities): top-level dispatch -- For, BackendsFor, ForKey, Matrix

Ports support()/backends_for()/matrix() from the pinned capabilities.py.
For(model, backend, op) never errors (both arguments are already-resolved
concrete values); ForKey is the fallible string-keyed convenience entry
point Python's support(str, ...) shape maps onto. Confirms every remaining
test_capabilities.py structural invariant not already covered by Tasks 4-7:
NO_BACKEND precedes the operation question, CONSOLE names itself as a
transport not a missing CLI, backend-fixed operations refuse by name,
matrix() carries zero NO_BACKEND rows and covers every model, every non-
supported row states a reason.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Facade-method-name parity test + root-package re-exports

**Files:**
- Create: `capabilities_facade_test.go` (repo root, package `netgearswitch_test`)
- Modify: `alias.go`

**Interfaces:**
- Consumes: everything from Tasks 3 and 8 (`capabilities.Operations`, `capabilities.OperationByName`, `capabilities.For`, `capabilities.ForKey`, `capabilities.BackendsFor`, `capabilities.Matrix`, `capabilities.Capability`, `capabilities.Operation`, `capabilities.OperationKind`, `capabilities.Support*`); `*netgearswitch.Switch`'s public method set (`switch.go`, `switch_write.go`, `backend_http.go`).
- Produces: root-package re-exports `netgearswitch.Capability`, `netgearswitch.Operation`, `netgearswitch.OperationKind`, `netgearswitch.Support` (type aliases); `netgearswitch.SupportSupported/SupportNoBackend/SupportUnsupported/SupportUnverified`, `netgearswitch.OperationKindRead/OperationKindWrite` (const aliases); `netgearswitch.Operations` (var alias); `netgearswitch.For`, `netgearswitch.ForKey`, `netgearswitch.BackendsFor`, `netgearswitch.Matrix` (wrapper funcs). **Deliberately NOT re-exported:** `ReadOperations`, `WriteOperations`, `OperationByName` — reachable only via `capabilities.X`, mirroring Python's `__init__.py` re-export asymmetry (dossier §2).

- [ ] **Step 1: Write the failing test.** Create `capabilities_facade_test.go` at the repo root:

```go
package netgearswitch_test

// capabilities_facade_test.go: pins two cross-package invariants the
// capabilities package itself cannot check (it must not import the root
// netgearswitch package -- that would cycle back through alias.go):
//
//  1. every capabilities.Operation.Name maps onto a real method on
//     *netgearswitch.Switch, mirroring Python's test_operations_are_facade_
//     methods -- with ONE known, documented exception (see below).
//  2. the root package's curated re-export subset (Task 9's alias.go
//     additions) actually compiles and behaves identically to calling
//     capabilities.X directly.

import (
	"reflect"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
)

// operationFacadeMethod maps each capabilities.Operation.Name to the real
// *netgearswitch.Switch method name it corresponds to. upload_certificate_scp
// is DELIBERATELY absent: fastpath.DeployCertificateSCP exists (slice-07)
// but is not yet wired into *Switch as an UploadCertificateSCP method -- a
// known, pre-existing gap this plan does not close (see the plan's
// "Deliberate non-fixes" section). The capability VERDICT for that operation
// is still fully derivable (fastpath.ScpProfile is the real gate, Task 7
// already ports it) and is tested in capabilities/support_cli_test.go; only
// the "is there a *Switch method with this name" check is skipped for it.
var operationFacadeMethod = map[string]string{
	"get_ports":           "GetPorts",
	"get_stats":           "GetStats",
	"get_vlans":           "GetVLANs",
	"get_pvids":           "GetPVIDs",
	"get_lldp":            "GetLLDP",
	"get_macs":            "GetMACs",
	"get_poe":             "GetPoE",
	"get_sensors":         "GetSensors",
	"get_mgmt_ip":         "GetMgmtIP",
	"nsdp_device":         "NSDPDevice",
	"set_port_enabled":    "SetPortEnabled",
	"set_poe":             "SetPoE",
	"cycle_poe":           "CyclePoE",
	"clear_poe_fault":     "ClearPoEFault",
	"set_pvid":            "SetPVID",
	"set_vlan_membership": "SetVlanMembership",
	"create_vlan":         "CreateVlan",
	"delete_vlan":         "DeleteVlan",
	"set_mgmt_ip":         "SetMgmtIP",
	"upload_certificate":  "UploadCertificate",
	// "upload_certificate_scp": intentionally absent -- see doc comment above.
}

func TestOperationsAreFacadeMethods(t *testing.T) {
	switchType := reflect.TypeOf((*netgearswitch.Switch)(nil))
	for _, op := range capabilities.Operations {
		methodName, mapped := operationFacadeMethod[op.Name]
		if !mapped {
			if op.Name != "upload_certificate_scp" {
				t.Errorf("operation %q has no entry in operationFacadeMethod (and is not the one documented exception)", op.Name)
			}
			continue
		}
		if _, ok := switchType.MethodByName(methodName); !ok {
			t.Errorf("capabilities operation %q -> *Switch.%s, but no such method exists", op.Name, methodName)
		}
	}
	for _, op := range capabilities.ReadOperations {
		if op.Kind != capabilities.OperationKindRead {
			t.Errorf("ReadOperations: %q has Kind %v, want OperationKindRead", op.Name, op.Kind)
		}
	}
	for _, op := range capabilities.WriteOperations {
		if op.Kind != capabilities.OperationKindWrite {
			t.Errorf("WriteOperations: %q has Kind %v, want OperationKindWrite", op.Name, op.Kind)
		}
	}
}

func TestRootPackageReExportsMatchCapabilitiesPackage(t *testing.T) {
	m, err := netgearswitch.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	viaRoot := netgearswitch.For(m, netgearswitch.BackendSNMP, capabilities.Operations[0])
	viaPkg := capabilities.For(m, model.BackendSNMP, capabilities.Operations[0])
	if !reflect.DeepEqual(viaRoot, viaPkg) {
		t.Errorf("netgearswitch.For(...) = %+v, want equal to capabilities.For(...) = %+v", viaRoot, viaPkg)
	}

	rootBackends := netgearswitch.BackendsFor(m)
	pkgBackends := capabilities.BackendsFor(m)
	if !reflect.DeepEqual(rootBackends, pkgBackends) {
		t.Errorf("netgearswitch.BackendsFor(...) = %v, want equal to capabilities.BackendsFor(...) = %v", rootBackends, pkgBackends)
	}

	if len(netgearswitch.Operations) != len(capabilities.Operations) {
		t.Errorf("len(netgearswitch.Operations) = %d, want %d", len(netgearswitch.Operations), len(capabilities.Operations))
	}

	rootCap, err := netgearswitch.ForKey("gsm7252ps", netgearswitch.BackendSNMP, "get_ports")
	if err != nil {
		t.Fatalf("netgearswitch.ForKey: %v", err)
	}
	if !rootCap.Supported() {
		t.Errorf("netgearswitch.ForKey(gsm7252ps, SNMP, get_ports).Supported() = false, want true")
	}
}
```

- [ ] **Step 2: Run, verify it fails to compile** (`netgearswitch.For`/`ForKey`/`BackendsFor`/`Operations`/`Capability` etc. undefined at root):

```
./scripts/jail.sh go test . -run "TestOperationsAreFacadeMethods|TestRootPackageReExports" -v
```

- [ ] **Step 3: Add the re-exports to `alias.go`.** Append to the existing type-alias block (the one already containing `SwitchModel = model.SwitchModel` etc.):

```go
	// Capability is aliased from capabilities.Capability.
	Capability = capabilities.Capability
	// Operation is aliased from capabilities.Operation.
	Operation = capabilities.Operation
	// OperationKind is aliased from capabilities.OperationKind.
	OperationKind = capabilities.OperationKind
	// Support is aliased from capabilities.Support.
	Support = capabilities.Support
```

Add a new const block (near the existing `Backend*` const block):

```go
// Support values, re-exported from capabilities.
const (
	SupportSupported   = capabilities.SupportSupported
	SupportNoBackend   = capabilities.SupportNoBackend
	SupportUnsupported = capabilities.SupportUnsupported
	SupportUnverified  = capabilities.SupportUnverified
)

// OperationKind values, re-exported from capabilities.
const (
	OperationKindRead  = capabilities.OperationKindRead
	OperationKindWrite = capabilities.OperationKindWrite
)
```

Add a var alias and wrapper functions (near the existing `GetModel`/`Models` wrapper functions):

```go
// Operations is the full 21-entry read+write operation table, re-exported
// from capabilities.Operations. ReadOperations/WriteOperations/
// OperationByName are DELIBERATELY not re-exported here -- reach them via
// the capabilities package directly, mirroring Python's netgear_switch
// top-level package re-exporting only a subset of netgear_switch.capabilities
// (dossier §2).
var Operations = capabilities.Operations

// For is the capability oracle's top-level verdict function; see
// capabilities.For.
func For(m *model.SwitchModel, backend model.Backend, op capabilities.Operation) capabilities.Capability {
	return capabilities.For(m, backend, op)
}

// ForKey is For's string-keyed convenience entry point; see capabilities.ForKey.
func ForKey(modelKey string, backend model.Backend, opName string) (capabilities.Capability, error) {
	return capabilities.ForKey(modelKey, backend, opName)
}

// BackendsFor returns a model's backends in the facade's default-preference
// order; see capabilities.BackendsFor.
func BackendsFor(m *model.SwitchModel) []model.Backend {
	return capabilities.BackendsFor(m)
}

// Matrix returns every capability verdict for modelKeys x their backends x
// operations; see capabilities.Matrix.
func Matrix(modelKeys []string, operations []capabilities.Operation) ([]capabilities.Capability, error) {
	return capabilities.Matrix(modelKeys, operations)
}
```

Add the import:

```go
	"github.com/mithro/go-netgear-switch-library/capabilities"
```

- [ ] **Step 4: Run, verify all pass.**

```
./scripts/jail.sh go test -race . -run "TestOperationsAreFacadeMethods|TestRootPackageReExports" -v
```

- [ ] **Step 5: Run the full gate.**

```
make fmt-check && ./scripts/jail.sh go vet ./... && make lint && ./scripts/jail.sh go test -race ./...
```

- [ ] **Step 6: Commit.**

```bash
git add capabilities_facade_test.go alias.go
git commit -m "$(cat <<'EOF'
feat: re-export capabilities oracle from the root package; pin facade parity

alias.go gains Capability/Operation/OperationKind/Support (types+consts),
Operations (var), For/ForKey/BackendsFor/Matrix (funcs) -- mirroring Python's
netgear_switch/__init__.py re-export subset exactly, deliberately leaving
ReadOperations/WriteOperations/OperationByName reachable only via
capabilities.X (dossier's noted __init__.py asymmetry).

New root-package test pins every capabilities.Operation.Name against a real
*Switch method, with ONE documented, deliberate exception:
upload_certificate_scp has no wired *Switch method yet (fastpath.
DeployCertificateSCP exists but isn't hooked into the facade) -- a
pre-existing gap this plan flags rather than silently works around.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Golden-fixture cross-check against the pinned Python `capabilities.py`

**Files:**
- Create: `capabilities/testdata/python_matrix_a9e0ebc.json`
- Create: `capabilities/matrix_parity_test.go`

**Interfaces:**
- Consumes: `capabilities.Matrix`, `capabilities.Capability` (Task 8).
- Produces: nothing consumed by later tasks — this is the plan's final, capstone faithfulness gate.

**Why this design (the "verdict, not reason bytes" decision, made concrete):** This plan's Global Constraints already establish that reason TEXT is not asserted byte-identical to Python (confirmed divergent even for a case that IS meant to share meaning, `nsdp.NoPortAdminMsg`'s embedded evidence prose). What SHOULD match, and is the actual faithfulness question worth a golden fixture, is: for every `(model_key, backend, operation)` triple, does the Go oracle's `Support` verdict equal the pinned Python oracle's, and does "has a reason" agree. This is exactly what would have caught the R1 dossier finding (NSDP create/delete VLAN) had it still been true, and is what would catch a future accidental verdict swap.

- [ ] **Step 1: Generate the golden fixture from the pinned Python source.** Run this from anywhere (it `cd`s into the pinned worktree itself); it prints JSON to stdout, which is redirected straight into this repo — no file is ever written inside the pinned (read-only) worktree:

```bash
cd /home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-a9e0ebc && \
uv run --extra async --extra http python3 -c "
import json
from netgear_switch.capabilities import matrix

rows = [
    {
        'model_key': c.model_key,
        'backend': c.backend.name.lower(),
        'operation': c.operation.name,
        'support': c.support.value,
        'reason_nonempty': bool(c.reason),
    }
    for c in matrix()
]
rows.sort(key=lambda r: (r['model_key'], r['backend'], r['operation']))
print(json.dumps(rows, indent=2))
" > /home/tim/github/mithro/go-netgear-switch-library/.claude/worktrees/capabilities-oracle/capabilities/testdata/python_matrix_a9e0ebc.json
```

Then **immediately** clean up the build artifacts `uv run` leaves in the pinned (read-only) worktree — verified necessary: running this DOES modify `uv.lock` and creates a `.venv/` there:

```bash
cd /home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-a9e0ebc && \
git checkout -- uv.lock && rm -rf .venv && git status --short
```

The last command must print nothing (clean tree) before proceeding. Confirmed by direct execution during this plan's research: 525 rows, `Counter({'supported': 381, 'unsupported': 144})`, zero `unverified` (every shipped spec is currently verified — matches Python's own `test_unverified_backend_gates_off` comment "Every shipped spec is currently verified"). If your count differs, STOP: either Task 1 wasn't applied to the Go side yet (525 depends on `gsm7228ps` having 3 backends, not 4) or the pin has moved (re-pin per project policy, and rename the fixture file to the new hash) — do not silently reconcile a mismatch by editing the fixture by hand.

- [ ] **Step 2: Write the failing test.** Create `capabilities/matrix_parity_test.go`:

```go
package capabilities

// matrix_parity_test.go: the capstone faithfulness gate. Pins Matrix(nil,
// nil)'s verdicts against a golden fixture generated directly from the
// pinned Python capabilities.py (go-port-pin-a9e0ebc's matrix()) -- see
// testdata/python_matrix_a9e0ebc.json's own generation command, recorded in
// this repo's implementation plan (docs/superpowers/plans/
// 2026-08-13-capabilities-oracle.md, Task 10).
//
// Deliberately does NOT compare reason text byte-for-byte -- this plan's
// Global Constraints document why (Go and Python's reason prose has already
// diverged in confirmed, legitimate ways, e.g. nsdpSweepEvidence's wording).
// What this DOES pin, per (model_key, backend, operation) triple: the
// Support verdict itself, and whether a reason is present at all.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

type pythonMatrixRow struct {
	ModelKey       string `json:"model_key"`
	Backend        string `json:"backend"`
	Operation      string `json:"operation"`
	Support        string `json:"support"`
	ReasonNonEmpty bool   `json:"reason_nonempty"`
}

func loadPythonMatrixFixture(t *testing.T) []pythonMatrixRow {
	t.Helper()
	data, err := os.ReadFile("testdata/python_matrix_a9e0ebc.json")
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	var rows []pythonMatrixRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("parsing golden fixture: %v", err)
	}
	return rows
}

func TestGoMatrixMatchesPinnedPythonMatrix(t *testing.T) {
	pythonRows := loadPythonMatrixFixture(t)

	goCaps, err := Matrix(nil, nil)
	if err != nil {
		t.Fatalf("Matrix(nil, nil): %v", err)
	}
	if len(goCaps) != len(pythonRows) {
		t.Fatalf("len(Matrix()) = %d, want %d (pinned Python row count) -- "+
			"if this is exactly 21 off, check model/registry.go's per-model "+
			"backend counts against the pinned registry.py first",
			len(goCaps), len(pythonRows))
	}

	type key struct{ modelKey, backend, operation string }
	byKey := make(map[key]pythonMatrixRow, len(pythonRows))
	for _, r := range pythonRows {
		byKey[key{r.ModelKey, r.Backend, r.Operation}] = r
	}

	seen := make(map[key]bool, len(goCaps))
	for _, c := range goCaps {
		k := key{c.ModelKey, string(c.Backend), c.Operation.Name}
		want, ok := byKey[k]
		if !ok {
			t.Errorf("Go Matrix() has row %s/%s/%s with no counterpart in the pinned Python fixture",
				c.ModelKey, c.Backend, c.Operation.Name)
			continue
		}
		seen[k] = true
		if string(c.Support) != want.Support {
			t.Errorf("%s/%s/%s: Go Support = %q, pinned Python Support = %q",
				c.ModelKey, c.Backend, c.Operation.Name, c.Support, want.Support)
		}
		if (c.Reason != "") != want.ReasonNonEmpty {
			t.Errorf("%s/%s/%s: Go reason-non-empty = %v, pinned Python reason-non-empty = %v",
				c.ModelKey, c.Backend, c.Operation.Name, c.Reason != "", want.ReasonNonEmpty)
		}
	}
	for k := range byKey {
		if !seen[k] {
			t.Errorf("pinned Python fixture has row %s/%s/%s with no counterpart in Go Matrix()",
				k.modelKey, k.backend, k.operation)
		}
	}
}

var _ = model.BackendSNMP // keep model imported if the above changes shrink
```

- [ ] **Step 3: Run, verify it fails** (the fixture file doesn't exist yet until Step 1 is actually run against the live pinned worktree — if you've already done Step 1, this instead verifies the file loads and, before Task 1-9's code is otherwise broken, should already PASS; if it fails here on a fresh implementation, treat any mismatch as a real bug to chase down via `systematic-debugging`, not a fixture to hand-edit):

```
./scripts/jail.sh go test ./capabilities/... -run TestGoMatrixMatchesPinnedPythonMatrix -v
```

- [ ] **Step 4: If it fails, debug — do not adjust the fixture to match.** The fixture is generated mechanically from the pinned Python source (Step 1); it is the parity target, not a free variable. A mismatch means either: (a) a Task 1–8 branch has a real bug (wrong verdict for some triple), or (b) the fixture generation command in Step 1 was run before Task 1's registry fix landed (regenerate it). Use the failing test's exact `model_key/backend/operation` output to find the offending branch in `capabilities/support_*.go`.

- [ ] **Step 5: Once green, run the full gate + coverage.**

```
make fmt-check && ./scripts/jail.sh go vet ./... && make lint && ./scripts/jail.sh go test -race ./... && ./scripts/jail.sh go test -race -coverprofile=coverage.out ./... && ./scripts/jail.sh go run ./scripts/coveragegate -profile coverage.out -min 90
```

- [ ] **Step 6: Commit.**

```bash
git add capabilities/testdata/python_matrix_a9e0ebc.json capabilities/matrix_parity_test.go
git commit -m "$(cat <<'EOF'
test(capabilities): golden-fixture cross-check against pinned Python matrix()

Generates capabilities/testdata/python_matrix_a9e0ebc.json directly from the
pinned python-netgear-switch-library worktree (go-port-pin-a9e0ebc)'s own
capabilities.matrix() -- 525 rows, 381 supported / 144 unsupported / 0
unverified. Pins Go Matrix(nil, nil)'s verdict per (model, backend,
operation) triple against it: Support value exact match, reason-presence
exact match. Deliberately does not compare reason TEXT byte-for-byte (this
repo's plan documents confirmed, legitimate divergent phrasing) -- this is
the capstone faithfulness gate the whole capabilities port exists to satisfy.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**1. Spec coverage.**

- Port dossier §2 (public API surface) — covered: `Support`/`OperationKind`/`Operation`/`Capability`/`Operations`/`ReadOperations`/`WriteOperations`/`OperationByName` (Task 3), `For`/`BackendsFor`/`Matrix`/`ForKey` (Task 8), the `__init__.py` re-export asymmetry (Task 9).
- Port dossier §3–§4 (the data model, every branch of `support()`) — covered: SNMP (Task 4), NSDP (Task 5, including the R1 create/delete-VLAN correction), HTTP (Task 6, including the cert-upload fold), CLI (Task 7), top-level dispatch/NO_BACKEND/CONSOLE/backend-fixed ops (Task 8).
- Port dossier §5 (13 Python tests) — every one has a named Go counterpart: `test_reads_match_reality`/`test_writes_match_reality` are explicitly NOT ported as a virtual-switch-driven test (R5: that is a materially larger prerequisite than this plan's scope; the golden-fixture cross-check in Task 10 is the chosen, explicitly-justified substitute faithfulness gate) — all 11 others map onto Tasks 3–9's tests directly (traced in each task's test file's own header comment).
- Port dossier §6 (consumption — docs generation, nothing in the real dispatch path) — the plan does not wire `capabilities` into `dispatch.go`/`write_dispatch.go`; this matches Python exactly (§6: "Nothing in the facade, readers, writers, CLI, or MCP server imports or calls this module"). Not a gap.
- Port dossier §7 (Go mapping proposal) — package placement (§7.1), type shapes (§7.2), the `support`/`Support` naming collision (§7.2, resolved as `For`), `ErrKnownUnimplemented` folding (§7.3, Task 6), all divergences (§7.4) — all addressed and cross-referenced from Global Constraints' "Deliberate divergences" list.
- Port dossier §8 risks — R1 (resolved, confirmed obsolete), R2 (resolved, confirmed obsolete), R3 (resolved, Task 2, decision: export), R4 (not blocking, noted, out of scope — no `capabilities.py` branch reads `snmp_vlan_write`/`snmp_vlan_split_membership_writes`), R5 (explicitly acknowledged as a weaker-but-justified substitute, Task 10), R6 (resolved, Task 6's explicit non-invention of a 5th `Support` value, pinned by test).
- Controller's "AUTHORITATIVE CORRECTIONS" block — all four items addressed explicitly (NSDP VLAN lifecycle = SUPPORTED confirmed in Task 5; CLI/SSH/Telnet ported faithfully in Task 7; NSDP constant-export decision made and justified in Task 2; cert-upload fold explicitly non-invented in Task 6).
- Controller's five design principles — each named verbatim in Global Constraints, each task's PR-facing commit message ties back to at least one where relevant (Task 1 -> principle 5; Task 2/5 -> principle 2; Task 3 -> principle 3, exercised by Task 8's `model.Models()`-driven tests).
- CI gates — every task's commit step runs `fmt-check`, `vet`, `lint`, `test -race`; Task 10 additionally runs `cover` (the coverage gate need only be checked once the whole package exists, but nothing prevents running it earlier too).
- New finding (gsm7228ps SSH bug) — fully scoped as Task 1, with its ripple (registry_test.go, facade_cli_integration_test.go, one stale comment) enumerated and fixed, not left as a TODO.

**2. Placeholder scan.** Searched this plan for "TBD"/"TODO"/"similar to Task N"/"add error handling" — none found. Every task's implementation step is complete, runnable Go code (verified for import correctness against this worktree's actual exported identifiers — `webui.HTTPSpec`, `webui.CertUploadKnownUnimplemented`, `fastpath.CLISpec`, `fastpath.ScpProfile`, `snmp.HasVendorOids`, `model.Models`/`GetModel`/`HasBackend`/`HasMACTable` — all confirmed to exist with these exact signatures by direct inspection of this worktree during this plan's research, not assumed from the dossier alone).

**3. Type consistency.** Traced every signature end to end:
- `Operation` (Task 3) -> consumed identically by `snmpSupport`/`nsdpSupport`/`httpSupport`/`cliSupport` (Tasks 4–7) -> `For`/`Matrix` (Task 8) -> `capabilities.Operations`/`OperationByName` (Task 9's facade test) -> `Matrix(nil, nil)` (Task 10). No signature drift.
- `Capability{ModelKey, Backend, Operation, Support, Reason}` field names used identically in every task that constructs or reads one (Tasks 3, 8, 9, 10).
- `httpSupport(m, spec, op)`'s three-argument shape (Task 6) is the exact shape `For`'s HTTP branch calls it with (Task 8) — checked, no accidental two-argument call anywhere.
- `cliReadsSupported`/`cliWritesSupported` (Task 7) return shapes match their only caller, `cliSupport` in the same file/task — no cross-task drift possible since both are defined together.
- `BackendsFor`/`For`/`ForKey`/`Matrix` (Task 8) re-exported in Task 9 with IDENTICAL parameter/return types (`*model.SwitchModel`, `model.Backend`, `capabilities.Operation`, `[]string`) — no silent type-narrowing at the alias boundary.
