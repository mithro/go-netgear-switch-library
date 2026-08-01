# Slice 07 — FASTPATH CLI backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Python FASTPATH device-CLI protocol backend (SSH/Telnet/Serial) to an idiomatic Go `fastpath` package with a byte-faithful fake that serves the CLI over BOTH an in-process interface AND real loopback SSH + Telnet listeners, wired into the facade as a first-class backend.

**Architecture:** New Go package `fastpath/` (command specs, output parsers, session state machine, three transports, reader, writer, SCP cert deploy). New `virtual/cliface.go` (in-process command dispatcher — the byte-accurate ground truth) plus `virtual/sshface.go` + `virtual/telnetface.go` (real loopback listeners wrapping the dispatcher). Root-package `backend_cli.go` shim + `switch.go` wiring add CLI to the single-backend dispatch. No fallback (principle 1).

**Tech Stack:** Go 1.26; `golang.org/x/crypto/ssh` (client, legacy `diffie-hellman-group14-sha1` KEX + `ssh-rsa` host keys); `github.com/gliderlabs/ssh` (fake SSH server); `github.com/ziutek/telnet` (client; fallback hand-rolled IAC if it misbehaves); `go.bug.st/serial` (115200 8N1); `regexp`/`bufio`/`strings` for parsers.

## Source of truth (REQUIRED READING for every task)

- **Pin snapshot (read-only):** `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-7ebfe5d`. Implementers read the SNAPSHOT, never the live checkout.
- **Protocol dossier:** `docs/superpowers/plans/2026-08-01-slice-07-dossier-cli-protocol.md` — every command string, every parser regex (verbatim), the op×model matrix, write-safety guards. Section numbers (§1.x/§2.x/§3.x/§4.x/§5/§6) are cited per task; the dossier quotes the exact values — use them verbatim.
- **Transport+fake dossier:** `docs/superpowers/plans/2026-08-01-slice-07-dossier-cli-transport-fake.md` — session state machine, per-transport specifics, the in-process fake, facade wiring, and the `[NEW DESIGN]` real-listener decisions (§7.7).

The dossiers are the verbatim quote source; this plan gives structure, interfaces, tests, and the Go-specific hazards. When a task says "per dossier §X", the exact strings/regexes/line numbers are there and in the pin — copy them exactly, do not paraphrase.

## Global Constraints

- **Package name `fastpath`** (NOT `cli` — that name belongs to the future `gngsw` tool in `cmd/gngsw/`, slice 08).
- **Five design principles bind** (see spec §1.2): (1) fail fast, NEVER switch backend mid-op — CLI adds to single-backend dispatch with NO fallback; (2) feature parity — a missing op is built, not assumed a device limit, UNLESS the pin quotes live device evidence (m4300-24x PoE, gsm7228ps SCP — preserve these as real gates with the quoted justification); (3) every model per-SKU; (4) a failure is yours to debug; (5) the fake seeds MEASURED values and must match hardware.
- **No functional CLI drift in the re-pin:** the `1841111→7ebfe5d` `parse.py` change (commit `e56fc34`) is docstring reST only; `commands.py`/`cli_read.py`/`cli_write.py` are byte-identical across the range (protocol dossier §7). There is nothing functional to reconcile — port the `7ebfe5d` state.
- **Error sentinels (spec error table):** reuse the existing `model` sentinels — `ErrUnsupportedCapability` (op the model genuinely lacks over CLI, with pin's quoted device evidence), `ErrKnownUnimplemented` (NotImplementedError analogue), `ErrProtectedPort`, `ErrCredential`, `*WriteVerificationError{Before,After}`. Do NOT invent new umbrella errors.
- **Verify-after-write everywhere** a write op has a read-back (mirror the SNMP/NSDP/HTTP writers already merged).
- **Leak-free `Stop()`** for the real listeners — mirror the deterministic, goroutine-leak-free Stop discipline of the existing `virtual` SNMP/HTTP/NSDP faces (transport dossier §5). The Go facade `Close()` MUST close cached CLI sessions — the Python `SyncSwitch.close()` does NOT (a real socket leak, transport dossier §0/§4.3); deliberately do not reproduce that bug.
- **Coverage gate:** library-only aggregate ≥ 90% (the repo `coveragegate`); run all tests through `scripts/jail.sh` (CPU/mem jail). `make fmt-check vet test cover` must pass.
- **Commit trailers** on every commit:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01HchhGh659AVsp7J4yyidLc`

---

### Task 1: `fastpath` package skeleton + `CliModelSpec` command specs

**Files:**
- Create: `fastpath/spec.go`
- Test: `fastpath/spec_test.go`

**Interfaces:**
- Produces: `CliModelSpec` struct (all fields per protocol dossier §1.2), its templating methods (`§1.3`: interface-address/`iface`, enable/paging/show-command templating), `CLIBackends` map (`§1.1`), `M4300Overrides` (`§1.5`), the 4 `CliModelSpec` instances (`§1.6`, EXHAUSTIVE — gsm7252ps, gsm7228ps, m4300-24x, s3300 per dossier), `ScpCertProfile` (`§1.7`), and dispatch funcs (`§1.8`). `iface(port)` per-model uplink addressing (split at `first_uplink_port`, e.g. gsm7228ps `1/g{port}` vs `1/xg{port}` at 49).
- Consumes: `model` package types (model IDs, PoE flags, port-count/first-uplink-port fields on the registry).

**Hazard:** `iface()` branch condition is `port >= first_uplink_port` — getting it wrong silently addresses the wrong physical interface (protocol dossier risk #3). Pin exact values from §1.6.

- [ ] **Step 1: Write failing tests** asserting: each of the 4 model specs produces the exact command strings from dossier §1.6 for a representative op; `iface()` returns the uplink-form template exactly at/after `first_uplink_port` and access-form below it for gsm7228ps and s3300; `M4300Overrides` replaces exactly the keys listed in §1.5.
- [ ] **Step 2: Run tests, verify they fail** (`scripts/jail.sh go test ./fastpath/ -run TestCliModelSpec -v`).
- [ ] **Step 3: Implement `spec.go`** transcribing §1.1–1.8 verbatim from the dossier + pin `protocols/cli/commands.py`.
- [ ] **Step 4: Run tests, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): CliModelSpec command specs for 4 CLI models`).

### Task 2: `parse.go` primitives (ruler/table engine) — the Go-slicing hazard

**Files:**
- Create: `fastpath/parse.go` (primitives only this task)
- Test: `fastpath/parse_primitives_test.go`

**Interfaces:**
- Produces: the primitive regexes (§2.1, verbatim), `labelledValues` (§2.2), `rulerSpans` (§2.3), `sliceCell`/`sliceRow` (§2.4), `iterTableRows` (§2.5), `headerColumns` (§2.6), `parseInt` (§2.7), `physPort` (§2.8).
- Consumes: nothing outside stdlib.

**Hazard (protocol dossier risk #2 — HIGHEST):** Python `row[start:end]` silently CLAMPS when the row is shorter than the ruler (blank Physical Status on a down port, bare LLDP rows). Go slicing `row[start:end]` PANICS on the same input. `sliceCell` MUST clamp `start`/`end` to `len(row)` (and handle `end==nil` → to end-of-row) to reproduce Python exactly. Test this explicitly with a short row.

- [ ] **Step 1: Write failing tests** including a ruler wider than a data row (assert `sliceCell` returns the clamped/empty substring, NOT a panic), a `headerColumns` case, and a `physPort` case for each model's iface form.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §2.1–2.8; clamp in `sliceCell`.
- [ ] **Step 4: Run, verify pass** (include a `-race` run).
- [ ] **Step 5: Commit** (`feat(fastpath): parse primitives with clamp-safe cell slicing`).

### Task 3: `parse.go` entity parsers, part 1 (version/ports/vlans/pvids)

**Files:** Modify `fastpath/parse.go`; Test: `fastpath/parse_entities1_test.go`
**Interfaces:** Produces `parseVersion` (§2.9), `parsePortStatus` (§2.10), `parseVLANBrief` (§2.11), `parseVLANDetail` (§2.12), `parsePVIDs` (§2.13) → `model` types (`DetectedModel`, `PortStatus`, `VLANInfo`, PVID pairs).

- [ ] **Step 1: Failing tests** using captured fixtures from the pin's CLI test data (copy the exact `show` outputs the pin's `tests/` use for these parsers into `fastpath/testdata/cli/` with a provenance README) — assert parsed structs field-for-field.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §2.9–2.13 verbatim.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): version/port/vlan/pvid parsers`).

### Task 4: `parse.go` entity parsers, part 2 (mac/lldp/poe/env/mgmt/counters)

**Files:** Modify `fastpath/parse.go`; Test: `fastpath/parse_entities2_test.go`
**Interfaces:** Produces `parseMacTable` (§2.14), `parseLLDP` (§2.15), `parsePoE` (§2.16), `parseEnvironment` (§2.17), `parseMgmtIP` (§2.18), `parseInterfaceCounters` (§2.19).

**Hazard (protocol dossier risk #1):** `parsePoE` looks up columns BY HEADER NAME, not fixed index — M4300 firmware omits the `Temperature` column gsm7252ps prints. Do NOT hardcode column indices; resolve via `headerColumns`. Test with both a gsm7252ps-shaped and an M4300-shaped PoE table.

- [ ] **Step 1: Failing tests** with pin fixtures for all 6 parsers, incl. the M4300-vs-gsm7252ps PoE column-count divergence and a down-port LLDP row with no neighbour (exercises the Task-2 clamp).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §2.14–2.19; header-name column resolution in `parsePoE`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): mac/lldp/poe/env/mgmt/counter parsers`).

### Task 5: `session.go` — shared shell driver state machine

**Files:** Create `fastpath/session.go`; Test: `fastpath/session_test.go`
**Interfaces:**
- Produces: `Session` interface (transport dossier §1.2 `CliSession` protocol — `Run(cmd) (string,error)`, setup/close), `ShellDriver` (§1.3 state machine: connect→auth→enable→`terminal length 0`→per-command send/read-until-prompt→close), the sentinels (§1.1, verbatim), `inMode` counted-unwind helper and `run` reject convention.
- Consumes: an abstract byte transport (io.ReadWriteCloser + prompt config) so ssh/telnet/serial plug in.

**Hazard (protocol dossier risk #5):** `inMode` must unwind exactly the levels ACTUALLY entered (post-success), not `len(enter)`; the unwind uses the RAW session write (errors discarded), never the wrapped `run` (which would mask the real failure). `run`'s convention: any non-empty output = command rejected → error. A wrong unwind strands the shared session in a nested config prompt and corrupts every later read. Test the partial-failure unwind with a fake transport.

- [ ] **Step 1: Failing tests** with an in-memory scripted transport: prompt-matching (`_PROMPT_RE` end-anchor `)...[#>]$`), read-until-prompt framing, `inMode` enter/partial-fail/unwind count, `run` non-empty→reject.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per transport dossier §1.
- [ ] **Step 4: Run, verify pass** (`-race`).
- [ ] **Step 5: Commit** (`feat(fastpath): shell-driver session state machine`).

### Task 6: `ssh.go` — SSH transport (legacy-firmware compatible)

**Files:** Create `fastpath/ssh.go`; Test: `fastpath/ssh_test.go` (against a gliderlabs/ssh test server, or defer live parts to the Task 14 capstone)
**Interfaces:** Produces `NewSSHTransport(cfg)` returning the byte transport `ShellDriver` consumes; opens a shell channel with PTY.

**Hazards (transport dossier §2.1):** paramiko uses `Transport` directly with ZERO host-key verification → Go client MUST use `ssh.InsecureIgnoreHostKey()`. Old FASTPATH firmware needs legacy algorithms explicitly enabled: `ssh.Config{KeyExchanges: [...,"diffie-hellman-group14-sha1"]}`, `HostKeyAlgorithms: [...,"ssh-rsa"]`. Password auth. Request PTY + shell (not exec).

- [ ] **Step 1: Failing test** — connect to an in-test `gliderlabs/ssh` server that only accepts the legacy KEX and a known password; assert a command round-trips through `ShellDriver`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** with the legacy `ssh.Config` + `InsecureIgnoreHostKey`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): x/crypto/ssh transport with legacy kex/hostkey`).

### Task 7: `telnet.go` + `serial.go` — Telnet and Serial transports

**Files:** Create `fastpath/telnet.go`, `fastpath/serial.go`; Test: `fastpath/telnet_test.go` (scripted listener), `serial.go` compile+unit only (no loopback serial in CI).
**Interfaces:** Produces `NewTelnetTransport(cfg)`, `NewSerialTransport(cfg)` — both yield the byte transport for `ShellDriver`. Telnet handles the `User:`/`Password:` login the shared `setup()` doesn't cover (transport dossier §2.2); refuse-everything IAC posture (match `telnetlib` default). Serial: 115200 8N1, prod-the-console then answer `User:`/`Password:` (§2.3).

**Hazard:** `telnetlib`'s two-tier eager/blocking read (`read_eager() or read_some()`) and default refuse-all IAC negotiation have no Go stdlib equivalent — use `ziutek/telnet`, and if it mishandles the FASTPATH negotiation, hand-roll ~100 lines of IAC (spec line 235). Document which path was taken.

- [ ] **Step 1: Failing tests** — a scripted telnet listener that sends `User:`/`Password:` then a prompt; assert login + command round-trip. Serial: unit-test the config/framing (baud 115200, 8N1) without a real port.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** both.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): telnet + serial transports`).

### Task 8: `reader.go` — `CliReader`, 10 read ops

**Files:** Create `fastpath/reader.go`; Test: `fastpath/reader_test.go`
**Interfaces:** Produces `Reader` with the 10 ops (protocol dossier §3.1–3.11: GetPorts, GetStats, GetVLANs, GetPVIDs, GetMACs, GetLLDP, GetPoE, GetSensors, GetMgmtIP, Identify), each wiring its command(s) (Task 1 spec) → session (Task 5) → parser (Tasks 3-4). Method names match the merged SNMP/NSDP/HTTP readers (GetVLANs/GetPVIDs/GetLLDP/GetMACs/GetPoE casing).

- [ ] **Step 1: Failing tests** driving `Reader` against a scripted `Session` returning pin fixture outputs; assert each op returns the right parsed data and issues the right command sequence.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §3.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): CliReader with 10 read ops`).

### Task 9: `writer.go` — VLAN + PVID writes, shared helpers, switchport-mode gate

**Files:** Create `fastpath/writer.go`; Test: `fastpath/writer_vlan_test.go`
**Interfaces:** Produces `Writer` shared helpers (§4.1: `inMode` use, verify-after-write), `CreateVLAN` (§4.2), `DeleteVLAN` (§4.3), `SetVLANMembership` (§4.4), `SetPVID` (§4.5). All take a `force` option mirroring the merged writers' `Write{Force}`.

**Hazard (fake §3, cli_write live finding):** per-port VLAN writes are INERT in `switchport mode access` — `switchport mode general` is a MANDATORY step of every per-port CLI VLAN write. Encode it; the fake (Task 11) enforces it, so a missing step will fail the round-trip.

- [ ] **Step 1: Failing tests** — round-trip each op against a scripted session; assert the `switchport mode general` step precedes `vlan participation`/`pvid`; assert verify-after-write reads back.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §4.1–4.5.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): CliWriter VLAN/PVID with switchport-mode gate`).

### Task 10: `writer.go` — PoE, port, mgmt-IP, reboot, SCP cert; op×model gates

**Files:** Modify `fastpath/writer.go`; Create `fastpath/cert_scp.go`; Test: `fastpath/writer_rest_test.go`
**Interfaces:** Produces `SetPoE`/`CyclePoE`/`ClearPoEFault` (§4.6), `SetPortEnabled` (§4.7), `SetMgmtIP` (§4.8), `Reboot` (§4.9), `DeployCertificateSCP` (§4.10 module func). Op×model matrix + write-safety guards (§5, §6).

**Hazard (protocol dossier risk #4 — principle 2/4):** m4300-24x PoE ops (`get/set/cycle/clear_poe`) and gsm7228ps SCP cert are GENUINELY device-limited with LIVE-QUOTED evidence in the pin (`poe_port_count==0`, `"poe ?"`→`"% Unrecognized command"`; gsm7228ps uses HTTP-multipart cert upload, not SCP). These MUST return `ErrUnsupportedCapability` wrapping the quoted device justification — they are real hardware gates, NOT gaps to build. Do NOT paper over; do NOT fake them supported.

- [ ] **Step 1: Failing tests** — each op round-trips on a supporting model; m4300-24x PoE and gsm7228ps SCP return `ErrUnsupportedCapability` with the device-evidence message; write-safety guards (protected/uplink port, link-state, force) reject/allow exactly per §6.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §4.6–4.11, §5, §6.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(fastpath): PoE/port/mgmt/reboot/SCP writes with device-limit gates`).

### Task 11: `virtual/cliface.go` — in-process byte-accurate fake dispatcher

**Files:** Create `virtual/cliface.go`; Test: `virtual/cliface_test.go`
**Interfaces:** Produces an in-process `CliSession` implementation (transport dossier §3): command regexes (§3.2 verbatim), mode stack (§3.3), config-mode commands (§3.4), the FULL literal output set (§3.5), model-gating predicates (§3.6), `interface`/`vlan database` command dispatch (§3.7/§3.8) mutating `VirtualSwitchState`, SCP stand-in (§3.9). Reads project through the SAME state as SNMP/NSDP/HTTP faces (a CLI write is visible over every protocol).

**Contracts (fake §3.1, correctness-critical):** accepted config command → EMPTY output; rejected → text. `vlan participation`/`tagging`/`pvid` accepted but INERT in `switchport mode access` (the live finding — a mock that applied them in access mode would hide the exact bug the finding prevents).

- [ ] **Step 1: Failing tests** — drive the in-process face with `fastpath.Reader`/`Writer` (real code from Tasks 8-10) against a seeded `VirtualSwitch`; assert read-back and cross-protocol visibility (CLI SetPVID visible via SNMP oid_map projection); assert access-mode inertness.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per §3.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(virtual): in-process FASTPATH CLI fake dispatcher`).

### Task 12: `virtual/sshface.go` + `virtual/telnetface.go` — real loopback listeners

**Files:** Create `virtual/sshface.go`, `virtual/telnetface.go`; Test: `virtual/cli_listeners_test.go`
**Interfaces:** Produces real loopback SSH (`gliderlabs/ssh`) and Telnet listeners that wrap the Task-11 in-process dispatcher, serving the FASTPATH shell over a socket (spec line 204; transport dossier §7.7 — `[NEW DESIGN]`, no Python ground truth, so match REAL DEVICE behavior: prompt `(manage-sw-netgear-s3300-1) >` style per registry.py:202-203, `User:`/`Password:` telnet login, accept the seeded username/password, legacy-friendly SSH server config so the Task-6 client connects).

**Contract:** leak-free deterministic `Stop()` (transport dossier §5) — per-connection goroutines drain and close; `Stop()` returns only after all are gone; a 10-connection open/close test shows zero leaked goroutines (mirror the HTTP face's leak test).

- [ ] **Step 1: Failing tests** — start the SSH listener, connect with the REAL `fastpath` SSH client (Task 6), round-trip a command; same for telnet (Task 7); a leak test (N connect/disconnect cycles, goroutine count stable).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** both listeners over the shared dispatcher.
- [ ] **Step 4: Run, verify pass** (`-race`).
- [ ] **Step 5: Commit** (`feat(virtual): real loopback SSH + telnet CLI listeners`).

### Task 13: Facade wiring — CLI backend registration + no-fallback dispatch

**Files:** Create root `backend_cli.go`; Modify `switch.go`, `registry`/dispatch shims as needed; Test: `backend_cli_test.go`
**Interfaces:** Produces the CLI backend shim mirroring `backend_http.go`/`backend_nsdp.go`: registers a CLI reader+writer builder, a lazily-built CLI session (transport dossier §4.3), an independent `cliPassword` resolveOnce cell + `WithCLIPassword`/`WithSSHPassword` options, backend preference order `SNMP→NSDP→HTTP→SSH` (spec §2.1 / dossier §4.3), cert-deploy wiring, and `Close()` that closes the built CLI session (fixing the Python leak). CLI added to `resolveBackend`; NO fallback (principle 1).

- [ ] **Step 1: Failing tests** — explicit `WithBackend(CLI)` routes reads/writes through the CLI reader/writer; a principle-1 spy test proves selecting CLI never invokes the SNMP/HTTP builder; `Close()` closes the CLI session (no leak); unsupported CLI op returns `ErrUnsupportedCapability`, not a credential error.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the shim + wiring.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat: wire FASTPATH CLI as a no-fallback facade backend`).

### Task 14: Capstone — CLI round-trip over in-process AND real SSH/telnet; op matrix

**Files:** Create `facade_cli_integration_test.go`; Test: same
**Interfaces:** Consumes everything. Proves the whole stack end-to-end.

- [ ] **Step 1: Write the capstone** — for each of the 4 CLI models: drive `fastpath.Reader`/`Writer` through the facade against the fake over (a) the in-process session, AND (b) the real loopback SSH listener, AND (c) the real telnet listener; assert identical parsed results across all three paths. Pin exact per-model op-matrix outcomes (supported ops succeed; m4300-24x PoE + gsm7228ps SCP return `ErrUnsupportedCapability`). Include a principle-1 no-fallback proof for CLI and a cross-protocol visibility check (a CLI write is visible via SNMP).
- [ ] **Step 2: Run** (`scripts/jail.sh go test ./... -race -run CLI`), verify pass.
- [ ] **Step 3: Full gates** — `make fmt-check vet test cover`; confirm aggregate ≥ 90%.
- [ ] **Step 4: Commit** (`test: FASTPATH CLI capstone across in-process + real SSH/telnet`).

---

## Self-review notes
- **Spec coverage:** commands (T1), all ~19 parsers (T2-4), session/transports (T5-7), reader (T8), writer incl. cert (T9-10), fake in-process (T11) + real listeners (T12), facade (T13), capstone (T14). Op×model matrix and write-safety appear in T10 (writes) and T8 (reads).
- **Deferred to slice 10 (cross-language):** wiring the Go fake's real listeners into the Python-lib-vs-Go-fake suite, AND the reverse asymmetry — the Python fake CLI has no socket (in-process only, cli.py:1-11), so "Go-lib-vs-Python-fake over CLI" needs a Python-side socket shim OR a documented one-directional conformance. Ledger this for slice 10; it is NOT slice-07 scope.
- **Type consistency:** read-op method names reuse the merged casing (GetVLANs/GetPVIDs/GetLLDP/GetMACs/GetPoE); write ops mirror the `Write{Force,Backend}` option shape from the SNMP/HTTP writers.
