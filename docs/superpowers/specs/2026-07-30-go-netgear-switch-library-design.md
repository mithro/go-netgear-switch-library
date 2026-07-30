# Go Netgear Switch Library — Design Spec

**Date:** 2026-07-30
**Status:** Approved (design), pending spec review
**Module:** `github.com/mithro/go-netgear-switch-library` · root package `netgearswitch`
**Binaries:** `gngsw`, `gngsw-mcp`, `gngsw-virtual`
**License:** Apache-2.0 · **Go:** ≥ 1.26 (Debian sid apt toolchain)
**Repo:** public GitHub repo `mithro/go-netgear-switch-library`

## 1. Purpose

A Go reimplementation of `python-netgear-switch-library` with 100% capability
parity: query and control Netgear switches over SNMP, NSDP, HTTP web-UI and
FASTPATH CLI (SSH/telnet/serial) behind one model-driven API, the same
command-line tool surface, an MCP server, and a complete reimplementation of
the virtual-switch testing fakes. The two implementations are tested **against
each other's fakes** in both directions, and against real hardware.

### 1.1 Reference implementation (normative)

The Python library is the behavioural reference:

- Repo: `/home/tim/github/mithro/python-netgear-switch-library`
  (`github.com/mithro/python-netgear-switch-library`)
- **Pinned reference:** branch `fix/s3300-52x-live-verify` @
  `1aa1274254a233ddce0409160849bb6ce8f8b2e7` (2026-07-30), frozen as a
  detached read-only snapshot worktree at
  `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274`
  — **implementers read the snapshot path, never the live checkout**, which
  the user actively develops (it moved twice mid-session; earlier pins:
  `b73e7519` fix/live-hardware-parity, then `aaab577`). The branch carries
  live-verified improvements the Go port must match (real S3300-52X capture
  + reseeded gsm7228ps with `verified=True`, `SYSOBJECTID_MODELS`
  authoritative sysObjectID detection tried before sysDescr,
  `MODEL_ALIASES` s3300→gsm7228ps, S3300-52X XE_FASTPATH HTTP captures).
  Slice 1's registry matches this state. Re-pin deliberately at slice
  boundaries (new snapshot worktree + doc update); parity claims are always
  against the pin.

Where this spec says "same as Python", the pinned source is normative. Protocol
constants (OID tables, NSDP tags/sizes, HTTP endpoints/login schemes/dialects,
FASTPATH command sets and parsers, registry entries, seed data) are ported
1:1 from the pinned files rather than re-derived; the cross-test matrix (§10)
is what proves the port faithful.

## 2. Parity contract

### 2.1 Identical capabilities

- **Models (10):** m4300-24x, m4300-16x, gsm7252ps, gsm7228ps, gs110emx,
  gs305ep, gs105pe, gs728tpp, m7300, xs748t — same port counts, PoE counts,
  backend sets, vendor OID bases, and honesty flags (`Verified`,
  `SchemeVerified`, `ReadsVerified`, `Captured`) as the Python registry.
- **Read ops:** ports, stats, VLANs, PVIDs, LLDP, MACs (managed only), PoE,
  sensors, mgmt-IP, snapshot, identify (SNMP model detection), NSDP device.
- **Write ops:** PoE on/off/cycle/clear-fault, port enable/disable, PVID,
  VLAN membership (untagged/tagged/excluded), VLAN create/delete, mgmt-IP
  (force-gated), certificate upload (HTTP multipart + GoAhead XML), certificate
  deploy via SCP+FASTPATH.
- **Semantics carried over exactly:** backend preference SNMP→NSDP→HTTP→SSH
  with UnsupportedCapability skip-and-re-raise-last; CredentialError never
  swallowed; reader/writer caching; lazy once-only secret resolution; lazy
  HTTP/CLI sessions (unsupported ops must not raise credential errors);
  `Snapshot` degrades unsupported fields to empty instead of failing;
  `Identify`/`NSDPDevice` bypass dispatch; facade-level protected-port guard on
  VLAN delete; cert upload on m4300-24x/-16x/gsm7252ps fails with a
  "known-unimplemented, use SCP" error distinct from UnsupportedCapability;
  verify-after-write everywhere; the PoE cycle/clear-fault state machine
  (off → poll ≤30 s → on → poll ≤60 s, 2 s interval, injectable clock); VLAN
  bitmap read-modify-write with atomic two-varbind SET; `dot1qPvid` SET as
  Gauge32; protected_ports refusing disruptive writes without force; the
  "honesty rules" (typed error at the earliest point, never fabricated data,
  UNVERIFIED paths gated).
- **CLI:** every `ngsw` subcommand, flag, table layout, JSON schema, prompt
  text, and exit code (0 ok / 1 error / 2 usage / 3 write-verification /
  4 protected-port). Target: **byte-identical stdout for identical device
  state** so CLI parity is machine-diffable (§10.4).
- **MCP:** same tool set, `NGSW_MCP_ALLOW_WRITES` write gating,
  `NGSW_INVENTORY` env var, `{"unsupported": true}` structured results.
- **Config:** the same inventory TOML schema — one config file shared between
  both libraries and CLIs — with literal / `${ENV_VAR}` / `!command` secret
  specs, 0600 enforcement for literal secrets, and the same resolution order
  (explicit flag → env var → config value → interactive prompt).
- **Capture:** `gngsw capture` emits the same snapshot JSON schema as
  `ngsw capture`, so captures are interchangeable.

### 2.2 Deliberate differences (Go-idiomatic, approved)

| Python | Go | Why |
|---|---|---|
| Dual `SyncSwitch`/`AsyncSwitch` + equivalence suite | Single `Switch`, every method takes `context.Context` | Goroutines make a second facade pointless; the independent-implementation check moves to cross-language testing (§10), which is stronger. |
| Two SNMP transports (net-snmp CLI subprocess + pysnmp) | One transport (gosnmp) | The two stacks existed to cross-check sync vs async. net-snmp CLI remains in play as a *test oracle* against the Go fake. |
| Exceptions | Typed error values for `errors.Is/As` | Sentinels `ErrUnsupportedCapability`, `ErrProtectedPort`, `ErrKnownUnimplemented` (the `NotImplementedError` analogue), `ErrCredential`, `ErrConfig`, `ErrUnknownModel`, `ErrSNMP`, `ErrNSDP`, `ErrHTTP` (with `ErrHTTPAuth`/`ErrHTTPUnexpectedPage` wrapping it); struct `*WriteVerificationError{Before, After}`. **Deliberately no analogue of the `NetgearSwitchError` root class**: Go error values don't carry tracebacks, so the CLI classifies via `errors.Is/As` for exit codes 3/4 and renders every other returned error as `error: <msg>` — behaviour parity without an umbrella sentinel. |
| `ngsw`, `ngsw-mcp` | `gngsw`, `gngsw-mcp` (+ `gngsw-virtual`); deb postinst symlinks `ngsw → gngsw` and `ngsw-mcp → gngsw-mcp` when those names are free, postrm removes only symlinks it owns | Coexistence on machines running both. |
| Virtual CLI face is in-process only | Go fake also serves FASTPATH over **real loopback SSH and telnet listeners** | Enables cross-language CLI-backend testing (Python paramiko → Go fake). An in-process interface remains for unit tests. |
| Rolling release, no tags | CI auto-tags `v0.N.0` per merge to main | Go modules resolve by tag; still zero manual bumps ("mergeable ⇒ released"). |
| `frozenset[int]` port sets | sorted `[]int` (canonical form) | Go has no set literal; canonical sorted slices keep `go-cmp` equality trivial. |
| mypy strict / ruff / pytest-cov | gofmt + go vet + golangci-lint + `-race` + coverage gate | Same "hard gates, local == CI, no skips/flakes" bar. |

Anything else that differs is a bug against this spec.

## 3. Architecture & package layout

Same two mirrored shapes as Python: the library is *protocol knowledge over one
device model*; the virtual switch is *protocol faces over one device state*.
Protocol knowledge stays pure (no sockets) and unit-testable on fixtures; I/O
lives in thin clients. Go's no-import-cycle rule forces one layout change:
shared data types live in a leaf package (`model`) that protocol packages
import; the root package re-exports them as type aliases so most users import
only the root.

```
go-netgear-switch-library/
  model/          Leaf package, imports nothing internal.
                  Types: PortStatus, PoEStatus, PoEDetect, VLANInfo, VlanMode,
                  LLDPNeighbor, MacEntry, Sensor, PortStats, MgmtIpConfig,
                  IpMode, SwitchData, DetectedModel.
                  Errors: the §2.2 sentinel/typed errors.
                  Registry: Backend, SwitchClass, SwitchModel, Models() /
                  GetModel(key) — all 10 entries + honesty flags.
  snmp/           oids.go (all OID constants, VendorOids for 4526.10/4526.11,
                  unimplemented-root logic), parse.go (row→model parsers incl.
                  M4300 ASCII-colon-hex base-MAC quirk, ifType filtering,
                  MSB-first bitmap decode), write.go (SetVarbind, type letters
                  i/u/s/x/a, bitmap RMW helpers, vlan_bitmap_width),
                  client.go (Client/WriteClient interfaces, Row, absent-type
                  handling), gosnmp.go (gosnmp-backed implementation, v2c,
                  host:port support, walk semantics identical to Python's),
                  reader.go / writer.go (model-driven ops, verify-after-write,
                  PoE cycle state machine with injectable clock/sleep).
  nsdp/           protocol.go (32-byte header codec, ops, all tag constants,
                  TLV framing, end-of-mark), types.go (NsdpDevice, LinkSpeed,
                  VLANEngine, ...), parse.go (strict-size parsers: 3-byte port
                  status, 49-byte statistics, variable-width mirroring, two-pass
                  device aggregation requiring MODEL), auth.go (v1 XOR with
                  "NtgrSmartSwitchRock"; v2 detected → typed error), write.go
                  (TLV builders), client.go (UDP client: ephemeral bind,
                  SO_BINDTODEVICE best-effort, overridable client/server ports,
                  2 s timeout, sequence handling), reader.go / writer.go
                  (per-op tag sets always prefixed with MODEL; unsupported ops
                  raise; verify-after-write; mgmt-IP force-gated).
  webui/          spec.go (LoginScheme, HtmlDialect, HttpModelSpec, all
                  per-model endpoint tables incl. web ports and needs_referer),
                  parse_*.go per dialect (STANDARD, GS110EMX never-closed rows,
                  GS105PE hi/lo counters, M4300 cheetah cells + field comments,
                  XE_FASTPATH coordinate-addressed cells, GOAHEAD_XML wcd),
                  forms.go (write form encoders incl. hiddenMem port codes
                  1/2/3), crypt.go (merge + MD5), session.go (Session
                  interface), client.go (net/http: no keep-alive, TLS verify
                  off, 15 s timeout, GET-only retry ×2, Referer enforcement,
                  SID/SIDSSL cookies, Gambit token, GoAhead session path +
                  sessionID header dance), reader.go / writer.go (gated on
                  ReadsVerified; cert upload incl. PKCS#1 conversion via
                  stdlib crypto and GS728TPP XML import).
  fastpath/       spec.go (CliModelSpec command sets + M4300 overrides,
                  ScpCertProfile table), parse.go (dotted-leader values,
                  ruler-driven fixed-width tables, all show-command parsers),
                  driver.go (ShellDriver: prompt/password regexes, echo/prompt
                  stripping, SCP TOFU dialogue, write-memory prestuff),
                  ssh.go (x/crypto/ssh with diffie-hellman-group14-sha1 +
                  ssh-rsa enabled), telnet.go, serial.go (115200 8N1),
                  reader.go, certdeploy.go (SCP cert sequence).
  virtual/        state.go (VirtualSwitchState + all Sim types, coherence
                  rules, snapshot/restore, strict nsdp_tlvs, http_sensors),
                  mibview.go (sorted OID view; GET/GETNEXT/BULK semantics;
                  noSuchObject vs noSuchInstance vs endOfMibView; atomic
                  multi-varbind SET with rollback), seed.go (per-model seeds
                  ported from Python's seed.py — identical values), faces:
                  snmpface.go, nsdpface.go (v1-auth validation, result 0x0700,
                  silent drop of malformed datagrams), httpface.go (all 5 login
                  schemes, byte-faithful per-dialect renderers ported from
                  web_*.py, 404 for unspecced paths, Referer 403),
                  cliface.go (in-process) + sshface.go + telnetface.go (real
                  loopback listeners serving the FASTPATH renderer),
                  server.go (VirtualSwitch binds only model-supported faces on
                  127.0.0.1 ephemeral ports; separate port fields per face;
                  deterministic teardown).
  (root)          netgearswitch: Switch facade + New/FromConfig + options,
                  dispatch.go (preference order, gating, caching),
                  config.go (TOML inventory, SwitchConfig, ResolveSecret,
                  EnsureSecureFile), detect.go (DetectModel via sysDescr
                  whole-word matching; never guesses), alias.go (type aliases
                  re-exporting model types).
  cmd/gngsw/      cobra CLI (§9).
  cmd/gngsw-mcp/  MCP server (official go-sdk), stdio.
  cmd/gngsw-virtual/  standalone fake runner (§8.3).
  crosstest/      cross-language harness assets (§10): endpoint-provider
                  abstraction, Python-fake launcher, pytest suite for
                  Python-lib-vs-Go-fake, CLI diff runner.
  internal/hwtest/ opt-in hardware conformance suite (§11).
```

## 4. Third-party libraries (popular over hand-rolled)

| Need | Choice | Notes |
|---|---|---|
| SNMP client | `github.com/gosnmp/gosnmp` | De facto standard Go SNMP client. v2c GET/GETNEXT/BULKWALK/SET. |
| SNMP agent (fake) | `github.com/slayercat/GoSNMPServer`, **decision gate** | Accepted only if the fake passes: net-snmp CLI walk == Python-fake walk, correct BULK/lexicographic order, atomic SET, noSuchObject/noSuchInstance/endOfMibView. If it can't, replace with a minimal in-repo v2c responder (the mibview stays identical either way; only the wire layer swaps). |
| HTML parsing | `github.com/PuerkitoBio/goquery` + targeted regex | Regex where Python's parsers depend on malformed-HTML quirks (never-closed `<tr>`, comment-tagged cells). |
| CLI framework | `github.com/spf13/cobra` | Most popular; supports the global-flags-anywhere pattern. |
| TOML | `github.com/BurntSushi/toml` | Shared inventory schema. |
| SSH client | `golang.org/x/crypto/ssh` | Legacy kex `diffie-hellman-group14-sha1` + `ssh-rsa` host keys explicitly configured (paramiko<3 equivalence). |
| SSH server (fake) | `github.com/gliderlabs/ssh` | Popular wrapper over x/crypto/ssh. |
| Telnet client | `github.com/ziutek/telnet`, fallback hand-rolled IAC | FASTPATH needs only trivial negotiation; if the lib misbehaves, ~100 lines of IAC handling in-repo. |
| Serial | `go.bug.st/serial` | Maintained, popular. |
| MCP | `github.com/modelcontextprotocol/go-sdk` | Official SDK. |
| Certificates / MD5 | stdlib `crypto/x509`, `encoding/pem`, `crypto/md5` | Python needed the `cryptography` package; Go stdlib covers PKCS#1 conversion. |
| Test diffing | `github.com/google/go-cmp` | Equality assertions on model types. |

## 5. Public API sketch

```go
import ngsw "github.com/mithro/go-netgear-switch-library"

sw, err := ngsw.New(ngsw.GetModel("m4300-24x"), "10.1.5.13",
    ngsw.WithSNMPCommunity("public"),
    ngsw.WithSNMPWriteCommunityResolver(resolver), // lazy, once
    ngsw.WithProtectedPorts(9, 10))
// or: sw, err := ngsw.FromConfig(cfg)   // cfg from ngsw.LoadInventory(path)
defer sw.Close()

ports, err := sw.GetPorts(ctx)                    // []ngsw.PortStatus
err = sw.SetPoE(ctx, 3, false, ngsw.Write{})      // Write{Force bool, DryRun…} options
err = sw.CyclePoE(ctx, 3, ngsw.Write{}, ngsw.WithPoETimeouts(t))
snap, err := sw.Snapshot(ctx)                     // ngsw.SwitchData
det, err := ngsw.DetectModel(ctx, host, ngsw.WithSNMPCommunity("public"))
```

- Every operation takes `context.Context` (cancellation + deadlines flow into
  gosnmp/net-http/ssh natively).
- Options pattern for construction; injected clients (SNMP `Client`, NSDP
  client, `webui.Session`, `fastpath.Session`) for tests, mirroring Python's
  injectable protocol clients.
- Write methods accept a `Write` options struct (`Force bool`); default zero
  value = safe behaviour.
- Method set (names Go-cased, semantics per §2.1): `GetPorts, GetStats,
  GetVLANs, GetPVIDs, GetLLDP, GetMACs, GetPoE, GetSensors, GetMgmtIP,
  Snapshot, Identify, NSDPDevice, SetPortEnabled, SetPoE, CyclePoE,
  ClearPoEFault, SetPVID, SetVLANMembership, CreateVLAN, DeleteVLAN,
  SetMgmtIP, UploadCertificate, UploadCertificateSCP`.

## 6. Config & credentials

- **Schema:** identical to Python's inventory TOML (`[switches.<name>]` with
  `model`, `host`, `snmp.community`, `snmp.write_community`, `http.password`,
  `nsdp.interface`, `protected_ports`, optional web port). One file serves
  both libraries; round-trip tests parse the Python repo's fixture inventories.
- **Secret specs:** literal, `${ENV_VAR}`, `!command args` (10 s timeout,
  stdout stripped). Literal secrets force a 0600 permission check
  (`EnsureSecureFile`). `!command` covers gdoc2netcfg-provided credentials.
- **Resolution order:** CLI flag → env var (`NGSW_COMMUNITY`,
  `NGSW_WRITE_COMMUNITY`) → inventory value → interactive prompt (stderr,
  skipped for non-SNMP models; empty input = unresolved). The HTTP password
  feeds both HTTP and NSDP v1 auth, as in Python.
- **Netgear defaults:** the hardware conformance harness (§11) — not the
  library resolution chain — falls back to well-known defaults when a
  credential is unset: SNMP read `public`, SNMP write `private`, web/NSDP
  password `password`.

## 7. Protocol fidelity requirements

The pinned Python sources are normative; the Go port carries these
known-critical behaviours (non-exhaustive — the cross-tests enforce the rest):

- **SNMP:** v2c only; walks yield rows equal to net-snmp `-On -Oe -OU` output
  semantics; integer-family collapsing; Hex-STRING → bytes; "No Such
  Object/Instance" raises on GET, skipped on walk; PVID SET is Gauge32 (`u`);
  VLAN membership is a read-modify-write of both egress+untagged bitmaps in one
  atomic two-varbind SET (width `max(8, ceil(port_count/8))` bytes), verifying
  both columns; VLAN create = RowStatus createAndGo(4) + name; delete =
  destroy(6) with existence precondition; PoE rearm = two sequential SETs,
  never one duplicate-OID set-many; mgmt-IP writes use the UNVERIFIED vendor
  OIDs, require Force, verify all three fields; sensors prefer vendor
  fan/PSU/temp columns and fall back to ENTITY-MIB, raising when a claimed
  vendor subtree walks empty; MACs/base-MAC handle the M4300 17-char ASCII
  colon-hex quirk.
- **NSDP:** header/TLV framing per Python `protocol.py` incl. the full-u32
  sequence field and `NSDP` signature; every read prepends `MODEL`; strict
  payload sizes (3-byte port status, 49-byte stats, `>H`+two-bitmap VLAN
  members, variable-width mirroring); speed byte map with 0xFF→10G and
  unknown→DOWN never raising; v1 XOR auth only, result 0x0700 → typed error
  naming v2; writes verify-after-write; PORT_PVID/VLAN_MEMBERS writes may be
  rejected by hardware (documented).
- **HTTP:** all five login schemes with their exact token/cookie mechanics;
  Referer enforcement (port-exact) for M4300; no connection reuse; GET retries
  ×2 on protocol errors, POSTs never retried; mid-session "redirect to login"
  → auth error; per-dialect parsers replicate Python's extraction including
  the GS105PE 32-bit hi/lo counter pairs and XE coordinate addressing;
  write forms carry the scraped CSRF `hash`; `SetPortEnabled`/`SetMgmtIP`/
  `ClearPoEFault` over HTTP are UnsupportedCapability (UNVERIFIED-pending-
  capture), same as Python.
- **FASTPATH:** command sets incl. M4300 overrides; prompt regex
  `\)\s*(?:\([^)]*\)\s*)?[#>]\s*$`; latin-1 decoding; SCP copy dialogue
  answers (TOFU yes, password, bare `y` byte); write-memory prestuff for
  gsm7252ps; PoE table column selection by header name (`Power (mW)` not
  `Max Power (mW)`).

## 8. Virtual switch (Go fakes)

### 8.1 State & MIB view

One authoritative mutable `VirtualSwitchState` per instance; faces are
projections. Seeds ported value-for-value from Python `virtual/seed.py` for
gsm7252ps, gsm7228ps, gs110emx, gs305ep, gs105pe, m4300-24x, m4300-16x,
gs728tpp (others: blank-but-valid). Coherence rules identical (PoE admin off →
detect disabled + link down; on → delivering). The MIB view distinguishes
noSuchObject (unregistered subtree, e.g. RFC 3621 on non-PoE models) from
noSuchInstance (absent row) from endOfMibView; multi-varbind SETs are
all-or-nothing with snapshot/rollback; non-physical ifType rows (LAG 161,
CPU 1, l2vlan 135) exist and are filtered by read paths; absent counters stay
absent (never fabricated zeros).

### 8.2 Faces

- **SNMP:** UDP agent on 127.0.0.1 ephemeral port (§4 decision gate).
- **NSDP:** UDP responder, strict requested-tags-only answers, v1 auth
  validation, silent drop of malformed datagrams.
- **HTTP:** TCP server; all five login flows; byte-faithful per-dialect
  renderers ported from Python's `web*.py` (fixed CSRF token `virtualhash`,
  same markers/quirks); 404 for paths absent from the model's spec; plain
  HTTP (no TLS), matching the Python fake.
- **FASTPATH:** the renderer from Python's `cli_fastpath.py`, exposed three
  ways: in-process `Session` (unit tests), a real loopback **SSH** server
  (password auth, legacy-algo tolerant), and a real loopback **telnet**
  listener.
- Distinct port fields per face (fixes the Python `self.port` overload).

### 8.3 `gngsw-virtual` runner

`gngsw-virtual --model gs305ep [--listen 127.0.0.1]` starts the fake and
prints one JSON line to stdout:
`{"model": "...", "host": "127.0.0.1", "snmp_port": N, "nsdp_port": N,
"http_port": N, "ssh_port": N, "telnet_port": N, "community": "public",
"password": "password"}` (absent faces omitted), then blocks until
SIGINT/SIGTERM/stdin-EOF; exits cleanly. Multiple `--model` flags start a
fleet (one JSON line each). This is the contract the Python cross-test
harness consumes; the Python repo PR adds the mirror-image runner with the
same JSON schema.

## 9. Command-line tools & MCP

- `gngsw` reproduces the full `ngsw` surface: global flags (`--config`,
  `--switch`, `--host`, `--model`, `--community`, `--write-community`,
  `--nsdp-interface`, `--http-password`, `--json`, `-v`) accepted before or
  after the subcommand; subcommands `models, ports, stats, vlans, pvids, lldp,
  macs, sensors, show, identify, nsdp-device, poe [port] [on|off|cycle|
  clear-fault], port <p> {up|down}, cycle-poe, clear-poe-fault,
  upload-certificate, upload-certificate-scp, pvid, vlan set|create|delete,
  ip [set], capture`; write rails `--dry-run` / `-y|--yes` / `--force` with
  Python's exact prompt/ok/aborted strings on the same streams; exit codes
  0/1/2/3/4.
- **Output contract:** byte-identical stdout to `ngsw` for the same device
  state (tables, JSON, `%g` sensor formatting, section headers). Enforced by
  the CLI-diff cross-test (§10.4).
- `gngsw-mcp`: official go-sdk over stdio; same tools, write-gating and
  structured unsupported results as `ngsw-mcp`.
- Debian package installs `ngsw` and `ngsw-mcp` symlinks via postinst only
  when the names are free; postrm removes only symlinks it owns.

## 10. Cross-testing matrix

The conformance suite is written once in Go against an **endpoint provider**
interface (start fake for model M → endpoints), so suites 1 and 2 are the same
tests with different providers.

1. **Go library ↔ Go fakes** (CI default): every read+write op × every model ×
   every supported face; cross-backend coherence (a write via one face visible
   via the others, with per-backend differences explicitly justified, as in
   Python's cross-backend suites); NSDP/HTTP/SSH/telnet transports exercised
   over real sockets.
2. **Go library ↔ Python fakes** (CI): job installs the Python library with
   uv from the pinned ref, launches Python fakes via the new standalone runner
   (Python repo PR, §10.6), runs the same Go conformance suite against them.
3. **Python library ↔ Go fakes** (CI): pytest suite in `crosstest/python/`
   pointing `SyncSwitch` and `AsyncSwitch` at `gngsw-virtual` endpoints —
   read and write paths, plus paramiko-SSH and telnet against the Go CLI
   faces.
4. **CLI parity diff** (CI): run `ngsw` and `gngsw` with the same subcommands
   against the same fake (each side, both fakes); assert byte-identical stdout
   and equal exit codes; JSON outputs compared structurally too.
5. **Fake-vs-fake** (CI, cheap and implied by 2+3 but asserted directly):
   walk both SNMP fakes with net-snmp CLI tools and diff; fetch every specced
   HTTP page from both fakes and diff; NSDP full-device read from both and
   diff.
6. **Hardware** (opt-in, §11).

**Python repo PR** (own worktree + branch + PR, never committed directly):
adds the standalone virtual-switch runner (same JSON contract as §8.3, e.g.
`python -m netgear_switch.virtual --model X`) and optionally a CI job running
suite 3 from the Python side. Nothing else changes in the Python repo.

## 11. Real-hardware testing

- **Inventory:** the shared TOML (live fleet currently described by the Python
  repo's `tmp/inventory.toml`: 3× m4300-16x, m4300-24x, 3× gsm7252ps,
  2× s3300/gsm7228ps, m7300, xs748t, 3× gs110emx, 3× gs305ep; SNMP community
  `public`, NSDP via `br-net`). Copied into a Go-repo-local hwtest inventory
  (not committed with secrets).
- **Reads:** every supported read path on every reachable switch, via both
  libraries, with a **differential mode**: run Python and Go against the same
  switch back-to-back and diff results excluding volatile fields (counters,
  LLDP ages, MAC tables, sensor values compared within tolerance).
- **Writes (approved policy, unattended-safe):**
  1. Uplinks derived via LLDP (any port whose neighbour is another switch in
     the fleet) and marked `protected_ports` before any write.
  2. Disruptive port/PoE writes only on currently link-down ports; prior state
     always restored (read → write → verify → restore → verify).
  3. VLAN lifecycle uses dedicated VLAN 3999 (create → membership/PVID checks
     on link-down ports → delete).
  4. PVID changes only on link-down ports, restored after.
  5. **Never** mgmt-IP set, certificate upload/deploy, or reboot against real
     hardware; those paths are proven against fakes + cross-language suites.
- **Credentials:** resolution chain of §6 with the harness-level Netgear
  default fallbacks; missing write credentials for a device simply skip its
  write phase with an explicit report (never silent).
- Hardware suites are `-tags hwtest`, never run in CI, and emit a conformance
  report (per switch × op × backend: pass/fail/skipped+reason).

## 12. Quality gates

- `gofmt -l` clean, `go vet` clean, `golangci-lint run` clean (installed as a
  release binary — no apt package exists on sid; version pinned in CI and a
  `make lint` target installs it locally).
- `go test -race ./...` green; coverage ≥ 90% statements on library packages
  (`model`, `snmp`, `nsdp`, `webui`, `fastpath`, `virtual`, root), enforced in
  CI; `cmd/` covered via CLI-level tests.
- No skipped tests except genuinely environment-conditional ones (serial pty
  availability); no flaky tests; local == CI.
- TDD per slice (superpowers test-driven-development skill); small discrete
  commits; merge to main via `--no-ff` merge commits per slice; main always
  green.

## 13. Release engineering

- **Auto-tag:** every merge to main, CI creates the next `v0.N.0` tag
  (monotonic counter; no manual bumps). Tags drive Go module resolution,
  GitHub Releases and deb versions (`0.N.0`).
- **GitHub Releases:** per tag, publish binaries of `gngsw`, `gngsw-mcp`,
  `gngsw-virtual` for linux/amd64 and linux/arm64 (static, CGO off) with
  checksums, built with goreleaser.
- **Debian:** `gngsw` binary package for **trixie and sid**, **amd64 + arm64**
  (Go binaries are arch-specific, unlike Python's arch:all), built in suite
  containers, published to a GPG-signed flat apt repo on GitHub Pages in the
  same style as the Python repo (fail-closed when the signing key secret is
  absent); postinst/postrm symlink handling per §9; package name `gngsw`,
  `Suggests: snmp` (useful oracle, not a dependency — the Go library needs no
  net-snmp at runtime).
- **CI (GitHub Actions):** lint/vet/test/race/coverage; cross-test suites
  2–5; deb builds; tag + release + apt publish jobs on main.

## 14. Implementation sequence (slices)

1. **Foundation:** repo + GitHub setup (github-setup skill), go.mod, `model`
   package (types, errors, registry), config/inventory + secret resolution,
   CI skeleton (lint/test gates).
2. **SNMP read core:** oids/parse/client + gosnmp transport + virtual state,
   mibview, SNMP face + seeds; conformance harness skeleton with the
   endpoint-provider abstraction; first Go-vs-Python-fake checks.
3. **Facade + read APIs:** Switch, dispatch, DetectModel; snapshot.
4. **SNMP write:** writer + verify-after-write + PoE cycle machine + safety
   rails; mutable fake behaviours; write cross-checks.
5. **NSDP:** codec/parsers/auth/client, reader/writer, NSDP face; Plus-model
   cross-tests.
6. **HTTP:** specs, dialect parsers, sessions/logins, reader/writer, HTTP
   face with byte-faithful renderers; cert upload paths.
7. **FASTPATH:** parsers/driver/transports, reader, SCP deploy, CLI face +
   SSH/telnet listeners.
8. **CLI:** `gngsw` (all subcommands, safety rails, capture), byte-parity
   fixtures against `ngsw`, CLI-diff harness.
9. **MCP:** `gngsw-mcp` + tests.
10. **Cross-test completion:** Python repo PR (runner + optional CI job),
    suites 2/3/4/5 wired into CI; `gngsw-virtual` fleet mode.
11. **Hardware conformance:** hwtest suite + differential mode; execute per
    §11 policy across the fleet; fix divergences.
12. **Packaging & release:** deb + apt Pages repo, auto-tag, GitHub Releases,
    README/docs.

Hardware verification threads through slices 2–9 (reads as each backend
lands), with the full sweep in slice 11. Development uses subagents (≤3
concurrent) per the executing-plans/subagent workflow.

## 15. Documentation (completion gate)

- **API documentation:** every exported identifier carries a proper godoc
  comment (enforced by lint); package-level docs with examples
  (`Example*` test functions) for the root package and each protocol package.
  Published automatically at pkg.go.dev once the repo is public and tagged;
  the README links it.
- **CLI documentation:** generated from cobra (`GenMarkdownTree`) for every
  `gngsw`/`gngsw-mcp`/`gngsw-virtual` command, committed under `docs/cli/` and
  published on the GitHub Pages site alongside the apt repo. Regeneration is
  CI-checked (drift fails the build).
- **Guides:** README (install via apt/Releases/`go install`, quick start,
  inventory format), a cross-testing guide (how to run the four cross-language
  suites), and the hardware conformance guide (§11 policy, how to run).

## 16. Resource limits during development & CI

All heavyweight local executions (Go builds, test runs, fake fleets, Python
cross-test processes) run inside resource jails so development never
overwhelms the host: `systemd-run --user --scope` with `MemoryMax` and
`CPUQuota` (fallback: `ulimit`-wrapped subshells where systemd is
unavailable). Development uses at most 3 concurrent subagents. CI jobs are
naturally isolated by the runner.

## 17. Out of scope

- Porting downstream tools (`sensors2mqtt`, `gdoc2netcfg`) to the Go library.
- NSDP v2 auth (matches Python: detected and reported, not implemented).
- Windows/macOS support for the serial backend (build-tagged Linux-first;
  other platforms best-effort via go.bug.st/serial).
- A TLS-serving HTTP fake (Python's fake is plain HTTP; parity kept).
- Publishing to any registry other than GitHub (Go modules resolve via the
  repo itself).
