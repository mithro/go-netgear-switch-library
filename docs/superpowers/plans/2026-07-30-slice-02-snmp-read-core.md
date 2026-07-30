# Slice 02: SNMP Read Core + Virtual Switch Substrate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** The `snmp` package (OIDs, parsers, gosnmp transport, model-driven
reader, model detection) and the `virtual` package's SNMP substrate (state,
seeds, mibview, wire-faithful v2c agent face, VirtualSwitch server), proven
by unit tests, integration tests against the Go fake, and net-snmp CLI
oracle tests.

**Architecture:** mirror of the Python reference. Two committed dossiers are
the task-level specification and MUST be read by every implementer before
coding:
- `docs/superpowers/plans/2026-07-30-slice-02-dossier-snmp.md` (referenced
  below as **D-SNMP**)
- `docs/superpowers/plans/2026-07-30-slice-02-dossier-virtual.md` (**D-VIRT**)

The pinned Python source (`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274` (frozen snapshot of
python-netgear-switch-library), branch `fix/s3300-52x-live-verify` @ `1aa1274` (snapshot: /home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274), read-only) is normative over
both dossiers; where they disagree, the source wins and the discrepancy is
reported in the task report. Pin guard: `git -C /home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274 rev-parse HEAD` must be `1aa1274...`; else STOP/BLOCKED (orchestrator re-pins at slice boundaries only).

**Tech Stack:** Go 1.26, `github.com/gosnmp/gosnmp` (client transport AND
the fake's PDU codec via `SnmpDecodePacket`/`SnmpPacket.MarshalMsg` — the
GoSNMPServer library was probed and REJECTED: it answers absent-OID GETs
with PDU-level v1-style noSuchName instead of per-varbind v2c exception
values), `github.com/google/go-cmp`, net-snmp CLI tools (test oracle,
installed on dev machine and in CI via `apt-get install -y snmp`).

## Global Constraints

- Parity pin: `fix/s3300-52x-live-verify` @ `1aa1274` (snapshot: /home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274) — source normative.
- Honesty rules: unsupported ⇒ wrap `model.ErrUnsupportedCapability` at the
  earliest point; absent values ⇒ nil, never fabricated zero/""; offending
  OID appears verbatim in every parse-error message (wrap `model.ErrSNMP`).
- v2c exception semantics are non-negotiable: per-varbind
  noSuchObject/noSuchInstance/endOfMibView VALUES, never PDU-level errors.
- OID ordering is numeric (`[]int` element-wise), never string comparison.
- Every op takes `context.Context`. Race detector clean. Coverage ≥90%
  library-only. gofmt/vet/golangci-lint clean. `make test` (jailed) for
  full runs. Commit trailers:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` +
  `Claude-Session: https://claude.ai/code/session_01HchhGh659AVsp7J4yyidLc`.
- Capture fixtures used by seed-grounding tests are COPIED into
  `virtual/testdata/captures/` from the Python repo's
  `tests/fixtures/captures/{gsm7252ps,gsm7228ps,m4300-24x,m4300-16x,gs728tpp}.json`
  (hermetic CI; provenance comment at copy time).

---

### Task 1: `snmp` package — OIDs and vendor tables

**Files:** Create `snmp/oids.go`; Test `snmp/oids_test.go`.

**Interfaces — Produces:**
```go
package snmp
// All D-SNMP §1.1 constants, same names Go-cased: SysDescr, SysObjectID,
// IfType, IfAdminStatus, IfOperStatus, IfInErrors, IfOutErrors, IfName,
// IfHCInOctets, IfHCInUcast, IfHCOutOctets, IfHCOutUcast, IfHighSpeed,
// IfAlias, Dot1dBaseBridgeAddress, Dot1dBasePortIfIndex, Dot1qTpFdbPort,
// Dot1qVlanStaticName, Dot1qVlanStaticEgress, Dot1qVlanStaticUntagged,
// Dot1qPvid, Dot1qVlanStaticRowStatus, RowStatusCreateAndGo=4,
// RowStatusDestroy=6, EntPhysicalDescr, EntPhysicalClass, EntPhysicalName,
// EntClassPowerSupply=6, EntClassFan=7, LldpRemTable, PethPsePortTable,
// IPAdEntAddr, IPAdEntIfIndex, IPAdEntNetmask, IPAddressIfIndex,
// IPRouteDest, IPRouteNextHop, DHCPModeOIDSuffix = "99.1",
// EthernetCsmacd = 6.
type VendorOids struct{ Base, PoEPowerMw, BoxFan, BoxPSUPower, BoxTemp,
    DHCPModeUnverified, MgmtWriteAddrUnverified, MgmtWriteNetmaskUnverified,
    MgmtWriteGatewayUnverified string }
func HasVendorOids(m *model.SwitchModel) bool
func GetVendorOids(m *model.SwitchModel) (VendorOids, error) // wraps model.ErrUnsupportedCapability
func UnimplementedRoots(m *model.SwitchModel) []string
func IsOIDImplemented(m *model.SwitchModel, oid string) bool
var BoxSensorColumns = [3]struct{ Kind, Unit, Suffix string }{...} // doc/reference only
```

- [ ] Steps: TDD per D-SNMP §1 — failing tests first pinning every §1.4
  concrete vendor-OID value, the gs110emx error, the §1.6/1.7
  unimplemented-roots matrix (PoE model → empty; zero-PoE+vendor → [PoE
  root, vendor mW]; zero-PoE no-vendor → [PoE root]) and is-implemented
  true/false cases; implement; `make test`/fmt/vet green; commit
  `feat(snmp): OID tables, vendor subtrees, unimplemented-root gating`.

---

### Task 2: `snmp` package — rows, errors, client interfaces

**Files:** Create `snmp/client.go`; Test `snmp/client_test.go`.

**Interfaces — Produces:**
```go
type Row struct{ OID string; Value any; SnmpType string } // Value: exactly one of int64, string, []byte
func NewIntRow(oid string, v int64) Row; func NewStrRow(oid, v string) Row; func NewBytesRow(oid string, v []byte) Row
var AbsentTypes = map[string]bool{"NOSUCHOBJECT":true,"NOSUCHINSTANCE":true,"ENDOFMIBVIEW":true}
func FullOID(oid, index string) string
type Client interface {
    Get(ctx context.Context, oids []string) ([]Row, error)
    Walk(ctx context.Context, baseOID string) ([]Row, error)
}
type SetVarbind struct{ OID string; Value any; TypeLetter string } // i/u/s/x/a; NewSetVarbind validates
type WriteClient interface { Client
    Set(ctx context.Context, vb SetVarbind) error
    SetMany(ctx context.Context, vbs []SetVarbind) error // one PDU, atomic
}
func errOID(oid string, format string, a ...any) error // helper: wraps model.ErrSNMP, message contains oid
```

- [ ] Steps: TDD per D-SNMP §2/§5.4 — Row equality via go-cmp; FullOID
  pinned pairs; NewSetVarbind rejects invalid letter (plain error, not
  ErrSNMP); AbsentTypes membership. Commit
  `feat(snmp): Row, client interfaces, SetVarbind`.

---

### Task 3: `snmp` parse — index columns, ports, stats

**Files:** Create `snmp/parse.go`; Test `snmp/parse_ports_test.go`.

**Interfaces — Produces:**
```go
func IndexIntColumn(rows []Row, baseOID string) (map[int]int64, error)
func IndexStrColumn(rows []Row, baseOID string) (map[int]string, error)
func ParsePortStatus(admin, oper, speed, names, aliases, ifTypes []Row) ([]model.PortStatus, error)
type PortStatsCols struct{ InOctets, OutOctets, InUcast, OutUcast, InErrors, OutErrors, IfTypes []Row }
func ParsePortStats(cols PortStatsCols) ([]model.PortStats, error)
```

- [ ] Steps: TDD per D-SNMP §3.0–§3.5 and the test intents of
  `test_parse_ports.py` (13 cases): ifType filtering present/absent for
  ports AND stats independently; down-port speed nil despite ifHighSpeed
  value; empty alias → nil; absent counters → nil; malformed
  index/non-integer/non-string errors containing the exact OID. Commit
  `feat(snmp): port status and stats parsers with physical-port filtering`.

---

### Task 4: `snmp` parse — bitmaps, VLANs, PVIDs

**Files:** Modify `snmp/parse.go`; Test `snmp/parse_vlans_test.go`.

**Interfaces — Produces:**
```go
func DecodePortBitmap(bitmap []byte) []int // sorted; MSB-first bit7-of-byte0 = port 1
func ParseVlans(names, egress, untagged []Row) ([]model.VLANInfo, error)
func ParsePvids(rows, ifTypes []Row) ([]model.Pvid, error)
```

- [ ] Steps: TDD per D-SNMP §3.6–§3.9 + `test_parse_vlans.py` intents:
  bitmap conventions (0b10100000→[1,3]; second-byte→[9]); names-walk-only
  VLAN enumeration; tagged = member − untagged; bitmap-less VLAN → empty
  sets; malformed index/type errors naming OID; **PVIDs filtered directly
  against physical ifIndexes with NO dot1dBasePortIfIndex translation**
  (docstring the why per D-SNMP §3.9). Note: string-typed bitmap rows from
  transports arrive as []byte in Go (no latin-1 dance). Commit
  `feat(snmp): VLAN bitmap decode, VLAN and PVID parsers`.

---

### Task 5: `snmp` parse — MACs, LLDP, base MAC

**Files:** Modify `snmp/parse.go`; Test `snmp/parse_lldp_macs_test.go`.

**Interfaces — Produces:**
```go
func ParseMacs(fdb, bridgePorts []Row) ([]model.MacEntry, error)
func ParseLldp(rows []Row) ([]model.LLDPNeighbor, error)
func ParseBaseMac(rows []Row) (*string, error)
```

- [ ] Steps: TDD per D-SNMP §3.10–§3.14 + `test_parse_lldp_macs.py`
  intents. THE critical asymmetry: 6-byte []byte port-id → always MAC-hex;
  6-char printable string → stays text (`"1/xg51"`); non-printable 6-char →
  MAC-hex. Base MAC accepts raw-6-bytes AND the 17-char ASCII colon-hex
  M4300-24X quirk; absent → nil; malformed → error naming OID. FDB
  fallback: unmapped bridge port → the bridge-port number itself. Commit
  `feat(snmp): MAC table, LLDP, base-MAC parsers (M4300 ASCII quirk)`.

---

### Task 6: `snmp` parse — PoE and sensors

**Files:** Modify `snmp/parse.go`; Test `snmp/parse_poe_sensors_test.go`.

**Interfaces — Produces:**
```go
var DetectMap = map[int64]model.PoEDetect{1: Disabled, 2: Searching, 3: Delivering, 4: Fault} // else Unknown
func ParsePoe(status, powerMw []Row) ([]model.PoEStatus, error)
type SensorColumn struct{ Kind, Unit string; Rows []Row }
func ParseBoxSensors(cols []SensorColumn) ([]model.Sensor, error)
func ParseEntitySensors(classRows, nameRows, descrRows []Row) ([]model.Sensor, error)
```

- [ ] Steps: TDD per D-SNMP §3.15–§3.18 + `test_parse_poe_sensors.py`
  intents: cols 3/6 only, wrong-arity status rows silently skipped,
  missing col 3/6 raises per port, mW keyed by final suffix component with
  silent skip of non-ints, power nil when absent; `"Not Supported"`
  skipped; entity sensors: classes 6/7 only, name fallback chain,
  `math.NaN()` value + unit "inventory" (tests use math.IsNaN), canon
  names (PowerSupply→PS). Commit
  `feat(snmp): PoE and sensor parsers (vendor + ENTITY-MIB fallback)`.

---

### Task 7: `snmp` parse — mgmt-IP, system info, model detection

**Files:** Modify `snmp/parse.go`; Test `snmp/parse_mgmt_sysinfo_test.go`.

**Interfaces — Produces:**
```go
func ParseMgmtIP(addr, netmask, routeDest, routeNexthop, dhcpMode, baseMac, addrRFC4293 []Row) (model.MgmtIPConfig, error)
func ParseSystemInfo(rows []Row) (sysDescr, sysObjectID *string, err error)
var SysObjectIDModels = map[string]string{"1.3.6.1.4.1.4526.100.10.19": "gsm7228ps"}
func DetectModelFromSysObjectID(sysObjectID *string, models []*model.SwitchModel) *string
func DetectModelFromSysDescr(sysDescr *string, models []*model.SwitchModel) *string
```

- [ ] Steps: TDD per D-SNMP §3.19–§3.26a: the full mgmt-IP matrix
  (RFC-1213 primary/RFC-4293 fallback/netmask-only-via-1213/default-route
  gateway/dhcp-mode first-row-only degrade-to-UNKNOWN); ParseSystemInfo
  exact-OID matching honesty; **the complete sysDescr test table from
  D-SNMP §3.26 verbatim as table-driven cases** including GS305EPP/
  S3300-28X rejections and ambiguity → nil; sysObjectID map hit/miss/
  unregistered/empty. `_WORD_STRIP_CHARS` built programmatically as all
  ASCII punctuation minus `-` with a test comparing against the literal
  Python value. Commit
  `feat(snmp): mgmt-IP parser and authoritative model detection`.

---

### Task 8: `snmp` gosnmp transport

**Files:** Create `snmp/gosnmp.go`; Test `snmp/gosnmp_test.go`.

**Interfaces — Produces:**
```go
type GoSNMPClient struct{ ... }
func NewGoSNMPClient(host string, community string, opts ...ClientOption) *GoSNMPClient // host may be "host:port"
// implements WriteClient. Timeout default 10s, retries 1, v2c.
// internal: normalizeVarbind(pdu gosnmp.SnmpPDU) (Row, error)
```
Normalization contract (D-SNMP §5.2/§5.3): gosnmp Asn1BER tag → token map
(Integer→"INTEGER", Gauge32/Unsigned32→"Gauge32", Counter32, Counter64,
TimeTicks→"Timeticks" int value, OctetString→printability heuristic
(all bytes 0x20–0x7E or empty → string "STRING", else []byte "Hex-STRING"),
IPAddress→string "IpAddress", ObjectIdentifier→dotted numeric string with
leading dot stripped "OID", NoSuchObject/NoSuchInstance/EndOfMibView →
absent tokens). Get: empty list → no I/O; absent row in GET → error naming
OID (wraps model.ErrSNMP). Walk: GetBulk MaxRepetitions=25 subtree-bounded
(gosnmp BulkWalk; verify boundedness with a test); mid-walk error → error;
absent/EndOfMibView → stop, keep rows. SetMany: one PDU; i→Integer,
u→Gauge32, a→IpAddress, s/x→OctetString. ctx honoured via
gosnmp.Context/conn deadlines. Errors wrap model.ErrSNMP unless already.

- [ ] Steps: TDD with a local fake UDP responder built from
  gosnmp.SnmpDecodePacket/MarshalMsg inside the test (pre-figures the Task
  12 face; keep it minimal, test-local) plus normalizeVarbind unit tests
  per type; value+TYPE parity pins per D-SNMP §6 test_value_parity (int64
  vs string vs []byte exact). Commit
  `feat(snmp): gosnmp v2c transport with normalized rows`.

---

### Task 9: `snmp` Reader + ReadSystemInfo

**Files:** Create `snmp/reader.go`; Test `snmp/reader_test.go`.

**Interfaces — Produces:**
```go
func ReadSystemInfo(ctx context.Context, c Client) (model.DetectedModel, error) // ONE Get([SysDescr, SysObjectID]); sysObjectID-first detection
type Reader struct{ ... }
func NewReader(c Client, m *model.SwitchModel) (*Reader, error) // wraps ErrUnsupportedCapability for non-SNMP models
// Methods (all take ctx): GetPorts, GetStats, GetVlans, GetPvids, GetLldp,
// GetMacs, GetPoe, GetSensors, GetMgmtIP, GetSystemInfo
```

- [ ] Steps: TDD per D-SNMP §4 with a fake `Client` serving canned rows by
  EXACT walked-OID key (the walked OID string per method is the contract).
  Must-have cases from `test_snmp_read.py`: constructor gate (gs305ep →
  error); GetPoe raises for m4300-24x even when the fake HAS PoE rows
  (guard before walk); GetSensors raise-vs-empty pair (gsm7252ps vendor
  claimed + all empty → error; gs728tpp no-vendor + empty ENTITY → `[]`);
  GetMgmtIP absent dhcp → IPModeUnknown; GetSystemInfo independent of bound
  model; walk-sequence assertions (fake records requested base OIDs; assert
  the §4.4–4.9 lists exactly). Commit
  `feat(snmp): model-driven reader and system-info detection`.

---

### Task 10: `virtual` state — Sims, projection, coherence

**Files:** Create `virtual/state.go`, `virtual/state_oidmap.go`; Test
`virtual/state_test.go`, `virtual/mutable_state_test.go`.

**Interfaces — Produces:**
```go
package virtual
// PortSim{Name string; Admin, Link bool; Speed int; IfType int (default 6 via NewPortSim);
//   RxOctets, TxOctets, RxUcast, TxUcast, RxErrors, TxErrors *uint64; Description *string}
// VlanSim{Name string; Member, Untagged map[int]bool}
// PoeSim{Admin bool; Detect int; PowerMw int}
// SensorSim{Kind, Instance, Raw string}; EntitySim{Index, PhysClass int; Name, Descr string}
// MacSim{Vlan int; MacBytes [6]byte; BridgePort int}
// LldpSim{TimeMark, LocalPort, RemIdx int; Chassis, PortID, PortDesc, SysName string}
// MgmtSim{Address, Netmask, Gateway, Mode string}
type State struct{ ModelKey string; Ports map[int]*PortSim; Vlans map[int]*VlanSim;
    Pvids map[int]int; Poe map[int]*PoeSim; Sensors []SensorSim; HTTPSensors []SensorSim;
    EntityComponents []EntitySim; Macs []MacSim; BridgePorts map[int]int; Lldp []LldpSim;
    Mgmt MgmtSim; ModelName, Serial, Firmware, Hostname, NsdpPassword string;
    NsdpMac [6]byte; SysDescr, SysObjectID string; Dot1dBaseMacASCII bool;
    /* NSDP-extra fields per D-VIRT §1.3 with pointer/nil-able semantics */ }
func NewState(modelKey string) *State // defaults per D-VIRT §1.3 (NsdpPassword "password", NsdpMac 28:c6:8e:00:00:01, Mgmt 0.0.0.0/dhcp)
type OIDEntry struct{ SnmpType, Value string } // Value latin-1-transparent: raw bytes stored as string(bytes)
func (s *State) OIDMap() map[string]OIDEntry
func (s *State) Snapshot() *State            // deep copy
func (s *State) Restore(snap *State)         // in-place field copy (pointer identity preserved)
func (s *State) ApplyWrite(oid string, value any) // all 9 branches + coherence; silent no-op for unhandled
func (s *State) IsWritableOID(oid string) bool
func (s *State) IsOIDImplemented(oid string) bool // via snmp.IsOIDImplemented
func EncodePortBitmap(ports map[int]bool, widthBytes int) []byte
```

- [ ] Steps: TDD per D-VIRT §1 in full: the exact OIDMap projection order/
  conditionals (nil counters/description → absent rows; vendor-nil → skip
  vendor columns AND vendor dhcp scalar; ASCII base-MAC quirk; sysDescr/
  sysObjectID fallbacks incl. `{base}.1` / `1.3.6.1.2.1`), ApplyWrite
  coherence (PoE admin↔detect↔link; ifAdmin-down→link-down; VLAN RowStatus
  create/destroy; name auto-create; vendor mgmt writes gated on vendor
  base; unhandled = silent no-op with oid_map-unchanged test),
  IsWritableOID full true/false matrix (ifOperStatus false; RowStatus true
  on absent row). Mirror every `test_mutable_state.py` case. Commit in two:
  `feat(virtual): switch state with SNMP OID projection` and
  `feat(virtual): state writes with device-coherence rules`.

---

### Task 11: `virtual` seeds (5 SNMP models) + capture grounding

**Files:** Create `virtual/seed.go`, `virtual/testdata/captures/*.json`
(copied from Python repo), Test `virtual/seed_test.go`.

**Interfaces — Produces:**
```go
func BuildState(modelKey string) *State // seeded for gsm7252ps, gsm7228ps, m4300-24x, m4300-16x, gs728tpp; blank-but-valid otherwise (NSDP/HTTP models' seed parts come in later slices)
func SeedGSM7252PS() *State // etc. per model
```

- [ ] Steps: values transcribed from the PINNED `virtual/seed.py` — D-VIRT
  §4 for gsm7252ps/m4300-24x/m4300-16x/gs728tpp; **gsm7228ps from the
  NEW capture-based seed (D-VIRT §4.2 stale note — read seed.py + capture
  JSON directly)**. Copy the 5 capture JSONs into testdata with provenance
  comments. Grounding tests mirror `test_state_seed.py`/`test_m4300_seeds.py`
  via a Go `assertSeedMatchesCapture` helper (ports/PVIDs/VLANs/PoE/
  sensors/mgmt against capture JSON parsed with model.SwitchData +
  Canonical; volatile fields excluded per Python harness); plus the pins:
  gsm7252ps 54 parsed ports incl CPU 417/lag 418, bridge_ports {10:110}
  trap, m4300-24x poe empty + ASCII base-MAC wire length 17, m4300-16x
  delivering {11,12}. Commit
  `feat(virtual): capture-grounded seeds for the five SNMP models`.

---

### Task 12: `virtual` mibview + SNMP face (gosnmp codec)

**Files:** Create `virtual/mibview.go`, `virtual/snmpface.go`; Test
`virtual/mibview_test.go`, `virtual/snmpface_test.go`.

**Interfaces — Produces:**
```go
type MibView struct{ ... }
func NewMibView(s *State) *MibView
func (v *MibView) Get(oid []int) (entry *ViewEntry, ok bool)
func (v *MibView) GetNext(oid []int) (entry *ViewEntry, ok bool)
func (v *MibView) Rebuild(); ApplyWrite / ApplyWriteUncommitted / SnapshotState / RestoreState / IsWritableOID / IsImplemented
type SnmpFace struct{ ... }
func NewSnmpFace(v *MibView, community, host string) *SnmpFace
func (f *SnmpFace) Start() (port int, err error) // UDP 127.0.0.1:0, goroutine serve loop
func (f *SnmpFace) Stop() error                  // conn.Close + goroutine join; idempotent
```

- [ ] Steps: TDD per D-VIRT §2/§3. MibView: numeric `[]int` sort
  (slices.Compare), bisect get/get_next, `.8.2 before .8.10` pin,
  exhaustive-walk-visits-every-entry-once test over SeedGSM7252PS's real
  OIDMap. Face: decode requests via a gosnmp codec seam
  (`SnmpDecodePacket`), dispatch GET/GETNEXT/GETBULK/SET, respond via
  `SnmpPacket.MarshalMsg`: per-varbind exception VALUES
  (gosnmp.NoSuchObject/NoSuchInstance/EndOfMibView types) with
  is-implemented gate FIRST; GETBULK = non-repeaters + max-repetitions
  chained next-steps with endOfMibView fill; SET whole-PDU atomic
  (snapshot → per-varbind IsWritableOID gate (notWritable, error-index =
  idx+1) → apply-uncommitted (failure → wrongValue) → restore on any
  failure → Rebuild once on success); community mismatch → silently drop
  (matches VACM reject behaviour); malformed packet → drop. SMI value
  mapping per D-VIRT §3.2 (INTEGER/Gauge32/Counter32/Counter64/OCTETSTR raw
  bytes/IPADDR/OID). Face tests via gosnmp client: GET present/absent-
  instance/absent-subtree; walk full 1.3.6.1 clean termination; type
  round-trips (Gauge32 ifHighSpeed, Counter64, Counter32, IpAddress,
  bitmap bytes, vendor mW); atomic SET rollback observable; 10
  start/stop cycles leak no goroutines (goleak-style check via runtime
  counts) nor FDs. Commits:
  `feat(virtual): sorted MIB view with SNMPv2c exception semantics` and
  `feat(virtual): wire-faithful v2c agent face on gosnmp codec`.

---

### Task 13: `virtual` server + net-snmp oracle + reader capstone

**Files:** Create `virtual/server.go`; Test `virtual/server_test.go`,
`virtual/oracle_test.go`, `snmp/integration_test.go` (package snmp_test).

**Interfaces — Produces:**
```go
type VirtualSwitch struct{ State *State; SnmpPort int; /* NsdpPort, HTTPPort, SSHPort, TelnetPort reserved for later slices */ }
func NewVirtualSwitch(modelKey string, opts ...Option) (*VirtualSwitch, error) // ErrUnknownModel early
func (v *VirtualSwitch) Start() error // binds the SNMP face iff model has BackendSNMP; no face bindable → ErrUnsupportedCapability
func (v *VirtualSwitch) Stop() error  // idempotent; stop-before-start no-op
type EndpointProvider interface { // conformance-harness seam for cross-language suites (slice 10)
    StartModel(ctx context.Context, modelKey string) (Endpoints, error)
}
type Endpoints struct{ Host string; SnmpPort int; Community string /* later: NsdpPort, HTTPPort, SSHPort, TelnetPort, Password */ }
```

- [ ] Steps: (1) server lifecycle tests (unknown model early error;
  gs305ep → no SNMP face bound and (until NSDP exists) Start returns
  ErrUnsupportedCapability with a TODO-slice-05 note in the test; separate
  port FIELDS from day one). (2) **net-snmp oracle tests** (skip with
  clear message iff binaries missing, but they exist in dev+CI):
  `snmpbulkwalk -v2c -c public -On -Oe -OU -Ln 127.0.0.1:PORT <root>`
  subprocess against the face — walk of dot1qVlanStaticName yields exactly
  the 14 gsm7252ps names; walk of PoE root on m4300-24x prints the literal
  `No Such Object available on this agent at this OID`; single-OID snmpget
  of present + absent instances behaves per net-snmp text conventions.
  (3) capstone `snmp/integration_test.go`: GoSNMPClient + Reader against
  VirtualSwitch(gsm7252ps) — every read op non-vacuous with the D-SNMP §6
  integration pins (port1 "1/0/1"/"eth0.rpi5-pmod", base MAC
  E0:91:F5:0C:D6:DB, vlan90 iot member 11 not 10, mgmt 10.1.5.22 STATIC,
  PoE port1 3500 mW, MAC join → 110, lldp port_id "1/xg51" ≠ desc,
  ReadSystemInfo → gsm7252ps) + the M4300-24X ASCII-base-MAC end-to-end
  pin and detection-by-sysObjectID pin against VirtualSwitch(gsm7228ps).
  Provider impl for the Go fake included. Commit
  `feat(virtual): VirtualSwitch server, net-snmp oracle tests, reader capstone`.

---

### Task 14: Orchestrator — gates, CI, final review, merge

- [ ] `make cover` ≥90% library-only; lint/vet/fmt clean; full `make test`
  under race. CI: add `sudo apt-get install -y snmp` step to ci.yml before
  tests. Push branch, PR, CI green, final whole-branch review (most capable
  model) with dossier-parity spot-checks, ONE fix wave + scoped re-review,
  merge --no-ff via PR, cleanup worktree/workspace, update roadmap/memory.

---

## Self-review

- Spec coverage: spec §3 snmp+virtual packages ✓ (Tasks 1–13), §8.1/8.2
  state/faces ✓ (10–13), decision-gate resolution recorded ✓ (header),
  conformance seam for §10 ✓ (Task 13), §16 jails via make ✓.
- No placeholders: every task names exact files, signatures, dossier
  sections, and concrete test pins; dossiers carry the verbatim constants
  (committed in-repo, readable by implementers).
- Type consistency: `snmp.Row`/`Client` (Task 2) consumed by Tasks 8/9/13;
  `virtual.State.OIDMap` (Task 10) consumed by MibView (Task 12);
  `model.Pvid`/`MgmtIPConfig`/aliases from slice 01 used throughout;
  `EncodePortBitmap` (Task 10) inverse-tested against `DecodePortBitmap`
  (Task 4).
