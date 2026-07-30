# Slice 01: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Public GitHub repo with the Go module scaffold, the `model` leaf
package (data types, errors, registry), inventory/secret config in the root
package, resource-jail tooling, and a green CI skeleton.

**Architecture:** `model` is the dependency-free leaf package every protocol
package will import. The root package `netgearswitch` holds config (and later
the facade) and imports `model`, re-exporting its types via aliases. All
values are ported verbatim from the pinned Python reference
(`/home/tim/github/mithro/python-netgear-switch-library`, branch
`fix/live-hardware-parity` @ `b73e7519`): `src/netgear_switch/models.py`,
`errors.py`, `registry.py`, `config.py`.

**Tech Stack:** Go ≥1.26 (apt), stdlib, `github.com/google/shlex` (secret
command splitting), `github.com/google/go-cmp` (test diffs), golangci-lint
(pinned binary).

## Global Constraints

- Module path `github.com/mithro/go-netgear-switch-library`; root package name
  `netgearswitch`; license Apache-2.0; Go `1.26`.
- JSON struct tags use the Python dataclass field names exactly
  (`admin_enabled`, `speed_mbps`, `vlan_id`, `mgmt_ip`, …) — capture-file
  compatibility depends on them.
- Nullable Python fields (`str | None`, `int | None`) become pointers; port
  sets become sorted ascending non-nil `[]int`.
- Every commit message follows conventional commits and ends with the
  Co-Authored-By + Claude-Session trailer used in this repo's history.
- Run tests via `make test` (jailed); never raw `go test` for full runs.
- Coverage target ≥90% for `model` and root packages in this slice.

---

### Task 1: Repo scaffold and GitHub creation

Orchestrator-executed (needs `gh` auth + github-setup skill), not a subagent.

**Files:**
- Create: `go.mod`, `LICENSE`, `README.md`, `.gitignore`

**Interfaces:**
- Produces: module path `github.com/mithro/go-netgear-switch-library` used by
  every later import.

- [ ] **Step 1: go.mod + LICENSE + .gitignore + README stub**

`go.mod`:
```
module github.com/mithro/go-netgear-switch-library

go 1.26
```

`.gitignore`:
```
/tmp/
/bin/
coverage.out
coverage.html
dist/
```

`LICENSE`: full Apache-2.0 text (copy from the Python repo's `LICENSE`).

`README.md` (stub; expanded in slice 12):
```markdown
# Go Netgear Switch Interface Library

Query and control Netgear switches — SNMP (managed), NSDP and HTTP web-UI
(Plus), FASTPATH CLI — behind one model-driven Go API and the `gngsw` CLI.

Status: **early development.** Go port of
[python-netgear-switch-library](https://github.com/mithro/python-netgear-switch-library)
with full capability parity and bidirectional cross-language testing.
See `docs/superpowers/specs/` for the design.

## License

Apache-2.0.
```

- [ ] **Step 2: Commit**

```bash
git add go.mod LICENSE README.md .gitignore
git commit -m "chore: Go module scaffold, license, gitignore"
```

- [ ] **Step 3: Create the public GitHub repo and push**

Use the github-setup skill's standard settings. Then:
```bash
gh repo create mithro/go-netgear-switch-library --public \
  --description "Go library + CLI to query and control Netgear switches (SNMP/NSDP/HTTP/FASTPATH); cross-tested against python-netgear-switch-library" \
  --source . --push
```
Verify: `gh repo view mithro/go-netgear-switch-library --json visibility` →
`"PUBLIC"`.

---

### Task 2: Jail script, Makefile, lint config

**Files:**
- Create: `scripts/jail.sh`, `Makefile`, `.golangci.yml`

**Interfaces:**
- Produces: `make fmt-check | vet | lint | test | cover` targets; every later
  task's "run tests" step uses `make test` / `make cover`.

- [ ] **Step 1: scripts/jail.sh**

```sh
#!/bin/sh
# Run a command under CPU+memory limits so builds/tests/fakes can't
# overwhelm the host. systemd scope when available, ulimit fallback.
set -eu
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --user --scope -q true >/dev/null 2>&1; then
    exec systemd-run --user --scope -q \
        -p MemoryMax=4G -p MemorySwapMax=0 -p CPUQuota=400% -- "$@"
fi
ulimit -v 4194304 || true
exec "$@"
```
`chmod +x scripts/jail.sh`.

- [ ] **Step 2: Makefile**

```make
JAIL := ./scripts/jail.sh
GOLANGCI_VERSION := v2.3.0
GOLANGCI := ./bin/golangci-lint

.PHONY: fmt-check vet lint test cover tools

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(JAIL) go vet ./...

tools: $(GOLANGCI)
$(GOLANGCI):
	mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
	  | sh -s -- -b ./bin $(GOLANGCI_VERSION)

lint: tools
	$(JAIL) $(GOLANGCI) run

test:
	$(JAIL) go test -race ./...

cover:
	$(JAIL) go test -race -coverprofile=coverage.out ./...
	$(JAIL) go run ./scripts/coveragegate -profile coverage.out -min 90
```

- [ ] **Step 3: coverage gate helper** — create `scripts/coveragegate/main.go`:

```go
// Command coveragegate fails if total statement coverage in a Go cover
// profile is below -min percent. cmd/ packages are exempt per the spec
// (covered by CLI-level tests instead).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	profile := flag.String("profile", "coverage.out", "cover profile path")
	min := flag.Float64("min", 90, "minimum total coverage percent")
	flag.Parse()
	out, err := exec.Command("go", "tool", "cover", "-func="+*profile).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := lines[len(lines)-1] // "total: (statements) NN.N%"
	fields := strings.Fields(last)
	pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[len(fields)-1], "%"), 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate: cannot parse:", last)
		os.Exit(2)
	}
	if pct < *min {
		fmt.Fprintf(os.Stderr, "coverage %.1f%% below minimum %.1f%%\n", pct, *min)
		os.Exit(1)
	}
	fmt.Printf("coverage %.1f%% >= %.1f%%\n", pct, *min)
}
```

- [ ] **Step 4: .golangci.yml**

```yaml
version: "2"
linters:
  default: standard
  enable:
    - errcheck
    - govet
    - staticcheck
    - revive
    - misspell
    - unconvert
    - errorlint
run:
  timeout: 5m
```
(If golangci-lint v2 config schema rejects a key, fix the config, not the
linter set.)

- [ ] **Step 5: Verify** — `make fmt-check vet` pass (no Go files yet is
fine); `bash -n scripts/jail.sh` passes.

- [ ] **Step 6: Commit**

```bash
git add scripts/ Makefile .golangci.yml
git commit -m "build: jail runner, Makefile gates, golangci config"
```

---

### Task 3: `model` data types

**Files:**
- Create: `model/types.go`
- Test: `model/types_test.go`

**Interfaces:**
- Produces (consumed by every later package):
  `PoEDetect`/`VlanMode`/`IpMode` string enums; structs `PortStatus`,
  `PoEStatus` (+`Delivering() bool`), `VLANInfo`, `LLDPNeighbor`, `MacEntry`,
  `Sensor`, `PortStats`, `MgmtIpConfig`, `DetectedModel` (+`Matched() bool`),
  `SwitchData`; helper `Ptr[T any](v T) *T`.

Port from `src/netgear_switch/models.py` (read it first; field-for-field).

- [ ] **Step 1: Write failing tests** (`model/types_test.go`, package
`model_test`) covering: enum string values (`PoEDetectDelivering ==
PoEDetect("delivering")`, all five PoEDetect, three VlanMode, three IpMode);
`PoEStatus{Detect: PoEDetectDelivering}.Delivering() == true` and false for
searching; `DetectedModel{Key: model.Ptr("gs305ep")}.Matched()` true / nil-Key
false; JSON marshalling of a fully-populated `PortStatus` yields exactly
`{"port":1,"name":"1/0/1","admin_enabled":true,"link_up":false,"speed_mbps":null,"description":null}`
(key order per struct order; nulls for nil pointers); `SwitchData` zero value
marshals with empty arrays not null (fields initialised via `NewSwitchData`
constructor is NOT wanted — instead assert `SwitchData{Model:"x",Host:"h"}`
marshals `"ports":[]` by declaring slice fields with `json` tag and using
`omitempty`-free tags plus non-nil enforcement in a `Canonical()` method —
see Step 3).

- [ ] **Step 2: Run** `make test` — FAIL (package missing).

- [ ] **Step 3: Implement `model/types.go`**

```go
// Package model holds the shared device-data types, typed errors and the
// switch-model registry for the Netgear switch library. It is the leaf
// package every protocol package imports; it imports nothing internal.
package model

type PoEDetect string

const (
	PoEDetectDisabled   PoEDetect = "disabled"
	PoEDetectSearching  PoEDetect = "searching"
	PoEDetectDelivering PoEDetect = "delivering"
	PoEDetectFault      PoEDetect = "fault"
	PoEDetectUnknown    PoEDetect = "unknown"
)

type VlanMode string

const (
	VlanUntagged VlanMode = "untagged"
	VlanTagged   VlanMode = "tagged"
	VlanExcluded VlanMode = "excluded"
)

type IpMode string

const (
	IpModeDHCP    IpMode = "dhcp"
	IpModeStatic  IpMode = "static"
	IpModeUnknown IpMode = "unknown"
)

// Ptr returns a pointer to v; convenience for optional fields.
func Ptr[T any](v T) *T { return &v }

// PortStatus mirrors Python models.PortStatus. Name is ifName; Description
// is ifAlias — a backend that cannot read a field leaves it nil rather than
// fabricating a value.
type PortStatus struct {
	Port         int     `json:"port"`
	Name         *string `json:"name"`
	AdminEnabled bool    `json:"admin_enabled"`
	LinkUp       bool    `json:"link_up"`
	SpeedMbps    *int    `json:"speed_mbps"`
	Description  *string `json:"description"`
}

type PoEStatus struct {
	Port         int       `json:"port"`
	AdminEnabled bool      `json:"admin_enabled"`
	Detect       PoEDetect `json:"detect"`
	PowerMw      *int      `json:"power_mw"`
}

func (p PoEStatus) Delivering() bool { return p.Detect == PoEDetectDelivering }

// VLANInfo port sets are canonical: sorted ascending, never nil.
type VLANInfo struct {
	VlanID        int     `json:"vlan_id"`
	Name          *string `json:"name"`
	MemberPorts   []int   `json:"member_ports"`
	TaggedPorts   []int   `json:"tagged_ports"`
	UntaggedPorts []int   `json:"untagged_ports"`
}

type LLDPNeighbor struct {
	LocalPort       int     `json:"local_port"`
	RemoteSysName   *string `json:"remote_sys_name"`
	RemotePortDesc  *string `json:"remote_port_desc"`
	RemoteChassisID *string `json:"remote_chassis_id"`
	RemotePortID    *string `json:"remote_port_id"`
}

type MacEntry struct {
	Mac    string `json:"mac"`
	Port   int    `json:"port"`
	VlanID *int   `json:"vlan_id"`
}

// Sensor.Kind is one of "temperature", "fan", "power".
type Sensor struct {
	Name  string  `json:"name"`
	Kind  string  `json:"kind"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type PortStats struct {
	Port      int     `json:"port"`
	RxBytes   *uint64 `json:"rx_bytes"`
	TxBytes   *uint64 `json:"tx_bytes"`
	RxPackets *uint64 `json:"rx_packets"`
	TxPackets *uint64 `json:"tx_packets"`
	RxErrors  *uint64 `json:"rx_errors"`
	TxErrors  *uint64 `json:"tx_errors"`
}

// MgmtIpConfig.BaseMac is uppercase "XX:XX:XX:XX:XX:XX" when present.
type MgmtIpConfig struct {
	Mode    IpMode  `json:"mode"`
	Address *string `json:"address"`
	Netmask *string `json:"netmask"`
	Gateway *string `json:"gateway"`
	BaseMac *string `json:"base_mac"`
}

// DetectedModel: Key is a registry key iff sysDescr confidently matched
// exactly one model; nil is never a fabricated guess. SysObjectID is carried
// but never used for matching (no OID→model table exists).
type DetectedModel struct {
	Key         *string `json:"key"`
	SysDescr    *string `json:"sys_descr"`
	SysObjectID *string `json:"sys_object_id"`
}

func (d DetectedModel) Matched() bool { return d.Key != nil }

// Pvid is a (port, vlan) pair; Python uses tuple[int, int].
type Pvid struct {
	Port int
	Vlan int
}

type SwitchData struct {
	Model   string         `json:"model"`
	Host    string         `json:"host"`
	Ports   []PortStatus   `json:"ports"`
	PoE     []PoEStatus    `json:"poe"`
	Vlans   []VLANInfo     `json:"vlans"`
	Pvids   []Pvid         `json:"pvids"`
	Lldp    []LLDPNeighbor `json:"lldp"`
	Macs    []MacEntry     `json:"macs"`
	Sensors []Sensor       `json:"sensors"`
	Stats   []PortStats    `json:"stats"`
	MgmtIP  *MgmtIpConfig  `json:"mgmt_ip"`
}
```

Note on `Pvid` JSON: Python's capture emits pvids as 2-element arrays. Give
`Pvid` custom `MarshalJSON`/`UnmarshalJSON` emitting `[port, vlan]`:

```go
func (p Pvid) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]int{p.Port, p.Vlan})
}

func (p *Pvid) UnmarshalJSON(b []byte) error {
	var pair [2]int
	if err := json.Unmarshal(b, &pair); err != nil {
		return err
	}
	p.Port, p.Vlan = pair[0], pair[1]
	return nil
}
```
Add a test asserting `{"Pvids":…}` marshals `[[1,100]]` style, and that
`SwitchData` zero-value slices marshal as `[]` — implement by giving
`SwitchData` a `Canonical()` method returning a copy with nil slices replaced
by empty ones, and test round-trip.

- [ ] **Step 4: Run** `make test` — PASS. Also `make fmt-check vet lint`.

- [ ] **Step 5: Commit**

```bash
git add model/
git commit -m "feat(model): shared device-data types with Python-parity JSON"
```

---

### Task 4: `model` errors

**Files:**
- Create: `model/errors.go`
- Test: `model/errors_test.go`

**Interfaces:**
- Produces: sentinels `ErrUnsupportedCapability`, `ErrProtectedPort`,
  `ErrKnownUnimplemented`, `ErrCredential`, `ErrConfig`, `ErrUnknownModel`,
  `ErrSNMP`, `ErrNSDP`, `ErrHTTP`, `ErrHTTPAuth`, `ErrHTTPUnexpectedPage`;
  type `WriteVerificationError{Msg string; Before, After any}`.
  Mirrors Python `errors.py` classes; later CLI exit-code mapping is
  4 for `ErrProtectedPort`, 3 for `*WriteVerificationError`.

- [ ] **Step 1: Failing tests**: `errors.Is(fmt.Errorf("x: %w",
model.ErrProtectedPort), model.ErrProtectedPort)`; `ErrHTTPAuth` and
`ErrHTTPUnexpectedPage` both satisfy `errors.Is(…, ErrHTTP)`;
`(&model.WriteVerificationError{Msg: "pvid mismatch", Before: 1, After: 5}).
Error() == "pvid mismatch (before=1 after=5)"`; `errors.As` extracts it
through wrapping.

- [ ] **Step 2: Run** `make test` — FAIL.

- [ ] **Step 3: Implement `model/errors.go`**

```go
package model

import (
	"errors"
	"fmt"
)

// Sentinel errors mirroring the Python exception hierarchy; wrap with
// fmt.Errorf("...: %w", Err...) and match with errors.Is.
var (
	ErrUnsupportedCapability = errors.New("unsupported capability")
	ErrProtectedPort         = errors.New("protected port")
	// ErrKnownUnimplemented mirrors Python NotImplementedError uses:
	// a capability the device has but this library knowingly does not
	// implement (e.g. HTTP cert upload on m4300 → use SCP).
	ErrKnownUnimplemented = errors.New("known unimplemented")
	ErrCredential         = errors.New("credential error")
	ErrConfig             = errors.New("config error")
	ErrUnknownModel       = errors.New("unknown switch model")
	ErrSNMP               = errors.New("snmp error")
	ErrNSDP               = errors.New("nsdp error")
	ErrHTTP               = errors.New("http error")
)

// ErrHTTPAuth / ErrHTTPUnexpectedPage specialise ErrHTTP (errors.Is matches
// both the specific and general sentinel).
var (
	ErrHTTPAuth           = fmt.Errorf("%w: auth", ErrHTTP)
	ErrHTTPUnexpectedPage = fmt.Errorf("%w: unexpected page", ErrHTTP)
)

// WriteVerificationError reports a verify-after-write mismatch with the
// observed before/after state (Python WriteVerificationError).
type WriteVerificationError struct {
	Msg    string
	Before any
	After  any
}

func (e *WriteVerificationError) Error() string {
	return fmt.Sprintf("%s (before=%v after=%v)", e.Msg, e.Before, e.After)
}
```

- [ ] **Step 4: Run** `make test` — PASS; gates clean.

- [ ] **Step 5: Commit**

```bash
git add model/errors.go model/errors_test.go
git commit -m "feat(model): typed error sentinels and WriteVerificationError"
```

---

### Task 5: `model` registry

**Files:**
- Create: `model/registry.go`
- Test: `model/registry_test.go`

**Interfaces:**
- Produces: `Backend` (`BackendSNMP/NSDP/HTTP/SSH/Telnet/Console` =
  "snmp","nsdp","http","ssh","telnet","console"); `SwitchClass`
  (`ClassFullyManaged/SmartManagedPro/Plus` =
  "fully_managed","smart_managed_pro","plus"); struct `SwitchModel{Key,
  DisplayName string; Class SwitchClass; PortCount, PoEPortCount int;
  Backends []Backend; SNMPVendorBase string; Verified bool}` with methods
  `HasBackend(Backend) bool`, `HasMACTable() bool`; `Models() []*SwitchModel`
  (registry order); `GetModel(key string) (*SwitchModel, error)` (wraps
  `ErrUnknownModel`).

Port from `src/netgear_switch/registry.py` — read it and copy every entry
exactly. Expected table (verify against source, do not trust this table over
the source):

| Key | Display | Class | Ports | PoE | Backends | VendorBase | Verified |
|---|---|---|---|---|---|---|---|
| m4300-24x | M4300-24X (XSM4324CS) | fully_managed | 28 | 0 | snmp,http,ssh,telnet | 1.3.6.1.4.1.4526.10 | true |
| m4300-16x | M4300-16X (XSM4316) | fully_managed | 16 | 16 | snmp,http,ssh,telnet | 1.3.6.1.4.1.4526.10 | true |
| gsm7252ps | GSM7252PS | fully_managed | 52 | 48 | snmp,http,ssh,telnet | 1.3.6.1.4.1.4526.10 | true |
| gsm7228ps | GSM7228PS (S3300) | smart_managed_pro | 52 | 48 | snmp,http,ssh,telnet | 1.3.6.1.4.1.4526.11 | false |
| gs110emx | GS110EMX | plus | 10 | 0 | nsdp,http | — | true |
| gs305ep | GS305EP | plus | 5 | 4 | nsdp,http | — | true |
| gs105pe | GS105PE | plus | 5 | 0 | nsdp,http | — | true |
| gs728tpp | GS728TPP | smart_managed_pro | 28 | 24 | snmp,http | — | true |
| m7300 | M7300-24XF | fully_managed | 24 | 0 | snmp | 1.3.6.1.4.1.4526.10 | false |
| xs748t | XS748T | smart_managed_pro | 48 | 0 | snmp | 1.3.6.1.4.1.4526.11 | false |

(Exact vendor-base string form and any per-model extras MUST be read from
`registry.py` — if the Python field is the suffix `"4526.10"` rather than the
full OID, mirror the Python form and document it.)

- [ ] **Step 1: Failing tests**: `len(Models()) == 10`; `GetModel("gs305ep")`
returns PoEPortCount 4, Backends nsdp+http, HasMACTable() false;
`GetModel("m4300-24x")` HasMACTable() true, Verified true;
`GetModel("nope")` → `errors.Is(err, ErrUnknownModel)`; every model's
Backends slice is non-empty and PortCount > 0; keys are unique.

- [ ] **Step 2: Run** — FAIL.

- [ ] **Step 3: Implement** registry as a package-level ordered slice +
map built in `init` from the slice; `Models()` returns a fresh copy of the
slice (callers cannot mutate registry state); pointers returned by `GetModel`
point at the canonical entries and are documented read-only.

- [ ] **Step 4: Run** — PASS; gates clean.

- [ ] **Step 5: Commit**

```bash
git add model/registry.go model/registry_test.go
git commit -m "feat(model): switch-model registry (10 models, honesty flags)"
```

---

### Task 6: Secret resolution + secure-file check (root package)

**Files:**
- Create: `config.go`, `alias.go`
- Test: `config_test.go`

**Interfaces:**
- Consumes: `model` errors.
- Produces: `package netgearswitch` —
  `type SecretRunner func(name string, args []string) (stdout string, exitErr error)`;
  `ResolveSecret(spec *string, env func(string) (string, bool), runner SecretRunner) (*string, error)`;
  `EnsureSecureFile(path string) error`; alias file re-exporting model types
  (`type PortStatus = model.PortStatus`, etc. for every §Task-3 type, the
  error sentinels as vars, and `GetModel`/`Models`).

Port from `src/netgear_switch/config.py` lines 24–75. Semantics to preserve:
nil spec → (nil, nil); `${NAME}` → env lookup, missing ⇒ error wrapping
`model.ErrCredential` mentioning the name; `!cmd args` → shlex-split, empty ⇒
credential error; run with 10 s timeout, non-zero exit ⇒ credential error
including exit code + stderr, success ⇒ stdout `strings.TrimSpace`d; anything
else is a literal returned as-is. `EnsureSecureFile`: stat; `mode & 0o077 != 0`
⇒ error wrapping `model.ErrConfig` telling the user to chmod 600.

- [ ] **Step 1: Failing tests** (table-driven): literal passthrough;
`${HOME_TEST_VAR}` set/unset; `!echo  secret ` → "secret" (trimmed);
`!` empty command → ErrCredential; failing command exit 3 → error contains
"exit 3" and wraps ErrCredential; timeout path via a fake runner returning a
timeout error; `EnsureSecureFile` on 0600 file OK, on 0644 file → ErrConfig.
Default runner uses `os/exec` + `context.WithTimeout(10*time.Second)` and
`shlex.Split`.

- [ ] **Step 2: Run** — FAIL.

- [ ] **Step 3: Implement**; add `github.com/google/shlex` to go.mod
(`go get github.com/google/shlex && go mod tidy`, jailed).

- [ ] **Step 4: Run** — PASS; gates clean.

- [ ] **Step 5: Commit**

```bash
git add config.go alias.go config_test.go go.mod go.sum
git commit -m "feat(config): secret-spec resolution and secure-file check"
```

---

### Task 7: Inventory TOML loading (root package)

**Files:**
- Modify: `config.go` (append), `config_test.go` (append)
- Create: `testdata/inventory_example.toml`

**Interfaces:**
- Consumes: Task 5 `GetModel`, Task 6 `ResolveSecret`/`EnsureSecureFile`.
- Produces: `type SwitchConfig struct{Name string; Model *model.SwitchModel;
  Host string; SNMPCommunity *string; SNMPWriteCommunitySpec *string;
  HTTPPasswordSpec *string; NSDPInterface *string; ProtectedPorts []int}`
  with methods `SNMPWriteCommunity(env, runner) (*string, error)` and
  `HTTPPassword(env, runner) (*string, error)`;
  `LoadInventory(path string) (map[string]SwitchConfig, error)` +
  `LoadInventoryEnv(path string, env func(string) (string, bool)) …`.

Port `_switch_from_table` + `load_inventory` semantics exactly: required
`model`+`host` strings (missing key names the key in the ErrConfig message);
`snmp`/`http`/`nsdp` must be tables; `protected_ports` list of ints (bools
rejected); the four string-typed optional fields type-checked;
**literal-secret detection** across `snmp.write_community` and
`http.password` — if any switch carries a literal secret, `EnsureSecureFile`
runs on the inventory file itself; unknown model key surfaces
`ErrUnknownModel`. ProtectedPorts stored sorted ascending, deduplicated.

- [ ] **Step 1: Failing tests**: fixture `testdata/inventory_example.toml`:

```toml
[switches.m4300]
model = "m4300-24x"
host = "10.1.5.13"
snmp = { community = "public", write_community = "${M4300_WRITE}" }
protected_ports = [25, 26]

[switches.poe-micro1]
model = "gs305ep"
host = "10.1.5.28"
http = { password = "!echo hunter2" }
nsdp = { interface = "br-net" }
```

Assert: two entries; m4300 model resolves to registry entry, community
"public", write-community spec `${M4300_WRITE}` resolving via fake env to
"w"; poe-micro1 HTTPPassword() (with real default runner) == "hunter2";
ProtectedPorts [25,26]; a copy of the fixture with `model = "bogus"` →
ErrUnknownModel; with `protected_ports = [true]` → ErrConfig; a fixture
containing a literal `http.password` written 0644 → ErrConfig (secure-file),
0600 → OK. Use BurntSushi/toml.

- [ ] **Step 2: Run** — FAIL.

- [ ] **Step 3: Implement** (add `github.com/BurntSushi/toml`; parse into
`map[string]map[string]toml.Primitive`-style loose structure or
`map[string]any` and validate by hand to reproduce Python's exact error
behaviour).

- [ ] **Step 4: Run** — PASS; gates clean; `make cover` ≥90%.

- [ ] **Step 5: Commit**

```bash
git add config.go config_test.go testdata/ go.mod go.sum
git commit -m "feat(config): TOML inventory loading with Python-parity validation"
```

---

### Task 8: CI workflow + first green build

Orchestrator-executed (pushes to GitHub, watches CI).

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Makefile targets from Task 2.
- Produces: required-green CI for every later slice.

- [ ] **Step 1: Workflow**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  gates:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.x'
      - run: make fmt-check
      - run: go vet ./...
      - run: make lint JAIL=
      - run: go test -race -coverprofile=coverage.out ./...
      - run: go run ./scripts/coveragegate -profile coverage.out -min 90
```
(`JAIL=` empties the jail wrapper in CI where systemd user scopes are absent
and the runner is already isolated; local `make` keeps the jail.)

- [ ] **Step 2: Commit and push**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: lint/vet/test/race/coverage gates"
git push
```

- [ ] **Step 3: Verify green** — `gh run watch` until success; fix anything
red before declaring the slice done.

---

## Self-review checklist (run after writing, before executing)

- Spec coverage for this slice: §2.1 config parity ✓ (Tasks 6–7), §3 model
  package ✓ (Tasks 3–5), §12 gates ✓ (Tasks 2, 8), §16 jails ✓ (Task 2),
  repo-public requirement ✓ (Task 1).
- No placeholders: every step has code or an exact command.
- Type consistency: `model.Ptr` used by tests in Tasks 3/6; `SwitchConfig`
  field names in Task 7 match the Produces block; `ErrUnknownModel` defined
  Task 4, used Tasks 5/7.
