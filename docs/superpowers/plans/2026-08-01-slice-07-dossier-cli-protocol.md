# FASTPATH CLI Protocol Layer — Porting Dossier (Slice 07)

**Pinned Python reference:** `python-netgear-switch-library` @
`7ebfe5d475411a7d88fd5cc68ff86ee3a4505362` (snapshot worktree:
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-7ebfe5d`,
committed 2026-07-31 15:41:29 +0930). **Pin guard verified:**
`git -C <snapshot> rev-parse HEAD` == `7ebfe5d475411a7d88fd5cc68ff86ee3a4505362`.
This snapshot repo is read-only; every quote below is verbatim from that state.
Where this dossier and the pinned source disagree, the source wins.

**Scope (slice 07):** the FASTPATH device-CLI PROTOCOL layer only:
`src/netgear_switch/protocols/cli/commands.py` (441 lines including trailing
newline; 440 `wc -l`), `src/netgear_switch/protocols/cli/parse.py` (676/677
lines), `src/netgear_switch/cli_read.py` (107 lines), `src/netgear_switch/cli_write.py`
(666/667 lines). Context-only citations: `protocols/cli/__init__.py` (1 line,
a module docstring only — no code), `errors.py` (CLI-relevant exception
types), `registry.py` (`Backend`, `SwitchModel`, per-model CLI capability
flags), and `transport/cli/session.py` (the `CliSession` protocol + shared
`ShellDriver` byte-framing that `cli_read.py`/`cli_write.py` depend on — cited
because the write-safety and command-sequencing sections are meaningless
without knowing exactly what `session.run`/`run_scp_copy`/`run_write_memory`
guarantee). **Explicitly OUT of scope** per the task: the top-level `cli/`
end-user package (`cli/main.py`, `cli/resolve.py`, `cli/safety.py`,
`cli/context.py`, `cli/format.py`) — that is the `gngsw` terminal tool, a
different slice, and is not read or cited here.

**Audience:** Go engineers porting the FASTPATH CLI protocol layer 1:1
without reading the Python source themselves.

---

## 0. Architecture overview

FASTPATH is NETGEAR's managed-switch CLI firmware (Fully Managed M4300/GSM7252PS
and Smart Managed Pro GSM7228PS/S3300 lines). The Python library talks to it
over three transports that all speak the identical shell protocol — SSH,
TELNET, CONSOLE (serial) — via one shared `CliSession` interface
(`transport/cli/session.py:50-72`) and one shared byte-framing driver,
`ShellDriver` (`transport/cli/session.py:79-241`). Four layers, cleanly
separated:

1. **`protocols/cli/commands.py`** — pure data: which command string each op
   sends, per model (`CliModelSpec`).
2. **`protocols/cli/parse.py`** — pure functions: device output text → the
   library's public model dataclasses. Zero I/O.
3. **`cli_read.py`** (`CliReader`) — glues 1+2 together over a live
   `CliSession`: for each read op, run the right command(s), parse the text.
4. **`cli_write.py`** (`CliWriter` + `deploy_certificate_scp`) — config-mode
   command sequences, safety gating (`ProtectedPortError`/`force`),
   verify-after-write via `CliReader`, and the SCP certificate deploy path.

The read/write split mirrors the SNMP/HTTP backends exactly (same op
vocabulary, same `WriteVerificationError` contract), which is the point per
`cli_write.py:150` ("the CALLER chooses one (CLAUDE.md principle 2)").

---

## 1. `protocols/cli/commands.py` — every command string, per model

### 1.1 `CLI_BACKENDS` (line 60)

```python
CLI_BACKENDS = frozenset({Backend.SSH, Backend.TELNET, Backend.CONSOLE})
```

A model with ANY of these three `Backend` enum members in its `SwitchModel.backends`
set uses the `CliModelSpec` machinery. `Backend` is defined in `registry.py:19-29`:
`SNMP`, `NSDP`, `HTTP`, `SSH`, `TELNET`, `CONSOLE`. `CONSOLE` (serial) is "a
transport option, not a network-reachable backend, so it is not registered on
any model" (`registry.py:25-29`) — no `SwitchModel` in the pinned registry
carries `Backend.CONSOLE`.

### 1.2 `CliModelSpec` dataclass — every field, with its default command string

Full field list, `commands.py:63-234` (`@dataclass(frozen=True)`):

| Field | Default | Purpose |
|---|---|---|
| `model_key: str` | — | registry key this spec is for |
| `captured: bool` | — | True only if backed by a REAL captured CLI transcript |
| `reads_verified: bool` | — | True if live CLI-vs-SNMP cross-verified |
| `writes_verified: bool` | `True` | True once the CLI WRITE path was driven against real hardware |
| `telnet_port: int` | `23` | TCP port the TELNET transport dials; only S3300 overrides (60000) |
| `enable_cmd: str` | `"enable"` | session-setup: enter privileged EXEC |
| `paging_off_cmd: str` | `"terminal length 0"` | session-setup: disable paging |
| `version_cmd: str` | `"show version"` | `identify()` |
| `port_status_cmd: str` | `"show port all"` | `get_ports()` |
| `vlan_brief_cmd: str` | `"show vlan brief"` | `get_vlans()` step 1 (VLAN ids+names) |
| `vlan_detail_cmd: str` | `"show vlan {vlan}"` | `get_vlans()` step 2 per VLAN (templated) |
| `pvid_cmd: str` | `"show vlan port all"` | `get_pvids()` |
| `mac_table_cmd: str` | `"show mac-addr-table"` | `get_macs()` |
| `lldp_cmd: str` | `"show lldp remote-device all"` | `get_lldp()` |
| `poe_cmd: str` | `"show poe port info all"` | `get_poe()` |
| `environment_cmd: str` | `"show environment"` | `get_sensors()` |
| `network_cmd: str` | `"show network"` | `get_mgmt_ip()` |
| `interface_stats_cmd: str` | `"show interface ethernet {iface}"` | `get_stats()` per port (templated) |
| `iface_template: str` | `"1/0/{port}"` | how this firmware ADDRESSES a physical port in a command |
| `uplink_iface_template: str \| None` | `None` | separate template for uplink ports (S3300 only) |
| `first_uplink_port: int \| None` | `None` | first port number that uses `uplink_iface_template` |
| `vlan_database_cmd: str` | `"vlan database"` | enter VLAN-database config mode |
| `vlan_create_cmd: str` | `"vlan {vlan}"` | create a VLAN (inside `vlan database`) |
| `vlan_name_cmd: str` | `"vlan name {vlan} {name}"` | name a VLAN |
| `vlan_delete_cmd: str` | `"no vlan {vlan}"` | delete a VLAN |
| `configure_cmd: str` | `"configure"` | enter global config mode |
| `interface_cmd: str` | `"interface {iface}"` | enter interface config mode (templated) |
| `switchport_general_cmd: str \| None` | `"switchport mode general"` | prelude for per-port VLAN commands to take effect; `None` on images with no switchport-mode concept |
| `vlan_participation_cmd: str` | `"vlan participation {action} {vlan}"` | include/exclude a VLAN on the current interface |
| `vlan_tagging_cmd: str` | `"vlan tagging {vlan}"` | tag the current interface in a VLAN |
| `vlan_no_tagging_cmd: str` | `"no vlan tagging {vlan}"` | untag the current interface in a VLAN |
| `vlan_pvid_cmd: str` | `"vlan pvid {vlan}"` | set PVID on the current interface |
| `exit_cmd: str` | `"exit"` | leave one config-mode level |
| `poe_enable_cmd: str` | `"poe"` | enable PoE (interface config mode) |
| `poe_disable_cmd: str` | `"no poe"` | disable PoE |
| `poe_reset_cmd: str` | `"poe reset"` | atomic PoE re-arm |
| `port_enable_cmd: str` | `"no shutdown"` | admin-enable port |
| `port_disable_cmd: str` | `"shutdown"` | admin-disable port |
| `mgmt_ip_exec_cmds: tuple[str, ...]` | `("network parms {address} {netmask} {gateway}",)` | privileged-EXEC mgmt-IP dialect |
| `mgmt_ip_config_cmds: tuple[str, ...]` | `()` | global-config mgmt-IP dialect (M4300 only) |
| `reload_cmd: str` | `"reload"` | reboot |

Exactly one of `mgmt_ip_exec_cmds`/`mgmt_ip_config_cmds` is non-empty per
model (`commands.py:167`).

### 1.3 `CliModelSpec` methods — exact templating logic (lines 175-233)

```python
def vlan_detail(self, vlan: int) -> str:
    return self.vlan_detail_cmd.format(vlan=vlan)

def iface(self, port: int) -> str:
    """The interface NAME this firmware addresses physical ``port`` by."""
    if (
        self.uplink_iface_template is not None
        and self.first_uplink_port is not None
        and port >= self.first_uplink_port
    ):
        return self.uplink_iface_template.format(port=port)
    return self.iface_template.format(port=port)

def interface_stats(self, port: int) -> str:
    return self.interface_stats_cmd.format(iface=self.iface(port))

def vlan_create(self, vlan: int) -> str:
    return self.vlan_create_cmd.format(vlan=vlan)

def vlan_name(self, vlan: int, name: str) -> str:
    return self.vlan_name_cmd.format(vlan=vlan, name=name)

def vlan_delete(self, vlan: int) -> str:
    return self.vlan_delete_cmd.format(vlan=vlan)

def interface(self, port: int) -> str:
    return self.interface_cmd.format(iface=self.iface(port))

def vlan_participation(self, vlan: int, *, include: bool) -> str:
    return self.vlan_participation_cmd.format(
        action="include" if include else "exclude", vlan=vlan
    )

def vlan_tagging(self, vlan: int, *, tagged: bool) -> str:
    cmd = self.vlan_tagging_cmd if tagged else self.vlan_no_tagging_cmd
    return cmd.format(vlan=vlan)

def vlan_pvid(self, vlan: int) -> str:
    return self.vlan_pvid_cmd.format(vlan=vlan)

def poe_admin(self, *, on: bool) -> str:
    return self.poe_enable_cmd if on else self.poe_disable_cmd

def port_admin(self, *, enabled: bool) -> str:
    return self.port_enable_cmd if enabled else self.port_disable_cmd

def mgmt_ip(
    self, address: str, netmask: str, gateway: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    fmt = {"address": address, "netmask": netmask, "gateway": gateway}
    return (
        tuple(c.format(**fmt) for c in self.mgmt_ip_exec_cmds),
        tuple(c.format(**fmt) for c in self.mgmt_ip_config_cmds),
    )
```

`iface(port)` (lines 178-186) is THE critical per-model addressing function:
uplink ports (S3300 only, `port >= first_uplink_port`) get a DIFFERENT
template than access ports. Every per-port command — read-side
`interface_stats` and write-side `interface` — routes through it.

### 1.4 `_CliCmdOverrides` TypedDict (lines 236-244)

```python
class _CliCmdOverrides(TypedDict, total=False):
    vlan_brief_cmd: str
    network_cmd: str
    mgmt_ip_exec_cmds: tuple[str, ...]
    mgmt_ip_config_cmds: tuple[str, ...]
```
Purpose per its docstring: "typed so `**` splatting into `CliModelSpec`
cannot touch `telnet_port` or any other int field" — a Go port should express
this as a small "overrides" struct (or explicit named constructor args), not
untyped map splatting, to preserve the same compile-time guarantee.

### 1.5 `_M4300_OVERRIDES` (lines 259-267) — exact dict

```python
_M4300_OVERRIDES: _CliCmdOverrides = {
    "vlan_brief_cmd": "show vlan",
    "network_cmd": "show ip management",
    "mgmt_ip_exec_cmds": (),
    "mgmt_ip_config_cmds": (
        "ip management address {address} {netmask}",
        "ip default-gateway {gateway}",
    ),
}
```
Rationale comment (lines 247-258): M4300 FASTPATH 12.0.13.8 renamed two read
commands vs the older gsm7252ps image — `"show vlan brief"` → `"show vlan"`
("show vlan brief" is Invalid input on M4300); `"show network"` → `"show ip
management"` ("show network" deprecated). The write path moved with the
read: M4300 has no `network parms` at all ("verified 2026-07-30 — '%
Unrecognized command' in both privileged EXEC and global config on
10.1.5.20").

### 1.6 The four `CliModelSpec` instances — EXHAUSTIVE (4 of 4)

**`_GSM7252PS`** (lines 282-287):
```python
_GSM7252PS = CliModelSpec(
    model_key="gsm7252ps",
    captured=True,
    reads_verified=True,
    switchport_general_cmd=None,
)
```
Everything else defaults. Key fact: `switchport_general_cmd=None` — this XE
image has NO switchport-mode concept at all (`"switchport mode ?"` →
`"% Unrecognized command"`, `"switchport ?"` offers only
private-group/protected — comment lines 271-276). `iface_template` stays the
default `"1/0/{port}"`.

**`_M4300_24X`** (lines 298-300):
```python
_M4300_24X = CliModelSpec(
    model_key="m4300-24x", captured=True, reads_verified=True, **_M4300_OVERRIDES
)
```
Takes the four `_M4300_OVERRIDES` fields; everything else (including
`switchport_general_cmd="switchport mode general"` and `iface_template=
"1/0/{port}"`) defaults. PoE absent on this SKU (`registry.py` `poe_port_count=0`).

**`_M4300_16X`** (lines 313-315):
```python
_M4300_16X = CliModelSpec(
    model_key="m4300-16x", captured=True, reads_verified=True, **_M4300_OVERRIDES
)
```
Same overrides as `_M4300_24X`. PoE-equipped (16 ports).

**`_GSM7228PS`** (S3300-52X) (lines 341-351):
```python
_GSM7228PS = CliModelSpec(
    model_key="gsm7228ps",
    captured=True,
    reads_verified=True,
    telnet_port=60000,
    vlan_brief_cmd="show vlan",
    network_cmd="show network",
    iface_template="1/g{port}",
    uplink_iface_template="1/xg{port}",
    first_uplink_port=49,
)
```
This is the one model that takes ONLY HALF of `_M4300_OVERRIDES`
(`vlan_brief_cmd` overridden to `"show vlan"` like the M4300s, but
`network_cmd` stays `"show network"` — NOT M4300's `"show ip management"` —
and `mgmt_ip_exec_cmds` stays the DEFAULT privileged-EXEC `"network parms
..."` form, unlike the M4300s). `switchport_general_cmd` stays the default
`"switchport mode general"` — unlike gsm7252ps, this Smart firmware DOES have
switchport modes (`"switchport mode ?"` → `access|general|trunk`, comment
line 325). Physical port naming is UNIQUE: `1/g1`..`1/g48` (access) and
`1/xg49`..`1/xg52` (10G uplinks), confirmed against the model's own captured
transcripts. `telnet_port=60000` (not the standard 23) — SSH is genuinely
absent on this device (comment `registry.py:199-206`: "the switch runs no ssh
listener on any port").

Model count check: `_SPECS` dict (lines 353-355) has exactly these 4 entries.
**No 5th CLI model exists in the pinned source** — `m7300`, `xs748t`,
`gs728tpp`, `gs105pe`, `gs110emx`, `gs305ep` in `registry.py` do NOT carry
`Backend.SSH`/`TELNET`/`CONSOLE` (confirmed by reading each model's backend
set in `registry.py:129-378` — only `m4300-24x`, `m4300-16x`, `gsm7252ps`
have `{SNMP, HTTP, SSH, TELNET}` and `gsm7228ps` has `{SNMP, HTTP, TELNET}`).

### 1.7 `ScpCertProfile` (lines 360-408) — SSL cert deploy, per-model

```python
@dataclass(frozen=True)
class ScpCertProfile:
    model_key: str
    crypto: str            # "modern" or "legacy"
    writemem_stuff: bool   # True iff the "write memory" (y/n) confirm must be pre-stuffed
    verify_port: int       # HTTPS port for a post-deploy fingerprint check (caller's job)
```
The 3 registered profiles (lines 393-406), EXHAUSTIVE:

| model_key | crypto | writemem_stuff | verify_port |
|---|---|---|---|
| `m4300-24x` | `"modern"` | `False` | `443` |
| `m4300-16x` | `"modern"` | `False` | `49152` |
| `gsm7252ps` | `"legacy"` | `True` | `443` |

`gsm7228ps` deliberately has NO profile: "the Smart Managed Pro line
(gsm7228ps/S3300) uses an HTTP multipart upload instead and is deliberately
absent here" (lines 365-366) — this is a genuine mechanism difference, not an
oversight; `scp_cert_profile()` raises `UnsupportedCapabilityError` for it
(see below).

### 1.8 Dispatch functions

```python
def scp_cert_profile(model: SwitchModel) -> ScpCertProfile:
    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no CLI backend for an SCP cert deploy"
        )
    try:
        return _SCP_CERT_PROFILES[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no known copy-scp SSL-certificate deploy profile"
        ) from None


def cli_spec(model: SwitchModel) -> CliModelSpec:
    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(f"model {model.key!r} has no CLI backend")
    try:
        return _SPECS[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has a CLI backend but no command spec"
        ) from None
```
(lines 411-441) Both are TWO-STAGE guards: first "does this model have ANY
CLI backend at all", then "does this SPECIFIC model have a spec/profile
entry" — two distinct `UnsupportedCapabilityError` messages, not merged. A Go
port must preserve both error paths distinctly (tests may assert on message
content/type).

---

## 2. `protocols/cli/parse.py` — every parser, verbatim

Two output shapes device-side (module docstring, lines 12-25):
* **Labelled scalars**: `Label.......... value` dotted-leader lines.
* **Fixed-width tables**: header + `----` ruler + data rows, sliced strictly
  by the ruler's dash-group spans (NOT `str.split()`, which would corrupt
  cells containing spaces like `"Delivering Power"`).

### 2.1 Primitive regexes (lines 57-69) — EXACT, quote verbatim

```python
_LABEL_RE = re.compile(r"^\s*(.+?)\s*\.{2,}\s*(.*?)\s*$")
_RULER_RE = re.compile(r"^[ \t]*-{2,}[- \t]*$")
_PHYS_IFACE_RE = re.compile(r"^(\d+)/0/(\d+)$")
_SMART_IFACE_RE = re.compile(r"^\d+/x?g(\d+)$")
_MAC_TEXT_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
```
* `_LABEL_RE`: label = group 1 (non-greedy `.+?`, so it stops at the FIRST run
  of 2+ dots), value = group 2 (non-greedy, trailing whitespace stripped by
  `\s*$`). Both groups are ALSO explicitly `.strip()`-ed again in
  `labelled_values` — redundant but harmless.
* `_RULER_RE`: a ruler line is 2+ dashes, optionally surrounded by
  spaces/tabs and MORE dash/space/tab runs — i.e. `"----  ----   ----"`
  matches, a line with any non-dash-space-tab character does not.
* `_PHYS_IFACE_RE`: ONLY matches `unit/0/port` (slot must be literal `0`) —
  captures `(unit, port)`; group 2 is the port number used.
* `_SMART_IFACE_RE`: `unit/g<port>` or `unit/xg<port>` (the `x` is optional
  via `x?`) — captures port number in group 1.
* `_MAC_TEXT_RE`: exactly `XX:XX:XX:XX:XX:XX`, hex pairs, colon-separated,
  case-insensitive by pattern (input is uppercased/matched separately by
  callers).

### 2.2 `labelled_values(text) -> dict[str, str]` (lines 72-85)

```python
def labelled_values(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    return out
```
"Later duplicate labels overwrite earlier ones (only the last wins)"; blank
values map to `""` (not omitted from the dict).

### 2.3 `_ruler_spans(ruler) -> list[tuple[int, int|None]]` (lines 88-112)

```python
def _ruler_spans(ruler: str) -> list[tuple[int, int | None]]:
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(ruler)
    while i < n:
        if ruler[i] == "-":
            start = i
            while i < n and ruler[i] == "-":
                i += 1
            starts.append(start)
            ends.append(i)
        else:
            i += 1
    spans: list[tuple[int, int | None]] = []
    for idx, start in enumerate(starts):
        end: int | None = starts[idx + 1] if idx + 1 < len(starts) else None
        spans.append((start, end))
    return spans
```
Column boundaries are derived ONLY from where each dash-RUN *starts*
(`ends` list is computed but its values are never actually used to build
`spans` — each column's `end` is the NEXT column's `start`, not this
column's own dash-run end). The last column's `end` is `None` (runs to
end-of-line). **This is a subtlety a naive Go port could get wrong**: if you
instead used each dash-run's own end as the column boundary, inter-column
padding immediately after the ruler dashes would NOT belong to the
column to its left, corrupting any cell whose header text overhangs past its
own ruler's dashes.

### 2.4 `_slice_cell`/`_slice_row` (lines 115-122)

```python
def _slice_cell(row: str, start: int, end: int | None) -> str:
    return (row[start:end] if end is not None else row[start:]).strip()

def _slice_row(spans: list[tuple[int, int | None]], row: str) -> list[str]:
    return [_slice_cell(row, start, end) for start, end in spans]
```
Standard Python slice semantics: `row[start:end]` where `end` may exceed
`len(row)` (Python silently truncates — a **Go port must replicate this
"slice past end of short line is not an error, just truncates" behavior**
explicitly, e.g. via `min(end, len(row))` clamping, since Go slicing panics
on an out-of-range index).

### 2.5 `iter_table_rows(text, *, after=None) -> Iterator[list[str]]` (lines 125-146)

```python
def iter_table_rows(text: str, *, after: str | None = None) -> Iterator[list[str]]:
    lines = text.splitlines()
    idx = 0
    if after is not None:
        while idx < len(lines) and after not in lines[idx]:
            idx += 1
    while idx < len(lines) and not _RULER_RE.match(lines[idx]):
        idx += 1
    if idx >= len(lines):
        return
    spans = _ruler_spans(lines[idx])
    for line in lines[idx + 1 :]:
        if not line.strip() or _RULER_RE.match(line):
            break
        yield _slice_row(spans, line)
```
Algorithm: (1) optionally skip forward to the first line CONTAINING the
`after` substring (used to disambiguate `show environment`'s three
sub-tables); (2) from there, skip forward to the first ruler line; (3) if no
ruler found, yield nothing (empty generator, NOT an error — `idx >=
len(lines)` after both scans just returns); (4) slice every subsequent line
by that ruler's spans UNTIL a blank line or another ruler line, INCLUSIVE
stop (that terminating line is NOT yielded). **Edge case**: an empty table
(header + ruler + zero data rows, immediately followed by blank line or EOF)
yields zero rows cleanly — no exception.

### 2.6 `header_columns(text, *, after=None) -> list[str]` (lines 149-182)

```python
def header_columns(text: str, *, after: str | None = None) -> list[str]:
    lines = text.splitlines()
    idx = 0
    if after is not None:
        while idx < len(lines) and after not in lines[idx]:
            idx += 1
    while idx < len(lines) and not _RULER_RE.match(lines[idx]):
        idx += 1
    if idx >= len(lines):
        return []
    spans = _ruler_spans(lines[idx])
    start = idx - 1
    while start >= 0 and lines[start].strip() and not _RULER_RE.match(lines[start]):
        start -= 1
    header_lines = lines[start + 1 : idx]
    names: list[str] = []
    for span_start, span_end in spans:
        pieces = [_slice_cell(hl, span_start, span_end) for hl in header_lines]
        names.append(re.sub(r"\s+", " ", " ".join(p for p in pieces if p)))
    return names
```
Finds the SAME ruler as `iter_table_rows`, then walks BACKWARD from the ruler
collecting the contiguous run of non-blank, non-ruler lines directly above it
(multi-line wrapped headers like `"High Power"` / `"Max Power (mW)"` /
`"Output Current (mA)"` stacked on 2-3 physical lines). Each header line is
sliced by the SAME ruler spans, then per-column pieces are joined with a
single space and whitespace-collapsed (`re.sub(r"\s+", " ", ...)`) — EMPTY
pieces are filtered out of the join (`if p`) so a column whose header text
only occupies row 1 of 3 doesn't get extra leading/trailing spaces. Returns
`[]` (not `None`, not an exception) if no ruler is found at all.

### 2.7 `_int(text) -> int | None` (lines 185-189)

```python
def _int(text: str) -> int | None:
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return None
```
Catches BOTH `ValueError` (non-numeric text) and `AttributeError` (e.g.
`text` is `None` and `.strip()` fails) — a Go port's equivalent helper
should accept a string (Go has no `None` string) but must still treat empty
string / non-numeric text as "no value", not zero.

### 2.8 `_phys_port(iface) -> int | None` (lines 192-204)

```python
def _phys_port(iface: str) -> int | None:
    s = iface.strip()
    m = _PHYS_IFACE_RE.match(s)
    if m:
        return int(m.group(2))
    m = _SMART_IFACE_RE.match(s)
    return int(m.group(1)) if m else None
```
Tries `_PHYS_IFACE_RE` (`"1/0/N"`) FIRST, falls back to `_SMART_IFACE_RE`
(`"1/gN"`/`"1/xgN"`) SECOND. `"lag 1"`, `"vlan 5"`, `"CPU Interface: ..."` →
`None` for both patterns. This function is model-agnostic — it is applied to
EVERY table row regardless of which `CliModelSpec` issued the command, so
both interface-naming dialects are always tried.

### 2.9 `parse_version(text, models) -> DetectedModel` (lines 212-230)

```python
def parse_version(text: str, models: Mapping[str, SwitchModel]) -> DetectedModel:
    from ..snmp.parse import detect_model_from_sysdescr

    fields = labelled_values(text)
    descr = fields.get("System Description") or fields.get("Machine Model") or ""
    key = detect_model_from_sysdescr(descr, models) if descr else None
    return DetectedModel(key=key, sys_descr=descr or None, sys_object_id=None)
```
Command: `show version`. Label map: `System Description` (primary), falls
back to `Machine Model` if absent. `sys_object_id` is ALWAYS `None` — "the
CLI exposes no sysObjectID". Model matching REUSES the SNMP backend's
`detect_model_from_sysdescr` (in `protocols/snmp/parse.py`, imported lazily
inside the function to avoid a module-level cross-protocol import) — "so CLI
and SNMP identify a switch identically". **Go port note**: this cross-package
call means the Go CLI parser package must depend on the SNMP parser package's
sysdescr-matching function (or a shared helper extracted from it) — not
duplicate the matching logic.

### 2.10 `parse_port_status(text) -> list[PortStatus]` (lines 259-288)

Column indices (comment lines 237-241, from `gsm7252ps_show_port_all.txt`):
header is `Intf | Type | Admin Mode | Physical Mode | Physical Status | Link
Status | Link Trap | LACP Mode | Flow Mode`.
```python
_PORT_INTF, _PORT_TYPE, _PORT_ADMIN = 0, 1, 2
_PORT_PHYS_MODE, _PORT_PHYS_STATUS, _PORT_LINK = 3, 4, 5
```
Speed regex and conversion (lines 243-256):
```python
_SPEED_RE = re.compile(r"(\d+)\s*([GgMm]?)")

def _speed_mbps(phys_status: str) -> int | None:
    m = _SPEED_RE.match(phys_status.strip())
    if not m:
        return None
    value = int(m.group(1))
    return value * 1000 if m.group(2).upper() == "G" else value
```
`"1000 Full"` → 1000; `"10G Full"` → 10000; `""` (blank on a down port) →
`None` — "never a fabricated 0". Note the unit letter check is
`.upper() == "G"` — `"m"`/`"M"` and no-suffix both fall through to the plain
`value` (Mbps assumed), so `"m"` is effectively a no-op multiplier despite
being captured by the regex.

Row logic (lines 259-288):
```python
def parse_port_status(text: str) -> list[PortStatus]:
    out: list[PortStatus] = []
    for cells in iter_table_rows(text):
        if len(cells) <= _PORT_LINK:
            continue
        port = _phys_port(cells[_PORT_INTF])
        if port is None:
            continue
        out.append(
            PortStatus(
                port=port,
                name=cells[_PORT_INTF],
                admin_enabled=cells[_PORT_ADMIN].strip().lower() == "enable",
                link_up=cells[_PORT_LINK].strip().lower() == "up",
                speed_mbps=(
                    _speed_mbps(cells[_PORT_PHYS_STATUS])
                    if cells[_PORT_LINK].strip().lower() == "up"
                    else None
                ),
                description=None,
            )
        )
    return out
```
`lag N` rows are skipped (`_phys_port` returns `None` for them — not
explicitly filtered by name). `speed_mbps` is `None` whenever Link Status is
NOT `"up"`, EVEN IF `Physical Status` happens to carry text (defensive — link
down implies no negotiated rate is meaningful). `description` is ALWAYS
`None` — "this command carries no ifAlias column" (honest omission, not a
bug).

### 2.11 `parse_vlan_brief(text) -> list[tuple[int, str]]` (lines 299-312)

Columns (`gsm7252ps_show_vlan_brief.txt`): `VLAN ID | VLAN Name | VLAN Type`.
```python
_VLAN_BRIEF_ID, _VLAN_BRIEF_NAME = 0, 1

def parse_vlan_brief(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for cells in iter_table_rows(text):
        vid = _int(cells[_VLAN_BRIEF_ID]) if cells else None
        if vid is None:
            continue
        name = cells[_VLAN_BRIEF_NAME] if len(cells) > _VLAN_BRIEF_NAME else ""
        out.append((vid, name))
    return out
```
Returns `[(vlan_id, name), ...]` — NO membership data (that requires a
follow-up `show vlan <id>` per VLAN, done by the caller `CliReader.get_vlans`,
see §3). Row with unparseable/absent VLAN ID is skipped; name defaults to
`""` if the row is short (rather than raising `IndexError`).

### 2.12 `parse_vlan_detail(text, *, name=None) -> VLANInfo` (lines 321-358)

Columns (`gsm7252ps_show_vlan_90.txt`): `Interface | Current | Configured |
Tagging`.
```python
_VLAN_D_IFACE, _VLAN_D_CURRENT, _VLAN_D_TAGGING = 0, 1, 3
_VLAN_HEADER_RE = re.compile(r"VLAN ID:\s*(\d+)")
_VLAN_NAME_RE = re.compile(r"VLAN Name:\s*(.*)")

def parse_vlan_detail(text: str, *, name: str | None = None) -> VLANInfo:
    header = {}
    m = _VLAN_HEADER_RE.search(text)
    if m:
        header["id"] = m.group(1)
    nm = _VLAN_NAME_RE.search(text)
    page_name = nm.group(1).strip() if nm else None
    vid = int(header.get("id", "0"))
    tagged: set[int] = set()
    untagged: set[int] = set()
    for cells in iter_table_rows(text):
        if len(cells) <= _VLAN_D_TAGGING:
            continue
        port = _phys_port(cells[_VLAN_D_IFACE])
        if port is None:
            continue
        if cells[_VLAN_D_CURRENT].strip().lower() != "include":
            continue
        if cells[_VLAN_D_TAGGING].strip().lower() == "tagged":
            tagged.add(port)
        else:
            untagged.add(port)
    return VLANInfo(
        vlan_id=vid,
        name=name if name is not None else page_name,
        member_ports=frozenset(tagged | untagged),
        tagged_ports=frozenset(tagged),
        untagged_ports=frozenset(untagged),
    )
```
Note column index 3 for Tagging (Configured, index 2, is DELIBERATELY
skipped — only `Current` (index 1) and `Tagging` (index 3) are consulted).
`vid` defaults to `0` if the `"VLAN ID:"` header is absent (never raises).
`Current != "include"` (case-insensitive) means the port is NOT an egress
member of this VLAN — excluded entirely, not added to either set. `lag N`
rows drop out via `_phys_port` returning `None`. The `name` PARAMETER (passed
by the caller from the `show vlan brief` pass) OVERRIDES the page's own
`"VLAN Name:"` line when non-`None` — this is how `CliReader.get_vlans`
merges the two commands' data (§3.3).

### 2.13 `parse_pvids(text) -> list[tuple[int, int]]` (lines 371-386)

Columns (`gsm7252ps_show_vlan_port_all.txt`): `Interface | Port VLAN ID
Configured | Current | Acceptable Frame Types | Ingress Filtering Configured
| Ingress Filtering Current | GVRP | Default Priority`.
```python
_PVID_IFACE, _PVID_CONFIGURED = 0, 1

def parse_pvids(text: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for cells in iter_table_rows(text):
        if len(cells) <= _PVID_CONFIGURED:
            continue
        port = _phys_port(cells[_PVID_IFACE])
        pvid = _int(cells[_PVID_CONFIGURED])
        if port is None or pvid is None:
            continue
        out.append((port, pvid))
    return out
```
Uses the "Port VLAN ID **Configured**" column (index 1), explicitly NOT
"Current" (index 2) — "matching what dot1qPvid reports over SNMP" (the
persistent/configured value, not any transient current value).

### 2.14 `parse_mac_table(text) -> list[MacEntry]` (lines 398-420)

Columns (`gsm7252ps_show_mac_addr_table.txt`): `VLAN ID | MAC Address |
Interface | IfIndex | Status`.
```python
_MAC_VLAN, _MAC_ADDR, _MAC_IFINDEX = 0, 1, 3

def parse_mac_table(text: str) -> list[MacEntry]:
    out: list[MacEntry] = []
    for cells in iter_table_rows(text):
        if len(cells) <= _MAC_IFINDEX:
            continue
        mac = cells[_MAC_ADDR].strip().upper()
        if not _MAC_TEXT_RE.match(mac):
            continue
        ifindex = _int(cells[_MAC_IFINDEX])
        vlan = _int(cells[_MAC_VLAN])
        if ifindex is None:
            continue
        out.append(MacEntry(mac=mac, port=ifindex, vlan_id=vlan))
    return out
```
Critical: `MacEntry.port` is the **IfIndex column** (index 3), NOT a
`_phys_port`-derived physical port number — "49 for `1/0/49`, 418 for `lag
1`, 417 for the CPU/Management row — the same ifIndex the SNMP FDB join
yields". A malformed MAC (fails `_MAC_TEXT_RE` after `.strip().upper()`)
silently drops the row rather than erroring. `vlan_id` may be `None` (no
`continue` if `_int(cells[_MAC_VLAN])` fails — only `ifindex is None` skips
the row).

### 2.15 `parse_lldp(text) -> list[LLDPNeighbor]` (lines 432-459)

Columns (`gsm7252ps_show_lldp_remote_device_all.txt`): `Local Interface |
RemID | Chassis ID | Port ID | System Name`.
```python
_LLDP_IFACE, _LLDP_CHASSIS, _LLDP_PORTID, _LLDP_SYSNAME = 0, 2, 3, 4

def parse_lldp(text: str) -> list[LLDPNeighbor]:
    out: list[LLDPNeighbor] = []
    for cells in iter_table_rows(text):
        if not cells:
            continue
        if _phys_port(cells[_LLDP_IFACE]) is None:
            continue
        if len(cells) <= _LLDP_SYSNAME or not cells[_LLDP_CHASSIS].strip():
            continue
        out.append(
            LLDPNeighbor(
                local_port=_phys_port(cells[_LLDP_IFACE]),  # type: ignore[arg-type]
                remote_sys_name=cells[_LLDP_SYSNAME].strip() or None,
                remote_port_desc=None,
                remote_chassis_id=cells[_LLDP_CHASSIS].strip().upper() or None,
                remote_port_id=cells[_LLDP_PORTID].strip() or None,
            )
        )
    return out
```
Note RemID (index 1) is skipped entirely — never read. A local-interface row
with NO neighbour (bare `"1/0/6"` with empty trailing cells) is dropped by
the `not cells[_LLDP_CHASSIS].strip()` check. `remote_port_desc` is ALWAYS
`None` — "this command has no port-description column (SNMP's
lldpRemPortDesc is the source for it)". Chassis ID uppercased "to match the
SNMP/HTTP backends". `_phys_port` is called TWICE (once for the filter check,
once for the field value) — same result both times, just not cached (a Go
port MAY memoize this without changing behavior).

### 2.16 `parse_poe(text) -> list[PoEStatus]` (lines 488-530)

**This is the trickiest parser** — the column SET differs by firmware image:
```
gsm7252ps: Intf|High Power|Max Power (mW)|Class|Power (mW)|Output Current (mA)|
           Output Voltage (V)|Temperature|Status|Fault Status   (10 columns)
m4300:     Intf|High Power|Max Power (mW)|Class|Power (mW)|Output Current (mA)|
           Output Voltage (V)|Status|Fault Status               (9 columns)
```
So columns are located by **HEADER NAME via `header_columns()`**, not fixed
index (comment lines 466-475 — this was a REAL bug fixed live, per the git
log entries `71b5826`/`b8b40d5` "fix(cli): parse_poe locates columns by
header name, not fixed index").
```python
_POE_INTF_HDR = "Intf"
_POE_OUTPUT_MW_HDR = "Power (mW)"   # the live draw, NOT "Max Power (mW)"
_POE_STATUS_HDR = "Status"           # the PSE state, NOT "Fault Status"

_POE_DETECT_TEXT: dict[str, PoEDetect] = {
    "delivering": PoEDetect.DELIVERING,
    "searching": PoEDetect.SEARCHING,
    "disabled": PoEDetect.DISABLED,
    "fault": PoEDetect.FAULT,
}

def parse_poe(text: str) -> list[PoEStatus]:
    names = header_columns(text)
    try:
        intf_i = names.index(_POE_INTF_HDR)
        mw_i = names.index(_POE_OUTPUT_MW_HDR)
        status_i = names.index(_POE_STATUS_HDR)
    except ValueError:
        return []
    last = max(intf_i, mw_i, status_i)
    out: list[PoEStatus] = []
    for cells in iter_table_rows(text):
        if len(cells) <= last:
            continue
        port = _phys_port(cells[intf_i])
        if port is None:
            continue
        status = cells[status_i].strip().lower()
        detect = next(
            (v for k, v in _POE_DETECT_TEXT.items() if k in status),
            PoEDetect.UNKNOWN,
        )
        out.append(
            PoEStatus(
                port=port,
                admin_enabled=detect is not PoEDetect.DISABLED,
                detect=detect,
                power_mw=_int(cells[mw_i]),
            )
        )
    return out
```
If ANY of the three required header names is missing, the function returns
`[]` (empty list) rather than raising — a silent-but-honest degrade. Note
`_POE_DETECT_TEXT` matching is SUBSTRING (`k in status`), not equality — the
real device text is `"Delivering Power"` (contains `"delivering"`),
`"Searching"`, `"Disabled"`, and anything containing `"Fault"` — dict
iteration order in Python 3.7+ is insertion order so `"delivering"` is tried
before `"searching"` before `"disabled"` before `"fault"`; since these four
substrings are mutually exclusive in practice this ordering is unlikely to
matter, but a Go port using a map should NOT assume iteration order and
should instead test in the SAME explicit sequence (delivering, searching,
disabled, fault) to be safe. No match → `PoEDetect.UNKNOWN`. **There is NO
admin column on this device output** — `admin_enabled` is INFERRED as
`detect is not PoEDetect.DISABLED` (comment lines 495-497: "a
searching/delivering PSE port is administratively on" — "Documented
inference, not a fabricated field").

### 2.17 `parse_environment(text) -> list[Sensor]` (lines 546-605)

Three sub-tables in one page (`gsm7252ps_show_environment.txt`):
```
Temperature Sensors: Unit | Sensor | Description | Temp (C) | State | Max
Fans:                Unit | Fan | Description | Type | Speed | Duty | State
Power supplies:      Unit | Power supply | Description | Type | State
```
```python
_ENV_TEMP_DESC, _ENV_TEMP_VALUE = 2, 3
_ENV_FAN_DESC, _ENV_FAN_SPEED = 2, 4
_ENV_PSU_DESC, _ENV_PSU_STATE = 2, 4

def parse_environment(text: str) -> list[Sensor]:
    out: list[Sensor] = []
    for cells in iter_table_rows(text, after="Temperature Sensors:"):
        if len(cells) <= _ENV_TEMP_VALUE:
            continue
        value = _int(cells[_ENV_TEMP_VALUE])
        if value is None:
            continue
        out.append(
            Sensor(
                name=cells[_ENV_TEMP_DESC].strip(),
                kind="temperature",
                value=float(value),
                unit="C",
            )
        )
    for cells in iter_table_rows(text, after="Fans:"):
        if len(cells) <= _ENV_FAN_SPEED:
            continue
        rpm = _int(cells[_ENV_FAN_SPEED])
        if rpm is None:
            continue  # "Not Supported" -- absent, not zero
        out.append(
            Sensor(
                name=cells[_ENV_FAN_DESC].strip(),
                kind="fan",
                value=float(rpm),
                unit="RPM",
            )
        )
    psu_after = "Power supplies:" if "Power supplies:" in text else "Power Modules:"
    for cells in iter_table_rows(text, after=psu_after):
        if len(cells) <= _ENV_PSU_STATE:
            continue
        state = cells[_ENV_PSU_STATE].strip().lower()
        out.append(
            Sensor(
                name=cells[_ENV_PSU_DESC].strip(),
                kind="power",
                value=1.0 if state == "operational" else 0.0,
                unit="state",
            )
        )
    return out
```
Three INDEPENDENT calls to `iter_table_rows` with different `after=`
substrings — each call re-scans from line 0 to find its own `after` marker
then its own ruler, so the three sub-tables are located completely
separately (not by continuing from where the previous scan left off).
Emission order in the returned list is FIXED: all temperature sensors, then
all fans, then all power sensors (never interleaved) — `kind` field values
are the literal strings `"temperature"`, `"fan"`, `"power"`. A fan reporting
non-numeric text (`"Not Supported"`) is SKIPPED entirely (not a zero-value
Sensor) — "absent, not zero". PSU health is a synthetic float flag: `1.0` if
state (case-insensitively) equals exactly `"operational"`, else `0.0` for
ANY other state text (no separate "unknown" state — degrades to 0.0). The PSU
sub-table header text itself varies by firmware: `"Power supplies:"`
(gsm7252ps) vs `"Power Modules:"` (M4300 12.0.13.8) — resolved by a plain
substring containment check on the WHOLE input text before calling
`iter_table_rows` a third time.

### 2.18 `parse_mgmt_ip(text) -> MgmtIpConfig` (lines 613-643)

Label map (`gsm7252ps_show_network.txt` / `m4300_24x_show_ip_management`):
```
IP Address               -> address
Subnet Mask              -> netmask
Default Gateway          -> gateway
Burned In MAC Address    -> base_mac (uppercased)
Configured IPv4 Protocol -> mode (DHCP -> DHCP, else STATIC)
```
```python
def parse_mgmt_ip(text: str) -> MgmtIpConfig:
    fields = labelled_values(text)
    proto = (
        (fields.get("Configured IPv4 Protocol") or fields.get("Method") or "")
        .strip()
        .upper()
    )
    mode = (
        IpMode.DHCP if proto == "DHCP" else (IpMode.STATIC if proto else IpMode.UNKNOWN)
    )
    mac = fields.get("Burned In MAC Address", "").strip().upper()
    return MgmtIpConfig(
        mode=mode,
        address=fields.get("IP Address") or None,
        netmask=fields.get("Subnet Mask") or None,
        gateway=fields.get("Default Gateway") or None,
        base_mac=mac if _MAC_TEXT_RE.match(mac) else None,
    )
```
`"show network"` labels the mode field `"Configured IPv4 Protocol"`; M4300's
`"show ip management"` labels the SAME concept `"Method"` — the parser
accepts EITHER label (`Configured IPv4 Protocol` tried first, falls back to
`Method`). Mode logic: exact match `"DHCP"` (case-normalized) → `IpMode.DHCP`;
any OTHER non-empty text → `IpMode.STATIC`; empty/absent → `IpMode.UNKNOWN`.
`address`/`netmask`/`gateway` are `None` if the field is empty/absent
(`fields.get(...) or None` — empty string coerces to `None`). `base_mac` is
validated against `_MAC_TEXT_RE` after uppercasing — an unparseable MAC
becomes `None`, never a raw invalid string.

### 2.19 `parse_interface_counters(text, port) -> PortStats` (lines 660-676)

Label map (`gsm7252ps_show_interface_ethernet_1_0_1.txt`, aligned to the SNMP
backend's `get_stats` fields):
```
Total Packets Received (Octets)        -> rx_bytes  (ifHCInOctets)
Total Packets Transmitted (Octets)     -> tx_bytes  (ifHCOutOctets)
Unicast Packets Received               -> rx_packets(ifHCInUcastPkts)
Unicast Packets Transmitted            -> tx_packets(ifHCOutUcastPkts)
Total Packets Received with MAC Errors -> rx_errors (ifInErrors)
Total Transmit Errors                  -> tx_errors (ifOutErrors)
```
```python
def parse_interface_counters(text: str, port: int) -> PortStats:
    fields = labelled_values(text)
    return PortStats(
        port=port,
        rx_bytes=_int(fields.get("Total Packets Received (Octets)", "")),
        tx_bytes=_int(fields.get("Total Packets Transmitted (Octets)", "")),
        rx_packets=_int(fields.get("Unicast Packets Received", "")),
        tx_packets=_int(fields.get("Unicast Packets Transmitted", "")),
        rx_errors=_int(fields.get("Total Packets Received with MAC Errors", "")),
        tx_errors=_int(fields.get("Total Transmit Errors", "")),
    )
```
`port` is a CALLER-SUPPLIED parameter, not derived from the text — "the
command output carries no interface number". Any missing/unparseable field
→ `None` via `_int`'s fallback (never a fabricated 0).

---

## 3. `cli_read.py` — `CliReader`, every op

Module docstring (lines 1-18) key facts: "Unlike `HttpReader`, construction
is NOT gated on `reads_verified`" — the reader class itself has no live-vs-mock
gate; that gate lives in the FACADE (`_dispatch.cli_reads_supported` /
`SyncSwitch._reader_for`, out of scope here but worth noting for the Go
dispatch layer). `get_poe` on the non-PoE M4300-24X is called out as "the
only such carve-out" among reads.

```python
def _unsupported(model_key: str, op: str) -> UnsupportedCapabilityError:
    return UnsupportedCapabilityError(f"model {model_key!r} CLI does not expose {op}")


class CliReader:
    def __init__(self, session: CliSession, model: SwitchModel) -> None:
        self._spec = cli_spec(model)
        self.session = session
        self.model = model
```
`__init__` calls `cli_spec(model)` (line 53) — so constructing a `CliReader`
for a model with no CLI backend or no spec raises `UnsupportedCapabilityError`
IMMEDIATELY at construction, before any op is called.

### 3.1 `get_ports()` (lines 57-58)
```python
def get_ports(self) -> list[PortStatus]:
    return parse.parse_port_status(self.session.run(self._spec.port_status_cmd))
```
One command: `show port all` (or model override). One round trip.

### 3.2 `get_stats()` (lines 60-74)
```python
def get_stats(self) -> list[PortStats]:
    out: list[PortStats] = []
    for status in self.get_ports():
        text = self.session.run(self._spec.interface_stats(status.port))
        out.append(parse.parse_interface_counters(text, status.port))
    return out
```
**N+1 round trips**: 1x `show port all` (via `get_ports()`) + 1x `show
interface ethernet <iface>` PER PHYSICAL PORT REPORTED BY THE SWITCH. Comment
(lines 61-69) explicitly explains WHY it iterates the REAL port list from
`get_ports()` rather than `range(1, model.port_count+1)`: registry
`port_count` can be a "nominal value that can exceed the real physical-port
count (e.g. m4300-24x registry port_count=28 but the XSM4324CS has only 24
physical ports)" — using the nominal count "would otherwise issue doomed
queries for phantom ports and fabricate empty PortStats." **This is a
load-bearing behavioral detail a Go port must replicate exactly**: never
derive the per-port stats loop from `SwitchModel.port_count`.

### 3.3 `get_vlans()` (lines 76-82)
```python
def get_vlans(self) -> list[VLANInfo]:
    brief = parse.parse_vlan_brief(self.session.run(self._spec.vlan_brief_cmd))
    out: list[VLANInfo] = []
    for vid, name in brief:
        detail = self.session.run(self._spec.vlan_detail(vid))
        out.append(parse.parse_vlan_detail(detail, name=name))
    return out
```
**N+1 round trips**: 1x `show vlan brief` (or model override, e.g. `show
vlan`) + 1x `show vlan <id>` PER VLAN listed in the brief page. The `name`
from the brief page is threaded into `parse_vlan_detail(..., name=name)`,
which — per §2.12 — OVERRIDES the detail page's own name field. So the VLAN
NAME always comes from `show vlan brief`, never from `show vlan <id>`'s own
`"VLAN Name:"` line, even though both are present.

### 3.4 `get_pvids()` (lines 84-85)
```python
def get_pvids(self) -> list[tuple[int, int]]:
    return parse.parse_pvids(self.session.run(self._spec.pvid_cmd))
```
One command: `show vlan port all`.

### 3.5 `get_macs()` (lines 87-90)
```python
def get_macs(self) -> list[MacEntry]:
    if not self.model.has_mac_table:
        raise _unsupported(self.model.key, "a MAC/FDB table")
    return parse.parse_mac_table(self.session.run(self._spec.mac_table_cmd))
```
Gated on `SwitchModel.has_mac_table` (`registry.py:96-99`: `Backend.SNMP in
self.backends`) — i.e. this is a MODEL-level gate unrelated to the CLI
backend itself; every CLI-capable model in the pinned registry ALSO carries
`Backend.SNMP`, so in practice this never actually fires for a CLI model
today, but the guard exists as written and must be ported faithfully (a
future CLI-only, non-SNMP model would trip it). Command: `show mac-addr-table`.

### 3.6 `get_lldp()` (lines 92-93)
```python
def get_lldp(self) -> list[LLDPNeighbor]:
    return parse.parse_lldp(self.session.run(self._spec.lldp_cmd))
```
One command: `show lldp remote-device all`.

### 3.7 `get_poe()` (lines 95-98)
```python
def get_poe(self) -> list[PoEStatus]:
    if self.model.poe_port_count == 0:
        raise _unsupported(self.model.key, "PoE (model has no PSE ports)")
    return parse.parse_poe(self.session.run(self._spec.poe_cmd))
```
Gated on `SwitchModel.poe_port_count == 0` — this is the ONE documented
"real gap vs device limit" case for CLI reads (module docstring line 15-16).
Justification is a REAL device limitation (M4300-24X has no PoE hardware),
not a missing library feature — the CLI command itself would presumably
error on that hardware too, but the guard fires BEFORE ever sending `show poe
port info all`. Command when NOT gated: `show poe port info all`.

### 3.8 `get_sensors()` (lines 100-101)
```python
def get_sensors(self) -> list[Sensor]:
    return parse.parse_environment(self.session.run(self._spec.environment_cmd))
```
One command: `show environment`. No model gating.

### 3.9 `get_mgmt_ip()` (lines 103-104)
```python
def get_mgmt_ip(self) -> MgmtIpConfig:
    return parse.parse_mgmt_ip(self.session.run(self._spec.network_cmd))
```
One command: `show network` (or `show ip management` on M4300). No gating.

### 3.10 `identify()` (lines 106-107)
```python
def identify(self) -> DetectedModel:
    return parse.parse_version(self.session.run(self._spec.version_cmd), MODELS)
```
One command: `show version`. Passes the GLOBAL `MODELS` registry map
(imported from `.registry`), not just the current model — this op is
model-DETECTION, so it must search the whole registry, unlike every other
op which already knows its model.

### 3.11 CLI read op inventory — 10 ops, EXHAUSTIVE

`get_ports`, `get_stats`, `get_vlans`, `get_pvids`, `get_macs`, `get_lldp`,
`get_poe`, `get_sensors`, `get_mgmt_ip`, `identify` — exactly 10 public
methods on `CliReader`. No others exist in the pinned file.

---

## 4. `cli_write.py` — `CliWriter` + `deploy_certificate_scp`, every op

### 4.1 Shared helpers (lines 215-289)

```python
class CliWriter:
    def __init__(
        self,
        session: CliSession,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        self._spec = cli_spec(model)
        self.session = session
        self.model = model
        self.protected_ports = protected_ports
        self._reader = CliReader(session, model)
```
`__init__` builds its OWN internal `CliReader` on the SAME session — every
write's verify-after-write read-back reuses this reader (and thus the exact
same parsers as a plain read).

```python
def _guard(self, port: int, force: bool) -> None:
    if port in self.protected_ports and not force:
        raise ProtectedPortError(
            f"port {port} is protected; pass force=True to override"
        )
```
The core protected-port gate: membership test against `self.protected_ports`
(a `frozenset[int]` passed at construction), bypassed by `force=True`.

```python
def _run(self, command: str) -> None:
    """Issue one configuration command, treating ANY output as failure."""
    out = self.session.run(command).strip()
    if out:
        raise CliCommandError(f"CLI rejected {command!r}: {out}")
```
**THE core FASTPATH accept/reject convention** (also stated in the class
docstring, lines 207-209): "FASTPATH answers an ACCEPTED configuration
command with EMPTY output, so any text back (`% Invalid input`, `ERROR:
...`) is treated as a failure and raised as `CliCommandError` — never
swallowed." This is a BLANKET rule applied uniformly via `_run` to every
config-mode command sent by `CliWriter` (VLAN commands, PoE commands, port
admin, mgmt-IP config-mode commands) — there is no per-command output
pattern matching, just "any non-empty trimmed output = reject". Note
`set_mgmt_ip`'s EXEC-mode commands also go through `_run` (line 630).

```python
def _in_mode(self, enter: Sequence[str], body: Sequence[str]) -> None:
    entered = 0
    try:
        for command in enter:
            self._run(command)
            entered += 1
        for command in body:
            self._run(command)
    finally:
        for _ in range(entered):
            self.session.run(self._spec.exit_cmd)
```
The config-mode-entry/exit wrapper used by EVERY write op that needs
config-mode nesting (`vlan database`, `configure`/`interface <n>`, etc.).
Critical safety property (docstring lines 249-256): "Always unwinds with one
`exit` per level ACTUALLY entered, even when a body command is rejected —
otherwise a failed write would leave the shared session parked in
`(Config)(Interface 1/0/4)#` and every subsequent read... would run in the
wrong mode." The unwind loop calls `self.session.run(self._spec.exit_cmd)`
DIRECTLY (not `self._run`) — "an error while backing out must not mask the
real failure" — so exit's own output (if any) is silently discarded, never
raised. `entered` only increments AFTER each `enter[]` command succeeds (via
`_run` not raising), so if the 2nd of 3 `enter` commands is rejected,
`entered == 1` and only ONE `exit` is issued during unwind, not three — the
Go port must count entered levels the same way (increment strictly after
success), not just `len(enter)`.

```python
def _general_mode(self) -> list[str]:
    cmd = self._spec.switchport_general_cmd
    return [] if cmd is None else [cmd]
```
Prepends `["switchport mode general"]` to a command sequence UNLESS the
model's spec has `switchport_general_cmd=None` (gsm7252ps only, per §1.6).

```python
def _vlan(self, vlan: int) -> VLANInfo | None:
    return next((v for v in self._reader.get_vlans() if v.vlan_id == vlan), None)

def _port_mode(self, info: VLANInfo | None, port: int) -> VlanMode:
    if info is None or port not in info.member_ports:
        return VlanMode.EXCLUDED
    return VlanMode.TAGGED if port in info.tagged_ports else VlanMode.UNTAGGED
```
`_vlan` re-runs the FULL `get_vlans()` (which itself is N+1 round trips per
§3.3) and linear-searches for the target VLAN — used both for
before/after-write snapshots. `_port_mode` derives a 3-way `VlanMode`
(`EXCLUDED`/`TAGGED`/`UNTAGGED`) from a `VLANInfo`'s membership sets.

### 4.2 `create_vlan(vlan, name, *, force=False)` (lines 293-315)

```python
def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
    del force
    before = self._vlan(vlan)
    self._in_mode(
        [self._spec.vlan_database_cmd],
        [self._spec.vlan_create(vlan), self._spec.vlan_name(vlan, name)],
    )
    after = self._vlan(vlan)
    if after is None or (after.name or "") != name:
        raise WriteVerificationError(
            f"VLAN {vlan} was not created with name {name!r}",
            before=before,
            after=after,
        )
```
Command sequence: `vlan database` → `vlan <vid>` → `vlan name <vid> <name>`
→ `exit`. **`force` parameter is ACCEPTED but explicitly discarded**
(`del force`) — "exists for signature symmetry with `delete_vlan`... creating
an EMPTY VLAN adds no port membership, so it is non-disruptive and needs no
force". No `ProtectedPortError` path exists here at all. Verification:
re-fetch VLANs, fail if the VLAN doesn't exist OR its name doesn't match
(comparing `after.name or ""` against `name` — so a `None` name reads as
empty string for comparison purposes).

### 4.3 `delete_vlan(vlan, *, force=False)` (lines 317-343)

```python
def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
    before = self._vlan(vlan)
    if before is None:
        raise CliCommandError(f"VLAN {vlan} does not exist")
    if not force:
        clash = before.member_ports & self.protected_ports
        if clash:
            raise ProtectedPortError(
                f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                f"pass force=True to delete it anyway"
            )
    self._in_mode([self._spec.vlan_database_cmd], [self._spec.vlan_delete(vlan)])
    after = self._vlan(vlan)
    if after is not None:
        raise WriteVerificationError(
            f"VLAN {vlan} still exists after {self._spec.vlan_delete(vlan)!r}",
            before=before,
            after=after,
        )
```
Command sequence: `vlan database` → `no vlan <vid>` → `exit`. TWO distinct
precondition/safety checks BEFORE any command is sent: (1) VLAN must exist
(`CliCommandError`, explicitly documented as "a precondition failure, NOT a
verification divergence — no command has been sent yet"); (2) if the VLAN's
`member_ports` set INTERSECTS `self.protected_ports`, refuse without `force`
(`ProtectedPortError` naming the sorted clashing ports). Verification: VLAN
must be gone.

### 4.4 `set_vlan_membership(vlan, port, mode, *, force=False)` (lines 347-386)

```python
def set_vlan_membership(
    self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
) -> None:
    self._guard(port, force)
    before = self._vlan(vlan)
    if before is None:
        raise CliCommandError(f"VLAN {vlan} does not exist")
    body = self._general_mode()
    if mode is VlanMode.EXCLUDED:
        body.append(self._spec.vlan_participation(vlan, include=False))
    else:
        body.append(self._spec.vlan_participation(vlan, include=True))
        body.append(self._spec.vlan_tagging(vlan, tagged=mode is VlanMode.TAGGED))
    self._in_mode([self._spec.configure_cmd, self._spec.interface(port)], body)
    after = self._vlan(vlan)
    if after is None:
        raise WriteVerificationError(
            f"VLAN {vlan} disappeared while setting membership for port {port}",
            before=before,
            after=after,
        )
    got = self._port_mode(after, port)
    if got is not mode:
        raise WriteVerificationError(
            f"VLAN {vlan} port {port} did not read back as {mode.value} "
            f"(got {got.value})",
            before=self._port_mode(before, port),
            after=got,
        )
```
Command sequence: `configure` → `interface <iface>` → [`switchport mode
general` if applicable] → EITHER `vlan participation exclude <vid>` (mode ==
EXCLUDED) OR `vlan participation include <vid>` + (`vlan tagging <vid>` if
TAGGED else `no vlan tagging <vid>`) → `exit` `exit`. `_guard(port, force)`
runs FIRST — protected-port check happens BEFORE the VLAN-exists check.
`CliCommandError` for a non-existent VLAN is a precondition failure (no
command sent). Verification is DELIBERATELY SCOPED to only the target port's
own participation (docstring lines 352-358): unlike SNMP (which SETs whole
bitmaps and must verify both in full), general-mode side effects can
legitimately move OTHER VLANs' membership for this port — "not this VLAN's
business" — so only `_port_mode(after, port) == mode` is checked, nothing
about other ports or other VLANs.

### 4.5 `set_pvid(port, vlan, *, force=False)` (lines 388-412)

```python
def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
    self._guard(port, force)
    before = dict(self._reader.get_pvids())
    self._in_mode(
        [self._spec.configure_cmd, self._spec.interface(port)],
        [*self._general_mode(), self._spec.vlan_pvid(vlan)],
    )
    after = dict(self._reader.get_pvids())
    if after.get(port) != vlan:
        raise WriteVerificationError(
            f"PVID for port {port} did not read back as {vlan} "
            f"(got {after.get(port)})",
            before=before.get(port),
            after=after.get(port),
        )
```
Command sequence: `configure` → `interface <iface>` → [`switchport mode
general`] → `vlan pvid <vid>` → `exit` `exit`. `_guard` first (disruptive,
honours protected ports). Whether the target VLAN must pre-exist is
DELIBERATELY left to the switch ("rejects the command (`->`
`CliCommandError`) if it does not" — no library-side existence check unlike
`set_vlan_membership`).

### 4.6 PoE ops (lines 414-569)

```python
def _poe_status(self, port: int) -> PoEStatus | None:
    return next((p for p in self._reader.get_poe() if p.port == port), None)

def _require_poe(self) -> None:
    if self.model.poe_port_count == 0:
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r} has no PSE ports, so its firmware has "
            "no 'poe' command (verified live: 'poe ?' -> '% Unrecognized "
            "command')"
        )
```
The write-side PoE gate, mirroring `CliReader.get_poe`'s read-side gate — SAME
justification, quoted from live probing ("`poe ?`" → "`% Unrecognized
command`" on the M4300-24X vs full help on the PoE-equipped M4300-16X). This
is the second of the two documented "real gap" carve-outs (module docstring
identifies it implicitly via the same `poe_port_count == 0` pattern as the
read path).

**`set_poe(port, on, *, force=False, timeouts=None, sleep=time.sleep,
clock=time.monotonic)`** (lines 441-487):
```python
def set_poe(
    self, port: int, on: bool, *, force: bool = False,
    timeouts: PoeCycleTimeouts | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    self._require_poe()
    if not on:
        self._guard(port, force)  # turning PoE off is disruptive
    limits = timeouts or _DEFAULT_POE_TIMEOUTS
    before = self._poe_status(port)
    self._in_mode(
        [self._spec.configure_cmd, self._spec.interface(port)],
        [self._spec.poe_admin(on=on)],
    )
    deadline = clock() + (limits.off_timeout if not on else limits.on_timeout)
    while True:
        after = self._poe_status(port)
        if after is not None and after.admin_enabled == on:
            return
        if clock() >= deadline:
            raise WriteVerificationError(
                f"PoE admin for port {port} did not read back as {on}",
                before=before,
                after=after,
            )
        sleep(limits.poll_interval)
```
Command sequence: `configure` → `interface <iface>` → `poe` (on) or `no poe`
(off) → `exit` `exit`. Protected-port guard ONLY applies when TURNING OFF
(`if not on: self._guard(...)`) — enabling PoE is never gated. **Verification
POLLS**, not a single read: comment (lines 458-465) documents a MEASURED
hardware fact — "Status is a DETECTION state, so it lags the admin write...
measured on the real M4300-16X... immediately after `poe` re-enabled port
1/0/1 the table still said `Disabled`, and the same port read `Searching`...
moments later. A single immediate read therefore reported a WORKING write as
a verification failure." Deadline = `clock() + off_timeout` (30.0s default,
turning off) or `+ on_timeout` (60.0s default, turning on) from
`PoeCycleTimeouts` (`snmp_write.py:312-318`: `off_timeout=30.0`,
`on_timeout=60.0`, `poll_interval=2.0`). `sleep`/`clock` are injectable for
tests.

**`_poe_reset(port, *, timeouts, sleep, clock, recovered, timeout_message)`**
(lines 489-522) — shared PoE-recovery-polling helper:
```python
def _poe_reset(
    self, port: int, *, timeouts: PoeCycleTimeouts,
    sleep: Callable[[float], None], clock: Callable[[], float],
    recovered: Callable[[PoEStatus | None], bool], timeout_message: str,
) -> None:
    self._require_poe()
    before = self._poe_status(port)
    self._in_mode(
        [self._spec.configure_cmd, self._spec.interface(port)],
        [self._spec.poe_reset_cmd],
    )
    deadline = clock() + timeouts.on_timeout
    while not recovered(self._poe_status(port)):
        if clock() >= deadline:
            raise WriteVerificationError(
                timeout_message.format(timeout=timeouts.on_timeout),
                before=before,
                after=self._poe_status(port),
            )
        sleep(timeouts.poll_interval)
```
Command sequence: `configure` → `interface <iface>` → `poe reset` → `exit`
`exit`. Uses `poe reset` — the device's OWN atomic re-arm command — "not
off-then-on... no failure between two commands can leave the port powered
down" (class docstring lines 500-503). Always uses `timeouts.on_timeout` as
the deadline (regardless of which of the two callers invokes it). Takes a
`recovered` PREDICATE callback + `timeout_message` FORMAT STRING (with a
`{timeout}` placeholder) — parameterizes the two public callers below.

**`cycle_poe(port, *, force=False, timeouts=None, sleep=..., clock=...)`**
(lines 524-544):
```python
def cycle_poe(
    self, port: int, *, force: bool = False,
    timeouts: PoeCycleTimeouts | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    self._guard(port, force)
    self._poe_reset(
        port,
        timeouts=timeouts or _DEFAULT_POE_TIMEOUTS,
        sleep=sleep, clock=clock,
        recovered=lambda st: bool(st and st.delivering),
        timeout_message=(
            f"PoE port {port} did not return to delivering within {{timeout}}s"
        ),
    )
```
`_guard(port, force)` FIRST (disruptive — power-cycling a PD). Recovery
predicate: `st.delivering` (i.e. `st.detect is PoEDetect.DELIVERING`, from
`models.py` `PoEStatus.delivering` property). If no powered device is
attached, this will legitimately TIME OUT and raise
`WriteVerificationError` — "honestly failing" is the documented expected
behavior in that case (per `commands.py` model-spec comments, e.g. line 337:
"cycle_poe honestly failing on a port with no powered device").

**`clear_poe_fault(port, *, force=False, timeouts=None, sleep=...,
clock=...)`** (lines 546-569):
```python
def clear_poe_fault(
    self, port: int, *, force: bool = False,
    timeouts: PoeCycleTimeouts | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    self._guard(port, force)
    self._poe_reset(
        port,
        timeouts=timeouts or _DEFAULT_POE_TIMEOUTS,
        sleep=sleep, clock=clock,
        recovered=lambda st: st is not None
        and st.detect in (PoEDetect.DELIVERING, PoEDetect.SEARCHING),
        timeout_message=(
            f"PoE port {port} still in FAULT after clear within {{timeout}}s"
        ),
    )
```
Same `poe reset` command, DIFFERENT recovery predicate — "has LEFT the fault
state (delivering or searching)" — "exactly the recovery predicate
`SnmpWriter.clear_poe_fault` uses" (cross-backend parity note).

### 4.7 `set_port_enabled(port, enabled, *, force=False)` (lines 573-597)

```python
def set_port_enabled(
    self, port: int, enabled: bool, *, force: bool = False
) -> None:
    if not enabled:
        self._guard(port, force)  # disabling a port is disruptive
    before = self._port_status(port)
    self._in_mode(
        [self._spec.configure_cmd, self._spec.interface(port)],
        [self._spec.port_admin(enabled=enabled)],
    )
    after = self._port_status(port)
    if after is None or after.admin_enabled != enabled:
        raise WriteVerificationError(
            f"admin state for port {port} did not read back as {enabled}",
            before=before,
            after=after,
        )

def _port_status(self, port: int) -> PortStatus | None:
    return next((p for p in self._reader.get_ports() if p.port == port), None)
```
Command sequence: `configure` → `interface <iface>` → `no shutdown`
(enabled) or `shutdown` (disabled) → `exit` `exit`. Guard ONLY when
DISABLING (`if not enabled`) — enabling a port is never gated, symmetric with
`set_poe`. SINGLE immediate read-back (no polling, unlike PoE) via `show
port all`'s Admin Mode column.

### 4.8 `set_mgmt_ip(address, netmask, gateway, *, force=False)` (lines 601-644)

```python
def set_mgmt_ip(
    self, address: str, netmask: str, gateway: str, *, force: bool = False
) -> None:
    if not force:
        raise ProtectedPortError(
            "set_mgmt_ip can strand the switch (and drops the CLI session "
            "it is issued over); pass force=True to proceed"
        )
    exec_cmds, config_cmds = self._spec.mgmt_ip(address, netmask, gateway)
    before = self._reader.get_mgmt_ip()
    for command in exec_cmds:
        self._run(command)
    if config_cmds:
        self._in_mode([self._spec.configure_cmd], config_cmds)
    after = self._reader.get_mgmt_ip()
    for field, want, got in (
        ("address", address, after.address),
        ("netmask", netmask, after.netmask),
        ("gateway", gateway, after.gateway),
    ):
        if got != want:
            raise WriteVerificationError(
                f"management {field} did not read back as {want!r} (got {got!r})",
                before=before,
                after=after,
            )
```
**`force=True` IS UNCONDITIONALLY REQUIRED** — `ProtectedPortError` is raised
whenever `force` is falsy, REGARDLESS of `protected_ports` membership (this
op ignores `self.protected_ports` entirely and always demands `force`).
Docstring (lines 604-620) explains why: "unlike the SNMP path (whose write
OIDs are placeholders), these commands are the switch's real documented ones
— but the op can still strand the switch, and it will normally drop the
very CLI session issuing it... Deliberately NOT live-tested for that
reason." Command dispatch: EXACTLY ONE of `exec_cmds`/`config_cmds` is
non-empty per model (`CliModelSpec.mgmt_ip()`, §1.3) — EXEC commands (if
any) run via plain `_run` (NOT wrapped in `_in_mode`, since they're
privileged-EXEC, not config-mode); config commands (if any) run inside a
`configure` block via `_in_mode`. Verification checks all THREE of
address/netmask/gateway independently, raising on the FIRST mismatch found
(loop `for field, want, got in (...)`, `if got != want: raise` — stops at
first divergent field, not a combined multi-field report).

### 4.9 `reboot(*, force=False)` (lines 646-666)

```python
def reboot(self, *, force: bool = False) -> None:
    if not force:
        raise ProtectedPortError("reboot is disruptive; pass force=True")
    try:
        self.session.run_write_memory(self._spec.reload_cmd, prestuff=True)
    except CliTransportError:
        # Expected: the switch tore the session down while rebooting.
        return
```
`force=True` unconditionally required (same pattern as `set_mgmt_ip`).
Command: `reload` (privileged EXEC), issued via `session.run_write_memory`
(reused because `reload` ALSO prompts a `(y/n)` confirm, same interactive
shape as `write memory`) with `prestuff=True` ALWAYS (regardless of the
model's own `writemem_stuff`/`ScpCertProfile` flag — that flag is for the SCP
cert deploy's `write memory`, not this). **`CliTransportError` is EXPLICITLY
CAUGHT AND SWALLOWED** — "a dropped session IS the success signal" — this is
the ONE place in `cli_write.py` where a transport-layer exception is treated
as SUCCESS rather than propagated. No read-back verification is attempted at
all (impossible by definition — "the switch stops answering").

### 4.10 `deploy_certificate_scp(...)` module-level function (lines 106-141)

```python
_SERVER_DEST = "nvram:sslpem-server"
_ROOT_DEST = "nvram:sslpem-root"
_SERVER_SUFFIX = "-server.pem"
_ROOT_SUFFIX = "-root.pem"
_WRITE_MEMORY = "write memory"
_HTTPS_OFF = "no ip http secure-server"
_HTTPS_ON = "ip http secure-server"

def scp_source_url(scp_source: str, remote_dir: str, filename: str) -> str:
    return f"scp://{scp_source}{remote_dir}/{filename}"

def _copy_cmd(scp_source: str, remote_dir: str, filename: str, dest: str) -> str:
    return f"copy {scp_source_url(scp_source, remote_dir, filename)} {dest}"

def deploy_certificate_scp(
    session: CliSession, *, scp_source: str, scp_password: str,
    remote_dir: str, base: str, chain: bool, writemem_stuff: bool,
) -> None:
    session.run(_HTTPS_OFF)
    session.run_scp_copy(
        _copy_cmd(scp_source, remote_dir, f"{base}{_SERVER_SUFFIX}", _SERVER_DEST),
        scp_password,
    )
    if chain:
        session.run_scp_copy(
            _copy_cmd(scp_source, remote_dir, f"{base}{_ROOT_SUFFIX}", _ROOT_DEST),
            scp_password,
        )
    session.run(_HTTPS_ON)
    session.run_write_memory(_WRITE_MEMORY, prestuff=writemem_stuff)
```
This is NOT a `CliWriter` method — a standalone function taking a raw
`CliSession`. Fixed 4-or-5-step sequence, EXHAUSTIVE:
1. `no ip http secure-server` (via plain `session.run`, NOT gated on empty
   output the way `CliWriter._run` is — no `CliCommandError` check here at
   all).
2. `copy scp://<scp_source><remote_dir>/<base>-server.pem
   nvram:sslpem-server` — interactive, via `session.run_scp_copy`.
3. OPTIONAL (only if `chain=True`): `copy scp://<scp_source><remote_dir>/<base>-root.pem
   nvram:sslpem-root` — interactive.
4. `ip http secure-server` (re-enable; "loads the new cert, no reboot").
5. `write memory`, with `prestuff=writemem_stuff` (the CALLER-supplied flag,
   sourced from `ScpCertProfile.writemem_stuff` per model, §1.7).

`scp_source_url` builds `scp://<user@host[:port]><remote_dir>/<filename>` —
note NO separating slash between `scp_source` and `remote_dir` in the
f-string (`f"scp://{scp_source}{remote_dir}/{filename}"`) — the CALLER's
`remote_dir` is expected to already start with `/` (an "ABSOLUTE staging
path", per the docstring). **A Go port must reproduce this exact
concatenation, not insert an extra `/`.**

This function is `verified: False`-equivalent at the code-comment level —
module docstring lines 41-47: "GROUNDED in the working certbot-hook
`FastpathScpUpdater`... MOCK-TESTED end-to-end, but NOT live-verified — a
real run is a production write that needs a staging SCP server." Not gated
by `force` at all (no `ProtectedPortError` path in this function).

### 4.11 CLI write op inventory — 9 `CliWriter` methods + 1 module function, EXHAUSTIVE

`create_vlan`, `delete_vlan`, `set_vlan_membership`, `set_pvid`, `set_poe`,
`cycle_poe`, `clear_poe_fault`, `set_port_enabled`, `set_mgmt_ip`, `reboot` —
**10** public `CliWriter` methods (not 9 — recount: create_vlan, delete_vlan,
set_vlan_membership, set_pvid, set_poe, cycle_poe, clear_poe_fault,
set_port_enabled, set_mgmt_ip, reboot = 10). Plus the standalone
`deploy_certificate_scp` module function and its `scp_source_url` helper.
`_poe_reset`/`_general_mode`/`_vlan`/`_port_mode`/`_guard`/`_run`/`_in_mode`/
`_poe_status`/`_require_poe`/`_port_status` are all PRIVATE helpers, not
independently callable ops.

---

## 5. Op × model support matrix

### 5.1 Reads (`CliReader`) — all 4 CLI models support all commands verbatim; gating is model-property-based, not per-model command absence

| Op | Command (base) | gsm7252ps | m4300-24x | m4300-16x | gsm7228ps |
|---|---|---|---|---|---|
| `identify` | `show version` | yes | yes | yes | yes |
| `get_ports` | `show port all` | yes | yes | yes | yes |
| `get_stats` | `show interface ethernet {iface}` ×N | yes | yes | yes | yes |
| `get_vlans` | `show vlan brief`/`show vlan {vlan}` | yes (`show vlan brief`) | yes (`show vlan`) | yes (`show vlan`) | yes (`show vlan`) |
| `get_pvids` | `show vlan port all` | yes | yes | yes | yes |
| `get_macs` | `show mac-addr-table` | yes† | yes† | yes† | yes† |
| `get_lldp` | `show lldp remote-device all` | yes | yes | yes | yes |
| `get_poe` | `show poe port info all` | yes | **`UnsupportedCapabilityError`** (poe_port_count=0) | yes | yes |
| `get_sensors` | `show environment` | yes | yes | yes | yes |
| `get_mgmt_ip` | `show network`/`show ip management` | yes (`show network`) | yes (`show ip management`) | yes (`show ip management`) | yes (`show network`) |

† gated on `SwitchModel.has_mac_table` (== `Backend.SNMP in backends`), true
for all 4 CLI models today, so no actual failure occurs; documented as a
guard that exists for correctness, not a live gap.

**The single documented read-side "real gap, not device limit" carve-out**:
`get_poe` on `m4300-24x` — but note this genuinely IS a device/hardware
limitation (no PSE ports on that SKU), quoted justification in
`cli_read.py`'s module docstring (line 15-16): "Ops a FASTPATH model's CLI
genuinely lacks raise `UnsupportedCapabilityError` honestly rather than
fabricating: `get_poe` on the non-PoE M4300-24X (PoE port count 0) is the
only such carve-out — every other `show` command exists on every FASTPATH
switch." I.e. per principle 2 in the task prompt, this IS a real device
limitation, not a "missing op to build" gap — the Python source itself makes
this distinction explicit.

### 5.2 Writes (`CliWriter`) — same per-model reality

| Op | gsm7252ps | m4300-24x | m4300-16x | gsm7228ps |
|---|---|---|---|---|
| `create_vlan` | yes | yes | yes | yes |
| `delete_vlan` | yes | yes | yes | yes |
| `set_vlan_membership` | yes (no switchport-mode prelude) | yes (switchport-mode prelude) | yes (switchport-mode prelude) | yes (switchport-mode prelude) |
| `set_pvid` | yes (no prelude) | yes (prelude) | yes (prelude) | yes (prelude) |
| `set_poe` | yes | **`UnsupportedCapabilityError`** (`_require_poe`) | yes | yes |
| `cycle_poe` | yes | **`UnsupportedCapabilityError`** | yes | yes |
| `clear_poe_fault` | yes | **`UnsupportedCapabilityError`** | yes | yes |
| `set_port_enabled` | yes | yes | yes | yes |
| `set_mgmt_ip` | yes (EXEC `network parms`) | yes (config `ip management address`+`ip default-gateway`) | yes (config) | yes (EXEC `network parms`) |
| `reboot` | yes (`reload`) | yes | yes | yes |
| `deploy_certificate_scp` (module fn, model-agnostic code but gated by `scp_cert_profile`) | yes (legacy crypto, writemem_stuff=True) | yes (modern crypto) | yes (modern crypto) | **`UnsupportedCapabilityError`** (`scp_cert_profile`; "uses an HTTP multipart upload instead", `commands.py:365-366`) |

PoE write ops on `m4300-24x` are the write-side echo of the same real
hardware limitation as the read-side gate (§5.1) — quoted justification in
`_require_poe` (`cli_write.py:419-439`): "Not a CLI limitation and not an
unimplemented op: the M4300-24X has no PoE ports... and its firmware
therefore does not carry the command at all — probed live 2026-07-30 on
10.1.5.13, where `poe ?` in interface config mode answers: `poe ?` / `%
Unrecognized command`". This is again a documented REAL device limitation.

The `gsm7228ps` cert-deploy gap is ALSO a genuine mechanism difference
(different upload transport entirely — HTTP multipart vs SCP), not a missing
Go feature to build within the CLI protocol layer — it is out of scope for
slice 07 regardless (belongs to the HTTP protocol layer / a certificate-deploy
slice), but is worth flagging so the Go op-support matrix doesn't silently
imply gsm7228ps has NO cert-deploy path at all — it has one, just not via
this module.

---

## 6. Write safety mechanisms — exact guards, quoted

1. **`ProtectedPortError`** gate (`_guard`, `cli_write.py:235-239`):
   ```python
   def _guard(self, port: int, force: bool) -> None:
       if port in self.protected_ports and not force:
           raise ProtectedPortError(
               f"port {port} is protected; pass force=True to override"
           )
   ```
   Applied to: `set_vlan_membership` (always), `set_pvid` (always), `set_poe`
   (only when `on=False`), `cycle_poe` (always), `clear_poe_fault` (always),
   `set_port_enabled` (only when `enabled=False`). NOT applied to:
   `create_vlan` (force accepted but discarded via `del force`).

2. **VLAN-membership-clash gate** on `delete_vlan` (`cli_write.py:329-335`):
   ```python
   if not force:
       clash = before.member_ports & self.protected_ports
       if clash:
           raise ProtectedPortError(
               f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
               f"pass force=True to delete it anyway"
           )
   ```
   Set-intersection check, distinct from the per-port `_guard` (this one
   inspects the VLAN's OWN membership, not a single target port).

3. **Unconditional `force=True` requirement** (no `protected_ports` check at
   all — force is mandatory regardless of port), on `set_mgmt_ip`
   (`cli_write.py:622-626`) and `reboot` (`cli_write.py:660-661`):
   ```python
   if not force:
       raise ProtectedPortError(
           "set_mgmt_ip can strand the switch (and drops the CLI session "
           "it is issued over); pass force=True to proceed"
       )
   ...
   if not force:
       raise ProtectedPortError("reboot is disruptive; pass force=True")
   ```

4. **Command-rejection detection** (`_run`, `cli_write.py:241-245`): "FASTPATH
   answers an ACCEPTED configuration command with EMPTY output, so any text
   back... is treated as a failure" → `CliCommandError`. Universal to every
   config/EXEC command `CliWriter` issues via `_run` (NOT applied inside
   `deploy_certificate_scp`, which calls `session.run` directly without this
   check).

5. **Mode-unwind-on-failure** (`_in_mode`, `cli_write.py:247-266`): `finally`
   block always issues one `exit` per level ENTERED (not per level intended),
   using the raw session (not `_run`), so a rejected body command cannot
   strand the session in a nested config-mode prompt for the NEXT read/write
   on the same session.

6. **General-mode prelude** (`_general_mode`, `cli_write.py:268-278`) — not a
   safety gate per se, but a CORRECTNESS precondition documented as a
   "deliberate, unavoidable side effect": `vlan participation`/`vlan tagging`
   commands are silently INERT (accepted, but non-functional) while a port is
   in `switchport mode access`; sent unconditionally (idempotent) before
   every per-port VLAN command EXCEPT on gsm7252ps (no switchport-mode
   concept there — sending it would be REJECTED outright, `"%
   Unrecognized command"`). CONSEQUENCE documented at
   `cli_write.py:195-203`: forcing general mode on the M4300 can
   PERMANENTLY change a port's PVID (measured: PVID jumped 1→10) unless later
   undone with `no switchport mode` (NOT `switchport mode access`, which
   instead ACTIVATES the previously-inert access-mode lines).

7. **Verify-after-write, always** — every write op (except `reboot`, which
   is provably unverifiable, and the two `deploy_certificate_scp` steps,
   which have their own success/failure detection via `ShellDriver`'s
   `_SCP_SUCCESS_RE`/`_SCP_FAILURE_RE`) re-reads via `CliReader` (the SAME
   session, SAME parsers) and raises `WriteVerificationError(message,
   before=..., after=...)` on divergence — carrying the observed state on
   both sides, never a silent success. `set_poe`/`cycle_poe`/`clear_poe_fault`
   POLL (with injectable `sleep`/`clock`) rather than reading once
   immediately, because PoE detect state measurably LAGS the admin write on
   real hardware (§4.6).

8. **No `write memory` / no persistence** on the VLAN/port/PoE/mgmt-IP write
   path (class docstring `cli_write.py:210-212`): "NOTHING is persisted: no
   `write memory` is issued, so these writes change the running config
   only... A caller that wants them to survive a reboot must save
   separately." The ONLY places `write memory` (or the `reload` equivalent
   using the same interactive machinery) IS issued are `reboot()` (via
   `run_write_memory(reload_cmd, prestuff=True)`) and
   `deploy_certificate_scp` (step 5, `prestuff=writemem_stuff` per-model).

9. **`reboot`'s transport-error-as-success inversion** (`cli_write.py:662-666`):
   the ONLY place a `CliTransportError` is caught and treated as SUCCESS
   rather than propagated — "a dropped session IS the success signal".

---

## 7. `parse.py` drift between pin `1841111` and pin `7ebfe5d`

Per `git -C <snapshot> log --oneline -5 -- src/netgear_switch/protocols/cli/parse.py`:
```
e56fc34 fix(docs): repair malformed reST in four docstrings
ed39c7b fix(cli/parse): resolve Smart-firmware 1/gN & 1/xgN port names
aaab577 feat(virtual): reseed gsm7228ps from real S3300-52X capture; verified=True
71b5826 fix(cli): parse_poe locates columns by header name, not fixed index
b8b40d5 fix(cli): parse_poe locates columns by header name, not fixed index
```
`git diff --stat 1841111..7ebfe5d` reports exactly `parse.py | 25 +-` (12
insertions, 13 deletions net "25" changed lines counted by `git diff --stat`'s
`+-` convention) — this is the "+25-line drift" the task refers to. The FULL
`git diff 1841111..7ebfe5d -- .../parse.py` content (reproduced in full, not
excerpted) shows this is **commit `e56fc34` ONLY** ("fix(docs): repair
malformed reST in four docstrings") — a **pure documentation formatting fix,
zero logic/behavior change**:

1. `parse_version`'s docstring: a plain-text label map (`"Column/label map
   (...):\n  System Description  -> ..."`) was converted to a proper reST
   literal block by adding `::` after the intro line, a blank line, and
   re-indenting the two label lines by 4 more spaces (`    System
   Description` → `        System Description`).
2. `parse_environment`'s docstring: added a blank line after "Emits, in
   order:" before the bullet list (reST requires a blank line before a list
   for it to render as a list rather than run-on text).
3. `parse_mgmt_ip`'s docstring: same treatment as #1 — the plain-text label
   map (`"Label map (...):\n  IP Address  -> address\n..."`) converted to a
   proper `::` literal block with re-indented lines.

**No code line changed.** Every regex, every column index, every parser
function body, every control-flow branch is byte-identical between the two
pins. The OTHER four commits touching `parse.py` (`ed39c7b`, `aaab577`,
`71b5826`, `b8b40d5`) are all AT OR BEFORE `1841111` in history (they precede
the pin range, not part of the `1841111..7ebfe5d` diff) — `git log --oneline
-5` shows the 5 most recent commits touching the file overall, not commits
within the diff range specifically; only `e56fc34` falls inside
`1841111..7ebfe5d`. **Action for the Go port: none required beyond normal
comment/doc fidelity** — this dossier already incorporates the corrected
(post-`e56fc34`) docstring wording throughout §2, so a Go port following this
dossier picks up the clean version automatically. `commands.py` and
`cli_read.py`/`cli_write.py` have EMPTY diffs over the same range (`git diff
1841111..7ebfe5d -- .../commands.py` and `-- .../cli_read.py
.../cli_write.py` both produced zero output) — those three files are
byte-identical between the two pins.

---

## 8. Idiomatic Go mapping recommendations

### 8.1 `CliModelSpec` → Go struct

A straightforward `struct` with the same fields, `string` for command
templates. Templating (`"vlan {vlan}".format(vlan=vlan)`) should NOT use
`fmt.Sprintf` with positional `%d` placeholders baked into the spec struct
(that would lose the "pure data, per-field override" property that lets
`_M4300_OVERRIDES` patch exactly 4 fields) — instead keep the Python-style
`{vlan}`/`{name}`/`{iface}` template strings as struct fields and do the
substitution in the METHOD (`VlanCreate(vlan int) string`, etc.), e.g. via
`strings.NewReplacer` or a tiny local `strings.ReplaceAll(tmpl, "{vlan}",
strconv.Itoa(vlan))` helper — this preserves byte-parity with the Python
`.format()` output AND keeps the override tables (`_M4300_OVERRIDES`
equivalent) expressible as plain field assignment. Recommend a small
unexported `applyIfaceTemplate(spec, port int) string` free function
mirroring `iface()` exactly (the `uplink_iface_template`/`first_uplink_port`
branch), since it is reused by both `interfaceStats` and `interface`.

The four `CliModelSpec` instances (§1.6) become four exported or
package-level `var` structs, keyed into a `map[string]CliModelSpec` (mirror
`CLI_SPECS`), with `CliSpec(model SwitchModel) (CliModelSpec, error)` doing
the exact two-stage guard from `cli_spec()` (§1.8) — check backend
membership first (distinct error), map lookup second (distinct error).

`_CliCmdOverrides`'s "only 4 fields, type-safe" property: in Go this is
naturally expressed as a small unexported `cliCmdOverrides` struct (4 string
fields, all with Go zero-value `""` meaning "no override" — BUT this
collides with `vlan_brief_cmd`/`network_cmd` being valid non-empty strings by
default, so use `*string`/pointer fields or an explicit
`applyOverrides(base CliModelSpec, o cliCmdOverrides) CliModelSpec` function
signature listing exactly the 4 fields as named args) — avoids Go's lack of
Python's `**kwargs` splat while keeping the "cannot accidentally override
`telnet_port`" guarantee the Python `TypedDict` provides via its type
checker.

### 8.2 `parse.py` → Go `regexp` + hand-rolled table slicer

All 5 primitive regexes (§2.1) translate directly to Go `regexp.MustCompile`
— Go's RE2 engine supports every construct used here (no backreferences,
lookaheads, etc. in any of these five patterns), so this is a mechanical
port. The one thing to get exactly right: Go string indexing/slicing is
BYTE-based, not rune-based; FASTPATH CLI output is ASCII (verified by every
quoted fixture excerpt and by `ShellDriver`'s explicit `"latin-1"` decode,
`session.py:111,170,218`), so byte-based slicing in `_slice_cell` is
actually CORRECT and matches Python's (rune-based) slicing for this
ASCII-only input — no rune-conversion needed, but WORTH A CODE COMMENT
explaining why (a future maintainer adding non-ASCII support would need to
switch to `[]rune`).

**`_slice_cell`'s "slice past end of short line" behavior (§2.4) is the
single highest-risk faithful-port detail in this whole file.** Python's
`row[start:end]` clamps silently; Go's `row[start:end]` PANICS if `end >
len(row)` or `start > len(row)`. The Go port MUST explicitly clamp:
```go
func sliceCell(row string, start int, end *int) string {
    if start > len(row) {
        start = len(row)
    }
    e := len(row)
    if end != nil && *end < e {
        e = *end
    }
    if e < start {
        e = start
    }
    return strings.TrimSpace(row[start:e])
}
```
(sketch only — exact signature is the porting task's call, but the CLAMP
behavior itself is not optional: real device output rows are frequently
SHORTER than the ruler when trailing columns are blank, e.g. a down port's
blank "Physical Status" cell, or LLDP's bare-interface rows with no
neighbour data at all — §2.15's very filtering logic DEPENDS on being able
to slice past a short row's end and get `""`, not a panic.)

`iter_table_rows`/`header_columns` are naturally Go functions returning
`([][]string, error)` or an iterator-style callback/channel; a plain
`[][]string` return (not a lazy `Iterator[list[str]]` generator) is idiomatic
Go and loses nothing here since callers always fully consume the sequence.

`header_columns`'s backward-scan-then-collapse-whitespace logic (§2.6) is a
direct, mechanical translation — `regexp.MustCompile(`\s+`).ReplaceAllString`
for the whitespace collapse.

`labelled_values` → `map[string]string`, same "last wins" semantics (Go map
assignment naturally overwrites, so a simple `for`-loop over lines mirrors
Python exactly, no extra care needed).

`parse_poe`'s substring-based `PoEDetect` classification (§2.16): Go maps
have NO iteration-order guarantee (Python 3.7+ dicts DO preserve insertion
order) — the Go port must NOT reimplement `_POE_DETECT_TEXT` as a
`map[string]PoEDetect` iterated in a `for k, v := range` loop, since Go would
randomize that order across runs. Use an ordered `[]struct{key string;
val PoEDetect}` slice (or a sequence of explicit `if strings.Contains(...)`
checks in the documented order: delivering, searching, disabled, fault) to
guarantee determinism.

### 8.3 `CliReader`/`CliWriter` → Go structs implementing the same op surface

`CliSession` (Protocol, `transport/cli/session.py:50-72`) maps to a Go
`interface` with `Run(command string) (string, error)`,
`RunSCPCopy(command, scpPassword string) (string, error)`,
`RunWriteMemory(command string, prestuff bool) (string, error)`, `Close()
error` — note the Python `Protocol` methods don't declare exceptions in their
signature (Python exceptions are implicit); the Go interface SHOULD return
`error` explicitly from every method, and `CliWriter._run`'s "any non-empty
output = reject" check becomes a Go-side wrapper, not a change to the
interface contract.

`CliReader`/`CliWriter`'s per-op N+1 round-trip patterns (`get_stats`,
`get_vlans`, and `CliWriter`'s `_vlan`/`_poe_status`/`_port_status` re-reads)
are naturally ported as sequential Go loops — no concurrency is implied or
should be added: the underlying `CliSession` is a SINGLE serial shell
connection, so parallelizing these round trips would corrupt the shared
prompt-framing state in `ShellDriver`. Preserve strict sequential ordering.

`_in_mode`'s exactly-once-per-entered-level unwind (§4.1) is best expressed
in Go via a `defer` combined with a counter, mirroring the `finally`/`entered`
pattern precisely:
```go
func (w *CliWriter) inMode(enter, body []string) error {
    entered := 0
    defer func() {
        for i := 0; i < entered; i++ {
            _, _ = w.session.Run(w.spec.ExitCmd) // errors intentionally discarded
        }
    }()
    for _, cmd := range enter {
        if err := w.run(cmd); err != nil {
            return err
        }
        entered++
    }
    for _, cmd := range body {
        if err := w.run(cmd); err != nil {
            return err
        }
    }
    return nil
}
```
This is a faithful, idiomatic translation — Go's `defer` is the natural
analogue of Python's `try/finally` here.

`WriteVerificationError`'s `before`/`after` payload (arbitrary Python
`object`) should become a typed Go error carrying `any`/`interface{}` fields
(or, better, generics — `WriteVerificationError[T any]{Before, After T}` —
if the Go codebase's existing SNMP/HTTP write-error types already establish
a convention; **this dossier does not read the Go repo per the task's
boundary, so match whatever pattern the Go `errors` package already
established for `SnmpWriter`/`HttpWriter`'s equivalent error, not a
new one**).

### 8.4 Python idioms that resist a faithful 1:1 Go port

* **`del force`** (`create_vlan`, §4.2) — Go has no equivalent "accept and
  discard a parameter for signature symmetry" idiom beyond simply naming the
  parameter `_` (blank identifier is not legal for named function
  parameters in Go, but an unused named parameter is allowed without
  triggering `go vet`/compiler errors, unlike unused local variables) — so
  `func (w *CliWriter) CreateVLAN(vlan int, name string, force bool) error`
  with `force` simply never referenced in the body is the direct
  equivalent; consider a `//lint:ignore` or doc comment noting it is
  intentionally unused, to preempt a linter flag.
* **Lazy generator functions** (`Iterator[list[str]]` from `iter_table_rows`)
  — as noted in §8.2, collapse to eager `[][]string` slices in Go; no
  meaningful behavior loss since every call site fully drains the iterator
  anyway (confirmed by reading every call site: `parse_port_status`,
  `parse_vlan_detail`, `parse_pvids`, `parse_mac_table`, `parse_lldp`,
  `parse_poe`, `parse_environment` all `for cells in iter_table_rows(...)`
  to completion, no early `break` anywhere in `parse.py`).
* **Multiple inheritance / `Protocol` structural typing** (`CliSession`) —
  Go interfaces are ALREADY structurally typed, so this is actually a
  SMOOTHER port than most Python idioms, not a resistance point.
  `ShellDriver` (a concrete class satisfying the `Protocol` implicitly via
  structural methods) maps directly to a Go struct satisfying a Go
  `interface`.
* **`Callable[[float], None]` injectable `sleep`/`clock` params** (PoE
  polling) — direct Go equivalent: `func(time.Duration)` and `func()
  time.Time` (or `func() float64` if matching Python's raw `float` seconds
  return of `time.monotonic()` is preferred for exact parity) as optional
  function-typed parameters, defaulting to `time.Sleep`/`time.Now` (or a
  monotonic-clock equivalent — Go's `time.Now()` is NOT guaranteed
  monotonic-only unless using `time.Since`/`time.Time.Sub`, so consider
  `func() time.Time` + `.Sub()` deltas rather than trying to mimic
  `time.monotonic()`'s raw float-seconds return type).
* **f-string error messages with `!r`** (Python `repr()` formatting, e.g.
  `f"CLI rejected {command!r}: {out}"` → `'the exact command'` with Python
  quoting/escaping rules) — Go's `%q` verb in `fmt.Errorf`/`fmt.Sprintf` is
  the closest analogue (Go-style double-quote escaping, not Python's), so
  error STRING output will differ in exact quoting style even when the
  semantic content matches; if any Go test asserts on exact error string
  text ported from a Python fixture, expect `%q` vs `!r` quoting-character
  differences and adjust expected strings accordingly rather than trying to
  hand-roll Python-style repr quoting in Go.
* **`dataclass(frozen=True)`** — maps to a Go struct with unexported fields
  + a constructor function returning by value (no setters), or simply an
  exported struct with a documented "treat as immutable" convention,
  whichever matches the Go repo's existing `models`/`registry` package
  convention (again, not read here per the task boundary).

---

## 9. Parity checklist

### 9.1 Commands — every exact command STRING template (verbatim, including per-model variants)

- [ ] `enable` (session setup, all 4 models)
- [ ] `terminal length 0` (session setup, all 4 models)
- [ ] `show version` (all 4 models)
- [ ] `show port all` (all 4 models)
- [ ] `show vlan brief` (gsm7252ps only)
- [ ] `show vlan` (m4300-24x, m4300-16x, gsm7228ps — `_M4300_OVERRIDES`/`_GSM7228PS`)
- [ ] `show vlan {vlan}` (all 4 models, templated)
- [ ] `show vlan port all` (all 4 models)
- [ ] `show mac-addr-table` (all 4 models)
- [ ] `show lldp remote-device all` (all 4 models)
- [ ] `show poe port info all` (all 4 models — call-site gated off for m4300-24x)
- [ ] `show environment` (all 4 models)
- [ ] `show network` (gsm7252ps, gsm7228ps)
- [ ] `show ip management` (m4300-24x, m4300-16x)
- [ ] `show interface ethernet {iface}` (all 4 models, templated per-port)
- [ ] `vlan database` (all 4 models)
- [ ] `vlan {vlan}` (all 4 models, templated)
- [ ] `vlan name {vlan} {name}` (all 4 models, templated)
- [ ] `no vlan {vlan}` (all 4 models, templated)
- [ ] `configure` (all 4 models)
- [ ] `interface {iface}` (all 4 models, templated; `1/0/{port}` default, `1/g{port}`/`1/xg{port}` on gsm7228ps)
- [ ] `switchport mode general` (m4300-24x, m4300-16x, gsm7228ps — NOT gsm7252ps)
- [ ] `vlan participation {action} {vlan}` (`action` = `include`|`exclude`, all 4 models, templated)
- [ ] `vlan tagging {vlan}` (all 4 models, templated)
- [ ] `no vlan tagging {vlan}` (all 4 models, templated)
- [ ] `vlan pvid {vlan}` (all 4 models, templated)
- [ ] `exit` (all 4 models)
- [ ] `poe` (all 4 models except m4300-24x which lacks the command entirely)
- [ ] `no poe` (same 3 models)
- [ ] `poe reset` (same 3 models)
- [ ] `no shutdown` (all 4 models)
- [ ] `shutdown` (all 4 models)
- [ ] `network parms {address} {netmask} {gateway}` (gsm7252ps, gsm7228ps — EXEC mode, templated)
- [ ] `ip management address {address} {netmask}` (m4300-24x, m4300-16x — config mode, templated)
- [ ] `ip default-gateway {gateway}` (m4300-24x, m4300-16x — config mode, templated)
- [ ] `reload` (all 4 models)
- [ ] `no ip http secure-server` (cert deploy, m4300-24x/-16x/gsm7252ps only — gsm7228ps has no SCP cert path)
- [ ] `copy scp://{scp_source}{remote_dir}/{base}-server.pem nvram:sslpem-server` (cert deploy, templated)
- [ ] `copy scp://{scp_source}{remote_dir}/{base}-root.pem nvram:sslpem-root` (cert deploy, optional `chain=True`, templated)
- [ ] `ip http secure-server` (cert deploy)
- [ ] `write memory` (cert deploy + `reboot`'s `reload` reuse of the same interactive machinery)

### 9.2 Parsers — every function in `protocols/cli/parse.py`

- [ ] `labelled_values(text) -> dict[str, str]`
- [ ] `_ruler_spans(ruler) -> list[tuple[int, int|None]]`
- [ ] `_slice_cell(row, start, end) -> str`
- [ ] `_slice_row(spans, row) -> list[str]`
- [ ] `iter_table_rows(text, *, after=None) -> Iterator[list[str]]`
- [ ] `header_columns(text, *, after=None) -> list[str]`
- [ ] `_int(text) -> int | None`
- [ ] `_phys_port(iface) -> int | None`
- [ ] `parse_version(text, models) -> DetectedModel`
- [ ] `_speed_mbps(phys_status) -> int | None`
- [ ] `parse_port_status(text) -> list[PortStatus]`
- [ ] `parse_vlan_brief(text) -> list[tuple[int, str]]`
- [ ] `parse_vlan_detail(text, *, name=None) -> VLANInfo`
- [ ] `parse_pvids(text) -> list[tuple[int, int]]`
- [ ] `parse_mac_table(text) -> list[MacEntry]`
- [ ] `parse_lldp(text) -> list[LLDPNeighbor]`
- [ ] `parse_poe(text) -> list[PoEStatus]`
- [ ] `parse_environment(text) -> list[Sensor]`
- [ ] `parse_mgmt_ip(text) -> MgmtIpConfig`
- [ ] `parse_interface_counters(text, port) -> PortStats`

### 9.3 `commands.py` data/logic

- [ ] `CliModelSpec` struct, all 34 fields (§1.2 table)
- [ ] `CliModelSpec` methods: `vlan_detail`, `iface`, `interface_stats`, `vlan_create`, `vlan_name`, `vlan_delete`, `interface`, `vlan_participation`, `vlan_tagging`, `vlan_pvid`, `poe_admin`, `port_admin`, `mgmt_ip` (13 methods)
- [ ] `_M4300_OVERRIDES` (4-field override table)
- [ ] `_GSM7252PS` spec instance
- [ ] `_M4300_24X` spec instance
- [ ] `_M4300_16X` spec instance
- [ ] `_GSM7228PS` spec instance (unique iface templates + telnet_port 60000)
- [ ] `cli_spec(model) -> CliModelSpec` two-stage-guard dispatcher
- [ ] `ScpCertProfile` struct
- [ ] 3 `ScpCertProfile` instances (m4300-24x, m4300-16x, gsm7252ps)
- [ ] `scp_cert_profile(model) -> ScpCertProfile` two-stage-guard dispatcher

### 9.4 `cli_read.py` ops — `CliReader`, 10 methods

- [ ] `get_ports()`
- [ ] `get_stats()` (N+1 round trips, iterates ACTUAL ports not nominal port_count)
- [ ] `get_vlans()` (N+1 round trips, name from brief page overrides detail page)
- [ ] `get_pvids()`
- [ ] `get_macs()` (gated on `has_mac_table`)
- [ ] `get_lldp()`
- [ ] `get_poe()` (gated on `poe_port_count == 0`)
- [ ] `get_sensors()`
- [ ] `get_mgmt_ip()`
- [ ] `identify()` (searches whole `MODELS` registry)

### 9.5 `cli_write.py` ops — `CliWriter`, 10 methods + module function

- [ ] `create_vlan(vlan, name, *, force)` (force discarded)
- [ ] `delete_vlan(vlan, *, force)` (existence precondition + membership-clash gate)
- [ ] `set_vlan_membership(vlan, port, mode, *, force)` (scoped verification)
- [ ] `set_pvid(port, vlan, *, force)`
- [ ] `set_poe(port, on, *, force, timeouts, sleep, clock)` (polled verify, guard only on off)
- [ ] `cycle_poe(port, *, force, timeouts, sleep, clock)` (`poe reset`, delivering predicate)
- [ ] `clear_poe_fault(port, *, force, timeouts, sleep, clock)` (`poe reset`, delivering-or-searching predicate)
- [ ] `set_port_enabled(port, enabled, *, force)` (guard only when disabling)
- [ ] `set_mgmt_ip(address, netmask, gateway, *, force)` (force always required, 2 dialects)
- [ ] `reboot(*, force)` (force always required, transport-error-as-success)
- [ ] `deploy_certificate_scp(session, *, scp_source, scp_password, remote_dir, base, chain, writemem_stuff)` (module fn, 5-step sequence)
- [ ] `scp_source_url(scp_source, remote_dir, filename) -> str` (module fn, no separator between scp_source/remote_dir)

### 9.6 Shared write-path helpers (private in Python, still need Go equivalents)

- [ ] `_guard(port, force)` — protected-port check
- [ ] `_run(command)` — empty-output-is-success convention
- [ ] `_in_mode(enter, body)` — nested config-mode with counted unwind
- [ ] `_general_mode()` — conditional switchport-mode prelude
- [ ] `_vlan(vlan)` — VLAN-by-id lookup via full `get_vlans()`
- [ ] `_port_mode(info, port)` — 3-way VlanMode derivation
- [ ] `_poe_status(port)` / `_port_status(port)` — single-port lookup via full read
- [ ] `_require_poe()` — PoE hardware-presence gate
- [ ] `_poe_reset(port, ..., recovered, timeout_message)` — shared `poe reset` + poll helper

### 9.7 Transport-layer context (cited, not this slice's primary scope, but load-bearing for command sequencing)

- [ ] `CliSession` protocol: `run`, `run_scp_copy`, `run_write_memory`, `close`
- [ ] `ShellDriver.setup()` — initial-prompt + enable(+password) + paging-off sequence
- [ ] `ShellDriver.run()` — command echo + trailing-prompt stripping (`_clean`)
- [ ] `ShellDriver.run_scp_copy()` — TOFU/password/confirm mid-flight prompt driving
- [ ] `ShellDriver.run_write_memory()` — `prestuff` vs read-then-answer confirm dialects
- [ ] Prompt/password/SCP regexes: `_PROMPT_RE`, `_PASSWORD_RE`, `_SCP_TOFU_RE`, `_SCP_PASSWORD_RE`, `_SCP_CONFIRM_RE`, `_SCP_SUCCESS_RE`, `_SCP_FAILURE_RE`
