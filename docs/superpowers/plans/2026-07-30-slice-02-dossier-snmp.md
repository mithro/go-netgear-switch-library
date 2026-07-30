# SNMP Read Core — Porting Dossier (Slice 02)

**Pinned Python reference:** `python-netgear-switch-library` branch
`fix/s3300-52x-live-verify` @ `aaab57751559c0b172ca61c323d4649cddfd1eae`.
This repo is read-only; every quote below is verbatim from that state.

**PIN NOTE (resolved during slice 02):** the spec originally pinned
`fix/live-hardware-parity` @ `b73e7519`. The Python checkout advanced
mid-session to `fix/s3300-52x-live-verify` (= old pin + 4 commits:
`95dd333` real S3300-52X capture, `bce5ba5` authoritative sysObjectID model
detection, `855acb0` s3300↔gsm7228ps aliases, `aaab577` gsm7228ps reseed +
`verified=True`). The spec has been re-pinned to `aaab577`; slice 1's Go
registry already matches it (MODEL_ALIASES, gsm7228ps Verified=true).
Consequences for this dossier, folded in below:
- `detect_model_from_sysobjectid` + `SYSOBJECTID_MODELS` **exist and are in
  scope** (§3.26a); `read_system_info` tries sysObjectID FIRST, sysDescr as
  fallback (§4.1).
- `seed_gsm7228ps` is now TRANSCRIBED from the real S3300-52X capture
  (`tests/fixtures/captures/gsm7228ps.json`, host 10.1.5.11) — the virtual
  dossier's §4.2 (illustrative seed) is stale; read `seed.py` directly for
  that seed's values.

**Audience:** Go engineers porting the SNMP read path 1:1 without reading the
Python source themselves. Where this dossier and the pinned source disagree,
the source wins.

---

## 1. `src/netgear_switch/protocols/snmp/oids.py`

### 1.1 Standard-MIB OID constants (verbatim)

```python
SYS_DESCR = "1.3.6.1.2.1.1.1.0"       # sysDescr: text incl. the model name
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"   # sysObjectID: matched via SYSOBJECTID_MODELS (authoritative), else carried raw
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"                # ifType (6=ethernetCsmacd=physical)
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"        # ifAdminStatus (1=up,2=down)
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"        # ifOperStatus  (1=up,2=down)
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_IN_UCAST = "1.3.6.1.2.1.31.1.1.1.7"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HC_OUT_UCAST = "1.3.6.1.2.1.31.1.1.1.11"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"    # Mbps
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
DOT1D_BASE_BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1"  # scalar (.0); BRIDGE-MIB base MAC
DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # MAC table, port column ONLY
DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"
DOT1Q_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"
DOT1Q_VLAN_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"
DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
DOT1Q_VLAN_STATIC_ROW_STATUS = "1.3.6.1.2.1.17.7.1.4.3.1.5"
ROW_STATUS_CREATE_AND_GO = 4
ROW_STATUS_DESTROY = 6
ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"   # int enum; 6=powerSupply,7=fan
ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
ENT_CLASS_POWER_SUPPLY = 6
ENT_CLASS_FAN = 7
LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1"   # columns: 5=chassis,7=portId,8=portDesc,9=sysName
PETH_PSE_PORT_TABLE = "1.3.6.1.2.1.105.1.1.1"  # RFC3621; col3=admin, col6=detect
IP_ADENT_ADDR = "1.3.6.1.2.1.4.20.1.1"
IP_ADENT_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_ADENT_NETMASK = "1.3.6.1.2.1.4.20.1.3"
IP_ADDRESS_IFINDEX = "1.3.6.1.2.1.4.34.1.3"   # RFC-4293 ipAddressTable (M4300 fallback)
IP_ROUTE_DEST = "1.3.6.1.2.1.4.21.1.1"
IP_ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"    # gateway where dest=0.0.0.0
```

Notes baked into the source comments (port as Go doc comments):
- `SYS_DESCR`/`SYS_OBJECT_ID` are `.0`-qualified scalar leaf OIDs, fetched
  with a plain exact-OID **GET** (never walked) by `read_system_info`.
- `IF_TYPE` value `6` = ethernetCsmacd = real physical port; filters
  LAG(161)/CPU(1)/l2vlan(135) pseudo-interfaces out of ports/stats/pvids.
- `LLDP_REM_TABLE` instance shape: `<column>.<timeMark>.<localPortNum>.<remIndex>`.
- `PETH_PSE_PORT_TABLE` instance shape: `<column>.<group>.<port>`; **only
  columns 3 (admin) and 6 (detect) are honoured — never column 1**.
- `IP_ADDRESS_IFINDEX` row index: `<type>.<len>.<addr-bytes...>` (type 1 =
  ipv4, len 4 → 4 octets = the address itself, encoded IN the index).

### 1.2 `BOX_SENSOR_COLUMNS` (verbatim)

```python
BOX_SENSOR_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("fan", "RPM", "6.1.4"),
    ("power", "W", "8.1.5"),
    ("temperature", "C", "15.1.3"),
)
```
Documentation/reference tuple only — **not consumed at runtime** (readers
construct the triple inline from `VendorOids` fields). A test asserts the
three kinds are covered. Port as a doc/reference table too.

### 1.3 `DHCP_MODE_OID_SUFFIX = "99.1"`

UNVERIFIED Netgear private OID for DHCP-vs-static mgmt-IP mode; an
unconfirmed guess used only so mock and reader agree under test; MUST be
confirmed via capture before trusted; until then `get_mgmt_ip` returns
IpMode.UNKNOWN when absent. Every call site derives via
`VendorOids.dhcp_mode_unverified` (`{base}.99.1`) — no bare `.99.1`
literals anywhere.

### 1.4 `VendorOids` — every field + formula

```python
@dataclass(frozen=True)
class VendorOids:
    base: str
    poe_power_mw: str                    # {base}.15.1.1.1.2
    box_fan: str                         # {base}.43.1.6.1.4
    box_psu_power: str                   # {base}.43.1.8.1.5
    box_temp: str                        # {base}.43.1.15.1.3
    dhcp_mode_unverified: str            # {base}.99.1
    mgmt_write_addr_unverified: str      # {base}.98.1
    mgmt_write_netmask_unverified: str   # {base}.98.2
    mgmt_write_gateway_unverified: str   # {base}.98.3
```
`vendor_oids(model)` raises `UnsupportedCapabilityError("model {key!r} has
no SNMP vendor OID subtree")` iff `model.snmp_vendor_base is None`. Bases:
`_FM = "1.3.6.1.4.1.4526.10"` (m4300-24x/-16x, gsm7252ps, m7300),
`_SMP = "1.3.6.1.4.1.4526.11"` (gsm7228ps, xs748t), `None` (gs110emx,
gs305ep, gs105pe, gs728tpp — gs728tpp is SNMP but standard-MIBs-only).

Test-pinned values:
```
vendor_oids(gsm7252ps).poe_power_mw         == "1.3.6.1.4.1.4526.10.15.1.1.1.2"
vendor_oids(gsm7252ps).box_fan              == "1.3.6.1.4.1.4526.10.43.1.6.1.4"
vendor_oids(gsm7252ps).box_psu_power        == "1.3.6.1.4.1.4526.10.43.1.8.1.5"
vendor_oids(gsm7252ps).box_temp             == "1.3.6.1.4.1.4526.10.43.1.15.1.3"
vendor_oids(gsm7252ps).dhcp_mode_unverified == "1.3.6.1.4.1.4526.10.99.1"
vendor_oids(gsm7228ps).poe_power_mw         == "1.3.6.1.4.1.4526.11.15.1.1.1.2"
vendor_oids(gs110emx)                       raises UnsupportedCapabilityError
```

### 1.5–1.7 `has_vendor_oids` / `unimplemented_roots` / `is_oid_implemented`

```python
def has_vendor_oids(model): return model.snmp_vendor_base is not None

def unimplemented_roots(model):
    if model.poe_port_count > 0: return []
    roots = [PETH_PSE_PORT_TABLE]
    if model.snmp_vendor_base is not None:
        roots.append(vendor_oids(model).poe_power_mw)
    return roots

def is_oid_implemented(model, oid):
    dotted = oid.lstrip(".")
    for root in unimplemented_roots(model):
        if dotted == root or dotted.startswith(root + "."):
            return False
    return True
```
Only PoE-gated (verified live on m4300-24x: bulkwalk of PoE root answers a
single noSuchObject). Deliberately narrower than "has a value right now".

---

## 2. `src/netgear_switch/protocols/snmp/client.py`

```python
ABSENT_TYPES = frozenset({"NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW"})

@dataclass(frozen=True)
class SnmpRow:
    oid: str
    value: int | str | bytes
    snmp_type: str

class SnmpError(NetgearSwitchError): ...

def full_oid(oid, oid_index):
    oid = oid.lstrip(".")
    return f"{oid}.{oid_index}" if oid_index else oid
```
- `SnmpRow.value` normalization contract: int for integer-family, str for
  text/OID/IP, bytes for raw octet strings — **all transports must yield
  equal values for the same wire value** (pinned by test_value_parity.py).
- `SnmpError` also used for parse-time drift (malformed row under a base),
  not just transport failures.
- `full_oid` test-pinned: `(".1.3.6.1.2.1.2.2.1.8","1")→"1.3.6.1.2.1.2.2.1.8.1"`;
  `("1.3.6.1.2.1.2.2.1.8.1","")→` unchanged. Neither Python transport
  actually calls it (kept for API parity).
- Protocols: `SnmpClient{get(oids)->rows, walk(base)->rows}`;
  `SnmpWriteClient` adds `set(varbind)`, `set_many(varbinds)` (one PDU,
  atomic). Async twins identical. `get([])` short-circuits to `[]` with no
  I/O in both transports (tested).

---

## 3. `src/netgear_switch/protocols/snmp/parse.py`

### 3.0 `_suffix(row, base)` — literal string-prefix match on `base + "."`; no OID normalization anywhere.

### 3.1 `index_int_column(rows, base_oid) -> dict[int, int]`
Single-int-index column → `{index: int_value}`. Skips rows with dotted
(deeper) suffixes or non-matching prefix. Errors: `SnmpError("malformed
index {suffix!r} at {oid}")`, `SnmpError("non-integer value {value!r} at
{oid}")`. Absent column → `{}`.

### 3.2 `index_str_column(rows, base_oid) -> dict[int, str]`
Text columns. bytes → `decode("utf-8","replace")` (never raises); str
as-is; other → `SnmpError("non-string value ...")`. Non-int index →
`SnmpError("non-integer index ...")`. Rationale: a text OCTET STRING can
arrive str (CLI) or bytes (pysnmp printability heuristic).

### 3.3 `ETHERNET_CSMACD = 6`, `_physical_ports(if_types) -> set[int] | None`
`None` when the ifType walk is entirely empty (caller keeps every
interface); else the set of ifIndexes with type 6. Verified live on M4300
(16 physical vs 146 total rows). Consumers: parse_port_status,
parse_port_stats, parse_pvids (all take optional `if_types`, default `()`).

### 3.4 `parse_port_status(admin, oper, speed, names, aliases, if_types=())`
Positional args in that order. Ports = sorted(admin ∪ oper keys), filtered
to physical. Per port: `link_up = oper==1`; `admin_enabled = admin==1`
(exactly 1); `speed_mbps = mbps if (mbps and link_up) else None` — **None
unless link is up** (down gsm7252ps port reports configured 10000, must
not surface) and 0 → None; `name`/`description` use `or None` — **empty
string is absent, never ""**.

### 3.5 `parse_port_stats(*, in_octets, out_octets, in_ucast, out_ucast, in_errors, out_errors, if_types=())`
Keyword-only. Columns map against IF_HC_IN_OCTETS / IF_HC_OUT_OCTETS /
IF_HC_IN_UCAST / IF_HC_OUT_UCAST / IF_IN_ERRORS / IF_OUT_ERRORS. Ports =
sorted union of all 6 key sets, physical-filtered. Absent → None, never 0.

### 3.6 `decode_port_bitmap(bitmap: bytes | str) -> frozenset[int]`
MSB-first: bit7 of byte0 = port 1 (`0x80>>bit`; port = byte_idx*8+bit+1).
Empty → empty set. str → latin-1 encode first; failure →
`SnmpError("malformed VLAN port bitmap {bitmap!r}")`. Pinned:
`0b10100000 → {1,3}`; `[0, 0b10000000] → {9}`.

### 3.7 `_vlan_bitmap_map(rows, base)` — VLAN index must be `isdigit()`
(rejects negatives); non-digit → `SnmpError("malformed VLAN index ...")`;
value not bytes/str → `SnmpError("malformed VLAN port bitmap type at ...")`.

### 3.8 `parse_vlans(names, egress, untagged)`
Enumerates **only VLANs present in the names walk** (bitmap-only VLANs
silently dropped). `member = decode(egress)`, `untag = decode(untagged)`,
`tagged = member - untag` (derived, never read). `name or None`.

### 3.9 `parse_pvids(rows, if_types=()) -> list[tuple[int, int]]`
Sorted (bridge_port, pvid) pairs, physical-filtered **directly against
ifIndex with NO dot1dBasePortIfIndex translation** — a translation was
tried and is provably WRONG (couples PVIDs to the independently-populated
FDB base-port map). Do not "fix" this when porting.

### 3.10 MAC helpers
- `_format_mac_bytes(seq_of_decimal_strings)` → `XX:XX:..` uppercase (FDB
  OID-index bytes).
- `_format_mac_octetstring(value)` → MAC iff bytes len 6 or str len 6
  (latin-1 chars); else None.
- `_mac_from_ascii_text(value)` → the **M4300-24X quirk**: accepts a
  17-char ASCII `XX:XX:XX:XX:XX:XX` (6 parts, each exactly 2 hex chars,
  0–0xFF), case-insensitive in, uppercase out; None on any mismatch.

### 3.11 LLDP text/ID formatting
- `_format_chassis_id`: MAC-shaped octetstring → colon-hex; else plain text
  (`str(value)` for non-str non-MAC bytes — a latent oddity; port literally).
- `_column_text`: bytes → utf-8-replace; str as-is; else str().
- `_format_port_id`: 6-byte bytes → always MAC; 6-char str → MAC **only if
  `not value.isprintable()`** — guards a genuine 6-char ASCII portId like
  `"1/xg51"` from corrupting into hex. **Single trickiest quirk in the
  file; get the printable check backwards and interface-name portIds
  corrupt silently.**

### 3.12 `parse_base_mac(rows) -> str | None`
Scans rows under `DOT1D_BASE_BRIDGE_ADDRESS + "."`; first match wins.
`_format_mac_octetstring(value) or _mac_from_ascii_text(value)`; both None
→ `SnmpError("malformed base MAC {value!r} at {oid}")`. No rows → None.

### 3.13 `parse_lldp(rows) -> list[LLDPNeighbor]`
Prefix `LLDP_REM_TABLE + ".1."`; suffix must be exactly 4 parts
(`col.timeMark.localPort.remIndex`) else `SnmpError("malformed LLDP index
at {oid}")`; non-int column → `SnmpError("non-integer LLDP column ...")`.
Group by (timeMark, localPort, remIndex) as raw strings. Columns 5/7/8/9 =
chassis/portId/portDesc/sysName; others ignored. All-empty group → skipped
entirely. Non-int local port at emit time → `SnmpError("non-integer LLDP
local port ...")`. Fields: `_column_text(x) or None` (sys_name, port_desc),
`_format_chassis_id(x) or None`, `_format_port_id(x) or None`. Sorted by
local_port.

### 3.14 `parse_macs(fdb, bridge_ports) -> list[MacEntry]`
`bridge_to_if = index_int_column(bridge_ports, DOT1D_BASE_PORT_IF_INDEX)`.
FDB suffix must be exactly 7 parts (vlan + 6 MAC bytes) else
`SnmpError("malformed FDB index at {oid}")`; non-int vlan/bridge-port raise
naming the OID. `port = bridge_to_if.get(bridge_port, bridge_port)` —
**fallback to the bridge port number when unmapped**. Sorted by
(port, mac).

### 3.15 `DETECT_MAP` + `parse_poe(status, power_mw)`
```python
DETECT_MAP = {1: DISABLED, 2: SEARCHING, 3: DELIVERING, 4: FAULT}  # else UNKNOWN
```
Status rows: suffix exactly 3 parts (`col.group.port`) else **silently
skipped** (not raised — unlike most parsers); only cols 3 and 6 kept;
non-int value → `SnmpError("non-integer PoE value ...")`. power_mw rows:
keyed by FINAL suffix component only; non-int **silently skipped**. Emit
sorted by (group, port): missing col 3 → `SnmpError("PoE port {port}
missing admin (col 3)")`; missing col 6 → analogous; `power_mw =
mw.get(port)` — None, never 0, when absent (covers no-vendor models via
`power=[]`).

### 3.16 `parse_box_sensors(rows_by_kind: Sequence[(kind, unit, rows)])`
`instance = oid.split(".")[-1]` (string, used verbatim in name).
`"Not Supported"` literal → skipped, not an error. Other non-int →
`SnmpError("non-integer {kind} reading {value!r} at {oid}")`. Emits
`Sensor(name=f"{kind}{instance}", kind, value=float(int), unit)`. Indices
walk-discovered, never hardcoded.

### 3.17 `parse_entity_sensors(class_rows, name_rows, descr_rows)`
ENTITY-MIB fallback (gs728tpp). `kind_of = {6: "power", 7: "fan"}`; other
classes skipped. Name fallback chain: entPhysicalName → entPhysicalDescr →
`f"{kind}{idx}"`. **`value = float("nan")`, `unit = "inventory"`** —
inventory-only, a real per-backend difference. Go: `math.NaN()`; test with
`math.IsNaN`, never `==`.

### 3.18 `_canon_sensor_name(name)` — `.replace("Power Supply","PS").replace("PowerSupply","PS")` so SNMP names match HTTP DiagnosticsUnitList labels ("Main PowerSupply"→"Main PS").

### 3.19 `_ip_str(row)` — non-str IpAddress value → `SnmpError("non-IP value {value!r} at {oid}")`.

### 3.20 `_ipv4_from_rfc4293_index(rows) -> str | None`
Index shape `<type>.<len>.<b1>.<b2>.<b3>.<b4>`; accept only type=="1" AND
len=="4" (skip IPv6 type 2/len 16 and short indexes); skip 127.0.0.1;
FIRST match wins; None otherwise.

### 3.21 `parse_mgmt_ip(addr, netmask, route_dest, route_nexthop, dhcp_mode, base_mac, addr_rfc4293=())`
1. RFC-1213 primary: first non-loopback `IP_ADENT_ADDR` row → ip +
   remembered `ip_index`.
2. RFC-4293 fallback ONLY if step 1 found nothing.
3. Netmask ONLY via the RFC-1213 path (exact-OID `IP_ADENT_NETMASK.<ip_index>`
   match); RFC-4293 path never gets a netmask (stays None honestly).
4. Gateway: build `{suffix: value}` from ALL route_dest rows; first
   nexthop row whose suffix's dest == "0.0.0.0" wins (default route).
5. DHCP mode: only the FIRST dhcp_mode row is ever consulted; int() failure
   → UNKNOWN (no raise); 1→DHCP, 2→STATIC, other→UNKNOWN. Explicitly
   best-effort/UNVERIFIED.
6. base_mac via parse_base_mac.
Errors: non-str value under addr/netmask/nexthop → SnmpError naming OID.
Test-pinned: RFC-4293 recovers 10.1.5.20 skipping loopback+IPv6; RFC-1213
wins when both populated; mode 3 → UNKNOWN; non-coercible mode value →
UNKNOWN; absent mode/gateway/base_mac independently None/UNKNOWN.

### 3.22 `_scalar_text(rows, oid)` — **EXACT OID equality** (not prefix; input
is a GET result). Absent → None; present-non-str → SnmpError naming OID.

### 3.23 `parse_system_info(rows) -> (sys_descr, sys_object_id)` — pure
extraction of the two scalars; NO matching here.

### 3.24 `_model_match_tokens(model) -> tuple[str, ...]`
`[key.upper()]` + display_name tokens: if the name ends with `)` and
contains `(`, BOTH the main name and the bracketed alias are tokens
("GSM7228PS (S3300)" → "GSM7228PS", "S3300"); else the stripped name.
Empty tokens filtered.

### 3.25 `_WORD_STRIP_CHARS = string.punctuation.replace("-", "")` and
`_candidate_tokens(sys_descr)` — whitespace-split, strip punctuation
(EXCEPT hyphen) from word edges, uppercase, frozenset. Hyphen deliberately
kept (meaningful inside SKUs like "M4300-24X").

### 3.26 `detect_model_from_sysdescr(sys_descr, models) -> str | None`
Whole-word, case-insensitive, exact-token matching. Falsy sys_descr → None.
Collect keys of models with ANY token in the candidate set; return the key
iff EXACTLY ONE model matched; else None (zero or ambiguous → None, never
guesses). HONESTY CONSTRAINTS (regression-pinned):
- `"GS305EPP"` must NOT match `GS305EP`; `"S3300-28X"`/`"S3300-28X-PoE+"`
  must NOT match alias token `S3300` (hyphens not stripped).
- Unregistered/garbage/non-Netgear → None. Multi-model collision → None.

Full test table (port verbatim as Go table-driven cases):
```
"NETGEAR M4300-24X, Software 12.0.11.9, Linux 3.6.5"  -> "m4300-24x"
"NETGEAR M4300-16X, Software 12.0.11.9"               -> "m4300-16x"
"NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6"  -> "gsm7252ps"
"NETGEAR GSM7228PS Managed Switch, firmware 6.4.2.9"  -> "gsm7228ps"
"NETGEAR GS110EMX"                                    -> "gs110emx"
"NETGEAR GS305EP"                                     -> "gs305ep"
"NETGEAR M7300-24XF, Software 12.0.4.5"               -> "m7300"
"NETGEAR XS748T Managed Switch"                       -> "xs748t"
"NETGEAR GS728TPP Managed Switch, firmware 6.4.2.9"   -> "gs728tpp"
"netgear gsm7252ps switch"                            -> "gsm7252ps"
"Netgear M4300-24X"                                   -> "m4300-24x"
"NETGEAR S3300 Managed Switch, firmware 6.4.2.9"      -> "gsm7228ps"
"NETGEAR XSM4324CS"                                   -> "m4300-24x"
"NETGEAR GS752TP switch"                              -> None
"NETGEAR M7300-28G"                                   -> None
"NETGEAR M7300 switch"                                -> "m7300"
"Cisco IOS Software, C2960"                           -> None
""                                                     -> None
None                                                   -> None
"NETGEAR GS305EPP Managed Switch"                      -> None
"NETGEAR S3300-28X"                                    -> None
"NETGEAR S3300-28X-PoE+ Managed Switch"                -> None
(two synthetic colliding fake models in one string)    -> None
```

### 3.26a `SYSOBJECTID_MODELS` + `detect_model_from_sysobjectid` (new-pin)

```python
SYSOBJECTID_MODELS: Mapping[str, str] = MappingProxyType(
    {"1.3.6.1.4.1.4526.100.10.19": "gsm7228ps"}
)

def detect_model_from_sysobjectid(sys_object_id, models) -> str | None:
    if not sys_object_id: return None
    key = SYSOBJECTID_MODELS.get(sys_object_id)
    if key is not None and key in models: return key
    return None
```
The AUTHORITATIVE detector: entries are added ONLY from real captures
(the single current entry is the live-captured S3300-52X product OID).
Returns a key only when the OID is in the map AND registered; never a
guess. Rationale: the real S3300-52X's sysDescr ("S3300-52X-PoE+ ...") is
DELIBERATELY unmatchable by the sysDescr heuristic (same textual shape as
the unregistered S3300-28X SKU), so the OID map is the only safe
auto-detect for it.

---

## 4. `src/netgear_switch/snmp_read.py`

### 4.1 `read_system_info(client) -> DetectedModel` (and async twin)

```python
def read_system_info(client: SnmpClient) -> DetectedModel:
    rows = client.get([oids.SYS_DESCR, oids.SYS_OBJECT_ID])   # ONE GET PDU, two OIDs
    sys_descr, sys_object_id = parse.parse_system_info(rows)
    key = parse.detect_model_from_sysobjectid(sys_object_id, MODELS) \
          or parse.detect_model_from_sysdescr(sys_descr, MODELS)
    return DetectedModel(key=key, sys_descr=sys_descr, sys_object_id=sys_object_id)
```
**sysObjectID first (authoritative), sysDescr fallback.** Module-level free
function taking a bare client (no model — identification exists for when
the model isn't yet known). Port the one-PDU batching of both OIDs.

### 4.2 `_require_snmp(model)` — raises
`UnsupportedCapabilityError("model {key!r} has no SNMP backend")` when
Backend.SNMP not in model.backends; called by reader constructors (Plus
models fail before any I/O).

### 4.3 Readers — `SnmpReader(client, model)` / `AsyncSnmpReader` mirror.
Vendor OIDs resolved lazily inside get_poe/get_sensors/get_mgmt_ip only.

### 4.4 `get_ports()` — 6 walks in order: IF_ADMIN_STATUS, IF_OPER_STATUS,
IF_HIGH_SPEED, IF_NAME, IF_ALIAS, IF_TYPE → parse_port_status positionally.

### 4.5 `get_stats()` — 7 walks: the 4 HC counters, IF_IN/OUT_ERRORS, IF_TYPE
→ parse_port_stats keywords.

### 4.6 `get_vlans()` (3 walks: NAME, EGRESS, UNTAGGED), `get_pvids()`
(DOT1Q_PVID + IF_TYPE), `get_lldp()` (one LLDP_REM_TABLE walk),
`get_macs()` (DOT1Q_TP_FDB_PORT + DOT1D_BASE_PORT_IF_INDEX; no
has_mac_table guard in the method — construction already enforced SNMP).

### 4.7 `get_poe()` — **guard BEFORE any walk**:
`poe_port_count == 0` → `UnsupportedCapabilityError("model {key!r} has no
PoE (no PSE ports)")` (even against a mock that would answer). Else walk
PETH_PSE_PORT_TABLE always + vendor poe_power_mw only if has_vendor_oids
(else `power = []` → power_mw all None).

### 4.8 `get_sensors()` — two exclusive paths:
1. No vendor subtree → ENTITY-MIB walks (CLASS, NAME, DESCR) →
   parse_entity_sensors; empty → `[]` honestly, never raises.
2. Vendor subtree → walk box_fan, box_psu_power, box_temp (units RPM/W/C in
   that order); **all three empty → raise UnsupportedCapabilityError**
   ("model {key!r} declares vendor sensor OIDs ({snmp_vendor_base}) but the
   vendor fan/PSU/temperature walk returned nothing") — the parity fix that
   exposed the historical gs728tpp mismatch; partial population is fine.

### 4.9 `get_mgmt_ip()` — 7 walk args to parse_mgmt_ip: IP_ADENT_ADDR,
IP_ADENT_NETMASK, IP_ROUTE_DEST, IP_ROUTE_NEXTHOP, dhcp (vendor walk or []
if no vendor base), DOT1D_BASE_BRIDGE_ADDRESS, IP_ADDRESS_IFINDEX. All
walks (never GET) — absent DHCP OID yields [] → UNKNOWN, no raise.

### 4.10 `get_system_info()` — `read_system_info(self.client)`; result does
NOT depend on self.model (tested: reader bound to gsm7252ps against a
GS110EMX device still returns gs110emx).

### 4.11 Async mirror — byte-identical OID lists/ordering; sync/async parity
directly tested feeding the same fake tables. In Go (single reader) the
walked-OID sequencing per method must still match exactly (fixtures key
off it).

---

## 5. Transports

### 5.1 net-snmp CLI transport (`transport/sync/snmp_netsnmp_cli.py`)

Go slice 2 uses gosnmp, not a CLI shell-out — but §5.1.3/§5.1.5 define the
NORMALIZED VALUE CONTRACT any Go transport must reproduce, and the net-snmp
CLI remains the cross-test oracle against the Go fake.

#### argv (exact)
`[binary, "-v2c", "-c", community, "-On", "-Oe", "-OU", "-Ln", "-t",
str(timeout=10), "-r", str(retries=1), host, ...]`; host is a single
"host[:port]" string. get → snmpget + each OID appended; walk →
snmpbulkwalk + base_oid (empty_subtree_ok=True); set_many → snmpset +
flattened (oid, type_letter, value) triples. Missing binary →
`SnmpError("net-snmp not installed: {binary!r} is not on PATH. ...")`.
Import of the module never shells out (tested).

#### `_normalize(snmp_type, value)` type mapping

| net-snmp token | value | notes |
|---|---|---|
| INTEGER, Integer32, Gauge32, Gauge, Unsigned32, Counter32, Counter64, Counter | int | non-numeric → SnmpError |
| Timeticks | int | regex `\((\d+)\)`; no match → SnmpError |
| STRING | str | strips one MATCHED pair of surrounding `"` only |
| Hex-STRING | bytes | multi-line joining below; never via _normalize |
| OID | str | `.lstrip(".")` leading dot only |
| IpAddress / other | str | passthrough, no quote-strip |

#### `parse_netsnmp_lines(text, *, empty_subtree_ok=False)` state machine
- Blank lines skipped. Lines without `" = "`: Hex-STRING continuation if
  pending, else skipped.
- On each `" = "` line: flush pending hex first; `oid = lhs.strip().lstrip(".")`.
- `rest in ('""', "")` → empty STRING row directly.
- `TYPE: value` (split on FIRST `": "`) or bare `TYPE:` → typed row;
  **checked BEFORE marker detection** (a STRING containing "no such object"
  parses as a value, never a marker).
- Hex-STRING: buffer chunks (first line + continuations); flush joins ALL
  whitespace-split 2-hex-digit tokens across lines into one bytes row.
  Final flush after the last line (trailing Hex-STRING works).
- No-type lines, lowercased, substring-matched:
  end-of-MIB markers ("no more variables left in this mib view", "past the
  end of the mib tree") → skip, keep rows;
  absent markers ("no such object", "no such instance") → skip if
  empty_subtree_ok (walk) else `SnmpError("absent OID in net-snmp output:
  {oid} = {rest}")` (get);
  anything else → `SnmpError("unrecognized net-snmp output line: ...")`.
- Rows parsed before a marker are NEVER discarded.

#### Error rule (exact)
```python
stderr = (proc.stderr or "").strip()
if proc.returncode != 0 or stderr:
    raise SnmpError(f"{argv[0]} exited {proc.returncode} for {self.host}: {stderr or 'unknown error'}")
```
**ANY non-empty stderr raises, even on exit 0.** OSError running the binary
→ `SnmpError("failed to run {argv[0]!r}: {exc}")`.

#### set_many value formatting
`x` → `bytes.hex()` lowercase (str values latin-1-encoded first); others →
`str(value)`. Echoed output parsed but discarded; returns None.

### 5.2 pysnmp transport — semantic deltas (the parity contract)

- Token map: Integer/Integer32→"INTEGER"; Gauge32/Unsigned32→"Gauge32";
  Counter32; Counter64; TimeTicks→"Timeticks"; IpAddress; ObjectIdentifier/
  ObjectIdentity→"OID". Absent classes: NoSuchObject/NoSuchInstance/
  EndOfMibView → uppercase token, empty value.
- `_octet_value(raw)`: `raw == b"" or all(0x20 <= b < 0x7F)` → (ascii str,
  "STRING"); else (bytes, "Hex-STRING"). The printability heuristic.
- **OID values use `str(value)`, NEVER `.prettyPrint()`** (hlapi can render
  well-known prefixes symbolically; numeric dotted form required).
  IpAddress DOES use prettyPrint.
- GET: empty list → [] no I/O; errorIndication/Status → SnmpError("GET
  {oids} on {host}: ..."); ANY absent-type row in a GET → SnmpError("absent
  OID in pysnmp GET response: {oid}").
- WALK: `bulk_walk_cmd(..., 0, 25, ..., lexicographicMode=False)` —
  **non-repeaters 0, max-repetitions 25, subtree-bounded**. Mid-walk
  error → ALWAYS raises (silent truncation indistinguishable from success
  otherwise). ENDOFMIBVIEW / any absent type → stop, keep rows, no raise.
- SET: `i`→Integer32, `u`→Gauge32, `a`→IpAddress, `s`/`x`→OctetString
  (same wire type); one PDU per set_many, set_cmd called once; empty list
  is a true no-op; notWritable(17) error surfaces the failing OID.
- Engine cleanup ALWAYS runs (finally) — Go: `defer engine/conn.Close()`.
- SnmpError passes through unwrapped; any other exception is wrapped into
  SnmpError. Port via errors.As check before wrapping.

### 5.3 Cross-transport invariant
Same wire value ⇒ identical `SnmpRow{oid, value, snmp_type}` including
exact value TYPE (int vs str vs bytes) — pinned per-type by
test_value_parity.py (Integer, Gauge32, printable STRING, Hex-STRING bytes,
IpAddress, Timeticks, OID). Port as exact-type assertions.

### 5.4 `SetVarbind` (context)
`{oid, value int|str|bytes, type_letter ∈ {i,u,s,x,a}}`; invalid letter →
ValueError at construction (not SnmpError).

---

## 6. Test coverage map (mirror the intent in Go)

- `tests/protocols/snmp/test_oids.py` — OID string values; vendor_oids
  derivations + no-base raise; BOX_SENSOR_COLUMNS kinds; unimplemented_roots
  matrix (PoE model → []; zero-PoE + vendor → [PoE root, vendor mW]; zero-PoE
  no vendor → [PoE root]); is_oid_implemented true/false matrix.
- `test_client.py` — SnmpRow frozen+hashable; SnmpError subclassing;
  full_oid; ABSENT_TYPES membership.
- `test_parse_ports.py` (13) — §3.4/3.5/3.9/3.1/3.2 incl. ifType filtering
  present/absent for ports+stats+pvids separately; down-port no speed;
  empty-alias None; absent counter None; exact SnmpError message substrings.
- `test_parse_vlans.py` (8) — bitmap bit conventions, empty, latin-1 paths,
  non-latin1 raise; name+egress+untagged join; tagged derivation;
  bitmap-less VLAN OK; malformed index/type raise naming OID; pvids sorted.
- `test_parse_lldp_macs.py` (11) — grouping; port_id vs port_desc distinct;
  port_id binary MAC vs printable ASCII (the critical asymmetry); malformed
  arity/column/local-port raises; MAC join; FDB arity/type raises.
- `test_parse_poe_sensors.py` (9) — col3/6 + mW join; missing col raises;
  empty vendor walk → power_mw None; "Not Supported" skip; entity sensors
  on real gs728tpp data (kinds, canon names, NaN, inventory unit, name
  fallback chain).
- `test_parse_mgmt_ip.py` (13) — the §3.21 matrix + 3 parse_base_mac tests;
  errors match exact OID via re.escape.
- `test_parse_system_info.py` (19) — extraction honesty + the FULL sysdescr
  table of §3.26 (+ sysobjectid tests on the new pin: map hit, map miss,
  unregistered-key miss, empty/None).
- `tests/test_snmp_read.py` (18) — FakeClient serves canned rows by EXACT
  walked-OID dict key (the reader's walked OID strings are the contract);
  constructor gates; per-method end-to-end; get_poe raises for zero-PSE even
  with PoE rows present in the fake; get_sensors raise-vs-[] pair (vendor
  claimed empty vs no-vendor empty — keep as two separate Go tests);
  get_mgmt_ip absent dhcp → UNKNOWN; full sync/async parity; system-info
  detection incl. independence from bound model.
- `tests/test_models_snmp_read.py` (3) — dataclass defaults (stats=(),
  mgmt_ip=None).
- `tests/transport/test_snmp_netsnmp_cli.py` (16) — §5.1 in full (incl.
  marker-vs-STRING ordering, argv layout, stderr-on-exit-0 raise, import
  purity).
- `tests/transport/test_snmp_pysnmp.py` (25) — §5.2 in full via injected
  fake pysnmp module (no sockets); engine-always-closed; wrap-vs-passthrough
  error contract.
- `tests/transport/test_value_parity.py` (7) — the cross-transport
  value+type parity pins. Port 1:1 against gosnmp + the Go fake.
- `tests/test_snmp_integration.py` (3) — capstone against the live virtual
  gsm7252ps: every reader method non-vacuous + equal across transports, with
  exact seed pins: port1 name "1/0/1" desc "eth0.rpi5-pmod"; base_mac
  "E0:91:F5:0C:D6:DB"; vlan 90 "iot" (port 11 member, 10 not); mgmt
  10.1.5.22 STATIC; PoE port 1 delivering 3500 mW; MAC C8:00:84:89:71:70 →
  port 110 (bridge_port 10 → ifIndex 110 non-identity join); lldp
  remote_port_id "1/xg51" ≠ port_desc "eth0"; detect → gsm7252ps.
- `tests/fixtures/snmp/*.txt` — vestigial, unreferenced by tests on the pin;
  do not wire into the Go port (informal evidence only: sensor readings
  arrive as STRING-quoted decimals).

---

## 7. Go porting notes

| Python construct | Recommendation |
|---|---|
| Sync+async Protocol pairs | ONE Go interface: `SnmpClient{ Get(ctx, oids []string) ([]SnmpRow, error); Walk(ctx, base string) ([]SnmpRow, error) }`; `SnmpWriteClient` embeds it adding `Set`/`SetMany`. The sync/async parity TEST intent survives as gosnmp-transport vs virtual-fake integration pins. |
| `SnmpRow.value: int\|str\|bytes` | `SnmpRow{OID string; Value any; SnmpType string}` with a documented "exactly one of int64/string/[]byte" contract (+constructor helper). Use go-cmp/custom Equal in tests ([]byte in any breaks ==). |
| `int\|None` / `str\|None` | `*int`/`*uint64`/`*string` nil-for-None per model package convention; empty-string-from-.get() maps to nil at parse call sites. |
| `frozenset[int]` port sets | sorted non-nil `[]int` (model package convention). decode_port_bitmap returns sorted []int. |
| keyword-only parse_port_stats | named struct arg `ParsePortStats(cols PortStatsCols)` to avoid 7-positional footgun. |
| SnmpError with OID in message | wrap `model.ErrSNMP` with the OID interpolated; tests assert strings.Contains(err, oid). |
| UnsupportedCapabilityError messages | wrap `model.ErrUnsupportedCapability`, mirror wording with %q. |
| `string.punctuation.replace("-","")` | exact const: `!"#$%&'()*+,./:;<=>?@[\]^_` + backtick + `{|}~` — verify against Python's value, don't transcribe by eye. |
| `float("nan")` | math.NaN(); tests use math.IsNaN. |
| pysnmp class-name dispatch | dispatch on gosnmp's `Asn1BER` type tags (Integer, OctetString, IPAddress, Counter32, Gauge32, TimeTicks, Counter64, ObjectIdentifier, NoSuchObject, NoSuchInstance, EndOfMibView). Build the token map on the enum. |
| Two transports cross-check | Go has one transport (gosnmp) — the virtual fake + net-snmp CLI oracle play the second-path role; port test_snmp_integration's pins against the Go fake, and drive the Go fake with real snmpget/snmpbulkwalk subprocesses in tests. |
| bulk walk knobs | mirror non-repeaters=0/max-repetitions=25/subtree-bounded semantics on gosnmp (verify gosnmp BulkWalk defaults; configure MaxRepetitions explicitly). |

---

## Completeness checklist

- oids.py — y (all constants, VendorOids, has/unimplemented/is_implemented,
  BOX_SENSOR_COLUMNS, DHCP_MODE_OID_SUFFIX)
- client.py — y (SnmpRow, SnmpError, ABSENT_TYPES, full_oid, 4 Protocols)
- parse.py — y (every function + private helpers, incl. new-pin
  detect_model_from_sysobjectid/SYSOBJECTID_MODELS)
- snmp_read.py — y (readers, all methods, read_system_info sysObjectID-first)
- transport netsnmp_cli — y (argv, parser state machine, error rules, set)
- transport pysnmp — y (as semantic delta/parity contract)
- test files — y (14 files mapped with assertions)
- write.py — context-only (SetVarbind; write logic is slice 04)
