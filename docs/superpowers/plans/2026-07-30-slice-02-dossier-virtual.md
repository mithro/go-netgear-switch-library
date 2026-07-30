# Slice 02 Dossier: Virtual-Switch Core (Python → Go porting reference)

> **Source of truth:** `/home/tim/github/mithro/python-netgear-switch-library`,
> branch `fix/live-hardware-parity` (pinned reference, read-only). All line
> numbers/values below are transcribed exactly from that branch as of
> 2026-07-30. This document targets Go engineers porting 1:1 without reading
> the Python source themselves.

---

## 1. `src/netgear_switch/virtual/state.py` (768 lines)

Module docstring: "The one authoritative in-memory virtual-switch device
state." `VirtualSwitchState` holds everything a simulated switch "knows"
about itself as small mutable `*Sim` dataclasses; `oid_map()` projects that
state onto the flat numeric `OID -> (snmp_type, value)` view a protocol face
serves. **Pure data + projection: no network.**

### 1.1 Helper functions

- `encode_port_bitmap(ports: set[int], width_bytes: int = 8) -> str` — inverse
  of `parse.decode_port_bitmap`. Delegates to
  `protocols/snmp/write.encode_port_bitmap` (bytes) and decodes latin-1 to
  `str` for callers. **MSB-first bit packing**: bit 7 (MSB) of byte 0 = port
  1; `byte_idx, bit = divmod(port - 1, 8)`; buffer grows past `width_bytes` if
  a port number needs it (never pre-sized to model port count).
- `_mbps_to_speed_byte(mbps: int) -> int` — NSDP LinkSpeed wire byte map:
  `{10: 0x02, 100: 0x04, 1000: 0x05, 10000: 0xFF}`, else `0x00`.

### 1.2 Every `Sim` dataclass (fields + defaults)

**`PortSim`** — one port's link/admin/speed/name + optional HC counters.
Counters are `int | None`: `None` = "this port does not expose this counter"
and must round-trip to an **absent row** in `oid_map()` (no fabricated
zero).

| field | type | default |
|---|---|---|
| `name` | `str` | (required) |
| `admin` | `bool` | (required) |
| `link` | `bool` | (required) |
| `speed` | `int` | (required) |
| `if_type` | `int` | `6` (ethernetCsmacd = physical port default; 1=other/CPU, 135=l2vlan, 161=ieee8023adLag are non-physical rows the read path filters OUT via `parse._physical_ports`) |
| `rx_octets` | `int \| None` | `None` |
| `tx_octets` | `int \| None` | `None` |
| `rx_ucast` | `int \| None` | `None` |
| `tx_ucast` | `int \| None` | `None` |
| `rx_errors` | `int \| None` | `None` |
| `tx_errors` | `int \| None` | `None` |
| `description` | `str \| None` | `None` (ifAlias; `None` = column instance entirely absent, never a fabricated `""`) |

**`VlanSim`** — one dot1q VLAN.

| field | type | default |
|---|---|---|
| `name` | `str` | (required) |
| `member` | `set[int]` | `set()` |
| `untagged` | `set[int]` | `set()` |

**`PoeSim`** — one PoE port (RFC3621 admin/detect + vendor delivered power).

| field | type | default |
|---|---|---|
| `admin` | `bool` | (required) |
| `detect` | `int` | (required) |
| `power_mw` | `int` | `0` |

**`SensorSim`** — one box sensor reading. `raw` is the literal wire text:
decimal-int string OR Netgear's `"Not Supported"` placeholder.

| field | type | default |
|---|---|---|
| `kind` | `str` (`"fan"` \| `"power"` \| `"temperature"`) | (required) |
| `instance` | `str` | (required) |
| `raw` | `str` | (required) |

**`EntitySim`** — one ENTITY-MIB `entPhysicalTable` component. Used ONLY by
models whose SNMP agent exposes fan/PSU INVENTORY via the standard
ENTITY-MIB instead of a Netgear vendor column (verified: GS728TPP).
`phys_class` = `entPhysicalClass` int enum (6=powerSupply, 7=fan). No live
value/status on the wire — inventory only.

| field | type | default |
|---|---|---|
| `index` | `int` | (required) |
| `phys_class` | `int` | (required) |
| `name` | `str` | (required) |
| `descr` | `str` | (required) |

**`MacSim`** — one learned MAC/FDB entry.

| field | type | default |
|---|---|---|
| `vlan` | `int` | (required) |
| `mac_bytes` | `tuple[int,int,int,int,int,int]` | (required) |
| `bridge_port` | `int` | (required) |

**`LldpSim`** — one `lldpRemTable` neighbour row group.

| field | type | default |
|---|---|---|
| `time_mark` | `int` | (required) |
| `local_port` | `int` | (required) |
| `rem_idx` | `int` | (required) |
| `chassis` | `str` | (required) |
| `port_id` | `str` | (required) |
| `port_desc` | `str` | (required) |
| `sys_name` | `str` | (required) |

**`MgmtSim`** — switch's own mgmt-IP config.

| field | type | default |
|---|---|---|
| `address` | `str` | (required) |
| `netmask` | `str` | (required) |
| `gateway` | `str` | (required) |
| `mode` | `str` (`"static"` \| `"dhcp"`) | (required) |

**`ScpCertDeploy`** — record of a FASTPATH `copy scp://` SSL-cert deploy the
mock CLI face received. Purely a record of the EXEC sequence the library
ISSUED (not part of any SNMP/NSDP/HTTP projection — CLI/HTTP-face concern,
not virtual-switch-core-for-SNMP-porting-relevant, listed for completeness).

| field | type | default |
|---|---|---|
| `commands` | `list[str]` | `[]` |
| `copies` | `list[tuple[str,str]]` | `[]` (source_url, dest) |
| `https_disabled` | `bool` | `False` |
| `https_enabled` | `bool` | `False` |
| `saved` | `bool` | `False` |

### 1.3 `VirtualSwitchState` — every field

| field | type | default |
|---|---|---|
| `model_key` | `str` | (required) |
| `ports` | `dict[int, PortSim]` | `{}` |
| `vlans` | `dict[int, VlanSim]` | `{}` |
| `pvids` | `dict[int, int]` | `{}` |
| `poe` | `dict[int, PoeSim]` | `{}` |
| `sensors` | `list[SensorSim]` | `[]` — the SNMP FACE's sensor set |
| `http_sensors` | `list[SensorSim] \| None` | `None` — HTTP-only sensor set when it differs from SNMP's (e.g. gsm7252ps: SNMP=fan RPM+PSU watts, HTTP=temps+health text); `None` when both faces agree (M4300) |
| `entity_components` | `list[EntitySim]` | `[]` — ENTITY-MIB inventory (only GS728TPP-style no-vendor models) |
| `macs` | `list[MacSim]` | `[]` |
| `bridge_ports` | `dict[int, int]` | `{}` (bridge_port -> ifIndex) |
| `lldp` | `list[LldpSim]` | `[]` |
| `mgmt` | `MgmtSim` | `MgmtSim(address="0.0.0.0", netmask="0.0.0.0", gateway="0.0.0.0", mode="dhcp")` |
| `model_name` | `str` | `""` |
| `serial` | `str` | `""` |
| `firmware` | `str` | `""` |
| `hostname` | `str` | `""` |
| `nsdp_password` | `str` | `"password"` |
| `nsdp_qos_engine` | `int \| None` | `None` (NSDP tag 0x3400; `None`=unseeded, tag omitted from `nsdp_tlvs()`) |
| `nsdp_port_mirroring_dest` | `int \| None` | `None` (NSDP tag 0x5C00; `None` dest = unseeded/disabled) |
| `nsdp_port_mirroring_sources` | `frozenset[int]` | `frozenset()` |
| `nsdp_igmp_snooping_enabled` | `bool \| None` | `None` (NSDP tag 0x6800) |
| `nsdp_igmp_snooping_vlan` | `int \| None` | `None` |
| `nsdp_broadcast_filtering` | `bool \| None` | `None` (NSDP tag 0x5400) |
| `nsdp_loop_detection` | `bool \| None` | `None` (NSDP tag 0x9000) |
| `nsdp_mac` | `bytes` | `b"\x28\xc6\x8e\x00\x00\x01"` — fixed seed MAC for device identity. Feeds BOTH the NSDP identity TLV (`Tag.MAC`) AND the SNMP `dot1dBaseBridgeAddress` scalar (same physical base MAC on real hardware) |
| `sys_descr` | `str` | `""` (MIB-II sysDescr; empty = oid_map() falls back to `f"Netgear {model.display_name}"`) |
| `sys_object_id` | `str` | `""` — **UNVERIFIED** test fixture; no known real sysObjectID->model table exists for most models; NEVER a claim about real hardware. Empty = oid_map() derives one from vendor base |
| `uploaded_cert` | `str \| None` | `None` (HTTP face concern, not SNMP-relevant) |
| `scp_cert_deploy` | `ScpCertDeploy \| None` | `None` (CLI face concern) |
| `dot1d_base_mac_ascii` | `bool` | `False` — **VERIFIED on real M4300-24X only**: that firmware answers `dot1dBaseBridgeAddress` as a 17-char ASCII colon-hex STRING ("XX:XX:...:XX") instead of 6 raw OCTET STRING bytes every other captured model uses. Only a seed with hardware evidence should set `True` |

**Property `sysinfo_sensors`** — `self.sensors if self.http_sensors is None else self.http_sensors`. The sensor set the HTTP sysInfo page renders.

### 1.4 `oid_map() -> dict[str, tuple[str, str]]` — FULL projection logic

Imports `protocols.snmp.oids` (OID constants) and
`protocols.snmp.write.vlan_bitmap_width`. Resolves `model = get_model(self.model_key)`.
`v = oids.vendor_oids(model) if oids.has_vendor_oids(model) else None` — a
model with no vendor subtree (gs728tpp) has `v = None` and every
vendor-column projection below is **skipped entirely** (matching a real
agent answering `noSuchObject` for the whole 4526 tree). `vlan_width =
vlan_bitmap_width(model)` = `max(8, (port_count + 7) // 8)`.

Builds `m: dict[str, tuple[str,str]]` in this exact order (order doesn't
matter for correctness — StateMibView sorts it — but is documented here for
completeness):

1. **`dot1dBaseBridgeAddress.0`** (`DOT1D_BASE_BRIDGE_ADDRESS + ".0"`, type
   `OCTETSTR`): reuses `nsdp_mac`. If `dot1d_base_mac_ascii`: value =
   `":".join(f"{b:02X}" for b in nsdp_mac)` (17-char ASCII colon-hex text).
   Else: value = `nsdp_mac.decode("latin-1")` (raw 6 bytes).
2. **`sysDescr` (`SYS_DESCR`, `OCTETSTR`)**: `self.sys_descr or f"Netgear {model.display_name}"`.
3. **`sysObjectID` (`SYS_OBJECT_ID`, `OID`)**: `self.sys_object_id or default_object_id`
   where `default_object_id = f"{v.base}.1" if v is not None else "1.3.6.1.2.1"`.
4. **Per-port** (`for port, sim in self.ports.items()`):
   - `ifAdminStatus.<port>` (`IF_ADMIN_STATUS`, `INTEGER`): `"1" if sim.admin else "2"`
   - `ifOperStatus.<port>` (`IF_OPER_STATUS`, `INTEGER`): `"1" if sim.link else "2"`
   - `ifHighSpeed.<port>` (`IF_HIGH_SPEED`, `Gauge32`): `str(sim.speed)`
   - `ifType.<port>` (`IF_TYPE`, `INTEGER`): `str(sim.if_type)`
   - `ifName.<port>` (`IF_NAME`, `OCTETSTR`): `sim.name`
   - `ifAlias.<port>` (`IF_ALIAS`, `OCTETSTR`): **only if `sim.description is not None`**: `sim.description`
   - Stat columns, **each emitted only if the field is not `None`** (never a fabricated 0):
     - `ifHCInOctets.<port>` (`IF_HC_IN_OCTETS`, `Counter64`) ← `rx_octets`
     - `ifHCOutOctets.<port>` (`IF_HC_OUT_OCTETS`, `Counter64`) ← `tx_octets`
     - `ifHCInUcastPkts.<port>` (`IF_HC_IN_UCAST`, `Counter64`) ← `rx_ucast`
     - `ifHCOutUcastPkts.<port>` (`IF_HC_OUT_UCAST`, `Counter64`) ← `tx_ucast`
     - `ifInErrors.<port>` (`IF_IN_ERRORS`, `Counter32`) ← `rx_errors`
     - `ifOutErrors.<port>` (`IF_OUT_ERRORS`, `Counter32`) ← `tx_errors`
5. **Per-VLAN** (`for vid, vsim in self.vlans.items()`):
   - `dot1qVlanStaticName.<vid>` (`DOT1Q_VLAN_STATIC_NAME`, `OCTETSTR`): `vsim.name`
   - `dot1qVlanStaticEgressPorts.<vid>` (`DOT1Q_VLAN_STATIC_EGRESS`, `OCTETSTR`): `encode_port_bitmap(vsim.member, width_bytes=vlan_width)`
   - `dot1qVlanStaticUntaggedPorts.<vid>` (`DOT1Q_VLAN_STATIC_UNTAGGED`, `OCTETSTR`): `encode_port_bitmap(vsim.untagged, width_bytes=vlan_width)`
6. **Per-port PVID** (`for port, pv in self.pvids.items()`): `dot1qPvid.<port>` (`DOT1Q_PVID`, `Gauge32`): `str(pv)`
7. **Per-PoE-port** (`for port, psim in self.poe.items()`):
   - `pethPsePortAdminEnable = <PETH_PSE_PORT_TABLE>.3.1.<port>` (`INTEGER`): `"1" if psim.admin else "2"`
   - `pethPsePortDetectionStatus = <PETH_PSE_PORT_TABLE>.6.1.<port>` (`INTEGER`): `str(psim.detect)`
   - Vendor delivered-power (`<v.poe_power_mw>.1.<port>`, `Gauge32`): `str(psim.power_mw)` — **only if `v is not None`** (a no-vendor model exposes NO such column at all)
8. **Box sensors** — **only if `v is not None`** (`for ssim in self.sensors`): base OID selected by `{"fan": v.box_fan, "power": v.box_psu_power, "temperature": v.box_temp}[ssim.kind]`; emits `<base>.<ssim.instance>` = (`OCTETSTR`, `ssim.raw`).
9. **ENTITY-MIB inventory** (`for ent in self.entity_components`, unconditional — no-vendor models use this):
   - `entPhysicalClass.<ent.index>` (`ENT_PHYSICAL_CLASS`, `INTEGER`): `str(ent.phys_class)`
   - `entPhysicalName.<ent.index>` (`ENT_PHYSICAL_NAME`, `OCTETSTR`): `ent.name`
   - `entPhysicalDescr.<ent.index>` (`ENT_PHYSICAL_DESCR`, `OCTETSTR`): `ent.descr`
10. **MAC/FDB** (`for msim in self.macs`): `dot1qTpFdbPort.<vlan>.<6 mac bytes as decimal-dotted>` (`DOT1Q_TP_FDB_PORT`, `INTEGER`): `str(msim.bridge_port)`. Then (`for bridge_port, ifindex in self.bridge_ports.items()`): `dot1dBasePortIfIndex.<bridge_port>` (`DOT1D_BASE_PORT_IF_INDEX`, `INTEGER`): `str(ifindex)`.
11. **LLDP** (`for nb in self.lldp`), columns 5/7/8/9 under `LLDP_REM_TABLE`, index = `f"{nb.time_mark}.{nb.local_port}.{nb.rem_idx}"`, all `OCTETSTR`:
    - `.1.5.<idx>` = `nb.chassis`
    - `.1.7.<idx>` = `nb.port_id`
    - `.1.8.<idx>` = `nb.port_desc`
    - `.1.9.<idx>` = `nb.sys_name`
12. **mgmt-IP** (unconditional): `idx = self.mgmt.address`:
    - `ipAdEntAddr.<idx>` (`IP_ADENT_ADDR`, `IPADDR`): `self.mgmt.address`
    - `ipAdEntNetMask.<idx>` (`IP_ADENT_NETMASK`, `IPADDR`): `self.mgmt.netmask`
    - `ipRouteDest.0.0.0.0` (`IP_ROUTE_DEST`, `IPADDR`): literal `"0.0.0.0"`
    - `ipRouteNextHop.0.0.0.0` (`IP_ROUTE_NEXTHOP`, `IPADDR`): `self.mgmt.gateway`
    - `<v.dhcp_mode_unverified>.0` (`INTEGER`) — **only if `v is not None`**: `"2" if self.mgmt.mode == "static" else "1"`

Returns `m`.

### 1.5 SNMP type strings and exactly where each is used

| type string | used for |
|---|---|
| `INTEGER` | ifAdminStatus, ifOperStatus, ifType, PoE admin(3.1), PoE detect(6.1), ENT_PHYSICAL_CLASS, dot1qTpFdbPort, dot1dBasePortIfIndex, vendor dhcp-mode scalar |
| `Gauge32` | ifHighSpeed, dot1qPvid, vendor PoE delivered-power (`poe_power_mw`) |
| `Counter32` | ifInErrors, ifOutErrors |
| `Counter64` | ifHCInOctets, ifHCOutOctets, ifHCInUcastPkts, ifHCOutUcastPkts |
| `OCTETSTR` | dot1dBaseBridgeAddress, sysDescr, ifName, ifAlias, dot1qVlanStaticName, dot1qVlanStaticEgressPorts/UntaggedPorts (raw port bitmaps), box sensor readings (fan/power/temp raw text), ENT_PHYSICAL_NAME, ENT_PHYSICAL_DESCR, LLDP chassis/portId/portDesc/sysName |
| `IPADDR` | ipAdEntAddr, ipAdEntNetMask, ipRouteDest, ipRouteNextHop |
| `OID` | sysObjectID only |

Note: every `OCTETSTR` value is stored as a Python `str` produced via
`chr(byte)`/plain ASCII (see `faces/snmp.py`'s `_to_smi_value` docstring) —
**a latin-1 encode is the exact wire-byte inverse in every case**, including
binary bitmaps and MAC bytes.

### 1.6 `snapshot()` / `restore()`

- `snapshot() -> VirtualSwitchState`: `copy.deepcopy(self)`. For atomic
  multi-varbind SET rollback — one SNMP SET PDU can carry several varbinds
  (e.g. `set_vlan_membership` writes both egress AND untagged bitmaps in one
  `set_many` call) and a real agent guarantees all-or-nothing.
- `restore(snapshot) -> None`: copies **every dataclass field** from
  `snapshot` onto `self` via `dataclasses.fields(self)` / `setattr` — **does
  NOT replace `self` itself** — so existing references to this exact object
  (`VirtualSwitch.state`, `StateMibView._state`) keep seeing the restored
  data. **Go porting note:** this is the critical detail — Go must mutate the
  existing struct's fields in place (`*s = snap` on a pointer receiver works
  when Snapshot() deep-copied every map/slice), not swap in a new struct
  other holders can't see.

### 1.7 `apply_write(oid: str, value: int | bytes | str) -> None` — ALL coherence rules

Dispatches on OID column prefix via `_tail(base)` helper (returns int suffix
if `oid` starts with `base + "."` and the rest is all-digit, else `None`)
and `_as_bytes(val)` helper (bytes passthrough; str → latin-1 encode; int →
`bytes([val])`). Resolves `v = vendor_oids(model) if has_vendor_oids else None`.
Dispatch order (first match wins, each branch `return`s):

1. **`ifAdminStatus.<port>`** (only if `port in self.ports`):
   `self.ports[port].admin = int(value) == 1`. **Coherence rule**: if
   `int(value) != 1` (i.e. admin-down), ALSO `self.ports[port].link = False`.
2. **`pethPsePortAdminEnable = PETH_PSE_PORT_TABLE.3.1.<port>`** (only if
   `p in self.poe`): `on = int(value) == 1`; `self.poe[p].admin = on`.
   **Coherence rule**: `self.poe[p].detect = 3 if on else 1` (3=delivering,
   1=unused/disabled). **Coherence rule**: if `not on and p in self.ports`,
   ALSO `self.ports[p].link = False`. (Matches real PoE-switch behaviour so
   `cycle_poe` terminates against the mock.)
3. **`dot1qPvid.<port>`**: `self.pvids[port] = int(value)` (no existence
   check — creates the pvids entry unconditionally).
4. **`dot1qVlanStaticEgressPorts.<vid>`** (only if `vid in self.vlans`):
   `self.vlans[vid].member = set(decode_port_bitmap(_as_bytes(value)))`.
5. **`dot1qVlanStaticUntaggedPorts.<vid>`** (only if `vid in self.vlans`):
   `self.vlans[vid].untagged = set(decode_port_bitmap(_as_bytes(value)))`.
6. **`dot1qVlanStaticRowStatus.<vid>`**: if `int(value) == ROW_STATUS_DESTROY (6)`:
   `self.vlans.pop(vid, None)`. Elif `int(value) == ROW_STATUS_CREATE_AND_GO (4)`
   AND `vid not in self.vlans`: `self.vlans[vid] = VlanSim(name="")`.
7. **`dot1qVlanStaticName.<vid>`**: decode `value` (bytes→latin-1, else
   `str(value)`). If `vid in self.vlans`: set `.name`. Else: create
   `self.vlans[vid] = VlanSim(name=name)` (so a name write alone can create a
   row too, independent of RowStatus).
8. **Vendor mgmt-IP/dhcp-mode writes** — **only if `v is not None`** (a
   no-vendor model like gs728tpp never advertises/accepts these; its SNMP
   mgmt-IP write path is honestly `UnsupportedCapabilityError` at the
   `snmp_write` layer):
   - `oid == v.mgmt_write_addr_unverified`: `self.mgmt.address = str(value)`
   - `oid == v.mgmt_write_netmask_unverified`: `self.mgmt.netmask = str(value)`
   - `oid == v.mgmt_write_gateway_unverified`: `self.mgmt.gateway = str(value)`
   - `oid == f"{v.dhcp_mode_unverified}.0"`: `self.mgmt.mode = "static" if int(value) == 2 else "dhcp"` (2=static, anything else=dhcp — matches `oid_map()`'s encoding)
9. **Unhandled writable OID**: deliberate **silent no-op** — the write
   "succeeds" but reads back unchanged. This is intentional: it's what a
   verify-after-write must catch. (Confirmed by
   `test_apply_write_unhandled_oid_is_a_silent_no_op`.)

### 1.8 `is_writable_oid(oid: str) -> bool` — the writable-OID set

Mirrors `apply_write`'s dispatch prefixes **on purpose** (same column
constants, kept in sync deliberately) but is a **separate, stricter gate**:
the SNMP face uses this to reject a SET on a genuinely unknown/read-only OID
with a proper SNMP `notWritable` error, BEFORE the always-succeeding no-op
`apply_write` itself would silently allow it.

Returns `True` for:
- `_is_col(IF_ADMIN_STATUS)` — column check: `oid.startswith(base+".") and oid[len(prefix):].isdigit()`
- `PETH_PSE_PORT_TABLE.3.1.<digits>`
- `_is_col(DOT1Q_PVID)`
- `_is_col(DOT1Q_VLAN_STATIC_EGRESS)`
- `_is_col(DOT1Q_VLAN_STATIC_UNTAGGED)`
- `_is_col(DOT1Q_VLAN_STATIC_ROW_STATUS)` — **even for a not-yet-existing VLAN row** (must allow createAndGo through)
- `_is_col(DOT1Q_VLAN_STATIC_NAME)`
- If `v is None`: **returns `False`** for everything else (short-circuits — a no-vendor model has NONE of the vendor-subtree writable OIDs)
- Else: `oid in (v.mgmt_write_addr_unverified, v.mgmt_write_netmask_unverified, v.mgmt_write_gateway_unverified)` OR `oid == f"{v.dhcp_mode_unverified}.0"`

**Notably NOT writable**: `ifOperStatus` (pinned by
`test_is_writable_oid_recognizes_known_columns_and_scalars` asserting
`not st.is_writable_oid(f"{oids.IF_OPER_STATUS}.1")`), any bogus OID like
`"1.2.3.4.5"`.

### 1.9 `is_oid_implemented(oid: str) -> bool`

Delegates entirely to `protocols.snmp.oids.is_oid_implemented(get_model(self.model_key), oid)`.
See §1.10.

### 1.10 `protocols/snmp/oids.py` — `unimplemented_roots` / `is_oid_implemented`

```python
def unimplemented_roots(model) -> list[str]:
    if model.poe_port_count > 0:
        return []
    roots = [PETH_PSE_PORT_TABLE]          # "1.3.6.1.2.1.105.1.1.1"
    if model.snmp_vendor_base is not None:
        roots.append(vendor_oids(model).poe_power_mw)
    return roots

def is_oid_implemented(model, oid: str) -> bool:
    dotted = oid.lstrip(".")
    for root in unimplemented_roots(model):
        if dotted == root or dotted.startswith(root + "."):
            return False
    return True
```

Real Netgear firmware only instantiates a MIB module when the underlying
hardware capability exists. Currently only the RFC3621 PoE MIB (+ vendor
PoE-power column) is gated this way — verified live: a GETNEXT/bulkwalk of
the PoE MIB root on a non-PoE switch (M4300-24X) answers a single
`noSuchObject`, never falls through to whatever unrelated OID sorts next.
**Deliberately narrower than "has a value right now"**: a
registered-but-empty table is a different, already-handled case
(noSuchInstance/endOfMibView).

### 1.11 `sysinfo_sensors` — see §1.3 property.

### 1.12 `nsdp_tlvs(tags: set[Tag]) -> list[TLVEntry]`

**STRICT**: answers with ONLY the tags requested (real Plus hardware does
exactly this — a read omitting MODEL gets a MODEL-less response). Unknown
requested tags silently skipped.

- `Tag.MODEL` (if requested): `TLVEntry(Tag.MODEL, (self.model_name or model.display_name).encode("ascii"))`
- `Tag.MAC`: `TLVEntry(Tag.MAC, self.nsdp_mac)`
- `Tag.PORT_COUNT`: `TLVEntry(Tag.PORT_COUNT, bytes([model.port_count]))`
- `Tag.SERIAL_NUMBER` (if `self.serial` truthy): `b"\x01" + serial.encode("ascii")`
- `Tag.HOSTNAME` (if `self.hostname` truthy): ascii-encoded
- `Tag.FIRMWARE_VER_1` (if `self.firmware` truthy): ascii-encoded
- `Tag.PORT_STATUS`: for each port sorted by key: `bytes([port, speed_byte, 0x01])` where `speed_byte = _mbps_to_speed_byte(sim.speed) if sim.link else 0x00`
- `Tag.PORT_STATISTICS`: for **EVERY** port sorted by key (verified real hardware returns one row per port, zeroed on idle ports): `bytes([port]) + struct.pack(">Q", rx_octets or 0) + struct.pack(">Q", tx_octets or 0) + struct.pack(">Q", rx_errors or 0) + b"\x00"*24`
- `Tag.VLAN_MEMBERS`: for each vlan sorted by vid: `tagged = member - untagged`; `struct.pack(">H", vid) + ports_to_bitmap(member, width) + ports_to_bitmap(tagged, width)` where `width = (port_count + 7) // 8`
- `Tag.PORT_PVID`: for each port sorted: `bytes([port]) + struct.pack(">H", pv)`
- `Tag.IP_ADDRESS` / `Tag.NETMASK` / `Tag.GATEWAY`: `socket.inet_aton(...)`
- `Tag.DHCP_MODE`: `b"\x00" if mode == "static" else b"\x01"`
- `Tag.QOS_ENGINE` (if `nsdp_qos_engine is not None`): `bytes([value])`
- `Tag.PORT_MIRRORING` (if `nsdp_port_mirroring_dest is not None`): `bytes([dest]) + ports_to_bitmap(sources, width)` — **width is model-dependent** (5-port GS105PE → 2-byte bitmap/3-byte TLV; 10-port GS110EMX → 3 bytes), derived from `port_count`, NOT hardcoded.
- `Tag.IGMP_SNOOPING` (if `nsdp_igmp_snooping_enabled is not None`): `bytes([0x00, 1 if enabled else 0, 0x00, vlan_byte])` where `vlan_byte = nsdp_igmp_snooping_vlan or 0`
- `Tag.BROADCAST_FILTERING` (if not `None`): `bytes([1 if enabled else 0])`
- `Tag.LOOP_DETECTION` (if not `None`): `bytes([1 if enabled else 0])`

### 1.13 `apply_nsdp_write(tag: Tag | int, value: bytes) -> None`

Unknown/read-only tags: deliberate no-op (verify-after-write catches it).

- `Tag.PORT_PVID`: `self.pvids[value[0]] = struct.unpack_from(">H", value, 1)[0]`
- `Tag.VLAN_MEMBERS`: `m = parse_vlan_members(value, model.port_count)`; preserves existing `.name` if the vlan row exists, else `""`; `self.vlans[m.vlan_id] = VlanSim(name=name, member=set(m.member_ports), untagged=set(m.untagged_ports))`
- `Tag.IP_ADDRESS` / `NETMASK` / `GATEWAY`: `socket.inet_ntoa(value)` into the corresponding `mgmt` field
- `Tag.DHCP_MODE`: `self.mgmt.mode = "dhcp" if value[:1] == b"\x01" else "static"`
- `REBOOT` / `FACTORY_RESET` / unknown: deliberate no-op

---

## 2. `src/netgear_switch/virtual/faces/mibview.py` (113 lines) — `StateMibView`

Pure OID responder over `VirtualSwitchState.oid_map()`. No pysnmp, no
network: a sorted `(oid_tuple, snmp_type, value)` list answering exact-match
GET and lexicographic GETNEXT with bisect.

### 2.1 Data structure

```python
_Entry = tuple[tuple[int, ...], str, str]  # (oid_tuple, snmp_type, value)

def _oid_to_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.lstrip(".").split("."))

class StateMibView:
    def __init__(self, state): self._state = state; self._load()
    def _load(self):
        entries = [(_oid_to_tuple(oid), t, v) for oid, (t, v) in self._state.oid_map().items()]
        entries.sort(key=lambda e: e[0])   # NUMERIC tuple sort, not string sort
        self._entries = entries
        self._oids = [e[0] for e in entries]  # parallel key list for bisect
```

**Critical detail**: sort key is `tuple[int, ...]` — numeric tuple
comparison, NOT lexicographic string comparison of the OID text. `.8.2` MUST
sort before `.8.10` (pinned by `test_get_next_uses_numeric_order`). **Go**:
`slices.Compare([]int, []int)`.

### 2.2 `get(oid)` — exact-match

`bisect_left` + equality check. `None` means "no instance at this exact OID
within an IMPLEMENTED subtree" → `NoSuchInstance`. Caller MUST check
`is_implemented(oid)` FIRST.

### 2.3 `get_next(oid)` — GETNEXT semantics

`bisect_right` (strictly greater — GETNEXT never returns the same OID).
`None` → `endOfMibView`. Same is_implemented-first caveat.

### 2.4 `rebuild()` — recompute the sorted view from current state (after writes).

### 2.5 `apply_write` vs `apply_write_uncommitted`

- `apply_write(oid, value)`: state.apply_write + rebuild (single write).
- `apply_write_uncommitted(oid, value)`: mutate WITHOUT rebuild — for atomic
  multi-varbind SET; caller rebuilds once after the whole PDU commits.

### 2.6 `snapshot_state()` / `restore_state(snapshot)` — passthroughs to state (§1.6). No rebuild needed after restore (only reached before any successful rebuild).

### 2.7 `is_writable_oid(oid)` — passthrough to state.

### 2.8 `is_implemented(oid_tuple)` — tuple→dotted-string, passthrough to §1.9/1.10. Checked by the face BEFORE get/get_next.

### 2.9 noSuchObject vs noSuchInstance vs endOfMibView — the three-way rule

1. `is_implemented(oid)` False → **noSuchObject** (checked BEFORE the bisect table).
2. GET + `get()` None → **noSuchInstance**.
3. GETNEXT + `get_next()` None → **endOfMibView**.
4. Otherwise → the found entry.

The gate applies to each varbind's own REQUESTED oid (GET and GETNEXT
alike). A walk that starts inside an implemented region never needs the gate
mid-walk: `oid_map()` emits no keys under unimplemented roots, so the bisect
naturally skips the gap. The gated case is a request that *targets* an
unimplemented root (raw bulkwalk of PoE MIB on non-PoE model) → single
noSuchObject.

### 2.10 Atomicity primitives live here; orchestration in the face (§3.5).

---

## 3. `src/netgear_switch/virtual/faces/snmp.py` (437 lines)

Real pysnmp v2c command-responder agent serving a StateMibView, bound to an
ephemeral UDP port on 127.0.0.1. pysnmp lazily imported inside start().

### 3.2 `_to_smi_value(snmp_type, value)` — value → wire object

```
INTEGER   -> Integer32(int(value))
Gauge32   -> Gauge32(int(value))
Counter32 -> Counter32(int(value))
Counter64 -> Counter64(int(value))
IPADDR    -> IpAddress(value)
OCTETSTR  -> OctetString(value.encode("latin-1"))
OID       -> ObjectIdentifier(value)
else      -> raise ValueError
```

### 3.3 `_from_smi_value(value)` — incoming SET value → plain value

```
Integer/Integer32/Gauge32/Unsigned32 -> int
OctetString -> bytes (asOctets)
IpAddress -> str (prettyPrint)
else -> str (prettyPrint)
```

### 3.4 `_StateInstrum` — instrumentation controller

`read_variables(*var_binds)` (GET): per varbind — `is_implemented`? no →
`(name, noSuchObject)`. Else `get()`; None → `(name, noSuchInstance)`; else
`(name, _to_smi_value(...))`.
`read_next_variables(...)` (GETNEXT/BULK step): same gate → noSuchObject;
`get_next()` None → `(name, endOfMibView)`; else `(next_oid, value)`.

**THE central fidelity point**: per-varbind exception *values* embedded in
the response PDU — never a PDU-level error status, never an exception
escaping to the dispatcher.

### 3.5 Atomic multi-varbind SET — full flow

```
snapshot = view.snapshot_state()
try:
    for idx, (name, val) in enumerate(var_binds):
        oid = dotted(name)
        if not view.is_writable_oid(oid): raise NotWritableError(name=name, idx=idx)
        try: view.apply_write_uncommitted(oid, _from_smi_value(val))
        except Exception as exc: raise WrongValueError(name=name, idx=idx) from exc
        out.append((name, val))
except Exception:
    view.restore_state(snapshot); raise
view.rebuild()
return out
```

- Whole PDU all-or-nothing (snapshot-then-restore, not validate-then-commit).
- `is_writable_oid` gate BEFORE apply per varbind → clean notWritable.
- apply failure → WrongValueError (never escapes to dispatcher = timeout).
- `idx` is the REAL 0-based failing-varbind position (wire error-index = idx+1).
- `rebuild()` exactly once after full success.

### 3.6 `VirtualSnmpFace` lifecycle

- `start() -> int`: bind UDP socket (host, 0) in the CALLING thread; spawn
  daemon thread running a fresh asyncio loop + pysnmp engine using that
  exact socket; wait on a ready-event; re-raise any setup error
  synchronously in the caller; return bound port.
- VACM: community "public" (configurable), read+write subtree `1.3.6.1`,
  v2c security model 2. Single instrumentation instance serves the whole
  default context — `is_implemented` decides what exists.
- Four responders registered: Get, Next, Bulk, Set.
- `stop()`: thread-safe dispatcher close, join (5 s), belt-and-braces socket
  close. (The Python asyncio deferred-close dance is asyncio-specific; in Go
  a plain `conn.Close()` + goroutine join is sufficient and deterministic.)

### 3.7 Intentional hardware-faithful behaviours

1. noSuchObject-before-noSuchInstance/endOfMibView ordering.
2. Per-varbind exception VALUES, not PDU-level genErr.
3. Atomic multi-varbind SET.
4. PoE write coherence (admin off→detect=1+link down; on→detect=3) so
   cycle_poe terminates against the mock.
5. M4300-24X ASCII base-MAC quirk round-trips end-to-end.
6. OCTETSTR byte-exact round-trip for binary payloads.

---

## 4. `src/netgear_switch/virtual/seed.py` (1277 lines) — SNMP-capable models

Helpers: `_port_name(port) -> f"1/0/{port}"` (FASTPATH ifName, verified);
`_mac_hex_to_raw("88:A2:9E:80:87:01")` → 6 raw latin-1 bytes.

### 4.1 `seed_gsm7252ps()` — 52-port, 48-PoE, TRANSCRIBED from real capture (10.1.5.22)

- **Ports** `_GSM7252PS_PORTS` (52): all admin=True; e.g. 1:(True,True,1000,'eth0.rpi5-pmod'),
  6:(True,False,0,None), 49:(True,True,10000,'1/0/2.sw-netgear-m4300-24x'), 52:(True,False,10000,None).
  Speeds: 100/1000/10000/0(down). Names all `1/0/<port>`.
- **Counters** `_GSM7252PS_COUNTERS` (52): (rx_octets,tx_octets,rx_ucast,tx_ucast,rx_errors,tx_errors);
  port 1: (45747246, 912689098, 217358, 235430, 0, 0); port 49: (28392074220, 9325801127, 77433287, 62142947, 0, 0); idle ports all-zero.
- **Non-physical**: ifIndex 417 `CPU Interface:  0/5/1` (if_type=1, speed 0);
  418 `lag 1` (if_type=161, speed=20000, description="lag.sw-netgear-gsm7252ps-s2").
- **PVIDs** (all 52): mostly 90; some 1, 4, 5, 20 (full dict in source).
- **VLANs** (14: 1,4,5,6,7,10,20,21,41,89,90,99,121,141) names:
  default,wifi,net,pwr,store,int,roam,fpgas,sm,sdr,iot,guest,t-fpgas,t-sm.
  Members incl. LAG ifIndexes range(418,482). Genuine quirk preserved:
  untagged NOT a subset of member for several VLANs (e.g. VLAN 6).
- **PoE** (48): all admin=True; detect codes 2, 3, 6 (6=otherFault→UNKNOWN, port 6);
  port 1: (True,3,3500).
- **Sensors (SNMP)**: fan "0"=2850, fan "2"=2350 (NO fan1), power "0".."3" = 49,30,32,31. NO temperature.
- **http_sensors**: 5 temps (System=29, CPU=49, MAC="N/A", MAC-A=32, MAC-B=31),
  5 fan health (Fan1/PWR..Fan3/SYS="OK", Fan4/Fan5="NA"), 2 power health ("Operational").
- **MACs**: (90, C8:00:84:89:71:70, bridge_port 10), (1, 00:1B:21:3C:4D:5E, bridge_port 11).
  **bridge_ports = {10: 110, 11: 11}** — deliberate non-identity join trap.
- **LLDP**: time_mark=75, local_port=49, rem_idx=7, chassis=raw MAC bytes of
  C8:00:84:89:71:70, port_id="1/xg51", port_desc="eth0", sys_name="sw-cisco-shed".
- **Mgmt**: 10.1.5.22/255.255.255.0 captured; gateway 10.1.5.1 + mode "static" ILLUSTRATIVE.
- **Identity**: model_name="GSM7252PS", serial="2BW20A47000CC", firmware="10.0.0.53",
  hostname="sw-netgear-gsm7252ps-s1.welland.mithis.com", nsdp_mac=e0:91:f5:0c:d6:db,
  sys_descr="NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6" (ILLUSTRATIVE),
  sys_object_id="1.3.6.1.4.1.4526.10.100.14" (UNVERIFIED). dot1d_base_mac_ascii=False.

### 4.2 `seed_gsm7228ps()` — **STALE SECTION — superseded on the re-pinned reference**

> **Re-pin note:** on the current pin (`fix/s3300-52x-live-verify` @
> `aaab577`), `seed_gsm7228ps` was RESEEDED from the real S3300-52X-PoE+
> capture (`tests/fixtures/captures/gsm7228ps.json`, host 10.1.5.11,
> sysObjectID 1.3.6.1.4.1.4526.100.10.19, captured 2026-07-30): real port
> names/admin/link/speed, all counters, every PVID, 5 VLANs with exact
> member/untagged sets incl. lag ifIndexes 314-339, 48 PoE ports (2
> delivering, 1 fault, rest searching), box sensors (3 fans + PSU watts +
> temperature under vendor 4526.11.43), mgmt 10.1.5.11 and base MAC.
> **Read `virtual/seed.py` + the capture JSON directly when porting this
> seed** — the subsection below describes the OLD illustrative seed and is
> kept only as a record of what changed.

#### (superseded) old illustrative seed — 52-port/48-PoE, MINIMAL-BUT-VALID

- Ports: all 52, `1/0/<p>`, admin=True, link=(port!=3), speed=1000. Ports 1-2
  counters (500000, 700000, 4000, 4500, 0, 0). Port 1 description="uplink-to-core".
- VLANs: 1 default(member=all 52, untagged=3..52); 50 lab(member={1,2,5}, untagged={1,2}).
- PVIDs: all 1 except ports 1,2 = 50.
- PoE 1-48: port 1 (True,3,9000); others (True,1,0).
- Sensors: fan "0"=3200, power "0"=45, temperature "0"=40.
- MACs: (50, 00:11:22:33:44:55, bp 1), (1, 00:11:22:33:44:56, bp 2); bridge_ports empty.
- LLDP: local_port=1, chassis=00:11:22:33:44:55 raw, port_id="eth0",
  port_desc="lab-uplink", sys_name="sw-lab-example".
- Mgmt: 10.1.5.21/255.255.255.0 gw 10.1.5.1 static.
- Identity: sys_descr="NETGEAR GSM7228PS (S3300) Managed Switch",
  sys_object_id="1.3.6.1.4.1.4526.11.100.28" (UNVERIFIED). No model_name/serial/firmware/hostname/nsdp_mac.

### 4.3 `seed_m4300_24x()` — 24-port, NO PoE, TRANSCRIBED from m4300-24x.json (10.1.5.13)

- Ports (24): `1/0/<p>`, admin=True; speeds 0/100/1000/10000; descriptions
  like "trunk.sw-cisco-shed", "bmc.big-storage", "empty". Full table in source.
- Stats: port -> (rx_bytes, tx_bytes, rx_errors), tx_errors=0; port 1:
  (14778916968081, 11768639639224, 5); port 19: (10574049492450, 7436979985884, 0).
- Non-physical: 769 CPU (if_type=1); 770 lag 1 (if_type=161, speed=40000,
  desc="lag.sw-bb-25g"); 771 lag 2 (admin=True, link=False, speed 0);
  898 vlan 1 + 899 vlan 5 (if_type=135, speed=10).
- VLANs: same 14 IDs/names as gsm7252ps; `_lags = set(range(770, 898))`;
  tagged = member - untagged invariant holds.
- PVIDs: explicit 24-port dict (1→1, 3→5, 15-24→10, ...).
- Sensors: fan "0"=5160, fan "1"=4560, power "0"=49, temperature "1"=49.
- **poe={}** — VERIFIED no PoE.
- MACs: 3 rows, all bridge_port=1 (identity join).
- LLDP: 3 neighbours mixing raw-MAC-bytes and plain-text port_id subtypes
  (local_port 1: both raw; 2: chassis raw + port_id "1/0/49" text; 6: both raw).
- Mgmt: 10.1.5.13/255.255.255.0 gw 10.1.5.1, mode "static" (ILLUSTRATIVE).
- Identity: nsdp_mac=8C:3B:AD:6B:BB:E0 (real), **dot1d_base_mac_ascii=True**
  (VERIFIED wire quirk), sys_descr="NETGEAR M4300-24X (XSM4324CS) Managed Switch",
  sys_object_id="1.3.6.1.4.1.4526.10.100.24" (UNVERIFIED).

### 4.4 `seed_m4300_16x()` — 16-port, ALL 16 PoE, TRANSCRIBED from m4300-16x.json

- Ports (16): `1/0/<p>`, admin=True; only 11 (1000), 12 (1000), 16 (10000) up.
- Stats: mostly (0,0); 11: (0, 7813924); 12: (30388, 7819868); 16: (3347925876, 7868391); errors 0.
- Non-physical: 769 CPU; 770 lag 1 (admin=True, **link=False**, 0); 898 vlan 5.
- VLANs: same 14 IDs; `_uplink_ports={9..16}` = member set of most non-default
  VLANs (untagged empty); VLAN 1: member=untagged=range(1,17)|lags.
- PVIDs: all 16 → 1.
- PoE (16): 10 ports detect=2/0 mW; ports 11 (5000 mW) and 12 (2100 mW) detect=3 — VERIFIED delivering pair.
- Sensors: fan "0"=4200, fan "1"=4080, power "0"=40, power "1"=42, temperature "1"=42.
- MACs: 3 rows, bridge_ports 12/16/16.
- LLDP: 2 neighbours (12: chassis raw + port_id "5" text; 16: both raw).
- Mgmt: **default blank** (0.0.0.0/dhcp) — capture honestly had None.
- Identity: nsdp_mac=8C:3B:AD:69:1C:38 (real), dot1d_base_mac_ascii=False,
  sys_descr="NETGEAR M4300-16X (XSM4316) Managed Switch",
  sys_object_id="1.3.6.1.4.1.4526.10.100.16".

### 4.5 `seed_gs728tpp()` — 28-port SMP, SNMP+HTTP, LIVE capture 10.2.5.10 (2026-07-29)

- **No vendor OIDs** (snmp_vendor_base=None): `sensors` EMPTY; ENTITY-MIB
  `entity_components` instead; PoE power_mw=None over SNMP.
- Ports: g1-g28 (names `g<p>`); up={2,5,12,23,24,26,28}; speed100={5,12,23}, rest 1000 when up.
- VLANs (12): 1, 2 "Voice VLAN", 3 "Auto Video VLAN" (empty), 5 "net"
  (untagged {3,5,12,23}), 6 "pwr", 7 "store", 10 "int" (untagged {1}),
  20 "roam", 31 "fpgas", 41 "sm", 90 "iot", 99 "guest".
  `_GS728TPP_TRUNK = range(1,26)|{27}`; `_GS728TPP_VLAN1` = 21 listed ports.
- PVIDs: explicit dict (1→10, 12→5, 23→5, rest mostly 1).
- PoE: ports 1-24, all (admin=True, detect=2 Searching, 0 mW).
- MACs: 12 rows across VLANs 1 and 5 (bridge_ports 2,5,12,23,24).
- LLDP: 4 neighbours (local_port 2,24,26,28; sys_name "ten64.monarto.mithis.com"/"reterm1").
- http_sensors (DiagnosticsUnitList; tag in instance, code in raw; 1=OK, 5=N/A):
  mainPSStatus=1, redundantPSStatus=1, fan1Status=1, fan2Status=1,
  fan3Status=5, fan4Status=5, fan5Status=5, tempSensorValue=0, tempSensorStatus=2.
- entity_components: (67109185, 6, "Main PowerSupply", "PowerSupply"),
  (67109186, 6, "Redundant PowerSupply", "PowerSupply"),
  (67109249, 7, "Fan1", "Fan"), (67109250, 7, "Fan2", "Fan").
- Mgmt: 10.2.5.10/255.255.255.0 gw 10.2.5.1 static.
- Identity: model_name="GS728TPP", serial="3AR476520016D", firmware="6.0.1.30",
  hostname="sw-netgear-gs728tpp", nsdp_mac=b0:39:56:77:54:29,
  sys_descr="Netgear GS728TPP ProSafe Smart Managed Pro Switch",
  **sys_object_id="1.3.6.1.4.1.4526.100.4.27" — REAL captured value** (bare
  identifier under 4526.100; a walk of 1.3.6.1.4.1.4526 on this switch
  answers noSuchObject).

### 4.6 `_SEEDS` map and blank-state path

```python
_SEEDS = {"gsm7252ps": ..., "gsm7228ps": ..., "gs110emx": ..., "gs305ep": ...,
          "gs105pe": ..., "m4300-24x": ..., "m4300-16x": ..., "gs728tpp": ...}
def _build_state(model): seed = _SEEDS.get(model); return seed() if seed else VirtualSwitchState(model_key=model)
```
Unseeded registered models get a blank-but-valid state (all defaults).

---

## 5. `src/netgear_switch/virtual/server.py` (133 lines) — `VirtualSwitch`

- `VirtualSwitch(model, community="public", http_password="password")`;
  `get_model(model)` raises UnknownModelError EARLY. `self.state = _build_state(model)`;
  `self.nsdp_password = state.nsdp_password`; `self.port = 0`; `self.http_port = 0`; host="127.0.0.1".
- `start()`: independent `if` per backend in registry entry — SNMP face
  (fresh `StateMibView(self.state)` built at start() time) → `self.port`;
  NSDP face → **also `self.port`** (shared field — Go MUST use separate
  fields per spec §8.2); HTTP face → `self.http_port`. If no face bound →
  `UnsupportedCapabilityError`.
- `cli_session()`: in-process CLI face (no socket).
- `stop()`: per-face guarded stop + reset fields; stop-before-start is a
  no-op (pinned by test). Context manager: `__enter__`=start, `__exit__`=stop always.

---

## 6. Tests covering the above (intent to mirror in Go)

### 6.1 `tests/virtual/test_mibview.py` (pure view, fake state)
- get exact match; get missing → None; **get_next numeric order (.8.2 → .8.10)**;
  get_next from bare column prefix lands on first instance; get_next past end → None;
  is_implemented default True / False under configured unimplemented prefix
  (exact root AND deeper OID; sibling stays True);
  **exhaustive walk of seed_gsm7252ps's real oid_map visits every OID exactly once,
  strictly increasing, no gaps/duplicates**.

### 6.2 `tests/virtual/test_virtual_snmp_face.py` (real agent, both transports)
- GET+walk via net-snmp CLI AND pysnmp: port 1 ifOperStatus up; walk of
  dot1qVlanStaticName → exactly 14 names incl. "default"/"iot".
- GETBULK walk of whole 1.3.6.1 terminates cleanly, yields every seeded OID
  under it exactly once (LLDP under 1.0.8802 excluded — outside subtree).
- Plus model (gs110emx) binds NSDP not SNMP; model with no backends raises
  UnsupportedCapability; stop-before-start no-op.
- Lifecycle emits no ResourceWarning (error-filter + recording pass with
  gc.collect); 10 start/stop cycles leak no fds.
- Type tokens round-trip: Gauge32(ifHighSpeed), Counter64(ifHCInOctets),
  Counter32(ifInErrors), IpAddress(ipAdEntAddr), bitmap→Hex-STRING on wire,
  vendor Gauge32 PoE power — values read from seeded state, never hardcoded.
- Non-PoE model: SnmpReader.get_poe raises UnsupportedCapability BEFORE
  walking; raw snmpbulkwalk of PoE root prints literal
  "No Such Object available on this agent at this OID". (+ async twin via
  pysnmp NoSuchObject class name.)
- M4300-24X ASCII base MAC → get_mgmt_ip().base_mac == "8C:3B:AD:6B:BB:E0"
  through BOTH transports; IpAddress+bitmap parity through net-snmp CLI too.

### 6.3 `tests/virtual/test_state_seed.py` (gsm7252ps grounding)
- Coherent oid_map (ifOperStatus.1 present; ≥1 delivering PoE with mW>0).
- Round-trips through parse_vlans/parse_mgmt_ip (VLANs ⊇ {1,90};
  10.1.5.22/10.1.5.1; base_mac E0:91:F5:0C:D6:DB).
- Non-empty stats (≥2 ports)/macs (≥2)/lldp (sys_name sw-cisco-shed,
  port_id 1/xg51 ≠ port_desc eth0).
- parse_port_status → **54** ports (52 phys + CPU 417 + lag 418); port 1
  speed 1000 desc eth0.rpi5-pmod; port 6 link=False desc=None;
  pvids 52 incl (1,90); poe 48, port 1 delivering 3500 mW; box sensors
  exactly {fan0=2850, fan2=2350, power0=49, power1=30, power2=32, power3=31}.
- Strict capture parity via assert_seed_matches_capture (ports/PVIDs/14
  VLANs/48 PoE/SNMP sensors/mgmt+base-MAC); stats pinned per-port for all
  52; VLAN 90 "iot" spot-check.

### 6.4 `tests/virtual/test_m4300_seeds.py`
- Both M4300 seeds pass assert_seed_matches_capture (16X mgmt honestly None →
  address checks skipped).
- 24X: poe=[] in capture, state.poe=={}, AND oid_map→parse_poe→[] round-trip;
  ASCII base-MAC wire value length 17 == capture value.
- 16X: 16 PoE rows, exactly 2 delivering {11,12}; base MAC raw-6-bytes form.

### 6.5 `tests/virtual/test_mutable_state.py` (state-level writes)
- PoE admin off → admin=False, detect=1, link down; back on → detect=3.
- ifAdminStatus.3=2 → admin False; dot1qPvid.10=90.
- VLAN egress bitmap write {1,2,10,25} round-trips; RowStatus 4 create +
  name write → vlans[200].name=="guests"; RowStatus 6 → gone.
- Vendor mgmt-IP write updates state AND oid_map projection; dhcp-mode
  write 1/2 flips mode and projection.
- Unhandled OID writes (bogus + known-column-absent-port) are silent no-ops
  (oid_map unchanged).
- is_writable_oid: True for all 7 patterns (+RowStatus/Name on absent row
  300; vendor mgmt trio + dhcp-mode); False for bogus OID and ifOperStatus.

### 6.6 `tests/test_snmp_integration.py` (capstone, virtual_gsm7252ps fixture)
- EVERY read op non-vacuous AND byte-identical between net-snmp-CLI reader
  and pysnmp reader, incl. MAC join proof (C8:00:84:89:71:70 → ifIndex 110,
  never bridge_port 10), LLDP port_id vs port_desc distinctness, mode STATIC.
- Spot pins: vlans[90]=="iot", mgmt.address, ≥1 PoE with power_mw>0.
- detect_model end-to-end both transports: key=="gsm7252ps", matched, sync==async.

### 6.7 `tests/conftest.py` — per-model `VirtualSwitch` fixtures with guaranteed stop() in finally.

---

## 7. Go porting notes

- **mibview**: `entries []mibEntry{OID []int; Type string; Value string}`,
  sorted with `slices.Compare`; `Get` = sort.Search(bisect_left)+eq;
  `GetNext` = sort.Search(bisect_right). NEVER compare OID strings.
- **State snapshot/restore**: `Snapshot()` deep-copies every map/slice;
  `Restore` via `*s = snap` on pointer receiver (pointer identity preserved
  for all holders).
- **Face**: `net.ListenUDP(host:0)` in caller; `go serve(conn)` loop with
  ReadFrom/WriteTo; `stop()` = `conn.Close()` + WaitGroup join (Go needs
  none of Python's asyncio deferred-close dance).
- **Codec**: per the resolved decision gate — gosnmp's exported
  `SnmpDecodePacket` / `SnmpPacket.MarshalMsg` (GoSNMPServer REJECTED:
  returns PDU-level noSuchName errors for absent OIDs; per-varbind exception
  values are non-negotiable).
- **v2c semantics to implement exactly**: GET → per-varbind value or
  noSuchObject/noSuchInstance exception VALUES (all N varbinds always
  answered); GETNEXT/GETBULK → per-varbind chained next steps with
  endOfMibView fill, is_implemented gate against each REQUESTED oid;
  GETBULK = non-repeaters + max-repetitions chaining; SET → whole-PDU
  atomic, snapshot/apply-uncommitted/restore-on-first-failure, notWritable
  vs wrongValue, wire error-index = 0-based idx + 1, rebuild once on success.
- **Types**: INTEGER→BER INTEGER (0x02); Gauge32→0x42; Counter32→0x41;
  Counter64→0x46; OCTETSTR→0x04 raw bytes (Go `[]byte` directly — latin-1
  dance is Python-only); IPADDR→0x40 4 bytes; OID→0x06.

---

## Completeness checklist

- [x] state.py: all 9 Sim dataclasses, all 25 state fields + property, oid_map
  full projection + conditional-emission rules, snapshot/restore, apply_write
  all 9 branches + coherence, is_writable_oid all patterns + v-nil
  short-circuit, is_oid_implemented, nsdp_tlvs per-tag table + strictness,
  apply_nsdp_write per-tag.
- [x] mibview.py full (bisect semantics, numeric sort, rebuild, uncommitted
  writes, snapshot/restore, is_implemented, three-way exception rule).
- [x] faces/snmp.py full (SMI value maps, instrumentation, atomic SET flow,
  lifecycle/threading, VACM, four responders, teardown).
- [x] seed.py: 5 SNMP-capable seeds complete + _SEEDS + blank path.
- [x] server.py full. oids.py/write.py referenced parts. All 7 test files'
  assertions listed.
