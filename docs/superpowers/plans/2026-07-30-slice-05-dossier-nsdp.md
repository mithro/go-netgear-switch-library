# Slice 05 Dossier: NSDP (Python → Go porting reference)

> **Source of truth:** `/home/tim/github/mithro/python-netgear-switch-library`,
> branch `fix/s3300-52x-live-verify` @ `1aa1274` — frozen snapshot worktree:
> `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274`
> (read implementation files from the SNAPSHOT path, never the live checkout).
> **Pin guard verified**: `git rev-parse HEAD` in that worktree returns
> `1aa1274254a233ddce0409160849bb6ce8f8b2e7` — starts with `1aa1274`. **PASS.**
> All line numbers/values below are transcribed exactly from that pin. This
> document targets Go engineers porting the complete NSDP stack 1:1 without
> reading the Python source themselves.
>
> **Cross-reference**: `docs/superpowers/plans/2026-07-30-slice-02-dossier-virtual.md`
> (D-VIRT) §1.12/§1.13 already speced `State.nsdp_tlvs`/`apply_nsdp_write`
> byte-exactly and is reproduced verbatim in §7 below — cross-checked against
> this pin and found **still accurate, no drift**. `docs/superpowers/plans/
> 2026-07-30-slice-03-dossier-facade.md` (D-FAC) is the facade dossier this
> slice's §8 extends (its own §1.5/§2.11/§2.16 already describe the SNMP
> analogues of everything NSDP needs). The roadmap
> (`2026-07-30-roadmap.md`, row 5) names the target package `nsdp` with
> deliverable "codec/parsers/auth/client/reader/writer + NSDP face".

---

## 1. `protocols/nsdp/protocol.py` — header codec, enums, packet framing

Located at `src/netgear_switch/protocols/nsdp/protocol.py` in the pinned repo.

### 1.1 32-byte header layout (byte-exact)

```python
NSDP_SIGNATURE = b"NSDP"
HEADER_SIZE = 32
HEADER_FORMAT = ">BB H 4s 6s 6s I 4s 4s"
END_MARKER = struct.pack(">HH", 0xFFFF, 0x0000)  # b"\xff\xff\x00\x00"
```

All big-endian (`>`). Total 32 bytes:

| offset | field | struct code | size | notes |
|---|---|---|---|---|
| 0x00 | version | `B` | 1 | always `0x01` (hardcoded on encode, not a settable field) |
| 0x01 | operation | `B` | 1 | `Op` value |
| 0x02 | result | `H` | 2 | 0x0000 = success |
| 0x04 | reserved1 | `4s` | 4 | zero bytes |
| 0x08 | client_mac | `6s` | 6 | |
| 0x0E | server_mac | `6s` | 6 | |
| 0x14 | sequence | `I` | 4 | **full 4-byte field** — see §1.2 |
| 0x18 | signature | `4s` | 4 | must equal `b"NSDP"` |
| 0x1C | reserved3 | `4s` | 4 | zero bytes |

### 1.2 Sequence-field correction (important, deliberate)

The header comment (protocol.py lines 24–31) explains a correction made against
`ngadmin` (herveboisse/ngadmin's `struct nsdp_header`, "the authoritative NSDP
layout"): the sequence number is a FULL 4-byte field, not "2 bytes + 2
reserved" as earlier prior-art assumed. A seqnum > 0xFFFF would previously
have been silently truncated on decode and mis-echoed by the mock. **Go must
decode/encode all 4 bytes of this field** even though every actual client in
this codebase only ever sends/increments the low 16 bits (see §5.5).

### 1.3 `Op` enum — all 4 values

```python
class Op(IntEnum):
    READ_REQUEST = 0x01
    READ_RESPONSE = 0x02
    WRITE_REQUEST = 0x03
    WRITE_RESPONSE = 0x04
```

### 1.4 `Tag` enum — all 34 values

```python
class Tag(IntEnum):
    # Packet markers
    START_OF_MARK = 0x0000
    END_OF_MARK = 0xFFFF

    # Device identity
    MODEL = 0x0001
    HOSTNAME = 0x0003
    MAC = 0x0004
    LOCATION = 0x0005
    IP_ADDRESS = 0x0006
    NETMASK = 0x0007
    GATEWAY = 0x0008
    DHCP_MODE = 0x000B
    FIRMWARE_VER_1 = 0x000D
    FIRMWARE_VER_2 = 0x000E
    PORT_COUNT = 0x6000
    SERIAL_NUMBER = 0x7800

    # Authentication
    PASSWORD = 0x000A
    AUTH_V2_SALT = 0x0017
    AUTH_V2_PASSWORD = 0x001A

    # Port information
    PORT_STATUS = 0x0C00
    PORT_STATISTICS = 0x1000

    # VLAN
    VLAN_ENGINE = 0x2000
    VLAN_MEMBERS = 0x2800
    PORT_PVID = 0x3000

    # QoS
    QOS_ENGINE = 0x3400
    PORT_QOS_PRIORITY = 0x3800

    # Traffic control
    INGRESS_RATE_LIMIT = 0x4C00
    EGRESS_RATE_LIMIT = 0x5000
    BROADCAST_FILTERING = 0x5400
    BROADCAST_BANDWIDTH = 0x5800
    PORT_MIRRORING = 0x5C00

    # IGMP
    IGMP_SNOOPING = 0x6800
    BLOCK_UNKNOWN_MULTICAST = 0x6C00
    IGMPV3_HEADER_VALIDATION = 0x7000
    IGMP_STATIC_ROUTER_PORTS = 0x8000

    # Other
    LOOP_DETECTION = 0x9000
    ACTIVE_FIRMWARE = 0x000C

    # Actions (write-only)
    REBOOT = 0x0013
    FACTORY_RESET = 0x0400
```

`ACTIVE_FIRMWARE = 0x000C` is filed under "Other" despite its low numeric
value — preserve the grouping comments in Go for diffability against Python,
but the numeric const values are what matter for wire compatibility.

### 1.5 `TLVEntry`

```python
@dataclass(frozen=True)
class TLVEntry:
    tag: Tag | int
    value: bytes = b""

    def encode(self) -> bytes:
        return struct.pack(">HH", int(self.tag), len(self.value)) + self.value

    @classmethod
    def decode(cls, data: bytes) -> tuple[TLVEntry, int]:
        if len(data) < 4:
            raise ValueError("NSDP TLV shorter than its 4-byte header")
        tag_raw, length = struct.unpack_from(">HH", data, 0)
        if len(data) < 4 + length:
            raise ValueError(
                f"NSDP TLV declares {length} value bytes but only "
                f"{len(data) - 4} are present"
            )
        value = data[4 : 4 + length]
        try:
            tag = Tag(tag_raw)
        except ValueError:
            tag = tag_raw  # unknown/uncatalogued tag: keep the raw int
        return cls(tag=tag, value=value), 4 + length
```

Fields: `tag` (enum-or-raw-int — **Go should model this as a plain numeric
type, e.g. `uint16`, with named `Tag` constants, not a closed enum**, since an
unrecognized tag must round-trip losslessly rather than error). `decode`
returns `(entry, bytesConsumed)`.

### 1.6 `NSDPPacket` — encode/decode

```python
@dataclass
class NSDPPacket:
    op: Op
    client_mac: bytes
    server_mac: bytes = b"\x00" * 6
    sequence: int = 0
    result: int = 0
    tlvs: list[TLVEntry] = field(default_factory=list)

    def add_tlv(self, tag: Tag | int, value: bytes = b"") -> None:
        self.tlvs.append(TLVEntry(tag=tag, value=value))

    def encode(self) -> bytes:
        header = struct.pack(HEADER_FORMAT, 0x01, int(self.op), self.result,
            b"\x00"*4, self.client_mac, self.server_mac, self.sequence,
            NSDP_SIGNATURE, b"\x00"*4)
        body = b"".join(t.encode() for t in self.tlvs)
        return header + body + END_MARKER

    @classmethod
    def decode(cls, data: bytes) -> NSDPPacket:
        if len(data) < HEADER_SIZE:
            raise ValueError(f"NSDP packet shorter than {HEADER_SIZE}-byte header")
        (_version, op_raw, result, _r1, client_mac, server_mac, sequence,
            signature, _r3) = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        if signature != NSDP_SIGNATURE:
            raise ValueError(f"bad NSDP signature {signature!r}")
        tlvs: list[TLVEntry] = []
        offset = HEADER_SIZE
        while offset + 4 <= len(data):
            entry, consumed = TLVEntry.decode(data[offset:])
            if entry.tag == Tag.END_OF_MARK:
                break
            tlvs.append(entry)
            offset += consumed
        return cls(op=Op(op_raw), client_mac=client_mac, server_mac=server_mac,
            sequence=sequence, result=result, tlvs=tlvs)
```

**encode()**: version is hardcoded `0x01` (not read from a field). TLVs
joined in order, then the 4-byte `END_MARKER` (`tag=0xFFFF, len=0`) is
unconditionally appended — it is NOT a `TLVEntry` produced by `add_tlv`.

**decode()**: `len < 32` → `ValueError("NSDP packet shorter than 32-byte
header")`. Bad signature → `ValueError(f"bad NSDP signature {signature!r}")`.
TLV loop starts at offset 32, continues `while offset+4 <= len(data)`;
**breaks (without appending) the instant a TLV's tag equals `END_OF_MARK`
(0xFFFF)** — trailing bytes after that point are never validated/consumed.

### 1.7 End-of-mark

Tag `0xFFFF`, wire form `b"\xff\xff\x00\x00"` (length 0). Terminates the TLV
loop on decode; unconditionally appended on encode. Go: after decoding the
tag/length pair, if tag==0xFFFF stop (don't require length==0 to match —
Python doesn't check it either, just breaks on tag match).

### 1.8 Sequence semantics

32-bit field at header offset 0x14. `protocol.py` itself has **no**
increment/wraparound logic — `NSDPPacket` just stores/round-trips whatever int
is given (default 0). Wraparound (`& 0xFFFF`) lives at the transport layer
(§5.5), not here.

---

## 2. `protocols/nsdp/types.py` — every NSDP-native type

Located at `src/netgear_switch/protocols/nsdp/types.py`. **None of these types
exist anywhere in the Go repo today** (verified: `grep -rn` for `NsdpDevice`,
`NsdpPortStatus`, `NsdpStatistics`/`NsdpPortStatistics`, `NsdpVlanMembership`,
`NsdpPortPvid`, `LinkSpeed`, `VLANEngine` across the whole Go repo returns no
matches as standalone types). Two Go names — `NsdpPortMirroring` and
`NsdpIgmpSnooping` — already appear, but ONLY as raw untyped fields on
`virtual.State` (`NsdpPortMirroringDest *int`/`NsdpPortMirroringSources
map[int]bool`, `NsdpIgmpSnoopingEnabled *bool`/`NsdpIgmpSnoopingVlan *int`) —
not as standalone struct types. **This slice must add all of the following as
new types**, and should consider whether `virtual.State`'s raw fields get
reshaped to embed the new `model.NsdpPortMirroring`/`model.NsdpIgmpSnooping`
structs (recommended, since it removes duplicate field lists) or stay as-is
(simpler diff, since `State`'s shape is declared frozen by D-VIRT).

### 2.1 `LinkSpeed` — every entry, including `0xFF`

```python
_MBPS = {0x00: 0, 0x01: 10, 0x02: 10, 0x03: 100, 0x04: 100, 0x05: 1000, 0xFF: 10000}

class LinkSpeed(IntEnum):
    DOWN = 0x00
    HALF_10M = 0x01
    FULL_10M = 0x02
    HALF_100M = 0x03
    FULL_100M = 0x04
    GIGABIT = 0x05
    # ASSUMED/UNVERIFIED — the reference spec states 2.5G/5G/10G speed byte
    # values are undocumented and require a hardware capture; 0xFF is carried
    # over from prior art without independent confirmation.
    TEN_GIGABIT = 0xFF

    @classmethod
    def from_byte(cls, value: int) -> LinkSpeed:
        try:
            return cls(value)
        except ValueError:
            return cls.DOWN  # unknown 2.5G/5G codes: report DOWN, never raise

    @property
    def speed_mbps(self) -> int:
        return _MBPS.get(int(self), 0)
```

`0xFF` → `TEN_GIGABIT` → 10000 Mbps, **explicitly flagged
ASSUMED/UNVERIFIED** — carry this exact caveat comment into the Go port.
`from_byte`/equivalent must return `DOWN` for any unrecognized byte (e.g.
`0x77`), never error.

### 2.2 `VLANEngine` — all 5 values

```python
class VLANEngine(IntEnum):
    DISABLED = 0
    BASIC_PORT = 1
    ADVANCED_PORT = 2
    BASIC_802_1Q = 3
    ADVANCED_802_1Q = 4
```

### 2.3 `NsdpPortStatus`

```python
@dataclass(frozen=True)
class NsdpPortStatus:
    port_id: int
    speed: LinkSpeed
```

### 2.4 `NsdpPortStatistics` (Python name — NOT `NsdpStatistics`; the task's
"NsdpStatistics" name in the prompt is inaccurate against source, note this)

```python
@dataclass(frozen=True)
class NsdpPortStatistics:
    port_id: int
    bytes_received: int
    bytes_sent: int
    crc_errors: int
```

### 2.5 `NsdpVlanMembership` (`untagged_ports` is a COMPUTED property, not a
stored field)

```python
@dataclass(frozen=True)
class NsdpVlanMembership:
    vlan_id: int
    member_ports: frozenset[int]
    tagged_ports: frozenset[int] = frozenset()

    @property
    def untagged_ports(self) -> frozenset[int]:
        return self.member_ports - self.tagged_ports
```

Go: represent `member_ports`/`tagged_ports` as `[]int` (sorted, canonical
form used elsewhere in this repo, per `model`'s existing `VLANInfo`
convention) or a `map[int]bool`; provide an `UntaggedPorts()` method computing
the set difference rather than a stored field, to match Python's semantics
exactly (mutating `tagged_ports` after construction, if ever possible, must
change `UntaggedPorts()`'s answer — though these are frozen/immutable in
Python so this is moot in practice, just keep the derivation logic, don't
store a stale copy).

### 2.6 `NsdpPortPvid`

```python
@dataclass(frozen=True)
class NsdpPortPvid:
    port_id: int
    vlan_id: int
```

### 2.7 `NsdpPortMirroring`

```python
@dataclass(frozen=True)
class NsdpPortMirroring:
    destination_port: int
    source_ports: frozenset[int] = frozenset()
```

### 2.8 `NsdpIgmpSnooping`

```python
@dataclass(frozen=True)
class NsdpIgmpSnooping:
    enabled: bool
    vlan_id: int | None = None
```

### 2.9 `NsdpDevice` — the aggregate/composite type

```python
@dataclass(frozen=True)
class NsdpDevice:
    model: str
    mac: str
    hostname: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    firmware_version: str | None = None
    dhcp_enabled: bool | None = None
    port_count: int | None = None
    serial_number: str | None = None
    vlan_engine: VLANEngine | None = None
    port_status: tuple[NsdpPortStatus, ...] = ()
    port_statistics: tuple[NsdpPortStatistics, ...] = ()
    vlan_members: tuple[NsdpVlanMembership, ...] = ()
    port_pvids: tuple[NsdpPortPvid, ...] = field(default_factory=tuple)
    qos_engine: int | None = None
    port_mirroring: NsdpPortMirroring | None = None
    igmp_snooping: NsdpIgmpSnooping | None = None
    broadcast_filtering: bool | None = None
    loop_detection: bool | None = None
}
```

`model`/`mac` required; everything else optional (`*T`/nil in Go, per this
repo's established nullable-field convention — see D-VIRT and `model/types.go`
which never fabricates a zero value for an absent optional field). Four
collection fields are slices in Go (`[]NsdpPortStatus`, `[]NsdpPortStatistics`,
`[]NsdpVlanMembership`, `[]NsdpPortPvid`).

### 2.10 Package-level re-export convention (Python) → Go placement recommendation

Python's `src/netgear_switch/__init__.py` re-exports these at package top
level with two renames (to avoid colliding with other package-level names):
`LinkSpeed as NsdpLinkSpeed`, `VLANEngine as NsdpVlanEngine`; the rest
(`NsdpDevice`, `NsdpPortStatus`, `NsdpPortStatistics`, `NsdpVlanMembership`,
`NsdpPortPvid`, `NsdpPortMirroring`, `NsdpIgmpSnooping`) already carry the
`Nsdp` prefix natively and need no rename. `protocols/nsdp/__init__.py`
itself is empty (docstring only, no `__all__`).

**Go placement recommendation**: put all of these in the **`model`** package
(not a new `nsdp` sub-package), following the pattern that `model` is "the
leaf package every protocol package imports; it imports nothing internal"
(types.go's own doc comment) and already holds the generic cross-backend
types (`PortStatus`, `PortStats`, `VLANInfo`, `MgmtIPConfig`, etc.) that the
`BackendReader`/`BackendWriter` interfaces speak in. Unlike those generic
types, the NSDP-native aggregate types are genuinely NSDP-wire-shaped (they
carry fields — like `NsdpPortStatus.Speed LinkSpeed` as a raw, unconverted
wire byte, or `NsdpDevice`'s flat `PortCount *int` alongside a `VlanEngine`
enum — that have no equivalent in the generic `model.PortStatus`/`VLANInfo`
types the facade otherwise returns), so keeping the Python package's `Nsdp`
prefix in Go (`model.NsdpDevice`, `model.NsdpPortStatus`, ...) is the right
call **even though** this repo's general convention (per the Go-inventory
research) is to name domain types without a per-backend prefix — the
prefix here disambiguates from the pre-existing, differently-shaped
`model.PortStatus`/`model.PortStats` the facade's `BackendReader` normalizes
to. Recommend: `model.LinkSpeed`, `model.VLANEngine` (no rename needed in Go —
there is no colliding bare `LinkSpeed`/`VLANEngine` symbol already in
`model`, unlike Python's package-top-level export needing `NsdpLinkSpeed` to
dodge a collision that doesn't exist in Go). Enums should follow this
package's existing `string`-based-const convention (see D-Go-inventory: `type
PoEDetect string` + const block) **or** a small `int`/`byte`-based type with a
`String()` method if wire-byte fidelity (e.g. `LinkSpeed` really is a raw wire
byte, not a semantic string) makes an integer type clearly better — an
`int`/`byte` base type is recommended specifically for `LinkSpeed` (it must
round-trip the exact wire byte, including `0xFF`) even though it breaks from
the rest of the package's `string`-enum convention; document why in the Go
doc comment.

---

## 3. `protocols/nsdp/parsers.py` — every parser, exact sizes/errors

### 3.1 `parse_ipv4(data) -> str`
Exactly 4 bytes else `ValueError(f"IPv4 TLV must be 4 bytes, got {len(data)}")`.
`socket.inet_ntoa(data)`.

### 3.2 `parse_mac(data) -> str`
Exactly 6 bytes else `ValueError(f"MAC TLV must be 6 bytes, got {len(data)}")`.
Lowercase colon-hex: `":".join(f"{b:02x}" for b in data)`.

### 3.3 `parse_port_status(data) -> NsdpPortStatus`
Exactly **3 bytes** else `ValueError(f"PORT_STATUS TLV must be 3 bytes, got {len(data)}")`.
`port_id = data[0]`, `speed = LinkSpeed.from_byte(data[1])` — **byte index 2 is
unused/ignored**.

### 3.4 `parse_port_statistics(data) -> NsdpPortStatistics`
Exactly **49 bytes** else `ValueError(f"PORT_STATISTICS TLV must be 49 bytes, got {len(data)}")`.
Layout: `port_id = data[0]` then `struct.unpack_from(">QQQ", data, 1)` → rx(8
bytes), tx(8 bytes), crc(8 bytes) = 1+24 = 25 of the 49 bytes consumed; the
**trailing 24 bytes are unused padding/other counters, not modeled**.

### 3.5 `parse_port_pvid(data) -> NsdpPortPvid`
Exactly **3 bytes** else `ValueError(f"PORT_PVID TLV must be 3 bytes, got {len(data)}")`.
`port_id = data[0]`, `vlan_id = struct.unpack_from(">H", data, 1)[0]`.

### 3.6 `parse_serial(data) -> str`
Non-empty, `data[0] == 0x01` else `ValueError(f"SERIAL_NUMBER TLV: unexpected prefix byte {data[:1]!r}")`.
`data[1:].decode("ascii", errors="replace").rstrip("\x00")`.

### 3.7 Bitmap helpers — MSB-first, 1-based, NSDP owns these locally

```python
def bitmap_to_ports(bitmap: bytes) -> frozenset[int]:
    """MSB-first, 1-based: byte 0 bit 0x80 = port 1 ... 0x01 = port 8."""
    ports: set[int] = set()
    for byte_idx, byte_val in enumerate(bitmap):
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                ports.add(byte_idx * 8 + bit + 1)
    return frozenset(ports)

def ports_to_bitmap(ports: Iterable[int], width_bytes: int) -> bytes:
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return bytes(data)
```

**Reuse-vs-separate verdict (settled)**: `parsers.py` imports nothing from
`protocols/snmp`; no bitmap utility file exists under `protocols/snmp` for it
to import from. **NSDP owns its own bitmap helpers, fully independent of
SNMP's.** Notably, the bit-packing convention (MSB-first, 1-based, same
`divmod(port-1, 8)` math) is IDENTICAL to SNMP's `encode_port_bitmap`/
`decode_port_bitmap` (see D-VIRT §1.1) — same algorithm, separately
implemented in each protocol package in Python. **Go recommendation**: given
Go's easier code-sharing story, consider a single shared internal helper
(e.g. `internal/bitmap` or a small exported one in `model`) used by both
`snmp` and `nsdp` packages — this is a legitimate simplification opportunity
Python didn't take, not a requirement to mirror the duplication. If in doubt,
duplicate first (matching Python exactly, zero risk) and only unify in a
follow-up cleanup pass.

### 3.8 `parse_vlan_members(data, port_count=8) -> NsdpVlanMembership`
`bitmap_bytes = (port_count+7)//8`; `expected = 2 + bitmap_bytes*2`; `len(data)
>= expected` else `ValueError(f"VLAN_MEMBERS TLV must be >={expected} bytes for {port_count} ports, got {len(data)}")`.
Layout: `vlan_id (2B, >H)` + `member bitmap (bitmap_bytes)` + `tagged bitmap
(bitmap_bytes)`, each via `bitmap_to_ports`.

### 3.9 `parse_port_mirroring(data) -> NsdpPortMirroring` — variable-length

```python
def parse_port_mirroring(data: bytes) -> NsdpPortMirroring:
    if not data:
        raise ValueError("PORT_MIRRORING TLV must be at least 1 byte, got 0")
    dest_port = data[0]
    source_ports = bitmap_to_ports(data[1:])
    return NsdpPortMirroring(destination_port=dest_port, source_ports=source_ports)
```

**How the variable length is resolved**: it isn't computed by this function
at all — the *outer* TLV length field (already consumed by `TLVEntry.decode`)
bounds `data`, so `data[1:]` is simply whatever remains, fed whole into
`bitmap_to_ports` (2 bytes on a 5-port GS105PE, 3 bytes on a 10-port
GS110EMX — both confirmed live 2026-07-21). Only a fully empty TLV (0 bytes)
is rejected. **Go must NOT hardcode a fixed-width source-port bitmap here** —
this is exactly the kind of hardcoding the Python history calls out as a
previously-fixed bug (see D-VIRT §1.12's PORT_MIRRORING note: width derives
from `port_count`, never hardcoded).

### 3.10 `parse_igmp_snooping(data) -> NsdpIgmpSnooping`
`len(data) >= 2` else `ValueError(f"IGMP_SNOOPING TLV must be >= 2 bytes, got {len(data)}")`.
`enabled = bool(data[1])`. If `len(data) >= 4`: `vlan_id = data[3] if data[3] != 0 else None`, else `vlan_id = None`.

### 3.11 `parse_device(packet) -> NsdpDevice` — two-pass aggregation

```python
def parse_device(packet: NSDPPacket) -> NsdpDevice:
    port_count = 8
    # Pass 1: learn the real port count (bitmaps need it).
    for tlv in packet.tlvs:
        if tlv.tag == Tag.PORT_COUNT and tlv.value:
            port_count = tlv.value[0]
    # Pass 2: full dispatch, using port_count for VLAN_MEMBERS.
    for tlv in packet.tlvs:
        ...
        elif tlv.tag == Tag.VLAN_MEMBERS:
            vlan_members.append(parse_vlan_members(tlv.value, port_count))
        ...
    if model is None:
        raise ValueError("no MODEL tag in NSDP response")
    if mac is None:
        mac = parse_mac(packet.server_mac)
    return NsdpDevice(...)
```

**Why two passes over the SAME flat `packet.tlvs` list**: `Tag.VLAN_MEMBERS`'s
bitmap width `(port_count+7)//8` is model-dependent, and a `VLAN_MEMBERS` TLV
can appear in the packet **before** the `PORT_COUNT` TLV — a single forward
pass risks misparsing an early VLAN_MEMBERS TLV with the wrong (default,
`port_count=8`) width. Pass 1 scans only for `Tag.PORT_COUNT` (default `8` if
absent); pass 2 does the real dispatch, using the now-known `port_count`.
Errors: `ValueError("no MODEL tag in NSDP response")` if no `Tag.MODEL` TLV.
No `Tag.MAC` TLV → MAC falls back to `parse_mac(packet.server_mac)` (the
packet header field), not an error.

---

## 4. `protocols/nsdp/write.py` + `auth.py` + `client.py`

### 4.1 write.py — constants + TLV builders

```python
RESULT_SUCCESS = 0x0000
RESULT_BAD_PASSWORD = 0x0700
```

- `build_read_request(client_mac, server_mac, sequence, tags: list[Tag]) -> NSDPPacket` —
  `Op.READ_REQUEST`; one length-0 TLV per tag ("please read this").
- `build_write_request(client_mac, server_mac, sequence, password, tlvs) -> NSDPPacket` —
  `Op.WRITE_REQUEST`; **prepends** `TLVEntry(Tag.PASSWORD, encode_password_v1(password))`
  as the FIRST TLV, then the caller's `tlvs` unchanged, in order.
- `pvid_tlv(port, vlan) -> TLVEntry` — `Tag.PORT_PVID`, value = `bytes([port]) + struct.pack(">H", vlan)` (3 bytes).
- `vlan_members_tlv(vlan, members, tagged, port_count) -> TLVEntry` — `Tag.VLAN_MEMBERS`,
  `width=(port_count+7)//8`, value = `struct.pack(">H", vlan) + ports_to_bitmap(members, width) + ports_to_bitmap(tagged, width)`.
- `ipv4_tlv(tag, dotted) -> TLVEntry` — value = `socket.inet_aton(dotted)` (any IPv4-shaped tag).
- `dhcp_tlv(enabled) -> TLVEntry` — `Tag.DHCP_MODE`, value = `b"\x01"` if enabled else `b"\x00"`.
- `reboot_tlv() -> TLVEntry` — `Tag.REBOOT`, empty value. **DEAD CODE from the
  write-facade's perspective — see §6.5, this is never called by
  `nsdp_write.py`.**

**Write-path is explicitly flagged UNVERIFIED** against real hardware (module
docstring) — `PORT_PVID` (0x3000) and `VLAN_MEMBERS` (0x2800) are documented
as **READ-ONLY (R)** in the reference spec
(`gdoc2netcfg/docs/nsdp-protocol.md`), unlike hostname/ip/netmask/gateway/
dhcp_mode/vlan_engine which are R/W. Their builders existing here is not
confirmation they're writable on real hardware — this is why `nsdp_write.py`
verifies every write by reading it back (§6.5).

### 4.2 auth.py — v1 XOR, v2 unimplemented

```python
V1_KEY = b"NtgrSmartSwitchRock"  # 19 bytes

def encode_password_v1(password: str) -> bytes:
    pw = password.encode("ascii")
    return bytes(b ^ V1_KEY[i % len(V1_KEY)] for i, b in enumerate(pw))
```

XOR is its own inverse — the SAME function both encodes an outgoing password
and would decode an incoming one; no separate decode function exists.

**v2 auth: genuinely NOT IMPLEMENTED, not merely "detected and rejected
proactively"**. There is no code path that inspects a password and decides
"this needs v2". The only "detection" is *reactive*: a switch that rejects v1
auth returns wire result `0x0700`, and `client.py::check_result()` turns that
into an `NsdpError` whose message embeds:

```python
AUTH_V2_UNSUPPORTED = (
    "NSDP v2 salt/hash auth (tags 0x0017/0x001A) is unverified and not "
    "implemented; this backend supports only v1 XOR auth"
)
```

### 4.3 client.py

- **`NsdpError(NetgearSwitchError)`** — plain marker subclass, no extra fields.
- **`check_result(packet) -> None`**:
  ```python
  def check_result(packet: NSDPPacket) -> None:
      if packet.result == RESULT_SUCCESS:
          return
      if packet.result == RESULT_BAD_PASSWORD:
          raise NsdpError(f"NSDP write rejected: bad password (result 0x0700). {AUTH_V2_UNSUPPORTED}")
      raise NsdpError(f"NSDP request failed with result 0x{packet.result:04x}")
  ```
  Only `0x0000` is silent success. `0x0700` gets the bad-password+v2-caveat
  message verbatim concatenated. Any other non-zero result gets
  `f"NSDP request failed with result 0x{result:04x}"` (4 lowercase hex
  digits, zero-padded).
- **`read_interface_mac(interface) -> bytes`**:
  ```python
  def read_interface_mac(interface: str) -> bytes:
      text = Path(f"/sys/class/net/{interface}/address").read_text().strip()
      raw = bytes.fromhex(text.replace(":", ""))
      if len(raw) != 6:
          raise NsdpError(f"interface {interface!r} MAC is not 6 bytes: {text!r}")
      return raw
  ```
  Linux-sysfs-only, no portability fallback attempted here (the *fallback to
  the dummy MAC* lives in the transport layer, §5.6 — this function itself
  either returns a real 6-byte MAC or raises).
- **"protocols registry"**: there is **no `PROTOCOLS` list**. What exists are
  four `typing.Protocol` structural-typing interfaces (pure interfaces, not a
  registry):
  ```python
  class NsdpClient(Protocol):
      def read(self, tags: list[Tag]) -> NSDPPacket: ...
  class NsdpWriteClient(NsdpClient, Protocol):
      def write(self, tlvs: list[TLVEntry], *, password: str) -> NSDPPacket: ...
  class AsyncNsdpClient(Protocol):
      async def read(self, tags: list[Tag]) -> NSDPPacket: ...
  class AsyncNsdpWriteClient(AsyncNsdpClient, Protocol):
      async def write(self, tlvs: list[TLVEntry], *, password: str) -> NSDPPacket: ...
  ```
  Go equivalent: plain interfaces `nsdp.Client { Read(ctx, tags []Tag)
  (*Packet, error) }` and `nsdp.WriteClient { nsdp.Client; Write(ctx, tlvs
  []TLVEntry, password string) (*Packet, error) }` (Go has no separate
  sync/async split, so only two interfaces are needed, not four).

---

## 5. Transport: `transport/sync/nsdp_udp.py` (+ `transport/aio/nsdp_udp.py` deltas)

`UdpNsdpClient` (sync, 119 lines) / `AsyncUdpNsdpClient` (aio, 160 lines).
Same logic; aio factors socket work into a standalone `_udp_transceive(payload,
addr, *, client_port, interface, timeout)` coroutine for unit-testability
(mirrors the sync client's injectable `sock_factory` seam). The only
behavioral delta: aio's `_udp_transceive` wraps socket setup in `except
BaseException: sock.close(); raise` to avoid an fd leak if
`create_datagram_endpoint` fails before taking ownership — sync doesn't need
this since it always owns/closes the socket in a `finally`.

### 5.1 Ports — constructor kwargs, not module constants/env vars

```python
client_port: int = 63321,
server_port: int = 63322,
timeout: float = 2.0,
```
Overridable per-instance (tests pass `client_port=0` for an ephemeral
unprivileged bind).

### 5.2 Ephemeral client bind
`sock.bind(("", self._client_port))` — all interfaces, configured client port
(default 63321, or 0 for ephemeral test binds). Identical in sync/async.

### 5.3 `SO_BINDTODEVICE` — best-effort, wrapped

```python
if self._interface is not None:
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
            self._interface.encode() + b"\0")
```
Needs `CAP_NET_RAW`/root; wrapped so an unprivileged caller still attempts
the query (succeeding on a directly-attached segment) rather than crashing.
Identical logic in async.

### 5.4 `SO_REUSEADDR` — unconditional, no try/except
`sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)`.

### 5.5 Timeout / recv buffer
`timeout: float = 2.0` default; sync applies via `sock.settimeout(...)`,
async via `asyncio.wait_for(future, timeout)`. Sync recv buffer: `sock.recvfrom(4096)`
(async has no equivalent cap; `DatagramProtocol.datagram_received` gets
whatever the OS delivers).

### 5.6 Sequence increment
```python
def _next_seq(self) -> int:
    self._sequence = (self._sequence + 1) & 0xFFFF
    return self._sequence
```
Starts at 0, **pre-increments** (first sequence sent is 1, not 0). `& 0xFFFF`
wraparound is deliberate (see §1.2's header-field note: the wire field is 32
bits, but this client only ever uses/increments the low 16).

### 5.7 Client MAC — sysfs read, dummy fallback

```python
_DUMMY_MAC = b"\x00\x00\x00\x00\x00\x01"  # 00:00:00:00:00:01
```
Selection (both sync/async `__init__`, identical):
```python
if client_mac is not None:
    self._client_mac = client_mac
elif interface is not None:
    self._client_mac = read_interface_mac(interface)  # can raise NsdpError
else:
    self._client_mac = _DUMMY_MAC
```
**Important**: this is NOT a try/except fallback. If `interface` is given and
`read_interface_mac` fails (missing file, wrong length), it **raises**
`NsdpError` — it does NOT silently fall back to the dummy MAC. The dummy MAC
is used only when *neither* `client_mac` nor `interface` was supplied at all.
There's also a `_BROADCAST_MAC = b"\x00"*6` used as the `server_mac` header
field placeholder on every outgoing request (read AND write) — the
destination MAC field is always zeroed, regardless of query type.

### 5.8 Unicast-only, no broadcast discovery
Destination for every send is always `(self.host, self._server_port)` — a
mandatory constructor `host` argument. **There is no broadcast-discovery
mode anywhere in this transport** — no `255.255.255.255`, no `SO_BROADCAST`.
The docstring calls this "the `query_ip` pattern — preferred over broadcast
discovery for a known host." `query_ip` = the constructor's `host` param,
full stop.

### 5.9 Op-check BEFORE check_result (ordering matters)

Write path (identical shape in sync/async):
```python
resp = self._exchange(req)
if resp.op != Op.WRITE_RESPONSE:
    raise NsdpError(f"expected WRITE_RESPONSE from {self.host}, got {resp.op}")
check_result(resp)
return resp
```
**Why order matters**: a stray/misrouted datagram (e.g. an old
`READ_RESPONSE` with `result=0x0000`) would pass `check_result` (which only
inspects `.result`) as if it were a successful write, if `check_result` ran
first. Checking `.op` first rules out anything that isn't actually a
`WRITE_RESPONSE` before ever consulting its result field. (`read()` has no
`check_result` call at all — only the op-code check against
`Op.READ_RESPONSE`.)

### 5.10 Exact error strings (transport layer)
- Timeout: `f"NSDP request to {self.host} timed out"`
- Malformed: `f"malformed NSDP response from {self.host}: {exc}"` (wrapping the `NSDPPacket.decode` `ValueError`)
- Wrong op on read: `f"expected READ_RESPONSE from {self.host}, got {resp.op}"`
- Wrong op on write: `f"expected WRITE_RESPONSE from {self.host}, got {resp.op}"`

---

## 6. `nsdp_read.py` / `nsdp_write.py` — per-op mapping, unsupported ops

### 6.1 Per-op tag sets

```python
def get_ports(self): return _ports(self._device([Tag.PORT_COUNT, Tag.PORT_STATUS]))
def get_stats(self): return _stats(self._device([Tag.PORT_STATISTICS]))
def get_vlans(self): return _vlans(self._device([Tag.PORT_COUNT, Tag.VLAN_MEMBERS]))
def get_pvids(self): dev = self._device([Tag.PORT_PVID]); ...
def get_mgmt_ip(self): return _mgmt(self._device([Tag.IP_ADDRESS, Tag.NETMASK, Tag.GATEWAY, Tag.DHCP_MODE]))
def get_device(self): return self._device(_FULL_DEVICE_TAGS)
```

```python
_FULL_DEVICE_TAGS = [
    Tag.MODEL, Tag.MAC, Tag.HOSTNAME, Tag.IP_ADDRESS, Tag.NETMASK, Tag.GATEWAY,
    Tag.FIRMWARE_VER_1, Tag.DHCP_MODE, Tag.PORT_COUNT, Tag.SERIAL_NUMBER,
    Tag.VLAN_ENGINE, Tag.PORT_STATUS, Tag.PORT_STATISTICS, Tag.VLAN_MEMBERS,
    Tag.PORT_PVID, Tag.QOS_ENGINE, Tag.PORT_MIRRORING, Tag.IGMP_SNOOPING,
    Tag.BROADCAST_FILTERING, Tag.LOOP_DETECTION,
]
```

### 6.2 `_with_model` — a wire-protocol necessity, NOT a model-metadata variant

```python
def _with_model(tags: list[Tag]) -> list[Tag]:
    """Prepend Tag.MODEL to a per-op read's tag list. Real Plus hardware
    answers a read with ONLY the tags requested (confirmed live on a
    GS105PE, 2026-07-21), and parse_device requires a MODEL tag."""
    if Tag.MODEL in tags:
        return tags
    return [Tag.MODEL, *tags]
```
Every internal `_device()` call routes its tag list through this — it just
guarantees `Tag.MODEL` is always in the wire request, because `parse_device`
unconditionally requires a MODEL TLV in the response and real hardware only
answers tags it was explicitly asked for. Nothing to do with consulting
model capability metadata despite the "_with_model" name's surface reading.

### 6.3 Field-mapping quirks (verbatim)

| quirk | code |
|---|---|
| admin always `True` | `admin_enabled=True,  # NSDP PORT_STATUS reports link speed only; cannot distinguish admin-disabled from link-down` |
| port name always `None` | `name=None,  # NSDP PORT_STATUS carries no port name` |
| speed "or None" | `speed_mbps=s.speed.speed_mbps or None,` |
| stats: no packet counters, rx_errors=CRC | `rx_packets=None, tx_packets=None, rx_errors=s.crc_errors, tx_errors=None,` |
| VLAN name always `None` | `name=None,  # NSDP VLAN_MEMBERS carries no VLAN name` |
| base MAC upper-cased | `base_mac=dev.mac.upper(),  # uppercased to match SNMP-backend formatting so the public field has one consistent case across backends` |

### 6.4 Unsupported reads (exact messages)

```python
_NO_MACS = "NSDP exposes no MAC/FDB table (Plus switches have no remote FDB)"
_NO_LLDP = "NSDP exposes no LLDP neighbours on these Plus switches"
_NO_SENSORS = "NSDP exposes no environmental sensors on these Plus switches"
_NO_POE = "NSDP exposes no PoE status; use the HTTP backend (Slice 6) for PoE"
```
Raised as `UnsupportedCapabilityError` from `get_macs`/`get_lldp`/
`get_sensors`/`get_poe` (both sync and async readers). Constructor-time guard:
`_require_nsdp()` raises `UnsupportedCapabilityError(f"model {model.key!r}
has no NSDP backend")` if `Backend.NSDP not in model.backends` — this is
distinct from (but textually similar to) the facade-level `require_nsdp_backend`
gate in §8.1; both must exist (defense in depth).

### 6.5 Writes — verify-after-write pattern

`set_pvid`, `set_vlan_membership`, `set_mgmt_ip` all do **read-before → write
→ read-after → compare, raising `WriteVerificationError` on mismatch**:

```python
# set_pvid
before = dict(self._reader.get_pvids())
self.client.write([pvid_tlv(port, vlan)], password=self._password)
after = dict(self._reader.get_pvids())
if after.get(port) != vlan:
    raise WriteVerificationError(f"PVID for port {port} did not read back as {vlan}",
        before=before.get(port), after=after.get(port))
```
(`set_vlan_membership` and `set_mgmt_ip` follow the identical
before/write/after/compare shape — see §4.1's UNVERIFIED-write caveat for
*why* this exists: `PORT_PVID`/`VLAN_MEMBERS` are documented read-only in the
reference spec, so verify-after-write is the runtime safety net.) Both
`set_pvid`/`set_vlan_membership` also run `_guard(port, force)` FIRST —
raises `ProtectedPortError(f"port {port} is protected; pass force=True to
override")` for a protected port without `force`.

### 6.6 Unsupported writes (exact messages)

```python
_NO_POE = "NSDP has no PoE control tag; use the HTTP backend (Slice 6) for PoE"
_NO_PORT_ADMIN = ("no per-port admin-enable is available on these Plus models: NSDP has no "
    "admin-enable tag, and the web UI has no grounded port-enable endpoint "
    "(UNVERIFIED-pending-capture)")
_NO_VLAN_LIFECYCLE = ("NSDP has no VLAN create/destroy tag on these Plus models; only VLAN "
    "membership/PVID are writable over NSDP")
```
Mapping: `set_poe`/`cycle_poe`/`clear_poe_fault` → `_NO_POE`;
`set_port_enabled` → `_NO_PORT_ADMIN`; `create_vlan`/`delete_vlan` →
`_NO_VLAN_LIFECYCLE`. All `UnsupportedCapabilityError`, both sync/async.

### 6.7 mgmt-IP force gate — blanket, not port-specific

```python
def set_mgmt_ip(self, address, netmask, gateway, *, force=False):
    if not force:
        raise ProtectedPortError("set_mgmt_ip can strand the switch; pass force=True to override")
```
Unconditional whole-operation gate (no `_guard()`/protected-ports set
involved) — without `force=True` it raises before ever touching the client.

### 6.8 Reboot — **NOT IMPLEMENTED as a write op** (important trap)

There is **no `reboot()` method anywhere in `NsdpWriter`/`AsyncNsdpWriter`**.
`write.reboot_tlv()` exists as a pure encoder (§4.1) but `grep -rn
"reboot_tlv"` shows it is referenced **only** from
`tests/protocols/nsdp/test_write_frame.py` — a frame-encoding unit test. It is
never called from `nsdp_write.py`, never wired to a public write-facade
method. **NSDP reboot is dead code in the pinned Python reference.** Reboot
IS implemented, but only for the HTTP backend (`http_write.py`, Slice 6). If
the Go port's `BackendWriter` interface ever grows a `Reboot` method, the
NSDP writer should treat it the same way it treats PoE/port-admin/VLAN-
lifecycle — `ErrUnsupportedCapability` — NOT attempt to synthesize a reboot
via `reboot_tlv()`, since that path is unverified and untested even in
Python. (Today's Go `BackendWriter` interface has no `Reboot` method at all,
so this is forward-looking, not an immediate gap.)

---

## 7. Virtual: `state.py` NSDP methods, `faces/nsdp.py`, `seed.py` Plus seeds, `server.py` binding

### 7.1 `State.NsdpTlvs`/`ApplyNsdpWrite` — cross-check against D-VIRT §1.12/§1.13

D-VIRT (`2026-07-30-slice-02-dossier-virtual.md`) §1.12/§1.13 already
transcribed `nsdp_tlvs(tags)`/`apply_nsdp_write(tag, value)` byte-exactly.
**Cross-checked against this pin (1aa1274) directly against
`src/netgear_switch/virtual/state.py` lines 573–735: still fully accurate, no
drift.** Reproduced verbatim below for this slice's self-containedness (do
not re-derive from Python — port from this text):

> ### `nsdp_tlvs(tags: set[Tag]) -> list[TLVEntry]`
>
> **STRICT**: answers with ONLY the tags requested (real Plus hardware does
> exactly this — a read omitting MODEL gets a MODEL-less response). Unknown
> requested tags silently skipped.
>
> - `Tag.MODEL` (if requested): `TLVEntry(Tag.MODEL, (self.model_name or model.display_name).encode("ascii"))`
> - `Tag.MAC`: `TLVEntry(Tag.MAC, self.nsdp_mac)`
> - `Tag.PORT_COUNT`: `TLVEntry(Tag.PORT_COUNT, bytes([model.port_count]))`
> - `Tag.SERIAL_NUMBER` (if `self.serial` truthy): `b"\x01" + serial.encode("ascii")`
> - `Tag.HOSTNAME` (if `self.hostname` truthy): ascii-encoded
> - `Tag.FIRMWARE_VER_1` (if `self.firmware` truthy): ascii-encoded
> - `Tag.PORT_STATUS`: for each port sorted by key: `bytes([port, speed_byte, 0x01])` where `speed_byte = _mbps_to_speed_byte(sim.speed) if sim.link else 0x00`
> - `Tag.PORT_STATISTICS`: for **EVERY** port sorted by key (real hardware returns one row per port, zeroed on idle ports): `bytes([port]) + struct.pack(">Q", rx_octets or 0) + struct.pack(">Q", tx_octets or 0) + struct.pack(">Q", rx_errors or 0) + b"\x00"*24`
> - `Tag.VLAN_MEMBERS`: for each vlan sorted by vid: `tagged = member - untagged`; `struct.pack(">H", vid) + ports_to_bitmap(member, width) + ports_to_bitmap(tagged, width)` where `width = (port_count + 7) // 8`
> - `Tag.PORT_PVID`: for each port sorted: `bytes([port]) + struct.pack(">H", pv)`
> - `Tag.IP_ADDRESS` / `Tag.NETMASK` / `Tag.GATEWAY`: `socket.inet_aton(...)`
> - `Tag.DHCP_MODE`: `b"\x00" if mode == "static" else b"\x01"`
> - `Tag.QOS_ENGINE` (if `nsdp_qos_engine is not None`): `bytes([value])`
> - `Tag.PORT_MIRRORING` (if `nsdp_port_mirroring_dest is not None`): `bytes([dest]) + ports_to_bitmap(sources, width)` — width is model-dependent (5-port GS105PE → 2-byte bitmap/3-byte TLV; 10-port GS110EMX → 3 bytes), derived from `port_count`, NOT hardcoded.
> - `Tag.IGMP_SNOOPING` (if `nsdp_igmp_snooping_enabled is not None`): `bytes([0x00, 1 if enabled else 0, 0x00, vlan_byte])` where `vlan_byte = nsdp_igmp_snooping_vlan or 0`
> - `Tag.BROADCAST_FILTERING` (if not `None`): `bytes([1 if enabled else 0])`
> - `Tag.LOOP_DETECTION` (if not `None`): `bytes([1 if enabled else 0])`
>
> ### `apply_nsdp_write(tag: Tag | int, value: bytes) -> None`
>
> Unknown/read-only tags: deliberate no-op (verify-after-write catches it).
>
> - `Tag.PORT_PVID`: `self.pvids[value[0]] = struct.unpack_from(">H", value, 1)[0]`
> - `Tag.VLAN_MEMBERS`: `m = parse_vlan_members(value, model.port_count)`; preserves existing `.name` if the vlan row exists, else `""`; `self.vlans[m.vlan_id] = VlanSim(name=name, member=set(m.member_ports), untagged=set(m.untagged_ports))`
> - `Tag.IP_ADDRESS` / `NETMASK` / `GATEWAY`: `socket.inet_ntoa(value)` into the corresponding `mgmt` field
> - `Tag.DHCP_MODE`: `self.mgmt.mode = "dhcp" if value[:1] == b"\x01" else "static"`
> - `REBOOT` / `FACTORY_RESET` / unknown: deliberate no-op

One nuance the live source has that D-VIRT's §1.12 prose slightly
undersells: `nsdp_tlvs`'s own docstring's first sentence ("MODEL/MAC/
PORT_COUNT... always included") is **stale relative to the actual code**,
which gates ALL THREE on `if Tag.X in tags` exactly like every other tag —
confirmed deliberate by an inline "STRICT" comment in the source and pinned
by `test_nsdp_tlvs_projects_ports_and_identity` (a PORT_STATUS-only request
must NOT also return MODEL). D-VIRT's bullet list (reproduced above) already
gets this right; only its own docstring-quoting prose (not reproduced here)
would mislead — **port the bullet-list behavior, not "always included"**.

**Go status**: `virtual/state.go` (this repo) already carries every field
`nsdp_tlvs`/`apply_nsdp_write` need (`NsdpPassword`, `NsdpMac [6]byte`,
`NsdpQosEngine *int`, `NsdpPortMirroringDest *int`,
`NsdpPortMirroringSources map[int]bool`, `NsdpIgmpSnoopingEnabled *bool`,
`NsdpIgmpSnoopingVlan *int`, `NsdpBroadcastFiltering *bool`,
`NsdpLoopDetection *bool`) — confirmed present at `virtual/state.go` lines
162–185, explicitly doc-commented "NOT consumed by anything in this slice...
slice-05 scope". **`NsdpTlvs`/`ApplyNsdpWrite` methods themselves do NOT
exist anywhere in the Go repo** (confirmed: no `func (s *State) NsdpTlvs` or
`func (s *State) ApplyNsdpWrite` in any `.go` file; the only hit for either
name is the doc-comment sentence naming them as forthcoming). This slice
must add both methods to `virtual/state.go`, using `[]model.TLVEntry`/
`model.Tag` (or a `nsdp.TLVEntry`/`nsdp.Tag` if those land in a new `nsdp`
package instead — see §10's package-placement discussion) as the wire type.

### 7.2 `faces/nsdp.py` — `VirtualNsdpFace`

- **`start()`**: `AF_INET`/`SOCK_DGRAM`, `SO_REUSEADDR`, bind `(host, 0)`
  (ephemeral; default `host="127.0.0.1"` — loopback-only, no root, no
  `SO_BINDTODEVICE`, unlike the real client transport), `settimeout(0.2)`,
  spawn daemon thread `"virtual-nsdp-face"` running `_serve`, return bound
  port.
- **`_serve()`**: `while not self._stop.is_set(): recvfrom(4096)`; `TimeoutError`
  → `continue` (lets it observe `_stop` every 0.2s); `OSError` → `break`;
  else `self._handle(data)` wrapped in `except ValueError: continue`
  (malformed drop); if a response was produced, `sendto` wrapped in
  `contextlib.suppress(OSError)`.
- **`_handle(data)`**: `NSDPPacket.decode(data)` (can raise `ValueError` —
  caught by `_serve`), dispatch on `req.op`: `READ_REQUEST` →
  `_read_response`, `WRITE_REQUEST` → `_write_response`, else `None` (no
  response sent — matches real hardware's silent-drop-of-unexpected-op
  behavior).
- **Auth validation (exact)**:
  ```python
  def _write_response(self, req: NSDPPacket) -> NSDPPacket:
      expected = encode_password_v1(self._state.nsdp_password)
      password_ok = any(t.tag == Tag.PASSWORD and t.value == expected for t in req.tlvs)
      resp = NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=req.client_mac,
          server_mac=self._state.nsdp_mac, sequence=req.sequence)
      if not password_ok:
          resp.result = RESULT_BAD_PASSWORD
          return resp
      for tlv in req.tlvs:
          if tlv.tag != Tag.PASSWORD:
              self._state.apply_nsdp_write(tlv.tag, tlv.value)
      resp.result = RESULT_SUCCESS
      return resp
  ```
  Plain `==` compare — intentionally NOT constant-time (loopback-only test
  mock, not a security boundary; **Go should follow this, not add
  `hmac.Equal` or similar** — that would be over-engineering a test fixture).
  On auth failure: `result = RESULT_BAD_PASSWORD` (0x0700), returned
  immediately, **no state mutation, no TLVs applied**.
- **Malformed drop (confirmed silent, not crash)**:
  ```python
  try:
      response = self._handle(data)
  except ValueError:
      continue  # malformed request datagram: ignore, as hardware does
  ```
- **Lifecycle**: `stop()` sets stop event, joins serve thread (timeout=5s),
  closes socket (suppressing `OSError`), resets port to 0 — designed to
  avoid `ResourceWarning` under `-W error::ResourceWarning`.

**Go analogue**: mirror `virtual/snmpface.go`'s exact shape (§10.3) — this
repo already has the pattern to follow 1:1, just with NSDP's own wire codec
instead of gosnmp's.

### 7.3 Seed data — gs110emx / gs305ep / gs105pe (Plus models)

Wired via `virtual/server.py`'s `_SEEDS` dict entries `"gs110emx":
seed_gs110emx`, `"gs305ep": seed_gs305ep`, `"gs105pe": seed_gs105pe`.
**None of these seed functions exist in the Go repo yet** — confirmed:
`virtual/seed.go`'s `BuildState` switch (lines 943–958) only handles
`gsm7252ps`/`gsm7228ps`/`m4300-24x`/`m4300-16x`/`gs728tpp`; its own doc
comment explicitly states *"NSDP/HTTP-only Plus models (gs110emx, gs305ep,
gs105pe) deliberately get a blank state here — their own seeds are Slice 05
(protocols/nsdp) and Slice 06 (protocols/http) scope, not this slice's."*
This slice must add `SeedGS110EMX`, `SeedGS305EP`, `SeedGS105PE` to
`virtual/seed.go` and wire them into `BuildState`'s switch.

#### `seed_gs110emx()` — grounded in real captures (10.1.5.25)

```python
def seed_gs110emx() -> VirtualSwitchState:
    real_speed = {6: 100, 8: 1000, 9: 10000, 10: 10000}
    real_octets = {
        6: (0, 70_892_018_242),
        8: (59_921_732_691, 78_637_274_870),
        9: (2_963_140_428_936, 1_189_358_575_871),
        10: (1_195_417_274_187, 3_027_396_511_187),
    }
    ports: dict[int, PortSim] = {}
    for port in range(1, 11):
        sim = PortSim(name=f"g{port}", admin=True, link=port in real_speed,
            speed=real_speed.get(port, 0), description="rumpus" if port == 8 else None)
        sim.rx_octets, sim.tx_octets = real_octets.get(port, (0, 0))
        sim.rx_errors = 0
        ports[port] = sim

    vlans = {
        1: VlanSim(name="", member=set(range(1, 11)), untagged=set(range(1, 9))),
        90: VlanSim(name="", member={1, 2, 10}, untagged={1, 2}),  # ILLUSTRATIVE (not captured)
    }
    pvids = dict.fromkeys(range(1, 11), 1)
    mgmt = MgmtSim(address="10.1.5.25", netmask="255.255.255.0", gateway="10.1.5.1", mode="static")

    return VirtualSwitchState(
        model_key="gs110emx", ports=ports, vlans=vlans, pvids=pvids, mgmt=mgmt,
        model_name="GS110EMX", serial="53H60253A0032", firmware="1.0.1.4",
        hostname="sw-netgear-gs110emx1",
        nsdp_mac=b"\xbc\xa5\x11\xb8\xec\xf1", nsdp_password="password",
        nsdp_qos_engine=1, nsdp_port_mirroring_dest=10,
        nsdp_port_mirroring_sources=frozenset({1, 2}),
        nsdp_igmp_snooping_enabled=True, nsdp_igmp_snooping_vlan=90,
        nsdp_broadcast_filtering=True, nsdp_loop_detection=True,
    )
```
Ports 6/8/9/10 up at 100M/1G/10G/10G (port 8 desc "rumpus"), rest down; static
10.1.5.25/24 via 10.1.5.1; MAC bc:a5:11:b8:ec:f1. VLAN 1 membership
transcribed from a real capture (`gs110emx_vlanmembership.html`,
`hiddenMem "1111111122"` = ports 1-8 untagged, 9-10 tagged); **VLAN 90's
member/untagged sets are explicitly ILLUSTRATIVE** (no capture of its
membership page exists, only its VLAN-ID listing). PVIDs all 1 (transcribed
from `gs110emx_pvid.html`). QoS/mirroring/IGMP/broadcast/loop-detection
values are explicitly labeled test fixtures ("STILL ILLUSTRATIVE... chosen so
`nsdp_device()` has something non-vacuous to decode on every parsed tag"), NOT
observed hardware values. No PoE fields (registry: `poe_count=0`), no box
sensors/MAC-FDB/LLDP (Plus family has none of these).

#### `seed_gs305ep()` — ENTIRELY HAND-INVENTED, and **incomplete NSDP identity**

```python
def seed_gs305ep() -> VirtualSwitchState:
    ports = {p: PortSim(name=f"Port {p}", admin=p != 3, link=p == 1, speed=1000 if p == 1 else 0)
        for p in range(1, 6)}
    ports[1].rx_octets = 1_000_000
    ports[1].tx_octets = 2_000_000
    ports[1].rx_errors = 0
    vlans = {
        1: VlanSim(name="default", member={1, 2, 3, 4, 5}, untagged={3, 4, 5}),
        90: VlanSim(name="iot", member={1, 2}, untagged={1, 2}),
    }
    pvids = {1: 90, 2: 90, 3: 1, 4: 1, 5: 1}
    poe = {
        1: PoeSim(admin=True, detect=3, power_mw=12_800),
        2: PoeSim(admin=True, detect=1, power_mw=0),
        3: PoeSim(admin=True, detect=1, power_mw=0),
        4: PoeSim(admin=False, detect=1, power_mw=0),
    }
    return VirtualSwitchState(model_key="gs305ep", ports=ports, vlans=vlans, pvids=pvids, poe=poe)
```
Docstring: **"HAND-INVENTED: no capture of any kind exists for gs305ep"** —
port speeds, the 12800 mW PoE reading, VLAN 90, PVIDs are all structural test
data, not observed values.

**IMPORTANT TRANSCRIPTION GAP** (flag for the Go port's design decision): this
constructor call passes **no** `model_name`/`serial`/`firmware`/`hostname`/
`nsdp_mac`/`nsdp_password`/any of the NSDP-extra fields
(`nsdp_qos_engine`/`nsdp_port_mirroring_*`/`nsdp_igmp_snooping_*`/
`nsdp_broadcast_filtering`/`nsdp_loop_detection`) at all — every one of them
falls back to the `VirtualSwitchState` dataclass default (`model_name=""`,
`serial=""`, `firmware=""`, `hostname=""`, `nsdp_password="password"`,
`nsdp_mac=b"\x28\xc6\x8e\x00\x00\x01"`, QoS/mirroring/IGMP/broadcast/loop all
`None`). `mgmt` is also left at the dataclass default (`address="0.0.0.0"`,
mode `"dhcp"`) rather than a real-looking seeded value. **Port this exact gap
1:1** (call `NewState`-equivalent defaults, don't invent values Python
doesn't have) — a Go seed that "helpfully" fills these in would silently
diverge from the parity reference and defeat any future Go↔Python
cross-fake-equivalence test (roadmap slice 10).

#### `seed_gs105pe()` — grounded in a real live capture (10.1.5.30 / poe-micro3, 2026-07-21)

```python
def seed_gs105pe() -> VirtualSwitchState:
    ports = {p: PortSim(name=f"Port {p}", admin=True, link=p in (3, 5),
        speed={3: 100, 5: 1000}.get(p, 0)) for p in range(1, 6)}
    ports[3].tx_octets = 10_246_512
    ports[5].rx_octets = 29_303_468
    ports[5].tx_octets = 289_149
    ports[5].rx_errors = 228_666
    vlans = {
        1: VlanSim(name="", member={5}, untagged={5}),
        41: VlanSim(name="", member={1, 2, 4, 5}, untagged={1, 2, 4}),
        90: VlanSim(name="", member={3, 5}, untagged={3}),
    }
    pvids = {1: 41, 2: 41, 3: 90, 4: 41, 5: 1}
    return VirtualSwitchState(
        model_key="gs105pe", ports=ports, vlans=vlans, pvids=pvids,
        mgmt=MgmtSim(address="10.1.5.30", netmask="255.255.255.0", gateway="10.1.5.1", mode="dhcp"),
        model_name="GS105PE", serial="61W19753A00A8", firmware="V1.6.0.4",
        hostname="poe-micro3", nsdp_mac=b"\x38\x94\xed\xb7\xcd\xe0", nsdp_password="password",
        nsdp_qos_engine=2, nsdp_port_mirroring_dest=0,
        nsdp_port_mirroring_sources=frozenset(), nsdp_igmp_snooping_enabled=True,
        nsdp_igmp_snooping_vlan=1, nsdp_broadcast_filtering=False, nsdp_loop_detection=False,
    )
```
Ports 3 (100M) and 5 (1G) up, rest down. VLANs 1/41/90 with real
member/untagged sets; real PVIDs; DHCP mgmt-IP (address still `10.1.5.30`
captured, mode `"dhcp"`). **Port mirroring OFF on this unit** (dest=0, empty
sources) — this is the exact unit whose 3-byte PORT_MIRRORING TLV exposed the
fixed-width parser bug that `parse_port_mirroring` (§3.9) had to be
generalized to fix — a valuable "dest=0/no sources" fixture to keep in the Go
port for regression coverage of that exact class of bug. No PoE (registry:
`poe_count=0`, "PoE pass-through" only, not PSE), no box sensors, **no
MAC/FDB over ANY interface** (confirmed firmware limitation, per registry.py
comment), no LLDP.

#### Registry metadata for all three (Go already has this — confirmed matching)

| model_key | display_name | port_count | poe_count | backends |
|---|---|---|---|---|
| `gs110emx` | GS110EMX | 10 | 0 | `{NSDP, HTTP}` |
| `gs305ep` | GS305EP | 5 | 4 | `{NSDP, HTTP}` |
| `gs105pe` | GS105PE | 5 | 0 | `{NSDP, HTTP}` |

Verified identical in `model/registry.go` (lines ~180-199 for gs110emx/
gs305ep, ~255-265 for gs105pe): `PortCount`/`PoEPortCount`/`Backends:
[]Backend{BackendNSDP, BackendHTTP}` already match exactly. No `model`
package changes needed for these three entries — only the seed data and
protocol/virtual-face code are missing.

### 7.4 `server.py` — NSDP binding

```python
def start(self) -> None:
    if Backend.SNMP in self._model_info.backends:
        ...
    if Backend.NSDP in self._model_info.backends:
        nsdp_face = VirtualNsdpFace(self.state, host=self.host)
        self.port = nsdp_face.start()
        self._nsdp_face = nsdp_face
    if Backend.HTTP in self._model_info.backends:
        ...
    if self._snmp_face is None and self._nsdp_face is None and self._http_face is None:
        raise UnsupportedCapabilityError(f"model {self.model!r} has no bindable protocol face")
```
For all three Plus models (`{NSDP, HTTP}`), `start()` independently
constructs+starts BOTH `VirtualNsdpFace` (into `self.port`) and
`VirtualHttpFace` (into `self.http_port`). **Trap**: Python's `self.port` is
a single shared field reused by both the SNMP and NSDP faces — never an
issue in practice (no model has both backends) but a documented latent trap.
**Go already avoids this trap deliberately**: `virtual/server.go`'s
`VirtualSwitch` struct has SEPARATE `SnmpPort`/`NsdpPort`/`HTTPPort`/
`SSHPort`/`TelnetPort` fields (the `NsdpPort int` field already exists,
reserved, always 0 until this slice). This slice's `Start()` change: add an
`if v.modelInfo.HasBackend(model.BackendNSDP)` block mirroring the existing
SNMP block exactly (build a `virtual.State`-backed `NsdpFace`, `Start()` it,
store into `v.NsdpPort`, keep the face reference for `Stop()`), and loosen the
current "only SNMP" no-face-bindable check into "none of SNMP/NSDP/HTTP/SSH
bound" as each slice lands (this slice: SNMP or NSDP).

---

## 8. Facade: dispatch gates, password plumbing, `sync_api.nsdp_device()`

### 8.1 `_dispatch.py` — `require_nsdp_backend` / `build_sync_nsdp_client`

```python
def require_nsdp_backend(model: SwitchModel) -> None:
    if Backend.NSDP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no NSDP backend")

def build_sync_nsdp_client(host: str, interface: str | None) -> NsdpWriteClient:
    from .transport.sync.nsdp_udp import UdpNsdpClient
    return UdpNsdpClient(host, interface=interface)
```
(async twin `build_async_nsdp_client` is identical, using
`AsyncUdpNsdpClient`.) **No password parameter at client construction** — the
raw transport client is password-agnostic; password is supplied per-write-call
only (§8.2). Return type annotated `NsdpWriteClient` (the richer protocol) so
a read-only caller can still use it, since `NsdpWriteClient` extends
`NsdpClient`.

**Go equivalent**: this slice adds `backend_nsdp.go` to the repo root
(`package netgearswitch`), following `backend_snmp.go`'s exact shape (§10.1):
`requireNSDPBackend`-equivalent is actually **already handled generically**
by `dispatch.go`'s `readVia`/`s.model.HasBackend(backend)` check — Go's
architecture doesn't need a separate `require_nsdp_backend` free function the
way Python's `_dispatch.py` does, EXCEPT for the `NsdpDevice()` bypass method
(§8.3), which — exactly like `Identify()` (switch.go lines 451-472) bypasses
`readVia` — will need its own explicit `model.HasBackend(model.BackendNSDP)`
check inline, since it doesn't go through `readVia`'s loop at all.

### 8.2 The "shared-password rule" — HTTP password feeds NSDP v1 auth

Traced fully in `sync_api.py`'s `SyncSwitch.from_config` (lines 265-272):

```python
def _resolve_nsdp_password() -> str | None:
    # Plus switches share ONE web-admin password across HTTP + NSDP, so
    # reusing the http_password spec as the NSDP v1 auth password is
    # intentional and correct.
    return cfg.http_password(env=_env)

def _resolve_http_password() -> str | None:
    return cfg.http_password(env=_env)

return cls(cfg.model, cfg.host, snmp_community=cfg.snmp_community,
    snmp_write_community_resolver=_resolve_write_community,
    nsdp_interface=cfg.nsdp_interface,
    nsdp_password_resolver=_resolve_nsdp_password,
    http_password_resolver=_resolve_http_password,
    protected_ports=cfg.protected_ports)
```
Both closures call the **SAME** `cfg.http_password(env=_env)` — there is no
separate `nsdp.password` config key; one web-admin password literally feeds
both. Full chain to the wire:
`cfg.http_password(env)` → `_resolve_nsdp_password` closure →
`SyncSwitch._nsdp_password_resolver` → `SyncSwitch._resolve_nsdp_password()`
(cached once) → `NsdpWriter(nsdp, model, password=password, ...)` →
`nsdp.write(tlvs, password=password)` on every write call.

```python
elif backend is Backend.NSDP:
    nsdp = self._nsdp_write_client
    if nsdp is None:
        nsdp = build_sync_nsdp_client(self.host, self._nsdp_interface)
    password = self._resolve_nsdp_password()
    if password is None:
        raise CredentialError(f"no NSDP admin password configured for {self.host!r}")
    writer = NsdpWriter(nsdp, self.model, password=password, protected_ports=self.protected_ports)
```

**CORRECTED post-Task-7 (this paragraph, and item #10 below, originally
understated the pin)**: re-reading `sync_api.py`'s `SyncSwitch.__init__`
directly (lines 185-218) shows `nsdp_password`/`nsdp_password_resolver` are
GENUINELY SEPARATE constructor parameters from `http_password`/
`http_password_resolver`, each with its OWN `_Unset`-sentinel resolve-once
cell (`self._resolved_nsdp_password` / `self._resolved_http_password`,
lines 214/218) and its own `_resolve_nsdp_password()`/`_resolve_http_password()`
method (lines 588-598 / 297-307). `from_config` (lines 265-272) is the ONLY
place that feeds both from the same `cfg.http_password(env=_env)` spec — and
its own comment says so explicitly as a deliberate, non-forced choice: *"A
dedicated `nsdp.password` config key is a trivial future follow-up (the
facade already accepts a distinct nsdp_password/nsdp_password_resolver) if a
deployment ever needs to split them; do NOT add a separate key now."* So the
earlier read here (and item #10) — "ONE `resolveOnce` cell, not two" — was
wrong about the constructor/option level; it only holds at the `from_config`
level, and even there the sharing is two independent resolutions of the same
underlying spec (see the "run twice" caveat item #10 itself half-noticed),
not a literal single cell.

**Go, corrected**: `switch.go` needs a SEPARATE `nsdpPassword *resolveOnce`
field (parallel to `httpPassword`) plus `WithNSDPPassword(string)`/
`WithNSDPPasswordResolver(func() (*string, error))` options (mirroring
`WithHTTPPasswordResolver`'s shape). `backend_nsdp.go`'s `buildNSDPWriter`
resolves `sw.nsdpPassword.resolve()` (NOT `sw.httpPassword`). `FromConfig`
wires BOTH cells from the SAME `cfg.HTTPPassword(os.LookupEnv, nil)` spec,
via two independent closures — matching Python's `from_config` exactly,
including the (intentional) consequence that a `!command`-style secret spec
resolves (and if it execs a subprocess, runs) independently for each cell on
its own first use. Gate a `nil` resolved NSDP password the same way SNMP's
write-community gate does — `fmt.Errorf("no NSDP admin password configured
for %q: %w", sw.host, model.ErrCredential)`, mirroring Python's
`CredentialError` message exactly.

### 8.3 `sync_api.py` — `nsdp_device()` bypass

```python
def nsdp_device(self) -> NsdpDevice:
    """... Unlike every other read op, this deliberately bypasses the
    SNMP/NSDP/HTTP backend-preference dispatch (_read): NSDP is the ONLY
    backend that can serve it, so a model without an NSDP backend raises
    UnsupportedCapabilityError directly (mirroring identify()'s bypass of
    that dispatch, and NsdpReader.__init__'s own _require_nsdp guard)."""
    reader = self._reader_for(Backend.NSDP)
    assert isinstance(reader, NsdpReader)
    return reader.get_device()
```
Calls `self._reader_for(Backend.NSDP)` **directly**, skipping the
`_BACKEND_PREFERENCE` loop (SNMP→NSDP→HTTP→SSH) entirely. If the model has no
NSDP backend, `_reader_for(Backend.NSDP)` itself raises
`UnsupportedCapabilityError` (via `NsdpReader.__init__`'s `_require_nsdp`
guard) — `nsdp_device()` never falls back to another backend, unlike every
other read op.

**NSDP reader/writer construction params** (from `_reader_for`/`_writer_for`):
```python
elif backend is Backend.NSDP:
    nsdp = self._nsdp_client
    if nsdp is None:
        nsdp = build_sync_nsdp_client(self.host, self._nsdp_interface)
    reader = NsdpReader(nsdp, self.model)
```
No port/timeout/password params exposed at this seam (internal to
`UdpNsdpClient`'s own defaults, §5.1); reader takes no password (reads are
unauthenticated in NSDP v1); writer adds `password=password,
protected_ports=self.protected_ports`.

**Go analogue**: this slice adds a `Switch.NsdpDevice(ctx context.Context)
(model.NsdpDevice, error)` method to `switch.go`, mirroring `Identify()`'s
bypass shape (lines 463-472) EXACTLY:
```go
func (s *Switch) NsdpDevice(ctx context.Context) (model.NsdpDevice, error) {
    if err := ctx.Err(); err != nil {
        return model.NsdpDevice{}, err
    }
    if !s.model.HasBackend(model.BackendNSDP) {
        return model.NsdpDevice{}, fmt.Errorf("model %q has no NSDP backend: %w", s.model.Key, model.ErrUnsupportedCapability)
    }
    reader, err := s.readerFor(model.BackendNSDP)  // still goes through the registry/cache, unlike Identify's bare client
    if err != nil {
        return model.NsdpDevice{}, err
    }
    nsdpReader, ok := reader.(interface{ GetDevice(context.Context) (model.NsdpDevice, error) })
    if !ok {
        return model.NsdpDevice{}, fmt.Errorf("model %q's NSDP reader has no GetDevice method: %w", s.model.Key, model.ErrUnsupportedCapability)
    }
    return nsdpReader.GetDevice(ctx)
}
```
(Exact type-assertion mechanics are a slice-05 implementation decision — the
`nsdp.Reader` concrete type could instead be looked up directly via a
dedicated internal accessor rather than a type-assert on `BackendReader`,
since `GetDevice` is NOT part of the 9-method `BackendReader` interface. Both
approaches are valid; pick whichever this repo's existing `Identify()`
precedent — which uses `buildSNMPClient(s)` directly, bypassing
`readerFor`/cache entirely — suggests is more idiomatic here. Recommend:
follow `Identify()`'s exact bypass shape, i.e. call a new `buildNSDPClient`+
`nsdp.NewReader` pair directly, NOT `s.readerFor`, since `readerFor`'s cache
holds `BackendReader`-typed values and `GetDevice` isn't on that interface —
type-asserting a cached value back to a concrete type works but is less clean
than just building fresh, exactly like `Identify` does for SNMP.)

---

## 9. Test inventory (tabulated)

### 9.1 `tests/protocols/nsdp/` (protocol/parser/auth/write-frame unit tests)

| File | Lines | Covers |
|---|---|---|
| `test_protocol.py` | 196 | Exact Op/Tag hex values; TLV encode/decode round-trip + error messages; header offsets (signature@0x18, sequence bytes 20-24); end-marker trailing-garbage tolerance; hand-built byte fixture cross-check; `test_sequence_number_is_a_full_4_byte_field` |
| `test_parsers.py` | 285 | `LinkSpeed.from_byte` incl. `0xFF→TEN_GIGABIT`/unknown→`DOWN`; byte-length assertions + exact error text; bitmap round-trip vectors; `parse_vlan_members` 8-port example; `parse_serial` prefix enforcement; port-mirroring variable-width vectors (2/3/4-byte forms, lifted from `gdoc2netcfg`); IGMP vectors; `parse_device` two-pass aggregation incl. "new tags" battery (QOS_ENGINE, PORT_MIRRORING, IGMP_SNOOPING, BROADCAST_FILTERING, LOOP_DETECTION) and MAC-fallback-to-server_mac case |
| `test_auth.py` | 25 | `V1_KEY` exact bytes/length (19), XOR self-inverse property, one deterministic vector for password `"AAAA"` |
| `test_write_frame.py` | 62 | `build_read_request`/`build_write_request` (password TLV prepended, order preserved); `pvid_tlv`/`vlan_members_tlv`/`ipv4_tlv`/`dhcp_tlv`/`reboot_tlv` exact byte outputs; `RESULT_SUCCESS`/`RESULT_BAD_PASSWORD` |

No dedicated `test_client.py` — `check_result`/`read_interface_mac`/
`NsdpError` are exercised only indirectly via `test_nsdp_read.py`,
`test_nsdp_integration.py`, `transport/test_nsdp_udp_sync.py`,
`virtual/test_virtual_nsdp_face.py`.

### 9.2 Transport tests

| File | Lines | Covers |
|---|---|---|
| `tests/transport/test_nsdp_udp_sync.py` | 363 | Both `UdpNsdpClient` and `AsyncUdpNsdpClient`/`_udp_transceive`; default `server_port=63322`; `client_port=0` ephemeral pattern; `SO_BINDTODEVICE` best-effort proven via `fail_on_opt` fakes; op-code-before-check_result ordering (`test_write_wrong_op_response_raises_nsdperror`); message matches for "bad password"/"timed out"/"malformed" |

### 9.3 Facade-level read/write tests

| File | Covers |
|---|---|
| `test_nsdp_read.py` | All field-mapping quirks (admin=True, speed None-for-down, rx_errors=CRC, VLAN name None, per-op MODEL-prefixing via `_TagFilteringNsdpClient`); four unsupported ops via `UnsupportedCapabilityError` |
| `test_nsdp_write.py` | Verify-after-write for `set_pvid`/`set_vlan_membership`/`set_mgmt_ip` incl. forced-failure case proving `WriteVerificationError` fires; `force` gate on `set_mgmt_ip`; protected-ports gate; all six unsupported writes parametrized (`set_poe`, `set_port_enabled`, `cycle_poe`, `clear_poe_fault`, `create_vlan`, `delete_vlan`); **no reboot test** (consistent with §6.8's finding) |
| `test_nsdp_integration.py` | 101 lines; sync-vs-async facade read/write parity; full-device facade |

### 9.4 Virtual-layer NSDP tests

| File | Test | Covers |
|---|---|---|
| `virtual/test_virtual_nsdp_face.py` | `test_face_read_returns_seed_ports` | READ for MODEL/PORT_COUNT/PORT_STATUS returns model "GS110EMX", ports 1..10 |
| | `test_face_authenticated_write_is_read_back` | Authenticated WRITE of a PVID TLV (port 5→VLAN 90) durably applied and read back |
| | `test_face_wrong_password_raises_bad_password` | Wrong password → `NsdpError` matching "bad password" |
| `virtual/test_nsdp_state.py` | `test_seed_has_plus_shape` | `seed_gs110emx()` yields correct model_key/serial/firmware/10 ports/PVID |
| | `test_nsdp_tlvs_projects_ports_and_identity` | PORT_STATUS-only request omits MODEL (strict filtering); combined request yields correct per-port speeds |
| | `test_nsdp_tlvs_projects_vlans_and_pvids_and_mgmt` | VLAN 90 member/untagged, mgmt IP, DHCP mode, PVID projection |
| | `test_apply_nsdp_write_pvid_and_membership_and_mgmt` | PVID/VLAN-membership/mgmt-IP mutation via `apply_nsdp_write` |

### 9.5 Facade-level NSDP intent tests (tabulated fully)

| File | Test | Assertion |
|---|---|---|
| `test_dispatch.py` | `test_require_nsdp_backend_passes_for_plus_model` | `require_nsdp_backend(get_model("gs110emx"))` doesn't raise |
| | `test_require_nsdp_backend_raises_for_snmp_only_model` | Raises `UnsupportedCapabilityError` for `gsm7252ps` |
| | `test_build_sync_nsdp_client_returns_udp_client` | Returns `UdpNsdpClient` with correct `.host` |
| | `test_build_async_nsdp_client_returns_async_udp_client` | Returns `AsyncUdpNsdpClient` with correct `.host` |
| `test_sync_api.py` | `test_plus_model_read_routes_to_nsdp` | gs305ep `get_ports()` routes via injected NSDP client |
| | `test_get_macs_on_plus_model_raises_no_mac_table` | Plus model `get_macs()` raises, message mentions "MAC" |
| | `test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections` | `snapshot()` populates ports from NSDP, empties macs/lldp/sensors, PoE from HTTP fallback |
| | `test_plus_model_write_raises_unsupported_capability` | NSDP writer refuses `set_port_enabled` untouched; HTTP fallback also refuses; last error surfaces mentioning "port-enable" |
| | `test_sync_switch_plus_model_reads_over_nsdp` | gs110emx `get_ports()` via NSDP; `get_macs()` still raises |
| | `test_sync_switch_plus_set_pvid_over_nsdp` | `set_pvid(1, 90)` writes via NSDP, records write's password arg as `"admin"` |
| | `test_gs305ep_poe_routes_to_http_ports_stay_nsdp` | NSDP `get_poe()` gap → HTTP fallback; ports stay NSDP |
| | `test_http_client_closed_after_http_routed_op` | Facade-built HTTP client closed even with `nsdp_client=object()` injected |
| | `test_injected_http_client_is_never_closed_by_facade` | Injected HTTP session never closed, NSDP present as stand-in |
| | `test_delete_vlan_guards_protected_member_before_http_fallback` | NSDP's `delete_vlan` always raises; guard fires before HTTP fallback |

`nsdp_device()` itself has no dedicated unit test in `test_sync_api.py` — its
coverage lives in `tests/cli/test_new_commands.py::test_nsdp_device_prints_record`
and `test_nsdp_integration.py`.

### 9.6 Broader NSDP-referencing test files (cross-check sweep)

| File | Purpose |
|---|---|
| `tests/test_registry.py` | `Backend.NSDP` membership; gs105pe's `{NSDP,HTTP}` set; live-verified NSDP MODEL string |
| `tests/test_config.py` | `SwitchConfig`/inventory parsing of `nsdp.interface` key |
| `tests/capture_parity.py` | Compares captured NSDP base-MAC bytes against seed data |
| `tests/equivalence.py` | Shared harness importing sync/async NSDP UDP clients |
| `tests/test_http_dispatch.py` | `http_reads_supported()` gating for gs305ep (NSDP+HTTP) |
| `tests/test_http_equivalence.py` | HTTP reads/PoE vs NSDP reads cross-verified against seeded gs305ep |
| `tests/conftest.py` | Shared fixture: seeded gs110emx (NSDP) VirtualSwitch on ephemeral UDP port |
| `tests/test_cli_write.py` | gs305ep (NSDP+HTTP, no CLI backend) rejects `scp_cert_profile` |
| `tests/test_aio_api.py` | Async mirror of `test_plus_model_read_routes_to_nsdp` |
| `tests/test_cross_backend_equivalence.py` | HTTP reader vs NSDP reader field-by-field cross-verification |
| `tests/test_http_read.py` | HTTP port/PVID reads identical to live NSDP backend output |
| `tests/cli/test_new_commands.py` | CLI `nsdp-device` subcommand |
| `tests/protocols/http/test_parse.py` | HTTP MAC parsing matches SNMP/NSDP base-MAC casing |
| `tests/protocols/http/test_endpoints.py` | HTTP endpoint spec covers "full NSDP read parity" surface for gs110emx |
| `tests/virtual/test_virtual_http_face.py` | Virtual HTTP face serves full NSDP read surface (gs110emx) |
| `tests/virtual/test_virtual_snmp_face.py` | `test_plus_model_binds_nsdp_not_snmp` — gs110emx binds NSDP not SNMP on `start()` |
| `tests/test_mcp_server.py` | MCP server tests injecting fake NSDP client / `NsdpError` |
| `tests/cli/test_resolve.py` | CLI cred resolution: `nsdp_interface` passthrough; NSDP-only switch never prompts SNMP community |
| `tests/cli/test_op_coverage.py` | Maps facade op `nsdp_device` → CLI subcommand `nsdp-device` |

---

## 10. Go porting notes, completeness checklist, trickiest traps

### 10.1 Existing Go scaffolding this slice builds on (confirmed present)

- `model/registry.go`: `BackendNSDP Backend = "nsdp"`; gs110emx/gs305ep/gs105pe
  already registered with correct `PortCount`/`PoEPortCount`/`Backends`
  (§7.3 table) — no `model` registry changes needed for these three.
- `model/errors.go`: `ErrNSDP = errors.New("nsdp error")` sentinel already
  exists (generic, matching this repo's `ErrSNMP`/`ErrHTTP` convention);
  `WriteVerificationError{Msg, Before, After any}` already exists (needed for
  §6.5's verify-after-write port).
- `virtual/state.go`: every NSDP-extra field already present (§7.1); `NsdpTlvs`/
  `ApplyNsdpWrite` methods NOT yet implemented — this slice's job.
- `virtual/server.go`: `VirtualSwitch.NsdpPort int` field already reserved
  (always 0); `Start()`'s SNMP `if` block is the exact template to copy for
  NSDP (§7.4).
- `virtual/snmpface.go`: `SnmpFace` is the exact goroutine-loop template for a
  new `NsdpFace` (§10.3).
- `switch.go`: `nsdpInterface *string` field + `WithNSDPInterface` option
  already exist ("unused until slice 05"); `httpPassword *resolveOnce`
  already documented as NSDP-shared (§8.2); `Identify()` (lines 451-472) is
  the exact bypass-dispatch template for `NsdpDevice()` (§8.3).
- `dispatch.go`/`write_dispatch.go`: `backendPreference` already includes
  `model.BackendNSDP` in SNMP→NSDP→HTTP→SSH order; `BackendReader`/
  `BackendWriter` interfaces (9 methods each) already exist and are what the
  new `nsdp.Reader`/`nsdp.Writer` must satisfy.
- `backend_snmp.go`: the exact shim-file template (§10.2) — a `backend_nsdp.go`
  follows its shape line-for-line.
- `virtual/seed.go`: `BuildState`'s switch explicitly defers gs110emx/gs305ep/
  gs105pe seeding to this slice (§7.3) — no seed functions exist yet.
- **Nothing else NSDP-shaped exists**: no `nsdp`/`protocols/nsdp` package or
  directory anywhere in the Go repo (confirmed via `find . -iname '*nsdp*'`)
  — the wire protocol/transport/reader/writer code is genuinely greenfield.

### 10.2 Root shim pattern — `backend_nsdp.go` mirrors `backend_snmp.go`

`backend_snmp.go` (repo root, `package netgearswitch`) structure: package doc
→ `init()` registering both builders → `requireSNMPCommunity` (read-side
credential gate) → `buildSNMPClient` → `buildSNMPReader` (the
`BackendBuilder`) → `requireSNMPWriteCommunity` (write-side, stricter: also
rejects `""`) → `buildSNMPWriteClient` → `buildSNMPWriter` (the
`WriteBackendBuilder`). `dispatch.go`'s own comment (lines 79-90) explicitly
anticipates: *"Slices 05-07 will add nsdp_backend.go/http_backend.go/
ssh_backend.go alongside this file, each following the same shape."*

`backend_nsdp.go` needs, in `package netgearswitch`:
```go
func init() {
    RegisterBackend(model.BackendNSDP, buildNSDPReader)
    RegisterWriteBackend(model.BackendNSDP, buildNSDPWriter)
}
```
- A credential/config gate analogous to `requireSNMPCommunity`/
  `requireSNMPWriteCommunity` — but for NSDP the READ side needs no
  credential at all (NSDP reads are unauthenticated, §8.3), only the WRITE
  side needs a password gate (mirroring §8.2's `CredentialError` message).
- `buildNSDPClient(sw *Switch) (nsdp.Client, error)` — returns `sw`'s injected
  client as-is, or lazily constructs a default `nsdp.NewUDPClient(sw.host,
  nsdp.WithInterface(sw.nsdpInterface))`-shaped one. **Must not block on
  I/O** (same contract as `buildSNMPClient` — runs under `s.mu`).
- `buildNSDPReader(sw *Switch) (BackendReader, error)` wrapping a new
  `nsdp.Reader` satisfying all 9 `BackendReader` methods (returning
  `model.ErrUnsupportedCapability`-wrapped errors for `GetMACs`/`GetLLDP`/
  `GetSensors`/`GetPoE`, per §6.4).
- `buildNSDPWriter(sw *Switch) (BackendWriter, error)` wrapping an
  `nsdp.Writer` satisfying all 9 `BackendWriter` methods (returning
  `model.ErrUnsupportedCapability` for `SetPoE`/`CyclePoE`/`ClearPoEFault`/
  `SetPortEnabled`/`CreateVlan`/`DeleteVlan`, per §6.6), resolving the shared
  password via `sw.httpPassword.resolve()` (§8.2) and gating a `nil` result
  with `model.ErrCredential`.
- This file is the only place that can reach `Switch`'s unexported fields
  (`nsdpInterface`, `httpPassword`), exactly like `backend_snmp.go` reaches
  `snmpClient`/`snmpCommunity`.

### 10.3 Virtual face — `NsdpFace` mirrors `SnmpFace`

`virtual/snmpface.go`'s `SnmpFace` shape to mirror exactly:
```go
type SnmpFace struct { view *MibView; community string; host string
    mu sync.Mutex; conn *net.UDPConn; wg sync.WaitGroup }
func NewSnmpFace(view *MibView, community, host string) *SnmpFace
func (f *SnmpFace) Start() (port int, err error)  // binds ephemeral UDP, go f.serve(conn)
func (f *SnmpFace) Stop() error                    // conn.Close() + wg.Wait(), idempotent
func (f *SnmpFace) serve(conn *net.UDPConn)         // for { conn.ReadFromUDP(...) }, exits on read error
```
`NsdpFace` equivalent:
```go
type NsdpFace struct { state *State; password string; host string
    mu sync.Mutex; conn *net.UDPConn; wg sync.WaitGroup }
func NewNsdpFace(state *State, host string) *NsdpFace
func (f *NsdpFace) Start() (port int, err error)
func (f *NsdpFace) Stop() error
func (f *NsdpFace) serve(conn *net.UDPConn)  // decode NSDPPacket, dispatch Read/Write, encode+reply
```
Password is read live from `f.state.NsdpPassword` at write-auth time (not
captured at construction — Python's `_write_response` reads
`self._state.nsdp_password` fresh every call, so a test that mutates state
mid-test sees the new password immediately; Go should match). Malformed
packet → drop-and-continue (never crash the goroutine, §7.2). Auth failure →
respond with `RESULT_BAD_PASSWORD`, no state mutation. Use plain byte-slice
`==` comparison for the password TLV match — no need for constant-time
compare (loopback test mock only, §7.2's explicit call-out).

### 10.4 Package placement decision the implementer must make

The roadmap names the target package `nsdp` (parallel to `snmp`) for
codec/parsers/auth/client/reader/writer. Recommendation matching this
repo's existing `snmp` package shape: `nsdp.Tag`, `nsdp.Op`, `nsdp.TLVEntry`,
`nsdp.Packet` (protocol/codec), `nsdp.ParseXxx` functions (parsers),
`nsdp.EncodePasswordV1` (auth), `nsdp.Client`/`nsdp.WriteClient` interfaces +
`nsdp.NewUDPClient` (transport), `nsdp.Reader`/`nsdp.NewReader`,
`nsdp.Writer`/`nsdp.NewWriter` (facade-facing) all live in a new top-level
`nsdp/` package, exactly mirroring `snmp/`'s existing file layout
(`reader.go`, `writer.go`, `writer_vlan.go`, `writer_cycle.go`, a
`gosnmp.go`-equivalent transport file). The NSDP-native **data types**
(`NsdpDevice` etc., §2) go in `model` (not `nsdp`) per §2.10's reasoning —
this mirrors Python's own split (`protocols/nsdp/types.py` holds the wire
types, but they're re-exported at package top level as the public API
surface, which in Go terms means `model`, the package every consumer already
imports).

### 10.5 Completeness checklist

- [ ] protocol.py: 32-byte header layout table, all 4 `Op` values, all 34
  `Tag` values, `TLVEntry` encode/decode incl. unknown-tag passthrough,
  `NSDPPacket` encode/decode incl. version-hardcoded-to-1 and end-marker
  handling, sequence-field 32-bit-wire/16-bit-usage distinction.
- [ ] types.py: `LinkSpeed` (7 values incl. `0xFF`→`TEN_GIGABIT` UNVERIFIED
  caveat + `from_byte` never-raises), `VLANEngine` (5 values),
  `NsdpPortStatus`, `NsdpPortStatistics`, `NsdpVlanMembership` (+ computed
  `UntaggedPorts`), `NsdpPortPvid`, `NsdpPortMirroring`, `NsdpIgmpSnooping`,
  `NsdpDevice` (20 fields) — all added to `model` package.
- [ ] parsers.py: all 11 parser functions with exact byte-size assertions and
  error text, bitmap helpers (owned locally, not shared with `snmp` unless a
  deliberate refactor), two-pass `parse_device` aggregation.
- [ ] write.py: `RESULT_SUCCESS`/`RESULT_BAD_PASSWORD`, all 7 TLV builders
  incl. dead-code `reboot_tlv`. auth.py: v1 XOR, v2 genuinely unimplemented
  (reactive-only detection via 0x0700). client.py: `NsdpError`,
  `check_result` (3-way branch), `read_interface_mac`, 4 `Protocol`
  interfaces (→ 2 Go interfaces).
- [ ] transport: ports 63321/63322 overridable, ephemeral bind, best-effort
  `SO_BINDTODEVICE`, unconditional `SO_REUSEADDR`, 2s timeout, 4096 recv buf,
  `&0xFFFF` sequence wraparound with pre-increment, client-MAC
  sysfs-read-or-raise vs dummy-MAC-only-when-neither-given distinction,
  unicast-only (no broadcast mode), op-check-before-check_result ordering,
  4 exact error-message templates.
- [ ] nsdp_read.py: per-op tag sets, `_with_model` wire necessity (not
  metadata-driven), 6 field-mapping quirks, 4 unsupported-read messages +
  constructor-time `_require_nsdp` guard.
- [ ] nsdp_write.py: verify-after-write for 3 real writes + `_guard`
  protected-port check, 6 unsupported-write messages, mgmt-IP blanket force
  gate, confirmed absence of a reboot write op (dead `reboot_tlv`).
- [ ] virtual: `NsdpTlvs`/`ApplyNsdpWrite` ported from D-VIRT §1.12/§1.13
  (cross-checked accurate against pin, docstring-vs-code STRICT-gating
  nuance called out), `NsdpFace` mirroring `SnmpFace`'s goroutine shape, 3
  Plus-model seeds transcribed (incl. gs305ep's deliberately-incomplete NSDP
  identity fields — port the gap, don't fill it), server binding into a
  dedicated `NsdpPort` field (Go already has this field reserved).
  Go must add both `NsdpTlvs`/`ApplyNsdpWrite` methods themselves — not yet
  implemented anywhere in the repo.
- [ ] facade: `backend_nsdp.go` shim (mirrors `backend_snmp.go`), shared
  HTTP/NSDP password reuse via the existing `httpPassword` `resolveOnce`
  cell, `Switch.NsdpDevice()` bypass method mirroring `Identify()`'s bypass
  shape exactly.
- [ ] All test files in §9 tabulated; Go test suite should mirror their
  intent (byte-exact fixtures, exact error-message assertions, not just
  "doesn't panic" checks).

### 10.6 Ten trickiest traps

1. **Sequence field is 32 bits on the wire but only 16 bits are ever used.**
   Decoding must round-trip the full `uint32`; the transport's own generator
   only ever produces/increments values `& 0xFFFF`. Don't conflate "the field
   Go decodes" with "the range Go's own client generates" — a Go NSDP
   *server* (virtual face) echoing back a client's sequence must preserve
   whatever 32-bit value it received, even a value with high bits set from
   a non-Python client.
2. **`0xFF` → `TEN_GIGABIT` (10000 Mbps) is explicitly ASSUMED/UNVERIFIED.**
   Don't silently upgrade this to "confirmed" in Go doc comments — carry the
   caveat forward. `from_byte`-equivalent must return `DOWN` for any
   unrecognized byte, never error/panic.
3. **`parse_port_mirroring`'s width is NOT fixed** — it's whatever remains
   after the outer TLV length minus 1 byte for the dest port. A Go port that
   hardcodes a 2-byte or 3-byte source bitmap reintroduces the exact bug the
   Python history documents fixing (gs105pe's 3-byte TLV exposed it).
4. **`parse_device`'s two-pass algorithm is not optional** — `VLAN_MEMBERS`
   TLVs can precede `PORT_COUNT` in the flat TLV list, so a single forward
   pass can misparse a VLAN's bitmap width. Go must do the same two passes
   over the same TLV slice.
5. **NSDP reboot is DEAD CODE, not a missing-but-planned feature.**
   `reboot_tlv()` exists and is unit-tested at the encoder level only; it is
   never wired to any write-facade method, and there's no reboot method on
   `NsdpWriter` at all. Do not "complete" this in the Go port by wiring
   `reboot_tlv` into `BackendWriter` — that would exceed Python parity and
   invent unverified hardware behavior. If a `Reboot` method is ever added to
   `BackendWriter`, the NSDP writer's implementation should be
   `ErrUnsupportedCapability`, matching the honesty-rules global constraint.
6. **`nsdp_tlvs`'s own docstring's first line ("MODEL/MAC/PORT_COUNT always
   included") is stale relative to the code**, which gates all three tags on
   `if tag in tags` like everything else — deliberately, per an inline
   "STRICT" comment and a test that pins the opposite of the docstring's
   claim. Port the code/bullet-list behavior (§7.1), not the docstring
   prose.
7. **`gs305ep`'s Python seed has NO NSDP identity fields set at all**
   (model_name/serial/firmware/hostname/nsdp_mac/nsdp_password/qos/
   mirroring/igmp/broadcast/loop all fall to defaults) — this is a genuine
   gap in the pinned reference, not an omission in this dossier. Port the gap
   faithfully; inventing plausible-looking values for gs305ep would silently
   diverge from a future Go↔Python fake-equivalence test (roadmap slice 10).
8. **Client MAC fallback has two different failure modes that must not be
   conflated**: `interface` given but unreadable/wrong-length → **raises**
   `NsdpError` (does NOT fall back to dummy MAC); neither `client_mac` nor
   `interface` given → dummy MAC `00:00:00:00:00:01`, no I/O attempted at
   all. A Go port that "helpfully" falls back to the dummy MAC on a read
   failure changes observable behavior (a caller who typo'd an interface
   name would silently get a fake MAC instead of an error).
9. **Op-code check must run BEFORE `check_result`, not after**, on both read
   and write — a misrouted/stale `READ_RESPONSE` with `result=0x0000` must
   never be mistaken for a successful `WRITE_RESPONSE`. This is a subtle
   ordering requirement, not just "check both eventually."
10. **CORRECTED (was wrong): the HTTP/NSDP password is TWO independent
   `resolveOnce` cells, not one.** `SyncSwitch.__init__` (lines 185-218 of
   the pin) takes genuinely separate `nsdp_password`/`nsdp_password_resolver`
   and `http_password`/`http_password_resolver` constructor parameters, each
   backed by its own `_Unset`-sentinel cell (`_resolved_nsdp_password` /
   `_resolved_http_password`) and its own resolve method. `from_config` is
   the ONLY caller that happens to feed both from the identical
   `cfg.http_password(env=_env)` spec, via two SEPARATELY-NAMED closures
   (`_resolve_nsdp_password`/`_resolve_http_password`) — and its own comment
   says this sharing is a deliberate, non-forced convenience, not an
   architectural constraint: *"the facade already accepts a distinct
   nsdp_password/nsdp_password_resolver ... if a deployment ever needs to
   split them; do NOT add a separate config key now."* Go must mirror this
   with a SEPARATE `sw.nsdpPassword` `resolveOnce` cell (plus
   `WithNSDPPassword`/`WithNSDPPasswordResolver` options), independent of
   `sw.httpPassword` — `FromConfig` wires both from the same spec (two
   independent closures, exactly like Python; yes, a `!command`-style secret
   resolver genuinely does run once per cell/once per first-use, matching
   Python's own behavior, not a bug to "fix" by sharing one cell). The
   original version of this item asserted the opposite and was wrong; do not
   trust it if referenced from an earlier draft/branch of this dossier.

---

**This dossier is self-contained**: a Go engineer should be able to implement
slice 05 (`nsdp` package + `virtual` NSDP face/seeds + `backend_nsdp.go` +
`Switch.NsdpDevice()`) from this document plus the existing Go source files
it cites, without reading the Python reference directly.
