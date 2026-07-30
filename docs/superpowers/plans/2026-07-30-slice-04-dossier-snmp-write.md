# SNMP Write Layer — Porting Dossier (Slice 04)

**Pinned Python reference:** `python-netgear-switch-library` @
`1aa1274254a233ddce0409160849bb6ce8f8b2e7` (snapshot worktree:
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274`).
**Pin guard verified:** `git -C <snapshot> rev-parse HEAD` ==
`1aa1274254a233ddce0409160849bb6ce8f8b2e7` — matches the required prefix
`1aa1274` (branch `fix/s3300-52x-live-verify`, committed 2026-07-30). This
snapshot repo is read-only; every quote below is verbatim from that state.
Where this dossier and the pinned source disagree, the source wins.

**Scope (slice 04):** SNMP write encoding (`protocols/snmp/write.py`), the
model-driven write facade (`snmp_write.py`'s `SnmpWriter`/`AsyncSnmpWriter`),
the facade-level write plumbing in `sync_api.py` (dispatch loop, protected-port
guards, write-community resolution), and what the Go `virtual` fake already
covers vs what remains. NSDP/HTTP/CLI writers are out of scope (slices 05-07);
`upload_certificate*` are out of scope (HTTP/FASTPATH, slices 06-07).

**Audience:** Go engineers porting the SNMP write path 1:1 without reading the
Python source themselves.

---

## 1. `src/netgear_switch/protocols/snmp/write.py` — pure encoding, no I/O

Already partially ported: `snmp.SetVarbind`/`snmp.NewSetVarbind`
(`snmp/client.go`) and `virtual.EncodePortBitmap`/`snmp.DecodePortBitmap`
already exist in Go. This section documents every function's EXACT semantics
and calls out precisely what's missing.

### 1.1 `SET_TYPE_LETTERS` / `SetVarbind` — ALREADY PORTED, note only

```python
SET_TYPE_LETTERS: frozenset[str] = frozenset({"i", "u", "s", "x", "a"})

@dataclass(frozen=True)
class SetVarbind:
    oid: str
    value: int | str | bytes
    type_letter: str
    def __post_init__(self) -> None:
        if self.type_letter not in SET_TYPE_LETTERS:
            raise ValueError(
                f"unknown SET type letter {self.type_letter!r}; "
                f"expected one of {sorted(SET_TYPE_LETTERS)}"
            )
```

Go equivalent already exists verbatim in `snmp/client.go`:
`SetVarbind{OID, Value, TypeLetter}` + `NewSetVarbind(oid, value, typeLetter)`
returning a plain (non-`ErrSNMP`-wrapped) `error` for an invalid letter —
matches Python's plain `ValueError` (not `SnmpError`). **Nothing to do here.**
One wording nit: Python's message sorts the letters (`['a', 'i', 's', 'u',
'x']`); Go's message is `"expected one of [a i s u x]"` — already
alphabetically sorted, so the two read the same modulo formatting. No action
needed.

### 1.2 `encode_port_bitmap(ports, width_bytes=8) -> bytes` — PARTIALLY PORTED (wrong package)

```python
def encode_port_bitmap(ports: Iterable[int], width_bytes: int = 8) -> bytes:
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return bytes(data)
```

Bit 7 (MSB) of byte 0 = port 1; the buffer grows past `width_bytes` if a port
number needs it (never pre-sized to the actual port count) — this is the
inverse of `parse.decode_port_bitmap`/`snmp.DecodePortBitmap`.

**Go status: a DUPLICATE implementation already exists, but in the WRONG
package for slice-04 purposes.** `virtual/state_oidmap.go:81`
(`func EncodePortBitmap(ports map[int]bool, widthBytes int) []byte`) has the
identical bit-packing logic, but lives in `virtual`, keyed by `map[int]bool`
(the virtual package's own port-set representation) rather than the `snmp`
package's `[]int` sorted-slice convention `DecodePortBitmap` returns. In
Python, `virtual/state.py`'s `encode_port_bitmap` explicitly **delegates to**
`protocols/snmp/write.encode_port_bitmap` (see D-VIRT §1.1: "Delegates to
`protocols/snmp/write.encode_port_bitmap` (bytes) and decodes latin-1 to `str`
for callers") — i.e. Python has ONE implementation, reused by both the write
layer and the virtual mock. **Slice 04 should add `snmp.EncodePortBitmap`
(the canonical inverse of `snmp.DecodePortBitmap`, taking `[]int` or a
port-set type consistent with `DecodePortBitmap`'s return type) and decide
whether `virtual.EncodePortBitmap` becomes a thin adapter over it** (converts
`map[int]bool` → `[]int` and calls `snmp.EncodePortBitmap`) to eliminate the
duplicate bit-packing logic, matching the Python architecture. This is a
judgment call flagged in trap #1 below — do not silently leave two
independently-maintained implementations of the same MSB-first packing rule.

### 1.3 `set_port_bit(current, port, present, *, width_bytes=None) -> bytes` — MISSING in Go

```python
def set_port_bit(
    current: bytes | str, port: int, present: bool, *, width_bytes: int | None = None
) -> bytes:
    if isinstance(current, bytes):
        current_width = len(current)
    else:
        current_width = len(current.encode("latin-1"))
    ports = set(decode_port_bitmap(current))
    if present:
        ports.add(port)
    else:
        ports.discard(port)
    target_width = max(8, current_width, width_bytes or 0)
    return encode_port_bitmap(ports, width_bytes=target_width)
```

Read-modify-write ONE port's bit in a VLAN bitmap; every other port's bit is
preserved untouched. **Width rule (exact, pin precisely — this is the
Fix-2/review-item-2 regression the Python test suite guards)**: the result
width is `max(8, len(current_as_bytes), width_bytes or 0)` — i.e.:
- Never narrower than 8 bytes (the Q-BRIDGE MIB's own default PortList
  width).
- Never narrower than the INPUT bitmap's own width (so a device that already
  returned a wider-than-8-byte bitmap for a >64-port switch doesn't get
  silently truncated by a RMW cycle).
- At least as wide as the caller-supplied `width_bytes` (typically
  `vlan_bitmap_width(model)`), but a wider input or wider 8-byte default wins
  if either is larger — `width_bytes` only ever WIDENS, never narrows.

`current` accepts BOTH `bytes` and `str` (latin-1) — a transport may hand
back either representation (see slice-02 dossier §5's normalized-value
contract); `set_port_bit` must decode/re-encode losslessly either way.
**No Go equivalent exists yet — this is new code for slice 04.**

### 1.4 `membership_bitmaps(*, mode, port, egress, untagged, width_bytes=None) -> (bytes, bytes)` — MISSING in Go

```python
def membership_bitmaps(
    *, mode: VlanMode, port: int, egress: bytes | str, untagged: bytes | str,
    width_bytes: int | None = None,
) -> tuple[bytes, bytes]:
    in_egress = mode in (VlanMode.UNTAGGED, VlanMode.TAGGED)
    in_untagged = mode is VlanMode.UNTAGGED
    return (
        set_port_bit(egress, port, in_egress, width_bytes=width_bytes),
        set_port_bit(untagged, port, in_untagged, width_bytes=width_bytes),
    )
```

Truth table (pin exactly):

| `mode` | egress bit | untagged bit |
|---|---|---|
| `UNTAGGED` | on | on |
| `TAGGED` | on | off |
| `EXCLUDED` | off | off |

Both bitmaps are computed via TWO independent `set_port_bit` calls (each its
own RMW against the CURRENT egress/untagged bitmap respectively) — `port`'s
bit is the only one that can change in either column; every other port's
membership is preserved. `width_bytes` forwards to BOTH calls identically.
**No Go equivalent exists yet.**

### 1.5 `vlan_bitmap_width(model) -> int` — PARTIALLY PORTED (unexported, wrong package)

```python
def vlan_bitmap_width(model: SwitchModel) -> int:
    return max(8, (model.port_count + 7) // 8)
```

Go status: `virtual/state_oidmap.go:66` has an **unexported**
`vlanBitmapWidth(m *model.SwitchModel) int` with the identical formula, used
only by `virtual`'s own `OIDMap()` projection. **Slice 04 needs an EXPORTED
`snmp.VlanBitmapWidth(m *model.SwitchModel) int`** (the write layer's
`SetVlanMembership`, ported below, needs to call it directly — it cannot
reach into the `virtual` package, and `virtual` importing `snmp` for this one
function, rather than the reverse, matches the existing dependency direction:
`virtual/state_oidmap.go` already imports `snmp` for `snmp.DecodePortBitmap`
and `snmp.Dot1qVlanStaticEgress` etc.). Once `snmp.VlanBitmapWidth` exists,
`virtual`'s private copy should be deleted and replaced with a call to it
(same duplication concern as §1.2).

### 1.6 Go reference: what already exists vs what's missing (summary table)

| Python construct | Go status | Location |
|---|---|---|
| `SetVarbind` + `SET_TYPE_LETTERS` | **DONE** | `snmp/client.go` (`SetVarbind`, `NewSetVarbind`) |
| `encode_port_bitmap` | **DUPLICATED, wrong package** | `virtual/state_oidmap.go:81` (`EncodePortBitmap`, keyed by `map[int]bool`) — needs an `snmp.EncodePortBitmap` counterpart |
| `set_port_bit` | **MISSING** | new: `snmp/write.go` |
| `membership_bitmaps` | **MISSING** | new: `snmp/write.go` |
| `vlan_bitmap_width` | **DUPLICATED, unexported, wrong visibility** | `virtual/state_oidmap.go:66` (`vlanBitmapWidth`, lowercase) — needs an exported `snmp.VlanBitmapWidth` |
| `snmp.DecodePortBitmap` | **DONE** | `snmp/parse.go:389` |

**Slice 04 action: create `snmp/write.go`** with `EncodePortBitmap`,
`SetPortBit`, `MembershipBitmaps`, `VlanBitmapWidth` — porting §1.2-§1.5
above — then, as a follow-up cleanup (not strictly blocking, but flagged so it
isn't silently skipped), make `virtual`'s `EncodePortBitmap`/`vlanBitmapWidth`
thin wrappers over the new `snmp` functions instead of independent
re-implementations.

---

## 2. `src/netgear_switch/snmp_write.py` — `SnmpWriter` (+ `AsyncSnmpWriter` deltas)

No Go equivalent exists yet (`snmp/writer.go` does not exist). Every method
below must be ported into a new `snmp.Writer` type. `model.WriteVerificationError`
and `model.ErrProtectedPort` already exist as the target error types (see
`model/errors.go`); nothing else in the error hierarchy needs to be added.

### 2.1 Module-level helpers

```python
def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")

def _poe_admin_oid(port: int) -> str:
    return f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"
```

`_require_snmp` is called ONCE, in the constructor, before anything else —
mirrors `snmp.NewReader`'s own gate (already ported: "returns an error
wrapping model.ErrUnsupportedCapability BEFORE any I/O"). Go's
`snmp.NewWriter(client, model, opts...)` should perform the identical gate
(`if !m.HasBackend(model.BackendSNMP) { return nil, fmt.Errorf(...: %w,
model.ErrUnsupportedCapability) }`) — no per-method re-check.

### 2.2 `PoeCycleTimeouts` (dataclass, defaults)

```python
@dataclass(frozen=True)
class PoeCycleTimeouts:
    off_timeout: float = 30.0
    on_timeout: float = 60.0
    poll_interval: float = 2.0

_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()
```

Go: a plain struct `PoeCycleTimeouts{OffTimeout, OnTimeout, PollInterval
time.Duration}` with a `DefaultPoeCycleTimeouts` var/func
(`30s`/`60s`/`2s`) — **use `time.Duration`, not `float64` seconds**, per Go
idiom; every call site (§2.5-2.7) converts consistently. This is a value
type passed by callers wanting fast test timeouts (tests use
`off_timeout=1, on_timeout=1, poll_interval=0` — i.e. `1*time.Second,
1*time.Second, 0`).

### 2.3 `_poe_is_off` / `_poe_recovered` — poll predicates (exact)

```python
def _poe_is_off(status: PoEStatus | None, port_up: bool) -> bool:
    return (
        status is not None
        and status.detect in (PoEDetect.DISABLED, PoEDetect.SEARCHING)
        and not port_up
    )

def _poe_recovered(status: PoEStatus | None) -> bool:
    """True once detect has left FAULT and settled to delivering/searching."""
    return status is not None and status.detect in (
        PoEDetect.DELIVERING, PoEDetect.SEARCHING,
    )
```

**`_poe_is_off` requires THREE conditions simultaneously**: status present,
detect ∈ {DISABLED, SEARCHING} (i.e. NOT delivering, NOT fault — "unused" per
the coherence rule in the virtual dossier: admin-off → `detect=1`
(unused/disabled)), AND the port's link is actually down. `_poe_recovered` is
looser: detect has left FAULT and reached EITHER delivering OR searching
(used by `clear_poe_fault`, which doesn't require the port to actually be
delivering power — just no longer faulted). `cycle_poe`'s own recovery
predicate (§2.6) is different again: `bool(st and st.delivering)` — STRICTLY
delivering, not "recovered or delivering". **Three distinct predicates, do
not conflate them:**

| Predicate | Used by | Condition |
|---|---|---|
| `_poe_is_off` | both (phase 1 of `_poe_rearm`) | detect ∈ {DISABLED, SEARCHING} AND port link down |
| `cycle_poe`'s phase-2 predicate | `cycle_poe` only | `status.Delivering()` (detect == DELIVERING) — strict |
| `_poe_recovered` | `clear_poe_fault` only | detect ∈ {DELIVERING, SEARCHING} (i.e. NOT fault, NOT disabled) |

### 2.4 `SnmpWriter.__init__` + `_guard` + status-lookup helpers

```python
def __init__(self, client, model, *, protected_ports=frozenset()):
    _require_snmp(model)
    self.client = client
    self.model = model
    self.protected_ports = protected_ports
    self._reader = SnmpReader(client, model)

def _guard(self, port, force):
    if port in self.protected_ports and not force:
        raise ProtectedPortError(f"port {port} is protected; pass force=True to override")

def _poe_status(self, port): return next((p for p in self._reader.get_poe() if p.port == port), None)
def _port_status(self, port): return next((p for p in self._reader.get_ports() if p.port == port), None)
def _vlan(self, vlan): return next((v for v in self._reader.get_vlans() if v.vlan_id == vlan), None)
def _port_up(self, port): status = self._port_status(port); return bool(status and status.link_up)
```

The writer HOLDS its own internal `SnmpReader` (`self._reader`) — every
verify-after-write re-read goes through this reader's normal `get_*` methods,
NOT a raw client `.get`/`.walk` call. Go: `snmp.Writer` embeds (or holds a
pointer to) a `*snmp.Reader` built from the same `client`/`model` at
construction, exactly mirroring this. `_guard` is the single protected-port
gate every disruptive op calls; port it as an unexported `guard(port int,
force bool) error` method returning `fmt.Errorf("port %d is protected; pass
force=True to override: %w", port, model.ErrProtectedPort)`.

**Exact error message strings to preserve verbatim (Go: `%w`-wrap `model.ErrProtectedPort`/`model.ErrUnsupportedCapability`, keep the English text identical modulo Go's lack of `!r`):**
- `f"port {port} is protected; pass force=True to override"` (generic per-port guard)
- `f"VLAN {vlan} includes protected port(s) {sorted(clash)}; pass force=True to delete it anyway"` (VLAN-delete guard, §2.9 and facade §3.3)
- `f"model {model.key!r} has no SNMP backend"` (constructor gate)

### 2.5 `set_poe(port, on, *, force=False)` — full semantics

```python
def set_poe(self, port, on, *, force=False):
    if not on:
        self._guard(port, force)  # turning PoE off is disruptive
    before = self._poe_status(port)
    self.client.set(SetVarbind(_poe_admin_oid(port), 1 if on else 2, "i"))
    after = self._poe_status(port)
    if after is None or after.admin_enabled != on:
        raise WriteVerificationError(
            f"PoE admin for port {port} did not read back as {on}",
            before=before, after=after,
        )
```

**Guard fires ONLY when turning OFF** (`if not on`) — turning PoE ON is
NEVER guarded, even on a protected port (enabling power is not disruptive by
this library's model). Single-varbind SET (`i` type letter, `1`=on/`2`=off).
Verify: re-read via `_poe_status`; fail if the port vanished from the walk
OR `admin_enabled` doesn't match the requested `on`. Exact error message:
`f"PoE admin for port {port} did not read back as {on}"` (Python's `{on}`
renders as `True`/`False`; Go: `%t` or `%v` on the bool — match the reader's
existing convention, likely `%v`).

### 2.6 `_poe_rearm` — the shared off→on re-arm primitive (full semantics, LOAD-BEARING)

```python
def _poe_rearm(self, port, *, timeouts, sleep, clock, on_recovered, on_timeout_message):
    before = self._poe_status(port)
    # Phase 1: off, poll until unused/searching + link down.
    self.client.set(SetVarbind(_poe_admin_oid(port), 2, "i"))
    deadline = clock() + timeouts.off_timeout
    while not _poe_is_off(self._poe_status(port), self._port_up(port)):
        if clock() >= deadline:
            raise WriteVerificationError(
                f"PoE port {port} did not turn off within {timeouts.off_timeout}s",
                before=before, after=self._poe_status(port),
            )
        sleep(timeouts.poll_interval)
    # Phase 2: on, poll until the caller's recovery predicate is met.
    self.client.set(SetVarbind(_poe_admin_oid(port), 1, "i"))
    deadline = clock() + timeouts.on_timeout
    while not on_recovered(self._poe_status(port)):
        if clock() >= deadline:
            raise WriteVerificationError(
                on_timeout_message.format(timeout=timeouts.on_timeout),
                before=before, after=self._poe_status(port),
            )
        sleep(timeouts.poll_interval)
```

**Absolutely critical (this IS the single trickiest piece of the whole
slice, called out 3× in the Python source's own comments):** the off→on
re-arm is **TWO SEPARATE single-varbind `client.set()` calls**, each polled
to completion BEFORE the next SET is issued — **NEVER one `set_many` PDU
carrying both varbinds for the same (duplicate) OID.** Quoted rationale
(verbatim, load-bearing): "Per-varbind ordering within one PDU carrying the
same OID twice is undefined on real hardware (RFC 3416); a real agent may
reject it or collapse it (last-wins), silently defeating the off->on
re-arm." This is pinned by `test_clear_poe_fault_recovers_detect` asserting
`[len(c) for c in poe_calls] == [1, 1]` (two separate 1-varbind calls, never
one 2-varbind call) — **a Go implementation that "optimizes" this into a
single `SetMany` call is a correctness regression, not a simplification.**

Polling shape: `deadline = clock() + timeout`; loop `while not
<predicate>(...)`, checking `clock() >= deadline` FIRST inside the loop body
(i.e. the predicate is checked once before ever sleeping — a
already-satisfied predicate on the very first check returns immediately with
zero sleeps), calling `sleep(poll_interval)` only when neither satisfied nor
timed out. **`clock` and `sleep` are BOTH constructor/call-site-injectable**
(`Callable[[float], None]` / `Callable[[], float]`, defaulting to
`time.sleep`/`time.monotonic` in production) — this is what lets the test
suite drive the whole state machine with zero real wall-clock delay via
`_incrementing_clock()` (jumps the fake clock forward on every call,
guaranteeing the timeout branch fires deterministically) and `sleep=lambda
_: None`. **Go MUST expose the same two injection points** — see §6's
"injectable clock shape" for the exact recommended Go signature.

Both phases re-read `self._poe_status(port)` fresh on every poll iteration
(never cached) via the writer's internal reader — so a mid-poll state change
(as effected by the real virtual-fake's own `ApplyWrite` coherence rules) is
observed on the very next iteration.

### 2.7 `cycle_poe` / `clear_poe_fault` — the two `_poe_rearm` callers

```python
def cycle_poe(self, port, *, force=False, timeouts=_DEFAULT_POE_TIMEOUTS,
              sleep=time.sleep, clock=time.monotonic):
    self._guard(port, force)
    self._poe_rearm(port, timeouts=timeouts, sleep=sleep, clock=clock,
        on_recovered=lambda st: bool(st and st.delivering),
        on_timeout_message=f"PoE port {port} did not return to delivering within {{timeout}}s")

def clear_poe_fault(self, port, *, force=False, timeouts=_DEFAULT_POE_TIMEOUTS,
                     sleep=time.sleep, clock=time.monotonic):
    self._guard(port, force)
    self._poe_rearm(port, timeouts=timeouts, sleep=sleep, clock=clock,
        on_recovered=_poe_recovered,
        on_timeout_message=f"PoE port {port} still in FAULT after clear within {{timeout}}s")
```

Both guard UNCONDITIONALLY (cycling/clearing a protected port always needs
`force=True` — unlike `set_poe`, which only guards the OFF direction).
`cycle_poe`'s success predicate is stricter (must reach DELIVERING);
`clear_poe_fault`'s is looser (must merely LEAVE fault — delivering OR
searching is fine, since a non-PoE-negotiating device that's simply
"searching" again is no longer faulted). Exact timeout message templates
(note the Python `{{timeout}}` double-brace escapes to a literal `{timeout}`
placeholder later filled by `.format(timeout=...)`):
- cycle_poe on-timeout: `f"PoE port {port} did not return to delivering within {timeout}s"`
- clear_poe_fault on-timeout: `f"PoE port {port} still in FAULT after clear within {timeout}s"`
- shared off-timeout (from `_poe_rearm` itself): `f"PoE port {port} did not turn off within {timeouts.off_timeout}s"`

### 2.8 `set_port_enabled(port, enabled, *, force=False)`

```python
def set_port_enabled(self, port, enabled, *, force=False):
    if not enabled:
        self._guard(port, force)  # disabling a port is disruptive
    before = self._port_status(port)
    self.client.set(SetVarbind(f"{oids.IF_ADMIN_STATUS}.{port}", 1 if enabled else 2, "i"))
    after = self._port_status(port)
    if after is None or after.admin_enabled != enabled:
        raise WriteVerificationError(
            f"admin state for port {port} did not read back as {enabled}",
            before=before, after=after,
        )
```

Structurally identical to `set_poe` (guard only on the disruptive direction,
one INTEGER SET, verify `admin_enabled`). Exact error:
`f"admin state for port {port} did not read back as {enabled}"`.

### 2.9 `set_pvid(port, vlan, *, force=False)`

```python
def set_pvid(self, port, vlan, *, force=False):
    self._guard(port, force)  # changing a port's PVID is disruptive
    before = self._reader.get_pvids()
    self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
    after = self._reader.get_pvids()
    if (port, vlan) not in after:
        raise WriteVerificationError(
            f"PVID for port {port} did not read back as {vlan}",
            before=before, after=after,
        )
```

Guard is UNCONDITIONAL (any PVID change is disruptive, not gated on
direction). `after` is the FULL `list[tuple[int,int]]` (all ports' PVIDs);
verify checks the exact `(port, vlan)` pair is a member — Go: iterate
`[]model.Pvid` for a `Pvid{Port: port, Vlan: vlan}` match (no `Contains`
helper exists yet on `[]model.Pvid`; write a small inline loop or add one).
Type letter is `"u"` (Gauge32/unsigned), not `"i"` — `dot1qPvid` is a
Gauge32 column.

### 2.10 `set_vlan_membership(vlan, port, mode, *, force=False)` — the richest write op

```python
def set_vlan_membership(self, vlan, port, mode, *, force=False):
    self._guard(port, force)
    before = self._vlan(vlan)
    if before is None:
        raise SnmpError(f"VLAN {vlan} does not exist")
    new_egress, new_untagged = membership_bitmaps(
        mode=mode, port=port,
        egress=encode_port_bitmap(before.member_ports),
        untagged=encode_port_bitmap(before.untagged_ports),
        width_bytes=vlan_bitmap_width(self.model),
    )
    self.client.set_many([
        SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
        SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"),
    ])
    after = self._vlan(vlan)
    want_egress = frozenset(decode_port_bitmap(new_egress))
    want_untagged = frozenset(decode_port_bitmap(new_untagged))
    if after is None:
        raise WriteVerificationError(
            f"VLAN {vlan} disappeared while setting membership for port {port}",
            before=before, after=after)
    if after.member_ports != want_egress:
        raise WriteVerificationError(
            f"VLAN {vlan} egress (member_ports) for port {port} did not "
            f"verify: wanted {sorted(want_egress)}, got {sorted(after.member_ports)}",
            before=before, after=after)
    if after.untagged_ports != want_untagged:
        raise WriteVerificationError(
            f"VLAN {vlan} untagged_ports for port {port} did not verify: "
            f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
            before=before, after=after)
```

Exact flow, pin every step:
1. **Guard first** — unconditional per-port guard (any membership change is
   disruptive to that port), BEFORE the existence check.
2. **Existence precondition**: `before is None` → raise `SnmpError(f"VLAN
   {vlan} does not exist")` — **this is a PRECONDITION failure, NOT a
   `WriteVerificationError`** (review item 9, called out explicitly in both
   sync and async code and both delete_vlan too, §2.11). No SET is EVER
   issued when the VLAN doesn't exist — `client.sets == []` is asserted by
   the test suite. Go: this must be `model.ErrSNMP`-wrapped (`snmp.Error`
   equivalent), NOT `model.WriteVerificationError`.
3. **RMW inputs**: `encode_port_bitmap(before.member_ports)` /
   `encode_port_bitmap(before.untagged_ports)` — re-encodes the CURRENTLY
   READ membership (from the very same `before` read used for the existence
   check — no second read), so the RMW is against a single consistent
   snapshot.
4. **`width_bytes=vlan_bitmap_width(self.model)`** — always model-derived,
   never the input bitmap's own width alone (though `set_port_bit`'s own
   `max(8, current_width, width_bytes)` rule means the wider of the two
   still wins if the model happens to be narrower than what was actually
   read).
5. **ONE `set_many` call, TWO varbinds** (egress + untagged for the SAME
   vlan), type letter `"x"` (hex/octet string) for both — this is the
   atomic-multi-varbind-SET use case the virtual fake's `handleSet` already
   exercises (§4 below).
6. **Verify BOTH columns** — egress (`member_ports`) AND untagged
   (`untagged_ports`) independently, each against the EXACT bitmap that was
   just SET (re-decoded, not re-derived from `mode`) — this catches a device
   that silently drops ONE of the two SETs (review item 1; pinned by
   `test_set_vlan_membership_catches_dropped_untagged_write`, whose fake
   client applies the egress SET but ignores the untagged one).
7. **`after is None`** (VLAN vanished entirely between the SET and the
   re-read) is its OWN branch, checked BEFORE the two per-column checks —
   exact message: `f"VLAN {vlan} disappeared while setting membership for
   port {port}"`.
8. Exact wording of the two per-column mismatch messages must be preserved,
   including `sorted(...)` rendering of the port sets in the message text
   (Go: `[]int` is already sorted per this codebase's `VLANInfo` convention,
   so no extra sort call is needed at the message-formatting site — just
   format the slice directly).

**Go type-shape note**: Python's `VLANInfo.member_ports`/`untagged_ports` are
`frozenset[int]`; Go's `model.VLANInfo.MemberPorts`/`UntaggedPorts` are
`[]int` (sorted ascending, canonical form per `model/types.go`'s doc
comment). The equality checks (`after.member_ports != want_egress`) become
`!slices.Equal(sortedInts(after.MemberPorts), sortedInts(wantEgress))` in
Go — since `snmp.DecodePortBitmap` already returns a sorted `[]int` (per
slice-02 dossier §7: "`decode_port_bitmap` returns sorted `[]int`"), a direct
`slices.Equal` on two already-sorted slices suffices, no set conversion
needed.

### 2.11 `create_vlan(vlan, name, *, force=False)`

```python
def create_vlan(self, vlan, name, *, force=False):
    # Creating an EMPTY VLAN adds no port membership, so it is non-disruptive
    # and does NOT require force. force exists only for signature symmetry
    # with delete_vlan (review item 3).
    before = self._vlan(vlan)
    self.client.set_many([
        SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}", oids.ROW_STATUS_CREATE_AND_GO, "i"),
        SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vlan}", name, "s"),
    ])
    after = self._vlan(vlan)
    if after is None or (after.name or "") != name:
        raise WriteVerificationError(
            f"VLAN {vlan} was not created with name {name!r}",
            before=before, after=after)
```

**`create_vlan` NEVER guards on protected ports** — an empty VLAN has no
member ports by construction, so `force` exists purely for API symmetry with
`delete_vlan` and is otherwise UNUSED inside this method body (it's still a
parameter for signature consistency, but no `self._guard(...)` call
anywhere). One `set_many` PDU: RowStatus `createAndGo` (int 4, type `"i"`)
+ Name (type `"s"`, plain string — NOT `"x"` like the VLAN-membership
bitmaps). Verify: VLAN exists AND `(after.name or "")` equals the requested
name exactly (Python's `after.name or ""` treats a `None` name the same as
empty string for the comparison — Go: `after.Name` is `*string`; compare
`derefOrEmpty(after.Name) == name`).

### 2.12 `delete_vlan(vlan, *, force=False)`

```python
def delete_vlan(self, vlan, *, force=False):
    before = self._vlan(vlan)
    if before is None:
        raise SnmpError(f"VLAN {vlan} does not exist")
    if not force:
        clash = before.member_ports & self.protected_ports
        if clash:
            raise ProtectedPortError(
                f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                f"pass force=True to delete it anyway")
    self.client.set(SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}", oids.ROW_STATUS_DESTROY, "i"))
    after = self._vlan(vlan)
    if after is not None:
        raise WriteVerificationError(f"VLAN {vlan} still exists after destroy", before=before, after=after)
```

**This is the ONLY writer method whose protected-port guard is a
SET-INTERSECTION check (`before.member_ports & self.protected_ports`), not a
single-port `self._guard(port, force)` call** — deleting a VLAN can strip
membership from MULTIPLE ports at once, so the guard must check ALL of the
VLAN's current members against the protected set, not just one port. Exact
message includes the SORTED clash set: `f"VLAN {vlan} includes protected
port(s) {sorted(clash)}; pass force=True to delete it anyway"` — this EXACT
string (module-level, not per-writer) is duplicated verbatim at the
facade layer too (§3.3's `_guard_vlan_delete_members`) — **both copies must
stay byte-identical**, since either one may fire depending on which backend
serves the delete. Existence precondition (before any SET) mirrors
`set_vlan_membership`'s: `SnmpError`, not `WriteVerificationError`, and no
SET issued (`client.sets == []`). Single-varbind SET: RowStatus `destroy`
(int 6, type `"i"`). Verify: after MUST be `None` (VLAN gone); if it still
exists, `WriteVerificationError("VLAN {vlan} still exists after destroy")`.

### 2.13 `set_mgmt_ip(address, netmask, gateway, *, force=False)`

```python
def set_mgmt_ip(self, address, netmask, gateway, *, force=False):
    if not force:
        raise ProtectedPortError(
            "set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; "
            "pass force=True to proceed")
    vo = oids.vendor_oids(self.model)
    before = self._reader.get_mgmt_ip()
    self.client.set_many([
        SetVarbind(vo.mgmt_write_addr_unverified, address, "a"),
        SetVarbind(vo.mgmt_write_netmask_unverified, netmask, "a"),
        SetVarbind(vo.mgmt_write_gateway_unverified, gateway, "a"),
    ])
    after = self._reader.get_mgmt_ip()
    for field, want, got in (
        ("address", address, after.address), ("netmask", netmask, after.netmask),
        ("gateway", gateway, after.gateway),
    ):
        if got != want:
            raise WriteVerificationError(
                f"management {field} did not read back as {want!r} (got {got!r})",
                before=before, after=after)
```

**Highest-strand-risk op in the whole write surface — force-gated
UNCONDITIONALLY** (not "unless a specific port is protected": `force=False`
ALWAYS raises, regardless of `protected_ports`, since a mgmt-IP write can
strand the ENTIRE switch, not just one port). Exact refusal message (uses
`ProtectedPortError`, reusing that error type even though no specific "port"
is involved — a deliberate, slightly odd type choice worth flagging so a Go
port doesn't invent a different error type for it):
`"set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; pass
force=True to proceed"`. `vo = oids.vendor_oids(self.model)` — raises
`UnsupportedCapabilityError` for a no-vendor-subtree model (gs728tpp)
BEFORE any read/write, propagating uncaught (not wrapped further). One
`set_many`, THREE `"a"` (IpAddress) varbinds. **Verify ALL THREE fields
independently, naming whichever diverged** (review item 2 — catches a
device that silently drops just the gateway write, pinned by
`test_set_mgmt_ip_verifies_gateway_not_just_address`). Note DHCP-mode
switching is explicitly NOT offered by this method — "even its read OID is
unverified; do not fabricate it" — the Go port must not add a DHCP toggle
here either.

### 2.14 `AsyncSnmpWriter` — deltas from `SnmpWriter`

**None, semantically.** Every method above has a byte-identical `async`
twin (`await self.client.set(...)`, `await self._reader.get_poe()`, etc.);
the Go port has no async facade at all (per D-FAC's precedent), so
`snmp.Writer`'s single (ctx-based) implementation covers both — there is
nothing here that differs from what's already documented above. `sleep`'s
injected type differs only in Python (`Callable[[float], Awaitable[None]]`
for async vs `Callable[[float], None]` for sync); Go's single `ctx
context.Context`-aware writer should accept `sleep func(ctx context.Context,
d time.Duration) error` (respects cancellation — see §6).

---

## 3. Facade write plumbing (`sync_api.py`)

### 3.1 `_write(op)` — the write dispatch loop (mirrors `_read` exactly, minus a return value)

```python
def _write(self, op: Callable[[SnmpWriter | NsdpWriter | HttpWriter], None]) -> None:
    last: UnsupportedCapabilityError | None = None
    for backend in _BACKEND_PREFERENCE:
        if backend not in self.model.backends:
            continue
        try:
            writer = self._writer_for(backend)
        except UnsupportedCapabilityError as exc:
            last = exc
            continue
        try:
            op(writer)
            return
        except UnsupportedCapabilityError as exc:
            last = exc
    if last is not None:
        raise last
    raise UnsupportedCapabilityError(
        f"model {self.model.key!r} has no backend supporting this operation")
```

**Identical structure to `_read` (D-FAC §2.7)**, with exactly one difference:
`op(writer); return` (writes return `None`, so the loop returns immediately
on success) vs `_read`'s `return op(reader)` (which returns the read
result). All SIX ordering rules from D-FAC §2.7 apply verbatim: fixed
`_BACKEND_PREFERENCE` order; silent skip for a backend not in
`model.backends`; writer-construction `UnsupportedCapabilityError` recorded
as `last`, loop continues; the op itself raising `UnsupportedCapabilityError`
recorded as `last`, loop continues; ANY other exception (notably
`CredentialError`) propagates uncaught immediately; exhausted loop re-raises
the LAST recorded error (least-preferred backend attempted), or a fresh
generic error if no backend even applied. **Go: this is `writeVia`, the
direct write-side twin of the already-implemented `readVia` in
`dispatch.go`** — same control flow, `op func(BackendWriter) error` instead
of `func(BackendReader) error`, no captured return value.

### 3.2 `_writer_for(backend)` (D-FAC §2.6, reproduced here since it's the
write-side analogue `writeVia`/`writerFor` must mirror)

Already fully documented in D-FAC §2.6 (facade dossier) — key points
relevant to slice 04's SNMP-only Go port:
```python
if backend is Backend.SNMP:
    client = self._snmp_write_client
    if client is None:
        client = build_sync_snmp_write_client(self.host, self._resolve_write_community())
    writer = SnmpWriter(client, self.model, protected_ports=self.protected_ports)
```
An injected write client is used as-is (bypassing community resolution
entirely, exactly like the read side); otherwise
`build_sync_snmp_write_client` is called with the LAZILY-resolved write
community (§3.3). The writer is cached in `_writer_cache` on SUCCESS ONLY
(a gate failure — e.g. `CredentialError` from an unresolvable write
community — is never cached, mirroring the reader-cache trap already noted
in D-FAC trap #3, though here a failure is NOT `UnsupportedCapabilityError`
so it wouldn't be caught/cached by `_write`'s own try/except either way — it
propagates straight out of `_writer_for` and out of `_write`).

### 3.3 `delete_vlan`'s facade-level guard — `_guard_vlan_delete_members` (full method, ALREADY documented in D-FAC §2.17, reproduced for this dossier's completeness)

```python
def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
    self._guard_vlan_delete_members(vlan, force=force)
    self._write(lambda w: w.delete_vlan(vlan, force=force))

def _guard_vlan_delete_members(self, vlan: int, *, force: bool) -> None:
    if force:
        return
    try:
        vlans = self._read(lambda r: r.get_vlans())
    except UnsupportedCapabilityError:
        return
    for v in vlans:
        if v.vlan_id == vlan:
            clash = v.member_ports & self.protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    f"pass force=True to delete it anyway")
            return
```

**This guard runs BEFORE `_write` is even called** — i.e. it does a full
`_read` dispatch (through the SAME backend-preference machinery, SNMP → NSDP
→ HTTP → SSH) to fetch `get_vlans()`, checks the target VLAN's
`member_ports` against `protected_ports`, and raises `ProtectedPortError`
using the EXACT SAME message text as `SnmpWriter.delete_vlan`'s own internal
guard (§2.12) — this is DELIBERATE duplication (rationale quoted in D-FAC
§2.17: "mirroring `SnmpWriter.delete_vlan`'s own protected-port check, so
EVERY backend gets the same safety rail regardless of which one actually
ends up serving the delete" — since e.g. `HttpWriter.delete_vlan` does NOT
guard member ports itself). **Degrades SILENTLY (not raise) if NO backend
can even read VLANs**: `except UnsupportedCapabilityError: return` — an
inability to check is NOT treated as a reason to block the delete. For
slice 04's SNMP-only Go port this facade guard is somewhat redundant with
`SnmpWriter.delete_vlan`'s own internal guard (§2.12) whenever SNMP ends up
serving the delete — but it is NOT redundant in general (it's the ONLY
thing standing between `force=False` and a protected-port VLAN strip on a
future NSDP/HTTP-only model, per D-FAC §2.17) and must still be ported now,
at the facade layer, exactly as Python has it — do not defer it to
slices 05/06 just because SNMP alone doesn't strictly need it today.

### 3.4 Write-community resolution — asymmetric gate (ALREADY partially built in Go)

Recall D-FAC §1.5/§2.13 (already ported by slice 03): `_resolve_write_community`
is a once-only cache (Go: `resolveOnce`, already implemented in `switch.go`);
the ASYMMETRY that matters for slice 04 is the CLIENT-BUILDER's own gate,
`_require_write_community`:

```python
def _require_write_community(host, community):
    if not community:  # rejects None AND ""
        raise CredentialError(f"no SNMP write community configured for {host!r}")
    return community
```

vs the READ-side gate (already ported in Go as `requireSNMPCommunity` in
`backend_snmp.go`), which rejects ONLY `nil`:
```go
func requireSNMPCommunity(host string, community *string) (string, error) {
    if community == nil {
        return "", fmt.Errorf("no SNMP read community configured for %q: %w", host, model.ErrCredential)
    }
    return *community, nil
}
```

**Slice 04 must add a SEPARATE `requireSNMPWriteCommunity(host string,
community *string) (string, error)`** that rejects BOTH `nil` AND an empty
string (mirroring Python's `not community` falsy check) — do NOT reuse or
generalize `requireSNMPCommunity` for this (D-FAC trap #1: "Read-community
gate rejects only nil; write-community/HTTP-password gates reject nil OR
empty-string. Unifying these into one helper silently breaks the `snmpset -c
""` regression test's intent"). Exact message: `fmt.Errorf("no SNMP write
community configured for %q: %w", host, model.ErrCredential)`.

The `resolveOnce` cell Go already has (`Switch.snmpWriteCommunity`, built via
`WithSNMPWriteCommunityResolver`) supplies the resolved `*string` that
`requireSNMPWriteCommunity` then gates — `buildSNMPWriteClient(sw *Switch)
(snmp.WriteClient, error)` (new, `backend_snmp.go`-shaped) should:
1. Return `sw.snmpClient` AS A `snmp.WriteClient` if an injected client
   satisfies that interface (Go: a type-assert `wc, ok :=
   sw.snmpClient.(snmp.WriteClient)`; Python has no equivalent check since
   its injected `_snmp_write_client` is a SEPARATE field from
   `_snmp_client` — **note Go's Switch currently has only ONE `snmpClient
   snmp.Client` field, not a separate write-client field** — slice 04 should
   add a distinct `snmpWriteClient snmp.WriteClient` field +
   `WithSNMPWriteClient` option, mirroring Python's separate
   `_snmp_write_client` constructor param, rather than trying to
   type-assert the read client).
2. Otherwise resolve the write community via `sw.snmpWriteCommunity.resolve()`
   (propagating any resolver error UNCAUGHT — this is where a `CredentialError`-
   equivalent surfaces on first write, exactly matching D-FAC trap #2's "a
   raising resolver is NOT cached as resolved").
3. Gate the resolved value through `requireSNMPWriteCommunity`.
4. Build `snmp.NewGoSNMPClient(sw.host, community)` (already satisfies
   `snmp.WriteClient` — `gosnmp.go` already implements `Set`/`SetMany`).

---

## 4. Virtual-fake write behaviour — ALREADY DONE in Go (verify coverage, no new work expected)

This is the good news of slice 04: **the Go `virtual` package's write-path
support is already fully ported and tested**, ahead of this slice, as part
of slice 02's scope. Cross-checked against the Python test files named in
the task brief:

### 4.1 State-level coherence (`tests/virtual/test_mutable_state.py` ↔ `virtual/mutable_state_test.go`)

Every coherence rule the Python state layer encodes (D-VIRT §1.7) is ALREADY
present in Go's `virtual/state.go` `ApplyWrite` + exercised by
`virtual/mutable_state_test.go`:
- PoE admin-off → `detect=1` (unused) + port link forced down; admin-on →
  `detect=3` (delivering) — `TestApplyWritePoeAdminOffSetsDetectAndLinkDown`.
- `ifAdminStatus` off → `admin=false` + coherent link-down —
  `TestApplyWriteIfAdminAndPvid`.
- VLAN egress/untagged bitmap RMW + RowStatus create/destroy/name-alone —
  `TestApplyWriteVlanMembershipRMWAndRowStatus`,
  `TestApplyWriteVlanNameAloneAutoCreatesRow`.
- Vendor mgmt-IP/dhcp-mode writes update the read projection —
  `TestApplyWriteMgmtIPUpdatesReadProjection`,
  `TestApplyWriteDhcpModeUpdatesReadProjection`.
- Unhandled-OID silent no-op — `TestApplyWriteUnhandledOIDIsSilentNoOp`.
- `IsWritableOID` full pattern set incl. no-vendor short-circuit —
  `TestIsWritableOIDRecognizesKnownColumnsAndScalars`,
  `TestIsWritableOIDNoVendorModelShortCircuits`.

**No gaps found.** This state-layer coverage is a superset of what
`tests/virtual/test_mutable_state.py` pins.

### 4.2 Wire-level atomic SET (`tests/virtual/test_snmp_write_face.py` ↔ `virtual/snmpface.go` + `virtual/snmpface_test.go`)

The real SNMP-agent SET path (D-VIRT §3.5's atomic-multi-varbind-SET flow:
snapshot → per-varbind `IsWritableOID` gate → apply-uncommitted → rollback-
on-any-failure → rebuild-once-on-full-success) is ALREADY implemented
(`virtual/snmpface.go`'s `handleSet`) and tested
(`virtual/snmpface_test.go`):
- `TestSnmpFaceSetSingleVarbindVisibleOnRebuild` — single SET visible after rebuild.
- `TestSnmpFaceSetNotWritableOID` — unknown/read-only OID → clean
  `notWritable`, not a silent accept or a hang (matches
  `test_set_unknown_oid_raises_snmperror_not_a_timeout` /
  `test_set_read_only_oid_raises_snmperror`).
- `TestSnmpFaceSetMultiVarbindRollsBackOnSecondFailure` — one valid + one
  invalid varbind in a single PDU applies NEITHER (matches
  `test_set_many_multi_varbind_pdu_atomic_rollback_on_failure`).
- `TestSnmpFaceSetOctetStringAgainstIntColumnIsWrongValue` — malformed value
  type → clean error, never an asyncio-timeout-shaped failure (matches
  `test_set_malformed_value_maps_to_snmperror_not_a_timeout`).

**No gaps found here either.** The Go virtual fake's write face already
covers everything `test_snmp_write_face.py`'s NON-writer-level tests
exercise (i.e. everything up through "SET → mutate → GET reflects it", tested
directly against `SnmpFace`/`gosnmp` rather than through a `SnmpWriter`
wrapper, since `snmp.Writer` doesn't exist in Go yet).

### 4.3 What genuinely IS new work for slice 04 (not a virtual-fake gap — a writer-layer gap)

The Python file `test_snmp_write_face.py` also contains tests that drive
`SnmpWriter`/`AsyncSnmpWriter` (not just raw clients) against the live
`VirtualSwitch` — e.g. `test_snmp_writer_cycle_poe_live_off_then_on`,
`test_snmp_writer_set_vlan_membership_live_preserves_other_ports`,
`test_snmp_writer_set_mgmt_ip_live_reflects_all_three_fields`. **These are
NOT virtual-fake gaps** — the fake already supports every SET these tests
issue (§4.1/§4.2 above prove the wire-level mutation and coherence exist).
What's missing is purely the `snmp.Writer` TYPE ITSELF (§2) that issues
these SETs and does the verify-after-write re-reads — once `snmp.Writer`
exists, these "live" integration tests should port directly against the
EXISTING virtual fake with no fake-side changes required.

### 4.4 PoE-cycle poll-observable timing — is anything special needed in the fake?

The task brief specifically asks: "is PoE-cycle poll-observable detect
transition timing needed?" **No new virtual-fake work is needed.** The
existing `ApplyWrite` coherence rule (admin-off → `detect=1` synchronously,
in the SAME `ApplyWrite` call that processes the admin SET; admin-on →
`detect=3` synchronously) means the fake's state transitions INSTANTLY on
each SET — there is no simulated propagation delay to model. This matches
Python's own virtual fake (same synchronous coherence rule in `apply_write`)
and is WHY the test suite can use `poll_interval=0`/tiny timeouts and still
pass deterministically: `_poe_rearm`'s poll loop's FIRST check (before any
`sleep`) already sees the post-SET state, because the SET and the coherence
mutation happen atomically together. The Go writer's poll loop (§2.6) must
preserve this "check before first sleep" ordering exactly, or a
zero-poll-interval test against the (instant-transition) fake would
needlessly sleep once before ever checking — behaviorally harmless with
`poll_interval=0` but observably different call-count-wise from Python if a
test ever asserts "zero sleeps for an already-satisfied predicate".

---

## 5. Tests — every intent tabulated

### 5.1 `tests/protocols/snmp/test_write_encode.py` (16 tests — pure encoding, no I/O)

| Test | Intent |
|---|---|
| `test_set_varbind_rejects_unknown_type_letter` | Invalid letter → `ValueError`("unknown SET type letter"); valid letters accepted; `SET_TYPE_LETTERS` membership. |
| `test_encode_is_inverse_of_decode` | `decode(encode(ports)) == ports` round-trip. |
| `test_set_port_bit_only_changes_target_bit` | Adding/removing one port preserves every other bit in an existing "trunk" bitmap. |
| `test_membership_bitmaps_untagged_tagged_excluded` | Full 3-mode truth table (§1.4) against a pre-existing egress/untagged pair, preserving other ports. |
| `test_encode_decode_large_port_set` | >64-port round-trip; buffer grows past 8 bytes without being told to. |
| `test_set_port_bit_preserves_str_input` | `bytes` and `str` (latin-1) inputs to `set_port_bit` yield identical results. |
| `test_set_port_bit_preserves_width` | 16-byte input stays 16 bytes; 8-byte input stays ≥8 bytes. |
| `test_vlan_bitmap_width_52_port_model_is_8` | `gsm7252ps` (52 ports) → 8 bytes. |
| `test_vlan_bitmap_width_synthetic_96_port_model_is_12` | A synthetic (non-registry) 96-port model → 12 bytes — `(96+7)//8=12`. |
| `test_set_port_bit_widens_to_requested_width_bytes` | `width_bytes=12` widens an 8-byte input to 12. |
| `test_set_port_bit_width_bytes_never_narrows_below_input_or_8` | `max(8, input, requested)` — wider input wins over a smaller requested width; default (no model width) stays 8. |
| `test_membership_bitmaps_forwards_width_bytes` | `width_bytes` threads through to BOTH returned bitmaps. |

### 5.2 `tests/test_snmp_write.py` (58 tests — `SnmpWriter`/`AsyncSnmpWriter` against a `FakeWriteClient`)

| Group | Representative tests | Intent |
|---|---|---|
| `set_poe` | `test_set_poe_off_issues_correct_set_and_verifies`, `test_set_poe_verification_failure_raises`, `test_protected_port_blocks_disruptive_write_without_force` | Exact SET issued; verify-failure raises with non-nil `after`; guard blocks unforced off, force bypasses. |
| `set_port_enabled` | `test_set_port_enabled_disable_sets_ifadmin_2` | Exact SET (type `i`, value 2). |
| `set_pvid` | `test_set_pvid_sets_gauge32`, `test_set_pvid_verification_failure_raises`, async twins | Type letter `u`; verify-failure `after` list excludes the target pair. |
| `set_vlan_membership` | `test_set_vlan_membership_rmw_preserves_other_ports`, `test_set_vlan_membership_catches_dropped_untagged_write`, `test_set_vlan_membership_missing_vlan_is_precondition_not_verify_error`, `test_set_vlan_membership_vlan_disappears_after_write_raises_verification_error`, `test_set_vlan_membership_bitmaps_are_8_bytes_for_52_port_model`, async twins | RMW correctness; dropped-untagged-column detection ("untagged" substring in message); missing-VLAN → `SnmpError` with zero SETs issued; VLAN-vanishes → `WriteVerificationError` with `after=None`, "disappeared" in message; width stays 8 bytes for a 52-port model. |
| `create_vlan`/`delete_vlan` | `test_create_vlan_sets_rowstatus_and_name`, `test_delete_vlan_destroys_and_verifies_absent`, `test_delete_vlan_protected_member_requires_force`, `test_delete_vlan_missing_vlan_is_precondition_not_verify_error`, async twins | Exact two-varbind SET sets for create; delete's set-intersection protected-port guard; missing-VLAN precondition (zero SETs). |
| `cycle_poe`/`clear_poe_fault` | `test_cycle_poe_off_then_on_terminates_fast`, `test_clear_poe_fault_recovers_detect`, `test_cycle_poe_protected_port_requires_force`, `test_clear_poe_fault_protected_port_requires_force`, `test_cycle_poe_off_never_reached_raises_timeout_and_terminates`, `test_cycle_poe_on_never_reached_raises_timeout_and_terminates`, `test_clear_poe_fault_never_recovers_raises_timeout_and_terminates`, async twins | Off-then-on admin sequence `[2, 1]`; **exactly two separate 1-varbind SET calls, never one 2-varbind call** (`[len(c) for c in poe_calls] == [1, 1]`); both guarded unconditionally; both timeout phases raise a typed `WriteVerificationError` with the exact message substring (`"did not turn off"` / `"did not return to delivering"` / `"still in FAULT"`) and terminate via the injected fake clock, never hang. |
| `set_mgmt_ip` | `test_set_mgmt_ip_requires_force`, `test_set_mgmt_ip_emits_three_ipaddress_sets`, `test_set_mgmt_ip_verifies_gateway_not_just_address`, async twins | Force-gate fires unconditionally with zero SETs when unset; exactly 3 `"a"`-typed varbinds; per-field verify names the diverging field (gateway-specific regression). |

### 5.3 `tests/virtual/test_snmp_write_face.py` (real transports against a live `VirtualSwitch`)

Already tabulated in §4 above (raw-client wire-level tests are ALREADY
covered by the existing Go virtual fake; `SnmpWriter`/`AsyncSnmpWriter`-level
tests are new work once `snmp.Writer` exists, requiring no fake changes).
Full list of writer-level tests to port once `snmp.Writer` exists:
`test_snmp_writer_set_vlan_membership_live_preserves_other_ports`,
`test_async_snmp_writer_set_vlan_membership_live_preserves_other_ports`,
`test_snmp_writer_set_pvid_live_preserves_other_ports`,
`test_snmp_writer_set_vlan_membership_missing_vlan_raises_snmperror_live`,
`test_snmp_writer_create_vlan_then_delete_vlan_live` (+ async),
`test_snmp_writer_delete_vlan_protected_member_requires_force_live`,
`test_snmp_writer_cycle_poe_live_off_then_on` (+ async),
`test_snmp_writer_clear_poe_fault_live_recovers_detect` (+ async),
`test_snmp_writer_cycle_poe_protected_port_requires_force_live`,
`test_snmp_writer_set_mgmt_ip_live_reflects_all_three_fields` (+ async).

### 5.4 `tests/test_write_equivalence.py` (13 tests — sync/async parity against a live mutable `VirtualSwitch`, via `assert_write_equivalent`)

Every write op (including every `VlanMode` variant: TAGGED, UNTAGGED,
EXCLUDED) applied through BOTH facades against FRESH mock instances each,
then asserting both post-write snapshots agree AND a supplied predicate
holds (e.g. "port 1's PoE admin is now off"). Go has no sync/async split, so
this collapses to: apply the write via `Switch`, take a `Snapshot()`,
assert the predicate — no cross-facade comparison needed, per D-FAC §4.2's
already-noted Go-port equivalent. The 13 covered ops:
`set_poe`(off, on-toggle), `set_port_enabled`, `set_pvid`,
`set_vlan_membership`(TAGGED, UNTAGGED, EXCLUDED), `create_vlan`,
`delete_vlan`, `cycle_poe`, `clear_poe_fault`, `set_mgmt_ip`.

### 5.5 `tests/test_sync_api.py` write-relevant tests (facade-level, already tabulated in D-FAC §4.1, cross-referenced here)

`test_sync_switch_set_port_enabled_delegates_to_writer`,
`test_sync_switch_write_methods_delegate_to_writer` (all 9 ops),
`test_plus_model_write_raises_unsupported_capability` (NSDP refuses → HTTP
refuses → last (HTTP's) error surfaces, containing "port-enable"),
`test_from_config_write_community_resolves_lazily_not_at_construction`,
`test_from_config_write_community_resolves_and_writes_when_set`,
`test_write_community_resolver_invoked_at_most_once_across_writes`,
`test_resolve_write_community_explicit_value_wins_over_resolver`,
`test_resolve_write_community_defaults_to_none_without_community_or_resolver`,
`test_sync_switch_plus_set_pvid_over_nsdp`,
`test_delete_vlan_guards_protected_member_before_http_fallback`. These
exercise the FACADE dispatch/resolution machinery (§3), not `SnmpWriter`
itself — port them once `writeVia`/`writerFor`/`buildSNMPWriteClient` exist,
using a fake `snmp.WriteClient` injected via a (new) `WithSNMPWriteClient`
option.

---

## 6. Go porting notes

### 6.1 Exact existing Go signatures to build against

```go
// snmp/client.go — ALREADY EXISTS
type SetVarbind struct { OID string; Value any; TypeLetter string }
func NewSetVarbind(oid string, value any, typeLetter string) (SetVarbind, error)
type WriteClient interface {
    Client
    Set(ctx context.Context, vb SetVarbind) error
    SetMany(ctx context.Context, vbs []SetVarbind) error
}

// snmp/gosnmp.go — ALREADY EXISTS, already satisfies WriteClient
func (c *GoSNMPClient) Set(ctx context.Context, vb SetVarbind) error
func (c *GoSNMPClient) SetMany(ctx context.Context, vbs []SetVarbind) error

// snmp/parse.go — ALREADY EXISTS
func DecodePortBitmap(bitmap []byte) []int  // sorted ascending

// snmp/reader.go — ALREADY EXISTS; snmp.Writer's internal reader reuses this directly
func NewReader(c Client, m *model.SwitchModel) (*Reader, error)
func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error)
func (r *Reader) GetVLANs(ctx context.Context) ([]model.VLANInfo, error)
func (r *Reader) GetPVIDs(ctx context.Context) ([]model.Pvid, error)
func (r *Reader) GetPoE(ctx context.Context) ([]model.PoEStatus, error)
func (r *Reader) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error)

// snmp/oids.go — ALREADY EXISTS
type VendorOids struct {
    BoxFan, BoxTemp string
    MgmtWriteAddrUnverified, MgmtWriteNetmaskUnverified, MgmtWriteGatewayUnverified string
    // ... PoePowerMw, DhcpModeUnverified etc.
}
func GetVendorOids(m *model.SwitchModel) (VendorOids, error)

// model/errors.go — ALREADY EXISTS, the exact target error types
var ErrProtectedPort = errors.New("protected port")
var ErrCredential = errors.New("credential error")
type WriteVerificationError struct { Msg string; Before, After any }
func (e *WriteVerificationError) Error() string

// model/registry.go — ALREADY EXISTS
func (m *SwitchModel) HasBackend(b Backend) bool

// switch.go — ALREADY EXISTS (slice 03 anticipated slice 04's needs)
type resolveOnce struct { /* ... */ }
func (c *resolveOnce) resolve() (*string, error)
// sw.snmpWriteCommunity *resolveOnce -- already a Switch field
// sw.protectedPorts []int -- already sorted-unique, already a Switch field
func WithSNMPWriteCommunityResolver(r func() (*string, error)) SwitchOption  // already exists
func WithProtectedPorts(ports ...int) SwitchOption                          // already exists

// dispatch.go — ALREADY EXISTS (readVia; writeVia is its write-side twin)
var backendPreference = []model.Backend{model.BackendSNMP, model.BackendNSDP, model.BackendHTTP, model.BackendSSH}
func RegisterBackend(b model.Backend, build BackendBuilder)  // read-side; needs a write-side RegisterWriteBackend twin
```

### 6.2 New code slice 04 must add

1. **`snmp/write.go`** (new file): `EncodePortBitmap([]int, widthBytes int)
   []byte`, `SetPortBit(current []byte, port int, present bool, widthBytes
   int) []byte` (Go: no `str`-vs-`bytes` union needed — gosnmp's `Row.Value`
   for an octet string is already `[]byte`, so `current` is always
   `[]byte`; drop the Python `bytes | str` duality entirely), `MembershipBitmaps(mode
   model.VlanMode, port int, egress, untagged []byte, widthBytes int) (newEgress,
   newUntagged []byte)`, `VlanBitmapWidth(m *model.SwitchModel) int`.

2. **`snmp/writer.go`** (new file): `type Writer struct { client WriteClient;
   model *model.SwitchModel; protectedPorts []int; reader *Reader }`,
   `NewWriter(client WriteClient, m *model.SwitchModel, protectedPorts []int)
   (*Writer, error)` (gates via `m.HasBackend(model.BackendSNMP)`), every
   method from §2.5-§2.13, `PoeCycleTimeouts{OffTimeout, OnTimeout,
   PollInterval time.Duration}` + `DefaultPoeCycleTimeouts`, and the
   **injectable clock/sleep shape** — recommended:
   ```go
   type PoeCycleOptions struct {
       Timeouts PoeCycleTimeouts
       Clock    func() time.Time              // default time.Now
       Sleep    func(ctx context.Context, d time.Duration) error // default: select{case <-time.After(d): case <-ctx.Done(): return ctx.Err()}
   }
   func (w *Writer) CyclePoE(ctx context.Context, port int, force bool, opts PoeCycleOptions) error
   func (w *Writer) ClearPoEFault(ctx context.Context, port int, force bool, opts PoeCycleOptions) error
   ```
   A ctx-aware default `Sleep` lets a caller's `context.Context` cancellation
   abort a stuck poll loop — something Python's `time.sleep`/`asyncio.sleep`
   defaults can't do, and a genuine Go-idiomatic improvement over the
   pinned reference as long as the DEFAULT behavior (real elapsed time,
   uninterrupted) matches Python's when no cancellation occurs. Tests
   inject `Clock`/`Sleep` exactly like Python's fake clock/no-op sleep.

3. **Facade write plumbing** (extend `dispatch.go`/`switch.go`/new
   `backend_snmp_write.go`):
   - `BackendWriter` interface (mirrors `BackendReader`, one method per op:
     `SetPoE`, `SetPortEnabled`, `SetPVID`, `SetVLANMembership`,
     `CreateVLAN`, `DeleteVLAN`, `CyclePoE`, `ClearPoEFault`, `SetMgmtIP` —
     all `(ctx, ...) error`).
   - `WriteBackendBuilder func(sw *Switch) (BackendWriter, error)` +
     `RegisterWriteBackend(b model.Backend, build WriteBackendBuilder)` +
     a `writerRegistry` map (mirrors `backendRegistry` exactly).
   - `Switch.writerCache map[model.Backend]BackendWriter` + `writerFor`
     (mirrors `readerFor`).
   - `Switch.writeVia(ctx, op string, fn func(BackendWriter) error) error`
     (mirrors `readVia`, six ordering rules identical, see §3.1).
   - `Switch.snmpWriteClient snmp.WriteClient` (new field) +
     `WithSNMPWriteClient(c snmp.WriteClient) SwitchOption` (new option,
     mirrors `WithSNMPClient` for the read side).
   - `requireSNMPWriteCommunity` (new, in `backend_snmp.go` or a new
     `backend_snmp_write.go`) per §3.4.
   - `buildSNMPWriter(sw *Switch) (BackendWriter, error)` (the
     `WriteBackendBuilder` registered for `model.BackendSNMP` via `init()`
     in the new write-backend shim file), calling `snmp.NewWriter` with
     `sw.protectedPorts`.
   - Nine public `Switch` write methods (`SetPoE`, `SetPortEnabled`,
     `SetPVID`, `SetVLANMembership`, `CreateVLAN`, `DeleteVLAN`, `CyclePoE`,
     `ClearPoEFault`, `SetMgmtIP`), each a thin `writeVia` wrapper — mirror
     the "Write options struct per spec §5" shape the task brief mentions:
     ```go
     type WriteOpts struct { Force bool }
     func (s *Switch) SetPoE(ctx context.Context, port int, on bool, opts WriteOpts) error
     func (s *Switch) DeleteVLAN(ctx context.Context, vlan int, opts WriteOpts) error {
         if err := s.guardVLANDeleteMembers(ctx, vlan, opts.Force); err != nil {
             return err
         }
         return s.writeVia(ctx, "delete_vlan", func(w BackendWriter) error {
             return w.DeleteVLAN(ctx, vlan, opts.Force)
         })
     }
     ```
     `CyclePoE`/`ClearPoEFault` additionally take a `PoeCycleOptions`
     parameter (or embed one in a richer `PoeCycleWriteOpts{WriteOpts;
     PoeCycleOptions}` struct) — a plain `bool force` param, as most other
     ops use, is not enough for these two.
   - `Switch.guardVLANDeleteMembers(ctx, vlan int, force bool) error` (new,
     §3.3): if `force`, return nil; else `s.GetVLANs(ctx)` (full `readVia`
     dispatch) — on `errors.Is(err, model.ErrUnsupportedCapability)`,
     degrade silently (`return nil`); on any OTHER error, propagate; else
     find the matching VLAN, intersect `MemberPorts` with `protectedPorts`,
     and return a `model.ErrProtectedPort`-wrapped error with the exact
     message from §2.12/§3.3 if the intersection is non-empty.

### 6.3 `virtual` package cleanup (non-blocking, but flag it)

Once `snmp.EncodePortBitmap`/`snmp.VlanBitmapWidth` exist (§1.2/§1.5),
`virtual/state_oidmap.go`'s private `EncodePortBitmap`/`vlanBitmapWidth`
should be refactored into thin wrappers (converting `map[int]bool` ↔
`[]int` at the boundary) rather than staying independent
re-implementations of the same bit-packing math — matching the Python
architecture where `virtual/state.py` explicitly delegates to
`protocols/snmp/write.py`. This is a "should", not a hard blocker for
slice 04's tests to pass, since the two current implementations already
agree bit-for-bit (verified: both use the identical `divmod(p-1, 8)` /
`0x80 >> bit` MSB-first formula) — but leaving two hand-maintained copies of
security/correctness-sensitive bit-packing code is the kind of
"papering-over" the roadmap's completion audit (`2026-07-30-roadmap.md`)
explicitly looks for, so do not skip it silently.

---

## Completeness checklist

- [x] `protocols/snmp/write.py` — every function (`SetVarbind`/
  `SET_TYPE_LETTERS` already ported; `encode_port_bitmap`/`vlan_bitmap_width`
  duplicated in the wrong package/visibility, flagged for consolidation;
  `set_port_bit`/`membership_bitmaps` fully missing, specified exactly).
- [x] `snmp_write.py` — `SnmpWriter` every method (`set_poe`,
  `set_port_enabled`, `set_pvid`, `set_vlan_membership` incl. RMW +
  dual-column verify, `create_vlan`, `delete_vlan` incl. existence
  precondition + set-intersection protected guard, `set_mgmt_ip` incl.
  unconditional force-gate + 3-field verify, `cycle_poe`/`clear_poe_fault`
  incl. `_poe_rearm`'s two-sequential-SET rule + `PoeCycleTimeouts` +
  `_poe_is_off`/`_poe_recovered`/cycle_poe's own strict-delivering
  predicate + injectable sleep/clock); `AsyncSnmpWriter` deltas (none
  found — byte-identical semantics).
- [x] Every `WriteVerificationError`/`ProtectedPortError`/`SnmpError` exact
  message quoted verbatim, with the precondition-vs-verification-failure
  distinction called out explicitly for `set_vlan_membership`/`delete_vlan`.
- [x] Facade write plumbing: `_write` loop (identical six rules to `_read`),
  `_writer_for`'s SNMP branch + asymmetric write-community gate,
  `delete_vlan`'s facade-level `_guard_vlan_delete_members` (full method,
  exact degrade-silently-on-unreadable-VLANs semantics), write-community
  once-only resolution (already built in Go via `resolveOnce`).
  `upload_certificate*` confirmed out of scope.
- [x] Virtual-fake write behaviour: audited against
  `test_mutable_state.py`/`test_snmp_write_face.py` — state-layer coherence
  and wire-level atomic SET are BOTH already fully ported and tested in Go
  (`virtual/state.go`, `virtual/snmpface.go` + their `_test.go` files); the
  only "gap" is the not-yet-existing `snmp.Writer` type itself, which is
  this slice's actual deliverable, not a fake-side gap. PoE-cycle timing
  question answered: no simulated propagation delay needed (coherence is
  synchronous in both Python and Go fakes).
- [x] Tests tabulated: `test_write_encode.py` (16), `test_snmp_write.py`
  (58), `test_snmp_write_face.py` (raw-client tests already covered;
  writer-level tests listed for slice-04 porting), `test_write_equivalence.py`
  (13, collapsing to single-facade snapshot assertions per D-FAC §4.2), plus
  the write-relevant subset of `test_sync_api.py` (cross-referenced to
  D-FAC §4.1).
- [x] Go porting notes: exact existing signatures quoted from
  `snmp/client.go`, `snmp/gosnmp.go`, `snmp/parse.go`, `snmp/reader.go`,
  `snmp/oids.go`, `model/errors.go`, `model/registry.go`, `switch.go`,
  `dispatch.go`; new-code inventory for `snmp/write.go`, `snmp/writer.go`,
  and the facade's write-backend registry/dispatch/guard/community-gate
  additions; a concrete `WriteOpts{Force bool}` + `PoeCycleOptions`
  sketch; a ctx-aware injectable clock/sleep shape.

---

## Ten trickiest traps (read this section twice before implementing)

1. **`encode_port_bitmap`/`vlan_bitmap_width` already exist in Go, but in
   the WRONG package (`virtual`, not `snmp`) and in the wrong shape/visibility.**
   A careless port that adds a THIRD copy in `snmp/write.go` without
   consolidating the `virtual` package's private copies leaves three
   implementations of the same bit-packing math to keep in sync forever.
2. **`_poe_rearm`'s off→on re-arm is TWO SEPARATE single-varbind `Set` calls,
   never one `SetMany` PDU with a duplicate OID.** RFC 3416 leaves
   per-varbind ordering undefined for a repeated OID; a real agent may
   reject or collapse it, silently defeating the re-arm. Pinned by an exact
   call-count assertion (`[1, 1]`, not `[2]`) — do not "optimize" this into
   one PDU.
3. **A missing VLAN in `set_vlan_membership`/`delete_vlan` is a
   PRECONDITION failure (`SnmpError`/`model.ErrSNMP`), never a
   `WriteVerificationError`** — and issues ZERO SETs. Conflating the two
   error types, or issuing a SET before checking existence, breaks a
   directly-pinned regression (review item 9).
4. **`set_vlan_membership` verifies BOTH the egress AND untagged columns
   independently** against the exact bitmap just written (re-decoded, not
   re-derived from `mode`) — a device that silently drops just one of the
   two SETs in the same PDU must be caught. Verifying only one column is a
   silent-failure regression (review item 1).
5. **`delete_vlan`'s protected-port guard is a SET-INTERSECTION check
   (`member_ports & protected_ports`), not a single-port guard** — deleting
   a VLAN can strip multiple ports' membership at once. This is the ONLY
   writer method whose guard shape differs from every other method's
   single-port `_guard(port, force)` call.
6. **`create_vlan` never guards on protected ports at all** (`force` exists
   only for signature symmetry with `delete_vlan`) — do not add a guard
   call "for consistency"; an empty VLAN has no members to protect.
7. **`set_mgmt_ip` is force-gated UNCONDITIONALLY, independent of
   `protected_ports`** — `force=False` always raises, regardless of which
   ports are marked protected, because a bad mgmt-IP write can strand the
   entire switch, not just one port.
8. **`set_poe`'s guard fires ONLY when turning OFF** (`if not on:
   self._guard(...)`) — turning PoE ON is never guarded. `cycle_poe`/
   `clear_poe_fault`, by contrast, guard UNCONDITIONALLY regardless of
   direction. Do not unify these three guard call sites into one shape.
9. **The write-community gate (`_require_write_community`) rejects `nil`
   AND `""`; the read-community gate rejects only `nil`.** These MUST stay
   two separate functions (`requireSNMPCommunity` already exists for reads;
   slice 04 adds a distinct `requireSNMPWriteCommunity` for writes) — do
   not unify them (D-FAC trap #1, restated here because it bites again at
   the write layer specifically).
10. **The facade-level `_guard_vlan_delete_members` and
    `SnmpWriter.delete_vlan`'s own internal guard use the BYTE-IDENTICAL
    error message string** (`"VLAN {vlan} includes protected port(s)
    {sorted(clash)}; pass force=True to delete it anyway"`) — this is
    deliberate duplication (every backend gets the same safety rail,
    per D-FAC §2.17's rationale), not an accident to deduplicate away by
    making one call the other. Keep both copies, keep them textually
    identical, and note the facade guard degrades SILENTLY (returns nil)
    if no backend can even read VLANs, while the writer's own guard has no
    such fallback (it always has a `before` VLAN in hand by the time its
    guard runs).
