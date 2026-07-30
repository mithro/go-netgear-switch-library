# Cross-Language Divergence Baseline (Go vs Python)

Accumulating record of ADJUDICATED, deliberate behavioural deltas between this
library and the pinned Python reference. The slice-10 cross-language
conformance suite treats everything NOT listed here as a parity bug. Each
entry: where, what differs, why accepted, and what the cross-tests must (not)
compare.

## Slice 02 (SNMP read core + virtual substrate)

1. **Truncated-multibyte UTF-8 replacement** (`snmp/parse.go` decodeUTF8Replace):
   Go emits one U+FFFD per invalid byte; Python's `decode("utf-8","replace")`
   collapses an invalid multi-byte prefix to one U+FFFD. Unreachable for real
   device data (ASCII); cross-tests must not construct truncated-multibyte
   name/alias values expecting byte-equal output.
2. **Reader walk order for vendor-conditional walks** (`snmp/reader.go`
   GetPoE/GetMgmtIP): Go walks the vendor column after the standard tables;
   Python's statement order walks it first. Results identical; cross-tests
   compare RESULTS, never request sequences.
3. **`dest_rows` gateway join strictness** (`snmp/parse.go` ParseMgmtIP): Go
   prefix-checks route rows before suffix extraction; Python slices
   unconditionally (admitting garbage keys for out-of-scope rows). Go is
   strictly safer; unobservable for base-OID-scoped walks.
4. **`asString` for `[]byte` VLAN-name SET values** (`virtual/state.go`): Go
   decodes bytes; Python's `str(bytes)` would produce a `b'…'` repr on that
   (unreached) path. Go behaviour is the intended one.
5. **Error TEXT is not byte-identical** (all packages): Go wraps sentinel
   errors with `%q`/`%w` phrasing; Python raises exception classes with `!r`
   phrasing. Error CLASS and the offending-OID-in-message contract are the
   parity surface; exact wording is not. (Also: Python's secret-command
   errors distinguish "could not be run" vs "failed (exit N)"; Go folds them.
   `EnsureSecureFile` prints `0644` (Go `%#o`) vs `0o644` (Python).)
6. **`full_oid`/`FullOID`** exists in both but is uncalled by both transports —
   API-parity only.
7. **Counter64 above 2^63** wraps in Go (`Row.Value` is int64); Python is
   arbitrary-precision. Physically unreachable on this hardware class.
8. **Walk monotonicity guard** (`snmp/gosnmp.go`): Go errors on a
   non-advancing agent ("OID not increasing", wraps ErrSNMP); Python (pysnmp
   `lexicographicMode=False`) has no such guard. Defensive addition; real
   agents and both fakes always advance.
9. **`toIntBestEffort` / `mustInt` reject `[]byte`** where Python's `int()`
   raises anyway (mgmt DHCP mode → UNKNOWN identically) — aligned with Python
   observable behaviour; noted because the internal mechanism differs
   (type-switch miss vs TypeError).
10. **Virtual server `self.port` split** (`virtual/server.go`): Go has
    separate SnmpPort/NsdpPort/HTTPPort/SSHPort/TelnetPort fields; Python
    shares `self.port` between SNMP and NSDP faces (never both bound).
    Spec-mandated improvement (§8.2).

## Slice 03

1. **Read-method casing**: Go's public read methods are `GetVLANs`,
   `GetPVIDs`, `GetLLDP`, `GetMACs`, `GetPoE` (spec §5 casing, matching this
   codebase's initialism style already used by the `VLANInfo`/
   `LLDPNeighbor`/`PoEStatus` type names) where Python's are `get_vlans`,
   `get_pvids`, `get_lldp`, `get_macs`, `get_poe` (snake_case, no
   initialism-casing question at all). Adjudicated at the slice-03 merge as
   a deliberate naming convention divergence, not a parity gap: cross-tests
   must compare behavior, never expect a literal name match across
   languages. (`GetPorts`/`GetStats`/`GetSensors`/`GetMgmtIP`/
   `GetSystemInfo` needed no change -- they were already spec-cased.)
2. **`Snapshot`'s field-read evaluation order** (`snapshot.go`): Go reads
   ports, stats, vlans, pvids, lldp, macs, poe, sensors, then mgmt_ip, in
   that fixed sequential order (matching Python's `snapshot()` statement
   order), but this order is inert: each field's `snapshotDegrade` call is
   independent (no shared mutable state, no field depends on another
   field's result), so reordering the calls would not change `SwitchData`'s
   final contents for any input -- the only externally-observable effect of
   the order is WHICH field's non-capability error (e.g. `ErrCredential`)
   surfaces first when more than one would fail, and that is not a
   parity-relevant guarantee cross-tests may depend on.
3. **`readVia`'s reraise-last semantics**: confirmed (not a divergence) to
   match Python exactly -- "least-preferred backend among those actually
   tried wins" (i.e. the last one attempted chronologically, not the first
   or most-preferred). An earlier D-FAC dossier gloss said "most preferred",
   which was backwards; it was corrected before this slice's implementation
   landed (see commit `9f298b5`), and `dispatch.go`'s `readVia` doc comment
   and `TestReadVia_SkipAndReraiseLast` both pin the corrected (matches
   Python) behavior.

## Slice 04 (SNMP write)

12. **CreateVlan drops Python's unused `force` parameter** (`snmp/writer_vlan.go`,
    facade `CreateVlan`): Python keeps `force=False` on `create_vlan` purely for
    signature symmetry and never reads it; Go omits it. Behaviourally inert.
13. **Clock/sleep injection is a Writer construction option** (`snmp.WithClock`)
    rather than Python's per-call test-only kwargs. Facade surface identical
    (timeouts only), matching Python's facade.
14. **PoERearm timeout errors reuse last-polled status** (`snmp/writer_poe.go`
    `SetPoERearm`): Go's verification error's `After` field carries the
    `before`-snapshot status when a rearm times out; Python performs one extra
    fresh read after timeout, seeing the actual post-timeout device state. Go's
    behaviour is negligible in practice (rearm is rarely interrupted and device
    state usually stabilizes fast) and arguably safer (stale context reuse avoids
    extra I/O). Documented for cross-language conformance suite awareness.

## Slice 05 (NSDP)

1. **`packMAC` fail-fast on an overlong MAC** (`nsdp/protocol.go`): Go's
   `Packet.Encode` returns an error wrapping `model.ErrNSDP` if `ClientMAC`/
   `ServerMAC` is longer than 6 bytes; Python's `struct.pack(HEADER_FORMAT,
   ...)` with a `"6s"` field code silently TRUNCATES a too-long `bytes` object
   to 6 bytes instead of raising (verified directly against the pinned
   interpreter: `struct.pack("6s", b"1234567") == b"123456"`, no exception).
   Both languages match on the short side (zero-pad to 6 bytes). Deliberate
   improvement, not a bug: silently dropping trailing bytes off a MAC address
   on the wire is exactly the class of corruption this codec should refuse to
   produce, and no caller in this codebase ever legitimately has a >6-byte
   MAC to encode. Cross-tests must not construct a >6-byte MAC expecting a
   truncated (rather than rejected) encode.

2. **`PvidTLV`/`VlanMembersTLV` fail-fast on an out-of-range VLAN ID or port**
   (`nsdp/write.go`): Go returns an error wrapping `model.ErrNSDP` up front if
   `vlan` doesn't fit a `uint16` (0-65535) or, for `PvidTLV`, if `port`
   doesn't fit a byte (0-255). Python's `pvid_tlv`/`vlan_members_tlv` only
   fail when the out-of-range value is later packed (`bytes([port])` raising
   `ValueError`, `struct.pack(">H", vlan)` raising `struct.error`) -- same
   outcome (reject rather than silently wrap/truncate), just checked earlier
   and with a different error type/message. Same fail-fast philosophy as
   entry 1 above: no caller in this codebase ever legitimately has an
   out-of-range port/VLAN to encode.
3. **`IPv4TLV` uses Go's stricter `net.ParseIP`, not `inet_aton`'s leniency**
   (`nsdp/write.go`): Python's `socket.inet_aton` accepts abbreviated forms
   (e.g. `"10.1.5"` -> `10.1.0.5`) that `net.ParseIP` rejects, requiring a
   full dotted-quad. Every call site in this codebase always passes a full
   dotted-quad address, so this is a no-op in practice; it fails fast on a
   malformed address rather than reproducing `inet_aton`'s abbreviated-form
   guessing.
4. **`State.ApplyNsdpWrite` no-ops on a too-short value for a known tag,
   rather than reproducing Python's uncaught `IndexError`/`struct.error`**
   (`virtual/state.go`): Python's `apply_nsdp_write` indexes `value[0]`/calls
   `struct.unpack_from` with no length guard; a too-short value for
   PORT_PVID/VLAN_MEMBERS raises an exception that `faces/nsdp.py`'s
   `_serve` does NOT catch (it only catches `ValueError` around `_handle`,
   and neither exception type is a `ValueError`), silently killing that one
   Python mock's serve thread permanently. An unrecovered Go panic from the
   same index-out-of-range in this package's background serve goroutine
   would crash the entire test process instead -- a strictly worse failure
   mode for input only a malformed/adversarial datagram could ever produce.
   Go instead guards the length up front and treats a too-short value as a
   no-op, exactly like every other unrecognized/read-only write. This only
   changes how a MALFORMED write degrades; every well-formed write's wire
   encoding and resulting state mutation are unchanged.
