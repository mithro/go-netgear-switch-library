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
   GetPoe/GetMgmtIP): Go walks the vendor column after the standard tables;
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
