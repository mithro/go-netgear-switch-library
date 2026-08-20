# Live-Hardware Findings (principle 5 reconciliation backlog)

Divergences observed between the Go library and real switches during opt-in
hardware smokes. Each must be resolved (fix the code, or fix the mock+seed to
match the device and re-capture) before the completion audit. Per principle 4,
resolution requires captured device output, not a guess.

## Gate-2 (2026-08-20): live re-verification + fake-fidelity fixes

Three real switches were read live this session, over both SNMP and NSDP
(read-only, per the approved hardware-write policy): m4300-24x @10.1.5.13
(firmware 12.0.13.8), gsm7252ps @10.1.5.22 (firmware 10.0.0.53), and
gs110emx @10.1.5.25 (firmware 1.0.2.8). All three readers work against
their live firmware; no new library defect was found. The live reads DID
surface three places where the Go virtual-switch FAKE had drifted from
what real hardware actually returns -- all three are fixed below, each
grounded in a committed real capture plus this session's own live reads
(principle 5: the fake must match hardware, not the other way round).

### Fix 1 -- LLDP Port ID: fake rendered raw bytes, hardware renders hex

Two committed real captures --
`webui/testdata/http/m4300_lldpRemoteInventory.html` (PortId
`E4:5F:01:8D:F4:FD`) and
`fastpath/testdata/cli/m4300_24x_show_lldp_remote_device_all.txt` -- show
real hardware renders a MAC-address-subtype `lldpRemPortId` as UPPERCASE
COLON-HEX, same as Chassis ID, never as raw bytes. The Go fake hex-encoded
Chassis ID but passed a MAC-subtype Port ID through RAW in three
renderers: `virtual/web_gsm7252ps.go` `RenderXELLDP` (XE HTTP LLDP page,
serving gsm7252ps/gsm7228ps/m4300-24x/m4300-16x), `virtual/
cliface_render.go` `renderLLDP` (FASTPATH telnet/CLI, all FASTPATH
models), and `virtual/web_gs728tpp.go`'s `goAheadLLDPIDText` (GS728TPP
GoAhead page) had a naive `len==6` hex check that would have mangled a
genuinely textual 6-character interface-name Port ID (e.g. `"1/xg51"`).

Fixed with one shared decision helper, `isMACShapedLLDPID` (`virtual/
web_gsm7252ps.go`): hex-encode a Port ID/Chassis ID ONLY when it is
exactly 6 bytes AND not printable ASCII (0x20-0x7E). Deliberately the
STRICT ASCII range, not the wider printable-Latin-1 definition
`snmp/parse.go`'s `formatPortID`/`isPrintableLatin1` uses for the
identical ambiguity on live SNMP-sourced values -- that function only
ever reaches its printability check for a value the SNMP transport
already decided was text; this package has no such upstream signal to
lean on, and the wider Latin-1 check was verified (against this package's
own gs728tpp seed) to misclassify a genuine raw MAC whose bytes happen to
all be Latin-1-printable. Verified live: telnet into a running
`gngsw-virtual -model m4300-24x` fake and `show lldp remote-device all`
now renders `88:A2:9E:80:87:01` / `E4:5F:01:8D:F4:FD`, not raw bytes;
`gngsw identify` unaffected.

### Fix 2 -- sysObjectID: fake values were unverified placeholders

`virtual/seed.go`'s `SeedM4300_24X`/`SeedGSM7252PS` carried sysObjectID
values explicitly documented (by both this Go port and the pinned Python
reference's own `seed.py`) as "UNVERIFIED virtual/test placeholder ...
NOT a claim about the real device's sysObjectID". This session's live
SNMP GET replaced them with the real measured values: m4300-24x
@10.1.5.13 = `1.3.6.1.4.1.4526.100.1.34`; gsm7252ps @10.1.5.22 =
`1.3.6.1.4.1.4526.100.1.10`. `snmp.SysObjectIDModels` (the sysObjectID ->
model detection map) was deliberately left unchanged -- it only contains
OIDs proven to identify a model, and both switches already detect fine
via `DetectModelFromSysDescr`. Verified: `gngsw identify` against the
fake now reports the real sysObjectID for both models.

### Fix 3 -- Stats packets: fake m4300-24x served null RxPackets/TxPackets

`virtual/seed.go`'s `SeedM4300_24X` never set `PortSim.RxUcast`/`TxUcast`,
so the fake served `-`/null RxPackets/TxPackets on every m4300-24x port,
while real hardware always answers them (this session, live port 1:
RxPackets~=20455434750, TxPackets~=18675057818). Fixed by wiring in the
per-port packet counters ALREADY PRESENT in the committed capture
`virtual/testdata/captures/m4300-24x.json`'s own `"stats"` section --
the same capture this seed's RxOctets/TxOctets/RxErrors/TxErrors were
already transcribed from; the packet counts were simply never wired into
the seed. `SeedGSM7252PS` already did this correctly and needed no
change.

### Cross-language ripple

All three fixes make the Go fake MORE faithful to real hardware than the
pinned Python reference implementation's own fake, whose seed data still
carries the placeholder/omission (that repo is read-only from here). Per
the established Go-fake-ahead-of-Python-fake precedent (the existing
`_KNOWN_LLDP_PORT_ID_DIVERGENCE` exclusion, `crosstest/python/
cc3_read_diff.py`), this was resolved as documented, self-verifying
exclusions rather than by reverting the hardware-faithful fixes:
- `_KNOWN_LLDP_PORT_ID_DIVERGENCE` grew from 2 to 3 entries (added
  m4300-24x/telnet, matching the pre-existing m4300-24x/http entry).
- `_KNOWN_LLDP_SYSNAME_DIVERGENCE` (new): m4300-16x/telnet local_port 16's
  raw Port ID bytes happen to embed a literal ASCII LF, which used to
  corrupt both fakes' fixed-width CLI table row identically (masking the
  divergence); Go's fix removed the embedded control byte, so only the
  still-unfixed Python fake's row remains corrupted.
- `_KNOWN_STATS_PACKETS_DIVERGENCE` (new): m4300-24x/{snmp,http,telnet}
  exclude only `rx_packets`/`tx_packets` from `get_stats`, every port row.

All 183 CC3 read triples still run; ten of them (up from six) now carry a
documented, self-verifying substitution instead of a plain differential.
See `test/crosslang/python_driver_test.go`'s `TestPythonLibVsGoFake_
AllBackends` doc comment and `cc3_read_diff.py` for the full, cited
rationale. `make crosslang` is green across all four suites.

### Other observations (not fixed this session)

- The gs110emx seed's port descriptions have drifted from the switch's
  current live configuration at 10.1.5.25 (cosmetic; does not affect any
  parser or read-op correctness). Left as a fixture-refresh opportunity,
  not fixed here.
- The gs110emx NSDP responder rate-locks under concurrent access; read it
  single-threaded (one in-flight NSDP request at a time) against real
  hardware.

## HW-1 (2026-07-31): gs110emx HTTP get_vlans fails on live firmware
- **Host/firmware:** gs110emx @ 10.1.5.25, br-net; web login via GAMBIT with a
  gdoc2netcfg-resolved password.
- **What worked:** HTTP login + `GetPorts` over HTTP returned real port data —
  validates the GAMBIT login, net/http transport, and the GS110EMX port parser
  against real silicon.
- **What failed:** `GetVLANs` over HTTP →
  `"8021qMembe.cgi: expected a hiddenMem input with the per-port wire codes,
  found none: unexpected page"`.
- **Root cause narrowed:** NOT a wrong-path bug — gs110emx's
  `VlanMembershipPath` correctly resolves to `/iss/specific/vlanMembership.html`
  and that is the page actually fetched (the `8021qMembe.cgi` string in the
  error is a hardcoded generic label inside `vlanInfoFromMembership`, reused
  for all STANDARD/GS110EMX/GS105PE membership parses — cosmetically
  misleading; check whether Python's error label is the same before "fixing"
  it). The real cause is that the **live firmware's `vlanMembership.html` lacks
  the `hiddenMem` per-port input** that the committed
  `gs110emx_vlanmembership.html` capture (which the unit tests pass against)
  contains. Either the capture came from a different gs110emx unit/firmware
  than 10.1.5.25, or the parser needs to handle a firmware variant. Since
  gs110emx is `reads_verified=true`, determine whether the Python reference
  ALSO fails on 10.1.5.25 (→ shared capture-drift, refresh the fixture) or
  succeeds (→ a real Go parser gap).
- **Next step (principle 4):** capture the live `vlanMembership`/`Cf8021q`
  page from 10.1.5.25, diff against the committed fixture, and either fix the
  Reader's page routing/parser or refresh the fixture + mock + seed to match
  the real device (whichever the capture shows is wrong). Then re-run the
  smoke and cross-check HTTP vs NSDP get_vlans.
- **Status (updated gate-2, 2026-08-20):** RE-TRIAGED, still OPEN but
  narrowed. `gs110emx` was live-read again this session (10.1.5.25, still
  firmware 1.0.2.8 — **not firmware drift**, the unit is on the exact same
  firmware as the original 2026-07-31 finding). The root cause is now
  understood precisely: `GetVLANs` HTTP-POSTs
  `/iss/specific/vlanMembership.html` once PER VLAN, but only VLAN 1's
  response was EVER captured (the committed
  `gs110emx_vlanmembership.html` fixture) — for every OTHER VLAN, both
  this Go fake AND the pinned Python reference's own fake generalize that
  single VLAN-1 capture as if it applied to every VLAN ID, which it does
  not on real firmware. This is a **capture-coverage gap SHARED
  IDENTICALLY with the Python reference implementation**, not a Go
  defect: the Reader's parser (`vlanInfoFromMembership`) fails LOUD on
  the live non-VLAN-1 page rather than silently fabricating data, exactly
  as Python's equivalent parser would (verified against the pinned
  reference's own `parse_membership`, `protocols/http/parse.py:1971-1980`
  — the identical missing-`hiddenMem` check, raising the BYTE-IDENTICAL
  message `"8021qMembe.cgi: expected a hiddenMem input with the per-port
  wire codes, found none"`, same fail-loud contract). Per
  principle 5 there is nothing to "fix the fake to match hardware" here
  yet, because no non-VLAN-1 hardware capture exists on EITHER side to
  fix it towards.
- **Next step, unchanged in kind, credential-store-blocked this session:**
  fully closing this needs a live RAW capture of a non-VLAN-1
  `vlanMembership.html` response from 10.1.5.25 (e.g. VLAN 5's page) to
  diff against the generalized VLAN-1 fixture and either confirm the
  per-VLAN page shape is identical (→ just refresh/extend the fixture set)
  or find a real per-VLAN structural difference the parser needs to
  handle. This session's credential store did not have the access needed
  to drive an authenticated multi-VLAN capture sequence against
  10.1.5.25; deferred, not abandoned.
- **Status:** OPEN — scheduled for slice 11 (hardware conformance) or a
  targeted follow-up. Does not block the slice-06 merge (the slice faithfully
  ports the pinned reference and passes all of the reference's own fixtures).
