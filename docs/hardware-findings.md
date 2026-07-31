# Live-Hardware Findings (principle 5 reconciliation backlog)

Divergences observed between the Go library and real switches during opt-in
hardware smokes. Each must be resolved (fix the code, or fix the mock+seed to
match the device and re-capture) before the completion audit. Per principle 4,
resolution requires captured device output, not a guess.

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
- **Status:** OPEN — scheduled for slice 11 (hardware conformance) or a
  targeted follow-up. Does not block the slice-06 merge (the slice faithfully
  ports the pinned reference and passes all of the reference's own fixtures).
