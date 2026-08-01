# FASTPATH CLI fixtures — provenance

Every file in this directory is copied **byte-for-byte** (verified with
`cmp`) from the pinned `python-netgear-switch-library` reference at commit
`7ebfe5d475411a7d88fd5cc68ff86ee3a4505362` (snapshot worktree:
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-7ebfe5d`),
path `tests/fixtures/cli/<same filename>`. That snapshot is read-only from
this repo; if a fixture ever needs to change, re-copy it from a newer pin,
never hand-edit.

These are the fixtures used by the pin's
`tests/protocols/cli/test_cli_parse.py`, restricted to the subset Task 3
needs: `parseVersion` (§2.9), `parsePortStatus` (§2.10), `parseVLANBrief`
(§2.11), `parseVLANDetail` (§2.12), `parsePVIDs` (§2.13). Real captured
device transcripts, per that test file's header comment (gsm7252ps from
10.1.5.22, m4300-24x from 10.1.5.13, m4300-16x from 10.1.5.20, gsm7228ps/
S3300-52X from 10.1.5.11:60000 telnet) — none synthesized.

## Files, by parser

### `parseVersion` — `show version`
- `gsm7252ps_show_version.txt`
- `m4300_24x_show_version.txt`
- `m4300_16x_show_version.txt`
- `gsm7228ps_show_version.txt`

### `parsePortStatus` — `show port all`
- `gsm7252ps_show_port_all.txt`
- `m4300_24x_show_port_all.txt`
- `m4300_16x_show_port_all.txt` (includes a `lag 1` row — exercises
  `physPort`'s pseudo-interface rejection)
- `gsm7228ps_port_all.txt` (Smart-firmware `1/gN`/`1/xgN` iface names)

### `parseVLANBrief` — `show vlan brief` (gsm7252ps) / `show vlan` (M4300s,
gsm7228ps — the command rename per dossier §1.5/§1.6)
- `gsm7252ps_show_vlan_brief.txt`
- `m4300_24x_show_vlan.txt`
- `m4300_16x_show_vlan.txt`
- `gsm7228ps_vlan.txt` — the actual VLAN summary table gsm7228ps returns
  for `show vlan` (its `CliModelSpec.vlan_brief_cmd` override, dossier
  §1.6); this is the fixture `parseVLANBrief` is exercised against for this
  model.
- `gsm7228ps_vlan_brief.txt` — **not** a table: this SKU's Smart firmware
  genuinely rejects the literal `show vlan brief` command (`"Invalid input.
  Please specify an integer in the range 1 to 4093."`, no ruler line at
  all). Kept as a fixture to pin `parseVLANBrief`'s honest empty-result
  behavior (`iterTableRows` finds no ruler -> zero rows, not an error) on
  malformed/rejected CLI output — this is why the reader must send `show
  vlan`, never the default `vlan_brief_cmd`, for this model.

### `parseVLANDetail` — `show vlan <id>`
- `gsm7252ps_show_vlan_90.txt`
- `m4300_24x_show_vlan_5.txt`
- `m4300_24x_show_vlan_90.txt`
- `m4300_16x_show_vlan_1.txt` (the default VLAN; also has ~128 `lag N` rows
  exercising the same pseudo-interface drop as port-status)
- `m4300_16x_show_vlan_4.txt`
- `m4300_16x_show_vlan_5.txt`

  No gsm7228ps per-VLAN detail fixture exists in the pin (its captured
  sweep only exercises the brief/summary table, not a per-VLAN detail
  page) — `parseVLANDetail` is exhaustively tested against the 3 models
  that do have one; nothing is fabricated for the 4th.

### `parsePVIDs` — `show vlan port all`
- `gsm7252ps_show_vlan_port_all.txt`
- `m4300_24x_show_vlan_port_all.txt`
- `m4300_16x_show_vlan_port_all.txt`
- `gsm7228ps_vlan_port_all.txt`

## Task 4 additions (parsers 2: mac/lldp/poe/environment/mgmt/counters)

Same provenance rule as above: byte-for-byte copies (verified with `cmp`)
from the same pin commit, restricted to the subset Task 4 needs:
`parseMacTable` (§2.14), `parseLLDP` (§2.15), `parsePoE` (§2.16),
`parseEnvironment` (§2.17), `parseMgmtIP` (§2.18),
`parseInterfaceCounters` (§2.19). Real captured device transcripts, per
`test_cli_parse.py`'s header comments — none synthesized.

### `parseMacTable` — `show mac-addr-table`
- `gsm7252ps_show_mac_addr_table.txt`
- `m4300_24x_show_mac_addr_table.txt`
- `m4300_16x_show_mac_addr_table.txt`
- `gsm7228ps_mac_table.txt` (includes the CPU/Management row whose
  interface text has internal spaces — exercises ruler-based slicing over
  naive whitespace splitting; ifIndex 313, not a physical port)

### `parseLLDP` — `show lldp remote-device all`
- `gsm7252ps_show_lldp_remote_device_all.txt` (includes `1/0/6`, a local
  interface printed with no neighbour at all — exercises the Task-2 clamp
  via the "no cells past Chassis ID" drop)
- `m4300_24x_show_lldp_remote_device_all.txt`
- `m4300_16x_show_lldp_remote_device_all.txt` (port 16 has two neighbour
  rows)
- `gsm7228ps_lldp.txt` (only the two 10G uplinks, `1/xg49`/`1/xg51`, have
  neighbours; the 48 `1/gN` access ports print with no remote device)

### `parsePoE` — `show poe port info all`
- `gsm7252ps_show_poe_port_info_all.txt` — 10-column shape, HAS the
  `Temperature` column
- `m4300_16x_show_poe_port_info_all.txt` — 9-column shape, OMITS the
  `Temperature` column (the header-name-lookup regression fixture, dossier
  §2.16 risk #1)
- `gsm7228ps_poe.txt` — 48 PoE-capable access ports (`1/gN`), no PoE on the
  10G uplinks

  No `m4300_24x` PoE fixture exists (nor is one added here): the M4300-24X
  has zero PSE hardware (`poe_port_count == 0`), so the pin's own
  `CliReader.get_poe` gates this model out before ever sending the command
  (dossier §3.7) — there is nothing genuine to capture, and nothing is
  fabricated in its place.

### `parseEnvironment` — `show environment`
- `gsm7252ps_show_environment.txt` — PSU sub-table headed `"Power
  supplies:"`
- `m4300_24x_show_environment.txt` — PSU sub-table headed `"Power
  Modules:"` (the alternate label parseEnvironment must also recognize)
- `m4300_16x_show_environment.txt` — both fans report `"-"` (non-numeric)
  Speed, exercising the "absent, not zero" fan-skip rule
- `gsm7228ps_environment.txt`

### `parseMgmtIP` — `show network` (gsm7252ps/gsm7228ps) / `show ip
management` (M4300s, dossier §1.5/§1.6 command rename)
- `gsm7252ps_show_network.txt` — labels the mode field `"Configured IPv4
  Protocol"`
- `m4300_24x_show_ip_management.txt` / `m4300_16x_show_ip_management.txt`
  — label the SAME field `"Method"` (the alternate label parseMgmtIP must
  also recognize)
- `gsm7228ps_network.txt`

### `parseInterfaceCounters` — `show interface ethernet <iface>`
- `gsm7252ps_show_interface_ethernet_1_0_1.txt` — non-zero counters
- `m4300_24x_show_interface_ethernet_1_0_1.txt` — very large (>1e12)
  64-bit counter values, exercising uint64 range
- `m4300_16x_show_interface_ethernet_1_0_1.txt` — every counter is 0 (a
  down port)

  No `gsm7228ps` per-interface-counters fixture exists in the pin (its
  captured sweep does not include a `show interface ethernet ...` page) —
  `parseInterfaceCounters` is exhaustively tested against the 3 models
  that do have one; nothing is fabricated for the 4th, matching the same
  policy already used for `parseVLANDetail`/gsm7228ps above.
