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
