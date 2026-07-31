# Slice 06 Dossier PART 2: HTTP read/write orchestration + virtual face + facade wiring (Python → Go porting reference)

> **Source of truth:** `/home/tim/github/mithro/python-netgear-switch-library`
> — frozen snapshot worktree:
> `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1841111`
> (read implementation files from the SNAPSHOT path, never the live checkout).
> **Pin guard verified**: `git -C <snapshot> rev-parse HEAD` returns
> `1841111c6d0b55ad3eece915e57ba115a0cfdd12` ("merge: gsm7252ps PoE-over-HTTP
> works — the refusal was OUR malformed body") — starts with `1841111`.
> **PASS.**
>
> **Companion dossier — do NOT duplicate**: `docs/superpowers/plans/
> 2026-07-31-slice-06-dossier-http-protocols.md` (PART 1) already covers the
> pure protocol layer byte-exactly: `protocols/http/{endpoints,parse,forms,
> crypt,session,types}.py` (`LoginScheme`, `HtmlDialect`, `HttpModelSpec`,
> `HTTP_SPECS` for all 8 models, every parser function, every form encoder,
> `crypt.merge`/`merge_hash_md5`) and `transport/http/client.py`
> (`HttpClient`/`AsyncHttpClient`, login/retry/referer machinery). This
> document (PART 2) picks up exactly where Part 1's "Part 2 handoff" section
> leaves off and covers everything layered ON TOP of that protocol
> foundation: `http_read.py`/`http_write.py` orchestration,
> `virtual/faces/http.py` + the byte-faithful `web*.py` renderers, HTTP seed
> data, `server.py` binding, facade dispatch/gating, and the test inventory.
> Cross-references into Part 1 use its own section numbers (e.g. "Part 1 §2.9").
>
> **Go-side context already in place** (confirmed by reading the Go repo
> directly, not inferred): `virtual/snmpface.go`/`virtual/nsdpface.go`
> establish the exact `Start()`/`Stop()` goroutine shape a `virtual/httpface.go`
> must follow (ephemeral bind, `sync.WaitGroup`-tracked serve goroutine,
> idempotent `Stop`). `virtual/server.go`'s `VirtualSwitch` has `HTTPPort int`
> reserved (currently always 0, doc comment explicitly says slice 06 wires
> it) and its `Start()` needs a third independent `if v.modelInfo.HasBackend
> (model.BackendHTTP)` block alongside the existing SNMP/NSDP ones.
> `dispatch.go`/`write_dispatch.go` already implement the NEW single-backend
> (no fallback loop) dispatch from slice-05b — `BackendReader`/`BackendWriter`
> interfaces, `RegisterBackend`/`RegisterWriteBackend`, `resolveBackend`,
> `readVia`/`writeVia`, `cannotServe` — all backend-agnostic; HTTP plugs into
> this exactly as `backend_snmp.go`/`backend_nsdp.go` already do for their
> backends, via a NEW `backend_http.go` shim. `switch.go` already has
> `httpPassword *resolveOnce` (field, `WithHTTPPasswordResolver` option,
> `FromConfig`'s two-independent-closures wiring) fully built and unused —
> slice 06 only needs to *consume* it in `backend_http.go`, not add it.
> `model/registry.go` already lists the 8 HTTP-capable models with
> `BackendHTTP` in `Backends`: `m4300-24x`, `m4300-16x`, `gsm7252ps`,
> `gsm7228ps` (alias `s3300`), `gs110emx`, `gs305ep`, `gs728tpp`, `gs105pe`.
> `model/errors.go` already declares `ErrHTTP`/`ErrHTTPAuth`/
> `ErrHTTPUnexpectedPage` (`errors.Is(err, model.ErrHTTP)` matches either
> specialization). `virtual/state.go`/`virtual/seed.go` already carry
> `HTTPSensors []SensorSim` + `SysinfoSensors()`, `UploadedCert *string`,
> `ScpCertDeploySim{Commands,Copies,HTTPSDisabled,HTTPSEnabled,Saved}` for
> all 8 HTTP models' seeds — but are missing the VLAN-membership-page fields
> this pin's headline fix depends on (see §5.2, the one concrete state-shape
> gap this dossier identifies).

---

## 1. `http_read.py` — `HttpReader` (+ `AsyncHttpReader`)

`src/netgear_switch/http_read.py`, 789 lines. `AsyncHttpReader` (lines
652-789) is a byte-for-byte mirror of the sync class (501-649): every method
body is identical with `await` inserted at each session call — there is no
independent async-only logic to port separately. One historical
sync/async divergence is called out in a comment (689-693) and is now fixed
at this pin: `get_vlans` must check the FASTPATH-dialect branch *before*
checking whether `vlan_membership_path` is `None`, because FASTPATH models
have `vlan_membership_path=None` **by design** (their read-only VLAN *list*
comes from `vlanStatus.html`; the separate membership *page* is reached via
a different spec field). Get this ordering backwards in Go and one of the
two code paths silently breaks while the other still passes.

### 1.1 Dialect dispatch — one `if/elif` chain per op, not a table

There is no separate "dialect registry" beyond the `HttpModelSpec.html_dialect`
field Part 1 §1.2 already documents. Each read op has a private
`_parse_<op>(spec, html) -> ...` dispatcher (lines 126-246) that branches on
small predicate helpers: `_is_gs110emx_dialect`, `_is_gs105pe_dialect`,
`_is_m4300_dialect`, `_is_xe_fastpath_dialect`, `_is_s3300_dialect`,
`_is_goahead_dialect`, plus two composites — `_uses_xe_grid` (XE_FASTPATH or
S3300) and `_is_fastpath_dialect` (M4300 or `_uses_xe_grid`, i.e. all four
"managed" models). Falling through every predicate lands on STANDARD
(gs305ep's plain CGI dialect) as the default.

Full per-op dispatch table (dash = that dialect has no page for this op —
the model's spec field is `None` and the op raises, see §1.5):

| op | GS110EMX | GS105PE | M4300 | XE_FASTPATH (gsm7252ps) | S3300 (gsm7228ps) | GOAHEAD_XML (gs728tpp) | STANDARD (gs305ep) |
|---|---|---|---|---|---|---|---|
| ports | `parse_gs110emx_port_status` | `parse_gs105pe_port_status` | `parse_m4300_port_status` | `parse_xe_port_status` | `parse_xe_port_status` | `parse_goahead_ports` | `parse_port_status` |
| stats | `parse_interface_stats` | `parse_gs105pe_stats` | `parse_m4300_stats` | `parse_xe_stats` | `parse_xe_stats` | — (no `stats_path`) | `parse_port_stats` |
| poe | — (no PSE) | — (no PSE) | `parse_xe_poe` | `parse_xe_poe` | `parse_xe_poe` | `parse_goahead_poe` | `parse_poe_status` |
| pvids | `parse_gs110emx_pvids` | `parse_gs105pe_pvids` | `parse_m4300_pvids` | `parse_xe_pvids` | `parse_xe_pvids` | `parse_goahead_pvids` | `parse_pvids` |
| vlans (list+ids) | `parse_gs110emx_vlan_ids` | via membership branch | `parse_m4300_vlans` | `parse_xe_vlans` | `parse_s3300_vlans` | `parse_goahead_vlans` | `parse_vlan_ids` |
| macs | — | — | `parse_m4300_macs` | `parse_xe_macs` | `parse_s3300_macs` | `parse_goahead_macs` | — |
| lldp | — | — | `parse_xe_lldp` (shared w/ gsm7252ps) | `parse_xe_lldp` | `parse_xe_lldp` | `parse_goahead_lldp` | — |
| sensors | — | — | `parse_m4300_sensors` | `parse_xe_sensors` | **excluded** (`_supports_sensors` false) | `parse_goahead_sensors` | — |
| mgmt-IP | `parse_sysinfo` | `parse_gs105pe_sysinfo` | `parse_m4300_sysinfo` | `parse_xui_mgmt_ip` (priority) else `parse_xe_mgmt_ip` | `parse_s3300_mgmt` | `parse_goahead_mgmt_ip` | `_mgmt_ip_from_sysinfo(parse_sysinfo(...))` |

Notes load-bearing for the Go port:

- `_supports_sensors` (line 178) is a per-model predicate, not just "spec
  field is None" — S3300 is *explicitly excluded* even though it shares
  every other page with XE_FASTPATH: its `sysInfo.html` carries no live
  fan/temp table at all, only a base MAC + a temperature-trap threshold.
- `mgmt_ip_fields` (an `XuiMgmtIpFields` instance, Part 1 §1.3) takes
  PRIORITY over the model's generic sysinfo-derived mgmt-IP parse when
  present — this is the dedicated management-IP CGI/XUI page, more
  authoritative than scraping it out of sysInfo.
- M4300/XE_FASTPATH/S3300 mgmt-IP reads require a **second page fetch** to
  merge in the base MAC (see §1.6) — `_fastpath_base_mac`/
  `_needs_fastpath_base_mac` (lines 451-474) and GoAhead's `_with_base_mac`
  (476-484).

### 1.2 `get_vlans` — the three-way branch that is NOT a simple dispatch call

`get_vlans()` (lines 526-565) is the single most important read method in
this file, and the one that changed behavior at this pin. It is not a
one-line dispatch — it is a three-way branch:

1. **GOAHEAD_XML** (`_is_goahead_dialect`): fetch `vlan_config_path` (VLAN
   names) + `pvid_path` (per-port `JoinVLANList`), combine via
   `parse.parse_goahead_vlans`. VLAN membership on this dialect is derived
   entirely from the PVID page's inline join-list — there is no separate
   membership page for GoAhead at all.
2. **FASTPATH** (`_is_fastpath_dialect` — all four managed models): fetch
   `vlan_config_path` (`vlanStatus.html`) for the VLAN id/name list, then
   call `_with_fastpath_egress` to OVERWRITE `tagged_ports`/`untagged_ports`/
   `member_ports` from the separate per-VLAN "VLAN Membership" page
   (`_fastpath_membership`, §1.3). **This branch is the pin's headline fix**
   — before it existed, `tagged_ports`/`untagged_ports` were always
   `frozenset()` on these four models.
3. **Else (STANDARD/GS110EMX/GS105PE — Plus-class CGI)**: the classic
   `8021qMembe.cgi`-style per-VLAN POST loop (`_membership_form`,
   `_require_csrf_hash`, `_check_membership_is_for`, §1.4).

### 1.3 THE fix: HTTP VLAN-membership reads now work on managed switches (was `None`)

**Before this pin's ancestor commit** (`2daa570`, "feat(http): VLAN-membership
read + write on every managed switch", merged via `e5eaff7`), `endpoints.py`
had `vlan_membership_path=None` for all four FASTPATH models with the comment
"vlanStatus carries the egress list inline". Consequence: `HttpReader.
get_vlans()` on gsm7252ps/gsm7228ps/m4300-24x/m4300-16x read only
`vlanStatus.html`'s "Member Ports" cell into `member_ports`, and **always
returned `tagged_ports=frozenset()`/`untagged_ports=frozenset()`** — exactly
the "was None" behavior this dossier's task brief refers to. `HttpWriter.
set_vlan_membership` correspondingly raised `UnsupportedCapabilityError` for
every managed model.

**The real page was found by reading the firmware's own JS nav tree**
(`GET /base/js/ng_sideNav.js`), after 15 plausible URL guesses 404'd on live
hardware:

```
str+=FrthLvl("lvl2","VLAN Membership",
             "switching/dot1q/vlan_port_cfg.html","none");
```

Wire endpoints (from Part 1's `endpoints.py` treatment, repeated here since
it's the crux of this fix):

```python
_FASTPATH_VLAN_MEMBERSHIP    = "/switching/dot1q/vlan_port_cfg.html"       # GET
_FASTPATH_VLAN_MEMBERSHIP_RW = "/switching/dot1q/vlan_port_cfg_rw.html"    # POST
_M4300_VLAN_MEMBERSHIP       = f"/v1{_FASTPATH_VLAN_MEMBERSHIP}"
_M4300_VLAN_MEMBERSHIP_RW    = f"/v1{_FASTPATH_VLAN_MEMBERSHIP_RW}"
```

Same endpoint serves reads (`submt=0`, re-render only, must NOT mutate
anything) and applies (`submt=16` / `0x10`, the value the firmware's own
`submitform()` JS sets).

#### THE single most important semantic to get right in Go: CURRENT vs CONFIGURED

The page carries **two views of the same VLAN**:

- `hiddenTagged`/`hiddenUnTagged` ifName lists = **CURRENT (operational)**
  egress — equals `show vlan <id>`'s `Current: Include` and
  `vlanStatus.html`'s own "Member Ports" cell.
- `hiddenMem` tri-state string (the grid) = **CONFIGURED** participation —
  equals SNMP's `dot1qVlanStaticEgressPorts`.

These **legitimately disagree** on real hardware: on gsm7252ps VLAN 1, ports
`1/0/50` and `1/0/51` are `Current: Exclude` / `Configured: Include`.

- **Reads report the CURRENT view** (`_with_fastpath_egress`, lines
  335-380) — this REPLACED trusting `vlanStatus.html`'s "Member Ports" cell,
  which was proven (by this fix) to actually report the *configured* set on
  M4300 firmware despite its field name
  (`SwitchingVlanCurrentConfig_VlanCurrentEgressPortList` — the field NAME
  lies about which view it is).
- **Writes set/verify the CONFIGURED view** (`hidden_mem`) — it's the only
  one the form can actually mutate; verifying a write against the CURRENT
  view would flag a perfectly correct write as failed on any link-down port.

**Wire-code inversion trap** — `hiddenMem` codes are `{1: TAGGED, 2:
UNTAGGED, 3: EXCLUDED}` — the **INVERSE** of the Plus-class `8021qMembe.cgi`
codes (`{1: UNTAGGED, 2: TAGGED, 3: EXCLUDED}`, Part 1 §2.3/§3.2). A Go
port must never let these two wire-code tables share an encoder/decoder
function — this is trap #2 in Part 1's own "ten trickiest traps" list, and
it applies with equal force here on the read side.

Two firmware grid encodings both parsed (`_fastpath_grid`):

- **Grid A** (older XE, gsm7252ps): `toggleImageFirst(this,<0-based
  slot>,0,'img_unit<N>',<interface#>)` + `grey_[btu].gif`/`blue_[btu].gif`
  image-state, 0-based `hiddenMem` index.
- **Grid B** (newer jQuery, gsm7228ps/S3300 + both M4300s):
  `aid='port-<ifname>'` + `switch_<state>[_bottom]_inactive.png` +
  `togImg(this,<1-based slot>,0,"hiddenMem")`, 1-based index (parser
  subtracts 1).

Two live-device requirements this fix baked into the transport (both are
Part 1's territory but repeated here because they gate whether this read
path even works):

1. M4300-16X answers `403 Forbidden` to every POST unless an `Origin`
   header accompanies `Referer` — Part 1 §6.6 (`_referer_headers`).
2. FASTPATH pages return **HTTP 200 even when refusing a write**, signaling
   refusal via hidden `err_flag`/`err_msg` fields, surfaced via
   `parse.parse_fastpath_err`/`_raise_on_fastpath_err_flag` (§2.2 below).
   Verbatim example from the fix's commit message:
   `err_msg='Unable to set VLAN membership for VLAN ( 4004 )'` when a port
   is in `access`/`trunk` mode rather than `general`.

`HttpReader.read_fastpath_membership(vlan)` (line 567) and the internal
`_fastpath_membership(vlans)` batch helper (line 586) are the read-side
entry points; `HttpWriter._set_fastpath_membership` (line 693) and
`_read_fastpath_membership` (line 738) are the write-side twins (§2.1).

**Which models are affected**: exactly the four FASTPATH/"managed" models —
`gsm7252ps`, `gsm7228ps`, `m4300-24x`, `m4300-16x`. GS110EMX/GS105PE/GS305EP
(STANDARD/GS110EMX dialects) and GS728TPP (GOAHEAD_XML) were never affected
— their membership read paths are unrelated to this fix and were already
correct.

### 1.4 Plus-class (STANDARD/GS105PE) membership quirks — unchanged at this pin, but load-bearing

`_membership_form` (lines 249-266): every model needs `VLAN_ID`, but
gs110emx additionally needs `vlanIdSel` (its `vlanMembership.html` returns
an EMPTY body without it), and gs105pe needs the per-page CSRF `hash` riding
along (its `8021qMembe.cgi` "ignores `VLAN_ID`... returning VLAN 1 every
time" without it). `ACTION` is deliberately never sent on a *read* POST — a
non-empty `ACTION` would apply a change.

`_require_csrf_hash` (line 269) raises `HttpUnexpectedPageError`, verbatim:

```
"8021qMembe.cgi: no CSRF 'hash' field -- without it the switch "
"ignores VLAN_ID and every VLAN would report the selected VLAN's "
"membership"
```

`_check_membership_is_for` (line 285, gs105pe only) raises:

```python
f"8021qMembe.cgi: asked for VLAN {vid} but the page shows VLAN "
f"{shown} -- refusing to report the wrong VLAN's membership"
```

### 1.5 `reads_verified` gating — construction-time, not per-call

There is **no separate "http_reads_supported" table** distinct from the
`HttpModelSpec.reads_verified: bool` field Part 1 §1.4/§1.5 already
documents field-by-field. The gate function (lines 55-59):

```python
def _require_verified_reads(spec: HttpModelSpec) -> None:
    if not spec.reads_verified:
        raise UnsupportedCapabilityError(
            f"model {spec.model_key!r} HTTP reads are UNVERIFIED-pending-capture"
        )
```

Called from **both** `HttpReader.__init__` (line 506) and
`AsyncHttpReader.__init__` (line 657) — **construction itself fails** for an
unverified model; there is no per-op re-check after that. At this pin,
EVERY registered spec has `reads_verified=True`, including `gs728tpp` and
`gsm7228ps` (both flipped to verified in earlier commits) — the module's own
example docstring naming "gsm7228ps cheetah/S3300 as unverified" is now
stale prose left over from an older pin; do not port that comment's example
as if it were still true. `HttpWriter`/`AsyncHttpWriter` do **not** gate on
`reads_verified` at all — writer construction always succeeds; individual
write ops raise `UnsupportedCapabilityError` per missing path via
`_require_path` instead (§2, and see §7.2 for exactly where this check sits
relative to session/password resolution in `sync_api.py`).

One level up, `endpoints.http_spec(model)` gates on the `Backend` enum
itself (not `HttpModelSpec`): `UnsupportedCapabilityError(f"model
{model.key!r} has no HTTP backend")` if `Backend.HTTP not in model.backends`,
or `f"model {model.key!r} has an HTTP backend but no endpoint spec"` if the
key isn't in `_SPECS` (currently unreachable — every HTTP-backend model has
a spec — but a real defensive check, not dead code).

### 1.6 Unsupported-op error messages (read side, verbatim)

- Missing page for an op (`_unsupported`/`_require_path`, lines 62-72):
  ```python
  f"model {model_key!r} web UI does not expose {op}"
  ```
  **Note this string DIFFERS from the write-side equivalent** (§2) — a
  companion commit (`1f2666b`) deliberately reworded the write-side
  `_require_path` message but left this read-side one unchanged at this
  pin. This is a latent inconsistency in the Python source; the Go port
  should pick ONE consistent message shape rather than reproducing both
  verbatim strings, and should say so in a doc comment (this dossier
  recommends following the more informative write-side wording — see §2 —
  for both, since CLAUDE.md principle 4's "no fabricated device
  limitations" concern applies equally to reads).
- Unverified reads: `f"model {spec.model_key!r} HTTP reads are
  UNVERIFIED-pending-capture"` (§1.5).
- `get_sensors` when `_supports_sensors` is false: `_unsupported(model.key,
  "box sensors")` → `"model {model_key!r} web UI does not expose box
  sensors"`.
- `get_mgmt_ip` when both `mgmt_ip_path` and `sysinfo_path` are `None`:
  `_unsupported(model.key, "management-IP config")`.

### 1.7 Shared model-dataclass mapping quirks (consolidated)

These apply to `model.PortStatus`/`PoEStatus`/`VLANInfo`/`LLDPNeighbor`/
`MacEntry`/`Sensor`/`PortStats`/`MgmtIPConfig` — the SAME Go types
`dispatch.go`'s `BackendReader` interface already returns (see this repo's
`model/types.go`, read directly — every field below maps 1:1 onto a field
already present there, no shared-type changes needed):

- **`PortStatus.Description`** — HTTP (like NSDP) always leaves this `nil`;
  only SNMP reads `ifAlias`.
- **`PoEStatus.PowerMw`** — requires firmware-variant unit disambiguation
  (Part 1 §2.7's `_poe_power_to_mw`): gsm7252ps renders integer milliwatts
  ("3500"→3500mW), M4300-16X renders decimal watts under the SAME "(mW)"
  column header ("4.60"→4600mW); disambiguated by presence of a decimal
  point, never by model.
- **`PoEStatus.Detect`** — GoAhead's `detectionStatus` code 6 ("OtherFault")
  and XE's free-text "Other Fault" both fold into `PoEDetectFault`; GoAhead
  code 5 ("Test") has no RFC3621 equivalent and is skipped, not mapped.
- **`VLANInfo.TaggedPorts`/`UntaggedPorts`** — empty ONLY when a caller
  somehow bypasses the fix in §1.3 (e.g. reading `vlanStatus.html` alone
  without the membership merge); the correct Go port always merges per
  §1.2-§1.3. GoAhead populates all three sets from the PVID page's inline
  `JoinVLANList`.
- **`LLDPNeighbor.RemotePortDesc`** — honestly `nil` on XE_FASTPATH
  (`lldpRemoteInventory.html` has no such column) and on GS110EMX/Plus (no
  LLDP at all); GoAhead does supply it.
- **`LLDPNeighbor.RemoteChassisID`/`RemotePortID`** — GoAhead's
  `_canon_lldp_id` upper-cases a colon-hex MAC-subtype ID to match SNMP's
  canonical formatting; a non-MAC id (plain interface-name string) passes
  through unchanged.
- **`MacEntry`** — every FASTPATH/M4300/S3300 parser explicitly SKIPS
  non-physical-port entries (LAG pseudo-interfaces, service/CPU interfaces
  like `0/5/1` or S3300's `c1`) rather than mis-attributing them. This means
  the HTTP FDB legitimately differs from the SNMP FDB by exactly the
  switch's own base-MAC entry (learned on the CPU ifIndex in SNMP, dropped
  in HTTP) — an EXPECTED, documented divergence, not a bug to "fix" by
  matching SNMP exactly.
- **`Sensor`** — several dialects report HEALTH STATE, not a physical
  reading, because the page only renders text like "OK"/"Operational":
  encoded as `Unit="state"`, `Value=1.0` (healthy) / `0.0` (any other
  reported state); an ABSENT slot (blank/"NA"/"N/A"/GoAhead status code 5)
  is SKIPPED ENTIRELY, never reported as `0.0` — absence is not failure.
  Applies to XE fan/PSU sensors and GoAhead fan/PSU sensors. M4300 sensors
  are temperature-only (no fan block — SNMP is the sole fan-RPM source for
  M4300); temperature-limit/threshold rows ("Max Operating Temperature")
  are explicitly excluded from being reported as a live reading.
- **`MgmtIPConfig.Mode`** — several dialects (M4300 sysInfo, XE sysInfo,
  S3300 sysInfo, GoAhead IPConf) carry no DHCP/static indicator at all →
  `model.IPModeUnknown` rather than a guess. Only the dedicated XUI
  mgmt-IP pages (via `XuiMgmtIpFields.Mode`) and the two CGI dialects know
  the mode.
- **`MgmtIPConfig.BaseMac`** — assembled via a SECOND page fetch on
  several dialects (§1.1): FASTPATH XUI mgmt pages carry no MAC at all
  (merged from `sysinfo_path`); GoAhead's IPConf page likewise has none
  (merged from the separate SystemInfo page). M4300's mgmt page DOES render
  a MAC (`v_4_4_1`) but it is explicitly NOT used — it's the
  management-interface MAC, "one off" from the base MAC SNMP reports
  (`dot1dBaseBridgeAddress`); using it would break cross-backend parity.
  All base-MAC values are upper-cased to match SNMP/NSDP formatting
  (captured HTML text is lowercase).

---

## 2. `http_write.py` — `HttpWriter` (+ `AsyncHttpWriter`)

`src/netgear_switch/http_write.py`, 1348 lines. Same sync/async mirroring
convention as §1 (lines 496-987 sync, 989-1348 async, line-for-line
`await`-inserted mirror).

`_require_path` error string (lines 278-297) — **the wording the Go port
should standardize on for BOTH read and write** (see §1.6):

```python
f"model {model_key!r} has no {op} page in its HTTP endpoint spec "
"(see protocols/http/endpoints.py for whether that is a measured "
"absence or an undiscovered page)"
```

This wording was deliberately chosen by a companion commit (`1f2666b`,
"stop claiming 'the web UI does not expose X' for a spec gap") after
auditing all 62 `UnsupportedCapabilityError` sites in this file: a `None`
path can mean either a MEASURED absence (e.g. gs110emx's ~39 enumerated
pages genuinely have no PoE/LLDP/MAC page, confirmed by live probing) or a
merely UNDISCOVERED one (switch was unreachable during capture) —
conflating the two violates this project's "no fabricated device
limitations" rule (CLAUDE.md principle 4). Port this wording, not the
read-side's older/vaguer string.

### 2.1 Per-write-op tabulation

| op | Managed FASTPATH mechanism | Plus/STANDARD mechanism | GS110EMX mechanism | Verify-after-write |
|---|---|---|---|---|
| `SetPoE` | `_xui_poe_admin`: `poeInterfaceConfiguration.html` row, column `v_1_2_2`, button `v_2_1_2`, `omit=_XUI_POE_APPLY_OMITS` | `PoEPortConfig.cgi`, `forms.poe_apply_form` | — (no PSE) | Re-GET `poe_status_path`, compare `admin_enabled` |
| `CyclePoE` | `_xui_poe_reset`: same page, column `v_1_2_20`="Reset", button via `_poe_reset_button`, `omit=_XUI_POE_RESET_OMITS` | `poe_reset_form` on `poe_config_path` | — | none (write-only field) — only `err_flag` check |
| `ClearPoEFault` | identical FASTPATH mechanism as `CyclePoE` | identical Plus mechanism as `CyclePoE` (re-running detection *is* the fault clear) | — | same |
| `SetPVID` | routes through the STANDARD path — no FASTPATH-specific PVID *write* built at this pin; only `pvid_path` GET/POST | `pvid_form`, re-GET + `parse_pvids` | same path | `WriteVerificationError` on readback mismatch |
| `SetVlanMembership` | `_set_fastpath_membership`: `vlan_port_cfg_rw.html`, replaces one `hidden_mem` slot via `fastpath_hidden_mem_with`, `submt=16`, verifies against `.configured` view (NOT current, §1.3) | `8021qMembe.cgi` 3-step POST (read→apply→verify), `membership_hidden_mem` builds the full 1/2/3 string | routes via `_is_fastpath_dialect` false → STANDARD path | `WriteVerificationError` |
| `CreateVlan`/`DeleteVlan` | no FASTPATH-specific create/delete; routes to `vlan_config_path` `8021qCf.cgi`-style forms `vlan_add_form`/`vlan_delete_form` | same | same | readback `parse_vlan_ids` contains/excludes vid |
| `Reboot` | `_require_path(reboot_path)`; **`nil` for gsm7252ps/gsm7228ps/m4300-24x/m4300-16x — never captured, still unsupported** | `device_reboot.cgi` (gs305ep/gs105pe only) | `sys_reload.html` (own mechanism) | none — capability-then-force gate only |
| `SetPortEnabled` | **NEW at 1841111**: `portsConfiguration.html` Admin Mode `v_1_2_6`, button `v_2_1_2`, no `omit` | still `UnsupportedCapabilityError` (`port_config_path=nil` — no Plus-class impl at this pin) | **NEW at 1841111**: `_set_gs110emx_port_enabled` via `port_settings.html`, own mechanism/form | Re-GET row, compare Admin Mode cell |
| `SetMgmtIP` | **NEW at 1841111**: per-model `XuiMgmtIpFields` on `mgmt_ip_path`, `submit_flag=8` apply | still `UnsupportedCapabilityError` (`_require_xui_mgmt_fields`, no Plus-class impl) | still `UnsupportedCapabilityError` (no `mgmt_ip_path`/fields wired for this dialect) | Re-GET, compares (address,netmask,gateway) — **the APPLY itself is deliberately NOT live-verified**, see §2.7 |
| Cert upload | GOAHEAD_XML→raw-XML POST (gs728tpp); multipart (gsm7228ps); m4300-24x/m4300-16x/gsm7252ps → `NotImplementedError` (SCP-only, §2.4) | multipart if `cert_upload_path` set, else `UnsupportedCapabilityError` | `UnsupportedCapabilityError` (no `cert_upload_path`) | response-body check only, no readback |

### 2.2 `_raise_on_fastpath_err_flag` — the "HTTP 200 that actually failed" guard

`http_write.py:312-334`. FASTPATH pages answer HTTP 200 even when refusing a
write, via hidden `err_flag=1`/`err_msg` fields parsed by
`parse.parse_fastpath_err` (Part 1 §2.9). Every FASTPATH apply in this
module is wrapped: `_raise_on_fastpath_err_flag(applied, "<what>")` raises
`HttpError(f"switch refused {what}: {flag}")` on a nonzero flag. Verbatim
live example from a docstring:

```
err_flag=1
err_msg='Unable to set VLAN membership for VLAN ( 4004 )'
```

A Go port MUST check this on every FASTPATH apply — an HTTP 200 status code
alone is never sufficient proof of success for these four models.

### 2.3 SSL certificate upload — full detail

**`CERT_UPLOAD_KNOWN_UNIMPLEMENTED`** (lines 84-99) — a `map[string]string`
keyed by registry model key → human mechanism name:

```python
{
    "m4300-24x": "SCP file-copy to the switch (FastpathScpUpdater)",
    "m4300-16x": "SCP file-copy to the switch (FastpathScpUpdater)",
    "gsm7252ps": "SCP file-copy to the switch (copy scp://)",
}
```

These three keys are exactly the FASTPATH members of `registry.
SCP_CERT_PROFILES` (defined in `protocols/cli/commands.py`, slice-07
territory, out of scope here). `_reject_known_unimplemented_cert_upload`
(106-115) raises `NotImplementedError` — deliberately **NOT**
`UnsupportedCapabilityError**`, because the hardware genuinely CAN load a
cert, just not over THIS transport:

```python
f"SSL-certificate upload for {model_key!r} uses {mechanism}, which "
"this HTTP writer does not perform; use "
"SyncSwitch.upload_certificate_scp instead"
```

`gs728tpp` USED to be in this map but is now implemented via the GoAhead XML
path (see below) — a Go port porting this map should NOT include gs728tpp.

**`_rsa_pkcs1_pair`** (lines 146-185) — GS728TPP's crypto conversion,
mirroring a `GS728TPPUpdater._convert_to_rsa_format`-shaped transform but via
the `cryptography` package instead of shelling out to `openssl rsa
-traditional`/`-RSAPublicKey_out`:

```python
private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
# raises ValueError if not isinstance(private_key, rsa.RSAPrivateKey)
private_pkcs1 = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,   # PKCS#1
    encryption_algorithm=serialization.NoEncryption(),
).decode()
public_pkcs1 = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1,
).decode()
```

**Go mapping** (stdlib only, no third-party crypto needed):
- Input parse: `pem.Decode` then `x509.ParsePKCS1PrivateKey` (try this
  first; PKCS#1) or `x509.ParsePKCS8PrivateKey` then type-assert
  `*rsa.PrivateKey` (reject any other key type — EC/Ed25519/DSA — with a
  clear "requires an RSA private key; got %T" error). Python's
  `password=None` in `load_pem_private_key` implicitly rejects an
  encrypted PEM (raises `TypeError`/`ValueError`); Go's `x509` parse
  functions likewise just fail on an encrypted block (no separate
  "encrypted" detection needed — a Go port should try `x509.
  DecryptPEMBlock`-free parsing and treat any parse failure as "could not
  parse the private key as an unencrypted PEM: %w").
- `PrivateFormat.TraditionalOpenSSL` (PKCS#1 `RSAPrivateKey` ASN.1 inside
  `-----BEGIN RSA PRIVATE KEY-----`) = Go's `x509.MarshalPKCS1PrivateKey`
  + `pem.Encode` with `Type: "RSA PRIVATE KEY"`.
- `PublicFormat.PKCS1` (RSA public key as `RSAPublicKey` ASN.1) = Go's
  `x509.MarshalPKCS1PublicKey` + `pem.Encode` with `Type: "RSA PUBLIC
  KEY"`.
- No encryption on the output private key (`NoEncryption()` = unencrypted
  PEM) — Go's `pem.Encode` never encrypts by default, so nothing extra
  needed there.

Error messages to preserve (verbatim strings, adapt `%r`→`%q`/`%v` for Go):
```python
f"could not parse the private key as an unencrypted PEM: {exc}"
f"GS728TPP SSL-certificate upload requires an RSA private key; got {type(private_key).__name__}"
```

**`_build_gs728tpp_cert_xml`** (lines 188-205) — exact XML template, only
the cert/pubkey/privkey PEM blocks are variable, each XML-escaped via
`xml.sax.saxutils.escape` with extra entities `{'"': "&quot;", "'":
"&apos;"}` (Go: `xml.EscapeText` handles `<>&` but NOT quote/apostrophe by
default — a Go port must add those two replacements manually, or use
`text/template` with `html/template`-style escaping disabled in favor of a
literal `strings.NewReplacer` matching Python's exact entity set):

```python
"<?xml version='1.0' encoding='utf-8'?>"
"<DeviceConfiguration>"
'<SSLCryptoCertificateImportList action="set">'
"<Entry><instance>1</instance>"
f"<certificate>{esc(cert_pem)}</certificate>"
f"<publicKey>{esc(public_pem)}</publicKey>"
f"<privateKey>{esc(private_pem)}</privateKey>"
"</Entry></SSLCryptoCertificateImportList>"
"</DeviceConfiguration>"
```

Posted via `session.post_xml(path, body)` where `path = spec.
cert_upload_path = "wcd"` for gs728tpp.

**`_check_goahead_upload_response`** (lines 251-268) — checks
`<statusCode>0</statusCode>` (regex `_UPLOAD_STATUS_RE = re.compile(r"<statusCode>(\d+)</statusCode>")`);
missing `<statusCode>` raises:

```
"GS728TPP cert upload: response carried no <statusCode> "
"(unexpected page -- not logged in, or wrong endpoint?)"
```

Non-zero code extracts `<statusString>` via a companion regex and raises:

```python
f"GS728TPP cert upload failed (statusCode={match.group(1)}): {reason}"
```

**S3300/gsm7228ps multipart path** — `_cert_upload_multipart` (lines
124-143) combines cert+key PEM into ONE file (`_combine_cert_key_pem`:
`cert + "\n" + key`), filename constant `_CERT_FILENAME =
"certificate.pem"`, uploaded as field `spec.cert_upload_file_field =
".v_1_3_1_handle"` to `spec.cert_upload_path =
"/http_file_download.html/a1"`, `content_type="application/octet-stream"`,
plus a large fixed `cert_upload_form_fields` map hard-coded at
`endpoints.py:566-591` (~20 required hidden fields: `submit_flag`,
`submit_target`, `err_flag`, `err_msg`, `clazz_information`, etc. — see
Part 1 §1.5's gsm7228ps section for the field-by-field spec dump).
`_check_multipart_cert_response` (lines 231-248) checks the RESPONSE BODY,
not status code — success marker is the literal substring "completed
successfully" (case-insensitive); on failure extracts an `error...` snippet
via regex or falls back to "no 'completed successfully' marker":

```python
raise HttpError(f"S3300 SSL-certificate upload was not accepted: {reason}")
```

### 2.4 `_vlan_checkbox_index` (line 489-493)

```python
def _vlan_checkbox_index(html: str, vlan: int) -> int | None:
    for m in re.finditer(r'name="vlanck(\d+)"[^>]*value="(\d+)"', html):
        if int(m.group(2)) == vlan:
            return int(m.group(1))
    return None
```

Scans STANDARD-dialect `8021qCf.cgi` checkbox inputs named `vlanck<N>` whose
`value` is the VLAN ID, returns the `<N>` index whose value matches the
target VLAN — used by `DeleteVlan` to build `vlan_delete_form(checkbox_index=
idx, ...)`. No match → `DeleteVlan` raises `HttpUnexpectedPageError(f"VLAN
{vlan} not present to delete")`.

### 2.5 GS110EMX port-admin write specifics

`_set_gs110emx_port_enabled` (lines 846-882) is a genuinely DIFFERENT
mechanism from the FASTPATH XUI grid: this page has no admin column at all;
disabling means POSTing "Physical Mode" as `PORT_CTRL_MODE=3` ("Disable"),
enabling as `PORT_CTRL_MODE=1` ("Auto"). `gs110emx_port_admin_form` (Part 1
§3.5) requires `PORT_NO` be **semicolon-terminated** (`f"{port};"`) — a bare
number is accepted with HTTP 200 but silently applies nothing, "caught live
on 10.1.5.25 by the verify-after-write, which is exactly what that check is
for." `FLOW_CONTROL_MODE` must be echoed from the port's CURRENT row
(scraped via `parse_gs110emx_port_form_fields`), never defaulted, or the
write silently rewrites flow control as a side effect. This is a genuine
firmware footgun a Go port must faithfully reproduce (semicolon suffix
required), not "fix" by being lenient.

### 2.6 THE gsm7252ps PoE fix — exact root cause (CRITICAL, this pin's namesake commit)

**Merge commit `1841111` itself** (HEAD), merging `bf33fad` "fix(http):
gsm7252ps PoE writes work — the refusal was our missing list-unit field"
into `1f2666b`.

#### Prior (wrong) belief, and why it looked correct

Before this fix, `endpoints.py`'s `_GSM7252PS` spec had
`poe_config_path=None` with a comment claiming the PoE form "REFUSES every
write." This was backed by REAL live evidence: a byte-identical form
builder (`xui_row_apply_form`) that successfully applied writes on the
sibling gsm7228ps and both M4300s got HTTP 200 + `err_flag=1` on
gsm7252ps, listing one `Error! Failed to Set '<column>' with '<value>'`
line PER read-write column — even for a no-op body. That genuinely looked
like a device-side refusal.

#### Actual root cause: a client-side malformed POST body

gsm7252ps's `poeInterfaceConfiguration.html` PoE rows carry NO hidden
"Unit" key column (`v_1_2_21`, `xk_1_2_21=1`, `xeleName="Unit"`) — unlike
gsm7228ps's and both M4300s' rows, which ARE self-identifying via that
column. Because the row itself doesn't identify its unit, this firmware
instead resolves the write's list scope from a PAGE-LEVEL field:
`urlListUnit`, rendered in the page's `class=deftestme` navigation rows
(the "Go To Port" bar), aliased in the firmware's own JS as
`xeData["xalias_urlListUnit"] = "1_1_1|1_3_1|3_1_1|3_4_1"`. These are
ENABLED hidden inputs — a real browser submits them on every apply — but
`xui_row_apply_form` (at the time) dropped them entirely, since it only
sent the target row + tokens + hidden redirection block, never the nav
block.

Live one-field A/B test on 10.1.5.22 port 1/0/35, bodies byte-identical
otherwise:

```
no unit field  -> HTTP 200, err_flag=1, "Failed to Set 'Admin Mode' ... 'Port Reset'"
+ v_1_1_1      -> err_flag=0, admin Disable -> Enable APPLIED
+ v_1_3_1      -> err_flag=0 (the alias also works)
+ v_1_1_2 only -> the same refusal (so it is NOT a type filter)
```

**Two secondary findings baked into the fix**, read from the firmware's own
`/scripts/_xe_poeInterfaceConfiguration.js`: each button's action array
carries shed lists at indices 14 (disable-on-click)/15 (enable-on-click),
enforced via `xuiShed(2, ...)` → `disabled=true`, so a real browser never
submits those inputs for that button:

```
xa_2_1_2 (APPLY) disable = "1_2_20|g_1_2_20"                             -- an APPLY must OMIT the write-only Port Reset column
xa_2_1_3 (RESET) disable = "1_2_2|1_2_3|...|1_2_18|g_1_2_2|...|g_1_2_18" -- a RESET must OMIT the config columns
```

Encoded as `_XUI_POE_APPLY_OMITS = (_XUI_POE_RESET,)` and
`_XUI_POE_RESET_OMITS = tuple(f"v_1_2_{n}" for n in range(2, 20))`
(`http_write.py:392-393`), threaded through a new `omit=` parameter on
`xui_row_apply_form` (Part 1 §3.4).

#### Code changes this fix comprises (map onto the Go port's own equivalents)

- `types.py`/`parse.py`: `XuiListPage.nav` field + parsing for the
  `deftestme` nav-row fields (Part 1 §2.8/§5.3).
- `forms.xui_row_apply_form` gains `body.update(page.nav)` and the `omit`
  parameter (Part 1 §3.4).
- `http_write.py`: `_XUI_POE_APPLY_OMITS`/`_XUI_POE_RESET_OMITS`
  constants; `_xui_poe_admin`/`_xui_poe_reset` (both sync and async) pass
  `omit=` to `xui_row_apply_form`.
- `endpoints.py`: `_GSM7252PS.poe_config_path` and `.poe_status_path`
  flipped from `None` to `_FASTPATH_POE_CONFIG`
  (`/poeInterfaceConfiguration.html`) — this is the literal one-line "the
  bug was OUR malformed body, not a device limitation" diff.
- `CERT_UPLOAD_KNOWN_UNIMPLEMENTED` comment updated to clarify gsm7252ps's
  cert upload is SEPARATELY SCP-only (unrelated to this PoE fix — don't
  conflate the two when porting comments).

Live-verified 2026-07-31 on gsm7252ps 10.1.5.22 port 1/0/35 (all four PoE
ops + `set_port_enabled`), plus regression checks on gsm7228ps port 12 and
m4300-16x port 15 to confirm the nav-block change didn't break the models
that were already working (their rows are self-identifying via the Unit
column, so they tolerate the nav block riding along harmlessly).

**Go-port implication**: `PoeCycleTimeouts`/`SetPoE`/`CyclePoE`/
`ClearPoEFault` on the HTTP backend's `gsm7252ps` writer path MUST include
the page's `nav` fields in every XUI apply body, and MUST apply the correct
`omit` set per button (APPLY vs RESET) for every managed model — not just
gsm7252ps. Getting the omit set wrong for gsm7228ps/M4300 (which don't
strictly need the nav-field fix) would not surface as a test failure today
since those rows self-identify, but a regression there would look
IDENTICAL in symptom to a gsm7252ps regression (HTTP 200 + `err_flag=1` +
per-column error text) — so Go tests must cover all four models' apply/reset
paths independently, per the counter-example test design in Python's
`tests/test_http_xui_writes.py` (§8).

### 2.7 `set_port_enabled`/`set_mgmt_ip`/`clear_poe_fault` — prior UnsupportedCapability → implemented

**Commit `cc11d7e`** ("feat(http): close the set_port_enabled / set_mgmt_ip
/ clear_poe_fault gaps", merged via `cd08f9b`). Module docstring
(`http_write.py:10-13`) states plainly: "`set_port_enabled`, `set_mgmt_ip`
and `clear_poe_fault` used to raise `UnsupportedCapabilityError` for EVERY
model. They were missing implementations, not device limitations."

| op | status per model at this pin |
|---|---|
| `SetPortEnabled` | managed FASTPATH (gsm7252ps/gsm7228ps/m4300-24x/m4300-16x): **implemented**, live-verified disable→re-read→enable→re-read on all four. GS110EMX: **implemented**, own `port_settings.html` mechanism, live-verified 10.1.5.26. Plus-class CGI (gs305ep/gs105pe): **still `UnsupportedCapabilityError`** — `port_config_path=nil` in every Plus-class spec, genuinely no implementation at this pin. |
| `ClearPoEFault` | managed models: **implemented**, reuses the same hidden write-only "Port Reset" column mechanism as `CyclePoE` (RESET button scraped via `_poe_reset_button`). Plus-class: **implemented**, reuses `PoEPortConfig.cgi` reset — "it used to raise even though the mechanism was already implemented next door as cycle_poe" (pure missing-method gap, no new device investigation needed). GS110EMX: no PSE, genuinely unsupported. |
| `SetMgmtIP` | managed FASTPATH: **implemented**, per-model `XuiMgmtIpFields`-driven form. **Deliberately NEVER live-verified against real hardware** (see caveat below). GS110EMX/Plus-class: **still `UnsupportedCapabilityError`**. |

Three corrected wrong beliefs (measured, from `cc11d7e`'s commit message —
port these as doc-comment corrections, not silent fixes, in the Go spec
table):

1. gsm7228ps mgmt-IP is NOT unreachable over HTTP — `/ipConfiguration.html`
   returns 200 with everything.
2. M4300 mgmt-IP lives on `mgmtVlanIpv4Configuration.html`, NOT
   `ipConfiguration.html` (the latter is the unused service port, always
   reads `0.0.0.0` on both SKUs).
3. `/mgmtVlanIpv4Configuration.html` 404s on both gsm72xx models, so the
   two families require genuinely SEPARATE `XuiMgmtIpFields` constants,
   never a shared one.

**The `SetMgmtIP` "unverified apply" caveat — preserve this as documented
scope, not silent equal-confidence with the other writes**: the docstring
(`http_write.py:884-907`) is explicit about what IS proven live (page
existence/correctness, field names/values via `get_mgmt_ip` readback, the
surrounding apply machinery shared with `SetPortEnabled`/
`SetVlanMembership`) vs what is NOT (the actual APPLY outcome — applying it
for real would move a reachable switch's own management address mid-session
and risk stranding it). The verify-after-write code path IS real and WILL
fire if the switch refuses via `err_flag`, but there is no positive live
confirmation the address actually changes. **The Go port's tests/docs for
`SetMgmtIP` on managed models should carry the same caveat explicitly** —
do not claim this path is "tested" in the same sense as
`SetPortEnabled`/`SetVlanMembership`.

---

## 3. `virtual/faces/http.py` — `VirtualHttpFace`

`src/netgear_switch/virtual/faces/http.py`, 703 lines.

### 3.1 Structure, bind/serve/stop — mapping to Go's `net/http`

Single class `VirtualHttpFace` (line 129). No module-level handler class —
`start()` (lines 167-170) defines a LOCAL `Handler(BaseHTTPRequestHandler)`
class closing over `face = self`, so all per-request state lives on the
outer `VirtualHttpFace` instance.

Constructor: `host: str = "127.0.0.1"`, `port: int = 0` (ephemeral, same
convention as `SnmpFace`/`NsdpFace`), `password`, `rand` (default nonce
`"1234"`), `spec: HttpModelSpec`, `state: VirtualSwitchState`.

Bind (lines 400-406):

```python
server = ThreadingHTTPServer((self.host, self.port), Handler)
self._server = server
self._thread = threading.Thread(
    target=server.serve_forever, name="virtual-http-face", daemon=True
)
self._thread.start()
return int(server.server_address[1])
```

`ThreadingHTTPServer.__init__` binds+listens SYNCHRONOUSLY (stdlib
`TCPServer.__init__` calls `server_bind`+`server_activate` before
returning), so `start()` can safely read back the bound port on the calling
thread with no race — exactly the property `net.ListenTCP` + `go f.serve()`
already gives Go's `SnmpFace.Start()`/`NsdpFace.Start()`.

Stop (lines 693-702):

```python
def stop(self) -> None:
    if self._server is not None:
        self._server.shutdown()
    if self._thread is not None:
        self._thread.join(timeout=5)
        self._thread = None
    if self._server is not None:
        self._server.server_close()
        self._server = None
```

Order: (1) `shutdown()` unblocks the accept-loop's select; (2)
`thread.join(timeout=5)` waits for the accept loop to actually exit; (3)
`server_close()` closes the listening socket — deliberately AFTER the loop
has returned, to avoid a spurious error inside the loop from a closed fd.
**Not handled**: in-flight PER-REQUEST handler threads (`ThreadingMixIn`
spawns one thread per accepted connection) — `shutdown()`/`join()` only
stop the ACCEPT loop, not any already-dispatched request-handler thread;
`stop()` can return while a slow handler is still running.

**Go mapping** (`net/http.Server` on `127.0.0.1:0`):

```go
type HTTPFace struct {
    // fields mirroring SnmpFace/NsdpFace's shape: state, spec, host, mu, wg
    srv      *http.Server
    listener net.Listener
}

func (f *HTTPFace) Start() (port int, err error) {
    ln, err := net.Listen("tcp", net.JoinHostPort(f.host, "0"))
    // ... construct srv with a handler closing over f, srv.Serve(ln) on a goroutine
}

func (f *HTTPFace) Stop() error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    err := f.srv.Shutdown(ctx) // waits for the goroutine + in-flight handlers
    f.wg.Wait()
    return err
}
```

Note the ONE behavioral difference worth flagging explicitly in a Go doc
comment rather than silently "fixing": Go's `http.Server.Shutdown(ctx)` DOES
wait for in-flight handlers to finish (stronger than Python's
`ThreadingHTTPServer.shutdown()`, which only stops new-connection
acceptance). This is a strict improvement for the Go port's determinism
(matches the "deterministic Stop like SnmpFace/NsdpFace" requirement this
dossier's task brief calls for) and should be embraced, not fought — just
document that it is not byte-for-byte identical to the Python original's
laxity.

### 3.2 All 5 login handshakes

Routing: every GET first checks `HtmlDialect.GOAHEAD_XML` (routes entirely
to `_goahead_get`, handshake 5); otherwise if `path == spec.login_path`
renders the login page (`web_gs110emx.render_login` if
`session_token_field is not None`, else `web.render_login`). Every POST
computes `login_post_path = spec.login_post_path or spec.login_path` and
routes to `_login_response(form)` if matched.

`_login_response` (lines 675-691) is the SINGLE validation function for 4 of
the 5 schemes:

```python
def _login_response(self, form: dict[str, str]) -> str:
    field = self.spec.password_field
    supplied = form.get(field, "")
    if self.spec.scheme in (LoginScheme.CHEETAH_FORM, LoginScheme.CHEETAH_V1):
        ok = supplied == self.password
        if self.spec.username_field is not None:
            ok = ok and form.get(self.spec.username_field, "") == self.spec.username
    else:
        ok = supplied == merge_hash_md5(self.password, self.rand)
    return "OK" if ok else "Login failed"
```

**1. `MERGE_HASH_CGI`** — `gs305ep`, `gs105pe`. Cookie session
(`cookie_name="SID"`), `needs_rand=True`.
- GET `login_path` (`/login.cgi`) → `web.render_login(rand)`:
  ```python
  f"<html><body><form>"
  f'<input type="hidden" id="rand" name="rand" value="{rand}">'
  f'<input type="hidden" name="hash" value="{_HASH}">'
  f"</form></body></html>"
  ```
  where `_HASH = "virtualhash"` (see §4.1 — a fixed literal, never actually
  validated by the face's login check).
- POST `login_path` with form field `password = merge_hash_md5(real_password,
  rand)`.
- Response: `"OK"`/`"Login failed"` body, status 200 either way;
  `Set-Cookie: SID=virtualsid; path=/` sent ONLY on success.
- **No server-side session table** — the mock never re-checks the `Cookie`
  header on later STANDARD-dialect requests; "login" is purely a
  password-hash gate on the login POST itself.

**2. `GAMBIT`** — `gs110emx` only. Token session (`session_token_field=
"Gambit"`, no cookie).
- GET `login_path` (`/`) → `web_gs110emx.render_login(rand)` (captured
  template, `__RAND__` substituted).
- POST `login_post_path` (`/redirect.html`) with `LoginPassword =
  merge_hash_md5(password, rand)`.
- Response: `web_gs110emx.render_redirect(token)` — captured template,
  `__GAMBIT__` substituted; success token is the module constant:
  ```python
  _VIRTUAL_TOKEN = "virtual-gambit-session-token-0123456789abcdef"  # line 51
  ```
  failure token = `""`. **No `Set-Cookie` is ever sent** — this is
  explicitly a non-cookie scheme.
- Routing to `_render_token_page` for later requests is gated purely on
  `spec.session_token_field is not None` — a DIALECT SWITCH, not an actual
  auth check of the request's `Gambit=` value.

**3. `CHEETAH_FORM`** — `gsm7228ps`, `gsm7252ps`. Cookie session, plaintext
password.
- GET `login_path` (`/base/cheetah_login.html`) → same `web.render_login
  (rand)` template as scheme 1 (rand is scraped but unused for hashing on
  this scheme).
- POST `login_path` (no separate `login_post_path`) with `pwd=<plaintext>`
  and, for these two models, `uname=<username>` (default `"admin"`) —
  validated by plaintext `==` compare (+ username compare when
  `username_field` set).
- Same "OK"/"Login failed" + conditional `Set-Cookie` shape as scheme 1.

**4. `CHEETAH_V1`** — `m4300-24x`, `m4300-16x`. Same plaintext form as
scheme 3, layered with a CSRF guard (`needs_referer=True`), plus an
additional `Origin` requirement on POSTs for the `secure`
(HTTPS/:49152) 16X variant.
- GET `login_path` (`/`) for the rand-page scrape; POST target is
  `login_post_path="/v1/base/cheetah_login.html"`.
- Referer/Origin enforcement runs BEFORE any login logic (§3.4) — the login
  POST itself is subject to the same 403 gate as every other request.
- `cookie_name="SID"` for m4300-24x, `"SIDSSL"` for m4300-16x — same
  "OK"/"Login failed" + conditional Set-Cookie shape.

**5. `XML_API` (GoAhead)** — `gs728tpp` only. The one genuinely three-step,
SESSION-CHECKED handshake, fully separate code path (`_goahead_get`/
`_goahead_post`, lines 217-299), gated purely by `spec.html_dialect is
HtmlDialect.GOAHEAD_XML` rather than by `scheme`:

- **Step 1** — `GET /` → 302 redirect to `/{session}/` where
  `_session_path = "cs0000face"` (line 158, a fixed per-face constant
  standing in for real firmware's per-login-minted session path).
- **Step 2** — `GET /{session}/System.xml?action=login&user=<u>&password=<p>`
  → validates plaintext `user`/`password` against `spec.username`/
  `self.password`; response:
  ```python
  '<?xml version="1.0" encoding="UTF-8" ?>'
  f"<ResponseData><statusCode>{code}</statusCode>"
  "</ResponseData>"
  ```
  `code="0"` success / `"1"` failure, `Content-Type: text/xml`; on SUCCESS
  ONLY, a `sessionID: virtualsid` **RESPONSE HEADER** is sent (explicitly
  NOT a `Set-Cookie`).
- **Step 3** — every subsequent read is `GET /{session}/wcd?{...}`; this is
  the ONE dialect that ACTUALLY CHECKS session state:
  ```python
  if "sessionID=virtualsid" not in self.headers.get("Cookie", ""):
      # 302 redirect back to /{session}/
  ```
  The client is expected to turn the response header into a REQUEST cookie
  itself (mirroring real client behavior); the mock checks for the literal
  substring `"sessionID=virtualsid"` in the `Cookie` header. Present →
  dispatch to `web_gs728tpp.render_wcd(state, query)`; `None` → 404; else
  send the rendered page.
- Writes (`_goahead_post`) apply the SAME unauthenticated-write guard (302
  if session cookie absent), require `path.endswith("/wcd")` (else 404),
  then parse the raw POST body as the cert-import XML (§3.6).

### 3.3 Per-dialect page-renderer dispatch

`_known_paths` (lines 84-89, built once in `__init__`) is the union of
every populated `*_path` field on the model's spec (excluding
`login_path`/`login_post_path`) plus the XUI `/a1` write-target aliases
(`port_config_path`, `poe_config_path`, `mgmt_ip_path`). Any path NOT in
this set 404s BEFORE any renderer runs — the "mock never fabricates a page"
invariant.

For a known path, `do_GET`/`do_POST` run an ordered `if (x := face._render_X(
...)) is not None: page = x elif ...` chain, all inside `with face._lock:`.
Priority order:

1. `_render_fastpath_vlan_page` — checked FIRST because the FASTPATH "VLAN
   Membership" page is shared verbatim across three dialects (M4300, S3300,
   XE_FASTPATH); matches on path membership, independent of `html_dialect`.
   Returns `None` (not a fabricated page) if `state.vlan_membership_page is
   None` (§5.2 — the state field this dossier flags as a Go gap).
2. `_render_fastpath_xui_page` — the managed XUI write pages
   (`port_config_path`, `poe_config_path`, `mgmt_ip_path` + `/a1` targets).
   Picks the renderer module by `spec.html_dialect`:
   ```python
   if dialect is HtmlDialect.M4300: module = web_m4300
   elif dialect is HtmlDialect.S3300: module = web_gsm7228ps
   elif dialect is HtmlDialect.XE_FASTPATH: module = web_gsm7252ps
   else: return None
   ```
   Applies the form (`module.apply_ports`/`apply_poe`/`web_fastpath_xui.
   apply_mgmt_ip`) BEFORE re-rendering; a refused apply renders `err_flag=1`
   on a 200, never an HTTP error status.
3. `spec.session_token_field is not None` → `_render_token_page` (GS110EMX
   only).
4. `_render_gs105pe_page` — gated on `HtmlDialect.GS105PE`; own path table.
5. `_render_m4300_page` — gated on `HtmlDialect.M4300`; dispatches most
   pages to `web_m4300.*` but CROSS-REUSES `web_gsm7252ps.render_lldp`/
   `render_poe(watts=True)` for `lldp_path`/`poe_status_path` (both M4300
   SKUs share the same XE FASTPATH cell grid with gsm7252ps; `watts=True`
   renders decimal watts vs gsm7252ps's integer mW).
6. `_render_s3300_page` — gated on `HtmlDialect.S3300`; reuses
   `web_gsm7228ps.*` for everything (its own module).
7. `_render_xe_page` — gated on `HtmlDialect.XE_FASTPATH`; dispatches to
   `web_gsm7252ps.*`.
8. Fallback: `web.render_page`/`web.apply_form` — the GENERIC
   `HtmlDialect.STANDARD` renderer (gs305ep/gs105pe's original CGI shape).
   The module docstring explicitly calls this catch-all "deliberately
   permissive" and unsafe to reach unless the path is genuinely
   spec-advertised — steps 1-7 pre-empt it for every non-STANDARD dialect,
   and `_known_paths` gates entry to the whole chain regardless.

### 3.4 Referer 403 enforcement

`_referer_ok` (lines 193-215), called at the very top of BOTH `do_GET`/
`do_POST`, BEFORE dialect dispatch, BEFORE login-path handling, BEFORE
everything:

```python
def _referer_ok(self, *, is_post: bool = False) -> bool:
    if not face.spec.needs_referer:
        return True
    if "Referer" not in self.headers:
        return False
    if is_post and face.spec.secure:
        return "Origin" in self.headers
    return True
```

Only `spec.needs_referer=True` models are gated — currently just M4300 (both
SKUs). Check is PRESENCE-ONLY (no value/URL matching). The `secure`
(M4300-16X HTTPS/:49152) extra POST rule mirrors a live-observed behavior:
same POST body got 403 with Referer alone, 200 once Origin was added, and
403 again with Origin-but-no-Referer (isolated live on 10.1.5.20:49152,
2026-07-30). Failure response: `self._send("403 Forbidden", 403)` — bare
13-byte text body (NOT wrapped in `<html>`, unlike the 404 body), no cookie.

### 3.5 Multipart cert-upload handling

Hand-rolled boundary parsing — no `cgi` module, no `email.parser`.
`_parse_multipart` (lines 92-126): splits raw body on `b"--" +
boundary.encode("latin-1")`, then per chunk: trims exactly one framing
`\r\n` off each side (NOT `.strip()`, to avoid eating an empty-value part's
body separator); skips any chunk without a `\r\n\r\n` header/body separator
(naturally drops the preamble and closing boundary markers); parses headers
via two regexes (`name="([^"]*)"` required, `filename="([^"]*)"` optional —
presence distinguishes file vs plain field parts).

Validation in `_handle_cert_upload` (called from `do_POST` before the
urlencoded-body parse, gated on `path == spec.cert_upload_path and
content_type.startswith("multipart/form-data")`):

1. Missing/absent boundary → `400, "<html><body>missing multipart
   boundary</body></html>"`.
2. `cert_upload_file_field is None or file_field not in files` → `400,
   "<html><body>missing cert file field</body></html>"`.
3. Any name in `spec.cert_upload_form_fields` not present in `fields` →
   `400, f"<html><body>missing fields: {missing}</body></html>"`.
4. Success: `self.state.uploaded_cert = content.decode("latin-1")` (under
   the lock), returns:
   ```python
   return 200, (
       "<html><body>SSL PEM Server Certificate file download through HTTP "
       "is completed successfully.</body></html>"
   )
   ```
   — this exact string matches real S3300 firmware's live-captured success
   marker (Part 1 §6.8 / this file's `_check_multipart_cert_response`).

Currently only `gsm7228ps` (S3300) has `cert_upload_path`/
`cert_upload_file_field`/`cert_upload_form_fields` populated.

### 3.6 GoAhead XML cert import

Separate flow entirely from §3.5's multipart path. Reached via
`_goahead_post` when `html_dialect is GOAHEAD_XML` (only `gs728tpp`):
requires the `sessionID=virtualsid` cookie (else 302), requires
`path.endswith("/wcd")` (else 404), reads the raw POST body as UTF-8 TEXT
(not multipart), calls `web_gs728tpp.apply_cert_import(state, xml_body)`.

`apply_cert_import` (`web_gs728tpp.py:211-236`):

- **XXE hardening**: rejects outright if `"<!DOCTYPE" in xml_body or
  "<!ENTITY" in xml_body` → `_status_response(3, "DTD/entity declaration
  rejected")`, BEFORE any XML parsing is attempted.
- Parses with `xml.etree.ElementTree.fromstring`; `ParseError` →
  `_status_response(1, f"malformed XML: {exc}")`.
- `root.find("./SSLCryptoCertificateImportList/Entry")` absent →
  `_status_response(2, "no SSLCryptoCertificateImportList/Entry")`.
- `certificate`/`privateKey` child text stripped; either empty →
  `_status_response(2, "missing certificate or privateKey")`.
- Success: `state.uploaded_cert = certificate` (ONLY the certificate text
  is stored, not the private key), returns `_status_response(0, "")`.

```python
def _status_response(code: int, message: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>'
        f"<ResponseData><statusCode>{code}</statusCode>"
        f"<statusString>{escape(message)}</statusString></ResponseData>"
    )
```

Same envelope shape as the login response's `<ResponseData><statusCode>`
(§3.2 step 2), plus `<statusString>`. `escape()` is `xml.sax.saxutils.escape`.
The face just sends this with default status 200 — the status code is
carried INSIDE the XML body, not as an HTTP status; a 200 wraps both
success and every documented failure code 1/2/3.

**Go's XXE-hardening equivalent**: `encoding/xml`'s `Decoder` does not
resolve external entities by default, but the Go port should still add the
same explicit `strings.Contains(body, "<!DOCTYPE")`/`"<!ENTITY"` string
reject BEFORE calling `Decode`, as belt-and-suspenders behavioral parity
(Part 1 §2.10 makes the identical recommendation for the parser side).

### 3.7 404 handling for unspecced paths

Uniform: literal body `"<html><body>Not Found</body></html>"`, status 404,
`Content-Type: text/html`, no cookie. Occurs at: the generic
`path not in _known_paths` gate (GET and POST, checked AFTER the
login-path/cert-upload-path special cases); GoAhead GET for any path not
`/`, not the login System.xml query, and not containing `wcd?`; GoAhead
POST for any path not ending `/wcd`.

**One documented inconsistency to flag, not silently "fix"**:
`_render_token_page` (GS110EMX)'s terminal fallback returns the SAME
literal 404-shaped HTML STRING directly (not via the `_send` 404 path) for
an unmatched-but-technically-known path — the caller still wraps it with
DEFAULT STATUS 200. I.e. this ONE specific fallback is a 200 with
404-shaped HTML BODY, not an actual HTTP 404 — an inconsistency baked into
the reference implementation. A Go port should note this explicitly in a
doc comment when porting `_render_token_page`'s Go equivalent, rather than
"correcting" it to a real 404 (which would deviate from the pinned
reference this project ports byte-for-byte).

### 3.8 Threading lock → Go mutex

Single `threading.Lock()`, `self._lock` (line 165), rationale: "do_GET/
do_POST mutate shared VirtualSwitchState via web.render_page/apply_form
with no lock of their own, so two overlapping requests... would race.
Serialize just the render/apply critical section on this single lock rather
than the whole request." Acquired as `with face._lock:` around: the entire
dialect-dispatch chain in `do_GET` (§3.3 steps 1-8, read-only renders
included); the entire chain in `do_POST` (apply-then-reread done as ONE
atomic critical section for the generic fallback, so no other thread's
render observes a half-applied state); `_goahead_get`'s `wcd` render
(narrower, separate `with` block); `_goahead_post`'s cert-import apply
(separate block); `_handle_cert_upload`'s single state-mutation line
(separate block). NOT covered: `_login_response` (no state mutation),
`_referer_ok`, header/body parsing — consistent with "just the render/apply
critical section."

**Go mapping**: a single `sync.Mutex` on the Go `HTTPFace` struct, held for
the duration of each dispatch-and-render/apply call — same granularity as
Python's, i.e. do NOT hold it for the entire HTTP handler (header parsing,
auth checks) the way you would NOT in Python either. This is materially
simpler than the multi-varbind atomic-SET-with-rollback pattern
`SnmpFace.handleSet` needs (no analogous "snapshot + restore on partial
failure" requirement here — HTTP writes are single-page, single-apply, not
multi-varbind PDUs).

### 3.9 Additional Python behaviors to replicate precisely (not already covered above)

- **Password hashing**: `merge(a, b)` interleaves characters, then
  `merge_hash_md5 = hex(md5(merge(pw,rand).encode()))` — this is Part 1 §4's
  territory (`crypt.go`), reused here unchanged for the `_login_response`
  hash-compare branch.
- **Form/body parsing**: `Content-Length` header → `int(...)` → `rfile.
  read(length)`; form bodies decoded via `urllib.parse.parse_qs` on
  `raw.decode("latin-1")`, collapsed to first-value-only
  (`{k: v[0] for k, v in parse_qs(...).items()}`) — DUPLICATE KEYS SILENTLY
  KEEP ONLY THE FIRST VALUE, no error. Go's `url.ParseQuery` returns
  `url.Values` (a `map[string][]string`) — a Go port must explicitly take
  `values[0]` per key to match this "first value wins" behavior, not
  `Get()`'s already-first-value semantics alone (worth confirming Go's
  `url.Values.Get` already does this — it does — but a hand-rolled
  first-value-collapse elsewhere in the Go face must match).
- **Cookies**: no structured cookie-jar parsing anywhere — raw string
  headers (`Set-Cookie: <name>=virtualsid; path=/`) and plain substring
  containment checks on the raw `Cookie` request header. A Go port can use
  raw `http.Header` string manipulation too; no need for `net/http.Cookie`
  parsing semantics to match anything specific here.
- **Response shape**: every response is a plain string encoded as UTF-8,
  `Content-Length` computed manually, no chunked transfer, no gzip.
  `Content-Type: text/html` (except the two `text/xml` GoAhead responses).
  No other headers (no `Server`, no `Date` override).
- **Full routing precedence to replicate exactly**: referer/origin check →
  GOAHEAD_XML dialect check (full early-return) → login-path check (GET) /
  login-post-path check (POST) → cert-upload-path+multipart check (POST,
  BEFORE form parse) → known-paths 404 gate → the 8-step per-dialect
  `_render_*` fallthrough chain → generic `web.render_page`/`apply_form`
  catch-all. Getting this ordering wrong (e.g. checking `_known_paths`
  before the login/cert-upload special-cased paths) breaks models whose
  `login_post_path`/`cert_upload_path` isn't itself a member of
  `_known_paths`.

---

## 4. `virtual/web.py` + per-model renderers — the byte-faithful HTML/XML

Files (`src/netgear_switch/virtual/`): `web.py` (211), `web_gs105pe.py`
(179), `web_gs110emx.py` (207) + `web_gs110emx_templates.py` (40),
`web_gsm7252ps.py` (510), `web_gsm7228ps.py` (184), `web_m4300.py` (268),
`web_gs728tpp.py` (246), `web_fastpath_vlan.py` (421),
`web_fastpath_xui.py` (287); `cli_fastpath.py` (418, CLI-face-only, see
§4.7). **Total literal-HTML/XML renderer code: ~2,553 lines across 10
files** (excluding cli_fastpath.py).

### 4.1 `web.py` — shared base machinery, the FIXED CSRF token

Renderer for the generic/simple cookie-session model family (gs305ep and
the STANDARD-dialect fallback). Single flat `if/elif` chain keyed on
`spec.<field>_path` (lines 42-60), not a dispatch table:

```python
def render_page(state, spec, path, form) -> str:
    if path == spec.dashboard_path: return _render_dashboard(state)
    if path == spec.stats_path: return _render_stats(state)
    if path == spec.poe_status_path: return _render_poe_status(state)
    if path == spec.pvid_path: return _render_pvid(state)
    if path == spec.vlan_config_path: return _render_vlan_cfg(state)
    if path == spec.vlan_membership_path: ... return _render_membership(state, vid)
    if path == spec.poe_config_path: return f"<html><body>{_hash_input()}</body></html>"
    return f"<html><body>OK{_hash_input()}</body></html>"     # permissive catch-all
```

`apply_form` (lines 143-153) is the matching write dispatcher, same
flat-if convention, delegating to `_apply_poe`/`_apply_pvid`/
`_apply_membership`/`_apply_vlan_cfg` — each scans form keys via
`re.fullmatch(r"port(\d+)", key)` and mutates `VirtualSwitchState` in
place, no return value (caller re-renders after).

**CSRF token — exact literal, `web.py:25`**:

```python
_HASH = "virtualhash"
```

Emitted two ways: `render_login` (inside the login form's hidden `hash`
input) and `_hash_input()` (spliced into `_render_dashboard`,
`_render_poe_status`, `_render_pvid`, `_render_vlan_cfg`,
`_render_membership`). **It is never validated anywhere** — grep confirms
the only hash-related check in `faces/http.py` is the LOGIN password hash
(`merge_hash_md5`), unrelated to this field. This is write-only decoration
in the mock, proving the round-trip shape, not an authorization mechanism —
a Go port needs ONLY emission with a constant string, no verification
logic.

**Three DISTINCT CSRF-shaped literals exist across this codebase — do not
conflate them**:

| literal | where | model(s) |
|---|---|---|
| `"virtualhash"` | `web.py:25` | gs305ep, gs105pe, gsm7228ps, gsm7252ps login/dashboard pages |
| `"18007"` (`VIRTUAL_CSRF_HASH`) | `web_gs105pe.py:34` | gs105pe's `8021qCf.cgi`/`8021qMembe.cgi` hidden `hash` inputs specifically |
| `"virtualcsrf"` | `web_fastpath_vlan.py:312` | the FASTPATH VLAN Membership page's own CSRF-shaped field |

### 4.2 Per-model renderer inventory

**`web_gs105pe.py`** — six GET renderers, one per `.cgi`: `render_status`
(`/status.cgi`), `render_port_statistics` (`/portStatistics.cgi`),
`render_pvid` (`/portPVID.cgi`), `render_vlan_config` (`/8021qCf.cgi`),
`render_vlan_membership` (`/8021qMembe.cgi`, GET+POST), `render_switch_info`
(`/switch_info.cgi`). NO `apply_*` functions here — write handling for this
model lives entirely in `web.py`'s generic dispatcher (this module is
read-only renderers). Deliberately-preserved quirks: `portStatistics.cgi`
rows are `<tr class="portID" name="portID">` (extra `name=` attribute other
pages lack); the Bytes-Received `<td>` cell is rendered EMPTY (every counter
is instead carried as a hidden `(hi, lo)` 32-bit pair, because that is the
wire shape `parse_gs105pe_stats` reads); `8021qMembe.cgi` marks the
currently-selected VLAN with `<option ... selected>`, and re-POSTing that
selection "makes real hardware drop the connection" (documented, not
simulated as a failure mode).

**`web_gs110emx.py` + `web_gs110emx_templates.py`** — split for lint
reasons only (`templates.py` is pure literal-string data, excluded from
line-length lint the same way `_version.py` is). Renderers:
`render_login`, `render_redirect` (Gambit token issuance), `render_sysinfo`
(`/iss/specific/sysInfo.html?Gambit=`), `render_port_settings` +
`apply_port_settings` (the ONLY write function in this file), `render_pvid`
(`vlan_pvidsetting.html`, read-only), `render_cf8021q` (`Cf8021q.html`,
read-only), `render_vlan_membership` (`vlanMembership.html`, read-only),
`render_interface_stats` (`/iss/specific/interface_stats.html?Gambit=`).
PVID/VLAN-config/VLAN-membership are read-only on this mock — only
port-admin state is writable.

**THE never-closed-`<tr>` GS110EMX bug — exact quote** (`web_gs110emx.py:
199-206`, `render_interface_stats`):

```python
rows = "".join(
    '<tr class="portID"> \n'
    + _t.STATS_ROW.replace("__PORT__", str(port))
    ...
    for port, sim in sorted(state.ports.items())
)
```

and the row template it concatenates (`web_gs110emx_templates.py:19`):

```python
STATS_ROW = '\t\t\t\t <td class="def firstCol" sel="text">__PORT__</td>\n\t\t\t\t \n\t\t\t\t <td class="def" sel="text">__RX__</td>\n\t\t\t\t \n\t\t\t\t <td class="def" sel="text">__TX__</td>\n\t\t\t\t \n\t\t\t\t <td class="def" sel="text">__CRC__</td>\n\t\t\t\t \n  \t\t        '
```

There is **no `</tr>` anywhere** in either the opening tag string or
`STATS_ROW`/`STATS_SUFFIX`. Each `<tr class="portID">` runs on until the
next `<tr>` opens or `</table>` closes the table. This is CONFIRMED to be a
FAITHFULLY-REPRODUCED REAL FIRMWARE BUG (captured verbatim off a physical
GS110EMX, `tests/fixtures/http/gs110emx_interface_stats.html`), not a mock
authoring error — `parse.parse_interface_stats` (not gs305ep's
`parse_port_stats`) exists specifically to read this malformed shape back.
A second, even more granular deliberate byte-deviation is documented: the
real capture's LAST port-10 row has 2 fewer whitespace bytes before
`</table>` than every other row (a capture artifact of the real device),
and the renderer does NOT special-case that — "a byte-diff against the
original 10-port capture differs by exactly those 2 bytes," an accepted,
intentional non-byte-identical spot even in an otherwise byte-faithful
module. **A Go porter should not chase phantom exactness there** — this is
explicit, documented tolerance, not a gap to close.

**Substitution mechanism — load-bearing design signal for Go**: plain
`str.replace("__MARKER__", value)`, explicitly NOT `.format()`/f-strings,
"because the captured pages' inline JavaScript is full of literal `{`/`}`
characters that would need escaping." Interface names are HTML-escaped
(`1&#x2F;0&#x2F;1`) deliberately — unescaped once collapsed every parsed
port number to 1 in a real regression (same convention reused in
`web_m4300.py`).

**`web_gsm7252ps.py`** — "XE FASTPATH" dialect, home of "XE NAME cells".
Renderers: `render_ports`/`apply_ports` (`/portsConfiguration.html`),
`render_port_statistics` (`/portStatistics.html`, packet counters only, no
octets), `render_pvids` (`/portPvidConfiguration.html`), `render_vlans`
(`/vlanStatus.html`), `render_mac_table` (`/basicAddressTable.html`),
`render_poe`/`apply_poe` (`/poeInterfaceConfiguration.html`), `render_lldp`
(`/lldpRemoteInventory.html`), `render_sysinfo`
(`/base/system/management/sysInfo.html` — NOT an XE page, plain labelled
cells).

**"XE NAME cells" — exact quote** (`web_gsm7252ps.py:42-47`):

```python
def _cell(instance: str, xid: str, value: str) -> str:
    return (
        f'<TD class="def alt0" p="{instance}0" id={xid}>'
        f"<INPUT xid={xid} TYPE=hidden NAME={instance}.v_{xid} "
        f'VALUE="{value}">{value}</TD>\n'
    )
```

Example: `<TD class="def alt0" p="1.0.520" id=1_2_10><INPUT xid=1_2_10
TYPE=hidden NAME=1.0.52.v_1_2_10 VALUE="Link Up">Link Up</TD>`. Every data
cell is a hidden `<INPUT>` whose `NAME` carries the row instance
(`1.<row-index>.<row-count>` — deliberately NOT unit/slot/port; a naive
parser extracting a "port number" from it produces nonsense exactly as on
real hardware) prefixed onto a `v_<xid>` column tag, with the visible
cell/column coordinate on `id`/`xid`, and CRITICALLY no semantic field-name
comment anywhere — a reader/writer must address fields purely by numeric
coordinate, not by name. This dialect is shared byte-for-byte by
`web_gsm7228ps.py` for most pages (imported directly and reused for
`render_port_statistics`/`render_pvids`/`render_lldp`).

`apply_poe` (`web_gsm7252ps.py:357-412`) is the richest write function in
this file — it's the file whose fix produced the pin's namesake merge
commit (§2.6). Reproduces the measured, live-verified `unit_required=True`
refusal for gsm7252ps specifically (no self-identifying Unit key column),
with the counter-example (`unit_required=False` for gsm7228ps/M4300)
encoded so an over-correction fails as loudly as a regression — mirrored
in the Go test suite the same way (§8/§9).

**`web_gsm7228ps.py`** — S3300 Smart-firmware variant. NOT a standalone
renderer set — it imports and reuses `web_gsm7252ps` wholesale for
`render_port_statistics`/`render_pvids`/`render_lldp`, thinly wrapping
`render_ports`/`apply_ports`/`render_poe`/`apply_poe`/`render_vlans` with
S3300-specific parameters (different checkbox names, different `1/gN`/
`1/xgN` iface naming, `unit_required=False`). Genuinely OWN renderers:
`render_mac_table` (columns shifted — VLAN in `v_1_2_2` not `v_1_2_1` — and
port name HTML-entity-escaped) and `render_sysinfo` (only Base MAC Address
exposed, no IPv4, no sensors).

**`web_m4300.py`** — "Cheetah /v1" dialect, home of "cheetah field
comments". Renderers: `render_ports`/`apply_ports` (`/v1/
portsConfiguration.html`), `render_poe`/`apply_poe` (`/v1/
poeInterfaceConfiguration.html`, delegates to `web_gsm7252ps.render_poe`/
`apply_poe` with `watts=True`, `unit_required=False`),
`render_port_statistics` (frame counters not octets), `render_pvids`,
`render_vlans`, `render_mac_table`, `render_sysinfo` (plain labelled cells,
no xid cells).

**"Cheetah field comments" — exact quote** (`web_m4300.py:34-38`):

```python
def _cell(instance: str, xid: str, value: str, field: str) -> str:
    return (
        f'<TD class="def" id={xid}><INPUT xid={xid} TYPE=hidden '
        f'NAME={instance}.v_{xid} VALUE="{value}">{value}</TD><!-- {field} -->\n'
    )
```

Example: `<TD id=1_2_10><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10
VALUE="Link Up">Link Up</TD><!-- baseport_LinkStatus2 -->`. The
distinguishing feature vs gsm7252ps's bare XE cell: an HTML COMMENT NAMING
THE FIELD SEMANTICALLY (`<!-- baseport_AdminMode -->`, `<!--
SwitchingVlanPortConfig_Pvid -->`, etc — real Cheetah/EmWeb template field
names). `parse.parse_cheetah_rows` reads fields BY THIS COMMENT NAME, not
by numeric coordinate — the OPPOSITE addressing convention from the
gsm7252ps XE dialect despite a superficially similar `<TD>/<INPUT>`
skeleton. A live-correction note in the code documents this mapping was
fixed against real hardware (10.1.5.13) after the mock originally emitted
coordinates that don't exist on real firmware but that the comment-keyed
parser tolerated anyway — a documented near-miss worth a Go doc comment.

**`web_gs728tpp.py`** — GoAhead `wcd` XML API, no HTML at all.
Architecturally distinct: renders `<ResponseData><DeviceConfiguration>...
</DeviceConfiguration></ResponseData>` envelopes (`_wcd` helper). Renderers:
`render_ports`, `render_pvids_membership`, `render_vlans`, `render_poe`,
`render_macs`, `render_lldp`, `render_mgmt_ip`,
`render_device_info_and_sensors`, each producing one `<...List
type="section">` block. Routed by SUBSTRING MATCH on the wcd query's
`file=` parameter via a `_ROUTES` table inside `render_wcd(state, query)`,
returning `None` (→ caller 404s) for any unrecognized file. `GoAhead
cert-import lives HERE, not in cli_fastpath.py` (see §4.7's correction) —
`apply_cert_import` (§3.6). No apply-form logic exists for the read-only
sections.

### 4.3 `web_fastpath_vlan.py` + `web_fastpath_xui.py` — shared cross-cutting scaffolding

Not per-model page renderers — the machinery the per-model files build
their PoE/ports/mgmt-IP pages on top of, plus one standalone page each
family serves identically. Shared by ALL FOUR managed models (gsm7252ps,
gsm7228ps, m4300-24x, m4300-16x).

**`web_fastpath_xui.py`** — the shared WRITE-FORM scaffolding for every
"XUI" page:

- TWO `<FORM>`s per page: `<page>.html/a0` (applet/redirect, no data) and
  `<page>.html/a1` (the real read+write form).
- Repeating rows `<TR p="<unit>.<row0>.<count>0">`, fields named
  `<unit>.<row0>.<count>.v_1_2_<column>`, each with its own `gecb*`
  checkbox; only checked rows apply.
- Trailing "redirection elements" (`submit_flag`/`submit_target`/
  `err_flag`/`err_msg`/`clazz_information`) plus a disabled hidden-button
  block. Apply flag is the firmware's own `submit_flag=8` constant.
- The "Go To Port" list-navigation block (`class=deftestme` rows carrying
  `v_1_1_1`/`v_1_3_1` — both aliases of `urlListUnit` — and `v_1_1_2`) —
  ENABLED hidden inputs a real browser submits on every apply; their
  absence is precisely what the gsm7252ps PoE-refusal bug (§2.6) hinges on.
- A generic `apply_port_admin` helper is the single Admin-Mode-column apply
  logic reused (with different `checkbox=`) by gsm7252ps, gsm7228ps (via
  delegation), and m4300's `apply_ports`.
- Also owns the two management-IP page render/apply functions shared
  across all four models (field maps differ per `HtmlDialect`, supplied
  via `spec.mgmt_ip_fields`), including the real firmware's exact IPv4
  validation error string.

**`web_fastpath_vlan.py`** — the "VLAN Membership" page (§1.3/§2.1's
`switching/dot1q/vlan_port_cfg.html` GET / `..._rw.html` POST), one page
shared byte-shape-wise across all four managed models but with per-model
GEOMETRY (`VlanMembershipPageSim`, §5.2) and two rendering variants:
`_grid_gif` (older gsm7252ps: `toggleImageFirst()` + `grey_[btu].gif`) vs
`_grid_png` (newer S3300/M4300: `togImg()` + `switch_*.png`, 1-based slot
indexing). Encoded real-hardware behaviors (all live-grounded 2026-07-30):
two different views of the same VLAN coexist on one page (§1.3's
CURRENT/CONFIGURED split); `submt=0` (the VLAN `<select>`'s own re-render)
must NOT mutate anything, only `submt=16` applies; an unknown requested
`vlanId` falls back to the lowest VLAN; LAG pseudo-interfaces occupy
`hiddenMem` slots AFTER physical ports, per-model slot counts (64/26/128) —
a writer that truncated the string on `port_count` would silently drop
them; the M4300 access/trunk-port refusal is reproduced verbatim
(`"Unable to set VLAN membership for VLAN ( {vid} )"`); its own CSRF-shaped
literal (`"virtualcsrf"`, §4.1) is a THIRD distinct constant.

**Role/relationship**: XUI is not an alternate write path competing with
the per-model `web_*.py` files — it IS the write path those files implement
against; the per-model modules are thin parameterizations (checkbox name,
iface-naming function, column labels) layered on this shared engine.
`web_fastpath_vlan.py` is a sibling shared page (VLAN Membership) all four
managed models serve with the same semantics but a different HTML skeleton
per firmware generation.

### 4.4-4.5 (cross-referenced above — "XE NAME cells" §4.2/`web_gsm7252ps.py`, "cheetah field comments" §4.2/`web_m4300.py`)

### 4.6 GoAhead wcd routing + cert import — CORRECTION to file attribution

The task brief's phrasing ("GoAhead wcd routing + cert import") groups this
with `cli_fastpath.py`; that attribution is WRONG and must not be carried
into the Go port's file layout. Confirmed by direct search: `cli_fastpath.py`
has ZERO references to `wcd`/`GoAhead`/`cert`. GoAhead `wcd` routing and
cert import live entirely in `web_gs728tpp.py` (`render_wcd`,
`apply_cert_import`, §3.6/§4.2), dispatched from `faces/http.py:254-296`.

### 4.7 `cli_fastpath.py` — NOT part of the HTTP face at all

418 lines, briefly noted per the task brief's ask but confirmed
UNRELATED to HTTP: it is the CLI-face analogue of the FASTPATH web
renderers — pure functions rendering fixed-width `show ...` command text
(ports, vlan brief/detail, PVIDs, MAC table, LLDP, PoE, environment/sensors,
version, network, interface counters) from `VirtualSwitchState`, consumed
EXCLUSIVELY by `virtual/faces/cli.py` (a separate SSH/Telnet-shaped face,
slice-07 territory). Every non-self reference in the repo to
`cli_fastpath` is from `faces/cli.py`; none from `faces/http.py`. **A Go
porter working on the HTTP backend should not look for GoAhead or
cert-import logic in a `cli_fastpath`-equivalent file** — it belongs to
`virtual/webgs728tpp.go`-equivalent territory (§4.2), fully separate from
whatever slice 07's CLI face eventually needs.

### 4.8 Byte-fidelity strategy — findings and recommendation

Inspected how the test suite actually exercises these renderers (§8).
**Finding: there is NO automated byte-diff test comparing a `web_*.py`
renderer's output against a fixture file anywhere in this repo.** Two
independent, deliberately-separated mechanisms exist instead (stated
explicitly in `tests/test_http_vlan_membership.py:1-17`):

1. **Fixture-driven parser tests** (`tests/test_http_read.py` et al.) load
   REAL captured `.html` files into a fake session and assert the PARSERS
   extract correct field values — this validates the parsers, not the mock
   renderers.
2. **Mock round-trip tests** (`test_http_write.py`, `test_http_xui_writes.
   py`, `test_http_vlan_membership.py`'s `test_mock_*`,
   `test_virtual_http_face.py`) spin up the mock HTTP face and a real
   switch, perform a write via the public reader/writer API, and assert on
   PARSED SEMANTIC FIELD VALUES or EXACT LITERAL ERROR-MESSAGE STRINGS —
   never a byte-diff against a captured `.html` fixture, even for the
   module explicitly claiming "byte-faithful pages" (GS110EMX).

**Implication**: the "byte-faithful" claims in the Python docstrings were
established ONCE, by hand, at authoring time (manual transcription from
`tests/fixtures/http/*.html` into `__MARKER__`-templated string literals),
and are subsequently protected only by the semantic round-trip tests above
— NOT by an ongoing automated fixture-equality check. This materially
loosens the porting requirement: exact byte-for-byte reproduction of every
whitespace character is NOT enforced by CI and NOT required for
correctness. But the documented cases (GS110EMX's never-closed `<tr>`, the
last-row 2-byte whitespace deviation, the XE/Cheetah field-addressing
conventions, the empty-first-`<td>` on gs105pe stats) show that
STRUCTURAL malformations and FIELD-ADDRESSING conventions genuinely ARE
load-bearing (they are exactly what the corresponding parser is built to
handle) and MUST be reproduced faithfully in Go, even though incidental
whitespace need not be.

**Recommendation for the Go port: hand-transcribe into Go string constants
using plain marker substitution — `strings.ReplaceAll`/`strings.
NewReplacer`, mirroring the Python design exactly.** The Python rationale
applies unchanged to Go: these pages embed literal inline JavaScript full
of `{`/`}` characters, which would collide badly with Go's `text/template`
`{{...}}` delimiters or `fmt.Sprintf`'s `%`-escaping requirements.
`strings.ReplaceAll` with `__MARKER__`-style tokens sidesteps both problems
identically in Go and needs no escaping of embedded JS/HTML.

A worthwhile refinement over pure inline Go string literals: use
`//go:embed` to keep the large literal blocks as separate `.html`/`.xml`
fragment files (structurally similar to `tests/fixtures/http/`), then do
the same `strings.ReplaceAll` substitution at render time — this keeps huge
multi-hundred-byte single-line literals out of `.go` source (avoiding
gofmt/lint noise analogous to Python's own line-length-lint exclusion for
`web_gs110emx_templates.py`) while preserving identical runtime behavior
and porting fidelity. Either approach satisfies "hand-transcribe with
marker substitution"; serving real captured fixtures live with minimal
templating is explicitly NOT what the Python original does and should not
be introduced as a new pattern in Go — the real captures in
`tests/fixtures/http/` remain solely the PARSER tests' input corpus, never
something served live by the mock.

---

## 5. Seed HTTP data

### 5.1 What Go already has (confirmed by direct read, `virtual/state.go`/`virtual/seed.go`)

Go's `State` struct already carries every HTTP/CLI-only field the Python
`VirtualSwitchState` dataclass has EXCEPT the VLAN-membership-page fields
(§5.2):

| Go field | Python equivalent | status |
|---|---|---|
| `HTTPSensors []SensorSim` | `http_sensors: list[SensorSim] \| None` | present, matches |
| `(*State).SysinfoSensors()` | `sysinfo_sensors` property | present, matches (`return s.Sensors if s.HTTPSensors == nil else s.HTTPSensors`) |
| `UploadedCert *string` | `uploaded_cert: str \| None` | present, matches |
| `ScpCertDeploySim{Commands,Copies,HTTPSDisabled,HTTPSEnabled,Saved}` | `ScpCertDeploy` dataclass | present, matches (CLI/slice-07 concern, carried for completeness) |

All 8 HTTP-capable models already have hand-authored `Seed*()` functions in
Go's `virtual/seed.go` (`SeedGSM7252PS`, `SeedGSM7228PS`, `SeedM4300_24X`,
`SeedM4300_16X`, `SeedGS728TPP`, `SeedGS110EMX`, `SeedGS305EP`,
`SeedGS105PE`) — this matches Python's seed-function set 1:1 (Python has a
9th, `seed_gs110emx_fw1028`, an alternate-firmware variant of GS110EMX; the
Go port has no equivalent — flagged as a minor, likely-intentional gap, not
this dossier's central finding, since no HTTP-specific field differs
between the two Python firmware variants).

### 5.2 THE GAP: `VlanMembershipPageSim` + `vlan_membership_locked_ports` — missing from Go

This is the one concrete `State`-shape gap this dossier identifies. Python's
`state.py` (lines 193-231, 495, 507) has:

```python
@dataclass
class VlanMembershipPageSim:
    """MEASURED shape of one model's FASTPATH "VLAN Membership" page."""
    slots: int
    lag_slot: int
    grid: str                    # "gif" | "png"
    trailing_comma: bool = False
    csrf: bool = False
    escape: bool = False

# on VirtualSwitchState:
vlan_membership_page: VlanMembershipPageSim | None = None
vlan_membership_locked_ports: frozenset[int] = frozenset()
```

This models the exact byte-for-byte rendering geometry of the FASTPATH
"VLAN Membership" page (§1.3/§4.3) — hidden-field grid size, LAG ifName
slot number, whether ifNames are HTML-escaped, whether there's a trailing
comma in `hiddenMem`/`hiddenTagged`, whether a per-page CSRF token is
required — all MEASURED live per model:

| model | slots | lag_slot | grid | trailing_comma | csrf | escape |
|---|---:|---:|---|:---:|:---:|:---:|
| gsm7252ps | 116 | 3 | gif | no | no | no |
| gsm7228ps | 78 | 3 | png | no | no | yes |
| m4300-24x | 152 | 13 | png | yes | no | yes |
| m4300-16x | 144 | 13 | png | yes | yes | yes |

`vlan_membership_locked_ports` models a real firmware quirk: a port whose
`switchport mode` is `access`/`trunk` refuses an explicit VLAN-membership
apply over HTTP, returning HTTP 200 with `err_flag=1` +
`err_msg="Unable to set VLAN membership for VLAN ( <vid> )"` (§2.2). This is
PER-PORT, not per-model — only `m4300-24x`'s seed sets it (`frozenset(range(
1, 25))` — every port on that live-captured unit is access/trunk mode);
`m4300-16x`'s ports 1-8 have no `switchport mode` line at all, so its seed
does NOT set this field (empty default), letting the apply succeed there —
deliberately encoded as a live counter-example pair (§8, `test_mock_
m4300_24x_refusal_is_surfaced_verbatim` vs
`test_mock_m4300_16x_accepts_what_the_24x_refuses`).

Which seeds populate `vlan_membership_page` in Python: `seed_gsm7252ps`
(1228, cited to `tests/fixtures/http/gsm7252ps_vlanPortCfg_vlan1.html`),
`seed_gsm7228ps` (1793-1795, cited to `gsm7228ps_vlanPortCfg_vlan5.html`),
`seed_m4300_24x` (2399-2401 + `vlan_membership_locked_ports` at 2412, cited
to `m4300_vlanportcfg_vlan1.html`), `seed_m4300_16x` (2594-2601, cited to
`m4300_16x_vlanportcfg_vlan4.html`). GS110EMX/GS305EP/GS105PE (no FASTPATH
VLAN-membership page — Plus-class) and GS728TPP (GoAhead, no separate
membership page) never set it.

**Required Go work** (this dossier's concrete, actionable gap for slice
06's implementation, not merely descriptive): add a
`VlanMembershipPageSim` struct + `VlanMembershipPage *VlanMembershipPageSim`
and `VlanMembershipLockedPorts map[int]bool` (or a sorted `[]int` — match
this repo's existing "canonical sorted, not a Python-frozenset-mirroring
map" convention where one already exists, e.g. `protectedPorts`) fields to
Go's `State`, wire them into `Snapshot()`/`Restore()` the same
deep-copy-by-hand way every other slice/map field there already is, and
populate them in the four managed-model `Seed*()` functions using the
table above. Without this, the Go virtual HTTP face has no way to render
the VLAN Membership page at all for the four managed models — the entire
§1.3/§2.1 fix this pin exists to port would have nothing to drive it.

### 5.3 `http_sensors` — per-model population (cross-check, no gap found)

`seed_gsm7252ps` sets 12 `SensorSim` entries (5 temperature, 5 fan-health-
text, 2 power-health-text — cited to `gsm7252ps_sysInfo.html`; SNMP reports
fan RPM + PSU watts and NO temperature, so this is a genuinely different
sensor interface, not derived data). `seed_gs728tpp` sets 9 entries keyed by
DiagnosticsUnitList XML tag names (`mainPSStatus`, `fan1Status`..
`fan5Status`, `tempSensorValue`, `tempSensorStatus` — cited to a live
capture 10.2.5.10; this agent implements zero Netgear vendor SNMP OIDs, so
`Sensors` stays empty and `HTTPSensors` is the real HTTP-only difference).
`seed_gsm7228ps`/`seed_m4300_24x`/`seed_m4300_16x` do NOT set `http_sensors`
(fall back to the SNMP `Sensors` set via `SysinfoSensors()`/`sysinfo_
sensors`). `seed_gs110emx`/`seed_gs305ep`/`seed_gs105pe` set neither
`http_sensors` nor `vlan_membership_page` (Plus-class, no such pages).
This exactly matches what Go's `virtual/seed.go` already does per the
grep performed directly against it (`HTTPSensors` set in
`SeedGSM7252PS`/`SeedGS728TPP` only) — **no gap here**, only §5.2's VLAN
fields are missing.

`uploaded_cert`/`scp_cert_deploy` are never seed data in either language —
both are runtime-populated by mock faces during a test session (HTTP
multipart/GoAhead-XML upload sets `uploaded_cert`; the CLI face's `copy
scp://` handling lazily initializes `scp_cert_deploy`) — Go's zero-value
`nil`/`nil` fields already match this.

---

## 6. `server.py` — HTTP face binding

### 6.1 Independent per-backend bind, separate port field

`VirtualSwitch.start()` (`server.py:98-128`) binds each backend in its OWN
independent `if` block — confirmed NOT mutually exclusive:

```python
if Backend.SNMP in self._model_info.backends:
    ...
    self.port = face.start()
if Backend.NSDP in self._model_info.backends:
    nsdp_face = VirtualNsdpFace(self.state, host=self.host, port=self.port)
    self.port = nsdp_face.start()
if Backend.HTTP in self._model_info.backends:
    http_face = VirtualHttpFace(
        self.state, http_spec(self._model_info),
        host=self.host, password=self.http_password, port=self.http_port,
    )
    self.http_port = http_face.start()
    self._http_face = http_face
```

HTTP is bound via a SEPARATE port field, `self.http_port`, distinct from
`self.port` (shared, in principle, by SNMP and NSDP — though no registered
model has both). Constructor doc states explicitly: "a `{NSDP, HTTP}` model
binds BOTH an NSDP face (`self.port`) and an HTTP face (`self.http_port`)
CONCURRENTLY" — confirmed true for `gs110emx`/`gs305ep`/`gs105pe`
(NSDP+HTTP) and for `m4300-24x`/`m4300-16x`/`gsm7252ps`/`gsm7228ps`
(SNMP+HTTP(+SSH/TELNET)). `bound_endpoints` reports `("HTTP", "tcp",
self.http_port)` alongside `("SNMP"/"NSDP", "udp", self.port)` — HTTP is
TCP, SNMP/NSDP are UDP, bound and reported independently.

**This exactly matches the Go repo's ALREADY-WRITTEN doc comments and
struct shape** in `virtual/server.go` — `HTTPPort int` is already a field
distinct from `SnmpPort`/`NsdpPort` (currently always 0, reserved), and
`Start()`'s own doc comment already says "TODO(slice-06/slice-07): once the
HTTP and SSH/Telnet faces exist, this gains their own independent `if`
blocks too (mirroring the Python reference's start())" — slice 06's
implementation work here is exactly and only: add the third `if
v.modelInfo.HasBackend(model.BackendHTTP) { ... }` block (mirroring the
existing SNMP/NSDP blocks' shape precisely), set `v.HTTPPort`/`v.httpFace`,
and extend `Stop()`'s teardown + the "no face bindable" check + the
`Endpoints` struct (add `HTTPPort int`) the same way `NsdpPort` was added in
slice 05. No structural surprises — this is the most mechanical piece of
slice 06's Go implementation.

### 6.2 Model → HTTP backend cross-check (no discrepancy)

Read `registry.py` in full: `Backend.HTTP` is present for exactly 8 models —
`m4300-24x`, `m4300-16x`, `gsm7252ps`, `gsm7228ps`, `gs110emx`, `gs305ep`,
`gs728tpp`, `gs105pe`. Two models registered WITHOUT HTTP: `m7300`
(unverified-pending-capture, SNMP-only) and `xs748t` (HTTP "deliberately
OMITTED here (not just unverified)" per its own registry comment). **This
exactly matches the Go registry's `model/registry.go`** (already confirmed
by direct read, §0 above) — zero discrepancy, no action needed here beyond
confirming during implementation that `HasBackend(model.BackendHTTP)`
returns true/false for exactly these same models.

---

## 7. Facade: HTTP dispatch, gating, password plumbing

### 7.1 `build_sync_http_client` — construction-time behavior (no I/O, value-check only)

`_dispatch.py:281-294`:

```python
def build_sync_http_client(host, password, model) -> HttpClient:
    spec = http_spec(model)
    return HttpClient(
        _http_host(host, spec), _require_http_password(host, password), spec,
        secure=spec.secure,
    )
```

`_require_http_password` (268-271) raises `CredentialError` if `password`
is falsy — a VALUE check, parallel to `_require_community`/
`_require_write_community`'s SNMP-side gates. No auth/session I/O happens
at construction: `HttpClient.__init__` (Part 1 §6.1) only builds an
`httpx.Client` (no connection opened until a request is issued) and sets
`_logged_in=False`/`_token=""`/`_session_path=""` — no `login()` call, no
request. This matches the lazy-connection pattern `buildSNMPClient`/
`buildNSDPClient` already use in Go (`backend_snmp.go`/`backend_nsdp.go`) —
`backend_http.go`'s equivalent builder should follow the identical shape:
construct a not-yet-connected client/session object, resolve+require the
password as a pure value check, no blocking I/O (per `BackendBuilder`'s own
documented no-blocking-I/O contract in `dispatch.go`, since `readerFor`/
`writerFor` hold `s.mu` for the entire builder call).

`_http_host(host, spec)` appends `:web_port` only for a non-standard-port
model (m4300-16x on `:49152`); otherwise passes the bare host through.

### 7.2 `http_reads_supported` gate — the pre-session-build ordering (CRITICAL)

```python
def http_reads_supported(model: SwitchModel) -> bool:
    if Backend.HTTP not in model.backends:
        return False
    spec = HTTP_SPECS.get(model.key)
    return spec is not None and spec.reads_verified
```

Gates on `HttpModelSpec.reads_verified` (Part 1 §1.4/§1.5) — the SAME
field-based gate as §1.5 above, reused verbatim for writes too (there is NO
separate `http_writes_supported` function; only the message text differs).

**The exact ordering in `sync_api.py`'s `_reader_for()`**, HTTP branch:

```python
elif backend is Backend.HTTP:
    # UNVERIFIED-reads models refuse HERE -- before any session build --
    # so the per-op loop sees a plain UnsupportedCapabilityError, NOT a
    # CredentialError from resolving a web password this backend will
    # never use.
    if not http_reads_supported(self.model):
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r} HTTP reads are UNVERIFIED-pending-capture"
        )
    reader = HttpReader(_LazyHttpSession(self._http_session), self.model)
```

**Confirmed exactly as this dossier's brief states**: `http_reads_supported
(self.model)` is checked and can raise `UnsupportedCapabilityError` BEFORE
`HttpReader(...)` is even constructed, and critically BEFORE
`self._http_session` is ever invoked — so `_resolve_http_password()`
(which raises `CredentialError`) is never reached for a model whose HTTP
reads are unverified. Even when the gate passes, `HttpReader` is
constructed with `_LazyHttpSession(self._http_session)` — a wrapper class
that DEFERS calling `self._http_session()` (and therefore password
resolution / `build_sync_http_client`) until an op that actually reaches
the wire (`login`/`get_page`/`post_form`/etc.) is invoked. Docstring: "Ops
an HttpReader/HttpWriter refuses honestly WITHOUT ever touching the session
(e.g. `get_macs`, `set_mgmt_ip` on a model lacking that page) must never
trigger HTTP password resolution or a live connection — only per-op
routing that HTTP actually ends up serving should pay that cost."

Identical pattern in `_writer_for()`'s HTTP branch (message text: "HTTP
writes are UNVERIFIED-pending-capture", same boolean check reused).

One deliberate exception: `_cert_writer()` bypasses this gate entirely —
cert upload is documented as "a GROUNDED web-UI write flow that is
INDEPENDENT of read verification."

**Go mapping for `backend_http.go`**: mirror `backend_nsdp.go`'s shape
exactly (the closest existing analogue — a password-gated writer builder).
`buildHTTPReader(sw *Switch) (BackendReader, error)` must check the
`reads_verified` gate FIRST (returning an error wrapping
`model.ErrUnsupportedCapability`, matching `readerFor`'s existing
"builder's error is NEVER cached" contract in `dispatch.go`) BEFORE calling
`sw.httpPassword.resolve()` — i.e. the gate check must precede, not follow,
password resolution, exactly like Python's ordering. Since Go's
`BackendBuilder`/`WriteBackendBuilder` contract already forbids blocking
I/O during the builder call (readerFor/writerFor hold `s.mu`), and since a
`resolveOnce.resolve()` call for `httpPassword` is itself non-blocking
(just a closure invocation, no network I/O per `resolveOnce`'s own
contract), there is no Go-specific "lazy session" wrapper equivalent to
Python's `_LazyHttpSession` strictly required for THIS no-blocking-I/O
requirement — but the ORDERING (gate check before password resolution)
must still be preserved by putting the `reads_verified`-equivalent check as
literally the first statement in `buildHTTPReader`/`buildHTTPWriter`,
before any call to `sw.httpPassword.resolve()`.

### 7.3 `scheme_verified` — separate metadata field, NOT an enforced runtime gate

`HttpModelSpec.scheme_verified: bool` (Part 1 §1.4) records whether the
LOGIN SCHEME ITSELF (as opposed to read/write page-scraping) is grounded in
prior art or a live capture. Difference from `reads_verified`: `scheme_
verified` = "we know how to log in" (auth mechanism grounded);
`reads_verified` = "login works AND every read op's page-scrape is
cross-verified against a live capture." A model can have `scheme_
verified=True` with `reads_verified=False`.

**Confirmed by grep**: `scheme_verified` is read NOWHERE outside
`protocols/http/endpoints.py` itself — not referenced by `_dispatch.py`,
`sync_api.py`, or any gate function. It is PURE DOCUMENTATION/METADATA on
the dataclass, not an enforced runtime gate (unlike `reads_verified`, which
IS the actual gate `http_reads_supported()` checks). **Go implication**:
port `ScehemeVerified`/`SchemeVerified bool` onto `http.ModelSpec` as a
documentation-only field (e.g. surfaced via a doc comment or a
`String()`/debug method), but do NOT wire it into `buildHTTPReader`/
`buildHTTPWriter`'s gating logic — only `ReadsVerified` gates construction.

### 7.4 Single-backend `resolveBackend` reaching HTTP — already correct in Go, confirmed by inspection

Python's `resolve_backend` (`_dispatch.py:35-71`) and `SyncSwitch.
resolve_backend` wrapper: when `requested is not None` (caller passed
`backend=Backend.HTTP` explicitly), the function returns `requested`
IMMEDIATELY on the first branch — the `preference` tuple/loop is NEVER
consulted. It only checks membership in `model.backends` (raising if the
model lacks HTTP), never compares against what the model's default/
highest-preference backend would otherwise be. So for e.g. `m4300-24x`
(whose default via `_BACKEND_PREFERENCE = (SNMP, NSDP, HTTP, SSH, TELNET,
CONSOLE)` is SNMP), calling `sw.get_ports(backend=Backend.HTTP)` resolves
straight to HTTP — SNMP is never considered.

**Confirmed this is EXACTLY what Go's `dispatch.go` `resolveBackend`
already implements** (read directly, §0 above): `requested != nil` returns
`*requested` immediately after the `HasBackend` membership check (lines
190-202 of `dispatch.go`), with `backendPreference = []model.Backend{
BackendSNMP, BackendNSDP, BackendHTTP, BackendSSH}` matching Python's
`_BACKEND_PREFERENCE` order (Go's list omits `TELNET`/`CONSOLE` since
slice 06/07 haven't registered those backends yet — not a discrepancy,
just a smaller enum of IMPLEMENTED backends at this point in the port).
**No Go dispatch-layer changes needed for HTTP to participate correctly in
explicit-backend selection** — `RegisterBackend(model.BackendHTTP,
buildHTTPReader)`/`RegisterWriteBackend(model.BackendHTTP, buildHTTPWriter)`
from `backend_http.go`'s `init()` is the ENTIRE remaining wiring
requirement; `readVia`/`writeVia`/`resolveBackend`/`cannotServe` need zero
modification.

### 7.5 `WithHTTPPassword`/`httpPassword` plumbing — already fully wired in Go, confirm consumption pattern only

Python's `SyncSwitch.__init__` keeps `nsdp_password`/`nsdp_password_
resolver` and `http_password`/`http_password_resolver` as FOUR genuinely
separate constructor parameters (two independent value+resolver pairs),
each with its own `_Unset`-sentinel resolve-once cell
(`_resolved_nsdp_password`/`_resolved_http_password`), resolved
independently via `_resolve_nsdp_password()`/`_resolve_http_password()`.
`from_config()`'s two resolver closures, verbatim:

```python
def _resolve_nsdp_password() -> str | None:
    # Plus switches share ONE web-admin password across HTTP + NSDP, so
    # reusing the http_password spec as the NSDP v1 auth password is
    # intentional and correct. ... do NOT add a separate key now.
    return cfg.http_password(env=_env)

def _resolve_http_password() -> str | None:
    return cfg.http_password(env=_env)
```

**Confirmed this EXACTLY matches Go's already-built `switch.go`** (read
directly, §0 above): `httpPassword *resolveOnce` (field, line 139),
`WithHTTPPasswordResolver` (option, lines 243-248), `FromConfig`'s two
independent closures (lines 344-354) both calling `cfg.HTTPPassword(os.
LookupEnv, nil)` — one wired into `WithNSDPPasswordResolver`, the other
into `WithHTTPPasswordResolver` — with the exact same doc-comment
justification already transcribed into the Go source ("Plus switches share
ONE web-admin password... do NOT add a separate config key now"). **This
plumbing needs ZERO additional Go work for slice 06** — `backend_http.go`'s
`buildHTTPWriter` simply calls `sw.httpPassword.resolve()` (mirroring
`buildNSDPWriter`'s `sw.nsdpPassword.resolve()` call in `backend_nsdp.go`
line 135) and gates a nil/empty result with a `requireHTTPPassword`-style
helper (mirroring `requireNSDPPassword`/`requireSNMPWriteCommunity`'s
shape — decide `nil`-only vs `nil-or-empty` rejection by checking Python's
`_require_http_password`'s exact falsy-check semantics, which reject BOTH
`None` and `""`, matching the write-side SNMP community gate's stricter
`community is None or community == ""` shape, not the NSDP password gate's
`is None`-only shape — this is worth getting right since the three
existing gates in this codebase are NOT uniform on this point, per
`backend_snmp.go`'s and `backend_nsdp.go`'s own doc comments calling out
this exact non-uniformity as deliberate).

Also relevant: `build_sync_cli_client` (slice-07 territory) similarly
reuses `self._resolve_http_password()` as the CLI SSH/telnet password by
default — a THIRD consumer of the same `http_password` value, out of scope
for slice 06 but worth knowing `httpPassword`'s Go cell will likely be
reused again when slice 07 lands.

---

## 8. Test inventory (tabulated)

292 total HTTP-related test functions across 14 files/locations (278 in
dedicated HTTP test files + 14 facade-intent tests scattered across
`test_sync_api.py`/`test_aio_api.py`), plus 67 fixture files.

| # | file | tests | covers |
|---|---|---:|---|
| 1a | `tests/protocols/http/test_crypt.py` | 4 | `merge`/`merge_hash_md5`, HTTP error hierarchy |
| 1b | `tests/protocols/http/test_endpoints.py` | 10 | per-model `HttpModelSpec` registry, one test per model family, incl. the 1841111 `reads_verified`/path corrections for gsm7228ps and gsm7252ps |
| 1c | `tests/protocols/http/test_forms.py` | 6 | Plus-CGI form encoders (PoE apply/reset, PVID, membership wire-code, VLAN add/delete/reboot) |
| 1d | `tests/protocols/http/test_parse.py` | 58 | every parser across every dialect; largest protocol-layer file |
| 2 | `tests/transport/test_http_client.py` | 35 | login/session transport layer, CSRF, cookie vs Gambit-token sessions, resource-leak guarantees |
| 3 | `tests/virtual/test_virtual_http_face.py` | 21 | the mock HTTP server end-to-end over a real bound socket, one block per dialect, incl. deterministic-stop-via-raw-fd-inspection (NOT `ResourceWarning`, proven unreliable) |
| 4 | `tests/virtual/test_web_projection.py` | 12 | state→HTML render paired against real parsers, STANDARD (gs305ep) dialect round-trip fidelity |
| 5 | `tests/test_http_dispatch.py` | 4 | `_dispatch.py` HTTP helpers: `require_http_backend`, `http_reads_supported`, `build_sync_http_client` |
| 6 | `tests/test_http_equivalence.py` | 2 | sync/async facade read+write parity over HTTP, gs305ep; documents `backend=Backend.HTTP` as now REQUIRED (not incidental) for a write the facade no longer silently re-routes |
| 7 | `tests/test_http_read.py` | 34 | `HttpReader`/`AsyncHttpReader` against every HTTP model via fixture-replaying fake session; incl. `test_gsm7252ps_every_read_op_is_served_over_http` (full parity) |
| 8 | `tests/test_http_write.py` | 50 | `HttpWriter`/`AsyncHttpWriter`, gs305ep-SPECIFIC write ops + SSL cert upload (multipart + XML); largest HTTP test file overall |
| 9 | `tests/test_http_vlan_membership.py` | 21 | PIN-CENTRAL: the §1.3/§2.1 VLAN-membership fix, fixture+mock evidence pairs, CURRENT-vs-CONFIGURED divergence pin, LAG-slot preservation, M4300-24X-refuses/16X-accepts counter-example pair |
| 10 | `tests/test_http_xui_writes.py` | 35 | PIN-CENTRAL: `set_port_enabled`/`set_mgmt_ip`/`clear_poe_fault` + the gsm7252ps PoE nav-field fix quartet of tests, GS110EMX's own mechanism + semicolon-terminated `PORT_NO` trap |
| 11 | `tests/http_specs.py` | 0 (helper) | `reads_verified(*model_keys)` contextmanager — a test-only seam that temporarily monkeypatches a spec's `reads_verified` flag, so parser/reader tests can exercise a not-yet-verified model without touching production code |
| 12 | facade intents: `tests/test_sync_api.py` (~8) + `tests/test_aio_api.py` (~6) | 14 | `backend=Backend.HTTP` explicit-selection contract tests (no dedicated `test_facade_http.py` exists in Python — scattered; a Go port choosing to consolidate this into one file is a deliberate structural improvement, not a straight port) |
| 13 | `tests/fixtures/http/` | 67 files | 58 `.html` real device captures (6 model families) + 9 `.xml` GoAhead `wcd` captures (gs728tpp only); 5 of the `.html` files are the PIN-NEW VLAN-membership-page captures, 3 more are PIN-NEW mgmt-IP captures |

**Standout pin-relevant test names worth the Go port replicating as named
equivalents** (non-exhaustive, the ones this dossier's own §1-§2 narrative
depends on):

- `test_fixture_current_and_configured_views_differ_on_real_hardware` —
  pins the ONE measured Current-vs-Configured divergence (gsm7252ps VLAN 1,
  ports 50/51) so a "simplification" refactor can't silently erase it.
- `test_mock_get_vlans_reports_tagged_and_untagged` — literally: "the
  defect this change closes: `get_vlans` used to return
  `untagged_ports=frozenset()` for every VLAN on every managed model."
- `test_mock_m4300_24x_refusal_is_surfaced_verbatim` /
  `test_mock_m4300_16x_accepts_what_the_24x_refuses` — counter-example
  pair so an over-fix of the refusal logic fails as loudly as a
  regression.
- `test_poe_apply_carries_the_pages_list_unit` /
  `test_gsm7252ps_poe_refuses_an_apply_with_no_list_unit` /
  `test_gsm7252ps_poe_refusal_names_every_rw_column_in_the_body` /
  `test_siblings_accept_a_poe_apply_with_no_list_unit` — the exact
  root-cause-fix quartet from this pin's namesake commit (§2.6).
- `test_gs110emx_port_no_must_be_semicolon_terminated` — the semicolon
  footgun (§2.5).
- `test_set_mgmt_ip_applies_and_verifies` — explicitly marked
  "UNVERIFIED-LIVE by design" in its own docstring (§2.7's caveat).
- `test_stop_closes_listening_socket_deterministically` — inspects the raw
  OS file descriptor directly rather than relying on `ResourceWarning`
  (proven unreliable under pytest's warning-filter machinery) — the Go
  equivalent should assert on the actual listener/connection lifecycle
  (e.g. attempting a new connection after `Stop()` returns `ECONNREFUSED`),
  not merely that `Stop()` returned without error.

---

## 9. Go porting notes

### 9.1 `net/http` face shape

`virtual/httpface.go` (new file) should mirror `virtual/snmpface.go`'s/
`virtual/nsdpface.go`'s established shape as closely as an HTTP/TCP server
allows: `NewHTTPFace(state *State, spec http.ModelSpec, host, password
string) *HTTPFace`; `Start() (port int, err error)` binds `net.Listen("tcp",
...)` on `host:0`, constructs an `*http.Server` with a handler closing over
the face, `go srv.Serve(ln)`; `Stop() error` calls `srv.Shutdown(ctx)` with
a bounded timeout (5s, matching Python's `join(timeout=5)`) then waits on a
`sync.WaitGroup` the serve goroutine signals — idempotent, safe to call
before Start or more than once, exactly like the UDP faces. See §3.1 above
for the one deliberate behavioral improvement (Go's `Shutdown` waits for
in-flight handlers; Python's doesn't) worth a doc comment, not a "fix".

### 9.2 `backend_http.go` shim — follows `backend_snmp.go`/`backend_nsdp.go` verbatim

```go
func init() {
    RegisterBackend(model.BackendHTTP, buildHTTPReader)
    RegisterWriteBackend(model.BackendHTTP, buildHTTPWriter)
}
```

`buildHTTPReader`/`buildHTTPWriter` check the `ReadsVerified`-equivalent
gate FIRST (§7.2), before ever touching `sw.httpPassword` — a gate failure
wraps `model.ErrUnsupportedCapability`, never cached (mirroring `readerFor`/
`writerFor`'s existing "builder error never cached" contract). No injected-
client field exists yet on `Switch` for HTTP (unlike `snmpClient`/
`nsdpClient`) — slice 06 should add one (`httpSession Session`, or similar,
mirroring `WithSNMPClient`/`WithNSDPClient`'s injection pattern for tests)
if test coverage needs to inject a fake `Session` the way NSDP/SNMP tests
inject fake clients today.

### 9.3 Byte-faithful renderer strategy — restated as the actionable recommendation

Per §4.8: hand-transcribe each model's literal HTML/XML page templates into
Go, using `strings.ReplaceAll`/`strings.NewReplacer` marker substitution
(NOT `text/template`, NOT `fmt.Sprintf` — both collide with the embedded
JS's literal `{`/`%` characters). Consider `//go:embed`-backed `.html`/
`.xml` fragment files per model to keep `.go` source files free of
multi-hundred-byte single-line literals. Exact byte-for-byte whitespace
fidelity is NOT required (§4.8's test-suite finding — Python itself doesn't
enforce it via automated fixture diff) but STRUCTURAL malformations
(GS110EMX's never-closed `<tr>`) and FIELD-ADDRESSING conventions (XE
coordinate-cells vs Cheetah comment-cells) ARE load-bearing and must be
reproduced exactly, since the corresponding Go parser (ported per Part 1)
is built specifically to read that exact shape back.

### 9.4 `Session` interface reuse — already specced in Part 1 §7.4

Part 1 already specs the `Session` interface (`Login`/`GetPage`/`PostForm`/
`PostMultipart`/`PostXML`, all `context.Context`-first) both the facade's
HTTP client and this dossier's virtual `HTTPFace` conceptually sit on
either side of — the face doesn't literally implement `Session` (it's a
server, not a client), but the SAME `MultipartFile`/`ModelSpec` types Part
1 §7.4 recommends for the client side should be reused verbatim for the
face's request-parsing side (§3.5's multipart parse, §2.3's cert-upload
form-field validation) rather than defining parallel types — one `http`
package, shared vocabulary between client and mock-server code, exactly
the role `snmp`/`nsdp` packages already play for their backends.

---

## 10. Completeness checklist

Every file/function/behavior this dossier covers, for cross-checking
against the Go port as it lands:

**http_read.py**: dialect dispatch table (all 9 ops × 7 dialects) ✓ §1.1 ·
`get_vlans` 3-way branch ✓ §1.2 · the VLAN-membership-read fix (endpoint
URLs, CURRENT-vs-CONFIGURED, wire-code inversion, two grid encodings) ✓ §1.3
· Plus-class membership quirks (`_membership_form`/`_require_csrf_hash`/
`_check_membership_is_for`, verbatim messages) ✓ §1.4 · `reads_verified`
construction-time gate ✓ §1.5 · unsupported-op messages ✓ §1.6 · model-type
mapping quirks (9 fields across 8 types) ✓ §1.7

**http_write.py**: per-op tabulation (9 ops × 3 dialect families) ✓ §2.1 ·
`_raise_on_fastpath_err_flag` ✓ §2.2 · SSL cert upload (RSA PKCS1
conversion, GoAhead XML template, GS3300 multipart, response-check
functions, verbatim error strings) ✓ §2.3 · `CERT_UPLOAD_KNOWN_
UNIMPLEMENTED` ✓ §2.3 · `_vlan_checkbox_index` ✓ §2.4 · GS110EMX
port-admin write (`PORT_NO` semicolon trap) ✓ §2.5 · gsm7252ps PoE fix root
cause (nav fields, omit sets, live A/B evidence) ✓ §2.6 ·
`set_port_enabled`/`set_mgmt_ip`/`clear_poe_fault` per-model
implementation status + `set_mgmt_ip`'s unverified-apply caveat ✓ §2.7

**virtual/faces/http.py**: bind/serve/stop shape ✓ §3.1 · all 5 login
handshakes ✓ §3.2 · per-dialect page dispatch (8-step chain) ✓ §3.3 ·
Referer/Origin 403 ✓ §3.4 · multipart cert upload validation ✓ §3.5 ·
GoAhead XML cert import + XXE hardening ✓ §3.6 · 404 handling + the
GS110EMX 200-with-404-body inconsistency ✓ §3.7 · threading lock scope ✓
§3.8 · form/cookie/body parsing details ✓ §3.9

**web.py + per-model renderers**: `web.py` shared dispatch + `"virtualhash"`
CSRF (never validated) ✓ §4.1 · full renderer inventory for gs105pe/
gs110emx(+templates)/gsm7252ps/gsm7228ps/m4300/gs728tpp ✓ §4.2 · the
never-closed-`<tr>` GS110EMX bug (exact quote + the accepted 2-byte
last-row deviation) ✓ §4.2 · "XE NAME cells" (coordinate addressing) ✓ §4.2
· "cheetah field comments" (name addressing) ✓ §4.2 · web_fastpath_vlan.py/
web_fastpath_xui.py shared scaffolding (nav block, omit shed-lists, two
grid generations) ✓ §4.3 · GoAhead wcd routing + cert import file-attribution
correction (belongs to web_gs728tpp.py, NOT cli_fastpath.py) ✓ §4.6 ·
cli_fastpath.py confirmed unrelated to HTTP ✓ §4.7 · byte-fidelity
strategy + recommendation ✓ §4.8

**Seed data**: existing Go field inventory (no gap: HTTPSensors/
SysinfoSensors/UploadedCert/ScpCertDeploySim) ✓ §5.1 · THE gap
(`VlanMembershipPageSim`/`vlan_membership_locked_ports`, per-model measured
table, required Go work) ✓ §5.2 · http_sensors per-model cross-check (no
gap) ✓ §5.3

**server.py**: independent per-backend bind + separate `http_port` field ✓
§6.1 · model list cross-check (exact match, no discrepancy) ✓ §6.2

**Facade**: `build_sync_http_client` construction-time behavior ✓ §7.1 ·
`http_reads_supported`/`reads_verified` gate ordering (before session
build, before password resolution) ✓ §7.2 · `scheme_verified`
(metadata-only, not enforced) ✓ §7.3 · `resolveBackend` explicit-HTTP-
selection (already correct in Go, confirmed) ✓ §7.4 · `httpPassword`
plumbing (already fully wired in Go, confirmed) ✓ §7.5

**Tests**: full tabulation, 292 functions across 14 files/locations + 67
fixtures ✓ §8

### 10.1 Ten trickiest traps (read this before writing a single line of Go)

1. **The VLAN-membership CURRENT-vs-CONFIGURED split is not a bug to
   "reconcile"** — reads must report CURRENT (`hiddenTagged`/
   `hiddenUnTagged`), writes must target and verify CONFIGURED
   (`hiddenMem`); they legitimately disagree on real hardware and a Go
   port that "fixes" the disagreement breaks parity with SNMP and with
   `show vlan`.
2. **Two INVERTED VLAN wire-code tables must never share an
   encoder/decoder**: Plus-CGI `8021qMembe.cgi` is `{1:Untagged,2:Tagged,
   3:Excluded}`; FASTPATH `hiddenMem` is `{1:Tagged,2:Untagged,
   3:Excluded}` — the exact inverse.
3. **The gsm7252ps PoE "refusal" was a CLIENT bug, not a device
   limitation** — every FASTPATH XUI apply must carry the page's `nav`
   fields (`v_1_1_1`/`v_1_3_1` list-unit aliases) and the correct
   per-button `omit` shed-list (APPLY omits the write-only Reset column;
   RESET omits every config column) — get either wrong and the symptom is
   IDENTICAL for every affected model (HTTP 200, `err_flag=1`, one
   per-column error line), impossible to distinguish from a genuine
   refusal without the A/B evidence this dossier records.
4. **`reads_verified` gates HttpReader/HttpWriter CONSTRUCTION, before any
   password resolution** — get the ordering backwards (resolve password
   first, gate second) and an unverified model raises `CredentialError`
   instead of the correct `UnsupportedCapabilityError`, changing the
   caller-visible error type for every unverified model.
5. **GS110EMX's `PORT_NO` must be semicolon-terminated** (`"3;"` not
   `"3"`) — a bare number is accepted with HTTP 200 and silently applies
   NOTHING; this is caught only by verify-after-write, and a Go port that
   "cleans up" the trailing semicolon as apparent noise reintroduces a
   real, previously-fixed bug.
6. **FASTPATH pages answer HTTP 200 even when refusing a write** — every
   apply must check the hidden `err_flag`/`err_msg` fields; a Go port that
   treats HTTP status alone as success/failure silently drops every
   refused write as if it had succeeded.
7. **The never-closed `<tr>` in GS110EMX's stats page is a faithfully-
   reproduced REAL FIRMWARE BUG**, not a mock authoring mistake — do not
   "fix" it by closing the tag; the matching Go parser must handle the
   malformed shape, matching Part 1's own parser-side documentation of the
   same quirk.
8. **XE-dialect cells are addressed by numeric COORDINATE
   (`v_1_2_6`), Cheetah/M4300 cells by semantic COMMENT NAME
   (`<!-- baseport_AdminMode -->`)** — despite a superficially near-
   identical `<TD>/<INPUT>` skeleton, these are opposite addressing
   conventions and must never share a cell-parsing helper between the two
   dialects.
9. **`set_mgmt_ip` on managed models is deliberately NEVER live-verified**
   (applying it for real risks stranding the session) — a Go port must
   carry this exact scope caveat in tests/docs, not silently present it as
   equally proven as `set_port_enabled`/`set_vlan_membership`.
10. **`VlanMembershipPageSim`-equivalent state does not exist in Go yet**
    (§5.2) — without it, nothing in the Go virtual HTTP face can render
    the VLAN Membership page for the four managed models at all; this is
    a hard prerequisite for porting §1.3/§2.1's fix, not an optional nice-
    to-have, and must land before (or as part of) the first PR that touches
    `virtual/httpface.go`.

---

## Part 1 cross-reference index

For convenience, the exact Part 1 section a Part 2 topic depends on:

| Part 2 topic | Part 1 section |
|---|---|
| `LoginScheme`/`HtmlDialect` enums | §1.1, §1.2 |
| `HttpModelSpec` full field list (incl. `reads_verified`/`scheme_verified`) | §1.4 |
| `HTTP_SPECS` per-model dump (all 8 models) | §1.5 |
| 1841111 endpoint-spec diffs (the `None`→real-path flips) | §1.6 |
| Every parser function (STANDARD/GS110EMX/GS105PE/M4300/XE/S3300/GOAHEAD) | §2.1-§2.10 |
| `parse_fastpath_membership` + the 8 helper functions | §2.9 |
| Every form encoder (incl. `xui_row_apply_form`'s `omit=` param) | §3 |
| `crypt.merge`/`merge_hash_md5` (full file, 30 lines) | §4 |
| `HttpSession`/`AsyncHttpSession` Protocol surface | §5.1 |
| `HttpSysInfo`, `FastpathMembership`, `XuiRow`, `XuiListPage`, `XuiFormPage` | §5.2, §5.3 |
| `HttpClient`/`AsyncHttpClient` (login, retry, referer, all 5 session methods) | §6 |
| `net/http` transport shape, regex-vs-goquery decision, MD5, `Session` Go interface | §7 |
| Completeness checklist + Part 1's own 10 trickiest traps | §8 |
