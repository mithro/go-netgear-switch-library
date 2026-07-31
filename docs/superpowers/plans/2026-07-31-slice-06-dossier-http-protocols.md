# Slice 06 Dossier PART 1: HTTP protocol layer + transport (Python → Go porting reference)

> **Source of truth:** `/home/tim/github/mithro/python-netgear-switch-library`
> — frozen snapshot worktree:
> `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1841111`
> (read implementation files from the SNAPSHOT path, never the live checkout).
> **Pin guard verified**: `git -C <snapshot> rev-parse HEAD` returns
> `1841111c6d0b55ad3eece915e57ba115a0cfdd12` — starts with `1841111`. **PASS.**
> All line numbers/values below are transcribed exactly from that pin. This
> document targets Go engineers porting the PURE HTTP PROTOCOL LAYER + wire
> transport 1:1 without reading the Python source themselves.
>
> **Scope**: `src/netgear_switch/protocols/http/{endpoints,parse,forms,crypt,
> session,types}.py` + `src/netgear_switch/transport/http/client.py`. This is
> PART 1 of two dossiers for slice 06 — the reader/writer orchestration layer
> (`http_read.py`/`http_write.py`), the virtual HTTP face + byte-faithful
> `web_*.py` renderers, seed HTTP fixture data, the facade shim
> (`http_backend.go`) and `reads_verified` gating, and tests are OUT OF SCOPE
> here — see "Part 2 handoff" at the end of this file.
>
> **Cross-reference (Go side, already built)**: `backend_snmp.go`/
> `backend_nsdp.go` establish the per-backend shim pattern slice 06's
> `http_backend.go` must follow (root-package file, `init()` calls
> `RegisterBackend`/`RegisterWriteBackend`, builder reads `Switch`'s unexported
> fields). `switch.go` already has the `httpPassword *resolveOnce` cell and
> `WithHTTPPasswordResolver` option wired end-to-end (lines 139, 246-248,
> 293, 314-354) — slice 06 only needs to CONSUME them, not add them.
> `model/errors.go` already declares `ErrHTTP`/`ErrHTTPAuth`/
> `ErrHTTPUnexpectedPage` (specializing `ErrHTTP`, matchable via
> `errors.Is(err, model.ErrHTTP)` for either). `model/registry.go` already
> lists every HTTP-capable model with `BackendHTTP` in its `Backends` slice:
> gs305ep, gs110emx, gsm7228ps (alias `s3300`), gs105pe, m4300-24x, m4300-16x,
> gsm7252ps, gs728tpp — the same eight this dossier covers.

---

## 0. File inventory + line counts (this pin)

| file | lines | covers |
|---|---|---|
| `src/netgear_switch/protocols/http/endpoints.py` | 969 | `LoginScheme`, `HtmlDialect`, `HttpModelSpec`, `HTTP_SPECS` (8 models) |
| `src/netgear_switch/protocols/http/parse.py` | 2772 | every HTML/XML parser, pure regex + one `ElementTree` XML parser |
| `src/netgear_switch/protocols/http/forms.py` | 273 | pure write-form encoders |
| `src/netgear_switch/protocols/http/crypt.py` | 30 | `merge`/`merge_hash_md5` |
| `src/netgear_switch/protocols/http/session.py` | 59 | `MultipartFile`, `HttpSession`/`AsyncHttpSession` Protocols |
| `src/netgear_switch/protocols/http/types.py` | 202 | `FastpathMembership`, `XuiRow`, `XuiListPage`, `XuiFormPage`, `HttpSysInfo` |
| `src/netgear_switch/transport/http/client.py` | 574 | `HttpClient`/`AsyncHttpClient` (httpx) |
| **total** | **4879** | |

No `lxml`/`bs4`/BeautifulSoup dependency anywhere: `parse.py` is 100% `re` +
stdlib `xml.etree.ElementTree` (only for the one XML dialect, GOAHEAD_XML).
This matters for the Go port: a pure `regexp`-based port is a faithful 1:1
translation; pulling in `goquery` would be an *upgrade*, not a port, and risks
behaving subtly differently on the malformed/quirky real-world HTML these
parsers were built against (see §7.2).

---

## 1. `protocols/http/endpoints.py` — per-model spec (pure data)

### 1.1 `LoginScheme` enum — all 5 values

```python
class LoginScheme(enum.Enum):
    MERGE_HASH_CGI = "merge_hash_cgi"  # Plus SID scheme (gs305ep, gs105pe) — GROUNDED
    GAMBIT = "gambit"                  # EMx merge-hash + token (gs110emx) — GROUNDED
    CHEETAH_FORM = "cheetah_form"      # Pro/S3300/gsm7252ps — plaintext form
    CHEETAH_V1 = "cheetah_v1"          # M4300 /v1 — uname+pwd + Referer CSRF
    XML_API = "xml_api"                # GS728TPP GoAhead XML API — 3-step handshake
```

Exact wire flow per scheme (from `endpoints.py` docstrings + `client.py`):

**MERGE_HASH_CGI** (gs305ep, gs105pe):
1. `GET /login.cgi` → scrape `<input id="rand" value="...">` (`parse_login_rand`).
2. `POST /login.cgi` with body `{"password": merge_hash_md5(password, rand)}`.
3. Success ⇒ response sets an `SID` cookie (`cookie_name="SID"`). No cookie ⇒
   `HttpAuthError`.
4. Every subsequent GET/POST rides the cookie jar automatically (httpx
   `Client.cookies`); no per-request token needed.

**GAMBIT** (gs110emx):
1. `GET /` (the `login_path`, NOT the POST target) → scrape the same
   `id="rand"` nonce off the home page.
2. `POST /redirect.html` (`login_post_path`, DIFFERENT from `login_path`) with
   body `{"LoginPassword": merge_hash_md5(password, rand)}`.
3. Success ⇒ the response body is an auto-submit form carrying
   `<input type="hidden" name="Gambit" value="...">` — this is a **TOKEN, not
   a cookie**: no `Set-Cookie` is ever sent on this firmware. `cookie_name=""`
   (unused).
4. Every later GET carries `?Gambit=<token>` as a query param; every POST
   carries `Gambit=<token>` as an extra form field (`session_token_field=
   "Gambit"`). See `_token_params`/`_token_form_field` in client.py.
5. Empty-string token (rejected login) and `None` (field absent) are both
   falsy ⇒ `HttpAuthError`.

**CHEETAH_FORM** (gsm7228ps/S3300, gsm7252ps):
1. `POST /base/cheetah_login.html` directly — **NO GET-for-nonce step**
   (`needs_rand=False`).
2. Body is `{password_field: <plaintext password>}` PLUS, only when the spec
   names a `username_field`, `{username_field: username}` too. gsm7228ps has
   no `username_field` (password-only, matches `S3300Updater`); gsm7252ps DOES
   validate a username and sets `username_field="uname"`, `username="admin"`.
3. Success ⇒ `SID` cookie. No cookie ⇒ `HttpAuthError`.

**CHEETAH_V1** (m4300-24x, m4300-16x):
1. `GET /` (`login_path`) → scrape the login page for an OPTIONAL
   `CSRFToken` hidden input (`_cheetah_csrf_token`, regex tolerant of
   attribute order: `name=` before or after `value=`). Older 24X firmware has
   none; the AV-era 16X firmware (HTTPS on :49152) does.
2. `POST /v1/base/cheetah_login.html` (`login_post_path`) with body
   `{uname_field: "admin", pwd_field: password}` + `{"CSRFToken": token}` IF
   a token was scraped. **NO password hashing at all** — plaintext, and
   `needs_rand=False`.
3. Success ⇒ `SID` cookie (24X) or `SIDSSL` cookie (16X, `cookie_name=
   "SIDSSL"`). Critically, on the 16X the cookie is **bound to the CSRFToken**:
   a login POST that omits the token still gets a `SIDSSL` cookie back, but
   every later read 302-bounces to the login page (unbound session) — so the
   token is not optional in practice on that SKU even though the code path
   tolerates its absence.
4. **Every subsequent request** (GET and POST) on a `needs_referer=True`
   model MUST carry `Referer: <scheme>://<host>/` or the switch answers
   `403 Forbidden` (CSRF guard). On POSTs to the AV-era 16X it ALSO needs
   `Origin: <scheme>://<host>` — Referer alone gets 403 on POST even though
   GET succeeds with Referer alone. Referer's host MUST include the port
   verbatim when non-standard (`:49152`) — an origin-exact check; dropping
   the port also 403s. See `_referer_headers` in client.py §6.6.

**XML_API** (gs728tpp) — the one genuinely THREE-STEP handshake, not a form POST:
1. `GET /` with `follow_redirects=False` → a `302` whose `Location` header
   carries an opaque per-session path segment, e.g. `/cs5f72b8e1/...`.
   Extracted via `_XML_API_SESSION_PATH_RE = re.compile(r"/([A-Za-z0-9]+)/")`.
   No `Location` / no match ⇒ `HttpAuthError`.
2. `GET /<sess>/System.xml?action=login&user=<user>&password=<password>`
   (URL-quoted). Plaintext password in the query string (matches
   `GS728TPPUpdater`).
3. Success is judged by TWO independent signals, BOTH required:
   - Response body contains the literal substring `<statusCode>0</statusCode>`.
   - Response carries a `sessionID` **response header** (never a
     `Set-Cookie` on this firmware).
   Either missing ⇒ `HttpAuthError` (wrong password, or switch locked out).
4. On success the client itself SETS three cookies into the jar:
   `userStatus=ok`, `usernme=<user>` (note: NOT "username" — that's the
   firmware's actual misspelling, preserve verbatim), `sessionID=<header
   value>` (`cookie_name="sessionID"`).
5. **Every subsequent read is a GET under the session path**: the transport
   prefixes every `path` handed to `get_page`/`post_xml` with
   `/<sess>/` before dispatching (`_read_url`, both sync/async clients). The
   "path" values in `HttpModelSpec` for this model are themselves `wcd?{...}`
   query strings (see §1.5 gs728tpp), so the final URL is
   `/<sess>/wcd?{file=...}{...}`.

### 1.2 `HtmlDialect` enum — all 7 values (CORRECTED: 7 not 6; S3300 is the 7th, used by gsm7228ps — verified vs source Task-1 review)

```python
class HtmlDialect(enum.Enum):
    STANDARD = "standard"        # gs305ep CGI: closed portID rows, vlanck checkboxes
    GS110EMX = "gs110emx"        # real GS110EMX: open portID rows, Advanced-802.1Q list
    GS105PE = "gs105pe"          # real GS105PE: status.cgi layout, hidden-input counters
    M4300 = "m4300"              # real M4300 Cheetah /v1: xid hidden inputs + field comments
    XE_FASTPATH = "xe_fastpath"  # "auto-generated by XE" pages (gsm7252ps): coordinate-addressed, NO comments
    S3300 = "s3300"              # gsm7228ps: same XE grid as gsm7252ps + 3 model-specific pages
    GOAHEAD_XML = "goahead_xml"  # gs728tpp: wcd DeviceConfiguration XML data blocks
```

Which model uses which dialect (`html_dialect=` field of `HttpModelSpec`,
default is `STANDARD`):

| model | dialect |
|---|---|
| gs305ep | STANDARD (default, not set explicitly) |
| gs110emx | GS110EMX |
| gsm7228ps | S3300 |
| gs105pe | GS105PE |
| m4300-24x | M4300 |
| m4300-16x | M4300 (inherited via `dataclasses.replace`) |
| gsm7252ps | XE_FASTPATH |
| gs728tpp | GOAHEAD_XML |

Dialect → parser-set selection is entirely a `http_read.py` concern (Part 2);
this dossier only records WHICH parser FUNCTIONS exist per dialect (§2).

Key wire-shape facts that justify each dialect being separate (not
collapsible into one parser with flags):

- **STANDARD vs GS110EMX**: STANDARD's `<tr class="portID">` rows are always
  properly closed (`_ROW_RE`, requires a matching `</tr>`); real GS110EMX
  firmware **never closes the row** (`_OPEN_ROW_RE`, cuts at the next `<tr`
  or `</table>` instead). A STANDARD-style parser fed GS110EMX HTML would
  swallow every row after the first into one giant "row".
- **GS105PE**: its own `<tr class="portID">` shape allows trailing attributes
  (`<tr class="portID" name="portID">` on `portStatistics.cgi` specifically)
  AND never closes either (`_GS105PE_ROW_RE`, its own open-row regex, subtly
  different from GS110EMX's). Its counters are HIDDEN 32-bit half-pairs, not
  visible `<td>` text (§2.3).
- **M4300 vs XE_FASTPATH**: both are "FASTPATH auto-generated" pages sharing
  the `<unit>.<row>.<count>.v_<a>_<b>_<c>` hidden-input NAME shape, but M4300
  pages carry a trailing `<!-- field_name -->` HTML comment naming each
  cell SEMANTICALLY, so cells address BY NAME (immune to column reorder).
  XE_FASTPATH pages carry NO such comment — cells address ONLY by their
  numeric COLUMN COORDINATE (`1_2_10`), scraped once per page from that
  page's own visible header row and hardcoded as a constant (e.g.
  `_XE_PORT_LINK = "1_2_10"`).
- **S3300**: reuses every `parse_xe_*` parser (same grid) EXCEPT three pages
  that differ: (1) `basicAddressTable.html` columns are SHIFTED (VLAN cell is
  `v_1_2_2` not `v_1_2_1`) and port ifNames are HTML-entity-escaped `1/gN`/
  `1/xgN` Smart-firmware form, not `1/0/N`; (2) `sysInfo.html` carries ONLY
  the base MAC (no IPv4 fields — those moved to `/ipConfiguration.html`,
  read via the shared `parse_xui_mgmt_ip`); (3) no live fan/temp sensor table
  ⇒ `get_sensors` unsupported over HTTP for this model.
- **GOAHEAD_XML**: the only dialect that is not HTML-scraping at all — a real
  (if hand-sliced) XML parse via stdlib `ElementTree`.

### 1.3 `XuiMgmtIpFields` dataclass — every field

```python
@dataclass(frozen=True)
class XuiMgmtIpFields:
    address: str
    netmask: str
    gateway: str
    mode: str            # field carrying the addressing METHOD
    static_value: str    # value of `mode` meaning static
    dhcp_value: str      # value of `mode` meaning DHCP
    apply_button: str    # the page's APPLY button field name
```

Deliberately PER-MODEL, never shared by dialect (two Cheetah families put the
management-IP info on different pages under different field names, and one
field NAME that looks shared means DIFFERENT things on two boxes of the same
family — see the two constant instances below).

```python
_GSM72XX_MGMT_IP_FIELDS = XuiMgmtIpFields(
    address="v_1_1_1", netmask="v_1_2_1", gateway="v_1_3_1",
    mode="v_1_18_1",          # the HIDDEN twin of the visible radio (v_1_8_1 on
                               # gsm7252ps, v_1_4_1 on gsm7228ps -- same name,
                               # different meaning per box, so ONLY the hidden
                               # one is used)
    static_value="None",      # allWebEnums e_v_1_18_1 = ["None","Bootp","DHCP"]
    dhcp_value="DHCP",
    apply_button="v_3_1_1",
)
_M4300_MGMT_IP_FIELDS = XuiMgmtIpFields(
    address="v_1_6_1", netmask="v_1_7_1", gateway="v_1_71_1",
    mode="v_1_5_3",           # xeData["xew_1_5_3_Enable"] = "DHCP" (page's own JS)
    static_value="Disable",   # xew_1_5_3_Disable = "Manual"
    dhcp_value="Enable",      # xew_1_5_3_Enable = "DHCP"
    apply_button="v_3_1_1",
)
```

Trap: on gsm7252ps/gsm7228ps, `/v1/mgmtVlanIpv4Configuration.html` (the
M4300's page) 404s; on both M4300 SKUs, `/v1/ipConfiguration.html` exists and
answers `200` but is the (unused) SERVICE-PORT interface — reads
`0.0.0.0/0.0.0.0` on both, so reading mgmt-IP from it would report the switch
as unaddressed. `mgmt_ip_path`/`mgmt_ip_fields` on `HttpModelSpec` are the
guard against this: they point at the RIGHT page, not the plausible one.

### 1.4 `HttpModelSpec` dataclass — EVERY field (34 total)

```python
@dataclass(frozen=True)
class HttpModelSpec:
    model_key: str
    scheme: LoginScheme
    scheme_verified: bool
    login_path: str
    password_field: str
    cookie_name: str                 # "" = unused (token-session model instead)
    needs_rand: bool
    dashboard_path: str | None
    stats_path: str | None
    poe_config_path: str | None
    poe_status_path: str | None
    vlan_config_path: str | None
    vlan_membership_path: str | None
    pvid_path: str | None
    reboot_path: str | None
    logout_path: str | None
    is_epx_poe: bool
    reads_verified: bool
    session_token_field: str | None = None       # e.g. "Gambit" (GAMBIT scheme)
    login_post_path: str | None = None            # POST target, if != login_path
    sysinfo_path: str | None = None                # device identity + mgmt-IP page
    mgmt_ip_path: str | None = None                # SEPARATE mgmt-IP page, if not sysinfo_path
    html_dialect: HtmlDialect = HtmlDialect.STANDARD
    mac_table_path: str | None = None
    username_field: str | None = None              # None = password-only login
    username: str = "admin"
    needs_referer: bool = False                     # M4300 /v1 CSRF guard
    lldp_path: str | None = None
    cert_upload_path: str | None = None
    cert_upload_file_field: str | None = None       # multipart file field name
    cert_upload_form_fields: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    secure: bool = False                             # True = https:// (M4300-16X :49152)
    vlan_membership_post_path: str | None = None    # POST target, if != vlan_membership_path
    web_port: int | None = None                      # non-standard TCP port
    port_config_path: str | None = None              # per-port ADMIN-MODE write page
    mgmt_ip_fields: XuiMgmtIpFields | None = None
```

Field-by-field semantics worth calling out for the Go port (Go struct field
docs should preserve these):

- **`cookie_name` vs `session_token_field`**: mutually exclusive — a model
  has EITHER a cookie session (`cookie_name` set, `session_token_field=None`)
  OR a token session (`cookie_name=""`, `session_token_field` set). Only
  gs110emx (GAMBIT) uses a token session; every other model uses a cookie.
  A Go `Session`/`Spec` type could model this as two pointer fields or (more
  idiomatically) as a small closed sum — see §7.4.
- **`login_post_path`**: `None` means POST goes to `login_path` itself
  (gs305ep, gs105pe, gsm7228ps, gsm7252ps). Two models diverge: gs110emx GETs
  `/` for the nonce but POSTs to `/redirect.html`; the M4300s GET `/` but POST
  to `/v1/base/cheetah_login.html`.
- **`sysinfo_path` vs `mgmt_ip_path`**: `mgmt_ip_path` is the escape hatch for
  a model whose mgmt-IP lives on a DIFFERENT page than device
  identity/sensors. Set for gsm7228ps, gsm7252ps, m4300-24x/16x (all XUI
  models, where identity is on `sysInfo.html` but IP config is on
  `ipConfiguration.html`/`mgmtVlanIpv4Configuration.html`) and gs728tpp (a
  separate `wcd` query). `None` (gs305ep, gs110emx, gs105pe) means mgmt-IP is
  read from `sysinfo_path` itself, or is unsupported when THAT is also
  `None` (gs305ep has neither — its mgmt-IP comes from NSDP/SNMP instead).
- **`is_epx_poe`**: only `True` for gs305ep — feeds `poe_apply_form`'s
  `POW_LIMT_TYP` field (`"2"` when true, `"0"` otherwise); see §3.
- **`web_port`**: only set for m4300-16x (`49152`). The facade forms the host
  as `<ip>:<web_port>` when non-nil.
- **`mgmt_ip_fields`**: only set alongside `mgmt_ip_path` for the four XUI
  models (gsm7228ps, gsm7252ps, m4300-24x, m4300-16x — the last inherits it
  from the 24X via `dataclasses.replace`). `None` for the CGI/Gambit/GoAhead
  models, whose mgmt-IP pages are shaped completely differently.
- **`cert_upload_form_fields`**: uses `default_factory=lambda:
  MappingProxyType({})`, NOT a bare mutable default — the comment explains
  this is a Python-3.11-vs-3.12 dataclass compatibility fix (`mappingproxy`
  as a bare default errors on 3.11, "tolerated" on 3.12). Not relevant to Go
  (no dataclass mutable-default rule), but the resulting map MUST still be
  treated as immutable/read-only in the Go equivalent (a package-level `var`
  literal, never mutated in place).

### 1.5 `HTTP_SPECS` — every field, every model (8 entries)

The registry `_SPECS`/`HTTP_SPECS` maps `model_key -> HttpModelSpec`.
Below is every field the endpoints.py source actually sets, per model
(fields omitted use the dataclass default shown in §1.4). `http_spec(model)`
looks the model up, raising `UnsupportedCapabilityError` if the model has no
`Backend.HTTP` at all, or (a defensive belt-and-braces case) has the backend
flag but no registered spec.

#### gs305ep (`_GS305EP`, lines 376-395)

Fully GROUNDED: `py_netgear_plus/models.py` (GS30xSeries/GS30xEPxSeries) +
`rcfiles/bin/netgear-smp-vlan` (merge-hash scheme, `8021qCf.cgi`/
`8021qMembe.cgi`/`portPVID.cgi` field shapes, wire codes). `sysinfo_path` is
DELIBERATELY still `None` — copying gs105pe's `/switch_info.cgi` here was
tried and rejected: the fleet units were all powered off during the capture
session, so it was never confirmed live and copying-across-siblings is
exactly the mistake that made the ORIGINAL gs305ep-derived gs105pe paths
wrong (see gs105pe below).

| field | value |
|---|---|
| scheme | MERGE_HASH_CGI |
| scheme_verified | True |
| login_path | `/login.cgi` |
| password_field | `password` |
| cookie_name | `SID` |
| needs_rand | True |
| dashboard_path | `/dashboard.cgi` |
| stats_path | `/portStatistics.cgi` |
| poe_config_path | `/PoEPortConfig.cgi` |
| poe_status_path | `/getPoePortStatus.cgi` |
| vlan_config_path | `/8021qCf.cgi` |
| vlan_membership_path | `/8021qMembe.cgi` |
| pvid_path | `/portPVID.cgi` |
| reboot_path | `/device_reboot.cgi` |
| logout_path | `/logout.cgi` |
| is_epx_poe | True |
| reads_verified | True |
| html_dialect | STANDARD (default) |
| everything else | default (sysinfo_path=None, mac_table_path=None, lldp_path=None, port_config_path=None, cert_upload=None, secure=False, web_port=None) |

#### gs110emx (`_GS110EMX`, lines 449-497)

GROUNDED in real captures (`tests/fixtures/http/gs110emx_*.html`) + live
2026-07-21/07-30/07-31 discovery on 10.1.5.25 (fw 1.0.2.8). HTTP covers the
FULL NSDP read surface here (an earlier probe wrongly concluded "NSDP-only"
after guessing wrong URLs and getting 404s — the real URLs live only as JS
string literals in `/frame.js`, harvested live).

| field | value |
|---|---|
| scheme | GAMBIT |
| scheme_verified | True |
| login_path | `/` |
| login_post_path | `/redirect.html` |
| password_field | `LoginPassword` |
| cookie_name | `""` (unused) |
| session_token_field | `Gambit` |
| needs_rand | True |
| dashboard_path | `/iss/specific/port_settings.html` |
| port_config_path | `/iss/specific/port_settings.html` (SAME page — LIVE-VERIFIED 2026-07-31, see §1.6 for the write mechanism) |
| stats_path | `/iss/specific/interface_stats.html` |
| sysinfo_path | `/iss/specific/sysInfo.html` |
| poe_config_path / poe_status_path | `None` / `None` (confirmed 404 — genuinely no PoE) |
| vlan_config_path | `/iss/specific/Cf8021q.html` |
| vlan_membership_path | `/iss/specific/vlanMembership.html` |
| pvid_path | `/iss/specific/vlan_pvidsetting.html` |
| reboot_path | `/iss/specific/sys_reload.html` (LIVE-DISCOVERED 2026-07-31) |
| logout_path | `/iss/specific/logout.html` (LIVE-DISCOVERED 2026-07-31, confirmed to actually end the session) |
| mac_table_path / lldp_path | `None` / `None` — ENUMERATED absent (39 harvested page literals contain neither; plausible-name probes 404'd; NSDP tag sweep also found neither) |
| is_epx_poe | False |
| reads_verified | True (caveat: only VLAN 1's membership page was captured; DHCP branch of sysInfo inferred, not captured — see `HttpSysInfo` §5.2) |
| html_dialect | GS110EMX |

#### gsm7228ps (`_GSM7228PS`, lines 514-592)

Login GROUNDED in `certbot-hook-netgear-switches/netgear-updater.py`
(`S3300Updater`). Read pages LIVE-VERIFIED on real S3300-52X (10.1.5.11,
2026-07-30): ports/stats/PVIDs/VLANs/PoE/LLDP EQUAL SNMP exactly (52/5/52/48/
52/2). `mgmt_ip_path` is a 1841111 CORRECTION — this spec used to claim the
IPv4 address was on an "unreachable JS-menu-only page"; that was wrong.

| field | value |
|---|---|
| scheme | CHEETAH_FORM |
| scheme_verified | True |
| login_path | `/base/cheetah_login.html` |
| password_field | `pwd` |
| username_field | `uname` |
| username | `admin` |
| cookie_name | `SID` |
| needs_rand | False |
| dashboard_path | `/portsConfiguration.html` |
| port_config_path | `/portsConfiguration.html` (`_FASTPATH_PORT_CONFIG`) |
| stats_path | `/portStatistics.html` |
| sysinfo_path | `/base/system/management/sysInfo.html` (base MAC only) |
| mgmt_ip_path | `/ipConfiguration.html` (`_GSM72XX_MGMT_IP`) — CORRECTED 2026-07-30 |
| mgmt_ip_fields | `_GSM72XX_MGMT_IP_FIELDS` |
| mac_table_path | `/basicAddressTable.html` |
| lldp_path | `/lldpRemoteInventory.html` |
| poe_config_path / poe_status_path | `/poeInterfaceConfiguration.html` / same |
| vlan_config_path | `/vlanStatus.html` |
| vlan_membership_path | `/switching/dot1q/vlan_port_cfg.html` (`_FASTPATH_VLAN_MEMBERSHIP`) — LIVE-DISCOVERED 2026-07-30 |
| vlan_membership_post_path | `/switching/dot1q/vlan_port_cfg_rw.html` |
| pvid_path | `/portPvidConfiguration.html` |
| reboot_path / logout_path | `None` / `None` (never captured, not guessed) |
| is_epx_poe | False |
| reads_verified | True |
| html_dialect | S3300 |
| cert_upload_path | `/http_file_download.html/a1` |
| cert_upload_file_field | `.v_1_3_1_handle` |
| cert_upload_form_fields | 19-key `MappingProxyType` — see §1.4/source lines 566-591, copied field-for-field from `S3300Updater.upload_certificate` |

Cert-upload form fields verbatim (all 19, values exactly as in source):
`v_1_1_3="HTTP"`, `v_1_1_2="SSL Server Certificate PEM File"`, `v_1_2_1=""`,
`v_1_3_2=" not in progress"`, `v_1_3_3=""`, `v_1_3_4=""`, `v_1_9_1="image1"`,
`v_1_9_5=""`, `v_1_9_2="1"`, `v_1_9_3="Enable"`, `v_1_19_1="32"`,
`v_1_20_1=""`, `v_1_200_1=""`, `v_2_3_1=" not in progress"`,
`v_2_4_3="None"`, `v_2_4_2=" not in progress"`, `v_4_1_1=""`,
`submit_flag="8"`, `submit_target="http_file_download.html"`,
`err_flag="0"`, `err_msg=""`, `clazz_information="http_file_download.html"`.

#### gs105pe (`_GS105PE`, lines 603-630)

LIVE-VERIFIED 2026-07-21 on real units (10.1.5.29/.30). Login scheme is
BYTE-IDENTICAL to gs305ep's — but the READ paths are NOT gs305ep's: those
copies were PARTLY WRONG on real hardware (`dashboard.cgi` and
`getPoePortStatus.cgi` both 404).

| field | value |
|---|---|
| scheme | MERGE_HASH_CGI |
| scheme_verified | True |
| login_path | `/login.cgi` |
| password_field | `password` |
| cookie_name | `SID` |
| needs_rand | True |
| dashboard_path | `/status.cgi` (NOT `dashboard.cgi`) |
| stats_path | `/portStatistics.cgi` |
| sysinfo_path | `/switch_info.cgi` |
| poe_config_path / poe_status_path | `None` / `None` — CONFIRMED 404: this is PoE pass-through, not a PSE (matches `poe_port_count=0` in the registry) |
| vlan_config_path | `/8021qCf.cgi` |
| vlan_membership_path | `/8021qMembe.cgi` |
| pvid_path | `/portPVID.cgi` |
| reboot_path | `/device_reboot.cgi` |
| logout_path | `/logout.cgi` |
| is_epx_poe | False |
| reads_verified | True |
| html_dialect | GS105PE |

#### m4300-24x (`_M4300`, lines 647-720)

LIVE-VERIFIED 2026-07-21/07-30/07-31 against real M4300-24X (10.1.5.13).
URLs recovered by harvesting `SetLinkPage('<page>')` handlers from a real
browser session (the Cheetah `/v1` menu is built at runtime in JS, not
statically discoverable). `lldp_path` is a 1841111 CORRECTION (was `None`
with a claim of "no chassis/port-id table available" — wrong, see below).

| field | value |
|---|---|
| scheme | CHEETAH_V1 |
| scheme_verified | True |
| login_path | `/` |
| login_post_path | `/v1/base/cheetah_login.html` |
| password_field | `pwd` |
| username_field | `uname` |
| username | `admin` (default) |
| cookie_name | `SID` |
| needs_rand | False |
| needs_referer | True |
| dashboard_path | `/v1/portsConfiguration.html` |
| port_config_path | `/v1/portsConfiguration.html` |
| stats_path | `/v1/portStatistics.html` |
| sysinfo_path | `/v1/base/system/management/sysInfo.html` |
| mgmt_ip_path | `/v1/mgmtVlanIpv4Configuration.html` (`_M4300_MGMT_IP`) |
| mgmt_ip_fields | `_M4300_MGMT_IP_FIELDS` |
| mac_table_path | `/v1/basicAddressTable.html` |
| lldp_path | `/v1/lldpRemoteInventory.html` — CORRECTED 2026-07-31 (SAME page the XE models use; found via `/v1/base/js/ng_sideNav.js`'s 463 page literals; `parse_xe_lldp` reads it EXACTLY equal to SNMP, 11/11 neighbours) |
| poe_config_path / poe_status_path | `None` / `None` — the 24X genuinely has no PoE (LIVE-MEASURED: page answers `200` with the full button set and ZERO `<TR p=...>` rows, not a 404) |
| vlan_config_path | `/v1/vlanStatus.html` |
| vlan_membership_path | `/v1/switching/dot1q/vlan_port_cfg.html` (`_M4300_VLAN_MEMBERSHIP`) — LIVE-DISCOVERED 2026-07-30 |
| vlan_membership_post_path | `/v1/switching/dot1q/vlan_port_cfg_rw.html` |
| pvid_path | `/v1/portPvidConfiguration.html` |
| reboot_path / logout_path | `None` / `None` (never captured) |
| is_epx_poe | False |
| reads_verified | True |
| html_dialect | M4300 |

#### m4300-16x (`_M4300_16X`, lines 740-762)

Built via `dataclasses.replace(_M4300, ...)` — INHERITS every field above
except the ones explicitly overridden. **NOT independently captured** for
scheme/paths (inherited "verified for the firmware family", not "captured
from a 16X") — but its PoE fields and `reads_verified` ARE independently
live-verified on the real unit (10.1.5.20:49152).

| field | value (override, else same as m4300-24x) |
|---|---|
| model_key | `m4300-16x` |
| reads_verified | `True` — LIVE cross-verified 2026-07-30: every HTTP read (ports/stats/PVIDs/VLANs/MACs/mgmt-IP + PoE) matches SNMP |
| cookie_name | `SIDSSL` (NOT `SID` — confirmed live) |
| poe_status_path | `/v1/poeInterfaceConfiguration.html` |
| poe_config_path | `/v1/poeInterfaceConfiguration.html` (SAME page, and it WRITES — live-proven by toggling Port Priority Low→High→Low and reading it back) |
| secure | `True` |
| web_port | `49152` |

Transport quirks specific to this SKU (not spec fields, but load-bearing for
the Go transport — see §6.6): this firmware answers `403 Forbidden` to EVERY
POST unless BOTH `Referer` and `Origin` headers are present (Referer alone
suffices for GET, not POST); it also issues a per-page `CSRFToken` hidden
field on its VLAN-membership form that a POST must echo back or get 403.

#### gsm7252ps (`_GSM7252PS`, lines 796-856)

LOGIN LIVE-VALIDATED against 10.1.5.22 (2026-07-22). Read pages at the ROOT
prefix (not `/base/` or `/v1/`), GROUNDED in real captures
(`tests/fixtures/http/gsm7252ps_*.html`). `poe_config_path` is a 1841111
CORRECTION — was `None` with a wrongly-blamed "the form refuses every
write" note; see §1.6.

| field | value |
|---|---|
| scheme | CHEETAH_FORM |
| scheme_verified | True |
| login_path | `/base/cheetah_login.html` |
| password_field | `pwd` |
| username_field | `uname` |
| username | `admin` |
| cookie_name | `SID` |
| needs_rand | False |
| dashboard_path | `/portsConfiguration.html` |
| port_config_path | `/portsConfiguration.html` |
| stats_path | `/portStatistics.html` |
| sysinfo_path | `/base/system/management/sysInfo.html` |
| mgmt_ip_path | `/ipConfiguration.html` (`_GSM72XX_MGMT_IP`) — moved off sysInfo (which lacks gateway/DHCP indicator) |
| mgmt_ip_fields | `_GSM72XX_MGMT_IP_FIELDS` |
| mac_table_path | `/basicAddressTable.html` |
| lldp_path | `/lldpRemoteInventory.html` |
| poe_config_path | `/poeInterfaceConfiguration.html` (`_FASTPATH_POE_CONFIG`) — **NOW WRITABLE**, LIVE-VERIFIED 2026-07-31 (Enable→Disable→Enable on port 1/0/35, `err_flag=0` each time; see §1.6 for the required-field discovery) |
| poe_status_path | `/poeInterfaceConfiguration.html` (same) |
| vlan_config_path | `/vlanStatus.html` |
| vlan_membership_path | `/switching/dot1q/vlan_port_cfg.html` — LIVE-DISCOVERED 2026-07-30 |
| vlan_membership_post_path | `/switching/dot1q/vlan_port_cfg_rw.html` |
| pvid_path | `/portPvidConfiguration.html` |
| reboot_path / logout_path | `None` / `None` (never captured) |
| is_epx_poe | False |
| reads_verified | True — live HTTP↔SNMP cross-verified 2026-07-23 |
| html_dialect | XE_FASTPATH |

#### gs728tpp (`_GS728TPP`, lines 878-941)

Login GROUNDED in `certbot-hook-netgear-switches/netgear-updater.py`
(`GS728TPPUpdater`) AND real captures (`tmp/gs728tpp_ground_truth.json`,
10.2.5.10). `reads_verified` REQUIRED a separate live cross-check against the
switch's OWN config (not SNMP — this model's SNMP OID family is itself
unverified-pending-capture, so cross-checking HTTP against SNMP here would
have proven nothing).

| field | value |
|---|---|
| scheme | XML_API |
| scheme_verified | True |
| login_path | `/` |
| password_field | `password` |
| username_field | `user` |
| username | `admin` |
| cookie_name | `sessionID` |
| needs_rand | False |
| dashboard_path | `wcd?{file=/Switching/Ports/portConfiguration_master_jq.htm}{Standard802_3List}` |
| stats_path | `None` — per-port stats unreachable (behind unresolvable JS nav on this UI); `get_stats` raises `UnsupportedCapabilityError`, SNMP is the source |
| sysinfo_path | `wcd?{file=/System/Management/SystemInfo_master_745.xml}{DeviceBasicInfo}{TimeSetting}{DiagnosticsUnitList}` |
| mgmt_ip_path | `wcd?{file=/System/Management/IPConf_master.xml}{IPv4InterfaceList}{IPv4GatewayList}` (SEPARATE query from sysinfo_path) |
| poe_config_path | `None` |
| poe_status_path | `wcd?{file=/System/PoE/PoeInterfaceConf_master.xml}{PoEPSEInterfaceList}` |
| vlan_config_path | `wcd?{file=/Switching/VLAN/VlanConfBasic_master.xml}{VLANList}` |
| vlan_membership_path | `None` — derived inline from the PVID page's per-port `JoinVLANList`, no separate membership request needed |
| pvid_path | `wcd?{file=/Switching/VLAN/PortPvidConf_master_745.xml}{VLANInterfaceList}` |
| mac_table_path | `wcd?{file=/Switching/Address Table/DynamicAddresses_master.xml}{ForwardingTable}` |
| lldp_path | `wcd?{file=/System/LLDP/NeighborsInformation_master.xml}{LLDPMEDNeighborList}` |
| reboot_path / logout_path | `None` / `None` |
| is_epx_poe | False |
| cert_upload_path | `"wcd"` — a raw XML POST (`SSLCryptoCertificateImportList` body to the session-path-prefixed `wcd` endpoint), NOT the gsm7228ps multipart form. `cert_upload_file_field` stays `None` (no multipart file part) |
| reads_verified | True — LIVE-VERIFIED 2026-07-29 against 28 g1..g28 ports, 24 PoE ports, real VLAN names, PVIDs, membership, 135 MAC entries, 4 LLDP neighbours, Fan1/Fan2/PSU sensors, mgmt-IP — all cross-checked vs the switch's own known config |
| html_dialect | GOAHEAD_XML |

The `wcd?{...}` path strings themselves ARE the endpoint paths on this
model — they are not placeholders; `_read_url` (client.py) just prepends the
session-path prefix in front of the literal string.

### 1.6 THE 1841111 CHANGES — write-op additions vs an earlier "None"/unsupported

This is the single most important delta for Go engineers who might have
skimmed an OLDER pin's docs or a stale mental model. As of 1841111, HTTP
newly implements/corrects the following (endpoints.py is DATA-only; the
actual write logic lives in `http_write.py`, Part 2 — but the SPEC FIELDS
that make each write possible are all in THIS file and are enumerated here):

1. **`set_port_enabled` over HTTP, gs110emx** — `port_config_path` field
   added (same as `dashboard_path`, `/iss/specific/port_settings.html`).
   This model's write mechanism is NOT an admin toggle at all: it is the
   port's "Physical Mode" select (`PORT_CTRL_MODE`), harvested from the
   firmware's own `/function.js::sendPortStatusForm()`. LIVE-VERIFIED
   2026-07-31 on 10.1.5.25. The `port_config_path` field itself (on
   `HttpModelSpec`) is a genuinely NEW field at this pin — every FASTPATH
   model also newly carries it, splitting "the page I read status from" from
   "the page I write admin mode to" as two independently-nameable concepts
   (`_FASTPATH_PORT_CONFIG = "/portsConfiguration.html"` for the four
   managed models).
2. **`set_mgmt_ip` over HTTP, all four FASTPATH/XUI models** — the
   `mgmt_ip_fields: XuiMgmtIpFields | None` field is new-at-this-pin
   plumbing that names EXACTLY which page cells carry address/netmask/
   gateway/mode/apply-button, discovered LIVE 2026-07-30 across all four
   managed switches (gsm7228ps, gsm7252ps, m4300-24x, m4300-16x). Previously
   at least gsm7228ps's mgmt-IP page was believed unreachable ("lives on a
   JS-menu-only page unreachable here" — WRONG, corrected live 2026-07-30:
   `GET /ipConfiguration.html` → 200, real address/mask/gateway/DHCP-vs-static).
3. **`clear_poe_fault`/`set_poe` over HTTP, gsm7252ps** — `poe_config_path`
   flipped from `None` (with an incorrect "the form REFUSES every write"
   note) to the real page, `/poeInterfaceConfiguration.html`. The refusal
   was the CALLER's bug, not the firmware's: every write attempt omitted the
   page's own `urlListUnit` scope field (`v_1_1_1`/`v_1_3_1`), which this
   firmware — uniquely among the four managed models — requires to resolve
   which row is being addressed (see `forms.xui_row_apply_form` / `nav`
   handling, §3.6). Once that field rode along, byte-identical writes that
   used to fail with `err_flag=1` succeeded. LIVE-VERIFIED 2026-07-31 on
   port 1/0/35: Enable→Disable→Enable, `err_flag=0` both times.
4. **`set_vlan_membership` over HTTP, all four managed switches** — the
   ENTIRE `_FASTPATH_VLAN_MEMBERSHIP`/`_FASTPATH_VLAN_MEMBERSHIP_RW`
   discovery (`vlan_membership_path`/`vlan_membership_post_path` fields) is
   new-at-this-pin for gsm7228ps, gsm7252ps, m4300-24x, m4300-16x. Before
   this, none of the four managed models exposed a VLAN-membership WRITE
   path over HTTP at all — fifteen plausible FASTPATH URL guesses were
   probed on 10.1.5.22 and every one 404'd; the real URL
   (`/switching/dot1q/vlan_port_cfg.html`, POSTing to the `_rw.html` twin)
   is a leaf of the firmware's own JS nav tree
   (`GET /base/js/ng_sideNav.js`) and was found by reading THAT instead of
   guessing. `parse_fastpath_membership`/`forms.fastpath_membership_form`
   (§2.7/§3.5) are the parser/encoder pair this unlocked, and they are
   BRAND NEW at this pin.
5. **`get_lldp` over HTTP, m4300-24x/16x** — corrected from an earlier
   "unsupported, this UI exposes only LLDP-MED remote data with no
   chassis/port-id table" claim to a real, working `lldp_path` (shared with
   the XE models: `lldpRemoteInventory.html`), found the same way as (4) by
   reading the firmware's own nav tree rather than guessing.
6. **mgmt-IP over HTTP, gsm7228ps** — corrected from "the IPv4 mgmt address
   lives on a JS-menu-only page unreachable here" to the real, working
   `mgmt_ip_path` (see item 2). This one is a READ correction, bundled here
   because it shares the exact same `_GSM72XX_MGMT_IP`/`XuiMgmtIpFields`
   machinery the write-side fix (item 2) depends on.

Net effect for a Go porting engineer: DO NOT treat a `None` field you find in
an older draft/memory of this spec as authoritative. Every field value in
§1.5's tables above is the CURRENT (1841111) value, already reflecting all
six corrections.

---

## 2. `protocols/http/parse.py` — every parser function

All regex-based (no external HTML-parsing library). Grounding varies BY
FUNCTION (see the module docstring, transcribed):

- `gs110emx_*`, `gs105pe_*`, `m4300_*` parsers are GROUNDED in real device
  captures and live-verified.
- `gs305ep`/STANDARD-dialect parsers (`parse_port_status`, `parse_port_stats`,
  `parse_poe_status`, `parse_pvids`, `parse_vlan_ids`) match only SYNTHETIC
  fixtures headed `UNVERIFIED-pending-capture` — confirm against real
  hardware before trusting them in production.

Two deliberate failure shapes, preserve BOTH in the Go port:
- A *token* scrape (`parse_login_rand`/`parse_csrf_hash`/
  `parse_selected_vlan`) returns "not found" (`None` in Python; a Go port
  should use `(string, bool)` or `*string`) — the CALLER decides whether
  that's fatal.
- A *table/page* parser that cannot find its documented structure RAISES
  (`HttpUnexpectedPageError` in Python; `model.ErrHTTPUnexpectedPage` in Go)
  naming what was expected — these pages are never legitimately empty on a
  real switch, so absence means "wrong page came back", not "empty switch".
  Never silently swallowed into an empty list/dict. An LLDP table (which CAN
  legitimately be empty — no neighbours) is the one class of exception, and
  each such parser says so explicitly in its own docstring below.

### 2.1 Shared helpers / regexes

```python
_ROW_RE       = re.compile(r'<tr\s+class="portID">(.*?)</tr>', re.DOTALL | re.IGNORECASE)
_OPEN_ROW_RE  = re.compile(r'<tr class="portID">(.*?)(?=<tr|</table>)', re.DOTALL)
_TD_RE        = re.compile(r"<td[^>]*>(.*?)</td>", re.DOTALL | re.IGNORECASE)
_TAG_RE       = re.compile(r"<[^>]+>")
_WIRE_TO_MODE = {"1": VlanMode.UNTAGGED, "2": VlanMode.TAGGED, "3": VlanMode.EXCLUDED}
_DETECT_TEXT  = {"delivering": DELIVERING, "searching": SEARCHING,
                 "disabled": DISABLED, "fault": FAULT}
```

- `_cells(row_html)` → `[_TAG_RE.sub("", c).strip() for c in _TD_RE.findall(row_html)]`
  — strips all tags from each `<td>`'s inner HTML, trims whitespace.
- `_int(text)` → first `-?\d+` match, or `None`.
- `_poe_power_to_mw(text)` → **firmware variance, both grounded**: gsm7252ps
  renders integer MILLIWATTS (`"3500"` = 3500 mW); M4300-16X renders WATTS
  with two decimals (`"4.60"` = 4600 mW) despite a SHARED "(mW)" column
  header (a firmware label bug). Disambiguated by presence of a decimal
  point: integer cell ⇒ already mW; decimal cell ⇒ watts, multiply by 1000
  and round. Empty/absent ⇒ `None`; `"0"`/`"0.00"` ⇒ `0`.
- `_speed_text_to_mbps(text)` → regex `(\d+(?:\.\d+)?)\s*([GM])` (case
  insensitive). `G` suffix ×1000, bare `M` as-is. **Must match the
  FRACTIONAL form**: GS110EMX NBASE-T ports negotiate `2.5G`/`5G`; matching
  only `(\d+)` would backtrack past the `2.` and misread `2.5G` as `5000`.
  No match ⇒ `None`.
- `_expand_port_list(raw)` — M4300/gsm7252ps FASTPATH egress-list expander:
  format `"1/0/1 - 1/0/2, 1/0/5, lag 1 - lag 128"`. Only `unit/slot/port`
  entries are physical; `lag N` entries are LINK AGGREGATION GROUPS and are
  SKIPPED (an earlier bug expanded `lag 1 - lag 128` into 128 phantom
  "ports" on a 24-port switch). A range expands only when both ends share
  `(unit, slot)` and `p1 <= p2`.
- `_expand_s3300_port_list(raw)` — same idea for the Smart-firmware
  `1/gN`/`1/xgN` ifName form (gsm7228ps); a range MAY mix the two prefixes
  (`"1/g48 - 1/xg52"`); `lag N` still skipped.

### 2.2 Token scrapers (return `None`, never raise)

| function | scrapes | regex |
|---|---|---|
| `parse_login_rand(html)` | `<input id="rand" ... value="...">` login nonce | `id=["\']rand["\'][^>]*value=["\']([^"\']*)["\']` |
| `parse_csrf_hash(html)` | `<input name="hash" value="...">` — the Plus-CGI per-page CSRF token every write form needs | `name=["\']hash["\'][^>]*value=["\']([^"\']*)["\']` |
| `parse_gambit_token(html)` | gs110emx's `/redirect.html` response's `<input type="hidden" name="Gambit" value="...">` — a SESSION IDENTITY, not the login nonce. Returns `None` (no such field) OR `""` (empty value — a rejected login); the caller's `if not token` catches EITHER shape | `name=["\']Gambit["\'][^>]*value=["\']([^"\']*)["\']` |
| `parse_selected_vlan(html)` | `8021qMembe.cgi`'s currently-selected `<option ... selected ... value="N">` in the VLAN dropdown — tries `selected` BEFORE `value=` first, then the reverse attribute order | two alternated regexes |

### 2.3 STANDARD dialect (gs305ep) — `UNVERIFIED-pending-capture`

- **`parse_port_status(html)`** — `dashboard.cgi` closed `portID` rows via
  `_ROW_RE`. Columns: `[1]`=port, `[2]`=link/speed text (`"up" in text.lower()`
  ⇒ link_up, then `_int(c[2])` as speed IF up), `[3]`=admin
  (`.lower().startswith("enable")`), `[4]`=name (empty ⇒ `None`). Requires
  ≥5 `<td>`s per row; raises on 0 rows or short rows.
- **`parse_port_stats(html)`** — `portStatistics.cgi` closed rows. `[0]`=port,
  `[1]`=rx_bytes, `[2]`=tx_bytes, `[3]`=rx_errors (crc). `rx_packets`/
  `tx_packets`/`tx_errors` always `None` — this page has no such columns.
- **`parse_poe_status(html)`** — `getPoePortStatus.cgi` closed rows. `[0]`=
  port, `[1]`=detect-state text (mapped via `_DETECT_TEXT`, unmatched ⇒
  `UNKNOWN`), `[2]`=power_mw (bare `_int`, no unit disambiguation needed on
  this page). `admin_enabled = detect is not DISABLED`.
- **`parse_pvids(html)`** — `portPVID.cgi`. NOT column-index based like the
  others: scans for `<td sel="text">(\d+)...</td>\s*<td sel="input">(\d+)</td>`
  pairs directly across the whole page (still requires `_ROW_RE` rows to
  exist first, as a page-sanity precondition, but the actual pairs come from
  a separate finditer over the raw HTML).
- **`parse_vlan_ids(html)`** — `8021qCf.cgi` VLAN checkboxes:
  `name="vlanckN" value="VID"` — every `vlanckN` input's `value`, deduped +
  sorted.
- **`parse_membership(html, port_count)`** — `8021qMembe.cgi`'s `hiddenMem`
  input value: one WIRE CODE character per port, **1=Untagged, 2=Tagged,
  3=Excluded** (`_WIRE_TO_MODE`). Tries `id="hiddenMem"` first, falls back to
  `name="hiddenMem"`. Requires `len(raw) >= port_count`; an unknown code
  character raises naming the offending port. Returns `{port: VlanMode}` for
  `1..port_count`.

### 2.4 GS110EMX dialect — grounded in real captures

- **`parse_gs110emx_port_status(html)`** — `port_settings.html` OPEN rows
  (`_OPEN_ROW_RE`). `[1]`=port, `[2]`=description (empty ⇒ `None`), `[3]`=
  link (`"up"` exact match, stripped+lowered), `[4]`=admin-mode cell
  (`admin_enabled = c[4].lower() != "disable"` — this is the SPEED/MODE cell
  doubling as admin state; NOT hardcoded `True`, a prior bug), `[5]`=speed
  text via `_speed_text_to_mbps` IF link up.
- **`parse_gs110emx_pvids(html)`** — `vlan_pvidsetting.html` OPEN rows.
  `[1]`=port, `[2]`=PVID.
- **`parse_gs110emx_vlan_ids(html)`** — `Cf8021q.html` (Advanced 802.1Q):
  each `<tr class="vlanID tableTr">` row's first `<td class="def">` cell is
  the VID. Dedup+sort.
- **`parse_interface_stats(html)`** — `interface_stats.html` OPEN rows.
  `[0]`=port, `[1]`=rx_bytes, `[2]`=tx_bytes, `[3]`=rx_errors (ONE combined
  error column, same rx_errors convention as gs305ep). No packet counts —
  `rx_packets`/`tx_packets`/`tx_errors` honestly `None`.
- **`parse_sysinfo(html)`** → `HttpSysInfo` (see §5.2). `sysInfo.html`
  identity via `<td>Label</td><td>value</td>` labelled cells
  (`_labeled_cell`) + `<input name=NAME value=...>` fields (`_named_input_value`,
  UPPERCASE names `IP_ADDRESS`/`SUBNET_MASK`/`GATEWAY_ADDRESS`/`switch_name`
  on THIS model — contrast gs105pe's lowercase names below). DHCP mode from
  `<tr data-select-value="N">` wrapping the mode `<select>` — `0`=static,
  `1`=DHCP. Missing ANY expected field (including the `data-select-value`
  attribute itself) ⇒ raise naming every missing field.
- **`parse_gs110emx_port_form_fields(html)`** → `{port: {field: value}}` —
  used to ECHO a port's current `FLOW_CONTROL_MODE` back on a write (see
  §3.7): each row's own hidden `PORT_NO`/`PHYSICAL_MODE`/
  `FLOW_CONTROL_MODE` inputs (`_EMX_HIDDEN_RE` finds every `name=...
  value=...` pair inside the row's OPEN-row slice).

### 2.5 GS105PE dialect — LIVE-VERIFIED on real hardware

```python
_GS105PE_ROW_RE = re.compile(r'<tr class="portID"[^>]*>(.*?)(?=<tr|</table>)', re.DOTALL)
_HIDDEN_VALUE_RE = re.compile(r'<input type="hidden" value="(\d+)">')
```

- **`parse_gs105pe_port_status(html)`** — `status.cgi`. `[1]`=port, `[2]`=
  link (`"up"` exact), `[3]`=admin (`!= "disable"`), `[4]`=speed text. `name`
  always `None` — this page has no description column.
- **`parse_gs105pe_pvids(html)`** — `portPVID.cgi`. `[1]`=port, `[2]`=PVID.
- **`parse_gs105pe_stats(html)`** — `portStatistics.cgi`. **THE hidden
  32-bit half-pair counter trap**: the VISIBLE `<td>` cells are UNRELIABLE —
  the first counter's cell is left empty and populated client-side by page
  JS. The AUTHORITATIVE values are HIDDEN inputs following each counter
  cell: **THREE consecutive `(hi, lo)` pairs** — Bytes Received, Bytes Sent,
  CRC Error Packets — each a 64-bit counter split into two 32-bit halves,
  reassembled as `hi * 2**32 + lo`. Requires ≥6 hidden-value matches per row
  (3 pairs); fewer ⇒ raise naming the port and the count found. Verified
  live against NSDP counters on the same ports.
- **`parse_gs105pe_sysinfo(html)`** → `HttpSysInfo`. Identity via the same
  `<td>Label</td><td>value</td>` shape as GS110EMX, BUT the mgmt-IP inputs
  are LOWERCASE (`ip_address`/`subnet_mask`/`gateway_address` — NOT the
  GS110EMX's uppercase `IP_ADDRESS` etc. — a genuinely different field-name
  convention between the two models despite sharing a login scheme). DHCP
  from a `<select id="dhcpMode">` whose `<option value="1" selected>` means
  Enable/DHCP, `"0"` means Disable/static.

### 2.6 M4300 (Cheetah `/v1`) dialect — field-comment addressing

Every M4300 data cell is a hidden input whose NAME encodes the ROW INSTANCE
and is IMMEDIATELY followed by an HTML comment naming the field semantically:

```html
<TD ... id=1_2_10><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10
     VALUE="Link Up">Link Up</TD><!-- baseport_LinkStatus2 -->
```

```python
_CHEETAH_CELL_RE = re.compile(
    r'NAME=([0-9.]+)\.v_[0-9_]+ VALUE="([^"]*)"[^<]*(?:</TD>)?<!-- (\w+) -->',
    re.IGNORECASE,
)
```

- **`parse_cheetah_rows(html)`** → `list[dict[str, str]]`, one dict per row
  instance, in first-seen order, keyed by the trailing comment's field name.
  Values are HTML-unescaped and stripped (Cheetah escapes cell values —
  interface names arrive as `"1&#x2F;0&#x2F;1"`). Empty list, never raises
  — caller decides.
- **`parse_m4300_port_status(html)`** — rows filtered to those with
  `baseport_LinkStatus2`. `baseport_ifIndex`=port (matches SNMP ifIndex
  keying), `baseinterfaceListing_Interfaces`=name (`"1/0/1"`),
  `baseport_AdminMode`=admin (`.lower() == "enable"`),
  `baseport_LinkStatus2`=link (`"up" in text.lower()`),
  `baseport_PhysicalStatus`=speed IF up.
- **`parse_m4300_stats(html)`** — reports **FRAMES, not octets**
  (`basePortStats_TotalFramesRx/Tx`); `rx_bytes`/`tx_bytes` honestly `None`,
  counts land in `rx_packets`/`tx_packets`. `basePortStats_TotalErrorFramesRx/Tx`
  → rx/tx_errors. If a row lacks `baseport_ifIndex`, falls back to parsing
  the trailing number out of `baseinterfaceListing_Interfaces` (this page
  keys some rows by interface name instead).
- **`parse_m4300_pvids(html)`** — rows with `SwitchingVlanPortConfig_Pvid`.
  Same ifIndex-then-interface-name port fallback as stats. Silently
  `continue`s a row with no parseable pair (not a per-row raise), but raises
  if the WHOLE result is empty.
- **`parse_m4300_vlans(html)`** — rows with
  `SwitchingVlanStaticConfig_VlanIndex`. `member_ports` from
  `SwitchingVlanCurrentConfig_VlanCurrentEgressPortList` via
  `_expand_port_list`. This page does NOT distinguish tagged/untagged —
  BOTH `tagged_ports`/`untagged_ports` left EMPTY, only `member_ports`
  populated.
- **`parse_m4300_macs(html)`** — TWO real-hardware traps deliberately
  avoided: (1) `Intf` cell is not always physical — `lag N`/`vlan N`/
  `0/15/1` service-port entries appear and are SKIPPED (only
  `unit/slot/port` fullmatches via `_FASTPATH_IFACE_RE` yield a port); (2)
  **THIS PAGE IS PAGINATED** — the true count is in
  `NAME=v_1_1_1 VALUE="(\d+)"` (a page-level scalar OUTSIDE the row-instance
  cells, matched by a SEPARATE top-level regex, not via `parse_cheetah_rows`)
  and if it exceeds `len(rows)`, this RAISES naming SNMP as the complete
  source rather than silently returning a truncated FDB.
- **`parse_m4300_sysinfo(html)` → `MgmtIpConfig`** — `IPv4 Management
  Address` cell renders `addr/netmask` inside a link (regex spans `.*?` with
  `DOTALL` between the label and the value); `System MAC Address` is a plain
  labelled cell. `mode` is ALWAYS `IpMode.UNKNOWN` — page carries no DHCP
  indicator. Raises only if BOTH the address AND the MAC are absent.
- **`parse_m4300_sensors(html)`** — Temperature block only:
  `<td>MAC</td><td>53 &#8451;</td>` shape, EXCLUDING threshold/limit rows
  (`_IS_TEMP_LIMIT_RE` matches `max|maximum|threshold|limit` in the label —
  the page mixes a live `"MAC 53 C"` reading with a static datasheet
  `"Max Operating Temperature 81 C"` LIMIT in the same block; returning the
  limit as a sensor would make "hottest sensor" alarm read 81°C forever).
  Fan block deliberately NOT returned — non-numeric state text
  (`"Fan-1 OK"`), and `Sensor.value` is a required float; SNMP is the real
  fan-RPM source for this model.

### 2.7 XE_FASTPATH dialect (gsm7252ps) — coordinate-addressed cells

No field-name comments; cells addressed ONLY by COLUMN COORDINATE, scraped
once from the page's own visible header row and hardcoded per page:

```python
_XE_CELL_RE = re.compile(r'NAME=(\d+(?:\.\d+)+)\.v_(\d+_\d+_\d+) VALUE="([^"]*)"', re.IGNORECASE)
```

Row-instance prefix is `1.<row-index>.<row-count>` — **the trailing number
is a ROW COUNT, not a port number** (on a 52-port capture, row 0 is
`1.0.52.v_1_2_1` and row 51 is `1.51.52.v_1_2_1`; the same trailing `52` on
every row). Port identity always comes from the row's OWN cells (ifindex
column or `1/0/N` ifName), never the prefix.

- **`parse_xe_rows(html)`** → `list[dict[coordinate, value]]`, one per row
  instance (`NAME=v_g_1_2_1` global/template row and page-scalar
  `NAME=v_1_1_1` are SKIPPED — no instance prefix).
- `_xe_port_from_iface(text)` — `"1/0/7"` (M4300/gsm7252ps) → 7, OR
  `"1/g7"`/`"1/xg49"` (S3300 Smart firmware) → 7/49 via
  `_XE_SMART_IFACE_RE = re.compile(r"1/x?g(\d+)")`.
- **`parse_xe_port_status(html)`** — column map (from the captured page's own
  header row): `1_2_1`=Port ifName, `1_2_6`=Admin Mode, `1_2_9`=Physical
  Status (NEGOTIATED speed — `"1000 Mbps"`/`"10G Full "`/`"Unknown"`), NOT
  `1_2_8` Physical Mode (the CONFIGURED mode, reads `"Auto"` on
  auto-negotiating ports — using it would report a fixed speed that isn't
  real), `1_2_10`=Link Status, `1_2_13`=ifindex (preferred port source,
  falls back to `_xe_port_from_iface` on the ifName cell).
- **`parse_xe_stats(html)`** — column map: `1_1_103`=Interface,
  `1_1_2`=RX packets, `1_1_3`=RX errors, `1_1_5`=TX packets, `1_1_6`=TX
  errors. NO octet column at all — `rx_bytes`/`tx_bytes` honestly `None`.
  Requires BOTH `1_1_103` AND `1_1_2` present per row (the LLDP page reuses
  the same `1_1_*` coordinate space, so requiring both keeps a wrong page
  from parsing into plausible garbage).
- **`parse_xe_pvids(html)`** — `1_2_1`=Interface, `1_2_4`=**Configured**
  PVID (NOT `1_2_9` Current PVID — the two disagree on trunk-member ports on
  real hardware, and SNMP's `dot1qPvid` matches the CONFIGURED column).
- **`parse_xe_vlans(html)` / `parse_s3300_vlans(html)`** — share
  `_xe_vlan_rows(html, expand_fn)`: `1_1_1`=VLAN ID, `1_1_2`=name,
  `1_1_3`=type (required-present but unused for output), `1_1_4`=Member
  Ports egress list. `parse_xe_vlans` expands with `_expand_port_list`
  (`1/0/N` form); `parse_s3300_vlans` with `_expand_s3300_port_list`
  (`1/gN`/`1/xgN` form, ranges may mix prefixes). An EMPTY member cell is
  real (a VLAN with no members) — reported as an empty set, not a parse
  failure. Neither distinguishes tagged/untagged — both left empty.
- **`parse_xe_macs(html)`** — `1_2_1`=VLAN, `1_2_3`=MAC, `1_2_4`=Port
  (`1/0/N`/`lag N`/`0/S/N` service). Physical ports are ONLY
  `<unit>/0/<port>` (slot MUST be `"0"`); `lag N` and any other slot
  (service/CPU interface, e.g. the switch's own base MAC on `0/5/1`) are
  SKIPPED. Same pagination-detection raise as `parse_m4300_macs`, keyed off
  the page-level scalar `NAME=v_1_1_1 VALUE="(\d+)"` ("Total MAC Addresses").
- **`parse_s3300_macs(html)`** — SHIFTED columns vs the sibling: `1_2_2`=VLAN
  (not `1_2_1`), `1_2_3`=MAC, `1_2_4`=Port in `1/gN`/`1/xgN` form,
  HTML-entity-escaped (`"1&#x2F;xg51"`, unescaped by `parse_xe_rows`
  already). The switch's OWN base MAC is learned on a CPU interface
  (rendered `"c1"`, status "Management") which `_xe_port_from_iface` does
  NOT resolve — skipped, same as `parse_m4300_macs`'s service-port
  omission. Same pagination raise.
- **`parse_s3300_mgmt(html)` → `MgmtIpConfig`** — `sysInfo.html` on THIS
  model carries ONLY the `Base MAC Address` labelled cell
  (`aid="1_16_1_right"`) — address/netmask/gateway are `None`; those come
  from `/ipConfiguration.html` via the shared `parse_xui_mgmt_ip` instead
  (see `http_read._fastpath_base_mac`, Part 2). `mode` always `UNKNOWN`.
- **`parse_xe_poe(html)`** — column map: `1_2_1`=Port, `1_2_2`=Admin Mode,
  `1_2_15`=Output Power (unit VARIES, see `_poe_power_to_mw`), `1_2_17`=
  Status text (matched against `_DETECT_TEXT` — `"Other Fault"` ⇒ FAULT,
  where SNMP's numeric detect map has no equivalent code and honestly
  reports UNKNOWN).
- **`parse_xe_lldp(html)`** — `1_1_1`=local interface, `1_1_7`=remote
  chassis id (MAC, uppercased), `1_1_8`=remote sys name, `1_1_9`=remote port
  id. **NO remote-port-DESCRIPTION column** on this page — always `None`
  (SNMP's `lldpRemPortDesc` is the source). **Legitimately empty is OK**
  (returns `[]`) UNLESS there are also zero rows AND the string `"lldp"`
  doesn't even appear in the page — that combination raises (wrong page
  entirely).
- **`parse_xe_labelled_values(html)` / `_xe_text` / `_xe_sysinfo_section` /
  `_xe_status_rows`** — the format-(B) "plain label/value table" reader for
  `sysInfo.html` (this page carries NO `v_` cells — an earlier draft grepped
  for `v_` and wrongly concluded values were JS-populated and unreachable).
  `_xe_sysinfo_section(html, title)` slices the page between two
  `tbhdr('<title>',...)` script calls (Temperature/FAN/Device Status blocks
  share cell classes and would merge without this). `_xe_status_rows`
  strips the header row (matched by `messageTableHeader` cell class, else
  its literal text — `"Sensor Type"` — would be emitted as a bogus sensor
  reading 1.0).
- **`parse_xe_sensors(html)`** — three blocks: Temperature (real numeric
  °C readings, `"N/A"` skipped as absent-not-zero), FAN (`unit="state"`
  health flags: `1.0`="ok"/"operational", `0.0`=any other REPORTED state,
  SKIPPED entirely if absent/`"NA"`/`"N/A"`/`"not supported"`/`"-"`), Device
  Status (ONLY the `RPS`/`Power Module` rows as `kind="power"` state flags —
  the firmware/serial rows in that same table are identity, not sensors).
- **`parse_xe_mgmt_ip(html)` → `MgmtIpConfig`** — `IPv4 Network Interface`
  field renders `addr/netmask` inside a link; `System MAC Address` a plain
  cell. `gateway`/`mode` always `None`/`UNKNOWN` — page carries neither.

### 2.8 Generic FASTPATH XUI "list"/"form" page parsers (shared)

These are dialect-agnostic parsers used by BOTH M4300 and XE_FASTPATH/S3300
pages that are structured as a two-`<FORM>` page (`.../a0` applet form +
`.../a1` write form):

```python
_XUI_FORM_RE = re.compile(r'<FORM\b[^>]*ACTION="([^"]*/a1)"', re.IGNORECASE)
_XUI_ROW_RE = re.compile(r'<TR\s+p="[\d.]+"[^>]*>(.*?)</TR>', re.IGNORECASE | re.DOTALL)
_XUI_ROW_FIELD_RE = re.compile(r"^((?:\d+\.)+)(v_\d+_\d+_\d+)$")
_XUI_HIDDEN_NAMES = ("submit_flag", "submit_target", "err_flag", "err_msg", "clazz_information")
_XUI_TOKEN_RE = re.compile(r"^CSRFToken$", re.IGNORECASE)
_XUI_NAV_ROW_RE = re.compile(r"<TR\b[^>]*\bclass=[\"']?deftestme[\"']?[^>]*>(.*?)</TR>", re.IGNORECASE | re.DOTALL)
_XUI_PAGE_FIELD_RE = re.compile(r"^v_\d+_\d+_\d+$")
```

- **`_xui_form_block(html, page)`** → `(action, inner_html)` of the SECOND
  form, or raise. Scoping to this form specifically matters because the
  first form (`/a0`) carries `applet_port`/`applet_unit`/`dbgopt` fields
  that must never leak into a data read.
- **`_xui_inputs(block)`** → `({name: value}, [checkbox names])`. Deliberately
  distinct from `_fastpath_form_fields` (§2.9): `DISABLED` inputs (every
  button) are dropped (a browser never submits them — the firmware ENABLES
  the clicked one via JS before submit); checkbox names are returned
  SEPARATELY (a checkbox carries no `value` attribute — echoing it as `""`
  would silently SELECT that row, and row-selection is exactly what these
  pages key writes off).
- **`_xui_buttons(html)`** → `{field: label}` scraped from
  `<div id="xuiButtonsDiv">` specifically (NOT matched by name pattern — on
  gsm7228ps's `ipConfiguration.html`, `v_2_1_1` is a REAL DATA field, not a
  button, so a name-shape guess would misclassify it and drop it from every
  echoed apply).
- **`parse_xui_list_page(html, page=...)` → `XuiListPage`** (see §5.3): one
  `XuiRow` per `<TR p="...">`; row PREFIX taken from the first field name
  matching `_XUI_ROW_FIELD_RE`, not from the `p="..."` attribute itself
  (the attribute's digits and the field-name digits happen to align, but the
  code deliberately derives from the field name). `nav` collected from
  `<TR class=deftestme>` rows (list-navigation/scope fields — see
  `XuiListPage.nav` in §5.3). ZERO rows is NOT an error (a present page with
  no rows, e.g. the M4300-24X's genuinely-PoE-less page) — only a MISSING
  write form raises.
- **`parse_xui_form_page(html, page=...)` → `XuiFormPage`** (see §5.3): same
  form-scoping, flat (non-repeating) field map.
- **`parse_xui_mgmt_ip(html, *, address_field, netmask_field, gateway_field,
  mode_field, page=...)` → `MgmtIpConfig`** — field names are PASSED IN
  (from `XuiMgmtIpFields`, §1.3), never assumed, because the same field name
  means different things on different boxes. `mode` mapped via:
  ```python
  _XUI_IP_MODE = {"none": STATIC, "manual": STATIC, "disable": STATIC,
                  "dhcp": DHCP, "enable": DHCP, "bootp": DHCP}
  ```
  `base_mac` always `None` here — neither XUI family's mgmt page carries the
  switch's BASE MAC (gsm7228ps's page has none at all; the M4300's `v_4_4_1`
  is the MANAGEMENT INTERFACE's MAC, one octet off from the true base MAC —
  using it would break SNMP parity). The reader merges base_mac from
  `sysinfo_path` separately (Part 2).

### 2.9 FASTPATH "VLAN Membership" page — `parse_fastpath_membership` (NEW at 1841111)

The single most intricate parser in the file. Parses
`switching/dot1q/vlan_port_cfg.html` → `FastpathMembership` (§5.1). Two
independently-verified views must AGREE or the parser refuses (see below).

Wire codes for `hiddenMem` are **1=Tagged, 2=Untagged, 3=Excluded** —
**THE INVERSE of the Plus-class `8021qMembe.cgi` map** (§2.3:
1=Untagged, 2=Tagged, 3=Excluded). Grounded in the firmware's own JS
(`rollover.js`'s `toggleImage()`/`togImg()`), and the module comment is
explicit that these two encoders must NEVER be shared:

```python
_FASTPATH_MEM_TO_MODE = {"1": TAGGED, "2": UNTAGGED, "3": EXCLUDED}
_MODE_TO_FASTPATH_MEM = {v: k for k, v in _FASTPATH_MEM_TO_MODE.items()}
```

Parse sequence:
1. Locate the form via
   `<form method="?post"? ACTION="([^"]*vlan_port_cfg_rw\.html)">` — this
   also excludes `document.write()`-ed markup inside `<script>` blocks that
   would otherwise pollute a naive scrape.
2. `_fastpath_form_fields(block)` — every named `<input>`/`<select>`
   VERBATIM (unlike `_xui_inputs`, nothing is filtered — this page must be
   byte-faithful on re-POST, including the M4300-16X's `CSRFToken`). A
   `<select>`'s value is its `selected` `<option>`, falling back to the
   FIRST option (what a browser sends when the firmware marks none
   selected).
3. Require `hiddenMem` present; split on `,`.
4. `_fastpath_grid(block)` → `{physical_port: (0-based_hiddenMem_slot,
   rendered_mode)}`. TWO firmware generations, BOTH must be tried:
   - **Grid style A** (gsm7252ps, older XE firmware): per-cell
     `toggleImageFirst(this,<0-based slot>,0,'img_unit<N>',<iface>)` handler
     + `<img src=".../grey_[btu].gif">`. LAG pseudo-ports use the SAME
     shape — the ENCLOSING `<table id="unitNtb">`'s own row label ("Port" vs
     other) is what separates physical ports from LAGs
     (`_FASTPATH_GRID_TABLE_RE` + `_FASTPATH_GRID_LABEL_RE`). Slot is
     **0-BASED** (`toggleImage()` computes `j = 2*index`).
   - **Grid style B** (gsm7228ps/S3300 + both M4300s, newer jQuery
     firmware): cell carries `aid='port-<ifname>'` and a
     `togImg(this,<1-based slot>,0,"hiddenMem")` handler; state is in the
     image FILENAME (`switch_<state>[_bottom]_inactive.png`). LAG cells have
     `aid='lag N'` which drops out naturally (not a port ifName). Slot is
     **1-BASED** (`togImg()` computes `j = (index-1)*2`) — the code
     subtracts 1 when storing it.
   Neither shape present ⇒ raise (a real page always renders one).
5. **Cross-check**: for every `(port, slot)` in the grid, decode
   `hiddenMem`'s code at that slot and compare it against the grid's OWN
   rendered mode. **They must be IDENTICAL** — a mismatch raises rather than
   trusting either one, because the two are two renderings of the SAME
   configured state and agreed on every live capture; disagreement means the
   slot mapping itself is wrong, and writing under a wrong mapping would hit
   the wrong port.
6. `_fastpath_vlan_select(block)` → `(selected_vlan_or_None, all_vlan_ids)`
   from the `<select name="vlanId">` SPECIFICALLY (the page ALSO has a
   `<select name="select">` Group-Operation menu with unrelated values
   `UntagAll`/`TagAll`/`RemoveAll` — scoping to `vlanId` by name avoids
   picking that one up). Case-INSENSITIVE `<OPTION ... SELECTED>` match
   (real firmware writes the tag uppercase, attribute bare) — the
   lowercase-only `parse_selected_vlan` (§2.2) reads `None` on this page.
7. `tagged_ports`/`untagged_ports` from `hiddenTagged`/`hiddenUnTagged`
   fields via `_fastpath_iface_list` — these are the **CURRENT (operational)**
   view (§5.1 explains why this differs from `configured`).

`parse_fastpath_err(html)` — every FASTPATH write-form page's OWN error
banner: `err_flag`/`err_msg` hidden fields, checked by the page's own JS
`check_error()`. The page STILL returns HTTP `200` on a refused write — this
scrape is the ONLY signal. Falls back to a generic
`f"err_flag={flag} with no err_msg"` string if the flag is set but the
message is empty.

`fastpath_hidden_mem_with(page, port, mode)` — a PURE function (not a raw
parser, but pairs with the parser) returning `page.hidden_mem` with exactly
`port`'s slot replaced, EVERY OTHER SLOT preserved verbatim (including LAG
pseudo-interfaces the library never models) — mirrors the SNMP writer's
"preserve the device's own PortList width" discipline. Raises if `port` is
not on the grid at all.

### 2.10 GOAHEAD_XML dialect (gs728tpp) — `ElementTree`-based, not regex

The ONLY dialect that is real XML parsing. Every read response is a
template of `BIND=` placeholders (NOT well-formed XML — unclosed
`<script>`/`<link>`, a literal `class=xui"` typo in the captured markup)
followed by a clean `<DeviceConfiguration>` data block. Only that trailing
block is parsed.

`_goahead_data_block(body)` — slices `body[body.find("<DeviceConfiguration>")
: body.find("</DeviceConfiguration>") + len(...)]`, then HARDENS against
XXE/entity-expansion WITHOUT a new dependency (`defusedxml` is not a project
dependency; stdlib `ElementTree` is mandated): rejects the slice outright if
it contains `<!DOCTYPE` or `<!ENTITY` (slicing already excludes the XML
prolog where a DTD would normally live; this catches one embedded INSIDE the
data block). `ElementTree.fromstring` on the survivor; a `ParseError` is
wrapped into `HttpUnexpectedPageError`.

`_goahead_section(body, name)` → the `<name type="section">` element, or
raise "no such section (wrong page?)".

`_goahead_port_num(name)` — `^g(\d+)$` fullmatch; a LAG (`"LAG3"`) or
anything else ⇒ `None` (skip, don't mis-attribute).

`_gtext(el, tag)` — `(el.find(tag).text or "").strip()`, or `""` if the
child is absent.

Enum wire codes (from the pages' own `<ENUM>` blocks / observed values):
`adminState`/`adminEnable`: 1=enabled, 2=disabled. `linkState`: 1=up, 2=down.
`taggingMode`: 1=untagged, 2=tagged. PoE `detectionStatus`: 1=Disabled,
2=Searching, 3=DeliveringPower, 4=Fault, 5=Test, 6=OtherFault (mapped to
`FAULT` too, "still a fault"). Diagnostics `*Status`: 1=OK, 2=Fail, 5=N/A
(absent slot).

| function | section | notes |
|---|---|---|
| `parse_goahead_ports(body)` | `Standard802_3List` | only `g<n>` physical ports; `speedOper` while up, else `None`; ALSO returns `description` (`interfaceDescription`) — the ONE dialect whose `PortStatus` populates `description` |
| `parse_goahead_pvids(body)` | `VLANInterfaceList` | `(port, PVID)` pairs, physical only |
| `parse_goahead_vlan_names(body)` | `VLANList` | `{vlan_id: name or None}` |
| `parse_goahead_port_vlan_membership(body)` | `VLANInterfaceList` | `{vlan_id: (tagged_ports, untagged_ports)}` built from each port's inline `JoinVLANList`/`VLANEntry` — NO separate per-VLAN membership request needed on this model |
| `parse_goahead_vlans(vlans_body, membership_body)` | combines the two above | full `VLANInfo` list, `member_ports = tagged \| untagged` |
| `parse_goahead_macs(body)` | `ForwardingTable` | physical `g<n>` only; empty table is legitimate (fresh boot) |
| `parse_goahead_poe(body)` | `PoEPSEInterfaceList` | `power_mw`=`outputPower`; `Test` code (5) has no RFC3621 equivalent ⇒ `UNKNOWN`, not invented |
| `parse_goahead_lldp(body)` | `LLDPMEDNeighborList` | empty list is LEGITIMATE (returns `[]`, no raise) UNLESS the whole section is missing; chassis/port-id MAC-shaped ids upper-cased via `_canon_lldp_id` to equal SNMP's formatting LITERALLY |
| `parse_goahead_sensors(body)` | `DiagnosticsUnitList` | Fan1-5/Main-PS/Redundant-PS as `unit="state"` health flags (status 5/blank = absent slot, skipped); `tempSensorValue` emitted as a real numeric ONLY when `> 0` (a captured `0` + status 2 is "not a reading", not "0 °C") |
| `parse_goahead_base_mac(body)` | `DeviceBasicInfo` | `MacAddre` (sic, firmware's own field-name typo — preserve verbatim) field, uppercased |
| `parse_goahead_mgmt_ip(body)` | `IPv4InterfaceList` + `IPv4GatewayList` | `mode` always `UNKNOWN`, `base_mac` always `None` (that's on the SystemInfo page instead) |

### 2.11 `parse_reboot_ok(html)`

Trivial: `"error" not in html.lower()`. Used for the Plus-CGI reboot
response (STANDARD dialect only — no other model has a captured
`reboot_path`).

---

## 3. `protocols/http/forms.py` — every write-form encoder (pure)

Field names/values GROUNDED against `py_netgear_plus` GS30xSeries
`get_switch_poe_port_data`/`get_power_cycle_poe_port_data` and
`rcfiles/bin/netgear-smp-vlan` (8021q/PVID forms). Every op below requires
the page's CSRF `hash` field, scraped by the CALLER (`http_write.py`, Part
2) just before POSTing via `parse_csrf_hash` (§2.2) — forms.py never
scrapes, only encodes.

```python
_WIRE = {UNTAGGED: "1", TAGGED: "2", EXCLUDED: "3"}   # Plus-CGI wire codes
```

### 3.1 Plus-CGI PoE (gs305ep)

```python
def poe_apply_form(*, port, on, is_epx, csrf_hash) -> dict[str, str]:
    return {
        "ACTION": "Apply", "portID": str(port - 1),
        "ADMIN_MODE": "1" if on else "0", "PORT_PRIO": "0", "POW_MOD": "3",
        "POW_LIMT_TYP": "2" if is_epx else "0",   # is_epx == HttpModelSpec.is_epx_poe
        "DETEC_TYP": "2", "DISCONNECT_TYP": "2",
        "hash": csrf_hash,
    }

def poe_reset_form(*, port, csrf_hash) -> dict[str, str]:
    return {"ACTION": "Reset", f"port{port - 1}": "checked", "hash": csrf_hash}
```

Note `portID`/`port{n}` are **0-based** (`port - 1`).

### 3.2 Plus-CGI PVID/VLAN (gs305ep, gs105pe)

```python
def pvid_form(*, port, vlan, csrf_hash) -> dict[str, str]:
    return {f"port{port - 1}": "checked", "pvid": str(vlan), "hash": csrf_hash}

def membership_hidden_mem(states: Mapping[int, VlanMode], port_count: int) -> str:
    return "".join(_WIRE[states.get(p, EXCLUDED)] for p in range(1, port_count + 1))

def membership_form(*, vlan, hidden_mem, csrf_hash) -> dict[str, str]:
    return {"VLAN_ID": str(vlan), "hiddenMem": hidden_mem, "hash": csrf_hash}

def vlan_add_form(*, vlan, csrf_hash) -> dict[str, str]:
    return {"ACTION": "Add", "ADD_VLANID": str(vlan), "status": "Enable", "hash": csrf_hash}

def vlan_delete_form(*, vlan, checkbox_index, csrf_hash) -> dict[str, str]:
    return {"ACTION": "Delete", f"vlanck{checkbox_index}": str(vlan), "status": "Enable", "hash": csrf_hash}

def reboot_form(*, csrf_hash) -> dict[str, str]:
    return {"hash": csrf_hash}
```

`membership_hidden_mem` a port with NO entry in `states` defaults to
**EXCLUDED**, not untagged — a deliberate "unmentioned means removed" rule.

### 3.3 FASTPATH VLAN Membership form — NEW at 1841111

```python
_FASTPATH_MEM_APPLY = "16"   # decimal string "16" -- the page's own rollover.js
                              # does `elements['submt'].value = 0x10` then submits;
                              # JS stringifies the hex literal to its decimal text
_FASTPATH_MEM_NOOP = "0"

def fastpath_membership_form(page: FastpathMembership, *, vlan, hidden_mem=None, apply=False) -> dict[str, str]:
    body = dict(page.fields)          # start from EVERY field the device rendered
    body["vlanId"] = str(vlan)
    body["hiddenTagged"] = ""          # CLEARED -- these are OUTPUT fields the
    body["hiddenUnTagged"] = ""        # device re-renders; echoing stale values
                                        # is not what a browser does
    body["submt"] = _FASTPATH_MEM_APPLY if apply else _FASTPATH_MEM_NOOP
    if hidden_mem is not None:
        body["hiddenMem"] = hidden_mem   # None keeps the page's own value (a READ:
                                          # posting a DIFFERENT VLAN's codes with
                                          # submt=0 is what the browser does when
                                          # you just pick another VLAN -- the
                                          # firmware ignores them in that mode)
    return body
```

Starts from `page.fields` (every field the device itself rendered, from
`parse_fastpath_membership`, §2.9) so the M4300-16X's `CSRFToken` rides
along automatically — this builder never needs to know that field exists.

### 3.4 FASTPATH XUI generic apply — NEW at 1841111

```python
XUI_OPERATION_SUBMIT = "8"   # firmware's own /scripts/_xeobj_jsvars.js: xui_operation_submit = 8
XUI_OPERATION_RELOAD = "1"

def xui_row_apply_form(page: XuiListPage, row: XuiRow, changes: Mapping[str, str], *,
                        button: str, omit: Collection[str] = ()) -> dict[str, str]:
    body = dict(page.tokens)          # per-page CSRFToken (M4300-16X)
    body.update(page.nav)             # list-navigation/scope fields (urlListUnit etc.
                                       # -- REQUIRED by gsm7252ps's PoE page, see §1.6 item 3)
    dropped = {row.prefix + column for column in omit}
    body.update({k: v for k, v in row.fields.items() if k not in dropped})
    for column, value in changes.items():
        name = row.prefix + column
        if name not in row.fields:
            raise KeyError(...)        # column the row doesn't render -> hard error
        body[name] = value
    if row.checkbox is not None:
        body[row.checkbox] = "on"      # SELECTS this row -- the mechanism that
                                        # scopes the write to exactly one port
    body.update(page.hidden)           # submit_flag/submit_target/err_flag/err_msg/clazz_information
    body["submit_flag"] = XUI_OPERATION_SUBMIT
    body["err_flag"] = "0"
    body["err_msg"] = ""
    body[button] = page.buttons[button]   # the clicked button's own rendered label
    return body

def xui_form_apply_form(page: XuiFormPage, changes: Mapping[str, str], *, button: str) -> dict[str, str]:
    body = dict(page.fields)           # start from every field the device rendered
    for name, value in changes.items():
        if name not in page.fields:
            raise KeyError(...)
        body[name] = value
    body.update(page.hidden)
    body["submit_flag"] = XUI_OPERATION_SUBMIT
    body["err_flag"] = "0"
    body["err_msg"] = ""
    body[button] = page.buttons[button]
    return body
```

`xui_row_apply_form` deliberately sends ONLY the target row's fields (plus
page-level tokens/nav/hidden/button) — NARROWER than a real browser (which
submits every row's hidden inputs and lets the firmware apply only checked
ones). This is a SAFETY property, not mere efficiency: a body that never
mentions the other 51 ports cannot change them even under a firmware bug
that ignores checkboxes. LIVE-PROVEN on all four managed switches: after
this exact body, re-reading the whole table showed ONLY the target row's
cell changed, every OTHER row byte-identical.

`page.nav` inclusion is THE fix behind 1841111's gsm7252ps PoE-write
unlock (§1.6 item 3) — omitting it produced `err_flag=1` even for a
no-op write.

`omit` drops named bare columns the CLICKED BUTTON's own metadata marks
disabled (`xeData.xa_<button>[14]`) — "do not send this", not "this column
must exist"; a column the row doesn't render is silently ignored when named
in `omit` (models differ in which columns exist).

### 3.5 GS110EMX port-admin form — NEW at 1841111

```python
_EMX_CTRL_MODE_AUTO = "1"
_EMX_CTRL_MODE_DISABLE = "3"

def gs110emx_port_admin_form(*, port, enabled, flow_control_mode) -> dict[str, str]:
    return {
        "PORT_NO": f"{port};",   # SEMICOLON-TERMINATED -- a bare "3" is accepted
                                  # with HTTP 200 but applies NOTHING (caught live
                                  # by verify-after-write on 10.1.5.25)
        "PORT_CTRL_MODE": _EMX_CTRL_MODE_AUTO if enabled else _EMX_CTRL_MODE_DISABLE,
        "PORT_CTRL_DUPLEX": "0",
        "PORT_CTRL_SPEED": "0",
        "FLOW_CONTROL_MODE": flow_control_mode,   # ECHOED from the port's own
                                                    # current row, never defaulted --
                                                    # omitting it would silently
                                                    # rewrite flow control
        "ACTION": "apply",
    }
```

The `Gambit` session token is added by the TRANSPORT layer (client.py's
`_token_form_field`), not by this encoder — consistent with every other
POST on this model.

---

## 4. `protocols/http/crypt.py` — the full file (30 lines, transcribe verbatim)

```python
def merge(str1: str, str2: str) -> str:
    """Interleave two strings character by character (Netgear login scheme)."""
    out: list[str] = []
    i = j = 0
    while i < len(str1) or j < len(str2):
        if i < len(str1):
            out.append(str1[i]); i += 1
        if j < len(str2):
            out.append(str2[j]); j += 1
    return "".join(out)

def merge_hash_md5(password: str, rand: str) -> str:
    """Return md5(merge(password, rand)) as lowercase hex (Plus login hash)."""
    return hashlib.md5(merge(password, rand).encode()).hexdigest()
```

`merge` interleaves CHARACTER BY CHARACTER, not byte by byte and not simple
concatenation: `merge("ab", "12345")` = `"a1b2345"` (once `str1` runs out,
the rest of `str2` is appended verbatim — the `while` condition is `i <
len(str1) or j < len(str2)`, an OR, and each iteration attempts BOTH strings
independently). `merge_hash_md5` then MD5-hashes the UTF-8 encoding of that
interleaved string and returns lowercase hex. GROUNDED against
`rcfiles/bin/netgear-smp-vlan` and `py_netgear_plus/netgear_crypt.py`. Used
by BOTH `MERGE_HASH_CGI` (gs305ep, gs105pe) and `GAMBIT` (gs110emx) login
schemes — identical hash function, different field name/URL/session
mechanism layered on top (§1.1).

Go: `crypto/md5` computes MD5; the interleave loop translates directly
(iterate by `rune` if password may contain non-ASCII, though the observed
real-world passwords are ASCII — match Python's iteration granularity,
which is by Unicode codepoint since Python 3 strings are codepoint
sequences, so Go should range by `rune`, not `byte`, to stay byte-identical
on any non-ASCII input).

---

## 5. `protocols/http/session.py` + `types.py`

### 5.1 `session.py` — the full Protocol surface (59 lines)

```python
@dataclass(frozen=True)
class MultipartFile:
    field: str          # form field name the switch expects the file under
    filename: str
    content: bytes
    content_type: str   # MIME, e.g. "application/octet-stream"

class HttpSession(Protocol):
    def login(self) -> None: ...
    def get_page(self, path: str) -> str: ...
    def post_form(self, path: str, data: dict[str, str]) -> str: ...
    def post_multipart(self, path: str, data: dict[str, str], file: MultipartFile) -> str: ...
    def post_xml(self, path: str, body: str) -> str: ...

class AsyncHttpSession(Protocol):
    async def login(self) -> None: ...
    async def get_page(self, path: str) -> str: ...
    async def post_form(self, path: str, data: dict[str, str]) -> str: ...
    async def post_multipart(self, path: str, data: dict[str, str], file: MultipartFile) -> str: ...
    async def post_xml(self, path: str, body: str) -> str: ...
```

Both `HttpClient`/`AsyncHttpClient` (client.py, §6) implement these exactly;
readers/writers (Part 2) depend ONLY on this five-method surface, so the
pure protocol layer is the single shared codebase across sync and async.
This is the interface a Go `Session` type (or interface) needs to expose to
the facade — see §7.4.

### 5.2 `types.py` — `HttpSysInfo` (GS110EMX device identity + mgmt-IP)

```python
@dataclass(frozen=True)
class HttpSysInfo:
    product_name: str
    switch_name: str
    serial_number: str
    mac_address: str
    firmware_version: str
    ip_mode: IpMode
    ip_address: str
    subnet_mask: str
    gateway_address: str
```

GROUNDED in `tests/fixtures/http/gs110emx_sysinfo.html` (a real capture).
`ip_mode` is inferred from a `<tr data-select-value="N">` wrapping the
DHCP-mode `<select>` (the real capture carries NO explicit `selected`
attribute on either `<option>` — that's set client-side by page JS): `0`
selects "Disable" (static), `1` selects "Enable" (DHCP). **CAVEAT**: only the
STATIC-IP branch (`data-select-value="0"`) was directly observed in the one
real capture that exists — the DHCP branch (`"1"` → `IpMode.DHCP`) is
inferred from the SAME `<select>`'s option ordering, never itself captured
from a real DHCP-configured device. Preserve this as a code-comment caveat
in the Go port, not just drop it.

### 5.3 `types.py` — the remaining dataclasses (used by `parse.py`/`forms.py`)

Although the task scope named only `HttpSysInfo` explicitly, these four
additional `types.py` dataclasses are load-bearing for §2.9/§2.7/§3.4 above
and are included here for completeness (the caller of `parse_*`/`*_form`
functions cannot avoid depending on them):

- **`FastpathMembership`** (§2.9's return type) — `vlan_id: int | None`,
  `vlan_ids: tuple[int, ...]`, `name: str | None`, `vlan_type: str | None`,
  `tagged_ports: frozenset[int]`, `untagged_ports: frozenset[int]`,
  `hidden_mem: str`, `port_slots: Mapping[int, int]` (physical port → 0-based
  slot in `hidden_mem`'s comma list, read off the page's own grid, NEVER
  computed as `port - 1` — the grid interleaves LAG pseudo-interfaces and
  the two firmware generations index differently), `configured:
  Mapping[int, VlanMode]`, `fields: Mapping[str, str]` (every rendered form
  field, verbatim), `action: str` (the `_rw.html` POST target, exposed so a
  test can pin it against `HttpModelSpec.vlan_membership_post_path`). The
  docstring's key insight (already summarized in §2.9): `tagged_ports`/
  `untagged_ports`/`member_ports` are the **CURRENT (operational)** egress
  view; `configured` is the **CONFIGURED** participation the form actually
  submits — these TWO VIEWS GENUINELY DISAGREE on real hardware (example:
  gsm7252ps VLAN 1 ports 1/0/50, 1/0/51 are `Current: Exclude` /
  `Configured: Include`). Reads report the current view; writes set+verify
  the configured view (the only one the form can actually change).
- **`XuiRow`** — one repeating row of an XUI list page: `prefix: str`
  (`"<unit>.<row0>.<count>."`, taken VERBATIM from the device, never
  computed from the port number), `checkbox: str | None` (name differs per
  firmware: `1.0.52.gecb5` on gsm7252ps, `1.0.52.gecb10` on gsm7228ps,
  `1.0.24.gecb_1_2` on the M4300s — always scraped, never constructed),
  `fields: Mapping[str, str]`, plus a `field(column)` helper returning
  `self.fields.get(self.prefix + column)`.
- **`XuiListPage`** — `action: str` (the `/a1` write-form target),
  `hidden: Mapping[str, str]` (the trailing `submit_flag`/... block),
  `buttons: Mapping[str, str]` (`v_2_1_2` → `"APPLY"` etc. — button LABELS
  are NOT interchangeable between models, always echoed from the page),
  `rows: tuple[XuiRow, ...]`, `tokens: Mapping[str, str] = {}` (per-page
  `CSRFToken`), `nav: Mapping[str, str] = {}` (list-scope fields — see
  §1.6 item 3 and §3.4), plus `row_for(column, value)` helper.
- **`XuiFormPage`** — the "detail page" (non-repeating) twin: `action`,
  `hidden`, `buttons`, `fields: Mapping[str, str]` (every named input,
  verbatim — used by `ipConfiguration.html`/`mgmtVlanIpv4Configuration.html`).

---

## 6. `transport/http/client.py` — `HttpClient`/`AsyncHttpClient` (httpx)

One codebase in spirit (sync + async mirror each other line-for-line): all
URL/crypto/parse logic lives in `protocols.http`; only the actual GET/POST
calls differ between `httpx.Client` and `httpx.AsyncClient`. Legacy Plus
switches are HTTP-only ⇒ `base_url` defaults to `http://`; `secure=True`
flips it (and the Referer scheme with it) to `https://` — only the M4300-16X
needs this. TLS verification defaults OFF (self-signed switch certs).

### 6.1 Construction

```python
_TIMEOUT = 15.0
_LIMITS = httpx.Limits(max_keepalive_connections=0)   # see §6.4

class HttpClient:
    def __init__(self, host, password, spec, *, secure=False, verify_tls=False, transport=None):
        scheme = "https" if secure else "http"
        self._client = httpx.Client(
            base_url=f"{scheme}://{host}",
            timeout=_TIMEOUT,
            verify=verify_tls,
            transport=transport,             # test seam: httpx.MockTransport
            follow_redirects=True,
            limits=_LIMITS,
            headers=_referer_headers(spec, host, secure=secure),
        )
        self._logged_in = False
        self._token = ""
        self._session_path = ""
```

Constants for the Go transport: **timeout 15s**, **follow_redirects=True**
by default (except the XML_API login's FIRST GET, which explicitly passes
`follow_redirects=False` to capture the 302 itself), **TLS verify off by
default**, **no keep-alive** (`max_keepalive_connections=0`).

### 6.2 `_login_body(spec, password, login_page_html)` — pure, shared sync+async

Builds the login POST body per scheme (already narrated wire-flow-wise in
§1.1; this is the literal branch structure):

```python
if spec.scheme is CHEETAH_V1:
    body = {spec.username_field or "uname": spec.username, spec.password_field: password}
    token = _cheetah_csrf_token(login_page_html)   # optional, only if present
    if token is not None:
        body["CSRFToken"] = token
    return body
if spec.scheme is CHEETAH_FORM:
    body = {spec.password_field: password}
    if spec.username_field is not None:
        body[spec.username_field] = spec.username
    return body
# MERGE_HASH_CGI / GAMBIT
rand = parse_login_rand(login_page_html) if spec.needs_rand else None
if spec.needs_rand and not rand:
    raise HttpUnexpectedPageError(f"no login 'rand' nonce on {spec.login_path} — not a {spec.model_key}?")
hashed = merge_hash_md5(password, rand or "")
return {spec.password_field: hashed}
```

`_cheetah_csrf_token`:
```python
_CHEETAH_CSRF_RE = re.compile(
    r'name=["\']?CSRFToken["\']?[^>]*?value=["\']([^"\']*)["\']'
    r'|value=["\']([^"\']*)["\'][^>]*?name=["\']?CSRFToken["\']?',
    re.IGNORECASE,
)
```
Two alternatives because attribute ORDER varies by firmware (`name=` before
`value=`, or vice versa).

### 6.3 XML_API's own three-step helpers (all pure, shared sync+async)

```python
_XML_API_SESSION_PATH_RE = re.compile(r"/([A-Za-z0-9]+)/")

def _xml_api_session_path(resp) -> str:
    m = _XML_API_SESSION_PATH_RE.search(resp.headers.get("Location", ""))
    if not m: raise HttpAuthError(...)
    return m.group(1)

def _xml_api_login_url(spec, session_path, password) -> str:
    return f"/{session_path}/System.xml?action=login&user={quote(spec.username)}&password={quote(password)}"

def _apply_xml_api_login(spec, resp, cookies) -> None:
    if "<statusCode>0</statusCode>" not in resp.text: raise HttpAuthError(...)
    session_id = resp.headers.get("sessionID", "")
    if not session_id: raise HttpAuthError(...)
    cookies.set("userStatus", "ok")
    cookies.set("usernme", spec.username)     # sic -- firmware's real cookie name
    cookies.set(spec.cookie_name, session_id) # "sessionID"
```

### 6.4 GET-retry-on-dropped-connection (2 retries, GET ONLY, never POST)

```python
_DROPPED_CONNECTION_RETRIES = 2

def _retry_on_dropped_connection(send, context):
    last = None
    for _ in range(_DROPPED_CONNECTION_RETRIES + 1):   # up to 3 attempts total
        try:
            return send()
        except httpx.RemoteProtocolError as exc:
            last = exc
    raise HttpError(f"{context}: connection dropped by switch: {last}") from last
```

Rationale (both grounded live, GS105PE confirmed 2026-07-21): real Plus
hardware aggressively closes idle keep-alive connections, so the FIRST
request reusing a pooled connection can fail with "Server disconnected
without sending a response" even though the switch is healthy — retrying
re-establishes and succeeds. **Only `httpx.RemoteProtocolError`** (a dropped
connection) is retried — never an HTTP error status. **Only `get_page`
retries** — `post_form`/`post_multipart`/`post_xml` NEVER retry, because
a dropped connection during a WRITE does not prove the switch ignored the
request (a reboot POST is literally answered BY dropping the link; retrying
would re-issue an already-applied write). `_LIMITS` (max_keepalive=0)
ALSO addresses this at the root — disabling keep-alive costs one extra TCP
handshake per request against a LAN switch but makes reads reliable without
even needing the retry in the common case; the retry is defense in depth,
not a substitute.

### 6.5 `_check_authed` / `_extract_session_token` / `_token_params` / `_token_form_field`

```python
def _check_authed(spec, cookies) -> None:
    if spec.cookie_name not in cookies:
        raise HttpAuthError(f"web-UI login failed for {spec.model_key} — no {spec.cookie_name} cookie (check password, or switch may be locked out)")

def _extract_session_token(spec, html) -> str:
    token = parse_gambit_token(html)
    if not token:   # catches BOTH None (absent) and "" (empty value)
        raise HttpAuthError(f"... no {spec.session_token_field} token returned ...")
    return token

def _token_params(spec, token) -> dict[str, str] | None:
    return None if spec.session_token_field is None else {spec.session_token_field: token}

def _token_form_field(spec, token) -> dict[str, str]:
    return {} if spec.session_token_field is None else {spec.session_token_field: token}
```

### 6.6 `_referer_headers(spec, host, *, secure)` — the CSRF-guard header builder

```python
def _referer_headers(spec, host, *, secure) -> dict[str, str]:
    if not spec.needs_referer:
        return {}
    scheme = "https" if secure else "http"
    return {"Referer": f"{scheme}://{host}/", "Origin": f"{scheme}://{host}"}
```

Only `needs_referer=True` models get ANY extra header (both M4300 SKUs).
`host` carries the PORT VERBATIM when non-standard (`10.1.5.20:49152`) — the
16X's origin-exact CSRF check 403s a Referer that drops the port even
though the connection itself succeeds. `Origin` is sent EVERY TIME
(including GETs — harmless: browsers omit Origin on same-origin GETs anyway,
and every model's GETs were re-verified live with it present), but it is
functionally required ONLY on the AV-era 16X firmware's POSTs — isolated
live: Referer-alone POST → 403 (`"403 Forbidden\r\n"`, 15 bytes); +Origin →
200 with the real page; Origin-without-Referer → 403 again (firmware wants
BOTH). Constructed ONCE at client construction time and baked into the
`httpx.Client`'s default `headers=` (so every request carries it without
per-call plumbing) — a Go `http.Client`/`http.Transport` should replicate
this via a `RoundTripper` wrapper or by setting default headers on every
request builder, since Go's stdlib has no per-client default-header
concept.

### 6.7 `_validate_response(resp, *, context, path=None)` — shared status/session check

```python
def _validate_response(resp, *, context, path=None) -> None:
    if resp.status_code >= 400:
        raise HttpError(f"{context} returned HTTP {resp.status_code}")
    if path is not None and "redirect to login" in resp.text.lower():
        raise HttpAuthError(f"session lost fetching {path}")
```

Called by EVERY GET/POST call site (login and mid-session alike) so
status-code/stale-session handling cannot drift between sync/async. The
`path is not None` guard means only mid-session READS (not the login call
itself) also probe for the "redirect to login" substring — a mid-session
303/302-style soft-bounce back to the login page some firmware use instead
of a hard 401/403.

### 6.8 The five `HttpSession` methods, sync (async is a line-for-line `await` mirror)

```python
def login(self) -> None:
    if self._spec.scheme is XML_API:
        self._xml_api_login(); return
    post_path = self._spec.login_post_path or self._spec.login_path
    page = self._client.get(self._spec.login_path)
    _validate_response(page, context=f"GET {self._spec.login_path}")
    body = _login_body(self._spec, self._password, page.text)
    resp = self._client.post(post_path, data=body)
    _validate_response(resp, context=f"POST {post_path}")
    if self._spec.session_token_field is not None:
        self._token = _extract_session_token(self._spec, resp.text)
    else:
        _check_authed(self._spec, self._client.cookies)
    self._logged_in = True

def get_page(self, path: str) -> str:
    if not self._logged_in: self.login()
    url = self._read_url(path)          # XML_API: prefixes "/<sess>/"; else passthrough
    params = _token_params(self._spec, self._token)
    resp = _retry_on_dropped_connection(lambda: self._client.get(url, params=params), f"GET {path}")
    _validate_response(resp, context=f"GET {path}", path=path)
    return resp.text

def post_form(self, path: str, data: dict[str, str]) -> str:
    if not self._logged_in: self.login()
    body = {**data, **_token_form_field(self._spec, self._token)}
    resp = self._client.post(path, data=body)   # NEVER retried -- see §6.4
    _validate_response(resp, context=f"POST {path}")
    return resp.text

def post_multipart(self, path, data, file: MultipartFile) -> str:
    if not self._logged_in: self.login()
    body = {**data, **_token_form_field(self._spec, self._token)}
    files = {file.field: (file.filename, file.content, file.content_type)}
    resp = self._client.post(path, data=body, files=files)   # NEVER retried
    _validate_response(resp, context=f"POST {path}")
    return resp.text

def post_xml(self, path: str, body: str) -> str:
    if not self._logged_in: self.login()
    url = self._read_url(path)          # SAME session-path prefixing as get_page
    resp = self._client.post(url, content=body.encode("utf-8"),
                              headers={"Content-Type": "application/xml; charset=utf-8"})
    resp = self._client.post(...)   # NEVER retried
    _validate_response(resp, context=f"POST {path}")
    return resp.text
```

Every transport-error path (`httpx.HTTPError`) is caught and re-wrapped as
`HttpError(f"... transport error: {exc}")` — a Go port should wrap the
`net/http`/`net` layer error the same way rather than leaking a raw Go
error type across the `Session` interface boundary.

`_read_url(path)`:
```python
def _read_url(self, path: str) -> str:
    if self._spec.scheme is XML_API:
        return f"/{self._session_path}/{path}"
    return path
```
Used by BOTH `get_page` and `post_xml` (the ONLY two methods XML_API's
session-path prefix applies to — `post_form`/`post_multipart` are never
called for this model, since its cert upload goes through `post_xml` not
`post_multipart`).

`close()`/`aclose()` — just `self._client.close()`; no other teardown.
`__enter__`/`__exit__` (`__aenter__`/`__aexit__`) are thin context-manager
sugar around that.

---

## 7. Go porting notes

### 7.1 `net/http` transport shape

- **Timeout**: `http.Client{Timeout: 15 * time.Second}` matches `_TIMEOUT`.
- **No keep-alive**: set `Transport.DisableKeepAlives = true` (Go's direct
  equivalent of `httpx.Limits(max_keepalive_connections=0)`) — do NOT use
  `MaxIdleConnsPerHost = 0` alone, which has different (looser) semantics;
  `DisableKeepAlives` is the literal match.
- **TLS**: `Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify:
  !verifyTLS}` (default `verifyTLS=false`, matching `verify=False`).
- **Cookie jar PER SESSION** (not per-process): construct a fresh
  `net/http/cookiejar.Jar` per `HttpClient`/`AsyncHttpClient`-equivalent
  instance, exactly like httpx's per-`Client` `cookies` object — sharing one
  jar across multiple switches' sessions would leak `SID` cookies between
  hosts.
- **`follow_redirects=True` default**, EXCEPT the XML_API login's first GET,
  which must use `CheckRedirect: func(...) error { return
  http.ErrUseLastResponse }` (Go's idiom for "don't follow, give me the
  302 back") to read its `Location` header — mirrors `follow_redirects=
  False` on that ONE call.
- **Referer/Origin default headers**: Go's `http.Client` has no per-client
  default-header hook. Implement via a custom `http.RoundTripper` that
  wraps `http.DefaultTransport` and injects the two headers on every
  request when `spec.NeedsReferer`, OR simply set them explicitly at each
  call site (GET/POST) inside the `Session` implementation — either is a
  faithful port; a `RoundTripper` wrapper is closer to httpx's
  "baked into the client" model and is recommended so a future call site
  can't forget the header.
- **GET retry (2x) on a dropped connection, NEVER on POST**: Go's
  equivalent trigger is a `net.Error` whose underlying cause is a
  connection reset/EOF rather than an HTTP status — in practice, checking
  `errors.Is(err, io.EOF)` or `errors.As` for a `*net.OpError`/
  `http.httpError` covers httpx's `RemoteProtocolError` case; the important
  invariant to preserve is HTTP-status errors (obtained AFTER a response
  was received) are NEVER retried, only a genuinely dropped connection
  (error obtained INSTEAD of a response) is — wrap the retry helper around
  `client.Do(req)` itself, checking the returned error, not the response.
- **POST never retried**: no special code needed beyond simply not wrapping
  POST calls in the retry helper — but comment it prominently (as the
  Python does) since it is easy for a future maintainer to "helpfully"
  unify the two call sites.

### 7.2 goquery vs regex — go with regex, matching the Python 1:1

The Python source uses ZERO HTML-parsing libraries — pure `re` (plus
`html.unescape` for entity decoding and stdlib `xml.etree.ElementTree` for
the one XML dialect). **Recommendation: port to Go's `regexp` package
1:1, do NOT introduce `goquery`/`golang.org/x/net/html`.** Reasons specific
to this codebase, not a generic style preference:

1. Several parsers depend on REAL FIRMWARE MALFORMED HTML that a
   spec-compliant HTML5 tree parser (which `golang.org/x/net/html` and
   `goquery` both are, under the hood) would silently "fix" or reinterpret
   — most importantly:
   - **GS110EMX/GS105PE never close `<tr class="portID">` rows** (§2.4,
     §2.5) — `_OPEN_ROW_RE`/`_GS105PE_ROW_RE` cut at the next `<tr` or
     `</table>` by REGEX LOOKAHEAD, which is straightforward in `re`/Go
     `regexp` (both support non-capturing lookahead via `(?=...)` — Go's
     RE2-based `regexp` package DOES support this specific construct even
     though RE2 famously lacks general lookaround, because `(?=...)` here
     is used only at the very end of a pattern in a way RE2's syntax
     permits... **CAVEAT**: verify this at implementation time — Go's
     `regexp` (RE2) does **NOT** support arbitrary lookahead assertions;
     the actual porting strategy for `_OPEN_ROW_RE`'s `(?=<tr|</table>)`
     must be a manual two-step split (find all `<tr class="portID">`
     start offsets, then slice each row's content up to the NEXT start
     offset or `</table>`, whichever comes first) rather than a literal
     regex-lookahead port. This is the single trickiest regex-compat trap
     in the whole file — see §8 trap list.
   - A tree parser would auto-close every `<tr>` per the HTML5 parsing
     algorithm, silently ERASING the exact malformed-markup signal these
     parsers key off — turning "the shape that proves this is a GS110EMX
     page" into indistinguishable well-formed markup.
2. The `<!-- field_name -->` COMMENT-based M4300 addressing (§2.6) and the
   `document.write()`-embedded markup the FASTPATH VLAN-membership page
   must be scoped AROUND (§2.9) are both naturally regex/string-slice
   operations already in Python; a DOM parser adds no value and would
   require re-deriving equivalent "slice to the form, then regex within
   it" scoping logic anyway (the Python code ALREADY does exactly that
   slicing — `_xui_form_block`, `block = html[action.end():]` etc.).
3. `re.IGNORECASE`/`re.DOTALL` map directly to Go `regexp`'s `(?i)`/`(?s)`
   inline flags or `(?i:...)` — no semantic gap.
4. Where Python uses HTML entity decoding (`html.unescape`), Go's
   `html.UnescapeString` (stdlib `net/html` — note: importing just this one
   function does NOT require the full tree-parser API) is the direct
   equivalent.

Net recommendation: `regexp` + `html.UnescapeString` for every dialect
except GOAHEAD_XML; `encoding/xml` (stdlib) for that one, mirroring
`xml.etree.ElementTree` — including the SAME `<!DOCTYPE`/`<!ENTITY`
string-reject hardening (§2.10) since Go's `encoding/xml` decoder, like
`ElementTree`, does not fetch external entities by default but a
belt-and-braces string check costs nothing and preserves the Python
behavior exactly.

### 7.3 MD5 via `crypto/md5`

```go
import "crypto/md5"
func mergeHashMD5(password, rand string) string {
    sum := md5.Sum([]byte(merge(password, rand)))
    return hex.EncodeToString(sum[:])
}
```
`merge` itself: range over both strings by **rune** (not byte) to match
Python 3's codepoint-wise string iteration exactly (§4).

### 7.4 The `Session` interface for the facade + face

Mirror `HttpSession` (§5.1) as a Go interface with five methods (async
variant folds away — Go has no separate async/sync client split; a single
interface with `context.Context` parameters covers what Python needed TWO
Protocols for):

```go
type MultipartFile struct {
    Field       string
    Filename    string
    Content     []byte
    ContentType string
}

type Session interface {
    Login(ctx context.Context) error
    GetPage(ctx context.Context, path string) (string, error)
    PostForm(ctx context.Context, path string, data map[string]string) (string, error)
    PostMultipart(ctx context.Context, path string, data map[string]string, file MultipartFile) (string, error)
    PostXML(ctx context.Context, path string, body string) (string, error)
}
```

This is the interface `http_read.py`/`http_write.py`'s Go equivalents
(Part 2) depend on, and the interface `httpClient`/the eventual virtual
HTTP face (Part 2) both implement — exactly the role `snmp.Client`/
`nsdp.Client` already play for their backends (`backend_snmp.go`,
`backend_nsdp.go`). The shim file this dossier's Part 2 will need,
`backend_http.go`, follows the SAME pattern those two already establish:
a root-package `init()` that calls `RegisterBackend(model.BackendHTTP,
buildHTTPReader)` / `RegisterWriteBackend(model.BackendHTTP,
buildHTTPWriter)`, with the builder reading `sw.httpPassword.resolve()`
(already wired, switch.go lines 135-139/243-248) exactly the way
`buildNSDPWriter` reads `sw.nsdpPassword.resolve()` today (backend_nsdp.go
lines 130-148) — including the SAME "gate failure is never cached, only a
successfully-built session/writer is" discipline `resolveOnce` already
gives for free.

`HttpModelSpec` (§1.4) itself should port as a Go struct in a new `http`
package (`http.ModelSpec`, mirroring `snmp`/`nsdp`'s existing per-protocol
package shape) — a `LoginScheme`/`HtmlDialect` pair of small string-typed
enums (mirroring `model.Backend`'s `type Backend string` pattern already
used throughout `model/registry.go`), and `HTTP_SPECS` as an unexported
`map[string]ModelSpec` behind an exported `Spec(model *model.SwitchModel)
(ModelSpec, error)` lookup function mirroring `http_spec()`.

---

## 8. Completeness checklist

Every file/function this dossier covers, for cross-checking against the Go
port as it lands:

**endpoints.py**: `LoginScheme` (5 values) ✓ §1.1 · `HtmlDialect` (6 values)
✓ §1.2 · `XuiMgmtIpFields` (7 fields, 2 instances) ✓ §1.3 · `HttpModelSpec`
(36 fields — CORRECTED from 34, verified vs source) ✓ §1.4 · `HTTP_SPECS`/`_SPECS` all 8 model entries, every field
✓ §1.5 · `http_spec()` ✓ §1.5 intro · 1841111 write-op diffs (6 items) ✓ §1.6

**parse.py** (60 top-level functions/regex constants covered): `_cells`,
`_int`, `_poe_power_to_mw`, `_speed_text_to_mbps`, `_expand_port_list`,
`_expand_s3300_port_list` ✓ §2.1 · `parse_login_rand`, `parse_csrf_hash`,
`parse_gambit_token`, `parse_selected_vlan` ✓ §2.2 · `parse_port_status`,
`parse_port_stats`, `parse_poe_status`, `parse_pvids`, `parse_vlan_ids`,
`parse_membership` ✓ §2.3 · `parse_gs110emx_port_status`,
`parse_gs110emx_pvids`, `parse_gs110emx_vlan_ids`, `parse_interface_stats`,
`parse_sysinfo`, `parse_gs110emx_port_form_fields` ✓ §2.4 ·
`parse_gs105pe_port_status`, `parse_gs105pe_pvids`, `parse_gs105pe_stats`,
`parse_gs105pe_sysinfo` ✓ §2.5 · `parse_cheetah_rows`,
`parse_m4300_port_status`, `parse_m4300_stats`, `parse_m4300_pvids`,
`parse_m4300_vlans`, `parse_m4300_macs`, `parse_m4300_sysinfo`,
`parse_m4300_sensors` ✓ §2.6 · `parse_xe_rows`, `_xe_port_from_iface`,
`parse_xe_port_status`, `parse_xe_stats`, `parse_xe_pvids`,
`parse_xe_vlans`/`parse_s3300_vlans`/`_xe_vlan_rows`, `parse_xe_macs`,
`parse_s3300_macs`, `parse_s3300_mgmt`, `parse_xe_poe`, `parse_xe_lldp`,
`parse_xe_labelled_values`, `parse_xe_sensors`, `parse_xe_mgmt_ip` ✓ §2.7 ·
`_xui_form_block`, `_xui_inputs`, `_xui_buttons`, `parse_xui_list_page`,
`parse_xui_form_page`, `parse_xui_mgmt_ip` ✓ §2.8 · `parse_fastpath_membership`
(+ 8 helper functions: `_tag_attrs`, `_fastpath_physical_port`,
`_fastpath_iface_list`, `_fastpath_form_fields`, `_fastpath_grid`,
`_fastpath_vlan_select`, `parse_fastpath_err`, `fastpath_hidden_mem_with`)
✓ §2.9 · `_goahead_data_block`, `_goahead_section`, `_goahead_port_num`,
`_gtext`, `parse_goahead_ports`, `parse_goahead_pvids`,
`parse_goahead_vlan_names`, `parse_goahead_port_vlan_membership`,
`parse_goahead_vlans`, `parse_goahead_macs`, `parse_goahead_poe`,
`_canon_lldp_id`, `parse_goahead_lldp`, `_goahead_state_sensor`,
`parse_goahead_sensors`, `parse_goahead_base_mac`, `parse_goahead_mgmt_ip`
✓ §2.10 · `parse_reboot_ok` ✓ §2.11

**forms.py**: `poe_apply_form`, `poe_reset_form` ✓ §3.1 · `pvid_form`,
`membership_hidden_mem`, `membership_form`, `vlan_add_form`,
`vlan_delete_form`, `reboot_form` ✓ §3.2 · `fastpath_membership_form` ✓ §3.3
· `xui_row_apply_form`, `xui_form_apply_form` ✓ §3.4 ·
`gs110emx_port_admin_form` ✓ §3.5

**crypt.py**: `merge`, `merge_hash_md5` ✓ §4 (full file, verbatim)

**session.py**: `MultipartFile`, `HttpSession`, `AsyncHttpSession` ✓ §5.1

**types.py**: `HttpSysInfo` ✓ §5.2 · `FastpathMembership`, `XuiRow`,
`XuiListPage`, `XuiFormPage` ✓ §5.3

**transport/http/client.py**: `_cheetah_csrf_token`, `_login_body` ✓ §6.2 ·
`_xml_api_session_path`, `_xml_api_login_url`, `_apply_xml_api_login` ✓ §6.3
· `_retry_on_dropped_connection`/`_aretry_on_dropped_connection` ✓ §6.4 ·
`_check_authed`, `_extract_session_token`, `_token_params`,
`_token_form_field` ✓ §6.5 · `_referer_headers` ✓ §6.6 · `_validate_response`
✓ §6.7 · `HttpClient`/`AsyncHttpClient`: `__init__`, `login`,
`_xml_api_login`, `get_page`, `post_form`, `post_multipart`, `post_xml`,
`close`/`aclose`, `_read_url`, context-manager sugar ✓ §6.8

### 8.1 Ten trickiest traps (read this before writing a single line of Go)

1. **RE2 has no general lookahead** — `_OPEN_ROW_RE`'s `(?=<tr|</table>)`
   needs a manual split-by-offset port in Go, not a literal `regexp`
   translation (§7.2 item 1).
2. **VLAN wire codes are INVERTED between the two families**: Plus-CGI
   `8021qMembe.cgi` is 1=Untagged/2=Tagged/3=Excluded; FASTPATH
   `vlan_port_cfg.html` is 1=Tagged/2=Untagged/3=Excluded. Never share an
   encoder/decoder between them (§2.3 vs §2.9).
3. **PoE power units vary per firmware on the SAME column header text**:
   gsm7252ps renders integer milliwatts, M4300-16X renders decimal watts —
   disambiguate by presence of a decimal point, not by model (`_poe_power_to_mw`).
4. **GS105PE's real byte/CRC counters are in HIDDEN 32-bit half-pairs**, not
   the visible `<td>` text (which is JS-populated and empty in the raw
   HTML) — `hi*2^32+lo`, three consecutive pairs per row.
5. **FASTPATH VLAN grid has TWO firmware generations with opposite slot
   indexing** — style A is 0-based, style B is 1-based; both must be tried,
   and the parser CROSS-CHECKS the grid against `hiddenMem` and refuses on
   any disagreement rather than trusting either alone.
6. **LAG pseudo-interfaces are unit `0`** (`0/<slot>/<n>`) on the FASTPATH
   egress-list/grid encodings — a bare `\d+/\d+/\d+` match without the
   unit-0 exclusion turns `lag 1 - lag 128` into 128 phantom physical ports
   (a real regression this codebase fixed once already).
7. **MAC/FDB tables are PAGINATED on M4300/XE_FASTPATH/S3300** — always
   cross-check the page's own stated total (`v_1_1_1`) against rendered row
   count and RAISE (never silently truncate) if the page is short; SNMP is
   the complete-table fallback.
8. **XML_API's GS728TPP session identity arrives as a RESPONSE HEADER
   (`sessionID`), never a `Set-Cookie`** — the client sets it into the
   cookie jar itself, and the whole login is a 3-step GET/GET/apply-cookies
   sequence, not a form POST at all.
9. **Referer/Origin CSRF guards differ by verb on the M4300-16X**: Referer
   alone suffices for GET but 403s on POST unless Origin ALSO rides along,
   and the Referer's host must include the non-standard `:49152` port
   verbatim (origin-exact check).
10. **GET retries (2x) on a dropped connection; POST NEVER retries, ever** —
    a write's dropped connection does not prove the switch didn't apply it
    (a reboot POST is answered BY the link dropping). Keep this asymmetry
    exact in the Go transport; unifying the two retry paths is a silent
    correctness regression, not a simplification.

---

## Part 2 handoff

This dossier (PART 1) covers ONLY the pure protocol layer (`protocols/
http/*.py`) and the httpx wire transport (`transport/http/client.py`). A
SEPARATE PART 2 dossier must cover everything that sits ABOVE this layer,
before Go implementation of the HTTP backend can begin end-to-end:

1. **`http_read.py`/`http_write.py`** — the reader/writer orchestration that
   calls the parsers/forms/client this dossier documents. In particular:
   - How each read op (`get_ports`, `get_stats`, `get_vlans`, `get_pvids`,
     `get_lldp`, `get_macs`, `get_poe`, `get_sensors`, `get_mgmt_ip`) is
     assembled PER DIALECT — which page(s) it fetches, which parser(s) it
     calls, and how results from multiple pages are merged (e.g. mgmt-IP
     merging `sysinfo_path`'s base MAC with `mgmt_ip_path`'s
     address/netmask/gateway on the four XUI models).
   - The **`reads_verified` GATING logic**: `HttpModelSpec.reads_verified`
     is a `HttpModelSpec` DATA field this Part-1 dossier fully documents
     (§1.5), but the actual REFUSAL BEHAVIOR — where/how `HttpReader`
     construction checks it and raises rather than serving an unverified
     model's reads — lives in `http_read.py` and must be captured in Part 2.
   - Every WRITE op's full flow: scrape CSRF/token → build the form (§3) →
     POST → verify-after-write (re-read and confirm the change landed,
     several traps this dossier already flagged require it — e.g. the
     GS110EMX `PORT_NO` semicolon bug, §3.5).
   - **SSL certificate upload**: the gsm7228ps multipart flow
     (`post_multipart` + `MultipartFile`, §5.1/§6.8) vs the gs728tpp raw-XML
     flow (`post_xml`, `_cert_upload_xml`) — both ride on THIS dossier's
     transport primitives but the XML BODY CONSTRUCTION and the
     multipart form-field assembly (`cert_upload_form_fields`, §1.5
     gsm7228ps) are Part 2 (`http_write.py`'s `CERT_UPLOAD_KNOWN_UNIMPLEMENTED`
     constant and per-model dispatch belong there too).
2. **`virtual/faces/http.py` + `virtual/faces/web_*.py`** — the byte-faithful
   virtual-switch HTTP face and its per-dialect HTML RENDERERS (the inverse
   of `parse.py`: given `State`, emit HTML byte-shaped like a real captured
   page). This is a SEPARATE, substantial body of code from the parsers
   documented here and needs its own exhaustive treatment (which fixture
   HTML each renderer must byte-match, CSRF/hash/token round-tripping in
   the virtual face, session/login simulation per scheme).
3. **Seed HTTP fixture data** — the `tests/fixtures/http/*.html` captures
   this dossier's parser docstrings repeatedly cite as GROUNDING evidence
   (gs110emx_*, gs105pe_*, m4300_*, gsm7252ps_*, gsm7228ps_*) and whatever
   seed/golden data the Go port's own test suite needs, including whether/
   how those fixtures get ported or re-captured.
4. **Facade `http` shim** (`http_backend.go`, following the
   `backend_snmp.go`/`backend_nsdp.go` pattern this dossier's §7.4 already
   sketches) and the **`reads_verified` gate's Go-side wiring** — where in
   `buildHTTPReader` the gate is checked, what error it returns
   (presumably wrapping `model.ErrUnsupportedCapability`, matching the
   existing NSDP/SNMP builder convention), and how `WithHTTPPasswordResolver`
   (already fully wired in `switch.go`, §0/§7.4 above) is consumed by
   `buildHTTPWriter`.
5. **Tests** — unit tests for the reader/writer orchestration, any
   integration/facade-level tests analogous to `facade_integration_test.go`/
   `facade_write_integration_test.go`, and whatever cross-verification
   (HTTP-vs-SNMP, HTTP-vs-NSDP) the Go port should replicate given how
   heavily the Python source leans on live cross-verification as its
   grounding evidence.

None of the above is covered in THIS document — Part 1 stops at "here is
every URL, every parser, every form encoder, every wire-protocol detail
below the reader/writer orchestration layer."
