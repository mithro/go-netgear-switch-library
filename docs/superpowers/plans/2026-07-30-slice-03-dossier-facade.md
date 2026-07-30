# Facade / Dispatch Layer — Porting Dossier (Slice 03)

**Pinned Python reference:** `python-netgear-switch-library` @
`1aa1274254a233ddce0409160849bb6ce8f8b2e7` (snapshot worktree:
`/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1aa1274`).
**Pin guard verified:** `git -C <snapshot> rev-parse HEAD` ==
`1aa1274254a233ddce0409160849bb6ce8f8b2e7` — matches the required prefix
`1aa1274`. This snapshot repo is read-only; every quote below is verbatim
from that state. Where this dossier and the pinned source disagree, the
source wins.

**Scope:** the READ-side facade/dispatch layer — `_dispatch.py` (backend
gates + client builders) and `sync_api.py`'s `SyncSwitch` in full (including
its write-method plumbing, documented for the shared dispatch machinery even
though slice 04 owns write *semantics*). The Go port has a single ctx-based
`Switch` (no async twin); `aio_api.py`'s `AsyncSwitch` is covered only as a
delta list at the end of §2, to flag exactly where Go's single facade must
NOT silently inherit an async-only restriction (or must, deliberately).

**Audience:** Go engineers building the slice-03 facade without reading the
Python source themselves.

---

## 1. `src/netgear_switch/_dispatch.py` (242 lines, full inventory)

Module docstring: "Internal backend-resolution seam shared by SyncSwitch and
AsyncSwitch. Only SNMP is wired in this slice [Python's slice numbering, not
Go's]. Model-driven dispatch lives here so the two facades stay identical
and Slices 5/6 can add NSDP/HTTP backends without touching the public facade
surface. Transport imports are function-local so `import netgear_switch`
never requires net-snmp binaries or pysnmp." **This is the exact
architectural intent the Go seam in §3 must replicate**: Go has ONE facade
(no async twin), but the same "backends not yet implemented must not break
the facade" property applies to NSDP/HTTP/CLI, which don't exist in the Go
tree yet.

### 1.1 `BACKEND_NOT_IMPLEMENTED` (module constant, exact string)

```python
BACKEND_NOT_IMPLEMENTED = (
    "model {key!r} has no SNMP backend; its NSDP backend is used instead. "
    "(An HTTP-only capability is not implemented until Slice 6.)"
)
```
Used only by `require_snmp_backend`. Note this message is Python-slice-plan
specific ("until Slice 6") — the Go port should NOT copy the sentence
verbatim; preserve the *shape* (names the model key, says what backend is
used instead) but drop the Python-slice-number reference.

### 1.2 Every `require_*` gate (exact behavior + exact error text)

All raise `UnsupportedCapabilityError` and take a `SwitchModel`; none touch
the network.

| Function | Guard | Exact message (format string) |
|---|---|---|
| `require_snmp_backend(model)` | `Backend.SNMP not in model.backends` | `BACKEND_NOT_IMPLEMENTED.format(key=model.key)` (see 1.1) |
| `require_mac_table(model)` | `not model.has_mac_table` | `f"model {model.key!r} has no MAC/FDB table"` |
| `require_nsdp_backend(model)` | `Backend.NSDP not in model.backends` | `f"model {model.key!r} has no NSDP backend"` |
| `require_http_backend(model)` | `Backend.HTTP not in model.backends` | `f"model {model.key!r} has no HTTP backend"` |
| `require_cli_backend(model)` | `not (CLI_BACKENDS & model.backends)` (lazy-imports `CLI_BACKENDS` from `protocols.cli.commands`) | `f"model {model.key!r} has no CLI backend"` |

`require_mac_table` is the ONLY one of these actually called from
`sync_api.py` in this slice (by `get_macs()`, unconditionally, before
`_read` dispatch — see §2.7). `require_snmp_backend`/`require_nsdp_backend`
exist as building blocks but are not directly wired into any `SyncSwitch`
method today (`_reader_for`/`_writer_for` inline-check `model.backends`
membership instead — see §2.5/§2.6). `require_http_backend` IS used, by
`upload_certificate` (§2.16). `require_cli_backend` is not called anywhere
in this slice (CLI gating for reads goes through `cli_reads_supported`
instead, §1.4).

### 1.3 `http_reads_supported(model) -> bool` (full semantics, verbatim docstring)

```python
def http_reads_supported(model: SwitchModel) -> bool:
    if Backend.HTTP not in model.backends:
        return False
    from .protocols.http.endpoints import HTTP_SPECS
    spec = HTTP_SPECS.get(model.key)
    return spec is not None and spec.reads_verified
```

Full docstring (load-bearing — pins exact per-model behavior the facade
depends on):

> "True only if the model's web reads/writes are grounded (reads_verified).
> The facade uses this to decide whether HTTP may join the per-op backend
> fallback. An UNVERIFIED-pending-capture model (gsm7228ps cheetah) returns
> False: its HTTP path is never used for read/write dispatch (SNMP stays
> authoritative; HTTP is reserved for firmware/reboot). gs110emx's Gambit
> login + sysInfo/interface_stats reads ARE grounded, so this returns True
> for it — but NSDP is still authoritative for every op it serves
> (ports/VLANs/PVIDs/stats/mgmt-IP). In practice this means gs110emx's HTTP
> get_stats/get_mgmt_ip are NEVER actually reached through the
> SyncSwitch/AsyncSwitch facade: NSDP's own get_stats/get_mgmt_ip always
> return a result rather than raising UnsupportedCapabilityError (unlike
> get_macs/get_lldp/get_sensors/get_poe, which NSDP genuinely doesn't have
> and does raise for), so the facade's per-op backend loop never falls
> through to HTTP for those two ops — only a directly-constructed
> HttpReader/AsyncHttpReader exercises them."

**This is called both for gate-time AND for `_writer_for(HTTP)`** (name
notwithstanding — Python reuses the same "reads_verified" flag to gate HTTP
*writes* too; there is no separate `http_writes_supported`). Despite the
`http_reads_supported` name, it is the single gate for both HTTP directions.
Go's registry seam (§3) must expose one predicate serving both.

### 1.4 `cli_reads_supported(model) -> bool` (mirrors 1.3)

```python
def cli_reads_supported(model: SwitchModel) -> bool:
    from .protocols.cli.commands import CLI_BACKENDS, CLI_SPECS
    if not (CLI_BACKENDS & model.backends):
        return False
    spec = CLI_SPECS.get(model.key)
    return spec is not None and spec.reads_verified
```
Docstring: "Mirrors `http_reads_supported`. A CLI spec with
`reads_verified=False` (CLI reader output not yet cross-verified against
SNMP on live hardware) gates OFF. The FASTPATH models (m4300-24x/-16x,
gsm7252ps) are now verified and return True; other models return False and
the facade never dispatches a live read to their CLI backend." There is no
`cli_writes_supported` — no CLI writer exists in this slice at all (see
§2.6, `_writer_for`'s CLI branch always raises).

### 1.5 SNMP client builders (read + write, sync + async)

```python
def _require_community(host, community):
    if community is None:
        raise CredentialError(f"no SNMP read community configured for {host!r}")
    return community

def build_sync_snmp_client(host, community) -> SnmpClient:
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
    return NetsnmpCliClient(host, _require_community(host, community))

def build_async_snmp_client(host, community) -> AsyncSnmpClient:
    from .transport.aio.snmp_pysnmp import PysnmpClient
    return PysnmpClient(host, _require_community(host, community))

def _require_write_community(host, community):
    # An empty string must be rejected too, not just None -- otherwise an
    # unresolved/blank write-community spec could silently flow through to
    # `snmpset -c ""` instead of raising (carry-forward review fix).
    if not community:
        raise CredentialError(f"no SNMP write community configured for {host!r}")
    return community

def build_sync_snmp_write_client(host, write_community) -> SnmpWriteClient:
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
    return NetsnmpCliClient(host, _require_write_community(host, write_community))

def build_async_snmp_write_client(host, write_community) -> AsyncSnmpWriteClient:
    from .transport.aio.snmp_pysnmp import PysnmpClient
    return PysnmpClient(host, _require_write_community(host, write_community))
```

**Read-community gate vs write-community gate are asymmetric**:
`_require_community` (read) rejects only `None`; `_require_write_community`
(write) rejects `None` **and** `""` (falsy check `not community`). This
asymmetry is deliberate (see comment) and MUST be preserved: a Go port must
NOT unify these into one helper. The Go equivalent of `SnmpClient` /
`SnmpWriteClient` here is `snmp.Client` (see `snmp/client.go`); the sync
`NetsnmpCliClient` transport has no Go equivalent yet (Go's only live SNMP
transport is `GoSNMPClient`, §5 below — no CLI-invoking net-snmp transport
exists nor is planned, since gosnmp is a pure-Go UDP transport).
**Consequence for the Go facade dispatch seam**: unlike Python (which has
two SNMP transports, sync=net-snmp-CLI and async=pysnmp, both wrapped by
`build_sync_snmp_client`/`build_async_snmp_client`), the Go port needs only
ONE SNMP client builder (`snmp.NewGoSNMPClient`, ctx-based) since there is
no sync/async split.

### 1.6 NSDP client builders (not usable yet in Go — no `nsdp` package exists)

```python
def build_sync_nsdp_client(host, interface) -> NsdpWriteClient:
    from .transport.sync.nsdp_udp import UdpNsdpClient
    return UdpNsdpClient(host, interface=interface)

def build_async_nsdp_client(host, interface) -> AsyncNsdpWriteClient:
    from .transport.aio.nsdp_udp import AsyncUdpNsdpClient
    return AsyncUdpNsdpClient(host, interface=interface)
```
One client class serves BOTH read and write (annotated with the richer
`NsdpWriteClient`/`AsyncNsdpWriteClient` protocol, which extends the
read-only `NsdpClient`/`AsyncNsdpClient`). No community/password argument at
construction — NSDP's admin password is supplied per-*write* call (see
`_writer_for`'s NSDP branch, §2.6), not at client-build time. **This is the
slice-05 seam**: Go's registry hook (§3) must plug in a
`func(host string, iface *string) (NsdpClient, error)` builder exactly
mirroring this shape once slice 05 lands.

### 1.7 HTTP backend gate + `_http_host` + client builders

```python
def _http_host(host, spec) -> str:
    """The web-UI host[:port] for `spec`: the bare IP for a standard-port
    model, or `<ip>:<web_port>` for one on a non-standard port (m4300-16x on
    :49152). `host` is the switch IP, never already carrying a port."""
    return f"{host}:{spec.web_port}" if spec.web_port is not None else host

def _require_http_password(host, password) -> str:
    if not password:
        raise CredentialError(f"no HTTP password configured for {host!r}")
    return password

def build_sync_http_client(host, password, model) -> HttpClient:
    from .protocols.http.endpoints import http_spec
    from .transport.http.client import HttpClient
    spec = http_spec(model)
    return HttpClient(_http_host(host, spec), _require_http_password(host, password), spec, secure=spec.secure)

def build_async_http_client(host, password, model) -> AsyncHttpClient:
    # identical shape, AsyncHttpClient
```
`_require_http_password` rejects `None` AND `""` (falsy), same shape as the
SNMP *write* gate (§1.5), NOT the SNMP *read* gate — HTTP has no
password-less "read" mode at all (every HTTP op needs to log in). `web_port`
comes from the model's `HttpModelSpec` (per-model, e.g. m4300-16x's
non-standard `:49152`); this is HTTP-spec data slice 06 owns, not part of
the slice-03 registry.

### 1.8 CLI client builder

```python
def build_sync_cli_client(host, username, password, model) -> CliSession:
    from .protocols.cli.commands import cli_spec
    from .transport.cli.ssh import SshCliTransport
    if not password:
        raise CredentialError(f"no CLI password configured for {host!r}")
    return SshCliTransport(host, username, password, cli_spec(model))
```
No async CLI builder exists — CLI transports (paramiko/telnetlib/pyserial)
are synchronous only; `AsyncSwitch` never builds one (§2 async-delta list).
`SyncSwitch` always passes `username="admin"` and reuses the resolved HTTP
password as the CLI password (`self._resolve_http_password()` — see
§2.5/§2.14): there is no separate CLI-password config field.

---

## 2. `src/netgear_switch/sync_api.py` (774 lines) — `SyncSwitch` in full

### 2.1 Module-level constants

```python
_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()   # slice-04 concern, listed for completeness

_BACKEND_PREFERENCE = (Backend.SNMP, Backend.NSDP, Backend.HTTP, Backend.SSH)
```
Comment (load-bearing, quoted in full — this IS the dispatch contract):

> "Per-op backend preference: try SNMP, then NSDP, then HTTP; the first
> backend whose reader/writer serves an op wins. HTTP joins this fallback
> only when a higher-priority backend's reader/writer CONSTRUCTION raises
> UnsupportedCapabilityError, or the op method itself explicitly raises it
> (e.g. NSDP's get_macs/get_lldp/get_sensors/get_poe — see nsdp_read.py's
> `_NO_*` constants). NSDP's get_stats/get_mgmt_ip are NOT such ops: they
> always return a (possibly sparse) result rather than raising
> UnsupportedCapabilityError, so for a {NSDP, HTTP} model (e.g. gs110emx)
> those two ops are ALWAYS served by NSDP through this facade — their real
> HTTP implementations in http_read.py are unreachable here; only a
> directly-constructed HttpReader ever exercises them. Do not read this
> preference order as 'HTTP only fills gaps' more broadly than that."

`Backend.SSH` is last in the tuple; in this slice `_reader_for`'s catch-all
`else` branch handles it (and TELNET/CONSOLE, though those aren't
independently registered on any model — see registry `Backend` doc). There
is no separate `Backend.TELNET`/`Backend.CONSOLE` entry in
`_BACKEND_PREFERENCE`: any backend not `SNMP`/`NSDP`/`HTTP` in
`model.backends` falls to the same CLI code path.

`_AnyReader = SnmpReader | NsdpReader | HttpReader | CliReader` — the reader
union type. Writer union: `SnmpWriter | NsdpWriter | HttpWriter` (no
`CliWriter` type exists — see §2.6).

### 2.2 `_Unset` sentinel + `_UNSET` (exact pattern, used 3×)

```python
class _Unset:
    """Sentinel type for "write community not yet resolved" ...: a resolved
    value of None (no community configured) must stay distinguishable from
    "never resolved"."""

_UNSET = _Unset()
```
Three independent fields use this exact pattern in `__init__`:
`_resolved_write_community`, `_resolved_nsdp_password`,
`_resolved_http_password` — each typed `str | None | _Unset`, each starting
at `_UNSET`. **Go has no ambient class-identity sentinel** — the idiomatic
port is a `*string` (nil = "not configured") plus a separate `resolved
bool` flag per field (or a tri-state enum), NOT overloading nil for both
"unresolved" and "resolved-to-none". Get this wrong and a `!command` secret
spec (§2.10, `_resolve_write_community`) could re-exec its subprocess on
every write — see the pinned regression test in §4
(`test_write_community_resolver_invoked_at_most_once_across_writes`).

### 2.3 `_LazyHttpSession` (full class, every method)

```python
class _LazyHttpSession:
    def __init__(self, resolve: Callable[[], HttpSession]) -> None:
        self._resolve = resolve
    def login(self) -> None: self._resolve().login()
    def get_page(self, path: str) -> str: return self._resolve().get_page(path)
    def post_form(self, path, data) -> str: return self._resolve().post_form(path, data)
    def post_multipart(self, path, data, file) -> str: return self._resolve().post_multipart(path, data, file)
    def post_xml(self, path, body) -> str: return self._resolve().post_xml(path, body)
```
Docstring: "Wraps `SyncSwitch._http_session` so building the real
HttpSession (which needs a resolved password) is deferred until an op that
genuinely reaches the wire (`login`/`get_page`/`post_form`) is called. Ops
an HttpReader/HttpWriter refuses honestly WITHOUT ever touching the session
(e.g. `get_macs`, `set_mgmt_ip`) must never trigger HTTP password resolution
or a live connection — only per-op routing that HTTP actually ends up
serving should pay that cost."

**Construction-vs-first-use semantics**: `_LazyHttpSession.__init__` does
ZERO work — `self._resolve` is stashed, nothing is called. `self._resolve`
is `SyncSwitch._http_session` itself (a bound method), which is where the
REAL laziness lives: `_http_session()` only builds `_built_http_client` (via
`build_sync_http_client`, which resolves the password and therefore can
raise `CredentialError`) the first time IT is called — i.e. the first time
any of `_LazyHttpSession`'s five methods run. Every call after the first
reuses the cached `self._built_http_client` (see §2.4). Note
`_LazyHttpSession` itself has NO cache of its own — every method call
re-invokes `self._resolve()`, but `_http_session()` is naturally idempotent
because it checks `self._built_http_client is None` first.

### 2.4 `_LazyCliSession` (full class, every method — richer than 2.3)

```python
class _LazyCliSession:
    def __init__(self, resolve: Callable[[], CliSession]) -> None:
        self._resolve = resolve
        self._session: CliSession | None = None
    def _live(self) -> CliSession:
        if self._session is None:
            self._session = self._resolve()
        return self._session
    def run(self, command: str) -> str: return self._live().run(command)
    def run_scp_copy(self, command, scp_password) -> str: return self._live().run_scp_copy(command, scp_password)
    def run_write_memory(self, command="write memory", *, prestuff) -> str:
        return self._live().run_write_memory(command, prestuff=prestuff)
    def close(self) -> None:
        if self._session is not None:
            self._session.close()
```
Docstring (load-bearing): "Wraps CLI-transport construction so building the
real SSH session (which needs a resolved password and raises
`CredentialError` if none is set) is deferred until an op actually RUNS a
command. Ops a `CliReader` refuses WITHOUT touching the session — e.g.
`get_poe` on a non-PoE model, which raises `UnsupportedCapabilityError`
before any `run()` — must never trigger CLI password resolution or a live
connection. Without this, the facade's SSH fall-through for such an op
raised `CredentialError` instead of the honest `UnsupportedCapabilityError`
(and diverged from AsyncSwitch, which never builds a CLI client)."

**Key difference from `_LazyHttpSession`: `_LazyCliSession` caches its OWN
session** (`self._session`), separate from any facade-level cache — because
unlike HTTP (where `_http_session()` itself is the memoized builder),
`_LazyCliSession` is constructed FRESH every time `_reader_for(SSH)` runs
(no `_reader_cache` reuse of the underlying transport across
`_LazyCliSession` instances — though `_reader_for`'s own `_reader_cache`
DOES cache the `CliReader` object, which holds one `_LazyCliSession`, so in
practice one `_LazyCliSession` per `SyncSwitch` per process is the norm).
`close()` is a no-op if `_session is None` — verified by the pinned test
`test_lazy_cli_session_defers_build_until_first_command` (§4): construction
+ `close()` before any command builds nothing.

### 2.5 `_reader_for(backend) -> _AnyReader` (full method, all 4 branches)

```python
def _reader_for(self, backend: Backend) -> _AnyReader:
    cached = self._reader_cache.get(backend)
    if cached is not None:
        return cached
    reader: _AnyReader
    if backend is Backend.SNMP:
        client = self._snmp_client
        if client is None:
            client = build_sync_snmp_client(self.host, self._snmp_community)
        reader = SnmpReader(client, self.model)
    elif backend is Backend.NSDP:
        nsdp = self._nsdp_client
        if nsdp is None:
            nsdp = build_sync_nsdp_client(self.host, self._nsdp_interface)
        reader = NsdpReader(nsdp, self.model)
    elif backend is Backend.HTTP:
        if not http_reads_supported(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} HTTP reads are UNVERIFIED-pending-capture"
            )
        reader = HttpReader(_LazyHttpSession(self._http_session), self.model)
    else:  # a CLI backend (SSH/telnet/console)
        if not cli_reads_supported(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} CLI reads are UNVERIFIED-pending cross-verify"
            )
        reader = CliReader(
            _LazyCliSession(lambda: build_sync_cli_client(
                self.host, "admin", self._resolve_http_password(), self.model
            )),
            self.model,
        )
    self._reader_cache[backend] = reader
    return reader
```
**Cache semantics**: `_reader_cache: dict[Backend, _AnyReader]`, keyed by
`Backend` enum value, populated lazily ONE TIME per backend per
`SyncSwitch` instance — including the SNMP/NSDP branches, which build (or
reuse an injected) client eagerly (no further laziness: an injected
`snmp_client`/`nsdp_client` is used as-is; a non-injected one is built via
`build_sync_*` IMMEDIATELY, i.e. SNMP/NSDP client construction is NOT
deferred to first wire use the way HTTP/CLI are — because SNMP/NSDP
transport construction never needs a resolved secret at construction time
(SNMP's `snmp_community` may already be known; NSDP's password is supplied
per-write-call, not at reader construction). HTTP and CLI readers, by
contrast, wrap a lazy session precisely because their construction requires
a resolved secret that may raise `CredentialError`.

Once a reader is built (successfully or via a raised
`UnsupportedCapabilityError` for HTTP/CLI's gate) — actually note: **if the
HTTP/CLI gate raises, NOTHING is cached** (the `raise` happens before
`self._reader_cache[backend] = reader`), so every subsequent call to
`_reader_for(HTTP)` on a gated-off model re-evaluates
`http_reads_supported(self.model)` from scratch (cheap — a dict lookup — so
this is a correctness point, not a performance one: don't accidentally
cache the "unsupported" outcome).

### 2.6 `_writer_for(backend) -> SnmpWriter | NsdpWriter | HttpWriter` (full method)

```python
def _writer_for(self, backend: Backend) -> SnmpWriter | NsdpWriter | HttpWriter:
    cached = self._writer_cache.get(backend)
    if cached is not None:
        return cached
    writer: SnmpWriter | NsdpWriter | HttpWriter
    if backend is Backend.SNMP:
        client = self._snmp_write_client
        if client is None:
            client = build_sync_snmp_write_client(self.host, self._resolve_write_community())
        writer = SnmpWriter(client, self.model, protected_ports=self.protected_ports)
    elif backend is Backend.NSDP:
        nsdp = self._nsdp_write_client
        if nsdp is None:
            nsdp = build_sync_nsdp_client(self.host, self._nsdp_interface)
        password = self._resolve_nsdp_password()
        if password is None:
            raise CredentialError(f"no NSDP admin password configured for {self.host!r}")
        writer = NsdpWriter(nsdp, self.model, password=password, protected_ports=self.protected_ports)
    elif backend is Backend.HTTP:
        if not http_reads_supported(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} HTTP writes are UNVERIFIED-pending-capture"
            )
        writer = HttpWriter(_LazyHttpSession(self._http_session), self.model, protected_ports=self.protected_ports)
    else:  # a CLI backend (SSH/telnet/console)
        raise UnsupportedCapabilityError(f"model {self.model.key!r} has no CLI write backend")
    self._writer_cache[backend] = writer
    return writer
```
Notable asymmetries vs `_reader_for`:
- NSDP's writer path DOES eagerly raise `CredentialError` if the NSDP
  password is unresolved (unlike the reader path, which needs no password
  at all — NSDP reads are unauthenticated). This is a genuine, NOT-lazy
  credential check at writer-construction time (contrast with HTTP/CLI,
  which defer to first wire use).
- The HTTP branch reuses `http_reads_supported` (not a separate
  `http_writes_supported`) — see §1.3.
- The CLI branch is UNCONDITIONAL `UnsupportedCapabilityError` — there is
  no CLI writer type in this slice at all (`SnmpWriter | NsdpWriter |
  HttpWriter` has no CLI member). This is a "slice adds CLI READS only"
  comment in the source, quoted: "This slice adds CLI READS only; there is
  no CLI writer yet, so any write dispatched to a CLI backend is honestly
  unsupported (SNMP remains the write path for every FASTPATH model)."

### 2.7 `_read(op)` — the dispatch loop (full method + exact skip/reraise semantics)

```python
def _read(self, op: Callable[[_AnyReader], _R]) -> _R:
    last: UnsupportedCapabilityError | None = None
    for backend in _BACKEND_PREFERENCE:
        if backend not in self.model.backends:
            continue
        try:
            reader = self._reader_for(backend)
        except UnsupportedCapabilityError as exc:
            last = exc
            continue
        try:
            return op(reader)
        except UnsupportedCapabilityError as exc:
            last = exc
    if last is not None:
        raise last
    raise UnsupportedCapabilityError(
        f"model {self.model.key!r} has no backend supporting this operation"
    )
```
Exact ordering rules (pin these precisely — this is the single most
important piece of dispatch logic in the whole facade):
1. Iterate `_BACKEND_PREFERENCE` = `(SNMP, NSDP, HTTP, SSH)` in that fixed
   order — never the model's own `backends` frozenset order (which is
   unordered in Python and MUST NOT be relied on for iteration order; the
   Go port's `[]Backend` slice per model likewise carries "no meaning" per
   its own doc comment — see `model/registry.go` line ~30).
2. `backend not in self.model.backends` → skip silently (not even a
   `continue`-with-tracking; it's just filtered out of the loop, no `last`
   update).
3. Reader/writer CONSTRUCTION raising `UnsupportedCapabilityError` → record
   as `last`, `continue` to next backend (do NOT retry the same backend).
4. The op call itself (`op(reader)`) raising `UnsupportedCapabilityError` →
   record as `last`, **fall through to the next loop iteration** (note:
   there's no explicit `continue` needed here — it's the last statement in
   the loop body, so it naturally proceeds).
5. Any OTHER exception type (notably `CredentialError`) is NEVER caught by
   either `try` — it propagates immediately, aborting the whole dispatch
   loop. This is explicit in the module comment: "A CredentialError (e.g. a
   missing NSDP write password) is NOT swallowed — it propagates."
6. If every applicable backend was exhausted (or none applied at all) and
   `last is not None`, re-raise `last` (the LAST — i.e. most preferred
   backend among those tried — error, not the first). If NO backend in
   `_BACKEND_PREFERENCE` was even present in `model.backends` (so `last`
   stayed `None`), raise a fresh generic `UnsupportedCapabilityError` naming
   the model (not any backend-specific message).

`_write(op)` (§2.6's companion, not separately quoted — structurally
identical to `_read` except it calls `op(writer); return` instead of
`return op(reader)`, since write ops return `None`).

### 2.8–2.9 Read methods (thin `_read` wrappers)

Every one of these is exactly `return self._read(lambda r: r.<method>())`,
so the ONLY per-method logic is which reader method name is invoked:

| SyncSwitch method | Reader method | Extra guard |
|---|---|---|
| `get_ports()` | `r.get_ports()` | none |
| `get_stats()` | `r.get_stats()` | none |
| `get_vlans()` | `r.get_vlans()` | none |
| `get_pvids()` | `r.get_pvids()` | none |
| `get_lldp()` | `r.get_lldp()` | none |
| `get_macs()` | `r.get_macs()` | `require_mac_table(self.model)` called FIRST, unconditionally, BEFORE `_read` — so a model with no MAC table (e.g. any Plus-class NSDP-only model) never even enters the dispatch loop; it raises directly from the guard. Pinned by `test_get_macs_on_plus_model_raises_no_mac_table` (§4). |
| `get_poe()` | `r.get_poe()` | none (per-backend readers each guard 0-PSE internally — see snmp `reader.go`'s `GetPoe`) |
| `get_sensors()` | `r.get_sensors()` | none |
| `get_mgmt_ip()` | `r.get_mgmt_ip()` | none |

### 2.10 `nsdp_device()` — deliberate bypass #1 (full method + rationale)

```python
def nsdp_device(self) -> NsdpDevice:
    reader = self._reader_for(Backend.NSDP)
    assert isinstance(reader, NsdpReader)
    return reader.get_device()
```
Docstring: returns the COMPLETE raw `NsdpDevice` — model, MAC, hostname,
mgmt IP, firmware, DHCP mode, port count, serial number, VLAN engine, raw
per-port status (speed byte NOT pre-converted to Mbps) and statistics, VLAN
membership, PVIDs, plus QoS engine/mirroring/IGMP snooping/broadcast
filtering/loop detection. "Unlike every other read op, this deliberately
bypasses the SNMP/NSDP/HTTP backend-preference dispatch (`_read`): NSDP is
the ONLY backend that can serve it, so a model without an NSDP backend
raises `UnsupportedCapabilityError` directly (mirroring `identify()`'s
bypass of that dispatch below, and `NsdpReader.__init__`'s own
`_require_nsdp` guard)." A model with no NSDP backend raises from
`_reader_for(Backend.NSDP)`'s own construction path (falls into whichever
branch `NsdpReader.__init__` gates on — this slice's Go port has no
`NsdpReader` yet; the Go seam must still expose an `nsdp_device`-shaped hook
that raises `ErrUnsupportedCapability` honestly until slice 05).

### 2.11 `identify()` — deliberate bypass #2 (full method + rationale)

```python
def identify(self) -> DetectedModel:
    client = self._snmp_client
    if client is None:
        client = build_sync_snmp_client(self.host, self._snmp_community)
    return read_system_info(client)
```
Docstring: "Detect this switch's ACTUAL model via SNMP sysDescr,
independent of `self.model`. Unlike every other read/write op, this
deliberately bypasses the per-op SNMP/NSDP/HTTP backend-preference dispatch
(`_read`) AND the `self.model` SNMP-backend gate entirely: it exists
precisely to confirm/discover a switch's real model when the caller does
not yet trust the model this facade happens to have been constructed with
... Reuses an injected `snmp_client`/`snmp_community` exactly like
`_reader_for(Backend.SNMP)` would, but never requires `self.model.backends`
to include SNMP." Pinned by
`test_sync_switch_identify_bypasses_model_snmp_gate` (constructs against
`gs110emx`, which has NO SNMP backend at all, and still succeeds) and
`test_sync_switch_identify_reflects_device_not_bound_model` (facade bound
to `gsm7252ps`, device reports `GS110EMX` sysDescr — `identify()` returns
`gs110emx`, proving it reflects the DEVICE, never `self.model`).

**Note the important asymmetry vs `_reader_for(SNMP)`**: `identify()` does
NOT go through `_reader_cache` at all — every call rebuilds (or reuses the
injected) client fresh; there is no reader object built or cached here,
just a bare client + a call to the free function `read_system_info`.

### 2.12 `snapshot() -> SwitchData` — degrade-to-empty semantics (full method)

```python
def snapshot(self) -> SwitchData:
    def _opt(op) -> tuple[Any, ...]:
        try:
            return tuple(self._read(op))
        except UnsupportedCapabilityError:
            return ()
    try:
        mgmt: MgmtIpConfig | None = self._read(lambda r: r.get_mgmt_ip())
    except UnsupportedCapabilityError:
        mgmt = None
    return SwitchData(
        model=self.model.key, host=self.host,
        ports=_opt(lambda r: r.get_ports()),
        stats=_opt(lambda r: r.get_stats()),
        vlans=_opt(lambda r: r.get_vlans()),
        pvids=_opt(lambda r: r.get_pvids()),
        mgmt_ip=mgmt,
        poe=_opt(lambda r: r.get_poe()),
        lldp=_opt(lambda r: r.get_lldp()),
        sensors=_opt(lambda r: r.get_sensors()),
        macs=_opt(lambda r: r.get_macs()),
    )
```
**Exact per-field swallow/propagate rule**: EVERY field goes through `_opt`
(which calls the full `_read` dispatch loop internally, so per-op backend
fallback still applies) EXCEPT `mgmt_ip`, which uses its own inline
try/except with the same catch type but assigns `None` on failure instead
of `()` (`mgmt_ip` is `MgmtIpConfig | None`, not a tuple, so it can't reuse
`_opt`'s tuple-returning shape). **Every field catches ONLY
`UnsupportedCapabilityError`** — nothing else is swallowed:
`CredentialError` from a misconfigured secret still propagates out of
`snapshot()` uncaught (this matters for e.g. a model whose write-community
resolver fails — though `snapshot()` never triggers write dispatch, only
read, so in practice this would only surface via an NSDP
read-path-adjacent... actually NSDP reads need no password, so this is
purely theoretical for reads today, but the rule stands: `snapshot()`
degrades ONLY for capability gaps, never for credential failures).
`macs=_opt(lambda r: r.get_macs())` notably does NOT call
`require_mac_table` first (unlike `get_macs()` itself, §2.9) — it just lets
`_read` naturally exhaust to `UnsupportedCapabilityError` and degrade to
`()`, since `SnmpReader`/`NsdpReader`/`HttpReader` all raise for a MAC-table
gap the same way `_read`'s catch already handles generically. No field is
special-cased beyond "does the reader raise `UnsupportedCapabilityError`
for it".

Pinned exactly by `test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections`
(§4): on `gs305ep` (NSDP+HTTP only), `macs`/`lldp`/`sensors` degrade to `()`
(neither backend serves them), `poe` populates via HTTP (NSDP gap, HTTP
fills it), `ports` populates via NSDP.

### 2.13 `_resolve_write_community()` / `_resolve_nsdp_password()` /
`_resolve_http_password()` — the once-only resolution pattern (3 near-identical methods)

```python
def _resolve_write_community(self) -> str | None:
    if not isinstance(self._resolved_write_community, _Unset):
        return self._resolved_write_community
    resolved: str | None
    if self._snmp_write_community is not None:
        resolved = self._snmp_write_community
    elif self._snmp_write_community_resolver is not None:
        resolved = self._snmp_write_community_resolver()
    else:
        resolved = None
    self._resolved_write_community = resolved
    return resolved
```
`_resolve_nsdp_password` and `_resolve_http_password` are the SAME
structure with different field names (`_nsdp_password`/
`_nsdp_password_resolver`/`_resolved_nsdp_password`, and
`_http_password`/`_http_password_resolver`/`_resolved_http_password`
respectively). **Precedence, identical in all 3**: (1) explicit value wins
outright — the resolver closure is NEVER even consulted if an explicit
value was passed to `__init__`; (2) else the resolver closure runs — exactly
ONCE, ever, for the lifetime of the `SyncSwitch` instance, its result (which
may itself be `None`) is cached in `self._resolved_*`; (3) if neither is
set, resolves to `None` (and THAT `None` is also cached — so a second call
does not re-check "is there now a value", it just returns the cached `None`
forever). Comment (write-community version, applies verbatim to all 3):
"Resolved once on first write, then cached: an explicit community wins,
else the stashed from_config resolver runs now (may raise), else None.
Every subsequent write reuses the cached result instead of re-invoking the
resolver (e.g. a `!command` spec must not re-exec its subprocess on every
single write)." **A resolver that RAISES (e.g. `CredentialError` from an
unresolvable `${ENV_VAR}` spec) is NOT caught here** — it propagates on
first invocation. Note this means a raising resolver is NOT cached as
"resolved to an exception" — `self._resolved_write_community` stays `_UNSET`
after a raising call, so a SECOND write attempt would re-invoke the resolver
and potentially raise again (not idempotent in the error path — only the
success path is cached-once). This is implicit in the code (the assignment
`self._resolved_write_community = resolved` never executes if
`self._snmp_write_community_resolver()` raises) and is NOT directly
pinned by a test in this slice, but is a natural consequence of exception
semantics the Go port must replicate faithfully (a Go implementation must
NOT mark "resolved" before calling the resolver — only after it returns
successfully).

### 2.14 `_http_session()` (the actual HTTP laziness point, full method)

```python
def _http_session(self) -> HttpSession:
    if self._http_client is not None:
        return self._http_client
    if self._built_http_client is None:
        self._built_http_client = build_sync_http_client(
            self.host, self._resolve_http_password(), self.model
        )
    return self._built_http_client
```
Precedence: an INJECTED `http_client` (constructor arg) always wins and is
NEVER torn down by `close()` (see §2.15) — `_built_http_client` stays `None`
forever in that case. Otherwise, build once (memoized on
`_built_http_client is None`), resolving the password via
`_resolve_http_password()` (§2.13) — which is where a `CredentialError` for
an unset HTTP password would surface, ONLY at first actual wire use (since
`_http_session` is only ever called from inside `_LazyHttpSession`'s
methods, §2.3).

### 2.15 `close()` / context manager (full semantics)

```python
def __enter__(self) -> Self: return self
def __exit__(self, exc_type, exc, tb) -> None: self.close()
def close(self) -> None:
    if self._built_http_client is not None:
        self._built_http_client.close()
        self._built_http_client = None
```
"Release the HTTP client THIS facade built (never one injected by the
caller). Safe to call even when no HTTP op was ever dispatched." HTTP is
called out as "the ONLY backend that holds a persistent connection worth
closing (SNMP/NSDP clients are built fresh per call and need no equivalent
teardown)." SNMP/NSDP clients (injected or built) are NEVER closed by
`close()` — there is no `_snmp_client.close()` or `_nsdp_client.close()`
call anywhere in this method. CLI sessions are ALSO not closed by
`SyncSwitch.close()` — only `upload_certificate_scp`'s own `finally` block
(§2.17) tears down a self-built CLI session; a `_LazyCliSession` built via
`_reader_for(SSH)` is never closed by `SyncSwitch.close()` at all (a latent
asymmetry in the Python reference; port it as-is — do not "fix" it in Go
without a deliberate, separately-flagged decision, since fixing it would be
a behavior change beyond a straight port). Pinned by
`test_http_client_closed_after_http_routed_op` (self-built client closed on
`__exit__`, not before) and `test_injected_http_client_is_never_closed_by_facade`
(injected client's `close()` must never even be called — asserted via a
`close()` that raises `AssertionError` if invoked).

### 2.16 `from_config(cfg, *, env=None) -> SyncSwitch` (classmethod, full method + field mapping)

```python
@classmethod
def from_config(cls, cfg: SwitchConfig, *, env=None) -> SyncSwitch:
    _env = env if env is not None else os.environ
    def _resolve_write_community(): return cfg.snmp_write_community(env=_env)
    def _resolve_nsdp_password(): return cfg.http_password(env=_env)  # NOTE: reuses http_password!
    def _resolve_http_password(): return cfg.http_password(env=_env)
    return cls(
        cfg.model, cfg.host,
        snmp_community=cfg.snmp_community,
        snmp_write_community_resolver=_resolve_write_community,
        nsdp_interface=cfg.nsdp_interface,
        nsdp_password_resolver=_resolve_nsdp_password,
        http_password_resolver=_resolve_http_password,
        protected_ports=cfg.protected_ports,
    )
```
Field-by-field `SwitchConfig` → `SyncSwitch.__init__` mapping:

| `SwitchConfig` field | `SyncSwitch` param | Notes |
|---|---|---|
| `cfg.model` | positional `model` | |
| `cfg.host` | positional `host` | |
| `cfg.snmp_community` | `snmp_community=` | passed as literal value, not a resolver (SNMP read community needs no secret-spec resolution — it's just a plain string already) |
| — | `snmp_write_community_resolver=` | a CLOSURE calling `cfg.snmp_write_community(env=_env)`, i.e. `resolve_secret(cfg.snmp_write_community_spec, env=_env)` — LAZY, not called at `from_config` time |
| `cfg.nsdp_interface` | `nsdp_interface=` | literal, not resolved (interface name is not a secret) |
| — | `nsdp_password_resolver=` | closure calling `cfg.http_password(env=_env)` — **reuses the HTTP password spec**, NOT a distinct `nsdp.password` config key. Comment: "Plus switches share ONE web-admin password across HTTP + NSDP, so reusing the http_password spec as the NSDP v1 auth password is intentional and correct. A dedicated `nsdp.password` config key is a trivial future follow-up ... if a deployment ever needs to split them; do NOT add a separate key now." |
| — | `http_password_resolver=` | closure calling `cfg.http_password(env=_env)` |
| `cfg.protected_ports` | `protected_ports=` | literal `frozenset[int]`, passed straight through |

**Nothing is resolved at `from_config` time** — every secret spec is
deferred to first write/session-use via the resolver closures. This is the
"review item 4" fix referenced throughout: "A read-only consumer whose env
lacks a resolvable write-community spec (e.g. `${UNSET_VAR}`) must still be
able to construct the facade and read; only an actual write attempt may
raise CredentialError/ConfigError." Pinned by
`test_from_config_builds_facade_without_touching_network`,
`test_from_config_write_community_resolves_lazily_not_at_construction`,
`test_http_password_resolved_lazily` (§4).

### 2.17 Write methods — one-line semantics list (full semantics is slice-04 scope)

All nine share the `_write(lambda w: w.<op>(...))` dispatch shape (via
`_BACKEND_PREFERENCE`, §2.7's `_write` companion). Listed here ONLY for the
shared plumbing (protected-ports/force) they carry through the dispatch
layer — implementation semantics belong to slice 04's snmp-write dossier.

| Method | Signature | One-line semantics |
|---|---|---|
| `set_poe(port, on, *, force=False)` | write | Enable/disable PoE delivery on one port. |
| `set_port_enabled(port, enabled, *, force=False)` | write | Admin up/down one port. |
| `set_pvid(port, vlan, *, force=False)` | write | Set a port's default/untagged VLAN. |
| `set_vlan_membership(vlan, port, mode, *, force=False)` | write | Add/remove one port from one VLAN (untagged/tagged/excluded). |
| `create_vlan(vlan, name, *, force=False)` | write | Create a new VLAN entry. |
| `delete_vlan(vlan, *, force=False)` | write | Delete a VLAN — see facade-level guard below, NOT delegated purely to `_write`. |
| `cycle_poe(port, *, force=False, timeouts=...)` | write | Power-cycle a PoE port (off/wait/on). |
| `clear_poe_fault(port, *, force=False, timeouts=...)` | write | Clear a PoE fault by cycling. |
| `set_mgmt_ip(address, netmask, gateway, *, force=False)` | write | Change the switch's own mgmt IP config. |

**`delete_vlan`'s facade-level protected-port guard is dispatch-layer
plumbing, not write-backend-specific, so it belongs in this dossier in
full**:
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
                    f"pass force=True to delete it anyway"
                )
            return
```
Rationale (verbatim, load-bearing): "SAFETY RAIL: HttpWriter.delete_vlan
does NOT itself guard protected member ports (only its per-port ops carry
an internal `_guard`; its own docstring defers VLAN-delete disruptiveness to
be 'guarded per-member elsewhere'). NsdpWriter.delete_vlan ALWAYS raises
UnsupportedCapabilityError (NSDP has no VLAN lifecycle ops at all), so on
any {NSDP, HTTP} model delete_vlan falls straight through to HTTP — meaning
nothing would otherwise stand between force=False and stripping a protected
port's VLAN membership. Guard here, mirroring SnmpWriter.delete_vlan's own
protected-port check, so EVERY backend gets the same safety rail regardless
of which one actually ends up serving the delete." **This guard runs a full
`_read` dispatch (through the SAME backend-preference machinery) BEFORE any
write is attempted**, and — critically — it degrades silently (`return`,
not raise) if NO backend can even serve `get_vlans()` (`except
UnsupportedCapabilityError: return`), i.e. an inability to read VLANs is NOT
treated as a reason to block the delete. Pinned by
`test_delete_vlan_guards_protected_member_before_http_fallback`: an NSDP+HTTP
model where NSDP's `write` raises `AssertionError` if EVER called and HTTP's
session raises `AssertionError` on `login`/`get_page`/`post_form` — proving
the guard fires BEFORE any backend write is even attempted, purely from the
prior read.

`upload_certificate(cert_pem, key_pem, *, force=False)` and
`upload_certificate_scp(...)` (§2.16's neighbors, HTTP-multipart and
FASTPATH-SCP cert deploy respectively) are OUT OF `_BACKEND_PREFERENCE`
dispatch entirely — both bypass `_write`/`_writer_for` (see their own
docstrings, quoted in the source, for `_cert_writer()`'s deliberate bypass
of `http_reads_supported` and `_write`'s SNMP-first ordering). These are
firmware/cert-lifecycle ops, not switch-config writes, and are explicitly
slice-06/07 scope; noted here only so the Go seam's registry doesn't
accidentally try to route them through the generic per-op backend loop.

---

## 2b. `AsyncSwitch` (`aio_api.py`) — delta from `SyncSwitch` (Go has NO async twin)

The Go port has a single ctx-based `Switch`; there is no async facade to
port. This section exists ONLY to flag semantics that DIFFER between the
two Python facades, so the Go single-facade design doesn't accidentally
inherit an async-only restriction (or accidentally DROP one that matters).

1. **CLI reads are UNCONDITIONALLY unavailable on `AsyncSwitch`** — its
   `_reader_for`'s CLI branch is not gated by `cli_reads_supported` at all;
   it ALWAYS raises:
   ```python
   raise UnsupportedCapabilityError(
       f"model {self.model.key!r} CLI reads are not available via the "
       "async facade (CLI is synchronous + UNVERIFIED-pending cross-verify)"
   )
   ```
   This is because the CLI transports (paramiko/telnetlib/pyserial) are
   synchronous with no async twin in Python — a Go-specific non-issue
   (Go's `net`/`ssh` packages are goroutine-safe and don't need a
   sync/async split), so **the Go `Switch`'s CLI dispatch should follow
   `SyncSwitch`'s gated-by-`cli_reads_supported` behavior, NOT
   `AsyncSwitch`'s unconditional-raise behavior**. Do not let "Go only has
   one facade" become an excuse to import the async restriction.
2. **`AsyncSwitch` has no CLI writer either** (same as sync — no delta).
3. **`upload_certificate_scp` ALWAYS raises on `AsyncSwitch`**, unconditionally,
   for the same "CLI is synchronous" reason:
   ```python
   raise UnsupportedCapabilityError(
       f"model {self.model.key!r}: upload_certificate_scp is CLI/SCP-based "
       "and the async facade has no CLI backend (CLI is synchronous) -- "
       "use SyncSwitch.upload_certificate_scp"
   )
   ```
   Again, Go-specific note: since Go's `Switch` is the ONLY facade (no
   sync/async split), it should behave like `SyncSwitch.upload_certificate_scp`
   (real FASTPATH-SCP dispatch, slice 07 scope), never like
   `AsyncSwitch`'s hard-coded raise.
4. Everything else is a mechanical `async`/`await` transliteration of the
   exact same logic: `_Unset`/`_UNSET` sentinel pattern, `_BACKEND_PREFERENCE`
   tuple, `_read`/`_write` skip-and-reraise-last loop, `_resolve_write_community`/
   `_resolve_nsdp_password`/`_resolve_http_password` once-only caching,
   `from_config`'s lazy-resolver closures, `snapshot()`'s per-field
   degrade-to-empty via the same `_opt`/`mgmt_ip` special case, `nsdp_device()`/
   `identify()`'s dispatch bypasses, `delete_vlan`'s protected-port guard.
   **None of these differ between sync and async** — the Go single facade
   ports ALL of them from `SyncSwitch` with zero semantic changes.
5. `AsyncSwitch.__aenter__`/`__aexit__`/`aclose()` mirror
   `SyncSwitch.__enter__`/`__exit__`/`close()` exactly (only the HTTP client
   is torn down; injected clients are never closed). Go's `Switch` should
   expose a plain `Close() error` (no separate async variant needed).

---

## 3. Reachability in slice 03's Go port + the backend-registry seam design

### 3.1 What's reachable today

Only `model.BackendSNMP` has a real Go backend (`snmp.Reader`,
`snmp.NewGoSNMPClient`, `snmp.ReadSystemInfo` — see §5 for exact
signatures). `model.BackendNSDP`/`BackendHTTP`/`BackendSSH`/`BackendTelnet`
have NO Go implementation yet (slices 05/06/07). Per the roadmap
(`docs/superpowers/plans/2026-07-30-roadmap.md`), slice 3 delivers "root
`Switch`, dispatch, `DetectModel`, `Snapshot`" — this dossier's facade must
work TODAY for every SNMP-only model (`gsm7252ps`, `m4300-24x`, `m4300-16x`,
`gsm7228ps`, `m7300`, `xs748t`, `gs728tpp`) and must degrade HONESTLY
(typed `ErrUnsupportedCapability`, never a panic, never a silently-empty
result masquerading as success) for every model whose registered
`Backends` includes NSDP/HTTP/SSH/Telnet with no Go implementation to serve
it (`gs110emx`, `gs305ep`, `gs105pe` — all `{NSDP, HTTP}`-only, meaning
`Switch.GetPorts()` etc. on these models must return
`ErrUnsupportedCapability` in slice 03, becoming real once slice 05 lands).

### 3.2 Why a registry/hook seam, not a `switch` statement, in `_readerFor`

A literal Go port of `_reader_for`'s `if backend is Backend.SNMP: ... elif
... NSDP ... elif ... HTTP ... else: # CLI` would hard-code exactly 4
branches inline in the facade file, meaning slices 05/06/07 would each need
to edit `switch.go` (or whatever the facade file is named) to add their
branch — directly contradicting the Python module docstring's stated
intent ("Model-driven dispatch lives here so the two facades stay identical
and Slices 5/6 can add NSDP/HTTP backends without touching the public
facade surface"). Go has no import-cycle-safe way to have `snmp`/`nsdp`/
`webui`/`fastpath` packages register themselves into a facade package
without EITHER (a) the facade importing all of them directly (defeating
"transport imports are function-local" — Python's function-local lazy
import equivalent doesn't exist in Go's static-import model), or (b) a
registry/hook seam the facade owns and each backend package populates via
`init()` or an explicit `Register` call from the CALLER (e.g. `cmd/ngsw`'s
`main()`), never from inside the root `netgearswitch` package itself.

**Recommended concrete minimal seam:**

```go
// package netgearswitch

// BackendReaderBuilder constructs a reader for one backend, given a ctx,
// the switch's host, its resolved model, and whatever per-backend
// credential/session material the Switch already resolved (community,
// password, injected client, etc.) via a narrow options struct — NOT the
// whole Switch (keeps backend packages decoupled from the facade type).
type BackendReaderBuilder func(ctx context.Context, host string, m *model.SwitchModel, opts BackendOptions) (Reader, error)

// BackendWriterBuilder mirrors BackendReaderBuilder for writes.
type BackendWriterBuilder func(ctx context.Context, host string, m *model.SwitchModel, opts BackendOptions) (Writer, error)

// Reader is the minimal per-backend reader contract every registered
// backend must satisfy -- mirrors the union of ops _AnyReader's Python
// readers share. A concrete backend reader (snmp.Reader today; nsdp.Reader/
// webui.Reader/fastpath.Reader in slices 05-07) is adapted to this
// interface by a thin per-package shim, so THIS package never imports
// snmp/nsdp/webui/fastpath directly -- registration flows the other way.
type Reader interface {
    GetPorts(ctx context.Context) ([]model.PortStatus, error)
    GetStats(ctx context.Context) ([]model.PortStats, error)
    GetVlans(ctx context.Context) ([]model.VLANInfo, error)
    GetPvids(ctx context.Context) ([]model.Pvid, error)
    GetLldp(ctx context.Context) ([]model.LLDPNeighbor, error)
    GetMacs(ctx context.Context) ([]model.MacEntry, error)
    GetPoe(ctx context.Context) ([]model.PoEStatus, error)
    GetSensors(ctx context.Context) ([]model.Sensor, error)
    GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error)
}

// RegisterBackend installs builder(s) for backend, called from an
// importing program's init()/main() (e.g. cmd/ngsw, or a build-tag'd file
// inside THIS package once slice 05/06/07 land and want the backend
// always available) -- never from inside a backend package's own init()
// implicitly, to keep "which backends are compiled in" an explicit,
// grep-able decision matching Python's lazy-import-per-call-site honesty
// (`import netgear_switch` never requires net-snmp binaries or pysnmp).
func RegisterBackend(b model.Backend, reader BackendReaderBuilder, writer BackendWriterBuilder) {
    backendRegistry[b] = backendEntry{reader: reader, writer: writer}
}
```

`Switch.readerFor(ctx, backend)` becomes a registry lookup + cache (mirrors
`_reader_cache`) instead of a hard-coded `switch`:
```go
func (s *Switch) readerFor(ctx context.Context, backend model.Backend) (Reader, error) {
    if r, ok := s.readerCache[backend]; ok {
        return r, nil
    }
    entry, ok := backendRegistry[backend]
    if !ok || entry.reader == nil {
        return nil, fmt.Errorf("model %q has no %s backend implementation yet: %w", s.model.Key, backend, model.ErrUnsupportedCapability)
    }
    r, err := entry.reader(ctx, s.host, s.model, s.backendOptions(backend))
    if err != nil {
        return nil, err // UnsupportedCapabilityError-equivalent from the gate (http_reads_supported etc.) propagates as-is
    }
    s.readerCache[backend] = r
    return r, nil
}
```
For slice 03, `RegisterBackend(model.BackendSNMP, snmpReaderBuilder,
snmpWriterBuilder)` is called from THIS package's own `init()` (SNMP is
always compiled in — it has no external-binary dependency the way
Python's net-snmp-CLI transport does; `snmp.NewGoSNMPClient` is pure Go via
`gosnmp`), so no caller wiring is needed for SNMP specifically. NSDP/HTTP/
SSH/Telnet stay unregistered until slices 05/06/07 add their own
`init()`-time (or explicit) `RegisterBackend` call in THEIR OWN package,
imported by `cmd/ngsw`'s `main.go` (a blank `_` import, Go's standard
plugin-registration idiom) — meaning `Switch`'s dispatch loop over
`_BACKEND_PREFERENCE`-equivalent (`snmp, nsdp, http, ssh` in that Go-const
order) naturally treats an unregistered backend exactly like Python's
"backend not implemented" case: `readerFor` returns
`model.ErrUnsupportedCapability`-wrapped, `_read`'s loop records it as
`last` and continues, exactly mirroring §2.7 rule 3. **This is the key
property the seam must deliver**: slices 05-07 add exactly one
`RegisterBackend` call (plus their reader/writer adapter type) and ZERO
edits to the facade file itself — satisfying the Python module docstring's
stated goal precisely.

`BackendOptions` (per-backend resolved credential/injection bag, mirroring
each of `_snmp_client`/`_snmp_community`/`_nsdp_client`/`_nsdp_interface`/
`_http_client`/`_cli_client` etc.) is deliberately a plain struct with
pointer/interface fields (nil = "not injected, build the default"), not an
interface — it's data, not behavior, exactly mirroring how Python passes
`self._snmp_client`, `self._snmp_community` etc. as plain constructor
kwargs today.

### 3.3 What must NOT change once slices 05-07 land

- The `_BACKEND_PREFERENCE`-equivalent fixed order (`SNMP, NSDP, HTTP,
  SSH`) — a Go `[4]model.Backend` array constant, never derived from
  `model.SwitchModel.Backends`' slice order (which the registry doc
  explicitly says carries no meaning).
- The skip-and-reraise-last semantics of §2.7 (rules 1-6) — implement
  ONCE in the generic `read`/`write` dispatch loop, never duplicated
  per-backend.
- `CredentialError`-equivalent (`model.ErrCredential`) must propagate
  UNCAUGHT through the dispatch loop — the loop's `try/except` (Go: a type
  assertion / `errors.Is` check) must test SPECIFICALLY for
  `model.ErrUnsupportedCapability`, never a bare "any error" catch, or a Go
  port would silently swallow a credential failure exactly like the trap
  this dossier's read-side test suite (§4) exists to prevent.

---

## 4. Tests — every test intent relevant to read-dispatch/facade construction/snapshot/detect

### 4.1 `tests/test_sync_api.py` (facade unit tests, FakeClient-based)

| Test | Intent |
|---|---|
| `test_get_ports_delegates_to_injected_client` | Basic happy path: injected SNMP client is used as-is, no default builder invoked. |
| `test_plus_model_read_routes_to_nsdp` | `gs305ep` ({NSDP,HTTP}) routes `get_ports()` to the injected NSDP client. |
| `test_get_macs_on_plus_model_raises_no_mac_table` | `require_mac_table` guard fires BEFORE dispatch on a Plus model; error text contains "mac"/"MAC". |
| `test_non_poe_m4300_get_poe_raises_unsupported_not_credential` | Regression: a 0-PoE model with ONLY an SNMP community (no HTTP/CLI password) must raise `UnsupportedCapabilityError`, NEVER `CredentialError`, from the SSH fall-through — proves lazy CLI session construction never demands a credential for an op it would refuse anyway. |
| `test_lazy_cli_session_defers_build_until_first_command` | `_LazyCliSession`: construction + `close()` before any command builds nothing; first `run()` builds once; subsequent calls reuse; `close()` after use tears down. |
| `test_from_config_builds_facade_without_touching_network` | `from_config` never touches the network at construction. |
| `test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections` | `snapshot()` on gs305ep: macs/lldp/sensors → `()`; poe (NSDP gap, HTTP fills) → populated; ports → populated via NSDP. |
| `test_reader_builds_default_client_when_not_injected` | No injected client → `build_sync_snmp_client(host, community)` is called exactly once with the right args. |
| `test_sync_switch_set_port_enabled_delegates_to_writer` | Write delegates to injected write client (slice-04-adjacent, dispatch-layer proof). |
| `test_sync_switch_write_methods_delegate_to_writer` | All 9 write methods round-trip through the injected write client (slice-04-adjacent). |
| `test_plus_model_write_raises_unsupported_capability` | NSDP write refuses (client never touched) → falls to HTTP → HTTP ALSO refuses (never resolves a password) → the LAST error (HTTP's) is what the caller sees; error text contains "port-enable". |
| `test_from_config_write_community_resolves_lazily_not_at_construction` | Unresolvable write-community spec: construction succeeds, reads work, FIRST write raises `CredentialError`. |
| `test_from_config_write_community_resolves_and_writes_when_set` | Resolvable spec flows through to the write-client builder lazily on first write. |
| `test_write_community_resolver_invoked_at_most_once_across_writes` | Resolver invoked exactly once across TWO writes (the once-only caching contract, §2.13). |
| `test_resolve_write_community_explicit_value_wins_over_resolver` | Explicit value used as-is; resolver never even called. |
| `test_resolve_write_community_defaults_to_none_without_community_or_resolver` | Neither set → build called with `community=None`. |
| `test_sync_switch_plus_model_reads_over_nsdp` | gs110emx ports read via NSDP; `get_macs()` still raises (Plus = no MAC table) even with NSDP wired. |
| `test_sync_switch_plus_set_pvid_over_nsdp` | NSDP write round-trip (slice-04-adjacent). |
| `test_gs305ep_poe_routes_to_http_ports_stay_nsdp` | Per-op three-way routing: NSDP raises for `get_poe()` (client never touched — proven via a bare `object()` NSDP client stand-in), HTTP serves it. |
| `test_gsm7228ps_http_gated_off_for_read_and_write` | gsm7228ps's `http_reads_supported` is False → BOTH `_reader_for(HTTP)` and `_writer_for(HTTP)` raise directly. |
| `test_http_password_resolved_lazily` | Unresolvable HTTP password spec: `from_config` construction does NOT raise. |
| `test_http_client_closed_after_http_routed_op` | Self-built HTTP client: not closed while `with` block active; closed exactly on `__exit__`. |
| `test_injected_http_client_is_never_closed_by_facade` | Injected HTTP client's `close()` is NEVER called by the facade (asserted via a `close()` that raises if invoked). |
| `test_detect_model_module_function_matches_registered_model` | `detect_model()` free function matches a known sysDescr. |
| `test_detect_model_module_function_unregistered_model_is_none` | Unregistered sysDescr → `key=None`, `matched=False`, but `sys_descr`/`sys_object_id` still carried. |
| `test_detect_model_builds_default_client_when_not_injected` | No injected client → default builder called with exact `(host, community)`. |
| `test_sync_switch_identify_bypasses_model_snmp_gate` | `identify()` works on a facade bound to an SNMP-less model (gs110emx). |
| `test_sync_switch_identify_reflects_device_not_bound_model` | `identify()` reflects the DEVICE's sysDescr, not `self.model`. |
| `test_delete_vlan_guards_protected_member_before_http_fallback` | Facade-level `ProtectedPortError` fires BEFORE any backend write is attempted (NSDP write / HTTP session both instrumented to assert-fail if touched). |

### 4.2 `tests/test_facade_equivalence.py` + `tests/equivalence.py` (live-mock sync/async parity harness — structure only; not directly portable since Go has no async twin, but documents WHICH invariants the Go conformance/virtual-mock tests should assert instead)

- `facades_for(sw)` / `http_facades_for(sw)`: build both `SyncSwitch` and
  `AsyncSwitch` wired to the SAME running `VirtualSwitch`, injecting the
  read+write client (one client instance serves both directions).
- `assert_facades_equivalent` / `assert_m4300_facades_equivalent` /
  `assert_nsdp_facades_equivalent` / `assert_http_facades_equivalent`: for
  each model class, assert (a) non-empty results (guards against a vacuous
  `[] == []` pass), (b) content pinned against known capture-grounded seed
  values (`EquivalencePins`/`M4300Pins`/`HttpEquivalencePins` dataclasses),
  (c) sync result == async result byte-for-byte for every read op AND for
  `snapshot()`, (d) ops a backend genuinely lacks raise
  `UnsupportedCapabilityError` on BOTH facades identically (never `[]` on
  one and raise on the other — e.g. m4300-24x's `get_poe()` on 0 PSE
  ports). **Go-port equivalent**: since there's only one facade, the
  parity check collapses to "the Go `Switch` against the Go
  `VirtualSwitch` matches the SAME pinned content values" — no
  sync-vs-async comparison needed, but the non-empty + content-pin +
  honest-raise assertions all still apply directly.
- `assert_write_equivalent` / `assert_http_write_equivalent`: apply the
  same write via each facade against a FRESH mock instance each, then
  assert both post-write snapshots are identical and the write took effect
  (slice-04 concern, listed for completeness of the harness shape).

### 4.3 `tests/test_public_api.py`

| Test | Intent |
|---|---|
| `test_public_types_importable_from_top_level` | Every name in `netgear_switch.__all__` is a real top-level attribute (spot-checked: `get_model("gsm7252ps").has_mac_table is True`, `PoEDetect.DELIVERING.value == "delivering"`). Go analogue: every aliased type in `alias.go` must resolve and be usable without importing `model` directly — already satisfied by the existing `alias.go`. |
| `test_facades_exported_from_top_level` | Both `SyncSwitch`/`AsyncSwitch` are exported AND constructible from just a model + host without touching the network. Go analogue: `netgearswitch.NewSwitch(model, host, ...)` (or equivalent constructor) must be network-silent at construction, exactly mirroring `SyncSwitch.__init__`'s "no I/O" contract. |

### 4.4 `tests/cli/test_op_coverage.py`

Coverage GUARD, not facade-semantics: every non-underscore, non-lifecycle
`SyncSwitch` method must have an entry in `_OP_TO_COMMAND` (mapping to a
`ngsw` CLI subcommand), and every mapped command must actually be
registered on the CLI parser. This is a CLI-completeness forcing function,
not something slice 03's Go facade itself needs to satisfy — but it
DOCUMENTS the full canonical list of "public switch operations" the facade
exposes, useful as a completeness cross-check for the Go `Switch`'s public
method surface:
```
get_ports, get_stats, get_vlans, get_pvids, get_lldp, get_macs, get_sensors,
get_poe, get_mgmt_ip, snapshot, identify, nsdp_device,
set_poe, set_port_enabled, set_pvid, set_vlan_membership, create_vlan,
delete_vlan, cycle_poe, clear_poe_fault, set_mgmt_ip,
upload_certificate, upload_certificate_scp
```
(`login`/`get_page`/`post_form`/`close`/`from_config` are explicitly
excluded — connection lifecycle/construction helpers, not switch ops.)

---

## 5. Go repo reference signatures (read directly from this repo, quoted exactly)

### 5.1 `snmp/reader.go`

```go
func ReadSystemInfo(ctx context.Context, c Client) (model.DetectedModel, error)

type Reader struct { /* unexported client, model fields */ }

func NewReader(c Client, m *model.SwitchModel) (*Reader, error)

func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error)
func (r *Reader) GetStats(ctx context.Context) ([]model.PortStats, error)
func (r *Reader) GetVlans(ctx context.Context) ([]model.VLANInfo, error)
func (r *Reader) GetPvids(ctx context.Context) ([]model.Pvid, error)
func (r *Reader) GetLldp(ctx context.Context) ([]model.LLDPNeighbor, error)
func (r *Reader) GetMacs(ctx context.Context) ([]model.MacEntry, error)
func (r *Reader) GetPoe(ctx context.Context) ([]model.PoEStatus, error)
func (r *Reader) GetSensors(ctx context.Context) ([]model.Sensor, error)
func (r *Reader) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error)
func (r *Reader) GetSystemInfo(ctx context.Context) (model.DetectedModel, error)
```
`NewReader` returns an error wrapping `model.ErrUnsupportedCapability`
BEFORE any I/O if `m` has no `model.BackendSNMP` — this IS the Go
equivalent of Python's `_require_snmp`-style construction gate baked
directly into the constructor (unlike Python's `SnmpReader`, which is
presumably gated the same way inside its own `__init__` — not read in this
dossier's scope, but the Go `Reader` docstring states it explicitly: "m
must have an SNMP backend ... a model without one ... returns an error
wrapping model.ErrUnsupportedCapability BEFORE any I/O -- this is the
single capability gate for the whole reader; no method below re-checks
it."). This is exactly the shape the facade's SNMP `BackendReaderBuilder`
(§3.2) should call: `snmp.NewReader(client, model)`, and if it errors, the
error already wraps `model.ErrUnsupportedCapability` and needs no further
wrapping by the facade.

`GetPoe` and `GetSensors` embed their OWN capability gates (0-PSE guard;
"claims a vendor sensor subtree but got nothing" guard) — the facade must
NOT re-implement these; it just propagates whatever `Reader.GetPoe`/
`GetSensors` return.

### 5.2 `snmp/gosnmp.go`

```go
func NewGoSNMPClient(host, community string, opts ...ClientOption) *GoSNMPClient

func WithTimeout(d time.Duration) ClientOption
func WithRetries(n int) ClientOption

func (c *GoSNMPClient) Get(ctx context.Context, oids []string) ([]Row, error)
func (c *GoSNMPClient) Walk(ctx context.Context, baseOID string) ([]Row, error)
func (c *GoSNMPClient) Set(ctx context.Context, vb SetVarbind) error
func (c *GoSNMPClient) SetMany(ctx context.Context, vbs []SetVarbind) error
```
`NewGoSNMPClient` takes `host` as either a bare host/IP (port defaults to
161) OR a `"host:port"` pair — this collapses Python's separate
`host`/`port` fields (used by `PysnmpClient` in the equivalence harness,
§`equivalence.py`'s `facades_for`) into ONE string argument. **The Go
facade's SNMP `BackendReaderBuilder` must decide how it renders `host` for
`NewGoSNMPClient`** — since the Go `Switch.host` field is presumably a bare
host/IP (mirroring Python's `SyncSwitch.host`), the builder passes it
straight through unless a non-standard SNMP port is ever needed (no model
in the registry needs one today — only HTTP's `web_port`, §1.7, has a
non-standard-port model, and that's slice 06 scope).

No error is returned by `NewGoSNMPClient` itself (unlike Python's
`build_sync_snmp_client`, which raises `CredentialError` if `community is
None` via `_require_community`, §1.5) — **the Go facade's SNMP reader
builder must perform this same read-community-required check ITSELF**
before calling `NewGoSNMPClient`, since `gosnmp.go` has no such gate (an
empty/absent community is presumably allowed all the way to the wire by
this transport, unlike Python's `_require_community`/
`_require_write_community` asymmetric gates, §1.5, which the facade seam
must still enforce at its OWN layer to preserve Python parity).

### 5.3 `virtual/server.go`

```go
func NewVirtualSwitch(modelKey string, opts ...Option) (*VirtualSwitch, error)
func (v *VirtualSwitch) Start() error
func (v *VirtualSwitch) Stop() error

type Endpoints struct { Host string; SnmpPort int; Community string }
type EndpointProvider interface {
    StartModel(ctx context.Context, modelKey string) (Endpoints, error)
}
type GoFakeProvider struct{ /* ... */ }
func (p *GoFakeProvider) StartModel(ctx context.Context, modelKey string) (Endpoints, error)
func (p *GoFakeProvider) CloseAll() error
```
Only the SNMP face is bound in this slice — `Start()` returns an error
wrapping `model.ErrUnsupportedCapability` for any Plus-class (NSDP/HTTP-only)
model, exactly mirroring what the FACADE itself must do for those same
models per §3.1 (the virtual mock and the real facade degrade identically
today — both wait on slices 05/06/07). The Go facade's SNMP-model
conformance tests should drive `VirtualSwitch`/`GoFakeProvider` via
`Endpoints{Host, SnmpPort, Community}` → `snmp.NewGoSNMPClient(fmt.Sprintf("%s:%d", ep.Host, ep.SnmpPort), ep.Community)`
— exactly mirroring how `tests/equivalence.py`'s `facades_for` wires
`NetsnmpCliClient(f"{sw.host}:{sw.port}", sw.community)` against the
Python `VirtualSwitch`.

### 5.4 `alias.go` / `model/registry.go` / `model/types.go` / `model/errors.go`

Already exist (slice 01/02) and need NO changes for slice 03: `GetModel`,
`Models`, every aliased type/constant/error sentinel the facade needs
(`model.Backend`/`BackendSNMP`/etc., `model.SwitchModel`/`HasBackend`/
`HasMACTable`, `model.ErrUnsupportedCapability`/`ErrCredential`/
`ErrProtectedPort`, `model.DetectedModel`/`Matched()`, `model.SwitchData`/
`Canonical()`, `model.Pvid`) are all already in place and directly usable
by the new facade file(s). `config.go`/`inventory.go` (`SwitchConfig`,
`ResolveSecret`, `LoadInventory(Env)`) are likewise already ported and
ready to be consumed by a Go `FromConfig`-equivalent constructor mirroring
§2.16's field mapping table exactly (`cfg.Model`, `cfg.Host`,
`cfg.SNMPCommunity`, `cfg.SNMPWriteCommunitySpec` via a resolver closure,
`cfg.NSDPInterface`, `cfg.HTTPPasswordSpec` reused for BOTH the NSDP and
HTTP password resolvers, `cfg.ProtectedPorts`).

---

## 6. Completeness checklist

- [x] Every `_dispatch.py` function inventoried: 5 `require_*` gates (exact
      messages), `http_reads_supported`/`cli_reads_supported` (full
      docstrings), 8 `build_*` client builders (SNMP read×2, SNMP write×2,
      NSDP×2, HTTP×2, CLI×1) + `_http_host` + the two asymmetric
      credential-gate helpers (`_require_community` vs
      `_require_write_community` vs `_require_http_password`).
- [x] `SyncSwitch.__init__` — every one of its 17 keyword parameters'
      semantics documented (via §2.2-§2.6, §2.13-§2.16 covering each field's
      read, resolution, caching and dispatch role).
- [x] `_UNSET`/`_Unset` lazy once-only resolution — documented for all 3
      fields it guards, including the non-cached-on-raise edge case.
- [x] `_reader_cache`/`_writer_cache` — exact caching semantics, including
      the "gate-raise is never cached" subtlety.
- [x] `_read`/`_write` dispatch loops — `_BACKEND_PREFERENCE` order,
      skip-vs-record-last-vs-reraise-last, `CredentialError` propagation,
      all 6 ordering rules spelled out.
- [x] Every READ method documented: `get_ports`...`get_mgmt_ip` (table),
      `snapshot()`'s exact per-field swallow/propagate rule, `identify()`
      and `nsdp_device()`'s dispatch-bypass semantics.
- [x] Write methods: listed with one-line semantics + the shared
      protected-port/force plumbing (`delete_vlan`'s facade-level guard,
      documented in full since it's dispatch-layer, not backend-layer).
- [x] `_LazyHttpSession`/`_LazyCliSession` — construction-vs-first-use,
      full method inventory, cache-ownership difference between the two.
- [x] `from_config` — full field-mapping table, including the
      NSDP-reuses-HTTP-password quirk.
- [x] `close()`/context-manager — exactly what's torn down (self-built HTTP
      only) vs never touched (injected clients, SNMP/NSDP, CLI sessions).
- [x] `detect_model()` free function — client-building defaults, injection.
- [x] Async (`AsyncSwitch`) deltas isolated to §2b — CLI-unconditional-raise
      and `upload_certificate_scp`-unconditional-raise are the ONLY two
      semantic differences from `SyncSwitch`; both flagged as Go-must-NOT-
      inherit since Go's single facade should behave like `SyncSwitch`.
- [x] Reachability analysis: SNMP-only models fully facade-able today;
      NSDP/HTTP/SSH-only models degrade honestly via
      `ErrUnsupportedCapability` until slices 05-07.
- [x] Backend-registry/hook seam: concrete minimal design given
      (`BackendReaderBuilder`/`BackendWriterBuilder`/`RegisterBackend`/
      `Reader` interface), with the specific property it must preserve
      (zero facade-file edits needed for slices 05-07) called out.
- [x] Tests: `test_sync_api.py` (28 tests tabulated), `test_facade_equivalence.py`
      + `equivalence.py` harness (structure + Go-port equivalent), `test_public_api.py`
      (2 tests), `test_op_coverage.py` (coverage-guard, full canonical op list
      extracted).
- [x] Go reference signatures quoted exactly from `snmp/reader.go`,
      `snmp/gosnmp.go`, `virtual/server.go`, plus confirmation that
      `alias.go`/`model/*.go`/`config.go`/`inventory.go` need no changes.

---

## 7. Ten trickiest traps (read this section twice before implementing)

1. **Read-community gate rejects only `nil`; write-community/HTTP-password
   gates reject `nil` OR empty-string.** Unifying these into one helper
   silently breaks the `snmpset -c ""` regression test's intent (§1.5).
2. **A raising secret-resolver is NOT cached as "resolved"** — only a
   successful resolution marks the `_UNSET` sentinel resolved (§2.13). Mark
   "resolved" only AFTER the resolver returns, or a second write after a
   first failed one won't get a retry.
3. **HTTP/CLI reader-construction gate failures are never cached** — only
   a SUCCESSFULLY built reader/writer goes into
   `_reader_cache`/`_writer_cache` (§2.5). Caching the gate's raise would
   be wrong but harmless-looking until a test catches stale state.
4. **`_read`'s catch is `UnsupportedCapabilityError`-only** — a bare "catch
   any error" implementation silently swallows `CredentialError` and
   breaks the explicit "must propagate" contract (§2.7 rule 5, §3.3).
5. **`get_macs()`'s `require_mac_table` guard runs BEFORE dispatch, but
   `snapshot()`'s `macs` field does NOT call it** — it just lets `_read`
   exhaust naturally to the same outcome (§2.12). Don't "fix" snapshot to
   call the guard too; it would change nothing observable but diverges from
   the reference's actual code path.
6. **`http_reads_supported` gates BOTH HTTP reads AND HTTP writes** — there
   is no separate `http_writes_supported` (§1.3, §2.6). A Go
   `HTTPReadsSupported`-only-named predicate used for writes too is correct
   parity, not a bug.
7. **NSDP's writer path eagerly raises `CredentialError` if the password
   is unresolved; NSDP's READER path needs no password at all** — don't
   apply the writer's credential check to the reader by "consistency"
   (§2.5 vs §2.6).
8. **`delete_vlan`'s protected-port guard degrades SILENTLY (not raise) if
   no backend can even read VLANs** — `except UnsupportedCapabilityError:
   return`, never blocking the delete on an inability to check (§2.17).
9. **`SyncSwitch.close()` never touches SNMP/NSDP clients or CLI
   sessions — only a self-built HTTP client.** A `_LazyCliSession` built
   via a read/write dispatch is NEVER closed by the facade's `close()` at
   all (only `upload_certificate_scp`'s own `finally` closes a
   self-built CLI session) — a latent asymmetry to port AS-IS (§2.15).
10. **The backend-registry seam must let an unregistered backend
    (NSDP/HTTP/SSH/Telnet in slice 03) fail EXACTLY like Python's
    "not implemented" case — `ErrUnsupportedCapability`, recorded as
    `last`, loop continues** — never a nil-pointer panic from an
    unpopulated registry map entry, and never a special-cased "not yet
    implemented" error type distinct from the ordinary capability-gap
    error the same model will legitimately raise post-slice-05/06/07 for
    an op that backend genuinely still can't serve (§3.2, §3.3).
