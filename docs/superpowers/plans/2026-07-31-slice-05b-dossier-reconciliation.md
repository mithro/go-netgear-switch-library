# Slice 05b Reconciliation Dossier: facade dispatch (no silent fallback) + mock VLAN PortList real widths

**Pin guard**: `git -C /home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-1841111 rev-parse HEAD`
→ `1841111c6d0b55ad3eece915e57ba115a0cfdd12` — starts `1841111`. Confirmed.

**Why this dossier exists**: Go slices 01-05 (facade, SNMP write, NSDP) were built against the OLD Python pin
`1aa1274`. Python has since moved to `1841111` on the same branch and, in doing so, ripped out the silent
backend-fallback loop in `sync_api.py`/`_dispatch.py` (Topic A) and started seeding/preserving the *real*
measured VLAN `PortList` byte-width in `virtual/state.py`/`seed.py` (Topic B). Both changes are principle
violations by the OLD shape now baked into the Go tree (`readVia`/`writeVia`'s loop-with-skip is a silent
fallback; `virtual/state.go`'s `snmp.VlanBitmapWidth(m.PortCount)` formula is a fake that doesn't match
hardware). This dossier is the exhaustive brief for reworking both.

---

## Topic A — Facade backend dispatch: no silent fallback

### A.1 What changed in Python, in one sentence

`sync_api.py` no longer loops over `_BACKEND_PREFERENCE` trying each backend in turn and swallowing
`UnsupportedCapabilityError`; it resolves **exactly one** backend per op (`resolve_backend`), dispatches to it,
and — if that one backend can't serve the op — raises, naming the backend, rather than silently trying the
next one. A caller who wants a specific protocol passes `backend=Backend.X`; a caller who wants a specific
protocol for the whole session passes `backend=` to the constructor.

### A.2 `_dispatch.py`: the shared `resolve_backend` function (full semantics)

```python
def resolve_backend(
    model: SwitchModel,
    requested: Backend | None,
    preference: tuple[Backend, ...],
) -> Backend:
    if requested is not None:
        if requested not in model.backends:
            have = ", ".join(sorted(b.name for b in model.backends))
            raise UnsupportedCapabilityError(
                f"model {model.key!r} has no {requested.name} backend "
                f"(it has: {have})"
            )
        return requested
    for backend in preference:
        if backend in model.backends:
            return backend
    raise UnsupportedCapabilityError(
        f"model {model.key!r} declares no backend this library can dispatch to"
    )
```

Two branches, two distinct message shapes, **neither one wrapped by `_cannot_serve`** (see A.4) — both are
raised directly out of `resolve_backend`, before any reader/writer is even built:

1. **`requested` is not `None`** (an explicit ask, either per-call or the facade's pinned default — see A.3's
   `or` subtlety): if the model doesn't have that backend at all, raise immediately with
   `f"model {model.key!r} has no {requested.name} backend (it has: {have})"` where `have` is the model's
   actual backend set, comma-joined, name-sorted uppercase (`Backend.name`, e.g. `"HTTP, NSDP"`).
   Otherwise return `requested` as-is — **no check that the resolved backend can serve the specific op**, only
   that the model declares it at all.
2. **`requested` is `None`**: walk `preference` (the fixed tuple, model-independent) and return the first
   member the model declares. If none of `preference`'s members are in `model.backends` at all (only possible
   for a model with a backend not on the preference list — none exist today, but the code doesn't assume it),
   raise `f"model {model.key!r} declares no backend this library can dispatch to"`.

`_BACKEND_PREFERENCE = (SNMP, NSDP, HTTP, SSH, TELNET, CONSOLE)` — unchanged, still the fixed
model-independent order (matches Go's `backendPreference` in dispatch.go exactly, module the trailing
SSH/TELNET/CONSOLE members Go hasn't wired yet).

### A.3 `SyncSwitch.__init__`: the new `backend` field

```python
def __init__(self, model, host, *, ..., backend: Backend | None = None) -> None:
    ...
    self.backend = backend
```

Docstring/comment: "Default backend for EVERY op on this facade (None = the model's highest-preference one).
Set it to pin a whole session to one protocol... A per-call `backend=` argument still wins over this."

`SyncSwitch.resolve_backend(self, backend: Backend | None = None) -> Backend`:

```python
def resolve_backend(self, backend: Backend | None = None) -> Backend:
    return resolve_backend(self.model, backend or self.backend, _BACKEND_PREFERENCE)
```

**Public method** — a caller can ask "what would this op talk to?" without performing it (pinned by
`test_facade_default_backend_pins_every_op`, `test_default_backend_resolution_is_deterministic`).

**TRAP (load-bearing, easy to miss)**: the composition is `backend or self.backend`, evaluated using Python's
truthy-`or`, not an explicit `is None` check. Since `Backend` enum members are always truthy, this is
behaviorally equivalent to "per-call wins, else facade default, else None" — but the Go port must NOT
implement it as a data-flow-preserving `nil`-coalesce done differently per call site; it must do the SAME
`requested := callBackend; if requested == nil { requested = sw.backend }` computation **both places it's
computed** (see A.4 — `_read`/`_write` recompute this exact expression independently of calling
`self.resolve_backend`, and BOTH computations must agree bit-for-bit, because the second one — not the
original per-call arg — is what flows into `_cannot_serve` for message-shape selection).

### A.4 `_read`/`_write`: single-backend dispatch, no loop

```python
def _read(self, op, backend):
    requested = backend or self.backend
    chosen = self.resolve_backend(requested)
    reader = self._reader_for(chosen)
    try:
        return op(reader)
    except UnsupportedCapabilityError as exc:
        raise self._cannot_serve(chosen, requested, exc) from exc

def _write(self, op, backend):
    requested = backend or self.backend
    chosen = self.resolve_backend(requested)
    writer = self._writer_for(chosen)
    try:
        op(writer)
    except UnsupportedCapabilityError as exc:
        raise self._cannot_serve(chosen, requested, exc) from exc
```

Six-rule-loop → three-step single dispatch:

1. Compute `requested` (per-call `backend` arg, else the facade's pinned `self.backend`, else `None`).
2. `chosen = resolve_backend(model, requested, preference)` — raises directly (A.2's two message shapes) if
   `requested` names a backend the model lacks, or (only when `requested is None`) if the model declares
   nothing in `preference` at all. **No fallback to a second backend under any circumstance.**
3. Build/reuse (via the SAME per-backend cache as before — see A.5) the reader/writer for `chosen`, run the
   op. If the op itself raises `UnsupportedCapabilityError` (a genuine capability gap on `chosen`, e.g. NSDP
   has no PoE tag), re-raise via `_cannot_serve(chosen, requested, exc)` — **the ONE place fallback used to
   happen; now it's a hard stop.** Any OTHER exception (notably `CredentialError`) propagates completely
   unchanged — `_read`/`_write` only catch `UnsupportedCapabilityError`.

**IMPORTANT for the Go rework**: there are now TWO distinct failure shapes reachable from one call, and they
must not be conflated:
- Resolution failure (step 2): raised directly by `resolve_backend`, names no "chosen" backend (there wasn't
  one), message shape per A.2.
- Op failure on the chosen backend (step 3): wrapped by `_cannot_serve`, message shape per A.6, ALWAYS names
  `chosen` plus the original underlying `exc` text.

### A.5 `_reader_for`/`_writer_for`: same per-backend cache, NO skip loop around them

Structurally unchanged from the old code (same as Go's `readerFor`/`writerFor` today) — cache lookup, build
via the same per-backend branch (SNMP/NSDP/HTTP/CLI), cache on success, gate failure never cached. The ONLY
thing that changed is that `_read`/`_write` no longer call `_reader_for`/`_writer_for` in a loop over multiple
backends — they call it exactly once, for `chosen`. Go's existing `readerFor`/`writerFor` (dispatch.go
lines 126-144, write_dispatch.go lines 84-102) need **no logic change at all**, only a change in how many
times and with what argument they're invoked (once, with the resolved backend, not in a preference loop).

### A.6 `_cannot_serve`: exact message text, both branches

```python
def _cannot_serve(self, chosen, requested, exc):
    if requested is None:
        others = sorted(b.name for b in self.model.backends if b is not chosen)
        hint = (
            f"; pass backend=Backend.<{'|'.join(others)}> to use another backend"
            if others else ""
        )
        return UnsupportedCapabilityError(
            f"model {self.model.key!r}: the default backend {chosen.name} "
            f"cannot serve this operation: {exc}{hint}"
        )
    return UnsupportedCapabilityError(
        f"model {self.model.key!r}: the requested backend {chosen.name} "
        f"cannot serve this operation: {exc}"
    )
```

Verbatim message templates (fill in `{model.key!r}` = Python `repr()` of the model key string, e.g.
`'gs305ep'`; `{chosen.name}` = uppercase enum name, e.g. `SNMP`/`NSDP`/`HTTP`; `{exc}` = the underlying
`UnsupportedCapabilityError`'s own `str()`, embedded and chained via `from exc`):

- **`requested is None` (facade default, unpinned session)**:
  `model {key!r}: the default backend {chosen.name} cannot serve this operation: {exc}; pass backend=Backend.<A|B> to use another backend`
  (hint omitted entirely — not even a bare `.` — when `others` is empty, i.e. the model has only ONE backend
  and it's the one that just failed).
- **`requested is not None` (either an explicit per-call `backend=`, OR a facade-level pinned `self.backend`
  — see A.3's trap)**:
  `model {key!r}: the requested backend {chosen.name} cannot serve this operation: {exc}`
  (no hint at all — a caller who explicitly named a backend gets no "try another" suggestion, even though the
  model may have alternates; this is deliberate: they asked for this one specifically).

`others` is `sorted(name for b in self.model.backends if b is not chosen)` — **the model's full backend set
minus `chosen`**, NOT filtered by which of those alternates could actually serve the op either (no such
introspection exists; the hint is a bare "here's what else this model has", not a guarantee).

### A.7 Which read/write ops take `backend=`; identify()/nsdp_device() bypass

**Every** read op takes `backend: Backend | None = None` as a keyword-only trailing parameter: `get_ports`,
`get_stats`, `get_vlans`, `get_pvids`, `get_lldp`, `get_macs`, `get_poe`, `get_sensors`, `get_mgmt_ip`,
`snapshot`. **Every** write op likewise: `set_poe`, `set_port_enabled`, `set_pvid`, `set_vlan_membership`,
`create_vlan`, `delete_vlan`, `cycle_poe`, `clear_poe_fault`, `set_mgmt_ip`.

`get_macs` still gates on `require_mac_table(self.model)` **before** calling `_read` — unchanged, still
independent of `backend` (the gate fires regardless of which backend would have been chosen).

`delete_vlan`'s facade-level guard (`_guard_vlan_delete_members`) now threads `backend` through to its own
internal `_read(lambda r: r.get_vlans(), backend)` call — **the guard reads over the SAME backend the delete
itself will use**, so a `backend=Backend.HTTP` delete's protected-port check also runs over HTTP, not
whatever the default would have been. This is new-in-1841111 plumbing Go's `guardVLANDeleteMembers` doesn't
have yet (it always uses `s.GetVLANs(ctx)`, i.e. the facade default, unconditionally) — must be threaded
through in the rework.

`identify()` and `nsdp_device()` **bypass dispatch entirely, unchanged from before** — confirmed by re-reading
both at 1841111: `identify()` builds a bare SNMP client via `build_sync_snmp_client` and never consults
`self.model.backends` or `self.backend`/`resolve_backend` at all; `nsdp_device()` calls
`self._reader_for(Backend.NSDP)` directly (still routes through the reader CACHE, unlike `identify()`), never
through `_read`. **Neither bypass changed shape in this pin** — Go's `Identify`/`NSDPDevice` (switch.go
541-580) need no rework for Topic A beyond making sure they still compile against whatever `Switch` struct
changes land (e.g. a new `backend *model.Backend` field doesn't touch either method).

### A.8 Exact new error-message tests pinned in `test_sync_api.py` (grep results)

All at pin 1841111, file `tests/test_sync_api.py`:

- `test_gs305ep_poe_needs_an_explicit_http_backend` (line 697): gs305ep's default backend is NSDP; NSDP has
  no PoE tag; `sw.get_poe()` (no `backend=`) must raise `UnsupportedCapabilityError` whose text contains BOTH
  `"NSDP"` (the backend that failed) and `"HTTP"` (the hint's suggested alternate); `sw.get_poe(backend=Backend.HTTP)`
  must actually succeed and return real PoE data.
- `test_requested_backend_is_never_substituted` (line 739): `sw.get_ports(backend=Backend.SNMP)` on gs305ep
  (NSDP+HTTP only) must raise with `"no SNMP backend"` in the text — this is the A.2 resolve-failure shape,
  NOT the A.6 `_cannot_serve` shape (no "chosen" backend, because resolution itself failed).
- `test_facade_default_backend_pins_every_op` (line 753): `SyncSwitch(model, host, backend=Backend.HTTP)` →
  `sw.resolve_backend()` returns `Backend.HTTP` (not the model's own top-preference backend); a per-call
  `sw.resolve_backend(Backend.SSH)` still overrides to `Backend.SSH`.
- `test_ngsw_backend_flag_pins_the_facade` (line 765): CLI-level `--backend http` flag threads into the
  constructor's `backend=` — **Go has no `ngsw` CLI in this repo yet**, so this specific test has no direct Go
  analogue; noted for completeness only, not an action item.
- `test_default_backend_resolution_is_deterministic` (line 784): `SyncSwitch(gs305ep).resolve_backend()` is
  `Backend.NSDP`; `SyncSwitch(gsm7252ps).resolve_backend()` is `Backend.SNMP`; `SyncSwitch(gs110emx).resolve_backend()`
  is `Backend.NSDP`; a named backend resolves to itself when present (`resolve_backend(Backend.HTTP)` →
  `Backend.HTTP`, `resolve_backend(Backend.SSH)` → `Backend.SSH`, even though `gsm7252ps` doesn't declare SSH
  in its captured registry list per this test's own assumption — re-verify against the Go `model` registry's
  actual `gsm7252ps` backend set before porting this exact assertion, since Go's registry.go's `gsm7252ps`
  entry — line ~134 — DOES include `BackendSSH`, so this should port cleanly).
- `test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections` (line 156): **the single most
  important test for Topic A's behavioral delta** — see A.9 below.

### A.9 `snapshot()`'s new single-backend-only semantics (the concrete regression)

`snapshot()` still calls `_read` once per field, all with the SAME `backend` argument (the one passed to
`snapshot(backend=...)` itself, defaulting to `None`) — but because `_read` now resolves to exactly ONE
backend per call, and `resolve_backend` is a *pure function of `(model, requested, preference)`* with no
memory of prior calls, **every field within one `snapshot()` call resolves to the identical chosen backend**.
A field that backend can't serve degrades to `()`/`None` (still tolerant — `UnsupportedCapabilityError` is
still caught per-field in `_opt`/the `mgmt` special-case) but **is never filled in from a second, different
backend** the way the old loop used to.

The pinned test proves this with `gs305ep` (NSDP-default, NSDP+HTTP model): `sw.snapshot()` with both an
NSDP fake AND an HTTP fake injected returns `data.poe == ()` — **empty**, even though the injected `FakeHttp`
*would* have answered a real PoE page if asked. Old (pre-1841111 / current Go) behavior filled this from
HTTP behind the caller's back; new behavior requires `sw.get_poe(backend=Backend.HTTP)` explicitly (see
`test_gs305ep_poe_needs_an_explicit_http_backend`, same `FakeHttp`).

**This directly contradicts Go's existing `switch_read_test.go`
`TestSnapshot_DegradesUnsupportedFieldsToEmptyAndFallsThroughToSecondBackend`** (lines 398-447), which
registers a fake NSDP reader (ports only, everything else `UnsupportedCapability`) AND a fake HTTP reader
(PoE only) and asserts `data.PoE` ends up populated **from HTTP** — i.e. it tests exactly the fallback
behavior Python removed. This test's core assertion (line 441-443) is now WRONG and its name is now
misleading; it must be rewritten to assert `data.PoE` degrades to **empty** (matching the new Python test),
and probably renamed to drop "FallsThroughToSecondBackend" (e.g.
`TestSnapshot_DegradesUnsupportedFieldsToEmptyNoCrossBackendFill`).

### A.10 Go rework guidance

**A.10.1 — `readVia`/`writeVia` → single-backend dispatch.**

Replace the `for _, backend := range backendPreference { ... }` loop bodies in `dispatch.go`'s `readVia` and
`write_dispatch.go`'s `writeVia` with the three-step shape from A.4:

```go
func (s *Switch) readVia(ctx context.Context, op string, requested *model.Backend, fn func(BackendReader) error) error {
    if err := ctx.Err(); err != nil {
        return err
    }
    effective := requested
    if effective == nil {
        effective = s.backend // the facade's pinned default, if any
    }
    chosen, err := resolveBackend(s.model, effective, backendPreference)
    if err != nil {
        return err // A.2 shape: resolution failure, never wrapped
    }
    reader, err := s.readerFor(chosen)
    if err != nil {
        if errors.Is(err, model.ErrUnsupportedCapability) {
            return s.cannotServe(chosen, effective, err) // A.6 shape
        }
        return err // e.g. CredentialError, propagates unwrapped
    }
    if err := fn(reader); err != nil {
        if errors.Is(err, model.ErrUnsupportedCapability) {
            return s.cannotServe(chosen, effective, err)
        }
        return err
    }
    return nil
}
```

(`writeVia` is the structural twin, same as today.) `op` (the snake_case diagnostic string) is still useful
purely for logging/debugging but is NO LONGER embedded in the fallback-exhausted error, since that error
shape (`resolveBackend`'s "declares no backend..." message) doesn't take an op name in Python either — port
`resolveBackend`'s two messages VERBATIM (translated to Go idiom) instead of reusing today's
`"model %q has no backend supporting %s: %w"` wording.

Add a free function `resolveBackend(m *model.SwitchModel, requested *model.Backend, preference []model.Backend) (model.Backend, error)`
in dispatch.go mirroring `_dispatch.resolve_backend` (A.2) — this becomes the shared implementation both
`readVia`/`writeVia` AND a new public `Switch.ResolveBackend` (mirroring `SyncSwitch.resolve_backend`, A.3)
call into. Both a `*model.Backend` (nil = unset) plumbed everywhere Python uses `Backend | None`.

**A.10.2 — new `Switch` field + option: `WithBackend`.**

Add `backend *model.Backend` to the `Switch` struct (switch.go) and `func WithBackend(b model.Backend) SwitchOption`
mirroring `WithProtectedPorts`'s shape — stores `&b`. `New`/`FromConfig` leave it nil by default (mirrors
`backend: Backend | None = None`).

**A.10.3 — per-op `backend` override: decide the Go shape.**

Go has no keyword arguments, so a per-call override needs a deliberate shape. Two candidates, weighed against
the EXISTING `Write{Force bool}` struct precedent this codebase already uses on every write method:

- **Reads**: every read method (`GetPorts`, `GetStats`, ... 9 of them, plus `Snapshot`) currently takes ONLY
  `ctx`. Adding a *mandatory* options struct parameter to all nine would force every existing call site
  (tests, docs, real callers) to pass an empty struct even when never customizing backend — high churn for a
  feature most callers never touch. **Recommendation: a variadic `...ReadOption` functional-option list**,
  mirroring the `CycleOption`/`WithCycleTimeouts` pattern this codebase ALREADY establishes for exactly this
  "optional per-call knob, Go has no kwargs" problem (switch_write.go lines 38-61). Add
  `type ReadOption func(*readOptions)` (unexported `readOptions{backend *model.Backend}`) and
  `func WithReadBackend(b model.Backend) ReadOption`. Every read method's signature grows a trailing
  `opts ...ReadOption`; zero-arg call sites are entirely unaffected (Go variadic with no args costs nothing at
  the call site).
- **Writes**: the `Write{Force bool}` struct is ALREADY a mandatory parameter on every write method (every
  call site already passes `netgearswitch.Write{}` at minimum) — so extending it with a `Backend *model.Backend`
  field costs NOTHING at existing call sites (the zero value `nil` is already what every caller not touching
  the field gets). **Recommendation: add `Backend *model.Backend` to the existing `Write` struct** rather than
  introducing a second, parallel option mechanism for writes — one struct, one place, matches the "kwarg
  bundle" role `Write` already plays for `Force`, and keeps write call sites textually unchanged
  (`netgearswitch.Write{Force: true}` still compiles; `netgearswitch.Write{Backend: &b}` is the new capability).

This asymmetry (variadic options for reads, a struct field for writes) is a deliberate, justified divergence
in shape between the two sides driven by what already exists in each — flag it explicitly in the Go source
comments so a future maintainer doesn't "fix" the asymmetry by accident.

**A.10.4 — `Switch.ResolveBackend` (public, mirrors `SyncSwitch.resolve_backend`).**

```go
func (s *Switch) ResolveBackend(requested ...model.Backend) (model.Backend, error)
```
(variadic-as-optional, 0 or 1 args; matches the `ReadOption`-style "Go has no `Backend | None`" idiom without
introducing a second pointer-vs-variadic inconsistency versus A.10.3's read-side choice). Body: apply A.3's
`effective := requested[0] (if given) else s.backend` then call the shared `resolveBackend` free function.

**A.10.5 — `cannotServe` helper.**

```go
func (s *Switch) cannotServe(chosen model.Backend, requested *model.Backend, exc error) error {
    if requested == nil {
        var others []string
        for _, b := range s.model.Backends {
            if b != chosen {
                others = append(others, string(b))
            }
        }
        sort.Strings(others)
        hint := ""
        if len(others) > 0 {
            hint = fmt.Sprintf("; pass backend=Backend.<%s> to use another backend", strings.Join(others, "|"))
        }
        return fmt.Errorf("model %q: the default backend %s cannot serve this operation: %w%s", s.model.Key, chosen, exc, hint)
    }
    return fmt.Errorf("model %q: the requested backend %s cannot serve this operation: %w", s.model.Key, chosen, exc)
}
```
Must still `%w`-wrap `exc` so `errors.Is(err, model.ErrUnsupportedCapability)` keeps working after this
rework (Go's `fmt.Errorf` with a single `%w` verb plus trailing plain `%s` text is fine; the hint string is
NOT part of the wrapped chain, matching Python's plain string concatenation).

**A.10.6 — message-text casing decision (flag, don't silently resolve).** Go's `model.Backend` is a lowercase
string type (`"snmp"`, `"nsdp"`, ...; model/registry.go:54-59), and EVERY existing dispatch/backend_*.go
message in this codebase already interpolates it lowercase (`"model %q has no %s backend implementation yet"`).
Python's messages use `.name`, which is uppercase (`SNMP`, `NSDP`, ...). Porting A.6/A.2's messages
byte-for-byte would require uppercasing Go's `Backend` values ONLY in these specific messages, breaking
consistency with every other message in dispatch.go/backend_snmp.go/backend_nsdp.go that already uses the
lowercase form. **Recommendation: keep Go's existing lowercase convention uniformly** (do not special-case
these two messages to uppercase) and treat this as a deliberate, already-established cross-language string
divergence (consistent with this codebase's own pattern of NOT chasing byte-identical prose everywhere —
only a few call-outs in the existing source, e.g. `formatIntList`, are marked byte-identical-required). Any
NEW Go tests asserting on this text must assert the lowercase form (`"snmp"`, not `"SNMP"`) — do not
copy-paste Python's `assert "NSDP" in text` assertions verbatim.

**A.10.7 — `guardVLANDeleteMembers` must thread the resolved backend through (A.7).** `DeleteVlan`'s call to
`s.guardVLANDeleteMembers(ctx, vlanID, o.Force)` must become
`s.guardVLANDeleteMembers(ctx, vlanID, o.Force, o.Backend)`, and the guard's internal `s.GetVLANs(ctx)` call
must become `s.GetVLANs(ctx, WithReadBackend(...))` (or equivalent) using the SAME `o.Backend` the delete
itself will use — this is new plumbing versus the current Go source, not just a mechanical rename.

**A.10.8 — `CredentialError` propagation.** Unchanged: `_read`/`_write`'s `except UnsupportedCapabilityError`
is the ONLY catch; everything else (`CredentialError`, a plain resolver error) propagates straight through
`readVia`/`writeVia` uncaught, exactly as today's `readVia`/`writeVia` already do for non-`ErrUnsupportedCapability`
errors (dispatch.go rule 5 in the existing doc comment). No behavior change needed here beyond the loop
removal itself.

### A.11 Every current Go call site that must change

**dispatch.go / write_dispatch.go** (the two files being rewritten themselves — not "call sites" but the
implementation, listed for completeness):
- `readVia` (dispatch.go:174) — full rewrite per A.10.1.
- `writeVia` (write_dispatch.go:111) — full rewrite, structural twin.

**switch.go** — every read method is a `readVia` call site; ALL NINE need their call updated to pass the
resolved-backend argument (from new `ReadOption`s) instead of just `(ctx, op, fn)`:
- `GetPorts` (383), `GetStats` (397), `GetVLANs` (411), `GetPVIDs` (425), `getMACsNoGate` (457, called by both
  `GetMACs` and `snapshot.go`'s `Snapshot`), `GetPoE` (487), `GetSensors` (502), `GetMgmtIP` (516).
- `GetMACs` (477) — the `require_mac_table` gate itself is untouched; only the `getMACsNoGate` call beneath it
  changes shape.
- `Identify` (541) and `NSDPDevice` (564) — **no change** (A.7 confirms both bypasses are stable across this
  pin).

**switch_write.go** — every write method is a `writeVia` call site, all NINE need updating to thread
`o.Backend` through:
- `SetPoE` (67), `SetPortEnabled` (77), `SetPVID` (87), `SetVlanMembership` (98), `CreateVlan` (112),
  `DeleteVlan` (127, plus its `guardVLANDeleteMembers` call at 128 — see A.10.7), `SetMgmtIP` (213),
  `CyclePoE` (224), `ClearPoEFault` (237).
- `guardVLANDeleteMembers` (150) itself — internal `s.GetVLANs(ctx)` call at line 154 needs the backend
  parameter threaded per A.10.7.

**snapshot.go** (not yet read in this dossier pass, but referenced by switch.go's `getMACsNoGate` doc comment
at line 453-456 as `Snapshot`'s macs-field caller) — MUST be re-read before implementation: `Snapshot`
presumably calls `s.readVia`/the read methods once per field with a single shared `backend` parameter exactly
like Python's `snapshot()` (A.9) — confirm it does NOT currently vary backend per field (it shouldn't, since
Go's `readVia` today has no per-call backend concept at all yet), and wire the SAME resolved-backend-per-call
semantics through once `ReadOption`/`WithReadBackend` exist. **Action item for the implementer, not fully
resolved by this research pass** — read `snapshot.go` first thing.

**backend_snmp.go / backend_nsdp.go** — `buildSNMPReader`/`buildSNMPWriter`/`buildNSDPReader`/`buildNSDPWriter`
and their `require*` gate helpers are UNCHANGED by Topic A (A.5 confirms `_reader_for`/`_writer_for`'s
per-backend branches are untouched; only the caller's loop-vs-single-call shape changed). No edits needed in
these two files for Topic A.

### A.12 Interaction with NSDP/SNMP writers already built; facade tests needing updates

**Interaction check**: the NSDP writer (`nsdp.Writer`/`nsdpWriterAdapter`) and SNMP writer (`snmp.Writer`)
built in slices 04/05 do NOT themselves loop over backends — each is already scoped to exactly one protocol,
called by `writeVia` only after a single backend has been chosen. **No interaction risk**: the rework is
entirely confined to dispatch.go/write_dispatch.go/switch.go/switch_write.go's dispatch LAYER; the protocol
writers underneath are untouched by Topic A. (`nsdpWriterAdapter`'s `CyclePoE`/`ClearPoEFault` stubs are
still called at most once, same as today — they never see a "try again on the next backend" retry either way.)

**Facade tests confirmed needing rewrite/rename** (exhaustive per this research pass):
- `switch_test.go`: ALL TEN `TestReadVia_*` tests (`SkipsBackendsModelDoesNotHave`, `SkipAndReraiseLast`,
  `CredentialErrorPropagatesImmediately`, `OpCredentialErrorPropagatesImmediately`,
  `UnregisteredBackendTreatedAsUnsupported`, `CancelledContextFailsFast`, `NoApplicableBackendRaisesFreshError`,
  `ReaderCacheBuilderCalledOnce`, `GateFailureIsNeverCached`, `BackendOrderIsFixedNotModelOrder`) test the OLD
  loop's skip/reraise-last mechanics directly and must become single-backend-resolution tests (some survive
  conceptually — e.g. "unregistered backend is unsupported", "reader cache built once", "context cancelled
  fails fast" — with rewritten bodies; `SkipAndReraiseLast` and `BackendOrderIsFixedNotModelOrder` test
  behavior that NO LONGER EXISTS and should be replaced outright with resolution-shape tests mirroring A.8's
  Python tests).
- `switch_write_test.go`: the ELEVEN structural twin `TestWriteVia_*` tests (same names, write side) — same
  treatment.
- `switch_read_test.go`: `TestSnapshot_DegradesUnsupportedFieldsToEmptyAndFallsThroughToSecondBackend`
  (398-447) — **must be rewritten**, core assertion (PoE filled from HTTP) is now wrong; see A.9. Likely
  rename to drop "FallsThroughToSecondBackend".
- `facade_integration_test.go`: `TestFacadeIntegration_GS110EMXNSDPServesReadsHTTPStillDegrades` (387-450) —
  comment at lines 402-406 explicitly describes the old "dispatch through NSDP then HTTP" two-hop behavior;
  under single-backend dispatch, `GetMACs`/`GetLLDP` on gs110emx (NSDP-default) will fail directly against
  NSDP via `_cannot_serve`'s "default backend NSDP cannot serve..." shape and NEVER reach the
  unregistered-HTTP branch at all. The `errors.Is(err, ErrUnsupportedCapability)` assertions likely still
  pass (both old and new shapes wrap the same sentinel), but the explanatory comment is now factually wrong
  and should be corrected; verify no assertion depends on which specific backend's message text appears.
- `facade_nsdp_integration_test.go`: `TestFacadeNSDPIntegration_GS110EMXUnsupportedReadsRaise` (226) and
  `TestFacadeNSDPIntegration_GS305EPUnsupportedReadsRaise` (508) — names suggest they only assert
  `errors.Is(..., ErrUnsupportedCapability)`, likely SURVIVE unchanged, but must be checked once the rework
  lands (not read in full during this pass — re-verify before/while implementing).
- `facade_write_integration_test.go` — no test name suggests reliance on cross-backend fallback; spot-checked
  `TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts` (186) for Topic B relevance
  instead (see B.11) — low risk for Topic A, but re-scan once `Write.Backend`/`ReadOption` land since every
  call site's signature is touched mechanically.
- **`snapshot.go`'s own test file** (not located/read in this pass — search for `snapshot_test.go` or
  equivalent before implementing; likely contains the direct Go analogue of
  `test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections` and may already be
  `TestSnapshot_DegradesUnsupportedFieldsToEmptyAndFallsThroughToSecondBackend` itself, i.e. the same test
  listed above under switch_read_test.go — confirm which file it actually lives in; this dossier found it via
  grep in switch_read_test.go and did not separately search for a dedicated snapshot_test.go).

---

## Topic B — Mock VLAN PortList real widths

### B.1 The Python field: `VirtualSwitchState.vlan_portlist_width`

`src/netgear_switch/virtual/state.py` (~line 449-462):

```python
# Fixed Q-BRIDGE PortList byte-width the SNMP agent reports for
# dot1qVlanStaticEgressPorts / dot1qVlanStaticUntaggedPorts. A real switch
# emits a CONSTANT-width bitmap covering every port it knows -- physical
# ports PLUS the LAG/CPU pseudo-ports far above the physical count -- so the
# width does NOT track the highest member. Measured LIVE (read-only,
# community "public"): GSM7252PS @10.1.5.22 = 79 bytes (highest set byte 60
# => LAG ~port 481); M4300 @10.1.5.13 = 131 bytes (highest set byte 112 =>
# ~port 897). None = unmeasured: oid_map() falls back to
# vlan_bitmap_width(model), the physical-port-only width. Seeding the REAL
# width is what lets the mock catch the historical writer bug (issue #3):
# the buggy writer re-encoded the decoded member set at max(8, port_count/8)
# rather than preserving the device width, so it sent a SET narrower than
# this -- which a stricter Q-BRIDGE agent rejects outright.
vlan_portlist_width: int | None = None
```

An `int | None` field on the dataclass (Go's `virtual.State` equivalent). `None` (unmeasured) is the default
for every model unless explicitly seeded.

### B.2 The measured per-model values (confirmed by direct grep of `seed.py`)

| Model (`seed_*` function) | `vlan_portlist_width` | Source |
|---|---|---|
| `gsm7252ps` (`seed_gsm7252ps`, line 1222) | **79 bytes** | live capture, GSM7252PS @10.1.5.22 |
| `gsm7228ps` (`seed_gsm7228ps`, line 1786) | **45 bytes** | live capture, S3300-52X @10.1.5.11 |
| `m4300_24x` (`seed_m4300_24x`, line 2393) | **131 bytes** | live capture, M4300-24X @10.1.5.13 |
| `m4300_16x` (`seed_m4300_16x`, line 2587) | **131 bytes** | same M4300 firmware family/measurement |
| `gs110emx`, `gs305ep`, `gs105pe`, `gs728tpp` | **unset (`None`)** | no measurement yet — falls back to the `vlan_bitmap_width(model)` formula |

(The owner's "79/131/45" recollection is confirmed exactly: 79=gsm7252ps, 131=both M4300s, 45=gsm7228ps.)

### B.3 `oid_map()`'s read-side emission rule (state.py ~679-693, 791-805)

```python
vlan_width = self.vlan_portlist_width or vlan_bitmap_width(model)
...
m[f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"] = ("OCTETSTR", encode_port_bitmap(vsim.configured, width_bytes=vlan_width))
m[f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"] = ("OCTETSTR", encode_port_bitmap(vsim.untagged, width_bytes=vlan_width))
```

Comment (verbatim intent): "Prefer the device's REAL fixed PortList width (live-measured, seeded on
`vlan_portlist_width`) so the mock is an INDEPENDENT source of truth for the wire width — not a re-derivation
of the same `vlan_bitmap_width()` formula the writer uses (that shared assumption is exactly why the mock
never caught issue #3)." **This is the crux of Topic B**: the mock's read side and the production writer must
NOT share one derivation path, or a writer bug that recomputes width wrong is invisible against a mock that
recomputes the SAME wrong way.

### B.4 `apply_write` (state.py ~1005-1035): the mock does NOT enforce width on writes — it just decodes what's sent

The write-application path (`_apply_write`'s `dot1qVlanStaticEgressPorts.<vid>`/`...UntaggedPorts.<vid>`
branches) does `decode_port_bitmap(_as_bytes(value))` on whatever bytes the SET PDU carried, with **no width
check or truncation guard of its own** — the comment is explicit: "A too-narrow PortList (the historical
writer bug) is faithfully truncating here: every member beyond the incoming byte width is silently dropped —
the exact silent VLAN corruption the GSM7252PS exhibits on hardware for an 8-byte SET against its 79-byte
PortList." I.e. the mock's job is to be a FAITHFUL passive receiver (accept whatever width was sent, replacing
the member set entirely with whatever that width decodes to) — it is the PRODUCTION WRITER's job to never
send a too-narrow SET in the first place. The mock catching the bug is an emergent property of (a) `oid_map()`
answering the real 79/131/45-byte width on subsequent reads regardless of what the writer sent, combined with
(b) a writer that (if buggy) sends an 8-byte SET, decodes to only the first 64 ports, and silently drops
everything above port 64 — a real regression the mock can now DETECT (via a subsequent get_vlans() losing
members) where before, with both sides sharing the same formula, it could not.

### B.5 The writer side: `snmp_write.py`'s `set_vlan_membership` RMW (the actual bug + actual fix)

```python
def _raw_bitmap(self, base_oid: str, vlan: int) -> bytes | None:
    """The device's own PortList octets for `vlan`, width intact.
    VLANInfo carries decoded port sets, so re-encoding from it would size
    the bitmap to the highest port in use rather than to the width the
    device actually uses. ... Returns None if the device did not report
    this VLAN as octets, so callers can fall back."""
    suffix = f".{vlan}"
    for row in self.client.walk(base_oid):
        if row.oid.endswith(suffix) and isinstance(row.value, bytes):
            return row.value
    return None

def set_vlan_membership(self, vlan, port, mode, *, force=False):
    ...
    # Feed set_port_bit the device's OWN bitmaps so it preserves their exact
    # wire width (that is what it is for); fall back to a re-encode of the
    # decoded sets only if the device did not report octets.
    raw_egress = self._raw_bitmap(oids.DOT1Q_VLAN_STATIC_EGRESS, vlan)
    raw_untagged = self._raw_bitmap(oids.DOT1Q_VLAN_STATIC_UNTAGGED, vlan)
    new_egress, new_untagged = membership_bitmaps(
        mode=mode, port=port,
        egress=(raw_egress if raw_egress is not None else encode_port_bitmap(before.member_ports)),
        untagged=(raw_untagged if raw_untagged is not None else encode_port_bitmap(before.untagged_ports)),
        width_bytes=vlan_bitmap_width(self.model),
    )
```

**The fix is a fresh WALK for the raw wire octets**, separate from (and in addition to) the already-performed
`get_vlans()` read used for the `before`/existence check: `_raw_bitmap` re-walks `dot1qVlanStaticEgressPorts`/
`...UntaggedPorts` and returns the LITERAL bytes the device just reported for this VLAN — untouched, at
whatever width the device actually uses — and `membership_bitmaps` (Go: `MembershipBitmaps`) flips exactly one
port's bit within THOSE bytes, so the SET PDU that goes out is exactly as wide as what came in.
`vlan_bitmap_width(self.model)` (the formula) is used ONLY as the fallback `width_bytes` for
`encode_port_bitmap` when `raw_egress`/`raw_untagged` is `None` (i.e. the device answered this VLAN as
something other than octets, or answered nothing at all) — it is NOT the primary width source anymore. This
is precisely the change: **prefer the freshly-walked raw device bytes; fall back to the formula only when raw
bytes are unavailable.**

### B.6 What Go slice-04's SNMP writer currently does (confirmed bug)

`snmp/writer_vlan.go` `SetVlanMembership` (lines 62-124), confirmed by direct read:

```go
width := VlanBitmapWidth(w.model.PortCount)
newEgress, newUntagged := MembershipBitmaps(
    EncodePortBitmap(before.MemberPorts, vlanEncodeWidth), // vlanEncodeWidth == 8, a CONSTANT
    EncodePortBitmap(before.UntaggedPorts, vlanEncodeWidth),
    port, mode, width,
)
```

This is EXACTLY the pre-fix Python shape (re-derive from the already-DECODED `before.MemberPorts`/
`UntaggedPorts` port sets via `EncodePortBitmap` at a throwaway 8-byte width, then widen to
`VlanBitmapWidth(w.model.PortCount)` — the FORMULA, never a raw wire read). **There is no `_raw_bitmap`
equivalent in Go today; `Writer` never calls `w.client.Walk` directly for this purpose (it goes through
`w.reader.GetVLANs`, which returns decoded `VLANInfo`, discarding the original octets entirely).**
`gsm7252ps` has `PortCount` 52 (physical), so `VlanBitmapWidth(52) = max(8, ceil(52/8)) = 8` bytes — versus
the model's REAL measured width of 79 bytes. **Once Topic B's virtual-mock fix lands (B.7) and the mock
starts answering the real 79-byte width, this Go writer will send an 8-byte SET, silently dropping every
member/untagged port above port 64 (e.g. the LAG pseudo-ports at ifIndex 418+) — this is the SAME historical
"issue #3" bug Python fixed, now live in Go's already-merged slice-04 code.** This is IN SCOPE for the
reconciliation, not just Topic B's mock: **the SNMP writer fix (B.5's `_raw_bitmap` equivalent) must land
alongside the mock-width fix, or `TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts`
(facade_write_integration_test.go:186, uses `gsm7252ps` VLAN 90) will start failing the moment the mock seed
gains its real 79-byte width** — this test is currently passing only because BOTH sides (mock's `OIDMap` via
`snmp.VlanBitmapWidth(m.PortCount)` and the writer via the same formula) already share the identical
(wrong-vs-hardware) 8-byte derivation, so they're self-consistent today, masking the bug exactly the way
Python's OLD code did before this exact fix landed there.

### B.7 Go rework guidance

**B.7.1 — `virtual.State`**: add `VlanPortlistWidth int` (Go convention: `0` = unmeasured/unset, mirroring
`vlan_portlist_width: int | None = None`; Go has no natural `nil` for a plain `int` field without a pointer,
and `0` is never a legitimate byte width, so `0`-as-sentinel is safe and idiomatic here — simpler than adding
a `*int`). Doc-comment it verbatim per B.1's Python comment (measured widths, why it exists, the issue-#3
callback).

**B.7.2 — `virtual/seed.go`**: set `VlanPortlistWidth: 79` in `SeedGSM7252PS`, `45` in a Go `SeedGSM7228PS`
(does this seed exist in Go yet? confirm — this dossier only directly read `SeedGSM7252PS`'s body in full;
`seed.go`'s file header lists `SeedGSM7228PS` among the ported functions, so it should already exist —
locate and add the field), `131` in `SeedM4300_24X` and `SeedM4300_16X`. Leave `SeedGS110EMX`/`SeedGS305EP`/
`SeedGS105PE`/`SeedGS728TPP` at the Go zero value (unset).

**B.7.3 — `virtual/state_oidmap.go`'s `OIDMap`**: change

```go
vlanWidth := snmp.VlanBitmapWidth(m.PortCount)
```

to

```go
vlanWidth := s.VlanPortlistWidth
if vlanWidth == 0 {
    vlanWidth = snmp.VlanBitmapWidth(m.PortCount)
}
```

— the exact `self.vlan_portlist_width or vlan_bitmap_width(model)` fallback chain (B.3), just with Go's
`0`-sentinel instead of Python's `None`-sentinel truthy-`or`.

**B.7.4 — `virtual/state.go`'s `ApplyWrite`**: NO CHANGE NEEDED — confirmed by B.4, the mock's write-apply
path already just decodes whatever bitmap width was sent (`snmp.DecodePortBitmap(asBytes(oid, value))`,
`state.go` lines 662/670) with no width enforcement of its own; that is correct AS-IS and matches Python's
"faithful passive receiver" behavior exactly. Do not add width validation here — the mock accepting a
too-narrow SET (and thereby losing members on the next read) is the INTENDED regression signal, not a bug to
suppress.

**B.7.5 — `snmp/writer_vlan.go`'s `SetVlanMembership`**: this is the scope-creep item flagged by the task
brief, confirmed necessary by B.6. Add a `rawBitmap` helper mirroring `_raw_bitmap`:

```go
// rawBitmap returns the device's own PortList octets for vlanID under
// baseOID (Dot1qVlanStaticEgress or Dot1qVlanStaticUntagged), width intact,
// via a fresh Walk -- NOT re-derived from already-decoded VLANInfo port
// sets, which would size the bitmap to the highest member rather than the
// device's real fixed width. Returns nil if the device didn't report this
// VLAN as an octet-string row, so the caller can fall back to a formula-
// derived encode. Mirrors Python's SnmpWriter._raw_bitmap.
func (w *Writer) rawBitmap(ctx context.Context, baseOID string, vlanID int) ([]byte, error) {
    rows, err := w.client.Walk(ctx, baseOID)
    if err != nil {
        return nil, err
    }
    suffix := fmt.Sprintf(".%d", vlanID)
    for _, row := range rows {
        if strings.HasSuffix(row.OID, suffix) {
            if b, ok := row.Value.([]byte); ok {
                return b, nil
            }
        }
    }
    return nil, nil
}
```

Then in `SetVlanMembership`, replace the `EncodePortBitmap(before.MemberPorts, vlanEncodeWidth)`/
`...UntaggedPorts...` re-derivation with:

```go
rawEgress, err := w.rawBitmap(ctx, Dot1qVlanStaticEgress, vlanID)
if err != nil { return err }
rawUntagged, err := w.rawBitmap(ctx, Dot1qVlanStaticUntagged, vlanID)
if err != nil { return err }
if rawEgress == nil {
    rawEgress = EncodePortBitmap(before.MemberPorts, vlanEncodeWidth)
}
if rawUntagged == nil {
    rawUntagged = EncodePortBitmap(before.UntaggedPorts, vlanEncodeWidth)
}
width := VlanBitmapWidth(w.model.PortCount) // fallback formula, now ONLY used when raw bytes are unavailable
newEgress, newUntagged := MembershipBitmaps(rawEgress, rawUntagged, port, mode, width)
```

Note `MembershipBitmaps`' own `width` parameter becomes vestigial in the common case (both raw bitmaps
present, already at the device's real width — `MembershipBitmaps` should not re-widen/shrink an
already-correctly-sized input; confirm its internal behavior when `len(egress) != width` before relying on
this — re-read `snmp/write.go:86`'s `MembershipBitmaps` body during implementation to confirm it treats an
already-wide-enough input as a no-op resize, not a truncate-to-`width`).

**B.7.6 — `snmp/write.go`'s `VlanBitmapWidth` callers**: after B.7.5, `VlanBitmapWidth` is called from exactly
two places that matter to this reconciliation: `virtual/state_oidmap.go`'s `OIDMap` (now only as B.7.3's
fallback) and `snmp/writer_vlan.go`'s `SetVlanMembership` (now only as B.7.5's fallback). Both fallbacks are
correct and should remain — `VlanBitmapWidth` itself is NOT wrong, it's a legitimate physical-port-only
estimate for a model with no measured width; the bug was always about PREFERRING it over real data when real
data exists. Grep `VlanBitmapWidth(` across the whole Go tree before implementing, to confirm no OTHER call
site (e.g. `snmp/reader.go`, any CLI/HTTP-adjacent code) also needs the same raw-preferred/formula-fallback
treatment — this dossier only confirmed the two call sites above.

**B.7.7 — files that change**: `virtual/state.go` (new field only, B.7.1), `virtual/seed.go` (4 seed
functions gain one field each, B.7.2), `virtual/state_oidmap.go` (`OIDMap`'s `vlanWidth` line, B.7.3),
`snmp/writer_vlan.go` (`SetVlanMembership`'s RMW, B.7.5) — **`snmp/write.go` itself does NOT need to change**
(`VlanBitmapWidth`/`MembershipBitmaps`/`EncodePortBitmap` are all still correct primitives; only their CALLERS'
preference order changes).

### B.8 Python tests pinning this behavior (grepped, `tests/virtual/test_virtual_snmp_face.py`)

Two call sites (lines ~244-252 and ~408-412), both asserting the SAME pattern against `gsm7252ps`:

```python
oid = f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90"
expected_bitmap = encode_port_bitmap(
    vlan90.member, width_bytes=sw.state.vlan_portlist_width
).encode("latin-1")
rows = asyncio.run(client.get([oid]))
assert rows == [SnmpRow(oid, expected_bitmap, "Hex-STRING")]
```

Comment: "the mock emits the device's REAL fixed PortList width (79 B, live-measured), so derive the expected
at that seeded width, still straight from the seed." — i.e. the test computes its own expected bitmap width
FROM `sw.state.vlan_portlist_width` (not from a formula), so it would catch a regression to formula-derived
width directly. **Go's `virtual` package test suite has no equivalent assertion today** (confirmed by this
dossier's read of `virtual/state_oidmap.go`/`state.go`/`seed.go` — no test file was read in full during this
pass; the implementer should add a Go analogue, likely in a `virtual/state_oidmap_test.go` or
`virtual/seed_test.go`, asserting `OIDMap()`'s egress/untagged bitmap for `gsm7252ps` VLAN 90 is exactly
79 bytes, not `VlanBitmapWidth(52)`'s 8 bytes).

### B.9 The live round-trip test pinning the WRITER fix (`tests/virtual/test_snmp_write_face.py:337`)

`test_snmp_writer_set_vlan_membership_live_preserves_other_ports` — drives `SnmpWriter.set_vlan_membership`
against a live `VirtualSwitch(model="gsm7252ps")` over the real (mock-served) wire, moves port 6 into VLAN 90
as TAGGED, and asserts every OTHER port's membership survives untouched (`after.member_ports - {6} ==
before.member_ports`, etc.). This test is the Python analogue of Go's
`TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts` (B.6) and is the concrete
regression-catcher for B.5/B.7.5's fix: it passes at 1841111 specifically BECAUSE `_raw_bitmap` preserves the
seeded 79-byte width through the RMW; it would FAIL against the pre-fix writer shape Go currently has, the
moment the mock's `oid_map()`/`OIDMap()` starts answering 79 bytes instead of 8.

### B.10 Cross-check: is `set_vlan_membership`'s fastpath-switchport branch (M4300s) affected?

No — `snmp_write.py`'s `set_vlan_membership` branches FIRST on `self.model.snmp_vlan_write ==
"fastpath_switchport"` (→ `_set_vlan_switchport`, an entirely different vendor-table code path that never
touches `dot1qVlanStaticEgressPorts`/`...UntaggedPorts` bitmaps or `_raw_bitmap` at all) BEFORE reaching the
`_raw_bitmap`-based Q-BRIDGE path this dossier documents. The M4300s (`vlan_portlist_width=131`) use the
switchport path in production, so their 131-byte measured width is consumed only by `oid_map()`'s STATIC
Q-BRIDGE mirror columns (still real, still worth seeding correctly per B.7.2 for read-side fidelity/parity
tests), not by any write-side RMW. **`gsm7252ps` (79B) and `gsm7228ps` (45B) are the two models where the
`_raw_bitmap` writer fix in B.5/B.7.5 is load-bearing for actual write correctness** — confirm Go's
`snmp.Writer.model.SnmpVlanWrite`-equivalent gate (if the Go registry has one — re-verify field name in
`model/registry.go`) is checked BEFORE the new `rawBitmap` logic, exactly mirroring this branch order, so the
M4300 switchport path is untouched by B.7.5's edit.

---

## Trickiest traps (10 lines)

1. **A.3/A.4**: `requested = backend or self.backend` is computed TWICE (once inside the public
   `resolve_backend()`, once directly in `_read`/`_write`) — the SECOND computation (not the raw per-call arg)
   is what flows into `_cannot_serve` for message-shape selection, so a session pinned via `backend=` at
   construction makes EVERY op read as "explicitly requested" (no hint) even when the per-call arg was `None`.
2. **A.6**: two DIFFERENT failure shapes exist per op — `resolveBackend` failing (model lacks the named
   backend at all; no "chosen" backend, no `_cannot_serve` wrapping) vs. the chosen backend's op itself
   failing (`_cannot_serve`-wrapped, names `chosen` plus the underlying `exc`). Don't conflate their messages.
3. **A.6**: the "pass backend=Backend.<X|Y>" hint appears ONLY when `requested is None` AND `others` is
   non-empty; a single-backend model degrading gets no hint at all (empty string, not even a period).
4. **A.9**: `snapshot()` now resolves ONE backend for the WHOLE call — a field that backend can't serve
   degrades to empty and is NEVER filled from a second backend, even if one was injected/available. Go's
   existing `TestSnapshot_..._FallsThroughToSecondBackend` tests exactly the removed behavior.
5. **A.7**: `delete_vlan`'s facade guard now reads `get_vlans` over the SAME `backend` the delete itself uses
   — new plumbing, not present in Go's current `guardVLANDeleteMembers`.
6. **B.1/B.3**: the mock's `oid_map()`/`OIDMap()` must treat `vlan_portlist_width`/`VlanPortlistWidth` as an
   INDEPENDENT source of truth from the production writer's own width derivation — sharing one formula on
   both sides is exactly how "issue #3" went undetected for months.
7. **B.4**: the mock's `ApplyWrite` deliberately does NOT enforce/validate width on incoming SETs — it just
   decodes whatever bytes arrived, silently truncating membership above the incoming width. This is a FEATURE
   (the regression detector), not a bug to "fix" by adding width validation.
8. **B.5/B.6**: the writer fix is "read the RAW device octets via a fresh Walk, mutate one bit in place,
   write back" — NOT "read decoded VLANInfo, re-encode at the model's formula width." Go's slice-04 writer
   currently does the latter and is bugged the same way pre-fix Python was.
9. **B.6**: this bug is CURRENTLY MASKED in Go because both the mock (`OIDMap`) and the writer
   (`SetVlanMembership`) independently call the SAME `VlanBitmapWidth(m.PortCount)` formula — fixing ONLY the
   mock's width (B.7.1-B.7.3) without ALSO fixing the writer (B.7.5) will make
   `TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts` and any new width-assertion test
   fail. Both fixes must land together (or the writer fix must land first/atomically).
10. **B.10**: the M4300 fastpath-switchport VLAN-write path never touches the Q-BRIDGE bitmap columns at all
    — confirm the Go writer's switchport-vs-Q-BRIDGE branch order is preserved so B.7.5's edit doesn't
    accidentally reach into the switchport code path.

---

## Completeness checklist

**Topic A**
- [ ] `_dispatch.resolve_backend` ported as a Go free function (`resolveBackend`), both error messages
      verbatim (mod A.10.6's lowercase decision), used by BOTH `readVia`/`writeVia` and a new
      `Switch.ResolveBackend`.
- [ ] `Switch.backend *model.Backend` field + `WithBackend` option added.
- [ ] `readVia`/`writeVia` rewritten to single-backend dispatch (A.10.1); loop/skip/reraise-last code deleted.
- [ ] `cannotServe` helper added, both message branches, `%w`-wraps the underlying capability error.
- [ ] Per-call backend override added: `ReadOption`/`WithReadBackend` (reads, variadic) + `Write.Backend`
      field (writes, struct field) — per A.10.3's asymmetric-but-justified decision.
- [ ] All 9 read methods (switch.go) + `Snapshot` (snapshot.go, re-read first) + all 9 write methods
      (switch_write.go) updated to accept/thread the backend override.
- [ ] `guardVLANDeleteMembers` threads the delete's own resolved backend into its internal `GetVLANs` call
      (A.10.7/A.7).
- [ ] `Identify`/`NSDPDevice` confirmed unchanged (A.7) — no edits, just re-verify after the `Switch` struct
      grows a `backend` field that neither method should consult.
- [ ] `backend_snmp.go`/`backend_nsdp.go` confirmed unchanged (A.5/A.11) — no edits.
- [ ] All `TestReadVia_*` (10) and `TestWriteVia_*` (11) tests rewritten or replaced with resolution-shape
      tests (A.12).
- [ ] `TestSnapshot_DegradesUnsupportedFieldsToEmptyAndFallsThroughToSecondBackend` rewritten: PoE degrades to
      empty, not HTTP-filled (A.9/A.12).
- [ ] `TestFacadeIntegration_GS110EMXNSDPServesReadsHTTPStillDegrades`'s comment corrected (A.12); assertions
      re-verified.
- [ ] `TestFacadeNSDPIntegration_GS110EMXUnsupportedReadsRaise`/`...GS305EPUnsupportedReadsRaise` re-verified
      (not fully read this pass).
- [ ] New Go tests added mirroring A.8's Python tests: explicit-backend-needed-for-a-gap
      (`test_gs305ep_poe_needs_an_explicit_http_backend`), requested-backend-never-substituted, default-backend
      pinning via `WithBackend`, deterministic default-resolution-per-model.

**Topic B**
- [ ] `virtual.State` gains `VlanPortlistWidth int` (0 = unmeasured), doc-commented per B.1/B.7.1.
- [ ] `SeedGSM7252PS`→79, `SeedGSM7228PS`→45, `SeedM4300_24X`→131, `SeedM4300_16X`→131 (B.7.2); confirm
      `SeedGSM7228PS` exists in Go `seed.go` (only `SeedGSM7252PS` was read in full this pass).
      Plus-class/no-vendor seeds left at 0/unset.
- [ ] `virtual/state_oidmap.go`'s `OIDMap` prefers `s.VlanPortlistWidth`, falls back to
      `snmp.VlanBitmapWidth(m.PortCount)` only when 0 (B.7.3).
- [ ] `virtual/state.go`'s `ApplyWrite` left UNCHANGED (B.7.4) — do not add width validation there.
- [ ] `snmp/writer_vlan.go`'s `SetVlanMembership` gains a `rawBitmap`/`_raw_bitmap`-equivalent Walk-based
      fetch, preferring raw device octets over `EncodePortBitmap(before.MemberPorts, ...)` re-derivation;
      `VlanBitmapWidth` demoted to fallback-only (B.7.5).
- [ ] Confirmed the M4300 fastpath-switchport VLAN-write branch (if present in Go) is untouched by the
      `rawBitmap` edit (B.10) — verify Go model registry's switchport-vlan-write gate/field name.
- [ ] `MembershipBitmaps`' behavior on an already-correctly-wide input re-read/confirmed (not a
      truncate-to-formula-width surprise) before relying on it in B.7.5's call (flagged, unresolved in this
      pass).
- [ ] New Go test(s) asserting `OIDMap()`'s VLAN egress/untagged bitmap width for `gsm7252ps` is 79 bytes
      (not `VlanBitmapWidth(52)`'s 8), mirroring `test_virtual_snmp_face.py`'s two call sites (B.8).
- [ ] `TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts` re-verified passing AFTER
      both the mock-width fix AND the writer fix land together (B.6/B.9) — do not land one without the other.
- [ ] Grep every `VlanBitmapWidth(` call site in the Go tree (only 2 confirmed this pass: `OIDMap`,
      `SetVlanMembership`) to rule out a third caller needing the same treatment (B.7.6).

**General**
- [ ] `snapshot.go` re-read in full before implementation (referenced but not read this pass) to confirm its
      current per-field dispatch shape and update it for both the backend-override plumbing (Topic A) and to
      re-confirm it needs no Topic B changes.
- [ ] Re-verify `model/registry.go`'s `gsm7252ps` backend set includes `BackendSSH` before porting
      `test_default_backend_resolution_is_deterministic`'s `resolve_backend(Backend.SSH)` assertion verbatim
      (spot-checked as likely-true, not exhaustively confirmed).
