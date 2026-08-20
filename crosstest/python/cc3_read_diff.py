#!/usr/bin/env python3
"""cc3_read_diff.py -- CC3's Python-lib-vs-Go-fake differential driver.

Run by the PINNED Python reference implementation's own venv interpreter
(never system Python -- see the caller, test/crosslang/python_driver_test.go,
for the exact absolute path), this is the Python-side half of CC3: Python's
library reading BOTH a running Go virtual-switch fake (over the real wire --
SNMP/NSDP/HTTP sockets, FASTPATH CLI over telnet) AND Python's OWN in-process
VirtualSwitch fake for the SAME model, then deep-comparing the two readings
for every (backend, operation) triple the caller hands it. There is no
hardcoded expectation table anywhere in this file: every assertion is
Python-object-to-Python-object equality, so any inequality is a genuine
Go-fake-vs-Python-fake fidelity divergence -- the entire point of this slice.

Protocol
--------
Reads ONE JSON object from stdin::

    {
      "model": "<registry model key>",
      "go": {
        "host": "127.0.0.1",
        "snmp_port": 12345, "nsdp_port": 0, "http_port": 12346,
        "ssh_port": 12347, "telnet_port": 12348,
        "community": "public", "http_password": "password"
      },
      "cli_username": "admin", "cli_password": "password",
      "triples": [
        {"backend": "snmp", "op": "get_ports"},
        {"backend": "telnet", "op": "get_users", "expected": [...]}
      ]
    }

A Go endpoint port of 0 means the Go fake does not serve that backend (mirrors
virtual.Endpoints' own convention on the Go side); this driver only builds a
client for a backend whose port is nonzero. ``ssh_port`` is accepted but
NEVER used to build a client -- see ``build_go_switch``'s own docstring for
why this driver is telnet-only for the CLI backend.

A triple carrying an ``expected`` key (test/crosslang/python_driver_test.go's
``referenceUnavailableInPythonFake`` set) is Go's OWN library's reading of
its OWN fake, already JSON-marshalled field-for-field compatible with the
matching Python dataclass -- see ``process_reference_unavailable_triple``'s
own docstring for why and how this driver substitutes a READER-PARITY check
(Python-lib(Go-fake) == Go-lib(Go-fake)) for the normal fidelity differential
on exactly these triples, and how it stays self-verifying rather than a
silent, permanent exception.

Writes a JSON ARRAY to stdout, one entry per input triple, in the same order::

    [{"backend": "snmp", "op": "get_ports", "equal": true,
      "go": "<repr of the normalized Go-fake reading>",
      "py": "<repr of the normalized Python-fake reading>",
      "error": null}, ...]

Exits 0 iff every entry has ``equal: true`` and ``error: null`` AND the
output array's length equals the input triple list's length (this driver
NEVER silently drops a triple -- a truncated output on a 0 exit would be
exactly the vacuous-pass failure mode this differential exists to prevent).
Any uncaught exception before the JSON array is written (e.g. the reference
VirtualSwitch fails to start, or a JSON parse error) propagates as an
ordinary Python traceback on stderr and a nonzero exit with NO JSON on
stdout at all -- the caller treats "stdout is not valid JSON" as its own
fail-loudly signal that this driver could not even get started.
"""

from __future__ import annotations

import contextlib
import dataclasses
import enum
import json
import sys
from typing import Any, Callable

# Operations whose result this driver KNOWS must be non-empty for every
# model this suite's caller ever asks about: every hand-authored seed on
# BOTH sides (virtual/seed.go and virtual/seed.py) gives every seeded model
# at least one port and at least VLAN 1 (cross-checked against
# test/crosslang/opmap.go's own portRowsWant/vlanIDsExpected tables, which
# this driver deliberately does NOT import -- that would be exactly the
# hardcoded expectation table this differential design forbids). An empty
# result for either of these two ops, on EITHER fake, is never a legitimate
# reading here: it is either a broken connection or a broken read that
# happens to agree on producing nothing, which is precisely the vacuous
# "[] == []" pass this driver's non-vacuity guard exists to catch.
_NEVER_EMPTY_OPS = frozenset({"get_ports", "get_vlans"})

# (model_key, backend) pairs whose get_stats `rx_packets`/`tx_packets`
# fields are EXCLUDED from the equality check, for EVERY port row -- gate-2
# hardware verification finding (2026-08-20).
#
# Root cause: Go's fake (virtual/seed.go's SeedM4300_24X) was fixed during
# gate-2 to serve real captured RxUcast/TxUcast (unicast packet counters)
# for every m4300-24x port. The data was not invented: it came from the
# SAME already-committed virtual/testdata/captures/m4300-24x.json this
# seed's rx_bytes/tx_bytes/rx_errors/tx_errors already transcribe -- that
# capture's own "stats" section already carried rx_packets/tx_packets for
# every port, simply never wired into the seed before. Real hardware
# always answers these counters (gate-2 live-verified, port 1:
# rx_packets~=20455434750, tx_packets~=18675057818 -- a larger, later
# snapshot than the committed capture's, exactly what a live incrementing
# counter looks like weeks on), matching every other read op this model
# already served real, non-nil data for (PoE, LLDP, etc). The pinned
# Python reference fake's own seed_m4300_24x is READ-ONLY from this repo
# and carries the IDENTICAL omission Go's fake is now fixed away from, so
# it still answers None (SNMP/HTTP) or 0 (CLI, where the parser's own
# honest-zero-vs-absent convention differs) for rx_packets/tx_packets on
# every port and every backend -- a DOCUMENTED
# Go-fake-ahead-of-Python-fake gap, not a Go regression.
#
# EVERY OTHER FIELD of every row (port, rx_bytes, tx_bytes, rx_errors,
# tx_errors) stays fully compared -- a regression there still fails
# normally. Self-verifying: process_triple checks (before stripping)
# whether the whole table already matches WITHOUT the exclusion, and fails
# loudly if so.
_KNOWN_STATS_PACKETS_DIVERGENCE: frozenset[tuple[str, str]] = frozenset(
    {
        ("m4300-24x", "snmp"),
        ("m4300-24x", "http"),
        ("m4300-24x", "telnet"),
    }
)


def _strip_stats_packet_fields(rows: Any) -> Any:
    """Drop `rx_packets`/`tx_packets` from every row in `rows` (a
    normalized get_stats list of dicts) -- see
    _KNOWN_STATS_PACKETS_DIVERGENCE's own doc comment. Unlike the LLDP
    exclusions above, this applies to EVERY row unconditionally (no
    per-port allowlist): the divergence affects every port on an affected
    (model_key, backend) pair, not a handful of specific ones."""
    if not isinstance(rows, list):
        return rows
    out = []
    for row in rows:
        if isinstance(row, dict):
            row = {k: v for k, v in row.items() if k not in ("rx_packets", "tx_packets")}
        out.append(row)
    return out


# (model_key, backend) -> the exact set of LLDP `local_port` rows whose
# `remote_port_id` is EXCLUDED from the get_lldp equality check -- ORIGINALLY
# a controller triage decision on the CC3 delivery report's finding #1
# (2026-08-18), RE-TRIAGED during gate-2 hardware verification (2026-08-20)
# now that real ground truth exists.
#
# Root cause, UPDATED: two committed real captures --
# webui/testdata/http/m4300_lldpRemoteInventory.html (row 1.2.11, PortId
# "E4:5F:01:8D:F4:FD") and
# fastpath/testdata/cli/m4300_24x_show_lldp_remote_device_all.txt (port
# 1/0/9, Port ID "1C:34:DA:42:E8:8D") -- prove real hardware renders a
# MAC-address-subtype LLDP Port ID as UPPERCASE COLON-HEX, the same as
# Chassis ID, never as raw bytes. Go's fake (virtual/web_gsm7252ps.go's
# lldpPortIDText/isMACShapedLLDPID, virtual/cliface_render.go's renderLLDP)
# was fixed to match during gate-2 and now does this correctly on every
# backend, including telnet/CLI (not just HTTP -- see the m4300-24x/telnet
# entry added below, alongside the pre-existing m4300-24x/http one). The
# PINNED PYTHON REFERENCE FAKE this driver diffs against is READ-ONLY from
# this repo and has NOT been fixed to match: its LldpSim.port_id for these
# rows still round-trips as raw, non-ASCII/binary bytes (e.g. the 6 bytes
# 88:A2:9E:80:87:01, mangled further by an unrelated UTF-8 re-encode on
# faces/http.py's `Handler._send`). This is therefore now a DOCUMENTED
# Go-fake-ahead-of-Python-fake fidelity gap, not an ambiguity pending a
# hardware capture (the prior comment here, before that capture existed)
# -- Go's fake is the one grounded in real hardware; the pinned Python
# fake is the one that has drifted from it.
#
# EVERY OTHER FIELD of these same rows (local_port, remote_sys_name,
# remote_port_desc, remote_chassis_id), and EVERY OTHER ROW of the same
# get_lldp table (e.g. m4300-24x/http local_port 2, whose plain-text
# "1/0/49" Port ID already matches and stays fully compared), is UNCHANGED
# by this exclusion -- a regression anywhere else in the same triple still
# fails it. Self-verifying: process_triple additionally checks (BEFORE
# stripping) whether remote_port_id has, in the meantime, come to match
# WITHOUT the exclusion; if it has, this table is stale and the triple
# fails loudly instead of silently carrying a no-longer-needed exception
# forever.
_KNOWN_LLDP_PORT_ID_DIVERGENCE: dict[tuple[str, str], frozenset[int]] = {
    ("m4300-24x", "http"): frozenset({1, 6}),
    ("m4300-24x", "telnet"): frozenset({1, 6}),
    ("m4300-16x", "telnet"): frozenset({16}),
}

# (model_key, backend) -> the exact set of LLDP `local_port` rows whose
# `remote_sys_name` is ALSO excluded from the get_lldp equality check, ON
# TOP OF remote_port_id (already excluded for the same rows by
# _KNOWN_LLDP_PORT_ID_DIVERGENCE above) -- gate-2 hardware verification
# finding (2026-08-20), discovered as a side effect of fixing Go's LLDP
# Port ID rendering (see that map's own doc comment for the base fix).
#
# Root cause: m4300-16x's own seed data for local_port 16's raw MAC-shaped
# LLDP ids (virtual/seed.go's SeedM4300_16X, and the pinned Python fake's
# matching seed_m4300_16x) happens to carry the raw byte 0x0A (ASCII LF)
# as the SECOND octet of its Port ID (00:0A:FA:24:28:1F). BEFORE the gate-2
# fix, Go's own FASTPATH CLI renderer (cliface_render.go's renderLLDP) also
# wrote that raw byte sequence verbatim into a fixed-width text table cell
# -- so the embedded LF split THAT row across two physical lines on the
# wire on BOTH fakes identically, and both readers derived the same
# (accidentally-corrupted) remote_sys_name, which is why this divergence
# was invisible before the fix (this exact row's `equal` check passed on
# remote_sys_name purely by both sides being equally broken). Go's fake
# now renders this value as clean printable hex ("00:0A:FA:24:28:1F", no
# embedded control byte -- see _KNOWN_LLDP_PORT_ID_DIVERGENCE), so its own
# row never breaks and remote_sys_name reads correctly. The pinned Python
# reference fake's telnet CLI renderer is unfixed and still emits the raw,
# LF-embedding bytes, so ITS row still splits and its own reader still
# recovers no system name (empty/None) for this row. A genuine
# Go-fake-ahead-of-Python-fake fidelity gap, not a Go regression: the two
# fakes now genuinely disagree on this field, for a well-understood reason,
# and Go's answer is the one a real device's clean text rendering would
# produce.
#
# EVERY OTHER FIELD of this row, and every other row of the same table, is
# UNCHANGED by this exclusion. Self-verifying exactly like
# _KNOWN_LLDP_PORT_ID_DIVERGENCE: process_triple checks (before stripping)
# whether remote_sys_name has, in the meantime, come to match WITHOUT this
# exclusion too, and fails loudly if so.
_KNOWN_LLDP_SYSNAME_DIVERGENCE: dict[tuple[str, str], frozenset[int]] = {
    ("m4300-16x", "telnet"): frozenset({16}),
}


def _strip_excluded_lldp_field(rows: Any, affected_ports: frozenset[int], field: str) -> Any:
    """Drop `field` from every row in `rows` (a normalized get_lldp list of
    dicts) whose `local_port` is in `affected_ports`. Every other row, and
    every other field of an affected row, passes through unchanged -- the
    shared mechanism behind both _KNOWN_LLDP_PORT_ID_DIVERGENCE (field=
    "remote_port_id") and _KNOWN_LLDP_SYSNAME_DIVERGENCE (field=
    "remote_sys_name"); see each map's own doc comment."""
    if not isinstance(rows, list):
        return rows
    out = []
    for row in rows:
        if isinstance(row, dict) and row.get("local_port") in affected_ports:
            row = {k: v for k, v in row.items() if k != field}
        out.append(row)
    return out


# Unique sentinel for _row_field: a field that is genuinely absent from a
# row must never compare equal to one that is present but happens to be
# None/empty -- see _row_field's own docstring.
_MISSING = object()


def _row_field(rows: Any, local_port: int, field: str) -> Any:
    """Return `field` off the (normalized get_lldp) row whose local_port
    matches, or the _MISSING sentinel if no such row or field exists.
    Powers the PER-FIELD staleness checks in process_triple: comparing one
    named field of one named row in isolation, rather than the whole
    table, so one exclusion's staleness check cannot be masked by an
    unrelated, still-genuinely-excluded field on the SAME row (exactly the
    m4300-16x/telnet local_port 16 situation, where both
    _KNOWN_LLDP_PORT_ID_DIVERGENCE and _KNOWN_LLDP_SYSNAME_DIVERGENCE
    apply to the same row for two independent reasons)."""
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and row.get("local_port") == local_port:
                return row.get(field, _MISSING)
    return _MISSING


def _normalize(value: Any) -> Any:
    """Recursively turn a facade return value into a plain, order-independent,
    JSON-comparable structure: dataclasses -> dicts (by field name), Enums ->
    their `.value`, and every list/tuple/frozenset -> a list sorted by its own
    canonical JSON form.

    The sort is deliberate and load-bearing: two independently hand-authored
    fakes (Go's and Python's own) are not guaranteed to enumerate rows in the
    same order for the same protocol (e.g. dict/hashmap iteration order), and
    none of the public dataclasses this driver compares (models.py,
    protocols/nsdp/types.py) document an ordering contract. Sorting makes the
    comparison robust to that non-signal while still failing on any REAL
    content difference -- a missing row, an extra row, or a wrong field
    value on an otherwise-matching row.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _normalize(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        # Reached for an "expected" value straight off JSON (Go's own
        # library reading, already marshalled field-for-field compatible
        # with the matching Python dataclass) rather than a live Python
        # object -- recurse into values so it normalizes exactly like the
        # dataclass case above would.
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (frozenset, set)):
        items = [_normalize(v) for v in value]
        items.sort(key=lambda v: json.dumps(v, sort_keys=True, default=str))
        return items
    if isinstance(value, (list, tuple)):
        items = [_normalize(v) for v in value]
        items.sort(key=lambda v: json.dumps(v, sort_keys=True, default=str))
        return items
    return value


# op name -> how to invoke it on a SyncSwitch. Every entry but "nsdp_device"
# forces the read over the caller-named `backend` (matching how
# test/crosslang/opmap.go's readOps drives netgearswitch.Switch with
# WithReadBackend); nsdp_device bypasses per-op backend dispatch entirely on
# the real facade too (SyncSwitch.nsdp_device takes no backend argument at
# all -- see its own docstring in sync_api.py), so this table mirrors that
# exactly rather than inventing a backend parameter the facade does not have.
def _dispatch(sw: Any, backend: Any, op_name: str) -> Any:
    if op_name == "nsdp_device":
        return sw.nsdp_device()
    method = getattr(sw, op_name)
    return method(backend=backend)


def build_reference_switch(model: Any, cleanup: list[Callable[[], None]]) -> Any:
    """Build the REFERENCE SyncSwitch: reads Python's OWN in-process
    VirtualSwitch fake for `model`, via the exact injection pattern
    tests/equivalence.py's facades_for/http_facades_for use against a live
    VirtualSwitch -- one client per backend the model registers, all
    injected so no implicit client-construction path (host-string dispatch,
    password resolution) is ever exercised here.
    """
    from netgear_switch.protocols.http.endpoints import http_spec
    from netgear_switch.registry import Backend
    from netgear_switch.sync_api import SyncSwitch
    from netgear_switch.transport.http.client import HttpClient
    from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
    from netgear_switch.virtual.server import VirtualSwitch

    vsw = VirtualSwitch(model.key)
    vsw.start()
    cleanup.append(vsw.stop)

    kwargs: dict[str, Any] = {}
    if Backend.SNMP in model.backends:
        client = NetsnmpCliClient(f"{vsw.host}:{vsw.port}", vsw.community)
        kwargs["snmp_client"] = client
        kwargs["snmp_community"] = vsw.community
    if Backend.NSDP in model.backends:
        nsdp = UdpNsdpClient(vsw.host, client_port=0, server_port=vsw.port)
        kwargs["nsdp_client"] = nsdp
    if Backend.HTTP in model.backends:
        spec = http_spec(model)
        http_client = HttpClient(f"{vsw.host}:{vsw.http_port}", vsw.http_password, spec, secure=False)
        cleanup.append(http_client.close)
        kwargs["http_client"] = http_client
    if {Backend.SSH, Backend.TELNET} & model.backends:
        # In-process: no socket, no transport to close (VirtualCliFace wraps
        # the SAME VirtualSwitchState vsw.start() already seeded).
        kwargs["cli_client"] = vsw.cli_session()

    return SyncSwitch(model, vsw.host, **kwargs)


def build_go_switch(
    model: Any,
    go_ep: dict[str, Any],
    cli_username: str,
    cli_password: str,
    cleanup: list[Callable[[], None]],
) -> Any:
    """Build the Go-fake-reading SyncSwitch: one client per backend `go_ep`
    reports a nonzero port for, pointed at the REAL Go virtual-switch fake's
    announced endpoint.

    CLI reads are driven over TELNET ONLY, never SSH, even for models
    go_ep reports a nonzero ssh_port for: this pinned venv has no paramiko
    installed (checked, not guessed -- `import paramiko` fails), and this is
    a READ-ONLY pinned snapshot of the Python reference implementation this
    driver must never modify to add a dependency it doesn't already carry.
    telnetlib's ShellDriver is the SAME parser/session-setup code SSH would
    use (transport/cli/telnet.py reuses transport/cli/session.py's
    ShellDriver, exactly like transport/cli/ssh.py does), so CLI fidelity is
    still fully exercised for every FASTPATH model here -- only the transport
    differs. See test/crosslang/python_driver_test.go's own doc comment for
    how the caller structurally excludes SSH-backend triples entirely (never
    silently skips them) so this never produces a false "0 results" gap.
    """
    from netgear_switch.protocols.cli.commands import cli_spec
    from netgear_switch.protocols.http.endpoints import http_spec
    from netgear_switch.sync_api import SyncSwitch
    from netgear_switch.transport.cli.telnet import TelnetCliTransport
    from netgear_switch.transport.http.client import HttpClient
    from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    host = go_ep["host"]
    kwargs: dict[str, Any] = {}
    if go_ep.get("snmp_port"):
        client = NetsnmpCliClient(f"{host}:{go_ep['snmp_port']}", go_ep["community"])
        kwargs["snmp_client"] = client
        kwargs["snmp_community"] = go_ep["community"]
    if go_ep.get("nsdp_port"):
        nsdp = UdpNsdpClient(host, client_port=0, server_port=go_ep["nsdp_port"])
        kwargs["nsdp_client"] = nsdp
    if go_ep.get("http_port"):
        spec = http_spec(model)
        http_client = HttpClient(f"{host}:{go_ep['http_port']}", go_ep["http_password"], spec, secure=False)
        cleanup.append(http_client.close)
        kwargs["http_client"] = http_client
    if go_ep.get("telnet_port"):
        transport = TelnetCliTransport(
            host, cli_username, cli_password, cli_spec(model), port=go_ep["telnet_port"], timeout=20.0
        )
        cleanup.append(transport.close)
        kwargs["cli_client"] = transport

    return SyncSwitch(model, host, **kwargs)


def process_reference_unavailable_triple(
    go_sw: Any, ref_sw: Any, backend_str: str, op_name: str, expected: Any
) -> dict[str, Any]:
    """READER-PARITY check for a triple whose Python REFERENCE fake cannot
    serve this op at all -- controller triage decision on the CC3 delivery
    report's finding #2 (2026-08-18): the pinned Python reference's own
    in-process VirtualCliFace.run() dispatch (virtual/faces/cli.py:505-563)
    has no case at all for `show users`, `show ip http`, `show ip ssh` or
    `show telnetcon` -- every one falls through to its final line-563
    "Command not found / Incomplete command..." -- so there is genuinely no
    Python reference to differential against for get_users/get_services over
    telnet on m4300-24x/gsm7252ps (test/crosslang/python_driver_test.go's
    referenceUnavailableInPythonFake documents exactly which four triples and
    why only these two models: m4300-16x/gsm7228ps's Go seeds carry no Users
    at all either, so their telnet/get_users trivially agrees with Python's
    empty fallback and never needed this substitution).

    Rather than DROP these triples (losing Python-lib<->Go-fake coverage for
    two real ops), this asks a different, still fully genuine question: does
    Python's OWN library, reading THIS repo's Go fake over the wire, get the
    SAME answer Go's OWN library gets reading that IDENTICAL running fake
    instance? `expected` is that Go-library reading, already JSON-marshalled
    field-for-field compatible with the matching Python dataclass (model.
    SwitchUser/ServiceStatus's own `json:"..."` tags mirror models.SwitchUser/
    ServiceStatus's field names exactly) by
    test/crosslang/python_driver_test.go's goLibraryReadJSON. This is NOT a
    hardcoded expectation table: the reference value is derived LIVE from
    Go's own fake on every run, never a hand-copied literal.

    Self-verifying, the OTHER direction: this ALSO re-attempts the ordinary
    Python-fake reference read (best-effort, exceptions swallowed -- the
    documented state is that it can't serve this op at all). If it now
    SUCCEEDS and agrees with the Go-library reading too, Python's reference
    fake has evidently been extended to answer this command since -- this
    exclusion is stale, and this triple FAILS loudly (rather than silently
    continuing to substitute reader-parity forever) so the fix is to remove
    it from referenceUnavailableInPythonFake and let it run the normal full
    differential.
    """
    from netgear_switch.registry import Backend

    backend = Backend(backend_str)
    result: dict[str, Any] = {"backend": backend_str, "op": op_name}
    expected_repr = repr(_normalize(expected))

    try:
        go_val = _dispatch(go_sw, backend, op_name)
    except Exception as exc:  # noqa: BLE001 -- a raise here is itself a result to report
        result["equal"] = False
        result["go"] = f"{type(exc).__name__}: {exc}"
        result["py"] = expected_repr
        result["error"] = "reader-parity: Python-lib(Go-fake) raised where Go-lib(Go-fake) succeeded"
        return result

    go_repr = repr(_normalize(go_val))
    equal = go_repr == expected_repr
    error: str | None = None
    if not equal:
        error = (
            "reader-parity MISMATCH: Python's library and Go's own library "
            "disagree reading the exact SAME running Go fake -- this is a "
            "genuine parser divergence (Python's CliReader vs Go's own "
            "reader for the same telnet output), independent of the "
            "Python-fake-has-no-reference gap this substitution exists for"
        )

    stale = _check_reference_became_available(ref_sw, backend, op_name, expected_repr)
    if stale is not None:
        equal = False
        error = stale

    result["equal"] = equal
    result["go"] = go_repr
    result["py"] = expected_repr
    result["error"] = error
    return result


def _check_reference_became_available(ref_sw: Any, backend: Any, op_name: str, expected_repr: str) -> str | None:
    """Best-effort: has Python's OWN in-process reference fake, in the
    meantime, come to agree with Go's library reading too? Returns a
    stale-exclusion error message if so, else None (including on any
    exception -- the documented, currently-expected state IS that this
    raises or disagrees; only a NEW agreement is news)."""
    try:
        py_val = _dispatch(ref_sw, backend, op_name)
    except Exception:  # noqa: BLE001 -- still unavailable, the documented state.
        return None
    if repr(_normalize(py_val)) != expected_repr:
        return None
    return (
        f"STALE EXCLUSION: {op_name} over this backend is listed in "
        "referenceUnavailableInPythonFake, but Python's OWN in-process "
        "reference fake now answers this op and AGREES with Go's library "
        "reading -- remove this triple from the exclusion set and let it "
        "run the normal full differential"
    )


def process_triple(go_sw: Any, ref_sw: Any, backend_str: str, op_name: str, model_key: str) -> dict[str, Any]:
    """Read (backend_str, op_name) from both switches and diff the results.

    ANY exception on EITHER side (transport error, UnsupportedCapabilityError,
    a genuine bug -- caught broadly and deliberately: a raise is itself a
    result this differential must report, never let crash the whole run and
    lose every OTHER triple's comparison) marks this triple unequal. The
    per-op non-vacuity floor (_NEVER_EMPTY_OPS) additionally marks a triple
    unequal if EITHER side's raw (pre-normalize) result is empty for an op
    known to always carry data, even if both sides happen to agree on empty
    -- see _NEVER_EMPTY_OPS's own doc comment for why that is never a
    legitimate pass. get_lldp additionally strips remote_port_id from the
    documented, narrowly-scoped rows in _KNOWN_LLDP_PORT_ID_DIVERGENCE, and
    remote_sys_name from the (smaller, overlapping) set of rows in
    _KNOWN_LLDP_SYSNAME_DIVERGENCE. get_stats additionally strips
    rx_packets/tx_packets (every row) for the (model_key, backend) pairs in
    _KNOWN_STATS_PACKETS_DIVERGENCE.
    """
    from netgear_switch.registry import Backend

    backend = Backend(backend_str)
    result: dict[str, Any] = {"backend": backend_str, "op": op_name}

    go_val = py_val = None
    go_err = py_err = None
    try:
        go_val = _dispatch(go_sw, backend, op_name)
    except Exception as exc:  # noqa: BLE001 -- must capture ANY failure honestly
        go_err = f"{type(exc).__name__}: {exc}"
    try:
        py_val = _dispatch(ref_sw, backend, op_name)
    except Exception as exc:  # noqa: BLE001
        py_err = f"{type(exc).__name__}: {exc}"

    if go_err is not None or py_err is not None:
        result["equal"] = False
        result["go"] = go_err if go_err is not None else repr(_normalize(go_val))
        result["py"] = py_err if py_err is not None else repr(_normalize(py_val))
        result["error"] = f"go_error={go_err!r} py_error={py_err!r}"
        return result

    go_norm = _normalize(go_val)
    py_norm = _normalize(py_val)

    lldp_stale_errors: list[str] = []
    if op_name == "get_lldp":
        # Applied independently, each with its OWN per-field, per-row
        # staleness check (via _row_field) so one exclusion's continued
        # need can never mask the other one having become stale -- see
        # _row_field's own docstring for why a whole-table comparison
        # would not be precise enough once a single row can carry both
        # exclusions at once (m4300-16x/telnet local_port 16 does).
        port_id_affected = _KNOWN_LLDP_PORT_ID_DIVERGENCE.get((model_key, backend_str))
        if port_id_affected:
            for port in sorted(port_id_affected):
                if _row_field(go_norm, port, "remote_port_id") == _row_field(py_norm, port, "remote_port_id"):
                    lldp_stale_errors.append(
                        f"STALE EXCLUSION: ({model_key!r}, {backend_str!r}) local_port {port} is "
                        "listed in _KNOWN_LLDP_PORT_ID_DIVERGENCE, but remote_port_id now matches "
                        "WITHOUT the exclusion too -- remove this row and let get_lldp run the "
                        "normal, full differential for it"
                    )
            go_norm = _strip_excluded_lldp_field(go_norm, port_id_affected, "remote_port_id")
            py_norm = _strip_excluded_lldp_field(py_norm, port_id_affected, "remote_port_id")

        sysname_affected = _KNOWN_LLDP_SYSNAME_DIVERGENCE.get((model_key, backend_str))
        if sysname_affected:
            for port in sorted(sysname_affected):
                if _row_field(go_norm, port, "remote_sys_name") == _row_field(py_norm, port, "remote_sys_name"):
                    lldp_stale_errors.append(
                        f"STALE EXCLUSION: ({model_key!r}, {backend_str!r}) local_port {port} is "
                        "listed in _KNOWN_LLDP_SYSNAME_DIVERGENCE, but remote_sys_name now matches "
                        "WITHOUT the exclusion too -- remove this row and let get_lldp run the "
                        "normal, full differential for it"
                    )
            go_norm = _strip_excluded_lldp_field(go_norm, sysname_affected, "remote_sys_name")
            py_norm = _strip_excluded_lldp_field(py_norm, sysname_affected, "remote_sys_name")

    stats_stale_error: str | None = None
    if op_name == "get_stats" and (model_key, backend_str) in _KNOWN_STATS_PACKETS_DIVERGENCE:
        # Self-verifying, same shape as the LLDP checks above: compare the
        # WHOLE table before stripping (a simple whole-table compare is
        # precise enough here, unlike get_lldp's per-row check, because no
        # OTHER exclusion ever overlaps get_stats) so a table that now
        # matches in full flags this exclusion as stale.
        if repr(go_norm) == repr(py_norm):
            stats_stale_error = (
                f"STALE EXCLUSION: ({model_key!r}, {backend_str!r}) is listed in "
                "_KNOWN_STATS_PACKETS_DIVERGENCE, but rx_packets/tx_packets now match "
                "WITHOUT the exclusion too -- remove this entry and let get_stats run "
                "the normal, full differential for it"
            )
        go_norm = _strip_stats_packet_fields(go_norm)
        py_norm = _strip_stats_packet_fields(py_norm)

    # Compared by repr, not `==`: a Sensor.value of float('nan') (this repo's
    # own honest encoding for an inventory-only sensor reading with no
    # numeric value -- see model/seed data for gs728tpp's fan/PSU rows) is
    # never equal to itself under IEEE 754 `==`, which would make two
    # genuinely IDENTICAL nan-carrying readings compare unequal for no
    # fidelity reason at all. repr() renders nan deterministically ("nan"),
    # so this comparison -- unlike `==` -- agrees with what a human reading
    # the "go"/"py" fields below would call equal.
    go_repr = repr(go_norm)
    py_repr = repr(py_norm)
    equal = go_repr == py_repr
    error: str | None = None

    if op_name in _NEVER_EMPTY_OPS and (not go_val or not py_val):
        equal = False
        error = (
            f"vacuous empty result for {op_name!r} (go_empty={not go_val}, "
            f"py_empty={not py_val}) -- every seeded model must have "
            "non-empty data for this op on both fakes"
        )
    elif lldp_stale_errors:
        equal = False
        error = "; ".join(lldp_stale_errors)
    elif stats_stale_error is not None:
        equal = False
        error = stats_stale_error

    result["equal"] = equal
    result["go"] = go_repr
    result["py"] = py_repr
    result["error"] = error
    return result


def main() -> int:
    payload = json.loads(sys.stdin.read())
    from netgear_switch.registry import get_model

    model_key = payload["model"]
    model = get_model(model_key)
    go_ep = payload["go"]
    cli_username = payload.get("cli_username", "admin")
    cli_password = payload.get("cli_password", "password")
    triples = payload["triples"]

    cleanup: list[Callable[[], None]] = []
    try:
        ref_sw = build_reference_switch(model, cleanup)
        go_sw = build_go_switch(model, go_ep, cli_username, cli_password, cleanup)

        results = []
        for t in triples:
            if "expected" in t:
                results.append(
                    process_reference_unavailable_triple(go_sw, ref_sw, t["backend"], t["op"], t["expected"])
                )
            else:
                results.append(process_triple(go_sw, ref_sw, t["backend"], t["op"], model_key))
    finally:
        for fn in reversed(cleanup):
            with contextlib.suppress(Exception):
                fn()

    json.dump(results, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()

    ok = len(results) == len(triples) and all(r["equal"] and r["error"] is None for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
