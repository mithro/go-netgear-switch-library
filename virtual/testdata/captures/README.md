# Capture fixture provenance

The four `*.json` files in this directory are byte-identical copies of
committed real-hardware SNMP captures from the Python reference
implementation:

- Source repo: `/home/tim/github/mithro/python-netgear-switch-library`
- Source path (per file): `tests/fixtures/captures/<name>.json`
- Pin: branch `fix/s3300-52x-live-verify` @ `1aa1274` (frozen snapshot
  worktree `.claude/worktrees/go-port-pin-1aa1274`)
- Copied: 2026-07-30, via plain byte-for-byte file copy (verified with
  `diff` against the source at copy time) -- no reformatting, no
  reserialization.

Files:

- `gsm7252ps.json` -- GSM7252PS, SNMP host 10.1.5.22.
- `gsm7228ps.json` -- GSM7228PS / S3300-52X-PoE+, SNMP host 10.1.5.11
  (sw-netgear-s3300-1), captured 2026-07-30.
- `m4300-24x.json` -- M4300-24X, SNMP host 10.1.5.13.
- `m4300-16x.json` -- M4300-16X (host unrecorded in the capture itself).

Each file's top-level shape is `{"model", "host", "snapshot", "note"}`,
where `snapshot` is a `netgear_switch.models.SwitchData`-shaped JSON object
(`ports`, `poe`, `vlans`, `pvids`, `lldp`, `macs`, `sensors`, `stats`,
`mgmt_ip`) -- the same field names as this Go library's `model.SwitchData`
JSON tags, so `virtual/seed_test.go`'s `assertSeedMatchesCapture` helper
parses `snapshot` directly into a `model.SwitchData` via `encoding/json`.

## gs728tpp: deliberately NOT copied here

Task 11's brief asked for a fifth file, `gs728tpp.json`, alongside these
four. It does not exist: `git log --all` against the pinned source repo
shows no commit ever added `tests/fixtures/captures/gs728tpp.json`, and no
`tests/virtual/test_gs728tpp_seed.py` exists there either (unlike every
other seeded model, which has one). `seed_gs728tpp`'s own docstring in the
Python source cites a real live capture
(`tmp/gs728tpp_ground_truth.json`, host 10.2.5.10, 2026-07-29) that was
apparently used to author the seed's literal values but was itself never
committed to the repository -- only its already-transcribed values survive,
inside `seed.py` itself.

Rather than fabricate a capture file that would misrepresent a real
device's data, `SeedGS728TPP` in `virtual/seed.go` is transcribed directly
from the pinned `seed.py` function's literal values (the same source every
other seed here is transcribed from), and is grounded in
`virtual/seed_test.go` via direct structural assertions against those
known values (entity-component inventory present, SNMP sensors empty,
the real captured `sysObjectID`, etc.) instead of the
`assertSeedMatchesCapture` capture-parity harness the other four seeds
use.
