//go:build crosslang

package crosslang

// python_driver_test.go: CC3 -- Python's library reading BOTH a running Go
// virtual-switch fake AND Python's OWN in-process fake for the SAME model,
// asserting the two readings agree, per (backend, operation) triple. This is
// the reverse direction from Suite 1/Suite 2 (Go's library reading a Go or
// Python fake): here it is PYTHON driving, and the question is whether Go's
// FAKE is wire-faithful enough that Python's independently-implemented
// library, talking real SNMP/NSDP/HTTP/telnet protocol bytes, cannot tell it
// apart from Python's own reference fake for the same seeded model.
//
// Architecture: this Go test starts a REAL Go fake per model (virtual.
// GoFakeProvider, exactly like Suite 1), enumerates its Supported read
// triples via the SAME triples()/capabilities.Matrix oracle Suite 1/Suite 2
// use, then shells the pinned Python reference implementation's own venv
// interpreter to run crosstest/python/cc3_read_diff.py (committed in THIS
// repo, read below) -- a DIFFERENTIAL driver with no hardcoded expectation
// table: it builds one SyncSwitch reading the Go fake over the wire (SNMP/
// NSDP/HTTP sockets, FASTPATH CLI over telnet) and a second SyncSwitch
// reading a fresh Python VirtualSwitch it starts in-process for the SAME
// model, runs every requested op on both, and reports Python-object-to-
// Python-object equality. Any inequality is therefore a genuine Go-fake-vs-
// Python-fake fidelity divergence, never a value drifting from a hand-copied
// expectation.
//
// CLI is driven over TELNET ONLY, never SSH: cc3_read_diff.py's own doc
// comment explains why (no paramiko in this READ-ONLY pinned venv -- checked,
// not guessed). cc3ServedBackends below drops BackendSSH from the served set
// BEFORE calling triples(), so every SSH-backend triple capabilities.Matrix
// would otherwise generate for m4300-24x/-16x/gsm7252ps is structurally
// ABSENT from this suite's payload, never silently skipped after being
// counted -- the same "delete before counting, not filter after" shape
// provider.go's own servedBackends uses for its m4300-16x/HTTP exclusion.
// Telnet exercises the exact same fastpath command parsers SSH would (both
// transports share transport/cli/session.py's ShellDriver), so CLI fidelity
// is still fully exercised for every FASTPATH model here -- only the
// transport differs, and that is recorded, not hidden.

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// cc3PythonInterpreter is the pinned Python reference implementation's own
// venv interpreter -- see crosstest/python/cc3_read_diff.py's own doc
// comment for why this driver must run under it (netgear_switch is
// installed there, nowhere else) and never under system Python.
const cc3PythonInterpreter = "/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-b26eb1f/.venv/bin/python3"

// cc3DriverScript is committed IN THIS REPO, referenced relative to this
// package's own directory (go test's working directory for a package is
// always that package's directory, so this resolves the same way regardless
// of which absolute path this worktree happens to be checked out at --
// unlike cc3PythonInterpreter above, which necessarily names a sibling
// worktree outside this repo and so cannot be relative).
const cc3DriverScript = "../../crosstest/python/cc3_read_diff.py"

// cc3DriverTimeout bounds one `cc3_read_diff.py` invocation, which covers
// EVERY read triple for one model in a single process (real SNMP net-snmp
// CLI subprocesses, NSDP UDP round trips, HTTP logins, and -- for FASTPATH
// models -- one telnet login plus one shell command per CLI triple).
// Generous for that under scripts/jail.sh's CPU/memory limits, short enough
// that a genuinely wedged driver still fails this test rather than hanging
// `make crosslang` forever.
const cc3DriverTimeout = 90 * time.Second

// cc3GoEndpoints is the "go" object in cc3_read_diff.py's stdin JSON
// contract (see that file's own doc comment for the exact shape) -- the Go
// fake's announced endpoint, verbatim off virtual.Endpoints.
type cc3GoEndpoints struct {
	Host         string `json:"host"`
	SnmpPort     int    `json:"snmp_port"`
	NsdpPort     int    `json:"nsdp_port"`
	HTTPPort     int    `json:"http_port"`
	SSHPort      int    `json:"ssh_port"`
	TelnetPort   int    `json:"telnet_port"`
	Community    string `json:"community"`
	HTTPPassword string `json:"http_password"`
}

// cc3Triple is one {"backend": ..., "op": ...} entry in the driver's input
// triple list -- deliberately its own JSON-tagged type (rather than reusing
// Triple, whose ModelKey field has no place in a per-model payload and whose
// Op field is a capabilities.Operation, not the bare name string the driver
// wants) so the wire contract stays exactly what cc3_read_diff.py documents.
type cc3Triple struct {
	Backend string `json:"backend"`
	Op      string `json:"op"`
}

// cc3Payload is cc3_read_diff.py's complete stdin contract.
type cc3Payload struct {
	Model       string         `json:"model"`
	Go          cc3GoEndpoints `json:"go"`
	CLIUsername string         `json:"cli_username"`
	CLIPassword string         `json:"cli_password"`
	Triples     []cc3Triple    `json:"triples"`
}

// cc3Result is one entry of the driver's stdout JSON array -- see
// cc3_read_diff.py's own doc comment for the exact contract this mirrors.
type cc3Result struct {
	Backend string  `json:"backend"`
	Op      string  `json:"op"`
	Equal   bool    `json:"equal"`
	Go      string  `json:"go"`
	Py      string  `json:"py"`
	Error   *string `json:"error"`
}

// cc3ServedBackends is servedBackends (provider.go) with BackendSSH removed:
// this suite drives CLI reads over telnet only (see this file's own doc
// comment), so SSH must never even reach triples() as a candidate backend --
// the m4300-16x/HTTP exclusion provider.go's servedBackends already encodes
// is kept as-is (same harness-reachability reasoning: this driver's HTTP
// client is built with an explicit host:port + secure=False exactly like
// provider.go's own excluded case would need to sidestep the fixed-WebPort/
// HTTPS requirement, but that combination is untested territory this slice
// deliberately does not take on -- see the CC3 report's own scope note).
func cc3ServedBackends(modelKey string, ep virtual.Endpoints) map[model.Backend]int {
	served := servedBackends(modelKey, ep)
	delete(served, model.BackendSSH)
	return served
}

// runCC3Driver shells cc3_read_diff.py once for modelKey, feeding it payload
// as JSON on stdin, and returns the parsed result array. Fails t loudly (via
// t.Fatalf, never a silently-empty return) if the process cannot even be
// started, if its stdout is not a valid JSON array at all (the driver's own
// contract: this happens only when it crashed before finishing, e.g. it
// could not connect to EITHER fake), or if the result count does not match
// len(payload.Triples) exactly -- the non-vacuity floor this whole suite
// exists to enforce: a driver that silently dropped triples while still
// exiting 0 would otherwise look identical to a fully green run.
func runCC3Driver(ctx context.Context, t *testing.T, payload cc3Payload) []cc3Result {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal cc3Payload for %q: %v", payload.Model, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, cc3DriverTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, cc3PythonInterpreter, cc3DriverScript)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var results []cc3Result
	if jsonErr := json.Unmarshal(stdout.Bytes(), &results); jsonErr != nil {
		t.Fatalf(
			"cc3_read_diff.py --model %s: stdout was not a valid JSON result array "+
				"(process err=%v) -- this driver could not get started or crashed before "+
				"finishing, which this suite treats as a fail-loud, not a silent pass.\n"+
				"parse error: %v\nstdout:\n%s\nstderr:\n%s",
			payload.Model, runErr, jsonErr, stdout.String(), stderr.String())
		return nil
	}
	if len(results) != len(payload.Triples) {
		t.Fatalf(
			"cc3_read_diff.py --model %s: returned %d results for %d requested triples -- "+
				"the driver silently dropped some (non-vacuity violation); stderr:\n%s",
			payload.Model, len(results), len(payload.Triples), stderr.String())
		return nil
	}

	allEqual := true
	for _, r := range results {
		if !r.Equal {
			allEqual = false
			break
		}
	}
	if allEqual != (runErr == nil) {
		t.Errorf(
			"cc3_read_diff.py --model %s: exit status inconsistent with its own JSON "+
				"(all results equal=%v, process err=%v) -- the driver's exit code and its "+
				"result array must agree; stderr:\n%s",
			payload.Model, allEqual, runErr, stderr.String())
	}

	return results
}

// buildCC3Payload assembles cc3_read_diff.py's stdin contract for modelKey:
// every triple() this file's cc3ServedBackends+triples() enumerate, plus the
// Go fake's own announced endpoint (verbatim -- never re-derived) and the
// same CLI credentials suite.go's buildSwitch uses for the Go-library-vs-Go-
// fake suites, so a mismatch there cannot be this test's own bug.
func buildCC3Payload(modelKey string, ep virtual.Endpoints, trips []Triple) cc3Payload {
	triples := make([]cc3Triple, len(trips))
	for i, tr := range trips {
		triples[i] = cc3Triple{Backend: string(tr.Backend), Op: tr.Op.Name}
	}
	return cc3Payload{
		Model: modelKey,
		Go: cc3GoEndpoints{
			Host:         ep.Host,
			SnmpPort:     ep.SnmpPort,
			NsdpPort:     ep.NsdpPort,
			HTTPPort:     ep.HTTPPort,
			SSHPort:      ep.SSHPort,
			TelnetPort:   ep.TelnetPort,
			Community:    ep.Community,
			HTTPPassword: ep.HTTPPassword,
		},
		CLIUsername: cliUsername,
		CLIPassword: cliPassword,
		Triples:     triples,
	}
}

// wantCC3TripleCount is the total number of (model, backend, op) READ
// triples this suite compares across every suite1Models entry -- measured
// directly (a live run while building this suite), and asserted below as
// the same coarser, whole-run net python_fake_test.go's own
// wantPythonReadTripleCount is: a regression that silently shrank this
// suite's coverage (a model losing a backend, a backend losing its triples)
// would still show green per-model if every triple that DID run kept
// passing, exactly the vacuity this number exists to catch.
const wantCC3TripleCount = 183

// Known, root-caused CC3 divergences (as of this suite's introduction --
// D-VIRT §5/slice CC3). This suite deliberately carries NO allowlist or
// exception table for these: every one below still fails its triple, loudly,
// on every run -- silently swallowing a known divergence is exactly the
// "loosen a comparison to hide it" failure mode this differential exists to
// refuse. They are recorded here only as a map for a future reader (or
// controller-triage pass) deciding whether/how to resolve each one,
// mirroring opmap.go's own precedent of naming every known gap explicitly
// rather than leaving a bare, unexplained red test.
//
//  1. m4300-24x/http/get_lldp and m4300-16x/telnet/get_lldp: the two LLDP
//     neighbours whose remote_port_id is raw, non-ASCII/binary bytes (a
//     MAC-address-subtype LLDP Port ID, e.g. 88:A2:9E:80:87:01) come back
//     DIFFERENT from the two fakes -- NOT a wire corruption on either
//     side's own transport (verified: Go's HTTP response bytes contain the
//     original 6 raw bytes VERBATIM; a plain `go vet`-clean diagnostic
//     confirmed this against a live GoFakeProvider instance). The two fakes
//     choose different representations for a raw byte string when handing
//     it to their own HTTP text layer: virtual/web_gsm7252ps.go's xeCell
//     (shared by the M4300 dialect) writes the Go byte-string straight onto
//     the wire unmodified, while the pinned Python fake's LldpSim.port_id is
//     stored as a str decoded latin-1-safe from the same captured bytes and
//     then re-encoded UTF-8 (its own faces/http.py Handler._send: `text.
//     encode()`) when served -- multi-byte for every byte above 0x7F. Since
//     httpx guesses "utf-8" for BOTH responses (neither fake declares an
//     explicit charset), Go's raw bytes decode as mangled U+FFFD replacement
//     characters while Python's already-UTF-8-encoded bytes decode back to
//     the original latin-1 codepoints losslessly -- by construction, not
//     because Python's wire bytes are "more correct" per se. m4300-16x's
//     case additionally has one raw byte (0x0A, a literal LF) land inside an
//     HTML attribute value, which appears to truncate BOTH fakes' answers
//     differently once decoded (Go: None; Python: only the leading NUL
//     survives) -- consistent with a single-line-oriented parse of the
//     VALUE="..." attribute somewhere in the shared (read-only, pinned)
//     Python http_read.py. CLASSIFICATION: legitimate-normalization-
//     artifact / needs-hardware-reverification -- neither fake's own wire
//     behaviour is provably the one a real M4300 emits for a binary,
//     MAC-subtype LLDP Port ID (a real device might render it as a
//     formatted hex string, the way BOTH fakes already do for
//     remote_chassis_id -- see formatChassisHex / the Python `":".join(f"{
//     ord(c):02X}"...)` twin -- rather than dumping raw bytes as text at
//     all; that would sidestep this whole class of divergence, but is an
//     independent modeling gap in BOTH languages' LLDP fake, not something
//     this differential's own scope covers). NOT fixed here: changing only
//     Go's side cannot make the two fakes AGREE (Python's pinned worktree is
//     read-only), and the "more real" fix needs a hardware LLDP Port ID
//     capture neither fake currently has.
//
//  2. m4300-24x/telnet/get_users, gsm7252ps/telnet/get_users,
//     m4300-24x/telnet/get_services, gsm7252ps/telnet/get_services: the
//     PINNED PYTHON reference fake's own in-process VirtualCliFace (virtual/
//     faces/cli.py's `run()` dispatch) has NO case at all for `show users`,
//     `show ip http`, `show ip ssh` or `show telnetcon` -- every one falls
//     through to its final "Command not found" line, which CliReader then
//     parses as zero rows / all-disabled defaults. This repo's OWN CLI fake
//     (virtual/cliface_render.go) DOES implement all four. Confirmed by
//     reading virtual/faces/cli.py directly (pinned worktree, read-only):
//     its command table stops at `show interface ethernet`, with nothing
//     for user-management or per-service admin-state pages at all --
//     capabilities.Matrix marks both ops Supported over CLI for these
//     models (cross-verified against Python's own capabilities.py, so
//     Python's OWN oracle agrees they should work), but its OWN reference
//     fake was simply never extended to answer them. CLASSIFICATION:
//     Python-fake incomplete -- not a Go-fake fidelity bug at all (if
//     anything, this repo's fake is the MORE complete of the two here); out
//     of scope to fix (the pinned worktree is read-only). An audit
//     follow-up for the Python side, not this slice.
//
// Every triple above genuinely, reproducibly fails this suite -- see this
// slice's own delivery report for the live run output each classification
// is grounded in.
func TestPythonLibVsGoFake_AllBackends(t *testing.T) {
	provider := &virtual.GoFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	total := 0
	for _, modelKey := range suite1Models {
		t.Run(modelKey, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
			defer cancel()

			ep, err := provider.StartModel(ctx, modelKey)
			if err != nil {
				t.Fatalf("StartModel(%q): %v", modelKey, err)
			}

			served := cc3ServedBackends(modelKey, ep)
			trips, err := triples(modelKey, capabilities.ReadOperations, served)
			if err != nil {
				t.Fatalf("triples(%q): %v", modelKey, err)
			}
			if len(trips) == 0 {
				t.Fatalf("triples(%q) = 0 read triples -- provider serves backends %v, want at least one Supported triple", modelKey, served)
			}
			total += len(trips)

			payload := buildCC3Payload(modelKey, ep, trips)
			results := runCC3Driver(ctx, t, payload)

			gotByKey := make(map[string]cc3Result, len(results))
			for _, r := range results {
				gotByKey[r.Backend+"/"+r.Op] = r
			}
			for _, tr := range trips {
				key := string(tr.Backend) + "/" + tr.Op.Name
				r, ok := gotByKey[key]
				if !ok {
					t.Errorf("%s: driver returned no result for this triple", tr)
					continue
				}
				if !r.Equal {
					errMsg := "(no error detail)"
					if r.Error != nil {
						errMsg = *r.Error
					}
					t.Errorf("%s: Go-fake vs Python-fake reading MISMATCH: %s\n  go: %s\n  py: %s",
						tr, errMsg, r.Go, r.Py)
				}
			}
		})
	}

	if total != wantCC3TripleCount {
		t.Errorf("total CC3 read triples across all %d models = %d, want %d -- see wantCC3TripleCount's own doc comment", len(suite1Models), total, wantCC3TripleCount)
	}
}

// TestCC3Driver_UnreachableGoEndpointFails is a META-test proving
// runCC3Driver's own non-vacuity floor: fed a Go endpoint nothing is
// listening on, the per-triple read must fail (an NsdpError from the
// UdpNsdpClient timing out) and be reported as an honest inequality --
// never silently treated as an empty-but-passing result. Run via t.Run so
// the expected subtest failure is confined to its own goroutine (t.Fatalf
// calls runtime.Goexit, which must never unwind this test's own goroutine)
// and this test asserts on the reported outcome rather than the subtest's
// pass/fail bit -- an unreachable endpoint is expected to produce a valid,
// countable, non-equal result, not to crash the driver outright.
func TestCC3Driver_UnreachableGoEndpointFails(t *testing.T) {
	payload := cc3Payload{
		Model: "gs110emx",
		Go: cc3GoEndpoints{
			Host:     "127.0.0.1",
			NsdpPort: 1, // nothing is listening here -- the read must fail to connect.
		},
		CLIUsername: cliUsername,
		CLIPassword: cliPassword,
		Triples:     []cc3Triple{{Backend: "nsdp", Op: "get_ports"}},
	}
	var results []cc3Result
	t.Run("unreachable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), cc3DriverTimeout)
		defer cancel()
		results = runCC3Driver(ctx, t, payload)
	})
	if len(results) != 1 {
		t.Fatalf("runCC3Driver against an unreachable Go endpoint returned %d results, want exactly 1 (non-vacuity floor itself broken)", len(results))
	}
	if results[0].Equal {
		t.Errorf("runCC3Driver against an unreachable Go endpoint reported equal=true -- an unreachable port must never compare as a successful read")
	}
}
