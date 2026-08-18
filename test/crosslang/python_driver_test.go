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
//
// Six of the 183 triples this suite compares are NOT a plain Go-fake-vs-
// Python-fake differential: TestPythonLibVsGoFake_AllBackends' own doc
// comment, referenceUnavailableInPythonFake's doc comment, and
// cc3_read_diff.py's _KNOWN_LLDP_PORT_ID_DIVERGENCE explain exactly which
// six, why, and how each substitution stays self-verifying rather than a
// silent, permanent exception.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
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
//
// Expected is set ONLY for a triple in referenceUnavailableInPythonFake:
// Go's OWN library's reading of THIS SAME running Go fake, JSON-marshalled
// (via goLibraryReadJSON) field-for-field compatible with the matching
// Python dataclass. Its presence (cc3_read_diff.py checks `"expected" in
// t`, not truthiness) is what tells the driver to substitute a
// reader-parity check for the normal fake-vs-fake differential on this one
// triple -- see referenceUnavailableInPythonFake's own doc comment.
type cc3Triple struct {
	Backend  string          `json:"backend"`
	Op       string          `json:"op"`
	Expected json.RawMessage `json:"expected,omitempty"`
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

// referenceUnavailableInPythonFake is the exact set of (model, backend, op)
// triples -- keyed "model/backend/op", matching Triple.String() -- for which
// this suite substitutes a READER-PARITY check for the normal Go-fake-vs-
// Python-fake differential: controller triage decision on the CC3 delivery
// report's finding #2 (2026-08-18).
//
// Root cause: the pinned Python reference implementation's own in-process
// VirtualCliFace.run() dispatch (go-port-pin-b26eb1f's src/netgear_switch/
// virtual/faces/cli.py:505-563) has NO case at all for `show users`,
// `show ip http`, `show ip ssh` or `show telnetcon` -- every one of those
// four commands falls through to that function's final line-563 "Command
// not found / Incomplete command. Use ? to list commands." -- so there is
// genuinely no Python REFERENCE fake to differential against for
// get_users/get_services over telnet on these two models specifically. Not
// listed here despite also lacking a working Python reference: m4300-16x's
// and gsm7228ps's telnet/get_users -- their own Go seeds carry NO Users at
// all either (see opmap.go's own usersKnownEmpty), so their reading
// trivially agrees with Python's "Command not found" -> empty fallback and
// never surfaced a divergence needing this substitution. This repo's OWN
// CLI fake (virtual/cliface_render.go) DOES implement all four commands --
// if anything, this is the MORE complete fake of the two here, not a Go
// fidelity bug.
//
// Every triple listed here still gets a genuine, non-hardcoded differential
// (see buildCC3Payload/goLibraryReadJSON and cc3_read_diff.py's
// process_reference_unavailable_triple): does Python's library, reading
// THIS repo's Go fake over the wire, get the SAME answer Go's OWN library
// gets reading that IDENTICAL running fake instance? The reference value is
// derived LIVE from Go's fake on every run, never a hand-copied literal.
//
// Self-verifying: the driver additionally re-attempts the ordinary
// Python-fake reference read for each of these triples and fails loudly if
// it has, in the meantime, come to agree with Go's library reading too
// (i.e. Python's reference fake has been extended to answer the command) --
// see cc3_read_diff.py's own doc comment on that check. This Go-side map is
// also asserted, once per full run, to have every one of its entries
// actually visited among the enumerated triples (TestPythonLibVsGoFake_
// AllBackends' own visitedExclusions tracking, checked at the end of that
// test) -- a model/backend pairing removed from the registry, or a
// capabilities change that drops one of these ops, would otherwise leave a
// stale, silently-unreachable entry here forever.
var referenceUnavailableInPythonFake = map[string]bool{
	"m4300-24x/telnet/get_users":    true,
	"m4300-24x/telnet/get_services": true,
	"gsm7252ps/telnet/get_users":    true,
	"gsm7252ps/telnet/get_services": true,
}

// goLibraryReadJSON runs opName over sw (already pinned to backend) via
// Go's OWN public facade and returns its result JSON-marshalled --
// field-for-field compatible with the matching Python dataclass, since
// model.SwitchUser/ServiceStatus's own `json:"..."` struct tags already
// mirror models.SwitchUser/ServiceStatus's field names exactly (name,
// access_mode, privileged, snmpv3_access/auth/encryption; name, enabled,
// port) -- for referenceUnavailableInPythonFake's reader-parity check. Only
// ever called for an op in that map, so the two cases below are the only
// ones this ever needs.
func goLibraryReadJSON(ctx context.Context, sw *netgearswitch.Switch, backend model.Backend, opName string) ([]byte, error) {
	switch opName {
	case "get_users":
		v, err := sw.GetUsers(ctx, netgearswitch.WithReadBackend(backend))
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)
	case "get_services":
		v, err := sw.GetServices(ctx, netgearswitch.WithReadBackend(backend))
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)
	default:
		return nil, fmt.Errorf("goLibraryReadJSON: no case for op %q -- referenceUnavailableInPythonFake needs a matching case added here", opName)
	}
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
//
// For a triple in referenceUnavailableInPythonFake, this ALSO builds a
// *netgearswitch.Switch pinned to the SAME running Go fake (buildSwitch --
// the identical helper suite.go's own Go-lib-vs-Go-fake suite uses) and
// attaches Go's own live reading as cc3Triple.Expected, so the driver can
// run the reader-parity check instead of the normal differential. visited
// records every referenceUnavailableInPythonFake key this call actually
// exercised, so the caller can assert none of that map's entries went
// unvisited across the whole suite.
func buildCC3Payload(ctx context.Context, t *testing.T, modelKey string, m *model.SwitchModel, ep virtual.Endpoints, trips []Triple, visited map[string]bool) cc3Payload {
	t.Helper()
	triples := make([]cc3Triple, len(trips))
	for i, tr := range trips {
		ct := cc3Triple{Backend: string(tr.Backend), Op: tr.Op.Name}
		if referenceUnavailableInPythonFake[tr.String()] {
			visited[tr.String()] = true
			sw := buildSwitch(t, ep, m, tr.Backend)
			expected, err := goLibraryReadJSON(ctx, sw, tr.Backend, tr.Op.Name)
			closeErr := sw.Close()
			if err != nil {
				t.Fatalf("%s: goLibraryReadJSON (reader-parity reference, Go's OWN library reading Go's OWN fake): %v", tr, err)
			}
			if closeErr != nil {
				t.Errorf("%s: sw.Close() after goLibraryReadJSON: %v", tr, closeErr)
			}
			ct.Expected = expected
		}
		triples[i] = ct
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

// TestPythonLibVsGoFake_AllBackends is CC3's own deliverable: for every
// model in suite1Models, starts a real Go fake (virtual.GoFakeProvider,
// exactly like Suite 1), enumerates its Supported read triples (SNMP/NSDP/
// HTTP + CLI-over-telnet; never SSH -- see cc3ServedBackends), and asserts
// Python's library reads the SAME thing from the Go fake as it does from its
// own in-process Python reference fake for every one of them -- except the
// two documented, self-verifying substitutions below, applied to exactly
// six triples out of 183 (all six discovered, root-caused and reported by
// this suite's own first run; see this slice's delivery reports):
//
//   - referenceUnavailableInPythonFake (4 triples): the Python reference
//     fake genuinely cannot serve get_users/get_services over telnet on
//     m4300-24x/gsm7252ps at all (see that map's own doc comment for the
//     virtual/faces/cli.py citation) -- these run a READER-PARITY check
//     (Go-lib(Go-fake) == Python-lib(Go-fake), both reading the SAME live
//     fake instance) instead of dropping the coverage entirely.
//   - _KNOWN_LLDP_PORT_ID_DIVERGENCE (2 triples, defined in
//     cc3_read_diff.py): get_lldp on m4300-24x/http and m4300-16x/telnet
//     excludes ONLY the remote_port_id field of the specific rows whose Port
//     ID is a raw binary MAC-subtype value the two fakes' HTTP/CLI text
//     layers round-trip differently (pending a hardware LLDP Port ID
//     capture) -- every other field, and every other row of the same
//     table, stays fully compared.
//
// Neither substitution is a bare allowlist: both are self-verifying (a
// per-triple check that FAILS this suite loudly the moment the substitution
// stops being necessary) and both are scoped as narrowly as the evidence
// supports, so a regression anywhere else -- a different model, a different
// field, a different row -- still fails normally.
func TestPythonLibVsGoFake_AllBackends(t *testing.T) {
	provider := &virtual.GoFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	visitedExclusions := make(map[string]bool, len(referenceUnavailableInPythonFake))
	total := 0
	for _, modelKey := range suite1Models {
		t.Run(modelKey, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
			defer cancel()

			ep, err := provider.StartModel(ctx, modelKey)
			if err != nil {
				t.Fatalf("StartModel(%q): %v", modelKey, err)
			}
			m, err := model.GetModel(modelKey)
			if err != nil {
				t.Fatalf("GetModel(%q): %v", modelKey, err)
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

			payload := buildCC3Payload(ctx, t, modelKey, m, ep, trips, visitedExclusions)
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

	// The other direction of "asserted both-ways" for
	// referenceUnavailableInPythonFake: every entry in that map must have
	// actually been reached by SOME model's enumerated triples above. An
	// entry that goes unvisited (a model renamed, a backend dropped, a
	// capabilities change) would otherwise sit in that map forever, dead
	// and unnoticed -- this fails loudly instead.
	for key := range referenceUnavailableInPythonFake {
		if !visitedExclusions[key] {
			t.Errorf("referenceUnavailableInPythonFake[%q] was never visited by any enumerated triple this run -- stale entry, remove it (or triples()/cc3ServedBackends stopped generating it)", key)
		}
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
