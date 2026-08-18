//go:build crosslang

package crosslang

// cli_bytediff_test.go: CC4 -- ngsw (the pinned Python reference's own CLI)
// vs gngsw (this repo's CLI) STDOUT byte-diff, driven against the SAME
// running Go SNMP fake (virtual.GoFakeProvider). Every earlier crosslang
// suite in this package compares LIBRARY-level results (Go/Python structs,
// or a differential driver's own equality check); this one is the first to
// go all the way through the CLI formatting layer -- cmd/internal/fmtx on
// the Go side, cli/format.py on the Python side -- by shelling BOTH real
// CLI binaries and diffing their stdout byte-for-byte, exactly the surface
// design spec §10.4 calls the CLI's own parity contract: STDOUT and EXIT
// CODE are compared; STDERR is explicitly OUT of scope (Go wraps errors
// with %q/%w, Python with !r -- docs/cross-language-divergences.md entry
// 5 -- so the two languages' error TEXT is a known, accepted divergence,
// never diffed here).
//
// gngsw's --host flows straight through resolve.Resolve's fromHostModel to
// netgearswitch.New(m, host, ...), and snmp/gosnmp.go's splitHostPort
// parses a "host:port" string for the SNMP transport specifically (falling
// back to the model's default SNMP port for a bare host) -- so
// "--host 127.0.0.1:PORT" already addresses a fake's ephemeral SNMP port
// with NO gngsw code change needed. ngsw's own --host flows just as
// directly to transport/sync/snmp_netsnmp_cli.py's NetsnmpCliClient, which
// passes self.host straight into the net-snmp CLI tools' own argv (snmpget/
// snmpbulkwalk/snmpset all accept a bare "AGENT[:PORT]" positional
// argument) -- so both CLIs reach the identical fake via the identical
// --host convention; this was confirmed live (STEP 0 of this slice's own
// brief) before any test code here was written, using both models this
// file exercises. No gngsw parity gap was found or needed fixing.
//
// Models: gsm7252ps and gs728tpp, both carrying substantial hand-authored
// SNMP seed data (virtual/seed.go) and both PoE-capable (PoEPortCount
// 48/24 -- covers the `poe` subcommand), but deliberately DIFFERENT in one
// respect: gsm7252ps's SNMP dialect serves get_syslog, gs728tpp's does not
// (capabilities.Matrix marks get_syslog/snmp Unsupported for gs728tpp --
// "registers no Netgear vendor OID subtree") -- so this suite exercises
// two genuinely different per-model op sets, not two labels for the same
// list, and proves the harness's op enumeration (via triples(), the SAME
// capabilities.Matrix-backed oracle every other suite in this package
// uses) tracks that difference correctly rather than a hand-maintained
// list drifting out of sync with the real capability table.
//
// Every SNMP-Supported read op this suite finds is run through BOTH its
// default (table) rendering and --json rendering (fmtx.ToJSON was built
// specifically for byte parity with Python's json.dumps -- see its own
// doc comment in cmd/internal/fmtx/json.go), plus one disruptive-write
// command (`pvid --dry-run`) to prove the "DRY-RUN: would ... (nothing
// sent)" line (safety.go/safety.py, byte-identical by design) matches too.
//
// get_users/get_services/nsdp_device are absent from cc4ReadCmd on
// purpose, not by oversight: capabilities.Operation.Backends restricts
// get_users/get_services to console/http/ssh/telnet (never snmp) and
// nsdp_device to nsdp alone (never snmp), so triples() -- filtered to
// backend=snmp here -- structurally never emits them; cc4ReadCmd's own
// Fatalf guard would catch it immediately if that ever changed.
//
// Every stdout comparison in this file came back byte-identical on a live
// run against both models (no fmtx bug found, no divergence needed) --
// this suite exists to KEEP proving that on every future change, not to
// document one that was found.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// cc4PythonNgsw is the pinned Python reference implementation's own venv
// console-script entry point for `ngsw` -- see cc3PythonInterpreter's doc
// comment (python_driver_test.go) for why THIS worktree specifically
// (netgear_switch is installed there, nowhere else) and never a system
// `ngsw`. Unlike CC3's driver (a Python script this repo ships, shelled via
// the venv's raw python3 interpreter), CC4 drives ngsw's own CLI entry
// point directly: its shebang already names the venv's python3
// absolutely, so no separate interpreter argument is needed here.
const cc4PythonNgsw = "/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-b26eb1f/.venv/bin/ngsw"

// cc4Timeout bounds StartModel plus every CLI invocation one top-level CC4
// test issues. A single model's subtest fans out to ~22 comparisons, each
// spawning TWO fresh CLI subprocesses (gngsw + a net-snmp-backed ngsw) over
// real loopback round trips under scripts/jail.sh's CPU/memory limits, so the
// per-model wall time is dominated by subprocess startup: gsm7252ps measured
// ~29s on this host. 90s leaves comfortable headroom for a slower CI runner
// while still failing (rather than hanging `make crosslang` forever) if a CLI
// genuinely wedges.
const cc4Timeout = 90 * time.Second

// cc4Models are the two SNMP-rich models this suite byte-diffs -- see this
// file's own doc comment for why these two specifically.
var cc4Models = []string{"gsm7252ps", "gs728tpp"}

// cc4ReadCmd maps every capabilities.Operation.Name this suite's triples()
// call can emit for backend=snmp to the CLI subcommand name -- IDENTICAL
// spelling in both cli/main.py's read_cmd(...) registrations and gngsw's
// own read.go/write.go command constructors (ports/stats/vlans/pvids/lldp/
// macs/poe/sensors/ip/hostname/syslog), confirmed by direct comparison of
// both files while building this suite. get_users/get_services/nsdp_device
// are deliberately absent -- see this file's own doc comment.
var cc4ReadCmd = map[string]string{
	"get_ports":    "ports",
	"get_stats":    "stats",
	"get_vlans":    "vlans",
	"get_pvids":    "pvids",
	"get_lldp":     "lldp",
	"get_macs":     "macs",
	"get_poe":      "poe",
	"get_sensors":  "sensors",
	"get_mgmt_ip":  "ip",
	"get_hostname": "hostname",
	"get_syslog":   "syslog",
}

// buildGngsw compiles cmd/gngsw fresh into a directory scoped to t's own
// lifetime (t.TempDir(), removed automatically once t -- and every subtest
// it spawned -- has finished), returning the built binary's path. NEVER
// committed anywhere: this repo's own gate ("git status --porcelain" empty
// before commit) is what enforces that, and t.TempDir() living outside the
// repo entirely (Go's os.TempDir()) makes an accidental commit structurally
// impossible regardless. `go build` here inherits whatever resource jail
// the OUTER `go test` process is already running under (`make crosslang`
// wraps the whole run with scripts/jail.sh), so this child process needs no
// jail.sh wrapper of its own.
func buildGngsw(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gngsw")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/mithro/go-netgear-switch-library/cmd/gngsw")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build -o %s github.com/mithro/go-netgear-switch-library/cmd/gngsw: %v\n%s", bin, err, stderr.String())
	}
	return bin
}

// cliResult is one CLI invocation's outcome: exit code plus stdout/stderr
// captured SEPARATELY (this suite only ever byte-diffs stdout -- see
// compareCLIOutputs' own doc comment for why stderr is out of scope).
type cliResult struct {
	exitCode int
	stdout   string
	stderr   string
}

// runCLIBinary runs bin with args to completion under ctx, capturing
// stdout/stderr separately and returning its exit code. Fails t via
// Fatalf if the process could not even be started or exited via a signal
// (anything a plain exec.ExitError can't report a numeric code for) --
// this suite's own non-vacuity floor for "did the CLI actually run at
// all", never silently swallowed into a bogus exit code.
func runCLIBinary(ctx context.Context, t *testing.T, bin string, args ...string) cliResult {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("%s %s: could not run to completion: %v\nstderr:\n%s", bin, strings.Join(args, " "), err, stderr.String())
		}
	}
	return cliResult{exitCode: code, stdout: stdout.String(), stderr: stderr.String()}
}

// firstDiffIndex returns the index of the first byte at which a and b
// differ, or the length of the shorter string if one is a prefix of the
// other -- purely a diagnostic aid for compareCLIOutputs' failure message.
func firstDiffIndex(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// cliDiff describes what, if anything, diverged between two cliResults --
// exit code and stdout are tracked as INDEPENDENT bools (never collapsed
// into one "differs" flag) so a caller can ask about either one
// specifically, as the non-vacuity meta-test below does.
type cliDiff struct {
	exitMismatch   bool
	stdoutMismatch bool
}

// any reports whether d records any divergence at all.
func (d cliDiff) any() bool { return d.exitMismatch || d.stdoutMismatch }

// diffCLIOutputs is the pure, *testing.T-free comparison predicate
// compareCLIOutputs (the suite's real assertion helper) and
// TestCLIByteDiff_ComparisonCatchesDivergence (the non-vacuity meta-test)
// both build on -- the SAME function, so the meta-test proves the EXACT
// predicate the real suite uses, never a separate reimplementation that
// could quietly drift out of sync with it. The zero cliDiff (both fields
// false) means IDENTICAL: stdout byte-for-byte, exit codes equal.
func diffCLIOutputs(goRes, pyRes cliResult) cliDiff {
	return cliDiff{
		exitMismatch:   goRes.exitCode != pyRes.exitCode,
		stdoutMismatch: goRes.stdout != pyRes.stdout,
	}
}

// compareCLIOutputs asserts goRes and pyRes are byte-identical on stdout
// and carry the same exit code -- the CC4 parity assertion (design spec
// §10.4): STDOUT and EXIT CODE are the parity surface; STDERR is
// deliberately excluded (see this file's own doc comment). desc labels the
// comparison in any failure message (normally the full argv compared).
// Never loosens to a substring/prefix/whitespace-insensitive check: a real
// divergence anywhere in stdout must fail this, full stop.
func compareCLIOutputs(t *testing.T, desc string, goRes, pyRes cliResult) {
	t.Helper()
	d := diffCLIOutputs(goRes, pyRes)
	if d.exitMismatch {
		t.Errorf("%s: exit code mismatch: gngsw=%d ngsw=%d\ngngsw stderr:\n%s\nngsw stderr:\n%s",
			desc, goRes.exitCode, pyRes.exitCode, goRes.stderr, pyRes.stderr)
	}
	if d.stdoutMismatch {
		t.Errorf("%s: stdout BYTE-DIFF at offset %d\n--- gngsw stdout (%d bytes) ---\n%s\n--- ngsw stdout (%d bytes) ---\n%s",
			desc, firstDiffIndex(goRes.stdout, pyRes.stdout),
			len(goRes.stdout), goRes.stdout, len(pyRes.stdout), pyRes.stdout)
	}
}

// wantCC4ReadComparisons is the total number of (model, op, format) stdout
// comparisons TestCLIByteDiff_SNMPReads runs -- measured directly against a
// live pair of runs: 11 SNMP-Supported read ops for gsm7252ps (including
// get_syslog) plus 10 for gs728tpp (get_syslog excluded -- see cc4Models'
// own doc comment), each compared in BOTH text and --json form:
// (11 + 10) * 2 = 42. Asserted as an EXACT count (the check is `!=`, so it
// catches silent shrinkage -- a model losing a backend, an op dropped from
// cc4ReadCmd, triples() changing -- AND unexplained growth) exactly like
// wantCC3TripleCount/wantPythonReadTripleCount elsewhere in this package: a
// regression that silently shrank coverage would otherwise still show green
// as long as every comparison that DID run kept passing.
const wantCC4ReadComparisons = 42

// TestCLIByteDiff_SNMPReads is CC4's own deliverable: for every model in
// cc4Models, starts a real Go SNMP fake, enumerates its Supported SNMP read
// triples (the SAME capabilities.Matrix-backed triples() every other suite
// in this package uses, restricted here to backend=snmp), and for each one
// runs BOTH gngsw and the pinned ngsw with IDENTICAL argv (only the binary
// differs) against the SAME running fake endpoint, in both default (table)
// and --json form, asserting stdout is byte-identical and exit codes match.
func TestCLIByteDiff_SNMPReads(t *testing.T) {
	bin := buildGngsw(t)
	provider := &virtual.GoFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	compared := 0
	for _, modelKey := range cc4Models {
		t.Run(modelKey, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), cc4Timeout)
			defer cancel()

			ep, err := provider.StartModel(ctx, modelKey)
			if err != nil {
				t.Fatalf("StartModel(%q): %v", modelKey, err)
			}

			// Restricted to SNMP ONLY: this suite diffs `--backend snmp`
			// exclusively, so only ops the capabilities oracle marks
			// Supported over SNMP for this model may appear here --
			// get_users/get_services/nsdp_device structurally never do
			// (see this file's own doc comment).
			served := map[model.Backend]int{model.BackendSNMP: ep.SnmpPort}
			trips, err := triples(modelKey, capabilities.ReadOperations, served)
			if err != nil {
				t.Fatalf("triples(%q): %v", modelKey, err)
			}
			if len(trips) == 0 {
				t.Fatalf("triples(%q) = 0 SNMP read triples, want at least one Supported op", modelKey)
			}
			host := fmt.Sprintf("%s:%d", ep.Host, ep.SnmpPort)

			for _, tr := range trips {
				cmdName, ok := cc4ReadCmd[tr.Op.Name]
				if !ok {
					t.Fatalf("cc4ReadCmd has no entry for op %q -- add one (get_users/get_services/nsdp_device are deliberately absent, see this file's own doc comment)", tr.Op.Name)
				}
				baseArgs := []string{cmdName, "--model", modelKey, "--host", host, "--community", ep.Community, "--backend", "snmp"}

				for _, asJSON := range []bool{false, true} {
					label := cmdName
					args := append([]string{}, baseArgs...)
					if asJSON {
						args = append(args, "--json")
						label += "/json"
					}
					t.Run(label, func(t *testing.T) {
						goRes := runCLIBinary(ctx, t, bin, args...)
						pyRes := runCLIBinary(ctx, t, cc4PythonNgsw, args...)

						// Non-vacuity guard: both CLIs must actually have
						// run a SUCCESSFUL read (exit 0, non-empty
						// stdout) before this counts as a real comparison
						// -- a silently-empty or erroring invocation on
						// EITHER side must never pass as "no diff found".
						if goRes.exitCode != 0 {
							t.Fatalf("gngsw %s: nonzero exit %d (want a successful read)\nstderr:\n%s", strings.Join(args, " "), goRes.exitCode, goRes.stderr)
						}
						if pyRes.exitCode != 0 {
							t.Fatalf("ngsw %s: nonzero exit %d (want a successful read)\nstderr:\n%s", strings.Join(args, " "), pyRes.exitCode, pyRes.stderr)
						}
						if goRes.stdout == "" {
							t.Fatalf("gngsw %s produced empty stdout", strings.Join(args, " "))
						}
						if pyRes.stdout == "" {
							t.Fatalf("ngsw %s produced empty stdout", strings.Join(args, " "))
						}

						compareCLIOutputs(t, strings.Join(args, " "), goRes, pyRes)
						compared++
					})
				}
			}
		})
	}

	if compared != wantCC4ReadComparisons {
		t.Errorf("compared %d (model, op, format) stdout pairs, want exactly %d -- see wantCC4ReadComparisons' own doc comment", compared, wantCC4ReadComparisons)
	}
}

// TestCLIByteDiff_DryRunWrite drives one disruptive-write command --
// `pvid PORT VLAN --dry-run` -- through both CLIs against the SAME running
// fake, over SNMP, and asserts the "DRY-RUN: would set PVID port ... on
// HOST (nothing sent)" line (safety.go's DoWrite / safety.py's do_write,
// designed to be byte-identical -- see safety.go's own doc comment) is
// byte-identical stdout with a matching exit code. --dry-run sends nothing
// over the wire (Action is never invoked), so this needs the fake
// addressable but never actually mutates it.
func TestCLIByteDiff_DryRunWrite(t *testing.T) {
	bin := buildGngsw(t)
	provider := &virtual.GoFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	const modelKey = "gs728tpp"
	ctx, cancel := context.WithTimeout(context.Background(), cc4Timeout)
	defer cancel()

	ep, err := provider.StartModel(ctx, modelKey)
	if err != nil {
		t.Fatalf("StartModel(%q): %v", modelKey, err)
	}
	m, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", modelKey, err)
	}
	op, err := capabilities.OperationByName("set_pvid")
	if err != nil {
		t.Fatalf("OperationByName(set_pvid): %v", err)
	}
	if verdict := capabilities.For(m, model.BackendSNMP, op); verdict.Support != capabilities.SupportSupported {
		t.Fatalf("set_pvid/snmp not Supported for %q per the capabilities oracle (%s) -- pick a different model", modelKey, verdict.Reason)
	}

	host := fmt.Sprintf("%s:%d", ep.Host, ep.SnmpPort)
	args := []string{
		"pvid", "1", "5",
		"--model", modelKey, "--host", host, "--community", ep.Community, "--backend", "snmp",
		"--dry-run",
	}
	goRes := runCLIBinary(ctx, t, bin, args...)
	pyRes := runCLIBinary(ctx, t, cc4PythonNgsw, args...)

	if goRes.exitCode != 0 {
		t.Fatalf("gngsw %s: nonzero exit %d\nstderr:\n%s", strings.Join(args, " "), goRes.exitCode, goRes.stderr)
	}
	if pyRes.exitCode != 0 {
		t.Fatalf("ngsw %s: nonzero exit %d\nstderr:\n%s", strings.Join(args, " "), pyRes.exitCode, pyRes.stderr)
	}
	if !strings.HasPrefix(goRes.stdout, "DRY-RUN: ") {
		t.Fatalf("gngsw --dry-run stdout does not start with %q: %q", "DRY-RUN: ", goRes.stdout)
	}
	if !strings.HasPrefix(pyRes.stdout, "DRY-RUN: ") {
		t.Fatalf("ngsw --dry-run stdout does not start with %q: %q", "DRY-RUN: ", pyRes.stdout)
	}

	compareCLIOutputs(t, strings.Join(args, " "), goRes, pyRes)
}

// TestCLIByteDiff_ComparisonCatchesDivergence is a META-test proving
// diffCLIOutputs' own non-vacuity floor -- the in-process analogue of the
// live tmp/ scratch experiment run while building this suite (a real
// gngsw `ports` reading, byte-mutated with `sed`, `cmp`'d against the
// unmutated original -- confirmed to differ at the mutated byte, never a
// false pass; see this slice's own delivery report for the exact
// transcript). Deliberately calls the PURE predicate (diffCLIOutputs)
// directly, not compareCLIOutputs -- calling the *testing.T-driven
// assertion helper with data KNOWN to diverge would fail this test itself,
// which is not what a meta-test proving "the predicate correctly detects
// divergence" wants; asking the same underlying function for its verdict
// and asserting on THAT verdict (via the outer test's own t.Errorf,
// exactly like any other assertion) proves the identical logic without
// needing to catch a deliberately-failing subtest.
func TestCLIByteDiff_ComparisonCatchesDivergence(t *testing.T) {
	base := cliResult{exitCode: 0, stdout: "Port  Name\n1     1/0/1\n"}
	mutatedStdout := cliResult{exitCode: 0, stdout: "Port  Name\n1     1/0/1  MUTATED\n"}
	mutatedExit := cliResult{exitCode: 1, stdout: base.stdout}

	if d := diffCLIOutputs(base, mutatedStdout); !d.stdoutMismatch {
		t.Errorf("diffCLIOutputs did not flag a mutated stdout byte -- non-vacuity floor broken")
	}
	if d := diffCLIOutputs(base, mutatedExit); !d.exitMismatch {
		t.Errorf("diffCLIOutputs did not flag a mismatched exit code -- non-vacuity floor broken")
	}
	if d := diffCLIOutputs(base, base); d.any() {
		t.Errorf("diffCLIOutputs flagged two IDENTICAL results as diverging -- comparison is too strict/broken")
	}
}
