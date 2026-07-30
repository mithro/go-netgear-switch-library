package virtual

// oracle_test.go: net-snmp CLI subprocess "oracle" tests against SnmpFace --
// i.e. tests driven by the REAL net-snmp reference implementation
// (snmpget/snmpbulkwalk binaries), not this repo's own gosnmp-based client
// (snmpface_test.go already covers the gosnmp-client path exhaustively).
// This is an independent proof that the wire codec + is_implemented gate
// this package implements (snmpface.go/mibview.go) is faithful to a real
// SNMP agent's on-the-wire text/behaviour, not merely internally
// self-consistent with our own client. See D-VIRT §3.7/§6.2 and Task 13's
// brief.
//
// The test binary itself is already run under scripts/jail.sh's CPU/memory
// limits by `make test`, so these subprocess calls are deliberately NOT
// re-wrapped in jail.sh here -- doing so would be a redundant, nested jail.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// netSnmpBinaries are the net-snmp CLI tools these tests subprocess into.
var netSnmpBinaries = []string{"snmpget", "snmpbulkwalk"}

// requireNetSnmp skips t (naming the missing binary) iff a net-snmp CLI
// tool this file needs is genuinely absent from PATH. Per the brief these
// binaries exist in dev+CI, so this is a defensive skip, never the
// expected path.
func requireNetSnmp(t *testing.T) {
	t.Helper()
	for _, bin := range netSnmpBinaries {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("net-snmp CLI tool %q not found on PATH (skipping oracle test): %v", bin, err)
		}
	}
}

// runNetSnmp runs one net-snmp CLI command under a bounded context timeout,
// returning its combined stdout+stderr and exit code. Fails the test
// (rather than skipping) on anything other than a normal exit or a
// deadline: requireNetSnmp already ruled out the binary being missing, so a
// failure to even start the process here is a genuine test-environment bug.
func runNetSnmp(t *testing.T, timeout time.Duration, name string, args ...string) (output string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()

	if ctx.Err() != nil {
		t.Fatalf("%s %v timed out after %s; output so far:\n%s", name, args, timeout, buf.String())
	}
	if err == nil {
		return buf.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return buf.String(), exitErr.ExitCode()
	}
	t.Fatalf("%s %v: failed to run: %v", name, args, err)
	return "", -1
}

// stringLineRE matches one net-snmp `-Oe -OU` STRING-typed varbind output
// line (e.g. `.1.3.6.1.2.1.17.7.1.4.3.1.1.90 = STRING: "iot"`), capturing
// the quoted value.
var stringLineRE = regexp.MustCompile(`= STRING: "(.*)"$`)

// parseStringLines extracts every `= STRING: "..."` value, in output-line
// order, from a net-snmp CLI command's combined output.
func parseStringLines(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		if m := stringLineRE.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

// TestOracleSnmpbulkwalkDot1qVlanStaticNameYieldsExactly14Names is the
// brief's headline oracle assertion: a REAL net-snmp CLI bulkwalk of
// dot1qVlanStaticName against the SNMP face serving gsm7252ps's seed must
// yield exactly the 14 VLAN names D-VIRT §4.1 transcribes from the real
// hardware capture -- never more (a leak from an adjacent subtree), never
// fewer (a dropped row), and matching by content, not just count.
func TestOracleSnmpbulkwalkDot1qVlanStaticNameYieldsExactly14Names(t *testing.T) {
	requireNetSnmp(t)
	sw := startVirtualSwitch(t, "gsm7252ps")
	addr := fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort)

	out, exit := runNetSnmp(t, 10*time.Second, "snmpbulkwalk",
		"-v2c", "-c", "public", "-On", "-Oe", "-OU", "-Ln", addr,
		"1.3.6.1.2.1.17.7.1.4.3.1.1", // dot1qVlanStaticName
	)
	if exit != 0 {
		t.Fatalf("snmpbulkwalk exit = %d, want 0; output:\n%s", exit, out)
	}

	names := parseStringLines(out)
	want := []string{
		"default", "wifi", "net", "pwr", "store", "int", "roam", "fpgas",
		"sm", "sdr", "iot", "guest", "t-fpgas", "t-sm",
	}
	if len(names) != len(want) {
		t.Fatalf("snmpbulkwalk of dot1qVlanStaticName yielded %d names, want exactly %d\nnames: %v\noutput:\n%s",
			len(names), len(want), names, out)
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("snmpbulkwalk names %v missing expected %q", names, w)
		}
	}
}

// TestOracleSnmpbulkwalkPoERootOnM4300ReportsSingleNoSuchObjectLine is the
// brief's second headline assertion: on m4300-24x (0 PSE ports -- VERIFIED
// no PoE, D-VIRT §4.3), a real net-snmp bulkwalk of the RFC3621 PoE MIB
// root must answer the literal net-snmp text for a noSuchObject varbind
// EXACTLY ONCE (never falling through to whatever unrelated OID sorts next
// in the seeded state, and never printed more than once even though
// snmpbulkwalk's GETBULK repeats several times per request -- see
// snmpface.go's handleGetBulk doc comment for why every repetition past
// the first is endOfMibView fill instead).
func TestOracleSnmpbulkwalkPoERootOnM4300ReportsSingleNoSuchObjectLine(t *testing.T) {
	requireNetSnmp(t)
	sw := startVirtualSwitch(t, "m4300-24x")
	addr := fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort)

	out, exit := runNetSnmp(t, 10*time.Second, "snmpbulkwalk",
		"-v2c", "-c", "public", "-On", "-Oe", "-OU", "-Ln", addr,
		"1.3.6.1.2.1.105.1.1.1", // pethPsePortTable (PoE MIB root)
	)
	if exit != 0 {
		t.Fatalf("snmpbulkwalk exit = %d, want 0; output:\n%s", exit, out)
	}

	const wantLine = "No Such Object available on this agent at this OID"
	if count := strings.Count(out, wantLine); count != 1 {
		t.Errorf("snmpbulkwalk of PoE MIB root on m4300-24x: %q occurs %d times, want exactly 1\noutput:\n%s",
			wantLine, count, out)
	}

	// Every other line in the response must be the GETBULK endOfMibView
	// fill, never real seeded data leaking from an unrelated subtree.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, wantLine) {
			continue
		}
		if !strings.Contains(line, "No more variables left in this MIB View") {
			t.Errorf("unexpected non-fill line in PoE-root walk output: %q", line)
		}
	}
}

// TestOracleSnmpgetPresentScalarSucceeds pins the "present instance"
// half of the brief's single-OID snmpget pair: a real net-snmp GET of
// sysDescr (a scalar every model implements) must succeed (exit 0) and
// carry the exact seeded text.
func TestOracleSnmpgetPresentScalarSucceeds(t *testing.T) {
	requireNetSnmp(t)
	sw := startVirtualSwitch(t, "gsm7252ps")
	addr := fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort)

	out, exit := runNetSnmp(t, 10*time.Second, "snmpget",
		"-v2c", "-c", "public", "-On", "-Oe", "-OU", addr,
		"1.3.6.1.2.1.1.1.0", // sysDescr
	)
	if exit != 0 {
		t.Fatalf("snmpget sysDescr exit = %d, want 0; output:\n%s", exit, out)
	}
	if !strings.Contains(out, "STRING:") {
		t.Errorf("snmpget sysDescr output missing a STRING: value; got:\n%s", out)
	}
	if !strings.Contains(out, sw.State.SysDescr) {
		t.Errorf("snmpget sysDescr output %q does not contain the seeded sysDescr %q", out, sw.State.SysDescr)
	}
}

// TestOracleSnmpgetAbsentInstanceReportsNoSuchInstanceAtExitZero pins the
// "absent instance" half of the brief's single-OID snmpget pair, and its
// exit-status convention: ifOperStatus is an IMPLEMENTED column (the
// IF-MIB always exists on every model), but port 9999 has no row -- the
// "implemented subtree, absent instance" branch of D-VIRT §2.9's
// three-way rule, which must answer noSuchInstance, distinct from
// noSuchObject. Per net-snmp's own exit-status convention (confirmed
// empirically against this exact mock): a per-varbind noSuchInstance
// exception VALUE embedded in a normal GetResponse PDU is not a
// protocol-level error, so snmpget still exits 0 -- unlike, say, a timeout
// or an unknown-host failure, which exit nonzero.
func TestOracleSnmpgetAbsentInstanceReportsNoSuchInstanceAtExitZero(t *testing.T) {
	requireNetSnmp(t)
	sw := startVirtualSwitch(t, "gsm7252ps")
	addr := fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort)

	out, exit := runNetSnmp(t, 10*time.Second, "snmpget",
		"-v2c", "-c", "public", "-On", "-Oe", "-OU", addr,
		"1.3.6.1.2.1.2.2.1.8.9999", // ifOperStatus.9999 (no such port)
	)
	if exit != 0 {
		t.Errorf("snmpget of absent instance exit = %d, want 0 (net-snmp treats a per-varbind noSuchInstance as a successful GET response, not a protocol error); output:\n%s", exit, out)
	}
	const want = "No Such Instance currently exists at this OID"
	if !strings.Contains(out, want) {
		t.Errorf("snmpget of absent instance output = %q, want it to contain %q", out, want)
	}
}

// TestOracleSnmpgetOfUnimplementedSubtreeReportsNoSuchObjectAtExitZero
// exercises the GET path's equivalent of the bulkwalk noSuchObject test
// above: a single-OID snmpget (not a walk) landing on an unimplemented
// subtree (the PoE MIB, on the non-PoE m4300-24x) must also answer
// noSuchObject, at the same exit-0 convention as the noSuchInstance case --
// proving the is_implemented gate applies identically to both request
// shapes (D-VIRT §2.9), not just to GETNEXT/GETBULK.
func TestOracleSnmpgetOfUnimplementedSubtreeReportsNoSuchObjectAtExitZero(t *testing.T) {
	requireNetSnmp(t)
	sw := startVirtualSwitch(t, "m4300-24x")
	addr := fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort)

	out, exit := runNetSnmp(t, 10*time.Second, "snmpget",
		"-v2c", "-c", "public", "-On", "-Oe", "-OU", addr,
		"1.3.6.1.2.1.105.1.1.1.3.1.1", // pethPsePortAdminEnable.1.1: under the unimplemented PoE root
	)
	if exit != 0 {
		t.Errorf("snmpget under unimplemented PoE subtree exit = %d, want 0; output:\n%s", exit, out)
	}
	const want = "No Such Object available on this agent at this OID"
	if !strings.Contains(out, want) {
		t.Errorf("snmpget under unimplemented PoE subtree output = %q, want it to contain %q", out, want)
	}
}
