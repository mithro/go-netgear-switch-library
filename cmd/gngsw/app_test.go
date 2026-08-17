package main

import (
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
)

// TestWrite_EmptyStdinEOF_TreatedAsDecline mirrors safety.Confirm's own
// documented EOF-is-a-decline-not-an-error contract (cmd/internal/safety),
// proving this package's write path (cc.streams()) actually wires stdin
// through so that contract is reachable from a real command, not just
// exercised inside the safety package's own unit tests.
func TestWrite_EmptyStdinEOF_TreatedAsDecline(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"poe", "1", "off"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitError {
		t.Fatalf("exit code = %d, want %d (an immediate EOF must decline, not error)", code, safety.ExitError)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if !strings.Contains(errOut, "aborted") {
		t.Errorf("stderr = %q, want \"aborted: no changes made\"", errOut)
	}
	if !vsw.State.Poe[1].Admin {
		t.Error("PoE admin state changed despite the EOF decline")
	}
}

// TestVerboseFlag_PrintsExtraDiagnostic proves -v/--verbose actually
// changes stderr output on a failing read (this package's best-effort
// analogue of Python's `-v` traceback -- see printVerboseChain's own doc
// comment for why it cannot be a literal port).
func TestVerboseFlag_PrintsExtraDiagnostic(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	// A model with no MAC table over the resolved backend would do, but the
	// simplest reliable failure is nsdp-device against an SNMP-only model:
	// GetMACs/NSDPDevice reject before touching the wire.
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	_, quietErr, quietErrOut := runCLI([]string{"nsdp-device"}, "", snmpSwitchFactory(sw))
	_, _, verboseErrOut := runCLI([]string{"-v", "nsdp-device"}, "", snmpSwitchFactory(sw))
	if quietErr != "" {
		t.Fatalf("unexpected stdout on error: %q", quietErr)
	}
	if !strings.Contains(quietErrOut, "error:") {
		t.Fatalf("quiet stderr = %q, want an \"error: ...\" line", quietErrOut)
	}
	if len(verboseErrOut) <= len(quietErrOut) {
		t.Errorf("-v stderr (%d bytes) not longer than non-verbose stderr (%d bytes); want extra diagnostic output", len(verboseErrOut), len(quietErrOut))
	}
	if !strings.HasSuffix(verboseErrOut, quietErrOut) {
		t.Errorf("-v stderr = %q, want it to END with the same \"error: ...\" line non-verbose prints (%q)", verboseErrOut, quietErrOut)
	}
}
