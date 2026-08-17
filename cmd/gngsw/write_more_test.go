package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
)

// write_more_test.go covers the remaining write subcommands
// write_test.go doesn't already exercise (flow-control, cycle-poe,
// clear-poe-fault, ip set, syslog set/add/remove, poe's on/cycle/
// clear-fault branches, speed's forced-rate "G" suffix branch), plus a
// couple of small pure-function edge cases (universalNewlines,
// scp-password-file-is-empty).

func TestWrite_FlowControl(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	// SNMP/NSDP/HTTP all refuse SetFlowControl by name (CLI-only op -- see
	// switch_write.go's own doc comment), so this pins dispatch to an
	// in-process CLI session, same as the speed test.
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))

	code, out, errOut := runCLI([]string{"flow-control", "3", "on", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: turn flow control on for port 3") {
		t.Errorf("stdout = %q", out)
	}
}

func TestWrite_CyclePoE(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"cycle-poe", "1", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: power-cycle PoE port 1") {
		t.Errorf("stdout = %q", out)
	}
}

func TestWrite_ClearPoEFault(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"clear-poe-fault", "1", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: clear PoE fault on port 1") {
		t.Errorf("stdout = %q", out)
	}
}

func TestWrite_Poe_OnCycleClearFault_Branches(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	factory := snmpSwitchFactory(sw)

	for _, tc := range []struct {
		action string
		want   string
	}{
		{"on", "ok: set PoE port 2 -> on"},
		{"cycle", "ok: set PoE port 2 -> cycle"},
		{"clear-fault", "ok: set PoE port 2 -> clear-fault"},
	} {
		code, out, errOut := runCLI([]string{"poe", "2", tc.action, "-y"}, "", factory)
		if code != safety.ExitOK {
			t.Fatalf("action=%s: exit code = %d, want 0 (stderr=%q)", tc.action, code, errOut)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("action=%s: stdout = %q, want it to contain %q", tc.action, out, tc.want)
		}
	}
}

func TestWrite_Poe_InvalidAction_ExitsUsage(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, _, errOut := runCLI([]string{"poe", "2", "bogus"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
}

func TestWrite_Speed_ForcedRateWithGSuffix(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))

	code, out, errOut := runCLI([]string{"speed", "3", "10G", "--duplex", "half", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: force port 3 to 10000 Mbit/s half-duplex") {
		t.Errorf("stdout = %q", out)
	}
}

func TestWrite_Speed_BadDuplex_ExitsUsage(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, _, errOut := runCLI([]string{"speed", "3", "100", "--duplex", "sideways", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
}

func TestWrite_IPSet_RequiresForce(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	factory := snmpSwitchFactory(sw)

	// SetMgmtIP's unconditional force-gate refuses without --force,
	// regardless of protected_ports -- see switch_write.go's own doc
	// comment. Proves the CLI thread's --force flag through, and that the
	// warning text is printed as part of the confirmation flow.
	code, _, errOut := runCLI([]string{"ip", "set", "10.1.5.99", "255.255.255.0", "10.1.5.1", "-y"}, "", factory)
	if code == safety.ExitOK {
		t.Fatalf("exit code = %d, want a non-zero refusal (no --force given)", code)
	}
	if !strings.Contains(errOut, "error:") {
		t.Errorf("stderr = %q, want an \"error: ...\" line", errOut)
	}

	code, out, errOut := runCLI([]string{"ip", "set", "10.1.5.99", "255.255.255.0", "10.1.5.1", "-y", "--force"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("--force: exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: set mgmt IP 10.1.5.99 netmask 255.255.255.0 gw 10.1.5.1") {
		t.Errorf("--force: stdout = %q", out)
	}
}

func TestWrite_SyslogSet(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"syslog", "set", "on", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: turn remote logging on") {
		t.Errorf("stdout = %q", out)
	}
}

func TestWrite_SyslogSet_BadState_ExitsUsage(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, _, errOut := runCLI([]string{"syslog", "set", "sideways", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
}

func TestWrite_SyslogAddRemove(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	// AddSyslogCollector/RemoveSyslogCollector are CLI-only ops.
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))

	code, out, errOut := runCLI([]string{"syslog", "add", "10.9.9.9", "--port", "5140", "--severity", "3", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("add: exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: add syslog collector 10.9.9.9 (port 5140, severity 3)") {
		t.Errorf("add: stdout = %q", out)
	}

	code, out, errOut = runCLI([]string{"syslog", "remove", "10.9.9.9", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("remove: exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: remove syslog collector 10.9.9.9") {
		t.Errorf("remove: stdout = %q", out)
	}
}

func TestWrite_SyslogAdd_BadSeverity_ExitsUsage(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))

	code, _, errOut := runCLI([]string{"syslog", "add", "10.9.9.9", "--severity", "9", "-y"}, "", factory)
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
}

// --- upload-certificate-scp: the "file empty after strip" branch ---------

func TestWrite_UploadCertificateSCP_EmptyPasswordFile_ExitsError(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(pwFile, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	code, _, errOut := runCLI([]string{
		"upload-certificate-scp", "--scp-source", "user@host", "--scp-password-file", pwFile,
	}, "", nil)
	if code != safety.ExitError {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitError)
	}
	if !strings.Contains(errOut, "--scp-password-file is empty") {
		t.Errorf("stderr = %q, want the empty-file message", errOut)
	}
}

func TestWrite_UploadCertificateSCP_MissingRequiredFlags_ExitsUsage(t *testing.T) {
	code, _, errOut := runCLI([]string{"upload-certificate-scp"}, "", nil)
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
}

// --- universalNewlines: direct unit test of the pure helper --------------

func TestUniversalNewlines(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\r\nb\r\nc", "a\nb\nc"},
		{"a\rb\rc", "a\nb\nc"},
		{"a\nb\nc", "a\nb\nc"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := universalNewlines(tc.in); got != tc.want {
			t.Errorf("universalNewlines(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
