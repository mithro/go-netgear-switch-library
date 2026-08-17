package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// --- upload-certificate / upload-certificate-scp: real success + dry-run,
// each proving the description/warning wiring reaches the exact literal
// "ok: ..."/"DRY-RUN: ..." STDOUT line every other write command already
// gets pinned against, against a REAL virtual.VirtualSwitch (never a
// SwitchFactory-injected fake protocol client for the success path).

// TestWrite_UploadCertificate_Success drives upload-certificate through
// the REAL resolve.Resolve path (--host host:port, no SwitchFactory
// bypass) against gsm7228ps's live HTTP face -- webui.Writer.
// UploadCertificate's S3300 multipart flow accepts any PEM-shaped string
// without parsing it (see facade_http_integration_test.go's own
// TestFacadeHTTPIntegration_GSM7228PSReadsNonVacuousSensorsUnsupportedAndCertUpload,
// whose exact certPEM/keyPEM literals this test reuses).
func TestWrite_UploadCertificate_Success(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.HTTPPort)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	argv := []string{
		"--host", host, "--model", "gsm7228ps", "--backend", "http", "--http-password", "password",
		"upload-certificate", "--cert", certPath, "--key", keyPath, "--force", "-y",
	}
	code, out, errOut := runCLI(argv, "", nil)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	want := fmt.Sprintf("ok: upload SSL certificate (%s) + key (%s)", certPath, keyPath)
	if !strings.Contains(out, want) {
		t.Errorf("stdout = %q, want it to contain %q", out, want)
	}
}

func TestWrite_UploadCertificate_DryRun(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.HTTPPort)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	argv := []string{
		"--host", host, "--model", "gsm7228ps", "--backend", "http", "--http-password", "password",
		"upload-certificate", "--cert", certPath, "--key", keyPath, "--dry-run",
	}
	code, out, errOut := runCLI(argv, "", nil)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	want := fmt.Sprintf("DRY-RUN: would upload SSL certificate (%s) + key (%s) on %s (nothing sent)", certPath, keyPath, host)
	if !strings.Contains(out, want) {
		t.Errorf("stdout = %q, want it to contain %q", out, want)
	}
}

// TestWrite_UploadCertificateSCP_Success drives upload-certificate-scp
// against gsm7252ps's in-process CLI session (the same cliBackedSwitch
// seam TestWrite_FlowControl/TestWrite_Speed_AutoAndForced use): CliFace.
// RunSCPCopy/RunWriteMemory (virtual/cliface.go) are a full in-process
// stand-in for the interactive copy-scp/(y/n) handshake and always
// report success, so this reaches DeployCertificateSCP's entire 5-step
// command sequence for real.
func TestWrite_UploadCertificateSCP_Success(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(pwFile, []byte("scppass123\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	argv := []string{"upload-certificate-scp", "--scp-source", "user@stagehost", "--scp-password-file", pwFile, "-y"}
	code, out, errOut := runCLI(argv, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	// remote-dir defaults to "/var/lib/switchcert/staging"; the description
	// concatenates scp_source and remote_dir with NO separating slash
	// (fastpath.ScpSourceURL's own documented hazard -- remote_dir already
	// starts with "/"), reproduced here VERBATIM, not "fixed".
	want := "ok: deploy SSL certificate over SCP from user@stagehost/var/lib/switchcert/staging"
	if !strings.Contains(out, want) {
		t.Errorf("stdout = %q, want it to contain %q", out, want)
	}
}

func TestWrite_UploadCertificateSCP_DryRun(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(pwFile, []byte("scppass123\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	argv := []string{"upload-certificate-scp", "--scp-source", "user@stagehost", "--scp-password-file", pwFile, "--dry-run"}
	code, out, errOut := runCLI(argv, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	want := "DRY-RUN: would deploy SSL certificate over SCP from user@stagehost/var/lib/switchcert/staging on"
	if !strings.Contains(out, want) {
		t.Errorf("stdout = %q, want it to contain %q", out, want)
	}
}

// --- upload-certificate-scp: the "file empty after strip" branch ---------

func TestWrite_UploadCertificateSCP_EmptyPasswordFile_ExitsError(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(pwFile, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// A working switch factory -- the switch is resolved BEFORE the
	// password file is read, mirroring main.py (see write.go's reorder
	// comment on newUploadCertificateSCPCmd) -- so this test genuinely
	// reaches the empty-password-file check.
	factory := dummySwitchFactory(t, "gsm7252ps")
	code, _, errOut := runCLI([]string{
		"upload-certificate-scp", "--scp-source", "user@host", "--scp-password-file", pwFile,
	}, "", factory)
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
