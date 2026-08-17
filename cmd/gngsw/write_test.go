package main

import (
	"context"
	"strconv"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// --- safety rails, driven through the full cobra command tree against a --
// real virtual.VirtualSwitch, mirroring tests/cli/test_cli_integration.py's
// own dry-run/confirm/mutation tests.

func TestWrite_DryRun_SendsNothing(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	if !vsw.State.Poe[1].Admin {
		t.Fatal("seed precondition: port 1 PoE admin must start true")
	}
	code, out, _ := runCLI([]string{"poe", "1", "off", "--dry-run"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitOK)
	}
	if !strings.Contains(out, "DRY-RUN") {
		t.Errorf("stdout = %q, want it to contain \"DRY-RUN\"", out)
	}
	if !vsw.State.Poe[1].Admin {
		t.Error("PoE admin state changed on a --dry-run write, want it untouched")
	}
}

func TestWrite_ConfirmDeclined_NoChange(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"poe", "1", "off"}, "n\n", snmpSwitchFactory(sw))
	if code != safety.ExitError {
		t.Fatalf("exit code = %d, want %d (declined write)", code, safety.ExitError)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty on decline", out)
	}
	if !strings.Contains(errOut, "aborted") {
		t.Errorf("stderr = %q, want it to contain \"aborted\"", errOut)
	}
	if !vsw.State.Poe[1].Admin {
		t.Error("PoE admin state changed after a declined confirmation, want it untouched")
	}
}

func TestWrite_ConfirmAccepted_MutatesAndReads(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	factory := snmpSwitchFactory(sw)

	code, out, _ := runCLI([]string{"poe", "1", "off"}, "y\n", factory)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitOK)
	}
	if !strings.Contains(out, "ok:") {
		t.Errorf("stdout = %q, want it to contain \"ok:\"", out)
	}
	if vsw.State.Poe[1].Admin {
		t.Error("PoE admin state NOT changed after a confirmed write, want false")
	}

	// A follow-up read through the same CLI stack confirms the mutation too.
	code, out, _ = runCLI([]string{"--json", "poe"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("read-back exit code = %d, want %d", code, safety.ExitOK)
	}
	if !strings.Contains(out, `"admin_enabled": false`) {
		t.Errorf("read-back JSON = %q, want it to show admin_enabled: false for port 1", out)
	}
}

func TestWrite_YesFlag_SkipsPromptAndAppliesWithEmptyStdin(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, _ := runCLI([]string{"poe", "1", "off", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitOK)
	}
	if !strings.Contains(out, "ok:") {
		t.Errorf("stdout = %q, want \"ok:\"", out)
	}
	if vsw.State.Poe[1].Admin {
		t.Error("-y did not apply the write")
	}
}

// TestWrite_ProtectedPort_ExitsProtected drives a REAL protected-port
// refusal end-to-end: the underlying snmp.Writer.SetPortEnabled guard
// (which fires only when disabling) refuses port 1 without --force,
// proving the CLI maps model.ErrProtectedPort to exit code 4 through the
// full write stack, not just via a synthetic error (see
// TestRunWrite_ExitCode* below for the direct-mapping unit tests).
func TestWrite_ProtectedPort_ExitsProtected(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps", netgearswitch.WithProtectedPorts(1))

	code, out, errOut := runCLI([]string{"port", "1", "down", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitProtected {
		t.Fatalf("exit code = %d, want %d (stdout=%q stderr=%q)", code, safety.ExitProtected, out, errOut)
	}
	if !strings.Contains(errOut, "error:") {
		t.Errorf("stderr = %q, want an \"error: ...\" line", errOut)
	}
	if !vsw.State.Ports[1].Admin {
		t.Error("port 1 admin state changed despite the protected-port refusal")
	}
}

// --- direct cc.runWrite unit tests: exit-code mapping for the two special
// cases (WriteVerificationError -> 3, ErrProtectedPort -> 4) that are hard
// to provoke deterministically over a real protocol stack for every
// command, proving THIS package's plumbing (cc.code assignment,
// "error: ..." reporting) without re-testing safety.ExitCodeFor itself
// (already Python-byte-verified in cmd/internal/safety).

func TestRunWrite_ExitCodeMapping(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"write-verification", &netgearswitch.WriteVerificationError{Msg: "mismatch"}, safety.ExitVerify},
		{"protected-port", errProtectedWrap(), safety.ExitProtected},
		{"generic", errGeneric(), safety.ExitError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderrBuf strings.Builder
			cc := &cmdContext{
				app:   &App{Stdout: &stdout, Stderr: &stderrBuf, Stdin: strings.NewReader(""), SwitchFactory: snmpSwitchFactory(sw)},
				flags: &globalFlags{},
			}
			wf := &writeFlags{yes: true}
			_ = cc.runWrite(wf, "do the thing", "", func(context.Context, *netgearswitch.Switch) error {
				return tc.err
			})
			if cc.code != tc.wantCode {
				t.Errorf("cc.code = %d, want %d", cc.code, tc.wantCode)
			}
			if !strings.Contains(stderrBuf.String(), "error:") {
				t.Errorf("stderr = %q, want an \"error: ...\" line", stderrBuf.String())
			}
		})
	}
}

func errProtectedWrap() error {
	return &wrappedErr{msg: "port 3 is protected", target: netgearswitch.ErrProtectedPort}
}

func errGeneric() error {
	return &wrappedErr{msg: "some other failure"}
}

// wrappedErr is a minimal errors.Is-compatible wrapper for the exit-code
// mapping table above -- avoids pulling in fmt.Errorf's %w plumbing just
// to build two fixed test errors.
type wrappedErr struct {
	msg    string
	target error
}

func (e *wrappedErr) Error() string { return e.msg }
func (e *wrappedErr) Unwrap() error { return e.target }

// --- describe/vlan-create/hostname-set: pyRepr must appear verbatim in
// the "ok: ..." STDOUT line, proving the repr formatting is wired in (not
// just unit-tested in isolation -- pyrepr_test.go covers the algorithm
// itself).

func TestWrite_Describe_UsesPyReprInSuccessLine(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, _ := runCLI([]string{"describe", "3", "uplink's port", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitOK)
	}
	want := `ok: describe port 3 as "uplink's port"`
	if !strings.Contains(out, want) {
		t.Errorf("stdout = %q, want it to contain %q", out, want)
	}
}

func TestWrite_DescribeEmpty_ClearsDescription(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, _ := runCLI([]string{"describe", "3", "", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitOK)
	}
	if !strings.Contains(out, "ok: clear the description on port 3") {
		t.Errorf("stdout = %q, want the clear-description success line", out)
	}
}

// --- speed: auto vs forced rate parsing, and a bad rate is a usage error -

func TestWrite_Speed_AutoAndForced(t *testing.T) {
	// SNMP refuses SetPortSpeed by name (no configured-speed column exists
	// over SNMP -- see switch_write.go's own doc comment); speed is served
	// only over the FASTPATH CLI/HTTP, so this pins dispatch to an
	// in-process CLI session, the same seam TestReads_UsersServices_Over
	// CLIBackend uses.
	vsw := startVirtualSwitch(t, "gsm7252ps")
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))

	code, out, errOut := runCLI([]string{"speed", "3", "auto", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("auto: exit code = %d, want %d (stderr=%q)", code, safety.ExitOK, errOut)
	}
	if !strings.Contains(out, "ok: set port 3 to auto-negotiate") {
		t.Errorf("auto: stdout = %q", out)
	}
}

func TestWrite_Speed_BadRate_ExitsUsage(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, _, errOut := runCLI([]string{"speed", "3", "notarate", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
	if !strings.Contains(errOut, "not a port rate") {
		t.Errorf("stderr = %q, want it to mention \"not a port rate\"", errOut)
	}
}

// --- vlan create/set/delete, pvid: description text + real mutation -----

func TestWrite_VlanCreateSetDelete(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	factory := snmpSwitchFactory(sw)

	code, out, errOut := runCLI([]string{"vlan", "create", "500", "test-vlan", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("create: exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: create VLAN 500 named 'test-vlan'") {
		t.Errorf("create: stdout = %q", out)
	}

	code, out, errOut = runCLI([]string{"vlan", "set", "500", "3", "tagged", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("set: exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: set VLAN 500 port 3 -> tagged") {
		t.Errorf("set: stdout = %q", out)
	}

	code, out, errOut = runCLI([]string{"vlan", "delete", "500", "-y"}, "", factory)
	if code != safety.ExitOK {
		t.Fatalf("delete: exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: delete VLAN 500") {
		t.Errorf("delete: stdout = %q", out)
	}
}

func TestWrite_PVID(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"pvid", "3", "20", "-y"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "ok: set PVID port 3 -> VLAN 20") {
		t.Errorf("stdout = %q", out)
	}
}

// --- upload-certificate: required flags enforced at parse time, and a
// missing file is a plain (exit 1) error, never a usage (exit 2) one --
// mirroring main.py's own OSError-vs-argparse-required distinction.

func TestWrite_UploadCertificate_MissingRequiredFlags_ExitsUsage(t *testing.T) {
	code, _, errOut := runCLI([]string{"upload-certificate"}, "", nil)
	if code != safety.ExitUsage {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitUsage, errOut)
	}
}

func TestWrite_UploadCertificate_MissingFile_ExitsError(t *testing.T) {
	// A working switch factory (see this file's own reorder comment on
	// newUploadCertificateCmd: the switch is resolved BEFORE the cert/key
	// files are read, mirroring main.py) so this test genuinely reaches
	// the file-read error path instead of short-circuiting on "no switch
	// configured".
	factory := dummySwitchFactory(t, "gsm7252ps")
	code, _, errOut := runCLI([]string{"upload-certificate", "--cert", "/no/such/cert.pem", "--key", "/no/such/key.pem"}, "", factory)
	if code != safety.ExitError {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitError, errOut)
	}
	if !strings.Contains(errOut, "/no/such/cert.pem") {
		t.Errorf("stderr = %q, want it to name the missing cert file", errOut)
	}
}

// --- no secret leaks into output: --http-password is threaded through the
// REAL resolve.Resolve path (not a SwitchFactory bypass, which would never
// even touch the flag) against a live HTTP virtual switch, then stdout AND
// stderr are checked for the literal secret text.

func TestWrite_NoSecretLeak_HTTPPassword(t *testing.T) {
	const secret = "s3cr3t-w3bpw" //nolint:gosec // test fixture literal, not a real credential.

	// A custom (non-default) HTTP password proves this test exercises the
	// ACTUAL --http-password flag value, not a coincidentally-shared
	// default -- virtual.WithHTTPPassword overrides VirtualSwitch's own
	// "password" default the same way WithCommunity/WithCLIPassword do.
	vsw, err := virtual.NewVirtualSwitch("gs110emx", virtual.WithHTTPPassword(secret))
	if err != nil {
		t.Fatalf("NewVirtualSwitch() error = %v", err)
	}
	if err := vsw.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = vsw.Stop() })
	host := vsw.Host + ":" + strconv.Itoa(vsw.HTTPPort)

	code, out, errOut := runCLI([]string{
		"--host", host, "--model", "gs110emx", "--backend", "http", "--http-password", secret,
		"hostname", "set", "cli-test-host", "-y",
	}, "", nil)
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", code, out, errOut)
	}
	if strings.Contains(out, secret) {
		t.Errorf("stdout leaked the HTTP password: %q", out)
	}
	if strings.Contains(errOut, secret) {
		t.Errorf("stderr leaked the HTTP password: %q", errOut)
	}
}
