package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/resolve"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
)

// fixedNow is runCapture's injectable clock (mirrors cli/capture.py's own
// `now: Callable[[], datetime] | None` test seam), pinned so
// captured_at is deterministic across test runs.
func fixedNow() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }

func TestRunCapture_SnapshotOnly(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	outPath := filepath.Join(t.TempDir(), "capture.json")

	ctx, cancel := context.WithTimeout(context.Background(), cliTestTimeout)
	defer cancel()
	record, err := runCapture(ctx, sw, outPath, true, nil, fixedNow)
	if err != nil {
		t.Fatalf("runCapture() error = %v", err)
	}
	if record.Model != "gsm7252ps" {
		t.Errorf("record.Model = %q, want \"gsm7252ps\"", record.Model)
	}
	if len(record.Notes) != 1 || record.Notes[0] != "snapshot-only: no raw protocol exchange recorded" {
		t.Errorf("record.Notes = %v, want exactly the snapshot-only note", record.Notes)
	}
	if len(record.RawExchanges) != 0 {
		t.Errorf("record.RawExchanges = %v, want empty on --snapshot-only", record.RawExchanges)
	}
	if len(record.Snapshot.Ports) == 0 {
		t.Error("record.Snapshot.Ports is empty, want the real virtual switch's port table")
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", outPath, err)
	}
	if strings.HasSuffix(string(raw), "\n") {
		t.Error("capture output file ends with a trailing newline, want none (matches Python's write_text with no appended newline)")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("capture output is not valid JSON: %v\n%s", err, raw)
	}
	if decoded["model"] != "gsm7252ps" {
		t.Errorf("decoded[model] = %v, want \"gsm7252ps\"", decoded["model"])
	}
	if decoded["captured_at"] != "2026-08-18T12:00:00Z" {
		t.Errorf("decoded[captured_at] = %v, want the fixed clock's RFC3339 rendering", decoded["captured_at"])
	}
}

func TestRunCapture_NoRawWalkGiven(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	outPath := filepath.Join(t.TempDir(), "capture.json")

	ctx, cancel := context.WithTimeout(context.Background(), cliTestTimeout)
	defer cancel()
	record, err := runCapture(ctx, sw, outPath, false, nil, fixedNow)
	if err != nil {
		t.Fatalf("runCapture() error = %v", err)
	}
	if len(record.Notes) != 1 || !strings.Contains(record.Notes[0], "no raw-capture backend available") {
		t.Errorf("record.Notes = %v, want the \"no raw-capture backend available\" note", record.Notes)
	}
}

func TestRunCapture_RawWalkSuccess(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	outPath := filepath.Join(t.TempDir(), "capture.json")

	fakeWalk := func(_ context.Context, host, base string) ([]string, error) {
		return []string{host + " " + base + " line1", "line2"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliTestTimeout)
	defer cancel()
	record, err := runCapture(ctx, sw, outPath, false, fakeWalk, fixedNow)
	if err != nil {
		t.Fatalf("runCapture() error = %v", err)
	}
	if len(record.RawExchanges) != 1 {
		t.Fatalf("record.RawExchanges = %v, want exactly 1 entry", record.RawExchanges)
	}
	exch := record.RawExchanges[0]
	if exch["protocol"] != "snmp" {
		t.Errorf("exchange[protocol] = %v, want \"snmp\"", exch["protocol"])
	}
	resp, ok := exch["response"].([]string)
	if !ok || len(resp) != 2 || resp[1] != "line2" {
		t.Errorf("exchange[response] = %v, want [\"...\", \"line2\"]", exch["response"])
	}
	if len(record.Notes) != 0 {
		t.Errorf("record.Notes = %v, want empty on a successful walk", record.Notes)
	}
}

func TestRunCapture_RawWalkFailure_RecordsHonestFailure(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	outPath := filepath.Join(t.TempDir(), "capture.json")

	walkErr := errors.New("snmpbulkwalk exited 1: timeout")
	fakeWalk := func(context.Context, string, string) ([]string, error) { return nil, walkErr }

	ctx, cancel := context.WithTimeout(context.Background(), cliTestTimeout)
	defer cancel()
	record, err := runCapture(ctx, sw, outPath, false, fakeWalk, fixedNow)
	if err != nil {
		t.Fatalf("runCapture() error = %v, want the walk failure recorded (not propagated)", err)
	}
	if len(record.RawExchanges) != 1 {
		t.Fatalf("record.RawExchanges = %v, want exactly 1 entry", record.RawExchanges)
	}
	if !strings.Contains(record.RawExchanges[0]["error"].(string), "timeout") {
		t.Errorf("exchange[error] = %v, want it to mention the walk failure", record.RawExchanges[0]["error"])
	}
	if len(record.Notes) != 1 || !strings.Contains(record.Notes[0], "raw protocol walk failed") {
		t.Errorf("record.Notes = %v, want a \"raw protocol walk failed\" note", record.Notes)
	}
}

func TestRunCapture_SwitchNotFound_ErrorsCleanly(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	// A directory that doesn't exist -- os.WriteFile fails, and the error
	// wraps model.ErrConfig, mirroring cli/capture.py's own ConfigError.
	badPath := filepath.Join(t.TempDir(), "no", "such", "dir", "capture.json")
	ctx, cancel := context.WithTimeout(context.Background(), cliTestTimeout)
	defer cancel()
	_, err := runCapture(ctx, sw, badPath, true, nil, fixedNow)
	if err == nil {
		t.Fatal("runCapture() with an unwritable path returned nil error, want one")
	}
}

// --- capture subcommand, end to end through the cobra command tree -------

func TestCaptureCmd_SnapshotOnly_EndToEnd(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	outPath := filepath.Join(t.TempDir(), "capture.json")

	code, out, errOut := runCLI([]string{"capture", outPath, "--snapshot-only"}, "", snmpSwitchFactory(sw))
	if code != safety.ExitOK {
		t.Fatalf("exit code = %d, want %d (stderr=%q)", code, safety.ExitOK, errOut)
	}
	if !strings.Contains(out, "wrote capture for gsm7252ps to "+outPath) {
		t.Errorf("stdout = %q, want the \"wrote capture for ...\" line", out)
	}
	if !strings.Contains(errOut, "note: snapshot-only") {
		t.Errorf("stderr = %q, want a \"note: snapshot-only ...\" line", errOut)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("capture output file was not written: %v", err)
	}
}

func TestCaptureCmd_SwitchResolutionFails_ExitsError(t *testing.T) {
	wantErr := errors.New("boom: no such switch")
	failFactory := func(resolve.Params) (*netgearswitch.Switch, error) { return nil, wantErr }
	outPath := filepath.Join(t.TempDir(), "capture.json")

	code, out, errOut := runCLI([]string{"capture", outPath}, "", failFactory)
	if code != safety.ExitError {
		t.Fatalf("exit code = %d, want %d", code, safety.ExitError)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if !strings.Contains(errOut, "boom: no such switch") {
		t.Errorf("stderr = %q, want it to contain the resolution error", errOut)
	}
}
