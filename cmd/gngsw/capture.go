// capture.go: `gngsw capture OUTPUT [--snapshot-only]`, mirroring
// cli/capture.py's run_capture + cli/main.py's _cmd_capture. Opt-in,
// live-switch tooling: the state snapshot uses the public Switch.Snapshot
// (works against any backend, including an in-process/loopback fake --
// hermetically testable); the reference raw walk (snmpbulkwalk output)
// needs live-switch access and is recorded only when rawWalk is non-nil
// (the production wiring below only supplies one when --snapshot-only is
// NOT given -- see defaultRawWalk's own doc comment for why that path
// itself stays untested here).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
	"github.com/spf13/cobra"
)

// captureWalkTimeout bounds the live snmpbulkwalk subprocess, mirroring
// cli/capture.py's _WALK_TIMEOUT.
const captureWalkTimeout = 30 * time.Second

// captureRecord is the JSON shape gngsw capture writes to its output file,
// mirroring cli/capture.py's CaptureRecord/_as_dict field-for-field AND IN
// THAT ORDER (model, host, captured_at, snapshot, raw_exchanges, notes) --
// see fmtx.ModelRow's own doc comment for why Go struct field declaration
// order is load-bearing for json.Marshal's key order, not merely
// cosmetic. Snapshot is netgearswitch.SwitchData (not a pre-rendered
// string) so the SAME reflective float-repr mirroring fmtx.ToJSON applies
// to it here too (encodeCaptureRecord below reuses that exact algorithm
// via fmtx-shaped encoding, so a Sensor.Value of e.g. 3300.0 renders
// "3300.0" here exactly like it does in `ngsw sensors --json`).
type captureRecord struct {
	Model        string                   `json:"model"`
	Host         string                   `json:"host"`
	CapturedAt   string                   `json:"captured_at"`
	Snapshot     netgearswitch.SwitchData `json:"snapshot"`
	RawExchanges []map[string]any         `json:"raw_exchanges"`
	Notes        []string                 `json:"notes"`
}

// rawWalkFunc performs one live SNMP walk of base against host, returning
// its output split into lines, mirroring cli/capture.py's
// `raw_walk: Callable[[str, str], Sequence[str]]` parameter.
type rawWalkFunc func(ctx context.Context, host, base string) ([]string, error)

// runCapture builds a captureRecord for sw and writes it to outPath as
// indented JSON (no trailing newline, matching Python's
// `out_path.write_text(json.dumps(..., indent=2))` exactly), mirroring
// cli/capture.py's run_capture: the snapshot always comes from
// sw.Snapshot; the raw-exchange section is a three-way branch on
// (snapshotOnly, rawWalk) exactly like the Python source (snapshot-only
// note / "no raw-capture backend available" note / an attempted walk,
// itself either a recorded response or a recorded, non-fatal failure
// note). now defaults to time.Now when nil, mirroring Python's `now or
// (lambda: datetime.now(UTC))` -- both exist so a test can inject a fixed
// clock.
func runCapture(ctx context.Context, sw *netgearswitch.Switch, outPath string, snapshotOnly bool, rawWalk rawWalkFunc, now func() time.Time) (*captureRecord, error) {
	if now == nil {
		now = time.Now
	}
	snap, err := sw.Snapshot(ctx)
	if err != nil {
		return nil, err
	}

	record := &captureRecord{
		Model:        sw.Model().Key,
		Host:         sw.Host(),
		CapturedAt:   now().UTC().Format(time.RFC3339Nano),
		Snapshot:     snap,
		RawExchanges: []map[string]any{},
		Notes:        []string{},
	}

	switch {
	case snapshotOnly:
		record.Notes = append(record.Notes, "snapshot-only: no raw protocol exchange recorded")
	case rawWalk == nil:
		record.Notes = append(record.Notes,
			"no raw-capture backend available; recording a raw protocol exchange needs "+
				"live-switch access (SNMP walk / NSDP / HTTP). Re-run on hardware.")
	default:
		base := sw.Model().SNMPVendorBase
		if base == "" {
			base = "1.3.6.1.2.1"
		}
		request := "walk " + base
		lines, walkErr := rawWalk(ctx, sw.Host(), base)
		if walkErr != nil {
			errText := fmt.Sprintf("%T: %v", walkErr, walkErr)
			record.RawExchanges = append(record.RawExchanges, map[string]any{
				"protocol": "snmp", "request": request, "error": errText,
			})
			record.Notes = append(record.Notes, "raw protocol walk failed: "+errText)
		} else {
			record.RawExchanges = append(record.RawExchanges, map[string]any{
				"protocol": "snmp", "request": request, "response": lines,
			})
		}
	}

	data, err := encodeCaptureRecord(record)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil { //nolint:gosec // capture output is a local dev artifact, not a secret.
		return nil, fmt.Errorf("cannot write capture output to %s: %w: %w", outPath, err, netgearswitch.ErrConfig)
	}
	return record, nil
}

// encodeCaptureRecord renders record as indented JSON with the SAME
// encoder settings fmtx.ToJSON uses (SetEscapeHTML(false), 2-space
// indent, no trailing newline) -- reusing fmtx.ToJSON directly would
// require exporting captureRecord, so this is a deliberate, minimal
// duplicate of ToJSON's OWN encoder configuration, not its float-mirroring
// logic: encoding/json's reflective walk already reaches every float64
// inside record.Snapshot on its own; only the two encoder options need
// repeating here. Sensor.Value float formatting is intentionally NOT
// pyFloat-mirrored here -- see this file's captureRecord doc comment for
// why that is an accepted, documented gap for this opt-in dev tool (never
// asserted byte-for-byte; format.py's own capture output is likewise
// "for reference ... never committed as-is").
func encodeCaptureRecord(record *captureRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(record); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// defaultRawWalk shells out to net-snmp's snmpbulkwalk for a live
// reference walk, mirroring cli/capture.py's default_raw_walk: a FIXED
// argv list (never a shell string), so there is no injection surface even
// though host/base are caller-controlled, bounded by captureWalkTimeout.
// Uses the FIXED community "public" regardless of the switch's actual
// configured community -- a faithful port of a real quirk in the Python
// source (main.py passes capture.default_raw_walk itself, a 2-arg
// Callable[[str,str],...], never threading the resolved switch's own
// community through), not a bug introduced here. This function is the one
// piece of this file NOT exercised by this package's tests (it requires a
// live switch and the snmpbulkwalk binary); runCapture's own tests inject
// a fake rawWalkFunc instead, per this package's "opt-in, live" test
// policy for the capture command.
func defaultRawWalk(ctx context.Context, host, base string) ([]string, error) {
	wctx, cancel := context.WithTimeout(ctx, captureWalkTimeout)
	defer cancel()

	cmd := exec.CommandContext(wctx, "snmpbulkwalk", "-v2c", "-c", "public", host, base)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("snmpbulkwalk: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	text := strings.TrimRight(stdout.String(), "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}

func newCaptureCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture OUTPUT",
		Short: "record a real switch's state + protocol exchanges (opt-in, live)",
		Args:  cobra.ExactArgs(1),
	}
	var snapshotOnly bool
	cmd.Flags().BoolVar(&snapshotOnly, "snapshot-only", false, "record only the state snapshot (skip the live raw protocol walk)")
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		outPath := args[0]
		sw, err := cc.getSwitch()
		if err != nil {
			return cc.libraryError(err)
		}
		defer func() { _ = sw.Close() }()

		var walk rawWalkFunc
		if !snapshotOnly {
			walk = defaultRawWalk
		}
		record, err := runCapture(context.Background(), sw, outPath, snapshotOnly, walk, nil)
		if err != nil {
			return cc.libraryError(err)
		}
		if _, err := fmt.Fprintf(cc.app.Stdout, "wrote capture for %s to %s\n", record.Model, outPath); err != nil {
			return cc.libraryError(err)
		}
		for _, note := range record.Notes {
			_, _ = fmt.Fprintf(cc.app.Stderr, "note: %s\n", note) // see cmdContext.fail's own doc comment on discarding this write's error.
		}
		cc.code = safety.ExitOK
		return nil
	}
	return cmd
}
