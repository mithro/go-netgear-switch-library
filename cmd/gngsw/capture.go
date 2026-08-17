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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/fmtx"
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
// string), and the WHOLE record is encoded via fmtx.ToJSON (not a bare
// json.Marshal/Encoder) so every float64 reachable from it -- today, only
// Sensor.Value inside Snapshot -- renders through the SAME pyFloatRepr
// mirroring `ngsw sensors --json` uses (a Sensor.Value of 3300.0 renders
// "3300.0", never Go's default "3300"), and NaN/Infinity readings encode
// the same JSON-illegal-but-Python-compatible bare tokens json.dumps
// emits by default. See runCapture's own doc comment for what capture
// output is STILL not fully byte-parity with the Python reference.
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
// clock. CapturedAt is rendered via pyIsoformatUTC to match Python's
// `datetime.now(UTC).isoformat()` exactly (a "+00:00" offset suffix, NOT
// Go's own "Z", and a 6-digit microsecond fraction only when non-zero).
//
// The ONE remaining documented non-parity in this file's output: a failed
// raw walk's recorded "error" text is Go's own "%T: %v" (this codebase's
// closest analogue of Python's exception typename), not a literal Python
// exception class name (e.g. "RuntimeError") -- Go has no equivalent
// concept to port faithfully here, so this is an honest, permanent
// deviation, not a gap to close (see defaultRawWalk's own doc comment).
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
		CapturedAt:   pyIsoformatUTC(now()),
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

	// fmtx.ToJSON gives capture output the SAME json.dumps(indent=2)-
	// compatible encoding (no HTML-escaping, pyFloatRepr-mirrored floats,
	// bare NaN/Infinity tokens) every other `--json` renderer in this
	// codebase already uses -- see captureRecord's own doc comment.
	jsonText, err := fmtx.ToJSON(record)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outPath, []byte(jsonText), 0o644); err != nil { //nolint:gosec // capture output is a local dev artifact, not a secret.
		return nil, fmt.Errorf("cannot write capture output to %s: %w: %w", outPath, err, netgearswitch.ErrConfig)
	}
	return record, nil
}

// pyIsoformatUTC renders t the way Python's `datetime.now(UTC).isoformat()`
// renders a UTC-aware datetime: "YYYY-MM-DDTHH:MM:SS+00:00" when the
// microsecond component is exactly zero, else
// "YYYY-MM-DDTHH:MM:SS.ffffff+00:00" with the fraction ALWAYS 6 digits,
// zero-padded, truncated (never rounded) from t's own sub-second
// precision -- verified against a live `python3 -c 'from datetime import
// datetime, UTC; print(datetime(...).isoformat())'` for both branches.
// Go's time.RFC3339Nano is NOT this format: it renders "Z" for UTC (not
// "+00:00") and trims trailing zero digits from the fraction instead of
// fixing it at 6.
func pyIsoformatUTC(t time.Time) string {
	t = t.UTC()
	base := t.Format("2006-01-02T15:04:05")
	microsecond := t.Nanosecond() / 1000
	if microsecond == 0 {
		return base + "+00:00"
	}
	return fmt.Sprintf("%s.%06d+00:00", base, microsecond)
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
