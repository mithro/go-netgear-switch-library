package snmp

// writer_cycle.go: the PoE off->on re-arm state machine (CyclePoE /
// ClearPoEFault), ported field-for-field from
// src/netgear_switch/snmp_write.py's SnmpWriter._poe_rearm/cycle_poe/
// clear_poe_fault (the normative source; see D-WR §2.2-§2.7). Any
// discrepancy between this file and the Python source is a bug in this
// file.
//
// The single trickiest piece of the whole write surface (called out 3x in
// the Python source's own comments): the off->on re-arm is TWO SEPARATE
// single-varbind client.Set calls, each polled to completion BEFORE the
// next Set is issued -- NEVER one SetMany PDU carrying both varbinds for
// the same (duplicate) OID. Per-varbind ordering within one PDU carrying
// the same OID twice is undefined on real hardware (RFC 3416); a real
// agent may reject it or collapse it (last-wins), silently defeating the
// off->on re-arm.

import (
	"context"
	"fmt"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

// PoeCycleTimeouts are the injectable PoE-cycle deadlines. Defaults match
// design spec §6 (DefaultPoeCycleTimeouts); tests pass tiny values (or
// zero for Poll) so cycles run fast against a fake/coherent client, driven
// by a WithClock-injected fake clock instead of any real wall-clock delay.
// Mirrors Python's PoeCycleTimeouts dataclass (off_timeout/on_timeout/
// poll_interval, seconds as float) using time.Duration per Go idiom.
type PoeCycleTimeouts struct {
	Off  time.Duration
	On   time.Duration
	Poll time.Duration
}

// DefaultPoeCycleTimeouts returns the production PoE-cycle deadlines
// (30s/60s/2s), mirroring Python's _DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts().
func DefaultPoeCycleTimeouts() PoeCycleTimeouts {
	return PoeCycleTimeouts{Off: 30 * time.Second, On: 60 * time.Second, Poll: 2 * time.Second}
}

// poeIsOff reports whether status/portUp together indicate PoE has
// actually turned off: detect has settled to DISABLED or SEARCHING
// ("unused", per the coherence rule: admin-off -> detect=disabled) AND the
// port's link is actually down. All THREE conditions (status present,
// detect in that set, link down) are required simultaneously. Mirrors
// Python's module-level _poe_is_off.
func poeIsOff(status *model.PoEStatus, portUp bool) bool {
	return status != nil &&
		(status.Detect == model.PoEDetectDisabled || status.Detect == model.PoEDetectSearching) &&
		!portUp
}

// poeRecovered reports whether detect has left FAULT and settled to
// DELIVERING or SEARCHING -- looser than CyclePoE's recovery predicate
// (model.PoeCycleComplete, which is strict about a port that WAS delivering
// having to deliver again): used by ClearPoEFault, which doesn't require the
// port to actually be delivering power, just no longer faulted, whatever it
// was doing before the clear. Mirrors Python's module-level _poe_recovered
// EXACTLY -- before is unused (clearing a fault succeeds when the port has
// left FAULT, whatever it was doing beforehand), kept in the signature only
// so both recovery predicates poeRearm accepts share one shape (see
// model.PoeCycleComplete, which CyclePoE passes directly).
func poeRecovered(_, status *model.PoEStatus) bool {
	return status != nil &&
		(status.Detect == model.PoEDetectDelivering || status.Detect == model.PoEDetectSearching)
}

// poeRearm is the shared off->on re-arm primitive behind CyclePoE and
// ClearPoEFault. Ported from Python's SnmpWriter._poe_rearm -- see D-WR
// §2.6, the load-bearing piece of this whole slice.
//
// Phase 1: SET admin off (one Set), then poll poeIsOff (status+link) every
// timeouts.Poll until either satisfied or timeouts.Off elapses (measured
// from a deadline computed via w.clock() right after the SET) --
// exceeding it raises *model.WriteVerificationError. Phase 2: SET admin on
// (a SECOND, separate Set -- never combined with phase 1's into one
// SetMany), then poll onRecovered every timeouts.Poll until either
// satisfied or timeouts.On elapses -- exceeding it raises
// *model.WriteVerificationError with onTimeoutMessage(timeouts.On) as the
// message.
//
// Both poll loops check the predicate BEFORE ever sleeping (an
// already-satisfied predicate on the very first check returns immediately
// with zero sleeps/deadline checks) and re-read fresh status on every
// iteration via the Writer's internal reader (never cached), so a
// mid-poll state change is observed on the very next iteration.
func (w *Writer) poeRearm(
	ctx context.Context,
	port int,
	timeouts PoeCycleTimeouts,
	onRecovered func(before, now *model.PoEStatus) bool,
	onTimeoutMessage func(timeout time.Duration) string,
) error {
	before, err := w.poeStatus(ctx, port)
	if err != nil {
		return err
	}

	// Phase 1: off, poll until unused/searching + link down.
	offVb, err := NewSetVarbind(poeAdminOID(port), 2, "i")
	if err != nil {
		return err
	}
	if err := w.client.Set(ctx, offVb); err != nil {
		return err
	}
	deadline := w.clock().Add(timeouts.Off)
	for {
		status, err := w.poeStatus(ctx, port)
		if err != nil {
			return err
		}
		portStatus, err := w.portStatus(ctx, port)
		if err != nil {
			return err
		}
		up := portStatus != nil && portStatus.LinkUp
		if poeIsOff(status, up) {
			break
		}
		if !w.clock().Before(deadline) {
			return &model.WriteVerificationError{
				Msg:    fmt.Sprintf("PoE port %d did not turn off within %s", port, formatSeconds(timeouts.Off)),
				Before: before,
				After:  status,
			}
		}
		if err := w.sleep(ctx, timeouts.Poll); err != nil {
			return err
		}
	}

	// Phase 2: on, poll until the caller's recovery predicate is met.
	onVb, err := NewSetVarbind(poeAdminOID(port), 1, "i")
	if err != nil {
		return err
	}
	if err := w.client.Set(ctx, onVb); err != nil {
		return err
	}
	deadline = w.clock().Add(timeouts.On)
	for {
		status, err := w.poeStatus(ctx, port)
		if err != nil {
			return err
		}
		if onRecovered(before, status) {
			return nil
		}
		if !w.clock().Before(deadline) {
			return &model.WriteVerificationError{
				Msg:    onTimeoutMessage(timeouts.On),
				Before: before,
				After:  status,
			}
		}
		if err := w.sleep(ctx, timeouts.Poll); err != nil {
			return err
		}
	}
}

// CyclePoE power-cycles port's PoE: off, poll until it actually turns off,
// on, poll until model.PoeCycleComplete says it has come back. Ported from
// Python's SnmpWriter.cycle_poe -- see D-WR §2.7.
//
// The guard fires UNCONDITIONALLY (unlike SetPoE's direction-gated guard):
// cycling a protected port always needs force=true. The recovery predicate
// used to be unconditionally "status present AND strictly Delivering()",
// which reported a successful cycle of a port with NOTHING attached as a
// WriteVerificationError (a port with no powered device can never reach
// DELIVERING) -- fixed by python-netgear-switch-library commit f8a890f to
// judge recovery relative to the port's PRIOR state; see
// model.PoeCycleComplete's doc comment for the measurement that isolated it.
func (w *Writer) CyclePoE(ctx context.Context, port int, timeouts PoeCycleTimeouts, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	return w.poeRearm(ctx, port, timeouts,
		model.PoeCycleComplete,
		func(timeout time.Duration) string {
			return fmt.Sprintf("PoE port %d did not come back after the power cycle within %s", port, formatSeconds(timeout))
		},
	)
}

// ClearPoEFault re-arms port's PoE the same way CyclePoE does, but with a
// looser recovery predicate: detect merely needs to have LEFT fault
// (delivering OR searching is fine -- a non-PoE-negotiating device that's
// simply "searching" again is no longer faulted). Ported from Python's
// SnmpWriter.clear_poe_fault -- see D-WR §2.7.
//
// The guard fires UNCONDITIONALLY, exactly like CyclePoE's.
func (w *Writer) ClearPoEFault(ctx context.Context, port int, timeouts PoeCycleTimeouts, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	return w.poeRearm(ctx, port, timeouts, poeRecovered,
		func(timeout time.Duration) string {
			return fmt.Sprintf("PoE port %d still in FAULT after clear within %s", port, formatSeconds(timeout))
		},
	)
}

// formatSeconds renders d the way the timeout error messages want it
// ("<N>s"), mirroring Python's f"{timeouts.off_timeout}s" (a plain float
// render) closely enough for the message's asserted substrings ("did not
// turn off", "did not return to delivering", "still in FAULT") -- the
// exact numeric formatting isn't itself pinned by the test suite, only
// those substrings are.
func formatSeconds(d time.Duration) string {
	return fmt.Sprintf("%gs", d.Seconds())
}

// defaultSleep is the production Sleep implementation: it waits for d (a
// no-op if d <= 0) unless ctx is cancelled first, in which case it returns
// ctx.Err() -- letting a caller's context cancellation abort a stuck poll
// loop. This is a deliberate, Go-idiomatic improvement over Python's plain
// time.sleep/asyncio.sleep defaults (which can't be interrupted), while
// matching Python's default behavior (real elapsed time, uninterrupted)
// whenever no cancellation occurs.
func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WithClock overrides the Writer's time source and poll-sleep function --
// the injectable clock/sleep seam CyclePoE/ClearPoEFault's poll loops use,
// mirroring Python's cycle_poe/clear_poe_fault accepting clock=time.monotonic/
// sleep=time.sleep as per-call keyword arguments, but as a Writer-level
// (constructor-time) option instead: tests inject a fake now/sleep pair
// exactly like Python's fake clock/no-op sleep to drive the whole state
// machine deterministically with zero real wall-clock delay. Either
// argument may be nil to leave that seam at its default (time.Now /
// defaultSleep).
func WithClock(now func() time.Time, sleep func(ctx context.Context, d time.Duration) error) WriterOption {
	return func(w *Writer) {
		if now != nil {
			w.clock = now
		}
		if sleep != nil {
			w.sleep = sleep
		}
	}
}
