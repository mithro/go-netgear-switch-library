package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

// poeFullTables builds a full set of tables (PoE admin+detect, ifAdmin,
// ifOper, ifHighSpeed, ifName) for port, on/delivering by default -- the
// starting state cycle_poe/clear_poe_fault's tests re-arm from. Mirrors
// Python test_snmp_write.py's _poe_full_tables.
func poeFullTables(port int) map[string][]Row {
	return map[string][]Row{
		PethPsePortTable: {
			NewIntRow(fmt.Sprintf("%s.3.1.%d", PethPsePortTable, port), 1),
			NewIntRow(fmt.Sprintf("%s.6.1.%d", PethPsePortTable, port), 3),
		},
		IfAdminStatus: {NewIntRow(fmt.Sprintf("%s.%d", IfAdminStatus, port), 1)},
		IfOperStatus:  {NewIntRow(fmt.Sprintf("%s.%d", IfOperStatus, port), 1)},
		IfHighSpeed:   {NewIntRow(fmt.Sprintf("%s.%d", IfHighSpeed, port), 1000)},
		IfName:        {NewStrRow(fmt.Sprintf("%s.%d", IfName, port), "1/0/5")},
	}
}

// toIntValue coerces a SetVarbind.Value (stored as a plain int by every
// PoE-admin SET this file issues) to an int, defaulting to 0 for anything
// else -- just enough coercion for these fakes' own coherence logic.
func toIntValue(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	}
	return 0
}

// coherentPoeClient mimics real device coherence for a Set on the PoE
// admin column: admin off -> detect=disabled(1) + link down; admin on ->
// detect=delivering(3) + link up. Mirrors Python test_snmp_write.py's
// CoherentPoeClient. Only Set is overridden since CyclePoE/ClearPoEFault's
// re-arm issues exclusively single-varbind Set calls, never SetMany.
type coherentPoeClient struct {
	*fakeWriteClient
}

func newCoherentPoeClient(tables map[string][]Row) *coherentPoeClient {
	return &coherentPoeClient{fakeWriteClient: newFakeWriteClient(tables, false)}
}

func (c *coherentPoeClient) Set(_ context.Context, vb SetVarbind) error {
	c.sets = append(c.sets, vb)
	c.calls = append(c.calls, []SetVarbind{vb})
	prefix := PethPsePortTable + ".3.1."
	if !strings.HasPrefix(vb.OID, prefix) {
		return nil
	}
	port := strings.TrimPrefix(vb.OID, prefix)
	on := toIntValue(vb.Value) == 1
	admin, detect, oper := int64(2), int64(1), int64(2)
	if on {
		admin, detect, oper = 1, 3, 1
	}
	c.tables[PethPsePortTable] = []Row{
		NewIntRow(fmt.Sprintf("%s.3.1.%s", PethPsePortTable, port), admin),
		NewIntRow(fmt.Sprintf("%s.6.1.%s", PethPsePortTable, port), detect),
	}
	c.tables[IfOperStatus] = []Row{NewIntRow(fmt.Sprintf("%s.%s", IfOperStatus, port), oper)}
	return nil
}

// stuckOffPoeClient turns off coherently (same as coherentPoeClient's off
// branch) but leaves admin-on entirely unwired, so detect never resumes
// delivering/searching-recovered after phase 2's SET -- used to exercise
// both cycle_poe's and clear_poe_fault's on-timeout branches. Mirrors
// Python test_snmp_write.py's StuckOffPoeClient.
type stuckOffPoeClient struct {
	*fakeWriteClient
}

func newStuckOffPoeClient(tables map[string][]Row) *stuckOffPoeClient {
	return &stuckOffPoeClient{fakeWriteClient: newFakeWriteClient(tables, false)}
}

func (c *stuckOffPoeClient) Set(_ context.Context, vb SetVarbind) error {
	c.sets = append(c.sets, vb)
	c.calls = append(c.calls, []SetVarbind{vb})
	prefix := PethPsePortTable + ".3.1."
	if !strings.HasPrefix(vb.OID, prefix) || toIntValue(vb.Value) != 2 {
		// admin on: intentionally left un-wired -> detect stays whatever it
		// last was forever, so phase 2 never terminates on its own.
		return nil
	}
	port := strings.TrimPrefix(vb.OID, prefix)
	c.tables[PethPsePortTable] = []Row{
		NewIntRow(fmt.Sprintf("%s.3.1.%s", PethPsePortTable, port), 2),
		NewIntRow(fmt.Sprintf("%s.6.1.%s", PethPsePortTable, port), 1),
	}
	c.tables[IfOperStatus] = []Row{NewIntRow(fmt.Sprintf("%s.%s", IfOperStatus, port), 2)}
	return nil
}

// stepPoeClient turns PoE off/on only after its underlying PoE-table walk
// has been polled a configured number of times following the relevant Set:
// offAfter/onAfter poll rounds see the PRE-transition state, and the
// (offAfter+1)th / (onAfter+1)th round (and every one after it) sees the
// transitioned state. This lets a test pin the EXACT number of poll
// iterations -- and therefore the exact sleep count -- a phase takes
// before its predicate is satisfied. Only Walk(PethPsePortAdmin) advances
// the per-phase counter (every other walk, e.g. GetPorts' ifAdminStatus/
// ifOperStatus/etc. walks, passes straight through unmodified), since
// poeRearm's poll loop reads PoE status exactly once per iteration --
// GetPoE now issues TWO column walks per call (PethPsePortAdmin then
// PethPsePortDetect, parity 86af0a9), so the counter must advance on only
// ONE of the pair to keep "one poll = one counter increment"; it advances
// on the FIRST of the two (PethPsePortAdmin) so any table transition
// decided there is already in place -- consistently, not torn -- by the
// time the SECOND walk of the same poll (PethPsePortDetect) reads the same
// underlying c.tables[PethPsePortTable].
type stepPoeClient struct {
	*fakeWriteClient
	port              int
	offAfter, onAfter int

	lastSet       int // 0 = no admin Set yet this phase; 2 = off requested; 1 = on requested
	pollsSinceSet int
}

func newStepPoeClient(tables map[string][]Row, port, offAfter, onAfter int) *stepPoeClient {
	return &stepPoeClient{
		fakeWriteClient: newFakeWriteClient(tables, false),
		port:            port,
		offAfter:        offAfter,
		onAfter:         onAfter,
	}
}

func (c *stepPoeClient) Set(_ context.Context, vb SetVarbind) error {
	c.sets = append(c.sets, vb)
	c.calls = append(c.calls, []SetVarbind{vb})
	if strings.HasPrefix(vb.OID, PethPsePortTable+".3.1.") {
		c.lastSet = toIntValue(vb.Value)
		c.pollsSinceSet = 0
	}
	return nil
}

func (c *stepPoeClient) Walk(ctx context.Context, base string) ([]Row, error) {
	if base == PethPsePortAdmin && c.lastSet != 0 {
		need := c.offAfter
		if c.lastSet == 1 {
			need = c.onAfter
		}
		if c.pollsSinceSet >= need {
			admin, detect, oper := int64(2), int64(1), int64(2)
			if c.lastSet == 1 {
				admin, detect, oper = 1, 3, 1
			}
			c.tables[PethPsePortTable] = []Row{
				NewIntRow(fmt.Sprintf("%s.3.1.%d", PethPsePortTable, c.port), admin),
				NewIntRow(fmt.Sprintf("%s.6.1.%d", PethPsePortTable, c.port), detect),
			}
			c.tables[IfOperStatus] = []Row{NewIntRow(fmt.Sprintf("%s.%d", IfOperStatus, c.port), oper)}
		}
		c.pollsSinceSet++
	}
	return c.fakeWriteClient.Walk(ctx, base)
}

// incrementingClock returns a fake `now` func that jumps forward by step on
// every call -- guarantees a bounded, deterministic test runtime with zero
// real sleeping, instead of racing a real wall clock. Mirrors Python
// test_snmp_write.py's _incrementing_clock.
func incrementingClock(step time.Duration) func() time.Time {
	t := time.Now()
	return func() time.Time {
		t = t.Add(step)
		return t
	}
}

// noSleep is a Sleep seam that never actually waits -- paired with
// incrementingClock so a timeout test's poll loop terminates immediately
// without any real wall-clock delay.
func noSleep(context.Context, time.Duration) error { return nil }

// --- CyclePoE / ClearPoEFault: happy path -----------------------------------

func TestCyclePoEOffThenOnTerminatesFast(t *testing.T) {
	client := newCoherentPoeClient(poeFullTables(5))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	if err := w.CyclePoE(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	prefix := PethPsePortTable + ".3.1."
	var adminSets []int
	for _, s := range client.sets {
		if strings.HasPrefix(s.OID, prefix) {
			adminSets = append(adminSets, toIntValue(s.Value))
		}
	}
	if got, want := adminSets, []int{2, 1}; !intSliceEqual(got, want) {
		t.Errorf("admin sets = %v, want %v (off then on)", got, want)
	}
	// Must be TWO SEPARATE single-varbind Set calls, never one SetMany PDU
	// carrying both varbinds for the same (duplicate) OID -- see D-WR §2.6.
	var poeCallLens []int
	for _, c := range client.calls {
		if len(c) > 0 && strings.HasPrefix(c[0].OID, prefix) {
			poeCallLens = append(poeCallLens, len(c))
		}
	}
	if got, want := poeCallLens, []int{1, 1}; !intSliceEqual(got, want) {
		t.Errorf("poe call lengths = %v, want %v (two separate single-varbind calls)", got, want)
	}
}

func TestClearPoEFaultRecoversDetect(t *testing.T) {
	tables := poeFullTables(5)
	tables[PethPsePortTable] = []Row{
		NewIntRow(fmt.Sprintf("%s.3.1.5", PethPsePortTable), 1),
		NewIntRow(fmt.Sprintf("%s.6.1.5", PethPsePortTable), 4), // FAULT
	}
	client := newCoherentPoeClient(tables)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// Start from DefaultPoeCycleTimeouts() and override just the fields
	// under test, mirroring the pinned Python test's
	// PoeCycleTimeouts(on_timeout=1, poll_interval=0) -- off_timeout is
	// left at its dataclass default (30.0) there. A Go zero-value
	// PoeCycleTimeouts{On: ..., Poll: ...} would silently leave Off at 0
	// (an already-expired deadline) instead of mirroring that default;
	// harmless in THIS test only because the coherent client's phase-1
	// transition is synchronous with the SET itself, so phase 1 never
	// even reaches its own deadline check -- but zero-value-as-default is
	// a footgun worth avoiding on principle rather than relying on.
	timeouts := DefaultPoeCycleTimeouts()
	timeouts.On = time.Second
	timeouts.Poll = 0
	if err := w.ClearPoEFault(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("ClearPoEFault: %v", err)
	}
	statuses, err := w.reader.GetPoE(context.Background())
	if err != nil {
		t.Fatalf("GetPoE: %v", err)
	}
	var detect model.PoEDetect
	for _, s := range statuses {
		if s.Port == 5 {
			detect = s.Detect
		}
	}
	if detect == model.PoEDetectFault {
		t.Errorf("detect = %v, want it to have left FAULT", detect)
	}
	prefix := PethPsePortTable + ".3.1."
	var adminSets []int
	for _, s := range client.sets {
		if strings.HasPrefix(s.OID, prefix) {
			adminSets = append(adminSets, toIntValue(s.Value))
		}
	}
	if got, want := adminSets, []int{2, 1}; !intSliceEqual(got, want) {
		t.Errorf("admin sets = %v, want %v (off then on)", got, want)
	}
	var poeCallLens []int
	for _, c := range client.calls {
		if len(c) > 0 && strings.HasPrefix(c[0].OID, prefix) {
			poeCallLens = append(poeCallLens, len(c))
		}
	}
	if got, want := poeCallLens, []int{1, 1}; !intSliceEqual(got, want) {
		t.Errorf("poe call lengths = %v, want %v (two separate single-varbind calls)", got, want)
	}
}

// --- CyclePoE / ClearPoEFault: unconditional protected-port guard -----------

func TestCyclePoEProtectedPortRequiresForce(t *testing.T) {
	client := newCoherentPoeClient(poeFullTables(5))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.CyclePoE(context.Background(), 5, DefaultPoeCycleTimeouts(), false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("CyclePoE error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
}

func TestClearPoEFaultProtectedPortRequiresForce(t *testing.T) {
	client := newCoherentPoeClient(poeFullTables(5))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.ClearPoEFault(context.Background(), 5, DefaultPoeCycleTimeouts(), false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("ClearPoEFault error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
}

// --- CyclePoE / ClearPoEFault: timeout branches -----------------------------

func TestCyclePoEOffNeverReachedRaisesTimeoutAndTerminates(t *testing.T) {
	// A device that never turns PoE off must raise a typed timeout error
	// instead of looping forever. The incrementing fake clock proves the
	// loop terminates deterministically without depending on real elapsed
	// time.
	client := newFakeWriteClient(poeFullTables(5), false) // SET never applied
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(incrementingClock(100*time.Second), noSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: time.Second, Poll: 0}
	err = w.CyclePoE(context.Background(), 5, timeouts, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("CyclePoE error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(verr.Msg, "did not turn off") {
		t.Errorf("verr.Msg = %q, want it to contain %q", verr.Msg, "did not turn off")
	}
}

func TestCyclePoEOnNeverReachedRaisesTimeoutAndTerminates(t *testing.T) {
	// Phase 2 (-> delivering again) must also time out with a typed error,
	// not hang, when detect never leaves "disabled" after admin is
	// re-enabled -- the genuine-failure half of the poe_cycle_complete
	// predicate (parity f8a890f): poeFullTables(5) starts the port
	// DELIVERING (before.Delivering() == true), so recovery here demands
	// delivering AGAIN, not merely SEARCHING -- and stuckOffPoeClient never
	// gets there.
	client := newStuckOffPoeClient(poeFullTables(5))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(incrementingClock(100*time.Second), noSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	err = w.CyclePoE(context.Background(), 5, timeouts, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("CyclePoE error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(verr.Msg, "did not come back after the power cycle") {
		t.Errorf("verr.Msg = %q, want it to contain %q", verr.Msg, "did not come back after the power cycle")
	}
}

// --- poe_cycle_complete predicate: relative to the port's PRIOR state ------
// (parity f8a890f: models.poe_cycle_complete)

// searchingOnlyPoeClient mimics a PoE port with NOTHING attached: admin off
// turns detect DISABLED and the link down exactly like coherentPoeClient's
// off branch, but admin on never reaches DELIVERING -- detect settles at
// SEARCHING and the link never comes up, exactly what a real port with no
// powered device does (LIVE-PROVEN on sw-netgear-gs728tpp.monarto.mithis.com
// port 17, 2026-08-03 -- see model.PoeCycleComplete's doc comment). A
// recovery predicate that unconditionally demanded DELIVERING would poll out
// the full timeout and report WriteVerificationError on a cycle that had
// actually worked; model.PoeCycleComplete must not.
type searchingOnlyPoeClient struct {
	*fakeWriteClient
}

func newSearchingOnlyPoeClient(tables map[string][]Row) *searchingOnlyPoeClient {
	return &searchingOnlyPoeClient{fakeWriteClient: newFakeWriteClient(tables, false)}
}

func (c *searchingOnlyPoeClient) Set(_ context.Context, vb SetVarbind) error {
	c.sets = append(c.sets, vb)
	c.calls = append(c.calls, []SetVarbind{vb})
	prefix := PethPsePortTable + ".3.1."
	if !strings.HasPrefix(vb.OID, prefix) {
		return nil
	}
	port := strings.TrimPrefix(vb.OID, prefix)
	on := toIntValue(vb.Value) == 1
	admin, detect := int64(2), int64(1) // off: disabled
	if on {
		admin, detect = 1, 2 // on: admin enabled, but only ever SEARCHING -- nothing attached
	}
	c.tables[PethPsePortTable] = []Row{
		NewIntRow(fmt.Sprintf("%s.3.1.%s", PethPsePortTable, port), admin),
		NewIntRow(fmt.Sprintf("%s.6.1.%s", PethPsePortTable, port), detect),
	}
	// The link never comes up -- there is nothing attached to negotiate with.
	c.tables[IfOperStatus] = []Row{NewIntRow(fmt.Sprintf("%s.%s", IfOperStatus, port), 2)}
	return nil
}

// TestCyclePoESucceedsWithNothingAttached is the success half of the
// poe_cycle_complete regression: before=SEARCHING (nothing attached) and
// after=SEARCHING (still nothing attached, so it never reaches DELIVERING)
// must SUCCEED -- no WriteVerificationError -- because the port was never
// delivering to begin with, so re-detecting is the whole of "back".
func TestCyclePoESucceedsWithNothingAttached(t *testing.T) {
	tables := poeFullTables(5)
	tables[PethPsePortTable] = []Row{
		NewIntRow(fmt.Sprintf("%s.3.1.5", PethPsePortTable), 1),
		NewIntRow(fmt.Sprintf("%s.6.1.5", PethPsePortTable), 2), // SEARCHING before the cycle
	}
	client := newSearchingOnlyPoeClient(tables)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	if err := w.CyclePoE(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("CyclePoE with nothing attached before/after cycle = %v, want success (parity f8a890f: a port that was never delivering must not be held to a DELIVERING bar)", err)
	}
}

func TestClearPoEFaultNeverRecoversRaisesTimeoutAndTerminates(t *testing.T) {
	// The off SET is coherent (so phase 1 completes), but re-enabling
	// admin never resumes delivering/searching -- detect never leaves
	// FAULT, so phase 2 must raise a typed timeout, not hang.
	tables := poeFullTables(5)
	tables[PethPsePortTable] = []Row{
		NewIntRow(fmt.Sprintf("%s.3.1.5", PethPsePortTable), 1),
		NewIntRow(fmt.Sprintf("%s.6.1.5", PethPsePortTable), 4), // stuck FAULT
	}
	client := newStuckOffPoeClient(tables)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(incrementingClock(100*time.Second), noSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	err = w.ClearPoEFault(context.Background(), 5, timeouts, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("ClearPoEFault error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(verr.Msg, "still in FAULT") {
		t.Errorf("verr.Msg = %q, want it to contain %q", verr.Msg, "still in FAULT")
	}
}

// --- DefaultPoeCycleTimeouts -------------------------------------------------

func TestDefaultPoeCycleTimeouts(t *testing.T) {
	got := DefaultPoeCycleTimeouts()
	want := PoeCycleTimeouts{Off: 30 * time.Second, On: 60 * time.Second, Poll: 2 * time.Second}
	if got != want {
		t.Errorf("DefaultPoeCycleTimeouts() = %+v, want %+v", got, want)
	}
}

// --- poll cadence honoured ---------------------------------------------------

func TestCyclePoEPollCadenceHonoured(t *testing.T) {
	// A client that only turns PoE off after being polled a fixed number
	// of times proves the poll interval is actually being waited between
	// checks: every recorded sleep duration must equal timeouts.Poll.
	client := newCoherentPoeClient(poeFullTables(5))
	var sleeps []time.Duration
	recordSleep := func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(time.Now, recordSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: 5 * time.Second, On: 5 * time.Second, Poll: 50 * time.Millisecond}
	if err := w.CyclePoE(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	// The coherent client transitions synchronously on the SET itself, so
	// the very first poll of each phase already observes the post-SET
	// state: zero sleeps expected (an already-satisfied predicate must
	// return before ever sleeping).
	if len(sleeps) != 0 {
		t.Errorf("sleeps = %v, want none (predicate satisfied on first check of each phase)", sleeps)
	}
}

// --- multi-round polling: sleep is actually invoked between checks ---------

func TestCyclePoEPhase1PollsMultipleRoundsBeforeSatisfied(t *testing.T) {
	// Phase 1's predicate only becomes true on the THIRD poll round (two
	// prior rounds see the pre-transition state): pins that poeRearm
	// actually calls Sleep(timeouts.Poll) between failed checks, not just
	// on the already-satisfied-first-check happy path every other test in
	// this file exercises. Phase 2 (onAfter=0) transitions on its very
	// first check, isolating this assertion to phase 1's sleep count.
	client := newStepPoeClient(poeFullTables(5), 5, 2, 0)
	var sleeps []time.Duration
	recordSleep := func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(time.Now, recordSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: 5 * time.Second, On: 5 * time.Second, Poll: 50 * time.Millisecond}
	if err := w.CyclePoE(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	want := []time.Duration{50 * time.Millisecond, 50 * time.Millisecond}
	if !durationSliceEqual(sleeps, want) {
		t.Errorf("sleeps = %v, want %v (two failed phase-1 checks, each followed by one Poll-duration sleep)", sleeps, want)
	}
}

func TestCyclePoEPhase2PollsMultipleRoundsBeforeSatisfied(t *testing.T) {
	// Mirror of the phase-1 test above, isolated to phase 2: offAfter=0
	// transitions instantly (zero phase-1 sleeps), onAfter=3 means phase
	// 2's predicate is satisfied only on the FOURTH poll round, so exactly
	// three Sleep(timeouts.Poll) calls must have happened first.
	client := newStepPoeClient(poeFullTables(5), 5, 0, 3)
	var sleeps []time.Duration
	recordSleep := func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(time.Now, recordSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	timeouts := PoeCycleTimeouts{Off: 5 * time.Second, On: 5 * time.Second, Poll: 50 * time.Millisecond}
	if err := w.CyclePoE(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	want := []time.Duration{50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond}
	if !durationSliceEqual(sleeps, want) {
		t.Errorf("sleeps = %v, want %v (three failed phase-2 checks, each followed by one Poll-duration sleep)", sleeps, want)
	}
}

// --- ctx cancellation aborts a stuck poll loop ------------------------------

func TestCyclePoESleepCtxCancellationAbortsPoll(t *testing.T) {
	// A predicate that never resolves must not force the caller to wait
	// out the full timeout: cancelling ctx mid-poll must abort the loop
	// immediately with ctx.Err(), using the REAL defaultSleep (not a fake)
	// so this exercises production behavior, not just a test double.
	client := newFakeWriteClient(poeFullTables(5), false) // SET never applied -- phase 1 never satisfied
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithClock(time.Now, defaultSleep))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Off/Poll are both generous (real wall-clock values) precisely so
	// that ctx cancellation -- not the timeout deadline -- is what
	// terminates the poll loop; if this test ever takes anywhere near
	// timeouts.Off to finish, that itself indicates a regression.
	timeouts := PoeCycleTimeouts{Off: time.Hour, Poll: 10 * time.Millisecond}
	err = w.CyclePoE(ctx, 5, timeouts, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CyclePoE error = %v, want context.Canceled", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("CyclePoE error is a *model.WriteVerificationError, want the raw ctx.Err() to propagate as-is")
	}
}

// --- defaultSleep: cover its select branches directly -----------------------

func TestDefaultSleepReturnsCtxErrOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultSleep(ctx, 10*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("defaultSleep(cancelled, 10ms) = %v, want context.Canceled", err)
	}
}

func TestDefaultSleepZeroDurationCancelledContextReturnsCtxErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultSleep(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("defaultSleep(cancelled, 0) = %v, want context.Canceled", err)
	}
}

func TestDefaultSleepZeroDurationIsNoOpWhenNotCancelled(t *testing.T) {
	if err := defaultSleep(context.Background(), 0); err != nil {
		t.Fatalf("defaultSleep(0): %v", err)
	}
}

func TestDefaultSleepWaitsForDurationWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if err := defaultSleep(context.Background(), 10*time.Millisecond); err != nil {
		t.Fatalf("defaultSleep(10ms): %v", err)
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Errorf("defaultSleep(10ms) returned after %v, want >= 10ms", elapsed)
	}
}

// durationSliceEqual reports whether a and b contain the same durations in
// the same order.
func durationSliceEqual(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// intSliceEqual reports whether a and b contain the same ints in the same
// order.
func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
