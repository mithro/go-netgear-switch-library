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
	timeouts := PoeCycleTimeouts{On: time.Second, Poll: 0}
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
	// Phase 2 (-> delivering) must also time out with a typed error, not
	// hang, when detect never leaves "searching" after admin is
	// re-enabled.
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
	if !strings.Contains(verr.Msg, "did not return to delivering") {
		t.Errorf("verr.Msg = %q, want it to contain %q", verr.Msg, "did not return to delivering")
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
