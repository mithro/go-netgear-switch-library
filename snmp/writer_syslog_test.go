package snmp

// Tests for Writer.AddSyslogCollector/RemoveSyslogCollector: AddSyslogCollector
// always refuses (MEASURED: the agent answers inconsistentValue/commitFailed
// to every row-creation mechanism, see writer.go's own doc comment);
// RemoveSyslogCollector writes RowStatus destroy(6) to the collector's OWN
// sparse table index -- re-read fresh from GetSyslog, NEVER derived from a
// row's position. Mirrors Python test_snmp_write.py's syslog-collector tests.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// syslogHostTables builds the SyslogHostAddr/Port/Severity/Status column
// tables for the given index->(host, port, severity) rows, all Active(1),
// plus the admin-mode/local-port scalars every GetSyslog call also reads.
func syslogHostTables(vo VendorOids, adminMode int, rows map[int]struct {
	host     string
	port     int
	severity int
}) map[string][]Row {
	addr := map[int]string{}
	port := map[int]int64{}
	severity := map[int]int64{}
	status := map[int]int64{}
	for idx, r := range rows {
		addr[idx] = r.host
		port[idx] = int64(r.port)
		severity[idx] = int64(r.severity)
		status[idx] = 1 // Active
	}
	return map[string][]Row{
		vo.SyslogAdminMode:    {NewIntRow(vo.SyslogAdminMode, int64(adminMode))},
		vo.SyslogLocalPort:    {NewIntRow(vo.SyslogLocalPort, 514)},
		vo.SyslogHostAddr:     strRows(vo.SyslogHostAddr, addr),
		vo.SyslogHostPort:     intRows(vo.SyslogHostPort, port),
		vo.SyslogHostSeverity: intRows(vo.SyslogHostSeverity, severity),
		vo.SyslogHostStatus:   intRows(vo.SyslogHostStatus, status),
	}
}

// applySyslogHostDestroy applies a RowStatus destroy(6) SET against
// vo.SyslogHostStatus.<index> by removing that index's row from all four
// host-table columns -- the SNMP-mock twin of applyVlanRowStatus, scoped to
// the syslog host table.
func applySyslogHostDestroy(vo VendorOids) scriptedApplyFunc {
	prefix := vo.SyslogHostStatus + "."
	return func(tables map[string][]Row, vbs []SetVarbind) {
		for _, vb := range vbs {
			if !strings.HasPrefix(vb.OID, prefix) {
				continue
			}
			idxText := strings.TrimPrefix(vb.OID, prefix)
			idx, err := strconv.Atoi(idxText)
			if err != nil {
				continue
			}
			if n, ok := vb.Value.(int); !ok || n != RowStatusDestroy {
				continue
			}
			for _, base := range []string{vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus} {
				target := fmt.Sprintf("%s.%d", base, idx)
				kept := tables[base][:0]
				for _, row := range tables[base] {
					if row.OID != target {
						kept = append(kept, row)
					}
				}
				tables[base] = kept
			}
		}
	}
}

// TestAddSyslogCollectorAlwaysRefuses proves AddSyslogCollector wraps
// model.ErrUnsupportedCapability unconditionally, issuing NO SNMP I/O at
// all -- MEASURED on m4300-24x (2026-08-05): createAndGo/createAndWait
// answer inconsistentValue, value-columns-only answers commitFailed.
func TestAddSyslogCollectorAlwaysRefuses(t *testing.T) {
	vo := syslogVendor(t)
	client := newScriptedWriteClient(syslogHostTables(vo, 1, nil), nil)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.AddSyslogCollector(context.Background(), "10.1.5.9", 514, 6, false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("AddSyslogCollector error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("AddSyslogCollector issued %d SET call(s), want none", len(client.calls))
	}
}

// TestRemoveSyslogCollectorDestroysRowStatusAndVerifies proves the single
// collector's RowStatus is destroyed and the removal reads back gone.
func TestRemoveSyslogCollectorDestroysRowStatusAndVerifies(t *testing.T) {
	vo := syslogVendor(t)
	tables := syslogHostTables(vo, 1, map[int]struct {
		host     string
		port     int
		severity int
	}{1: {"10.1.5.1", 514, 6}})
	client := newScriptedWriteClient(tables, applySyslogHostDestroy(vo))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); err != nil {
		t.Fatalf("RemoveSyslogCollector: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.%d", vo.SyslogHostStatus, 1), Value: RowStatusDestroy, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

// TestRemoveSyslogCollectorAddressesSparseIndexNotPosition is THE
// sparse-index crux test: a table with collectors at Index 1 and Index 3
// (nothing at 2, the exact shape measured on m4300-24x 10.1.5.13,
// 2026-08-05) -- removing the Index-3 host ("10.1.5.3", the SECOND row by
// POSITION) must SET RowStatus destroy at "<base>.3", never "<base>.2"
// (position-derived) and never "<base>.1" (the wrong row). Index-1's own
// collector ("10.1.5.1") must survive untouched.
func TestRemoveSyslogCollectorAddressesSparseIndexNotPosition(t *testing.T) {
	vo := syslogVendor(t)
	tables := syslogHostTables(vo, 1, map[int]struct {
		host     string
		port     int
		severity int
	}{
		1: {"10.1.5.1", 514, 6},
		3: {"10.1.5.3", 601, 3},
	})
	client := newScriptedWriteClient(tables, applySyslogHostDestroy(vo))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.3", false); err != nil {
		t.Fatalf("RemoveSyslogCollector: %v", err)
	}

	want := []SetVarbind{{OID: fmt.Sprintf("%s.%d", vo.SyslogHostStatus, 3), Value: RowStatusDestroy, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v (destroy at index 3, never 2 or 1)", client.sets, want)
	}

	// Index 1's own collector must survive, byte-identical, proving the
	// destroy targeted exactly one row.
	r, err := NewReader(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	after, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog: %v", err)
	}
	if len(after.Servers) != 1 || after.Servers[0].Host != "10.1.5.1" || after.Servers[0].Index == nil || *after.Servers[0].Index != 1 {
		t.Fatalf("Servers after remove = %+v, want exactly index=1 host=10.1.5.1 surviving", after.Servers)
	}
}

// TestRemoveSyslogCollectorRefusesUnknownHost proves a host not in the
// table is refused as a PRECONDITION failure (not
// model.ErrUnsupportedCapability -- the backend CAN serve this op, the
// switch simply has no such row), with NO SET issued.
func TestRemoveSyslogCollectorRefusesUnknownHost(t *testing.T) {
	vo := syslogVendor(t)
	tables := syslogHostTables(vo, 1, map[int]struct {
		host     string
		port     int
		severity int
	}{1: {"10.1.5.1", 514, 6}})
	client := newScriptedWriteClient(tables, applySyslogHostDestroy(vo))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.RemoveSyslogCollector(context.Background(), "10.9.9.9", false)
	if err == nil {
		t.Fatal("RemoveSyslogCollector(unknown host): want error, got nil")
	}
	if errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("RemoveSyslogCollector(unknown host) error = %v, want a precondition failure, not ErrUnsupportedCapability", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("RemoveSyslogCollector issued %d SET call(s), want none", len(client.calls))
	}
}

// TestRemoveSyslogCollectorNotForceGated proves force=false succeeds --
// redirecting logs cannot strand a switch.
func TestRemoveSyslogCollectorNotForceGated(t *testing.T) {
	vo := syslogVendor(t)
	tables := syslogHostTables(vo, 1, map[int]struct {
		host     string
		port     int
		severity int
	}{1: {"10.1.5.1", 514, 6}})
	client := newScriptedWriteClient(tables, applySyslogHostDestroy(vo))
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); err != nil {
		t.Fatalf("RemoveSyslogCollector(force=false) = %v, want success (not force-gated)", err)
	}
}

// TestRemoveSyslogCollectorVerificationFailureRaises proves a switch that
// accepts the SET but leaves the row in place surfaces a
// *model.WriteVerificationError, never a silent success.
func TestRemoveSyslogCollectorVerificationFailureRaises(t *testing.T) {
	vo := syslogVendor(t)
	tables := syslogHostTables(vo, 1, map[int]struct {
		host     string
		port     int
		severity int
	}{1: {"10.1.5.1", 514, 6}})
	// nil apply: the device ignores the write, so the re-read never moves.
	client := newScriptedWriteClient(tables, nil)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("RemoveSyslogCollector error = %v, want *model.WriteVerificationError", err)
	}
}

// TestRemoveSyslogCollectorPropagatesErrorFromBeforeRead proves a transport
// failure on the very first (before-read) call short-circuits the write
// before any SET is ever issued.
func TestRemoveSyslogCollectorPropagatesErrorFromBeforeRead(t *testing.T) {
	vo := syslogVendor(t)
	wantErr := errors.New("boom")
	tables := syslogHostTables(vo, 1, map[int]struct {
		host     string
		port     int
		severity int
	}{1: {"10.1.5.1", 514, 6}})
	inner := newScriptedWriteClient(tables, applySyslogHostDestroy(vo))
	client := &errBeforeSetWriteClient{scriptedWriteClient: inner, failErr: wantErr}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); !errors.Is(err, wantErr) {
		t.Errorf("RemoveSyslogCollector() error = %v, want wrapping %v", err, wantErr)
	}
	if len(client.sets) != 0 {
		t.Errorf("RemoveSyslogCollector issued %d SET(s), want none -- the before-read error must fire first", len(client.sets))
	}
}

// TestRemoveSyslogCollectorPropagatesErrorFromAfterRead proves a transport
// failure on the RE-READ (after the SET already went out) propagates
// as-is, never swallowed into a fabricated verification result.
func TestRemoveSyslogCollectorPropagatesErrorFromAfterRead(t *testing.T) {
	vo := syslogVendor(t)
	wantErr := errors.New("boom")
	client := &failAfterSetWriteClient{
		fakeWriteClient: newFakeWriteClient(syslogHostTables(vo, 1, map[int]struct {
			host     string
			port     int
			severity int
		}{1: {"10.1.5.1", 514, 6}}), true),
		failErr: wantErr,
	}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); !errors.Is(err, wantErr) {
		t.Errorf("RemoveSyslogCollector() error = %v, want wrapping %v", err, wantErr)
	}
}

// TestAddSyslogCollectorRefusesByNameOnNoVendorModel and
// TestRemoveSyslogCollectorRefusesByNameOnNoVendorModel prove gs728tpp (no
// vendor OID subtree) is refused BY NAME before any I/O, mirroring
// GetSyslog's own gate.
func TestAddSyslogCollectorRefusesByNameOnNoVendorModel(t *testing.T) {
	client := newScriptedWriteClient(nil, nil)
	w, err := NewWriter(client, mustModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.AddSyslogCollector(context.Background(), "10.1.5.9", 514, 6, false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("AddSyslogCollector error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

func TestRemoveSyslogCollectorRefusesByNameOnNoVendorModel(t *testing.T) {
	client := newScriptedWriteClient(nil, nil)
	w, err := NewWriter(client, mustModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("RemoveSyslogCollector error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("RemoveSyslogCollector issued %d SET call(s), want none -- refusal must fire before any", len(client.calls))
	}
}
