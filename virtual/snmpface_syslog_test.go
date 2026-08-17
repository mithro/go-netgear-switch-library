package virtual

// Tests for SnmpFace's syslog-host RowStatus column, driven over real UDP
// against gosnmp clients (mirroring snmpface_test.go's own conventions):
// destroy(6) on an EXISTING row removes it (and, for a SPARSE table, the
// removal must address the row's OWN index, never a position -- THE
// sparse-index crux, mirrored here at the wire-mock level to complement
// snmp/writer_syslog_test.go's writer-level proof); any RowStatus write at
// an index with NO existing row is refused with SNMPError InconsistentValue,
// mirroring the real m4300-24x agent's measured refusal to CREATE a syslog
// host row (see state.go's ApplyWrite RowStatus-column block and
// snmpface.go's applyUncommitted).

import (
	"context"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// twoSyslogCollectorState returns a gsm7252ps-seeded State whose syslog
// host table holds Index 1 and Index 3, nothing at 2 -- the exact shape
// measured on m4300-24x 10.1.5.13 (2026-08-05), mirroring
// fastpath/parse_syslog_test.go's own sparse fixture.
func twoSyslogCollectorState() *State {
	st := SeedGSM7252PS()
	st.Syslog = SyslogSim{
		AdminMode: 1,
		LocalPort: 514,
		Collectors: []SyslogCollectorSim{
			{Host: "10.1.5.1", Port: 514, Severity: 6, Status: 1, Index: 1},
			{Host: "10.1.5.3", Port: 601, Severity: 3, Status: 1, Index: 3},
		},
	}
	return st
}

// TestSnmpFaceSyslogHostStatusDestroyRemovesRow proves a destroy(6) SET
// against an EXISTING collector's own RowStatus instance removes it, and
// the removal is visible on the next Walk.
func TestSnmpFaceSyslogHostStatusDestroyRemovesRow(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	ctx := context.Background()

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}

	oid := vo.SyslogHostStatus + ".1"
	vb, err := snmp.NewSetVarbind(oid, snmp.RowStatusDestroy, "i")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	if err := client.Set(ctx, vb); err != nil {
		t.Fatalf("Set(%s=destroy) error = %v", oid, err)
	}

	rows, err := client.Walk(ctx, vo.SyslogHostAddr)
	if err != nil {
		t.Fatalf("Walk(%s) after destroy error = %v", vo.SyslogHostAddr, err)
	}
	if len(rows) != 0 {
		t.Errorf("SyslogHostAddr rows after destroy = %+v, want none", rows)
	}
}

// TestSnmpFaceSyslogHostStatusDestroyAddressesSparseIndexNotPosition is THE
// sparse-index crux test at the virtual-agent level: a table with
// collectors at Index 1 and Index 3 (nothing at 2) -- destroying the
// Index-3 row (the SECOND row by POSITION) must leave Index 1's own row
// (10.1.5.1) completely untouched, proving the mock addresses rows by their
// OWN RowStatus OID instance, never by walk position.
func TestSnmpFaceSyslogHostStatusDestroyAddressesSparseIndexNotPosition(t *testing.T) {
	addr, _, _ := startFace(t, twoSyslogCollectorState())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	ctx := context.Background()

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}

	oid := vo.SyslogHostStatus + ".3"
	vb, err := snmp.NewSetVarbind(oid, snmp.RowStatusDestroy, "i")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	if err := client.Set(ctx, vb); err != nil {
		t.Fatalf("Set(%s=destroy) error = %v", oid, err)
	}

	rows, err := client.Walk(ctx, vo.SyslogHostAddr)
	if err != nil {
		t.Fatalf("Walk(%s) after destroy error = %v", vo.SyslogHostAddr, err)
	}
	if len(rows) != 1 || rows[0].OID != vo.SyslogHostAddr+".1" || rows[0].Value != "10.1.5.1" {
		t.Fatalf("SyslogHostAddr rows after destroying index 3 = %+v, want exactly index 1 (10.1.5.1) surviving", rows)
	}
}

// TestSnmpFaceSyslogHostStatusCreateAndGoIsInconsistentValue proves a
// createAndGo(4) SET at an index with NO existing collector row is refused
// with SNMPError InconsistentValue -- mirroring the real m4300-24x agent's
// measured refusal to CREATE a syslog host row (probed 2026-08-05:
// createAndGo/createAndWait -> inconsistentValue) -- and that the state is
// left completely unchanged (no phantom row created).
func TestSnmpFaceSyslogHostStatusCreateAndGoIsInconsistentValue(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	g := rawClient(t, addr)

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}

	// Index 2 is free: SeedGSM7252PS's own syslog table holds only Index 1.
	oid := vo.SyslogHostStatus + ".2"
	pkt, err := g.Set([]gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Integer, Value: snmp.RowStatusCreateAndGo}})
	if err != nil {
		t.Fatalf("raw Set(%s=createAndGo) error = %v", oid, err)
	}
	if pkt.Error != gosnmp.InconsistentValue {
		t.Errorf("Set(%s=createAndGo) error-status = %s, want InconsistentValue", oid, pkt.Error)
	}
	if pkt.ErrorIndex != 1 {
		t.Errorf("Set(%s=createAndGo) error-index = %d, want 1", oid, pkt.ErrorIndex)
	}

	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	rows, err := client.Walk(context.Background(), vo.SyslogHostAddr)
	if err != nil {
		t.Fatalf("Walk(%s) after refused createAndGo error = %v", vo.SyslogHostAddr, err)
	}
	if len(rows) != 1 || rows[0].OID != vo.SyslogHostAddr+".1" {
		t.Errorf("SyslogHostAddr rows after refused createAndGo = %+v, want unchanged (only index 1)", rows)
	}
}

// TestSnmpFaceSyslogHostStatusCreateAndWaitIsInconsistentValue is
// CreateAndGoIsInconsistentValue's sibling for createAndWait(5) -- the
// OTHER row-creation mechanism the real agent was measured refusing the
// same way.
func TestSnmpFaceSyslogHostStatusCreateAndWaitIsInconsistentValue(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	g := rawClient(t, addr)

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}

	const rowStatusCreateAndWait = 5
	oid := vo.SyslogHostStatus + ".2"
	pkt, err := g.Set([]gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Integer, Value: rowStatusCreateAndWait}})
	if err != nil {
		t.Fatalf("raw Set(%s=createAndWait) error = %v", oid, err)
	}
	if pkt.Error != gosnmp.InconsistentValue {
		t.Errorf("Set(%s=createAndWait) error-status = %s, want InconsistentValue", oid, pkt.Error)
	}
}
