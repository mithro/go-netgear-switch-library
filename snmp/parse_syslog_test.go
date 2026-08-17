package snmp

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// syslogVendor resolves gsm7252ps's VendorOids, the fixture model most
// syslog tests below use.
func syslogVendor(t *testing.T) VendorOids {
	t.Helper()
	vo, err := GetVendorOids(mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	return vo
}

func TestParseSyslogEnabledWithOneCollector(t *testing.T) {
	vo := syslogVendor(t)
	cfg, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 1)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		strRows(vo.SyslogHostAddr, map[int]string{1: "10.1.5.1"}),
		intRows(vo.SyslogHostPort, map[int]int64{1: 514}),
		intRows(vo.SyslogHostSeverity, map[int]int64{1: 6}),
		intRows(vo.SyslogHostStatus, map[int]int64{1: 1}),
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if err != nil {
		t.Fatalf("ParseSyslog: %v", err)
	}
	if !cfg.Enabled {
		t.Errorf("Enabled = false, want true")
	}
	if cfg.LocalPort != 514 {
		t.Errorf("LocalPort = %d, want 514", cfg.LocalPort)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("Servers = %+v, want 1 entry", cfg.Servers)
	}
	s := cfg.Servers[0]
	if s.Host != "10.1.5.1" || s.Port != 514 || s.Severity != 6 || !s.Active {
		t.Errorf("server = %+v, want {10.1.5.1 514 6 true}", s)
	}
	if s.Index == nil || *s.Index != 1 {
		t.Errorf("Index = %v, want pointer to 1", s.Index)
	}
}

// TestParseSyslogSparseIndexNeverDerivedFromPosition proves a gap in the
// host table's own index (1 and 3, nothing at 2 -- measured on m4300-24x
// 10.1.5.13) is preserved rather than renumbered, and that each column is
// matched to its row by INDEX, not by walk/slice position.
func TestParseSyslogSparseIndexNeverDerivedFromPosition(t *testing.T) {
	vo := syslogVendor(t)
	cfg, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 1)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		strRows(vo.SyslogHostAddr, map[int]string{1: "10.1.5.1", 3: "10.1.5.3"}),
		intRows(vo.SyslogHostPort, map[int]int64{1: 514, 3: 601}),
		intRows(vo.SyslogHostSeverity, map[int]int64{1: 6, 3: 3}),
		intRows(vo.SyslogHostStatus, map[int]int64{1: 1, 3: 1}),
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if err != nil {
		t.Fatalf("ParseSyslog: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("Servers = %+v, want 2 entries (indices 1 and 3, nothing at 2)", cfg.Servers)
	}
	// Sorted by index ascending.
	first, second := cfg.Servers[0], cfg.Servers[1]
	if first.Host != "10.1.5.1" || first.Index == nil || *first.Index != 1 {
		t.Errorf("first server = %+v, want host=10.1.5.1 index=1", first)
	}
	if second.Host != "10.1.5.3" || second.Index == nil || *second.Index != 3 {
		t.Errorf("second server = %+v, want host=10.1.5.3 index=3", second)
	}
	// The port/severity/status for index 3 must NOT have shifted onto
	// index 1's row (the position-for-index bug this test guards against).
	if first.Port != 514 || first.Severity != 6 {
		t.Errorf("first server port/severity = %d/%d, want 514/6 (not index 3's 601/3)", first.Port, first.Severity)
	}
	if second.Port != 601 || second.Severity != 3 {
		t.Errorf("second server port/severity = %d/%d, want 601/3", second.Port, second.Severity)
	}
}

func TestParseSyslogDisabledAdminMode(t *testing.T) {
	vo := syslogVendor(t)
	cfg, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 2)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		nil, nil, nil, nil,
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if err != nil {
		t.Fatalf("ParseSyslog: %v", err)
	}
	if cfg.Enabled {
		t.Errorf("Enabled = true, want false (admin mode 2)")
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("Servers = %+v, want none", cfg.Servers)
	}
}

// TestParseSyslogAbsentScalarsAreHonestlyZero proves a missing admin-mode/
// local-port GET (empty rows) degrades to Enabled=false/LocalPort=0 rather
// than raising -- mirrors Python's `_first_int(...) or 0`.
func TestParseSyslogAbsentScalarsAreHonestlyZero(t *testing.T) {
	vo := syslogVendor(t)
	cfg, err := ParseSyslog(nil, nil, nil, nil, nil, nil,
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus)
	if err != nil {
		t.Fatalf("ParseSyslog: %v", err)
	}
	if cfg.Enabled || cfg.LocalPort != 0 || len(cfg.Servers) != 0 {
		t.Errorf("cfg = %+v, want zero value", cfg)
	}
}

// TestParseSyslogEmptyAddressRowIsSkipped proves a row whose address is
// empty/whitespace-only is dropped, mirroring Python's
// `if address.strip()`.
func TestParseSyslogEmptyAddressRowIsSkipped(t *testing.T) {
	vo := syslogVendor(t)
	cfg, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 1)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		strRows(vo.SyslogHostAddr, map[int]string{1: "  "}),
		intRows(vo.SyslogHostPort, map[int]int64{1: 514}),
		intRows(vo.SyslogHostSeverity, map[int]int64{1: 6}),
		intRows(vo.SyslogHostStatus, map[int]int64{1: 1}),
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if err != nil {
		t.Fatalf("ParseSyslog: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("Servers = %+v, want none (blank address row skipped)", cfg.Servers)
	}
}

// TestParseSyslogPortDefaultsToZeroWhenMissingFromRow proves a collector
// row with no matching port/severity/status entry (a column walk that
// somehow came back short for that index) reports Port/Severity 0 rather
// than raising -- mirroring Python's `.get(index, 0)`.
func TestParseSyslogPortDefaultsToZeroWhenMissingFromRow(t *testing.T) {
	vo := syslogVendor(t)
	cfg, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 1)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		strRows(vo.SyslogHostAddr, map[int]string{1: "10.1.5.1"}),
		nil, nil, nil,
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if err != nil {
		t.Fatalf("ParseSyslog: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("Servers = %+v, want 1 entry", cfg.Servers)
	}
	s := cfg.Servers[0]
	if s.Port != 0 || s.Severity != 0 || s.Active {
		t.Errorf("server = %+v, want Port=0 Severity=0 Active=false", s)
	}
}

// TestParseSyslogMalformedPortColumnPropagatesSNMPError proves a drifted
// port/severity/status column (a non-integer value under its own base OID)
// raises too, not just a malformed address-column index.
func TestParseSyslogMalformedPortColumnPropagatesSNMPError(t *testing.T) {
	vo := syslogVendor(t)
	_, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 1)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		strRows(vo.SyslogHostAddr, map[int]string{1: "10.1.5.1"}),
		[]Row{NewStrRow(vo.SyslogHostPort+".1", "not-a-number")},
		nil, nil,
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseSyslog error = %v, want wrapping model.ErrSNMP", err)
	}
}

// TestParseSyslogMalformedIndexPropagatesSNMPError proves a walk that
// drifted (a non-integer index under the address base OID) raises, rather
// than silently dropping the row.
func TestParseSyslogMalformedIndexPropagatesSNMPError(t *testing.T) {
	vo := syslogVendor(t)
	_, err := ParseSyslog(
		[]Row{NewIntRow(vo.SyslogAdminMode, 1)},
		[]Row{NewIntRow(vo.SyslogLocalPort, 514)},
		[]Row{NewStrRow(vo.SyslogHostAddr+".x", "10.1.5.1")},
		nil, nil, nil,
		vo.SyslogHostAddr, vo.SyslogHostPort, vo.SyslogHostSeverity, vo.SyslogHostStatus,
	)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseSyslog error = %v, want wrapping model.ErrSNMP", err)
	}
}
