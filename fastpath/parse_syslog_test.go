package fastpath

// Tests for parseSyslog/colonFields (parse.go). The primary transcript
// below is parse_syslog's OWN docstring example (protocols/cli/parse.py:
// 838-846, pin b26eb1f) -- captured 2026-08-02 from m4300-24x (10.1.5.13),
// m4300-16x (10.1.5.20) and gsm7252ps (10.1.5.22) -- reproduced VERBATIM,
// mirroring parse_users_services_test.go's docstring-transcript convention.

import (
	"errors"
	"testing"
)

// syslogLoggingText/syslogHostsText are parse_syslog's own docstring
// transcript, VERBATIM.
const (
	syslogLoggingText = "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	syslogHostsText = "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp"
)

func TestParseSyslog_DocstringTranscript(t *testing.T) {
	cfg, err := parseSyslog(syslogLoggingText, syslogHostsText)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
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

// TestParseSyslog_M4300EightColumnShapeIgnoresTrailingColumns proves the
// M4300's wider host-table row (through Cert#, 8 columns) parses
// identically to gsm7252ps's narrower 5-column row -- only the first five
// whitespace-separated fields are taken.
func TestParseSyslog_M4300EightColumnShapeIgnoresTrailingColumns(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp   none  1"
	cfg, err := parseSyslog(syslogLoggingText, hosts)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Host != "10.1.5.1" {
		t.Errorf("Servers = %+v, want one row for 10.1.5.1", cfg.Servers)
	}
}

// TestParseSyslog_SparseIndexNeverDerivedFromPosition proves the table's
// OWN Index column (1 and 3, nothing at 2 -- measured on m4300-24x
// 10.1.5.13) is preserved rather than renumbered by row position.
func TestParseSyslog_SparseIndexNeverDerivedFromPosition(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp\n" +
		"3     10.1.5.3                 error      601    Active    udp"
	cfg, err := parseSyslog(syslogLoggingText, hosts)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("Servers = %+v, want 2 entries", cfg.Servers)
	}
	first, second := cfg.Servers[0], cfg.Servers[1]
	if first.Index == nil || *first.Index != 1 || first.Host != "10.1.5.1" {
		t.Errorf("first server = %+v, want index=1 host=10.1.5.1", first)
	}
	if second.Index == nil || *second.Index != 3 || second.Host != "10.1.5.3" {
		t.Errorf("second server = %+v, want index=3 host=10.1.5.3", second)
	}
}

// TestParseSyslog_DisabledAdminModeWord proves the enabled flag is decoded
// from the "Syslog Logging" field's own word, not defaulted.
func TestParseSyslog_DisabledAdminModeWord(t *testing.T) {
	logging := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	cfg, err := parseSyslog(logging, "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n"+
		"----- ------------------------ ---------- ------ --------- ----- ----- -----")
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if cfg.Enabled {
		t.Errorf("Enabled = true, want false")
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("Servers = %+v, want none (header+ruler only)", cfg.Servers)
	}
}

// TestParseSyslog_InactiveStatusWord proves a non-"Active" status word
// reports Active=false, mirroring Python's `status.lower() == "active"`.
func TestParseSyslog_InactiveStatusWord(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Inactive  udp"
	cfg, err := parseSyslog(syslogLoggingText, hosts)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Active {
		t.Errorf("Servers = %+v, want one row with Active=false", cfg.Servers)
	}
}

// TestParseSyslog_NonDigitPortDefaultsToZero proves a malformed Port cell
// degrades to 0 rather than aborting the whole row, mirroring Python's
// `int(port) if port.isdigit() else 0`.
func TestParseSyslog_NonDigitPortDefaultsToZero(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       -      Active    udp"
	cfg, err := parseSyslog(syslogLoggingText, hosts)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Port != 0 {
		t.Errorf("Servers = %+v, want one row with Port=0", cfg.Servers)
	}
}

// TestParseSyslog_SignedIndexCellRowSkipped is the regression test for A5:
// a SIGNED Index cell ("-1") must be treated as non-numeric and skip the
// row entirely, mirroring the pin's `not cells[0].isdigit()` row filter
// exactly (parse.py:881, pin b26eb1f) -- Python's isdigit() rejects a sign,
// unlike Go's strconv.Atoi/parseInt, which would otherwise happily parse
// "-1" as a real (negative) index.
func TestParseSyslog_SignedIndexCellRowSkipped(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"-1    10.1.5.1                 info       514    Active    udp\n" +
		"1     10.1.5.9                 info       514    Active    udp"
	cfg, err := parseSyslog(syslogLoggingText, hosts)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Host != "10.1.5.9" {
		t.Errorf("Servers = %+v, want ONLY the well-formed row (10.1.5.9); the -1 row must be skipped, not parsed as index -1", cfg.Servers)
	}
}

// TestParseSyslog_SignedPortCellDefaultsToZero is A5's sibling for the Port
// cell: a SIGNED Port ("-514") must degrade to 0, mirroring the pin's
// `int(port) if port.isdigit() else 0` exactly (parse.py:887, pin
// b26eb1f) -- isdigit() rejects the sign, so a signed port is treated the
// same as any other non-numeric Port cell (see
// TestParseSyslog_NonDigitPortDefaultsToZero above), never parsed as a
// negative port number.
func TestParseSyslog_SignedPortCellDefaultsToZero(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       -514   Active    udp"
	cfg, err := parseSyslog(syslogLoggingText, hosts)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Port != 0 {
		t.Errorf("Servers = %+v, want one row with Port=0 (signed port must not parse as negative)", cfg.Servers)
	}
}

// TestParseSyslog_UnknownSeverityWordRaises proves an unrecognised
// severity word propagates model.SyslogSeverity's own error rather than
// being silently swallowed.
func TestParseSyslog_UnknownSeverityWordRaises(t *testing.T) {
	hosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 bogus      514    Active    udp"
	_, err := parseSyslog(syslogLoggingText, hosts)
	if err == nil {
		t.Fatal("parseSyslog: want error for unknown severity word, got nil")
	}
}

// TestParseSyslog_NoLoggingBlockRaisesCliCommandRejected proves an
// unparseable `show logging` (e.g. "Command not found") raises rather than
// reporting a confidently wrong "remote logging is off" answer.
func TestParseSyslog_NoLoggingBlockRaisesCliCommandRejected(t *testing.T) {
	_, err := parseSyslog("Command not found / Incomplete command.", syslogHostsText)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("parseSyslog error = %v, want wrapping ErrCliCommandRejected", err)
	}
}

// TestParseSyslog_NonNumericLocalPortRaises proves a non-numeric local
// port value raises rather than being silently coerced.
func TestParseSyslog_NonNumericLocalPortRaises(t *testing.T) {
	logging := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : N/A"
	_, err := parseSyslog(logging, syslogHostsText)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("parseSyslog error = %v, want wrapping ErrCliCommandRejected", err)
	}
}

// TestColonFields_SkipsLinesWithoutAColon proves a line with no colon
// contributes nothing, and the first colon splits label from value.
func TestColonFields_SkipsLinesWithoutAColon(t *testing.T) {
	fields := colonFields("no colon here\nLabel : value : with : colons\n : blank label ignored")
	if len(fields) != 1 {
		t.Fatalf("fields = %+v, want exactly 1 entry", fields)
	}
	if fields["Label"] != "value : with : colons" {
		t.Errorf(`fields["Label"] = %q, want "value : with : colons"`, fields["Label"])
	}
}
