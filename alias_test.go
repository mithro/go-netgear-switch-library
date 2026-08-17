package netgearswitch

// Tests for the root package's thin re-export wrappers around
// model.SyslogSeverity/SyslogSeverityWord/SyslogSeverityLabel (alias.go),
// proving each forwards to its model.* counterpart unchanged rather than
// diverging.

import "testing"

func TestSyslogSeverityAlias(t *testing.T) {
	got, err := SyslogSeverity("info")
	if err != nil {
		t.Fatalf("SyslogSeverity(info) error = %v", err)
	}
	if got != 6 {
		t.Errorf("SyslogSeverity(info) = %d, want 6", got)
	}
	if _, err := SyslogSeverity("bogus"); err == nil {
		t.Error("SyslogSeverity(bogus) error = nil, want an error")
	}
}

func TestSyslogSeverityWordAlias(t *testing.T) {
	got, err := SyslogSeverityWord(6)
	if err != nil {
		t.Fatalf("SyslogSeverityWord(6) error = %v", err)
	}
	if got != "info" {
		t.Errorf("SyslogSeverityWord(6) = %q, want %q", got, "info")
	}
	if _, err := SyslogSeverityWord(99); err == nil {
		t.Error("SyslogSeverityWord(99) error = nil, want an error")
	}
}

func TestSyslogSeverityLabelAlias(t *testing.T) {
	got, err := SyslogSeverityLabel(6)
	if err != nil {
		t.Fatalf("SyslogSeverityLabel(6) error = %v", err)
	}
	if got != "Info" {
		t.Errorf("SyslogSeverityLabel(6) = %q, want %q", got, "Info")
	}
	if _, err := SyslogSeverityLabel(99); err == nil {
		t.Error("SyslogSeverityLabel(99) error = nil, want an error")
	}
}
