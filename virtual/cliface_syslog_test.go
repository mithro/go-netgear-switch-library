package virtual

// Tests for the virtual CLI face's remote-logging surface (show logging /
// show logging hosts / logging syslog / no logging syslog), driven over the
// SAME real fastpath.Reader/fastpath.Writer + CliFace pairing
// cliface_test.go's hostname tests use -- proving the CLI parser round
// trips through this mock's renderer, not just against hand-built text.

import (
	"context"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// TestCliSyslogSeverityWordFallsBackToNumber proves an out-of-range
// severity (never measured on any real switch, but not something this mock
// should ever crash on) renders as its own stringified number rather than
// a fabricated word, mirroring Python's `_SEVERITY_WORDS.get(n, str(n))`.
func TestCliSyslogSeverityWordFallsBackToNumber(t *testing.T) {
	if got := cliSyslogSeverityWord(99); got != "99" {
		t.Errorf("cliSyslogSeverityWord(99) = %q, want %q", got, "99")
	}
	if got := cliSyslogSeverityWord(6); got != "info" {
		t.Errorf("cliSyslogSeverityWord(6) = %q, want %q", got, "info")
	}
}

// TestRenderLoggingHostsRendersMultipleCollectorsAndOutOfRangeSeverity
// exercises renderLoggingHosts directly (not through the reader/parser
// round trip the other tests use) against a state with more than one row
// and a severity number the CLI word map has no entry for.
func TestRenderLoggingHostsRendersMultipleCollectorsAndOutOfRangeSeverity(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Syslog = SyslogSim{
		AdminMode: 1,
		LocalPort: 514,
		Collectors: []SyslogCollectorSim{
			{Host: "10.1.5.1", Port: 514, Severity: 6, Status: 1, Index: 1},
			{Host: "10.1.5.9", Port: 601, Severity: 42, Status: 0, Index: 3},
		},
	}
	face, _ := newTestCliFace(t, "gsm7252ps", st)
	out := face.renderLoggingHosts()
	if !strings.Contains(out, "10.1.5.1") || !strings.Contains(out, "info") {
		t.Errorf("renderLoggingHosts() = %q, want it to contain the first row (10.1.5.1/info)", out)
	}
	if !strings.Contains(out, "10.1.5.9") || !strings.Contains(out, "42") {
		t.Errorf("renderLoggingHosts() = %q, want it to contain the second row (10.1.5.9/42)", out)
	}
	if !strings.Contains(out, "Inactive") {
		t.Errorf("renderLoggingHosts() = %q, want the Status=0 row to render Inactive", out)
	}
}

// TestSyslogCLIReadMatchesSeededState proves GetSyslog over the CLI face
// reports exactly what each FASTPATH model's own seed carries, for every
// one of the four CLI-capable managed models (including gsm7228ps, whose
// seed is deliberately disabled/empty -- the fleet's only "logging
// configured nowhere" case).
func TestSyslogCLIReadMatchesSeededState(t *testing.T) {
	for _, key := range hostnameCLIModels {
		key := key
		t.Run(key, func(t *testing.T) {
			st := seedByKey(t, key)
			face, m := newTestCliFace(t, key, st)
			reader, err := fastpath.NewReader(face, m)
			if err != nil {
				t.Fatalf("fastpath.NewReader: %v", err)
			}
			got, err := reader.GetSyslog(context.Background())
			if err != nil {
				t.Fatalf("GetSyslog: %v", err)
			}
			wantEnabled := st.Syslog.AdminMode == 1
			if got.Enabled != wantEnabled || got.LocalPort != st.Syslog.LocalPort {
				t.Errorf("GetSyslog() = %+v, want Enabled=%v LocalPort=%d", got, wantEnabled, st.Syslog.LocalPort)
			}
			if len(got.Servers) != len(st.Syslog.Collectors) {
				t.Fatalf("GetSyslog() returned %d servers, want %d (seeded)", len(got.Servers), len(st.Syslog.Collectors))
			}
			for i, c := range st.Syslog.Collectors {
				s := got.Servers[i]
				if s.Host != c.Host || s.Port != c.Port || s.Severity != c.Severity {
					t.Errorf("server[%d] = %+v, want host=%s port=%d severity=%d", i, s, c.Host, c.Port, c.Severity)
				}
				if s.Index == nil || *s.Index != c.Index {
					t.Errorf("server[%d].Index = %v, want %d (the table's OWN sparse index)", i, s.Index, c.Index)
				}
			}
		})
	}
}

// TestSyslogCLIRoundTrip mirrors TestHostnameCLIRoundTrip's shape: toggle
// remote logging off then back on through the CLI writer, verifying each
// step reads back correctly, then restore the original state.
func TestSyslogCLIRoundTrip(t *testing.T) {
	for _, key := range hostnameCLIModels {
		key := key
		t.Run(key, func(t *testing.T) {
			st := seedByKey(t, key)
			face, m := newTestCliFace(t, key, st)
			reader, err := fastpath.NewReader(face, m)
			if err != nil {
				t.Fatalf("fastpath.NewReader: %v", err)
			}
			writer, err := fastpath.NewWriter(face, m)
			if err != nil {
				t.Fatalf("fastpath.NewWriter: %v", err)
			}
			ctx := context.Background()

			original, err := reader.GetSyslog(ctx)
			if err != nil {
				t.Fatalf("GetSyslog (before): %v", err)
			}

			if err := writer.SetSyslogEnabled(ctx, !original.Enabled, false); err != nil {
				t.Fatalf("SetSyslogEnabled(%v): %v", !original.Enabled, err)
			}
			if got, err := reader.GetSyslog(ctx); err != nil || got.Enabled != !original.Enabled {
				t.Errorf("GetSyslog after toggle = (%+v, %v), want Enabled=%v", got, err, !original.Enabled)
			}

			if err := writer.SetSyslogEnabled(ctx, original.Enabled, false); err != nil {
				t.Fatalf("SetSyslogEnabled (restore): %v", err)
			}
			if got, err := reader.GetSyslog(ctx); err != nil || got.Enabled != original.Enabled {
				t.Errorf("GetSyslog after restore = (%+v, %v), want Enabled=%v", got, err, original.Enabled)
			}
		})
	}
}

// TestSyslogCLIAndSNMPAgree mirrors TestHostnameCLIAndSNMPAgree: the CLI
// face's "show logging"/"show logging hosts" and the SNMP face's vendor
// `.14` subtree must report the SAME configuration for one seeded state.
func TestSyslogCLIAndSNMPAgree(t *testing.T) {
	for _, key := range hostnameCLIModels {
		key := key
		t.Run(key, func(t *testing.T) {
			st := seedByKey(t, key)
			face, m := newTestCliFace(t, key, st)
			reader, err := fastpath.NewReader(face, m)
			if err != nil {
				t.Fatalf("fastpath.NewReader: %v", err)
			}
			cliCfg, err := reader.GetSyslog(context.Background())
			if err != nil {
				t.Fatalf("GetSyslog: %v", err)
			}

			vo, err := snmp.GetVendorOids(m)
			if err != nil {
				t.Fatalf("snmp.GetVendorOids: %v", err)
			}
			om := st.OIDMap()
			snmpEnabled := om[vo.SyslogAdminMode].Value == "1"
			if cliCfg.Enabled != snmpEnabled {
				t.Errorf("CLI Enabled = %v, SNMP admin-mode enabled = %v, want equal", cliCfg.Enabled, snmpEnabled)
			}
			if len(cliCfg.Servers) != len(st.Syslog.Collectors) {
				t.Errorf("CLI Servers = %d, SNMP state Collectors = %d, want equal", len(cliCfg.Servers), len(st.Syslog.Collectors))
			}
		})
	}
}
