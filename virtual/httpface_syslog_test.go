package virtual

// Tests for the virtual HTTP face's syslogConfiguration.html rendering,
// driven over real TCP loopback against webui.HTTPClient/webui.Reader --
// mirroring httpface_test.go's own established convention (startHTTPFace +
// webui.NewHTTPClient + webui.NewReader) and Python's
// tests/virtual/test_syslog_fidelity.py at pin b26eb1f.

import (
	"context"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// httpSyslogReader starts an HTTPFace over a freshly-seeded State and
// returns a logged-in webui.Reader bound to it, mirroring
// TestHTTPFaceXEFaceServesEveryReadOpFromState's own setup.
func httpSyslogReader(t *testing.T, key string, st *State) *webui.Reader {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("model.GetModel(%q): %v", key, err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec(%q): %v", key, err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", clientSpec(spec))
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader(%q): %v", key, err)
	}
	return reader
}

// TestHTTPFaceSyslogMatchesSeededState mirrors the CLI face's own
// TestSyslogCLIReadMatchesSeededState, for every managed model's real HTTP
// page render -- INCLUDING gsm7228ps, whose seed has NO collectors, which
// also proves the page's blank g_2_1_* template row (real firmware emits
// it, this mock reproduces it) is not parsed as a phantom collector with an
// empty host.
func TestHTTPFaceSyslogMatchesSeededState(t *testing.T) {
	for _, key := range hostnameCLIModels { // the four managed models
		key := key
		t.Run(key, func(t *testing.T) {
			st := seedByKey(t, key)
			reader := httpSyslogReader(t, key, st)

			got, err := reader.GetSyslog(context.Background())
			if err != nil {
				t.Fatalf("GetSyslog() error = %v", err)
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
			}
		})
	}
}

// TestHTTPFaceSyslogAgreesWithSNMP mirrors Python's
// test_fake_serves_the_page_and_agrees_with_its_own_snmp: the fake must
// answer GetSyslog IDENTICALLY over HTTP and SNMP for the same seeded
// state. gsm7228ps is the load-bearing case (empty host table both ways).
func TestHTTPFaceSyslogAgreesWithSNMP(t *testing.T) {
	for _, key := range []string{"gsm7252ps", "gsm7228ps", "m4300-24x"} {
		key := key
		t.Run(key, func(t *testing.T) {
			st := seedByKey(t, key)
			overHTTP, err := httpSyslogReader(t, key, st).GetSyslog(context.Background())
			if err != nil {
				t.Fatalf("HTTP GetSyslog() error = %v", err)
			}

			m, err := model.GetModel(key)
			if err != nil {
				t.Fatalf("model.GetModel(%q): %v", key, err)
			}
			addr, _, _ := startFace(t, st)
			snmpClient := snmp.NewGoSNMPClient(addr, "public")
			snmpReader, err := snmp.NewReader(snmpClient, m)
			if err != nil {
				t.Fatalf("snmp.NewReader: %v", err)
			}
			overSNMP, err := snmpReader.GetSyslog(context.Background())
			if err != nil {
				t.Fatalf("SNMP GetSyslog() error = %v", err)
			}

			if overHTTP.Enabled != overSNMP.Enabled {
				t.Errorf("HTTP Enabled = %v, SNMP Enabled = %v, want equal", overHTTP.Enabled, overSNMP.Enabled)
			}
			if overHTTP.LocalPort != overSNMP.LocalPort || overHTTP.LocalPort != 514 {
				t.Errorf("HTTP LocalPort = %d, SNMP LocalPort = %d, want both 514", overHTTP.LocalPort, overSNMP.LocalPort)
			}
			if len(overHTTP.Servers) != len(overSNMP.Servers) {
				t.Fatalf("HTTP Servers = %d, SNMP Servers = %d, want equal", len(overHTTP.Servers), len(overSNMP.Servers))
			}
			for i := range overHTTP.Servers {
				h, s := overHTTP.Servers[i], overSNMP.Servers[i]
				if h.Host != s.Host || h.Port != s.Port || h.Severity != s.Severity || h.Active != s.Active {
					t.Errorf("server[%d]: HTTP=%+v SNMP=%+v, want equal", i, h, s)
				}
			}
		})
	}
}

// TestHTTPFaceSyslogUnsupportedOnGS305EP mirrors Python's
// test_a_model_with_no_syslog_page_refuses_by_name: the Plus/GoAhead UIs
// have no such page -- that must raise, not read empty.
func TestHTTPFaceSyslogUnsupportedOnGS305EP(t *testing.T) {
	reader := httpSyslogReader(t, "gs305ep", SeedGS305EP())
	_, err := reader.GetSyslog(context.Background())
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetSyslog() error = %v, want errors.Is(..., model.ErrUnsupportedCapability)", err)
	}
}
