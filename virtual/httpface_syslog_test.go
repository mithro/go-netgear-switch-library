package virtual

// Tests for the virtual HTTP face's syslogConfiguration.html rendering,
// driven over real TCP loopback against webui.HTTPClient/webui.Reader --
// mirroring httpface_test.go's own established convention (startHTTPFace +
// webui.NewHTTPClient + webui.NewReader) and Python's
// tests/virtual/test_syslog_fidelity.py at pin b26eb1f.

import (
	"context"
	"errors"
	"strings"
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

// httpSyslogWriter is httpSyslogReader's write-side twin: a logged-in
// webui.Writer bound to a freshly-started HTTPFace over st.
func httpSyslogWriter(t *testing.T, key string, st *State) *webui.Writer {
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
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter(%q): %v", key, err)
	}
	return writer
}

// TestHTTPFaceRemoveSyslogCollectorRoundTrip proves the M4300 XUI
// row-status "Delete" apply removes the seeded collector and GetSyslog no
// longer reports it -- live-verified per webui.Writer.RemoveSyslogCollector's
// own doc comment, exercised here against the real HTTPFace/httptest server
// (not a hand-built fake session).
func TestHTTPFaceRemoveSyslogCollectorRoundTrip(t *testing.T) {
	st := seedByKey(t, "m4300-24x")
	if len(st.Syslog.Collectors) == 0 {
		t.Fatal("fixture precondition: m4300-24x's seed must carry at least one collector")
	}
	host := st.Syslog.Collectors[0].Host
	writer := httpSyslogWriter(t, "m4300-24x", st)

	if err := writer.RemoveSyslogCollector(context.Background(), host, false); err != nil {
		t.Fatalf("RemoveSyslogCollector(%q): %v", host, err)
	}

	reader := httpSyslogReader(t, "m4300-24x", st)
	after, err := reader.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog (after remove): %v", err)
	}
	for _, s := range after.Servers {
		if s.Host == host {
			t.Errorf("Servers after remove still contains %q", host)
		}
	}
}

// TestHTTPFaceAddSyslogCollectorUnsupported proves the M4300 web UI still
// refuses a collector ADD by name -- MEASURED (see
// webui.Writer.AddSyslogCollector's own doc comment) -- even against the
// real HTTPFace, issuing no page write.
func TestHTTPFaceAddSyslogCollectorUnsupported(t *testing.T) {
	st := seedByKey(t, "m4300-24x")
	writer := httpSyslogWriter(t, "m4300-24x", st)
	err := writer.AddSyslogCollector(context.Background(), "192.0.2.1", 514, 6, false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("AddSyslogCollector() error = %v, want errors.Is(..., model.ErrUnsupportedCapability)", err)
	}
}

// TestApplyXUISyslogRowsRefusesAdd drives ApplyXUISyslogRows's ADD-refusal
// branch DIRECTLY, rather than through webui.Writer.AddSyslogCollector:
// that facade method refuses unconditionally before any HTTP I/O (see
// TestHTTPFaceAddSyslogCollectorUnsupported above), so this fake's own
// "Error! Failed to Set 'Host Address' with ..." branch -- reproducing what
// the live M4300 actually answers a filled ADD template row with (see
// ApplyXUISyslogRows's own doc comment, driven live against m4300-24x
// 10.1.5.13 on 2026-08-05) -- is otherwise never exercised by any test.
// This constructs the fake state and calls the apply+render path exactly as
// renderFastpathXUIPage does, so the measured refusal behavior itself is
// covered, not just the facade's independent (and earlier) refusal.
func TestApplyXUISyslogRowsRefusesAdd(t *testing.T) {
	st := seedByKey(t, "m4300-24x")
	before := append([]SyslogCollectorSim(nil), st.Syslog.Collectors...)

	const addr = "192.0.2.55"
	form := map[string]string{
		"v_g_2_1_1": addr, // filled ADD template row's Host Address field
		"v_g_2_1_5": "Active",
	}
	errMsg := ApplyXUISyslogRows(st, form)

	wantErr := "Error! Failed to Set 'Host Address' with '" + addr + "'"
	if errMsg != wantErr {
		t.Fatalf("ApplyXUISyslogRows() errMsg = %q, want %q", errMsg, wantErr)
	}
	if len(st.Syslog.Collectors) != len(before) {
		t.Fatalf("ApplyXUISyslogRows() changed Collectors count from %d to %d, want unchanged (refused)",
			len(before), len(st.Syslog.Collectors))
	}
	for _, c := range st.Syslog.Collectors {
		if c.Host == addr {
			t.Fatalf("ApplyXUISyslogRows() added %q to Collectors despite refusing it", addr)
		}
	}

	m, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("model.GetModel(m4300-24x): %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec(m4300-24x): %v", err)
	}
	html := RenderXUISyslog(st, spec.SyslogPath, errMsg)
	if !strings.Contains(html, `NAME="err_flag" XC=hidden VALUE="1"`) {
		t.Errorf("RenderXUISyslog() did not set err_flag=1 on the refused add:\n%s", html)
	}
	if !strings.Contains(html, `NAME="err_msg" XC=hidden VALUE="`+wantErr+`"`) {
		t.Errorf("RenderXUISyslog() did not surface %q as err_msg:\n%s", wantErr, html)
	}
	// The refused address legitimately appears inside err_msg's own text
	// above; it must NOT also appear as a v_2_1_1 data-row cell value (that
	// would mean the fake actually added it despite refusing).
	if strings.Contains(html, `v_2_1_1 VALUE="`+addr+`"`) {
		t.Errorf("RenderXUISyslog() rendered the refused address %q as a v_2_1_1 data row", addr)
	}
}

// TestHTTPFaceRemoveSyslogCollectorUnsupportedOnNonM4300 proves gsm7252ps
// (XE FASTPATH, not M4300) is refused by name -- only the M4300 pages
// declare the cell metadata this write depends on.
func TestHTTPFaceRemoveSyslogCollectorUnsupportedOnNonM4300(t *testing.T) {
	st := seedByKey(t, "gsm7252ps")
	writer := httpSyslogWriter(t, "gsm7252ps", st)
	err := writer.RemoveSyslogCollector(context.Background(), "10.1.5.1", false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("RemoveSyslogCollector() error = %v, want errors.Is(..., model.ErrUnsupportedCapability)", err)
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
