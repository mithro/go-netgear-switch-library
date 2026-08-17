package webui_test

// Tests for webui.Reader.GetSyslog (reader.go), driven against the SAME
// real captured fixtures parse_syslog_test.go's parser tests use -- this
// file exercises the READER'S wiring (right path fetched, right parser
// called, the SyslogPath refusal-by-name gate on every dialect that has no
// such page), not parser correctness a second time.

import (
	"context"
	"testing"
)

func TestReaderGetSyslogGSM7252PS(t *testing.T) {
	pages := map[string]any{
		"/syslogConfiguration.html": readFixture(t, "gsm7252ps_syslog_configuration.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "gsm7252ps")

	got, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog() error = %v", err)
	}
	if !got.Enabled || got.LocalPort != 514 || len(got.Servers) != 1 || got.Servers[0].Host != "10.1.5.1" {
		t.Errorf("GetSyslog() = %+v, want enabled/514/[10.1.5.1]", got)
	}
}

func TestReaderGetSyslogGSM7228PS(t *testing.T) {
	pages := map[string]any{
		"/syslogConfiguration.html": readFixture(t, "gsm7228ps_syslog_configuration.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "gsm7228ps")

	got, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog() error = %v", err)
	}
	if !got.Enabled || got.LocalPort != 514 || len(got.Servers) != 1 {
		t.Errorf("GetSyslog() = %+v, want enabled/514/[1 server]", got)
	}
}

func TestReaderGetSyslogM4300_24X(t *testing.T) {
	pages := map[string]any{
		"/v1/syslogConfiguration.html": readFixture(t, "m4300_24x_syslog_configuration.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "m4300-24x")

	got, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog() error = %v", err)
	}
	if !got.Enabled || got.LocalPort != 514 || len(got.Servers) != 1 {
		t.Errorf("GetSyslog() = %+v, want enabled/514/[1 server]", got)
	}
}

func TestReaderGetSyslogM4300_16X(t *testing.T) {
	pages := map[string]any{
		"/v1/syslogConfiguration.html": readFixture(t, "m4300_16x_syslog_configuration.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "m4300-16x")

	got, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog() error = %v", err)
	}
	if !got.Enabled || got.LocalPort != 514 || len(got.Servers) != 1 {
		t.Errorf("GetSyslog() = %+v, want enabled/514/[1 server]", got)
	}
}

// TestReaderGetSyslogPropagatesSessionError proves a session/transport
// failure fetching the (correctly resolved) syslog page propagates as-is,
// rather than being swallowed into an empty result.
func TestReaderGetSyslogPropagatesSessionError(t *testing.T) {
	// No page registered for /syslogConfiguration.html: the fake session
	// answers every GetPage with an error, exactly like a transport failure
	// would.
	r := mustNewReader(t, newFakeSession(map[string]any{}), "gsm7252ps")
	_, err := r.GetSyslog(context.Background())
	if err == nil {
		t.Fatal("GetSyslog() error = nil, want the session's fetch error to propagate")
	}
}

// TestReaderGetSyslogUnsupportedOnPlusAndGoAheadDialects mirrors Python's
// test_a_model_with_no_syslog_page_refuses_by_name: every dialect whose
// spec carries no SyslogPath (every Plus-class/GoAhead model) must refuse
// honestly, BEFORE ever touching the session -- an empty page map proves
// no GetPage call happens.
func TestReaderGetSyslogUnsupportedOnPlusAndGoAheadDialects(t *testing.T) {
	for _, key := range []string{"gs305ep", "gs110emx", "gs105pe", "gs728tpp"} {
		key := key
		t.Run(key, func(t *testing.T) {
			r := mustNewReader(t, newFakeSession(map[string]any{}), key)
			_, err := r.GetSyslog(context.Background())
			wantUnsupported(t, err, "GetSyslog")
		})
	}
}
