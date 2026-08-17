package webui_test

// Tests for webui.ParseXUISyslog, driven against REAL captured
// syslogConfiguration.html pages copied into testdata/http/ (see that
// directory's README.md for exact provenance) -- mirroring the pinned
// python-netgear-switch-library @ b26eb1f tests/test_http_syslog.py.

import (
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/webui"
)

// syslogFixtures is CAPTURES from test_http_syslog.py: the page each
// managed switch really served. All four carry the SAME configuration --
// enabled, local port 514, one Active IPv4 collector 10.1.5.1:514 at
// severity "Info" (6) -- which is what the fleet was set to when captured
// 2026-08-03.
var syslogFixtures = map[string]string{
	"gsm7252ps": "gsm7252ps_syslog_configuration.html",
	"gsm7228ps": "gsm7228ps_syslog_configuration.html",
	"m4300-24x": "m4300_24x_syslog_configuration.html",
	"m4300-16x": "m4300_16x_syslog_configuration.html",
}

// TestParseXUISyslogMatchesCapture mirrors test_http_syslog.py's own test
// that reads every managed switch's real page: the two web-UI families are
// NOT the same page (the M4300s are Cheetah and add a trailing
// "<!-- baselogCfg_* -->" comment per cell plus two scalars the GSMs don't
// emit), yet every coordinate the parser addresses is identical, so one
// parser correctly reads all four real captures.
func TestParseXUISyslogMatchesCapture(t *testing.T) {
	for key, fixture := range syslogFixtures {
		key, fixture := key, fixture
		t.Run(key, func(t *testing.T) {
			cfg, err := webui.ParseXUISyslog(readFixture(t, fixture))
			if err != nil {
				t.Fatalf("ParseXUISyslog(%s) error = %v", fixture, err)
			}
			if !cfg.Enabled {
				t.Errorf("ParseXUISyslog(%s) Enabled = false, want true", fixture)
			}
			if cfg.LocalPort != 514 {
				t.Errorf("ParseXUISyslog(%s) LocalPort = %d, want 514", fixture, cfg.LocalPort)
			}
			if len(cfg.Servers) != 1 {
				t.Fatalf("ParseXUISyslog(%s) Servers = %+v, want 1 entry", fixture, cfg.Servers)
			}
			s := cfg.Servers[0]
			if s.Host != "10.1.5.1" || s.Port != 514 || s.Severity != 6 || !s.Active {
				t.Errorf("ParseXUISyslog(%s) server = %+v, want {10.1.5.1 514 6 true}", fixture, s)
			}
		})
	}
}

// TestParseXUISyslogUnknownSeverityWordRaises mirrors
// test_severity_word_is_translated_not_defaulted: a severity word this
// library has not measured must raise, not silently read as 0 (0 is a
// real, plausible level -- "emergency" -- so defaulting to it would report
// the switch as forwarding emergencies only, wrongly and invisibly).
func TestParseXUISyslogUnknownSeverityWordRaises(t *testing.T) {
	html := strings.ReplaceAll(readFixture(t, syslogFixtures["gsm7252ps"]), `VALUE="Info"`, `VALUE="Verbose"`)
	_, err := webui.ParseXUISyslog(html)
	if err == nil {
		t.Fatal("ParseXUISyslog(unknown severity) error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "Verbose") {
		t.Errorf("ParseXUISyslog(unknown severity) error = %v, want it to mention %q", err, "Verbose")
	}
}

// TestParseXUISyslogPageWithoutAdminFieldIsRefused mirrors
// test_a_page_without_the_admin_field_is_refused: a fetch that landed
// somewhere else must not read as "logging disabled".
func TestParseXUISyslogPageWithoutAdminFieldIsRefused(t *testing.T) {
	_, err := webui.ParseXUISyslog("<html><body>login required</body></html>")
	if err == nil {
		t.Fatal("ParseXUISyslog(no admin field) error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "Admin Status") {
		t.Errorf("ParseXUISyslog(no admin field) error = %v, want it to mention \"Admin Status\"", err)
	}
}
