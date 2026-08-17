package webui_test

// Tests for webui.ParseXUIUsers/webui.ParseServicePage, driven against REAL
// captured pages copied into testdata/http/ (see that directory's README.md
// for exact provenance) -- mirroring the pinned python-netgear-switch-library
// @ b26eb1f tests/test_http_users.py and tests/test_http_services.py.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// --- userManagement.html ---------------------------------------------------

// TestParseXUIUsersMatchesCapture pins ParseXUIUsers against the two real
// captures (test_http_users.py::test_parses_the_real_user_management_page):
// both switches list the same two accounts, in the same order, with the
// same privileged verdict -- but this PAGE'S OWN wording ("Super User"/
// "Read Only"), not either switch's CLI wording.
func TestParseXUIUsersMatchesCapture(t *testing.T) {
	cases := map[string]string{
		"gsm7252ps": "gsm7252ps_user_management.html",
		"m4300-24x": "m4300_24x_user_management.html",
	}
	for key, fixture := range cases {
		fixture := fixture
		t.Run(key, func(t *testing.T) {
			users, err := webui.ParseXUIUsers(readFixture(t, fixture))
			if err != nil {
				t.Fatalf("ParseXUIUsers(%s) error = %v", fixture, err)
			}
			if len(users) != 2 {
				t.Fatalf("ParseXUIUsers(%s) returned %d users, want 2", fixture, len(users))
			}
			if users[0].Name != "admin" || users[1].Name != "guest" {
				t.Errorf("ParseXUIUsers(%s) names = [%q, %q], want [admin, guest]", fixture, users[0].Name, users[1].Name)
			}
			if users[0].AccessMode != "Super User" || users[1].AccessMode != "Read Only" {
				t.Errorf("ParseXUIUsers(%s) access modes = [%q, %q], want [Super User, Read Only]",
					fixture, users[0].AccessMode, users[1].AccessMode)
			}
			if users[0].Privileged == nil || !*users[0].Privileged {
				t.Errorf("ParseXUIUsers(%s) admin.Privileged = %v, want true", fixture, users[0].Privileged)
			}
			if users[1].Privileged == nil || *users[1].Privileged {
				t.Errorf("ParseXUIUsers(%s) guest.Privileged = %v, want false", fixture, users[1].Privileged)
			}
		})
	}
}

// TestParseXUIUsersRejectsSNMPv3Page pins the trap userConfiguration.html
// sounds like the login-accounts page and is not: on every managed switch
// it is the SNMPv3 user page, and reporting its rows as login accounts
// would be a confident wrong answer -- worse than refusing.
func TestParseXUIUsersRejectsSNMPv3Page(t *testing.T) {
	html := readFixture(t, "gsm7252ps_user_configuration.html")
	_, err := webui.ParseXUIUsers(html)
	if err == nil {
		t.Fatal("ParseXUIUsers(SNMPv3 page) error = nil, want an error naming \"no user rows\"")
	}
	if !strings.Contains(err.Error(), "no user rows") {
		t.Errorf("ParseXUIUsers(SNMPv3 page) error = %v, want it to mention \"no user rows\"", err)
	}
}

// TestParseXUIUsersRejectsPageWithNoRows covers a switch always having at
// least the account that authenticated the request -- an empty result
// means the fetch landed somewhere else, not that the switch has no users.
func TestParseXUIUsersRejectsPageWithNoRows(t *testing.T) {
	_, err := webui.ParseXUIUsers("<html><body>login required</body></html>")
	if err == nil {
		t.Fatal("ParseXUIUsers(no rows) error = nil, want an error")
	}
}

// --- the four management-service pages -------------------------------------

// serviceCase is one (model, service, fixture) -> expected (enabled, port)
// row, transcribed from test_http_services.py's REAL dict.
type serviceCase struct {
	model, service, fixture string
	enabled                 bool
	port                    *int
}

// TestParseServicePageMatchesCapture pins ParseServicePage against all
// eight real captures (test_http_services.py::
// test_parses_the_real_service_page).
func TestParseServicePageMatchesCapture(t *testing.T) {
	cases := []serviceCase{
		{"gsm7252ps", "http", "gsm7252ps_http_configuration.html", true, nil},
		{"gsm7252ps", "https", "gsm7252ps_https_configuration.html", true, model.Ptr(443)},
		{"gsm7252ps", "ssh", "gsm7252ps_ssh_configuration.html", true, nil},
		// Telnet really is off on 10.1.5.22 -- independently confirmed by
		// TCP 23 being refused there, while it is open on the m4300.
		{"gsm7252ps", "telnet", "gsm7252ps_telnet.html", false, nil},
		{"m4300-24x", "http", "m4300_24x_http_configuration.html", true, model.Ptr(80)},
		{"m4300-24x", "https", "m4300_24x_https_configuration.html", true, model.Ptr(443)},
		{"m4300-24x", "ssh", "m4300_24x_ssh_configuration.html", true, model.Ptr(22)},
		// The telnet page prints NO port on either switch. `show telnetcon`
		// reports 23 here, the page does not carry it, so nil is the
		// honest answer -- never defaulted to 23.
		{"m4300-24x", "telnet", "m4300_24x_telnet.html", true, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.model+"/"+c.service, func(t *testing.T) {
			status, err := webui.ParseServicePage(readFixture(t, c.fixture), c.service)
			if err != nil {
				t.Fatalf("ParseServicePage(%s, %q) error = %v", c.fixture, c.service, err)
			}
			if status.Name != c.service {
				t.Errorf("ParseServicePage(%s, %q).Name = %q, want %q", c.fixture, c.service, status.Name, c.service)
			}
			if status.Enabled != c.enabled {
				t.Errorf("ParseServicePage(%s, %q).Enabled = %v, want %v", c.fixture, c.service, status.Enabled, c.enabled)
			}
			if (status.Port == nil) != (c.port == nil) || (status.Port != nil && *status.Port != *c.port) {
				t.Errorf("ParseServicePage(%s, %q).Port = %s, want %s",
					c.fixture, c.service, intPtrString(status.Port), intPtrString(c.port))
			}
		})
	}
}

func intPtrString(p *int) string {
	if p == nil {
		return "<nil>"
	}
	return strconv.Itoa(*p)
}

// TestParseServicePageTheLastCheckedRadioWins pins the plain-form radio
// trap verbatim (test_http_services.py::test_the_last_checked_radio_wins):
// both radios of m4300-24x's httpConfiguration.html group carry a checked
// attribute, spelled two different ways -- a browser applies them in
// document order, so Enable (the LAST one) is what the page shows, and that
// must be the reading since the page was fetched OVER HTTP.
func TestParseServicePageTheLastCheckedRadioWins(t *testing.T) {
	html := readFixture(t, "m4300_24x_http_configuration.html")
	if !strings.Contains(html, `checked="checked"`) {
		t.Fatal(`fixture does not carry the Disable radio's checked="checked" -- fixture changed?`)
	}
	if !strings.Contains(html, "CHECKED>") {
		t.Fatal("fixture does not carry the Enable radio's bare uppercase CHECKED -- fixture changed?")
	}
	status, err := webui.ParseServicePage(html, "http")
	if err != nil {
		t.Fatalf("ParseServicePage() error = %v", err)
	}
	if !status.Enabled {
		t.Error("ParseServicePage(m4300-24x http) Enabled = false, want true (last checked radio wins)")
	}
}

// TestParseServicePageRejectsPageWithNoControl pins the S3300's
// httpConfiguration.html, which carries NO admin control at all (only
// timeouts/session counts) -- it must raise rather than read as "HTTP
// disabled": the page not carrying the control says nothing about whether
// the service is running, and it plainly is, since the page came back over
// it (test_http_services.py::test_a_page_without_the_control_is_refused).
func TestParseServicePageRejectsPageWithNoControl(t *testing.T) {
	html := readFixture(t, "gsm7228ps_http_configuration.html")
	_, err := webui.ParseServicePage(html, "http")
	if err == nil {
		t.Fatal("ParseServicePage(gsm7228ps http, no control) error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "no admin-state control") {
		t.Errorf("ParseServicePage() error = %v, want it to mention \"no admin-state control\"", err)
	}
}
