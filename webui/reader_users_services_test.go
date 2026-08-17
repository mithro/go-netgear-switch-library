package webui_test

// Tests for webui.Reader.GetUsers/GetServices (reader.go), driven against
// the SAME real captured fixtures parse_users_services_test.go's parser
// tests use -- this file exercises the READER'S wiring (right path
// fetched, right parser called, the all-or-nothing services gate, the
// UsersPath/*ServicePath refusal-by-name gate), not parser correctness a
// second time.

import (
	"context"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestReaderGetUsersGSM7252PS(t *testing.T) {
	pages := map[string]any{
		"/userManagement.html": readFixture(t, "gsm7252ps_user_management.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "gsm7252ps")

	got, err := r.GetUsers(context.Background())
	if err != nil {
		t.Fatalf("GetUsers() error = %v", err)
	}
	if len(got) != 2 || got[0].Name != "admin" || got[0].AccessMode != "Super User" {
		t.Errorf("GetUsers() = %+v, want [admin/Super User, guest/Read Only]", got)
	}
}

func TestReaderGetUsersM4300(t *testing.T) {
	pages := map[string]any{
		"/v1/userManagement.html": readFixture(t, "m4300_24x_user_management.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "m4300-24x")

	got, err := r.GetUsers(context.Background())
	if err != nil {
		t.Fatalf("GetUsers() error = %v", err)
	}
	if len(got) != 2 || got[0].Name != "admin" || got[0].AccessMode != "Super User" {
		t.Errorf("GetUsers() = %+v, want [admin/Super User, guest/Read Only]", got)
	}
}

// TestReaderGetUsersUnsupportedOnGSM7228PS mirrors Python's
// test_a_model_whose_switch_404s_the_page_refuses_by_name: gsm7228ps really
// does answer 404 for /userManagement.html (measured 2026-08-03), so its
// spec has no UsersPath and the reader must refuse honestly -- BEFORE ever
// touching the session (an empty page map proves no GetPage call happens).
func TestReaderGetUsersUnsupportedOnGSM7228PS(t *testing.T) {
	r := mustNewReader(t, newFakeSession(map[string]any{}), "gsm7228ps")
	_, err := r.GetUsers(context.Background())
	wantUnsupported(t, err, "GetUsers")
}

func TestReaderGetServicesGSM7252PS(t *testing.T) {
	pages := map[string]any{
		"/httpConfiguration.html":  readFixture(t, "gsm7252ps_http_configuration.html"),
		"/httpsConfiguration.html": readFixture(t, "gsm7252ps_https_configuration.html"),
		"/sshConfiguration.html":   readFixture(t, "gsm7252ps_ssh_configuration.html"),
		"/telnet.html":             readFixture(t, "gsm7252ps_telnet.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "gsm7252ps")

	got, err := r.GetServices(context.Background())
	if err != nil {
		t.Fatalf("GetServices() error = %v", err)
	}
	want := []struct {
		name    string
		enabled bool
		port    *int
	}{
		{"http", true, nil},
		{"https", true, model.Ptr(443)},
		{"ssh", true, nil},
		{"telnet", false, nil},
	}
	if len(got) != len(want) {
		t.Fatalf("GetServices() returned %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w.name || got[i].Enabled != w.enabled {
			t.Errorf("GetServices()[%d] = %+v, want name=%s enabled=%v", i, got[i], w.name, w.enabled)
		}
		if (got[i].Port == nil) != (w.port == nil) || (got[i].Port != nil && *got[i].Port != *w.port) {
			t.Errorf("GetServices()[%d].Port = %v, want %v", i, got[i].Port, w.port)
		}
	}
}

func TestReaderGetServicesM4300(t *testing.T) {
	pages := map[string]any{
		"/v1/httpConfiguration.html":  readFixture(t, "m4300_24x_http_configuration.html"),
		"/v1/httpsConfiguration.html": readFixture(t, "m4300_24x_https_configuration.html"),
		"/v1/sshConfiguration.html":   readFixture(t, "m4300_24x_ssh_configuration.html"),
		"/v1/telnet.html":             readFixture(t, "m4300_24x_telnet.html"),
	}
	r := mustNewReader(t, newFakeSession(pages), "m4300-24x")

	got, err := r.GetServices(context.Background())
	if err != nil {
		t.Fatalf("GetServices() error = %v", err)
	}
	want := []struct {
		name    string
		enabled bool
		port    *int
	}{
		{"http", true, model.Ptr(80)},
		{"https", true, model.Ptr(443)},
		{"ssh", true, model.Ptr(22)},
		{"telnet", true, nil},
	}
	if len(got) != len(want) {
		t.Fatalf("GetServices() returned %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w.name || got[i].Enabled != w.enabled {
			t.Errorf("GetServices()[%d] = %+v, want name=%s enabled=%v", i, got[i], w.name, w.enabled)
		}
		if (got[i].Port == nil) != (w.port == nil) || (got[i].Port != nil && *got[i].Port != *w.port) {
			t.Errorf("GetServices()[%d].Port = %v, want %v", i, got[i].Port, w.port)
		}
	}
}

// TestReaderGetServicesUnsupportedOnGSM7228PS mirrors Python's
// test_a_model_missing_any_page_refuses_the_whole_op: gsm7228ps's spec has
// NO service paths at all (all-or-nothing: its httpConfiguration.html
// carries no admin control and its sshConfiguration.html 404s), so the
// reader must refuse the WHOLE op honestly -- before ever touching the
// session.
func TestReaderGetServicesUnsupportedOnGSM7228PS(t *testing.T) {
	r := mustNewReader(t, newFakeSession(map[string]any{}), "gsm7228ps")
	_, err := r.GetServices(context.Background())
	wantUnsupported(t, err, "GetServices")
}
