package webui_test

import (
	"context"
	"testing"

	"github.com/mithro/go-netgear-switch-library/webui"
)

// fakeSession is a minimal webui.Session implementation used only to prove
// the interface's method set compiles against a real implementer (there is
// no transport client yet -- that lands in a later task) and to exercise
// its context-first, five-method shape mirrors Python's HttpSession/
// AsyncHttpSession Protocols collapsed into one (dossier D-HTTP-P §7.4).
type fakeSession struct {
	loggedIn bool
}

func (f *fakeSession) Login(_ context.Context) error {
	f.loggedIn = true
	return nil
}

func (f *fakeSession) GetPage(_ context.Context, path string) (string, error) {
	return "GET " + path, nil
}

func (f *fakeSession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "POST " + path, nil
}

func (f *fakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, file webui.MultipartFile) (string, error) {
	return "POST(multipart) " + path + " " + file.Field, nil
}

func (f *fakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "POST(xml) " + path, nil
}

// TestSessionInterfaceIsImplementable is a compile-time + smoke check that
// webui.Session's five methods (dossier §5.1/§7.4) are exactly what a
// transport implementation must provide.
func TestSessionInterfaceIsImplementable(t *testing.T) {
	var s webui.Session = &fakeSession{}
	ctx := context.Background()
	if err := s.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if got, err := s.GetPage(ctx, "/dashboard.cgi"); err != nil || got != "GET /dashboard.cgi" {
		t.Errorf("GetPage() = (%q, %v), want (\"GET /dashboard.cgi\", nil)", got, err)
	}
	if got, err := s.PostForm(ctx, "/login.cgi", map[string]string{"password": "h"}); err != nil || got != "POST /login.cgi" {
		t.Errorf("PostForm() = (%q, %v), want (\"POST /login.cgi\", nil)", got, err)
	}
	file := webui.MultipartFile{Field: ".v_1_3_1_handle", Filename: "cert.pem", Content: []byte("x"), ContentType: "application/octet-stream"}
	if got, err := s.PostMultipart(ctx, "/http_file_download.html/a1", nil, file); err != nil || got != "POST(multipart) /http_file_download.html/a1 .v_1_3_1_handle" {
		t.Errorf("PostMultipart() = (%q, %v), want the field name echoed", got, err)
	}
	if got, err := s.PostXML(ctx, "wcd", "<Body/>"); err != nil || got != "POST(xml) wcd" {
		t.Errorf("PostXML() = (%q, %v), want (\"POST(xml) wcd\", nil)", got, err)
	}
}

// TestXuiRowField exercises XuiRow.Field's prefix-then-lookup shape and its
// ok=false-for-absent/ok=true-for-empty distinction, mirroring Python
// XuiRow.field.
func TestXuiRowField(t *testing.T) {
	row := webui.XuiRow{
		Prefix: "1.0.52.",
		Fields: map[string]string{
			"1.0.52.v_1_2_1": "1/0/1",
			"1.0.52.v_1_2_6": "",
		},
	}
	if v, ok := row.Field("v_1_2_1"); !ok || v != "1/0/1" {
		t.Errorf("Field(v_1_2_1) = (%q, %v), want (\"1/0/1\", true)", v, ok)
	}
	if v, ok := row.Field("v_1_2_6"); !ok || v != "" {
		t.Errorf("Field(v_1_2_6) = (%q, %v), want (\"\", true) -- rendered but empty", v, ok)
	}
	if _, ok := row.Field("v_9_9_9"); ok {
		t.Errorf("Field(v_9_9_9) ok = true, want false -- column never rendered")
	}
}

// TestXuiListPageRowFor exercises XuiListPage.RowFor, mirroring Python
// XuiListPage.row_for: the row whose column renders value.
func TestXuiListPageRowFor(t *testing.T) {
	page := webui.XuiListPage{
		Rows: []webui.XuiRow{
			{Prefix: "1.0.2.", Fields: map[string]string{"1.0.2.v_1_2_1": "1/0/1"}},
			{Prefix: "1.1.2.", Fields: map[string]string{"1.1.2.v_1_2_1": "1/0/2"}},
		},
	}
	row, ok := page.RowFor("v_1_2_1", "1/0/2")
	if !ok || row.Prefix != "1.1.2." {
		t.Errorf("RowFor(v_1_2_1, 1/0/2) = (%+v, %v), want prefix \"1.1.2.\"", row, ok)
	}
	if _, ok := page.RowFor("v_1_2_1", "1/0/99"); ok {
		t.Errorf("RowFor(v_1_2_1, 1/0/99) ok = true, want false -- no such row")
	}
}
