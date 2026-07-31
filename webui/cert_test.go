package webui_test

// cert_test.go: TDD coverage for webui.Writer's SSL-certificate upload
// (cert.go), ported scenario-for-scenario from the certificate section of
// tests/test_http_write.py at pin 1841111 in python-netgear-switch-library
// (the sync HttpWriter half only).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

const (
	certPEMFixture = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n"
	keyPEMFixture  = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
)

// expectedCertUploadForm is the exact fixed hidden-field set the S3300
// cert-upload page submits, mirroring test_http_write.py's
// _EXPECTED_CERT_FORM (copied field-for-field from
// gsm7228psSpec.CertUploadFormFields in endpoints.go).
var expectedCertUploadForm = map[string]string{
	"v_1_1_3":           "HTTP",
	"v_1_1_2":           "SSL Server Certificate PEM File",
	"v_1_2_1":           "",
	"v_1_3_2":           " not in progress",
	"v_1_3_3":           "",
	"v_1_3_4":           "",
	"v_1_9_1":           "image1",
	"v_1_9_5":           "",
	"v_1_9_2":           "1",
	"v_1_9_3":           "Enable",
	"v_1_19_1":          "32",
	"v_1_20_1":          "",
	"v_1_200_1":         "",
	"v_2_3_1":           " not in progress",
	"v_2_4_3":           "None",
	"v_2_4_2":           " not in progress",
	"v_4_1_1":           "",
	"submit_flag":       "8",
	"submit_target":     "http_file_download.html",
	"err_flag":          "0",
	"err_msg":           "",
	"clazz_information": "http_file_download.html",
}

type multipartCall struct {
	path string
	data map[string]string
	file webui.MultipartFile
}

// certSpySession records the single multipart POST a cert upload should
// drive, mirroring Python's _CertSpySession; GetPage/PostForm/PostXML must
// never be called by a multipart cert-upload flow.
type certSpySession struct {
	calls    []multipartCall
	response string
}

func newCertSpySession(response string) *certSpySession {
	return &certSpySession{response: response}
}

func (s *certSpySession) Login(context.Context) error { return nil }

func (s *certSpySession) GetPage(_ context.Context, path string) (string, error) {
	return "", fmt.Errorf("cert upload should not GetPage(%q)", path)
}

func (s *certSpySession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("cert upload should not PostForm(%q)", path)
}

func (s *certSpySession) PostMultipart(_ context.Context, path string, data map[string]string, file webui.MultipartFile) (string, error) {
	s.calls = append(s.calls, multipartCall{path: path, data: cloneMap(data), file: file})
	return s.response, nil
}

func (s *certSpySession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "", fmt.Errorf("gsm7228ps cert upload must be multipart, not XML(%q)", path)
}

var _ webui.Session = (*certSpySession)(nil)

const s3300UploadSuccess = "<html><body>SSL PEM Server Certificate file download through HTTP " +
	"is completed successfully.</body></html>"

func TestUploadCertificateDrivesGroundedMultipartPost(t *testing.T) {
	sess := newCertSpySession(s3300UploadSuccess)
	w := mustNewWriter(t, sess, "gsm7228ps")
	if err := w.UploadCertificate(context.Background(), certPEMFixture, keyPEMFixture, true); err != nil {
		t.Fatalf("UploadCertificate() error = %v", err)
	}
	if len(sess.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(sess.calls))
	}
	call := sess.calls[0]
	if call.path != "/http_file_download.html/a1" {
		t.Errorf("path = %q, want /http_file_download.html/a1", call.path)
	}
	if !mapsEqual(call.data, expectedCertUploadForm) {
		t.Errorf("data = %v, want %v", call.data, expectedCertUploadForm)
	}
	if call.file.Field != ".v_1_3_1_handle" {
		t.Errorf("file.Field = %q, want \".v_1_3_1_handle\"", call.file.Field)
	}
	if call.file.Filename != "certificate.pem" {
		t.Errorf("file.Filename = %q, want \"certificate.pem\"", call.file.Filename)
	}
	if call.file.ContentType != "application/octet-stream" {
		t.Errorf("file.ContentType = %q, want \"application/octet-stream\"", call.file.ContentType)
	}
	wantContent := strings.TrimRight(certPEMFixture, "\n") + "\n" + keyPEMFixture
	if string(call.file.Content) != wantContent {
		t.Errorf("file.Content = %q, want %q", call.file.Content, wantContent)
	}
}

func TestUploadCertificateRaisesWhenSwitchRejects(t *testing.T) {
	sess := newCertSpySession("<html><body>Error: invalid certificate file</body></html>")
	w := mustNewWriter(t, sess, "gsm7228ps")
	err := w.UploadCertificate(context.Background(), certPEMFixture, keyPEMFixture, true)
	if err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("error = %v, want it to contain \"not accepted\"", err)
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want model.ErrHTTP", err)
	}
}

func TestUploadCertificateRequiresForce(t *testing.T) {
	sess := newCertSpySession(s3300UploadSuccess)
	w := mustNewWriter(t, sess, "gsm7228ps")
	err := w.UploadCertificate(context.Background(), certPEMFixture, keyPEMFixture, false)
	wantProtectedPort(t, err, "UploadCertificate without force")
	if len(sess.calls) != 0 {
		t.Errorf("calls = %v, want none sent when force is withheld", sess.calls)
	}
}

func TestUploadCertificateM4300IsKnownUnimplementedNotUnsupported(t *testing.T) {
	sess := newCertSpySession(s3300UploadSuccess)
	w := mustNewWriter(t, sess, "m4300-24x")
	err := w.UploadCertificate(context.Background(), certPEMFixture, keyPEMFixture, true)
	if err == nil || !strings.Contains(err.Error(), "SCP") {
		t.Fatalf("error = %v, want it to mention SCP", err)
	}
	if !errors.Is(err, model.ErrKnownUnimplemented) {
		t.Errorf("error = %v, want model.ErrKnownUnimplemented", err)
	}
	if errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("error = %v, must NOT wrap model.ErrUnsupportedCapability -- the hardware can load a cert, just not over HTTP", err)
	}
	if len(sess.calls) != 0 {
		t.Errorf("calls = %v, want none", sess.calls)
	}
}

func TestUploadCertificateGsm7252psIsKnownUnimplementedPointsToSCP(t *testing.T) {
	// Parity fix 3a (dossier D-HTTP-F §2.3): gsm7252ps DOES have a
	// cert-upload mechanism (SCP), reachable via upload_certificate_scp. The
	// writer must raise model.ErrKnownUnimplemented naming SCP -- never
	// model.ErrUnsupportedCapability claiming "no known mechanism".
	sess := newCertSpySession(s3300UploadSuccess)
	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.UploadCertificate(context.Background(), certPEMFixture, keyPEMFixture, true)
	if err == nil || !strings.Contains(err.Error(), "SCP") {
		t.Fatalf("error = %v, want it to mention SCP", err)
	}
	if !strings.Contains(err.Error(), "upload_certificate_scp") {
		t.Errorf("error = %v, want it to name upload_certificate_scp", err)
	}
	if !errors.Is(err, model.ErrKnownUnimplemented) {
		t.Errorf("error = %v, want model.ErrKnownUnimplemented", err)
	}
	if len(sess.calls) != 0 {
		t.Errorf("calls = %v, want none", sess.calls)
	}
}

func TestUploadCertificateUnknownModelIsUnsupported(t *testing.T) {
	// gs305ep has an HTTP backend but no known cert-upload mechanism at all.
	sess := newCertSpySession(s3300UploadSuccess)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.UploadCertificate(context.Background(), certPEMFixture, keyPEMFixture, true)
	wantUnsupported(t, err, "UploadCertificate on gs305ep")
}

// --- GS728TPP GoAhead XML-API SSL-cert upload -------------------------------

type xmlCall struct {
	path string
	body string
}

// xmlCertSpySession records the single raw-XML POST the GoAhead cert-upload
// writer drives, mirroring Python's _XmlCertSpySession.
type xmlCertSpySession struct {
	calls    []xmlCall
	response string
}

func newXMLCertSpySession(response string) *xmlCertSpySession {
	return &xmlCertSpySession{response: response}
}

func (s *xmlCertSpySession) Login(context.Context) error { return nil }

func (s *xmlCertSpySession) GetPage(_ context.Context, path string) (string, error) {
	return "", fmt.Errorf("cert upload should not GetPage(%q)", path)
}

func (s *xmlCertSpySession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("cert upload should not PostForm(%q)", path)
}

func (s *xmlCertSpySession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("gs728tpp cert upload must be XML, not multipart(%q)", path)
}

func (s *xmlCertSpySession) PostXML(_ context.Context, path, body string) (string, error) {
	s.calls = append(s.calls, xmlCall{path: path, body: body})
	return s.response, nil
}

var _ webui.Session = (*xmlCertSpySession)(nil)

const goAheadUploadOK = `<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>0</statusCode></ResponseData>`

// rsaKeyPEM returns a freshly generated RSA private key as an unencrypted
// PKCS#8 PEM (the shape a real cert+key pair carries), mirroring Python's
// _rsa_key_pem() helper.
func rsaKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// ecKeyPEM returns a freshly generated EC private key as an unencrypted
// PKCS#8 PEM, for the "switch accepts only RSA" rejection test.
func ecKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestUploadCertificateGs728tppDrivesGroundedXMLPost(t *testing.T) {
	sess := newXMLCertSpySession(goAheadUploadOK)
	w := mustNewWriter(t, sess, "gs728tpp")
	if err := w.UploadCertificate(context.Background(), certPEMFixture, rsaKeyPEM(t), true); err != nil {
		t.Fatalf("UploadCertificate() error = %v", err)
	}
	if len(sess.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(sess.calls))
	}
	call := sess.calls[0]
	if call.path != "wcd" {
		t.Errorf("path = %q, want \"wcd\"", call.path)
	}
	if !strings.Contains(call.body, `<SSLCryptoCertificateImportList action="set">`) {
		t.Errorf("body missing SSLCryptoCertificateImportList: %q", call.body)
	}
	if !strings.Contains(call.body, "<instance>1</instance>") {
		t.Errorf("body missing <instance>1</instance>: %q", call.body)
	}
	// The RSA key was converted to PKCS#1 "traditional" form, and its
	// PKCS#1 public key extracted -- NOT the PKCS#8 "BEGIN PRIVATE KEY" it
	// came in as.
	if !strings.Contains(call.body, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("body missing PKCS#1 private key marker: %q", call.body)
	}
	if !strings.Contains(call.body, "-----BEGIN RSA PUBLIC KEY-----") {
		t.Errorf("body missing PKCS#1 public key marker: %q", call.body)
	}
	if strings.Contains(call.body, "BEGIN PRIVATE KEY") {
		t.Errorf("body still carries the PKCS#8 wrapper, want only PKCS#1: %q", call.body)
	}
	if !strings.Contains(call.body, "BEGIN CERTIFICATE") {
		t.Errorf("body missing the cert PEM: %q", call.body)
	}
}

func TestUploadCertificateGs728tppRequiresForce(t *testing.T) {
	sess := newXMLCertSpySession(goAheadUploadOK)
	w := mustNewWriter(t, sess, "gs728tpp")
	err := w.UploadCertificate(context.Background(), certPEMFixture, rsaKeyPEM(t), false)
	wantProtectedPort(t, err, "UploadCertificate(gs728tpp) without force")
	if len(sess.calls) != 0 {
		t.Errorf("calls = %v, want none sent when force is withheld", sess.calls)
	}
}

func TestUploadCertificateGs728tppRejectsNonRSAKey(t *testing.T) {
	sess := newXMLCertSpySession(goAheadUploadOK)
	w := mustNewWriter(t, sess, "gs728tpp")
	err := w.UploadCertificate(context.Background(), certPEMFixture, ecKeyPEM(t), true)
	if err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("error = %v, want it to mention RSA", err)
	}
	if len(sess.calls) != 0 {
		t.Errorf("calls = %v, want none sent -- key parsing fails before any POST", sess.calls)
	}
}

func TestUploadCertificateGs728tppSurfacesErrorStatus(t *testing.T) {
	sess := newXMLCertSpySession(`<?xml version="1.0" ?><ResponseData><statusCode>7</statusCode>` +
		`<statusString>invalid certificate</statusString></ResponseData>`)
	w := mustNewWriter(t, sess, "gs728tpp")
	err := w.UploadCertificate(context.Background(), certPEMFixture, rsaKeyPEM(t), true)
	if err == nil || !strings.Contains(err.Error(), "invalid certificate") {
		t.Fatalf("error = %v, want it to contain \"invalid certificate\"", err)
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want model.ErrHTTP", err)
	}
}

func TestUploadCertificateGs728tppMissingStatusCodeIsSurfaced(t *testing.T) {
	sess := newXMLCertSpySession("<html>not the wcd API at all</html>")
	w := mustNewWriter(t, sess, "gs728tpp")
	err := w.UploadCertificate(context.Background(), certPEMFixture, rsaKeyPEM(t), true)
	if err == nil || !strings.Contains(err.Error(), "no <statusCode>") {
		t.Fatalf("error = %v, want it to contain \"no <statusCode>\"", err)
	}
}
