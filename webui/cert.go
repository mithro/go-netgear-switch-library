package webui

// cert.go: SSL-certificate upload, ported field-for-field from
// src/netgear_switch/http_write.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Deliberately split out of writer.go (which the
// Python source does not do -- upload_certificate and its helpers live
// alongside every other write op in the single http_write.py) purely for Go
// file-size/topic hygiene, per this task's brief; the split introduces no
// behavioural difference.
//
// Two wire shapes, dispatched by HTMLDialect:
//   - GOAHEAD_XML (gs728tpp): a raw XML POST (SSLCryptoCertificateImportList)
//     to the session-path-prefixed "wcd" endpoint. The RSA private key is
//     converted from whatever PEM shape it arrived in (PKCS#1 or PKCS#8) to
//     the PKCS#1 "traditional" pair the switch's GoAhead API requires, using
//     Go's stdlib crypto/x509 + encoding/pem -- NOT by shelling out to
//     openssl, mirroring the Python source's use of the `cryptography`
//     package over GS728TPPUpdater's original `openssl rsa` shell-out.
//   - multipart (gsm7228ps/S3300): the combined cert+key PEM as one file,
//     POSTed alongside ~20 fixed hidden form fields (endpoints.go's
//     gsm7228psSpec.CertUploadFormFields).
//
// A model whose real cert-upload mechanism is known but is not an HTTP form
// at all (m4300-24x, m4300-16x, gsm7252ps -- all FASTPATH SCP-cert switches,
// dossier D-HTTP-F §2.3) raises an error wrapping model.ErrKnownUnimplemented
// pointing at the SCP path, NEVER model.ErrUnsupportedCapability: the
// hardware genuinely CAN load a certificate, just not over this transport,
// and claiming otherwise would violate CLAUDE.md principle 4 ("no fabricated
// device limitations") exactly as much as claiming a capability that does
// not exist at all.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// CertUploadKnownUnimplemented maps a registry model key -> a human name for
// its known-but-not-HTTP SSL-certificate upload mechanism, mirroring
// Python's CERT_UPLOAD_KNOWN_UNIMPLEMENTED (http_write.py:84-99). These
// three keys are exactly the FASTPATH members of registry.SCP_CERT_PROFILES
// (slice-07 territory) -- gs728tpp deliberately does NOT appear here: its
// GoAhead XML-API upload is implemented (certUploadXML below), unlike at an
// earlier pin.
var CertUploadKnownUnimplemented = map[string]string{
	// The M4300 FASTPATH image takes the cert over SCP ("copy scp://.../
	// cert ..."), not an HTTP form -- a different transport entirely.
	"m4300-24x": "SCP file-copy to the switch (FastpathScpUpdater)",
	"m4300-16x": "SCP file-copy to the switch (FastpathScpUpdater)",
	// gsm7252ps is ALSO a FASTPATH SCP cert switch (in SCP_CERT_PROFILES):
	// its cert upload IS implemented, just over SCP not HTTP. The writer
	// must therefore NOT claim "no known mechanism" -- it points at the SCP
	// path, exactly like m4300.
	"gsm7252ps": "SCP file-copy to the switch (copy scp://)",
}

// certFilename is the filename real S3300 firmware is sent (S3300Updater
// posts the combined cert+key PEM as "certificate.pem").
const certFilename = "certificate.pem"

// rejectKnownUnimplementedCertUpload returns an error wrapping
// model.ErrKnownUnimplemented if modelKey's cert-upload mechanism is
// known-but-unimplemented over HTTP (see CertUploadKnownUnimplemented), or
// nil otherwise. Mirrors Python's _reject_known_unimplemented_cert_upload.
func rejectKnownUnimplementedCertUpload(modelKey string) error {
	mechanism, ok := CertUploadKnownUnimplemented[modelKey]
	if !ok {
		return nil
	}
	return fmt.Errorf(
		"SSL-certificate upload for %q uses %s, which this HTTP writer does not perform; use SyncSwitch.upload_certificate_scp instead: %w",
		modelKey, mechanism, model.ErrKnownUnimplemented,
	)
}

// combineCertKeyPEM concatenates the certificate and private-key PEMs into
// the single file S3300 firmware expects, mirroring Python's
// _combine_cert_key_pem: cert + "\n" + key, after trimming any trailing
// newline(s) off cert so exactly one separates the two blocks.
func combineCertKeyPEM(certPEM, keyPEM string) string {
	return strings.TrimRight(certPEM, "\n") + "\n" + keyPEM
}

// certUploadMultipart returns the (path, form fields, file part) for spec's
// grounded SSL-cert upload, or an error wrapping
// model.ErrUnsupportedCapability if it has none. Pure; mirrors Python's
// _cert_upload_multipart.
func certUploadMultipart(spec *HTTPModelSpec, certPEM, keyPEM string) (string, map[string]string, MultipartFile, error) {
	if spec.CertUploadPath == "" || spec.CertUploadFileField == "" {
		return "", nil, MultipartFile{}, fmt.Errorf("model %q has no known SSL-certificate upload mechanism: %w", spec.ModelKey, model.ErrUnsupportedCapability)
	}
	payload := MultipartFile{
		Field:       spec.CertUploadFileField,
		Filename:    certFilename,
		Content:     []byte(combineCertKeyPEM(certPEM, keyPEM)),
		ContentType: "application/octet-stream",
	}
	fields := make(map[string]string, len(spec.CertUploadFormFields))
	for k, v := range spec.CertUploadFormFields {
		fields[k] = v
	}
	return spec.CertUploadPath, fields, payload, nil
}

// rsaPKCS1Pair converts an RSA private key PEM (PKCS#1 or PKCS#8, unencrypted)
// to the PKCS#1 "traditional" pair the GS728TPP GoAhead API requires:
// (privateKeyPKCS1, publicKeyPKCS1). Mirrors Python's _rsa_pkcs1_pair, but
// via Go's stdlib crypto/x509+encoding/pem instead of the `cryptography`
// package. The switch accepts ONLY RSA keys, so a non-RSA key (EC/Ed25519/
// DSA) returns a clear error rather than silently producing a body the
// switch would reject.
//
// Parse order mirrors dossier D-HTTP-F §2.3's Go-porting guidance: try
// x509.ParsePKCS1PrivateKey first (the PKCS#1 shape), falling back to
// x509.ParsePKCS8PrivateKey (the shape Python's `cryptography.hazmat.
// primitives.serialization.load_pem_private_key` would also accept) with a
// type-assertion to *rsa.PrivateKey. An encrypted PEM block fails both
// parses (Go's x509 parsers do not decrypt), landing on the same
// "could not parse ... as an unencrypted PEM" error Python's
// password=None-implies-unencrypted rejection produces.
func rsaPKCS1Pair(keyPEM string) (privatePKCS1, publicPKCS1 string, err error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return "", "", fmt.Errorf("could not parse the private key as an unencrypted PEM: no PEM block found in input")
	}
	key, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err1 != nil {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", "", fmt.Errorf("could not parse the private key as an unencrypted PEM: %w", err2)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return "", "", fmt.Errorf("GS728TPP SSL-certificate upload requires an RSA private key; got %T", parsed)
		}
		key = rsaKey
	}
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	pubBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}
	return strings.TrimSpace(string(pem.EncodeToMemory(privBlock))), strings.TrimSpace(string(pem.EncodeToMemory(pubBlock))), nil
}

// xmlCertEscaper XML-escapes a PEM block for embedding in the
// SSLCryptoCertificateImportList body, mirroring Python's use of
// xml.sax.saxutils.escape with the extra {'"': "&quot;", "'": "&apos;"}
// entities (Go's encoding/xml only escapes <>&, never the two quote forms,
// so both are added explicitly here). strings.Replacer performs a single
// left-to-right scan rather than iterative substitution, so listing "&"
// first is not load-bearing for correctness -- but it mirrors the Python
// entity table's own ordering for readability.
var xmlCertEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// buildGS728TPPCertXML builds the SSLCryptoCertificateImportList XML body,
// mirroring Python's _build_gs728tpp_cert_xml exactly (source lines
// 188-205), only the three PEM blocks varying.
func buildGS728TPPCertXML(certPEM, publicPEM, privatePEM string) string {
	esc := xmlCertEscaper.Replace
	return "<?xml version='1.0' encoding='utf-8'?>" +
		"<DeviceConfiguration>" +
		`<SSLCryptoCertificateImportList action="set">` +
		"<Entry><instance>1</instance>" +
		"<certificate>" + esc(certPEM) + "</certificate>" +
		"<publicKey>" + esc(publicPEM) + "</publicKey>" +
		"<privateKey>" + esc(privatePEM) + "</privateKey>" +
		"</Entry></SSLCryptoCertificateImportList>" +
		"</DeviceConfiguration>"
}

// certUploadXML returns the (path, xml body) for spec's GoAhead XML-API
// SSL-cert upload, or an error wrapping model.ErrUnsupportedCapability if it
// has no upload endpoint. Mirrors Python's _cert_upload_xml. Returns a
// non-sentinel error (mirroring Python's ValueError) from rsaPKCS1Pair for a
// non-RSA key, unwrapped -- a caller-input mistake, not a device-capability
// question.
func certUploadXML(spec *HTTPModelSpec, certPEM, keyPEM string) (string, string, error) {
	if spec.CertUploadPath == "" {
		return "", "", fmt.Errorf("model %q has no known SSL-certificate upload mechanism: %w", spec.ModelKey, model.ErrUnsupportedCapability)
	}
	privatePKCS1, publicPKCS1, err := rsaPKCS1Pair(keyPEM)
	if err != nil {
		return "", "", err
	}
	return spec.CertUploadPath, buildGS728TPPCertXML(strings.TrimSpace(certPEM), publicPKCS1, privatePKCS1), nil
}

var (
	uploadStatusRE       = regexp.MustCompile(`<statusCode>(\d+)</statusCode>`)
	uploadStatusStringRE = regexp.MustCompile(`<statusString>([^<]*)</statusString>`)
	multipartErrorRE     = regexp.MustCompile(`(?i)(error[^<>\n]{0,80})`)
)

// checkMultipartCertResponse returns an error wrapping model.ErrHTTP unless
// an S3300 multipart cert-upload response reports success, mirroring
// Python's _check_multipart_cert_response. The S3300 http_file_download
// page returns HTTP 200 even on a rejected certificate -- the real outcome
// is in the page BODY (mirrors the certbot hook's own check): success is
// the literal (case-insensitive) substring "completed successfully".
func checkMultipartCertResponse(text string) error {
	if strings.Contains(strings.ToLower(text), "completed successfully") {
		return nil
	}
	reason := "no 'completed successfully' marker"
	if m := multipartErrorRE.FindStringSubmatch(text); m != nil {
		reason = strings.TrimSpace(m[1])
	}
	return fmt.Errorf("S3300 SSL-certificate upload was not accepted: %s: %w", reason, model.ErrHTTP)
}

// checkGoAheadUploadResponse returns an error wrapping model.ErrHTTP if a
// GoAhead cert-upload response is not success, mirroring Python's
// _check_goahead_upload_response. Success is
// "<statusCode>0</statusCode>"; a missing <statusCode> or a non-zero code
// is surfaced with the switch's own <statusString> -- never treated as a
// silent success (the S3300 cert-verify commit f5ef222's lesson applied to
// the GoAhead path too).
func checkGoAheadUploadResponse(text string) error {
	match := uploadStatusRE.FindStringSubmatch(text)
	if match == nil {
		return fmt.Errorf("GS728TPP cert upload: response carried no <statusCode> (unexpected page -- not logged in, or wrong endpoint?): %w", model.ErrHTTP)
	}
	if match[1] != "0" {
		reason := "unknown error"
		if detail := uploadStatusStringRE.FindStringSubmatch(text); detail != nil {
			reason = detail[1]
		}
		return fmt.Errorf("GS728TPP cert upload failed (statusCode=%s): %s: %w", match[1], reason, model.ErrHTTP)
	}
	return nil
}

// UploadCertificate uploads an HTTPS SSL server certificate (combined
// cert+key PEM), mirroring Python HttpWriter.upload_certificate
// (http_write.py:942-974). GROUNDED for gsm7228ps/S3300 (multipart form)
// and gs728tpp (GoAhead XML-API). A model whose real mechanism is a
// non-HTTP SCP copy raises an error wrapping model.ErrKnownUnimplemented
// pointing at the SCP path; a model with no known mechanism raises one
// wrapping model.ErrUnsupportedCapability. Disruptive (replaces the running
// certificate), so force=true is required -- capability is resolved BEFORE
// the force gate, mirroring Reboot.
func (w *Writer) UploadCertificate(ctx context.Context, certPEM, keyPEM string, force bool) error {
	if err := rejectKnownUnimplementedCertUpload(w.model.Key); err != nil {
		return err
	}
	if w.spec.HTMLDialect == HTMLDialectGoAheadXML {
		path, body, err := certUploadXML(w.spec, certPEM, keyPEM)
		if err != nil {
			return err
		}
		if !force {
			return fmt.Errorf("SSL-certificate upload replaces the switch's running certificate and is disruptive; pass force=true: %w", model.ErrProtectedPort)
		}
		resp, err := w.session.PostXML(ctx, path, body)
		if err != nil {
			return err
		}
		return checkGoAheadUploadResponse(resp)
	}
	path, fields, payload, err := certUploadMultipart(w.spec, certPEM, keyPEM)
	if err != nil {
		return err
	}
	if !force {
		return fmt.Errorf("SSL-certificate upload replaces the switch's running certificate and is disruptive; pass force=true: %w", model.ErrProtectedPort)
	}
	resp, err := w.session.PostMultipart(ctx, path, fields, payload)
	if err != nil {
		return err
	}
	return checkMultipartCertResponse(resp)
}
