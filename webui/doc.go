// Package webui implements the HTTP backend (model.BackendHTTP) for the
// root netgearswitch facade: reading and writing a NETGEAR switch's own web
// UI, by logging in, scraping its HTML/XML pages, and posting the same
// forms a browser would. Named webui, not http, to avoid stuttering
// against the stdlib net/http package this package's transport is built
// on.
//
// # Dialects
//
// A NETGEAR web UI is not one product: HTMLDialect names the seven
// distinct page shapes measured across the product line (HTMLDialectStandard,
// HTMLDialectGS110EMX, HTMLDialectGS105PE, HTMLDialectM4300,
// HTMLDialectXEFastpath, HTMLDialectS3300, HTMLDialectGoAheadXML), each with
// its own login handshake, page paths and parsers -- e.g. the ParseXE*
// family for the GS110EMX/xe_fastpath dialect, ParseM4300*/ParseS3300* for
// their respective managed-switch UIs, ParseGoAhead* for the GS728TPP's
// GoAhead XML-API dialect, and ParseXUI*/XuiListPage/XuiFormPage for the
// generic row/form page shape several dialects share. HTTPModelSpec
// (HTTPSpec), looked up per model, is what tells the rest of this package
// (and the capabilities package's oracle) which dialect and endpoint paths
// a given model actually has.
//
// # Session, reading and writing
//
// Session is the transport-agnostic authenticated-session interface
// (Login, GetPage, PostForm, PostMultipart, PostXML) every dialect's
// reader/writer is built on; HTTPClient (NewHTTPClient) is the production
// net/http-backed implementation, handling each dialect's own login crypto
// (crypt.go's Merge/MergeHashMD5, the Plus-family obfuscation scheme) and
// cookie/token/CSRF-hash bookkeeping. Reader (NewReader) and Writer
// (NewWriter) are this backend's netgearswitch.BackendReader/
// BackendWriter implementations, dispatching internally to whichever
// dialect's parse/form functions HTTPModelSpec names. UploadCertificate
// (cert.go) is the HTTPS-certificate deployment path for models that take
// one over the web UI (rejectKnownUnimplementedCertUpload names the real
// mechanism -- FASTPATH SCP, see package fastpath -- for models that do
// not).
//
// Ported field-for-field from src/netgear_switch/protocols/http/ (the
// normative source; that repo is read-only from here). Any discrepancy
// between this package and the pinned Python source is a bug in this
// package, not a deliberate deviation, unless called out in a comment.
package webui
