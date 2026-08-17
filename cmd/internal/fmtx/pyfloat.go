package fmtx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// pyFloatRepr reproduces Python's json.dumps encoding of a float --
// float.__repr__ (the SHORTEST decimal string that round-trips to the
// exact same float64), NOT %g. This is a DIFFERENT algorithm from pyG
// (pyg.go): pyG mirrors format.py's sensors_table TEXT rendering
// (f"{v:g}", fixed 6 significant digits), while pyFloatRepr mirrors
// json.dumps's float encoding for the JSON path (jsonify never touches
// floats specially, so json.dumps' own default float handling applies).
// Verified byte-for-byte against a live `python3 -c "import json;
// print(json.dumps(v))"` for: 0.0, -0.0, 3300.0, 100.0, negatives, the
// scientific-notation boundaries (1e15 fixed / 1e16 scientific / 1e17
// scientific, 1e-4 fixed / 1e-5 scientific), and NaN/+Inf/-Inf (which
// json.dumps -- with its default allow_nan=True, never overridden by
// this codebase's to_json -- renders as the non-standard-JSON tokens
// "NaN"/"Infinity"/"-Infinity"; see ToJSON's sentinel-substitution dance
// in json.go for how those non-numeric tokens get past Go's strict
// encoder, which would otherwise reject them as invalid JSON).
//
// Ported from CPython's format_float_short (Python/pystrtod.c) repr
// mode: get the shortest round-tripping digit string plus its decimal
// exponent (Go's strconv, with 'e' format and precision -1, computes the
// IDENTICAL shortest-digit-string algorithm Python's dtoa does -- both
// implement a Grisu/Steele-White-family shortest-round-trip algorithm,
// so the DIGITS always agree; only the fixed-vs-scientific FORMATTING
// policy differs, which this function applies itself rather than
// trusting Go's own 'g' verb, whose threshold is different), then choose
// scientific notation when decpt <= -4 or decpt > 16 (Python's own
// threshold; decpt is "how many digits would be left of the decimal
// point if written out in full", equivalently the 'e'-format exponent +
// 1) -- and, in fixed notation, ALWAYS keep a ".0" for a whole number
// (Python's Py_DTSF_ADD_DOT_0 flag; Go's default float formatting does
// NOT do this, which is the whole bug this function exists to fix).
func pyFloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}

	neg := math.Signbit(f)
	v := f
	if neg {
		v = -v
	}

	// Shortest round-tripping scientific form: "d[.ddd]e±dd".
	sci := strconv.FormatFloat(v, 'e', -1, 64)
	eIdx := strings.IndexByte(sci, 'e')
	mantissa := sci[:eIdx]
	exp, err := strconv.Atoi(sci[eIdx+1:])
	if err != nil {
		// Unreachable: strconv's 'e' verb always emits a parseable
		// "e[+-]DD" suffix.
		return sci
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	decpt := exp + 1 // digits before the decimal point, Steele-White style

	var out string
	switch {
	case decpt <= -4 || decpt > 16:
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		out = m + "e" + expSuffix(exp)
	case decpt <= 0:
		out = "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		out = digits[:decpt] + "." + digits[decpt:]
	}

	if neg {
		return "-" + out
	}
	return out
}

// expSuffix formats exp the way Python's repr does: an explicit sign and
// AT LEAST two digits (e.g. "+16", "-05", "+100" -- never "+6").
func expSuffix(exp int) string {
	sign := "+"
	if exp < 0 {
		sign = "-"
		exp = -exp
	}
	digits := strconv.Itoa(exp)
	if len(digits) < 2 {
		digits = "0" + digits
	}
	return sign + digits
}

// pyFloat is a float64 wrapper whose MarshalJSON emits pyFloatRepr's text
// instead of Go's default float encoding. It carries a pointer to the
// jsonSentinels its ENCLOSING ToJSON call generated (see jsonSentinels'
// doc comment for why this must be per-call, not a package-level
// constant) so a non-finite value's MarshalJSON can emit that call's
// sentinel string. It is never used directly by model types (which stay
// plain float64, per this codebase's existing struct definitions) --
// ToJSON substitutes it in, generically, via mirrorFloats, immediately
// before marshaling.
type pyFloat struct {
	v float64
	s *jsonSentinels
}

// jsonSentinels holds ONE ToJSON call's fresh, unpredictable marker
// strings for NaN/+Inf/-Inf: Go's encoding/json validates whatever bytes
// a MarshalJSON implementation returns (via its internal compact/scan
// step) and REJECTS bare identifiers like `NaN`, so pyFloat.MarshalJSON
// cannot emit Python's literal NaN/Infinity/-Infinity tokens directly --
// it emits a quoted sentinel STRING instead (ordinary, valid JSON), and
// ToJSON does one final, exact substitution (quotes and all) after the
// whole document is encoded, swapping each sentinel for the bare
// non-standard-JSON token Python itself writes.
//
// The sentinels are generated FRESH, cryptographically at random, on
// EVERY ToJSON call (see newJSONSentinels/randomSentinelToken) --
// NOT a fixed package-level constant. A fixed sentinel was this
// package's original design, and a real, live bug: encoding/json
// preserves raw bytes end-to-end (including NUL, which snmp/parse.go's
// SNMP-string decoding can pass through verbatim from a device's
// EntPhysicalName reply into model.Sensor.Name/PortStatus.Name/
// VLANInfo.Name and others), so a field whose value happened to equal
// the fixed sentinel text byte-for-byte would be silently corrupted by
// the blind whole-document string-replace: a quoted string field turning
// into a bare `NaN` token. A per-call random sentinel makes that
// collision cryptographically negligible instead of merely "unlikely
// arbitrary text" -- there is no fixed value across calls for a field to
// ever coincide with. The FINAL --json output stays fully deterministic
// regardless (the sentinel never survives past ToJSON's own return), so
// every existing byte-parity test is unaffected.
type jsonSentinels struct {
	nan, posInf, negInf             string // raw sentinel text
	nanJSON, posInfJSON, negInfJSON string // ALREADY JSON-string-encoded (quoted)
}

// newJSONSentinels builds a fresh jsonSentinels for one ToJSON call.
func newJSONSentinels() *jsonSentinels {
	s := &jsonSentinels{
		nan:    randomSentinelToken(),
		posInf: randomSentinelToken(),
		negInf: randomSentinelToken(),
	}
	s.nanJSON = mustMarshalString(s.nan)
	s.posInfJSON = mustMarshalString(s.posInf)
	s.negInfJSON = mustMarshalString(s.negInf)
	return s
}

// randomSentinelToken returns a fresh, cryptographically unpredictable
// per-call token: 16 bytes from crypto/rand, hex-encoded, wrapped in a
// human-recognisable (but not guessable) fixed prefix/suffix purely for
// debuggability if one were ever somehow observed mid-encode. On the
// (essentially unreachable, per crypto/rand.Read's own contract on every
// platform Go supports) chance the OS entropy source is unavailable,
// falls back to a still-effectively-unique, process/time-derived token
// rather than panicking a CLI/MCP command over a JSON-formatting detail.
func randomSentinelToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "\x00ngsw:pyfloat:" + hex.EncodeToString(b[:]) + "\x00"
	}
	return fmt.Sprintf("\x00ngsw:pyfloat:fallback:%d:%p\x00", time.Now().UnixNano(), &b)
}

func mustMarshalString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// Unreachable: json.Marshal of a plain Go string never fails.
		panic(err)
	}
	return string(b)
}

// MarshalJSON implements json.Marshaler for pyFloat; see pyFloat's and
// jsonSentinels' doc comments above.
func (f pyFloat) MarshalJSON() ([]byte, error) {
	switch {
	case math.IsNaN(f.v):
		return json.Marshal(f.s.nan)
	case math.IsInf(f.v, 1):
		return json.Marshal(f.s.posInf)
	case math.IsInf(f.v, -1):
		return json.Marshal(f.s.negInf)
	}
	return []byte(pyFloatRepr(f.v)), nil
}
