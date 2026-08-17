package fmtx

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
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

// pyFloat is a float64 wrapper whose MarshalJSON emits pyFloatRepr's
// text instead of Go's default float encoding. It is never used
// directly by model types (which stay plain float64, per this
// codebase's existing struct definitions) -- ToJSON substitutes it in,
// generically, via mirrorFloats below, immediately before marshaling.
type pyFloat float64

// nan/posInf/negInfSentinel are unique marker strings pyFloat.MarshalJSON
// emits (as ordinary, VALID JSON strings) in place of the literal
// NaN/Infinity/-Infinity tokens Python's json.dumps would write: Go's
// encoding/json validates whatever bytes a MarshalJSON implementation
// returns (via its internal compact/scan step) and REJECTS bare
// identifiers like `NaN`, so emitting them directly would make Encode
// fail outright. Emitting a quoted sentinel string keeps every
// intermediate step valid JSON; ToJSON does one final, exact string
// substitution (quotes and all) after the full document is encoded, to
// swap each sentinel for the bare non-standard-JSON token Python itself
// writes. The markers are arbitrary but distinctive enough that no real
// model field could ever legitimately contain one.
const (
	nanSentinel    = "\x00ngsw:pyfloat:nan\x00"
	posInfSentinel = "\x00ngsw:pyfloat:posinf\x00"
	negInfSentinel = "\x00ngsw:pyfloat:neginf\x00"
)

// nanSentinelJSON etc. are the sentinels ALREADY JSON-string-encoded
// (quotes and any necessary escaping included), computed once so
// ToJSON's post-encode substitution matches byte-for-byte regardless of
// exactly how encoding/json escapes the sentinel's control characters.
var (
	nanSentinelJSON    = mustMarshalString(nanSentinel)
	posInfSentinelJSON = mustMarshalString(posInfSentinel)
	negInfSentinelJSON = mustMarshalString(negInfSentinel)
)

func mustMarshalString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// Unreachable: json.Marshal of a plain Go string never fails.
		panic(err)
	}
	return string(b)
}

// MarshalJSON implements json.Marshaler for pyFloat; see pyFloat's and
// the sentinel constants' doc comments above.
func (f pyFloat) MarshalJSON() ([]byte, error) {
	v := float64(f)
	switch {
	case math.IsNaN(v):
		return json.Marshal(nanSentinel)
	case math.IsInf(v, 1):
		return json.Marshal(posInfSentinel)
	case math.IsInf(v, -1):
		return json.Marshal(negInfSentinel)
	}
	return []byte(pyFloatRepr(v)), nil
}
