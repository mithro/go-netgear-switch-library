package fmtx

import (
	"math"
	"strconv"
	"strings"
)

// pyGPrecision is the SIGNIFICANT-digit count Python's default `%g`/f"{v:g}"
// formatting uses -- a FIXED 6, unlike Go's strconv.FormatFloat(v, 'g', -1,
// 64), whose -1 precision picks the MINIMAL digit count that round-trips
// the exact float64 value (the "shortest repr" Go's own %v/String()
// convention favours). The two diverge for any value whose shortest
// round-tripping representation needs fewer or more than 6 digits -- e.g.
// Go's -1-precision 'g' renders 100000.5 as "100000.5" (7 significant
// digits, because that's the shortest string that reads back to the exact
// same float64), where Python's 6-sig-fig %g rounds it to "100000" -- so
// naively reusing strconv.FormatFloat(v,'g',-1,64) for sensors_table would
// silently disagree with the pinned Python source on real sensor readings.
const pyGPrecision = 6

// pyG reproduces Python's f"{v:g}" (== C's printf("%g", v) with the
// default precision of 6 significant digits) byte-for-byte, for
// sensors_table's Value column (format.py: f"{s.value:g}"). Ported from
// the C standard's %g algorithm: round v to pyGPrecision significant
// digits: if the result's decimal exponent is < -4 or >= pyGPrecision, use
// scientific notation (Go's 'e' verb, which already matches Python's
// "e+NN"/"e-NN" -- at-least-2-digit, explicitly-signed exponent
// convention); otherwise use fixed notation. Either way, trailing
// fractional zeros -- and a bare trailing decimal point once they're all
// gone -- are trimmed, matching %g's default (non-'#'-flag) behaviour.
func pyG(v float64) string {
	switch {
	case math.IsNaN(v):
		return "nan"
	case math.IsInf(v, 1):
		return "inf"
	case math.IsInf(v, -1):
		return "-inf"
	}
	if v == 0 {
		if math.Signbit(v) {
			return "-0"
		}
		return "0"
	}

	// Round to pyGPrecision significant digits via Go's 'e' verb (prec-1
	// digits after the mantissa's leading digit == prec total significant
	// digits), then read the ROUNDED decimal exponent back out of that
	// string -- not math.Log10(v) -- so a value like 999999.6 that rounds
	// UP to 1.00000e+06 correctly switches to scientific notation exactly
	// where C/Python's algorithm does.
	sci := strconv.FormatFloat(v, 'e', pyGPrecision-1, 64)
	eIdx := strings.IndexByte(sci, 'e')
	exp, err := strconv.Atoi(sci[eIdx+1:])
	if err != nil {
		// Unreachable: strconv.FormatFloat's 'e' verb always emits a
		// parseable "e[+-]DD" suffix.
		return sci
	}

	if exp < -4 || exp >= pyGPrecision {
		return trimSciZeros(sci[:eIdx], sci[eIdx:])
	}
	decimals := pyGPrecision - 1 - exp
	if decimals < 0 {
		decimals = 0
	}
	return trimFixedZeros(strconv.FormatFloat(v, 'f', decimals, 64))
}

// trimFixedZeros strips trailing fractional zeros from a fixed-notation
// numeral, then the decimal point itself if nothing follows it --
// matching %g's "trailing zeros are removed" default (no '#' flag).
// Numerals with no decimal point (already integral, e.g. from a decimals
// count of 0) pass through unchanged.
func trimFixedZeros(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// trimSciZeros applies trimFixedZeros to a scientific-notation numeral's
// mantissa (the part before "e"), then reattaches expPart (the "e+NN"/
// "e-NN" suffix) unchanged.
func trimSciZeros(mantissa, expPart string) string {
	return trimFixedZeros(mantissa) + expPart
}
