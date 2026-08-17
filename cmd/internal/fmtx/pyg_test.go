package fmtx

import (
	"math"
	"testing"
)

// TestPyG checks pyG against hand-verified Python f"{v:g}" outputs
// (Python's default %g formatting: 6 significant digits, trailing
// fractional zeros/decimal point trimmed, scientific notation only when
// the decimal exponent is < -4 or >= 6). Every case in the task's
// required edge-value list is covered (0, negative, 1000000, 0.0001,
// 123.456789, integers-as-floats), plus a few more to pin down the
// fixed/scientific boundary and other common shapes a real sensor
// reading might produce.
func TestPyG(t *testing.T) {
	tests := []struct {
		name string
		v    float64
		want string
	}{
		{"zero", 0, "0"},
		{"negative_zero", negZero(), "-0"},
		{"integer_as_float_five", 5.0, "5"},
		{"integer_as_float_hundred", 100.0, "100"},
		{"negative_integer_as_float", -42.0, "-42"},
		{"one_million_switches_to_scientific", 1000000, "1e+06"},
		{"one_million_minus_one_stays_fixed", 999999, "999999"},
		{"small_fixed_boundary", 0.0001, "0.0001"},
		{"just_below_fixed_boundary_switches_to_scientific", 0.00001, "1e-05"},
		{"typical_temperature", 123.456789, "123.457"},
		{"negative_typical_value", -123.456789, "-123.457"},
		{"simple_decimal", 0.1, "0.1"},
		{"trailing_zero_after_rounding", 25.0, "25"},
		{"half_precision", 12.5, "12.5"},
		{"six_sig_figs_exact", 123456, "123456"},
		{"seven_digits_rounds_and_switches", 1234567, "1.23457e+06"},
		{"large_negative_scientific", -1234567, "-1.23457e+06"},
		{"fan_rpm_like_value", 3300.0, "3300"},
		{"voltage_like_value", 3.3, "3.3"},
		{"tiny_positive", 1e-10, "1e-10"},
		{"tiny_negative", -1e-10, "-1e-10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pyG(tt.v); got != tt.want {
				t.Errorf("pyG(%v) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

// negZero returns IEEE-754 negative zero without the compiler constant-
// folding -0.0 into +0.0 (Go's untyped float constant -0.0 is just 0.0).
func negZero() float64 {
	zero := 0.0
	return -zero
}

// TestPyGNonFinite exercises pyG's NaN/+Inf/-Inf special cases -- a
// sensor reading can plausibly surface one of these (a disconnected
// probe, a firmware bug), and pyG must not panic or fall through to the
// exponent-parsing logic (which assumes a finite value) for any of them.
// Python's f"{v:g}" renders these as "nan"/"inf"/"-inf" (via its own
// float.__format__), which pyG mirrors directly rather than via the
// %g-exponent algorithm.
func TestPyGNonFinite(t *testing.T) {
	tests := []struct {
		name string
		v    float64
		want string
	}{
		{"nan", math.NaN(), "nan"},
		{"positive_infinity", math.Inf(1), "inf"},
		{"negative_infinity", math.Inf(-1), "-inf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pyG(tt.v); got != tt.want {
				t.Errorf("pyG(%v) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}
