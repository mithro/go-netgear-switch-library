package fmtx

import (
	"math"
	"testing"
)

// TestPyFloatRepr checks pyFloatRepr against live `python3 -c "import
// json; print(json.dumps(v))"` output (not hand-derived) for every value
// in the bug report's required list: 0.0, -0.0, 3300.0, 100.0,
// negatives, the scientific-notation boundaries (1e15/1e16/1e17,
// 1e-4/1e-5), and NaN/+Inf/-Inf.
func TestPyFloatRepr(t *testing.T) {
	tests := []struct {
		name string
		v    float64
		want string
	}{
		{"zero", 0.0, "0.0"},
		{"negative_zero", negZero(), "-0.0"},
		{"sensor_value_whole_number", 3300.0, "3300.0"},
		{"hundred", 100.0, "100.0"},
		{"negative_whole_number", -42.0, "-42.0"},
		{"negative_fractional", -123.456789, "-123.456789"},
		{"fractional", 45.678912, "45.678912"},
		{"one_e15_stays_fixed", 1e15, "1000000000000000.0"},
		{"one_e16_switches_to_scientific", 1e16, "1e+16"},
		{"one_e17_scientific", 1e17, "1e+17"},
		{"one_e_minus4_stays_fixed", 1e-4, "0.0001"},
		{"one_e_minus5_switches_to_scientific", 1e-5, "1e-05"},
		{"point_one", 0.1, "0.1"},
		{"one", 1.0, "1.0"},
		{"voltage_like", 3.3, "3.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pyFloatRepr(tt.v); got != tt.want {
				t.Errorf("pyFloatRepr(%v) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

// TestPyFloatReprNonFinite confirms pyFloatRepr's NaN/+Inf/-Inf text
// matches what Python's json.dumps ACTUALLY emits by default
// (allow_nan=True, never overridden by this codebase's to_json): the
// non-standard-JSON tokens "NaN"/"Infinity"/"-Infinity" -- verified via
// live `python3 -c "import json; print(json.dumps(float('nan')))"` (and
// the inf/-inf equivalents).
func TestPyFloatReprNonFinite(t *testing.T) {
	tests := []struct {
		name string
		v    float64
		want string
	}{
		{"nan", math.NaN(), "NaN"},
		{"positive_infinity", math.Inf(1), "Infinity"},
		{"negative_infinity", math.Inf(-1), "-Infinity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pyFloatRepr(tt.v); got != tt.want {
				t.Errorf("pyFloatRepr(%v) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}
