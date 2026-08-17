package main

import "testing"

// TestPyRepr pins pyRepr against CPython's own repr() output for str --
// every expected value below was verified against a live
// `python3 -c 'print(repr(...))'` run, not guessed.
func TestPyRepr(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", `''`},
		{"plain", "uplink to core", `'uplink to core'`},
		{"single_quote_only", "uplink's port", `"uplink's port"`},
		{"double_quote_only", `say "hi"`, `'say "hi"'`},
		{"both_quotes_prefers_single", `it's "quoted"`, `'it\'s "quoted"'`},
		{"backslash", `a\b`, `'a\\b'`},
		{"newline_tab_cr", "a\nb\tc\rd", `'a\nb\tc\rd'`},
		{"del_control_char", "a\x7fb", `'a\x7fb'`},
		{"low_control_char", "a\x01b", `'a\x01b'`},
		{"unicode_passthrough", "café", `'café'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pyRepr(tc.in)
			if got != tc.want {
				t.Errorf("pyRepr(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
