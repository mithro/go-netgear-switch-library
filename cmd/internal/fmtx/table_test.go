package fmtx

import "testing"

// TestTableBasic hand-derives the expected output from format.py's
// _table algorithm: widths = max(header, cell) per column, cells
// left-justified, columns joined by exactly two spaces.
func TestTableBasic(t *testing.T) {
	headers := []string{"Port", "Name"}
	rows := [][]string{
		{"1", "uplink"},
		{"22", "-"},
	}
	// Column widths: Port -> max(len("Port")=4, len("1")=1, len("22")=2) = 4
	//                Name -> max(len("Name")=4, len("uplink")=6, len("-")=1) = 6
	want := "Port  Name  \n" +
		"1     uplink\n" +
		"22    -     "
	if got := table(headers, rows); got != want {
		t.Errorf("table() =\n%q\nwant\n%q", got, want)
	}
}

func TestTableEmptyRows(t *testing.T) {
	got := table([]string{"A", "B"}, nil)
	want := "A  B"
	if got != want {
		t.Errorf("table(no rows) = %q, want %q", got, want)
	}
}

// TestTableLastColumnKeepsTrailingSpaces confirms this port deliberately
// reproduces format.py's ljust-on-every-column behaviour: a row whose
// last cell is shorter than that column's widest cell is NOT rstripped.
func TestTableLastColumnKeepsTrailingSpaces(t *testing.T) {
	headers := []string{"X"}
	rows := [][]string{{"a"}, {"bbbb"}}
	got := table(headers, rows)
	want := "X   \na   \nbbbb"
	if got != want {
		t.Errorf("table() =\n%q\nwant\n%q", got, want)
	}
}

// TestTableRuneWidth confirms column widths are measured by RUNE count,
// not byte length -- a multi-byte UTF-8 cell must not desync padding
// from a byte-length count (Python's len()/ljust count code points).
func TestTableRuneWidth(t *testing.T) {
	headers := []string{"Description"}
	rows := [][]string{
		{"café"}, // 4 runes, 5 bytes (é is 2 bytes in UTF-8)
		{"x"},
	}
	// Width = max(len("Description")=11, runeLen("café")=4, runeLen("x")=1) = 11
	got := table(headers, rows)
	want := "Description\n" +
		"café       \n" + // "café" (4 runes) + 7 spaces to reach 11 runes
		"x          " // "x" (1 rune) + 10 spaces
	if got != want {
		t.Errorf("table() =\n%q\nwant\n%q", got, want)
	}
}

func TestLjust(t *testing.T) {
	tests := []struct {
		s     string
		width int
		want  string
	}{
		{"ab", 5, "ab   "},
		{"ab", 2, "ab"},
		{"ab", 1, "ab"}, // already past width: unchanged, never truncated
		{"", 3, "   "},
		{"café", 6, "café  "}, // 4 runes + 2 spaces
	}
	for _, tt := range tests {
		if got := ljust(tt.s, tt.width); got != tt.want {
			t.Errorf("ljust(%q, %d) = %q, want %q", tt.s, tt.width, got, tt.want)
		}
	}
}

func TestPyBool(t *testing.T) {
	if got := pyBool(true); got != "True" {
		t.Errorf("pyBool(true) = %q, want %q", got, "True")
	}
	if got := pyBool(false); got != "False" {
		t.Errorf("pyBool(false) = %q, want %q", got, "False")
	}
}

func TestStrOrDash(t *testing.T) {
	empty := ""
	val := "hello"
	tests := []struct {
		name string
		in   *string
		want string
	}{
		{"nil", nil, "-"},
		{"empty", &empty, "-"},
		{"value", &val, "hello"},
	}
	for _, tt := range tests {
		if got := strOrDash(tt.in); got != tt.want {
			t.Errorf("strOrDash(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIntOrDash(t *testing.T) {
	zero := 0
	five := 5
	if got := intOrDash(nil); got != "-" {
		t.Errorf("intOrDash(nil) = %q, want %q", got, "-")
	}
	if got := intOrDash(&zero); got != "0" {
		t.Errorf("intOrDash(0) = %q, want %q (a present zero must NOT become a dash)", got, "0")
	}
	if got := intOrDash(&five); got != "5" {
		t.Errorf("intOrDash(5) = %q, want %q", got, "5")
	}
}

func TestUint64OrDash(t *testing.T) {
	var zero uint64
	var big uint64 = 18446744073709551615 // math.MaxUint64
	if got := uint64OrDash(nil); got != "-" {
		t.Errorf("uint64OrDash(nil) = %q, want %q", got, "-")
	}
	if got := uint64OrDash(&zero); got != "0" {
		t.Errorf("uint64OrDash(0) = %q, want %q", got, "0")
	}
	if got := uint64OrDash(&big); got != "18446744073709551615" {
		t.Errorf("uint64OrDash(max) = %q, want %q", got, "18446744073709551615")
	}
}

func TestBoolOrDash(t *testing.T) {
	tru := true
	fals := false
	if got := boolOrDash(nil); got != "-" {
		t.Errorf("boolOrDash(nil) = %q, want %q", got, "-")
	}
	if got := boolOrDash(&fals); got != "False" {
		t.Errorf("boolOrDash(false) = %q, want %q (a present false must NOT become a dash)", got, "False")
	}
	if got := boolOrDash(&tru); got != "True" {
		t.Errorf("boolOrDash(true) = %q, want %q", got, "True")
	}
}

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		name string
		in   []int
		want string
	}{
		{"empty", nil, "-"},
		{"single", []int{5}, "5"},
		{"sorted_input", []int{1, 2, 3}, "1,2,3"},
		{"unsorted_input_gets_sorted", []int{3, 1, 2}, "1,2,3"},
	}
	for _, tt := range tests {
		if got := formatPorts(tt.in); got != tt.want {
			t.Errorf("formatPorts(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEnabledWord(t *testing.T) {
	if got := enabledWord(true); got != "enabled" {
		t.Errorf("enabledWord(true) = %q, want %q", got, "enabled")
	}
	if got := enabledWord(false); got != "disabled" {
		t.Errorf("enabledWord(false) = %q, want %q", got, "disabled")
	}
}

func TestLinkWord(t *testing.T) {
	if got := linkWord(true); got != "up" {
		t.Errorf("linkWord(true) = %q, want %q", got, "up")
	}
	if got := linkWord(false); got != "down" {
		t.Errorf("linkWord(false) = %q, want %q", got, "down")
	}
}
