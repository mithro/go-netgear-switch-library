package fastpath

import (
	"reflect"
	"testing"
)

// lldpFixture is a trimmed excerpt of the REAL captured
// tests/fixtures/cli/gsm7228ps_lldp.txt (pinned
// python-netgear-switch-library @ 7ebfe5d) -- header, ruler, and a
// representative slice of its 52 data rows, with column alignment
// preserved exactly. It is the grounding for the module's central hazard:
// every "1/gN" row (no LLDP neighbour yet) is FAR shorter than the ruler's
// later column spans -- Python's row[start:end] silently clamps/truncates
// on these rows; a naive Go row[start:end] would panic.
const lldpFixture = `LLDP Remote Device Summary

Local
Interface  RemID   Chassis ID            Port ID             System Name
--------- -------  --------------------  ------------------  ------------------
1/g1
1/g2
1/g3
1/xg49     2       E0:91:F5:0C:D6:DB     1/0/48              sw-netgear-gsm ...
1/xg50
1/xg51     1       E0:91:F5:0C:D5:C7     1/0/50              sw-netgear-gsm ...
1/xg52
`

// poeFixture is a trimmed excerpt (header + ruler + 2 of 16 data rows,
// column alignment preserved exactly) of the REAL captured
// tests/fixtures/cli/m4300_16x_show_poe_port_info_all.txt. Its 3-line
// wrapped header ("High Power" / "Max Power (mW)" / "Output Current (mA)"
// stacked over 3 physical lines) grounds headerColumns' multi-line
// reconstruction.
const poeFixture = `        High     Max                      Output  Output
Intf    Power   Power     Class   Power   Current Voltage      Status            Fault
                 (mW)              (mW)     (mA)   (V)                           Status
------ ------- -------- -------- -------  ------- -------  ----------------- -----------------
1/0/1    Yes   30000    Unknown  0         0       0       Searching          No Error
1/0/12   Yes   30000    4        4600      86      54      Delivering Power   No Error
`

// environmentFixture is a trimmed excerpt (column alignment preserved
// exactly, including its genuine leading blank line) of the REAL captured
// tests/fixtures/cli/gsm7252ps_show_environment.txt, through the start of
// its third ("Power supplies:") sub-table. It grounds the after=
// disambiguation shared by iterTableRows/headerColumns ("show environment"
// prints three tables back to back; after picks out the second one,
// "Fans:").
const environmentFixture = `
Temp (C)....................................... 36
Fan Speed, RPM................................. 3150
Fan Duty Level................................. Not Supported
Temperature traps range: 0 to 90 degrees (Celsius)

Temperature Sensors:
Unit     Sensor  Description       Temp (C)    State           Max_Temp (C)
----     ------  ----------------  ----------  --------------  --------------
1        1       CPU               49          Normal          55
1        2       System            30          Normal          35

Fans:
Unit Fan Description    Type      Speed         Duty level    State
---- --- -------------- --------- ------------- ------------- --------------
1    1   Fan-1          Fixed     3150          Not Supported Operational
1    2   Fan-2          Fixed     Not Supported Not Supported Operational
1    3   Fan-3          Fixed     2750          Not Supported Operational

Power supplies:
Unit     Power supply   Description        Type          State
----     ------------   ----------------   ----------    --------------
1        1              AC                 Fixed         Operational
`

func TestParseSplitLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"no trailing newline", "a\nb", []string{"a", "b"}},
		{"one trailing newline", "a\nb\n", []string{"a", "b"}},
		{"blank line then trailing newline", "a\nb\n\n", []string{"a", "b", ""}},
		{"lone newline", "\n", []string{""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitLines(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitLines(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestParseLabelledValues(t *testing.T) {
	// Grounded against the pinned Python labelled_values on this exact
	// text (verified interactively against parse.py): later duplicates
	// overwrite earlier ones, and a blank value maps to "" (not omitted).
	text := "System Description............. GSM7252PS\n" +
		"Machine Model.................... GSM7252PS\n" +
		"Bootcode Version...........\n" +
		"System Description............. GSM7252PS-DUP\n"
	got := labelledValues(text)
	want := map[string]string{
		"System Description": "GSM7252PS-DUP",
		"Machine Model":      "GSM7252PS",
		"Bootcode Version":   "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("labelledValues() = %#v, want %#v", got, want)
	}
}

func TestParseLabelledValuesNoMatch(t *testing.T) {
	// A line with no ".." dotted leader at all contributes nothing.
	got := labelledValues("just some text\nwith no leader\n")
	if len(got) != 0 {
		t.Errorf("labelledValues() = %#v, want empty", got)
	}
}

func TestParseRulerSpans(t *testing.T) {
	// Both rulers below are the REAL ruler lines from lldpFixture/
	// poeFixture; expected spans hand-verified against the pinned Python
	// _ruler_spans on the same input.
	cases := []struct {
		name  string
		ruler string
		want  []rulerSpan
	}{
		{
			name:  "lldp",
			ruler: "--------- -------  --------------------  ------------------  ------------------",
			want: []rulerSpan{
				{start: 0, end: 10},
				{start: 10, end: 19},
				{start: 19, end: 41},
				{start: 41, end: 61},
				{start: 61, end: -1},
			},
		},
		{
			name:  "poe",
			ruler: "------ ------- -------- -------- -------  ------- -------  ----------------- -----------------",
			want: []rulerSpan{
				{start: 0, end: 7},
				{start: 7, end: 15},
				{start: 15, end: 24},
				{start: 24, end: 33},
				{start: 33, end: 42},
				{start: 42, end: 50},
				{start: 50, end: 59},
				{start: 59, end: 77},
				{start: 77, end: -1},
			},
		},
		{
			name:  "single column",
			ruler: "----",
			want:  []rulerSpan{{start: 0, end: -1}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rulerSpans(c.ruler)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("rulerSpans(%q) = %#v, want %#v", c.ruler, got, c.want)
			}
		})
	}
}

// TestParseSliceCellClampsShortRow is THE hazard test the task brief calls
// for: a ruler span far wider than the data row it's applied to. Python's
// row[start:end] silently clamps/truncates in this situation; a naive Go
// row[start:end] slice panics on out-of-range indices. This must return the
// clamped (here: empty) substring, not panic.
func TestParseSliceCellClampsShortRow(t *testing.T) {
	row := "1/g2" // len 4 -- the real short LLDP row from lldpFixture
	cases := []struct {
		name string
		span rulerSpan
		want string
	}{
		// start (10) and end (19) both far past len(row)=4.
		{"span entirely past end of row", rulerSpan{start: 10, end: 19}, ""},
		// start (61) past end, open-ended span (end=-1, "to end of row").
		{"open span past end of row", rulerSpan{start: 61, end: -1}, ""},
		// start (0) within row, end (19) past it -> truncate, don't panic.
		{"end past row, start in range", rulerSpan{start: 0, end: 19}, "1/g2"},
		// start exactly at len(row) -> empty, not an error.
		{"start exactly at len(row)", rulerSpan{start: 4, end: 19}, ""},
		// the ordinary in-range case, for contrast.
		{"fully in range", rulerSpan{start: 0, end: 3}, "1/g"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("sliceCell panicked: %v", r)
				}
			}()
			got := sliceCell(row, c.span)
			if got != c.want {
				t.Errorf("sliceCell(%q, %+v) = %q, want %q", row, c.span, got, c.want)
			}
		})
	}
}

func TestParseSliceRow(t *testing.T) {
	spans := rulerSpans("------ -------")
	got := sliceRow(spans, "1/0/1  Enable")
	want := []string{"1/0/1", "Enable"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sliceRow() = %#v, want %#v", got, want)
	}
}

// TestParseIterTableRowsClampsShortRows exercises the hazard end-to-end
// through the public entry point every entity parser will call: a full
// table whose early data rows ("1/g1".."1/g3", no LLDP neighbour yet) are
// far shorter than the ruler, and whose later rows ("1/xg49", "1/xg51")
// are fully populated. Expected values hand-verified against the pinned
// Python iter_table_rows on the identical fixture text.
func TestParseIterTableRowsClampsShortRows(t *testing.T) {
	var rows [][]string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("iterTableRows panicked: %v", r)
			}
		}()
		rows = iterTableRows(lldpFixture, "")
	}()

	want := [][]string{
		{"1/g1", "", "", "", ""},
		{"1/g2", "", "", "", ""},
		{"1/g3", "", "", "", ""},
		{"1/xg49", "2", "E0:91:F5:0C:D6:DB", "1/0/48", "sw-netgear-gsm ..."},
		{"1/xg50", "", "", "", ""},
		{"1/xg51", "1", "E0:91:F5:0C:D5:C7", "1/0/50", "sw-netgear-gsm ..."},
		{"1/xg52", "", "", "", ""},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("iterTableRows(lldpFixture) = %#v, want %#v", rows, want)
	}
}

func TestParseIterTableRowsAfter(t *testing.T) {
	// "show environment" prints three tables back to back; after="Fans:"
	// must skip past the first (Temperature Sensors) table entirely.
	got := iterTableRows(environmentFixture, "Fans:")
	want := [][]string{
		{"1", "1", "Fan-1", "Fixed", "3150", "Not Supported", "Operational"},
		{"1", "2", "Fan-2", "Fixed", "Not Supported", "Not Supported", "Operational"},
		{"1", "3", "Fan-3", "Fixed", "2750", "Not Supported", "Operational"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("iterTableRows(after=%q) = %#v, want %#v", "Fans:", got, want)
	}
}

func TestParseIterTableRowsNoRuler(t *testing.T) {
	got := iterTableRows("no ruler here\njust plain text\n", "")
	if got != nil {
		t.Errorf("iterTableRows() = %#v, want nil", got)
	}
}

func TestParseIterTableRowsEmptyTable(t *testing.T) {
	// Header + ruler + zero data rows, immediately EOF: yields zero rows
	// cleanly, not an error.
	got := iterTableRows("Intf\n----\n", "")
	if got != nil {
		t.Errorf("iterTableRows() = %#v, want nil (zero rows)", got)
	}
}

// TestParseHeaderColumnsWrapped grounds the multi-line wrapped-header case
// the brief calls for: "High Power" / "Max Power (mW)" / "Output Current
// (mA)" are stacked across 3 physical lines above the ruler in the real
// poeFixture. Expected value hand-verified against the pinned Python
// header_columns on the identical fixture text.
func TestParseHeaderColumnsWrapped(t *testing.T) {
	got := headerColumns(poeFixture, "")
	want := []string{
		"Intf",
		"High Power",
		"Max Power (mW)",
		"Class",
		"Power (mW)",
		"Output Current (mA)",
		"Output Voltage (V)",
		"Status",
		"Fault Status",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("headerColumns(poeFixture) = %#v, want %#v", got, want)
	}
}

func TestParseHeaderColumnsAfter(t *testing.T) {
	// Grounded against the pinned Python header_columns(environmentFixture,
	// after="Fans:"): the "Fans:" section-label line itself is non-blank
	// and directly above the ruler, so it is walked into the header block
	// and bleeds into column 0's name -- this is Python's actual behavior,
	// not a Go-port simplification.
	got := headerColumns(environmentFixture, "Fans:")
	want := []string{"Fans: Unit", "Fan", "Description", "Type", "Speed", "Duty level", "State"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("headerColumns(after=%q) = %#v, want %#v", "Fans:", got, want)
	}
}

func TestParseHeaderColumnsNoRuler(t *testing.T) {
	got := headerColumns("no ruler here\njust plain text\n", "")
	if got != nil {
		t.Errorf("headerColumns() = %#v, want nil", got)
	}
}

func TestParseInt(t *testing.T) {
	cases := []struct {
		text     string
		wantVal  int
		wantOK   bool
		testName string
	}{
		{"42", 42, true, "plain"},
		{"  7 ", 7, true, "surrounding whitespace"},
		{"-5", -5, true, "negative"},
		{"", 0, false, "empty"},
		{"   ", 0, false, "whitespace only"},
		{"abc", 0, false, "non-numeric"},
		{"Not Supported", 0, false, "text field"},
		{"4.5", 0, false, "float text is not an int"},
	}
	for _, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			v, ok := parseInt(c.text)
			if v != c.wantVal || ok != c.wantOK {
				t.Errorf("parseInt(%q) = (%d, %v), want (%d, %v)", c.text, v, ok, c.wantVal, c.wantOK)
			}
		})
	}
}

// TestParsePhysPort covers a per-model iface form for every CLI model this
// slice supports (dossier §1.6): "1/0/N" (gsm7252ps, m4300-24x, m4300-16x
// -- the Fully Managed line) and "1/gN"/"1/xgN" (gsm7228ps -- the
// Smart-firmware S3300-52X access/uplink dialects), plus the
// deliberately-not-a-port forms every model's table rows can also contain.
func TestParsePhysPort(t *testing.T) {
	cases := []struct {
		iface    string
		wantPort int
		wantOK   bool
	}{
		{"1/0/7", 7, true},     // Fully Managed (gsm7252ps, m4300-24x, m4300-16x)
		{"1/0/1", 1, true},     // Fully Managed, port 1
		{"1/g7", 7, true},      // gsm7228ps access port
		{"1/g48", 48, true},    // gsm7228ps access port, top of range
		{"1/xg49", 49, true},   // gsm7228ps uplink port, bottom of range
		{"1/xg52", 52, true},   // gsm7228ps uplink port, top of range
		{"  1/0/9  ", 9, true}, // surrounding whitespace trimmed
		{"lag 1", 0, false},
		{"vlan 5", 0, false},
		{"CPU Interface:  0/5/1", 0, false},
		{"", 0, false},
		{"1/1/7", 0, false}, // slot must be literal 0, not just any digit
	}
	for _, c := range cases {
		t.Run(c.iface, func(t *testing.T) {
			port, ok := physPort(c.iface)
			if port != c.wantPort || ok != c.wantOK {
				t.Errorf("physPort(%q) = (%d, %v), want (%d, %v)", c.iface, port, ok, c.wantPort, c.wantOK)
			}
		})
	}
}
