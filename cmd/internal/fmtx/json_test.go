package fmtx

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// TestToJSONNoHTMLEscaping confirms Go's default <, >, & escaping is
// turned off: Python's json.dumps NEVER escapes these (it has no
// browser-embedding safety mode), so a description/name field containing
// them must round-trip byte-for-byte, not become < etc.
func TestToJSONNoHTMLEscaping(t *testing.T) {
	p := model.PortStatus{Port: 1, Description: model.Ptr("<a> & <b>")}
	got, err := ToJSON(p)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	// The raw, unescaped characters MUST appear verbatim -- Go's default
	// HTML-safe escaping (now disabled via SetEscapeHTML(false)) would
	// instead emit the six-character \uXXXX sequences checked for below.
	if !strings.Contains(got, "<a> & <b>") {
		t.Errorf("ToJSON() = %s, want it to contain the literal, unescaped %q", got, "<a> & <b>")
	}
	for _, unicodeEscape := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if strings.Contains(got, unicodeEscape) {
			t.Errorf("ToJSON() = %s, want no %s HTML-escaping (Python's json.dumps never escapes these)", got, unicodeEscape)
		}
	}
}

// TestToJSONIndentTwoSpaces confirms 2-space indentation, matching
// Python's json.dumps(..., indent=2).
func TestToJSONIndentTwoSpaces(t *testing.T) {
	p := model.PortStatus{Port: 1, AdminEnabled: true}
	got, err := ToJSON(p)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "port": 1,
  "name": null,
  "admin_enabled": true,
  "link_up": false,
  "speed_mbps": null,
  "description": null,
  "full_duplex": null,
  "flow_control": null,
  "speed_config": null
}`
	if got != want {
		t.Errorf("ToJSON() =\n%s\nwant\n%s", got, want)
	}
}

// TestToJSONNoTrailingNewline confirms ToJSON's return value has NO
// trailing newline -- matching Python's to_json (json.dumps itself never
// appends one); Emit is the layer that adds exactly one, mirroring
// print().
func TestToJSONNoTrailingNewline(t *testing.T) {
	got, err := ToJSON(model.PortStatus{Port: 1})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("ToJSON() = %q, want no trailing newline", got)
	}
}

// TestToJSONArrayNeverNull confirms an empty (but non-nil) slice field
// marshals as "[]", matching Python's default-empty-tuple dataclass
// fields (jsonify never emits null for a collection field) -- exercised
// via VLANInfo's canonical never-nil port-slice convention (model/types.go).
func TestToJSONArrayNeverNull(t *testing.T) {
	v := model.VLANInfo{VlanID: 1, MemberPorts: []int{}, TaggedPorts: []int{}, UntaggedPorts: []int{}}
	got, err := ToJSON(v)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	if !strings.Contains(got, `"tagged_ports": []`) {
		t.Errorf("ToJSON() = %s, want an empty array, not null, for a never-nil canonical port slice", got)
	}
}

// TestToJSONSwitchDataCanonical confirms SwitchData.Canonical() (this
// codebase's own null->[] normalisation for the aggregate snapshot type)
// composes correctly with ToJSON, matching Python's default-()-fields
// SwitchData dataclass.
func TestToJSONSwitchDataCanonical(t *testing.T) {
	sd := model.SwitchData{Model: "gsm7252ps", Host: "10.0.0.5"}.Canonical()
	got, err := ToJSON(sd)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	for _, field := range []string{`"ports": []`, `"poe": []`, `"vlans": []`, `"pvids": []`, `"lldp": []`, `"macs": []`, `"sensors": []`, `"stats": []`} {
		if !strings.Contains(got, field) {
			t.Errorf("ToJSON(Canonical SwitchData) = %s, want it to contain %q", got, field)
		}
	}
	if !strings.Contains(got, `"mgmt_ip": null`) {
		t.Errorf("ToJSON(Canonical SwitchData) = %s, want mgmt_ip: null (never set here)", got)
	}
}

// TestToJSONPvidTupleShape confirms Pvid's custom MarshalJSON produces
// Python's tuple[int,int] shape: a bare 2-element array, not an object.
func TestToJSONPvidTupleShape(t *testing.T) {
	got, err := ToJSON([]model.Pvid{{Port: 1, Vlan: 100}})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `[
  [
    1,
    100
  ]
]`
	if got != want {
		t.Errorf("ToJSON([]Pvid) =\n%s\nwant\n%s", got, want)
	}
}

// --- float64 (model.Sensor.Value) byte-parity with json.dumps -------
//
// The expected strings below were captured VERBATIM from a live run of
// the pinned Python source's cli/format.to_json against the SAME
// model.Sensor values constructed here (see the bug this regression-
// tests: ToJSON previously let Go's default float encoder handle
// float64, which renders a whole-number float with no ".0" and diverges
// from Python's repr()-based encoding at the 1e15/1e16 and 1e-4/1e-5
// scientific-notation boundaries -- see pyfloat_test.go for the
// unit-level pyFloatRepr checks against the same live Python source).

func TestToJSONSensorWholeNumberValueKeepsDotZero(t *testing.T) {
	s := model.Sensor{Name: "Fan1", Kind: "fan", Value: 3300.0, Unit: "rpm"}
	got, err := ToJSON(s)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "name": "Fan1",
  "kind": "fan",
  "value": 3300.0,
  "unit": "rpm"
}`
	if got != want {
		t.Errorf("ToJSON(Sensor) =\n%s\nwant\n%s", got, want)
	}
}

func TestToJSONSensorSliceMatchesPython(t *testing.T) {
	sensors := []model.Sensor{
		{Name: "Fan1", Kind: "fan", Value: 3300.0, Unit: "rpm"},
		{Name: "Temp1", Kind: "temperature", Value: 45.678912, Unit: "C"},
		{Name: "PSU1", Kind: "power", Value: 0.0, Unit: "W"},
	}
	got, err := ToJSON(sensors)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `[
  {
    "name": "Fan1",
    "kind": "fan",
    "value": 3300.0,
    "unit": "rpm"
  },
  {
    "name": "Temp1",
    "kind": "temperature",
    "value": 45.678912,
    "unit": "C"
  },
  {
    "name": "PSU1",
    "kind": "power",
    "value": 0.0,
    "unit": "W"
  }
]`
	if got != want {
		t.Errorf("ToJSON([]Sensor) =\n%s\nwant\n%s", got, want)
	}
}

func TestToJSONSensorScientificNotationBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  string
	}{
		{"one_e15_stays_fixed", 1e15, "1000000000000000.0"},
		{"one_e16_switches_to_scientific", 1e16, "1e+16"},
		{"one_e_minus5_switches_to_scientific", 1e-5, "1e-05"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToJSON(model.Sensor{Name: "s", Kind: "k", Value: tt.value, Unit: "u"})
			if err != nil {
				t.Fatalf("ToJSON() error = %v, want nil", err)
			}
			wantLine := `  "value": ` + tt.want + `,`
			if !strings.Contains(got, wantLine) {
				t.Errorf("ToJSON(Sensor{Value: %v}) = %s, want it to contain %q", tt.value, got, wantLine)
			}
		})
	}
}

func TestToJSONSensorNonFiniteValue(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  string
	}{
		{"nan", math.NaN(), `  "value": NaN,`},
		{"positive_infinity", math.Inf(1), `  "value": Infinity,`},
		{"negative_infinity", math.Inf(-1), `  "value": -Infinity,`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToJSON(model.Sensor{Name: "s", Kind: "k", Value: tt.value, Unit: "u"})
			if err != nil {
				t.Fatalf("ToJSON() error = %v, want nil", err)
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("ToJSON(Sensor{Value: %v}) = %s, want it to contain %q", tt.value, got, tt.want)
			}
			// No leftover internal sentinel bytes -- the substitution
			// must have replaced ALL of them, and the sentinel's raw
			// (non-JSON-string-encoded) form must never leak either.
			if strings.Contains(got, "ngsw:pyfloat:") {
				t.Errorf("ToJSON(Sensor{Value: %v}) = %s, leaked an internal sentinel", tt.value, got)
			}
		})
	}
}

// TestToJSONOldFixedSentinelNoLongerSpecial is the Round-2 adversarial-
// review regression test: this package's ORIGINAL (pre-fix) design used
// a FIXED, package-level sentinel string for the NaN placeholder, and
// ToJSON did a blind whole-document strings.ReplaceAll of it -- so a real
// field whose value happened to equal that exact text byte-for-byte was
// silently corrupted from a quoted JSON string into a bare `NaN` token.
// This is reachable in practice: encoding/json preserves raw bytes
// end-to-end, and snmp/parse.go's SNMP-string decoding can pass a NUL
// byte straight through from a device's raw reply into
// model.Sensor.Name/PortStatus.Name/VLANInfo.Name and others, so an
// agent whose EntPhysicalName happened to equal the old fixed sentinel
// would have corrupted `--json` output.
//
// The fix (pyfloat.go's jsonSentinels) makes the sentinel fresh and
// cryptographically random on EVERY ToJSON call, so there is no longer
// any FIXED text for a field to collide with. This test proves it
// directly: construct a Sensor whose Name is byte-identical to the OLD
// fixed sentinel text (kept here, inert, purely to build this
// regression case -- it is no longer referenced by any production code)
// and confirm the name survives as an ordinary, correctly quoted JSON
// string, NOT as a corrupted bare `NaN` token.
func TestToJSONOldFixedSentinelNoLongerSpecial(t *testing.T) {
	// The exact fixed sentinel text this package used to hardcode for
	// NaN before the per-call-random fix. Deliberately NOT referencing
	// any production symbol (there is none any more) -- this is the
	// literal bytes a real device's SNMP reply could have produced.
	const oldFixedNaNSentinel = "\x00ngsw:pyfloat:nan\x00"

	s := model.Sensor{Name: oldFixedNaNSentinel, Kind: "fan", Value: 1.0, Unit: "rpm"}
	got, err := ToJSON(s)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}

	if strings.Contains(got, `"name": NaN`) {
		t.Fatalf("ToJSON() corrupted a field value equal to the OLD fixed sentinel into a bare NaN token -- the exact Round-2 regression: %s", got)
	}

	wantNameJSON, err := json.Marshal(oldFixedNaNSentinel)
	if err != nil {
		t.Fatalf("json.Marshal(sentinel) error = %v", err)
	}
	wantLine := `  "name": ` + string(wantNameJSON) + `,`
	if !strings.Contains(got, wantLine) {
		t.Errorf("ToJSON(Sensor{Name: <old fixed sentinel>}) = %s, want the name preserved as a properly quoted JSON string: %s", got, wantLine)
	}
	// value: 1.0 (a real, unrelated float) must still render correctly
	// too -- the fix must not have broken the ACTUAL NaN/Inf path for a
	// genuinely non-finite value elsewhere in the same document (see
	// TestToJSONSensorNonFiniteValue for that direct coverage); this
	// just confirms this specific document's other field is untouched.
	if !strings.Contains(got, `"value": 1.0`) {
		t.Errorf("ToJSON(Sensor{Value: 1.0}) = %s, want \"value\": 1.0", got)
	}
}

// TestJSONSentinelsAreRandomPerCall directly proves newJSONSentinels'
// core property: two separate calls (i.e. two separate ToJSON
// invocations) never produce the same sentinel text, which is what makes
// the whole-document substitution in ToJSON safe against ANY fixed field
// value (there is no longer a fixed value to check against).
func TestJSONSentinelsAreRandomPerCall(t *testing.T) {
	a := newJSONSentinels()
	b := newJSONSentinels()
	if a.nan == b.nan {
		t.Error("newJSONSentinels() produced the same NaN sentinel twice in a row, want cryptographically distinct per-call tokens")
	}
	if a.posInf == b.posInf {
		t.Error("newJSONSentinels() produced the same +Inf sentinel twice in a row, want cryptographically distinct per-call tokens")
	}
	if a.negInf == b.negInf {
		t.Error("newJSONSentinels() produced the same -Inf sentinel twice in a row, want cryptographically distinct per-call tokens")
	}
	// The three sentinels within ONE call must also be pairwise distinct
	// -- otherwise a NaN value could be mistaken for +Inf after
	// substitution.
	if a.nan == a.posInf || a.nan == a.negInf || a.posInf == a.negInf {
		t.Errorf("newJSONSentinels() produced overlapping sentinels within one call: nan=%q posInf=%q negInf=%q", a.nan, a.posInf, a.negInf)
	}
}

// TestToJSONSwitchDataWithSensorsNestedFloat exercises the FULL
// GetSensors/Snapshot shape the bug report named: a float64 nested two
// levels deep (SwitchData -> []Sensor -> Value), confirming mirrorFloats'
// recursive struct/slice handling reaches it.
func TestToJSONSwitchDataWithSensorsNestedFloat(t *testing.T) {
	sd := model.SwitchData{
		Model: "gsm7252ps",
		Host:  "10.0.0.5",
		Sensors: []model.Sensor{
			{Name: "Fan1", Kind: "fan", Value: 3300.0, Unit: "rpm"},
		},
	}.Canonical()
	got, err := ToJSON(sd)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	if !strings.Contains(got, `"value": 3300.0`) {
		t.Errorf("ToJSON(SwitchData with Sensors) = %s, want a nested \"value\": 3300.0 (not 3300)", got)
	}
}

// TestToJSONPointerToSensor exercises mirrorFloats' pointer-mirroring
// path (a *model.Sensor, not a bare value) -- e.g. how a *SwitchData with
// a MgmtIP-like optional nested struct would be reached if it ever grew
// a float64 field.
func TestToJSONPointerToSensor(t *testing.T) {
	s := &model.Sensor{Name: "Fan1", Kind: "fan", Value: 3300.0, Unit: "rpm"}
	got, err := ToJSON(s)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	if !strings.Contains(got, `"value": 3300.0`) {
		t.Errorf("ToJSON(*Sensor) = %s, want \"value\": 3300.0", got)
	}
}

// TestMirrorFloatsNoOpWithoutAnyFloatField confirms the fix is a true
// no-op (returns the exact original value, doing zero reconstruction)
// for every type with no float64 anywhere -- the overwhelming majority
// of this codebase's JSON output -- so the float64 fix carries no
// regression risk for anything else already byte-parity-tested above.
// Passing a nil *jsonSentinels also proves the no-op path never even
// dereferences it (it would panic on a real float64 field, but
// PortStatus has none).
func TestMirrorFloatsNoOpWithoutAnyFloatField(t *testing.T) {
	v := model.PortStatus{Port: 1, AdminEnabled: true}
	got := mirrorFloats(v, nil)
	gotPS, ok := got.(model.PortStatus)
	if !ok {
		t.Fatalf("mirrorFloats(PortStatus) returned %T, want model.PortStatus unchanged", got)
	}
	if gotPS != v {
		t.Errorf("mirrorFloats(PortStatus) = %+v, want the identical, unmodified value %+v", gotPS, v)
	}
}

// --- Emit ----------------------------------------------------------

func TestEmitJSONSingleValue(t *testing.T) {
	var buf bytes.Buffer
	if err := Emit(&buf, []model.PortStatus{{Port: 1, AdminEnabled: true}}, true, PortsTable); err != nil {
		t.Fatalf("Emit() error = %v, want nil", err)
	}
	js, err := ToJSON([]model.PortStatus{{Port: 1, AdminEnabled: true}})
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}
	want := js + "\n"
	if buf.String() != want {
		t.Errorf("Emit(json) =\n%q\nwant\n%q", buf.String(), want)
	}
}

func TestEmitTable(t *testing.T) {
	var buf bytes.Buffer
	ports := []model.PortStatus{{Port: 1, AdminEnabled: true, LinkUp: true}}
	if err := Emit(&buf, ports, false, PortsTable); err != nil {
		t.Fatalf("Emit() error = %v, want nil", err)
	}
	want := PortsTable(ports) + "\n"
	if buf.String() != want {
		t.Errorf("Emit(table) =\n%q\nwant\n%q", buf.String(), want)
	}
}

func TestEmitJSONErrorPropagates(t *testing.T) {
	var buf bytes.Buffer
	// A Go channel value cannot be marshalled to JSON -- forces ToJSON to
	// return an error, which Emit must propagate rather than swallow.
	err := Emit[any](&buf, make(chan int), true, func(any) string { return "" })
	if err == nil {
		t.Fatal("Emit() error = nil, want a JSON marshal error")
	}
}

func TestEmitWriteErrorPropagates(t *testing.T) {
	err := Emit[any](failingWriter{}, "value", false, func(v any) string { return v.(string) })
	if err == nil {
		t.Fatal("Emit() error = nil, want the underlying writer's error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }
