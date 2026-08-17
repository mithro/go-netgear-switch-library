package fmtx

import (
	"bytes"
	"errors"
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
