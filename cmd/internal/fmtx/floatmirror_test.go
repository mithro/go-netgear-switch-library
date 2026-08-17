package fmtx

import (
	"testing"
)

func TestMirrorFloatsNil(t *testing.T) {
	if got := mirrorFloats(nil, newJSONSentinels()); got != nil {
		t.Errorf("mirrorFloats(nil) = %v, want nil", got)
	}
}

// interfaceHolder exercises mirrorValue's reflect.Interface case: a
// struct field typed `any` holding a float64 dynamically, which no
// current model type has, but a future one plausibly could (e.g. a
// generic "extra" bag of vendor-specific values).
type interfaceHolder struct {
	V any `json:"v"`
}

func TestMirrorValueInterfaceHoldingFloat(t *testing.T) {
	got, err := ToJSON(interfaceHolder{V: 3300.0})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "v": 3300.0
}`
	if got != want {
		t.Errorf("ToJSON(interfaceHolder) =\n%s\nwant\n%s", got, want)
	}
}

func TestMirrorValueNilInterface(t *testing.T) {
	got, err := ToJSON(interfaceHolder{V: nil})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "v": null
}`
	if got != want {
		t.Errorf("ToJSON(interfaceHolder{nil}) =\n%s\nwant\n%s", got, want)
	}
}

func TestMirrorValueInterfaceHoldingNonFloat(t *testing.T) {
	// No float anywhere -- must be a true no-op, matching Go's default
	// encoding for an int held in an `any` field.
	got, err := ToJSON(interfaceHolder{V: 42})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "v": 42
}`
	if got != want {
		t.Errorf("ToJSON(interfaceHolder{42}) =\n%s\nwant\n%s", got, want)
	}
}

// TestMirrorValueArray exercises mirrorValue's reflect.Array case (a
// fixed-size array, distinct from a slice) -- no current model type uses
// one, but the algorithm handles it identically to a slice.
func TestMirrorValueArray(t *testing.T) {
	type arrayHolder struct {
		V [2]float64 `json:"v"`
	}
	got, err := ToJSON(arrayHolder{V: [2]float64{3300.0, 0.5}})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "v": [
    3300.0,
    0.5
  ]
}`
	if got != want {
		t.Errorf("ToJSON(arrayHolder) =\n%s\nwant\n%s", got, want)
	}
}

// TestMirrorSequenceMixedNilAndNonNilPointers exercises mirrorSequence's
// "some elements changed, some didn't (nil pointers short-circuit)"
// branch: a []*float64 with a nil entry alongside a non-nil one must
// still produce a HOMOGENEOUSLY typed mirrored slice ([]*pyFloat), with
// the nil entry becoming a nil *pyFloat rather than being left as the
// old, now-mismatched *float64 type.
func TestMirrorSequenceMixedNilAndNonNilPointers(t *testing.T) {
	type ptrSliceHolder struct {
		V []*float64 `json:"v"`
	}
	val := 3300.0
	got, err := ToJSON(ptrSliceHolder{V: []*float64{&val, nil}})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "v": [
    3300.0,
    null
  ]
}`
	if got != want {
		t.Errorf("ToJSON(ptrSliceHolder) =\n%s\nwant\n%s", got, want)
	}
}

// TestMirrorValueNilSliceStaysNull confirms a nil []float64 field still
// marshals as JSON null (Go's ordinary nil-slice behaviour), not "[]" --
// mirrorValue's short-circuit for a nil slice must not accidentally
// force it non-nil.
func TestMirrorValueNilSliceStaysNull(t *testing.T) {
	type sliceHolder struct {
		V []float64 `json:"v"`
	}
	got, err := ToJSON(sliceHolder{V: nil})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	want := `{
  "v": null
}`
	if got != want {
		t.Errorf("ToJSON(sliceHolder{nil}) =\n%s\nwant\n%s", got, want)
	}
}

// TestMirrorValueMapLeftUnchanged documents mirrorFloats' deliberate
// scope limit (see floatmirror.go's doc comment): a map field is passed
// through untouched, so a float64 MAP VALUE would NOT get pyFloatRepr
// treatment. No current model type has a JSON-visible map field, so this
// is a known, honest limitation rather than a silent gap -- this test
// pins the CURRENT (pass-through) behaviour so a future map-mirroring
// implementation change is a deliberate decision, not an accident.
func TestMirrorValueMapLeftUnchanged(t *testing.T) {
	type mapHolder struct {
		V map[string]float64 `json:"v"`
	}
	got, err := ToJSON(mapHolder{V: map[string]float64{"a": 3300.0}})
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	// Go's default float encoding (NOT pyFloatRepr) applies here --
	// "3300", not "3300.0" -- documenting the known gap.
	want := `{
  "v": {
    "a": 3300
  }
}`
	if got != want {
		t.Errorf("ToJSON(mapHolder) =\n%s\nwant\n%s", got, want)
	}
}
