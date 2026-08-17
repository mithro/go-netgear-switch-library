package fmtx

import "reflect"

// jsonMarshalerType is the reflect.Type of json.Marshaler, used to detect
// (and skip mirroring inside) any type that already controls its own
// JSON encoding -- e.g. model.Pvid's custom 2-element-array MarshalJSON.
// None of this package's current callers combine a custom MarshalJSON
// with a float64 field, so "leave it alone" is always correct today; it
// is also the only SAFE default in general, since reaching inside a
// type's private representation to rewrite a float it may not even
// expose the same way in its own MarshalJSON would be actively wrong.
var jsonMarshalerType = reflect.TypeFor[interface{ MarshalJSON() ([]byte, error) }]()

// mirrorFloats returns a value that json.Marshal renders IDENTICALLY to
// v, field-for-field, EXCEPT that every float64 reachable from v (direct
// field, slice/array element, or pointee -- recursively) is replaced by
// a pyFloat (carrying s, THIS call's sentinels -- see jsonSentinels' doc
// comment in pyfloat.go for why they must be per-call), so it marshals
// via pyFloatRepr (json.dumps-compatible) instead of Go's default float
// formatting. This is what makes ToJSON's float handling GENERIC rather
// than a one-off for model.Sensor.Value: any float64 field this
// codebase's model types gain in the future gets the same treatment
// automatically, with no fmtx change required.
//
// When v contains no float64 anywhere (the overwhelming majority of this
// codebase's JSON output -- every type except model.Sensor and anything
// that embeds it), mirrorFloats does no reconstruction at all and
// returns v UNCHANGED: mirrorValue reports "no change" at every level,
// so json.Marshal ends up encoding the exact original value exactly as
// it did before this function existed. This keeps the fix a true no-op
// for every already-correct type, rather than a rewrite with new
// regression surface.
//
// Maps are deliberately NOT mirrored (returned as-is): no current model
// type has a JSON-visible map field, so this is an honest scope
// limit, not a silent gap -- a future float64-valued map field would
// need this function extended, and would fail loudly in a byte-parity
// test (a "3300" instead of "3300.0" in the JSON) rather than silently,
// exactly like every other renderer in this package that documents what
// it does NOT yet handle rather than guessing.
func mirrorFloats(v any, s *jsonSentinels) any {
	if v == nil {
		return nil
	}
	mv, changed := mirrorValue(reflect.ValueOf(v), s)
	if !changed {
		return v
	}
	return mv.Interface()
}

// mirrorValue recursively mirrors rv (see mirrorFloats), returning the
// (possibly reconstructed) value and whether anything actually changed.
// A false changed return means the caller may keep using rv/v as-is.
func mirrorValue(rv reflect.Value, s *jsonSentinels) (reflect.Value, bool) {
	if !rv.IsValid() {
		return rv, false
	}
	t := rv.Type()

	// A type with its own MarshalJSON is opaque to us -- never peek
	// inside it (see jsonMarshalerType's doc comment).
	if t.Implements(jsonMarshalerType) {
		return rv, false
	}

	switch t.Kind() {
	case reflect.Float64:
		return reflect.ValueOf(pyFloat{v: rv.Float(), s: s}), true

	case reflect.Pointer:
		if rv.IsNil() {
			return rv, false
		}
		elem, changed := mirrorValue(rv.Elem(), s)
		if !changed {
			return rv, false
		}
		p := reflect.New(elem.Type())
		p.Elem().Set(elem)
		return p, true

	case reflect.Interface:
		if rv.IsNil() {
			return rv, false
		}
		elem, changed := mirrorValue(rv.Elem(), s)
		if !changed {
			return rv, false
		}
		return elem, true

	case reflect.Slice:
		if rv.IsNil() {
			return rv, false
		}
		return mirrorSequence(rv, t, s)

	case reflect.Array:
		return mirrorSequence(rv, t, s)

	case reflect.Struct:
		return mirrorStruct(rv, t, s)

	default:
		// string, int*, uint*, bool, map, chan, func, complex*, etc.:
		// none of this package's model types carry a float64 through
		// any of these (see the doc comment's Maps note), so passing
		// them through untouched is correct for everything reachable
		// today.
		return rv, false
	}
}

// mirrorSequence mirrors a slice or array's elements; see mirrorValue.
func mirrorSequence(rv reflect.Value, t reflect.Type, s *jsonSentinels) (reflect.Value, bool) {
	n := rv.Len()
	elems := make([]reflect.Value, n)
	anyChanged := false
	elemType := t.Elem()
	for i := 0; i < n; i++ {
		ev, changed := mirrorValue(rv.Index(i), s)
		if changed {
			anyChanged = true
		}
		elems[i] = ev
	}
	if !anyChanged {
		return rv, false
	}

	// All CHANGED elements mirror to the same new type (mirroring is a
	// pure function of the original static Go type); an unchanged
	// element (e.g. a nil pointer, which short-circuits before its
	// pointee type would matter) keeps the OLD element type, so find the
	// mirrored type from any changed element for the new sequence's
	// element type, then convert every remaining old-typed element (nils
	// only, by construction) to the new type's zero value.
	newElemType := elemType
	for _, ev := range elems {
		if ev.Type() != elemType {
			newElemType = ev.Type()
			break
		}
	}

	var out reflect.Value
	if t.Kind() == reflect.Array {
		out = reflect.New(reflect.ArrayOf(t.Len(), newElemType)).Elem()
	} else {
		out = reflect.MakeSlice(reflect.SliceOf(newElemType), n, n)
	}
	for i, ev := range elems {
		if ev.Type() != newElemType {
			ev = reflect.Zero(newElemType)
		}
		out.Index(i).Set(ev)
	}
	return out, true
}

// mirrorStruct mirrors t's exported fields (unexported fields are never
// JSON-visible -- encoding/json ignores them -- so they are dropped from
// the mirror type entirely rather than copied verbatim; this also
// sidesteps any reflect.StructOf restriction on unexported fields,
// without changing the JSON output either way). Field order and every
// json/other struct tag are preserved exactly, so key order and naming
// stay byte-identical to the original type's own marshaling.
func mirrorStruct(rv reflect.Value, t reflect.Type, s *jsonSentinels) (reflect.Value, bool) {
	n := t.NumField()
	fields := make([]reflect.StructField, 0, n)
	values := make([]reflect.Value, 0, n)
	anyChanged := false

	for i := 0; i < n; i++ {
		sf := t.Field(i)
		if sf.PkgPath != "" {
			continue // unexported: never JSON-visible, drop from the mirror
		}
		fv := rv.Field(i)
		nv, changed := mirrorValue(fv, s)
		if changed {
			anyChanged = true
			sf.Type = nv.Type()
			fields = append(fields, sf)
			values = append(values, nv)
		} else {
			fields = append(fields, sf)
			values = append(values, fv)
		}
	}
	if !anyChanged {
		return rv, false
	}

	mt := reflect.StructOf(fields)
	mv := reflect.New(mt).Elem()
	for i, v := range values {
		mv.Field(i).Set(v)
	}
	return mv, true
}
