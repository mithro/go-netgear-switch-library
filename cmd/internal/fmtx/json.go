package fmtx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ToJSON renders v as indented JSON, matching Python's format.to_json:
// `json.dumps(jsonify(obj), indent=2)`. Python's jsonify walks dataclasses
// (-> dict by field name), enums (-> .value) and sets/frozensets (->
// sorted list) at runtime before handing the result to json.dumps; this
// codebase's model types already do that translation STATICALLY via
// struct field `json:"snake_case"` tags (matching every dataclass field
// name), plain lowercase-valued string enum types (PoEDetect, VlanMode,
// IPMode, ...) that marshal as their bare string value with no extra
// step, and pre-sorted-never-nil canonical slices in place of Python's
// frozenset (see model/types.go's VLANInfo doc comment) -- so
// json.Marshal of a model value already produces jsonify's output, and
// ToJSON only needs to reproduce json.dumps' own formatting:
//
//   - SetEscapeHTML(false): Go's encoder escapes <, > and & by default
//     (a browser-embedding safety default irrelevant to a CLI/MCP
//     response and NOT shared by Python's json.dumps, which never
//     escapes them), so it must be turned off for byte parity.
//   - SetIndent("", "  "): two-space indentation, matching indent=2.
//   - NO trailing newline beyond what json.dumps itself produces (none --
//     json.Encoder.Encode always appends one, which this function trims;
//     format.py's own trailing newline comes from `print()`, reproduced
//     by Emit below, not by ToJSON).
func ToJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// Emit writes v to w as JSON (asJSON=true, via ToJSON) or via tableFn
// (asJSON=false), followed by exactly one trailing newline -- mirroring
// Python format.emit's `print(to_json(obj) if ctx.as_json else
// table_fn(obj), file=ctx.out)`. tableFn is one of this package's
// *Table/*Text renderers, ignored entirely when asJSON (matching Python:
// to_json(obj) is computed instead of calling table_fn at all).
func Emit[T any](w io.Writer, v T, asJSON bool, tableFn func(T) string) error {
	var s string
	if asJSON {
		js, err := ToJSON(v)
		if err != nil {
			return err
		}
		s = js
	} else {
		s = tableFn(v)
	}
	_, err := fmt.Fprintln(w, s)
	return err
}
