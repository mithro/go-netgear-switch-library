// result.go: the structured-result shapes every tool's outcome collapses
// into, mirroring server.py's `_jsonable`/`_read`/`_write` helpers exactly.
//
// Unlike the CLI (cmd/gngsw), which renders a result as either a table or
// (--json) fmtx.ToJSON text, every MCP tool result goes through ToJSON
// unconditionally -- an MCP client only ever sees JSON -- reusing the SAME
// float-correct, Python-json.dumps-compatible marshaling the CLI's --json
// output uses (fmtx.ToJSON), rather than encoding/json's default float
// formatting (which would print whole-valued floats like power readings as
// "3300" instead of "3300.0", and cannot represent NaN/Infinity at all).
//
// Every one of this package's tool handlers returns a NON-NIL
// *mcp.CallToolResult built by jsonResult, with Out left as the zero `any`
// (nil): the go-sdk's own ToolHandlerFor only auto-populates
// CallToolResult.Content/StructuredContent from the returned Out value when
// that value is non-nil (see AddTool's own doc comment, "if the handler
// returns a nil result, the effective result will be populated...") -- since
// this package always supplies Content itself (via fmtx.ToJSON) and always
// returns a nil Out, that auto-population path never fires, so the
// structured JSON text below is the ONLY encoding of a tool's result that
// ever reaches the wire, with no second, encoding/json-based marshaling of
// the same value racing it.
package main

import (
	"errors"

	"github.com/mithro/go-netgear-switch-library/cmd/internal/fmtx"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// jsonResult renders v via fmtx.ToJSON and wraps it as the sole content
// block of a *mcp.CallToolResult -- the terminal step every tool handler in
// this package ends on, mirroring format.emit/to_json's role in the CLI but
// for MCP's Content-block wire shape instead of a printed line. Returns the
// exact 3-tuple every ToolHandlerFor must produce, so every call site in
// this package can simply `return jsonResult(...)` directly; the middle
// (Out) value is always nil -- see this file's own doc comment for why.
func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	text, err := fmtx.ToJSON(v)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

// readResult converts a read op's outcome into the value a read tool
// reports as its structured result, mirroring server.py's `_read` exactly:
// success -> v itself (later walked into plain JSON by fmtx.ToJSON, the Go
// analogue of `_jsonable`); an error wrapping model.ErrUnsupportedCapability
// -> {"unsupported": true, "op": opName, "detail": err}, an honest "this
// model's backends don't expose that" rather than a fabricated empty
// result; any other error -> {"error": err, "op": opName}. Every error a
// facade read method can return is already a library-domain error (Go has
// no exception hierarchy to distinguish a "NetgearSwitchError" from an
// arbitrary uncaught exception the way server.py's `except
// NetgearSwitchError` does), so the catch-all branch below is this port's
// exact analogue of that final except clause.
func readResult(opName string, v any, err error) any {
	if err == nil {
		return v
	}
	if errors.Is(err, model.ErrUnsupportedCapability) {
		return map[string]any{"unsupported": true, "op": opName, "detail": err.Error()}
	}
	return map[string]any{"error": err.Error(), "op": opName}
}

// writeResult converts a write op's outcome into the value a write tool
// reports as its structured result, mirroring server.py's `_write` exactly:
// success -> {"ok": true, "op": opName}; an error wrapping
// model.ErrUnsupportedCapability -> {"unsupported": true, "op": opName,
// "detail": err} (a capability the model's backends genuinely do not
// expose); an error wrapping model.ErrKnownUnimplemented ->
// {"not_implemented": true, "op": opName, "detail": err} (a mechanism the
// hardware HAS but this library hasn't wired yet -- reported distinctly so
// a client is not told the switch cannot do it); any other error ->
// {"error": err, "op": opName}.
func writeResult(opName string, err error) map[string]any {
	if err == nil {
		return map[string]any{"ok": true, "op": opName}
	}
	if errors.Is(err, model.ErrUnsupportedCapability) {
		return map[string]any{"unsupported": true, "op": opName, "detail": err.Error()}
	}
	if errors.Is(err, model.ErrKnownUnimplemented) {
		return map[string]any{"not_implemented": true, "op": opName, "detail": err.Error()}
	}
	return map[string]any{"error": err.Error(), "op": opName}
}
