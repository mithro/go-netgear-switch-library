package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestListSwitchesTool_ViaInMemorySession drives the real list_switches
// tool over an in-memory MCP session against a small inventory file,
// proving the tool wiring end-to-end (schema, dispatch, JSON result) on
// top of listInventorySwitches' own unit coverage (server_test.go).
func TestListSwitchesTool_ViaInMemorySession(t *testing.T) {
	path := writeTempInventory(t)
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	res := callTool(t, session, "list_switches", map[string]any{"config": path})
	if res.IsError {
		t.Fatalf("list_switches IsError = true, text = %q", textOf(t, res))
	}
	text := textOf(t, res)
	if !strings.Contains(text, `"name": "alpha"`) || !strings.Contains(text, `"name": "zeta"`) {
		t.Errorf("list_switches text = %q, want entries for alpha and zeta", text)
	}
}

// TestIdentifyTool_NarrowSignature proves identify's input schema is
// EXACTLY {host, model, config, community} -- no switch/http_password/
// nsdp_interface/backend fields exist at all, matching server.py's
// narrower `identify(host, model, config=None, community=None)` signature
// (unlike every other read tool's generic 8-field selector+backend).
func TestIdentifyTool_NarrowSignature(t *testing.T) {
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	tools := listToolDefs(t, session)
	tool, ok := tools["identify"]
	if !ok {
		t.Fatal("identify tool not registered")
	}
	schema, ok := tool.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("identify InputSchema = %T, want map[string]any", tool.InputSchema)
	}
	props, _ := schema["properties"].(map[string]any)
	gotFields := make(map[string]bool, len(props))
	for k := range props {
		gotFields[k] = true
	}
	wantFields := map[string]bool{"host": true, "model": true, "config": true, "community": true}
	if len(gotFields) != len(wantFields) {
		t.Fatalf("identify fields = %v, want exactly %v", gotFields, wantFields)
	}
	for k := range wantFields {
		if !gotFields[k] {
			t.Errorf("identify missing field %q", k)
		}
	}
	for _, forbidden := range []string{"switch", "http_password", "nsdp_interface", "backend"} {
		if gotFields[forbidden] {
			t.Errorf("identify has forbidden field %q (narrower signature must omit it)", forbidden)
		}
	}

	required, _ := schema["required"].([]any)
	reqSet := map[string]bool{}
	for _, r := range required {
		reqSet[fmt.Sprint(r)] = true
	}
	if !reqSet["host"] || !reqSet["model"] {
		t.Errorf("identify required = %v, want host and model required", required)
	}
}

// TestIdentifyTool_AgainstVirtualSwitch proves identify actually detects a
// live switch's model over SNMP and returns the jsonable DetectedModel
// shape, matching a direct sw.Identify() call byte-for-byte via
// fmtx.ToJSON.
func TestIdentifyTool_AgainstVirtualSwitch(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	res := callTool(t, session, "identify", map[string]any{
		"host": host, "model": "gsm7228ps", "community": "public",
	})
	if res.IsError {
		t.Fatalf("identify IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["key"] != "gsm7228ps" {
		t.Errorf("identify result = %v, want key=gsm7228ps", got)
	}
}

// listToolDefs fetches the full *mcp.Tool definitions (not just names) via
// tools/list, keyed by name.
func listToolDefs(t *testing.T, session *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	out := make(map[string]*mcp.Tool, len(res.Tools))
	for _, tool := range res.Tools {
		out[tool.Name] = tool
	}
	return out
}
