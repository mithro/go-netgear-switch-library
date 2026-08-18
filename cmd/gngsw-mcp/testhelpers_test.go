package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/virtual"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testTimeout bounds every context used against a real (loopback) virtual
// switch or an in-memory MCP session -- generous enough for CI, short
// enough that a genuine hang (e.g. an accidental stdin block) still fails
// the test promptly rather than the whole suite timing out.
const testTimeout = 10 * time.Second

// mapEnv adapts a plain map into the EnvFunc shape BuildServer/resolveSwitch
// consume, so tests can inject a fake environment without touching the
// process's real one.
func mapEnv(m map[string]string) EnvFunc {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

// newTestSession builds srv and connects a real MCP client to it over an
// in-memory transport pair (mcp.NewInMemoryTransports), returning the live
// client session -- this package's primary test seam: it exercises the
// REAL server object (tool registration/gating, JSON-schema input
// validation, handler dispatch), not bare Go function calls. t.Cleanup
// closes both ends.
func newTestSession(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("Server.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "gngsw-mcp-test-client", Version: "0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession
}

// callTool calls name with args against session, failing the test on a
// transport-level error (a malformed request, a schema-validation
// rejection) -- NOT on a tool-level IsError result, which callers assert on
// explicitly (a structured {"error":...}/{"unsupported":...} outcome, or an
// IsError result for a raw resolve failure, are both EXPECTED shapes some
// tests deliberately trigger).
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%q) error = %v", name, err)
	}
	return res
}

// textOf returns res's sole TextContent block's text, failing the test if
// res carries no text content at all (every tool in this package always
// returns exactly one TextContent block, success or error).
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("CallToolResult has no content blocks")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("CallToolResult.Content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// jsonObjectOf unmarshals res's text content as a JSON object, failing the
// test if it isn't one (every structured result this package returns --
// success or error -- is a JSON object, never an array or scalar).
func jsonObjectOf(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	text := textOf(t, res)
	var v map[string]any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", text, err)
	}
	return v
}

// toolNames returns the sorted-by-registration-order names of every tool
// srv currently exposes, via a real tools/list round-trip over an in-memory
// session (proving the write gate operates at REGISTRATION time, not just
// via some in-handler check).
func toolNames(t *testing.T, srv *mcp.Server) []string {
	t.Helper()
	session := newTestSession(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	names := make([]string, len(res.Tools))
	for i, tool := range res.Tools {
		names[i] = tool.Name
	}
	return names
}

// startVirtualSwitch builds and starts a virtual.VirtualSwitch for modelKey
// with opts applied, registering t.Cleanup to stop it. Local to this
// package (cmd/gngsw-mcp is `package main`, so it cannot import the root
// module's own internal test helpers of the same name/shape).
func startVirtualSwitch(t *testing.T, modelKey string, opts ...virtual.Option) *virtual.VirtualSwitch {
	t.Helper()
	sw, err := virtual.NewVirtualSwitch(modelKey, opts...)
	if err != nil {
		t.Fatalf("virtual.NewVirtualSwitch(%q) error = %v", modelKey, err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("VirtualSwitch.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("VirtualSwitch.Stop() error = %v", err)
		}
	})
	return sw
}
