package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeEnabledEnv builds an EnvFunc with the write gate open and
// NGSW_WRITE_COMMUNITY set: the MCP tool surface (mirroring server.py's own
// `resolver()` closure) has NO `write_community` parameter on ANY tool, so
// an SNMP write via the host+model selection path can only ever authenticate
// via this env var (or, on the inventory `switch` path, the inventory's own
// snmp.write_community -- irrelevant to the ad-hoc host/model tests in this
// file). This is not a gap this port introduced: resolve.go's own
// fromHostModel only installs a write-community resolver when
// NGSW_WRITE_COMMUNITY is present, mirroring resolve.py's identical
// behaviour exactly.
func writeEnabledEnv(extra map[string]string) EnvFunc {
	m := map[string]string{writeEnvVar: "1", "NGSW_WRITE_COMMUNITY": "public"}
	for k, v := range extra {
		m[k] = v
	}
	return mapEnv(m)
}

// TestWriteTool_AppliesAndRoundTrips proves a write tool doesn't just
// report {"ok": true} vacuously: set_hostname's new value is independently
// confirmed by a follow-up get_hostname read against the same live switch.
func TestWriteTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	args := map[string]any{"host": host, "model": "gsm7228ps", "community": "public"}

	setArgs := map[string]any{"name": "mcp-test-hostname", "force": true}
	for k, v := range args {
		setArgs[k] = v
	}
	res := callTool(t, session, "set_hostname", setArgs)
	if res.IsError {
		t.Fatalf("set_hostname IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_hostname" {
		t.Fatalf("set_hostname result = %v, want ok=true op=set_hostname", got)
	}

	readRes := callTool(t, session, "get_hostname", args)
	if readRes.IsError {
		t.Fatalf("get_hostname IsError = true, text = %q", textOf(t, readRes))
	}
	name := strings.Trim(textOf(t, readRes), "\"")
	if name != "mcp-test-hostname" {
		t.Errorf("get_hostname after set_hostname = %q, want %q (write did not actually reach the switch)", name, "mcp-test-hostname")
	}
}

// TestWriteTool_UnsupportedOpReportsHonestly proves set_flow_control (FASTPATH
// CLI only) run over gsm7228ps's default SNMP backend reports the
// structured {"unsupported": true, ...} shape rather than silently
// succeeding or crashing.
func TestWriteTool_UnsupportedOpReportsHonestly(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	res := callTool(t, session, "set_flow_control", map[string]any{
		"host": host, "model": "gsm7228ps", "community": "public",
		"port": 1, "enabled": true, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_flow_control IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["unsupported"] != true || got["op"] != "set_flow_control" {
		t.Errorf("set_flow_control result = %v, want unsupported=true op=set_flow_control", got)
	}
}

// TestSetPortSpeedTool_InvalidRatePreResolveShape proves an unparseable
// rate returns server.py's own bespoke {"ok": false, "error": ...} shape
// (no "op" key, unlike every other structured result this package
// produces) BEFORE the switch is even resolved -- a bogus/empty selector
// must not matter here.
func TestSetPortSpeedTool_InvalidRatePreResolveShape(t *testing.T) {
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	res := callTool(t, session, "set_port_speed", map[string]any{
		"host": "127.0.0.1", "model": "gsm7228ps", "port": 1, "rate": "garbage",
	})
	if res.IsError {
		t.Fatalf("set_port_speed(bad rate) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != false {
		t.Errorf("set_port_speed(bad rate) ok = %v, want false", got["ok"])
	}
	if _, hasOp := got["op"]; hasOp {
		t.Errorf("set_port_speed(bad rate) result = %v, must NOT have an 'op' key (server.py's own bespoke shape)", got)
	}
	errText, _ := got["error"].(string)
	if !strings.Contains(errText, "'garbage'") {
		t.Errorf("set_port_speed(bad rate) error = %q, want it to quote the bad rate Python-repr-style", errText)
	}
}

// TestSetVlanMembershipTool_InvalidModePreResolveShape proves an invalid
// mode returns _write's {"error": ..., "op": "set_vlan_membership"} shape
// BEFORE the switch is resolved.
func TestSetVlanMembershipTool_InvalidModePreResolveShape(t *testing.T) {
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	res := callTool(t, session, "set_vlan_membership", map[string]any{
		"host": "127.0.0.1", "model": "gsm7228ps", "vlan": 5, "port": 1, "mode": "bogus",
	})
	if res.IsError {
		t.Fatalf("set_vlan_membership(bad mode) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["op"] != "set_vlan_membership" {
		t.Errorf("set_vlan_membership(bad mode) op = %v, want set_vlan_membership", got["op"])
	}
	errText, _ := got["error"].(string)
	if !strings.Contains(errText, "'bogus'") || !strings.Contains(errText, "tagged|untagged|excluded") {
		t.Errorf("set_vlan_membership(bad mode) error = %q, want it to quote the bad mode and list valid ones", errText)
	}
}

// TestUploadCertificateTool_Succeeds proves upload_certificate reaches
// gsm7228ps's real (S3300 multipart) HTTP cert-upload flow -- and that its
// input schema carries NO backend field at all (see registerUploadCertificate's
// doc comment).
func TestUploadCertificateTool_Succeeds(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	tools := listToolDefs(t, session)
	tool, ok := tools["upload_certificate"]
	if !ok {
		t.Fatal("upload_certificate not registered")
	}
	schema, _ := tool.InputSchema.(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if _, has := props["backend"]; has {
		t.Error("upload_certificate has a 'backend' field, want none (deliberately omitted)")
	}

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	res := callTool(t, session, "upload_certificate", map[string]any{
		"host": host, "model": "gsm7228ps", "http_password": "password", "force": true,
		"cert_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
		"key_pem":  "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n",
	})
	if res.IsError {
		t.Fatalf("upload_certificate IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "upload_certificate" {
		t.Errorf("upload_certificate result = %v, want ok=true op=upload_certificate", got)
	}
}

// TestUploadCertificateSCPTool_UnsupportedOnNonFastpathModel proves
// upload_certificate_scp (M4300/GSM7252PS FASTPATH only) refuses honestly
// on gsm7228ps, and that its schema also carries no backend field.
func TestUploadCertificateSCPTool_UnsupportedOnNonFastpathModel(t *testing.T) {
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	tools := listToolDefs(t, session)
	tool, ok := tools["upload_certificate_scp"]
	if !ok {
		t.Fatal("upload_certificate_scp not registered")
	}
	schema, _ := tool.InputSchema.(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if _, has := props["backend"]; has {
		t.Error("upload_certificate_scp has a 'backend' field, want none (deliberately omitted)")
	}

	res := callTool(t, session, "upload_certificate_scp", map[string]any{
		"host": "127.0.0.1", "model": "gsm7228ps",
		"scp_source": "user@example.com", "scp_password": "hunter2", "remote_dir": "/staging",
	})
	if res.IsError {
		t.Fatalf("upload_certificate_scp IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["unsupported"] != true || got["op"] != "upload_certificate_scp" {
		t.Errorf("upload_certificate_scp result = %v, want unsupported=true op=upload_certificate_scp", got)
	}
}

// TestWriteTool_UnresolvableSelectorIsRawError proves a structurally
// missing selector (neither `switch` nor both `host`+`model`) fails
// resolveSwitch itself -- server.py's resolver() call happens OUTSIDE
// `_write`'s try/except, so this surfaces as a raw IsError result, NOT the
// {"error": ..., "op": ...} structured shape.
func TestWriteTool_UnresolvableSelectorIsRawError(t *testing.T) {
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	res := callTool(t, session, "set_hostname", map[string]any{"name": "whatever", "force": true})
	if !res.IsError {
		t.Fatalf("set_hostname(no selector) IsError = false, text = %q, want a raw error result", textOf(t, res))
	}
}

// TestWriteTools_AbsentWithoutWriteGate proves calling a write tool by name
// when the write gate is closed fails at the MCP protocol level (the tool
// is simply not registered), not merely hidden from tools/list.
func TestWriteTools_AbsentWithoutWriteGate(t *testing.T) {
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "set_hostname", Arguments: map[string]any{"name": "x"}})
	if err == nil {
		t.Fatal("CallTool(set_hostname) with write gate closed error = nil, want an error (tool not registered)")
	}
}

// TestWriteTool_NoCredentialLeak proves an http_password supplied on a call
// never appears anywhere in that call's JSON result text, success or
// failure.
func TestWriteTool_NoCredentialLeak(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	const secretMarker = "LEAKY-PASSWORD-MARKER-DO-NOT-LEAK"
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	res := callTool(t, session, "set_hostname", map[string]any{
		"host": host, "model": "gsm7228ps", "community": "public",
		"http_password": secretMarker, "name": "leak-check-hostname", "force": true,
	})
	text := textOf(t, res)
	if strings.Contains(text, secretMarker) {
		t.Errorf("set_hostname result leaked the http_password: %q", text)
	}
}
