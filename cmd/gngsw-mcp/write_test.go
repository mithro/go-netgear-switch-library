package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/virtual"
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

// --- direct-facade read-back helpers -------------------------------------
//
// The tests below verify a write tool's outcome by reading the SAME live
// virtual switch back through the root package's own facade directly
// (bypassing the MCP layer entirely for the verification half) --
// mirroring facade_write_integration_test.go's own read-back helpers of the
// same shape (getVlan/getPoE/getPort). That file's helpers live in the root
// module's `netgearswitch_test` package and are unexported, so they cannot
// be imported across the package boundary; duplicated here instead.

// pvidOf returns port's current PVID from a live sw.GetPVIDs() dispatch.
func pvidOf(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, port int) (vlan int, found bool) {
	t.Helper()
	pvids, err := sw.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	for _, p := range pvids {
		if p.Port == port {
			return p.Vlan, true
		}
	}
	return 0, false
}

// vlanOf returns vlanID's VLANInfo from a live sw.GetVLANs() dispatch.
func vlanOf(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, vlanID int) (netgearswitch.VLANInfo, bool) {
	t.Helper()
	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	for _, v := range vlans {
		if v.VlanID == vlanID {
			return v, true
		}
	}
	return netgearswitch.VLANInfo{}, false
}

// poeOf returns port's PoEStatus from a live sw.GetPoE() dispatch, failing
// the test if it is absent.
func poeOf(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, port int) netgearswitch.PoEStatus {
	t.Helper()
	statuses, err := sw.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	for _, s := range statuses {
		if s.Port == port {
			return s
		}
	}
	t.Fatalf("no PoE port %d in GetPoE() result", port)
	return netgearswitch.PoEStatus{}
}

// portOf returns port's PortStatus from a live sw.GetPorts(opts...)
// dispatch, failing the test if it is absent.
func portOf(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, port int, opts ...netgearswitch.ReadOption) netgearswitch.PortStatus {
	t.Helper()
	ports, err := sw.GetPorts(ctx, opts...)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	for _, p := range ports {
		if p.Port == port {
			return p
		}
	}
	t.Fatalf("no port %d in GetPorts() result", port)
	return netgearswitch.PortStatus{}
}

// --- the 12 previously-untested write tools: success + applied verification

// TestSetPVIDTool_AppliesAndRoundTrips proves set_pvid reaches the real SNMP
// write path against gsm7252ps: vlan 41 is one of this model's own seeded
// VLANs (SnmpWriter.SetPVID refuses up front unless the target VLAN already
// exists), so a bogus/nonexistent vlan could not fake success here. Applied
// state is confirmed by a DIRECT facade GetPVIDs call, independent of the
// tool's own {"ok":true} claim.
func TestSetPVIDTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const port, vlan = 6, 41

	res := callTool(t, session, "set_pvid", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"port": port, "vlan": vlan, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_pvid IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_pvid" {
		t.Fatalf("set_pvid result = %v, want ok=true op=set_pvid", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	gotVlan, found := pvidOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), port)
	if !found || gotVlan != vlan {
		t.Errorf("GetPVIDs() after set_pvid: port %d = (vlan=%d, found=%v), want (vlan=%d, found=true)", port, gotVlan, found, vlan)
	}
}

// TestSetPortDescriptionTool_AppliesAndRoundTrips proves set_port_description
// reaches the real SNMP write path against gsm7252ps and the new label is
// visible through a direct facade GetPorts call afterward.
func TestSetPortDescriptionTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const port = 5
	const description = "mcp-test-description"

	res := callTool(t, session, "set_port_description", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"port": port, "description": description, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_port_description IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_port_description" {
		t.Fatalf("set_port_description result = %v, want ok=true op=set_port_description", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	p := portOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), port)
	if p.Description == nil || *p.Description != description {
		t.Errorf("GetPorts() after set_port_description: port %d Description = %s, want %q", port, derefStrLocal(p.Description), description)
	}
}

// TestSetPortEnabledTool_AppliesAndRoundTrips proves set_port_enabled
// reaches the real SNMP write+verify path against gsm7252ps and the new
// admin state is visible through a direct facade GetPorts call afterward.
func TestSetPortEnabledTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const port = 4

	res := callTool(t, session, "set_port_enabled", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"port": port, "enabled": false, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_port_enabled IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_port_enabled" {
		t.Fatalf("set_port_enabled result = %v, want ok=true op=set_port_enabled", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	p := portOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), port)
	if p.AdminEnabled {
		t.Errorf("GetPorts() after set_port_enabled(false): port %d AdminEnabled = true, want false", port)
	}
}

// TestSetPoETool_AppliesAndRoundTrips proves set_poe reaches the real SNMP
// write+verify path against gsm7252ps: port 1 starts PoE-delivering on this
// model's seed data (facade_write_integration_test.go's own capstone relies
// on the same fact), so turning it off is a genuine transition, not a no-op.
func TestSetPoETool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const port = 1

	res := callTool(t, session, "set_poe", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"port": port, "on": false, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_poe IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_poe" {
		t.Fatalf("set_poe result = %v, want ok=true op=set_poe", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	p := poeOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), port)
	if p.AdminEnabled {
		t.Errorf("GetPoE() after set_poe(off): port %d AdminEnabled = true, want false", port)
	}
	if p.Delivering() {
		t.Errorf("GetPoE() after set_poe(off): port %d Detect = %v, want NOT delivering", port, p.Detect)
	}
}

// TestCreateVlanTool_AppliesAndRoundTrips proves create_vlan reaches the
// real SNMP write path against gsm7252ps: vlan 3910 does not exist in this
// model's seed data, so its appearance afterward is unambiguous proof the
// write reached the fake, not a vacuous pass.
func TestCreateVlanTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const vlanID = 3910
	const name = "mcp-create-vlan"

	res := callTool(t, session, "create_vlan", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"vlan": vlanID, "name": name, "force": true,
	})
	if res.IsError {
		t.Fatalf("create_vlan IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "create_vlan" {
		t.Fatalf("create_vlan result = %v, want ok=true op=create_vlan", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	vlan, found := vlanOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), vlanID)
	if !found {
		t.Fatalf("GetVLANs() after create_vlan: vlan %d not present", vlanID)
	}
	if vlan.Name == nil || *vlan.Name != name {
		t.Errorf("GetVLANs() after create_vlan: vlan %d Name = %s, want %q", vlanID, derefStrLocal(vlan.Name), name)
	}
}

// TestDeleteVlanTool_AppliesAndRoundTrips proves delete_vlan reaches the
// real SNMP write path against gsm7252ps: it first creates vlan 3920
// through the ALREADY-PROVEN create_vlan tool (rather than a raw facade
// call), then deletes it through delete_vlan and confirms it is gone via a
// direct facade GetVLANs call.
func TestDeleteVlanTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const vlanID = 3920
	args := map[string]any{"host": host, "model": "gsm7252ps", "community": "public", "force": true}

	createArgs := map[string]any{"vlan": vlanID, "name": "mcp-delete-vlan"}
	for k, v := range args {
		createArgs[k] = v
	}
	if res := callTool(t, session, "create_vlan", createArgs); res.IsError {
		t.Fatalf("create_vlan (setup) IsError = true, text = %q", textOf(t, res))
	}

	deleteArgs := map[string]any{"vlan": vlanID}
	for k, v := range args {
		deleteArgs[k] = v
	}
	res := callTool(t, session, "delete_vlan", deleteArgs)
	if res.IsError {
		t.Fatalf("delete_vlan IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "delete_vlan" {
		t.Fatalf("delete_vlan result = %v, want ok=true op=delete_vlan", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, found := vlanOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), vlanID); found {
		t.Errorf("GetVLANs() after delete_vlan: vlan %d still present, want it gone", vlanID)
	}
}

// TestCyclePoETool_AppliesAndRoundTrips proves cycle_poe reaches the real
// SNMP off->on re-arm path against gsm7252ps: port 3 is proven (by
// facade_write_integration_test.go's own short-timeout capstone) to recover
// to Delivering after a cycle on this model's seed data. The MCP tool
// exposes no timeout override at all, so this call runs the PRODUCTION
// default timeouts (30s/60s/2s) -- it still completes promptly because the
// virtual fake's state transitions synchronously with each SET, so the
// first poll check (before any sleep) already observes success.
func TestCyclePoETool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const port = 3

	res := callTool(t, session, "cycle_poe", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"port": port, "force": true,
	})
	if res.IsError {
		t.Fatalf("cycle_poe IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "cycle_poe" {
		t.Fatalf("cycle_poe result = %v, want ok=true op=cycle_poe", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	p := poeOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), port)
	if !p.AdminEnabled {
		t.Error("GetPoE() after cycle_poe: AdminEnabled = false, want true")
	}
	if !p.Delivering() {
		t.Errorf("GetPoE() after cycle_poe: Detect = %v, want Delivering", p.Detect)
	}
}

// TestClearPoEFaultTool_AppliesAndRoundTrips proves clear_poe_fault reaches
// the real SNMP off->on re-arm path against gsm7252ps, with its looser
// recovery predicate (leaving FAULT is enough -- Delivering OR Searching
// both satisfy it, unlike cycle_poe's strict Delivering requirement), same
// no-timeout-override caveat as cycle_poe above.
func TestClearPoEFaultTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const port = 7

	res := callTool(t, session, "clear_poe_fault", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"port": port, "force": true,
	})
	if res.IsError {
		t.Fatalf("clear_poe_fault IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "clear_poe_fault" {
		t.Fatalf("clear_poe_fault result = %v, want ok=true op=clear_poe_fault", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	p := poeOf(ctx, t, snmpFacadeFor(t, vsw, "gsm7252ps"), port)
	if !p.AdminEnabled {
		t.Error("GetPoE() after clear_poe_fault: AdminEnabled = false, want true")
	}
	if p.Detect != netgearswitch.PoEDetectDelivering && p.Detect != netgearswitch.PoEDetectSearching {
		t.Errorf("GetPoE() after clear_poe_fault: Detect = %v, want Delivering or Searching (no longer FAULT)", p.Detect)
	}
}

// TestSetMgmtIPTool_ForceAppliesAndRoundTrips proves set_mgmt_ip reaches the
// real SNMP unconditional-force-gate write path against gsm7252ps (a model
// with a vendor OID subtree, required for the mgmt-write OIDs to resolve)
// and the new address/netmask/gateway are visible through a direct facade
// GetMgmtIP call afterward.
func TestSetMgmtIPTool_ForceAppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const address, netmask, gateway = "10.1.5.99", "255.255.255.0", "10.1.5.1"

	res := callTool(t, session, "set_mgmt_ip", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"address": address, "netmask": netmask, "gateway": gateway, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_mgmt_ip IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_mgmt_ip" {
		t.Fatalf("set_mgmt_ip result = %v, want ok=true op=set_mgmt_ip", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	mgmt, err := snmpFacadeFor(t, vsw, "gsm7252ps").GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != address {
		t.Errorf("GetMgmtIP() after set_mgmt_ip: Address = %s, want %q", derefStrLocal(mgmt.Address), address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != netmask {
		t.Errorf("GetMgmtIP() after set_mgmt_ip: Netmask = %s, want %q", derefStrLocal(mgmt.Netmask), netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != gateway {
		t.Errorf("GetMgmtIP() after set_mgmt_ip: Gateway = %s, want %q", derefStrLocal(mgmt.Gateway), gateway)
	}
}

// TestSetSyslogEnabledTool_AppliesAndRoundTrips proves set_syslog_enabled
// reaches the real SNMP write path against gsm7252ps, which seeds remote
// logging ON, so turning it off is a genuine transition, confirmed by a
// direct facade GetSyslog call afterward.
func TestSetSyslogEnabledTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)

	res := callTool(t, session, "set_syslog_enabled", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"enabled": false, "force": true,
	})
	if res.IsError {
		t.Fatalf("set_syslog_enabled IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_syslog_enabled" {
		t.Fatalf("set_syslog_enabled result = %v, want ok=true op=set_syslog_enabled", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	syslog, err := snmpFacadeFor(t, vsw, "gsm7252ps").GetSyslog(ctx)
	if err != nil {
		t.Fatalf("GetSyslog() error = %v", err)
	}
	if syslog.Enabled {
		t.Error("GetSyslog() after set_syslog_enabled(false): Enabled = true, want false")
	}
}

// TestRemoveSyslogCollectorTool_AppliesAndRoundTrips proves
// remove_syslog_collector reaches the real SNMP RowStatus-destroy write
// path against gsm7252ps, which seeds exactly one collector (10.1.5.1),
// confirmed gone by a direct facade GetSyslog call afterward.
func TestRemoveSyslogCollectorTool_AppliesAndRoundTrips(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const collectorHost = "10.1.5.1"

	res := callTool(t, session, "remove_syslog_collector", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"host_address": collectorHost, "force": true,
	})
	if res.IsError {
		t.Fatalf("remove_syslog_collector IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "remove_syslog_collector" {
		t.Fatalf("remove_syslog_collector result = %v, want ok=true op=remove_syslog_collector", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	syslog, err := snmpFacadeFor(t, vsw, "gsm7252ps").GetSyslog(ctx)
	if err != nil {
		t.Fatalf("GetSyslog() error = %v", err)
	}
	for _, s := range syslog.Servers {
		if s.Host == collectorHost {
			t.Fatalf("GetSyslog() after remove_syslog_collector: collector %q still present: %+v", collectorHost, syslog.Servers)
		}
	}
}

// TestAddSyslogCollectorTool_UnsupportedOverDefaultBackend proves
// add_syslog_collector genuinely reaches the real facade call (not just
// tool registration) against gsm7252ps's default (SNMP) backend, which
// refuses this op by name -- add_syslog_collector is served ONLY over the
// FASTPATH CLI (switch_write.go's own doc comment on
// (*Switch).AddSyslogCollector), exactly the same shape
// TestWriteTool_UnsupportedOpReportsHonestly above already establishes for
// set_flow_control.
//
// This package's resolveSwitch (server.go) cannot reach a live FASTPATH-CLI
// virtual face at all, on ANY model: cmd/internal/resolve.Params (and the
// inventory-path SwitchConfig behind it) carries no ssh_port/telnet_port
// override, and virtual.TelnetFace/SSHFace always bind an EPHEMERAL port
// with no way to pin it (unlike WithPort/WithHTTPPort for SNMP/NSDP/HTTP) --
// confirmed by grep across resolve.go, inventory.go and virtual/server.go.
// The root package's OWN CLI-capable tests (facade_cli_integration_test.go)
// only reach a live CLI face by constructing the Switch DIRECTLY with
// netgearswitch.WithSSHPort/WithTelnetPort, bypassing resolve.Resolve
// entirely -- a construction path this package's tool handlers never take.
// A genuine {"ok":true} round trip for add_syslog_collector is therefore
// not reachable through this package's actual MCP tool surface today; this
// is a pre-existing gap in cmd/internal/resolve (also affecting cmd/gngsw's
// own --host/--model flag path, not something introduced by or in scope
// for this test-coverage change), not a defect in add_syslog_collector's
// own wiring, which this test DOES prove executes correctly end-to-end.
func TestAddSyslogCollectorTool_UnsupportedOverDefaultBackend(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	res := callTool(t, session, "add_syslog_collector", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"host_address": "10.9.9.9", "force": true,
	})
	if res.IsError {
		t.Fatalf("add_syslog_collector IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["unsupported"] != true || got["op"] != "add_syslog_collector" {
		t.Errorf("add_syslog_collector result = %v, want unsupported=true op=add_syslog_collector", got)
	}
}

// --- writeResult's two previously-untested branches (result.go) ----------

// TestUploadCertificateTool_KnownUnimplementedReportsNotImplemented proves
// writeResult's {"not_implemented":true,...} branch: m4300-24x's real
// cert-upload mechanism is SCP (upload_certificate_scp), not HTTP, so
// UploadCertificate refuses wrapping model.ErrKnownUnimplemented BEFORE
// ever resolving an http_password -- mirroring backend_http_test.go's
// TestUploadCertificate_KnownUnimplementedMechanismRefusesBeforeCredentialResolution
// exactly (same model, same deliberate absence of http_password/live
// switch: the refusal fires before any network I/O), reused here through
// the MCP tool surface.
func TestUploadCertificateTool_KnownUnimplementedReportsNotImplemented(t *testing.T) {
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	res := callTool(t, session, "upload_certificate", map[string]any{
		"host": "10.0.0.1", "model": "m4300-24x", "force": true,
		"cert_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
		"key_pem":  "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n",
	})
	if res.IsError {
		t.Fatalf("upload_certificate(m4300-24x) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["not_implemented"] != true || got["op"] != "upload_certificate" {
		t.Errorf("upload_certificate(m4300-24x) result = %v, want not_implemented=true op=upload_certificate", got)
	}
	if _, hasOK := got["ok"]; hasOK {
		t.Errorf("upload_certificate(m4300-24x) result = %v, must not also carry an 'ok' key", got)
	}
}

// TestRemoveSyslogCollectorTool_UnknownHostReportsGenericError proves
// writeResult's catch-all {"error":...,"op":...} branch: removing a
// collector for a host gsm7252ps has no row for is a PRECONDITION failure
// (snmp.Writer.RemoveSyslogCollector's own doc comment), wrapping plain
// model.ErrSNMP -- neither model.ErrUnsupportedCapability nor
// model.ErrKnownUnimplemented -- so it must land on writeResult's final,
// generic branch, distinct from both structured shapes.
func TestRemoveSyslogCollectorTool_UnknownHostReportsGenericError(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const unknownHost = "10.9.9.9"
	res := callTool(t, session, "remove_syslog_collector", map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"host_address": unknownHost, "force": true,
	})
	if res.IsError {
		t.Fatalf("remove_syslog_collector(unknown host) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["op"] != "remove_syslog_collector" {
		t.Errorf("remove_syslog_collector(unknown host) op = %v, want remove_syslog_collector", got["op"])
	}
	if _, isUnsupported := got["unsupported"]; isUnsupported {
		t.Errorf("remove_syslog_collector(unknown host) result = %v, must NOT be the unsupported shape", got)
	}
	if _, isNotImplemented := got["not_implemented"]; isNotImplemented {
		t.Errorf("remove_syslog_collector(unknown host) result = %v, must NOT be the not_implemented shape", got)
	}
	errText, _ := got["error"].(string)
	if !strings.Contains(errText, unknownHost) {
		t.Errorf("remove_syslog_collector(unknown host) error = %q, want it to mention %q", errText, unknownHost)
	}
}

// --- set_port_speed's success path (only the invalid-rate pre-resolve error
// was previously tested) ---------------------------------------------------
//
// The only reachable backend (through this package's actual resolveSwitch)
// that can genuinely APPLY a forced port speed is the web UI's GoAhead
// dialect (gs728tpp): SNMP and NSDP refuse set_port_speed entirely
// (switch_write.go), and the FASTPATH CLI backend -- which could -- is not
// reachable at all (see TestAddSyslogCollectorTool_UnsupportedOverDefaultBackend's
// doc comment above for why). gs728tpp's own ports page offers only
// 10/100 half-or-full, 1000 FULL ONLY, and Auto (webui/goahead_write.go's
// goAheadForcedSpeeds) -- so "auto" and "100" can be proven to genuinely
// APPLY here, but a forced "10G" cannot: no backend+model combination this
// test harness can reach ever offers it. The "10G" case below instead
// proves parsePortRate's *1000 conversion reached the real facade call (the
// refusal's own detail text names the resulting 10000M configuration), the
// closest genuine, non-fabricated proof available in this environment.

// TestSetPortSpeedTool_AutoSucceeds proves rate="auto" genuinely applies
// against gs728tpp's HTTP GoAhead backend, confirmed by a direct facade
// GetPorts(backend=http) call (SNMP's ifSpeed cannot report the CONFIGURED
// speed at all, only negotiated -- the read-back MUST go over HTTP too).
func TestSetPortSpeedTool_AutoSucceeds(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs728tpp")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	const port = 2

	res := callTool(t, session, "set_port_speed", map[string]any{
		"host": host, "model": "gs728tpp", "http_password": "password", "backend": "http",
		"port": port, "rate": "auto", "force": true,
	})
	if res.IsError {
		t.Fatalf("set_port_speed(auto) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_port_speed" {
		t.Fatalf("set_port_speed(auto) result = %v, want ok=true op=set_port_speed", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	direct := httpFacadeFor(t, vsw, "gs728tpp")
	p := portOf(ctx, t, direct, port, netgearswitch.WithReadBackend(netgearswitch.BackendHTTP))
	if p.SpeedConfig == nil || !p.SpeedConfig.Equal(netgearswitch.AutoPortSpeed()) {
		t.Errorf("GetPorts() after set_port_speed(auto): port %d SpeedConfig = %v, want auto", port, p.SpeedConfig)
	}
}

// TestSetPortSpeedTool_Forced100Succeeds proves rate="100" with an explicit
// duplex genuinely applies against gs728tpp's HTTP GoAhead backend.
func TestSetPortSpeedTool_Forced100Succeeds(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs728tpp")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	const port = 2

	res := callTool(t, session, "set_port_speed", map[string]any{
		"host": host, "model": "gs728tpp", "http_password": "password", "backend": "http",
		"port": port, "rate": "100", "duplex": "full", "force": true,
	})
	if res.IsError {
		t.Fatalf("set_port_speed(100, full) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["ok"] != true || got["op"] != "set_port_speed" {
		t.Fatalf("set_port_speed(100, full) result = %v, want ok=true op=set_port_speed", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	direct := httpFacadeFor(t, vsw, "gs728tpp")
	p := portOf(ctx, t, direct, port, netgearswitch.WithReadBackend(netgearswitch.BackendHTTP))
	want := netgearswitch.ForcedPortSpeed(100, true)
	if p.SpeedConfig == nil || !p.SpeedConfig.Equal(want) {
		t.Errorf("GetPorts() after set_port_speed(100, full): port %d SpeedConfig = %v, want %v", port, p.SpeedConfig, want)
	}
}

// TestSetPortSpeedTool_Forced10GVerifiesConversionViaRefusal proves
// parsePortRate's "10G" -> 10*1000 = 10000 Mbit conversion (write.go)
// reaches the real facade call: gs728tpp's HTTP GoAhead ports page does not
// offer a forced 10G choice, so webui.Writer.SetPortSpeed refuses by name
// (wrapping model.ErrUnsupportedCapability) -- but its own refusal message
// names the SPEED IT WAS ASKED FOR, so a message naming "10000M" is
// non-fabricated proof the "G" suffix was correctly multiplied by 1000
// before ever reaching the writer, even though no backend this harness can
// reach can actually APPLY a forced 10G rate (see this section's own
// header comment for why a genuine {"ok":true} isn't reachable here).
func TestSetPortSpeedTool_Forced10GVerifiesConversionViaRefusal(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs728tpp")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	res := callTool(t, session, "set_port_speed", map[string]any{
		"host": host, "model": "gs728tpp", "http_password": "password", "backend": "http",
		"port": 2, "rate": "10G", "duplex": "full", "force": true,
	})
	if res.IsError {
		t.Fatalf("set_port_speed(10G) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["unsupported"] != true || got["op"] != "set_port_speed" {
		t.Fatalf("set_port_speed(10G) result = %v, want unsupported=true op=set_port_speed", got)
	}
	detail, _ := got["detail"].(string)
	if !strings.Contains(detail, "10000M") {
		t.Errorf("set_port_speed(10G) detail = %q, want it to name the converted 10000M rate (proving the *1000 conversion happened)", detail)
	}
}

// --- add_syslog_collector's `port` *int fix (write.go) --------------------

// TestAddSyslogCollectorPort_OmittedDefaultsExplicitZeroPreserved is a pure
// unit test of the exact defaulting arithmetic the bug fix changed: an
// omitted `port` (nil) still defaults to 514, but an explicit `port: 0`
// (a non-nil pointer TO zero) must pass through unchanged -- the bug this
// port *int fix corrects was a plain `int` collapsing both cases onto Go's
// own zero value.
func TestAddSyslogCollectorPort_OmittedDefaultsExplicitZeroPreserved(t *testing.T) {
	if got := addSyslogCollectorPort(nil); got != 514 {
		t.Errorf("addSyslogCollectorPort(nil) = %d, want 514 (omitted -> default)", got)
	}
	zero := 0
	if got := addSyslogCollectorPort(&zero); got != 0 {
		t.Errorf("addSyslogCollectorPort(&0) = %d, want 0 (explicit zero must NOT be coerced to 514)", got)
	}
	other := 5140
	if got := addSyslogCollectorPort(&other); got != other {
		t.Errorf("addSyslogCollectorPort(&5140) = %d, want 5140", got)
	}
}

// TestAddSyslogCollectorTool_ExplicitZeroPortReachesHandlerUnchanged proves
// the fix end-to-end through the REAL go-sdk JSON decode (not a hand-rolled
// encoding/json.Unmarshal): a call carrying an explicit `"port": 0` must be
// accepted by the tool's JSON schema (a *int field decodes a literal `0`
// into a non-nil pointer, exactly like the sibling `severity` field always
// has) and reach the SAME real facade call/refusal shape an omitted `port`
// does -- proving the fix does not confuse the schema layer or crash the
// handler for the zero value specifically. (The two calls' outward result
// shapes are identical here because add_syslog_collector's only backend
// (FASTPATH CLI) is unreachable in this harness and refuses before ever
// consulting `port` -- see TestAddSyslogCollectorTool_UnsupportedOverDefaultBackend's
// doc comment; the VALUE-level proof that 0 survives uncoerced is the pure
// function test directly above.)
func TestAddSyslogCollectorTool_ExplicitZeroPortReachesHandlerUnchanged(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	srv := BuildServer(writeEnabledEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	base := map[string]any{
		"host": host, "model": "gsm7252ps", "community": "public",
		"host_address": "10.9.9.9", "force": true,
	}

	omitted := map[string]any{}
	for k, v := range base {
		omitted[k] = v
	}
	resOmitted := callTool(t, session, "add_syslog_collector", omitted)
	if resOmitted.IsError {
		t.Fatalf("add_syslog_collector(port omitted) IsError = true, text = %q", textOf(t, resOmitted))
	}
	gotOmitted := jsonObjectOf(t, resOmitted)

	explicitZero := map[string]any{"port": 0}
	for k, v := range base {
		explicitZero[k] = v
	}
	resZero := callTool(t, session, "add_syslog_collector", explicitZero)
	if resZero.IsError {
		t.Fatalf("add_syslog_collector(port=0) IsError = true, text = %q", textOf(t, resZero))
	}
	gotZero := jsonObjectOf(t, resZero)

	if gotZero["unsupported"] != true || gotZero["op"] != "add_syslog_collector" {
		t.Errorf("add_syslog_collector(port=0) result = %v, want unsupported=true op=add_syslog_collector", gotZero)
	}
	if gotOmitted["unsupported"] != gotZero["unsupported"] || gotOmitted["op"] != gotZero["op"] {
		t.Errorf("add_syslog_collector(port omitted) = %v, add_syslog_collector(port=0) = %v, want the same shape", gotOmitted, gotZero)
	}
}

// --- small local helpers ---------------------------------------------------

// httpFacadeFor mirrors read_test.go's own inline pattern (e.g.
// TestGetPoETool_PerCallBackendOverride) for building a
// *netgearswitch.Switch bound directly to vsw's live HTTP face, bypassing
// resolveSwitch entirely -- used ONLY to compute this file's "expected"
// read-back values independently of the code path under test.
func httpFacadeFor(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	sw, err := netgearswitch.New(m, host, netgearswitch.WithHTTPPassword("password"))
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// derefStrLocal renders s for an error message: "<nil>" for a nil pointer,
// else the quoted string value.
func derefStrLocal(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", *s)
}
