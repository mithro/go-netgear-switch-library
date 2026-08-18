package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/fmtx"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/virtual"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// snmpFacadeFor mirrors the root package's own facade_integration_test.go
// helper of the same shape (unexported there, so duplicated here): a
// *netgearswitch.Switch built DIRECTLY (bypassing resolveSwitch/
// resolve.Resolve entirely) against vsw's live SNMP face, used ONLY to
// compute each test's "expected" value independently of the code path
// under test.
func snmpFacadeFor(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	sw, err := netgearswitch.New(m, host, netgearswitch.WithSNMPCommunity("public"))
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// readToolCase pairs a read tool's name with a closure over the SAME
// *netgearswitch.Switch method registerRead wires it to (read.go), so the
// table below stays a single source of truth for "which tool calls which
// method" shared between production wiring and this test.
type readToolCase struct {
	name string
	get  func(ctx context.Context, sw *netgearswitch.Switch) (any, error)
}

var readToolCases = []readToolCase{
	{"get_ports", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetPorts(ctx) }},
	{"get_stats", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetStats(ctx) }},
	{"get_vlans", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetVLANs(ctx) }},
	{"get_pvids", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetPVIDs(ctx) }},
	{"get_macs", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetMACs(ctx) }},
	{"get_lldp", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetLLDP(ctx) }},
	{"get_sensors", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetSensors(ctx) }},
	{"get_poe", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetPoE(ctx) }},
	{"get_mgmt_ip", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetMgmtIP(ctx) }},
	{"get_hostname", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetHostname(ctx) }},
	{"get_users", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetUsers(ctx) }},
	{"get_services", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetServices(ctx) }},
	{"get_syslog", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.GetSyslog(ctx) }},
	{"snapshot", func(ctx context.Context, sw *netgearswitch.Switch) (any, error) { return sw.Snapshot(ctx) }},
}

// TestReadTools_MatchDirectFacadeCall proves every generically-registered
// read tool (all but get_device, special-cased below) produces EXACTLY the
// same JSON text a direct facade call + readResult + fmtx.ToJSON would --
// self-verifying regardless of which ops gsm7228ps' SNMP backend actually
// serves (success or a structured unsupported/error result), since both
// sides of the comparison run the identical op against the identical live
// switch.
func TestReadTools_MatchDirectFacadeCall(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	for _, tc := range readToolCases {
		t.Run(tc.name, func(t *testing.T) {
			directSw := snmpFacadeFor(t, vsw, "gsm7228ps")
			v, err := tc.get(ctx, directSw)
			wantJSON, jerr := fmtx.ToJSON(readResult(tc.name, v, err))
			if jerr != nil {
				t.Fatalf("fmtx.ToJSON() error = %v", jerr)
			}

			res := callTool(t, session, tc.name, map[string]any{
				"host": host, "model": "gsm7228ps", "community": "public",
			})
			if res.IsError {
				t.Fatalf("%s IsError = true, text = %q", tc.name, textOf(t, res))
			}
			got := textOf(t, res)
			if got != wantJSON {
				t.Errorf("%s text =\n%s\nwant:\n%s", tc.name, got, wantJSON)
			}
		})
	}
}

// TestGetDeviceTool_AgainstVirtualSwitch proves get_device (special-cased
// in read.go, see registerGetDevice's own doc comment) returns the same
// jsonable NsdpDevice a direct sw.NSDPDevice(ctx) call produces. The
// virtual switch's NSDP face is pinned to nsdp.DefaultServerPort: unlike
// SNMP's "host:port" convention, the facade's default NSDP client
// (buildNSDPClient, backend_nsdp.go) dials a BARE host on the fixed
// default port with no way to override it via resolve.Params -- exactly
// like resolveSwitch's own real production path -- so this is the only way
// to reach a real NSDP virtual face through the actual code this package
// ships, not a test-only shortcut.
func TestGetDeviceTool_AgainstVirtualSwitch(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx", virtual.WithPort(nsdp.DefaultServerPort))
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	m, err := netgearswitch.GetModel("gs110emx")
	if err != nil {
		t.Fatalf("GetModel() error = %v", err)
	}
	directSw, err := netgearswitch.New(m, vsw.Host)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	v, opErr := directSw.NSDPDevice(ctx)
	wantJSON, jerr := fmtx.ToJSON(readResult("get_device", v, opErr))
	if jerr != nil {
		t.Fatalf("fmtx.ToJSON() error = %v", jerr)
	}

	res := callTool(t, session, "get_device", map[string]any{"host": vsw.Host, "model": "gs110emx"})
	if res.IsError {
		t.Fatalf("get_device IsError = true, text = %q", textOf(t, res))
	}
	got := textOf(t, res)
	if got != wantJSON {
		t.Errorf("get_device text =\n%s\nwant:\n%s", got, wantJSON)
	}
}

// TestGetDeviceTool_MismatchedBackendIsUnsupported proves a `backend` other
// than "nsdp" (or omitted) refuses HONESTLY (the structured "unsupported"
// shape) rather than either crashing (the pinned Python reference's actual
// behaviour, see registerGetDevice's doc comment) or silently ignoring the
// override and running over NSDP anyway.
func TestGetDeviceTool_MismatchedBackendIsUnsupported(t *testing.T) {
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	// No live switch needed: resolveSwitch only needs to construct
	// (host/model are enough; the mismatch is caught before any op runs).
	res := callTool(t, session, "get_device", map[string]any{
		"host": "127.0.0.1", "model": "gs110emx", "backend": "http",
	})
	if res.IsError {
		t.Fatalf("get_device(backend=http) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["unsupported"] != true || got["op"] != "get_device" {
		t.Errorf("get_device(backend=http) = %v, want unsupported=true op=get_device", got)
	}
}

// TestGetPoETool_PerCallBackendOverride proves a tool's `backend` param
// genuinely changes which protocol serves the op: gs305ep's PoE data is
// only reachable over HTTP in this test (its NSDP face isn't started at
// all, via virtual.WithPort/virtual.WithHTTPPort left at their defaults but
// the model's own default backend preference is NSDP) -- an explicit
// backend="http" must still reach real PoE data.
func TestGetPoETool_PerCallBackendOverride(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	m, err := netgearswitch.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("GetModel() error = %v", err)
	}
	directSw, err := netgearswitch.New(m, host, netgearswitch.WithHTTPPassword("password"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	v, opErr := directSw.GetPoE(ctx, netgearswitch.WithReadBackend(netgearswitch.BackendHTTP))
	if opErr != nil {
		t.Fatalf("direct GetPoE(backend=http) error = %v, want nil (gs305ep serves PoE over HTTP)", opErr)
	}
	wantJSON, jerr := fmtx.ToJSON(readResult("get_poe", v, nil))
	if jerr != nil {
		t.Fatalf("fmtx.ToJSON() error = %v", jerr)
	}

	res := callTool(t, session, "get_poe", map[string]any{
		"host": host, "model": "gs305ep", "http_password": "password", "backend": "http",
	})
	if res.IsError {
		t.Fatalf("get_poe(backend=http) IsError = true, text = %q", textOf(t, res))
	}
	got := textOf(t, res)
	if got != wantJSON {
		t.Errorf("get_poe(backend=http) text =\n%s\nwant:\n%s", got, wantJSON)
	}
}

// TestReadTool_BadSelectorProducesCredentialError proves "a bad selector"
// -- here, an SNMP model with NO community configured anywhere (no
// `community` arg, no NGSW_COMMUNITY env) -- surfaces as `_read`'s generic
// {"error": ..., "op": ...} shape: resolveSwitch's own construction
// succeeds (community resolution is LAZY), and the CredentialError only
// fires when GetPorts actually tries to build an SNMP client -- INSIDE
// readResult's error handling, unlike a structurally-missing selector
// (neither switch nor host+model), which fails resolveSwitch itself and
// surfaces as a raw IsError result instead (see write_test.go's
// TestWriteTool_UnresolvableSelectorIsRawError for that other shape).
func TestReadTool_BadSelectorProducesCredentialError(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	res := callTool(t, session, "get_ports", map[string]any{"host": host, "model": "gsm7228ps"})
	if res.IsError {
		t.Fatalf("get_ports(no community) IsError = true, text = %q", textOf(t, res))
	}
	got := jsonObjectOf(t, res)
	if got["op"] != "get_ports" {
		t.Errorf("get_ports(no community) = %v, want op=get_ports", got)
	}
	errText, _ := got["error"].(string)
	if !strings.Contains(errText, "community") {
		t.Errorf("get_ports(no community) error = %q, want it to mention the missing SNMP community", errText)
	}
}

// TestReadTool_NeverBlocksOnStdin proves resolveSwitch's deliberate
// omission of any resolve.WithPrompt actually holds at the tool-call level:
// the SAME no-community selector as
// TestReadTool_BadSelectorProducesCredentialError returns promptly (well
// inside testTimeout) with the structured credential error, never hanging
// waiting for interactive input -- the concrete, executable proof behind
// resolveSwitch's own doc comment.
func TestReadTool_NeverBlocksOnStdin(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	srv := BuildServer(mapEnv(nil))
	session := newTestSession(t, srv)

	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	type callOutcome struct {
		res *mcp.CallToolResult
		err error
	}
	done := make(chan callOutcome, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "get_ports",
			Arguments: map[string]any{"host": host, "model": "gsm7228ps"},
		})
		done <- callOutcome{res: res, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("CallTool() error = %v", r.err)
		}
		if r.res.IsError {
			t.Fatalf("get_ports(no community) IsError = true, text = %q", textOf(t, r.res))
		}
	case <-time.After(testTimeout):
		t.Fatal("get_ports(no community) did not return within testTimeout -- it blocked (possibly on stdin)")
	}
}
