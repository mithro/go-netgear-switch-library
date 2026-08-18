// read.go: the 15 read tools, mirroring server.py's `_register_read` calls
// one-for-one -- 14 of them (every op except get_device) share the exact
// same generic shape server.py's `_register_read` helper gives them:
// resolve the switch, parse `backend`, call exactly one facade method with
// it, shape the outcome via readResult. get_device is special-cased (see
// its own doc comment below) because its facade method, unlike every other
// read op, takes no backend override at all.
package main

import (
	"context"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// readIn is the shared input every one of the 15 read tools accepts,
// mirroring server.py's `_register_read`-generated tool signature exactly:
// the 7 selector params plus `backend`.
type readIn struct {
	selectorFields
	backendField
}

// registerRead registers one read tool backed by call (a thin closure over
// one *netgearswitch.Switch method, e.g. `sw.GetPorts`), mirroring
// server.py's `_register_read(name, method, doc)` -- description gets
// backendDoc appended, exactly like server.py's `doc + _BACKEND_DOC`.
func registerRead[T any](s *mcp.Server, env EnvFunc, name, description string, call func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) (T, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description + backendDoc},
		func(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, any, error) {
			sw, err := resolveSwitch(env, in.selectorFields)
			if err != nil {
				return nil, nil, err
			}
			defer func() { _ = sw.Close() }()

			backend, err := parseBackendName(in.Backend)
			if err != nil {
				return nil, nil, err
			}
			v, opErr := call(ctx, sw, readOptsForBackend(backend)...)
			return jsonResult(readResult(name, v, opErr))
		})
}

// registerReadTools registers all 15 read tools, in server.py's own
// registration order.
func registerReadTools(s *mcp.Server, env EnvFunc) {
	registerRead(s, env, "get_ports", "Per-port link status and speed.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.PortStatus, error) {
			return sw.GetPorts(ctx, opts...)
		})
	registerRead(s, env, "get_stats", "Per-port byte/packet counters.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.PortStats, error) {
			return sw.GetStats(ctx, opts...)
		})
	registerRead(s, env, "get_vlans", "VLANs with member/tagged/untagged ports.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.VLANInfo, error) {
			return sw.GetVLANs(ctx, opts...)
		})
	registerRead(s, env, "get_pvids", "Per-port PVID (native VLAN).",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.Pvid, error) {
			return sw.GetPVIDs(ctx, opts...)
		})
	registerRead(s, env, "get_macs", "The MAC/FDB table (SNMP models).",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.MacEntry, error) {
			return sw.GetMACs(ctx, opts...)
		})
	registerRead(s, env, "get_lldp", "LLDP neighbours (SNMP models).",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.LLDPNeighbor, error) {
			return sw.GetLLDP(ctx, opts...)
		})
	registerRead(s, env, "get_sensors", "Fan/temperature/PSU sensors.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.Sensor, error) {
			return sw.GetSensors(ctx, opts...)
		})
	registerRead(s, env, "get_poe", "Per-port PoE status and delivered power.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.PoEStatus, error) {
			return sw.GetPoE(ctx, opts...)
		})
	registerRead(s, env, "get_mgmt_ip", "Management IP config and base MAC.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) (netgearswitch.MgmtIPConfig, error) {
			return sw.GetMgmtIP(ctx, opts...)
		})
	registerRead(s, env, "get_hostname", "The switch's configured host name.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) (string, error) {
			return sw.GetHostname(ctx, opts...)
		})
	registerRead(s, env, "get_users",
		"Local login accounts and their access level. The access mode is the firmware's own wording, "+
			"which differs between images, with a normalised 'privileged' flag beside it.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.SwitchUser, error) {
			return sw.GetUsers(ctx, opts...)
		})
	registerRead(s, env, "get_services",
		"Which management services (http/https/telnet/ssh) are enabled, and on which port where the firmware reports one.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) ([]netgearswitch.ServiceStatus, error) {
			return sw.GetServices(ctx, opts...)
		})
	registerRead(s, env, "get_syslog",
		"Remote-logging configuration: whether it is on, the local source port, and the configured collectors.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) (netgearswitch.SyslogConfig, error) {
			return sw.GetSyslog(ctx, opts...)
		})
	registerRead(s, env, "snapshot",
		"Every read op at once (ports, stats, VLANs, PVIDs, mgmt-IP, PoE, LLDP, sensors), each routed to the first "+
			"backend that serves it. Fields no backend can serve come back empty rather than failing the whole call.",
		func(ctx context.Context, sw *netgearswitch.Switch, opts ...netgearswitch.ReadOption) (netgearswitch.SwitchData, error) {
			return sw.Snapshot(ctx, opts...)
		})

	registerGetDevice(s, env)
}

// registerGetDevice registers get_device, mirroring server.py's
// `_register_read("get_device", "nsdp_device", ...)` -- WITH ONE DELIBERATE
// CORRECTION. server.py's generic `_register_read` wrapper always invokes
// `getattr(sw, method)(backend=chosen)`; but `SyncSwitch.nsdp_device(self)`
// (sync_api.py) takes NO backend parameter at all -- so on the pinned
// Python reference, EVERY call to the get_device tool raises a bare
// TypeError ("nsdp_device() got an unexpected keyword argument 'backend'"),
// regardless of whether a caller ever supplies `backend`. This is a real
// bug in server.py's tool wiring, not a documented, intentional
// restriction: nsdp_device's own docstring says it "deliberately bypasses"
// backend dispatch (exactly like identify(), which server.py registers
// SEPARATELY with no backend param at all, and which this port mirrors
// faithfully via meta.go's own identify handler) -- the intent is clearly
// that get_device never takes a functioning backend override, not that
// calling it should always crash.
//
// netgearswitch.Switch.NSDPDevice(ctx) mirrors that same documented intent
// at the Go facade layer: it has no ReadOption parameter at all (switch.go),
// so there is no way to literally reproduce server.py's crash here even if
// this port wanted to (Go's static typing forecloses passing an option the
// method signature doesn't accept). Rather than silently dropping a
// `backend` argument a caller passed (a quiet lie: "your override did
// nothing" -- exactly what _BACKEND_DOC's own text forbids: "the chosen
// backend either serves the operation or the call fails -- it is NEVER
// quietly run over a different protocol"), this handler treats a `backend`
// naming anything other than "nsdp" as a genuine unsupported-capability
// refusal (the same structured shape any other read tool reports for a
// backend that cannot serve it), and otherwise (omitted, or explicitly
// "nsdp") calls NSDPDevice normally. The `backend` field stays in the input
// schema for structural parity with every other read tool's uniform
// signature.
func registerGetDevice(s *mcp.Server, env EnvFunc) {
	const name = "get_device"
	description := "The complete raw NSDP device record (model, MAC, firmware, DHCP mode, serial, per-port " +
		"status/statistics, VLAN membership, PVIDs, QoS, mirroring, IGMP snooping). NSDP-capable models only." + backendDoc

	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, any, error) {
			sw, err := resolveSwitch(env, in.selectorFields)
			if err != nil {
				return nil, nil, err
			}
			defer func() { _ = sw.Close() }()

			backend, err := parseBackendName(in.Backend)
			if err != nil {
				return nil, nil, err
			}
			if backend != nil && *backend != netgearswitch.BackendNSDP {
				return jsonResult(map[string]any{
					"unsupported": true,
					"op":          name,
					"detail":      "get_device is served over NSDP only; backend " + in.Backend + " cannot serve it",
				})
			}

			v, opErr := sw.NSDPDevice(ctx)
			return jsonResult(readResult(name, v, opErr))
		})
}
