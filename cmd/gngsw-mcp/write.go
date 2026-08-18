// write.go: the 18 write tools, registered ONLY when writesEnabled(env)
// (see server.go's BuildServer), mirroring server.py's
// `_register_write_tools` one-for-one. Every disruptive op still requires
// the caller to pass force=true -- the same rail the CLI and library
// enforce -- forwarded unchanged to the facade as netgearswitch.Write.Force.
//
// upload_certificate/upload_certificate_scp deliberately take NO `backend`
// field: mirroring server.py's own comment on both tools verbatim, offering
// a backend knob there would be a knob that does nothing (principle 1) --
// upload_certificate IS the web UI's HTTP mechanism and upload_certificate_scp
// IS the separate CLI/SCP mechanism; a caller picks between them by NAME,
// not by parameter.
package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runWrite is the shared body every write tool (other than the two
// certificate-upload tools) delegates to: resolve the switch, parse
// `backend`, run action, shape the outcome via writeResult -- mirroring
// server.py's `sw = resolver(...); chosen = _as_backend(backend); return
// _write(name, lambda: sw.method(..., backend=chosen))` shape exactly.
func runWrite(ctx context.Context, env EnvFunc, sel selectorFields, backendStr, opName string, action func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error) (*mcp.CallToolResult, any, error) {
	sw, err := resolveSwitch(env, sel)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = sw.Close() }()

	backend, err := parseBackendName(backendStr)
	if err != nil {
		return nil, nil, err
	}
	opErr := action(ctx, sw, backend)
	return jsonResult(writeResult(opName, opErr))
}

// runWriteNoBackend is runWrite's twin for upload_certificate/
// upload_certificate_scp, which never parse or forward a backend at all.
func runWriteNoBackend(ctx context.Context, env EnvFunc, sel selectorFields, opName string, action func(ctx context.Context, sw *netgearswitch.Switch) error) (*mcp.CallToolResult, any, error) {
	sw, err := resolveSwitch(env, sel)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = sw.Close() }()

	opErr := action(ctx, sw)
	return jsonResult(writeResult(opName, opErr))
}

// registerWriteTools registers all 18 write tools, in server.py's own
// registration order.
func registerWriteTools(s *mcp.Server, env EnvFunc) {
	registerSetPVID(s, env)
	registerSetPortDescription(s, env)
	registerSetPortSpeed(s, env)
	registerAddSyslogCollector(s, env)
	registerRemoveSyslogCollector(s, env)
	registerSetFlowControl(s, env)
	registerSetHostname(s, env)
	registerSetSyslogEnabled(s, env)
	registerSetPortEnabled(s, env)
	registerSetPoE(s, env)
	registerSetVlanMembership(s, env)
	registerCreateVlan(s, env)
	registerDeleteVlan(s, env)
	registerCyclePoE(s, env)
	registerClearPoEFault(s, env)
	registerSetMgmtIP(s, env)
	registerUploadCertificate(s, env)
	registerUploadCertificateSCP(s, env)
}

// --- set_pvid ---------------------------------------------------------

type setPVIDIn struct {
	Port  int  `json:"port" jsonschema:"port number"`
	Vlan  int  `json:"vlan" jsonschema:"VLAN id to set as this port's PVID"`
	Force bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetPVID(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_pvid",
		Description: "Set a port's PVID (native VLAN). Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setPVIDIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_pvid", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetPVID(ctx, in.Port, in.Vlan, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_port_description ----------------------------------------------

type setPortDescriptionIn struct {
	Port        int    `json:"port" jsonschema:"port number"`
	Description string `json:"description" jsonschema:"port description; an empty string clears it"`
	Force       bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetPortDescription(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_port_description",
		Description: "Set a port's description. Pass an empty string to clear it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setPortDescriptionIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_port_description", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetPortDescription(ctx, in.Port, in.Description, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_port_speed -----------------------------------------------------

type setPortSpeedIn struct {
	Port   int    `json:"port" jsonschema:"port number"`
	Rate   string `json:"rate" jsonschema:"'auto', or a forced rate spelled as the switch spells it ('100', '10G')"`
	Duplex string `json:"duplex,omitempty" jsonschema:"'full' (default) or 'half'; ignored for rate 'auto'"`
	Force  bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

// parsePortRate mirrors server.py's set_port_speed inline rate parse:
// "auto" (case/whitespace-insensitive) -> AutoPortSpeed(); else the token
// upper-cased, "G" meaning *1000 -- e.g. "100" -> 100Mbit, "10G" ->
// 10000Mbit. ok is false when rate is neither, mirroring the ValueError
// branch server.py catches around its own int() conversion.
func parsePortRate(rate string) (mbps int, ok bool) {
	token := strings.ToUpper(strings.TrimSpace(rate))
	if strings.HasSuffix(token, "G") {
		n, err := strconv.Atoi(strings.TrimSuffix(token, "G"))
		if err != nil {
			return 0, false
		}
		return n * 1000, true
	}
	n, err := strconv.Atoi(token)
	if err != nil {
		return 0, false
	}
	return n, true
}

func registerSetPortSpeed(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "set_port_speed",
		Description: "Force a port's speed/duplex, or restore auto-negotiation. rate is \"auto\", or a forced rate " +
			"spelled as the switch spells it (\"100\", \"10G\"). 1000 cannot be FORCED -- 1000BASE-T requires " +
			"auto-negotiation and the firmware's grammar omits it. Disruptive: applying either setting bounces the link.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setPortSpeedIn) (*mcp.CallToolResult, any, error) {
		// Mirrors server.py: the rate is parsed BEFORE resolving the switch,
		// and an unparseable rate returns a structured (non-error) result
		// DIRECTLY -- note this shape has NO "op" key, unlike every other
		// structured-error result in this package (server.py's own
		// `{"ok": False, "error": ...}` literal, distinct from `_write`'s
		// shapes).
		duplex := in.Duplex
		if duplex == "" {
			duplex = "full"
		}
		var speed netgearswitch.PortSpeed
		if strings.ToLower(strings.TrimSpace(in.Rate)) == "auto" {
			speed = netgearswitch.AutoPortSpeed()
		} else {
			mbps, ok := parsePortRate(in.Rate)
			if !ok {
				return jsonResult(map[string]any{
					"ok":    false,
					"error": fmt.Sprintf("not a port rate: %s (try 'auto', '100', '10G')", pyRepr(in.Rate)),
				})
			}
			speed = netgearswitch.ForcedPortSpeed(mbps, duplex == "full")
		}
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_port_speed", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetPortSpeed(ctx, in.Port, speed, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- add_syslog_collector / remove_syslog_collector ---------------------

type addSyslogCollectorIn struct {
	HostAddress string `json:"host_address" jsonschema:"remote syslog collector address (where logs are SENT; distinct from the switch selector 'host')"`
	// Port is *int (not int), mirroring Severity below: server.py's
	// `port: int = 514` is a plain Python default parameter, which FastMCP
	// binds straight through -- the 514 default applies ONLY when a caller
	// OMITS `port` from the call entirely, never when they pass an explicit
	// `0` (Python has no way to distinguish "not given" from "given as the
	// zero value" other than a sentinel/Optional, and this parameter uses
	// neither, so an explicit 0 reaches sw.add_syslog_collector(port=0)
	// unchanged). A plain `int` here would collapse both cases (omitted,
	// and explicitly 0) onto the same Go zero value, silently over-riding a
	// caller's explicit `"port": 0` to 514 -- exactly the bug this pointer
	// avoids.
	Port     *int `json:"port,omitempty" jsonschema:"collector UDP port (default: 514)"`
	Severity *int `json:"severity,omitempty" jsonschema:"forward messages at or above this severity (0 emergency .. 7 debug; default: 6 info)"`
	Force    bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

// addSyslogCollectorPort resolves add_syslog_collector's `port` argument,
// mirroring Python's `port: int = 514` FastMCP binding exactly: nil (the
// field was OMITTED from the call) defaults to 514; any non-nil value
// (INCLUDING a pointer to 0) passes through unchanged -- an explicit
// `"port": 0` must never collapse onto the same default 514 an omitted
// `port` gets. Pulled out as its own function so this exact defaulting
// arithmetic is unit-testable without a live switch (see write_test.go).
func addSyslogCollectorPort(port *int) int {
	if port != nil {
		return *port
	}
	return 514
}

func registerAddSyslogCollector(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "add_syslog_collector",
		Description: "Add a remote syslog collector (FASTPATH CLI only). host_address is where logs are SENT; host " +
			"stays the switch selector. severity is the standard syslog number, 0 emergency to 7 debug, and the " +
			"switch forwards messages at or above it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in addSyslogCollectorIn) (*mcp.CallToolResult, any, error) {
		port := addSyslogCollectorPort(in.Port)
		severity := 6
		if in.Severity != nil {
			severity = *in.Severity
		}
		return runWrite(ctx, env, in.selectorFields, in.Backend, "add_syslog_collector", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.AddSyslogCollector(ctx, in.HostAddress, port, severity, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

type removeSyslogCollectorIn struct {
	HostAddress string `json:"host_address" jsonschema:"remote syslog collector address to remove"`
	Force       bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerRemoveSyslogCollector(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "remove_syslog_collector",
		Description: "Remove a remote syslog collector (FASTPATH CLI only).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in removeSyslogCollectorIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "remove_syslog_collector", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.RemoveSyslogCollector(ctx, in.HostAddress, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_flow_control -----------------------------------------------------

type setFlowControlIn struct {
	Port    int  `json:"port" jsonschema:"port number"`
	Enabled bool `json:"enabled" jsonschema:"true to turn flow control on, false to turn it off"`
	Force   bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetFlowControl(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "set_flow_control",
		Description: "Turn IEEE 802.3x flow control on or off for a port. Served over the FASTPATH CLI only. " +
			"Disruptive: pause frames change how the link behaves under congestion.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setFlowControlIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_flow_control", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetFlowControl(ctx, in.Port, in.Enabled, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_hostname -----------------------------------------------------

type setHostnameIn struct {
	Name  string `json:"name" jsonschema:"new host name"`
	Force bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetHostname(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_hostname",
		Description: "Set the switch's host name. Reversible by writing the old name back.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setHostnameIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_hostname", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetHostname(ctx, in.Name, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_syslog_enabled --------------------------------------------------

type setSyslogEnabledIn struct {
	Enabled bool `json:"enabled" jsonschema:"true to turn remote logging on, false to turn it off"`
	Force   bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetSyslogEnabled(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_syslog_enabled",
		Description: "Turn remote logging on or off. Does not change the collector list.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setSyslogEnabledIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_syslog_enabled", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetSyslogEnabled(ctx, in.Enabled, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_port_enabled -----------------------------------------------------

type setPortEnabledIn struct {
	Port    int  `json:"port" jsonschema:"port number"`
	Enabled bool `json:"enabled" jsonschema:"true to administratively enable the port, false to disable it"`
	Force   bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetPortEnabled(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_port_enabled",
		Description: "Administratively enable/disable a port. Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setPortEnabledIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_port_enabled", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetPortEnabled(ctx, in.Port, in.Enabled, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_poe -----------------------------------------------------------

type setPoEIn struct {
	Port  int  `json:"port" jsonschema:"port number"`
	On    bool `json:"on" jsonschema:"true to turn PoE on, false to turn it off"`
	Force bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetPoE(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_poe",
		Description: "Turn a port's PoE on/off. Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setPoEIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_poe", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetPoE(ctx, in.Port, in.On, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_vlan_membership -------------------------------------------------

// vlanModes maps set_vlan_membership's mode string to netgearswitch.VlanMode,
// mirroring server.py's `VlanMode(mode)` enum conversion.
var vlanModes = map[string]netgearswitch.VlanMode{
	"untagged": netgearswitch.VlanUntagged,
	"tagged":   netgearswitch.VlanTagged,
	"excluded": netgearswitch.VlanExcluded,
}

type setVlanMembershipIn struct {
	Vlan  int    `json:"vlan" jsonschema:"VLAN id"`
	Port  int    `json:"port" jsonschema:"port number"`
	Mode  string `json:"mode" jsonschema:"membership mode: tagged|untagged|excluded"`
	Force bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetVlanMembership(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "set_vlan_membership",
		Description: "Set a port's membership in a VLAN (mode: tagged|untagged|excluded). " +
			"Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setVlanMembershipIn) (*mcp.CallToolResult, any, error) {
		// Mirrors server.py: the mode is validated BEFORE resolving the
		// switch, and an invalid mode returns `_write`'s own {"error":...,
		// "op":...} shape directly (as a normal, non-error result).
		mode, ok := vlanModes[in.Mode]
		if !ok {
			return jsonResult(map[string]any{
				"error": fmt.Sprintf("invalid mode %s: use tagged|untagged|excluded", pyRepr(in.Mode)),
				"op":    "set_vlan_membership",
			})
		}
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_vlan_membership", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetVlanMembership(ctx, in.Vlan, in.Port, mode, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- create_vlan / delete_vlan -------------------------------------------

type createVlanIn struct {
	Vlan  int    `json:"vlan" jsonschema:"VLAN id to create"`
	Name  string `json:"name" jsonschema:"VLAN name"`
	Force bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerCreateVlan(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_vlan",
		Description: "Create a VLAN. Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in createVlanIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "create_vlan", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.CreateVlan(ctx, in.Vlan, in.Name, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

type deleteVlanIn struct {
	Vlan  int  `json:"vlan" jsonschema:"VLAN id to delete"`
	Force bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerDeleteVlan(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_vlan",
		Description: "Delete a VLAN. Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in deleteVlanIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "delete_vlan", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.DeleteVlan(ctx, in.Vlan, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- cycle_poe / clear_poe_fault -----------------------------------------

type cyclePoEIn struct {
	Port  int  `json:"port" jsonschema:"port number"`
	Force bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerCyclePoE(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "cycle_poe",
		Description: "Power-cycle a port's PoE (off, wait, on) -- reboots the attached powered device. " +
			"Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in cyclePoEIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "cycle_poe", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.CyclePoE(ctx, in.Port, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

type clearPoEFaultIn struct {
	Port  int  `json:"port" jsonschema:"port number"`
	Force bool `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerClearPoEFault(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "clear_poe_fault",
		Description: "Clear a port's latched PoE fault by cycling its power. Disruptive: needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clearPoEFaultIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "clear_poe_fault", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.ClearPoEFault(ctx, in.Port, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- set_mgmt_ip -----------------------------------------------------

type setMgmtIPIn struct {
	Address string `json:"address" jsonschema:"static management IP address"`
	Netmask string `json:"netmask" jsonschema:"management IP netmask"`
	Gateway string `json:"gateway" jsonschema:"management IP gateway"`
	Force   bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
	backendField
}

func registerSetMgmtIP(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "set_mgmt_ip",
		Description: "Set the switch's static management IP, netmask and gateway. HIGHLY disruptive -- changing " +
			"this can make the switch unreachable at its current address. Needs force=true.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setMgmtIPIn) (*mcp.CallToolResult, any, error) {
		return runWrite(ctx, env, in.selectorFields, in.Backend, "set_mgmt_ip", func(ctx context.Context, sw *netgearswitch.Switch, backend *model.Backend) error {
			return sw.SetMgmtIP(ctx, in.Address, in.Netmask, in.Gateway, netgearswitch.Write{Force: in.Force, Backend: backend})
		})
	})
}

// --- upload_certificate / upload_certificate_scp -------------------------

type uploadCertificateIn struct {
	CertPEM string `json:"cert_pem" jsonschema:"PEM certificate text"`
	KeyPEM  string `json:"key_pem" jsonschema:"PEM private-key text"`
	Force   bool   `json:"force,omitempty" jsonschema:"override protected-port and other force-gates"`
	selectorFields
}

func registerUploadCertificate(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "upload_certificate",
		Description: "Upload an HTTPS SSL server certificate + private key (both PEM text) to the switch. " +
			"Implemented for gsm7228ps/S3300; a model whose mechanism is known but not yet implemented reports " +
			"that honestly. HIGHLY disruptive -- replaces the running certificate. Needs force=true. Deliberately " +
			"takes NO 'backend' parameter: this op is the web UI's certificate upload specifically, and " +
			"upload_certificate_scp is the separate CLI/SCP mechanism.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in uploadCertificateIn) (*mcp.CallToolResult, any, error) {
		return runWriteNoBackend(ctx, env, in.selectorFields, "upload_certificate", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.UploadCertificate(ctx, in.CertPEM, in.KeyPEM, in.Force)
		})
	})
}

type uploadCertificateSCPIn struct {
	SCPSource   string `json:"scp_source" jsonschema:"SCP source the switch pulls the staged PEM from (user@host[:port])"`
	SCPPassword string `json:"scp_password" jsonschema:"password for the SCP source"`
	RemoteDir   string `json:"remote_dir" jsonschema:"directory on the SCP source holding the staged PEM(s)"`
	Chain       bool   `json:"chain,omitempty" jsonschema:"also copy the CA-chain PEM to nvram:sslpem-root"`
	selectorFields
}

func registerUploadCertificateSCP(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "upload_certificate_scp",
		Description: "Deploy an HTTPS SSL certificate over SCP to a FASTPATH switch (M4300/GSM7252PS): the switch " +
			"pulls the PEM the CALLER has already staged on scp_source (user@host[:port]) under remote_dir. Only " +
			"these FASTPATH models; every other model reports unsupported. HIGHLY disruptive -- replaces the " +
			"running certificate (toggles the secure web server). Takes NO 'backend' parameter: this IS the " +
			"CLI/SCP mechanism, the sibling of the web UI's upload_certificate.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in uploadCertificateSCPIn) (*mcp.CallToolResult, any, error) {
		return runWriteNoBackend(ctx, env, in.selectorFields, "upload_certificate_scp", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.UploadCertificateSCP(ctx, in.SCPSource, in.SCPPassword, in.RemoteDir, in.Chain)
		})
	})
}
