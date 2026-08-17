// Package fastpath ports src/netgear_switch/protocols/cli/commands.py --
// the per-model FASTPATH device-CLI command specs -- pure data (which
// command string each op sends, per model) plus the small set of templating
// methods that build the final command string for a per-port/per-VLAN op.
// It is the CLI-protocol analogue of the webui package's HTTPModelSpec.
//
// Ported field-for-field from the pinned
// python-netgear-switch-library @ 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362,
// src/netgear_switch/protocols/cli/commands.py (441 lines). Field mapping
// notes (Python -> Go), mirroring the conventions already established by
// webui.HTTPModelSpec (see that package's doc comment):
//
//   - Every `str | None` field on the Python CliModelSpec dataclass becomes
//     a plain Go string, with "" standing in for Python's None -- none of
//     these fields (command templates) can legitimately be the empty
//     string, so "" is an unambiguous sentinel. This applies to
//     UplinkIfaceTemplate and SwitchportGeneralCmd.
//   - `int | None` (FirstUplinkPort) becomes *int, since 0 is not "unset"
//     for a port number and nil is the only unambiguous "not set" value --
//     the same reasoning webui.HTTPModelSpec.WebPort already uses.
//   - `tuple[str, ...]` (MgmtIPExecCmds / MgmtIPConfigCmds) becomes
//     []string. Every CliModelSpec value in this file is a package-level
//     var populated once and never mutated after init -- treat every slice
//     field as read-only, exactly as the Python frozen dataclass enforces
//     at runtime there.
//   - The Python `_CliCmdOverrides` TypedDict (commands.py:236-244) --
//     "typed so ** splatting into CliModelSpec cannot touch telnet_port or
//     any other int field" -- becomes the M4300Overrides struct below: a
//     small, explicitly-typed value with exactly its 4 fields, applied via
//     applyM4300Overrides rather than untyped map splatting, preserving the
//     same compile-time guarantee the dossier calls for (§1.4).
package fastpath

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// cliBackends mirrors Python CLI_BACKENDS (commands.py:60): the three
// transports that all speak the identical FASTPATH shell protocol. A model
// with ANY of these three backends uses the CliModelSpec machinery.
// BackendConsole is included for parity with the Python frozenset even
// though (per model/registry.go's own doc comment) no model in this
// registry currently carries it.
var cliBackends = []model.Backend{model.BackendSSH, model.BackendTelnet, model.BackendConsole}

// hasCLIBackend reports whether m carries any of cliBackends, mirroring
// Python's `CLI_BACKENDS & model.backends` truthiness check.
func hasCLIBackend(m *model.SwitchModel) bool {
	for _, b := range cliBackends {
		if m.HasBackend(b) {
			return true
		}
	}
	return false
}

// CliModelSpec is the per-model FASTPATH CLI command spec: which command
// string each read op issues, the config-mode command sequence each write
// op issues, session-setup commands, and the per-model physical-interface
// naming template every per-port command is addressed through. Mirrors
// Python protocols.cli.commands.CliModelSpec (all fields, commands.py:63-
// 173) field-for-field. Every CliModelSpec value in this package is
// populated once at init and never mutated afterward -- treat it as
// read-only.
type CliModelSpec struct {
	ModelKey       string
	Captured       bool
	ReadsVerified  bool
	WritesVerified bool

	// TelnetPort is the TCP port the TELNET transport dials for this model.
	// Standard telnet is 23; only gsm7228ps overrides it (60000).
	TelnetPort int

	// Session setup, run once after the shell opens.
	EnableCmd    string
	PagingOffCmd string

	// Read-op commands. The two templated ones (VlanDetailCmd,
	// InterfaceStatsCmd) are formatted via VlanDetail/InterfaceStats below.
	VersionCmd        string
	PortStatusCmd     string
	VlanBriefCmd      string
	VlanDetailCmd     string
	PvidCmd           string
	MacTableCmd       string
	LldpCmd           string
	PoeCmd            string
	EnvironmentCmd    string
	NetworkCmd        string
	InterfaceStatsCmd string
	// UsersCmd/HTTPServiceCmd/TelnetServiceCmd/SSHServiceCmd: local login
	// accounts and management-service state. Constant across every FASTPATH
	// model (no per-model override exists in commands.py:139-147) --
	// HTTPServiceCmd deliberately covers BOTH the plain and secure web
	// servers in one command, and TelnetServiceCmd is "show telnetcon", NOT
	// "show telnet" (which reports the switch as an outbound telnet CLIENT,
	// not the inbound server this library's TELNET backend connects to).
	UsersCmd         string
	HTTPServiceCmd   string
	TelnetServiceCmd string
	SSHServiceCmd    string
	// HostsCmd is "show hosts" (get_hostname): deliberately NOT "show
	// running-config | include hostname" -- the two report different values
	// on real hardware, and only this one agrees with SNMP's sysName. See
	// snmp.SysName's own doc comment for the measured m4300-16x example.
	// Constant across every FASTPATH model (no per-model override exists in
	// commands.py).
	HostsCmd string
	// LoggingCmd/LoggingHostsCmd are "show logging" / "show logging hosts"
	// (get_syslog): two commands because the switch splits it that way --
	// the globals (admin mode, local port) live in the first, the
	// collectors in the second. Constant across every FASTPATH model (no
	// per-model override exists in commands.py).
	LoggingCmd      string
	LoggingHostsCmd string

	// --- physical-interface naming -----------------------------------
	// IfaceTemplate is how this model's firmware ADDRESSES one physical
	// port in a command. UplinkIfaceTemplate/FirstUplinkPort are set
	// TOGETHER only on a model whose uplink ports carry a different prefix
	// than its access ports (gsm7228ps); "" / nil means "one template for
	// all ports" -- true of every Fully Managed model. See Iface below for
	// the exact branch condition (the hazard the brief calls out).
	IfaceTemplate       string
	UplinkIfaceTemplate string
	FirstUplinkPort     *int

	// --- write (config-mode) commands ---------------------------------
	VlanDatabaseCmd string
	VlanCreateCmd   string
	VlanNameCmd     string
	VlanDeleteCmd   string
	ConfigureCmd    string
	InterfaceCmd    string
	// SwitchportGeneralCmd is "" when this firmware image has NO
	// switchport-mode concept at all (gsm7252ps) -- the write path must not
	// send it in that case.
	SwitchportGeneralCmd string
	VlanParticipationCmd string
	VlanTaggingCmd       string
	VlanNoTaggingCmd     string
	VlanPvidCmd          string
	// PortDescriptionCmd/PortNoDescriptionCmd are the interface-config-mode
	// per-port label commands (set_port_description). The single quotes in
	// PortDescriptionCmd's default are the firmware's OWN form: READ OFF a
	// live GSM7252PS (10.1.5.22, 2026-08-03) whose `show running-config`
	// renders its labelled ports as `description 'eth0.rpi5-pmod'`.
	PortDescriptionCmd   string
	PortNoDescriptionCmd string
	// PortDescriptionShowCmd is the per-port command that reports a
	// description BACK -- `show port all` carries no description column, so
	// SetPortDescription's verify-after-write goes through this instead.
	PortDescriptionShowCmd string
	// PortSpeedAutoCmd/PortSpeedForcedCmd are the interface-config-mode
	// per-port speed/duplex commands (set_port_speed). Both grammars were
	// PROVEN BY EXECUTION on gsm7252ps 10.1.5.22 port 1/0/8 (2026-08-03,
	// link-down, undescribed, restored afterward): "speed 100 full-duplex"
	// moved Physical Mode to "100 Full", "speed auto" moved it back. No
	// per-model rate table is kept -- the forced rates a port offers follow
	// its PHY, not the firmware, so an unsupported rate is sent unchecked
	// and the device's own "% Invalid input" surfaces through the writer's
	// treat-any-output-as-failure rule.
	PortSpeedAutoCmd   string
	PortSpeedForcedCmd string
	// PortFlowControlCmd/PortNoFlowControlCmd are the interface-config-mode
	// IEEE 802.3x flow-control bare toggles (set_flow_control) -- PROVEN as
	// a full round trip on gsm7252ps 10.1.5.22 port 1/0/8, 2026-08-03.
	PortFlowControlCmd   string
	PortNoFlowControlCmd string
	ExitCmd              string
	PoeEnableCmd         string
	PoeDisableCmd        string
	PoeResetCmd          string
	PortEnableCmd        string
	PortDisableCmd       string
	// HostnameConfigCmd is "hostname {name}" (set_hostname), a global-config
	// command -- NOT interface-scoped. Constant across every FASTPATH model
	// (no per-model override exists in commands.py).
	HostnameConfigCmd string
	// LoggingSyslogCmd/LoggingNoSyslogCmd are the global-config remote-
	// logging enable/disable (set_syslog_enabled). LoggingSyslogCmd is
	// VERBATIM from every switch's own `show running-config` (all four
	// FASTPATH models print the bare line "logging syslog", read
	// 2026-08-05); the negation is the standard FASTPATH "no" and is
	// inferred -- a wrong form is rejected by the device and raised, never
	// swallowed. Constant across every FASTPATH model (no per-model
	// override exists in commands.py).
	LoggingSyslogCmd   string
	LoggingNoSyslogCmd string
	// MgmtIPExecCmds / MgmtIPConfigCmds: exactly one is non-empty per model
	// (commands.py:167) -- the two management-IP write dialects (privileged
	// EXEC "network parms ..." vs global-config "ip management address ..."
	// + "ip default-gateway ...").
	MgmtIPExecCmds   []string
	MgmtIPConfigCmds []string
	ReloadCmd        string
}

// formatOne replaces the single placeholder "{name}" in tmpl with value.
// Every CliModelSpec command template has each placeholder name appear at
// most once, so a single non-overlapping replace is exact (mirrors Python's
// str.format(name=value) for that placeholder).
func formatOne(tmpl, name, value string) string {
	return strings.Replace(tmpl, "{"+name+"}", value, 1)
}

// VlanDetail returns VlanDetailCmd with {vlan} filled in, mirroring Python
// CliModelSpec.vlan_detail (commands.py:175-176).
func (s *CliModelSpec) VlanDetail(vlan int) string {
	return formatOne(s.VlanDetailCmd, "vlan", strconv.Itoa(vlan))
}

// Iface returns the interface NAME this firmware addresses physical port
// by, mirroring Python CliModelSpec.iface (commands.py:178-186) EXACTLY:
// the uplink template applies only when BOTH UplinkIfaceTemplate is set AND
// FirstUplinkPort is set AND port >= *FirstUplinkPort ("at and after", not
// "strictly after") -- getting this branch wrong silently addresses the
// wrong physical interface (the hazard called out by the task brief).
func (s *CliModelSpec) Iface(port int) string {
	if s.UplinkIfaceTemplate != "" && s.FirstUplinkPort != nil && port >= *s.FirstUplinkPort {
		return formatOne(s.UplinkIfaceTemplate, "port", strconv.Itoa(port))
	}
	return formatOne(s.IfaceTemplate, "port", strconv.Itoa(port))
}

// InterfaceStats returns InterfaceStatsCmd templated with Iface(port),
// mirroring Python CliModelSpec.interface_stats (commands.py:188-189).
func (s *CliModelSpec) InterfaceStats(port int) string {
	return formatOne(s.InterfaceStatsCmd, "iface", s.Iface(port))
}

// VlanCreate returns VlanCreateCmd with {vlan} filled in, mirroring Python
// CliModelSpec.vlan_create (commands.py:191-192).
func (s *CliModelSpec) VlanCreate(vlan int) string {
	return formatOne(s.VlanCreateCmd, "vlan", strconv.Itoa(vlan))
}

// VlanName returns VlanNameCmd with {vlan} and {name} filled in, mirroring
// Python CliModelSpec.vlan_name (commands.py:194-195).
func (s *CliModelSpec) VlanName(vlan int, name string) string {
	out := formatOne(s.VlanNameCmd, "vlan", strconv.Itoa(vlan))
	return formatOne(out, "name", name)
}

// VlanDelete returns VlanDeleteCmd with {vlan} filled in, mirroring Python
// CliModelSpec.vlan_delete (commands.py:197-198).
func (s *CliModelSpec) VlanDelete(vlan int) string {
	return formatOne(s.VlanDeleteCmd, "vlan", strconv.Itoa(vlan))
}

// Interface returns InterfaceCmd templated with Iface(port), mirroring
// Python CliModelSpec.interface (commands.py:200-201).
func (s *CliModelSpec) Interface(port int) string {
	return formatOne(s.InterfaceCmd, "iface", s.Iface(port))
}

// VlanParticipation returns VlanParticipationCmd with {action} ("include"
// or "exclude") and {vlan} filled in, mirroring Python
// CliModelSpec.vlan_participation (commands.py:203-206).
func (s *CliModelSpec) VlanParticipation(vlan int, include bool) string {
	action := "exclude"
	if include {
		action = "include"
	}
	out := formatOne(s.VlanParticipationCmd, "action", action)
	return formatOne(out, "vlan", strconv.Itoa(vlan))
}

// VlanTagging returns VlanTaggingCmd or VlanNoTaggingCmd (selected by
// tagged) with {vlan} filled in, mirroring Python
// CliModelSpec.vlan_tagging (commands.py:208-210).
func (s *CliModelSpec) VlanTagging(vlan int, tagged bool) string {
	cmd := s.VlanNoTaggingCmd
	if tagged {
		cmd = s.VlanTaggingCmd
	}
	return formatOne(cmd, "vlan", strconv.Itoa(vlan))
}

// VlanPvid returns VlanPvidCmd with {vlan} filled in, mirroring Python
// CliModelSpec.vlan_pvid (commands.py:212-213).
func (s *CliModelSpec) VlanPvid(vlan int) string {
	return formatOne(s.VlanPvidCmd, "vlan", strconv.Itoa(vlan))
}

// PortDescription returns PortNoDescriptionCmd for an empty text (clearing
// the label), or PortDescriptionCmd with {text} filled in otherwise,
// mirroring Python CliModelSpec.port_description.
func (s *CliModelSpec) PortDescription(text string) string {
	if text == "" {
		return s.PortNoDescriptionCmd
	}
	return formatOne(s.PortDescriptionCmd, "text", text)
}

// PortDescriptionShow returns PortDescriptionShowCmd templated with
// Iface(port), mirroring Python CliModelSpec.port_description_show.
func (s *CliModelSpec) PortDescriptionShow(port int) string {
	return formatOne(s.PortDescriptionShowCmd, "iface", s.Iface(port))
}

// fastpathRate renders mbps the way FASTPATH spells a port rate in a
// "speed" command, mirroring Python's module-level fastpath_rate
// (commands.py:81-90): sub-gigabit rates go as bare Mbit/s ("100"), gigabit
// multiples take the "G" suffix ("10000" -> "10G"). Not a lookup table --
// this is a formatting rule applied to whatever rate the caller asks for,
// including one this firmware doesn't have; the device's own "% Invalid
// input" is what surfaces for that, through the writer's
// treat-any-output-as-failure convention.
func fastpathRate(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%dG", mbps/1000)
	}
	return strconv.Itoa(mbps)
}

// PortSpeed returns the interface-config command that applies speed,
// mirroring Python CliModelSpec.port_speed: PortSpeedAutoCmd for an
// auto-negotiating configuration, or PortSpeedForcedCmd with {rate}/{duplex}
// filled in for a forced one. Callers must not pass a forced PortSpeed with
// a nil SpeedMbps/FullDuplex (model.ForcedPortSpeed's own invariant, mirrors
// Python's `assert speed.speed_mbps is not None`); this method trusts that
// invariant rather than re-checking it.
func (s *CliModelSpec) PortSpeed(speed model.PortSpeed) string {
	if speed.Autonegotiate {
		return s.PortSpeedAutoCmd
	}
	rate := fastpathRate(*speed.SpeedMbps)
	duplex := "half"
	if speed.FullDuplex != nil && *speed.FullDuplex {
		duplex = "full"
	}
	out := formatOne(s.PortSpeedForcedCmd, "rate", rate)
	return formatOne(out, "duplex", duplex)
}

// PortFlowControl returns PortFlowControlCmd or PortNoFlowControlCmd,
// mirroring Python CliModelSpec.port_flow_control.
func (s *CliModelSpec) PortFlowControl(enabled bool) string {
	if enabled {
		return s.PortFlowControlCmd
	}
	return s.PortNoFlowControlCmd
}

// PoeAdmin returns PoeEnableCmd or PoeDisableCmd, mirroring Python
// CliModelSpec.poe_admin (commands.py:215-216).
func (s *CliModelSpec) PoeAdmin(on bool) string {
	if on {
		return s.PoeEnableCmd
	}
	return s.PoeDisableCmd
}

// PortAdmin returns PortEnableCmd or PortDisableCmd, mirroring Python
// CliModelSpec.port_admin (commands.py:218-219).
func (s *CliModelSpec) PortAdmin(enabled bool) string {
	if enabled {
		return s.PortEnableCmd
	}
	return s.PortDisableCmd
}

// HostnameConfig returns HostnameConfigCmd with {name} filled in, mirroring
// Python CliModelSpec's `hostname_config_cmd.format(name=name)` use in
// CliWriter.set_hostname.
func (s *CliModelSpec) HostnameConfig(name string) string {
	return formatOne(s.HostnameConfigCmd, "name", name)
}

// LoggingSyslog returns LoggingSyslogCmd when enabled, else
// LoggingNoSyslogCmd, mirroring Python CliModelSpec.logging_syslog
// (commands.py:389-390).
func (s *CliModelSpec) LoggingSyslog(enabled bool) string {
	if enabled {
		return s.LoggingSyslogCmd
	}
	return s.LoggingNoSyslogCmd
}

// MgmtIP returns (execCmds, configCmds) with {address}/{netmask}/{gateway}
// filled in on every entry of MgmtIPExecCmds/MgmtIPConfigCmds, mirroring
// Python CliModelSpec.mgmt_ip (commands.py:221-233). Exactly one of the two
// returned slices is non-empty, per this model's dialect.
func (s *CliModelSpec) MgmtIP(address, netmask, gateway string) (execCmds, configCmds []string) {
	fill := func(tmpl string) string {
		out := formatOne(tmpl, "address", address)
		out = formatOne(out, "netmask", netmask)
		return formatOne(out, "gateway", gateway)
	}
	for _, c := range s.MgmtIPExecCmds {
		execCmds = append(execCmds, fill(c))
	}
	for _, c := range s.MgmtIPConfigCmds {
		configCmds = append(configCmds, fill(c))
	}
	return execCmds, configCmds
}

// M4300Overrides is the subset of CliModelSpec command fields a model may
// override via applyM4300Overrides, mirroring Python's _CliCmdOverrides
// TypedDict (commands.py:236-244) -- explicitly typed to exactly these 4
// fields so it cannot touch TelnetPort or any other field, the same
// compile-time guarantee the Python TypedDict's docstring calls for.
type M4300Overrides struct {
	VlanBriefCmd     string
	NetworkCmd       string
	MgmtIPExecCmds   []string
	MgmtIPConfigCmds []string
}

// M4300OverridesValue is the exact _M4300_OVERRIDES dict (commands.py:259-
// 267): M4300 FASTPATH 12.0.13.8 renamed "show vlan brief" -> "show vlan"
// and "show network" -> "show ip management", and replaced the
// privileged-EXEC "network parms ..." management-IP write with the
// global-config pair "ip management address ..." + "ip default-gateway
// ...".
var M4300OverridesValue = M4300Overrides{
	VlanBriefCmd:   "show vlan",
	NetworkCmd:     "show ip management",
	MgmtIPExecCmds: nil, // () -- this image rejects "network parms" outright
	MgmtIPConfigCmds: []string{
		"ip management address {address} {netmask}",
		"ip default-gateway {gateway}",
	},
}

// applyM4300Overrides sets exactly the 4 M4300Overrides fields on s,
// leaving every other field at whatever newCliModelSpec already set,
// mirroring Python's `CliModelSpec(..., **_M4300_OVERRIDES)` splat.
func applyM4300Overrides(s *CliModelSpec) {
	s.VlanBriefCmd = M4300OverridesValue.VlanBriefCmd
	s.NetworkCmd = M4300OverridesValue.NetworkCmd
	s.MgmtIPExecCmds = M4300OverridesValue.MgmtIPExecCmds
	s.MgmtIPConfigCmds = M4300OverridesValue.MgmtIPConfigCmds
}

// newCliModelSpec builds a CliModelSpec with every field set to the Python
// CliModelSpec dataclass's default value (commands.py:63-173), for the
// given model_key/captured/reads_verified -- the 3 fields every one of the
// 4 model constructors below supplies explicitly. Per-model callers then
// override only the fields their model's own CliModelSpec(...) call names.
func newCliModelSpec(modelKey string, captured, readsVerified bool) CliModelSpec {
	return CliModelSpec{
		ModelKey:       modelKey,
		Captured:       captured,
		ReadsVerified:  readsVerified,
		WritesVerified: true,
		TelnetPort:     23,

		EnableCmd:    "enable",
		PagingOffCmd: "terminal length 0",

		VersionCmd:        "show version",
		PortStatusCmd:     "show port all",
		VlanBriefCmd:      "show vlan brief",
		VlanDetailCmd:     "show vlan {vlan}",
		PvidCmd:           "show vlan port all",
		MacTableCmd:       "show mac-addr-table",
		LldpCmd:           "show lldp remote-device all",
		PoeCmd:            "show poe port info all",
		EnvironmentCmd:    "show environment",
		NetworkCmd:        "show network",
		InterfaceStatsCmd: "show interface ethernet {iface}",

		UsersCmd:         "show users",
		HTTPServiceCmd:   "show ip http",
		TelnetServiceCmd: "show telnetcon",
		SSHServiceCmd:    "show ip ssh",
		HostsCmd:         "show hosts",
		LoggingCmd:       "show logging",
		LoggingHostsCmd:  "show logging hosts",

		IfaceTemplate:       "1/0/{port}",
		UplinkIfaceTemplate: "", // None
		FirstUplinkPort:     nil,

		VlanDatabaseCmd:        "vlan database",
		VlanCreateCmd:          "vlan {vlan}",
		VlanNameCmd:            "vlan name {vlan} {name}",
		VlanDeleteCmd:          "no vlan {vlan}",
		ConfigureCmd:           "configure",
		InterfaceCmd:           "interface {iface}",
		SwitchportGeneralCmd:   "switchport mode general",
		VlanParticipationCmd:   "vlan participation {action} {vlan}",
		VlanTaggingCmd:         "vlan tagging {vlan}",
		VlanNoTaggingCmd:       "no vlan tagging {vlan}",
		VlanPvidCmd:            "vlan pvid {vlan}",
		PortDescriptionCmd:     "description '{text}'",
		PortNoDescriptionCmd:   "no description",
		PortDescriptionShowCmd: "show port description {iface}",
		PortSpeedAutoCmd:       "speed auto",
		PortSpeedForcedCmd:     "speed {rate} {duplex}-duplex",
		PortFlowControlCmd:     "flowcontrol",
		PortNoFlowControlCmd:   "no flowcontrol",
		ExitCmd:                "exit",
		PoeEnableCmd:           "poe",
		PoeDisableCmd:          "no poe",
		PoeResetCmd:            "poe reset",
		PortEnableCmd:          "no shutdown",
		PortDisableCmd:         "shutdown",
		HostnameConfigCmd:      "hostname {name}",
		LoggingSyslogCmd:       "logging syslog",
		LoggingNoSyslogCmd:     "no logging syslog",
		MgmtIPExecCmds:         []string{"network parms {address} {netmask} {gateway}"},
		MgmtIPConfigCmds:       nil, // ()
		ReloadCmd:              "reload",
	}
}

// The four CliModelSpec instances, EXHAUSTIVE per dossier §1.6
// (commands.py:282-351): gsm7252ps, m4300-24x, m4300-16x, gsm7228ps. No 5th
// CLI model exists in the pinned source -- every other registered model
// lacks BackendSSH/BackendTelnet/BackendConsole entirely (see
// model/registry.go). "s3300" is a registry ALIAS for gsm7228ps (see
// model.GetModel), not a separate spec -- it resolves to gsm7228psSpec via
// the same _SPECS entry, exactly as Python's get_model() aliasing does.

// gsm7252psSpec: real captured transcript, live CLI<->SNMP cross-verified.
// switchport_general_cmd="" (None): this XE image has NO switchport-mode
// concept at all ("switchport mode ?" -> "% Unrecognized command").
// Everything else is the base default (commands.py:282-287).
var gsm7252psSpec = func() CliModelSpec {
	s := newCliModelSpec("gsm7252ps", true, true)
	s.SwitchportGeneralCmd = ""
	return s
}()

// m430024xSpec: real captured transcript, live CLI-verified. Takes exactly
// the 4 M4300Overrides fields; everything else (including
// SwitchportGeneralCmd and IfaceTemplate) stays the base default
// (commands.py:298-300). PoE is absent on this SKU.
var m430024xSpec = func() CliModelSpec {
	s := newCliModelSpec("m4300-24x", true, true)
	applyM4300Overrides(&s)
	return s
}()

// m430016xSpec: real captured transcript, live CLI-verified (PoE included).
// Same M4300Overrides as m430024xSpec (commands.py:313-315).
var m430016xSpec = func() CliModelSpec {
	s := newCliModelSpec("m4300-16x", true, true)
	applyM4300Overrides(&s)
	return s
}()

// gsm7228psSpec (the S3300-52X): real captured telnet transcript (port
// 60000 -- SSH is genuinely absent on this device). Takes ONLY HALF of
// M4300Overrides (VlanBriefCmd overridden to "show vlan" like the M4300s,
// but NetworkCmd stays the default "show network", NOT the M4300's "show ip
// management", and MgmtIPExecCmds stays the default privileged-EXEC
// dialect) -- so it is constructed directly, not via applyM4300Overrides.
// switchport_general_cmd stays the default "switchport mode general":
// unlike gsm7252ps, this Smart firmware DOES have switchport modes.
// Physical port naming is UNIQUE: "1/g1".."1/g48" (access, ports 1-48) and
// "1/xg49".."1/xg52" (10G uplinks, ports 49-52) -- commands.py:341-351.
var gsm7228psSpec = func() CliModelSpec {
	s := newCliModelSpec("gsm7228ps", true, true)
	s.TelnetPort = 60000
	s.VlanBriefCmd = "show vlan"
	// NetworkCmd deliberately left at its base default "show network" --
	// NOT overridden, unlike the M4300s.
	s.IfaceTemplate = "1/g{port}"
	s.UplinkIfaceTemplate = "1/xg{port}"
	firstUplinkPort := 49
	s.FirstUplinkPort = &firstUplinkPort
	return s
}()

// cliSpecs is the private, canonical model_key -> *CliModelSpec registry,
// mirroring Python's `_SPECS` (commands.py:353-355).
var cliSpecs = map[string]*CliModelSpec{
	gsm7252psSpec.ModelKey: &gsm7252psSpec,
	m430024xSpec.ModelKey:  &m430024xSpec,
	m430016xSpec.ModelKey:  &m430016xSpec,
	gsm7228psSpec.ModelKey: &gsm7228psSpec,
}

// CLISpecs is the FASTPATH CLI spec registry, mirroring Python's
// module-level CLI_SPECS mapping: model_key -> the model's CliModelSpec,
// for every one of the 4 models with a fastpath.CliModelSpec ("s3300", the
// gsm7228ps alias, deliberately does NOT appear as its own key here --
// resolve it via model.GetModel first, exactly as Python's get_model()
// does). Every entry is a pointer into this package's own frozen data;
// treat it as read-only.
var CLISpecs = cliSpecs

// CLISpec returns the FASTPATH CLI command spec for m, mirroring Python
// protocols.cli.commands.cli_spec (commands.py:431-440): a TWO-STAGE guard,
// wrapping model.ErrUnsupportedCapability with a distinct message for "no
// CLI backend at all" vs "has a CLI backend but no registered spec".
func CLISpec(m *model.SwitchModel) (*CliModelSpec, error) {
	if !hasCLIBackend(m) {
		return nil, fmt.Errorf("model %q has no CLI backend: %w", m.Key, model.ErrUnsupportedCapability)
	}
	spec, ok := cliSpecs[m.Key]
	if !ok {
		return nil, fmt.Errorf("model %q has a CLI backend but no command spec: %w", m.Key, model.ErrUnsupportedCapability)
	}
	return spec, nil
}

// ScpCertProfile is a model's FASTPATH SSL-certificate-over-SCP deploy
// profile, mirroring Python protocols.cli.commands.ScpCertProfile
// (commands.py:360-387).
type ScpCertProfile struct {
	ModelKey string
	// Crypto is "modern" or "legacy": which SSH key-exchange/host-key
	// algorithm set the switch's sshd needs.
	Crypto string
	// WritememStuff is true when "write memory"'s confirm has a tiny
	// timeout, so the "y" must be pre-stuffed in one write (gsm7252ps);
	// false for the M4300s, which take a normal read-then-answer confirm.
	WritememStuff bool
	// VerifyPort is the HTTPS port a post-deploy fingerprint check connects
	// to (the caller's job, not this library's).
	VerifyPort int
}

// scpCertProfiles is the private, canonical model_key -> *ScpCertProfile
// registry, mirroring Python's `_SCP_CERT_PROFILES` (commands.py:393-406).
// EXHAUSTIVE (3 of 3): only the Fully Managed FASTPATH models that take a
// certificate over "copy scp://" carry one. gsm7228ps (Smart Managed Pro)
// deliberately has NO entry -- it uses an HTTP multipart upload instead
// (webui package).
var scpCertProfiles = map[string]*ScpCertProfile{
	"m4300-24x": {ModelKey: "m4300-24x", Crypto: "modern", WritememStuff: false, VerifyPort: 443},
	"m4300-16x": {ModelKey: "m4300-16x", Crypto: "modern", WritememStuff: false, VerifyPort: 49152},
	"gsm7252ps": {ModelKey: "gsm7252ps", Crypto: "legacy", WritememStuff: true, VerifyPort: 443},
}

// ScpCertProfiles is the SCP cert-deploy profile registry, mirroring
// Python's module-level SCP_CERT_PROFILES mapping. Every entry is a pointer
// into this package's own frozen data; treat it as read-only.
var ScpCertProfiles = scpCertProfiles

// ScpProfile returns the FASTPATH SCP cert-deploy profile for m, mirroring
// Python protocols.cli.commands.scp_cert_profile (commands.py:411-428): the
// same TWO-STAGE guard as CLISpec -- "no CLI backend for an SCP cert
// deploy" (any non-CLI model) vs "no known copy-scp SSL-certificate deploy
// profile" (a CLI model with a different cert-deploy mechanism, i.e.
// gsm7228ps).
func ScpProfile(m *model.SwitchModel) (*ScpCertProfile, error) {
	if !hasCLIBackend(m) {
		return nil, fmt.Errorf("model %q has no CLI backend for an SCP cert deploy: %w", m.Key, model.ErrUnsupportedCapability)
	}
	profile, ok := scpCertProfiles[m.Key]
	if !ok {
		// Today this branch only ever fires for gsm7228ps (the other 3 CLI
		// models all carry a profile, dossier §1.7) -- a REAL mechanism
		// difference, not a missing Go feature: quoting the pin's own
		// justification (commands.py:365-366) verbatim so a caller sees WHY,
		// not just that the lookup failed.
		return nil, fmt.Errorf("model %q has no known copy-scp SSL-certificate deploy profile (the Smart Managed Pro line uses an HTTP multipart upload instead and is deliberately absent here): %w", m.Key, model.ErrUnsupportedCapability)
	}
	return profile, nil
}
