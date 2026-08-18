// cliface.go ports src/netgear_switch/virtual/faces/cli.py's
// VirtualCliFace (421 lines) -- the normative source; that repo is
// read-only from here -- pin b26eb1f. Any discrepancy between this file and
// the Python source is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-08-01-slice-07-dossier-cli-transport-fake.md
// §3 for the full porting dossier this mirrors.
//
// CliFace is an IN-PROCESS implementation of fastpath.Session: it
// dispatches each command string straight to a render function (reads) or
// a State mutation (writes) -- no SSH server, no socket, no host keys, no
// prompt/banner text on any wire (there is no wire). This is deliberate
// and honest, mirroring the Python module's own docstring: live SSH
// cannot be exercised from CI, and the real byte transports (session.go +
// ssh.go/telnet.go/serial.go) are transport-only, so this face proves the
// command-dispatch + parser round trip -- the part that CAN be tested --
// against the SAME VirtualSwitchState every other protocol face (SNMP
// oid_map, NSDP TLVs, HTTP pages) reads and writes. A write through this
// face (e.g. `vlan pvid`) is therefore visible over every other protocol
// too, exactly as a write on real hardware is.
//
// Two behaviours are modelled on purpose because the library's
// correctness depends on them (dossier §3.1):
//
//   - An accepted configuration command returns EMPTY output; anything
//     the switch would reject returns text. (The empty/non-empty CONTRACT
//     is live-proven on an M4300-24X; the exact wording of the rejection
//     strings below is NOT a transcription of any capture, and nothing in
//     the library parses them.)
//   - `vlan participation` / `vlan tagging` / `vlan pvid` are accepted
//     but completely INERT while the port is in `switchport mode access`
//     -- the live finding (fastpath.Writer's generalMode prelude, writer.go)
//     that makes `switchport mode general` a mandatory step of every
//     per-port CLI VLAN write. A mock that silently applied them in
//     access mode would hide exactly the bug that finding exists to
//     prevent -- see general() below.
//
// The `show` output renderers this face dispatches to (cliface_render.go)
// are a field-for-field PORT of Python's separate `virtual/cli_fastpath.py`
// module (418 lines, "the CLI analogue of virtual/web_gsm7252ps.py") --
// NOT a from-scratch design cross-checked only against the Go parsers.
// Every column/header/title/spacing choice there mirrors that source
// exactly; see that file's own doc comment for the mapping.

package virtual

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

// --- Command regexes (dossier §3.2, quoted verbatim) -----------------------

var (
	cliShowVlanIDRE = regexp.MustCompile(`^show vlan (\d+)$`)
	// cliShowIfaceRE accepts ANY interface-name shape a model prints
	// ("1/0/7", "1/g7", "1/xg49") and resolves it via portForIface's exact
	// Name match against seeded State, not a hardcoded dialect regex.
	cliShowIfaceRE = regexp.MustCompile(`^show interface ethernet (\S+)$`)
	cliSetupRE     = regexp.MustCompile(`^(enable|terminal length \d+|disable)$`)
	cliCopyRE      = regexp.MustCompile(`^copy\s+(\S+)\s+(\S+)$`)

	cliConfigureRE      = regexp.MustCompile(`^config(?:ure)?(?: terminal)?$`)
	cliVlanDatabaseRE   = regexp.MustCompile(`^vlan database$`)
	cliVlanCreateRE     = regexp.MustCompile(`^vlan (\d+)$`)
	cliVlanNameRE       = regexp.MustCompile(`^vlan name (\d+) (\S+)$`)
	cliVlanDeleteRE     = regexp.MustCompile(`^no vlan (\d+)$`)
	cliInterfaceRE      = regexp.MustCompile(`^interface (\S+)$`)
	cliSwitchportModeRE = regexp.MustCompile(`^switchport mode (access|general|trunk)$`)
	cliParticipationRE  = regexp.MustCompile(`^vlan participation (include|exclude) (\d+)$`)
	cliTaggingRE        = regexp.MustCompile(`^(no )?vlan tagging (\d+)$`)
	cliPvidRE           = regexp.MustCompile(`^vlan pvid (\d+)$`)
	// cliDescriptionRE/cliNoDescriptionRE/cliPortDescriptionShowRE mirror the
	// per-port description commands (dossier: NOT mode-gated, unlike the
	// VLAN commands -- a label is cosmetic and does not depend on the
	// port's switchport mode). The single-quoted form is the firmware's
	// OWN: a live GSM7252PS (10.1.5.22, 2026-08-03) renders its labelled
	// ports in `show running-config` as `description 'eth0.rpi5-pmod'`.
	cliDescriptionRE         = regexp.MustCompile(`^description '([^']*)'$`)
	cliNoDescriptionRE       = regexp.MustCompile(`^no description$`)
	cliPortDescriptionShowRE = regexp.MustCompile(`^show port description (\S+)$`)
	// cliSpeedAutoRE/cliSpeedForcedRE mirror the per-port speed/duplex
	// commands -- TWO grammars meaning opposite things, both executed on
	// the real gsm7252ps (10.1.5.22 port 1/0/8, 2026-08-03): "speed 100
	// full-duplex" moved Physical Mode to "100 Full", "speed auto" moved
	// it back.
	cliSpeedAutoRE   = regexp.MustCompile(`^speed auto$`)
	cliSpeedForcedRE = regexp.MustCompile(`^speed (\d+G?) (full|half)-duplex$`)
	// cliFlowControlRE mirrors the bare IEEE 802.3x flow-control toggle,
	// round-tripped live on gsm7252ps 10.1.5.22 port 1/0/8 (2026-08-03):
	// `flowcontrol` moved Flow Mode from Disable to Enable and added a
	// running-config line, `no flowcontrol` undid both.
	cliFlowControlRE  = regexp.MustCompile(`^(no )?flowcontrol$`)
	cliPoeRE          = regexp.MustCompile(`^(no )?poe$`)
	cliPoeResetRE     = regexp.MustCompile(`^poe reset$`)
	cliShutdownRE     = regexp.MustCompile(`^(no )?shutdown$`)
	cliIPPattern      = `(\d+\.\d+\.\d+\.\d+)`
	cliNetworkParmsRE = regexp.MustCompile(`^network parms ` + cliIPPattern + ` ` + cliIPPattern + `(?: ` + cliIPPattern + `)?$`)
	cliIPMgmtAddrRE   = regexp.MustCompile(`^ip management address ` + cliIPPattern + ` ` + cliIPPattern + `$`)
	cliIPGatewayRE    = regexp.MustCompile(`^ip default-gateway ` + cliIPPattern + `$`)
	// cliHostnameRE mirrors the global-config `hostname <name>` command
	// (set_hostname). Not mode-gated beyond the surrounding `f.mode() ==
	// cliModeConfig` check -- a bare "hostname" (no argument) deliberately
	// does NOT match this regex, so it falls through to the catch-all
	// "Command not found" response, mirroring the real device rejecting it.
	// The captured group can carry a wrapping quote ("hostname \"x\"", a
	// real running-config's own quoted form) or not ("hostname x") -- see
	// its use below, which strips one exactly like the pin's own
	// _HOSTNAME_RE capture (cli.py:63, pin b26eb1f) plus its
	// `.strip().strip('"')` (cli.py:432) [cliface-quote-strip].
	cliHostnameRE = regexp.MustCompile(`^hostname (.+)$`)
	// cliLoggingSyslogRE mirrors the global-config remote-logging enable/
	// disable (set_syslog_enabled): `logging syslog` / `no logging
	// syslog`.
	cliLoggingSyslogRE = regexp.MustCompile(`^(no )?logging syslog$`)
	// cliLoggingHostAddRE mirrors the global-config remote-logging
	// collector-add line, VERBATIM from every FASTPATH switch's own
	// running-config (read 2026-08-05): `logging host "10.1.5.1" ipv4 514
	// info`. The address-kind token (ipv4/ipv6/dns) is captured but unused
	// here, exactly as Python's `_kind` -- the mock does not validate it
	// against the address.
	cliLoggingHostAddRE = regexp.MustCompile(`^logging host "([^"]+)" (ipv4|ipv6|dns) (\d+) (\w+)$`)
	// cliLoggingHostNegationRE mirrors `no logging host ...` in EVERY
	// spelling -- MEASURED as rejected on a live gsm7252ps (10.1.5.22,
	// 2026-08-05, "% Invalid input detected at '^' marker." in every
	// spelling tried: bare index, quoted address, unquoted address, both
	// with a trailing `ipv4`). Matched explicitly so the mock answers it
	// the way the device does, rather than falling through to the generic
	// "Command not found" and being merely accidentally-not-wrong.
	cliLoggingHostNegationRE = regexp.MustCompile(`^no logging host\b.*$`)
	// cliLoggingHostRemoveRE mirrors the removal SUBCOMMAND (NOT a
	// negation) -- `logging host remove <index>`, addressed by the table's
	// own 1-based Index column from `show logging hosts`.
	cliLoggingHostRemoveRE = regexp.MustCompile(`^logging host remove (\d+)$`)
)

// Mode names for CliFace.modes (dossier §3.3).
const (
	cliModeVlanDB    = "vlan-db"
	cliModeConfig    = "config"
	cliModeInterface = "interface"
)

// Rejection/accept literal text (dossier §3.5). The exact wording is NOT
// ground truth (no capture of a rejected FASTPATH config command exists);
// what IS proven, and what the library relies on, is only that a rejected
// command answers with SOMETHING and an accepted one answers with
// NOTHING.
const (
	cliInvalid  = "% Invalid input detected at '^' marker."
	cliAccepted = ""
)

// cliNoForcedRate is the MEASURED refusal, and the reason this mock is not
// merely permissive: a live gsm7252ps port answered "speed 1000
// full-duplex" with cliInvalid and left Physical Mode UNCHANGED.
// 1000BASE-T requires auto-negotiation, so the firmware keeps 1000 out of
// the forced grammar while offering it in "speed auto [10] [100] [1000]
// [10G]". NOT modelled, and deliberately so: which OTHER rates a port will
// force is a property of its PHY, not of the firmware, so no per-model rate
// table is kept here -- this mock and the real library agree on exactly the
// one rule that was measured.
const cliNoForcedRate = "1000"

func cliNoSuchVlan(vlan int) string {
	return fmt.Sprintf("ERROR: VLAN %d does not exist", vlan)
}

// CliFace is an in-process fastpath.Session serving a *State, mirroring
// Python VirtualCliFace. Construct with NewCliFace.
type CliFace struct {
	state *State
	spec  *fastpath.CliModelSpec

	// modes is the command-mode stack, innermost last: nil/empty is EXEC
	// mode, [vlan-db] is the VLAN database, [config, interface] is
	// interface config mode. "exit" pops one level and "end" returns to
	// EXEC, like a real shell.
	modes []string
	// ifacePort is the port `interface <iface>` selected, while in
	// interface mode; nil when not in interface mode.
	ifacePort *int
}

// NewCliFace constructs an in-process CLI session over state, dispatching
// show commands through spec's per-model command strings, mirroring
// Python VirtualCliFace.__init__.
func NewCliFace(state *State, spec *fastpath.CliModelSpec) *CliFace {
	return &CliFace{state: state, spec: spec}
}

var _ fastpath.Session = (*CliFace)(nil)

// mode returns the innermost mode, or "exec" when modes is empty.
func (f *CliFace) mode() string {
	if len(f.modes) == 0 {
		return "exec"
	}
	return f.modes[len(f.modes)-1]
}

// deploy lazily creates + returns this switch's cert-deploy record.
func (f *CliFace) deploy() *ScpCertDeploySim {
	if f.state.ScpCertDeploy == nil {
		f.state.ScpCertDeploy = &ScpCertDeploySim{}
	}
	return f.state.ScpCertDeploy
}

// portForIface resolves a device interface-name string (e.g. "1/0/7",
// "1/g7", "1/xg49") to a physical port number by exact match against this
// switch's OWN seeded PortSim.Name values -- the renderer's own naming,
// not a model-keyed regex dialect, mirroring cli_fastpath.port_for_iface
// (dossier §3.2's comment on _SHOW_IFACE_RE) via the simplest mechanism
// that is ALSO exactly what the show-table renderers below emit as the
// Intf column, so a value round-trips through render then re-parse with
// zero drift.
func (f *CliFace) portForIface(iface string) (int, bool) {
	for port, sim := range f.state.Ports {
		if sim.Name == iface {
			return port, true
		}
	}
	return 0, false
}

// general reports whether port HONOURS the per-port VLAN commands
// (`vlan participation`/`vlan tagging`/`vlan pvid`) -- true in
// "general"/"trunk" switchport mode; false (accepted-but-INERT) in
// "access" mode, the live finding this whole file exists to reproduce
// faithfully (dossier §3.1/§3.6). Precedence:
//  1. An explicit `switchport mode <mode>` this face already executed
//     (PortSim.SwitchportMode non-empty) always wins.
//  2. Otherwise falls back to the MEASURED VlanMembershipLockedPorts
//     signal (seed.go's own doc comment: "LIVE-PROVEN 2026-07-30 on
//     10.1.5.13: EVERY port on this switch is switchport mode access or
//     trunk" for every M4300-24X port) -- the SAME live finding observed
//     over the HTTP VLAN-membership page there and over the CLI here, so
//     a locked port defaults to NOT general; an unlocked port (every
//     other seeded model's default, since VlanMembershipLockedPorts is
//     empty there) defaults to general -- matching Go's zero-value ""
//     for SwitchportMode standing in for Python's dataclass default
//     "general" (see PortSim.SwitchportMode's own doc comment in
//     state.go for why no seed literal needed to change).
func (f *CliFace) general(port int) bool {
	sim := f.state.Ports[port]
	if sim == nil {
		return false
	}
	if sim.SwitchportMode != "" {
		return sim.SwitchportMode == "general" || sim.SwitchportMode == "trunk"
	}
	return !f.state.VlanMembershipLockedPorts[port]
}

// hasSwitchportModes reports whether this model's firmware has a
// `switchport mode` command at all. Probed live 2026-07-30: the
// gsm7252ps (XE image) answers "% Unrecognized command" to `switchport
// mode ?`, while the M4300 12.0.x images and the S3300 Smart image all
// offer access|general|trunk. Keyed on the MODEL rather than read out of
// CliModelSpec on purpose: this mock has to be an independent statement
// of what the device does, so a wrong spec is caught here instead of
// being mirrored (mirrors Python _has_switchport_modes, dossier §3.6).
func (f *CliFace) hasSwitchportModes() bool {
	return f.state.ModelKey != "gsm7252ps"
}

// usesIPManagementDialect reports whether this model's mgmt-IP write is
// the global-config `ip management address` + `ip default-gateway` pair
// (M4300 12.0.x, which reject `network parms` outright) rather than the
// older images' privileged-EXEC `network parms` (mirrors Python
// _uses_ip_management_dialect, dossier §3.6).
func (f *CliFace) usesIPManagementDialect() bool {
	return strings.HasPrefix(f.state.ModelKey, "m4300")
}

// poeCapable reports whether this SKU has PSE hardware at all -- the
// M4300-24X has none, and its firmware consequently has no `poe` command
// whatsoever (mirrors Python _poe_capable, dossier §3.6).
func (f *CliFace) poeCapable() bool {
	return f.state.mustModel().PoEPortCount > 0
}

// applyPoeAdmin switches a PSE port's admin state via the SAME
// State.ApplyPoeAdmin helper the SNMP SET path (State.ApplyWrite's
// pethPsePortAdminEnable branch) now also routes through -- see that
// method's own doc comment for the full pin citation (state.py:1135-1157)
// and the CliStatusLagReads side effect it applies identically regardless
// of backend. Kept as a thin same-file wrapper (not inlined at the call
// site) purely so `f.applyPoeAdmin(port, ...)` reads the same as it always
// has at this file's one call site.
func (f *CliFace) applyPoeAdmin(port int, on bool) {
	f.state.ApplyPoeAdmin(port, on)
}

// applyPoeReset re-arms PSE detection on port (the CLI's `poe reset`): the
// port is powered down and detection starts again, ending up DELIVERING
// only if a powered device is actually drawing power (PowerMw != 0), else
// back to SEARCHING (2) -- a reset does not conjure a PD onto an empty
// port. Unknown port: deliberate no-op.
func (f *CliFace) applyPoeReset(port int) {
	psim, exists := f.state.Poe[port]
	if !exists {
		return
	}
	psim.Admin = true
	if psim.PowerMw != 0 {
		psim.Detect = 3 // delivering
	} else {
		psim.Detect = 2 // searching
	}
}

// --- vlan database mode (dossier §3.8) --------------------------------

// vlanDBCommand handles one command inside `vlan database`, returning
// ok=false when c is not one of this mode's commands (mirrors Python
// _vlan_db_command).
func (f *CliFace) vlanDBCommand(c string) (string, bool) {
	if m := cliVlanCreateRE.FindStringSubmatch(c); m != nil {
		vid, _ := strconv.Atoi(m[1])
		// Selecting an existing VLAN is accepted too (idempotent),
		// matching a real switch: "vlan 5" on an existing VLAN 5 is not
		// an error.
		if _, exists := f.state.Vlans[vid]; !exists {
			// Member/Untagged non-nil -- see the other VLAN-creation sites'
			// matching comment (state.go) for why.
			f.state.Vlans[vid] = &VlanSim{Name: "", Member: map[int]bool{}, Untagged: map[int]bool{}}
		}
		return cliAccepted, true
	}
	if m := cliVlanNameRE.FindStringSubmatch(c); m != nil {
		vid, _ := strconv.Atoi(m[1])
		name := m[2]
		vl, exists := f.state.Vlans[vid]
		if !exists {
			return cliNoSuchVlan(vid), true
		}
		vl.Name = name
		return cliAccepted, true
	}
	if m := cliVlanDeleteRE.FindStringSubmatch(c); m != nil {
		vid, _ := strconv.Atoi(m[1])
		if vid == 1 {
			return "ERROR: The default VLAN cannot be deleted", true
		}
		if _, exists := f.state.Vlans[vid]; !exists {
			return cliNoSuchVlan(vid), true
		}
		delete(f.state.Vlans, vid)
		// Device coherence (a deliberate model of real behaviour, not a
		// transcription): no port can be left with its PVID pointing at
		// a VLAN that no longer exists, so those ports fall back to
		// VLAN 1.
		for port, pvid := range f.state.Pvids {
			if pvid == vid {
				f.state.Pvids[port] = 1
			}
		}
		return cliAccepted, true
	}
	return "", false
}

// --- interface mode (dossier §3.7) --------------------------------------

// interfaceCommand handles one command inside `interface <iface>`,
// returning ok=false when c is not one of this mode's commands (mirrors
// Python _interface_command).
func (f *CliFace) interfaceCommand(c string, port int) (string, bool) {
	if m := cliSwitchportModeRE.FindStringSubmatch(c); m != nil {
		if !f.hasSwitchportModes() {
			return cliInvalid, true // this image has no switchport-mode concept
		}
		f.state.Ports[port].SwitchportMode = m[1]
		return cliAccepted, true
	}
	if cliPoeResetRE.MatchString(c) {
		if !f.poeCapable() {
			return cliInvalid, true
		}
		f.applyPoeReset(port)
		return cliAccepted, true
	}
	if m := cliPoeRE.FindStringSubmatch(c); m != nil {
		if !f.poeCapable() {
			return cliInvalid, true
		}
		f.applyPoeAdmin(port, m[1] == "") // "no poe" -> off
		return cliAccepted, true
	}
	if m := cliShutdownRE.FindStringSubmatch(c); m != nil {
		// "no shutdown" enables, "shutdown" disables. Go's FindStringSubmatch
		// yields "" for the absent optional "(no )?" group (no nil/None
		// distinction like Python's re.group(1)), so the faithful port of the
		// pin's `enabled = m.group(1) is not None` (cli.py:251) is `m[1] != ""`
		// -- "no shutdown" captures "no " (enable), bare "shutdown" captures ""
		// (disable). Using `== ""` inverts admin state.
		enabled := m[1] != ""
		sim, exists := f.state.Ports[port]
		if !exists {
			return cliInvalid, true
		}
		sim.Admin = enabled
		if !enabled {
			// A shut port cannot stay linked -- same coherence the SNMP
			// ifAdminStatus write applies (State.ApplyWrite).
			sim.Link = false
		}
		return cliAccepted, true
	}
	if m := cliParticipationRE.FindStringSubmatch(c); m != nil {
		include := m[1] == "include"
		vid, _ := strconv.Atoi(m[2])
		vsim, exists := f.state.Vlans[vid]
		if !exists {
			return cliNoSuchVlan(vid), true
		}
		// ACCEPTED-BUT-INERT in access mode -- the live-proven behaviour.
		if !f.general(port) {
			return cliAccepted, true
		}
		if include {
			vsim.Member[port] = true
			// A newly included port is UNTAGGED until "vlan tagging"
			// says otherwise (that is why the writer always sends one
			// of the two).
			vsim.Untagged[port] = true
		} else {
			delete(vsim.Member, port)
			delete(vsim.Untagged, port)
		}
		return cliAccepted, true
	}
	if m := cliTaggingRE.FindStringSubmatch(c); m != nil {
		tagged := m[1] == ""
		vid, _ := strconv.Atoi(m[2])
		vsim, exists := f.state.Vlans[vid]
		if !exists {
			return cliNoSuchVlan(vid), true
		}
		if !f.general(port) {
			return cliAccepted, true // accepted-but-inert, as above
		}
		if tagged {
			delete(vsim.Untagged, port)
		} else {
			vsim.Untagged[port] = true
		}
		return cliAccepted, true
	}
	if m := cliPvidRE.FindStringSubmatch(c); m != nil {
		vid, _ := strconv.Atoi(m[1])
		if _, exists := f.state.Vlans[vid]; !exists {
			return cliNoSuchVlan(vid), true
		}
		if !f.general(port) {
			return cliAccepted, true // accepted-but-inert, as above
		}
		f.state.Pvids[port] = vid
		return cliAccepted, true
	}
	if m := cliFlowControlRE.FindStringSubmatch(c); m != nil {
		// Configured state only: the link is not renegotiated, exactly as
		// observed on the live DOWN port whose Flow Mode still moved.
		f.state.Ports[port].FlowControl = m[1] == "" // "no flowcontrol" -> off
		return cliAccepted, true
	}
	if cliSpeedAutoRE.MatchString(c) {
		f.state.Ports[port].PhysicalMode = "Auto"
		return cliAccepted, true
	}
	if m := cliSpeedForcedRE.FindStringSubmatch(c); m != nil {
		rate, duplex := m[1], m[2]
		if rate == cliNoForcedRate {
			return cliInvalid, true // measured: the switch has no forced 1000
		}
		// Physical Mode ONLY. The negotiated rate (Speed, rendered in the
		// Physical Status column) is untouched, because forcing the
		// configuration of a DOWN port negotiates nothing -- exactly what
		// the live port did.
		f.state.Ports[port].PhysicalMode = rate + " " + strings.ToUpper(duplex[:1]) + duplex[1:]
		return cliAccepted, true
	}
	if m := cliDescriptionRE.FindStringSubmatch(c); m != nil {
		if m[1] != "" {
			text := m[1]
			f.state.Ports[port].Description = &text
		} else {
			f.state.Ports[port].Description = nil
		}
		return cliAccepted, true
	}
	if cliNoDescriptionRE.MatchString(c) {
		f.state.Ports[port].Description = nil
		return cliAccepted, true
	}
	return "", false
}

// --- mode entry/exit + every configuration command (dossier §3.4) --------

// configCommand handles mode entry/exit and every configuration command,
// returning ok=false when c is not a config command at all (meaning: try
// the show dispatch instead), mirroring Python _config_command.
func (f *CliFace) configCommand(c string) (string, bool) {
	if c == "exit" {
		if len(f.modes) > 0 {
			f.modes = f.modes[:len(f.modes)-1]
			if f.mode() != cliModeInterface {
				f.ifacePort = nil
			}
		}
		return cliAccepted, true
	}
	if c == "end" {
		f.modes = nil
		f.ifacePort = nil
		return cliAccepted, true
	}
	if cliVlanDatabaseRE.MatchString(c) {
		// Reachable from EXEC and from global config mode on real
		// FASTPATH.
		if f.mode() == "exec" || f.mode() == cliModeConfig {
			f.modes = append(f.modes, cliModeVlanDB)
			return cliAccepted, true
		}
		return cliInvalid, true
	}
	if cliConfigureRE.MatchString(c) {
		if f.mode() == "exec" {
			f.modes = append(f.modes, cliModeConfig)
			return cliAccepted, true
		}
		return cliInvalid, true
	}
	if m := cliNetworkParmsRE.FindStringSubmatch(c); m != nil {
		// Privileged EXEC only, and only on the images that HAVE it: the
		// M4300 12.0.x rejects "network parms" in every mode (probed
		// live).
		if f.mode() != "exec" || f.usesIPManagementDialect() {
			return cliInvalid, true
		}
		f.state.Mgmt.Address = m[1]
		f.state.Mgmt.Netmask = m[2]
		if m[3] != "" {
			f.state.Mgmt.Gateway = m[3]
		}
		f.state.Mgmt.Mode = "static"
		return cliAccepted, true
	}
	if f.mode() == cliModeVlanDB {
		return f.vlanDBCommand(c)
	}
	if f.mode() == cliModeConfig {
		if m := cliHostnameRE.FindStringSubmatch(c); m != nil {
			// strip('"') after strip(): a wrapping quote from a real
			// running-config's own `hostname "x"` form must not become part
			// of the stored name, mirroring the pin's
			// m.group(1).strip().strip('"') exactly (cli.py:432, pin
			// b26eb1f) [cliface-quote-strip]. Inert today: no writer this
			// codebase builds sends a quoted hostname.
			f.state.Hostname = strings.Trim(strings.TrimSpace(m[1]), `"`)
			return cliAccepted, true
		}
		if m := cliLoggingSyslogRE.FindStringSubmatch(c); m != nil {
			// AdminMode is the device's own enum, 1=enabled / 2=not.
			if m[1] == "" {
				f.state.Syslog.AdminMode = 1
			} else {
				f.state.Syslog.AdminMode = 2
			}
			return cliAccepted, true
		}
		if m := cliLoggingHostAddRE.FindStringSubmatch(c); m != nil {
			address, word := m[1], m[4]
			severity, err := model.SyslogSeverity(word)
			if err != nil {
				return cliInvalid, true // a word this firmware would not accept
			}
			port, convErr := strconv.Atoi(m[3])
			if convErr != nil {
				return cliInvalid, true
			}
			// A real switch appends a SECOND row for an address it already
			// has rather than replacing the first -- which is exactly why
			// fastpath.Writer.AddSyslogCollector refuses a duplicate before
			// sending anything. The mock reproduces the append so that
			// refusal has something real to prevent.
			//
			// A NEW index, never a renumbering: real FASTPATH hands out the
			// next free slot and leaves existing rows where they are,
			// which is how the table becomes sparse after a removal.
			next := 0
			for _, col := range f.state.Syslog.Collectors {
				if col.Index > next {
					next = col.Index
				}
			}
			next++
			f.state.Syslog.Collectors = append(f.state.Syslog.Collectors, SyslogCollectorSim{
				Host:     address,
				Port:     port,
				Severity: severity,
				Status:   1,
				Index:    next,
			})
			return cliAccepted, true
		}
		if cliLoggingHostNegationRE.MatchString(c) {
			return cliInvalid, true // removal is a subcommand, not a negation
		}
		if m := cliLoggingHostRemoveRE.FindStringSubmatch(c); m != nil {
			index, convErr := strconv.Atoi(m[1])
			if convErr != nil {
				return cliInvalid, true
			}
			pos := -1
			for i, col := range f.state.Syslog.Collectors {
				if col.Index == index {
					pos = i
					break
				}
			}
			if pos < 0 {
				// The device's own words, measured on 10.1.5.13.
				return fmt.Sprintf("Error! Logging Host with index of %d is non-existent.", index), true
			}
			// Survivors KEEP their index -- that is what makes the table
			// sparse, and what a position-based remover gets wrong.
			f.state.Syslog.Collectors = append(f.state.Syslog.Collectors[:pos], f.state.Syslog.Collectors[pos+1:]...)
			return cliAccepted, true
		}
		if m := cliInterfaceRE.FindStringSubmatch(c); m != nil {
			port, ok := f.portForIface(m[1])
			if !ok {
				return cliInvalid, true // no such interface on this switch
			}
			f.ifacePort = &port
			f.modes = append(f.modes, cliModeInterface)
			return cliAccepted, true
		}
		if m := cliIPMgmtAddrRE.FindStringSubmatch(c); m != nil {
			if !f.usesIPManagementDialect() {
				return cliInvalid, true // older images have no "ip management"
			}
			f.state.Mgmt.Address = m[1]
			f.state.Mgmt.Netmask = m[2]
			f.state.Mgmt.Mode = "static"
			return cliAccepted, true
		}
		if m := cliIPGatewayRE.FindStringSubmatch(c); m != nil {
			if !f.usesIPManagementDialect() {
				return cliInvalid, true
			}
			f.state.Mgmt.Gateway = m[1]
			return cliAccepted, true
		}
		return "", false
	}
	if f.mode() == cliModeInterface && f.ifacePort != nil {
		return f.interfaceCommand(c, *f.ifacePort)
	}
	return "", false
}

// --- dispatch (dossier §3.5/§3.7) ---------------------------------------

// run is the actual per-command dispatcher Run/RunSCPCopy/RunWriteMemory
// delegate to, mirroring Python VirtualCliFace.run.
func (f *CliFace) run(command string) string {
	c := strings.TrimSpace(command)
	if cliSetupRE.MatchString(c) {
		return ""
	}
	if c == "no ip http secure-server" {
		d := f.deploy()
		d.HTTPSDisabled = true
		d.Commands = append(d.Commands, c)
		return ""
	}
	if c == "ip http secure-server" {
		d := f.deploy()
		d.HTTPSEnabled = true
		d.Commands = append(d.Commands, c)
		return ""
	}
	// Configuration commands (and mode changes) first: a config command is
	// never also a "show" command, and a mis-moded one must be REJECTED
	// rather than silently applied -- that is what proves the writer
	// really entered "vlan database"/"configure" before issuing it.
	if out, handled := f.configCommand(c); handled {
		return out
	}
	// "show" commands answer in any mode, exactly as on real hardware.
	switch c {
	case f.spec.VersionCmd:
		return f.renderVersion()
	case f.spec.PortStatusCmd:
		return f.renderPorts()
	}
	if m := cliPortDescriptionShowRE.FindStringSubmatch(c); m != nil {
		return f.renderPortDescription(m[1])
	}
	switch c {
	case f.spec.VlanBriefCmd:
		return f.renderVlanBrief()
	case f.spec.PvidCmd:
		return f.renderPvids()
	case f.spec.MacTableCmd:
		return f.renderMacTable()
	case f.spec.LldpCmd:
		return f.renderLLDP()
	case f.spec.PoeCmd:
		return f.renderPoE()
	case f.spec.EnvironmentCmd:
		return f.renderEnvironment()
	case f.spec.NetworkCmd:
		return f.renderNetwork()
	case f.spec.HostsCmd:
		return f.renderHosts()
	case f.spec.LoggingHostsCmd:
		return f.renderLoggingHosts()
	case f.spec.LoggingCmd:
		return f.renderLogging()
	case f.spec.UsersCmd:
		return f.renderUsers()
	case f.spec.HTTPServiceCmd:
		return f.renderHTTPService()
	case f.spec.TelnetServiceCmd:
		return f.renderTelnetService()
	case f.spec.SSHServiceCmd:
		return f.renderSSHService()
	}
	if m := cliShowVlanIDRE.FindStringSubmatch(c); m != nil {
		vid, _ := strconv.Atoi(m[1])
		return f.renderVlanDetail(vid)
	}
	if m := cliShowIfaceRE.FindStringSubmatch(c); m != nil {
		port, ok := f.portForIface(m[1])
		if !ok {
			return cliInvalid
		}
		return f.renderInterfaceCounters(port)
	}
	return "Command not found / Incomplete command. Use ? to list commands."
}

// --- fastpath.Session --------------------------------------------------

// Run implements fastpath.Session.
//
// Holds State's lock for the whole call (Go-only; see State.mu's own doc
// comment): a *CliFace is constructed fresh per SSH/Telnet session
// (SSHFace.handleSession/TelnetFace.serveConn), but every session over the
// same VirtualSwitch -- CLI or otherwise -- shares the SAME *State, mutated
// concurrently from each session's own goroutine. f.run and everything it
// calls (configCommand, interfaceCommand, vlanDBCommand, the render*
// helpers, applyPoeAdmin/applyPoeReset) must NEVER lock again (this mutex
// is not reentrant); Run/RunSCPCopy/RunWriteMemory are their only callers
// (fastpath.Session's three write/command entry points), each locking
// independently since none of the three ever calls another.
func (f *CliFace) Run(ctx context.Context, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.state.LockState()
	defer f.state.UnlockState()
	return f.run(command), nil
}

// RunSCPCopy implements fastpath.Session as an in-process stand-in for the
// interactive `copy scp://...` step (dossier §3.9): it directly parses
// `copy <src> <dest>`, records into ScpCertDeploySim, and always reports
// success -- there is no byte stream here to drive the real TOFU/
// password/(y/n) handshake fastpath.ShellDriver.RunSCPCopy drives.
//
// Holds State's lock for the whole call -- see Run's own doc comment for
// why (same reasoning, independent lock: RunSCPCopy never calls Run or vice
// versa).
func (f *CliFace) RunSCPCopy(ctx context.Context, command, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.state.LockState()
	defer f.state.UnlockState()
	trimmed := strings.TrimSpace(command)
	m := cliCopyRE.FindStringSubmatch(trimmed)
	if m == nil {
		return "% Invalid input: expected 'copy <src> <dest>'", nil
	}
	source, dest := m[1], m[2]
	d := f.deploy()
	d.Commands = append(d.Commands, trimmed)
	d.Copies = append(d.Copies, ScpCopy{Source: source, Dest: dest})
	return fmt.Sprintf("Data transfer complete. bytes transferred to %s", dest), nil
}

// RunWriteMemory implements fastpath.Session as an in-process stand-in for
// a command with a `(y/n)` confirm (dossier §3.9/§3.10 area, mirrors
// Python run_write_memory). "reload" and "write memory" are NOT
// interchangeable: a reload must never look like a config save. A real
// reload also tears the session down; this mock cannot restart itself, so
// it records the request (State.Reboots) and returns, which is what lets
// a test prove the right command was issued. prestuff is accepted for
// Session-interface parity but has no observable effect here -- there is
// no byte stream to pre-stuff a "y" answer into.
//
// Holds State's lock for the whole call -- see Run's own doc comment for
// why (same reasoning, independent lock: RunWriteMemory never calls Run or
// vice versa).
func (f *CliFace) RunWriteMemory(ctx context.Context, command string, _ bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.state.LockState()
	defer f.state.UnlockState()
	c := strings.TrimSpace(command)
	if c == "reload" {
		f.state.Reboots++
		return "", nil
	}
	d := f.deploy()
	d.Commands = append(d.Commands, c)
	d.Saved = true
	return "", nil
}

// Close implements fastpath.Session. A no-op, mirroring Python
// VirtualCliFace.close (dossier §3.10, "def close(self) -> None: pass"):
// there is no socket, no host key, nothing to drain or leak-check here.
func (f *CliFace) Close() error {
	return nil
}

// --- prompt-rendering accessors (Task 12, dossier §7.7) -------------------
//
// Mode/InterfaceName are pure getters over state this file already
// maintains for dispatch -- added so the real-socket listeners
// (virtual/sshface.go, virtual/telnetface.go) can render a mode-appropriate
// FASTPATH prompt after each command without duplicating any accept/reject
// or mode-transition logic: those listeners drive commands purely through
// Run (this file's own dispatch decides every mode change), then ask this
// face what mode it ended up in. No behavior lives here beyond exposing the
// existing modes/ifacePort fields.

// Mode returns the current command-mode label: "exec" (the zero/top-level
// mode) or one of cliModeVlanDB/cliModeConfig/cliModeInterface.
func (f *CliFace) Mode() string {
	return f.mode()
}

// InterfaceName returns the device interface name (e.g. "1/0/7") of the
// port currently selected via `interface <iface>`, and true -- only while
// Mode() == cliModeInterface; ("", false) otherwise, including the
// (unreachable in practice) case of a selected port no longer present in
// state.Ports.
//
// Holds State's lock for the whole call (Go-only; see State.mu's own doc
// comment): unlike Mode() (f.modes is session-local, never touched by
// another goroutine), this reads f.state.Ports -- the SAME shared *State
// every other face's goroutine can mutate. Called from cli_socket.go's
// cliPrompt on the SSH/Telnet per-connection goroutine, AFTER CliFace.Run's
// own critical section has already ended (cliListenerLoop calls cliPrompt
// only once face.Run has fully returned) -- so this is never nested inside
// another State.mu acquisition; it is its own, independent, outermost
// critical section, safe to lock directly.
func (f *CliFace) InterfaceName() (string, bool) {
	if f.ifacePort == nil {
		return "", false
	}
	f.state.LockState()
	defer f.state.UnlockState()
	sim, ok := f.state.Ports[*f.ifacePort]
	if !ok {
		return "", false
	}
	return sim.Name, true
}
