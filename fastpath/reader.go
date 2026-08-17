// reader.go: CliReader -- the FASTPATH CLI read facade, wiring each read
// op's command(s) (spec.go, Task 1) through a live Session (session.go +
// ssh.go/telnet.go/serial.go, Tasks 5-7) to the right parser (parse.go,
// Tasks 3-4). Ported field-for-field from the pinned
// python-netgear-switch-library @ 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362,
// src/netgear_switch/cli_read.py (107 lines), dossier §3 (§3.1-§3.11). Any
// discrepancy between this file and the pin is a bug in this file, not a
// deliberate deviation, unless called out in a comment.
//
// Parallel to snmp/reader.go, nsdp/reader.go and webui/reader.go: maps
// FASTPATH's parsed CLI output onto the SAME shared model types so a caller
// sees one uniform shape regardless of backend. Reader's eleven Get*
// methods (GetPorts/GetStats/GetVLANs/GetPVIDs/GetLLDP/GetMACs/GetPoE/
// GetSensors/GetMgmtIP/GetUsers/GetServices) satisfy the root package's
// BackendReader interface verbatim -- see dispatch.go there. Identify is a
// further read op (dossier §3.10) --
// like Switch.Identify (switch.go) and snmp.ReadSystemInfo, it is NOT part
// of BackendReader (model detection is inherently backend-specific
// plumbing a future fastpath backend wiring, out of this task's scope,
// would call directly).
//
// Unlike webui.NewReader, construction here is NOT gated on
// CliModelSpec.ReadsVerified -- the module docstring of the pinned
// cli_read.py says so explicitly ("Unlike HttpReader, construction is NOT
// gated on reads_verified"); that gate lives in the facade dispatch layer
// (Python's cli_reads_supported/SyncSwitch._reader_for), out of scope for
// this package.

package fastpath

import (
	"context"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// unsupportedReadOp wraps model.ErrUnsupportedCapability naming modelKey
// and op, mirroring Python cli_read.py's module-level `_unsupported`
// helper (dossier §3, "cli_read.py:1004-1005": `f"model {model_key!r} CLI
// does not expose {op}"`).
func unsupportedReadOp(modelKey, op string) error {
	return fmt.Errorf("model %q CLI does not expose %s: %w", modelKey, op, model.ErrUnsupportedCapability)
}

// Reader is a model-driven FASTPATH CLI read facade over one already-
// authenticated Session, mirroring Python CliReader (cli_read.py:52-107).
// Construct with NewReader; every Get*/Identify method issues its op's
// command(s) on session and parses the result with the matching parse.go
// function.
type Reader struct {
	session Session
	spec    *CliModelSpec
	model   *model.SwitchModel
}

// NewReader constructs a Reader bound to session and m, mirroring Python
// `CliReader.__init__` (cli_read.py:53-56): resolving m's CliModelSpec via
// CLISpec fails immediately -- before any session use -- for a model with
// no CLI backend or no registered spec, exactly the same two-stage guard
// CLISpec itself documents.
func NewReader(session Session, m *model.SwitchModel) (*Reader, error) {
	spec, err := CLISpec(m)
	if err != nil {
		return nil, err
	}
	return &Reader{session: session, spec: spec, model: m}, nil
}

// GetPorts reads per-port link/admin/speed status, mirroring Python
// `CliReader.get_ports` (dossier §3.1, cli_read.py:57-58). One command:
// PortStatusCmd ("show port all", or a model override).
func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error) {
	text, err := r.session.Run(ctx, r.spec.PortStatusCmd)
	if err != nil {
		return nil, err
	}
	return parsePortStatus(text), nil
}

// GetStats reads the per-port traffic-counter snapshot, mirroring Python
// `CliReader.get_stats` (dossier §3.2, cli_read.py:60-74): an N+1 round
// trip -- one GetPorts call, then one InterfaceStats command PER PHYSICAL
// PORT THE SWITCH ITSELF REPORTED. This deliberately iterates the REAL port
// list from GetPorts rather than r.model.PortCount: the registry's nominal
// port count can exceed a SKU's real physical-port count (dossier §3.2's
// m4300-24x/XSM4324CS example), and querying a phantom port would fabricate
// an empty PortStats for it. This is a load-bearing behavioral detail, not
// an optimization choice -- never change this to a range over
// r.model.PortCount.
func (r *Reader) GetStats(ctx context.Context) ([]model.PortStats, error) {
	ports, err := r.GetPorts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.PortStats, 0, len(ports))
	for _, port := range ports {
		text, err := r.session.Run(ctx, r.spec.InterfaceStats(port.Port))
		if err != nil {
			return nil, err
		}
		out = append(out, parseInterfaceCounters(text, port.Port))
	}
	return out, nil
}

// GetVLANs reads the VLAN table (id/name/membership), mirroring Python
// `CliReader.get_vlans` (dossier §3.3, cli_read.py:76-82): another N+1
// round trip -- one VlanBriefCmd command (VLAN id + name list), then one
// VlanDetail command PER VLAN listed there. Each detail page's own "VLAN
// Name:" line is OVERRIDDEN by the brief page's name (parseVLANDetail's
// name parameter) -- per dossier §2.12/§3.3, the VLAN name always comes
// from the brief pass, never from the per-VLAN detail page, even though
// both carry one.
func (r *Reader) GetVLANs(ctx context.Context) ([]model.VLANInfo, error) {
	briefText, err := r.session.Run(ctx, r.spec.VlanBriefCmd)
	if err != nil {
		return nil, err
	}
	brief := parseVLANBrief(briefText)
	out := make([]model.VLANInfo, 0, len(brief))
	for _, row := range brief {
		detailText, err := r.session.Run(ctx, r.spec.VlanDetail(row.vlan))
		if err != nil {
			return nil, err
		}
		name := row.name
		out = append(out, parseVLANDetail(detailText, &name))
	}
	return out, nil
}

// GetPVIDs reads each port's configured default/untagged VLAN, mirroring
// Python `CliReader.get_pvids` (dossier §3.4, cli_read.py:84-85). One
// command: PvidCmd ("show vlan port all").
func (r *Reader) GetPVIDs(ctx context.Context) ([]model.Pvid, error) {
	text, err := r.session.Run(ctx, r.spec.PvidCmd)
	if err != nil {
		return nil, err
	}
	return parsePVIDs(text), nil
}

// GetMACs reads the switch's MAC/FDB table, mirroring Python
// `CliReader.get_macs` (dossier §3.5, cli_read.py:87-90). Gated on
// r.model.HasMACTable() -- a MODEL-level gate unrelated to the CLI backend
// itself; every CLI-capable model in the current registry also carries an
// SNMP backend, so this never actually fires today, but the guard is ported
// faithfully for a future CLI-only, non-SNMP model. Command when not gated:
// MacTableCmd ("show mac-addr-table").
func (r *Reader) GetMACs(ctx context.Context) ([]model.MacEntry, error) {
	if !r.model.HasMACTable() {
		return nil, unsupportedReadOp(r.model.Key, "a MAC/FDB table")
	}
	text, err := r.session.Run(ctx, r.spec.MacTableCmd)
	if err != nil {
		return nil, err
	}
	return parseMacTable(text), nil
}

// GetLLDP reads the LLDP neighbour table, mirroring Python
// `CliReader.get_lldp` (dossier §3.6, cli_read.py:92-93). One command:
// LldpCmd ("show lldp remote-device all").
func (r *Reader) GetLLDP(ctx context.Context) ([]model.LLDPNeighbor, error) {
	text, err := r.session.Run(ctx, r.spec.LldpCmd)
	if err != nil {
		return nil, err
	}
	return parseLLDP(text), nil
}

// GetPoE reads the per-port Power-over-Ethernet status, mirroring Python
// `CliReader.get_poe` (dossier §3.7, cli_read.py:95-98). Gated on
// r.model.PoEPortCount == 0 -- the one documented "real gap vs device
// limit" case among CLI reads (a genuine hardware limitation, e.g.
// m4300-24x has no PSE ports at all): the guard fires BEFORE ever sending
// PoeCmd. Command when not gated: PoeCmd ("show poe port info all").
func (r *Reader) GetPoE(ctx context.Context) ([]model.PoEStatus, error) {
	if r.model.PoEPortCount == 0 {
		return nil, unsupportedReadOp(r.model.Key, "PoE (model has no PSE ports)")
	}
	text, err := r.session.Run(ctx, r.spec.PoeCmd)
	if err != nil {
		return nil, err
	}
	return parsePoE(text), nil
}

// GetSensors reads box environmental sensors (temperature/fan/power),
// mirroring Python `CliReader.get_sensors` (dossier §3.8, cli_read.py:
// 100-101). One command: EnvironmentCmd ("show environment"). No model
// gating.
func (r *Reader) GetSensors(ctx context.Context) ([]model.Sensor, error) {
	text, err := r.session.Run(ctx, r.spec.EnvironmentCmd)
	if err != nil {
		return nil, err
	}
	return parseEnvironment(text), nil
}

// GetMgmtIP reads the switch's own management-IP configuration, mirroring
// Python `CliReader.get_mgmt_ip` (dossier §3.9, cli_read.py:103-104). One
// command: NetworkCmd ("show network", or "show ip management" on M4300).
// No model gating.
func (r *Reader) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error) {
	text, err := r.session.Run(ctx, r.spec.NetworkCmd)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	return parseMgmtIP(text), nil
}

// GetUsers reads the switch's local login accounts, mirroring Python
// `CliReader.get_users` (cli_read.py:122-129). One command: UsersCmd ("show
// users"). The access-mode wording differs between firmware images, so
// model.SwitchUser.AccessMode keeps the raw text and Privileged carries the
// normalised reading -- see parseUsers.
func (r *Reader) GetUsers(ctx context.Context) ([]model.SwitchUser, error) {
	text, err := r.session.Run(ctx, r.spec.UsersCmd)
	if err != nil {
		return nil, err
	}
	return parseUsers(text), nil
}

// GetServices reads which management services are enabled and on which
// ports, mirroring Python `CliReader.get_services` (cli_read.py:109-120).
// Three commands, because the switch splits it that way -- and the telnet
// one is TelnetServiceCmd ("show telnetcon"), NOT "show telnet".
func (r *Reader) GetServices(ctx context.Context) ([]model.ServiceStatus, error) {
	httpText, err := r.session.Run(ctx, r.spec.HTTPServiceCmd)
	if err != nil {
		return nil, err
	}
	telnetText, err := r.session.Run(ctx, r.spec.TelnetServiceCmd)
	if err != nil {
		return nil, err
	}
	sshText, err := r.session.Run(ctx, r.spec.SSHServiceCmd)
	if err != nil {
		return nil, err
	}
	return parseServices(httpText, telnetText, sshText), nil
}

// GetHostname reads the switch's host name from "show hosts", mirroring
// Python `CliReader.get_hostname` (cli_read.py:143-150). One command:
// HostsCmd ("show hosts"). No model gating.
//
// Deliberately NOT "show running-config": the two report different values
// on real hardware, and only "show hosts" agrees with SNMP's sysName -- see
// parseHostname's own doc comment.
func (r *Reader) GetHostname(ctx context.Context) (string, error) {
	text, err := r.session.Run(ctx, r.spec.HostsCmd)
	if err != nil {
		return "", err
	}
	return parseHostname(text)
}

// GetSyslog reads remote-logging configuration, from "show logging" +
// its host table, mirroring Python CliReader.get_syslog (cli_read.py:
// 131-141).
//
// Two commands because the switch splits it that way: the globals live in
// LoggingCmd ("show logging") and the collectors in LoggingHostsCmd ("show
// logging hosts"). The host table's column set differs by firmware -- see
// parseSyslog.
func (r *Reader) GetSyslog(ctx context.Context) (model.SyslogConfig, error) {
	loggingText, err := r.session.Run(ctx, r.spec.LoggingCmd)
	if err != nil {
		return model.SyslogConfig{}, err
	}
	hostsText, err := r.session.Run(ctx, r.spec.LoggingHostsCmd)
	if err != nil {
		return model.SyslogConfig{}, err
	}
	return parseSyslog(loggingText, hostsText)
}

// Identify detects a switch's model from "show version" output, mirroring
// Python `CliReader.identify` (dossier §3.10, cli_read.py:106-107). Unlike
// every other op, this passes the GLOBAL model registry (model.Models()),
// not just r.model -- this op is model DETECTION, so it searches the whole
// registry rather than assuming r.model is already correct. One command:
// VersionCmd ("show version").
func (r *Reader) Identify(ctx context.Context) (model.DetectedModel, error) {
	text, err := r.session.Run(ctx, r.spec.VersionCmd)
	if err != nil {
		return model.DetectedModel{}, err
	}
	return parseVersion(text, model.Models()), nil
}
