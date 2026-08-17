package fmtx

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// PortsTable renders per-port status, mirroring format.py's ports_table.
func PortsTable(ports []model.PortStatus) string {
	rows := make([][]string, len(ports))
	for i, p := range ports {
		rows[i] = []string{
			strconv.Itoa(p.Port),
			strOrDash(p.Name),
			linkWord(p.LinkUp),
			enabledWord(p.AdminEnabled),
			intOrDash(p.SpeedMbps),
			strOrDash(p.Description),
		}
	}
	return table([]string{"Port", "Name", "Link", "Admin", "Speed", "Description"}, rows)
}

// PoeTable renders per-port PoE status, mirroring format.py's poe_table.
func PoeTable(entries []model.PoEStatus) string {
	rows := make([][]string, len(entries))
	for i, e := range entries {
		rows[i] = []string{
			strconv.Itoa(e.Port),
			enabledWord(e.AdminEnabled),
			string(e.Detect),
			intOrDash(e.PowerMw),
		}
	}
	return table([]string{"Port", "Admin", "Detect", "Power(mW)"}, rows)
}

// VlansTable renders the static VLAN table, mirroring format.py's
// vlans_table.
func VlansTable(vlans []model.VLANInfo) string {
	rows := make([][]string, len(vlans))
	for i, v := range vlans {
		rows[i] = []string{
			strconv.Itoa(v.VlanID),
			strOrDash(v.Name),
			formatPorts(v.UntaggedPorts),
			formatPorts(v.TaggedPorts),
		}
	}
	return table([]string{"VLAN", "Name", "Untagged", "Tagged"}, rows)
}

// PvidsTable renders each port's default/untagged VLAN, mirroring
// format.py's pvids_table.
func PvidsTable(pvids []model.Pvid) string {
	rows := make([][]string, len(pvids))
	for i, p := range pvids {
		rows[i] = []string{strconv.Itoa(p.Port), strconv.Itoa(p.Vlan)}
	}
	return table([]string{"Port", "PVID"}, rows)
}

// LldpTable renders the LLDP remote-neighbor table, mirroring format.py's
// lldp_table. Header spelling ("RemotePortId", lowercase d; "ChassisID",
// uppercase ID) is copied VERBATIM from the Python source.
func LldpTable(neighbors []model.LLDPNeighbor) string {
	rows := make([][]string, len(neighbors))
	for i, n := range neighbors {
		rows[i] = []string{
			strconv.Itoa(n.LocalPort),
			strOrDash(n.RemoteSysName),
			strOrDash(n.RemotePortID),
			strOrDash(n.RemotePortDesc),
			strOrDash(n.RemoteChassisID),
		}
	}
	return table([]string{"Port", "Neighbor", "RemotePortId", "RemotePortDesc", "ChassisID"}, rows)
}

// MacsTable renders the MAC address / forwarding table, mirroring
// format.py's macs_table.
func MacsTable(entries []model.MacEntry) string {
	rows := make([][]string, len(entries))
	for i, e := range entries {
		rows[i] = []string{e.Mac, strconv.Itoa(e.Port), intOrDash(e.VlanID)}
	}
	return table([]string{"MAC", "Port", "VLAN"}, rows)
}

// StatsTable renders the per-port traffic-counter snapshot, mirroring
// format.py's stats_table.
func StatsTable(stats []model.PortStats) string {
	rows := make([][]string, len(stats))
	for i, s := range stats {
		rows[i] = []string{
			strconv.Itoa(s.Port),
			uint64OrDash(s.RxBytes),
			uint64OrDash(s.TxBytes),
			uint64OrDash(s.RxPackets),
			uint64OrDash(s.TxPackets),
			uint64OrDash(s.RxErrors),
			uint64OrDash(s.TxErrors),
		}
	}
	return table([]string{"Port", "RxBytes", "TxBytes", "RxPackets", "TxPackets", "RxErrors", "TxErrors"}, rows)
}

// SensorsTable renders environmental sensor readings, mirroring format.py's
// sensors_table. Value uses pyG (Python's f"{v:g}"), NOT Go's default
// FormatFloat('g',-1,...) -- see pyg.go's doc comment for why they
// diverge.
func SensorsTable(sensors []model.Sensor) string {
	rows := make([][]string, len(sensors))
	for i, s := range sensors {
		rows[i] = []string{s.Name, s.Kind, pyG(s.Value), s.Unit}
	}
	return table([]string{"Sensor", "Kind", "Value", "Unit"}, rows)
}

// UsersTable renders local login accounts, mirroring format.py's
// users_table. Headers are deliberately lowercase ("user", "access mode",
// "privileged"), copied VERBATIM from the Python source -- unlike every
// other table's Title-Case headers.
func UsersTable(users []model.SwitchUser) string {
	rows := make([][]string, len(users))
	for i, u := range users {
		rows[i] = []string{u.Name, u.AccessMode, boolOrDash(u.Privileged)}
	}
	return table([]string{"user", "access mode", "privileged"}, rows)
}

// ServicesTable renders which management services are enabled, mirroring
// format.py's services_table. Headers are lowercase, copied VERBATIM.
func ServicesTable(services []model.ServiceStatus) string {
	rows := make([][]string, len(services))
	for i, s := range services {
		rows[i] = []string{s.Name, pyBool(s.Enabled), intOrDash(s.Port)}
	}
	return table([]string{"service", "enabled", "port"}, rows)
}

// SyslogText renders remote-logging configuration, mirroring format.py's
// syslog_text: a two-line head (enabled/local port), then either
// "collectors: none" or a "collectors:" line followed by the servers
// table -- copied VERBATIM including its lowercase table headers.
func SyslogText(cfg model.SyslogConfig) string {
	head := []string{
		fmt.Sprintf("enabled:    %s", pyBool(cfg.Enabled)),
		fmt.Sprintf("local port: %d", cfg.LocalPort),
	}
	if len(cfg.Servers) == 0 {
		return strings.Join(append(head, "collectors: none"), "\n")
	}
	rows := make([][]string, len(cfg.Servers))
	for i, s := range cfg.Servers {
		rows[i] = []string{s.Host, strconv.Itoa(s.Port), strconv.Itoa(s.Severity), pyBool(s.Active)}
	}
	rendered := table([]string{"collector", "port", "severity", "active"}, rows)
	return strings.Join(append(head, "collectors:", rendered), "\n")
}

// DetectedModelText renders an SNMP model-detection result, mirroring
// format.py's detected_model_text. key is "(unmatched)" -- NOT "-" --
// when detection matched no registered model (never a fabricated guess;
// see model.DetectedModel's doc comment).
func DetectedModelText(d model.DetectedModel) string {
	key := "(unmatched)"
	if d.Key != nil && *d.Key != "" {
		key = *d.Key
	}
	return strings.Join([]string{
		fmt.Sprintf("key:           %s", key),
		fmt.Sprintf("sys_descr:     %s", strOrDash(d.SysDescr)),
		fmt.Sprintf("sys_object_id: %s", strOrDash(d.SysObjectID)),
	}, "\n")
}

// NsdpDeviceText renders the headline fields of a raw NSDP device record,
// mirroring format.py's nsdp_device_text. The full record (per-port
// status/statistics, VLANs, QoS, etc.) is available via JSON (Emit's
// asJSON path) only -- this text form deliberately covers just the
// summary fields the Python source does.
func NsdpDeviceText(d model.NsdpDevice) string {
	return strings.Join([]string{
		fmt.Sprintf("model:    %s", d.Model),
		fmt.Sprintf("mac:      %s", d.Mac),
		fmt.Sprintf("hostname: %s", strOrDash(d.Hostname)),
		fmt.Sprintf("ip:       %s", strOrDash(d.IP)),
		fmt.Sprintf("netmask:  %s", strOrDash(d.Netmask)),
		fmt.Sprintf("gateway:  %s", strOrDash(d.Gateway)),
		fmt.Sprintf("firmware: %s", strOrDash(d.FirmwareVersion)),
		fmt.Sprintf("serial:   %s", strOrDash(d.SerialNumber)),
		fmt.Sprintf("ports:    %s", intOrDash(d.PortCount)),
	}, "\n")
}

// MgmtIPText renders the switch's own management IP configuration,
// mirroring format.py's mgmt_ip_text.
func MgmtIPText(cfg model.MgmtIPConfig) string {
	return strings.Join([]string{
		fmt.Sprintf("mode:    %s", string(cfg.Mode)),
		fmt.Sprintf("address: %s", strOrDash(cfg.Address)),
		fmt.Sprintf("netmask: %s", strOrDash(cfg.Netmask)),
		fmt.Sprintf("gateway: %s", strOrDash(cfg.Gateway)),
		fmt.Sprintf("mac:     %s", strOrDash(cfg.BaseMac)),
	}, "\n")
}

// HostnameText renders the switch's host name, mirroring format.py's
// hostname_text: a pure passthrough (kept as a named function, not
// inlined at call sites, so every ngsw text renderer has a
// same-shaped entry point for Emit's tableFn parameter).
func HostnameText(name string) string { return name }

// SnapshotText renders a complete switch snapshot as sectioned text,
// mirroring format.py's snapshot_text exactly: a header line, then one
// "## Section" + table per collection, with an optional "## Mgmt IP"
// section appended ONLY when data.MgmtIP is non-nil (mirrors Python's
// `if data.mgmt_ip is not None`).
func SnapshotText(data model.SwitchData) string {
	sections := []string{
		fmt.Sprintf("# %s @ %s", data.Model, data.Host),
		"## Ports", PortsTable(data.Ports),
		"## PoE", PoeTable(data.PoE),
		"## VLANs", VlansTable(data.Vlans),
		"## PVIDs", PvidsTable(data.Pvids),
		"## LLDP", LldpTable(data.Lldp),
		"## MACs", MacsTable(data.Macs),
		"## Sensors", SensorsTable(data.Sensors),
	}
	if data.MgmtIP != nil {
		sections = append(sections, "## Mgmt IP", MgmtIPText(*data.MgmtIP))
	}
	return strings.Join(sections, "\n")
}
