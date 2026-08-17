package virtual

// web_gs728tpp.go ports src/netgear_switch/virtual/web_gs728tpp.py (the
// normative source; that repo is read-only from here -- pin 1841111,
// branch go-port-pin-1841111). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4 for the porting dossier this mirrors.
//
// GS728TPP GoAhead wcd XML-API renderers for the virtual HTTP face.
//
// Each function renders one wcd response from a *State in the SAME shape
// the real switch 10.2.5.10 returns (a trailing <DeviceConfiguration> data
// block of <Object type="section"> elements), so the SAME
// webui.ParseGoAhead* parsers that read the real captures read the mock
// back -- proving seed<->render<->parse round-trips with no hardware.
//
// Only the data block matters to the parsers (they slice it out and ignore
// the surrounding template), so this emits a minimal-but-faithful
// <ResponseData><DeviceConfiguration>.. envelope.
//
// apply_cert_import (goaheadApplyCertImport) already lives in httpface.go
// (Task 8 landed the cert-upload flow before this file's read routing
// existed); this file only adds RenderGS728TPPWcd's read-side routing.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// goAheadAdminText/goAheadLinkText are the GoAhead wire codes (see
// webui/parse_goahead.go's docstring): 1=up/enabled, 2=down/disabled.
func goAheadAdminText(admin bool) string {
	if admin {
		return "1"
	}
	return "2"
}

func goAheadLinkText(link bool) string {
	if link {
		return "1"
	}
	return "2"
}

func goAheadWcd(dataBlock string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<ResponseData>\n" +
		"<DeviceConfiguration>\n<version>1.0</version>\n" +
		dataBlock + "\n</DeviceConfiguration>\n</ResponseData>\n"
}

func goAheadMacText(raw [6]byte) string {
	parts := make([]string, 6)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// physicalGS728TPPPorts returns the switch's PHYSICAL ports only, in
// order, mirroring Python web_gs728tpp._physical_ports.
//
// The seed carries ifIndex-keyed entries for the eight LAG pseudo-
// interfaces ("po 1".."po 8" at 1000-1007, ifType 161) because the
// switch's Q-BRIDGE bitmaps really do include them (see
// SeedGS728TPP -- GAP-2 fix parity with Python commit 3f25b0b). The real
// wcd pages list ONLY physical ports: a live Standard802_3List fetch
// returns 28 <Entry> rows, and the per-port VLANInterfaceList likewise.
// Rendering the LAGs would make the HTTP reader report interfaces the web
// UI never shows -- and disagree with SNMP, which filters them by ifType
// (snmp.ParseVlans/ParsePvids).
func physicalGS728TPPPorts(state *State) []int {
	portCount := state.mustModel().PortCount
	all := sortedIntKeys(state.Ports)
	out := make([]int, 0, len(all))
	for _, p := range all {
		if p <= portCount {
			out = append(out, p)
		}
	}
	return out
}

// RenderGS728TPPPorts renders the Standard802_3List wcd section. Mirrors
// Python web_gs728tpp.render_ports.
func RenderGS728TPPPorts(state *State) string {
	var rows strings.Builder
	for _, p := range physicalGS728TPPPorts(state) {
		sim := state.Ports[p]
		desc := ""
		if sim.Description != nil {
			desc = *sim.Description
		}
		fmt.Fprintf(&rows,
			"<Entry><interfaceName>g%d</interfaceName>"+
				"<interfaceType>1</interfaceType><interfaceID>%d</interfaceID>"+
				"<interfaceDescription>%s</interfaceDescription>"+
				"<adminState>%s</adminState>"+
				"<linkState>%s</linkState>"+
				"<speedOper>%d</speedOper></Entry>",
			p, p, xmlEscape(desc), goAheadAdminText(sim.Admin), goAheadLinkText(sim.Link), sim.Speed)
	}
	return goAheadWcd("<Standard802_3List type=\"section\">" + rows.String() + "</Standard802_3List>")
}

// RenderGS728TPPPvidsMembership renders the VLANInterfaceList wcd section
// (PVID + per-VLAN join list per port). Mirrors Python
// web_gs728tpp.render_pvids_membership.
func RenderGS728TPPPvidsMembership(state *State) string {
	var rows strings.Builder
	for _, p := range physicalGS728TPPPorts(state) {
		var entries strings.Builder
		for _, vid := range sortedIntKeys(state.Vlans) {
			vlan := state.Vlans[vid]
			if !vlan.Member[p] {
				continue
			}
			tagging := "2"
			if vlan.Untagged[p] {
				tagging = "1"
			}
			fmt.Fprintf(&entries, "<VLANEntry><VLANID>%d</VLANID>"+
				"<taggingMode>%s</taggingMode>"+
				"<customerMulticastTVVLANEnabled>2</customerMulticastTVVLANEnabled>"+
				"</VLANEntry>", vid, tagging)
		}
		pvid := 1
		if v, ok := state.Pvids[p]; ok {
			pvid = v
		}
		fmt.Fprintf(&rows,
			"<Interface><interfaceName>g%d</interfaceName>"+
				"<interfaceType>1</interfaceType><interfaceID>%d</interfaceID>"+
				"<PVID>%d</PVID><frameType>1</frameType>"+
				"<ingressFilteringEnabled>2</ingressFilteringEnabled>"+
				"<JoinVLANList>%s</JoinVLANList></Interface>",
			p, p, pvid, entries.String())
	}
	return goAheadWcd("<VLANInterfaceList type=\"section\">" + rows.String() + "</VLANInterfaceList>")
}

// RenderGS728TPPVlans renders the VLANList wcd section. Mirrors Python
// web_gs728tpp.render_vlans.
func RenderGS728TPPVlans(state *State) string {
	var rows strings.Builder
	for _, vid := range sortedIntKeys(state.Vlans) {
		vlanType := "2"
		if vid == 1 {
			vlanType = "1"
		}
		fmt.Fprintf(&rows, "<VLAN><VLANID>%d</VLANID><VLANName>%s</VLANName>"+
			"<authorizationType>1</authorizationType>"+
			"<VLANType>%s</VLANType></VLAN>", vid, xmlEscape(state.Vlans[vid].Name), vlanType)
	}
	return goAheadWcd("<VLANList type=\"section\">" + rows.String() + "</VLANList>")
}

// RenderGS728TPPPoE renders the PoEPSEInterfaceList wcd section. Mirrors
// Python web_gs728tpp.render_poe.
func RenderGS728TPPPoE(state *State) string {
	var rows strings.Builder
	for _, p := range sortedIntKeys(state.Poe) {
		sim := state.Poe[p]
		fmt.Fprintf(&rows,
			"<Interface><interfaceName>g%d</interfaceName>"+
				"<interfaceType>1</interfaceType><interfaceID>%d</interfaceID>"+
				"<adminEnable>%s</adminEnable>"+
				"<detectionStatus>%d</detectionStatus>"+
				"<poweredDevice></poweredDevice><powerPriority>3</powerPriority>"+
				"<powerClassification>1</powerClassification>"+
				"<outputVoltage>0</outputVoltage><outputCurrent>0</outputCurrent>"+
				"<outputPower>%d</outputPower>"+
				"<powerLimit>30000</powerLimit></Interface>",
			p, p, goAheadAdminText(sim.Admin), sim.Detect, sim.PowerMw)
	}
	return goAheadWcd("<PoEPSEInterfaceList type=\"section\">" + rows.String() + "</PoEPSEInterfaceList>")
}

// RenderGS728TPPMacs renders the ForwardingTable wcd section. Mirrors
// Python web_gs728tpp.render_macs.
func RenderGS728TPPMacs(state *State) string {
	var rows strings.Builder
	for _, m := range state.Macs {
		fmt.Fprintf(&rows,
			"<Entry><VLANName>default</VLANName>"+
				"<VLANID>%d</VLANID>"+
				"<MACAddress>%s</MACAddress>"+
				"<interfaceType>1</interfaceType><interfaceName>g%d"+
				"</interfaceName><addressType>3</addressType></Entry>",
			m.Vlan, goAheadMacText(m.MacBytes), m.BridgePort)
	}
	return goAheadWcd("<ForwardingTable type=\"section\">" + rows.String() + "</ForwardingTable>")
}

// goAheadLLDPIDText renders an LLDP chassis/port-id for the wcd page. A
// MAC-address subtype id is stored in the shared LldpSim field as the 6 raw
// latin-1 bytes; the real GS728TPP web page renders that as lowercase
// colon-hex. A non-MAC id (a plain interface-name string) is rendered
// unchanged. Mirrors Python web_gs728tpp._lldp_id_text.
func goAheadLLDPIDText(raw string) string {
	if len(raw) == 6 {
		parts := make([]string, 6)
		for i, c := range []byte(raw) {
			parts[i] = fmt.Sprintf("%02x", c)
		}
		return strings.Join(parts, ":")
	}
	return raw
}

// RenderGS728TPPLLDP renders the LLDPMEDNeighborList wcd section. Mirrors
// Python web_gs728tpp.render_lldp.
func RenderGS728TPPLLDP(state *State) string {
	var rows strings.Builder
	for _, n := range state.Lldp {
		fmt.Fprintf(&rows,
			"<NeighborEntry><interfaceID>%d</interfaceID>"+
				"<interfaceType>1</interfaceType><interfaceName>g%d"+
				"</interfaceName><deviceIDSubtype>4</deviceIDSubtype>"+
				"<deviceID>%s</deviceID>"+
				"<advertisedPortIDSubtype>3</advertisedPortIDSubtype>"+
				"<advertisedPortID>%s</advertisedPortID>"+
				"<portDescription>%s</portDescription>"+
				"<systemName>%s</systemName></NeighborEntry>",
			n.LocalPort, n.LocalPort,
			xmlEscape(goAheadLLDPIDText(n.Chassis)), xmlEscape(goAheadLLDPIDText(n.PortID)),
			xmlEscape(n.PortDesc), xmlEscape(n.SysName))
	}
	return goAheadWcd("<LLDPMEDNeighborList type=\"section\">" + rows.String() + "</LLDPMEDNeighborList>")
}

// RenderGS728TPPMgmtIP renders the IPv4InterfaceList/IPv4GatewayList wcd
// sections. Mirrors Python web_gs728tpp.render_mgmt_ip.
func RenderGS728TPPMgmtIP(state *State) string {
	m := state.Mgmt
	data := "<IPv4InterfaceList type=\"section\"><ifEntry>" +
		"<interfaceName>VLAN5</interfaceName>" +
		"<IPAddr>" + m.Address + "</IPAddr><subnetMask>" + m.Netmask + "</subnetMask>" +
		"<owner>2</owner></ifEntry></IPv4InterfaceList>" +
		"<IPv4GatewayList type=\"section\"><GWEntry>" +
		"<IPAddr>" + m.Gateway + "</IPAddr><fwdStatus>1</fwdStatus>" +
		"</GWEntry></IPv4GatewayList>"
	return goAheadWcd(data)
}

// RenderGS728TPPDeviceInfoAndSensors renders DeviceBasicInfo (cosmetic
// identity) + DiagnosticsUnitList (the sensors the library actually reads
// back via webui.ParseGoAheadSensors). The DiagnosticsUnitList fields come
// from state.SysinfoSensors() (each SensorSim carries the XML tag in
// Instance and the wire code in Raw). Mirrors Python
// web_gs728tpp.render_device_info_and_sensors.
func RenderGS728TPPDeviceInfoAndSensors(state *State) string {
	var diag strings.Builder
	for _, s := range state.SysinfoSensors() {
		fmt.Fprintf(&diag, "<%s>%s</%s>", s.Instance, s.Raw, s.Instance)
	}
	dev := "<DeviceBasicInfo type=\"section\">" +
		"<deviceName>" + xmlEscape(state.Hostname) + "</deviceName>" +
		"<model>164</model>" +
		"<firmwareVersion>" + xmlEscape(state.Firmware) + "</firmwareVersion>" +
		"<MacAddre>" + goAheadMacText(state.NsdpMac) + "</MacAddre>" +
		"<serialNumber>" + xmlEscape(state.Serial) + "</serialNumber>" +
		"<bootVersion>2.0.0.11</bootVersion>" +
		"<systemUpTime>1366421600</systemUpTime></DeviceBasicInfo>"
	diagSec := "<DiagnosticsUnitList type=\"section\"><Entry><unitID>1</unitID>" +
		diag.String() + "<upTime>1366421600</upTime></Entry></DiagnosticsUnitList>"
	return goAheadWcd(dev + diagSec)
}

// goAheadWcdRoute is one file= substring -> renderer mapping. An ordered
// slice (not a map) so route matching is deterministic, mirroring Python
// web_gs728tpp._ROUTES's tuple-of-tuples order (not that overlapping
// needles exist today, but a future one should not depend on map
// iteration order to resolve).
type goAheadWcdRoute struct {
	Needle   string
	Renderer func(*State) string
}

var goAheadWcdRoutes = []goAheadWcdRoute{
	{"SystemInfo_master", RenderGS728TPPDeviceInfoAndSensors},
	{"IPConf_master", RenderGS728TPPMgmtIP},
	{"portConfiguration_master", RenderGS728TPPPorts},
	{"PortPvidConf_master", RenderGS728TPPPvidsMembership},
	{"VlanConfBasic_master", RenderGS728TPPVlans},
	{"DynamicAddresses_master", RenderGS728TPPMacs},
	{"PoeInterfaceConf_master", RenderGS728TPPPoE},
	{"NeighborsInformation_master", RenderGS728TPPLLDP},
}

// RenderGS728TPPWcd routes a (percent-decoded) wcd?{file=..}{Object}..
// query to its renderer, ok=false if this face serves no such wcd query
// (the caller 404s, never fabricating a page). Mirrors Python
// web_gs728tpp.render_wcd.
func RenderGS728TPPWcd(state *State, query string) (string, bool) {
	for _, route := range goAheadWcdRoutes {
		if strings.Contains(query, route.Needle) {
			return route.Renderer(state), true
		}
	}
	return "", false
}

// xmlEscape escapes text for embedding as XML character data, mirroring
// Python's xml.sax.saxutils.escape usage throughout web_gs728tpp.py (this
// Go port uses the stdlib encoding/xml escaper -- same one httpface.go's
// goaheadStatusResponse already uses -- rather than hand-rolling a
// replacer, for one shared correct implementation).
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
