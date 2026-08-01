// cliface_render.go: the `show` output renderers CliFace.run dispatches to
// (cliface.go). Unlike Python's separate `cli_fastpath` render module (out
// of the porting dossier's scope, referenced there only by name -- see
// cliface.go's file-level doc comment), no equivalent Go package exists,
// so this file IS the renderer: an auto-sizing fixed-width table builder
// (renderCLITable) plus one function per `show` command, each reading
// straight off the SAME *State every other protocol face projects.
//
// Every renderer here is cross-checked by construction, not by chasing a
// captured transcript: its output is fed straight into the ALREADY-PORTED,
// ALREADY-tested fastpath parsers (fastpath/parse.go, cross-checked there
// against real captures under fastpath/testdata/cli/), and the resulting
// values are asserted against the SAME seeded State fields these renderers
// read from (cliface_test.go). A renderer that drifts from what its own
// parser counterpart expects fails that round-trip immediately.
package virtual

import (
	"fmt"
	"strconv"
	"strings"
)

// --- generic fixed-width table builder ------------------------------------

// renderCLITable builds a FASTPATH-shaped table: a leading blank line, a
// header row, a "----" ruler row, then one data row per rows entry, each
// column auto-sized to fit the WIDER of its header text and every row's
// cell in that column (never a fixed guess that a long seeded value could
// overflow into the next column's ruler span). minWidths optionally floors
// a column's width below the header/data-derived one (e.g. so a narrow
// "VLAN ID" column doesn't collapse to exactly 3 characters); pass nil to
// skip flooring entirely.
func renderCLITable(headers []string, minWidths []int, rows [][]string) string {
	n := len(headers)
	widths := make([]int, n)
	for i, h := range headers {
		w := len(h)
		if minWidths != nil && i < len(minWidths) && minWidths[i] > w {
			w = minWidths[i]
		}
		widths[i] = w
	}
	for _, row := range rows {
		for i := 0; i < n && i < len(row); i++ {
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}
	pad := func(s string, w int) string {
		if len(s) >= w {
			return s + " "
		}
		return s + strings.Repeat(" ", w-len(s))
	}
	rowLine := func(cells []string) string {
		parts := make([]string, n)
		for i := 0; i < n; i++ {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			parts[i] = pad(cell, widths[i])
		}
		return strings.TrimRight(strings.Join(parts, "  "), " ")
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(rowLine(headers))
	b.WriteString("\n")
	dashes := make([]string, n)
	for i, w := range widths {
		dashes[i] = strings.Repeat("-", w)
	}
	b.WriteString(strings.TrimRight(strings.Join(dashes, "  "), " "))
	b.WriteString("\n")
	for _, row := range rows {
		b.WriteString(rowLine(row))
		b.WriteString("\n")
	}
	return b.String()
}

// cliLabelLine renders one "Label.......... value" dotted-leader line,
// matching fastpath's labelRE (`^\s*(.+?)\s*\.{2,}\s*(.*?)\s*$`).
func cliLabelLine(label, value string) string {
	dots := 50 - len(label)
	if dots < 3 {
		dots = 3
	}
	if value == "" {
		return label + strings.Repeat(".", dots)
	}
	return label + strings.Repeat(".", dots) + " " + value
}

func cliLabelBlock(pairs [][2]string) string {
	var b strings.Builder
	b.WriteString("\n")
	for _, p := range pairs {
		b.WriteString(cliLabelLine(p[0], p[1]))
		b.WriteString("\n")
	}
	return b.String()
}

// cliMacHex formats raw MAC bytes as "XX:XX:XX:XX:XX:XX", matching
// fastpath's macTextRE.
func cliMacHex(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// --- show version --------------------------------------------------------

// renderVersion renders "show version", mirroring what fastpath's
// parseVersion reads: "System Description" (primary label), falling back
// to "Machine Model". Reuses State.SysDescr/ModelName/Serial/Firmware --
// the SAME fields the SNMP identify path already reads, so a caller
// identifying this switch over CLI resolves the SAME model key SNMP would.
func (f *CliFace) renderVersion() string {
	s := f.state
	return cliLabelBlock([][2]string{
		{"System Description", s.SysDescr},
		{"Machine Model", s.ModelName},
		{"Serial Number", s.Serial},
		{"Burned In MAC Address", cliMacHex(s.NsdpMac[:])},
		{"Software Version", s.Firmware},
	})
}

// --- show port all ---------------------------------------------------------

// renderPorts renders "show port all": one row per State.Ports entry
// (physical AND pseudo/LAG rows alike -- fastpath's own physPort() drops
// the latter via the SAME Intf-name regexes it would apply to a real
// capture, exactly as it does here). Intf is PortSim.Name verbatim -- the
// SAME text portForIface matches on, so `interface <iface>` and `show
// interface ethernet <iface>` resolve every port this table lists.
func (f *CliFace) renderPorts() string {
	headers := []string{"Intf", "Type", "Admin Mode", "Physical Mode", "Physical Status", "Link Status"}
	minW := []int{9, 6, 10, 10, 15, 6}
	var rows [][]string
	for _, port := range sortedIntKeys(f.state.Ports) {
		sim := f.state.Ports[port]
		admin := "Disable"
		if sim.Admin {
			admin = "Enable"
		}
		link := "Down"
		physStatus := ""
		if sim.Link {
			link = "Up"
			physStatus = strconv.Itoa(sim.Speed) + " Full"
		}
		rows = append(rows, []string{sim.Name, "", admin, "Auto", physStatus, link})
	}
	return renderCLITable(headers, minW, rows)
}

// --- show vlan brief / show vlan (M4300/gsm7228ps rename) -----------------

// renderVlanBrief renders the VLAN id/name summary table, mirroring what
// fastpath's parseVLANBrief reads (VLAN ID + VLAN Name columns only).
func (f *CliFace) renderVlanBrief() string {
	headers := []string{"VLAN ID", "VLAN Name", "VLAN Type"}
	minW := []int{7, 20, 10}
	var rows [][]string
	for _, vid := range sortedIntKeys(f.state.Vlans) {
		vtype := "Static"
		if vid == 1 {
			vtype = "Default"
		}
		rows = append(rows, []string{strconv.Itoa(vid), f.state.Vlans[vid].Name, vtype})
	}
	return renderCLITable(headers, minW, rows)
}

// --- show vlan <id> ---------------------------------------------------------

// renderVlanDetail renders one VLAN's per-port membership page, mirroring
// what fastpath's parseVLANDetail reads: a "VLAN ID: N" / "VLAN Name: name"
// scalar header (matched anywhere in the text, not per-line), then a table
// with Interface/Current/Configured/Tagging columns -- only Current and
// Tagging are actually consulted by the parser (Configured is
// deliberately skipped there too), so this renders every port on the
// switch (mirroring a real "show vlan <id>" page, which lists every port
// regardless of membership), with Current "Include" only for actual
// members. ConfiguredOnly ports (VlanSim.ConfiguredOnly, D-VIRT's own
// documented live divergence) render "Current: Exclude / Configured:
// Include", matching seed.go's own doc comment on that field -- though the
// PARSER drops them either way (Current != "include"), exactly as real
// "show vlan" output does.
func (f *CliFace) renderVlanDetail(vid int) string {
	vsim := f.state.Vlans[vid]
	name := ""
	if vsim != nil {
		name = vsim.Name
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("VLAN ID: %d\n", vid))
	b.WriteString(fmt.Sprintf("VLAN Name: %s\n", name))
	b.WriteString("VLAN Type: Static\n")

	headers := []string{"Interface", "Current", "Configured", "Tagging"}
	minW := []int{9, 7, 10, 7}
	var rows [][]string
	for _, port := range sortedIntKeys(f.state.Ports) {
		sim := f.state.Ports[port]
		current, configured, tagging := "Exclude", "Autodetect", "Untagged"
		if vsim != nil {
			member := vsim.Member[port]
			configuredOnly := vsim.ConfiguredOnly[port]
			switch {
			case member:
				current, configured = "Include", "Include"
			case configuredOnly:
				current, configured = "Exclude", "Include"
			}
			if !vsim.Untagged[port] {
				tagging = "Tagged"
			}
		}
		rows = append(rows, []string{sim.Name, current, configured, tagging})
	}
	b.WriteString(renderCLITable(headers, minW, rows))
	return b.String()
}

// --- show vlan port all -----------------------------------------------------

// renderPvids renders "show vlan port all", mirroring what fastpath's
// parsePVIDs reads: Interface + Port VLAN ID Configured columns (the
// CONFIGURED column, index 1, deliberately not Current -- matching what
// dot1qPvid reports over SNMP, the persistent value). Ports with no
// State.Pvids entry default to VLAN 1, the real device's own default.
func (f *CliFace) renderPvids() string {
	headers := []string{"Interface", "Port VLAN ID Configured", "Port VLAN ID Current"}
	minW := []int{9, 10, 8}
	var rows [][]string
	for _, port := range sortedIntKeys(f.state.Ports) {
		sim := f.state.Ports[port]
		pvid := 1
		if v, ok := f.state.Pvids[port]; ok {
			pvid = v
		}
		rows = append(rows, []string{sim.Name, strconv.Itoa(pvid), strconv.Itoa(pvid)})
	}
	return renderCLITable(headers, minW, rows)
}

// --- show mac-addr-table -----------------------------------------------------

// renderMacTable renders "show mac-addr-table", mirroring what fastpath's
// parseMacTable reads: VLAN ID / MAC Address / (Interface, deliberately
// skipped) / IfIndex columns. IfIndex is the SAME joined ifIndex value the
// SNMP FDB join yields (State.BridgePorts[MacSim.BridgePort] when a join
// entry exists, else MacSim.BridgePort itself when the seed carries no
// join map at all -- every CLI-model seed except gsm7252ps), matching
// parse.go's own documented "the same ifIndex the SNMP FDB join yields"
// contract.
func (f *CliFace) renderMacTable() string {
	headers := []string{"VLAN ID", "MAC Address", "Interface", "IfIndex", "Status"}
	minW := []int{7, 18, 10, 7, 8}
	var rows [][]string
	for _, m := range f.state.Macs {
		ifIndex := m.BridgePort
		if joined, ok := f.state.BridgePorts[m.BridgePort]; ok {
			ifIndex = joined
		}
		iface := ""
		if sim, ok := f.state.Ports[ifIndex]; ok {
			iface = sim.Name
		}
		status := "Learned"
		rows = append(rows, []string{strconv.Itoa(m.Vlan), cliMacHex(m.MacBytes[:]), iface, strconv.Itoa(ifIndex), status})
	}
	return renderCLITable(headers, minW, rows)
}

// --- show lldp remote-device all --------------------------------------------

// renderLLDP renders "show lldp remote-device all", mirroring what
// fastpath's parseLLDP reads: Local Interface / RemID / Chassis ID /
// Port ID / System Name columns.
func (f *CliFace) renderLLDP() string {
	headers := []string{"Local Interface", "RemID", "Chassis ID", "Port ID", "System Name"}
	minW := []int{9, 5, 18, 10, 10}
	var rows [][]string
	for _, n := range f.state.Lldp {
		iface := strconv.Itoa(n.LocalPort)
		if sim, ok := f.state.Ports[n.LocalPort]; ok {
			iface = sim.Name
		}
		rows = append(rows, []string{iface, strconv.Itoa(n.RemIdx), cliMacHex([]byte(n.Chassis)), n.PortID, n.SysName})
	}
	return renderCLITable(headers, minW, rows)
}

// --- show poe port info all -------------------------------------------------

// cliPoeStatusText maps a PoeSim.Detect RFC 3621 pethPsePortDetectionStatus
// wire int (State.ApplyWrite/OIDMap's own canonical encoding: 1=disabled,
// 2=searching, 3=deliveringPower, 4=fault, 5=test, 6=otherFault) to the
// Status-column text fastpath's parsePoE substring-matches against
// ("delivering"/"searching"/"disabled"/"fault", in that priority order).
func cliPoeStatusText(detect int) string {
	switch detect {
	case 1:
		return "Disabled"
	case 2:
		return "Searching"
	case 3:
		return "Delivering Power"
	case 4, 6:
		return "Fault"
	case 5:
		return "Test"
	default:
		return "Unknown"
	}
}

// renderPoE renders "show poe port info all", mirroring what fastpath's
// parsePoE reads: it resolves its three required columns BY NAME (Intf /
// "Power (mW)" / Status, parse.go's poeIntfHdr/poeOutputMwHdr/
// poeStatusHdr), so the header text below must match those literally.
func (f *CliFace) renderPoE() string {
	headers := []string{"Intf", "Power (mW)", "Status"}
	minW := []int{9, 10, 17}
	var rows [][]string
	for _, port := range sortedIntKeys(f.state.Poe) {
		psim := f.state.Poe[port]
		iface := strconv.Itoa(port)
		if sim, ok := f.state.Ports[port]; ok {
			iface = sim.Name
		}
		rows = append(rows, []string{iface, strconv.Itoa(psim.PowerMw), cliPoeStatusText(psim.Detect)})
	}
	return renderCLITable(headers, minW, rows)
}

// --- show environment --------------------------------------------------------

// renderEnvironment renders "show environment"'s three independently
// scanned sub-tables (Temperature Sensors: / Fans: / Power supplies:),
// mirroring what fastpath's parseEnvironment reads: Description at column
// index 2 and Temp/Speed/State at index 3 (temperature) or 4 (fans/PSU) in
// every sub-table, per parse.go's envTempDesc/envTempValue/envFanDesc/
// envFanSpeed/envPsuDesc/envPsuState constants. Reads State.Sensors -- the
// SAME canonical sensor list the SNMP face projects (NOT HTTPSensors,
// which is an HTTP-page-specific alternate view per its own doc comment)
// -- so a model with no "temperature"-kind entries in Sensors (e.g.
// gsm7252ps, whose temperature readings live only in HTTPSensors) honestly
// reports an empty temperature sub-table over CLI too, exactly as that
// model's real SNMP agent does.
//
// The Power supplies sub-table reports OPERATIONAL STATE text, not the
// wattage State.Sensors' "power"-kind Raw field actually carries (a real,
// documented cross-protocol divergence: real "show environment" output has
// no PSU-wattage column at all, only state -- see the fixture cited in
// this file's own package doc). Every seeded "power"-kind sensor is
// therefore reported "Operational" here (health=1.0 once parsed) -- an
// honest CLI-protocol limitation, not a claim about the wattage value.
func (f *CliFace) renderEnvironment() string {
	var b strings.Builder
	b.WriteString("\n")

	tempHeaders := []string{"Unit", "Sensor", "Description", "Temp (C)"}
	var tempRows [][]string
	fanHeaders := []string{"Unit", "Fan", "Description", "Type", "Speed"}
	var fanRows [][]string
	psuHeaders := []string{"Unit", "PSU", "Description", "Type", "State"}
	var psuRows [][]string

	tempN, fanN, psuN := 0, 0, 0
	for _, sensor := range f.state.Sensors {
		switch sensor.Kind {
		case "temperature":
			tempN++
			tempRows = append(tempRows, []string{"1", strconv.Itoa(tempN), sensor.Instance, sensor.Raw})
		case "fan":
			fanN++
			fanRows = append(fanRows, []string{"1", strconv.Itoa(fanN), sensor.Instance, "Fixed", sensor.Raw})
		case "power":
			psuN++
			psuRows = append(psuRows, []string{"1", strconv.Itoa(psuN), sensor.Instance, "Fixed", "Operational"})
		}
	}

	b.WriteString("Temperature Sensors:")
	b.WriteString(renderCLITable(tempHeaders, []int{4, 6, 12, 8}, tempRows))
	b.WriteString("\nFans:")
	b.WriteString(renderCLITable(fanHeaders, []int{4, 3, 12, 6, 6}, fanRows))
	b.WriteString("\nPower supplies:")
	b.WriteString(renderCLITable(psuHeaders, []int{4, 4, 12, 6, 8}, psuRows))
	return b.String()
}

// --- show network / show ip management (M4300 dialect) ---------------------

// renderNetwork renders "show network" (or M4300's "show ip management"),
// mirroring what fastpath's parseMgmtIP reads. The mode label depends on
// this model's dialect (usesIPManagementDialect): "Method" for M4300
// (matching spec.NetworkCmd == "show ip management" there), "Configured
// IPv4 Protocol" for every other model -- rendering only the label THIS
// model's real firmware would show, rather than both, so a test exercising
// the M4300 dialect actually exercises the "Method" fallback branch
// parseMgmtIP has for it.
func (f *CliFace) renderNetwork() string {
	modeLabel := "Configured IPv4 Protocol"
	if f.usesIPManagementDialect() {
		modeLabel = "Method"
	}
	proto := "DHCP"
	if f.state.Mgmt.Mode == "static" {
		proto = "Static"
	}
	return cliLabelBlock([][2]string{
		{"IP Address", f.state.Mgmt.Address},
		{"Subnet Mask", f.state.Mgmt.Netmask},
		{"Default Gateway", f.state.Mgmt.Gateway},
		{"Burned In MAC Address", cliMacHex(f.state.NsdpMac[:])},
		{modeLabel, proto},
	})
}

// --- show interface ethernet <iface> ----------------------------------------

// cliCounterLabels pairs each labelledValues line label
// parseInterfaceCounters reads (parse.go's counterRxBytesLabel etc.) with
// the PortSim field it should carry.
type cliCounterLabel struct {
	label string
	value *uint64
}

// renderInterfaceCounters renders "show interface ethernet <iface>",
// mirroring what fastpath's parseInterfaceCounters reads: six labelled
// counter lines. A nil PortSim counter pointer (this port never exposed
// that counter) OMITS the line entirely -- never a fabricated "0" -- so
// the parser's own "missing -> nil, never a fabricated 0" contract holds
// on the round trip.
func (f *CliFace) renderInterfaceCounters(port int) string {
	sim := f.state.Ports[port]
	if sim == nil {
		return ""
	}
	labels := []cliCounterLabel{
		{"Total Packets Received (Octets)", sim.RxOctets},
		{"Total Packets Transmitted (Octets)", sim.TxOctets},
		{"Unicast Packets Received", sim.RxUcast},
		{"Unicast Packets Transmitted", sim.TxUcast},
		{"Total Packets Received with MAC Errors", sim.RxErrors},
		{"Total Transmit Errors", sim.TxErrors},
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, l := range labels {
		if l.value == nil {
			continue
		}
		b.WriteString(cliLabelLine(l.label, strconv.FormatUint(*l.value, 10)))
		b.WriteString("\n")
	}
	return b.String()
}
