// cliface_render.go ports src/netgear_switch/virtual/cli_fastpath.py
// (418 lines) -- the normative source; that repo is read-only from here --
// pin 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362. Any discrepancy between
// this file and the Python source is a bug here, unless called out in a
// comment.
//
// "Render FASTPATH CLI `show` output from a VirtualSwitchState. The CLI
// analogue of `virtual/web_gsm7252ps.py`: pure functions turning device
// state into the exact fixed-width text shapes the `protocols.cli.parse`
// parsers consume, so a VirtualSwitch answers the FASTPATH CLI like real
// hardware. Only PHYSICAL ports (ifIndex <= the model's port_count) are
// ever printed -- the CPU/LAG pseudo-interfaces in state never appear on a
// `show port all` / `show vlan` page, exactly as on the real switch."
// (cli_fastpath.py:1-8)

package virtual

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// physPorts returns the physical ports this switch prints on a `show port
// all`/`show vlan <id>`/`show vlan port all` page: every port key present
// in State.Ports whose ifIndex is within [1, model.PortCount] -- NOT an
// IfType check -- mirroring Python `_phys_ports` (cli_fastpath.py:28-30)
// exactly. Every seeded pseudo-interface (CPU/LAG/VLAN-routing rows) has
// an ifIndex well above PortCount, so this range check drops them the
// same way the Python source's does.
func (f *CliFace) physPorts() []int {
	portCount := f.state.mustModel().PortCount
	var out []int
	for p := range f.state.Ports {
		if p >= 1 && p <= portCount {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// iface is the ifName the CLI prints for port, mirroring Python `_iface`
// (cli_fastpath.py:33-42): the seeded PortSim.Name when present and
// non-empty (so gsm7228ps renders "1/gN"/"1/xgN" exactly as seeded),
// falling back to the "1/0/N" form for a port with no seeded name (e.g.
// an LLDP local port absent from State.Ports).
func (f *CliFace) iface(port int) string {
	if sim, ok := f.state.Ports[port]; ok && sim.Name != "" {
		return sim.Name
	}
	return fmt.Sprintf("1/0/%d", port)
}

// isM4300 reports whether this is the M4300 FASTPATH image, whose `show
// poe`/`show environment` column shapes differ from the gsm7252ps image
// (no PoE Temperature column; the PSU sub-table is headed "Power
// Modules:" not "Power supplies:"), mirroring Python `_is_m4300`
// (cli_fastpath.py:60-66). Identical predicate to usesIPManagementDialect
// (cliface.go) -- kept as a separate, identically-named method here for
// direct correspondence with the ported source.
func (f *CliFace) isM4300() bool {
	return f.usesIPManagementDialect()
}

// cliDotted renders one "Label.......... value" dotted-leader line,
// mirroring Python `_dotted` (cli_fastpath.py:69-71) EXACTLY: fill =
// max(2, 46 - len(label)), and ALWAYS a single space before value (even
// when value is "").
func cliDotted(label, value string) string {
	fill := 46 - len(label)
	if fill < 2 {
		fill = 2
	}
	return label + strings.Repeat(".", fill) + " " + value
}

// cliTable renders headers + a "----" ruler + rows as FASTPATH's
// fixed-width table shape, mirroring Python `_table` (cli_fastpath.py:
// 74-81) EXACTLY: each cell is left-justified to its column's width
// (Python str.ljust -- a cell whose content already meets or exceeds the
// width is left UNCHANGED, no forced trailing padding), and cells are
// joined with a SINGLE space (not two). No leading or trailing blank
// line -- unlike a byte-for-byte real-hardware transcript (whose leading
// blank line is an artifact of the real device's command-echo/prompt
// framing that this in-process mock never produces), this is exactly what
// cli_fastpath.py itself returns.
func cliTable(headers []string, widths []int, rows [][]string) string {
	ljust := func(s string, w int) string {
		if len(s) >= w {
			return s
		}
		return s + strings.Repeat(" ", w-len(s))
	}
	line := func(cells []string) string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			parts[i] = ljust(cell, w)
		}
		return strings.Join(parts, " ")
	}
	lines := make([]string, 0, len(rows)+2)
	lines = append(lines, line(headers))
	dashes := make([]string, len(widths))
	for i, w := range widths {
		dashes[i] = strings.Repeat("-", w)
	}
	lines = append(lines, strings.Join(dashes, " "))
	for _, row := range rows {
		lines = append(lines, line(row))
	}
	return strings.Join(lines, "\n")
}

// cliMacHex formats raw MAC-shaped bytes as "XX:XX:XX:XX:XX:XX", mirroring
// Python `_mac_text` (cli_fastpath.py:84-87) -- the str-vs-bytes branch
// there exists only because Python's LldpSim.chassis is a `str` of raw
// latin-1-valued characters while NsdpMac/MacBytes are `bytes`; Go's raw
// byte slice covers both uniformly.
func cliMacHex(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// cliSpeedText mirrors Python `_speed_text` (cli_fastpath.py:90-93): "1G
// Full" for a multiple of 1000 Mbps >= 1000, else "<mbps> Full".
func cliSpeedText(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%dG Full", mbps/1000)
	}
	return fmt.Sprintf("%d Full", mbps)
}

// --- show version / show network (cli_fastpath.py:99-127) ------------------

// renderVersion mirrors Python `render_version` (cli_fastpath.py:99-112).
func (f *CliFace) renderVersion() string {
	sm := f.state.mustModel()
	descr := f.state.SysDescr
	if descr == "" {
		descr = fmt.Sprintf("NETGEAR %s Managed Switch", sm.DisplayName)
	}
	modelName := f.state.ModelName
	if modelName == "" {
		modelName = sm.DisplayName
	}
	return strings.Join([]string{
		"Switch: 1",
		"",
		cliDotted("System Description", descr),
		cliDotted("Machine Model", modelName),
		cliDotted("Serial Number", f.state.Serial),
		cliDotted("Burned In MAC Address", cliMacHex(f.state.NsdpMac[:])),
		cliDotted("Software Version", f.state.Firmware),
	}, "\n")
}

// renderNetwork mirrors Python `render_network` (cli_fastpath.py:115-127).
// Deliberately ALWAYS uses the "Configured IPv4 Protocol" label -- even on
// M4300, whose real firmware labels this "Method" (parse.go's parseMgmtIP
// tries that as a fallback) -- because the ported source itself never
// branches on model here; only the CLI COMMAND name differs by model
// (spec.NetworkCmd), not this renderer's output shape.
func (f *CliFace) renderNetwork() string {
	proto := "None"
	if f.state.Mgmt.Mode == "dhcp" {
		proto = "DHCP"
	}
	return strings.Join([]string{
		cliDotted("Interface Status", "Up"),
		cliDotted("IP Address", f.state.Mgmt.Address),
		cliDotted("Subnet Mask", f.state.Mgmt.Netmask),
		cliDotted("Default Gateway", f.state.Mgmt.Gateway),
		cliDotted("Burned In MAC Address", cliMacHex(f.state.NsdpMac[:])),
		cliDotted("Configured IPv4 Protocol", proto),
		cliDotted("Management VLAN ID", "1"),
	}, "\n")
}

// --- show port all (cli_fastpath.py:133-163) --------------------------------

// renderPorts mirrors Python `render_ports` (cli_fastpath.py:171-204):
// NINE columns -- Intf/Type/Admin/Physical(Mode)/Physical(Status)/
// Link(Status)/Link(Trap)/LACP(Mode)/Flow(Mode). Link Trap and LACP Mode are
// FIXED constants ("Enable"/"Enable"), never derived from State -- the
// ported source itself never models them. Physical Mode comes from
// PortSim.physicalMode() (defaults to "Auto") and Flow Mode from
// PortSim.FlowControl -- FROM STATE, not hardcoded, so this face can show a
// speed/flow-control write at all.
//
// On the M4300 dialect ONLY, a tenth "Stack Capable" column is appended,
// always "Yes" for a physical port -- MEASURED real-hardware shape (see
// testdata/cli/m4300_24x_show_port_all.txt: every physical-port row reads
// "Yes", every lag/vlan pseudo-row reads "No", and this face only ever
// renders physical rows here). Python's own mock never modelled this column
// at all -- a real gap on that side, not something this port narrows for
// its own sake: without it, no virtual-fake round-trip exercises
// fastpath.parsePortStatus's BY-HEADER-NAME Flow Mode lookup, the exact
// column-position hazard that column caused on real M4300 firmware (see
// parsePortStatus's doc comment).
func (f *CliFace) renderPorts() string {
	headers := []string{"Intf", "Type", "Admin", "Physical", "Physical", "Link", "Link", "LACP", "Flow"}
	widths := []int{9, 6, 9, 10, 10, 6, 7, 6, 7}
	stackCapable := f.isM4300()
	if stackCapable {
		headers = append(headers, "Stack")
		widths = append(widths, 8)
	}
	var rows [][]string
	for _, p := range f.physPorts() {
		sim := f.state.Ports[p]
		physStatus := ""
		if sim.Link && sim.Speed != 0 {
			physStatus = cliSpeedText(sim.Speed)
		}
		admin := "Disable"
		if sim.Admin {
			admin = "Enable"
		}
		link := "Down"
		if sim.Link {
			link = "Up"
		}
		flow := "Disable"
		if sim.FlowControl {
			flow = "Enable"
		}
		row := []string{
			f.iface(p), "", admin, sim.physicalMode(), physStatus, link, "Enable", "Enable", flow,
		}
		if stackCapable {
			row = append(row, "Yes")
		}
		rows = append(rows, row)
	}
	return cliTable(headers, widths, rows)
}

// --- show vlan brief / show vlan <id> (cli_fastpath.py:169-200) ------------

// renderVlanBrief mirrors Python `render_vlan_brief` (cli_fastpath.py:
// 169-177).
func (f *CliFace) renderVlanBrief() string {
	headers := []string{"VLAN ID", "VLAN Name", "VLAN Type"}
	widths := []int{7, 32, 19}
	var rows [][]string
	for _, vid := range sortedIntKeys(f.state.Vlans) {
		vtype := "Static"
		if vid == 1 {
			vtype = "Default"
		}
		rows = append(rows, []string{strconv.Itoa(vid), f.state.Vlans[vid].Name, vtype})
	}
	return cliTable(headers, widths, rows)
}

// renderVlanDetail mirrors Python `render_vlan_detail` (cli_fastpath.py:
// 180-200) EXACTLY, including that it consults ONLY VlanSim.Member (never
// ConfiguredOnly) -- a ConfiguredOnly-only port renders identically to any
// other non-member port ("Exclude"/"Autodetect"/"Untagged"), matching the
// ported source's own behavior (the parser only ever reads Current ==
// "Include" rows regardless).
func (f *CliFace) renderVlanDetail(vid int) string {
	vsim := f.state.Vlans[vid]
	name := ""
	vtype := "Static"
	if vid == 1 {
		vtype = "Default"
	}
	if vsim != nil {
		name = vsim.Name
	}
	header := []string{
		fmt.Sprintf("VLAN ID: %d", vid),
		fmt.Sprintf("VLAN Name: %s", name),
		"VLAN Type: " + vtype,
		"",
	}
	headers := []string{"Interface", "Current", "Configured", "Tagging"}
	widths := []int{10, 8, 11, 8}
	var member, untagged map[int]bool
	if vsim != nil {
		member, untagged = vsim.Member, vsim.Untagged
	}
	var rows [][]string
	for _, p := range f.physPorts() {
		var current, configured, tagging string
		if member[p] {
			current, configured = "Include", "Include"
			tagging = "Tagged"
			if untagged[p] {
				tagging = "Untagged"
			}
		} else {
			current, configured, tagging = "Exclude", "Autodetect", "Untagged"
		}
		rows = append(rows, []string{f.iface(p), current, configured, tagging})
	}
	return strings.Join(header, "\n") + "\n" + cliTable(headers, widths, rows)
}

// --- show vlan port all / PVIDs (cli_fastpath.py:206-233) ------------------

// renderPvids mirrors Python `render_pvids` (cli_fastpath.py:206-233):
// EIGHT columns, of which only Interface + the first "Port" (VLAN ID
// Configured) column are consulted by the parser -- the rest (Acceptable
// Frame Types, both Ingress Filtering columns, GVRP, Default Priority)
// are FIXED constants, never derived from State.
func (f *CliFace) renderPvids() string {
	headers := []string{"Interface", "Port", "Port", "Acceptable", "Ingress", "Ingress", "GVRP", "Default"}
	widths := []int{9, 10, 8, 11, 10, 9, 7, 8}
	var rows [][]string
	for _, p := range f.physPorts() {
		pvid := 1
		if v, ok := f.state.Pvids[p]; ok {
			pvid = v
		}
		pvidStr := strconv.Itoa(pvid)
		rows = append(rows, []string{f.iface(p), pvidStr, pvidStr, "Admit All", "Disable", "Disable", "Enable", "0"})
	}
	return cliTable(headers, widths, rows)
}

// --- show mac-addr-table (cli_fastpath.py:239-248) --------------------------

// renderMacTable mirrors Python `render_mac_table` (cli_fastpath.py:
// 239-248): IfIndex is State.BridgePorts[MacSim.BridgePort] when a join
// entry exists, else MacSim.BridgePort itself (the seed's own bridge-port
// number standing in directly, for every seed with no BridgePorts join
// map at all).
func (f *CliFace) renderMacTable() string {
	headers := []string{"VLAN ID", "MAC Address", "Interface", "IfIndex", "Status"}
	widths := []int{7, 18, 21, 7, 12}
	var rows [][]string
	for _, m := range f.state.Macs {
		ifIndex := m.BridgePort
		if joined, ok := f.state.BridgePorts[m.BridgePort]; ok {
			ifIndex = joined
		}
		iface := fmt.Sprintf("1/0/%d", ifIndex)
		if sim, ok := f.state.Ports[ifIndex]; ok {
			iface = sim.Name
		}
		rows = append(rows, []string{
			strconv.Itoa(m.Vlan), cliMacHex(m.MacBytes[:]), iface, strconv.Itoa(ifIndex), "Learned",
		})
	}
	return cliTable(headers, widths, rows)
}

// --- show lldp remote-device all (cli_fastpath.py:254-269) -----------------

// renderLLDP mirrors Python `render_lldp` (cli_fastpath.py:254-269): a
// 3-line title block ("LLDP Remote Device Summary", "", "Local") ABOVE the
// table -- the SECOND physical header line's own text is just "Local"
// (the real device wraps "Local\nInterface" over two lines; this ported
// source's own table header column is plain "Interface").
func (f *CliFace) renderLLDP() string {
	headers := []string{"Interface", "RemID", "Chassis ID", "Port ID", "System Name"}
	widths := []int{9, 8, 20, 18, 18}
	var rows [][]string
	for _, n := range f.state.Lldp {
		chassis := ""
		if n.Chassis != "" {
			chassis = cliMacHex([]byte(n.Chassis))
		}
		rows = append(rows, []string{f.iface(n.LocalPort), strconv.Itoa(n.RemIdx), chassis, n.PortID, n.SysName})
	}
	title := []string{"LLDP Remote Device Summary", "", "Local"}
	return strings.Join(title, "\n") + "\n" + cliTable(headers, widths, rows)
}

// --- show poe port info all (cli_fastpath.py:275-345) -----------------------

// cliPoeStatusText is the Status-column text a real switch prints for one
// PSE port, mirroring Python `_poe_status_text` (cli_fastpath.py:275-300)
// EXACTLY, including its side effect: a positive CliStatusLagReads is
// CONSUMED (decremented) by this call, mirroring "rendering it consumes
// the lag, exactly as re-reading the table on the device eventually shows
// the new state." See PoeSim.CliStatusLagReads's own doc comment
// (state.go) for the hardware measurement this reproduces.
func cliPoeStatusText(psim *PoeSim) string {
	if psim.CliStatusLagReads > 0 {
		psim.CliStatusLagReads--
		return "Disabled"
	}
	if !psim.Admin {
		return "Disabled"
	}
	if psim.Detect == 3 {
		return "Delivering Power"
	}
	if psim.Detect == 4 || psim.Detect == 6 {
		return "Fault"
	}
	return "Searching"
}

// renderPoE mirrors Python `render_poe` (cli_fastpath.py:303-345) EXACTLY,
// including the M4300 Temperature-column omission (parse.go's parsePoE
// resolves columns BY NAME, so either shape parses; the mock must emit
// whichever the driving model really prints) and the synthetic,
// port-index-threshold-derived High-Power/Max-Power/Output-Voltage
// columns the ported source itself hardcodes (NOT derived from any seeded
// field) -- ported verbatim rather than invented independently.
func (f *CliFace) renderPoE() string {
	m4300 := f.isM4300()
	headers := []string{"Intf", "High Power", "Max Power (mW)", "Class", "Power (mW)", "Output Current (mA)", "Output Voltage (V)"}
	widths := []int{7, 11, 15, 9, 11, 20, 19}
	if !m4300 {
		headers = append(headers, "Temperature")
		widths = append(widths, 13)
	}
	headers = append(headers, "Status", "Fault Status")
	widths = append(widths, 18, 13)

	var rows [][]string
	for _, p := range sortedIntKeys(f.state.Poe) {
		psim := f.state.Poe[p]
		status := cliPoeStatusText(psim)
		highPower := "No"
		maxPower := "18000"
		if p <= 8 {
			highPower = "Yes"
			maxPower = "32000"
		}
		class := "Unknown"
		if psim.PowerMw != 0 {
			class = "4"
		}
		outputVoltage := "0"
		if psim.PowerMw != 0 {
			outputVoltage = "54"
		}
		row := []string{
			f.iface(p), highPower, maxPower, class, strconv.Itoa(psim.PowerMw), "0", outputVoltage,
		}
		if !m4300 {
			row = append(row, "30")
		}
		row = append(row, status, "No Error")
		rows = append(rows, row)
	}
	return cliTable(headers, widths, rows)
}

// --- show environment (cli_fastpath.py:351-394) ------------------------

// renderEnvironment mirrors Python `render_environment` (cli_fastpath.py:
// 351-394): a "Temp (C)"/"Fan Speed, RPM" leading summary pair (falling
// back to the FIXED constants "36"/"Not Supported" when State.Sensors
// carries no temperature/fan entry at all -- never derived from anything
// else), then the three sub-tables (Temperature Sensors: / Fans: / the
// M4300-vs-else PSU header), each with its full column set.
func (f *CliFace) renderEnvironment() string {
	var temps, fans, psus []SensorSim
	for _, s := range f.state.Sensors {
		switch s.Kind {
		case "temperature":
			temps = append(temps, s)
		case "fan":
			fans = append(fans, s)
		case "power":
			psus = append(psus, s)
		}
	}

	summaryTemp := "36"
	if len(temps) > 0 {
		summaryTemp = temps[0].Raw
	}
	summaryFan := "Not Supported"
	if len(fans) > 0 {
		summaryFan = fans[0].Raw
	}

	out := []string{
		cliDotted("Temp (C)", summaryTemp),
		cliDotted("Fan Speed, RPM", summaryFan),
		"",
		"Temperature Sensors:",
	}

	var tempRows [][]string
	for i, s := range temps {
		tempRows = append(tempRows, []string{"1", strconv.Itoa(i + 1), s.Instance, s.Raw, "Normal", "55"})
	}
	out = append(out, cliTable(
		[]string{"Unit", "Sensor", "Description", "Temp (C)", "State", "Max_Temp (C)"},
		[]int{4, 6, 16, 10, 14, 14},
		tempRows,
	))

	out = append(out, "", "Fans:")
	var fanRows [][]string
	for i, s := range fans {
		fanRows = append(fanRows, []string{"1", strconv.Itoa(i + 1), s.Instance, "Fixed", s.Raw, "Not Supported", "Operational"})
	}
	out = append(out, cliTable(
		[]string{"Unit", "Fan", "Description", "Type", "Speed", "Duty", "State"},
		[]int{4, 3, 14, 9, 13, 13, 14},
		fanRows,
	))

	psuHeader := "Power supplies:"
	if f.isM4300() {
		psuHeader = "Power Modules:"
	}
	out = append(out, "", psuHeader)
	var psuRows [][]string
	for i, s := range psus {
		psuRows = append(psuRows, []string{"1", strconv.Itoa(i + 1), s.Instance, "Fixed", "Operational"})
	}
	out = append(out, cliTable(
		[]string{"Unit", "Power supply", "Description", "Type", "State"},
		[]int{4, 12, 16, 10, 14},
		psuRows,
	))

	return strings.Join(out, "\n")
}

// --- show interface ethernet <iface> (cli_fastpath.py:400-418) -------------

// renderInterfaceCounters mirrors Python `render_interface_counters`
// (cli_fastpath.py:400-418) EXACTLY -- including that, unlike every other
// renderer in this file, it does NOT honor a "missing counter -> omit the
// line" contract: a nil PortSim counter (or an entirely absent port)
// renders as literal "0" ("rx_octets or 0"), so all SEVEN lines (six
// counters plus the fixed "Time Since Counters Last Cleared" line) are
// ALWAYS present. A seed's nil counter therefore reads back over CLI as a
// present zero, not nil -- a genuine (ported, not invented) CLI-protocol
// behavior, different from every other backend's "never fabricate a 0"
// convention.
func (f *CliFace) renderInterfaceCounters(port int) string {
	sim := f.state.Ports[port]
	u64 := func(p *uint64) string {
		if sim == nil || p == nil {
			return "0"
		}
		return strconv.FormatUint(*p, 10)
	}
	var rxOctets, rxUcast, rxErrors, txOctets, txUcast, txErrors *uint64
	if sim != nil {
		rxOctets, rxUcast, rxErrors = sim.RxOctets, sim.RxUcast, sim.RxErrors
		txOctets, txUcast, txErrors = sim.TxOctets, sim.TxUcast, sim.TxErrors
	}
	return strings.Join([]string{
		cliDotted("Total Packets Received (Octets)", u64(rxOctets)),
		cliDotted("Unicast Packets Received", u64(rxUcast)),
		cliDotted("Total Packets Received with MAC Errors", u64(rxErrors)),
		cliDotted("Total Packets Transmitted (Octets)", u64(txOctets)),
		cliDotted("Unicast Packets Transmitted", u64(txUcast)),
		cliDotted("Total Transmit Errors", u64(txErrors)),
		cliDotted("Time Since Counters Last Cleared", "1 day 0 hr 0 min 0 sec"),
	}, "\n")
}

// --- show users / show ip http / show telnetcon / show ip ssh ------------
//
// PRINCIPLE-5 NOTE: Python's virtual CLI face has NO renderer for any of
// these four commands at pin b26eb1f -- UserSim's own doc comment says so
// explicitly ("The CLI face has no `show users` yet"), and cli_fastpath.py
// has no render_users/render_services function to port. The shapes below
// are grounded in parse_users'/parse_services' own docstring transcripts
// (protocols/cli/parse.py, pin b26eb1f) rather than in an existing Python
// fake renderer -- see fastpath/parse.go's matching principle-5 note for
// the parser side of the same gap.

// cliDottedColon renders one "Label: .......... value" dotted-leader line,
// the format `show ip ssh` alone uses among every FASTPATH scalar command:
// a trailing colon BEFORE the dots (measured: "Administrative Mode:
// .......... Enabled"). Every other cliDotted call in this file omits the
// colon; see fastpath/parse.go's parseServices doc comment for why
// `show ip ssh` needs the split.
func cliDottedColon(label, value string) string {
	return cliDotted(label+":", value)
}

// cliUsersTable renders headers1/headers2/rows as FASTPATH's `show users`
// fixed-width table shape: TWO header lines (the real device wraps "User
// Name"/"SNMPv3 Access Mode"/etc. over two rows) above the ruler, mirroring
// the transcript in parse_users' own doc comment (parse.py:779-782, pin
// b26eb1f). A dedicated helper rather than a second cliTable overload: this
// is the only FASTPATH table this package renders with more than one
// header line.
func cliUsersTable(headers1, headers2 []string, widths []int, rows [][]string) string {
	ljust := func(s string, w int) string {
		if len(s) >= w {
			return s
		}
		return s + strings.Repeat(" ", w-len(s))
	}
	line := func(cells []string) string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			parts[i] = ljust(cell, w)
		}
		return strings.Join(parts, " ")
	}
	lines := []string{line(headers1), line(headers2)}
	dashes := make([]string, len(widths))
	for i, w := range widths {
		dashes[i] = strings.Repeat("-", w)
	}
	lines = append(lines, strings.Join(dashes, " "))
	for _, row := range rows {
		lines = append(lines, line(row))
	}
	return strings.Join(lines, "\n")
}

// renderUsers renders "show users" from f.state.Users -- see the package
// PRINCIPLE-5 note above. Column widths (24/12/11/14/10) are transcribed
// from parse_users' own docstring transcript, which is the only measured
// column-width evidence available at this pin. Most rows' SNMPv3 columns
// render blank (UserSim.SNMPv3Access/Auth/Encryption default to ""): only
// ONE row anywhere in the pinned Python source has a measured SNMPv3
// value (m4300-24x's admin row -- see SeedM4300_24X).
func (f *CliFace) renderUsers() string {
	headers1 := []string{"User", "", "SNMPv3", "SNMPv3", "SNMPv3"}
	headers2 := []string{"User Name", "Access Mode", "Access Mode", "Authentication", "Encryption"}
	widths := []int{24, 12, 11, 14, 10}
	var rows [][]string
	for _, u := range f.state.Users {
		rows = append(rows, []string{u.Name, u.CLIAccessMode, u.SNMPv3Access, u.SNMPv3Auth, u.SNMPv3Encryption})
	}
	return cliUsersTable(headers1, headers2, widths, rows)
}

// cliServicePort renders one optional port line, omitted entirely (not
// printed blank) when sim.CLIPort is nil -- mirroring the measured absence
// of an "SSH Port"/"Telnet Server Port" line on a firmware image that
// genuinely does not print one (see ServiceSim.CLIPort's doc comment).
func cliServicePort(dotted func(label, value string) string, label string, sim ServiceSim) string {
	if sim.CLIPort == nil {
		return ""
	}
	return "\n" + dotted(label, strconv.Itoa(*sim.CLIPort))
}

// renderHTTPService renders "show ip http", which carries BOTH the plain
// and secure web servers in one command, mirroring the transcript in
// parse_services' own doc comment ("HTTP Mode (Unsecure)"/"HTTP Port"/
// "HTTP Mode (Secure)"/"Secure Port").
func (f *CliFace) renderHTTPService() string {
	http := f.state.Services["http"]
	https := f.state.Services["https"]
	return cliDotted("HTTP Mode (Unsecure)", enableWord(http.Enabled)) +
		cliServicePort(cliDotted, "HTTP Port", http) +
		"\n" + cliDotted("HTTP Mode (Secure)", enableWord(https.Enabled)) +
		cliServicePort(cliDotted, "Secure Port", https)
}

// enableWord is FASTPATH's long-form Enabled/Disabled spelling, used by
// `show ip http` and `show ip ssh` (see enabledText's doc comment for the
// two spellings this package's parser accepts back).
func enableWord(on bool) string {
	if on {
		return "Enabled"
	}
	return "Disabled"
}

// enableWordShort is FASTPATH's short-form Enable/Disable spelling, used by
// `show telnetcon`'s "Telnet Server Admin Mode" line (measured verbatim in
// parse_services' own doc comment).
func enableWordShort(on bool) string {
	if on {
		return "Enable"
	}
	return "Disable"
}

// renderTelnetService renders "show telnetcon" -- NOT "show telnet" -- the
// INBOUND telnet server, mirroring parse_services' own doc comment.
func (f *CliFace) renderTelnetService() string {
	telnet := f.state.Services["telnet"]
	return cliDotted("Telnet Server Admin Mode", enableWordShort(telnet.Enabled)) +
		cliServicePort(cliDotted, "Telnet Server Port", telnet)
}

// renderSSHService renders "show ip ssh", whose labels carry a trailing
// colon before the dotted leader -- unlike every other FASTPATH scalar
// command (see cliDottedColon).
func (f *CliFace) renderSSHService() string {
	ssh := f.state.Services["ssh"]
	return cliDottedColon("Administrative Mode", enableWord(ssh.Enabled)) +
		cliServicePort(cliDottedColon, "SSH Port", ssh)
}
