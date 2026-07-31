package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/parse.py at pin 1841111 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries the HTMLDialectGS105PE dialect's own parsers, LIVE-
// VERIFIED on a real GS105PE (10.1.5.29/.30) -- source lines 363-483
// (_GS105PE_ROW_RE/_HIDDEN_VALUE_RE, parse_gs105pe_port_status/pvids/
// stats). GS105PE's VLAN-checkbox page (8021qCf.cgi), membership page
// (8021qMembe.cgi) and login page (login.cgi) are BYTE-IDENTICAL in shape
// to gs305ep's -- confirmed against webui/testdata/http/gs105pe_vlancfg.html
// /gs105pe_membership.html -- so this dialect reuses parse_standard.go's
// ParseVLANIDs, ParseMembership, ParseSelectedVlan, ParseLoginRand and
// ParseCSRFHash verbatim rather than redefining them; only port-status/
// PVID/stats get their own parser here because GS105PE's own portID row
// shape differs from gs305ep's (never closed, and portStatistics.cgi
// specifically carries a trailing `name="portID"` attribute the other
// GS105PE pages don't).
//
// GS105PE's real firmware never closes a `<tr class="portID">` row either
// (the same quirk GS110EMX has -- see parse_gs110emx.go's header comment
// for why this needs splitOpenRows rather than a literal regexp port of
// Python's `(?=<tr|</table>)` lookahead), so every parser here reuses that
// same helper with gs105peRowStartRE.

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// gs105peRowStartRE mirrors Python parse._GS105PE_ROW_RE's start half: real
// firmware writes `<tr class="portID">` on status.cgi/portPVID.cgi but
// `<tr class="portID" name="portID">` on portStatistics.cgi specifically, so
// (unlike gs110emxRowStartRE) this tolerates trailing attributes.
var gs105peRowStartRE = regexp.MustCompile(`<tr class="portID"[^>]*>`)

// ParseGS105PEPortStatus parses GS105PE's status.cgi portID rows: [1]=port,
// [2]=link ("up" exact, trimmed+lowered), [4]=speed text ("No Speed"/"100M"/
// "1000M") via speedTextToMbps IF link is up. Mirrors Python
// parse.parse_gs105pe_port_status (source lines 373-411). GROUNDED in
// gs105pe_status.html (a real capture from 10.1.5.30). AdminEnabled comes
// from the mode cell [3] (Auto/forced speed when enabled, "Disable" when
// not) -- hardcoding true would report an admin-disabled port as enabled.
// Name is always nil -- this page has no description column.
func ParseGS105PEPortStatus(html string) ([]model.PortStatus, error) {
	rows := splitOpenRows(html, gs105peRowStartRE)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`status.cgi: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PortStatus, 0, len(rows))
	for _, row := range rows {
		c := cells(row)
		if len(c) < 5 {
			return nil, errUnexpectedPage("status.cgi: expected >=5 <td> columns per portID row, got %d", len(c))
		}
		port, ok := parseIntCell(c[1])
		if !ok {
			return nil, errUnexpectedPage("status.cgi: could not parse a port number from column %q", c[1])
		}
		linkUp := strings.ToLower(strings.TrimSpace(c[2])) == "up"
		var speed *int
		if linkUp {
			if v, ok := speedTextToMbps(c[4]); ok {
				speed = model.Ptr(v)
			}
		}
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         nil,
			AdminEnabled: strings.ToLower(strings.TrimSpace(c[3])) != "disable",
			LinkUp:       linkUp,
			SpeedMbps:    speed,
		})
	}
	return out, nil
}

// ParseGS105PEPVIDs parses GS105PE's portPVID.cgi portID rows: [1]=port,
// [2]=PVID. Mirrors Python parse.parse_gs105pe_pvids (source lines 414-435).
// GROUNDED in gs105pe_pvid.html.
func ParseGS105PEPVIDs(html string) ([]model.Pvid, error) {
	rows := splitOpenRows(html, gs105peRowStartRE)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`portPVID.cgi: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.Pvid, 0, len(rows))
	for _, row := range rows {
		c := cells(row)
		if len(c) < 3 {
			return nil, errUnexpectedPage("portPVID.cgi: expected >=3 <td> columns per portID row, got %d", len(c))
		}
		port, portOK := parseIntCell(c[1])
		pvid, pvidOK := parseIntCell(c[2])
		if !portOK || !pvidOK {
			return nil, errUnexpectedPage("portPVID.cgi: could not parse port/PVID from row %v", c)
		}
		out = append(out, model.Pvid{Port: port, Vlan: pvid})
	}
	return out, nil
}

// hiddenValueRE mirrors Python parse._HIDDEN_VALUE_RE: a bare
// `<input type="hidden" value="N">` half-counter, with no `name` attribute
// (that's what makes it invisible to the generic cells() <td> scan -- these
// inputs live directly inside the row, not inside a labelled <td>).
var hiddenValueRE = regexp.MustCompile(`<input type="hidden" value="(\d+)">`)

// ParseGS105PEStats parses GS105PE's portStatistics.cgi -> per-port byte/CRC
// counters. Mirrors Python parse.parse_gs105pe_stats (source lines 438-483).
// GROUNDED in gs105pe_portstats.html, LIVE-VERIFIED against NSDP counters on
// the same real switch (10.1.5.30).
//
// THE hidden 32-bit half-pair counter trap: the VISIBLE <td> cells are
// UNRELIABLE -- the first counter's cell is left empty in the raw HTML and
// populated client-side by page JS. The AUTHORITATIVE values are the HIDDEN
// inputs that follow each counter cell: THREE consecutive (hi, lo) pairs --
// Bytes Received, Bytes Sent, CRC Error Packets -- each a 64-bit counter
// split into two 32-bit halves, reassembled EXACTLY as the source does it,
// hi*2**32+lo (implemented here as hi<<32 | lo, its bitwise equivalent since
// lo is always < 2**32). Requires >=6 hidden-value matches per row (3
// pairs); fewer is an error naming the port and the count found.
func ParseGS105PEStats(html string) ([]model.PortStats, error) {
	rows := splitOpenRows(html, gs105peRowStartRE)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`portStatistics.cgi: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PortStats, 0, len(rows))
	for _, row := range rows {
		c := cells(row)
		var port int
		var ok bool
		if len(c) > 0 {
			port, ok = parseIntCell(c[0])
		}
		if !ok {
			return nil, errUnexpectedPage("portStatistics.cgi: could not parse a port number from row %v", c)
		}
		halfMatches := hiddenValueRE.FindAllStringSubmatch(row, -1)
		if len(halfMatches) < 6 {
			return nil, errUnexpectedPage("portStatistics.cgi: port %d expected 6 hidden counter halves (rx/tx/crc hi+lo), got %d", port, len(halfMatches))
		}
		halves := make([]uint64, 6)
		for i := range 6 {
			v, err := strconv.ParseUint(halfMatches[i][1], 10, 32)
			if err != nil {
				return nil, errUnexpectedPage("portStatistics.cgi: port %d invalid hidden counter half %q", port, halfMatches[i][1])
			}
			halves[i] = v
		}
		out = append(out, model.PortStats{
			Port:     port,
			RxBytes:  model.Ptr(halves[0]<<32 | halves[1]),
			TxBytes:  model.Ptr(halves[2]<<32 | halves[3]),
			RxErrors: model.Ptr(halves[4]<<32 | halves[5]),
		})
	}
	return out, nil
}

// gs105peDHCPSelectRE mirrors Python parse.parse_gs105pe_sysinfo's inline
// DHCP-mode scrape: a `<select id="dhcpMode">` whose FIRST `<option
// value="1">` carries `selected` means Enable/DHCP; `"0"` means
// Disable/static.
var gs105peDHCPSelectRE = regexp.MustCompile(`(?s)<select[^>]*id="dhcpMode".*?<option value="1"[^>]*selected`)

// ParseGS105PESysInfo parses GS105PE's switch_info.cgi -> device identity +
// mgmt-IP config, mirroring Python parse.parse_gs105pe_sysinfo (source
// lines 486-523, dossier §2.5). GROUNDED in gs105pe_switch_info.html.
// Identity comes from the same `<td>Label</td><td>value</td>` rows
// labeledCell reads for GS110EMX's ParseSysInfo; the mgmt IP/mask/gateway
// come from the LOWERCASE ip_address/subnet_mask/gateway_address inputs
// (NOT GS110EMX's uppercase IP_ADDRESS etc. -- a genuinely different
// field-name convention between the two models despite sharing a login
// scheme).
func ParseGS105PESysInfo(html string) (HTTPSysInfo, error) {
	productName, okProduct := labeledCell(html, "Product Name")
	serialNumber, okSerial := labeledCell(html, "Serial Number")
	macAddress, okMAC := labeledCell(html, "MAC Address")
	firmwareVersion, okFirmware := labeledCell(html, "Firmware Version")
	ipAddress, okIP := namedInputValue(html, "ip_address")
	subnetMask, okMask := namedInputValue(html, "subnet_mask")
	gatewayAddress, okGateway := namedInputValue(html, "gateway_address")

	var missing []string
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"Product Name", okProduct},
		{"Serial Number", okSerial},
		{"MAC Address", okMAC},
		{"Firmware Version", okFirmware},
		{"ip_address", okIP},
		{"subnet_mask", okMask},
		{"gateway_address", okGateway},
	} {
		if !f.ok {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return HTTPSysInfo{}, errUnexpectedPage("switch_info.cgi: missing expected field(s): %s", strings.Join(missing, ", "))
	}
	ipMode := model.IPModeStatic
	if gs105peDHCPSelectRE.MatchString(html) {
		ipMode = model.IPModeDHCP
	}
	switchName, _ := namedInputValue(html, "switch_name")
	return HTTPSysInfo{
		ProductName:     productName,
		SwitchName:      switchName,
		SerialNumber:    serialNumber,
		MacAddress:      macAddress,
		FirmwareVersion: firmwareVersion,
		IPMode:          ipMode,
		IPAddress:       ipAddress,
		SubnetMask:      subnetMask,
		GatewayAddress:  gatewayAddress,
	}, nil
}
