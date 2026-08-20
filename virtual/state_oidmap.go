package virtual

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// OIDEntry is one projected OID's SNMP type token plus its wire value.
// Value is byte-transparent: a Go string is already a raw byte sequence
// (unlike Python's Unicode str, which needed an explicit latin-1
// encode/decode step to stay wire-exact), so every OCTETSTR/IPADDR/OID
// value here is exactly string(rawBytes) with no further transcoding.
type OIDEntry struct {
	SnmpType string
	Value    string
}

func entry(snmpType, value string) OIDEntry {
	return OIDEntry{SnmpType: snmpType, Value: value}
}

func boolToStatus(b bool) string {
	if b {
		return "1"
	}
	return "2"
}

// mustModel resolves s.ModelKey via model.GetModel, panicking on an unknown
// key. Every State method that needs the registry entry calls this: an
// unknown ModelKey is a caller bug (State is always constructed via
// NewState(validKey)), and the Produces interface for these methods has no
// error return to report it through instead.
func (s *State) mustModel() *model.SwitchModel {
	m, err := model.GetModel(s.ModelKey)
	if err != nil {
		panic(fmt.Sprintf("virtual: State.ModelKey %q: %v", s.ModelKey, err))
	}
	return m
}

// resolveVendorOids returns m's VendorOids table, or nil if m has no vendor
// OID subtree (mirrors the Python `v = vendor_oids(model) if
// has_vendor_oids(model) else None` idiom used throughout state.py).
func resolveVendorOids(m *model.SwitchModel) *snmp.VendorOids {
	if !snmp.HasVendorOids(m) {
		return nil
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		// Unreachable: HasVendorOids just confirmed a non-empty base.
		panic(fmt.Sprintf("virtual: GetVendorOids(%q) after HasVendorOids=true: %v", m.Key, err))
	}
	return &vo
}

// OIDMap projects this state onto the full numeric OID -> (type, value)
// view, built directly from the exact OID layouts in package snmp so a
// protocol face can serve it. See D-VIRT §1.4 for the full conditional-
// emission rule set this mirrors line-for-line.
func (s *State) OIDMap() map[string]OIDEntry {
	m := s.mustModel()
	v := resolveVendorOids(m)
	// Prefer the device's REAL fixed PortList width (live-measured, seeded
	// on State.VLANPortListWidth) so the mock is an INDEPENDENT source of
	// truth for the wire width -- not a re-derivation of the same
	// snmp.VlanBitmapWidth formula the writer uses (D-REC Topic B). Falls
	// back to the physical-port-only formula for a model whose real width
	// hasn't been measured.
	vlanWidth := snmp.VlanBitmapWidth(m.PortCount)
	if s.VLANPortListWidth != nil {
		vlanWidth = *s.VLANPortListWidth
	}
	out := make(map[string]OIDEntry)

	// dot1dBaseBridgeAddress.0: reuses NsdpMac -- on real hardware the SNMP
	// bridge base address and the NSDP identity MAC are the same physical
	// address. Dot1dBaseMacASCII (verified only on the real M4300-24X)
	// switches the wire encoding from 6 raw OCTET STRING bytes to a
	// 17-character ASCII colon-hex STRING.
	var baseMacWire string
	if s.Dot1dBaseMacASCII {
		parts := make([]string, len(s.NsdpMac))
		for i, b := range s.NsdpMac {
			parts[i] = fmt.Sprintf("%02X", b)
		}
		baseMacWire = strings.Join(parts, ":")
	} else {
		baseMacWire = string(s.NsdpMac[:])
	}
	out[snmp.Dot1dBaseBridgeAddress+".0"] = entry("OCTETSTR", baseMacWire)

	// MIB-II System group. sysObjectID has no known OID->model table for
	// most models; the fallback is an UNVERIFIED test fixture, never a
	// claim about real hardware (see State.SysObjectID doc intent in
	// D-VIRT §1.3).
	sysDescr := s.SysDescr
	if sysDescr == "" {
		sysDescr = "Netgear " + m.DisplayName
	}
	out[snmp.SysDescr] = entry("OCTETSTR", sysDescr)

	defaultObjectID := "1.3.6.1.2.1"
	if v != nil {
		defaultObjectID = v.Base + ".1"
	}
	sysObjectID := s.SysObjectID
	if sysObjectID == "" {
		sysObjectID = defaultObjectID
	}
	out[snmp.SysObjectID] = entry("OID", sysObjectID)

	// sysName: the switch's host name. A STANDARD MIB-II scalar, WRITABLE on
	// every SNMP model in this fleet (see snmp.SysName's own doc comment) --
	// unlike sysDescr/sysObjectID above, this has no model-derived fallback:
	// an unnamed switch's State.Hostname is honestly "", exactly like real
	// hardware that has never had `hostname` (CLI) or a sysName SET issued.
	out[snmp.SysName] = entry("OCTETSTR", s.Hostname)

	for port, sim := range s.Ports {
		out[colKey(snmp.IfAdminStatus, port)] = entry("INTEGER", boolToStatus(sim.Admin))
		out[colKey(snmp.IfOperStatus, port)] = entry("INTEGER", boolToStatus(sim.Link))
		out[colKey(snmp.IfHighSpeed, port)] = entry("Gauge32", strconv.Itoa(sim.Speed))
		out[colKey(snmp.IfType, port)] = entry("INTEGER", strconv.Itoa(sim.IfType))
		out[colKey(snmp.IfName, port)] = entry("OCTETSTR", sim.Name)
		if sim.Description != nil {
			out[colKey(snmp.IfAlias, port)] = entry("OCTETSTR", *sim.Description)
		}
		// EtherLike-MIB duplex/pause columns: emitted ONLY for a model whose
		// real agent was measured serving them (see PortSim.ServesEtherlike),
		// exactly like a real agent answering noSuchObject for the whole
		// subtree on every other model. dot3StatsDuplexStatus: 3 fullDuplex
		// while the link is up, 1 unknown while it is down -- what the live
		// GS728TPP returns for every one of its 28 ports. dot3PauseOperMode/
		// AdminMode: 1 disabled, 4 enabledXmitAndRcv.
		if sim.ServesEtherlike {
			duplex := "1"
			if sim.Link {
				duplex = "3"
			}
			out[colKey(snmp.Dot3StatsDuplexStatus, port)] = entry("INTEGER", duplex)
			pauseMode := "1"
			if sim.FlowControl {
				pauseMode = "4"
			}
			out[colKey(snmp.Dot3PauseOperMode, port)] = entry("INTEGER", pauseMode)
			out[colKey(snmp.Dot3PauseAdminMode, port)] = entry("INTEGER", pauseMode)
		}
		// Stat columns: emitted only if the field is not nil (never a
		// fabricated 0).
		for _, sc := range []struct {
			base string
			typ  string
			val  *uint64
		}{
			{snmp.IfHCInOctets, "Counter64", sim.RxOctets},
			{snmp.IfHCOutOctets, "Counter64", sim.TxOctets},
			{snmp.IfHCInUcast, "Counter64", sim.RxUcast},
			{snmp.IfHCOutUcast, "Counter64", sim.TxUcast},
			{snmp.IfInErrors, "Counter32", sim.RxErrors},
			{snmp.IfOutErrors, "Counter32", sim.TxErrors},
		} {
			if sc.val != nil {
				out[colKey(sc.base, port)] = entry(sc.typ, strconv.FormatUint(*sc.val, 10))
			}
		}
	}

	// FASTPATH vendor switchport table, for a model whose VLAN membership is
	// owned by switchport mode. Emitted for every physical port so the
	// table has a row per interface exactly like the real agent, and so the
	// writer's read-modify-write of the allowed-VLAN column finds octets to
	// modify. Mirrors Python's oid_map() switchport block (state.py:
	// 951-988) -- INCLUDING that block's own side effect of calling
	// switchportDefaults(port) (Python's _switchport_defaults) while
	// building this read-only projection, so a fresh mock answers every
	// switchport column for every port on its very first GET/walk, exactly
	// like a real agent (which has a row per interface from power-on).
	if isSwitchportModel(m) {
		for port := range s.Ports {
			s.switchportDefaults(port)
			out[colKey(snmp.FastpathSwitchportMode, port)] = entry("INTEGER", strconv.Itoa(s.SwitchportMode[port]))
			out[colKey(snmp.FastpathSwitchportAccessVlan, port)] = entry("Gauge32", strconv.Itoa(s.SwitchportAccessVlan[port]))
			out[colKey(snmp.FastpathSwitchportNativeVlan, port)] = entry("Gauge32", strconv.Itoa(s.SwitchportNativeVlan[port]))
			out[colKey(snmp.FastpathSwitchportAllowedVlans, port)] = entry("OCTETSTR", string(s.SwitchportAllowedVlans[port]))
			// The two notWritable columns: the GENERAL-mode participation
			// lists. Emitted from their own stored config, NOT derived from
			// effective membership -- live proof they are independent is
			// m4300-24x port 1/0/15, an access port on VLAN 10 (so really
			// untagged in 10) whose column 7 still read VLAN 1.
			out[colKey(snmp.FastpathSwitchportTaggedVlans, port)] = entry("OCTETSTR", string(vlanBitmapBytes(s.SwitchportGeneralTagged[port])))
			out[colKey(snmp.FastpathSwitchportUntaggedVlans, port)] = entry("OCTETSTR", string(vlanBitmapBytes(s.SwitchportGeneralUntagged[port])))
		}
	}

	for vid, vsim := range s.Vlans {
		// dot1qVlanCurrentTable -- the OPERATIONAL view, indexed
		// <timeMark>.<vlanIndex>. Real agents publish it for EVERY VLAN,
		// including ones with no static row, which is the only place a VLAN
		// with VlanSim.NoStaticRow set appears at all (MEASURED on a
		// GS728TPP, 10.2.5.10, firmware 6.0.1.30: its default VLAN 1 has no
		// dot1qVlanStaticTable row, only a current-table row). Time mark 0
		// is what that switch reports on every row.
		out[fmt.Sprintf("%s.0.%d", snmp.Dot1qVlanCurrentEgress, vid)] = entry("OCTETSTR", string(snmp.EncodePortBitmap(sliceFromPortSet(vsim.Member), vlanWidth)))
		out[fmt.Sprintf("%s.0.%d", snmp.Dot1qVlanCurrentUntagged, vid)] = entry("OCTETSTR", string(snmp.EncodePortBitmap(sliceFromPortSet(vsim.Untagged), vlanWidth)))
		// 1=other, 2=permanent: the live GS728TPP reports 1 for its
		// static-row-less VLAN 1 and 2 for all 12 configured VLANs.
		status := "2"
		if vsim.NoStaticRow {
			status = "1"
		}
		out[fmt.Sprintf("%s.0.%d", snmp.Dot1qVlanStatus, vid)] = entry("INTEGER", status)
		if vsim.NoStaticRow {
			// No dot1qVlanStaticTable row at all -- not an empty one. The
			// distinction is the whole point: an empty row would still make
			// the VLAN visible to a static-table-only reader.
			continue
		}
		out[colKey(snmp.Dot1qVlanStaticName, vid)] = entry("OCTETSTR", vsim.Name)
		// dot1qVlanStaticEgressPorts is the STATIC (configured) table, so it
		// reports vsim.Configured(), not the current Member set -- proven
		// live on GSM7252PS @10.1.5.22, whose VLAN 1 static egress bitmap
		// includes 1/0/50 and 1/0/51 even though vlanStatus.html omits them
		// (see VlanSim.ConfiguredOnly).
		out[colKey(snmp.Dot1qVlanStaticEgress, vid)] = entry("OCTETSTR", string(snmp.EncodePortBitmap(sliceFromPortSet(vsim.Configured()), vlanWidth)))
		out[colKey(snmp.Dot1qVlanStaticUntagged, vid)] = entry("OCTETSTR", string(snmp.EncodePortBitmap(sliceFromPortSet(vsim.Untagged), vlanWidth)))
	}

	for port, pv := range s.Pvids {
		out[colKey(snmp.Dot1qPvid, port)] = entry("Gauge32", strconv.Itoa(pv))
	}

	for port, psim := range s.Poe {
		out[fmt.Sprintf("%s.3.1.%d", snmp.PethPsePortTable, port)] = entry("INTEGER", boolToStatus(psim.Admin))
		out[fmt.Sprintf("%s.6.1.%d", snmp.PethPsePortTable, port)] = entry("INTEGER", strconv.Itoa(psim.Detect))
		// Per-port delivered power (mW) is a Netgear vendor column; a
		// no-vendor model (gs728tpp) exposes no such column at all.
		if v != nil {
			out[fmt.Sprintf("%s.1.%d", v.PoEPowerMw, port)] = entry("Gauge32", strconv.Itoa(psim.PowerMw))
		}
	}

	// Vendor box sensors (fan RPM / PSU watts / temperature) -- only for a
	// model with a vendor subtree. Entirely skipped (not just individually
	// absent) on a no-vendor model, matching a real agent answering
	// noSuchObject for the whole 4526 tree.
	if v != nil {
		for _, ssim := range s.Sensors {
			var base string
			switch ssim.Kind {
			case "fan":
				base = v.BoxFan
			case "power":
				base = v.BoxPSUPower
			case "temperature":
				base = v.BoxTemp
			default:
				panic(fmt.Sprintf("virtual: OIDMap: unknown sensor kind %q", ssim.Kind))
			}
			out[fmt.Sprintf("%s.%s", base, ssim.Instance)] = entry("OCTETSTR", ssim.Raw)
		}
	}

	// ENTITY-MIB entPhysical inventory: unconditional -- the standard-MIB
	// sensor components for a no-vendor model (gs728tpp exposes fan/PSU
	// ONLY here, with no live value).
	for _, ent := range s.EntityComponents {
		out[colKey(snmp.EntPhysicalClass, ent.Index)] = entry("INTEGER", strconv.Itoa(ent.PhysClass))
		out[colKey(snmp.EntPhysicalName, ent.Index)] = entry("OCTETSTR", ent.Name)
		out[colKey(snmp.EntPhysicalDescr, ent.Index)] = entry("OCTETSTR", ent.Descr)
	}

	// MAC/FDB: dot1qTpFdbPort keyed by <vlan>.<6 MAC bytes as decimal-dotted
	// suffix>, plus the dot1dBasePortIfIndex bridge-port -> ifIndex rows.
	for _, msim := range s.Macs {
		parts := make([]string, len(msim.MacBytes))
		for i, b := range msim.MacBytes {
			parts[i] = strconv.Itoa(int(b))
		}
		macSuffix := strings.Join(parts, ".")
		out[fmt.Sprintf("%s.%d.%s", snmp.Dot1qTpFdbPort, msim.Vlan, macSuffix)] = entry("INTEGER", strconv.Itoa(msim.BridgePort))
	}
	for bridgePort, ifindex := range s.BridgePorts {
		out[colKey(snmp.Dot1dBasePortIfIndex, bridgePort)] = entry("INTEGER", strconv.Itoa(ifindex))
	}

	// LLDP remote neighbours across lldpRemTable columns 5/7/8/9.
	for _, nb := range s.Lldp {
		idx := fmt.Sprintf("%d.%d.%d", nb.TimeMark, nb.LocalPort, nb.RemIdx)
		out[fmt.Sprintf("%s.1.5.%s", snmp.LldpRemTable, idx)] = entry("OCTETSTR", nb.Chassis)
		out[fmt.Sprintf("%s.1.7.%s", snmp.LldpRemTable, idx)] = entry("OCTETSTR", nb.PortID)
		out[fmt.Sprintf("%s.1.8.%s", snmp.LldpRemTable, idx)] = entry("OCTETSTR", nb.PortDesc)
		out[fmt.Sprintf("%s.1.9.%s", snmp.LldpRemTable, idx)] = entry("OCTETSTR", nb.SysName)
	}

	// mgmt-ip: ipAddrTable + ipRouteTable + DHCP mode.
	idx := s.Mgmt.Address
	out[fmt.Sprintf("%s.%s", snmp.IPAdEntAddr, idx)] = entry("IPADDR", s.Mgmt.Address)
	out[fmt.Sprintf("%s.%s", snmp.IPAdEntNetmask, idx)] = entry("IPADDR", s.Mgmt.Netmask)
	out[snmp.IPRouteDest+".0.0.0.0"] = entry("IPADDR", "0.0.0.0")
	out[snmp.IPRouteNextHop+".0.0.0.0"] = entry("IPADDR", s.Mgmt.Gateway)
	// Single named UNVERIFIED DHCP-mode OID -- absent on a no-vendor model
	// (gs728tpp), matching that model's HTTP mgmt-IP read (IpMode.UNKNOWN).
	if v != nil {
		mode := "1"
		if s.Mgmt.Mode == "static" {
			mode = "2"
		}
		out[v.DHCPModeUnverified+".0"] = entry("INTEGER", mode)
	}

	// Remote logging, under <vendor base>.14 -- the same columns the real
	// agents publish, and ONLY for a model that has a vendor subtree. A
	// model with none (gs728tpp) must stay unable to answer GetSyslog here
	// exactly as it is on the wire, rather than this mock inventing a
	// reply.
	if v != nil {
		out[v.SyslogAdminMode] = entry("INTEGER", strconv.Itoa(s.Syslog.AdminMode))
		out[v.SyslogLocalPort] = entry("Gauge32", strconv.Itoa(s.Syslog.LocalPort))
		// col.Index, NOT the enumeration position: the real table is
		// SPARSE (Index 1 and 3 with nothing at 2, measured on m4300-24x
		// 10.1.5.13) and the OID instance IS that index.
		for _, col := range s.Syslog.Collectors {
			// Column 2 (<base>.14.1.4.5.1.2.<index>) is a RowStatus-shaped
			// column a real walk of this table surfaces alongside 3/4/5/7 --
			// mirroring the pin's mock exactly (state.py:906, pin b26eb1f):
			// a fixed "1" (active), never derived from col, never read by
			// GetSyslog (snmp/reader.go only walks
			// SyslogHostAddr/Port/Severity/Status, columns 3/4/5/7) or
			// written by any writer. No named VendorOids field exists for
			// it -- like the pin, which has no syslog_host_row_status
			// constant either -- because nothing but this walk-completeness
			// projection ever needs it.
			out[fmt.Sprintf("%s.14.1.4.5.1.2.%d", v.Base, col.Index)] = entry("INTEGER", "1")
			out[colKey(v.SyslogHostAddr, col.Index)] = entry("OCTETSTR", col.Host)
			out[colKey(v.SyslogHostPort, col.Index)] = entry("Gauge32", strconv.Itoa(col.Port))
			out[colKey(v.SyslogHostSeverity, col.Index)] = entry("INTEGER", strconv.Itoa(col.Severity))
			out[colKey(v.SyslogHostStatus, col.Index)] = entry("INTEGER", strconv.Itoa(col.Status))
		}
	}

	return out
}

// colKey formats a "<base>.<index>" OID column key.
func colKey(base string, index int) string {
	return fmt.Sprintf("%s.%d", base, index)
}

// IsOIDImplemented reports whether oid does NOT fall under a subtree root
// this model's real SNMP agent never registers at all (e.g. the RFC3621
// PoE MIB on a non-PoE model). Delegates entirely to snmp.IsOIDImplemented.
func (s *State) IsOIDImplemented(oid string) bool {
	return snmp.IsOIDImplemented(s.mustModel(), oid)
}
