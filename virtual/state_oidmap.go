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

// vlanBitmapWidth is the wire byte-width of model's dot1q VLAN egress/
// untagged bitmaps: max(8, ceil(port_count/8)). Ported from
// protocols/snmp/write.vlan_bitmap_width (Python); this package owns the Go
// copy per the task brief (that helper lives in a different Python module
// than state.py, but has no Go home yet outside this package).
func vlanBitmapWidth(m *model.SwitchModel) int {
	w := (m.PortCount + 7) / 8
	if w < 8 {
		return 8
	}
	return w
}

// EncodePortBitmap is the inverse of snmp.DecodePortBitmap: a port set ->
// a wire-format bitmap. Bit 7 (MSB) of byte 0 is port 1; byteIdx, bit =
// divmod(port-1, 8). The buffer grows past widthBytes if a port number
// needs it -- never pre-sized to a model's port count, so a bogus
// out-of-range port set still encodes rather than silently truncating.
// Only ports with a true value in the set are encoded; a false-valued or
// absent key is simply not a member.
func EncodePortBitmap(ports map[int]bool, widthBytes int) []byte {
	data := make([]byte, widthBytes)
	for port, present := range ports {
		if !present {
			continue
		}
		byteIdx := (port - 1) / 8
		bit := (port - 1) % 8
		for byteIdx >= len(data) {
			data = append(data, 0)
		}
		data[byteIdx] |= 0x80 >> uint(bit)
	}
	return data
}

// OIDMap projects this state onto the full numeric OID -> (type, value)
// view, built directly from the exact OID layouts in package snmp so a
// protocol face can serve it. See D-VIRT §1.4 for the full conditional-
// emission rule set this mirrors line-for-line.
func (s *State) OIDMap() map[string]OIDEntry {
	m := s.mustModel()
	v := resolveVendorOids(m)
	vlanWidth := vlanBitmapWidth(m)
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

	for port, sim := range s.Ports {
		out[colKey(snmp.IfAdminStatus, port)] = entry("INTEGER", boolToStatus(sim.Admin))
		out[colKey(snmp.IfOperStatus, port)] = entry("INTEGER", boolToStatus(sim.Link))
		out[colKey(snmp.IfHighSpeed, port)] = entry("Gauge32", strconv.Itoa(sim.Speed))
		out[colKey(snmp.IfType, port)] = entry("INTEGER", strconv.Itoa(sim.IfType))
		out[colKey(snmp.IfName, port)] = entry("OCTETSTR", sim.Name)
		if sim.Description != nil {
			out[colKey(snmp.IfAlias, port)] = entry("OCTETSTR", *sim.Description)
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

	for vid, vsim := range s.Vlans {
		out[colKey(snmp.Dot1qVlanStaticName, vid)] = entry("OCTETSTR", vsim.Name)
		out[colKey(snmp.Dot1qVlanStaticEgress, vid)] = entry("OCTETSTR", string(EncodePortBitmap(vsim.Member, vlanWidth)))
		out[colKey(snmp.Dot1qVlanStaticUntagged, vid)] = entry("OCTETSTR", string(EncodePortBitmap(vsim.Untagged, vlanWidth)))
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
