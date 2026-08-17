// reader.go: model-driven Reader + system-info detection, ported
// field-for-field from src/netgear_switch/snmp_read.py (the normative
// source; that repo is read-only from here). Any discrepancy between this
// file and the Python source is a bug in this file.

package snmp

import (
	"context"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// ReadSystemInfo identifies a switch's model over SNMP: sysObjectID first
// (authoritative), sysDescr fallback.
//
// Deliberately a free function taking a bare Client (no model): model
// identification exists precisely for when the caller does NOT yet
// know/trust the model, unlike every other read in this file which requires
// an already-known *model.SwitchModel (NewReader's _require_snmp-equivalent
// gate). Both OIDs are fetched in ONE Get call (one PDU, two OIDs), never
// two round-trips.
func ReadSystemInfo(ctx context.Context, c Client) (model.DetectedModel, error) {
	rows, err := c.Get(ctx, []string{SysDescr, SysObjectID})
	if err != nil {
		return model.DetectedModel{}, err
	}
	sysDescr, sysObjectID, err := ParseSystemInfo(rows)
	if err != nil {
		return model.DetectedModel{}, err
	}
	models := model.Models()
	key := DetectModelFromSysObjectID(sysObjectID, models)
	if key == nil {
		key = DetectModelFromSysDescr(sysDescr, models)
	}
	return model.DetectedModel{Key: key, SysDescr: sysDescr, SysObjectID: sysObjectID}, nil
}

// Reader is a model-driven SNMP reader: every method below joins one or more
// walk-discovered MIB columns via the corresponding Parse* function in
// parse.go. Vendor OIDs (see GetVendorOids) are resolved lazily, only inside
// the three methods that need the vendor subtree (GetPoE/GetSensors/
// GetMgmtIP) -- constructing a Reader never touches vendor OIDs.
type Reader struct {
	client Client
	model  *model.SwitchModel
}

// NewReader constructs a Reader bound to client and m.
//
// m must have an SNMP backend (model.BackendSNMP in m.Backends); a model
// without one (e.g. a Plus-class model, NSDP-only) returns an error wrapping
// model.ErrUnsupportedCapability BEFORE any I/O -- this is the single
// capability gate for the whole reader; no method below re-checks it.
func NewReader(c Client, m *model.SwitchModel) (*Reader, error) {
	if !m.HasBackend(model.BackendSNMP) {
		return nil, fmt.Errorf("model %q has no SNMP backend: %w", m.Key, model.ErrUnsupportedCapability)
	}
	return &Reader{client: c, model: m}, nil
}

// walkAll walks each oid in oids in order over c, stopping at the first
// error. The walked-OID sequence (and its order) is the contract a fake
// Client's test asserts against, so oids must be passed in the exact order
// documented by each exported method below.
func walkAll(ctx context.Context, c Client, oids ...string) ([][]Row, error) {
	out := make([][]Row, len(oids))
	for i, oid := range oids {
		rows, err := c.Walk(ctx, oid)
		if err != nil {
			return nil, err
		}
		out[i] = rows
	}
	return out, nil
}

// GetPorts reads per-port administrative/operational status, speed, name and
// description, filtered to physical Ethernet ports.
//
// Walks, in order: IfAdminStatus, IfOperStatus, IfHighSpeed, IfName,
// IfAlias, IfType.
func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error) {
	cols, err := walkAll(ctx, r.client, IfAdminStatus, IfOperStatus, IfHighSpeed, IfName, IfAlias, IfType)
	if err != nil {
		return nil, err
	}
	return ParsePortStatus(cols[0], cols[1], cols[2], cols[3], cols[4], cols[5])
}

// GetStats reads the per-port traffic-counter snapshot.
//
// Walks, in order: the four ifHC64 counters (InOctets, OutOctets, InUcast,
// OutUcast), IfInErrors, IfOutErrors, IfType.
func (r *Reader) GetStats(ctx context.Context) ([]model.PortStats, error) {
	cols, err := walkAll(ctx, r.client,
		IfHCInOctets, IfHCOutOctets, IfHCInUcast, IfHCOutUcast,
		IfInErrors, IfOutErrors, IfType,
	)
	if err != nil {
		return nil, err
	}
	return ParsePortStats(PortStatsCols{
		InOctets:  cols[0],
		OutOctets: cols[1],
		InUcast:   cols[2],
		OutUcast:  cols[3],
		InErrors:  cols[4],
		OutErrors: cols[5],
		IfTypes:   cols[6],
	})
}

// GetVLANs reads the VLAN table (name + member/tagged/untagged port sets),
// completed by the dot1qVlanCurrentTable and physical-port-filtered by
// IfType -- see ParseVlans for why both matter (a GS728TPP, measured live,
// loses VLAN 1 without the current-table read and invents a phantom LAG
// member port without the ifType filter).
//
// Walks, in order: Dot1qVlanStaticName, Dot1qVlanStaticEgress,
// Dot1qVlanStaticUntagged, IfType, Dot1qVlanCurrentEgress,
// Dot1qVlanCurrentUntagged.
func (r *Reader) GetVLANs(ctx context.Context) ([]model.VLANInfo, error) {
	cols, err := walkAll(ctx, r.client,
		Dot1qVlanStaticName, Dot1qVlanStaticEgress, Dot1qVlanStaticUntagged,
		IfType, Dot1qVlanCurrentEgress, Dot1qVlanCurrentUntagged,
	)
	if err != nil {
		return nil, err
	}
	return ParseVlans(cols[0], cols[1], cols[2], cols[3], cols[4], cols[5])
}

// GetPVIDs reads each physical port's default/untagged VLAN (PVID).
//
// Walks, in order: Dot1qPvid, IfType.
func (r *Reader) GetPVIDs(ctx context.Context) ([]model.Pvid, error) {
	cols, err := walkAll(ctx, r.client, Dot1qPvid, IfType)
	if err != nil {
		return nil, err
	}
	return ParsePvids(cols[0], cols[1])
}

// GetLLDP reads the LLDP remote-neighbor table.
//
// Walks: LldpRemTable (one walk).
func (r *Reader) GetLLDP(ctx context.Context) ([]model.LLDPNeighbor, error) {
	rows, err := r.client.Walk(ctx, LldpRemTable)
	if err != nil {
		return nil, err
	}
	return ParseLldp(rows)
}

// GetMACs reads the MAC address / forwarding-database table.
//
// Walks, in order: Dot1qTpFdbPort, Dot1dBasePortIfIndex. No has_mac_table
// guard here: NewReader's SNMP-backend gate already enforced it.
func (r *Reader) GetMACs(ctx context.Context) ([]model.MacEntry, error) {
	cols, err := walkAll(ctx, r.client, Dot1qTpFdbPort, Dot1dBasePortIfIndex)
	if err != nil {
		return nil, err
	}
	return ParseMacs(cols[0], cols[1])
}

// GetPoE reads the per-port PoE (Power-over-Ethernet) status.
//
// A model with zero PSE ports (e.g. m4300-24x) has no PoE at all: this
// raises an error wrapping model.ErrUnsupportedCapability BEFORE any walk,
// mirroring the CLI/HTTP readers, so PoE is reported unsupported
// CONSISTENTLY across every backend rather than SNMP silently returning []
// from an empty PethPsePortTable while CLI/HTTP raise. Otherwise walks the
// standard PethPsePortTable always, plus the Netgear vendor per-port
// delivered-power (mW) column ONLY when the model has a vendor OID subtree
// (HasVendorOids); a model with none (e.g. gs728tpp) leaves power_mw
// honestly nil for every port.
func (r *Reader) GetPoE(ctx context.Context) ([]model.PoEStatus, error) {
	if r.model.PoEPortCount == 0 {
		return nil, fmt.Errorf("model %q has no PoE (no PSE ports): %w", r.model.Key, model.ErrUnsupportedCapability)
	}
	status, err := r.client.Walk(ctx, PethPsePortTable)
	if err != nil {
		return nil, err
	}
	var power []Row
	if HasVendorOids(r.model) {
		vendor, verr := GetVendorOids(r.model)
		if verr != nil {
			return nil, verr
		}
		power, err = r.client.Walk(ctx, vendor.PoEPowerMw)
		if err != nil {
			return nil, err
		}
	}
	return ParsePoe(status, power)
}

// GetSensors reads the switch's environmental sensors (fans, PSUs,
// temperature).
//
// Two exclusive paths:
//   - No vendor OID subtree (HasVendorOids false, e.g. gs728tpp): walks the
//     standard ENTITY-MIB physical inventory (EntPhysicalClass,
//     EntPhysicalName, EntPhysicalDescr, in that order) and returns
//     ParseEntitySensors's result as-is -- an empty result here is honest
//     (never raises).
//   - Vendor OID subtree present: walks the vendor fan/PSU-power/temperature
//     columns (RPM/W/C units, in that order). If ALL THREE walk completely
//     empty, this model CLAIMS a vendor sensor subtree but the agent
//     answered nothing for it -- raise an error wrapping
//     model.ErrUnsupportedCapability rather than silently returning [] (the
//     historical gs728tpp-class parity bug); partial population across the
//     three columns is fine.
func (r *Reader) GetSensors(ctx context.Context) ([]model.Sensor, error) {
	if !HasVendorOids(r.model) {
		cols, err := walkAll(ctx, r.client, EntPhysicalClass, EntPhysicalName, EntPhysicalDescr)
		if err != nil {
			return nil, err
		}
		return ParseEntitySensors(cols[0], cols[1], cols[2])
	}
	vendor, err := GetVendorOids(r.model)
	if err != nil {
		return nil, err
	}
	cols, err := walkAll(ctx, r.client, vendor.BoxFan, vendor.BoxPSUPower, vendor.BoxTemp)
	if err != nil {
		return nil, err
	}
	columns := []SensorColumn{
		{Kind: "fan", Unit: "RPM", Rows: cols[0]},
		{Kind: "power", Unit: "W", Rows: cols[1]},
		{Kind: "temperature", Unit: "C", Rows: cols[2]},
	}
	anyRows := false
	for _, c := range columns {
		if len(c.Rows) > 0 {
			anyRows = true
			break
		}
	}
	if !anyRows {
		return nil, fmt.Errorf(
			"model %q declares vendor sensor OIDs (%s) but the vendor fan/PSU/temperature walk returned nothing: %w",
			r.model.Key, r.model.SNMPVendorBase, model.ErrUnsupportedCapability,
		)
	}
	return ParseBoxSensors(columns)
}

// GetMgmtIP reads the switch's own management IP configuration (address,
// netmask, gateway, DHCP-vs-static mode, base MAC).
//
// Walks, in order: IPAdEntAddr, IPAdEntNetmask, IPRouteDest, IPRouteNextHop,
// the vendor DHCP-mode OID (ONLY when the model has a vendor OID subtree;
// nil rows otherwise), Dot1dBaseBridgeAddress, IPAddressIfIndex. Every read
// here is a WALK, never a GET, so an absent DHCP-mode OID (no vendor subtree,
// or an unpopulated vendor subtree) yields no rows rather than an error --
// the parser maps that absence to model.IPModeUnknown.
func (r *Reader) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error) {
	addr, err := r.client.Walk(ctx, IPAdEntAddr)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	netmask, err := r.client.Walk(ctx, IPAdEntNetmask)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	routeDest, err := r.client.Walk(ctx, IPRouteDest)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	routeNexthop, err := r.client.Walk(ctx, IPRouteNextHop)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	var dhcp []Row
	if HasVendorOids(r.model) {
		vendor, verr := GetVendorOids(r.model)
		if verr != nil {
			return model.MgmtIPConfig{}, verr
		}
		dhcp, err = r.client.Walk(ctx, vendor.DHCPModeUnverified)
		if err != nil {
			return model.MgmtIPConfig{}, err
		}
	}
	baseMac, err := r.client.Walk(ctx, Dot1dBaseBridgeAddress)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	addrRFC4293, err := r.client.Walk(ctx, IPAddressIfIndex)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	return ParseMgmtIP(addr, netmask, routeDest, routeNexthop, dhcp, baseMac, addrRFC4293)
}

// GetSystemInfo identifies this switch's model via ReadSystemInfo, reusing
// this reader's already-connected client.
//
// Unlike every other method on Reader, the result does NOT depend on
// r.model matching the real device -- useful to confirm/discover a switch's
// real model via a reader that was (possibly wrongly) constructed against a
// different model key.
func (r *Reader) GetSystemInfo(ctx context.Context) (model.DetectedModel, error) {
	return ReadSystemInfo(ctx, r.client)
}
