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

// GetPorts reads per-port administrative/operational status, speed, name,
// description, duplex and flow control, filtered to physical Ethernet
// ports.
//
// Walks, in order: IfAdminStatus, IfOperStatus, IfHighSpeed, IfName,
// IfAlias, IfType, Dot3StatsDuplexStatus, Dot3PauseOperMode. The two
// EtherLike-MIB columns are walked UNCONDITIONALLY: an agent that does not
// serve them (most models -- see ParsePortStatus) answers an empty
// subtree, which ParsePortStatus renders as FullDuplex/FlowControl == nil,
// never a fabricated value.
func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error) {
	cols, err := walkAll(ctx, r.client,
		IfAdminStatus, IfOperStatus, IfHighSpeed, IfName, IfAlias, IfType,
		Dot3StatsDuplexStatus, Dot3PauseOperMode,
	)
	if err != nil {
		return nil, err
	}
	return ParsePortStatus(cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6], cols[7])
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
// from an empty PethPsePortTable while CLI/HTTP raise. Otherwise walks TWO
// column-scoped OIDs (PethPsePortAdmin, PethPsePortDetect) rather than the
// whole PethPsePortTable -- ParsePoe honours only those two columns, and on
// real hardware the whole-table walk is over 4x slower than the two column
// walks combined (see PethPsePortAdmin's doc comment for the measurement;
// parity python-netgear-switch-library commit 86af0a9) -- plus the Netgear
// vendor per-port delivered-power (mW) column ONLY when the model has a
// vendor OID subtree (HasVendorOids); a model with none (e.g. gs728tpp)
// leaves power_mw honestly nil for every port.
func (r *Reader) GetPoE(ctx context.Context) ([]model.PoEStatus, error) {
	if r.model.PoEPortCount == 0 {
		return nil, fmt.Errorf("model %q has no PoE (no PSE ports): %w", r.model.Key, model.ErrUnsupportedCapability)
	}
	admin, err := r.client.Walk(ctx, PethPsePortAdmin)
	if err != nil {
		return nil, err
	}
	detect, err := r.client.Walk(ctx, PethPsePortDetect)
	if err != nil {
		return nil, err
	}
	// A fresh slice, not append(admin, detect...): that form can reuse
	// admin's backing array when it has spare capacity, aliasing a slice
	// this function received from the client -- harmless single-threaded
	// today (admin is never read again below), but a latent trap for a
	// future caller that keeps its own reference to admin.
	status := make([]Row, 0, len(admin)+len(detect))
	status = append(status, admin...)
	status = append(status, detect...)
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

// GetHostname reads the switch's host name from the standard MIB-II sysName
// scalar, mirroring Python SnmpReader.get_hostname (snmp_read.py:216-222).
// Standard, so this works on every SNMP model -- including gs728tpp, which
// publishes no Netgear vendor subtree at all.
func (r *Reader) GetHostname(ctx context.Context) (string, error) {
	rows, err := r.client.Get(ctx, []string{SysName})
	if err != nil {
		return "", err
	}
	return ParseHostname(rows)
}

// GetSyslog reads remote-logging configuration: whether it is on, and where
// it sends, mirroring Python SnmpReader.get_syslog (snmp_read.py:224-252).
//
// VENDOR columns, so a model with no Netgear subtree cannot serve this.
// gs728tpp is exactly that model -- a walk of 1.3.6.1.4.1.4526 answers
// noSuchObject -- and it is refused by name rather than returned empty,
// which would read as "no collectors configured".
func (r *Reader) GetSyslog(ctx context.Context) (model.SyslogConfig, error) {
	if !HasVendorOids(r.model) {
		return model.SyslogConfig{}, fmt.Errorf(
			"model %q registers no Netgear vendor OID subtree, and the logging columns are vendor-only; an empty result here would be indistinguishable from a switch with no syslog collectors configured: %w",
			r.model.Key, model.ErrUnsupportedCapability,
		)
	}
	vendor, err := GetVendorOids(r.model)
	if err != nil {
		return model.SyslogConfig{}, err
	}
	adminMode, err := r.client.Get(ctx, []string{vendor.SyslogAdminMode})
	if err != nil {
		return model.SyslogConfig{}, err
	}
	localPort, err := r.client.Get(ctx, []string{vendor.SyslogLocalPort})
	if err != nil {
		return model.SyslogConfig{}, err
	}
	cols, err := walkAll(ctx, r.client, vendor.SyslogHostAddr, vendor.SyslogHostPort, vendor.SyslogHostSeverity, vendor.SyslogHostStatus)
	if err != nil {
		return model.SyslogConfig{}, err
	}
	return ParseSyslog(adminMode, localPort, cols[0], cols[1], cols[2], cols[3],
		vendor.SyslogHostAddr, vendor.SyslogHostPort, vendor.SyslogHostSeverity, vendor.SyslogHostStatus)
}

// GetUsers always returns an error wrapping model.ErrUnsupportedCapability:
// this backend does not serve local user accounts, mirroring Python
// SnmpReader.get_users (snmp_read.py:265-274). Refused BY NAME rather than
// returned empty -- an empty answer here would be indistinguishable from a
// switch that genuinely has none. Users is deliberately NOT served over
// SNMP even though a vendor user table exists: the S3300's SNMP user table
// (4526.11.1.2.1.3) disagrees with its own CLI (one user where the CLI
// shows two), so the two backends do not report the same set.
func (r *Reader) GetUsers(_ context.Context) ([]model.SwitchUser, error) {
	return nil, fmt.Errorf(
		"model %q: this backend does not expose local user accounts (no such tag/page/table on this backend): %w",
		r.model.Key, model.ErrUnsupportedCapability)
}

// GetServices always returns an error wrapping
// model.ErrUnsupportedCapability: this backend does not serve
// management-service state, mirroring Python SnmpReader.get_services
// (snmp_read.py's sibling to get_users). Refused BY NAME rather than
// returned empty, for the same reason GetUsers is.
func (r *Reader) GetServices(_ context.Context) ([]model.ServiceStatus, error) {
	return nil, fmt.Errorf(
		"model %q: this backend does not expose management-service state (http/https/telnet/ssh): %w",
		r.model.Key, model.ErrUnsupportedCapability)
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
