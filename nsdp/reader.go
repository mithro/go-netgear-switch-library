package nsdp

// reader.go: model-driven NSDP read facade, ported field-for-field from
// src/netgear_switch/nsdp_read.py at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy
// between this file and that pin is a bug in this file, not a deliberate
// deviation, unless called out in a comment.
//
// Parallel to snmp/reader.go: maps NSDP TLVs (via ParseDevice) onto the SAME
// shared model types (model.PortStatus/PortStats/VLANInfo/Pvid/MgmtIPConfig)
// so the facade sees one uniform shape regardless of backend. NSDP genuinely
// exposes only port link/speed, byte/CRC statistics, VLAN membership, PVID
// and management IP on these Plus switches; MAC/FDB, LLDP, sensors and PoE
// are not in the protocol, so those ops raise an error wrapping
// model.ErrUnsupportedCapability rather than fabricating an empty result.

import (
	"context"
	"fmt"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// nsdpSweepEvidence is the live-device proof every NSDP unsupported-capability
// message cites, mirroring Python nsdp_read.py's _SWEEP module constant. These
// are MEASURED device limits, not assumed ones (design principle: a capability
// a backend lacks must be backed by captured device output, never presumed):
// an exhaustive NSDP tag sweep of a real GS110EMX covering the entire 16-bit
// tag space found no tag for MAC/FDB, LLDP, sensors or PoE.
const nsdpSweepEvidence = "measured by an exhaustive NSDP tag sweep of a real GS110EMX " +
	"(10.1.5.25, firmware 1.0.2.8, 2026-07-30) covering every tag in the 16-bit space; " +
	"see the nsdp package for the full tag inventory"

// Unsupported-read messages, mirroring Python nsdp_read.py's
// _NO_MACS/_NO_LLDP/_NO_SENSORS/_NO_POE module constants (each embeds _SWEEP /
// nsdpSweepEvidence so the device limit carries its proof).
const (
	noMACsMsg    = "NSDP has no MAC/FDB table tag (" + nsdpSweepEvidence + ")"
	noLLDPMsg    = "NSDP has no LLDP neighbour tag (" + nsdpSweepEvidence + ")"
	noSensorsMsg = "NSDP has no environmental-sensor tag (" + nsdpSweepEvidence + ")"
	noPoEReadMsg = "NSDP has no PoE status tag (" + nsdpSweepEvidence + "); use the HTTP backend for PoE"
)

// fullDeviceTags is the tag set GetDevice requests to build an NsdpDevice in
// one round trip -- identity, mgmt IP, per-port status/stats, VLANs/PVIDs, and
// the QoS/mirroring/IGMP/broadcast-filtering/loop-detection tags. Ported from
// Python's _FULL_DEVICE_TAGS. One tag the pin's list also carries is NOT here:
// PORT_NAME (0xB000, per-port operator descriptions) -- the pin reads it into
// NsdpDevice.port_names and surfaces it as PortStatus.name, whereas this
// package has the write-side builder (write_tlv.go) but not yet the read
// projection, parser, or NsdpDevice field. That NSDP read-side reconciliation
// is tracked in the project ledger, not marked inline.
var fullDeviceTags = []Tag{
	TagModel,
	TagMAC,
	TagHostname,
	TagIPAddress,
	TagNetmask,
	TagGateway,
	TagFirmwareVer1,
	TagDHCPMode,
	TagPortCount,
	TagSerialNumber,
	TagVLANEngine,
	TagPortStatus,
	TagPortStatistics,
	TagVLANMembers,
	TagPortPVID,
	TagQOSEngine,
	TagPortMirroring,
	TagIGMPSnooping,
	TagBroadcastFiltering,
	TagLoopDetection,
}

// requireNSDP mirrors Python's _require_nsdp: an error wrapping
// model.ErrUnsupportedCapability if m has no NSDP backend, message
// byte-identical to Python's `f"model {model.key!r} has no NSDP backend"`
// (Go's %q renders the same single-quoted form as Python's !r for a plain
// ASCII string).
func requireNSDP(m *model.SwitchModel) error {
	if !m.HasBackend(model.BackendNSDP) {
		return fmt.Errorf("model %q has no NSDP backend: %w", m.Key, model.ErrUnsupportedCapability)
	}
	return nil
}

// withModel prepends TagModel to tags unless already present, mirroring
// Python's _with_model: real Plus hardware answers a read with ONLY the
// tags requested, and ParseDevice requires a MODEL TLV in every response.
func withModel(tags []Tag) []Tag {
	for _, t := range tags {
		if t == TagModel {
			return tags
		}
	}
	out := make([]Tag, 0, len(tags)+1)
	out = append(out, TagModel)
	out = append(out, tags...)
	return out
}

// unsupportedRead wraps model.ErrUnsupportedCapability with msg verbatim,
// mirroring Python's raise UnsupportedCapabilityError(msg).
func unsupportedRead(msg string) error {
	return fmt.Errorf("%s: %w", msg, model.ErrUnsupportedCapability)
}

// Reader is a model-driven NSDP reader, mirroring Python's NsdpReader.
type Reader struct {
	client Client
	model  *model.SwitchModel
}

// NewReader constructs a Reader bound to c and m.
//
// m must have an NSDP backend (model.BackendNSDP in m.Backends); a model
// without one returns an error wrapping model.ErrUnsupportedCapability
// BEFORE any I/O -- this is the single capability gate for the whole
// reader; no method below re-checks it. Mirrors Python's
// NsdpReader.__init__ calling _require_nsdp(model) first.
func NewReader(c Client, m *model.SwitchModel) (*Reader, error) {
	if err := requireNSDP(m); err != nil {
		return nil, err
	}
	return &Reader{client: c, model: m}, nil
}

// device reads tags (with TagModel prepended via withModel) and parses the
// response into an NsdpDevice, mirroring Python's NsdpReader._device.
func (r *Reader) device(ctx context.Context, tags []Tag) (model.NsdpDevice, error) {
	pkt, err := r.client.Read(ctx, withModel(tags))
	if err != nil {
		return model.NsdpDevice{}, err
	}
	return ParseDevice(*pkt)
}

// mapPorts maps dev.PortStatus onto []model.PortStatus, mirroring Python's
// module-level _ports: AdminEnabled is always true (NSDP PORT_STATUS
// reports link speed only -- it cannot distinguish an admin-disabled port
// from a link-down one, so the honest "not administratively removed"
// default is reported), Name is always nil (NSDP PORT_STATUS carries no
// port name), LinkUp is s.Speed != LinkSpeedDown, and SpeedMbps is
// s.Speed.SpeedMbps() or nil when that's 0 (Python's `speed_mbps or None`).
func mapPorts(dev model.NsdpDevice) []model.PortStatus {
	out := make([]model.PortStatus, 0, len(dev.PortStatus))
	for _, s := range dev.PortStatus {
		var speedMbps *int
		if v := s.Speed.SpeedMbps(); v != 0 {
			speedMbps = model.Ptr(v)
		}
		out = append(out, model.PortStatus{
			Port:         s.PortID,
			Name:         nil,
			AdminEnabled: true,
			LinkUp:       s.Speed != model.LinkSpeedDown,
			SpeedMbps:    speedMbps,
			Description:  nil,
		})
	}
	return out
}

// mapStats maps dev.PortStatistics onto []model.PortStats, mirroring
// Python's module-level _stats: NSDP PORT_STATISTICS has no packet
// counters (RxPackets/TxPackets always nil) and no separate TX error
// counter (TxErrors always nil); RxErrors reports the CRC-error counter.
func mapStats(dev model.NsdpDevice) []model.PortStats {
	out := make([]model.PortStats, 0, len(dev.PortStatistics))
	for _, s := range dev.PortStatistics {
		out = append(out, model.PortStats{
			Port:      s.PortID,
			RxBytes:   model.Ptr(s.BytesReceived),
			TxBytes:   model.Ptr(s.BytesSent),
			RxPackets: nil,
			TxPackets: nil,
			RxErrors:  model.Ptr(s.CrcErrors),
			TxErrors:  nil,
		})
	}
	return out
}

// mapVLANs maps dev.VlanMembers onto []model.VLANInfo, mirroring Python's
// module-level _vlans: Name is always nil (NSDP VLAN_MEMBERS carries no
// VLAN name); MemberPorts/TaggedPorts/UntaggedPorts pass through the
// already-canonical (sorted, non-nil) NsdpVlanMembership fields/method.
func mapVLANs(dev model.NsdpDevice) []model.VLANInfo {
	out := make([]model.VLANInfo, 0, len(dev.VlanMembers))
	for _, m := range dev.VlanMembers {
		out = append(out, model.VLANInfo{
			VlanID:        m.VlanID,
			Name:          nil,
			MemberPorts:   m.MemberPorts,
			TaggedPorts:   m.TaggedPorts,
			UntaggedPorts: m.UntaggedPorts(),
		})
	}
	return out
}

// mapMgmtIP maps dev's IP/Netmask/Gateway/DhcpEnabled/Mac fields onto a
// model.MgmtIPConfig, mirroring Python's module-level _mgmt: Mode is
// IPModeUnknown when DhcpEnabled is nil, else IPModeDHCP/IPModeStatic;
// BaseMac is dev.Mac upper-cased to match the SNMP backend's formatting, so
// the public field has one consistent case across backends -- NSDP always
// has a MAC (ParseDevice falls back to the packet header field), so this is
// honestly always populated, never a guess.
func mapMgmtIP(dev model.NsdpDevice) model.MgmtIPConfig {
	mode := model.IPModeUnknown
	if dev.DhcpEnabled != nil {
		if *dev.DhcpEnabled {
			mode = model.IPModeDHCP
		} else {
			mode = model.IPModeStatic
		}
	}
	return model.MgmtIPConfig{
		Mode:    mode,
		Address: dev.IP,
		Netmask: dev.Netmask,
		Gateway: dev.Gateway,
		BaseMac: model.Ptr(strings.ToUpper(dev.Mac)),
	}
}

// GetPorts reads per-port link/speed status, mapped onto the shared
// model.PortStatus type (see mapPorts for the exact field-mapping quirks).
//
// Requests, via device: TagPortCount, TagPortStatus (plus TagModel,
// prepended by withModel). The pin's get_ports also requests PORT_NAME to
// fill PortStatus.name; that read-side reconciliation is pending (see
// fullDeviceTags' note), so this list is PORT_COUNT+PORT_STATUS for now and
// every PortStatus.Name is left nil.
func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error) {
	dev, err := r.device(ctx, []Tag{TagPortCount, TagPortStatus})
	if err != nil {
		return nil, err
	}
	return mapPorts(dev), nil
}

// GetStats reads the per-port traffic-counter snapshot, mapped onto the
// shared model.PortStats type (see mapStats for the exact field-mapping
// quirks: no packet counters, RxErrors is the CRC-error counter).
//
// Requests, via device: TagPortStatistics (plus TagModel), mirroring
// Python's get_stats/[Tag.PORT_STATISTICS].
func (r *Reader) GetStats(ctx context.Context) ([]model.PortStats, error) {
	dev, err := r.device(ctx, []Tag{TagPortStatistics})
	if err != nil {
		return nil, err
	}
	return mapStats(dev), nil
}

// GetVLANs reads the VLAN membership table, mapped onto the shared
// model.VLANInfo type (see mapVLANs: Name is always nil).
//
// Requests, via device: TagPortCount, TagVLANMembers (plus TagModel),
// mirroring Python's get_vlans/[Tag.PORT_COUNT, Tag.VLAN_MEMBERS] -- the
// port count is needed to size the VLAN_MEMBERS bitmap correctly (see
// ParseVlanMembers/ParseDevice's two-pass dispatch).
func (r *Reader) GetVLANs(ctx context.Context) ([]model.VLANInfo, error) {
	dev, err := r.device(ctx, []Tag{TagPortCount, TagVLANMembers})
	if err != nil {
		return nil, err
	}
	return mapVLANs(dev), nil
}

// GetPVIDs reads each port's default/untagged VLAN (PVID), mirroring
// Python's get_pvids/[Tag.PORT_PVID] (plus TagModel).
func (r *Reader) GetPVIDs(ctx context.Context) ([]model.Pvid, error) {
	dev, err := r.device(ctx, []Tag{TagPortPVID})
	if err != nil {
		return nil, err
	}
	out := make([]model.Pvid, 0, len(dev.PortPvids))
	for _, p := range dev.PortPvids {
		out = append(out, model.Pvid{Port: p.PortID, Vlan: p.VlanID})
	}
	return out, nil
}

// GetMgmtIP reads the switch's own management IP configuration, mapped
// onto the shared model.MgmtIPConfig type (see mapMgmtIP).
//
// Requests, via device: TagIPAddress, TagNetmask, TagGateway, TagDHCPMode
// (plus TagModel), mirroring Python's
// get_mgmt_ip/[Tag.IP_ADDRESS, Tag.NETMASK, Tag.GATEWAY, Tag.DHCP_MODE].
func (r *Reader) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error) {
	dev, err := r.device(ctx, []Tag{TagIPAddress, TagNetmask, TagGateway, TagDHCPMode})
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	return mapMgmtIP(dev), nil
}

// GetDevice returns the COMPLETE raw NsdpDevice for this switch: every tag
// ParseDevice knows how to decode, in one round trip. Unlike the other
// Get* methods above, this returns the NSDP-native shape (including the
// raw port-status speed byte) rather than mapping onto the shared model
// types -- callers that need the full protocol surface use this instead of
// the per-field ops. Mirrors Python's NsdpReader.get_device.
func (r *Reader) GetDevice(ctx context.Context) (model.NsdpDevice, error) {
	return r.device(ctx, fullDeviceTags)
}

// GetLLDP always returns an error wrapping model.ErrUnsupportedCapability:
// NSDP exposes no LLDP neighbor table on these Plus switches. Mirrors
// Python's NsdpReader.get_lldp. ctx is accepted-but-unused, purely so this
// method's signature matches the shared BackendReader surface (see
// dispatch.go).
func (r *Reader) GetLLDP(_ context.Context) ([]model.LLDPNeighbor, error) {
	return nil, unsupportedRead(noLLDPMsg)
}

// GetMACs always returns an error wrapping model.ErrUnsupportedCapability:
// NSDP exposes no MAC/FDB table on these Plus switches. Mirrors Python's
// NsdpReader.get_macs. ctx is accepted-but-unused; see GetLLDP's doc
// comment.
func (r *Reader) GetMACs(_ context.Context) ([]model.MacEntry, error) {
	return nil, unsupportedRead(noMACsMsg)
}

// GetPoE always returns an error wrapping model.ErrUnsupportedCapability:
// NSDP exposes no PoE status; use the HTTP backend (Slice 6) for PoE.
// Mirrors Python's NsdpReader.get_poe. ctx is accepted-but-unused; see
// GetLLDP's doc comment.
func (r *Reader) GetPoE(_ context.Context) ([]model.PoEStatus, error) {
	return nil, unsupportedRead(noPoEReadMsg)
}

// GetSensors always returns an error wrapping
// model.ErrUnsupportedCapability: NSDP exposes no environmental sensors on
// these Plus switches. Mirrors Python's NsdpReader.get_sensors. ctx is
// accepted-but-unused; see GetLLDP's doc comment.
func (r *Reader) GetSensors(_ context.Context) ([]model.Sensor, error) {
	return nil, unsupportedRead(noSensorsMsg)
}
