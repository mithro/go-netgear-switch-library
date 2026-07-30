package netgearswitch

import (
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// Device-data and enum types below are aliased from model so callers need
// only import this top-level package. See model/types.go and
// model/registry.go for field-by-field documentation.
type (
	// PoEDetect is aliased from model.PoEDetect.
	PoEDetect = model.PoEDetect
	// VlanMode is aliased from model.VlanMode.
	VlanMode = model.VlanMode
	// IPMode is aliased from model.IPMode.
	IPMode = model.IPMode
	// PortStatus is aliased from model.PortStatus.
	PortStatus = model.PortStatus
	// PoEStatus is aliased from model.PoEStatus.
	PoEStatus = model.PoEStatus
	// VLANInfo is aliased from model.VLANInfo.
	VLANInfo = model.VLANInfo
	// LLDPNeighbor is aliased from model.LLDPNeighbor.
	LLDPNeighbor = model.LLDPNeighbor
	// MacEntry is aliased from model.MacEntry.
	MacEntry = model.MacEntry
	// Sensor is aliased from model.Sensor.
	Sensor = model.Sensor
	// PortStats is aliased from model.PortStats.
	PortStats = model.PortStats
	// MgmtIPConfig is aliased from model.MgmtIPConfig.
	MgmtIPConfig = model.MgmtIPConfig
	// DetectedModel is aliased from model.DetectedModel.
	DetectedModel = model.DetectedModel
	// Pvid is aliased from model.Pvid.
	Pvid = model.Pvid
	// SwitchData is aliased from model.SwitchData.
	SwitchData = model.SwitchData
	// Backend is aliased from model.Backend.
	Backend = model.Backend
	// SwitchClass is aliased from model.SwitchClass.
	SwitchClass = model.SwitchClass
	// SwitchModel is aliased from model.SwitchModel.
	SwitchModel = model.SwitchModel
	// LinkSpeed is aliased from model.LinkSpeed.
	LinkSpeed = model.LinkSpeed
	// VLANEngine is aliased from model.VLANEngine.
	VLANEngine = model.VLANEngine
	// NsdpPortStatus is aliased from model.NsdpPortStatus.
	NsdpPortStatus = model.NsdpPortStatus
	// NsdpPortStatistics is aliased from model.NsdpPortStatistics.
	NsdpPortStatistics = model.NsdpPortStatistics
	// NsdpVlanMembership is aliased from model.NsdpVlanMembership.
	NsdpVlanMembership = model.NsdpVlanMembership
	// NsdpPortPvid is aliased from model.NsdpPortPvid.
	NsdpPortPvid = model.NsdpPortPvid
	// NsdpPortMirroring is aliased from model.NsdpPortMirroring.
	NsdpPortMirroring = model.NsdpPortMirroring
	// NsdpIgmpSnooping is aliased from model.NsdpIgmpSnooping.
	NsdpIgmpSnooping = model.NsdpIgmpSnooping
	// NsdpDevice is aliased from model.NsdpDevice.
	NsdpDevice = model.NsdpDevice
)

// WriteVerificationError is aliased from model; see model.WriteVerificationError.
type WriteVerificationError = model.WriteVerificationError

// PoeCycleTimeouts is aliased from snmp.PoeCycleTimeouts, so callers
// configuring a CyclePoE/ClearPoEFault call (via WithCycleTimeouts) need not
// import the snmp package directly. See snmp/writer_cycle.go.
type PoeCycleTimeouts = snmp.PoeCycleTimeouts

// DefaultPoeCycleTimeouts returns the production PoE-cycle deadlines
// (30s/60s/2s); see snmp.DefaultPoeCycleTimeouts.
func DefaultPoeCycleTimeouts() PoeCycleTimeouts {
	return snmp.DefaultPoeCycleTimeouts()
}

// PoEDetect values, re-exported from model.
const (
	PoEDetectDisabled   = model.PoEDetectDisabled
	PoEDetectSearching  = model.PoEDetectSearching
	PoEDetectDelivering = model.PoEDetectDelivering
	PoEDetectFault      = model.PoEDetectFault
	PoEDetectUnknown    = model.PoEDetectUnknown
)

// VlanMode values, re-exported from model.
const (
	VlanUntagged = model.VlanUntagged
	VlanTagged   = model.VlanTagged
	VlanExcluded = model.VlanExcluded
)

// IPMode values, re-exported from model.
const (
	IPModeDHCP    = model.IPModeDHCP
	IPModeStatic  = model.IPModeStatic
	IPModeUnknown = model.IPModeUnknown
)

// Backend values, re-exported from model.
const (
	BackendSNMP    = model.BackendSNMP
	BackendNSDP    = model.BackendNSDP
	BackendHTTP    = model.BackendHTTP
	BackendSSH     = model.BackendSSH
	BackendTelnet  = model.BackendTelnet
	BackendConsole = model.BackendConsole
)

// SwitchClass values, re-exported from model.
const (
	ClassFullyManaged    = model.ClassFullyManaged
	ClassSmartManagedPro = model.ClassSmartManagedPro
	ClassPlus            = model.ClassPlus
)

// LinkSpeed values, re-exported from model.
const (
	LinkSpeedDown       = model.LinkSpeedDown
	LinkSpeedHalf10M    = model.LinkSpeedHalf10M
	LinkSpeedFull10M    = model.LinkSpeedFull10M
	LinkSpeedHalf100M   = model.LinkSpeedHalf100M
	LinkSpeedFull100M   = model.LinkSpeedFull100M
	LinkSpeedGigabit    = model.LinkSpeedGigabit
	LinkSpeedTenGigabit = model.LinkSpeedTenGigabit
)

// LinkSpeedFromByte decodes a raw NSDP wire byte into a LinkSpeed; see
// model.LinkSpeedFromByte.
func LinkSpeedFromByte(b byte) LinkSpeed {
	return model.LinkSpeedFromByte(b)
}

// VLANEngine values, re-exported from model.
const (
	VLANEngineDisabled      = model.VLANEngineDisabled
	VLANEngineBasicPort     = model.VLANEngineBasicPort
	VLANEngineAdvancedPort  = model.VLANEngineAdvancedPort
	VLANEngineBasic8021Q    = model.VLANEngineBasic8021Q
	VLANEngineAdvanced8021Q = model.VLANEngineAdvanced8021Q
)

// Error sentinels, re-exported from model. Match with errors.Is (and
// errors.As for WriteVerificationError); see model/errors.go.
var (
	ErrUnsupportedCapability = model.ErrUnsupportedCapability
	ErrProtectedPort         = model.ErrProtectedPort
	ErrKnownUnimplemented    = model.ErrKnownUnimplemented
	ErrCredential            = model.ErrCredential
	ErrConfig                = model.ErrConfig
	ErrUnknownModel          = model.ErrUnknownModel
	ErrSNMP                  = model.ErrSNMP
	ErrNSDP                  = model.ErrNSDP
	ErrHTTP                  = model.ErrHTTP
	ErrHTTPAuth              = model.ErrHTTPAuth
	ErrHTTPUnexpectedPage    = model.ErrHTTPUnexpectedPage
)

// GetModel looks up a switch model by its canonical registry key or a known
// alias; see model.GetModel.
func GetModel(key string) (*SwitchModel, error) {
	return model.GetModel(key)
}

// Models returns the full switch-model registry in canonical order; see
// model.Models.
func Models() []*SwitchModel {
	return model.Models()
}
