package netgearswitch

import (
	"github.com/mithro/go-netgear-switch-library/capabilities"
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
	// PortSpeed is aliased from model.PortSpeed.
	PortSpeed = model.PortSpeed
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
	// ServiceStatus is aliased from model.ServiceStatus.
	ServiceStatus = model.ServiceStatus
	// SwitchUser is aliased from model.SwitchUser.
	SwitchUser = model.SwitchUser
	// SyslogServer is aliased from model.SyslogServer.
	SyslogServer = model.SyslogServer
	// SyslogConfig is aliased from model.SyslogConfig.
	SyslogConfig = model.SyslogConfig
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
	// Capability is aliased from capabilities.Capability.
	Capability = capabilities.Capability
	// Operation is aliased from capabilities.Operation.
	Operation = capabilities.Operation
	// OperationKind is aliased from capabilities.OperationKind.
	OperationKind = capabilities.OperationKind
	// Support is aliased from capabilities.Support.
	Support = capabilities.Support
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

// Support values, re-exported from capabilities.
const (
	SupportSupported   = capabilities.SupportSupported
	SupportNoBackend   = capabilities.SupportNoBackend
	SupportUnsupported = capabilities.SupportUnsupported
	SupportUnverified  = capabilities.SupportUnverified
)

// OperationKind values, re-exported from capabilities.
const (
	OperationKindRead  = capabilities.OperationKindRead
	OperationKindWrite = capabilities.OperationKindWrite
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

// AutoPortSpeed returns the auto-negotiate PortSpeed configuration; see
// model.AutoPortSpeed.
func AutoPortSpeed() PortSpeed {
	return model.AutoPortSpeed()
}

// ForcedPortSpeed returns a forced fixed-rate/duplex PortSpeed
// configuration; see model.ForcedPortSpeed.
func ForcedPortSpeed(speedMbps int, fullDuplex bool) PortSpeed {
	return model.ForcedPortSpeed(speedMbps, fullDuplex)
}

// PrivilegedAccess reports whether accessMode is a full-privilege access
// level; see model.PrivilegedAccess.
func PrivilegedAccess(accessMode string) *bool {
	return model.PrivilegedAccess(accessMode)
}

// SyslogSeverity maps a switch's severity WORD to its standard number; see
// model.SyslogSeverity.
func SyslogSeverity(name string) (int, error) {
	return model.SyslogSeverity(name)
}

// SyslogSeverityWord maps a severity NUMBER to the CLI's word for it; see
// model.SyslogSeverityWord.
func SyslogSeverityWord(level int) (string, error) {
	return model.SyslogSeverityWord(level)
}

// SyslogSeverityLabel maps a severity NUMBER to the web UI's word for it;
// see model.SyslogSeverityLabel.
func SyslogSeverityLabel(level int) (string, error) {
	return model.SyslogSeverityLabel(level)
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

// Operations is the full 21-entry read+write operation table, re-exported
// from capabilities.Operations. ReadOperations/WriteOperations/
// OperationByName are DELIBERATELY not re-exported here -- reach them via
// the capabilities package directly, mirroring Python's netgear_switch
// top-level package re-exporting only a subset of netgear_switch.capabilities
// (dossier §2).
var Operations = capabilities.Operations

// For is the capability oracle's top-level verdict function; see
// capabilities.For.
func For(m *model.SwitchModel, backend model.Backend, op capabilities.Operation) capabilities.Capability {
	return capabilities.For(m, backend, op)
}

// ForKey is For's string-keyed convenience entry point; see capabilities.ForKey.
func ForKey(modelKey string, backend model.Backend, opName string) (capabilities.Capability, error) {
	return capabilities.ForKey(modelKey, backend, opName)
}

// BackendsFor returns a model's backends in the facade's default-preference
// order; see capabilities.BackendsFor.
func BackendsFor(m *model.SwitchModel) []model.Backend {
	return capabilities.BackendsFor(m)
}

// Matrix returns every capability verdict for modelKeys x their backends x
// operations; see capabilities.Matrix.
func Matrix(modelKeys []string, operations []capabilities.Operation) ([]capabilities.Capability, error) {
	return capabilities.Matrix(modelKeys, operations)
}
