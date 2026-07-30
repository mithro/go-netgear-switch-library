package netgearswitch

import "github.com/mithro/go-netgear-switch-library/model"

// Device-data and enum types, aliased from model so callers need only
// import this top-level package. See model/types.go and
// model/registry.go for field-by-field documentation.
type (
	PoEDetect     = model.PoEDetect
	VlanMode      = model.VlanMode
	IpMode        = model.IpMode
	PortStatus    = model.PortStatus
	PoEStatus     = model.PoEStatus
	VLANInfo      = model.VLANInfo
	LLDPNeighbor  = model.LLDPNeighbor
	MacEntry      = model.MacEntry
	Sensor        = model.Sensor
	PortStats     = model.PortStats
	MgmtIpConfig  = model.MgmtIpConfig
	DetectedModel = model.DetectedModel
	Pvid          = model.Pvid
	SwitchData    = model.SwitchData
	Backend       = model.Backend
	SwitchClass   = model.SwitchClass
	SwitchModel   = model.SwitchModel
)

// WriteVerificationError is aliased from model; see model.WriteVerificationError.
type WriteVerificationError = model.WriteVerificationError

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

// IpMode values, re-exported from model.
const (
	IpModeDHCP    = model.IpModeDHCP
	IpModeStatic  = model.IpModeStatic
	IpModeUnknown = model.IpModeUnknown
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
