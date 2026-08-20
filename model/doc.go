// Package model holds the shared device-data types, typed errors and the
// switch-model registry used throughout this library. It is the leaf
// package every protocol package (snmp, nsdp, webui, fastpath,
// capabilities, virtual) and the root netgearswitch facade import; it
// imports nothing internal, so it can never participate in an import
// cycle.
//
// # Data types
//
// types.go and nsdp.go define the device-data shapes every backend reads
// and writes into: PortStatus, PortStats, VLANInfo, Pvid, LLDPNeighbor,
// MacEntry, PoEStatus, Sensor, MgmtIPConfig, ServiceStatus, SwitchUser,
// SyslogConfig and the NSDP-native Nsdp* types (NsdpPortStatus,
// NsdpVlanMembership, NsdpDevice, ...), plus the small enums that appear
// across several of them (PoEDetect, VlanMode, IPMode, LinkSpeed,
// VLANEngine). Every optional field that a backend may honestly not be
// able to report is a pointer (nil means "unknown/not reported here", not
// a fabricated zero value) -- see PortStatus.Description or
// MgmtIPConfig.Address for examples. SwitchData bundles one of everything
// into a single snapshot value, mirroring what Switch.Snapshot returns.
//
// # Registry
//
// registry.go declares the fixed set of NETGEAR switch models this library
// knows about (Models, GetModel) as SwitchModel values: each names the
// model's product line (SwitchClass), port/PoE-port counts, which
// Backend(s) it speaks, and (SNMPVendorBase/SNMPCanCreateVLAN) a couple of
// SNMP-specific capability flags the capabilities package's oracle reads
// directly. Backend is the shared enum naming a wire protocol (BackendSNMP,
// BackendNSDP, BackendHTTP, BackendSSH, BackendTelnet, BackendConsole);
// SwitchModel.HasBackend/HasMACTable are the two derived queries built on
// top of it. Every SwitchModel entry in the registry carries the
// provenance of its own fields (Verified, and per-field comments) rather
// than presenting spec-sheet guesses as measured fact.
//
// # Errors
//
// errors.go defines the sentinel errors this library's failures wrap
// (ErrUnsupportedCapability, ErrProtectedPort, ErrKnownUnimplemented,
// ErrCredential, ErrConfig, ErrUnknownModel, ErrSNMP, ErrNSDP, ErrHTTP and
// its ErrHTTPAuth/ErrHTTPUnexpectedPage specializations) -- match them with
// errors.Is -- plus WriteVerificationError, the structured before/after
// mismatch a write's own verify-after-write check returns.
package model
