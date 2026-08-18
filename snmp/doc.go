// Package snmp implements the SNMP backend (model.BackendSNMP) for the root
// netgearswitch facade: reading and writing a NETGEAR switch's standard
// MIB-II tables and its per-product-family NETGEAR vendor OID subtree.
// It is the richest and generally fastest backend on the fully-managed and
// Smart Managed Pro product lines that speak it.
//
// # Client and transport
//
// Client and WriteClient are the minimal Get/Walk and Set method sets this
// package's Reader/Writer need; GoSNMPClient (NewGoSNMPClient) is the
// production implementation, built on github.com/gosnmp/gosnmp. Row is the
// (OID, value) pair every Get/Walk call returns; NewIntRow/NewStrRow/
// NewBytesRow construct one directly, primarily for tests and for the
// virtual package's fake SNMP face. Both interfaces are satisfied by any
// client a caller wants to inject (see the root package's WithSNMPClient/
// WithSNMPWriteClient), including a fake one in tests.
//
// # Reading and writing
//
// Reader (NewReader) and Writer (NewWriter), each bound to a Client/
// WriteClient and a *model.SwitchModel, are this backend's
// netgearswitch.BackendReader/BackendWriter implementations: one method per
// facade operation (GetPorts, GetVLANs, SetPVID, CreateVlan, ...). Every
// write verifies its own effect by reading the changed state back
// immediately afterward; WriterOption (WithProtectedPorts, WithClock) tunes
// the protected-port guard and, for CyclePoE/ClearPoEFault's poll loop, the
// clock/sleep functions a test can fake to avoid real wall-clock delays.
// ReadSystemInfo is the one exception to the model-bound Reader shape: a
// free function taking a bare Client, used for model DISCOVERY (see the
// root package's DetectModel/Switch.Identify) before any *model.SwitchModel
// is known or trusted.
//
// # OID tables and encoding
//
// oids.go holds the standard-MIB and NETGEAR vendor OID constants
// (SysDescr, SysObjectID, ...) and their vendor-subtree derivation
// (GetVendorOids, HasVendorOids); parse.go holds the Parse* functions that
// turn a walked column's raw Rows into model types (ParsePortStatus,
// ParseVlans, ParsePoe, ...) plus the VLAN egress/untagged bitmap codec
// (EncodePortBitmap/DecodePortBitmap/SetPortBit/MembershipBitmaps) SNMP's
// Q-BRIDGE MIB VLAN writes and reads share. DetectModelFromSysObjectID and
// DetectModelFromSysDescr are the two model-identification heuristics
// ReadSystemInfo tries in order (the OID map first, since it is
// unambiguous; the sysDescr text match only as a fallback).
//
// Ported field-for-field from src/netgear_switch/protocols/snmp/ (the
// normative source; that repo is read-only from here). Any discrepancy
// between this package and the pinned Python source is a bug in this
// package, not a deliberate deviation, unless called out in a comment.
package snmp
