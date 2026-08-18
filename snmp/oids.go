// oids.go holds the standard-MIB and Netgear vendor OID tables used to
// read a switch over SNMP, ported field-for-field from
// src/netgear_switch/protocols/snmp/oids.py (the normative source; that
// repo is read-only from here). Any discrepancy between this file and the
// Python source is a bug in this file. See package snmp's doc comment
// (doc.go) for the package overview.

package snmp

import (
	"fmt"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Standard-MIB OID constants.
//
// SysDescr and SysObjectID are full, instance-qualified (".0") leaf OIDs,
// fetched with a plain exact-OID GET (unlike the walk-based base-OIDs
// below) -- see the (later-slice) system-info reader. SysObjectID is
// matched via the (later-slice) SYSOBJECTID_MODELS table, the authoritative
// signal tried first; SysDescr is the fallback text heuristic.
const (
	// SysDescr is sysDescr: text including the model name.
	SysDescr = "1.3.6.1.2.1.1.1.0"
	// SysObjectID is sysObjectID: matched via SYSOBJECTID_MODELS
	// (authoritative), else carried raw.
	SysObjectID = "1.3.6.1.2.1.1.2.0"

	// SysName is sysName: the switch's host name. A STANDARD MIB-II
	// scalar, which is why it is the one hostname source that also works
	// on gs728tpp -- that agent publishes no Netgear vendor subtree at
	// all.
	//
	// WRITABLE on every SNMP model in this fleet. Measured 2026-08-02 by
	// SETting the value the switch already had: a zero-impact writability
	// probe, since the device state cannot change but a read-only column
	// still answers notWritable. All five accepted -- gsm7228ps
	// (10.1.5.11) on community `public`, which is the only one it has,
	// and m4300-24x (.13), m4300-16x (.20), gsm7252ps (.22) and gs728tpp
	// (10.2.5.10) on `private`.
	//
	// NOT the same value as the FASTPATH `hostname` running-config
	// directive. On m4300-16x sysName is
	// "sw-netgear-m4300-16x-poe-s2" while running-config holds
	// "manage-sw-netgear-m4300-16x-poe-s2", and on gsm7252ps
	// running-config carries no hostname at all. sysName tracks `show
	// hosts`, which is therefore what the CLI reader parses so that the
	// two backends cannot disagree.
	SysName = "1.3.6.1.2.1.1.5.0"

	// IfType is ifType (6 = ethernetCsmacd = physical port); see
	// EthernetCsmacd. Filters LAG(161)/CPU(1)/l2vlan(135) pseudo-interfaces
	// out of ports/stats/pvids.
	IfType = "1.3.6.1.2.1.2.2.1.3"
	// IfAdminStatus is ifAdminStatus (1=up, 2=down).
	IfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	// IfOperStatus is ifOperStatus (1=up, 2=down).
	IfOperStatus = "1.3.6.1.2.1.2.2.1.8"
	// IfInErrors is ifInErrors.
	IfInErrors = "1.3.6.1.2.1.2.2.1.14"
	// IfOutErrors is ifOutErrors.
	IfOutErrors = "1.3.6.1.2.1.2.2.1.20"
	// IfName is ifName.
	IfName = "1.3.6.1.2.1.31.1.1.1.1"
	// IfHCInOctets is ifHCInOctets.
	IfHCInOctets = "1.3.6.1.2.1.31.1.1.1.6"
	// IfHCInUcast is ifHCInUcastPkts.
	IfHCInUcast = "1.3.6.1.2.1.31.1.1.1.7"
	// IfHCOutOctets is ifHCOutOctets.
	IfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	// IfHCOutUcast is ifHCOutUcastPkts.
	IfHCOutUcast = "1.3.6.1.2.1.31.1.1.1.11"
	// IfHighSpeed is ifHighSpeed, in Mbps.
	IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15"
	// IfAlias is ifAlias.
	IfAlias = "1.3.6.1.2.1.31.1.1.1.18"

	// EtherLike-MIB (RFC 3635) per-port duplex and pause (flow control).
	// NOT served by every agent, and the difference is per-model,
	// measured 2026-08-03:
	//
	//   gs728tpp 10.2.5.10 : dot3StatsTable has column 19,
	//                        dot3PauseTable has columns 1 and 2 -- both
	//                        readable for all 36 interfaces.
	//   gsm7252ps 10.1.5.22: dot3StatsTable stops at column 16 (no 19)
	//                        and dot3PauseTable serves only the COUNTERS
	//                        (3-6), not AdminMode/OperMode. So duplex and
	//                        flow control are genuinely unavailable over
	//                        SNMP there, and stay nil rather than being
	//                        invented.
	//
	// Dot3StatsDuplexStatus: 1 unknown, 2 halfDuplex, 3 fullDuplex.
	// Dot3PauseOperMode:     1 disabled, 2 enabledXmit, 3 enabledRcv,
	//                        4 enabledXmitAndRcv.

	// Dot3StatsDuplexStatus is dot3StatsDuplexStatus.
	Dot3StatsDuplexStatus = "1.3.6.1.2.1.10.7.2.1.19"
	// Dot3PauseAdminMode is dot3PauseAdminMode.
	Dot3PauseAdminMode = "1.3.6.1.2.1.10.7.10.1.1"
	// Dot3PauseOperMode is dot3PauseOperMode.
	Dot3PauseOperMode = "1.3.6.1.2.1.10.7.10.1.2"

	// Dot1dBaseBridgeAddress is dot1dBaseBridgeAddress: a scalar (.0);
	// BRIDGE-MIB base MAC.
	Dot1dBaseBridgeAddress = "1.3.6.1.2.1.17.1.1"
	// Dot1dBasePortIfIndex is dot1dBasePortIfIndex.
	Dot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"
	// Dot1qTpFdbPort is dot1qTpFdbPort: MAC table, port column ONLY.
	Dot1qTpFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	// Dot1qVlanStaticName is dot1qVlanStaticName.
	Dot1qVlanStaticName = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	// Dot1qVlanStaticEgress is dot1qVlanStaticEgressPorts.
	Dot1qVlanStaticEgress = "1.3.6.1.2.1.17.7.1.4.3.1.2"
	// Dot1qVlanStaticUntagged is dot1qVlanStaticUntaggedPorts.
	Dot1qVlanStaticUntagged = "1.3.6.1.2.1.17.7.1.4.3.1.4"
	// Dot1qVlanCurrentEgress is dot1qVlanCurrentEgressPorts -- the
	// OPERATIONAL VLAN table, indexed by <dot1qVlanTimeMark>.<dot1qVlanIndex>
	// (the static columns above are indexed by the VLAN id alone). Read
	// alongside the static table because a VLAN can exist here and NOT
	// there: MEASURED on a GS728TPP (10.2.5.10, firmware 6.0.1.30) VLAN 1
	// has no dot1qVlanStaticTable row at all, only a current-table row with
	// dot1qVlanStatus = 1 (other) -- see ParseVlans.
	Dot1qVlanCurrentEgress = "1.3.6.1.2.1.17.7.1.4.2.1.4"
	// Dot1qVlanCurrentUntagged is dot1qVlanCurrentUntaggedPorts.
	Dot1qVlanCurrentUntagged = "1.3.6.1.2.1.17.7.1.4.2.1.5"
	// Dot1qVlanStatus is dot1qVlanStatus (1 other, 2 permanent,
	// 3 dynamicGvrp). Documented for parity with the Python source; not
	// walked anywhere today -- ParseVlans distinguishes a static-table row
	// from a current-table-only row by presence in the name column instead.
	Dot1qVlanStatus = "1.3.6.1.2.1.17.7.1.4.2.1.6"
	// Dot1qPvid is dot1qPvid.
	Dot1qPvid = "1.3.6.1.2.1.17.7.1.4.5.1.1"
	// Dot1qVlanStaticRowStatus is dot1qVlanStaticRowStatus.
	Dot1qVlanStaticRowStatus = "1.3.6.1.2.1.17.7.1.4.3.1.5"
	// RowStatusCreateAndGo is the RFC 2579 RowStatus createAndGo value.
	RowStatusCreateAndGo = 4
	// RowStatusDestroy is the RFC 2579 RowStatus destroy value.
	RowStatusDestroy = 6

	// ENTITY-MIB entPhysicalTable columns (RFC 4133/2737). Some Netgear
	// agents (verified: the GS728TPP, whose SNMP agent implements ZERO 4526
	// vendor OIDs) expose their fan/PSU sensor components ONLY as this
	// standard physical inventory -- EntPhysicalClass says what a row is,
	// EntPhysicalName/EntPhysicalDescr name it -- with NO live status/value
	// anywhere in SNMP.

	// EntPhysicalDescr is entPhysicalDescr.
	EntPhysicalDescr = "1.3.6.1.2.1.47.1.1.1.1.2"
	// EntPhysicalClass is entPhysicalClass: int enum; 6=powerSupply,7=fan.
	EntPhysicalClass = "1.3.6.1.2.1.47.1.1.1.1.5"
	// EntPhysicalName is entPhysicalName.
	EntPhysicalName = "1.3.6.1.2.1.47.1.1.1.1.7"
	// EntClassPowerSupply is the entPhysicalClass value for a power supply.
	EntClassPowerSupply = 6
	// EntClassFan is the entPhysicalClass value for a fan.
	EntClassFan = 7

	// LldpRemTable is lldpRemTable's base OID. Instance shape:
	// <column>.<timeMark>.<localPortNum>.<remIndex>. Columns:
	// 5=chassis,7=portId,8=portDesc,9=sysName.
	LldpRemTable = "1.0.8802.1.1.2.1.4.1"

	// PethPsePortTable is pethPsePortTable's base OID (RFC 3621). Instance
	// shape: <column>.<group>.<port>; only columns 3 (admin) and 6 (detect)
	// are honoured -- never column 1.
	PethPsePortTable = "1.3.6.1.2.1.105.1.1.1"
	// PethPsePortAdmin/PethPsePortDetect are the ONLY two columns ParsePoe
	// honours (pethPsePortAdminEnable / pethPsePortDetectionStatus) --
	// walked as two column-scoped GETBULKs instead of the whole table
	// (GetPoE, reader.go), per python-netgear-switch-library commit
	// 86af0a9. Not a micro-optimisation on real hardware: MEASURED on
	// sw-netgear-gs728tpp.monarto.mithis.com (10.2.5.10, firmware 6.0.1.30,
	// via the ten64 jump host), each figure the mean of repeated runs on an
	// otherwise idle switch --
	//
	//	ifName (69 rows)                    1.5s
	//	whole PethPsePortTable (288 rows) 102.0s
	//	PethPsePortAdmin       (24 rows)   11.7s
	//	PethPsePortDetect      (24 rows)   11.4s
	//
	// -- so the agent answers this MIB at roughly 0.35s/varbind: two column
	// walks cost ~23s where the table walk cost 102s. That is what made a
	// PoE WRITE (which verifies by re-reading) unusable rather than merely
	// slow. Raising max-repetitions is NOT an alternative -- it is actively
	// unsafe here: -Cr25 returned a TRUNCATED 50 rows in 44s, i.e. this
	// agent mishandles large GETBULKs on this table. Fetching fewer
	// varbinds is the only sound speed-up.
	PethPsePortAdmin  = PethPsePortTable + ".3" // pethPsePortAdminEnable
	PethPsePortDetect = PethPsePortTable + ".6" // pethPsePortDetectionStatus

	// IPAdEntAddr is ipAdEntAddr (RFC-1213 ipAddrTable).
	IPAdEntAddr = "1.3.6.1.2.1.4.20.1.1"
	// IPAdEntIfIndex is ipAdEntIfIndex.
	IPAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2"
	// IPAdEntNetmask is ipAdEntNetmask.
	IPAdEntNetmask = "1.3.6.1.2.1.4.20.1.3"
	// IPAddressIfIndex is ipAddressIfIndex (RFC-4293 ipAddressTable): newer
	// firmware (M4300) leaves the RFC-1213 ipAddrTable EMPTY and publishes
	// the management address here instead, encoded in the row index:
	// ipAddressIfIndex.<type>.<len>.<ip-bytes> (type 1=ipv4).
	IPAddressIfIndex = "1.3.6.1.2.1.4.34.1.3"
	// IPRouteDest is ipRouteDest.
	IPRouteDest = "1.3.6.1.2.1.4.21.1.1"
	// IPRouteNextHop is ipRouteNextHop (gateway where dest=0.0.0.0).
	IPRouteNextHop = "1.3.6.1.2.1.4.21.1.7"

	// EthernetCsmacd is the ifType value (6) identifying a real physical
	// port; used to filter LAG/CPU/l2vlan pseudo-interfaces out of
	// ports/stats/pvids reads.
	EthernetCsmacd = 6

	// --- Netgear FASTPATH vendor switchport table --------------------------
	//
	// 1.3.6.1.4.1.4526.10.1.2.8.37.1.<column>.<ifIndex>. On FASTPATH 12.x the
	// standard Q-BRIDGE dot1qVlanStaticEgress/UntaggedPorts PortLists above
	// are READ-ONLY MIRRORS -- writing them returns commitFailed even for
	// byte-identical values -- because per-port SWITCHPORT MODE owns VLAN
	// membership. These columns are the writable control plane. Ported from
	// protocols/snmp/oids.py's FASTPATH_SWITCHPORT_* block (pin b26eb1f).
	//
	// Column meanings and writability were established EMPIRICALLY on a real
	// M4300-24X (10.1.5.13, firmware 12.0.13.8): a full snmpwalk was
	// captured, VLAN membership was changed through the switch's own CLI,
	// the tree was walked again, and the two walks were diffed -- so every
	// column below is grounded in an observed change, not a MIB guess (no
	// Netgear MIB file was available).

	// FastpathSwitchportMode is agentSwitchportMode -- writable.
	FastpathSwitchportMode = "1.3.6.1.4.1.4526.10.1.2.8.37.1.2"
	// FastpathSwitchportAccessVlan is the port's access VLAN (col3) --
	// writable.
	FastpathSwitchportAccessVlan = "1.3.6.1.4.1.4526.10.1.2.8.37.1.3"
	// FastpathSwitchportNativeVlan is the port's trunk native VLAN (col4) --
	// writable, but only to an EXISTING VLAN in 1..4093 (see
	// PlanSwitchportMembership's own doc comment).
	FastpathSwitchportNativeVlan = "1.3.6.1.4.1.4526.10.1.2.8.37.1.4"
	// FastpathSwitchportAllowedVlans is the trunk-mode allowed-VLAN 512-byte
	// bitmap (col6, 4096 VLANs, MSB-first, VLAN 1 = bit 7 of byte 0) --
	// writable.
	FastpathSwitchportAllowedVlans = "1.3.6.1.4.1.4526.10.1.2.8.37.1.6"
	// FastpathSwitchportUntaggedVlans is the general-mode untagged
	// participation VLAN bitmap (col7) -- notWritable.
	FastpathSwitchportUntaggedVlans = "1.3.6.1.4.1.4526.10.1.2.8.37.1.7"
	// FastpathSwitchportTaggedVlans is the general-mode tagged participation
	// VLAN bitmap (col8) -- notWritable.
	FastpathSwitchportTaggedVlans = "1.3.6.1.4.1.4526.10.1.2.8.37.1.8"

	// SwitchportModeAccess/Trunk/General are the agentSwitchportMode enum
	// values, confirmed by CLI<->SNMP correlation: `switchport mode access`
	// reads 1 and `switchport mode general` reads 3.
	SwitchportModeAccess  = 1
	SwitchportModeTrunk   = 2
	SwitchportModeGeneral = 3
	// SwitchportVlanBitmapBytes is the VLAN bitmap width for the switchport
	// VLAN-list columns: 4096 VLANs / 8.
	SwitchportVlanBitmapBytes = 512

	// DHCPModeOIDSuffix is the UNVERIFIED Netgear private OID suffix for
	// DHCP-vs-static management-IP mode.
	//
	// This is an unconfirmed guess used only so the mock and the reader
	// agree under test; it MUST be confirmed against real hardware via the
	// capture utility (Slice 7) before it is trusted. Until then reading
	// the management IP mode reports IPModeUnknown when this OID is absent.
	// The ONE symbol every call site uses for this OID is
	// VendorOids.DHCPModeUnverified -- no call site may hard-code a
	// ".99.1" literal.
	DHCPModeOIDSuffix = "99.1"
)

// BoxSensorColumns is the (kind, unit, column suffix under {base}.43.1)
// reference table for the vendor box-sensor subtree. Documentation/
// reference only -- not consumed at runtime (readers construct the triple
// inline from VendorOids fields).
var BoxSensorColumns = [3]struct{ Kind, Unit, Suffix string }{
	{"fan", "RPM", "6.1.4"},
	{"power", "W", "8.1.5"},
	{"temperature", "C", "15.1.3"},
}

// VendorOids is a per-model Netgear vendor-specific OID table, resolved by
// GetVendorOids from a SwitchModel's SNMPVendorBase.
type VendorOids struct {
	// Base is the model's vendor OID subtree root (e.g.
	// "1.3.6.1.4.1.4526.10").
	Base string
	// PoEPowerMw is {Base}.15.1.1.1.2.
	PoEPowerMw string
	// BoxFan is {Base}.43.1.6.1.4.
	BoxFan string
	// BoxPSUPower is {Base}.43.1.8.1.5.
	BoxPSUPower string
	// BoxTemp is {Base}.43.1.15.1.3.
	BoxTemp string
	// DHCPModeUnverified is {Base}.99.1 -- see DHCPModeOIDSuffix. The ONE
	// symbol every call site uses for the DHCP-mode OID; no call site may
	// hard-code a ".99.1" literal.
	DHCPModeUnverified string
	// SyslogAdminMode is {Base}.14.1.4.1.0.
	SyslogAdminMode string
	// SyslogLocalPort is {Base}.14.1.4.3.0.
	SyslogLocalPort string
	// SyslogHostAddr is {Base}.14.1.4.5.1.3.
	SyslogHostAddr string
	// SyslogHostPort is {Base}.14.1.4.5.1.4.
	SyslogHostPort string
	// SyslogHostSeverity is {Base}.14.1.4.5.1.5.
	SyslogHostSeverity string
	// SyslogHostStatus is {Base}.14.1.4.5.1.7.
	//
	// SyslogAdminMode/SyslogLocalPort/SyslogHostAddr/SyslogHostPort/
	// SyslogHostSeverity/SyslogHostStatus are remote-logging
	// configuration, under <base>.14 on BOTH vendor families -- 4526.10
	// (FASTPATH) and 4526.11 (S3300) share the column layout.
	//
	// Located 2026-08-02 by reading each switch's own `show logging` /
	// `show logging hosts` and then searching a full walk for those
	// values; every field of the CLI output is accounted for by a column
	// and the two agree. On m4300-24x (10.1.5.13) the host row reads
	// 10.1.5.1 / port 514 / severity 6 / status 1 against a CLI table of
	// "10.1.5.1  info  514 Active" -- so severity is the standard syslog
	// scale (6 = info) and status 1 = Active.
	//
	// <base>.17 is NOT this: it looks like logging until you notice it
	// holds port 123 and the string "NTP Bits". It is SNTP, and this
	// fleet's NTP server and syslog server are the same host, which is
	// what makes the confusion easy.
	//
	// The admin-mode enum is 1 = enabled, 2 = disabled, confirmed twice
	// over on m4300-24x: syslog reads 1 while `show logging` says
	// "Syslog Logging : enabled", and the console column reads 2 while
	// it says "Console Logging : disabled". The console severity column
	// independently reads 3 against a CLI "error", matching the same
	// syslog scale.
	SyslogHostStatus string
	// MgmtWriteAddrUnverified is {Base}.98.1.
	MgmtWriteAddrUnverified string
	// MgmtWriteNetmaskUnverified is {Base}.98.2.
	MgmtWriteNetmaskUnverified string
	// MgmtWriteGatewayUnverified is {Base}.98.3.
	//
	// MgmtWriteAddrUnverified/MgmtWriteNetmaskUnverified/
	// MgmtWriteGatewayUnverified are UNVERIFIED writable management-IP
	// OIDs -- placeholders pending Slice 7 hardware capture. They are
	// NEVER trusted on real hardware (writing the management IP is
	// force-gated and documented UNVERIFIED); they exist so the mutable
	// mock and the writer agree under test, mirroring the
	// DHCPModeUnverified precedent above. No call site may hard-code these
	// literals.
	MgmtWriteGatewayUnverified string
}

// vendorOidsFor builds the VendorOids table for a non-empty vendor base,
// applying the §1.4 formulas verbatim. Callers must have already verified
// base != "".
func vendorOidsFor(base string) VendorOids {
	return VendorOids{
		Base:                       base,
		PoEPowerMw:                 base + ".15.1.1.1.2",
		BoxFan:                     base + ".43.1.6.1.4",
		BoxPSUPower:                base + ".43.1.8.1.5",
		BoxTemp:                    base + ".43.1.15.1.3",
		DHCPModeUnverified:         base + "." + DHCPModeOIDSuffix,
		SyslogAdminMode:            base + ".14.1.4.1.0",
		SyslogLocalPort:            base + ".14.1.4.3.0",
		SyslogHostAddr:             base + ".14.1.4.5.1.3",
		SyslogHostPort:             base + ".14.1.4.5.1.4",
		SyslogHostSeverity:         base + ".14.1.4.5.1.5",
		SyslogHostStatus:           base + ".14.1.4.5.1.7",
		MgmtWriteAddrUnverified:    base + ".98.1",
		MgmtWriteNetmaskUnverified: base + ".98.2",
		MgmtWriteGatewayUnverified: base + ".98.3",
	}
}

// HasVendorOids reports whether m's SNMP agent implements the Netgear
// vendor OID subtree (SNMPVendorBase set), so GetVendorOids is safe to
// call.
//
// False for a model whose agent serves EVERYTHING via standard MIBs and
// registers no 4526 vendor OIDs at all (verified: the GS728TPP -- a walk of
// 1.3.6.1.4.1.4526 answers noSuchObject). Such a model's PoE, box sensors
// and DHCP-mode reads use the standard-MIB code paths instead of the vendor
// columns.
func HasVendorOids(m *model.SwitchModel) bool {
	return m.SNMPVendorBase != ""
}

// GetVendorOids resolves the vendor OID table for m.
//
// It returns an error wrapping model.ErrUnsupportedCapability if m has no
// SNMP vendor OID subtree (SNMPVendorBase == ""); match with errors.Is.
func GetVendorOids(m *model.SwitchModel) (VendorOids, error) {
	if !HasVendorOids(m) {
		return VendorOids{}, fmt.Errorf("model %q has no SNMP vendor OID subtree: %w", m.Key, model.ErrUnsupportedCapability)
	}
	return vendorOidsFor(m.SNMPVendorBase), nil
}

// UnimplementedRoots returns the OID roots m's real SNMP agent does NOT
// register at all.
//
// Real Netgear firmware only instantiates a MIB module when the underlying
// hardware capability actually exists: the RFC 3621 PoE MIB
// (PethPsePortTable) -- and Netgear's own vendor PoE-power column -- is
// entirely ABSENT, not merely empty, on a non-PoE model such as the
// M4300-24X. Verified live: a GETNEXT/bulkwalk of the PoE MIB root on that
// switch answers a single noSuchObject, never silently falls through to
// whatever unrelated OID happens to sort next (see IsOIDImplemented). Every
// other MIB group this library reads (system/if/ifX/BRIDGE/Q-BRIDGE/IP/
// LLDP) is implemented by every currently-registered SNMP-backend model, so
// only the PoE-gated roots are tracked here; extend this if a future model
// is found to lack some other subtree entirely.
func UnimplementedRoots(m *model.SwitchModel) []string {
	if m.PoEPortCount > 0 {
		return []string{}
	}
	roots := []string{PethPsePortTable}
	if HasVendorOids(m) {
		roots = append(roots, vendorOidsFor(m.SNMPVendorBase).PoEPowerMw)
	}
	return roots
}

// IsOIDImplemented reports whether oid does NOT fall under a subtree root
// UnimplementedRoots says m's agent has no registration for at all.
//
// This is deliberately narrower than "does this OID have a value right
// now": a table that IS registered but simply has no rows yet (or an
// instance that's absent) is a completely different, honest case handled
// by the transport's normal noSuchInstance/endOfMibView responses. Only a
// whole MIB module the device never registers gets noSuchObject here.
func IsOIDImplemented(m *model.SwitchModel, oid string) bool {
	dotted := trimLeadingDots(oid)
	for _, root := range UnimplementedRoots(m) {
		if dotted == root || strings.HasPrefix(dotted, root+".") {
			return false
		}
	}
	return true
}

// trimLeadingDots strips every leading '.' from oid, mirroring Python's
// str.lstrip(".").
func trimLeadingDots(oid string) string {
	return strings.TrimLeft(oid, ".")
}
