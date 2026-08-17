package snmp_test

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// TestOIDConstants pins every §1.1 standard-MIB OID constant verbatim
// against src/netgear_switch/protocols/snmp/oids.py (the normative source).
func TestOIDConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"SysDescr", snmp.SysDescr, "1.3.6.1.2.1.1.1.0"},
		{"SysObjectID", snmp.SysObjectID, "1.3.6.1.2.1.1.2.0"},
		{"SysName", snmp.SysName, "1.3.6.1.2.1.1.5.0"},
		{"IfType", snmp.IfType, "1.3.6.1.2.1.2.2.1.3"},
		{"IfAdminStatus", snmp.IfAdminStatus, "1.3.6.1.2.1.2.2.1.7"},
		{"IfOperStatus", snmp.IfOperStatus, "1.3.6.1.2.1.2.2.1.8"},
		{"IfInErrors", snmp.IfInErrors, "1.3.6.1.2.1.2.2.1.14"},
		{"IfOutErrors", snmp.IfOutErrors, "1.3.6.1.2.1.2.2.1.20"},
		{"IfName", snmp.IfName, "1.3.6.1.2.1.31.1.1.1.1"},
		{"IfHCInOctets", snmp.IfHCInOctets, "1.3.6.1.2.1.31.1.1.1.6"},
		{"IfHCInUcast", snmp.IfHCInUcast, "1.3.6.1.2.1.31.1.1.1.7"},
		{"IfHCOutOctets", snmp.IfHCOutOctets, "1.3.6.1.2.1.31.1.1.1.10"},
		{"IfHCOutUcast", snmp.IfHCOutUcast, "1.3.6.1.2.1.31.1.1.1.11"},
		{"IfHighSpeed", snmp.IfHighSpeed, "1.3.6.1.2.1.31.1.1.1.15"},
		{"IfAlias", snmp.IfAlias, "1.3.6.1.2.1.31.1.1.1.18"},
		{"Dot3StatsDuplexStatus", snmp.Dot3StatsDuplexStatus, "1.3.6.1.2.1.10.7.2.1.19"},
		{"Dot3PauseAdminMode", snmp.Dot3PauseAdminMode, "1.3.6.1.2.1.10.7.10.1.1"},
		{"Dot3PauseOperMode", snmp.Dot3PauseOperMode, "1.3.6.1.2.1.10.7.10.1.2"},
		{"Dot1dBaseBridgeAddress", snmp.Dot1dBaseBridgeAddress, "1.3.6.1.2.1.17.1.1"},
		{"Dot1dBasePortIfIndex", snmp.Dot1dBasePortIfIndex, "1.3.6.1.2.1.17.1.4.1.2"},
		{"Dot1qTpFdbPort", snmp.Dot1qTpFdbPort, "1.3.6.1.2.1.17.7.1.2.2.1.2"},
		{"Dot1qVlanStaticName", snmp.Dot1qVlanStaticName, "1.3.6.1.2.1.17.7.1.4.3.1.1"},
		{"Dot1qVlanStaticEgress", snmp.Dot1qVlanStaticEgress, "1.3.6.1.2.1.17.7.1.4.3.1.2"},
		{"Dot1qVlanStaticUntagged", snmp.Dot1qVlanStaticUntagged, "1.3.6.1.2.1.17.7.1.4.3.1.4"},
		{"Dot1qPvid", snmp.Dot1qPvid, "1.3.6.1.2.1.17.7.1.4.5.1.1"},
		{"Dot1qVlanStaticRowStatus", snmp.Dot1qVlanStaticRowStatus, "1.3.6.1.2.1.17.7.1.4.3.1.5"},
		{"EntPhysicalDescr", snmp.EntPhysicalDescr, "1.3.6.1.2.1.47.1.1.1.1.2"},
		{"EntPhysicalClass", snmp.EntPhysicalClass, "1.3.6.1.2.1.47.1.1.1.1.5"},
		{"EntPhysicalName", snmp.EntPhysicalName, "1.3.6.1.2.1.47.1.1.1.1.7"},
		{"LldpRemTable", snmp.LldpRemTable, "1.0.8802.1.1.2.1.4.1"},
		{"PethPsePortTable", snmp.PethPsePortTable, "1.3.6.1.2.1.105.1.1.1"},
		{"PethPsePortAdmin", snmp.PethPsePortAdmin, "1.3.6.1.2.1.105.1.1.1.3"},
		{"PethPsePortDetect", snmp.PethPsePortDetect, "1.3.6.1.2.1.105.1.1.1.6"},
		{"IPAdEntAddr", snmp.IPAdEntAddr, "1.3.6.1.2.1.4.20.1.1"},
		{"IPAdEntIfIndex", snmp.IPAdEntIfIndex, "1.3.6.1.2.1.4.20.1.2"},
		{"IPAdEntNetmask", snmp.IPAdEntNetmask, "1.3.6.1.2.1.4.20.1.3"},
		{"IPAddressIfIndex", snmp.IPAddressIfIndex, "1.3.6.1.2.1.4.34.1.3"},
		{"IPRouteDest", snmp.IPRouteDest, "1.3.6.1.2.1.4.21.1.1"},
		{"IPRouteNextHop", snmp.IPRouteNextHop, "1.3.6.1.2.1.4.21.1.7"},
		{"DHCPModeOIDSuffix", snmp.DHCPModeOIDSuffix, "99.1"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
			}
		})
	}
}

// TestIntConstants pins the non-string OID-related constants.
func TestIntConstants(t *testing.T) {
	intCases := []struct {
		name string
		got  int
		want int
	}{
		{"RowStatusCreateAndGo", snmp.RowStatusCreateAndGo, 4},
		{"RowStatusDestroy", snmp.RowStatusDestroy, 6},
		{"EntClassPowerSupply", snmp.EntClassPowerSupply, 6},
		{"EntClassFan", snmp.EntClassFan, 7},
		{"EthernetCsmacd", snmp.EthernetCsmacd, 6},
	}
	for _, c := range intCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
			}
		})
	}
}

// TestBoxSensorColumns pins the doc/reference (kind, unit, suffix) table,
// verbatim from oids.py's BOX_SENSOR_COLUMNS. Not consumed at runtime by
// this package (readers construct the triple inline from VendorOids
// fields) -- this test only asserts the three kinds are covered, mirroring
// the Python test.
func TestBoxSensorColumns(t *testing.T) {
	want := [3]struct{ Kind, Unit, Suffix string }{
		{"fan", "RPM", "6.1.4"},
		{"power", "W", "8.1.5"},
		{"temperature", "C", "15.1.3"},
	}
	if snmp.BoxSensorColumns != want {
		t.Errorf("BoxSensorColumns = %+v, want %+v", snmp.BoxSensorColumns, want)
	}
}

// TestGetVendorOidsGSM7252PS pins every VendorOids formula for a
// fully-managed-family model (§1.4).
func TestGetVendorOidsGSM7252PS(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7252ps) error: %v", err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids(gsm7252ps) error: %v", err)
	}
	want := snmp.VendorOids{
		Base:                       "1.3.6.1.4.1.4526.10",
		PoEPowerMw:                 "1.3.6.1.4.1.4526.10.15.1.1.1.2",
		BoxFan:                     "1.3.6.1.4.1.4526.10.43.1.6.1.4",
		BoxPSUPower:                "1.3.6.1.4.1.4526.10.43.1.8.1.5",
		BoxTemp:                    "1.3.6.1.4.1.4526.10.43.1.15.1.3",
		DHCPModeUnverified:         "1.3.6.1.4.1.4526.10.99.1",
		SyslogAdminMode:            "1.3.6.1.4.1.4526.10.14.1.4.1.0",
		SyslogLocalPort:            "1.3.6.1.4.1.4526.10.14.1.4.3.0",
		SyslogHostAddr:             "1.3.6.1.4.1.4526.10.14.1.4.5.1.3",
		SyslogHostPort:             "1.3.6.1.4.1.4526.10.14.1.4.5.1.4",
		SyslogHostSeverity:         "1.3.6.1.4.1.4526.10.14.1.4.5.1.5",
		SyslogHostStatus:           "1.3.6.1.4.1.4526.10.14.1.4.5.1.7",
		MgmtWriteAddrUnverified:    "1.3.6.1.4.1.4526.10.98.1",
		MgmtWriteNetmaskUnverified: "1.3.6.1.4.1.4526.10.98.2",
		MgmtWriteGatewayUnverified: "1.3.6.1.4.1.4526.10.98.3",
	}
	if vo != want {
		t.Errorf("GetVendorOids(gsm7252ps) = %+v, want %+v", vo, want)
	}
}

// TestGetVendorOidsGSM7228PS pins the smart-managed-pro family base and its
// PoE-power OID (the one field the dossier explicitly test-pins).
func TestGetVendorOidsGSM7228PS(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7228ps) error: %v", err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids(gsm7228ps) error: %v", err)
	}
	if vo.Base != "1.3.6.1.4.1.4526.11" {
		t.Errorf("Base = %q, want %q", vo.Base, "1.3.6.1.4.1.4526.11")
	}
	if vo.PoEPowerMw != "1.3.6.1.4.1.4526.11.15.1.1.1.2" {
		t.Errorf("PoEPowerMw = %q, want %q", vo.PoEPowerMw, "1.3.6.1.4.1.4526.11.15.1.1.1.2")
	}
	// The syslog column layout under <base>.14 is shared by BOTH vendor
	// families (4526.10 FASTPATH and 4526.11 S3300) -- see VendorOids's
	// SyslogHostStatus doc comment.
	if vo.SyslogHostAddr != "1.3.6.1.4.1.4526.11.14.1.4.5.1.3" {
		t.Errorf("SyslogHostAddr = %q, want %q", vo.SyslogHostAddr, "1.3.6.1.4.1.4526.11.14.1.4.5.1.3")
	}
}

// TestGetVendorOidsGS110EMXError verifies GetVendorOids errors, wrapping
// model.ErrUnsupportedCapability, for a model with no SNMP vendor OID
// subtree (SNMPVendorBase == ""), mirroring Python's
// UnsupportedCapabilityError("model 'gs110emx' has no SNMP vendor OID subtree").
func TestGetVendorOidsGS110EMXError(t *testing.T) {
	m, err := model.GetModel("gs110emx")
	if err != nil {
		t.Fatalf("GetModel(gs110emx) error: %v", err)
	}
	_, err = snmp.GetVendorOids(m)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("errors.Is(err, ErrUnsupportedCapability) = false, want true (err=%v)", err)
	}
}

// TestHasVendorOids spot-checks the vendor/no-vendor gate across model
// families.
func TestHasVendorOids(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"m4300-24x", true},
		{"gsm7252ps", true},
		{"gsm7228ps", true},
		{"xs748t", true},
		{"gs110emx", false},
		{"gs305ep", false},
		{"gs728tpp", false}, // SNMP but standard-MIBs-only, verified live
		{"gs105pe", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.key, func(t *testing.T) {
			m, err := model.GetModel(c.key)
			if err != nil {
				t.Fatalf("GetModel(%s) error: %v", c.key, err)
			}
			if got := snmp.HasVendorOids(m); got != c.want {
				t.Errorf("HasVendorOids(%s) = %v, want %v", c.key, got, c.want)
			}
		})
	}
}

// TestUnimplementedRoots pins the §1.6 gating matrix: PoE model -> empty;
// zero-PoE+vendor -> [PoE root, vendor PoE-power OID]; zero-PoE no-vendor ->
// [PoE root].
func TestUnimplementedRoots(t *testing.T) {
	t.Run("PoE model returns empty", func(t *testing.T) {
		// m4300-16x: PoEPortCount = 16 > 0.
		m, err := model.GetModel("m4300-16x")
		if err != nil {
			t.Fatalf("GetModel(m4300-16x) error: %v", err)
		}
		got := snmp.UnimplementedRoots(m)
		if len(got) != 0 {
			t.Errorf("UnimplementedRoots(m4300-16x) = %v, want empty", got)
		}
	})

	t.Run("zero-PoE with vendor OIDs", func(t *testing.T) {
		// m4300-24x: PoEPortCount = 0, SNMPVendorBase = fully-managed family.
		m, err := model.GetModel("m4300-24x")
		if err != nil {
			t.Fatalf("GetModel(m4300-24x) error: %v", err)
		}
		got := snmp.UnimplementedRoots(m)
		want := []string{snmp.PethPsePortTable, "1.3.6.1.4.1.4526.10.15.1.1.1.2"}
		if len(got) != len(want) {
			t.Fatalf("UnimplementedRoots(m4300-24x) = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("UnimplementedRoots(m4300-24x)[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("zero-PoE no vendor OIDs", func(t *testing.T) {
		// gs110emx: PoEPortCount = 0, SNMPVendorBase = "".
		m, err := model.GetModel("gs110emx")
		if err != nil {
			t.Fatalf("GetModel(gs110emx) error: %v", err)
		}
		got := snmp.UnimplementedRoots(m)
		want := []string{snmp.PethPsePortTable}
		if len(got) != len(want) {
			t.Fatalf("UnimplementedRoots(gs110emx) = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("UnimplementedRoots(gs110emx)[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

// TestIsOIDImplemented pins the §1.7 subtree-matching logic: exact root
// match, dotted-descendant match, and unrelated OIDs staying implemented,
// including a model where the PoE root is fully implemented.
func TestIsOIDImplemented(t *testing.T) {
	m4300_24x, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("GetModel(m4300-24x) error: %v", err)
	}
	m4300_16x, err := model.GetModel("m4300-16x")
	if err != nil {
		t.Fatalf("GetModel(m4300-16x) error: %v", err)
	}

	cases := []struct {
		name  string
		m     *model.SwitchModel
		oid   string
		want  bool
		descr string
	}{
		{"exact root, zero-PoE", m4300_24x, snmp.PethPsePortTable, false, "PoE MIB root itself unimplemented"},
		{"descendant, zero-PoE", m4300_24x, snmp.PethPsePortTable + ".3.1.5", false, "instance under unimplemented root"},
		{"leading-dot descendant, zero-PoE", m4300_24x, "." + snmp.PethPsePortTable + ".3.1.5", false, "leading dot stripped like Python lstrip"},
		{"vendor PoE-power root, zero-PoE+vendor", m4300_24x, "1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", false, "vendor PoE-power OID also unimplemented"},
		{"unrelated OID, zero-PoE", m4300_24x, snmp.IfType, true, "unrelated MIB unaffected"},
		{"prefix-but-not-subtree lookalike", m4300_24x, snmp.PethPsePortTable + "0.3.1", true, "must not match a numeric lookalike sibling"},
		{"PoE model, PoE root implemented", m4300_16x, snmp.PethPsePortTable + ".3.1.5", true, "PoE-capable model has no unimplemented roots"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := snmp.IsOIDImplemented(c.m, c.oid); got != c.want {
				t.Errorf("IsOIDImplemented(%s, %q) = %v, want %v (%s)", c.m.Key, c.oid, got, c.want, c.descr)
			}
		})
	}
}
