package capabilities

// support_nsdp_test.go: pins nsdpSupport against Python's _nsdp_support
// (capabilities.py:222-240) -- in particular that create_vlan/delete_vlan
// are SUPPORTED (the R1 dossier finding: nsdp/writer.go implements these for
// real over NSDP; there must be no refusal-dict entry for either).

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/nsdp"
)

func TestNSDPSupportRefusals(t *testing.T) {
	m := mustModelSnmp(t, "gs110emx") // any NSDP model; nsdpSupport ignores m today
	cases := []struct {
		op     string
		reason string
	}{
		{"get_macs", nsdp.NoMACsMsg},
		{"get_lldp", nsdp.NoLLDPMsg},
		{"get_sensors", nsdp.NoSensorsMsg},
		{"get_poe", nsdp.NoPoEReadMsg},
		{"set_poe", nsdp.NoPoEWriteMsg},
		{"cycle_poe", nsdp.NoPoEWriteMsg},
		{"clear_poe_fault", nsdp.NoPoEWriteMsg},
		{"set_port_enabled", nsdp.NoPortAdminMsg},
	}
	for _, c := range cases {
		op, err := OperationByName(c.op)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", c.op, err)
		}
		support, reason := nsdpSupport(m, op)
		if support != SupportUnsupported {
			t.Errorf("nsdpSupport(%s) = %v, want SupportUnsupported", c.op, support)
		}
		if reason != c.reason {
			t.Errorf("nsdpSupport(%s) reason = %q, want %q", c.op, reason, c.reason)
		}
	}
}

func TestNSDPSupportVlanLifecycleIsSupported(t *testing.T) {
	// R1: nsdp/writer.go's CreateVlan/DeleteVlan are real (verified-after-
	// write). The oracle must agree -- neither op appears in the refusal
	// dict, matching the pinned Python source exactly.
	m := mustModelSnmp(t, "gs110emx")
	for _, opName := range []string{"create_vlan", "delete_vlan"} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := nsdpSupport(m, op)
		if support != SupportSupported {
			t.Errorf("nsdpSupport(%s) = %v (%s), want SupportSupported", opName, support, reason)
		}
	}
}

func TestNSDPSupportOtherReadsAndWritesSupported(t *testing.T) {
	m := mustModelSnmp(t, "gs110emx")
	for _, opName := range []string{
		"get_ports", "get_stats", "get_vlans", "get_pvids", "get_mgmt_ip",
		"set_pvid", "set_vlan_membership", "set_mgmt_ip",
	} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := nsdpSupport(m, op)
		if support != SupportSupported {
			t.Errorf("nsdpSupport(%s) = %v (%s), want SupportSupported", opName, support, reason)
		}
	}
}
