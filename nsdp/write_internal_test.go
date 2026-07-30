package nsdp

// Whitebox test for rebootTLV, the one unexported write-builder (see
// write.go's doc comment: dead code preserved for Python parity, unit-tested
// at the encoder level only, mirroring
// tests/protocols/nsdp/test_write_frame.py::test_ipv4_and_dhcp_and_reboot_tlvs's
// reboot_tlv() assertions -- never wired to any exported writer API.

import "testing"

func TestRebootTLV(t *testing.T) {
	tlv := rebootTLV()
	if tlv.Tag != TagReboot {
		t.Errorf("Tag = %v, want TagReboot", tlv.Tag)
	}
	if len(tlv.Value) != 0 {
		t.Errorf("Value = %v, want empty", tlv.Value)
	}
}
