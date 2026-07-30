package snmp

import (
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// dhcpModeOID mirrors test_parse_mgmt_ip.py's module-level _DHCP_MODE_OID:
// the DHCP-mode OID comes from the ONE named constant
// (VendorOids.DHCPModeUnverified), never a bare ".99.1" literal.
func dhcpModeOID(t *testing.T) string {
	t.Helper()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7252ps): %v", err)
	}
	vo, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	return vo.DHCPModeUnverified + ".0"
}

// --- ParseMgmtIP -------------------------------------------------------

// TestParseMgmtIPRFC4293FallbackWhenIPAddrTableEmpty mirrors
// test_parse_mgmt_ip_rfc4293_fallback_when_ipaddrtable_empty: the M4300
// leaves the RFC-1213 ipAddrTable EMPTY and publishes its mgmt address in
// the RFC-4293 ipAddressTable index instead
// (ipAddressIfIndex.<type>.<len>.<ip-bytes>). ParseMgmtIP must recover the
// IPv4 from that index.
func TestParseMgmtIPRFC4293FallbackWhenIPAddrTableEmpty(t *testing.T) {
	baseMac := []Row{
		NewBytesRow(Dot1dBaseBridgeAddress+".0", []byte{0x8C, 0x3B, 0xAD, 0x69, 0x1C, 0x38}),
	}
	rfc4293 := []Row{
		// loopback (must be skipped) + an IPv6 row (type 2, must be
		// skipped) + the real IPv4 mgmt address.
		NewIntRow(IPAddressIfIndex+".1.4.127.0.0.1", 1),
		NewIntRow(IPAddressIfIndex+".2.16.36.4.14.128.161.55.1.5.0.0.0.0.0.0.0.32", 898),
		NewIntRow(IPAddressIfIndex+".1.4.10.1.5.20", 898),
	}
	cfg, err := ParseMgmtIP(nil, nil, nil, nil, nil, baseMac, rfc4293)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if deref(cfg.Address) != "10.1.5.20" {
		t.Errorf("Address = %q, want %q", deref(cfg.Address), "10.1.5.20")
	}
	if deref(cfg.BaseMac) != "8C:3B:AD:69:1C:38" {
		t.Errorf("BaseMac = %q, want %q", deref(cfg.BaseMac), "8C:3B:AD:69:1C:38")
	}
}

// TestParseMgmtIPRFC1213WinsOverRFC4293 mirrors
// test_parse_mgmt_ip_rfc1213_wins_over_rfc4293: when the classic
// ipAddrTable IS populated it is authoritative; the RFC-4293 walk is only
// a fallback and must not override it.
func TestParseMgmtIPRFC1213WinsOverRFC4293(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.9.9.9", "10.9.9.9")}
	rfc4293 := []Row{NewIntRow(IPAddressIfIndex+".1.4.10.1.5.20", 1)}
	cfg, err := ParseMgmtIP(addr, nil, nil, nil, nil, nil, rfc4293)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if deref(cfg.Address) != "10.9.9.9" {
		t.Errorf("Address = %q, want %q", deref(cfg.Address), "10.9.9.9")
	}
}

// TestParseMgmtIPStaticWithGateway mirrors
// test_parse_mgmt_ip_static_with_gateway.
func TestParseMgmtIPStaticWithGateway(t *testing.T) {
	addr := []Row{
		NewStrRow("1.3.6.1.2.1.4.20.1.1.127.0.0.1", "127.0.0.1"),
		NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20"),
	}
	netmask := []Row{
		NewStrRow("1.3.6.1.2.1.4.20.1.3.10.1.5.20", "255.255.255.0"),
	}
	routeDest := []Row{NewStrRow("1.3.6.1.2.1.4.21.1.1.0.0.0.0", "0.0.0.0")}
	routeNext := []Row{NewStrRow("1.3.6.1.2.1.4.21.1.7.0.0.0.0", "10.1.5.1")}
	dhcp := []Row{NewIntRow(dhcpModeOID(t), 2)} // static
	baseMac := []Row{
		NewBytesRow(Dot1dBaseBridgeAddress+".0", []byte{0x28, 0xC6, 0x8E, 0x00, 0x00, 0x01}),
	}

	cfg, err := ParseMgmtIP(addr, netmask, routeDest, routeNext, dhcp, baseMac, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if deref(cfg.Address) != "10.1.5.20" {
		t.Errorf("Address = %q, want %q", deref(cfg.Address), "10.1.5.20")
	}
	if deref(cfg.Netmask) != "255.255.255.0" {
		t.Errorf("Netmask = %q, want %q", deref(cfg.Netmask), "255.255.255.0")
	}
	if deref(cfg.Gateway) != "10.1.5.1" {
		t.Errorf("Gateway = %q, want %q", deref(cfg.Gateway), "10.1.5.1")
	}
	if cfg.Mode != model.IPModeStatic {
		t.Errorf("Mode = %v, want Static", cfg.Mode)
	}
	if deref(cfg.BaseMac) != "28:C6:8E:00:00:01" {
		t.Errorf("BaseMac = %q, want %q", deref(cfg.BaseMac), "28:C6:8E:00:00:01")
	}
}

// TestParseMgmtIPDHCPAndUnknownDefault mirrors
// test_parse_mgmt_ip_dhcp_and_unknown_default.
func TestParseMgmtIPDHCPAndUnknownDefault(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	cfg, err := ParseMgmtIP(addr, nil, nil, nil, []Row{NewIntRow(dhcpModeOID(t), 1)}, nil, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if cfg.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want DHCP", cfg.Mode)
	}

	// Mode OID absent -> UNKNOWN (never a guessed dhcp/static), gateway nil.
	cfg2, err := ParseMgmtIP(addr, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if cfg2.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want Unknown", cfg2.Mode)
	}
	if cfg2.Gateway != nil {
		t.Errorf("Gateway = %v, want nil", cfg2.Gateway)
	}
	// base_mac walk absent entirely -> honest nil, never fabricated.
	if cfg2.BaseMac != nil {
		t.Errorf("BaseMac = %v, want nil", cfg2.BaseMac)
	}
}

// TestParseMgmtIPUnrecognizedDHCPModeValueIsUnknown mirrors
// test_parse_mgmt_ip_unrecognized_dhcp_mode_value_is_unknown.
func TestParseMgmtIPUnrecognizedDHCPModeValueIsUnknown(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	dhcp := []Row{NewIntRow(dhcpModeOID(t), 3)} // unrecognized value
	cfg, err := ParseMgmtIP(addr, nil, nil, nil, dhcp, nil, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if cfg.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want Unknown", cfg.Mode)
	}
}

// TestParseMgmtIPNonIntCoercibleDHCPModeValueIsUnknown mirrors
// test_parse_mgmt_ip_non_int_coercible_dhcp_mode_value_is_unknown: this OID
// is explicitly UNVERIFIED/best-effort -- a genuinely non-int-coercible
// value must degrade to UNKNOWN, never raise.
func TestParseMgmtIPNonIntCoercibleDHCPModeValueIsUnknown(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	dhcp := []Row{NewBytesRow(dhcpModeOID(t), []byte{0xc0, 0x00})}
	cfg, err := ParseMgmtIP(addr, nil, nil, nil, dhcp, nil, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if cfg.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want Unknown", cfg.Mode)
	}
}

// TestParseMgmtIPDHCPModeStringValueCoerces is not a mirrored Python test
// (every real transport normalizes an INTEGER-typed OID to an int64 --
// see Row's docstring -- so a genuinely string-typed dhcp-mode value
// never occurs in practice), but it pins the general Python
// int(row.value) coercion the docstring promises: a numeric STRING value
// still resolves to DHCP/STATIC, exercising toIntBestEffort's string
// branch.
func TestParseMgmtIPDHCPModeStringValueCoerces(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	dhcp := []Row{NewStrRow(dhcpModeOID(t), "1")}
	cfg, err := ParseMgmtIP(addr, nil, nil, nil, dhcp, nil, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if cfg.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want DHCP", cfg.Mode)
	}
}

// TestParseMgmtIPMalformedAddressRaisesSNMPError mirrors
// test_parse_mgmt_ip_malformed_address_raises_snmp_error: present-but-
// malformed (non-str where an IpAddress is required) is drift, not
// absence, and must error naming the offending OID.
func TestParseMgmtIPMalformedAddressRaisesSNMPError(t *testing.T) {
	const oid = "1.3.6.1.2.1.4.20.1.1.10.1.5.20"
	addr := []Row{NewIntRow(oid, 12345)}
	_, err := ParseMgmtIP(addr, nil, nil, nil, nil, nil, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMgmtIP error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error %q does not mention OID %q", err.Error(), oid)
	}
}

// TestParseMgmtIPMalformedNetmaskRaisesSNMPError mirrors
// test_parse_mgmt_ip_malformed_netmask_raises_snmp_error.
func TestParseMgmtIPMalformedNetmaskRaisesSNMPError(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	const oid = "1.3.6.1.2.1.4.20.1.3.10.1.5.20"
	netmask := []Row{NewIntRow(oid, 255)}
	_, err := ParseMgmtIP(addr, netmask, nil, nil, nil, nil, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMgmtIP error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error %q does not mention OID %q", err.Error(), oid)
	}
}

// TestParseMgmtIPMalformedGatewayRaisesSNMPError mirrors
// test_parse_mgmt_ip_malformed_gateway_raises_snmp_error.
func TestParseMgmtIPMalformedGatewayRaisesSNMPError(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	routeDest := []Row{NewStrRow("1.3.6.1.2.1.4.21.1.1.0.0.0.0", "0.0.0.0")}
	const oid = "1.3.6.1.2.1.4.21.1.7.0.0.0.0"
	routeNext := []Row{NewIntRow(oid, 12345)}
	_, err := ParseMgmtIP(addr, nil, routeDest, routeNext, nil, nil, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMgmtIP error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error %q does not mention OID %q", err.Error(), oid)
	}
}

// TestParseMgmtIPMalformedBaseMacRaisesSNMPError mirrors
// test_parse_mgmt_ip_malformed_base_mac_raises_snmp_error: ParseMgmtIP
// propagates ParseBaseMac's own error.
func TestParseMgmtIPMalformedBaseMacRaisesSNMPError(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20")}
	baseMac := []Row{NewStrRow(Dot1dBaseBridgeAddress+".0", "not-six-bytes")}
	_, err := ParseMgmtIP(addr, nil, nil, nil, nil, baseMac, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMgmtIP error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), Dot1dBaseBridgeAddress+".0") {
		t.Errorf("error %q does not mention OID %q", err.Error(), Dot1dBaseBridgeAddress+".0")
	}
}

// TestParseMgmtIPBaseMacFromASCIIColonHexString mirrors
// test_parse_mgmt_ip_base_mac_from_ascii_colon_hex_string: the M4300-24X
// (verified live) returns dot1dBaseBridgeAddress as a 17-char ASCII
// string rather than 6 raw bytes; ParseMgmtIP must parse it via
// ParseBaseMac's quirk handling, not raise "malformed".
func TestParseMgmtIPBaseMacFromASCIIColonHexString(t *testing.T) {
	addr := []Row{NewStrRow("1.3.6.1.2.1.4.20.1.1.10.1.5.13", "10.1.5.13")}
	baseMac := []Row{NewStrRow(Dot1dBaseBridgeAddress+".0", "8c:3b:ad:6b:bb:e0")}
	cfg, err := ParseMgmtIP(addr, nil, nil, nil, nil, baseMac, nil)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if deref(cfg.BaseMac) != "8C:3B:AD:6B:BB:E0" {
		t.Errorf("BaseMac = %q, want %q", deref(cfg.BaseMac), "8C:3B:AD:6B:BB:E0")
	}
}

// --- ParseSystemInfo -----------------------------------------------------

// TestParseSystemInfoExtractsBothScalars mirrors
// test_parse_system_info_extracts_both_scalars.
func TestParseSystemInfoExtractsBothScalars(t *testing.T) {
	rows := []Row{
		NewStrRow(SysDescr, "NETGEAR GSM7252PS"),
		NewStrRow(SysObjectID, "1.3.6.1.4.1.4526.10.100.14"),
	}
	descr, objectID, err := ParseSystemInfo(rows)
	if err != nil {
		t.Fatalf("ParseSystemInfo: %v", err)
	}
	if deref(descr) != "NETGEAR GSM7252PS" {
		t.Errorf("descr = %q, want %q", deref(descr), "NETGEAR GSM7252PS")
	}
	if deref(objectID) != "1.3.6.1.4.1.4526.10.100.14" {
		t.Errorf("objectID = %q, want %q", deref(objectID), "1.3.6.1.4.1.4526.10.100.14")
	}
}

// TestParseSystemInfoAbsentScalarsAreHonestlyNil mirrors
// test_parse_system_info_absent_scalars_are_honestly_none.
func TestParseSystemInfoAbsentScalarsAreHonestlyNil(t *testing.T) {
	descr, objectID, err := ParseSystemInfo(nil)
	if err != nil {
		t.Fatalf("ParseSystemInfo: %v", err)
	}
	if descr != nil {
		t.Errorf("descr = %v, want nil", descr)
	}
	if objectID != nil {
		t.Errorf("objectID = %v, want nil", objectID)
	}
}

// TestParseSystemInfoDecodesBytesOctetstring mirrors
// test_parse_system_info_decodes_bytes_octetstring.
func TestParseSystemInfoDecodesBytesOctetstring(t *testing.T) {
	rows := []Row{NewBytesRow(SysDescr, []byte("NETGEAR M4300-24X"))}
	descr, objectID, err := ParseSystemInfo(rows)
	if err != nil {
		t.Fatalf("ParseSystemInfo: %v", err)
	}
	if deref(descr) != "NETGEAR M4300-24X" {
		t.Errorf("descr = %q, want %q", deref(descr), "NETGEAR M4300-24X")
	}
	if objectID != nil {
		t.Errorf("objectID = %v, want nil", objectID)
	}
}

// TestParseSystemInfoMalformedValueRaisesSNMPError mirrors
// test_parse_system_info_malformed_value_raises_snmp_error: present-but-
// wrong-type (e.g. an int where text is required) is drift, not absence,
// and must error naming the offending OID.
func TestParseSystemInfoMalformedValueRaisesSNMPError(t *testing.T) {
	rows := []Row{NewIntRow(SysDescr, 12345)}
	_, _, err := ParseSystemInfo(rows)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseSystemInfo error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), SysDescr) {
		t.Errorf("error %q does not mention OID %q", err.Error(), SysDescr)
	}
}

// TestParseSystemInfoIgnoresUnrelatedRows mirrors
// test_parse_system_info_ignores_unrelated_rows.
func TestParseSystemInfoIgnoresUnrelatedRows(t *testing.T) {
	rows := []Row{
		NewStrRow("1.3.6.1.2.1.1.5.0", "some-hostname"), // sysName, unrelated
		NewStrRow(SysObjectID, "1.3.6.1.4.1.4526.11.100.1"),
	}
	descr, objectID, err := ParseSystemInfo(rows)
	if err != nil {
		t.Fatalf("ParseSystemInfo: %v", err)
	}
	if descr != nil {
		t.Errorf("descr = %v, want nil", descr)
	}
	if deref(objectID) != "1.3.6.1.4.1.4526.11.100.1" {
		t.Errorf("objectID = %q, want %q", deref(objectID), "1.3.6.1.4.1.4526.11.100.1")
	}
}

// --- DetectModelFromSysDescr: full sysDescr table (D-SNMP §3.26) ---------

// TestDetectModelFromSysDescrFullTable ports the full sysDescr test table
// from D-SNMP §3.26 / test_parse_system_info.py verbatim (except the
// synthetic-colliding-fake-models row, which needs its own non-registry
// models argument -- see TestDetectModelFromSysDescrAmbiguousMatchIsNone
// below).
func TestDetectModelFromSysDescrFullTable(t *testing.T) {
	models := model.Models()
	cases := []struct {
		name     string
		sysDescr *string
		want     *string
	}{
		{"m4300-24x realistic", model.Ptr("NETGEAR M4300-24X, Software 12.0.11.9, Linux 3.6.5"), model.Ptr("m4300-24x")},
		{"m4300-16x realistic", model.Ptr("NETGEAR M4300-16X, Software 12.0.11.9"), model.Ptr("m4300-16x")},
		{"gsm7252ps realistic", model.Ptr("NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6"), model.Ptr("gsm7252ps")},
		{"gsm7228ps realistic", model.Ptr("NETGEAR GSM7228PS Managed Switch, firmware 6.4.2.9"), model.Ptr("gsm7228ps")},
		{"gs110emx realistic", model.Ptr("NETGEAR GS110EMX"), model.Ptr("gs110emx")},
		{"gs305ep realistic", model.Ptr("NETGEAR GS305EP"), model.Ptr("gs305ep")},
		{"m7300 realistic", model.Ptr("NETGEAR M7300-24XF, Software 12.0.4.5"), model.Ptr("m7300")},
		{"xs748t realistic", model.Ptr("NETGEAR XS748T Managed Switch"), model.Ptr("xs748t")},
		{"gs728tpp realistic", model.Ptr("NETGEAR GS728TPP Managed Switch, firmware 6.4.2.9"), model.Ptr("gs728tpp")},
		{"case-insensitive gsm7252ps", model.Ptr("netgear gsm7252ps switch"), model.Ptr("gsm7252ps")},
		{"case-insensitive m4300-24x", model.Ptr("Netgear M4300-24X"), model.Ptr("m4300-24x")},
		{"s3300 alias for gsm7228ps", model.Ptr("NETGEAR S3300 Managed Switch, firmware 6.4.2.9"), model.Ptr("gsm7228ps")},
		{"xsm alias for m4300-24x", model.Ptr("NETGEAR XSM4324CS"), model.Ptr("m4300-24x")},
		{"unregistered gs752tp", model.Ptr("NETGEAR GS752TP switch"), nil},
		{"unregistered m7300-28g extension", model.Ptr("NETGEAR M7300-28G"), nil},
		{"bare m7300 token", model.Ptr("NETGEAR M7300 switch"), model.Ptr("m7300")},
		{"non-netgear garbage", model.Ptr("Cisco IOS Software, C2960"), nil},
		{"empty string", model.Ptr(""), nil},
		{"nil sysDescr", nil, nil},
		{"gs305epp rejected (extends gs305ep)", model.Ptr("NETGEAR GS305EPP Managed Switch"), nil},
		{"s3300-28x rejected (extends s3300 alias)", model.Ptr("NETGEAR S3300-28X"), nil},
		{"s3300-28x-poe+ rejected (extends s3300 alias)", model.Ptr("NETGEAR S3300-28X-PoE+ Managed Switch"), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DetectModelFromSysDescr(c.sysDescr, models)
			if (got == nil) != (c.want == nil) {
				t.Fatalf("DetectModelFromSysDescr(%s) = %v, want %v", deref(c.sysDescr), deref(got), deref(c.want))
			}
			if got != nil && *got != *c.want {
				t.Errorf("DetectModelFromSysDescr(%s) = %q, want %q", deref(c.sysDescr), *got, *c.want)
			}
		})
	}
}

// TestDetectModelFromSysDescrAmbiguousMatchIsNone mirrors
// test_detect_model_from_sysdescr_ambiguous_match_is_none: defence-in-
// depth -- if a sysDescr text happened to contain TWO different
// registered models' tokens, this must return nil (never pick one
// arbitrarily), proven with a deliberately-constructed pair of tiny fake
// models whose tokens both appear in one string, since the real registry
// currently has no such collision.
func TestDetectModelFromSysDescrAmbiguousMatchIsNone(t *testing.T) {
	fakeModels := []*model.SwitchModel{
		{Key: "fake-a", DisplayName: "FAKEA"},
		{Key: "fake-b", DisplayName: "FAKEB"},
	}
	got := DetectModelFromSysDescr(model.Ptr("NETGEAR FAKEA FAKEB switch"), fakeModels)
	if got != nil {
		t.Errorf("DetectModelFromSysDescr(ambiguous) = %q, want nil", *got)
	}
}

// TestDetectModelFromSysDescrStillCannotIdentifyRealS3300_52X mirrors
// test_detect_model_from_sysdescr_still_cannot_identify_real_s3300_52x:
// the whole reason the sysObjectID map exists -- the real firmware
// sysDescr is UNmatchable by text (same shape as the unregistered
// S3300-28X SKU).
func TestDetectModelFromSysDescrStillCannotIdentifyRealS3300_52X(t *testing.T) {
	models := model.Models()
	sysDescr := "S3300-52X-PoE+ ProSAFE 48-Port Gigabit Stackable Smart Switch with PoE+ and 4 10G uplinks"
	got := DetectModelFromSysDescr(&sysDescr, models)
	if got != nil {
		t.Errorf("DetectModelFromSysDescr(real S3300-52X sysDescr) = %q, want nil", *got)
	}
}

// --- DetectModelFromSysObjectID: authoritative sysObjectID matching -------

// TestDetectModelFromSysObjectIDMatchesRealS3300_52X mirrors
// test_detect_model_from_sysobjectid_matches_real_s3300_52x: ground
// truth -- the real S3300-52X-PoE+ (registered as gsm7228ps) reports
// sysObjectID 1.3.6.1.4.1.4526.100.10.19 (live capture 2026-07-30).
// sysDescr matching CANNOT identify it, so the sysObjectID map is the
// ONLY safe, authoritative detector.
func TestDetectModelFromSysObjectIDMatchesRealS3300_52X(t *testing.T) {
	models := model.Models()
	oid := "1.3.6.1.4.1.4526.100.10.19"
	got := DetectModelFromSysObjectID(&oid, models)
	if got == nil {
		t.Fatal("DetectModelFromSysObjectID = nil, want gsm7228ps")
	}
	if *got != "gsm7228ps" {
		t.Errorf("DetectModelFromSysObjectID = %q, want gsm7228ps", *got)
	}
}

// TestDetectModelFromSysObjectIDUnmappedOrAbsentIsNone mirrors
// test_detect_model_from_sysobjectid_unmapped_or_absent_is_none: an OID
// with no real-capture-confirmed mapping is honestly nil, never a guess
// -- and so are absent/empty inputs.
func TestDetectModelFromSysObjectIDUnmappedOrAbsentIsNone(t *testing.T) {
	models := model.Models()
	cases := []struct {
		name string
		oid  *string
	}{
		{"unmapped OID", model.Ptr("1.3.6.1.4.1.9.1.1")},
		{"registered-but-unmapped sysObjectID", model.Ptr("1.3.6.1.4.1.4526.10.100.14")},
		{"nil sysObjectID", nil},
		{"empty sysObjectID", model.Ptr("")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectModelFromSysObjectID(c.oid, models); got != nil {
				t.Errorf("DetectModelFromSysObjectID(%s) = %q, want nil", deref(c.oid), *got)
			}
		})
	}
}

// TestDetectModelFromSysObjectIDOnlyReturnsModelsActuallyPresent mirrors
// test_detect_model_from_sysobjectid_only_returns_models_actually_present:
// honesty -- even a mapped OID resolves ONLY when the target key is
// present in the passed models slice (never conjures a model out of the
// map).
func TestDetectModelFromSysObjectIDOnlyReturnsModelsActuallyPresent(t *testing.T) {
	oid := "1.3.6.1.4.1.4526.100.10.19"
	if got := DetectModelFromSysObjectID(&oid, nil); got != nil {
		t.Errorf("DetectModelFromSysObjectID(no models) = %q, want nil", *got)
	}
}

// --- _WORD_STRIP_CHARS parity ---------------------------------------------

// TestWordStripCharsMatchPythonPunctuationMinusHyphen pins wordStripChars
// against the literal value of Python's
// string.punctuation.replace("-", "") (computed once via
// `python3 -c "import string; print(string.punctuation.replace('-', ”))"`
// and confirmed to be 31 characters): !"#$%&'()*+,./:;<=>?@[\]^_`{|}~
func TestWordStripCharsMatchPythonPunctuationMinusHyphen(t *testing.T) {
	const pythonValue = "!\"#$%&'()*+,./:;<=>?@[\\]^_`{|}~"
	if wordStripChars != pythonValue {
		t.Errorf("wordStripChars = %q (len %d), want %q (len %d)",
			wordStripChars, len(wordStripChars), pythonValue, len(pythonValue))
	}
}
