package snmp

import (
	"errors"
	"math"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// --- ParsePoe --------------------------------------------------------------

// TestParsePoeUsesCol3AdminCol6DetectAndVendorMw mirrors
// test_parse_poe_uses_col3_admin_col6_detect_and_vendor_mw: only columns 3
// (admin) and 6 (detect) of pethPsePortTable are honoured, joined to the
// vendor per-port mW walk by the final OID suffix component.
func TestParsePoeUsesCol3AdminCol6DetectAndVendorMw(t *testing.T) {
	tbl := PethPsePortTable
	status := []Row{
		NewIntRow(tbl+".3.1.1", 1), // admin enabled
		NewIntRow(tbl+".6.1.1", 3), // delivering
		NewIntRow(tbl+".3.1.2", 2), // admin disabled
		NewIntRow(tbl+".6.1.2", 1), // disabled
	}
	power := []Row{
		NewIntRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", 12800),
		NewIntRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.2", 0),
	}
	poe, err := ParsePoe(status, power)
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	if len(poe) != 2 {
		t.Fatalf("len(poe) = %d, want 2", len(poe))
	}
	if poe[0].Port != 1 || poe[1].Port != 2 {
		t.Fatalf("ports = [%d,%d], want [1,2]", poe[0].Port, poe[1].Port)
	}
	if !poe[0].AdminEnabled {
		t.Error("poe[0].AdminEnabled = false, want true")
	}
	if poe[0].Detect != model.PoEDetectDelivering {
		t.Errorf("poe[0].Detect = %v, want Delivering", poe[0].Detect)
	}
	if poe[0].PowerMw == nil || *poe[0].PowerMw != 12800 {
		t.Errorf("poe[0].PowerMw = %v, want 12800", poe[0].PowerMw)
	}
	if poe[1].AdminEnabled {
		t.Error("poe[1].AdminEnabled = true, want false")
	}
	if poe[1].Detect != model.PoEDetectDisabled {
		t.Errorf("poe[1].Detect = %v, want Disabled", poe[1].Detect)
	}
}

// TestParsePoeMissingDetectColumnRaises mirrors
// test_parse_poe_missing_detect_column_raises: a port present with only
// col3 (no col6) is drift, not absence, and errors.
func TestParsePoeMissingDetectColumnRaises(t *testing.T) {
	tbl := PethPsePortTable
	status := []Row{NewIntRow(tbl+".3.1.1", 1)} // no col6
	_, err := ParsePoe(status, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParsePoe error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestParsePoeMissingAdminColumnRaises mirrors
// test_parse_poe_missing_admin_column_raises: the col3/col6 analogue.
func TestParsePoeMissingAdminColumnRaises(t *testing.T) {
	tbl := PethPsePortTable
	status := []Row{NewIntRow(tbl+".6.1.1", 3)} // no col3
	_, err := ParsePoe(status, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParsePoe error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestParsePoeNonIntegerStatusValueRaises mirrors
// test_parse_poe_non_integer_status_value_raises: a present-but-malformed
// (wrong-type) status value is drift, not absence.
func TestParsePoeNonIntegerStatusValueRaises(t *testing.T) {
	tbl := PethPsePortTable
	status := []Row{NewStrRow(tbl+".3.1.1", "not_a_number")}
	_, err := ParsePoe(status, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParsePoe error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestParsePoeEmptyVendorPowerYieldsNone mirrors
// test_parse_poe_empty_vendor_power_yields_none: a model with no vendor mW
// column (gs728tpp) passes an empty power walk; every port then reports
// PowerMw nil, never a fabricated 0.
func TestParsePoeEmptyVendorPowerYieldsNone(t *testing.T) {
	tbl := PethPsePortTable
	status := []Row{
		NewIntRow(tbl+".3.1.1", 1),
		NewIntRow(tbl+".6.1.1", 2), // searching
	}
	poe, err := ParsePoe(status, nil)
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	if len(poe) != 1 {
		t.Fatalf("len(poe) = %d, want 1", len(poe))
	}
	if !poe[0].AdminEnabled {
		t.Error("AdminEnabled = false, want true")
	}
	if poe[0].Detect != model.PoEDetectSearching {
		t.Errorf("Detect = %v, want Searching", poe[0].Detect)
	}
	if poe[0].PowerMw != nil {
		t.Errorf("PowerMw = %v, want nil", poe[0].PowerMw)
	}
}

// TestParsePoeAcceptsStringTypedVendorMw mirrors a case implicit in the
// Python test suite that the strict-int64 port originally missed: the
// Python test test_parse_poe_uses_col3_admin_col6_detect_and_vendor_mw
// constructs its vendor mW rows as SnmpRow(oid, "12800", "Gauge32") --
// a STRING-typed numeric value, not a Python int -- and Python's
// int(row.value) coerces it transparently. ParsePoe's vendor-mW join must
// accept a numeric string exactly like ParseBoxSensors does (shared via
// parseSensorReading), not silently drop the reading by requiring int64.
func TestParsePoeAcceptsStringTypedVendorMw(t *testing.T) {
	tbl := PethPsePortTable
	status := []Row{
		NewIntRow(tbl+".3.1.1", 1),
		NewIntRow(tbl+".6.1.1", 3), // delivering
	}
	power := []Row{NewStrRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", "12800")}
	poe, err := ParsePoe(status, power)
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	if len(poe) != 1 {
		t.Fatalf("len(poe) = %d, want 1", len(poe))
	}
	if poe[0].PowerMw == nil || *poe[0].PowerMw != 12800 {
		t.Errorf("PowerMw = %v, want 12800", poe[0].PowerMw)
	}
}

// --- ParseBoxSensors ---------------------------------------------------

// TestParseBoxSensorsSkipsNotSupported mirrors
// test_parse_box_sensors_skips_not_supported: the literal "Not Supported"
// placeholder is skipped, not an error; readings arrive as STRING-typed
// numeric text (e.g. "3500"), which ParseBoxSensors must still accept.
func TestParseBoxSensorsSkipsNotSupported(t *testing.T) {
	fan := "1.3.6.1.4.1.4526.10.43.1.6.1.4"
	rows := []Row{
		NewStrRow(fan+".0", "3500"),
		NewStrRow(fan+".1", "Not Supported"),
		NewStrRow(fan+".2", "3450"),
	}
	sensors, err := ParseBoxSensors([]SensorColumn{{Kind: "fan", Unit: "RPM", Rows: rows}})
	if err != nil {
		t.Fatalf("ParseBoxSensors: %v", err)
	}
	if len(sensors) != 2 {
		t.Fatalf("len(sensors) = %d, want 2", len(sensors))
	}
	if sensors[0].Name != "fan0" || sensors[1].Name != "fan2" {
		t.Errorf("names = [%q, %q], want [fan0, fan2]", sensors[0].Name, sensors[1].Name)
	}
	if sensors[0].Kind != "fan" {
		t.Errorf("Kind = %q, want fan", sensors[0].Kind)
	}
	if sensors[0].Unit != "RPM" {
		t.Errorf("Unit = %q, want RPM", sensors[0].Unit)
	}
	if sensors[0].Value != 3500.0 {
		t.Errorf("Value = %v, want 3500.0", sensors[0].Value)
	}
}

// TestParseBoxSensorsAcceptsInt64Reading verifies the other half of the
// D-SNMP §3.16 dual-type contract not exercised by any Python test: a
// reading that arrives as a plain int64 (Gauge32/INTEGER wire value,
// rather than the STRING-typed decimal text covered above) must be
// accepted directly, without needing the strconv fallback.
func TestParseBoxSensorsAcceptsInt64Reading(t *testing.T) {
	psu := "1.3.6.1.4.1.4526.10.43.1.8.1.5"
	rows := []Row{NewIntRow(psu+".0", 42)}
	sensors, err := ParseBoxSensors([]SensorColumn{{Kind: "power", Unit: "W", Rows: rows}})
	if err != nil {
		t.Fatalf("ParseBoxSensors: %v", err)
	}
	if len(sensors) != 1 {
		t.Fatalf("len(sensors) = %d, want 1", len(sensors))
	}
	if sensors[0].Value != 42.0 {
		t.Errorf("Value = %v, want 42.0", sensors[0].Value)
	}
	if sensors[0].Name != "power0" {
		t.Errorf("Name = %q, want power0", sensors[0].Name)
	}
}

// TestParseBoxSensorsRaisesOnOtherNonInteger mirrors
// test_parse_box_sensors_raises_on_other_non_integer: a non-"Not Supported"
// non-numeric reading is present-but-malformed and errors.
func TestParseBoxSensorsRaisesOnOtherNonInteger(t *testing.T) {
	temp := "1.3.6.1.4.1.4526.10.43.1.15.1.3"
	rows := []Row{NewStrRow(temp+".1", "warm")}
	_, err := ParseBoxSensors([]SensorColumn{{Kind: "temperature", Unit: "C", Rows: rows}})
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseBoxSensors error = %v, want wrap of model.ErrSNMP", err)
	}
}

// --- ParseEntitySensors --------------------------------------------------

// TestParseEntitySensorsInventoryFromRealCapture mirrors
// test_parse_entity_sensors_inventory_from_real_capture: real gs728tpp
// ENTITY-MIB rows (10.2.5.10 capture) -- two PSUs (class 6) and two fans
// (class 7); chassis/module rows (other classes) are ignored, and names
// are canonicalized to the web UI's "PS" abbreviation.
func TestParseEntitySensorsInventoryFromRealCapture(t *testing.T) {
	cls, name, descr := EntPhysicalClass, EntPhysicalName, EntPhysicalDescr
	classRows := []Row{
		NewIntRow(cls+".67108992", 1), // "Netgear" chassis -> ignored
		NewIntRow(cls+".67109185", 6), // PSU
		NewIntRow(cls+".67109186", 6), // PSU
		NewIntRow(cls+".67109249", 7), // fan
		NewIntRow(cls+".67109250", 7), // fan
		NewIntRow(cls+".68420352", 3), // "GS728TPP" module -> ignored
	}
	nameRows := []Row{
		NewStrRow(name+".67109185", "Main PowerSupply"),
		NewStrRow(name+".67109186", "Redundant PowerSupply"),
		NewStrRow(name+".67109249", "Fan1"),
		NewStrRow(name+".67109250", "Fan2"),
	}
	descrRows := []Row{
		NewStrRow(descr+".67109185", "PowerSupply"),
		NewStrRow(descr+".67109249", "Fan"),
	}
	sensors, err := ParseEntitySensors(classRows, nameRows, descrRows)
	if err != nil {
		t.Fatalf("ParseEntitySensors: %v", err)
	}
	want := []struct{ Name, Kind, Unit string }{
		{"Main PS", "power", "inventory"},
		{"Redundant PS", "power", "inventory"},
		{"Fan1", "fan", "inventory"},
		{"Fan2", "fan", "inventory"},
	}
	if len(sensors) != len(want) {
		t.Fatalf("len(sensors) = %d, want %d", len(sensors), len(want))
	}
	for i, w := range want {
		if sensors[i].Name != w.Name || sensors[i].Kind != w.Kind || sensors[i].Unit != w.Unit {
			t.Errorf("sensors[%d] = %+v, want %+v", i, sensors[i], w)
		}
		// Inventory only -- SNMP supplies NO live reading for these
		// components. math.IsNaN, never ==, per D-SNMP §3.17.
		if !math.IsNaN(sensors[i].Value) {
			t.Errorf("sensors[%d].Value = %v, want NaN", i, sensors[i].Value)
		}
	}
}

// TestParseEntitySensorsFallsBackToDescrThenIndex mirrors
// test_parse_entity_sensors_falls_back_to_descr_then_index: with no
// entPhysicalName rows at all, name falls back to entPhysicalDescr, then to
// a synthetic "<kind><index>" when descr is absent too.
func TestParseEntitySensorsFallsBackToDescrThenIndex(t *testing.T) {
	cls, descr := EntPhysicalClass, EntPhysicalDescr
	classRows := []Row{
		NewIntRow(cls+".10", 7),
		NewIntRow(cls+".11", 6),
	}
	descrRows := []Row{NewStrRow(descr+".10", "Fan")}
	sensors, err := ParseEntitySensors(classRows, nil, descrRows)
	if err != nil {
		t.Fatalf("ParseEntitySensors: %v", err)
	}
	want := []struct{ Name, Kind string }{
		{"Fan", "fan"},
		{"power11", "power"},
	}
	if len(sensors) != len(want) {
		t.Fatalf("len(sensors) = %d, want %d", len(sensors), len(want))
	}
	for i, w := range want {
		if sensors[i].Name != w.Name || sensors[i].Kind != w.Kind {
			t.Errorf("sensors[%d] = %+v, want %+v", i, sensors[i], w)
		}
	}
}
