package snmp

// Tests for the gosnmp transport (GoSNMPClient). Most tests drive a
// minimal, test-local fake SNMP agent (fakeAgent below) over real UDP,
// built from gosnmp's own exported wire codec (GoSNMP.SnmpDecodePacket to
// parse incoming requests, SnmpPacket.MarshalMsg to build responses) --
// this is real wire traffic through the real gosnmp client code, just
// answered by a canned table instead of a live switch. It deliberately
// prefigures the shape of Task 12's virtual-switch face without trying to
// be that face: no MIB tree, no persistence, just enough GET/GETBULK/SET
// handling to exercise this file's contract.

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/mithro/go-netgear-switch-library/model"
)

// -- fake UDP SNMP agent -----------------------------------------------------

// fakeAgent is a minimal SNMP v2c responder for one test. Configure its
// exported-ish fields, call start(t), then point a GoSNMPClient at
// addr(). All fields are set by the test goroutine before start() spawns
// serve() (a `go` statement is itself a happens-before edge), so serve()
// needs no locking to read them; the only state serve() writes after
// start is delivered back to the test over setCh, a channel (also a
// proper happens-before edge).
type fakeAgent struct {
	// rows is the canned data table, served two ways: Get answers an
	// exact Name match from it; GetBulk answers with the run of entries
	// immediately following the requested OID (GETNEXT/GETBULK
	// semantics), sorted numerically by start().
	rows []gosnmp.SnmpPDU

	// errorOnPrefix, if non-empty, makes a GetBulk request whose sole
	// requested OID starts with this prefix fail with walkErrStatus
	// instead of returning data -- simulates a mid-walk device error.
	errorOnPrefix string
	walkErrStatus gosnmp.SNMPError

	// getErrStatus, if not NoError, makes every Get request fail with
	// this error-status.
	getErrStatus gosnmp.SNMPError

	// setErrStatus/setErrIndex, if setErrStatus != NoError, make every
	// Set request fail with that error-status/index instead of
	// succeeding.
	setErrStatus gosnmp.SNMPError
	setErrIndex  uint8

	// blackhole, if true, reads and silently drops every request --
	// never responds. Used to test ctx deadline handling.
	blackhole bool

	conn  *net.UDPConn
	setCh chan []gosnmp.SnmpPDU
}

// start binds a UDP socket and begins serving in the background,
// registering cleanup with t. Call only after every field above is set.
func (a *fakeAgent) start(t *testing.T) {
	t.Helper()
	sorted := append([]gosnmp.SnmpPDU(nil), a.rows...)
	sort.Slice(sorted, func(i, j int) bool { return cmpOID(sorted[i].Name, sorted[j].Name) < 0 })
	a.rows = sorted

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("fakeAgent: listen udp: %v", err)
	}
	a.conn = conn
	a.setCh = make(chan []gosnmp.SnmpPDU, 8)
	t.Cleanup(func() { _ = conn.Close() })
	go a.serve()
}

// addr returns "host:port" for NewGoSNMPClient.
func (a *fakeAgent) addr() string { return a.conn.LocalAddr().String() }

func (a *fakeAgent) serve() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (test cleanup): stop serving
		}
		if a.blackhole {
			continue
		}
		decoder := &gosnmp.GoSNMP{}
		reqPkt, err := decoder.SnmpDecodePacket(buf[:n])
		if err != nil {
			continue
		}
		resp := a.respond(reqPkt)
		out, err := resp.MarshalMsg()
		if err != nil {
			continue
		}
		_, _ = a.conn.WriteToUDP(out, raddr)
	}
}

func (a *fakeAgent) respond(req *gosnmp.SnmpPacket) *gosnmp.SnmpPacket {
	resp := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: req.Community,
		PDUType:   gosnmp.GetResponse,
		RequestID: req.RequestID,
	}
	switch req.PDUType {
	case gosnmp.GetRequest:
		resp.Variables = a.handleGet(req.Variables)
		if a.getErrStatus != gosnmp.NoError {
			resp.Error = a.getErrStatus
			resp.ErrorIndex = 1
		}
	case gosnmp.GetBulkRequest:
		if a.errorOnPrefix != "" && len(req.Variables) > 0 &&
			strings.HasPrefix(strings.TrimLeft(req.Variables[0].Name, "."), a.errorOnPrefix) {
			resp.Error = a.walkErrStatus
			resp.ErrorIndex = 1
			resp.Variables = []gosnmp.SnmpPDU{{Name: req.Variables[0].Name, Type: gosnmp.Null, Value: nil}}
			break
		}
		resp.Variables = a.handleBulk(req.Variables)
	case gosnmp.SetRequest:
		cp := append([]gosnmp.SnmpPDU(nil), req.Variables...)
		a.setCh <- cp
		resp.Variables = req.Variables
		if a.setErrStatus != gosnmp.NoError {
			resp.Error = a.setErrStatus
			resp.ErrorIndex = a.setErrIndex
		}
	}
	return resp
}

func (a *fakeAgent) handleGet(reqVars []gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	out := make([]gosnmp.SnmpPDU, len(reqVars))
	for i, rv := range reqVars {
		name := strings.TrimLeft(rv.Name, ".")
		out[i] = gosnmp.SnmpPDU{Name: rv.Name, Type: gosnmp.NoSuchObject, Value: nil}
		for _, row := range a.rows {
			if strings.TrimLeft(row.Name, ".") == name {
				out[i] = row
				break
			}
		}
	}
	return out
}

// handleBulk answers a single-OID GETBULK request with the run of rows
// strictly after the requested OID, up to maxRepetitions, or a single
// EndOfMibView PDU if none remain. This is deliberately naive (no
// non-repeaters support, a.rows must be pre-sorted) -- sufficient for a
// test fixture, not a MIB engine.
func (a *fakeAgent) handleBulk(reqVars []gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	if len(reqVars) == 0 {
		return nil
	}
	current := reqVars[0].Name
	idx := -1
	for i, row := range a.rows {
		if cmpOID(row.Name, current) > 0 {
			idx = i
			break
		}
	}
	if idx == -1 {
		return []gosnmp.SnmpPDU{{Name: current, Type: gosnmp.EndOfMibView, Value: nil}}
	}
	end := idx + bulkMaxRepetitions
	if end > len(a.rows) {
		end = len(a.rows)
	}
	out := make([]gosnmp.SnmpPDU, end-idx)
	copy(out, a.rows[idx:end])
	return out
}

// cmpOID compares two dotted numeric OID strings component-wise as
// integers (matching gosnmp's own internal oidCompare, which this
// duplicates: that function is unexported, and re-implementing it here
// is simpler than trying to reach it from a different package). A
// naive string compare would misorder e.g. ".7.10" before ".7.9".
func cmpOID(a, b string) int {
	pa, pb := oidParts(a), oidParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	default:
		return 0
	}
}

func oidParts(oid string) []int {
	oid = strings.TrimLeft(oid, ".")
	if oid == "" {
		return nil
	}
	fields := strings.Split(oid, ".")
	out := make([]int, len(fields))
	for i, f := range fields {
		n := 0
		for _, c := range f {
			if c < '0' || c > '9' {
				continue
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

// -- NewGoSNMPClient / options -----------------------------------------------

func TestNewGoSNMPClient_HostPort(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		wantHost string
		wantPort uint16
	}{
		{"bare host", "switch.example.com", "switch.example.com", 161},
		{"bare IP", "10.1.5.20", "10.1.5.20", 161},
		{"host with port", "switch.example.com:1161", "switch.example.com", 1161},
		{"IP with port", "10.1.5.20:161", "10.1.5.20", 161},
		{"non-numeric port falls back to default", "switch.example.com:snmp", "switch.example.com", 161},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewGoSNMPClient(tt.host, "public")
			if c.host != tt.wantHost {
				t.Errorf("host = %q, want %q", c.host, tt.wantHost)
			}
			if c.port != tt.wantPort {
				t.Errorf("port = %d, want %d", c.port, tt.wantPort)
			}
		})
	}
}

func TestNewGoSNMPClient_Defaults(t *testing.T) {
	c := NewGoSNMPClient("switch.example.com", "public")
	if c.community != "public" {
		t.Errorf("community = %q, want %q", c.community, "public")
	}
	if c.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", c.timeout, defaultTimeout)
	}
	if c.retries != defaultRetries {
		t.Errorf("retries = %d, want %d", c.retries, defaultRetries)
	}
}

func TestNewGoSNMPClient_Options(t *testing.T) {
	c := NewGoSNMPClient("switch.example.com", "public", WithTimeout(3*time.Second), WithRetries(5))
	if c.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", c.timeout)
	}
	if c.retries != 5 {
		t.Errorf("retries = %d, want 5", c.retries)
	}
}

// -- normalizeVarbind: pure unit tests, no I/O -------------------------------

func TestNormalizeVarbind_Types(t *testing.T) {
	tests := []struct {
		name     string
		pdu      gosnmp.SnmpPDU
		wantOID  string
		wantVal  any
		wantType string
	}{
		{
			name:     "Integer",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Integer, Value: int(42)},
			wantOID:  "1.3.6.1.2.1.1.1.0",
			wantVal:  int64(42),
			wantType: "INTEGER",
		},
		{
			name:     "Gauge32",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.5.1", Type: gosnmp.Gauge32, Value: uint(1000000)},
			wantOID:  "1.3.6.1.2.1.2.2.1.5.1",
			wantVal:  int64(1000000),
			wantType: "Gauge32",
		},
		{
			name:     "Uinteger32 maps to Gauge32 token",
			pdu:      gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.Uinteger32, Value: uint32(7)},
			wantOID:  "1.2.3",
			wantVal:  int64(7),
			wantType: "Gauge32",
		},
		{
			name:     "Counter32",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.14.1", Type: gosnmp.Counter32, Value: uint(500)},
			wantOID:  "1.3.6.1.2.1.2.2.1.14.1",
			wantVal:  int64(500),
			wantType: "Counter32",
		},
		{
			name:     "Counter64",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.31.1.1.1.6.1", Type: gosnmp.Counter64, Value: uint64(9999999999)},
			wantOID:  "1.3.6.1.2.1.31.1.1.1.6.1",
			wantVal:  int64(9999999999),
			wantType: "Counter64",
		},
		{
			name:     "TimeTicks",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(123456)},
			wantOID:  "1.3.6.1.2.1.1.3.0",
			wantVal:  int64(123456),
			wantType: "Timeticks",
		},
		{
			name:     "printable OctetString",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.31.1.1.1.1.1", Type: gosnmp.OctetString, Value: []byte("1/0/1")},
			wantOID:  "1.3.6.1.2.1.31.1.1.1.1.1",
			wantVal:  "1/0/1",
			wantType: "STRING",
		},
		{
			name:     "empty OctetString is printable",
			pdu:      gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.OctetString, Value: []byte{}},
			wantOID:  "1.2.3",
			wantVal:  "",
			wantType: "STRING",
		},
		{
			name:     "binary OctetString",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.17.1.1.0", Type: gosnmp.OctetString, Value: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}},
			wantOID:  "1.3.6.1.2.1.17.1.1.0",
			wantVal:  []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00},
			wantType: "Hex-STRING",
		},
		{
			name:     "IPAddress",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.4.20.1.1.10.1.5.20", Type: gosnmp.IPAddress, Value: "10.1.5.20"},
			wantOID:  "1.3.6.1.2.1.4.20.1.1.10.1.5.20",
			wantVal:  "10.1.5.20",
			wantType: "IpAddress",
		},
		{
			name:     "ObjectIdentifier",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.4.1.4526.100.10.19"},
			wantOID:  "1.3.6.1.2.1.1.2.0",
			wantVal:  "1.3.6.1.4.1.4526.100.10.19",
			wantType: "OID",
		},
		{
			name:     "ObjectIdentifier value with leading dot is stripped too",
			pdu:      gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.4526.100.10.19"},
			wantOID:  "1.2.3",
			wantVal:  "1.3.6.1.4.1.4526.100.10.19",
			wantType: "OID",
		},
		{
			name:     "NoSuchObject",
			pdu:      gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.NoSuchObject, Value: nil},
			wantOID:  "1.2.3",
			wantVal:  "",
			wantType: "NOSUCHOBJECT",
		},
		{
			name:     "NoSuchInstance",
			pdu:      gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.NoSuchInstance, Value: nil},
			wantOID:  "1.2.3",
			wantVal:  "",
			wantType: "NOSUCHINSTANCE",
		},
		{
			name:     "EndOfMibView",
			pdu:      gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.EndOfMibView, Value: nil},
			wantOID:  "1.2.3",
			wantVal:  "",
			wantType: "ENDOFMIBVIEW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row, err := normalizeVarbind(tt.pdu)
			if err != nil {
				t.Fatalf("normalizeVarbind() error = %v", err)
			}
			if row.OID != tt.wantOID {
				t.Errorf("OID = %q, want %q", row.OID, tt.wantOID)
			}
			if row.SnmpType != tt.wantType {
				t.Errorf("SnmpType = %q, want %q", row.SnmpType, tt.wantType)
			}
			switch want := tt.wantVal.(type) {
			case int64:
				got, ok := row.Value.(int64)
				if !ok {
					t.Fatalf("Value type = %T, want int64", row.Value)
				}
				if got != want {
					t.Errorf("Value = %d, want %d", got, want)
				}
			case string:
				got, ok := row.Value.(string)
				if !ok {
					t.Fatalf("Value type = %T, want string", row.Value)
				}
				if got != want {
					t.Errorf("Value = %q, want %q", got, want)
				}
			case []byte:
				got, ok := row.Value.([]byte)
				if !ok {
					t.Fatalf("Value type = %T, want []byte", row.Value)
				}
				if string(got) != string(want) {
					t.Errorf("Value = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestNormalizeVarbind_Errors(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
	}{
		{"Integer with non-int value", gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.Integer, Value: "not an int"}},
		{"OctetString with non-byte value", gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.OctetString, Value: "not bytes"}},
		{"IPAddress with non-string value", gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.IPAddress, Value: 42}},
		{"ObjectIdentifier with non-string value", gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.ObjectIdentifier, Value: 42}},
		{"unsupported wire type", gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.BitString, Value: []byte{0x01}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizeVarbind(tt.pdu)
			if err == nil {
				t.Fatal("normalizeVarbind() error = nil, want error")
			}
			if !errors.Is(err, model.ErrSNMP) {
				t.Errorf("error %v does not wrap model.ErrSNMP", err)
			}
			if !strings.Contains(err.Error(), "1.2.3") {
				t.Errorf("error %q does not name the OID", err.Error())
			}
		})
	}
}

// -- Get ----------------------------------------------------------------------

func TestGoSNMPClient_Get_AllTypes(t *testing.T) {
	agent := &fakeAgent{rows: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.99999.1.0", Type: gosnmp.Integer, Value: int(42)},
		{Name: ".1.3.6.1.4.1.99999.2.0", Type: gosnmp.Gauge32, Value: uint(1000)},
		{Name: ".1.3.6.1.4.1.99999.3.0", Type: gosnmp.Counter32, Value: uint(500)},
		{Name: ".1.3.6.1.4.1.99999.4.0", Type: gosnmp.Counter64, Value: uint64(9999999999)},
		{Name: ".1.3.6.1.4.1.99999.5.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
		{Name: ".1.3.6.1.4.1.99999.6.0", Type: gosnmp.OctetString, Value: []byte("hello")},
		{Name: ".1.3.6.1.4.1.99999.7.0", Type: gosnmp.OctetString, Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{Name: ".1.3.6.1.4.1.99999.8.0", Type: gosnmp.IPAddress, Value: "10.1.5.20"},
		{Name: ".1.3.6.1.4.1.99999.9.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.4.1.4526.100.10.19"},
	}}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	oids := []string{
		"1.3.6.1.4.1.99999.1.0", "1.3.6.1.4.1.99999.2.0", "1.3.6.1.4.1.99999.3.0",
		"1.3.6.1.4.1.99999.4.0", "1.3.6.1.4.1.99999.5.0", "1.3.6.1.4.1.99999.6.0",
		"1.3.6.1.4.1.99999.7.0", "1.3.6.1.4.1.99999.8.0", "1.3.6.1.4.1.99999.9.0",
	}
	rows, err := client.Get(context.Background(), oids)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(rows) != len(oids) {
		t.Fatalf("Get() returned %d rows, want %d", len(rows), len(oids))
	}

	want := []struct {
		val any
		typ string
	}{
		{int64(42), "INTEGER"},
		{int64(1000), "Gauge32"},
		{int64(500), "Counter32"},
		{int64(9999999999), "Counter64"},
		{int64(12345), "Timeticks"},
		{"hello", "STRING"},
		{[]byte{0xDE, 0xAD, 0xBE, 0xEF}, "Hex-STRING"},
		{"10.1.5.20", "IpAddress"},
		{"1.3.6.1.4.1.4526.100.10.19", "OID"},
	}
	for i, w := range want {
		if rows[i].OID != oids[i] {
			t.Errorf("rows[%d].OID = %q, want %q", i, rows[i].OID, oids[i])
		}
		if rows[i].SnmpType != w.typ {
			t.Errorf("rows[%d].SnmpType = %q, want %q", i, rows[i].SnmpType, w.typ)
		}
		switch wv := w.val.(type) {
		case []byte:
			gv, ok := rows[i].Value.([]byte)
			if !ok || string(gv) != string(wv) {
				t.Errorf("rows[%d].Value = %#v, want %#v", i, rows[i].Value, wv)
			}
		default:
			if rows[i].Value != w.val {
				t.Errorf("rows[%d].Value = %#v (%T), want %#v (%T)", i, rows[i].Value, rows[i].Value, w.val, w.val)
			}
		}
	}
}

func TestGoSNMPClient_Get_Empty_NoIO(t *testing.T) {
	// An address nothing listens on and that can't even resolve/dial;
	// if Get did any I/O for an empty oid list, this would error or
	// hang. Getting back (nil, nil) proves it didn't try.
	client := NewGoSNMPClient("256.256.256.256:161", "public", WithTimeout(50*time.Millisecond))
	rows, err := client.Get(context.Background(), nil)
	if err != nil {
		t.Fatalf("Get(nil) error = %v, want nil (no I/O)", err)
	}
	if rows != nil {
		t.Errorf("Get(nil) rows = %v, want nil", rows)
	}
}

func TestGoSNMPClient_Get_AbsentError(t *testing.T) {
	agent := &fakeAgent{rows: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.99999.1.0", Type: gosnmp.Integer, Value: int(1)},
	}}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	_, err := client.Get(context.Background(), []string{"1.3.6.1.4.1.99999.999.0"})
	if err == nil {
		t.Fatal("Get() error = nil, want absent-OID error")
	}
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("error %v does not wrap model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), "absent OID in GET response") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "absent OID in GET response")
	}
	if !strings.Contains(err.Error(), "1.3.6.1.4.1.99999.999.0") {
		t.Errorf("error = %q, want it to name the OID", err.Error())
	}
}

func TestGoSNMPClient_Get_PDUErrorStatus(t *testing.T) {
	agent := &fakeAgent{getErrStatus: gosnmp.GenErr}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	_, err := client.Get(context.Background(), []string{"1.3.6.1.4.1.99999.1.0"})
	if err == nil {
		t.Fatal("Get() error = nil, want error-status error")
	}
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("error %v does not wrap model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), "GenErr") {
		t.Errorf("error = %q, want it to name the error-status", err.Error())
	}
}

// -- Walk -----------------------------------------------------------------

func TestGoSNMPClient_Walk_StopsAtSubtreeBoundary(t *testing.T) {
	// Column A (walked) has 3 rows; column B is a numerically-later
	// sibling with 1 row. All 4 fit in a single GetBulk response
	// (bulkMaxRepetitions=25), so this specifically tests boundedness
	// WITHIN a batch, not just at table exhaustion.
	agent := &fakeAgent{rows: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.99999.10.1", Type: gosnmp.Integer, Value: int(1)},
		{Name: ".1.3.6.1.4.1.99999.10.2", Type: gosnmp.Integer, Value: int(2)},
		{Name: ".1.3.6.1.4.1.99999.10.3", Type: gosnmp.Integer, Value: int(3)},
		{Name: ".1.3.6.1.4.1.99999.20.1", Type: gosnmp.Integer, Value: int(999)},
	}}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	rows, err := client.Walk(context.Background(), "1.3.6.1.4.1.99999.10")
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}
	wantOIDs := []string{
		"1.3.6.1.4.1.99999.10.1",
		"1.3.6.1.4.1.99999.10.2",
		"1.3.6.1.4.1.99999.10.3",
	}
	if len(rows) != len(wantOIDs) {
		t.Fatalf("Walk() returned %d rows, want %d: %+v", len(rows), len(wantOIDs), rows)
	}
	for i, oid := range wantOIDs {
		if rows[i].OID != oid {
			t.Errorf("rows[%d].OID = %q, want %q", i, rows[i].OID, oid)
		}
	}
	for _, row := range rows {
		if strings.HasPrefix(row.OID, "1.3.6.1.4.1.99999.20") {
			t.Errorf("Walk() leaked out-of-subtree row %+v", row)
		}
	}
}

func TestGoSNMPClient_Walk_EndOfMibView(t *testing.T) {
	// Column B is the last branch in the table: walking it runs off the
	// end, forcing a second round trip whose GetBulk response is a bare
	// EndOfMibView PDU.
	agent := &fakeAgent{rows: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.99999.10.1", Type: gosnmp.Integer, Value: int(1)},
		{Name: ".1.3.6.1.4.1.99999.20.1", Type: gosnmp.Integer, Value: int(999)},
	}}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	rows, err := client.Walk(context.Background(), "1.3.6.1.4.1.99999.20")
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}
	if len(rows) != 1 || rows[0].OID != "1.3.6.1.4.1.99999.20.1" {
		t.Fatalf("Walk() = %+v, want exactly [99999.20.1]", rows)
	}
}

func TestGoSNMPClient_Walk_EmptySubtree(t *testing.T) {
	// Nothing at all under the walked base: the very first GetBulk
	// response is already EndOfMibView.
	agent := &fakeAgent{rows: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.4.1.99999.10.1", Type: gosnmp.Integer, Value: int(1)},
	}}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	rows, err := client.Walk(context.Background(), "1.3.6.1.4.1.99999.99")
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("Walk() = %+v, want empty", rows)
	}
}

func TestGoSNMPClient_Walk_MidWalkError(t *testing.T) {
	agent := &fakeAgent{
		errorOnPrefix: "1.3.6.1.4.1.88888",
		walkErrStatus: gosnmp.GenErr,
	}
	agent.start(t)

	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))
	rows, err := client.Walk(context.Background(), "1.3.6.1.4.1.88888")
	if err == nil {
		t.Fatalf("Walk() error = nil, rows = %+v, want mid-walk error", rows)
	}
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("error %v does not wrap model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), "GenErr") {
		t.Errorf("error = %q, want it to name the error-status", err.Error())
	}
}

// -- SetMany / Set ------------------------------------------------------------

func TestGoSNMPClient_SetMany_RecordsOnePDU(t *testing.T) {
	agent := &fakeAgent{}
	agent.start(t)
	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))

	vbI, err := NewSetVarbind("1.3.6.1.4.1.99999.1.0", int64(7), "i")
	if err != nil {
		t.Fatalf("NewSetVarbind(i): %v", err)
	}
	vbU, err := NewSetVarbind("1.3.6.1.4.1.99999.2.0", int64(123), "u")
	if err != nil {
		t.Fatalf("NewSetVarbind(u): %v", err)
	}
	vbA, err := NewSetVarbind("1.3.6.1.4.1.99999.3.0", "192.168.1.50", "a")
	if err != nil {
		t.Fatalf("NewSetVarbind(a): %v", err)
	}
	vbS, err := NewSetVarbind("1.3.6.1.4.1.99999.4.0", "hello", "s")
	if err != nil {
		t.Fatalf("NewSetVarbind(s): %v", err)
	}
	vbX, err := NewSetVarbind("1.3.6.1.4.1.99999.5.0", []byte{0xAB, 0xCD}, "x")
	if err != nil {
		t.Fatalf("NewSetVarbind(x): %v", err)
	}
	vbs := []SetVarbind{vbI, vbU, vbA, vbS, vbX}

	if err := client.SetMany(context.Background(), vbs); err != nil {
		t.Fatalf("SetMany() error = %v", err)
	}

	var seen []gosnmp.SnmpPDU
	select {
	case seen = <-agent.setCh:
	case <-time.After(2 * time.Second):
		t.Fatal("agent never saw a SET request")
	}

	if len(seen) != len(vbs) {
		t.Fatalf("agent recorded %d varbinds, want %d (one PDU, all varbinds): %+v", len(seen), len(vbs), seen)
	}
	wantTypes := []gosnmp.Asn1BER{gosnmp.Integer, gosnmp.Gauge32, gosnmp.IPAddress, gosnmp.OctetString, gosnmp.OctetString}
	for i, wt := range wantTypes {
		if seen[i].Type != wt {
			t.Errorf("varbind[%d].Type = %s, want %s", i, seen[i].Type, wt)
		}
		if strings.TrimLeft(seen[i].Name, ".") != vbs[i].OID {
			t.Errorf("varbind[%d].Name = %q, want %q", i, seen[i].Name, vbs[i].OID)
		}
	}
	if v, ok := seen[0].Value.(int); !ok || v != 7 {
		t.Errorf("varbind[0].Value = %#v, want int(7)", seen[0].Value)
	}
	if s, ok := seen[3].Value.([]byte); !ok || string(s) != "hello" {
		t.Errorf("varbind[3].Value = %#v, want []byte(\"hello\")", seen[3].Value)
	}
}

func TestGoSNMPClient_Set_SingleVarbind(t *testing.T) {
	agent := &fakeAgent{}
	agent.start(t)
	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))

	vb, err := NewSetVarbind("1.3.6.1.4.1.99999.1.0", int64(1), "i")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	if err := client.Set(context.Background(), vb); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	select {
	case seen := <-agent.setCh:
		if len(seen) != 1 {
			t.Fatalf("agent recorded %d varbinds, want 1", len(seen))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never saw a SET request")
	}
}

func TestGoSNMPClient_SetMany_InvalidValueType(t *testing.T) {
	// toSetPDU rejects a value whose Go type doesn't match its
	// TypeLetter before any I/O, so an unroutable host is fine here.
	tests := []struct {
		name       string
		value      any
		typeLetter string
	}{
		{"i with string value", "not an int", "i"},
		{"u with string value", "not an int", "u"},
		{"a with int value", 42, "a"},
		{"s with int value", 42, "s"},
		{"x with int value", 42, "x"},
	}
	client := NewGoSNMPClient("256.256.256.256:161", "public", WithTimeout(50*time.Millisecond))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vb, err := NewSetVarbind("1.3.6.1.4.1.99999.1.0", tt.value, tt.typeLetter)
			if err != nil {
				t.Fatalf("NewSetVarbind: %v", err)
			}
			err = client.SetMany(context.Background(), []SetVarbind{vb})
			if err == nil {
				t.Fatal("SetMany() error = nil, want error")
			}
			if !errors.Is(err, model.ErrSNMP) {
				t.Errorf("error %v does not wrap model.ErrSNMP", err)
			}
		})
	}
}

func TestGoSNMPClient_SetMany_Empty_NoIO(t *testing.T) {
	client := NewGoSNMPClient("256.256.256.256:161", "public", WithTimeout(50*time.Millisecond))
	if err := client.SetMany(context.Background(), nil); err != nil {
		t.Fatalf("SetMany(nil) error = %v, want nil (no I/O)", err)
	}
}

func TestGoSNMPClient_SetMany_ErrorStatus(t *testing.T) {
	agent := &fakeAgent{setErrStatus: gosnmp.NotWritable, setErrIndex: 2}
	agent.start(t)
	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(2*time.Second))

	vb1, _ := NewSetVarbind("1.3.6.1.4.1.99999.1.0", int64(1), "i")
	vb2, _ := NewSetVarbind("1.3.6.1.4.1.99999.2.0", int64(2), "i")
	vb3, _ := NewSetVarbind("1.3.6.1.4.1.99999.3.0", int64(3), "i")

	err := client.SetMany(context.Background(), []SetVarbind{vb1, vb2, vb3})
	if err == nil {
		t.Fatal("SetMany() error = nil, want error")
	}
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("error %v does not wrap model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), vb2.OID) {
		t.Errorf("error = %q, want it to name the failing OID %q (error-index 2 -> vbs[1])", err.Error(), vb2.OID)
	}
	if !strings.Contains(err.Error(), "NotWritable") {
		t.Errorf("error = %q, want it to name the error-status", err.Error())
	}
}

// -- ctx cancellation / deadline ----------------------------------------------

func TestGoSNMPClient_Get_CtxAlreadyCancelled(t *testing.T) {
	client := NewGoSNMPClient("127.0.0.1:1", "public", WithTimeout(10*time.Second), WithRetries(0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := client.Get(ctx, []string{"1.3.6.1.2.1.1.1.0"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Get() error = nil, want error from cancelled ctx")
	}
	if elapsed > time.Second {
		t.Errorf("Get() took %v with an already-cancelled ctx and a 10s client timeout; ctx cancellation was not honoured promptly", elapsed)
	}
}

func TestGoSNMPClient_Get_CtxDeadline_BlackHole(t *testing.T) {
	agent := &fakeAgent{blackhole: true}
	agent.start(t)

	// Client timeout is deliberately much larger than the ctx deadline,
	// so a prompt return here can only be explained by gosnmp honouring
	// ctx.Deadline() as (part of) the effective per-attempt deadline.
	client := NewGoSNMPClient(agent.addr(), "public", WithTimeout(10*time.Second), WithRetries(0))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.Get(ctx, []string{"1.3.6.1.2.1.1.1.0"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Get() error = nil, want deadline error from a black-hole agent")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not wrap context.DeadlineExceeded", err)
	}
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("error %v does not wrap model.ErrSNMP", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("Get() took %v against a 150ms ctx deadline and a 10s client timeout; ctx deadline was not honoured", elapsed)
	}
}
