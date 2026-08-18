package virtual

// snmpface.go ports src/netgear_switch/virtual/faces/snmp.py's
// VirtualSnmpFace (the normative source; that repo is read-only from here --
// pin 1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy between
// this file and the Python source is a bug here. See D-VIRT §3/§7 for the
// full porting dossier this mirrors.
//
// SnmpFace is a real SNMPv2c command-responder agent serving a MibView,
// bound to an ephemeral UDP port on 127.0.0.1. Unlike the Python reference
// (which wraps pysnmp's asyncio dispatcher), this is a direct wire-codec
// implementation on top of gosnmp's exported encode/decode primitives
// (GoSNMP.SnmpDecodePacket / SnmpPacket.MarshalMsg) -- the resolved decision
// gate per D-VIRT §7: GoSNMPServer was rejected because it answers PDU-level
// noSuchName errors for absent OIDs, and per-varbind exception VALUES
// (NoSuchObject/NoSuchInstance/EndOfMibView embedded in the response, never
// a whole-PDU error status) are non-negotiable for hardware fidelity here.
//
// THE central fidelity point, mirrored exactly from the Python reference:
// every GET/GETNEXT/GETBULK varbind is always answered, with an
// is_implemented gate checked BEFORE the view's flat bisect for each
// varbind's own requested OID -- never a PDU-level error for an absent
// value. A SET PDU is the opposite: whole-PDU atomic (snapshot before any
// varbind applies; restore and answer a PDU-level error status if any
// varbind is rejected; rebuild once only after every varbind in the PDU has
// applied cleanly).

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
)

// SnmpFace is an SNMPv2c command-responder agent serving a MibView. Runs its
// receive loop on a dedicated goroutine, bound to an ephemeral UDP port on
// host (or a caller-pinned one, see SetPort). Construct with NewSnmpFace;
// call Start to bind and begin serving, Stop to tear down (idempotent; safe
// to call before Start or more than once).
type SnmpFace struct {
	view      *MibView
	community string
	host      string
	port      int // 0 (the default) asks the OS for an ephemeral port; see SetPort.

	mu   sync.Mutex
	conn *net.UDPConn
	wg   sync.WaitGroup
}

// NewSnmpFace builds an SnmpFace serving view, accepting only requests
// whose community string matches community, bound to host (typically
// "127.0.0.1") once Start is called.
func NewSnmpFace(view *MibView, community, host string) *SnmpFace {
	return &SnmpFace{view: view, community: community, host: host}
}

// SetPort pins the UDP port Start binds to, mirroring the Python
// reference's VirtualSwitch(port=...) constructor argument (server.py's own
// "self.port" -- see D-VIRT §5's shared-port-field note). The default, 0,
// asks the OS for an ephemeral port, same as before this method existed.
// Call before Start; a call after Start has no effect until the next Start
// following a Stop.
func (f *SnmpFace) SetPort(port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.port = port
}

// Start binds f.host:f.port (an ephemeral port when f.port is 0, the
// default) and begins serving on a background goroutine, returning the
// bound port. Calling Start twice without an intervening Stop is an error.
func (f *SnmpFace) Start() (port int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return 0, fmt.Errorf("virtual: SnmpFace.Start: already started")
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(f.host), Port: f.port})
	if err != nil {
		return 0, fmt.Errorf("virtual: SnmpFace.Start: listen udp on %s: %w", f.host, err)
	}
	f.conn = conn

	f.wg.Add(1)
	go f.serve(conn)

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		// Unreachable: net.ListenUDP("udp", ...) always returns a *net.UDPAddr
		// from LocalAddr().
		return 0, fmt.Errorf("virtual: SnmpFace.Start: unexpected local addr type %T", conn.LocalAddr())
	}
	return udpAddr.Port, nil
}

// Stop closes the listening socket and waits for the serve goroutine to
// exit. Idempotent: a Stop before Start, or a second Stop, is a no-op.
func (f *SnmpFace) Stop() error {
	f.mu.Lock()
	conn := f.conn
	f.conn = nil
	f.mu.Unlock()

	if conn == nil {
		return nil
	}
	err := conn.Close()
	f.wg.Wait()
	if err != nil {
		return fmt.Errorf("virtual: SnmpFace.Stop: %w", err)
	}
	return nil
}

// serve is the receive loop: decode each incoming datagram with gosnmp's own
// wire codec, dispatch, and reply in kind. A malformed packet, a non-v2c
// version, or a community mismatch is silently dropped -- no response at
// all, matching a real agent's VACM reject behaviour (D-VIRT §3.6) and the
// mock's deliberately v2c-only scope. Exits when conn is closed (Stop, or
// any other read error).
func (f *SnmpFace) serve(conn *net.UDPConn) {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (Stop): stop serving
		}

		decoder := &gosnmp.GoSNMP{}
		reqPkt, err := decoder.SnmpDecodePacket(buf[:n])
		if err != nil {
			continue // malformed packet: drop
		}
		if reqPkt.Version != gosnmp.Version2c {
			continue // v1/v3: drop (this mock is v2c-only)
		}
		if reqPkt.Community != f.community {
			continue // wrong community: silently drop, matching VACM reject
		}

		resp := f.handle(reqPkt)
		if resp == nil {
			continue // unsupported PDU type: drop
		}
		out, err := resp.MarshalMsg()
		if err != nil {
			continue
		}
		_, _ = conn.WriteToUDP(out, raddr)
	}
}

// handle dispatches one decoded request packet to the matching PDU handler
// and builds the response envelope (same RequestID, community echoed).
// Returns nil for any PDU type this mock doesn't serve (traps, informs,
// v3 reports -- unreachable here since serve() already filtered to v2c) so
// the caller drops it.
func (f *SnmpFace) handle(req *gosnmp.SnmpPacket) *gosnmp.SnmpPacket {
	resp := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: req.Community,
		PDUType:   gosnmp.GetResponse,
		RequestID: req.RequestID,
	}
	switch req.PDUType {
	case gosnmp.GetRequest:
		resp.Variables = f.handleGet(req.Variables)
	case gosnmp.GetNextRequest:
		resp.Variables = f.handleGetNext(req.Variables)
	case gosnmp.GetBulkRequest:
		resp.Variables = f.handleGetBulk(req)
	case gosnmp.SetRequest:
		vars, errStatus, errIdx := f.handleSet(req.Variables)
		resp.Variables = vars
		resp.Error = errStatus
		resp.ErrorIndex = errIdx
	default:
		return nil
	}
	return resp
}

// handleGet answers a GET: exact-match lookup per requested OID. Every
// requested varbind is always answered -- an unimplemented subtree yields a
// NoSuchObject varbind, an implemented-but-absent instance yields
// NoSuchInstance, and neither is ever a PDU-level error.
func (f *SnmpFace) handleGet(vars []gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	out := make([]gosnmp.SnmpPDU, len(vars))
	for i, vb := range vars {
		out[i] = f.getPDU(vb.Name)
	}
	return out
}

// getPDU answers one GET varbind: the is_implemented gate is checked BEFORE
// the view's bisect (D-VIRT §2.9's three-way rule), so a request that
// targets a whole unregistered subtree root answers NoSuchObject rather
// than whatever unrelated (but implemented) OID the bisect would otherwise
// find next.
func (f *SnmpFace) getPDU(name string) gosnmp.SnmpPDU {
	oid, ok := oidToInts(name)
	if !ok {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.NoSuchObject}
	}
	if !f.view.IsImplemented(oid) {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.NoSuchObject}
	}
	entry, ok := f.view.Get(oid)
	if !ok {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.NoSuchInstance}
	}
	val, typ := toWireValue(entry.Type, entry.Value)
	return gosnmp.SnmpPDU{Name: name, Type: typ, Value: val}
}

// handleGetNext answers a plain GETNEXT: one chained next-step per
// requested varbind.
func (f *SnmpFace) handleGetNext(vars []gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	out := make([]gosnmp.SnmpPDU, len(vars))
	for i, vb := range vars {
		out[i] = f.getNextPDU(vb.Name)
	}
	return out
}

// getNextPDU answers one GETNEXT step from name: the is_implemented gate
// applies to name itself (the REQUESTED oid for this step -- see D-VIRT
// §7's chaining note: a GETBULK repetition's "requested" oid for step N+1
// is the OID returned by step N, so re-checking here is exactly the
// per-step gate the dossier calls for, not a redundant recheck). Past the
// end of the view answers EndOfMibView, never a PDU-level error.
func (f *SnmpFace) getNextPDU(name string) gosnmp.SnmpPDU {
	oid, ok := oidToInts(name)
	if !ok {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.NoSuchObject}
	}
	if !f.view.IsImplemented(oid) {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.NoSuchObject}
	}
	entry, ok := f.view.GetNext(oid)
	if !ok {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.EndOfMibView}
	}
	val, typ := toWireValue(entry.Type, entry.Value)
	return gosnmp.SnmpPDU{Name: "." + intsToOID(entry.OID), Type: typ, Value: val}
}

// handleGetBulk answers a GETBULK PDU: the first NonRepeaters varbinds each
// get one GetNext-style step (like handleGetNext); the remaining varbinds
// are each stepped MaxRepetitions times, chaining each step's result OID
// into the next step's request -- laid out row-major (repetition 0 for
// every repeated varbind, then repetition 1, ...), matching RFC 3416.
// Once a repeated varbind's chain reaches EndOfMibView or NoSuchObject, every
// further repetition for that column is filled with EndOfMibView rather
// than re-querying (a real agent's walk terminator, once reached, stays
// reached).
func (f *SnmpFace) handleGetBulk(req *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	vars := req.Variables
	nonRepeaters := int(req.NonRepeaters)
	if nonRepeaters > len(vars) {
		nonRepeaters = len(vars)
	}
	maxReps := int(req.MaxRepetitions)

	out := make([]gosnmp.SnmpPDU, 0, len(vars))
	for i := 0; i < nonRepeaters; i++ {
		out = append(out, f.getNextPDU(vars[i].Name))
	}

	repeated := vars[nonRepeaters:]
	if len(repeated) == 0 || maxReps <= 0 {
		return out
	}

	current := make([]string, len(repeated))
	done := make([]bool, len(repeated))
	for i, vb := range repeated {
		current[i] = vb.Name
	}
	for r := 0; r < maxReps; r++ {
		for i := range repeated {
			if done[i] {
				out = append(out, gosnmp.SnmpPDU{Name: current[i], Type: gosnmp.EndOfMibView})
				continue
			}
			pdu := f.getNextPDU(current[i])
			out = append(out, pdu)
			if pdu.Type == gosnmp.EndOfMibView || pdu.Type == gosnmp.NoSuchObject {
				done[i] = true
			} else {
				current[i] = pdu.Name
			}
		}
	}
	return out
}

// handleSet answers a SET PDU atomically (D-VIRT §3.5): snapshot the
// underlying state; for each varbind in order, reject an unrecognized OID
// with notWritable (wire error-index = idx+1) or a failed apply with
// wrongValue; on ANY failure, restore the snapshot and return a PDU-level
// error status echoing the ORIGINAL request varbinds (never the
// partially-applied out slice); on full success, rebuild the view exactly
// once and echo the applied varbinds back.
func (f *SnmpFace) handleSet(vars []gosnmp.SnmpPDU) (out []gosnmp.SnmpPDU, errStatus gosnmp.SNMPError, errIndex uint8) {
	snapshot := f.view.SnapshotState()
	applied := make([]gosnmp.SnmpPDU, len(vars))
	for i, vb := range vars {
		oid := strings.TrimLeft(vb.Name, ".")
		if !f.view.IsWritableOID(oid) {
			f.view.RestoreState(snapshot)
			return echoRequest(vars), gosnmp.NotWritable, uint8(i + 1) //nolint:gosec // a SET PDU carries at most a handful of varbinds, never close to 255
		}
		status, ok := applyUncommitted(f.view, oid, fromWireValue(vb))
		if !ok {
			f.view.RestoreState(snapshot)
			return echoRequest(vars), status, uint8(i + 1) //nolint:gosec // see above
		}
		applied[i] = vb
	}
	f.view.Rebuild()
	return applied, gosnmp.NoError, 0
}

// echoRequest copies vars, for a SET error response: the PDU-level error
// path must echo back exactly what the client sent, never the (possibly
// partially built) success-path output slice.
func echoRequest(vars []gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	return append([]gosnmp.SnmpPDU(nil), vars...)
}

// applyUncommitted calls view.ApplyWriteUncommitted(oid, value), reporting
// ok=false instead of letting a panic escape: State.ApplyWrite's int/byte
// coercion helpers (mustInt/asBytes) panic on a value of a shape no real
// call site should ever pass (D-VIRT §1.7) -- for this face, an
// attacker-or-bug-controlled SET value reaching that helper is exactly the
// "apply-uncommitted failure" the dossier maps to a clean wrongValue error
// status, never a crashed/dropped response.
//
// One panic value is distinguished from every other: State.ApplyWrite
// raises errSyslogRowCreateRefused for a syslog-host RowStatus SET at an
// index with no existing collector row, mirroring a real m4300-24x
// agent's own SMI error-status for that measured refusal
// (inconsistentValue, not the generic wrongValue every other rejected SET
// in this mock answers with -- see state.go's RowStatus-column block).
func applyUncommitted(v *MibView, oid string, value any) (status gosnmp.SNMPError, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
			if err, isErr := r.(error); isErr && errors.Is(err, errSyslogRowCreateRefused) {
				status = gosnmp.InconsistentValue
			} else {
				status = gosnmp.WrongValue
			}
		}
	}()
	v.ApplyWriteUncommitted(oid, value)
	return gosnmp.NoError, true
}

// toWireValue converts one ViewEntry's (type, value) pair to the gosnmp
// wire value/type gosnmp's own marshaller expects for that Asn1BER tag (see
// marshal.go's marshalVarbind type switch) -- D-VIRT §3.2's SMI value
// mapping. Go's OCTETSTR/IPADDR/OID values are already raw bytes/strings
// (no latin-1 encode step needed, unlike the Python reference).
func toWireValue(snmpType, value string) (any, gosnmp.Asn1BER) {
	switch snmpType {
	case "INTEGER":
		n, err := strconv.Atoi(value)
		if err != nil {
			panic(fmt.Sprintf("virtual: toWireValue: INTEGER value %q not an int", value))
		}
		return n, gosnmp.Integer
	case "Gauge32":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			panic(fmt.Sprintf("virtual: toWireValue: Gauge32 value %q not a uint32", value))
		}
		return uint32(n), gosnmp.Gauge32 //nolint:gosec // bounds-checked by ParseUint(..., 32)
	case "Counter32":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			panic(fmt.Sprintf("virtual: toWireValue: Counter32 value %q not a uint32", value))
		}
		return uint32(n), gosnmp.Counter32 //nolint:gosec // bounds-checked by ParseUint(..., 32)
	case "Counter64":
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			panic(fmt.Sprintf("virtual: toWireValue: Counter64 value %q not a uint64", value))
		}
		return n, gosnmp.Counter64
	case "OCTETSTR":
		return []byte(value), gosnmp.OctetString
	case "IPADDR":
		return value, gosnmp.IPAddress
	case "OID":
		return value, gosnmp.ObjectIdentifier
	default:
		panic(fmt.Sprintf("virtual: toWireValue: unsupported snmp type token %q", snmpType))
	}
}

// fromWireValue converts an incoming SET varbind's decoded gosnmp value to
// a plain Go value for State.ApplyWrite, mirroring the Python reference's
// _from_smi_value: any integer-family wire type widens to int; OctetString
// passes through as []byte; IPAddress and anything else render as their
// wire-decoded string form (gosnmp already decodes IPAddress to a dotted
// string -- see gosnmp.go's normalizeVarbind in package snmp).
func fromWireValue(vb gosnmp.SnmpPDU) any {
	switch v := vb.Value.(type) {
	case int:
		return v
	case int8:
		return int(v)
	case int16:
		return int(v)
	case int32:
		return int(v)
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint8:
		return int(v)
	case uint16:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v) //nolint:gosec // SET values are switch config knobs (VLAN IDs, PVIDs, ...), never near 2^63
	case []byte:
		return v
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}
