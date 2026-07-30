package snmp

// GoSNMPClient is the real WriteClient transport, backed by
// github.com/gosnmp/gosnmp (SNMP v2c over UDP). It normalizes gosnmp's
// decoded varbinds into the package's Row contract per D-SNMP dossier §5.2
// (the pysnmp transport's semantic-delta contract, which this Go transport
// reproduces byte-for-byte since Go has only one live transport).
//
// ctx handling: each call sets gosnmp.GoSNMP.Context to the caller's ctx
// before connecting. gosnmp honours it two ways (see its marshal.go
// sendOneRequest): it checks ctx.Err() before every request/retry attempt,
// and it computes each request's socket read deadline as the earlier of
// the client's configured Timeout and ctx's Deadline(). So an already-done
// ctx (Err() != nil, e.g. already cancelled) aborts before any I/O; a ctx
// with a Deadline shorter than the client Timeout is honoured as the
// effective per-attempt deadline. A ctx cancelled via CancelFunc with NO
// Deadline is only observed between attempts (at the top of the retry
// loop) -- it cannot interrupt an already in-flight blocking socket Read,
// since gosnmp arms the deadline once per attempt rather than watching
// ctx.Done() concurrently. Callers that need mid-read cancellation should
// use context.WithTimeout/WithDeadline rather than a bare cancel.
//
// Connections are not pooled: every Get/Walk/Set/SetMany opens a fresh
// UDP "connection" (just a bound local socket; UDP has no handshake) and
// closes it before returning, mirroring the pysnmp transport's per-call
// SnmpEngine that is always torn down in a finally block.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/mithro/go-netgear-switch-library/model"
)

const (
	defaultPort    = 161
	defaultTimeout = 10 * time.Second
	defaultRetries = 1

	// bulkMaxRepetitions is the GETBULK max-repetitions used by Walk,
	// matching the pysnmp transport's bulk_walk_cmd(..., 0, 25, ...) (D-SNMP
	// §5.2): non-repeaters 0 (fixed; Walk always asks for one OID), 25
	// max-repetitions.
	bulkMaxRepetitions = 25
)

// GoSNMPClient is a WriteClient for one switch, speaking SNMP v2c via
// gosnmp. Construct with NewGoSNMPClient.
type GoSNMPClient struct {
	host      string
	port      uint16
	community string
	timeout   time.Duration
	retries   int
}

// ClientOption configures a GoSNMPClient at construction time.
type ClientOption func(*GoSNMPClient)

// WithTimeout overrides the per-request timeout (default 10s).
func WithTimeout(d time.Duration) ClientOption {
	return func(c *GoSNMPClient) { c.timeout = d }
}

// WithRetries overrides the retry count (default 1).
func WithRetries(n int) ClientOption {
	return func(c *GoSNMPClient) { c.retries = n }
}

// NewGoSNMPClient creates an SNMP v2c client for host, which may be a bare
// hostname/IP ("switch.example.com", "10.1.5.20") or a "host:port" pair; if
// no port is given, 161 is used. Defaults: 10s per-request timeout, 1
// retry -- override with WithTimeout/WithRetries.
func NewGoSNMPClient(host, community string, opts ...ClientOption) *GoSNMPClient {
	h, port := splitHostPort(host)
	c := &GoSNMPClient{
		host:      h,
		port:      port,
		community: community,
		timeout:   defaultTimeout,
		retries:   defaultRetries,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// splitHostPort splits "host:port" into (host, port); a bare host (no
// colon, or a colon net.SplitHostPort can't parse) yields (host,
// defaultPort).
func splitHostPort(host string) (string, uint16) {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host, defaultPort
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return h, defaultPort
	}
	return h, uint16(n) //nolint:gosec // bounds-checked by ParseUint(..., 16)
}

// target renders host:port for error messages.
func (c *GoSNMPClient) target() string {
	return net.JoinHostPort(c.host, strconv.Itoa(int(c.port)))
}

// session builds a fresh, unconnected gosnmp handle for one call. See the
// package-level ctx doc comment above for how ctx.Context is honoured.
func (c *GoSNMPClient) session(ctx context.Context) *gosnmp.GoSNMP {
	return &gosnmp.GoSNMP{
		Target:    c.host,
		Port:      c.port,
		Community: c.community,
		Version:   gosnmp.Version2c,
		Timeout:   c.timeout,
		Retries:   c.retries,
		Context:   ctx,
	}
}

// Get performs a single SNMP GET PDU for oids, returning one Row per
// returned varbind in response order (normally oid order). An empty oids
// is a no-op: ([]Row(nil), nil), no I/O. A connection failure or a
// PDU-level error-status wraps model.ErrSNMP, naming host and oids. Unlike
// Walk, ANY absent-type varbind (NoSuchObject/NoSuchInstance/EndOfMibView)
// in a GET response is itself an error -- a GET is a request for specific
// OIDs, so silently answering one is never valid.
func (c *GoSNMPClient) Get(ctx context.Context, oids []string) ([]Row, error) {
	if len(oids) == 0 {
		return nil, nil
	}

	g := c.session(ctx)
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("connect to %s for GET %v: %w: %w", c.target(), oids, err, model.ErrSNMP)
	}
	defer func() { _ = g.Close() }()

	pkt, err := g.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("GET %v on %s: %w: %w", oids, c.target(), err, model.ErrSNMP)
	}
	if pkt.Error != gosnmp.NoError {
		return nil, errSNMP("GET %v on %s: agent returned error-status %s at varbind index %d",
			oids, c.target(), pkt.Error, pkt.ErrorIndex)
	}

	rows := make([]Row, 0, len(pkt.Variables))
	for _, pdu := range pkt.Variables {
		row, err := normalizeVarbind(pdu)
		if err != nil {
			return nil, err
		}
		if AbsentTypes[row.SnmpType] {
			return nil, errSNMP("absent OID in GET response: %s", row.OID)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Walk retrieves every row under baseOID using repeated SNMP GETBULK
// requests (max-repetitions 25; see bulkMaxRepetitions), subtree-bounded:
// it stops as soon as a returned OID falls outside baseOID's subtree, or
// the agent signals EndOfMibView or an absent-type varbind (both benign
// walk terminators) -- in either case the rows collected so far are
// returned with a nil error. A GetBulk transport failure or a non-absent
// PDU-level error-status always returns an error instead: silently
// truncating there would be indistinguishable from a genuinely complete
// walk (D-SNMP §5.2).
//
// gosnmp's own BulkWalk (walk.go) implements the same subtree-bounded,
// terminator-tolerant loop, and was used to confirm that boundedness
// behaviour (also pinned by TestGoSNMPClient_Walk_StopsAtSubtreeBoundary).
// This method reimplements the GETBULK loop directly instead of calling
// BulkWalk, because BulkWalk swallows a mid-walk PDU error-status
// (response.Error != NoError) silently -- it just logs and stops, with no
// way for a caller to distinguish that from a real EndOfMibView/absent
// termination -- which would violate the mid-walk-error-must-raise rule
// above.
func (c *GoSNMPClient) Walk(ctx context.Context, baseOID string) ([]Row, error) {
	g := c.session(ctx)
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("connect to %s for WALK %s: %w: %w", c.target(), baseOID, err, model.ErrSNMP)
	}
	defer func() { _ = g.Close() }()

	root := strings.TrimLeft(baseOID, ".")
	prefix := root + "."
	oid := baseOID

	var rows []Row
	for {
		pkt, err := g.GetBulk([]string{oid}, 0, bulkMaxRepetitions)
		if err != nil {
			return nil, fmt.Errorf("WALK %s on %s: %w: %w", baseOID, c.target(), err, model.ErrSNMP)
		}
		if pkt.Error != gosnmp.NoError {
			return nil, errSNMP("WALK %s on %s: agent returned error-status %s at varbind index %d",
				baseOID, c.target(), pkt.Error, pkt.ErrorIndex)
		}
		if len(pkt.Variables) == 0 {
			break
		}

		stop := false
		for _, pdu := range pkt.Variables {
			if pdu.Type == gosnmp.EndOfMibView || pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
				stop = true
				break
			}
			if !strings.HasPrefix(strings.TrimLeft(pdu.Name, "."), prefix) {
				stop = true
				break
			}
			row, err := normalizeVarbind(pdu)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		if stop {
			break
		}
		oid = pkt.Variables[len(pkt.Variables)-1].Name
	}
	return rows, nil
}

// Set performs a single-varbind SetMany.
func (c *GoSNMPClient) Set(ctx context.Context, vb SetVarbind) error {
	return c.SetMany(ctx, []SetVarbind{vb})
}

// SetMany performs one SNMP SET PDU covering every varbind in vbs
// (RFC 3416: an agent applies all varbinds in a SET PDU or none, so this
// is the atomic write primitive; Set is SetMany of one). An empty vbs is
// a no-op: nil, no I/O. Type-letter -> wire type: i=Integer, u=Gauge32,
// a=IpAddress, s/x=OctetString (both write raw bytes on the wire; a
// string value is converted via []byte(s), the inverse of the read-side
// printable-OctetString-as-string normalization). A connection/transport
// failure or a PDU-level error-status wraps model.ErrSNMP; the
// error-status case names the failing OID via the response's error-index.
func (c *GoSNMPClient) SetMany(ctx context.Context, vbs []SetVarbind) error {
	if len(vbs) == 0 {
		return nil
	}

	pdus := make([]gosnmp.SnmpPDU, len(vbs))
	for i, vb := range vbs {
		pdu, err := toSetPDU(vb)
		if err != nil {
			return err
		}
		pdus[i] = pdu
	}

	g := c.session(ctx)
	if err := g.Connect(); err != nil {
		return fmt.Errorf("connect to %s for SET %v: %w: %w", c.target(), oidsOf(vbs), err, model.ErrSNMP)
	}
	defer func() { _ = g.Close() }()

	pkt, err := g.Set(pdus)
	if err != nil {
		return fmt.Errorf("SET %v on %s: %w: %w", oidsOf(vbs), c.target(), err, model.ErrSNMP)
	}
	if pkt.Error != gosnmp.NoError {
		failingOID := "?"
		if idx := int(pkt.ErrorIndex); idx >= 1 && idx <= len(vbs) {
			failingOID = vbs[idx-1].OID
		}
		return errSNMP("SET %v on %s: agent rejected %s with error-status %s",
			oidsOf(vbs), c.target(), failingOID, pkt.Error)
	}
	return nil
}

// oidsOf collects the OIDs of vbs, for error messages.
func oidsOf(vbs []SetVarbind) []string {
	out := make([]string, len(vbs))
	for i, vb := range vbs {
		out[i] = vb.OID
	}
	return out
}

// toSetPDU maps a SetVarbind to the gosnmp wire type/value its
// TypeLetter selects. NewSetVarbind already validates TypeLetter is one
// of i/u/s/x/a, so the default case below is unreachable via that
// constructor; it stays as defense against a SetVarbind built without it.
func toSetPDU(vb SetVarbind) (gosnmp.SnmpPDU, error) {
	switch vb.TypeLetter {
	case "i":
		v, ok := pduIntValue(vb.Value)
		if !ok {
			return gosnmp.SnmpPDU{}, errOID(vb.OID, "non-integer value %v for SET type 'i'", vb.Value)
		}
		return gosnmp.SnmpPDU{Name: vb.OID, Type: gosnmp.Integer, Value: int(v)}, nil
	case "u":
		v, ok := pduIntValue(vb.Value)
		if !ok {
			return gosnmp.SnmpPDU{}, errOID(vb.OID, "non-integer value %v for SET type 'u'", vb.Value)
		}
		return gosnmp.SnmpPDU{Name: vb.OID, Type: gosnmp.Gauge32, Value: uint32(v)}, nil //nolint:gosec // SET values are switch config knobs, not attacker-controlled wire input
	case "a":
		s, ok := vb.Value.(string)
		if !ok {
			return gosnmp.SnmpPDU{}, errOID(vb.OID, "non-string value %v for SET type 'a'", vb.Value)
		}
		return gosnmp.SnmpPDU{Name: vb.OID, Type: gosnmp.IPAddress, Value: s}, nil
	case "s", "x":
		b, ok := toOctetBytes(vb.Value)
		if !ok {
			return gosnmp.SnmpPDU{}, errOID(vb.OID, "unsupported value type %T for SET type %q", vb.Value, vb.TypeLetter)
		}
		return gosnmp.SnmpPDU{Name: vb.OID, Type: gosnmp.OctetString, Value: b}, nil
	default:
		return gosnmp.SnmpPDU{}, errOID(vb.OID, "unsupported SET type letter %q", vb.TypeLetter)
	}
}

// toOctetBytes converts a SET varbind value to the raw bytes an
// OctetString PDU carries: a []byte value passes through; a string value
// is converted via []byte(s) (latin-1/raw, not UTF-8 re-encoding, mirroring
// the pysnmp transport's `str(value).encode("latin-1")`... for the ASCII
// subrange the two encodings agree, which covers every value this
// package's write call sites ever construct).
func toOctetBytes(v any) ([]byte, bool) {
	switch val := v.(type) {
	case []byte:
		return val, true
	case string:
		return []byte(val), true
	default:
		return nil, false
	}
}

// pduIntValue widens any of gosnmp's integer-family Go types (as produced
// by its Integer/Gauge32/Counter32/Counter64/TimeTicks/Uinteger32 decoders,
// and accepted by its Integer/Gauge32 SET encoders) to int64.
func pduIntValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true //nolint:gosec // SNMP counters/gauges never approach 2^63 in practice; matches Python's unbounded-int parity contract
	default:
		return 0, false
	}
}

// isPrintableOctets is the printability heuristic (D-SNMP §5.2
// `_octet_value`): empty, or every byte in the printable-ASCII range
// 0x20-0x7E.
func isPrintableOctets(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// normalizeVarbind converts one gosnmp.SnmpPDU into the package's Row
// contract, per the token/type dispatch table in D-SNMP §5.2/§5.3:
// Integer -> ("INTEGER", int64); Gauge32/Uinteger32 -> ("Gauge32", int64);
// Counter32/Counter64/TimeTicks(as "Timeticks") -> int64; OctetString ->
// the printability heuristic (string/"STRING" or []byte/"Hex-STRING");
// IPAddress -> (string, "IpAddress"); ObjectIdentifier -> (dotted numeric
// string with any leading dot stripped, "OID"); NoSuchObject/
// NoSuchInstance/EndOfMibView -> (empty string, the matching AbsentTypes
// token). The OID itself always has its leading dot stripped (gosnmp
// always decodes a leading-dot form).
//
// Any other wire type, or a value whose Go type doesn't match what gosnmp
// itself decodes for that Asn1BER tag (see its helper.go decodeValue),
// is an error wrapping model.ErrSNMP naming the OID -- there is no silent
// fallback, matching this package's parse.go convention for drifted data.
func normalizeVarbind(pdu gosnmp.SnmpPDU) (Row, error) {
	oid := strings.TrimLeft(pdu.Name, ".")

	switch pdu.Type {
	case gosnmp.Integer:
		v, ok := pduIntValue(pdu.Value)
		if !ok {
			return Row{}, errOID(oid, "non-integer INTEGER value %v (%T)", pdu.Value, pdu.Value)
		}
		return intRow(oid, v, "INTEGER"), nil
	case gosnmp.Gauge32, gosnmp.Uinteger32:
		v, ok := pduIntValue(pdu.Value)
		if !ok {
			return Row{}, errOID(oid, "non-integer Gauge32 value %v (%T)", pdu.Value, pdu.Value)
		}
		return intRow(oid, v, "Gauge32"), nil
	case gosnmp.Counter32:
		v, ok := pduIntValue(pdu.Value)
		if !ok {
			return Row{}, errOID(oid, "non-integer Counter32 value %v (%T)", pdu.Value, pdu.Value)
		}
		return intRow(oid, v, "Counter32"), nil
	case gosnmp.Counter64:
		v, ok := pduIntValue(pdu.Value)
		if !ok {
			return Row{}, errOID(oid, "non-integer Counter64 value %v (%T)", pdu.Value, pdu.Value)
		}
		return intRow(oid, v, "Counter64"), nil
	case gosnmp.TimeTicks:
		v, ok := pduIntValue(pdu.Value)
		if !ok {
			return Row{}, errOID(oid, "non-integer Timeticks value %v (%T)", pdu.Value, pdu.Value)
		}
		return intRow(oid, v, "Timeticks"), nil
	case gosnmp.OctetString:
		raw, ok := pdu.Value.([]byte)
		if !ok {
			return Row{}, errOID(oid, "non-byte OCTET STRING value %v (%T)", pdu.Value, pdu.Value)
		}
		if isPrintableOctets(raw) {
			return strRow(oid, string(raw), "STRING"), nil
		}
		cp := make([]byte, len(raw))
		copy(cp, raw)
		return bytesRow(oid, cp, "Hex-STRING"), nil
	case gosnmp.IPAddress:
		s, ok := pdu.Value.(string)
		if !ok {
			return Row{}, errOID(oid, "non-string IpAddress value %v (%T)", pdu.Value, pdu.Value)
		}
		return strRow(oid, s, "IpAddress"), nil
	case gosnmp.ObjectIdentifier:
		s, ok := pdu.Value.(string)
		if !ok {
			return Row{}, errOID(oid, "non-string OID value %v (%T)", pdu.Value, pdu.Value)
		}
		return strRow(oid, strings.TrimLeft(s, "."), "OID"), nil
	case gosnmp.NoSuchObject:
		return strRow(oid, "", "NOSUCHOBJECT"), nil
	case gosnmp.NoSuchInstance:
		return strRow(oid, "", "NOSUCHINSTANCE"), nil
	case gosnmp.EndOfMibView:
		return strRow(oid, "", "ENDOFMIBVIEW"), nil
	default:
		return Row{}, errOID(oid, "unsupported SNMP type %s", pdu.Type)
	}
}

// intRow, strRow, and bytesRow build a Row via the package's constructors
// (for the Value-type guarantee they enforce) and then set SnmpType --
// which every constructor deliberately leaves "" for the transport layer
// to fill in.
func intRow(oid string, v int64, typ string) Row {
	r := NewIntRow(oid, v)
	r.SnmpType = typ
	return r
}

func strRow(oid, v, typ string) Row {
	r := NewStrRow(oid, v)
	r.SnmpType = typ
	return r
}

func bytesRow(oid string, v []byte, typ string) Row {
	r := NewBytesRow(oid, v)
	r.SnmpType = typ
	return r
}
