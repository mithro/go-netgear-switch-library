package snmp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Row represents one SNMP varbind: full numeric OID, normalized value, type token.
//
// The value is exactly one of int64, string, or []byte, normalized so that
// different SNMP transports (e.g., gosnmp, net-snmp CLI) yield identical
// values for the same wire data. Clients MUST NOT construct Rows directly;
// use NewIntRow, NewStrRow, or NewBytesRow instead.
type Row struct {
	OID      string
	Value    any
	SnmpType string
}

// NewIntRow creates a Row with an integer value.
func NewIntRow(oid string, v int64) Row {
	return Row{OID: oid, Value: v, SnmpType: ""}
}

// NewStrRow creates a Row with a string value.
func NewStrRow(oid, v string) Row {
	return Row{OID: oid, Value: v, SnmpType: ""}
}

// NewBytesRow creates a Row with a []byte value.
func NewBytesRow(oid string, v []byte) Row {
	return Row{OID: oid, Value: v, SnmpType: ""}
}

// AbsentTypes maps SNMP type tokens that represent "no value present".
// These appear in SNMP responses to indicate the OID exists but has no value,
// or the entire subtree is absent on the agent.
var AbsentTypes = map[string]bool{
	"NOSUCHOBJECT":   true,
	"NOSUCHINSTANCE": true,
	"ENDOFMIBVIEW":   true,
}

// FullOID joins an optional instance index onto a base OID as a full numeric OID.
//
// A transport may hand back the whole numeric OID in oid with an empty index,
// or split the instance into index. Joining both and stripping any leading
// dot is correct either way.
func FullOID(oid, index string) string {
	oid = strings.TrimLeft(oid, ".")
	if index != "" {
		return oid + "." + index
	}
	return oid
}

// Client is the SNMP v2c read-only client interface for a single switch.
type Client interface {
	Get(ctx context.Context, oids []string) ([]Row, error)
	Walk(ctx context.Context, baseOID string) ([]Row, error)
}

// SetVarbind represents one SNMP SET varbind: full numeric OID, value,
// and net-snmp type letter (i/u/s/x/a).
//
// Construct via NewSetVarbind, which validates the type letter.
type SetVarbind struct {
	OID        string
	Value      any
	TypeLetter string
}

// NewSetVarbind creates a SetVarbind with validation of the type letter.
//
// The type letter must be one of: i (INTEGER), u (Gauge32/unsigned),
// s (string), x (hex/octet string), a (IP address). Returns a plain
// (non-ErrSNMP-wrapped) error if the type letter is invalid, mirroring
// Python's ValueError.
func NewSetVarbind(oid string, value any, typeLetter string) (SetVarbind, error) {
	validLetters := map[string]bool{"i": true, "u": true, "s": true, "x": true, "a": true}
	if !validLetters[typeLetter] {
		return SetVarbind{}, fmt.Errorf("unknown SET type letter %q; expected one of [a i s u x]", typeLetter)
	}
	return SetVarbind{OID: oid, Value: value, TypeLetter: typeLetter}, nil
}

// WriteClient is the SNMP v2c read+write client interface for a single switch.
//
// It extends Client with SET operations. SetMany is one PDU (atomic).
// A write RW community can also read, so a single write client verifies
// its own writes via the inherited Get/Walk methods.
type WriteClient interface {
	Client
	Set(ctx context.Context, vb SetVarbind) error
	SetMany(ctx context.Context, vbs []SetVarbind) error
}

// errOID is an unexported helper that creates an error wrapping model.ErrSNMP
// with the OID included in the message.
func errOID(oid string, format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	return fmt.Errorf("%s at %s: %w", msg, oid, model.ErrSNMP)
}
