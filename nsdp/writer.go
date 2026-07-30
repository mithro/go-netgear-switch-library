package nsdp

// writer.go: model-driven NSDP write facade, ported field-for-field from
// src/netgear_switch/nsdp_write.py at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy
// between this file and that pin is a bug in this file, not a deliberate
// deviation, unless called out in a comment.
//
// Every supported write here performs the NSDP WRITE_REQUEST (v1-
// authenticated, via WriteClient.Write) then re-reads through this Writer's
// own internal Reader to verify (*model.WriteVerificationError with
// before/after on mismatch) -- never a raw client Read call directly,
// mirroring Python's NsdpWriter holding its own private NsdpReader.
// Disruptive per-port writes to a protected port are refused unless
// force=true. Writes NSDP has no tag for (PoE, per-port admin, VLAN
// create/delete) return an error wrapping model.ErrUnsupportedCapability --
// never a silent no-op.
//
// NOTE on scope: Python's NsdpWriter also defines cycle_poe/clear_poe_fault
// (both unconditionally raising the same PoE-unsupported error as set_poe,
// with an accepted-but-unused timeouts parameter purely to typecheck against
// the facade's SnmpWriter|NsdpWriter union). This package deliberately does
// NOT port those two methods: this slice's progress ledger already recorded
// the decision that the PoeCycleTimeouts type's package "home" is deferred
// to Slice 06, and NSDP's writer has no cycle ops of its own to hang a
// timeouts parameter off. The facade wiring (Slice 05 Task 7) is expected to
// answer CyclePoE/ClearPoEFault for the NSDP backend with a constant
// model.ErrUnsupportedCapability adapter that never calls into this
// package, exactly as it would for any other backend method this package
// doesn't implement.

import (
	"context"
	"fmt"
	"slices"

	"github.com/mithro/go-netgear-switch-library/model"
)

// NoPoEWriteMsg is the exact message SetPoE below wraps in every error it
// returns, mirroring Python nsdp_write.py's _NO_POE module constant
// verbatim. Exported so callers outside this package that must surface the
// identical "NSDP has no PoE control tag" text -- without themselves calling
// into a Writer (e.g. the root package's CyclePoE/ClearPoEFault adapter
// stubs in backend_nsdp.go, which this package's own doc comment on Writer
// explicitly defers to the facade layer) -- can reference this constant
// instead of duplicating the string.
const NoPoEWriteMsg = "NSDP has no PoE control tag; use the HTTP backend (Slice 6) for PoE"

// Exact unsupported-write messages for the two remaining unsupported
// writes, mirroring Python nsdp_write.py's _NO_PORT_ADMIN/
// _NO_VLAN_LIFECYCLE module constants verbatim. Unexported: nothing outside
// this package needs to reproduce these two messages independently (unlike
// NoPoEWriteMsg above).
const (
	noPortAdminMsg = "no per-port admin-enable is available on these Plus models: NSDP has no " +
		"admin-enable tag, and the web UI has no grounded port-enable endpoint " +
		"(UNVERIFIED-pending-capture)"
	noVLANLifecycleMsg = "NSDP has no VLAN create/destroy tag on these Plus models; only VLAN " +
		"membership/PVID are writable over NSDP"
)

// unsupportedWrite wraps model.ErrUnsupportedCapability with msg verbatim,
// mirroring Python's raise UnsupportedCapabilityError(msg).
func unsupportedWrite(msg string) error {
	return fmt.Errorf("%s: %w", msg, model.ErrUnsupportedCapability)
}

// Writer is a model-driven NSDP write facade, mirroring Python's
// NsdpWriter. Every write issues the WRITE_REQUEST(s) then re-reads and
// verifies via its own internal Reader (never a raw client call directly).
type Writer struct {
	client         WriteClient
	model          *model.SwitchModel
	password       string
	protectedPorts map[int]bool
	reader         *Reader
}

// WriterOption configures optional Writer construction parameters (only
// protected-ports today) via the functional-options pattern already used by
// snmp.Writer (see snmp/writer.go's WithProtectedPorts).
type WriterOption func(*Writer)

// WithProtectedPorts marks ports as protected: every disruptive write to a
// protected port is refused unless force is passed as true, mirroring
// Python's NsdpWriter(..., protected_ports=frozenset({...})).
func WithProtectedPorts(ports ...int) WriterOption {
	return func(w *Writer) {
		for _, p := range ports {
			w.protectedPorts[p] = true
		}
	}
}

// NewWriter constructs a Writer bound to c and m, authenticating every
// subsequent write with password.
//
// m must have an NSDP backend (model.BackendNSDP in m.Backends); a model
// without one returns an error wrapping model.ErrUnsupportedCapability
// BEFORE any I/O -- this is the single capability gate for the whole
// writer (delegated to NewReader, which performs the identical check with
// the identical message), matching Python's _require_nsdp being called
// once, in the constructor, before anything else. No method below
// re-checks it.
func NewWriter(c WriteClient, m *model.SwitchModel, password string, opts ...WriterOption) (*Writer, error) {
	reader, err := NewReader(c, m)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		client:         c,
		model:          m,
		password:       password,
		protectedPorts: make(map[int]bool),
		reader:         reader,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// guard is the single protected-port gate SetPVID/SetVlanMembership call:
// it refuses port when port is protected and force is false, mirroring
// Python's NsdpWriter._guard verbatim (including the exact message text).
func (w *Writer) guard(port int, force bool) error {
	if w.protectedPorts[port] && !force {
		return fmt.Errorf("port %d is protected; pass force=True to override: %w", port, model.ErrProtectedPort)
	}
	return nil
}

// vlan returns vlanID's current VLANInfo via the internal reader, or nil if
// absent from the device's VLAN table. Mirrors Python's NsdpWriter._vlan.
func (w *Writer) vlan(ctx context.Context, vlanID int) (*model.VLANInfo, error) {
	vlans, err := w.reader.GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	for i := range vlans {
		if vlans[i].VlanID == vlanID {
			return &vlans[i], nil
		}
	}
	return nil, nil
}

// pvidMap builds a port->vlan lookup from pairs, mirroring Python's
// `dict(self._reader.get_pvids())`.
func pvidMap(pairs []model.Pvid) map[int]int {
	m := make(map[int]int, len(pairs))
	for _, p := range pairs {
		m[p.Port] = p.Vlan
	}
	return m
}

// pvidLookup returns (m[port], true) rendered as an `any` for
// *model.WriteVerificationError's Before/After fields -- nil when port is
// absent, mirroring Python's `before.get(port)` (None on a missing key).
func pvidLookup(m map[int]int, port int) any {
	if v, ok := m[port]; ok {
		return v
	}
	return nil
}

// SetPVID sets port's default/untagged VLAN (PVID) to vlan and verifies the
// change read back correctly. Ported from Python's NsdpWriter.set_pvid.
//
// UNVERIFIED pending a hardware capture: PORT_PVID (0x3000) is documented
// READ-ONLY in the reference spec, so a real switch may reject this write
// -- the read-after verify below is the runtime guard. The guard is
// UNCONDITIONAL (any PVID change is disruptive). One WRITE_REQUEST with a
// single PvidTLV. Verify: re-read the full PVID list via the internal
// reader's GetPVIDs and check the exact (port, vlan) pair is present.
func (w *Writer) SetPVID(ctx context.Context, port, vlan int, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	beforePairs, err := w.reader.GetPVIDs(ctx)
	if err != nil {
		return err
	}
	before := pvidMap(beforePairs)

	tlv, err := PvidTLV(port, vlan)
	if err != nil {
		return err
	}
	if _, err := w.client.Write(ctx, []TLVEntry{tlv}, w.password); err != nil {
		return err
	}

	afterPairs, err := w.reader.GetPVIDs(ctx)
	if err != nil {
		return err
	}
	after := pvidMap(afterPairs)

	if gotVlan, ok := after[port]; !ok || gotVlan != vlan {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PVID for port %d did not read back as %d", port, vlan),
			Before: pvidLookup(before, port),
			After:  pvidLookup(after, port),
		}
	}
	return nil
}

// membersAfter computes the read-modify-write (members, tagged) port sets
// for one membership change, mirroring Python's module-level
// _members_after: current is nil when the VLAN doesn't exist yet (treated
// as empty member/tagged sets). Both returned slices are sorted ascending
// and non-nil, matching this package's canonical-port-set convention.
func membersAfter(current *model.VLANInfo, port int, mode model.VlanMode) (members, tagged []int) {
	memberSet := map[int]bool{}
	taggedSet := map[int]bool{}
	if current != nil {
		for _, p := range current.MemberPorts {
			memberSet[p] = true
		}
		for _, p := range current.TaggedPorts {
			taggedSet[p] = true
		}
	}
	if mode == model.VlanExcluded {
		delete(memberSet, port)
		delete(taggedSet, port)
	} else {
		memberSet[port] = true
		if mode == model.VlanTagged {
			taggedSet[port] = true
		} else {
			delete(taggedSet, port)
		}
	}
	return sortedKeys(memberSet), sortedKeys(taggedSet)
}

// sortedKeys returns set's keys in ascending order.
func sortedKeys(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// membershipOK reports whether after reflects port having been set to mode,
// mirroring Python's module-level _membership_ok exactly (including its
// after==nil special case: a VLAN that vanished/never existed after the
// write is only "ok" for VlanExcluded, since excluding a port from a
// nonexistent VLAN is trivially satisfied).
func membershipOK(after *model.VLANInfo, port int, mode model.VlanMode) bool {
	if after == nil {
		return mode == model.VlanExcluded
	}
	inMembers := slices.Contains(after.MemberPorts, port)
	inTagged := slices.Contains(after.TaggedPorts, port)
	if mode == model.VlanExcluded {
		return !inMembers
	}
	return inMembers && (inTagged == (mode == model.VlanTagged))
}

// SetVlanMembership sets port's membership mode (untagged/tagged/excluded)
// within vlanID and verifies the change read back correctly. Ported from
// Python's NsdpWriter.set_vlan_membership.
//
// UNVERIFIED pending a hardware capture: VLAN_MEMBERS (0x2800) is
// documented READ-ONLY in the reference spec, so a real switch may reject
// this write -- the read-after verify below is the runtime guard. The
// guard is UNCONDITIONAL (any membership change is disruptive). The
// read-modify-write re-encodes the CURRENTLY READ member/tagged sets (via
// membersAfter), widened by w.model.PortCount -- always model-derived,
// never a fixed default width. One WRITE_REQUEST with a single
// VlanMembersTLV. Verify: re-read vlanID via the internal reader's
// GetVLANs and check port's membership matches mode (via membershipOK).
func (w *Writer) SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	before, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}

	members, tagged := membersAfter(before, port, mode)
	tlv, err := VlanMembersTLV(vlanID, members, tagged, w.model.PortCount)
	if err != nil {
		return err
	}
	if _, err := w.client.Write(ctx, []TLVEntry{tlv}, w.password); err != nil {
		return err
	}

	after, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	if !membershipOK(after, port, mode) {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d membership for port %d did not read back as %s", vlanID, port, mode),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// mgmtIPMatches reports whether cfg's address/netmask/gateway all equal the
// requested values, mirroring Python's
// `(after.address, after.netmask, after.gateway) != (address, netmask, gateway)`
// tuple comparison: a nil field never matches (Python's `None != "..."` is
// always True), so this deliberately does NOT treat a nil pointer as
// equivalent to the empty string.
func mgmtIPMatches(cfg model.MgmtIPConfig, address, netmask, gateway string) bool {
	return cfg.Address != nil && *cfg.Address == address &&
		cfg.Netmask != nil && *cfg.Netmask == netmask &&
		cfg.Gateway != nil && *cfg.Gateway == gateway
}

// SetMgmtIP sets the switch's own management IP (address/netmask/gateway)
// and verifies all three fields read back correctly. Ported from Python's
// NsdpWriter.set_mgmt_ip.
//
// force-gated UNCONDITIONALLY: force=false ALWAYS refuses (a bad mgmt-IP
// write can strand the entire switch), with the exact message text
// "set_mgmt_ip can strand the switch; pass force=True to override" --
// deliberately NOT the SNMP writer's longer "...and uses UNVERIFIED
// OIDs..." wording; the two backends' messages are pinned separately.
// UNVERIFIED pending a hardware capture: the NSDP write path + v1 auth are
// unconfirmed against real hardware -- the read-after verify below is the
// runtime guard. One WRITE_REQUEST with three IPv4 TLVs (IP_ADDRESS,
// NETMASK, GATEWAY, in that order). Unlike the SNMP writer's per-field
// verification message, a mismatch on ANY of the three fields raises the
// SAME generic message, matching Python's single tuple-inequality check
// exactly.
func (w *Writer) SetMgmtIP(ctx context.Context, address, netmask, gateway string, force bool) error {
	if !force {
		return fmt.Errorf("set_mgmt_ip can strand the switch; pass force=True to override: %w", model.ErrProtectedPort)
	}

	before, err := w.reader.GetMgmtIP(ctx)
	if err != nil {
		return err
	}

	addrTLV, err := IPv4TLV(TagIPAddress, address)
	if err != nil {
		return err
	}
	netmaskTLV, err := IPv4TLV(TagNetmask, netmask)
	if err != nil {
		return err
	}
	gatewayTLV, err := IPv4TLV(TagGateway, gateway)
	if err != nil {
		return err
	}
	if _, err := w.client.Write(ctx, []TLVEntry{addrTLV, netmaskTLV, gatewayTLV}, w.password); err != nil {
		return err
	}

	after, err := w.reader.GetMgmtIP(ctx)
	if err != nil {
		return err
	}
	if !mgmtIPMatches(after, address, netmask, gateway) {
		return &model.WriteVerificationError{
			Msg:    "management IP did not read back as written",
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetPoE always returns an error wrapping model.ErrUnsupportedCapability:
// NSDP has no PoE control tag. Mirrors Python's NsdpWriter.set_poe. Every
// parameter is accepted-but-unused, purely so this method's signature
// matches the shared BackendWriter surface (see write_dispatch.go).
func (w *Writer) SetPoE(_ context.Context, _ int, _ bool, _ bool) error {
	return unsupportedWrite(NoPoEWriteMsg)
}

// SetPortEnabled always returns an error wrapping
// model.ErrUnsupportedCapability: no per-port admin-enable is available on
// these Plus models. Mirrors Python's NsdpWriter.set_port_enabled. Every
// parameter is accepted-but-unused; see SetPoE's doc comment.
func (w *Writer) SetPortEnabled(_ context.Context, _ int, _ bool, _ bool) error {
	return unsupportedWrite(noPortAdminMsg)
}

// CreateVlan always returns an error wrapping
// model.ErrUnsupportedCapability: NSDP has no VLAN create/destroy tag on
// these Plus models. Mirrors Python's NsdpWriter.create_vlan. Every
// parameter is accepted-but-unused; see SetPoE's doc comment.
func (w *Writer) CreateVlan(_ context.Context, _ int, _ string) error {
	return unsupportedWrite(noVLANLifecycleMsg)
}

// DeleteVlan always returns an error wrapping
// model.ErrUnsupportedCapability: NSDP has no VLAN create/destroy tag on
// these Plus models. Mirrors Python's NsdpWriter.delete_vlan. Every
// parameter is accepted-but-unused; see SetPoE's doc comment.
func (w *Writer) DeleteVlan(_ context.Context, _ int, _ bool) error {
	return unsupportedWrite(noVLANLifecycleMsg)
}
