// switch_write.go: the public Switch write methods, mirroring Python's
// SyncSwitch write methods (sync_api.py) -- every method below is a thin
// writeVia wrapper. writeVia (write_dispatch.go) resolves exactly ONE
// backend per call -- o.Backend if set, else this Switch's pinned model
// default -- builds/reuses that single BackendWriter, and runs the op over
// it; there is NO fallback to a second backend under any circumstance, and
// an op that backend can't serve raises naming it (wrapping
// model.ErrUnsupportedCapability), exactly paralleling switch.go's read
// methods and readVia. Ported from the pinned Python source (that repo is
// read-only from here); any discrepancy between this file and the pinned
// Python source is a bug in this file. See
// docs/superpowers/plans/2026-07-30-slice-04-dossier-snmp-write.md (D-WR)
// §3 for the full semantics this file implements.

package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// Write carries the per-call options every disruptive write method takes,
// mirroring Python's `force: bool = False` keyword-only parameter (spec
// §5's options struct). Force overrides the protected-port guard(s) each
// BackendWriter method applies internally (see snmp.Writer's per-method
// docs, D-WR §2.4-§2.13) -- the facade itself forwards Force through
// unchanged; it does NOT re-implement any per-op guard (those live in the
// writer, per Task 5's brief correction), with the SOLE exception of
// DeleteVlan's facade-level member-guard below (D-WR §3.3), which is
// deliberately duplicated at this layer so every backend gets the same
// safety rail regardless of which one ends up serving the delete.
type Write struct {
	Force bool
	// Backend, if set, runs THIS write call over exactly that backend,
	// overriding both this Switch's pinned default (WithBackend) and the
	// model's own highest-preference backend -- the write-side twin of
	// ReadOption/WithReadBackend (D-REC A.10.3). Writes reuse this ALREADY-
	// mandatory options struct rather than a second, parallel functional-
	// option mechanism: every write call site already passes a Write{}
	// value at minimum, so extending it costs nothing at existing call
	// sites (nil is already what every caller not touching this field
	// gets). The named backend must be one the model declares or the call
	// raises naming it (resolveBackend's "no such backend" shape,
	// dispatch.go); it need not be one that can actually serve the
	// operation -- an op it cannot serve still raises, never silently
	// falling back to a different backend.
	Backend *model.Backend
}

// CycleOption configures a PoE cycle/clear-fault call's poll timeouts,
// mirroring Python's cycle_poe/clear_poe_fault accepting a `timeouts`
// keyword argument (defaulting to snmp.DefaultPoeCycleTimeouts()) -- a
// functional option here since Go has no keyword arguments. See
// WithCycleTimeouts.
type CycleOption func(*snmp.PoeCycleTimeouts)

// WithCycleTimeouts overrides the default PoE cycle timeouts
// (30s/60s/2s -- snmp.DefaultPoeCycleTimeouts) for one CyclePoE/
// ClearPoEFault call.
func WithCycleTimeouts(t snmp.PoeCycleTimeouts) CycleOption {
	return func(pt *snmp.PoeCycleTimeouts) { *pt = t }
}

// cycleTimeoutsFromOptions applies opts (in order) to
// snmp.DefaultPoeCycleTimeouts(), mirroring Python's default-then-override
// keyword-argument shape.
func cycleTimeoutsFromOptions(opts []CycleOption) snmp.PoeCycleTimeouts {
	timeouts := snmp.DefaultPoeCycleTimeouts()
	for _, opt := range opts {
		opt(&timeouts)
	}
	return timeouts
}

// SetPoE sets port's PoE admin state to on, dispatched through the resolved
// backend (o.Backend, or this Switch's default). The disruptive-direction
// protected-port guard (fires only when turning PoE off) lives entirely in
// the BackendWriter (snmp.Writer.SetPoE, D-WR §2.5); o.Force is forwarded
// unchanged.
func (s *Switch) SetPoE(ctx context.Context, port int, on bool, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetPoE(ctx, port, on, o.Force)
	})
}

// SetPortEnabled sets port's ifAdminStatus, dispatched through the resolved
// backend (o.Backend, or this Switch's default). The disruptive-direction
// protected-port guard (fires only when disabling) lives entirely in the
// BackendWriter (snmp.Writer.SetPortEnabled, D-WR §2.8); o.Force is
// forwarded unchanged.
func (s *Switch) SetPortEnabled(ctx context.Context, port int, enabled bool, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetPortEnabled(ctx, port, enabled, o.Force)
	})
}

// SetPortDescription labels port (ifAlias), dispatched through the resolved
// backend (o.Backend, or this Switch's default). Pass "" to clear the label.
// Cosmetic -- it moves no traffic and cannot strand a switch, so it is NOT
// force-gated beyond the ordinary protected-port guard every BackendWriter
// method applies internally (snmp.Writer.SetPortDescription, nsdp.Writer.
// SetPortDescription, fastpath.Writer.SetPortDescription, webui.Writer.
// SetPortDescription); o.Force is forwarded unchanged.
func (s *Switch) SetPortDescription(ctx context.Context, port int, description string, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetPortDescription(ctx, port, description, o.Force)
	})
}

// SetPortSpeed forces port's speed/duplex, or returns it to auto-negotiation
// (model.AutoPortSpeed()), dispatched through the resolved backend
// (o.Backend, or this Switch's default). DISRUPTIVE -- applying either
// bounces the link -- so the protected-port guard every BackendWriter method
// applies internally (snmp.Writer.SetPortSpeed, fastpath.Writer.
// SetPortSpeed, webui.Writer.SetPortSpeed; nsdp.Writer.SetPortSpeed always
// refuses) fires unless o.Force overrides it. SNMP and NSDP refuse this op
// by name (wrapping model.ErrUnsupportedCapability): neither backend
// exposes a genuine CONFIGURED-speed column, only the negotiated rate.
func (s *Switch) SetPortSpeed(ctx context.Context, port int, speed PortSpeed, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetPortSpeed(ctx, port, speed, o.Force)
	})
}

// SetFlowControl turns IEEE 802.3x flow control on or off for port,
// dispatched through the resolved backend (o.Backend, or this Switch's
// default). Served only over the FASTPATH CLI (fastpath.Writer.
// SetFlowControl); SNMP, NSDP and HTTP all refuse this op by name (wrapping
// model.ErrUnsupportedCapability) -- SNMP has never issued a SET against
// dot3PauseAdminMode, NSDP has no write tag for it, and the HTTP web UIs
// measured here carry no control for it at all. o.Force is forwarded
// unchanged to the CLI backend's protected-port guard.
func (s *Switch) SetFlowControl(ctx context.Context, port int, enabled bool, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetFlowControl(ctx, port, enabled, o.Force)
	})
}

// SetPVID sets port's default/untagged VLAN, dispatched through the
// resolved backend (o.Backend, or this Switch's default). The unconditional
// protected-port guard lives entirely in the BackendWriter (snmp.Writer.
// SetPVID, D-WR §2.9); o.Force is forwarded unchanged.
func (s *Switch) SetPVID(ctx context.Context, port, vlan int, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetPVID(ctx, port, vlan, o.Force)
	})
}

// SetVlanMembership sets port's membership mode within vlanID, dispatched
// through the resolved backend (o.Backend, or this Switch's default). The
// unconditional protected-port guard lives entirely in the BackendWriter
// (snmp.Writer.SetVlanMembership, D-WR §2.10); o.Force is forwarded
// unchanged.
func (s *Switch) SetVlanMembership(ctx context.Context, vlanID, port int, mode VlanMode, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetVlanMembership(ctx, vlanID, port, mode, o.Force)
	})
}

// CreateVlan creates vlanID with the given name, dispatched through the
// resolved backend (o.Backend, or this Switch's default). CreateVlan never
// guards on protected ports (an empty VLAN has no member ports by
// construction, D-WR §2.11); the underlying BackendWriter.CreateVlan takes
// no force parameter at all, so o.Force is not forwarded -- only o.Backend
// is consulted.
func (s *Switch) CreateVlan(ctx context.Context, vlanID int, name string, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.CreateVlan(ctx, vlanID, name)
	})
}

// DeleteVlan destroys vlanID, dispatched through the resolved backend
// (o.Backend, or this Switch's default). Unlike every other write method,
// this ALSO runs a facade-level guard (guardVLANDeleteMembers, D-WR §3.3)
// BEFORE dispatch: a GetVLANs read over the SAME backend the delete itself
// will use (D-REC A.7/A.10.7 -- new plumbing versus the pre-reconciliation
// Go source, which always read over the facade default regardless of
// o.Backend) checks the target VLAN's member ports against s.protectedPorts,
// refusing with the SAME message text snmp.Writer.DeleteVlan's own internal
// guard uses -- so every backend gets the same safety rail even though only
// the SNMP writer enforces it natively today. The guard degrades SILENTLY
// (no error) if that backend can't even read VLANs, and is skipped entirely
// when o.Force is true.
func (s *Switch) DeleteVlan(ctx context.Context, vlanID int, o Write) error {
	if err := s.guardVLANDeleteMembers(ctx, vlanID, o.Force, o.Backend); err != nil {
		return err
	}
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.DeleteVlan(ctx, vlanID, o.Force)
	})
}

// readOptsForBackend converts a write-side *model.Backend override
// (Write.Backend, possibly nil) into the ReadOption slice
// guardVLANDeleteMembers's internal GetVLANs read needs to run over the
// SAME backend the delete itself will use (D-REC A.7/A.10.7): nil yields no
// options, so GetVLANs falls through to its own default resolution --
// identical to what the delete's own writeVia call uses for backend=nil.
func readOptsForBackend(b *model.Backend) []ReadOption {
	if b == nil {
		return nil
	}
	return []ReadOption{WithReadBackend(*b)}
}

// guardVLANDeleteMembers is the facade-level duplicate of
// snmp.Writer.DeleteVlan's own protected-port guard, mirroring Python's
// SyncSwitch._guard_vlan_delete_members exactly (D-WR §3.3): if force is
// true, it is a no-op. Otherwise it reads VLANs over the SAME backend the
// delete itself will use (backend, threaded through as a ReadOption -- D-REC
// A.7/A.10.7); an UnsupportedCapability failure there (that backend can't
// even read VLANs) degrades SILENTLY -- an inability to check is not treated
// as a reason to block the delete -- while any OTHER error propagates. If
// the target VLAN is found, its MemberPorts are intersected with
// s.protectedPorts; a non-empty clash raises an error wrapping
// model.ErrProtectedPort with the EXACT message text snmp.Writer.DeleteVlan's
// own guard uses (formatIntList below is a deliberate byte-identical
// duplicate of the snmp package's private helper of the same name, per D-WR
// trap #10 -- both copies must stay in sync).
func (s *Switch) guardVLANDeleteMembers(ctx context.Context, vlanID int, force bool, backend *model.Backend) error {
	if force {
		return nil
	}
	vlans, err := s.GetVLANs(ctx, readOptsForBackend(backend)...)
	if err != nil {
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return nil
		}
		return err
	}
	for _, v := range vlans {
		if v.VlanID != vlanID {
			continue
		}
		var clash []int
		for _, p := range v.MemberPorts {
			if s.isProtected(p) {
				clash = append(clash, p)
			}
		}
		if len(clash) > 0 {
			return fmt.Errorf(
				"VLAN %d includes protected port(s) %s; pass force=True to delete it anyway: %w",
				vlanID, formatIntList(clash), model.ErrProtectedPort,
			)
		}
		return nil
	}
	return nil
}

// isProtected reports whether port is one of s.protectedPorts.
func (s *Switch) isProtected(port int) bool {
	for _, p := range s.protectedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// formatIntList renders ports as a Python-`sorted(...)`-style bracketed,
// comma-separated list (e.g. "[1, 2, 10]") -- a deliberate byte-identical
// duplicate of snmp/writer_vlan.go's private formatIntList (D-WR §3.3/trap
// #10: the facade-level and writer-level DeleteVlan guards must render the
// SAME message text). ports is expected already sorted ascending (this
// codebase's canonical VLANInfo.MemberPorts convention), so no extra sort
// call is needed here.
func formatIntList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// SetHostname sets the switch's host name, dispatched through the resolved
// backend (o.Backend, or this Switch's default).
//
// Written over SNMP (sysName), NSDP (the HOSTNAME tag), the FASTPATH CLI
// (hostname), or the web UI (GS110EMX's read-modify-write sysInfo form, or
// the GS728TPP's GoAhead DeviceBasicInfo/deviceName), whichever backend
// resolves. NOT force-gated: renaming cannot strand a switch and is
// reversible by writing the old name back, unlike SetMgmtIP, which drops
// the session that issues it. o.Force is forwarded unchanged, but every
// backend ignores it -- accepted only so the signature matches every other
// writer.
func (s *Switch) SetHostname(ctx context.Context, name string, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetHostname(ctx, name, o.Force)
	})
}

// SetMgmtIP sets the switch's own management IP (address/netmask/gateway),
// dispatched through the resolved backend (o.Backend, or this Switch's
// default). The unconditional force-gate (force=false ALWAYS refuses,
// independent of protected_ports -- a bad mgmt-IP write can strand the
// entire switch) lives entirely in the BackendWriter (snmp.Writer.
// SetMgmtIP, D-WR §2.13); o.Force is forwarded unchanged -- the facade adds
// no separate check of its own.
func (s *Switch) SetMgmtIP(ctx context.Context, address, netmask, gateway string, o Write) error {
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.SetMgmtIP(ctx, address, netmask, gateway, o.Force)
	})
}

// CyclePoE power-cycles port's PoE (off, poll until off, on, poll until
// delivering), dispatched through the resolved backend (o.Backend, or this
// Switch's default). The unconditional protected-port guard lives entirely
// in the BackendWriter (snmp.Writer.CyclePoE, D-WR §2.7); o.Force is
// forwarded unchanged. opts override the default PoE cycle timeouts
// (snmp.DefaultPoeCycleTimeouts).
func (s *Switch) CyclePoE(ctx context.Context, port int, o Write, opts ...CycleOption) error {
	timeouts := cycleTimeoutsFromOptions(opts)
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.CyclePoE(ctx, port, timeouts, o.Force)
	})
}

// ClearPoEFault re-arms port's PoE the same way CyclePoE does, but with a
// looser recovery predicate (leaving FAULT is enough; delivering is not
// required), dispatched through the resolved backend (o.Backend, or this
// Switch's default). The unconditional protected-port guard lives entirely
// in the BackendWriter (snmp.Writer.ClearPoEFault, D-WR §2.7); o.Force is
// forwarded unchanged. opts override the default PoE cycle timeouts.
func (s *Switch) ClearPoEFault(ctx context.Context, port int, o Write, opts ...CycleOption) error {
	timeouts := cycleTimeoutsFromOptions(opts)
	return s.writeVia(ctx, o.Backend, func(w BackendWriter) error {
		return w.ClearPoEFault(ctx, port, timeouts, o.Force)
	})
}
