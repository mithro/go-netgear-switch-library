// snapshot.go: Switch.Snapshot, ported from src/netgear_switch/sync_api.py's
// SyncSwitch.snapshot (the normative source; that repo is read-only from
// here). Any discrepancy between this file and the pinned Python source is a
// bug in this file. See D-FAC (docs/superpowers/plans/
// 2026-07-30-slice-03-dossier-facade.md) §2.12 for the exact per-field
// degrade semantics this file implements.

package netgearswitch

import (
	"context"
	"errors"

	"github.com/mithro/go-netgear-switch-library/model"
)

// snapshotDegrade calls fn (a closure over one of Switch's read methods,
// already bound to ctx) and returns its result as-is on success. On error,
// it returns the zero value of T with a nil error IF the error wraps
// model.ErrUnsupportedCapability -- a capability gap degrades that field to
// empty/zero, mirroring Python's snapshot() `_opt` closure (D-FAC §2.12).
// Any OTHER error (notably one wrapping model.ErrCredential) is returned
// as-is, aborting Snapshot entirely: snapshot() degrades ONLY for capability
// gaps, never for credential/transport failures (D-FAC §2.12, trap #5's
// neighbor rule).
func snapshotDegrade[T any](fn func() (T, error)) (T, error) {
	v, err := fn()
	if err != nil {
		var zero T
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return zero, nil
		}
		return zero, err
	}
	return v, nil
}

// Snapshot reads every capability this switch's registered backends can
// serve into one SwitchData, degrading a per-field capability gap
// (model.ErrUnsupportedCapability) to that field's empty/zero value instead
// of failing the whole snapshot -- mirroring Python's SyncSwitch.snapshot
// exactly (D-FAC §2.12):
//
//   - Every tuple-shaped field (ports, stats, vlans, pvids, lldp, poe,
//     sensors) goes through snapshotDegrade, which runs the FULL readVia
//     dispatch loop internally, so per-op backend fallback still applies.
//   - mgmt_ip is the one field that is NOT tuple-shaped (a single
//     model.MgmtIPConfig, not a slice): it degrades to a nil pointer instead
//     of an empty slice, via the same snapshotDegrade helper.
//   - macs deliberately calls getMACsNoGate, NOT the public GetMACs: it does
//     NOT apply GetMACs's require_mac_table guard first, instead letting the
//     dispatch loop exhaust naturally to the same
//     model.ErrUnsupportedCapability outcome for a MAC-table-less model
//     (D-FAC §2.12/trap #5 -- do not "fix" this to call the guard too; it
//     would diverge from the reference's actual code path even though it
//     changes nothing observable for any real backend).
//   - A non-UnsupportedCapability error from ANY field (e.g. a misconfigured
//     SNMP read community surfacing as model.ErrCredential) aborts Snapshot
//     immediately, propagating that error to the caller -- Snapshot never
//     swallows a credential or transport failure.
func (s *Switch) Snapshot(ctx context.Context) (model.SwitchData, error) {
	if err := ctx.Err(); err != nil {
		return model.SwitchData{}, err
	}

	data := model.SwitchData{Model: s.model.Key, Host: s.host}
	var err error

	if data.Ports, err = snapshotDegrade(func() ([]model.PortStatus, error) { return s.GetPorts(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.Stats, err = snapshotDegrade(func() ([]model.PortStats, error) { return s.GetStats(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.Vlans, err = snapshotDegrade(func() ([]model.VLANInfo, error) { return s.GetVLANs(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.Pvids, err = snapshotDegrade(func() ([]model.Pvid, error) { return s.GetPVIDs(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.Lldp, err = snapshotDegrade(func() ([]model.LLDPNeighbor, error) { return s.GetLLDP(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.Macs, err = snapshotDegrade(func() ([]model.MacEntry, error) { return s.getMACsNoGate(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.PoE, err = snapshotDegrade(func() ([]model.PoEStatus, error) { return s.GetPoE(ctx) }); err != nil {
		return model.SwitchData{}, err
	}
	if data.Sensors, err = snapshotDegrade(func() ([]model.Sensor, error) { return s.GetSensors(ctx) }); err != nil {
		return model.SwitchData{}, err
	}

	mgmt, err := snapshotDegradePtr(func() (model.MgmtIPConfig, error) { return s.GetMgmtIP(ctx) })
	if err != nil {
		return model.SwitchData{}, err
	}
	data.MgmtIP = mgmt

	return data, nil
}

// snapshotDegradePtr is snapshotDegrade's mgmt_ip-shaped sibling: on a
// capability gap it returns (nil, nil) instead of a zero T, since mgmt_ip's
// field type is *model.MgmtIPConfig (Python's `MgmtIpConfig | None`), not a
// slice snapshotDegrade's zero value already handles correctly.
func snapshotDegradePtr(fn func() (model.MgmtIPConfig, error)) (*model.MgmtIPConfig, error) {
	v, err := fn()
	if err != nil {
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}
