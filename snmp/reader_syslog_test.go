package snmp

// Tests for Reader.GetSyslog: served over the vendor `.14` logging subtree
// for a model with a Netgear vendor OID base, refused BY NAME on a model
// that has none (gs728tpp), mirroring Python SnmpReader.get_syslog
// (snmp_read.py:224-252).

import (
	"context"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestGetSyslogReadsAdminModeLocalPortAndHostTable(t *testing.T) {
	vo := syslogVendor(t)
	tables := map[string][]Row{
		vo.SyslogAdminMode:    {NewIntRow(vo.SyslogAdminMode, 1)},
		vo.SyslogLocalPort:    {NewIntRow(vo.SyslogLocalPort, 514)},
		vo.SyslogHostAddr:     strRows(vo.SyslogHostAddr, map[int]string{1: "10.1.5.1"}),
		vo.SyslogHostPort:     intRows(vo.SyslogHostPort, map[int]int64{1: 514}),
		vo.SyslogHostSeverity: intRows(vo.SyslogHostSeverity, map[int]int64{1: 6}),
		vo.SyslogHostStatus:   intRows(vo.SyslogHostStatus, map[int]int64{1: 1}),
	}
	fc := newFakeReaderClient(tables)
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	cfg, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog: %v", err)
	}
	if !cfg.Enabled || cfg.LocalPort != 514 {
		t.Errorf("cfg = %+v, want Enabled=true LocalPort=514", cfg)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Host != "10.1.5.1" {
		t.Errorf("Servers = %+v, want one row for 10.1.5.1", cfg.Servers)
	}
}

// TestGetSyslogEmptyHostTableIsHonestlyEmpty proves a model with a vendor
// subtree but no collectors configured (gsm7228ps, measured 2026-08-02)
// reports zero servers rather than an error.
func TestGetSyslogEmptyHostTableIsHonestlyEmpty(t *testing.T) {
	vo, err := GetVendorOids(mustModel(t, "gsm7228ps"))
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	tables := map[string][]Row{
		vo.SyslogAdminMode: {NewIntRow(vo.SyslogAdminMode, 2)},
		vo.SyslogLocalPort: {NewIntRow(vo.SyslogLocalPort, 514)},
	}
	fc := newFakeReaderClient(tables)
	r, err := NewReader(fc, mustModel(t, "gsm7228ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	cfg, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog: %v", err)
	}
	if cfg.Enabled || len(cfg.Servers) != 0 {
		t.Errorf("cfg = %+v, want Enabled=false and no servers", cfg)
	}
}

// errAtOIDClient wraps fakeReaderClient so Get/Walk fails with err for the
// exact OID/base named failOn, and otherwise delegates normally -- used to
// prove GetSyslog propagates a transport error from any of its three calls
// (admin-mode GET, local-port GET, or the host-table walk) rather than
// swallowing it.
type errAtOIDClient struct {
	*fakeReaderClient
	failOn string
	err    error
}

func (e *errAtOIDClient) Get(ctx context.Context, oids []string) ([]Row, error) {
	for _, o := range oids {
		if o == e.failOn {
			return nil, e.err
		}
	}
	return e.fakeReaderClient.Get(ctx, oids)
}

func (e *errAtOIDClient) Walk(ctx context.Context, base string) ([]Row, error) {
	if base == e.failOn {
		return nil, e.err
	}
	return e.fakeReaderClient.Walk(ctx, base)
}

func TestGetSyslogPropagatesTransportErrorFromAnyCall(t *testing.T) {
	vo := syslogVendor(t)
	wantErr := errors.New("boom")
	for _, failOn := range []string{vo.SyslogAdminMode, vo.SyslogLocalPort, vo.SyslogHostAddr} {
		failOn := failOn
		t.Run(failOn, func(t *testing.T) {
			client := &errAtOIDClient{fakeReaderClient: newFakeReaderClient(nil), failOn: failOn, err: wantErr}
			r, err := NewReader(client, mustModel(t, "gsm7252ps"))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			if _, err := r.GetSyslog(context.Background()); !errors.Is(err, wantErr) {
				t.Errorf("GetSyslog() error = %v, want wrapping %v", err, wantErr)
			}
		})
	}
}

// TestGetSyslogRefusesByNameOnNoVendorModel proves gs728tpp (no Netgear
// vendor OID subtree at all) is refused BY NAME, before any walk -- an
// empty result would be indistinguishable from "no collectors configured".
func TestGetSyslogRefusesByNameOnNoVendorModel(t *testing.T) {
	fc := newFakeReaderClient(nil)
	r, err := NewReader(fc, mustModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	cfg, err := r.GetSyslog(context.Background())
	if cfg.Enabled || cfg.LocalPort != 0 || len(cfg.Servers) != 0 {
		t.Errorf("GetSyslog() cfg = %+v, want zero value", cfg)
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetSyslog() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if len(fc.walked) != 0 || len(fc.getCalls) != 0 {
		t.Errorf("GetSyslog() issued I/O (walked=%v, getCalls=%v), want none -- refusal must fire before any", fc.walked, fc.getCalls)
	}
}
