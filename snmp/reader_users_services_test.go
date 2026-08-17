package snmp

// Tests for Reader.GetUsers/GetServices: SNMP refuses both BY NAME (never a
// fabricated empty list), mirroring Python SnmpReader.get_users/
// get_services (snmp_read.py:265-274 + its get_services sibling). Users is
// deliberately NOT served over SNMP even though a vendor user table exists
// (the S3300's SNMP user table disagrees with its own CLI -- one user where
// the CLI shows two); services likewise CLI+HTTP only.

import (
	"context"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestGetUsersRefusesByNameBeforeAnyWalk(t *testing.T) {
	fc := newFakeReaderClient(nil)
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	users, err := r.GetUsers(context.Background())
	if users != nil {
		t.Errorf("GetUsers() users = %v, want nil", users)
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetUsers() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if len(fc.walked) != 0 || len(fc.getCalls) != 0 {
		t.Errorf("GetUsers() issued I/O (walked=%v, getCalls=%v), want none -- refusal must fire before any", fc.walked, fc.getCalls)
	}
}

func TestGetServicesRefusesByNameBeforeAnyWalk(t *testing.T) {
	fc := newFakeReaderClient(nil)
	r, err := NewReader(fc, mustModel(t, "m4300-24x"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	services, err := r.GetServices(context.Background())
	if services != nil {
		t.Errorf("GetServices() services = %v, want nil", services)
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetServices() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if len(fc.walked) != 0 || len(fc.getCalls) != 0 {
		t.Errorf("GetServices() issued I/O (walked=%v, getCalls=%v), want none -- refusal must fire before any", fc.walked, fc.getCalls)
	}
}
