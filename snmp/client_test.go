package snmp

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mithro/go-netgear-switch-library/model"
)

// TestRowConstructorsAndValues verifies Row constructors create correct values.
func TestRowConstructorsAndValues(t *testing.T) {
	tests := []struct {
		name    string
		row     Row
		wantOID string
		wantVal any
		wantTyp string
	}{
		{
			name:    "NewIntRow",
			row:     NewIntRow("1.3.6.1.2.1.1.1.0", 42),
			wantOID: "1.3.6.1.2.1.1.1.0",
			wantVal: int64(42),
			wantTyp: "",
		},
		{
			name:    "NewStrRow",
			row:     NewStrRow("1.3.6.1.2.1.1.1.0", "hello"),
			wantOID: "1.3.6.1.2.1.1.1.0",
			wantVal: "hello",
			wantTyp: "",
		},
		{
			name:    "NewBytesRow",
			row:     NewBytesRow("1.3.6.1.2.1.1.1.0", []byte{0xDE, 0xAD}),
			wantOID: "1.3.6.1.2.1.1.1.0",
			wantVal: []byte{0xDE, 0xAD},
			wantTyp: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.row.OID != tt.wantOID {
				t.Errorf("OID = %q, want %q", tt.row.OID, tt.wantOID)
			}
			if !cmp.Equal(tt.row.Value, tt.wantVal) {
				t.Errorf("Value = %v, want %v (diff: %s)", tt.row.Value, tt.wantVal, cmp.Diff(tt.wantVal, tt.row.Value))
			}
			if tt.row.SnmpType != tt.wantTyp {
				t.Errorf("SnmpType = %q, want %q", tt.row.SnmpType, tt.wantTyp)
			}
		})
	}
}

// TestRowEquality verifies Row equality via go-cmp.
func TestRowEquality(t *testing.T) {
	r1 := NewIntRow("1.3.6.1.2.1.1.1.0", 42)
	r2 := NewIntRow("1.3.6.1.2.1.1.1.0", 42)
	r3 := NewIntRow("1.3.6.1.2.1.1.1.0", 43)

	if !cmp.Equal(r1, r2) {
		t.Errorf("identical rows should be equal")
	}
	if cmp.Equal(r1, r3) {
		t.Errorf("rows with different values should not be equal")
	}
}

// TestRowHashable verifies Row can be used as a map key.
func TestRowHashable(t *testing.T) {
	r1 := NewIntRow("1.3.6.1.2.1.1.1.0", 42)
	r2 := NewIntRow("1.3.6.1.2.1.1.1.0", 42)

	m := make(map[Row]bool)
	m[r1] = true

	if !m[r2] {
		t.Errorf("identical rows should hash to same key")
	}
}

// TestAbsentTypes verifies AbsentTypes contains the three sentinel types.
func TestAbsentTypes(t *testing.T) {
	tests := []struct {
		name     string
		typeName string
		wantOK   bool
	}{
		{"NOSUCHOBJECT", "NOSUCHOBJECT", true},
		{"NOSUCHINSTANCE", "NOSUCHINSTANCE", true},
		{"ENDOFMIBVIEW", "ENDOFMIBVIEW", true},
		{"NOTABSENT", "NOTABSENT", false},
		{"integer", "integer", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok := AbsentTypes[tt.typeName]
			if ok != tt.wantOK {
				t.Errorf("AbsentTypes[%q] = %v, want %v", tt.typeName, ok, tt.wantOK)
			}
		})
	}
}

// TestFullOID verifies the FullOID function strips leading dots and joins correctly.
func TestFullOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      string
		index    string
		wantFull string
	}{
		{
			name:     "with leading dot and index",
			oid:      ".1.3.6.1.2.1.2.2.1.8",
			index:    "1",
			wantFull: "1.3.6.1.2.1.2.2.1.8.1",
		},
		{
			name:     "without leading dot and index",
			oid:      "1.3.6.1.2.1.2.2.1.8",
			index:    "1",
			wantFull: "1.3.6.1.2.1.2.2.1.8.1",
		},
		{
			name:     "with leading dot, no index",
			oid:      ".1.3.6.1.2.1.2.2.1.8.1",
			index:    "",
			wantFull: "1.3.6.1.2.1.2.2.1.8.1",
		},
		{
			name:     "without leading dot, no index",
			oid:      "1.3.6.1.2.1.2.2.1.8.1",
			index:    "",
			wantFull: "1.3.6.1.2.1.2.2.1.8.1",
		},
		{
			name:     "multiple leading dots",
			oid:      "...1.3.6.1",
			index:    "1",
			wantFull: "1.3.6.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FullOID(tt.oid, tt.index)
			if got != tt.wantFull {
				t.Errorf("FullOID(%q, %q) = %q, want %q", tt.oid, tt.index, got, tt.wantFull)
			}
		})
	}
}

// TestSetVarbindValidation verifies NewSetVarbind validates type letters.
func TestSetVarbindValidation(t *testing.T) {
	tests := []struct {
		name       string
		oid        string
		value      any
		typeLetter string
		wantErr    bool
	}{
		{"valid i", "1.3.6.1.2.1.1.1.0", int64(42), "i", false},
		{"valid u", "1.3.6.1.2.1.1.1.0", int64(42), "u", false},
		{"valid s", "1.3.6.1.2.1.1.1.0", "hello", "s", false},
		{"valid x", "1.3.6.1.2.1.1.1.0", []byte{0xDE, 0xAD}, "x", false},
		{"valid a", "1.3.6.1.2.1.1.1.0", "192.168.1.1", "a", false},
		{"invalid b", "1.3.6.1.2.1.1.1.0", "value", "b", true},
		{"invalid I (uppercase)", "1.3.6.1.2.1.1.1.0", int64(42), "I", true},
		{"invalid empty", "1.3.6.1.2.1.1.1.0", "value", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSetVarbind(tt.oid, tt.value, tt.typeLetter)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSetVarbind(..., %q) error = %v, want error = %v", tt.typeLetter, err, tt.wantErr)
			}
			// Verify that invalid type letter errors are NOT ErrSNMP wraps
			if err != nil && tt.wantErr {
				if errors.Is(err, model.ErrSNMP) {
					t.Errorf("invalid type letter should return plain error, not wrapped ErrSNMP")
				}
			}
		})
	}
}

// TestSetVarbindCreation verifies successful SetVarbind creation.
func TestSetVarbindCreation(t *testing.T) {
	vb, err := NewSetVarbind("1.3.6.1.2.1.1.1.0", int64(42), "i")
	if err != nil {
		t.Fatalf("NewSetVarbind failed: %v", err)
	}

	if vb.OID != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("OID = %q, want %q", vb.OID, "1.3.6.1.2.1.1.1.0")
	}
	if vb.Value != int64(42) {
		t.Errorf("Value = %v, want %v", vb.Value, int64(42))
	}
	if vb.TypeLetter != "i" {
		t.Errorf("TypeLetter = %q, want %q", vb.TypeLetter, "i")
	}
}

// TestErrOIDFormat verifies errOID wraps ErrSNMP and includes OID in message.
func TestErrOIDFormat(t *testing.T) {
	oid := "1.3.6.1.2.1.1.1.0"
	err := errOID(oid, "invalid value %q", "bad")

	// Check that error wraps model.ErrSNMP
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("errOID error should wrap model.ErrSNMP")
	}

	// Check that OID is in message
	errMsg := err.Error()
	if !contains(errMsg, oid) {
		t.Errorf("errOID message %q should contain OID %q", errMsg, oid)
	}
}

// TestClientInterface verifies Client interface can be implemented.
func TestClientInterface(_ *testing.T) {
	// This is a compile-time check; we're just verifying the interface exists
	// and can be used in a type assertion.
	var _ Client = (*mockClient)(nil)
}

// TestWriteClientInterface verifies WriteClient interface can be implemented.
func TestWriteClientInterface(_ *testing.T) {
	// This is a compile-time check; we're just verifying the interface exists
	// and embeds Client.
	var _ WriteClient = (*mockWriteClient)(nil)
}

// Mock implementations for interface checks
type mockClient struct{}

func (m *mockClient) Get(_ context.Context, _ []string) ([]Row, error) {
	return nil, nil
}

func (m *mockClient) Walk(_ context.Context, _ string) ([]Row, error) {
	return nil, nil
}

type mockWriteClient struct{}

func (m *mockWriteClient) Get(_ context.Context, _ []string) ([]Row, error) {
	return nil, nil
}

func (m *mockWriteClient) Walk(_ context.Context, _ string) ([]Row, error) {
	return nil, nil
}

func (m *mockWriteClient) Set(_ context.Context, _ SetVarbind) error {
	return nil
}

func (m *mockWriteClient) SetMany(_ context.Context, _ []SetVarbind) error {
	return nil
}

// Helper function for string containment
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
