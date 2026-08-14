package nsdp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// TestAuthV2PasswordKnownVector byte-verifies AuthV2Password against the
// upstream go-nsdp TestAuthV2Password vector (also pinned in Python
// tests/protocols/nsdp/test_auth.py) -- the authoritative known-answer test
// for this reverse-engineered scheme.
func TestAuthV2PasswordKnownVector(t *testing.T) {
	mac := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	salt := []byte{0x12, 0x34, 0x56, 0x78}
	want := []byte{0xc4, 0xaf, 0x7c, 0x00, 0xa6, 0xc4, 0x1a, 0x7d}
	got, err := AuthV2Password("password", mac, salt)
	if err != nil {
		t.Fatalf("AuthV2Password: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AuthV2Password = % x, want % x", got, want)
	}
}

func TestAuthV2Password_LengthAndASCIIValidation(t *testing.T) {
	mac := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	salt := []byte{0x12, 0x34, 0x56, 0x78}
	if _, err := AuthV2Password("pw", mac, []byte{1, 2, 3}); !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("short salt: want ErrNSDP, got %v", err)
	}
	if _, err := AuthV2Password("pw", []byte{1, 2, 3}, salt); !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("short MAC: want ErrNSDP, got %v", err)
	}
	if _, err := AuthV2Password("pw\x80", mac, salt); !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("non-ASCII password: want ErrNSDP, got %v", err)
	}
}

// TestAuthV2Password_TruncatesTo20 confirms only the first 20 password bytes
// feed the key (the web UI caps the field at 20 chars): a 25-char password and
// its 20-char prefix produce the same token.
func TestAuthV2Password_TruncatesTo20(t *testing.T) {
	mac := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	salt := []byte{0x12, 0x34, 0x56, 0x78}
	full, err := AuthV2Password("abcdefghijklmnopqrstUVWXY", mac, salt) // 25 chars
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := AuthV2Password("abcdefghijklmnopqrst", mac, salt) // first 20
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full, prefix) {
		t.Fatalf("token differs beyond 20 chars: %x vs %x", full, prefix)
	}
}

func TestEncpassIsV2(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte{0x00, 0x00, 0x00, 0x10}, true},
		{[]byte{0x10}, true},
		{[]byte{0x01}, false},
		{[]byte{0x00, 0x00, 0x00, 0x01}, false},
		{nil, false},
		{[]byte{}, false},
	}
	for _, c := range cases {
		if got := EncpassIsV2(c.in); got != c.want {
			t.Errorf("EncpassIsV2(% x) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAuthV2PasswordTLV(t *testing.T) {
	mac := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	salt := []byte{0x12, 0x34, 0x56, 0x78}
	tlv, err := AuthV2PasswordTLV("password", mac, salt)
	if err != nil {
		t.Fatal(err)
	}
	if tlv.Tag != TagAuthV2Password {
		t.Fatalf("tag = %#x, want TagAuthV2Password (%#x)", tlv.Tag, TagAuthV2Password)
	}
	if !bytes.Equal(tlv.Value, []byte{0xc4, 0xaf, 0x7c, 0x00, 0xa6, 0xc4, 0x1a, 0x7d}) {
		t.Fatalf("TLV value = % x", tlv.Value)
	}
}
