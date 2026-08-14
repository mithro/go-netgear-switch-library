package nsdp

// V1Key is the 19-byte repeating XOR key used by NSDP v1 authentication (the
// only detail the source spec -- gdoc2netcfg/docs/nsdp-protocol.md -- gives:
// no worked example, no padding rule).
var V1Key = []byte("NtgrSmartSwitchRock")

// AuthV2Unsupported is the hint appended to a ResultBadPassword (0x0700)
// write-rejection error: the v2 salted-token TRANSFORM is now implemented and
// known-answer-verified (AuthV2Password, below), but the default NSDP Writer
// still sends a v1 PASSWORD TLV, which a v2-only switch (e.g. GS110EMX fw
// 1.0.2.8) rejects with 0x0700. Auto-negotiating v2 (read AUTH_V2_ENCPASS to
// pick the scheme, read AUTH_V2_SALT for salt+MAC, then send the
// token-FIRST write) is a separate Writer wiring step; until it lands, a
// caller hitting a v2 switch sees this message.
const AuthV2Unsupported = "the switch requires NSDP v2 salted write auth; the v2 token " +
	"transform is implemented (AuthV2Password) but this writer still sends v1 -- v2 write-flow negotiation pending"

// EncodePasswordV1 repeating-XORs password's raw bytes against V1Key.
// XOR is its own inverse, so this single function both encodes an outgoing
// password and would decode an incoming PASSWORD TLV -- no separate decode
// function exists, mirroring Python's encode_password_v1.
//
// Returns an error wrapping model.ErrNSDP if password contains a non-ASCII
// byte, mirroring Python's password.encode("ascii") raising
// UnicodeEncodeError before the XOR ever runs.
//
// UNVERIFIED: no padding/truncation rule is documented (module docstring);
// if a real switch rejects this, a hardware capture is needed to confirm
// the exact byte handling.
func EncodePasswordV1(password string) ([]byte, error) {
	for i := 0; i < len(password); i++ {
		if password[i] >= 0x80 {
			return nil, errNSDP("NSDP password must be ASCII, got byte 0x%02X at index %d", password[i], i)
		}
	}
	out := make([]byte, len(password))
	for i := 0; i < len(password); i++ {
		out[i] = password[i] ^ V1Key[i%len(V1Key)]
	}
	return out, nil
}

// PasswordTLV builds the TagPassword TLV that a write request prepends
// ahead of the caller's other TLVs (mirroring Python write.py's
// build_write_request, which constructs
// TLVEntry(Tag.PASSWORD, encode_password_v1(password)) inline). Returns an
// error wrapping model.ErrNSDP if password contains a non-ASCII byte (see
// EncodePasswordV1).
func PasswordTLV(password string) (TLVEntry, error) {
	enc, err := EncodePasswordV1(password)
	if err != nil {
		return TLVEntry{}, err
	}
	return TLVEntry{Tag: TagPassword, Value: enc}, nil
}

// AUTH_V2_ENCPASS (0x0014) values that select the write-auth scheme, mirroring
// Python auth.py's ENCPASS_V1/ENCPASS_V2.
const (
	EncpassV1 = 0x01
	EncpassV2 = 0x10
)

// EncpassIsV2 decides the write-auth scheme from an AUTH_V2_ENCPASS (0x0014)
// read value: v2 iff the advertised value is 0x10 (observed 0x00000010 on a
// GS110EMX fw 1.0.2.8); any other value (notably 1) is legacy v1 XOR, and an
// absent/empty value is treated as v1 (the historical default). Ported
// verbatim from Python auth.py's encpass_is_v2.
func EncpassIsV2(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	var n uint64
	for _, b := range value {
		n = n<<8 | uint64(b)
	}
	return n == EncpassV2
}

// AuthV2Password computes the 8-byte NSDP v2 auth token for a write, mirroring
// Python auth.py's auth_v2_password (itself transcribed byte-for-byte from
// CursedHardware/go-nsdp's AuthV2Password -- the reverse-engineered scheme NCC
// Group documented as CVE-2020-35221).
//
// switchMAC is the device's OWN 6-byte MAC (the server MAC echoed in the
// AUTH_V2_SALT read response); salt is that read's fresh 4-byte value (it
// rotates on every read). The password is taken as a 20-byte key: ASCII,
// zero-padded / truncated to 20 bytes (the web UI caps the field at 20 chars).
// The token is NOT a hash -- each output byte XOR-folds three password bytes
// with salt and MAC bytes. Returns an error wrapping model.ErrNSDP on a
// non-ASCII password or wrong-length salt/MAC.
//
// Known-answer vector (go-nsdp TestAuthV2Password, byte-verified in the test):
// password "password", MAC 12:34:56:78:9a:bc, salt 12:34:56:78 ->
// c4:af:7c:00:a6:c4:1a:7d.
func AuthV2Password(password string, switchMAC, salt []byte) ([]byte, error) {
	if len(salt) != 4 {
		return nil, errNSDP("NSDP v2 salt must be 4 bytes, got %d", len(salt))
	}
	if len(switchMAC) != 6 {
		return nil, errNSDP("NSDP v2 switch MAC must be 6 bytes, got %d", len(switchMAC))
	}
	for i := 0; i < len(password); i++ {
		if password[i] >= 0x80 {
			return nil, errNSDP("NSDP password must be ASCII, got byte 0x%02X at index %d", password[i], i)
		}
	}
	// 20-byte key: password bytes, zero-padded/truncated to 20.
	var k [20]byte
	n := len(password)
	if n > 20 {
		n = 20
	}
	copy(k[:], password[:n])
	s, m := salt, switchMAC
	return []byte{
		s[3] ^ s[2] ^ m[1] ^ m[5] ^ k[0] ^ k[1] ^ k[2],
		s[3] ^ s[1] ^ m[4] ^ m[0] ^ k[3] ^ k[4] ^ k[5],
		s[0] ^ s[2] ^ m[3] ^ m[2] ^ k[6] ^ k[7] ^ k[8],
		s[0] ^ s[1] ^ m[4] ^ m[5] ^ k[9] ^ k[10] ^ k[11],
		s[3] ^ s[2] ^ m[1] ^ m[5] ^ k[12] ^ k[13] ^ k[14],
		s[3] ^ s[1] ^ m[4] ^ m[0] ^ k[15] ^ k[16] ^ k[17],
		s[0] ^ s[2] ^ m[3] ^ m[2] ^ k[18] ^ k[19] ^ k[0],
		s[0] ^ s[1] ^ m[4] ^ m[5] ^ k[1] ^ k[3] ^ k[5],
	}, nil
}

// AuthV2PasswordTLV builds the TagAuthV2Password (0x001A) TLV that a v2 write
// request prepends AHEAD of the config TLVs -- the token MUST come first or
// the switch rejects the write (error 13), live-verified on a GS110EMX. See
// AuthV2Password for the token computation.
func AuthV2PasswordTLV(password string, switchMAC, salt []byte) (TLVEntry, error) {
	tok, err := AuthV2Password(password, switchMAC, salt)
	if err != nil {
		return TLVEntry{}, err
	}
	return TLVEntry{Tag: TagAuthV2Password, Value: tok}, nil
}
