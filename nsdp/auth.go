package nsdp

// V1Key is the 19-byte repeating XOR key used by NSDP v1 authentication (the
// only detail the source spec -- gdoc2netcfg/docs/nsdp-protocol.md -- gives:
// no worked example, no padding rule).
var V1Key = []byte("NtgrSmartSwitchRock")

// AuthV2Unsupported explains, verbatim, why NSDP v2 salt/hash auth (tags
// TagAuthV2Salt/TagAuthV2Password, 0x0017/0x001A) is recognised by name in
// this package's Tag constants but has no implementation: the source spec
// names only the two tag numbers and gives no algorithm (no hash function,
// no salt ordering), so there is nothing to implement honestly without a
// hardware capture. A switch that rejects v1 auth returns Result
// ResultBadPassword (0x0700); the transport layer surfaces that as an error
// telling the caller v2 is required.
const AuthV2Unsupported = "NSDP v2 salt/hash auth (tags 0x0017/0x001A) is unverified and not " +
	"implemented; this backend supports only v1 XOR auth"

// EncodePasswordV1 repeating-XORs password's raw bytes against V1Key.
// XOR is its own inverse, so this single function both encodes an outgoing
// password and would decode an incoming PASSWORD TLV -- no separate decode
// function exists, mirroring Python's encode_password_v1.
//
// UNVERIFIED: no padding/truncation rule is documented (module docstring);
// if a real switch rejects this, a hardware capture is needed to confirm
// the exact byte handling.
func EncodePasswordV1(password string) []byte {
	out := make([]byte, len(password))
	for i := 0; i < len(password); i++ {
		out[i] = password[i] ^ V1Key[i%len(V1Key)]
	}
	return out
}

// PasswordTLV builds the TagPassword TLV that a write request prepends
// ahead of the caller's other TLVs (mirroring Python write.py's
// build_write_request, which constructs
// TLVEntry(Tag.PASSWORD, encode_password_v1(password)) inline). Returns an
// error wrapping model.ErrNSDP if password contains a non-ASCII byte,
// mirroring Python's password.encode("ascii") raising UnicodeEncodeError
// before the XOR ever runs.
func PasswordTLV(password string) (TLVEntry, error) {
	for i := 0; i < len(password); i++ {
		if password[i] >= 0x80 {
			return TLVEntry{}, errNSDP("NSDP password must be ASCII, got byte 0x%02X at index %d", password[i], i)
		}
	}
	return TLVEntry{Tag: TagPassword, Value: EncodePasswordV1(password)}, nil
}
