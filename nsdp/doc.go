// Package nsdp implements the NSDP backend (model.BackendNSDP) for the
// root netgearswitch facade: NETGEAR's own Switch Discovery Protocol, a UDP
// broadcast-capable protocol and the only backend (besides the web UI) the
// unmanaged "Plus" product line (GS110EMX, GS305EP, GS105PE, ...) speaks.
//
// # Wire codec
//
// protocol.go and auth.go are a pure, zero-dependency wire codec with no
// socket I/O of their own: Packet (DecodePacket/Encode) is one NSDP
// datagram -- a fixed HeaderSize-byte header (Signature, Op, sequence
// number, client/server MAC, Result) followed by a sequence of TLVEntry
// values (DecodeTLV/Encode) terminated by EndMarker. Op and Tag are the
// packet's operation code and per-field TLV tags. BuildReadRequest/
// BuildWriteRequest/BuildWriteRequestV2 assemble a request packet;
// CheckResult inspects a response's Result field. auth.go implements the
// two write-authentication schemes a switch may demand: EncodePasswordV1's
// XOR obfuscation against V1Key, and AuthV2Password's salted-challenge
// scheme (AuthV2PasswordTLV) for switches that reject V1 (EncpassIsV2
// detects which one a given ENCPASS response value asks for).
//
// # Transport, reading and writing
//
// client.go's UDPClient (NewUDPClient) is the real transport: it sends and
// receives NSDP packets over a UDP socket, resolving a switch's server MAC
// via broadcast discovery and holding the per-connection sequence counter
// and auth-scheme negotiation. Client and WriteClient are the minimal
// Read/Write method sets Reader/Writer need, so a fake can be injected in
// tests without a real socket (see the root package's WithNSDPClient).
// Reader (NewReader) and Writer (NewWriter) are this backend's
// netgearswitch.BackendReader/BackendWriter implementations, translating
// each facade operation into a Read/Write over the tags parse.go's Parse*
// functions (ParsePortStatus, ParseVlanMembers, ParseDevice, ...) and
// write_tlv.go/write.go's TLV builders (PvidTLV, VlanMembersTLV,
// HostnameTLV, ...) know how to decode/encode. Every NoXMsg constant
// (NoPoEReadMsg, NoLLDPMsg, NoSensorsMsg, ...) is the refusal text Reader/
// Writer return for a facade operation NSDP genuinely has no tag for --
// each backed by an exhaustive live tag sweep of real hardware, never
// assumed absent.
//
// Ported field-for-field from src/netgear_switch/protocols/nsdp/ (the
// normative source; that repo is read-only from here). Any discrepancy
// between this package and the pinned Python source is a bug in this
// package, not a deliberate deviation, unless called out in a comment.
package nsdp
