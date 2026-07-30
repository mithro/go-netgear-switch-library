package netgearswitch

// backend_nsdp_test.go: unit tests for backend_nsdp.go's builder wiring and
// Switch.NSDPDevice's bypass, mirroring switch_write_test.go's SNMP
// write-builder unit tests exactly in shape (fakeModel, withRegisteredBackend-
// style isolation is unnecessary here since these call the build* functions
// directly, never through readerFor/writerFor's registry). See D-NSDP §8 for
// the semantics pinned below; facade_nsdp_integration_test.go covers the
// real-UDP end-to-end capstone this file's fakes stand in for.

import (
	"context"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// --- fakes ------------------------------------------------------------

// fakeNsdpRWClient is a minimal nsdp.Client + nsdp.WriteClient test double:
// Read always returns a canned packet with just enough TLVs for
// nsdp.ParseDevice to succeed (TagModel/TagMAC), plus a PORT_PVID TLV per
// entry currently in pvids -- so a SetPVID round-trip (write, then
// nsdp.Writer's internal verify-by-re-read) actually observes the write it
// just made, exactly like the real virtual-switch NSDP face does. Write
// records its arguments, applies a PORT_PVID TLV (if present) to pvids, and
// returns writeErr.
type fakeNsdpRWClient struct {
	readErr error
	pvids   map[int]int

	writeCalls []struct {
		tlvs     []nsdp.TLVEntry
		password string
	}
	writeErr error
}

func (f *fakeNsdpRWClient) Read(_ context.Context, _ []nsdp.Tag) (*nsdp.Packet, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	pkt := &nsdp.Packet{Op: nsdp.OpReadResponse, ClientMAC: make([]byte, 6), ServerMAC: make([]byte, 6)}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0xbc, 0xa5, 0x11, 0xb8, 0xec, 0xf1})
	for port, vlan := range f.pvids {
		tlv, err := nsdp.PvidTLV(port, vlan)
		if err == nil {
			pkt.TLVs = append(pkt.TLVs, tlv)
		}
	}
	return pkt, nil
}

func (f *fakeNsdpRWClient) Write(_ context.Context, tlvs []nsdp.TLVEntry, password string) (*nsdp.Packet, error) {
	f.writeCalls = append(f.writeCalls, struct {
		tlvs     []nsdp.TLVEntry
		password string
	}{tlvs, password})
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	if f.pvids == nil {
		f.pvids = map[int]int{}
	}
	for _, tlv := range tlvs {
		if tlv.Tag == nsdp.TagPortPVID && len(tlv.Value) == 3 {
			port := int(tlv.Value[0])
			vlan := int(tlv.Value[1])<<8 | int(tlv.Value[2])
			f.pvids[port] = vlan
		}
	}
	return &nsdp.Packet{Op: nsdp.OpWriteResponse, Result: nsdp.ResultSuccess}, nil
}

// readOnlyNsdpClient implements ONLY nsdp.Client (no Write method), so a
// type-assertion to nsdp.WriteClient must fail -- proving buildNSDPWriter
// doesn't panic/blindly assume an injected client is write-capable.
type readOnlyNsdpClient struct{}

func (readOnlyNsdpClient) Read(context.Context, []nsdp.Tag) (*nsdp.Packet, error) {
	return &nsdp.Packet{Op: nsdp.OpReadResponse}, nil
}

func nsdpModel(key string) *model.SwitchModel {
	return fakeModel(key, model.BackendNSDP)
}

// --- requireNSDPPassword --------------------------------------------------

func TestRequireNSDPPassword_RejectsNil(t *testing.T) {
	_, err := requireNSDPPassword("10.0.0.1", nil)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("requireNSDPPassword(nil) error = %v, want wrapping ErrCredential", err)
	}
}

func TestRequireNSDPPassword_AcceptsEmptyString(t *testing.T) {
	// Unlike SNMP's write-community gate, Python's NSDP gate only checks
	// `password is None` (sync_api.py: `if password is None: raise
	// CredentialError(...)`) -- an empty string is a configured (if useless)
	// password, not an unconfigured one. Mirror that exactly: no `!= ""`
	// check here.
	empty := ""
	got, err := requireNSDPPassword("10.0.0.1", &empty)
	if err != nil {
		t.Fatalf("requireNSDPPassword(\"\") error = %v, want nil", err)
	}
	if got != "" {
		t.Fatalf("requireNSDPPassword(\"\") = %q, want \"\"", got)
	}
}

func TestRequireNSDPPassword_AcceptsNonEmptyString(t *testing.T) {
	password := "admin"
	got, err := requireNSDPPassword("10.0.0.1", &password)
	if err != nil {
		t.Fatalf("requireNSDPPassword() error = %v, want nil", err)
	}
	if got != password {
		t.Fatalf("requireNSDPPassword() = %q, want %q", got, password)
	}
}

// --- buildNSDPClient -------------------------------------------------------

func TestBuildNSDPClient_InjectedClientUsedAsIs(t *testing.T) {
	injected := &fakeNsdpRWClient{}
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPClient(injected))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client, err := buildNSDPClient(sw)
	if err != nil {
		t.Fatalf("buildNSDPClient() error = %v", err)
	}
	if client != injected {
		t.Fatalf("buildNSDPClient() = %v, want the injected client", client)
	}
}

func TestBuildNSDPClient_DefaultBuiltWhenNoneInjected(t *testing.T) {
	sw, err := New(nsdpModel("fake"), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client, err := buildNSDPClient(sw)
	if err != nil {
		t.Fatalf("buildNSDPClient() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("buildNSDPClient() = nil, want a default-built nsdp.Client")
	}
	udpClient, ok := client.(*nsdp.UDPClient)
	if !ok {
		t.Fatalf("buildNSDPClient() = %T, want *nsdp.UDPClient", client)
	}
	if udpClient.Host != "10.0.0.1" {
		t.Errorf("buildNSDPClient().Host = %q, want %q", udpClient.Host, "10.0.0.1")
	}
}

func TestBuildNSDPClient_DefaultBuiltUsesConfiguredInterface(t *testing.T) {
	// WithInterface reads the real interface's MAC via sysfs, so a bogus
	// interface name must propagate the read error, proving the interface
	// option was actually threaded through to nsdp.NewUDPClient.
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPInterface("nonexistent-iface-xyz"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildNSDPClient(sw)
	if err == nil {
		t.Fatal("buildNSDPClient() error = nil, want a sysfs read error for a nonexistent interface")
	}
}

// --- buildNSDPWriteClient ---------------------------------------------------

func TestBuildNSDPWriteClient_InjectedClientTypeAssertedToWriteClient(t *testing.T) {
	injected := &fakeNsdpRWClient{}
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPClient(injected))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	wc, err := buildNSDPWriteClient(sw)
	if err != nil {
		t.Fatalf("buildNSDPWriteClient() error = %v", err)
	}
	if wc != injected {
		t.Fatalf("buildNSDPWriteClient() = %v, want the injected client", wc)
	}
}

func TestBuildNSDPWriteClient_ReadOnlyInjectedClientErrors(t *testing.T) {
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPClient(readOnlyNsdpClient{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildNSDPWriteClient(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildNSDPWriteClient() error = %v, want wrapping ErrUnsupportedCapability (injected client has no Write method)", err)
	}
}

// --- buildNSDPWriter ---------------------------------------------------

func TestBuildNSDPWriter_PropagatesCredentialErrorWhenNoPasswordConfigured(t *testing.T) {
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPClient(&fakeNsdpRWClient{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildNSDPWriter(sw)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("buildNSDPWriter() error = %v, want wrapping ErrCredential", err)
	}
}

func TestBuildNSDPWriter_ResolvesFromNSDPPasswordCell(t *testing.T) {
	// D-NSDP §8.2 (corrected): buildNSDPWriter resolves sw's OWN nsdpPassword
	// cell, NOT httpPassword -- these are independent, mirroring Python's
	// separate nsdp_password_resolver/http_password_resolver constructor
	// params. Only FromConfig happens to feed both from the same spec (see
	// TestFromConfig_FeedsBothPasswordCellsFromSameHTTPPasswordSpec).
	injected := &fakeNsdpRWClient{}
	sw, err := New(nsdpModel("fake"), "10.0.0.1",
		WithNSDPClient(injected),
		WithNSDPPasswordResolver(func() (*string, error) {
			p := "admin"
			return &p, nil
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	writer, err := buildNSDPWriter(sw)
	if err != nil {
		t.Fatalf("buildNSDPWriter() error = %v, want nil", err)
	}
	if writer == nil {
		t.Fatal("buildNSDPWriter() returned nil writer")
	}
	if err := writer.SetPVID(context.Background(), 1, 90, false); err != nil {
		t.Fatalf("SetPVID() error = %v, want nil", err)
	}
	if len(injected.writeCalls) != 1 {
		t.Fatalf("writeCalls = %d, want 1", len(injected.writeCalls))
	}
	if injected.writeCalls[0].password != "admin" {
		t.Errorf("write password = %q, want %q (resolved from the nsdpPassword cell)", injected.writeCalls[0].password, "admin")
	}
}

func TestBuildNSDPWriter_IndependentFromHTTPPassword(t *testing.T) {
	// The core of the coordinator's correction: WithNSDPPassword must win
	// for NSDP writes regardless of what (if anything) WithHTTPPasswordResolver
	// configured -- the two cells never read each other.
	injected := &fakeNsdpRWClient{}
	sw, err := New(nsdpModel("fake"), "10.0.0.1",
		WithNSDPClient(injected),
		WithNSDPPassword("nsdp-secret"),
		WithHTTPPasswordResolver(func() (*string, error) {
			p := "http-secret"
			return &p, nil
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	writer, err := buildNSDPWriter(sw)
	if err != nil {
		t.Fatalf("buildNSDPWriter() error = %v, want nil", err)
	}
	if err := writer.SetPVID(context.Background(), 1, 90, false); err != nil {
		t.Fatalf("SetPVID() error = %v, want nil", err)
	}
	if len(injected.writeCalls) != 1 {
		t.Fatalf("writeCalls = %d, want 1", len(injected.writeCalls))
	}
	if injected.writeCalls[0].password != "nsdp-secret" {
		t.Errorf("write password = %q, want %q (WithNSDPPassword, independent of WithHTTPPasswordResolver's \"http-secret\")",
			injected.writeCalls[0].password, "nsdp-secret")
	}
}

func TestBuildNSDPWriter_NoNSDPBackendModelErrors(t *testing.T) {
	// A password IS configured here so the failure genuinely comes from
	// nsdp.NewWriter's own _require_nsdp-equivalent gate, not from
	// requireNSDPPassword rejecting an unconfigured password first --
	// mirroring Python's own check order (password resolved/gated BEFORE
	// NsdpWriter's constructor runs its backend guard).
	m := fakeModel("fake") // no backends at all
	sw, err := New(m, "10.0.0.1",
		WithNSDPClient(&fakeNsdpRWClient{}),
		WithNSDPPassword("admin"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildNSDPWriter(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildNSDPWriter() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

func TestBuildNSDPWriter_CyclePoEAndClearPoEFaultReturnUnsupported(t *testing.T) {
	sw, err := New(nsdpModel("fake"), "10.0.0.1",
		WithNSDPClient(&fakeNsdpRWClient{}),
		WithNSDPPassword("admin"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	writer, err := buildNSDPWriter(sw)
	if err != nil {
		t.Fatalf("buildNSDPWriter() error = %v", err)
	}

	timeouts := DefaultPoeCycleTimeouts()
	if err := writer.CyclePoE(context.Background(), 1, timeouts, false); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("CyclePoE() error = %v, want wrapping ErrUnsupportedCapability (NSDP has no PoE control tag)", err)
	}
	if err := writer.ClearPoEFault(context.Background(), 1, timeouts, false); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("ClearPoEFault() error = %v, want wrapping ErrUnsupportedCapability (NSDP has no PoE control tag)", err)
	}
}

// --- Switch.NSDPDevice bypass -----------------------------------------------

func TestNSDPDevice_NoNSDPBackendErrors(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP) // no NSDP backend
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = sw.NSDPDevice(context.Background())
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("NSDPDevice() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

func TestNSDPDevice_BuildsFreshReaderNotCached(t *testing.T) {
	injected := &fakeNsdpRWClient{}
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPClient(injected))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	dev, err := sw.NSDPDevice(context.Background())
	if err != nil {
		t.Fatalf("NSDPDevice() error = %v, want nil", err)
	}
	if dev.Model != "GS110EMX" {
		t.Errorf("NSDPDevice().Model = %q, want %q", dev.Model, "GS110EMX")
	}
	// NSDPDevice never populates s.readerCache -- GetDevice isn't part of
	// BackendReader, so nothing should be cached under model.BackendNSDP.
	if _, cached := sw.readerCache[model.BackendNSDP]; cached {
		t.Error("NSDPDevice() populated s.readerCache; it must bypass readerFor entirely")
	}
}

func TestNSDPDevice_ContextCanceledPropagates(t *testing.T) {
	sw, err := New(nsdpModel("fake"), "10.0.0.1", WithNSDPClient(&fakeNsdpRWClient{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = sw.NSDPDevice(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("NSDPDevice() error = %v, want wrapping context.Canceled", err)
	}
}
