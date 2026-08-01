package virtual

// nsdp_coverage_test.go: a direct all-tags exercise of State.NsdpTlvs (the
// NSDP read projection) -- the nsdp face only ever requests a subset per
// request, so a single call with every tag set, on a seed with the optional
// NSDP feature fields populated, drives every branch. Real assertions.

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

func TestNsdpTlvs_AllTagsAllFieldsPopulated(t *testing.T) {
	st := SeedGS105PE()

	// Populate the optional NSDP feature fields so their append branches (not
	// just the tag-presence check) execute.
	st.NsdpQosEngine = model.Ptr(1)
	st.NsdpPortMirroringDest = model.Ptr(2)
	st.NsdpPortMirroringSources = map[int]bool{1: true, 3: true}
	st.NsdpIgmpSnoopingEnabled = model.Ptr(true)
	st.NsdpIgmpSnoopingVlan = model.Ptr(1)
	st.NsdpBroadcastFiltering = model.Ptr(true)
	st.NsdpLoopDetection = model.Ptr(true)
	if st.Serial == "" {
		st.Serial = "SER123"
	}
	if st.Hostname == "" {
		st.Hostname = "sw-test"
	}
	if st.Firmware == "" {
		st.Firmware = "1.0.0.0"
	}

	allTags := map[nsdp.Tag]bool{
		nsdp.TagModel: true, nsdp.TagMAC: true, nsdp.TagPortCount: true,
		nsdp.TagSerialNumber: true, nsdp.TagHostname: true, nsdp.TagFirmwareVer1: true,
		nsdp.TagPortStatus: true, nsdp.TagPortStatistics: true, nsdp.TagVLANMembers: true,
		nsdp.TagPortPVID: true, nsdp.TagIPAddress: true, nsdp.TagNetmask: true,
		nsdp.TagGateway: true, nsdp.TagDHCPMode: true, nsdp.TagQOSEngine: true,
		nsdp.TagPortMirroring: true, nsdp.TagIGMPSnooping: true,
		nsdp.TagBroadcastFiltering: true, nsdp.TagLoopDetection: true,
	}

	out := st.NsdpTlvs(allTags)
	if len(out) == 0 {
		t.Fatalf("NsdpTlvs(all tags) returned no entries")
	}
	// The optional-feature tags we populated must appear.
	seen := map[nsdp.Tag]bool{}
	for _, e := range out {
		seen[e.Tag] = true
	}
	for _, want := range []nsdp.Tag{nsdp.TagModel, nsdp.TagQOSEngine, nsdp.TagIGMPSnooping, nsdp.TagLoopDetection, nsdp.TagPortMirroring} {
		if !seen[want] {
			t.Errorf("NsdpTlvs output missing tag %v (its populated branch did not execute)", want)
		}
	}

	// Empty tag set -> no entries (covers the all-false path cheaply).
	if got := st.NsdpTlvs(map[nsdp.Tag]bool{}); len(got) != 0 {
		t.Errorf("NsdpTlvs(no tags) = %d entries, want 0", len(got))
	}
}
