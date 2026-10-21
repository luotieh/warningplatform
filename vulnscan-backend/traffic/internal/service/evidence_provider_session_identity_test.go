package service

import (
	"testing"

	"vulnscan-backend/evidence"
)

func TestProviderPeerSessionIdentities(t *testing.T) {
	for _, mode := range []string{"same_copy", "different_counters", "different_source", "different_endpoint", "different_device", "different_asset"} {
		t.Run(mode, func(t *testing.T) {
			scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "tcp://192.0.2.1:443"}
			value := evidence.Session{ID: "session", SourceID: "hit", HitIDs: []string{"hit2", "hit"}, ByteUnit: "wire", ObservationOnly: true, UpBytes: 10}
			copy := value
			copy.HitIDs = []string{"hit", "hit2"}
			other := scope
			want := 1
			switch mode {
			case "different_counters":
				copy.UpBytes++
				want = 0
			case "different_source":
				copy.SourceID = "other"
				want = 0
			case "different_endpoint":
				other.EndpointID = "tcp://192.0.2.2:443"
				want = 0
			case "different_device":
				other.DeviceID = "other"
				want = 2
			case "different_asset":
				other.AssetID = "other"
				want = 2
			}
			out := SnapshotEvidenceInput{Request: evidence.Request{Inputs: []evidence.Input{
				{Scope: scope, Network: &evidence.NetworkData{Sessions: []evidence.Session{value}}},
				{Scope: other, Network: &evidence.NetworkData{Sessions: []evidence.Session{copy}}},
			}}}
			resolveProviderSessionIdentities(&out)
			count := 0
			for _, in := range out.Request.Inputs {
				count += len(in.Network.Sessions)
				if in.Network.Complete || in.Network.Verified {
					t.Fatal("identity repair upgraded network proof")
				}
			}
			if count != want {
				t.Fatalf("got %d sessions, want %d", count, want)
			}
			if want == 0 && (len(out.Manifest.Issues) != 1 || out.Manifest.Issues[0].Code != "peer_session_identity_conflict") {
				t.Fatal("ambiguous identity was silently dropped")
			}
			if value.HitIDs[0] != "hit2" {
				t.Fatal("identity repair mutated original source references")
			}
		})
	}
}
