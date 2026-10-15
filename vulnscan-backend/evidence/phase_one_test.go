package evidence

import "testing"

func TestPhaseOnePartialIOCAndScorePolicy(t *testing.T) {
	scope := Scope{AssetID: "a", EndpointID: "tcp://203.0.113.1:443", DeviceID: "n"}
	b := PhaseOneBinding{Scope: scope, IOCType: "ip", IOCValue: "203.0.113.1", SourceID: "wire", Field: "ipv4.dst_ip", Verified: true}
	f := Finding{FactID: "F_HIST_ASSET_IOC_RECURRENCE", IOCType: b.IOCType, IOCValue: b.IOCValue, Scope: scope, SnapshotVersion: 34, Status: Observed, Eligibility: "eligible", Quality: "partial", SourceIDs: []string{"h1", "h2"}}
	cfg := DefaultPhaseOneConfig()
	cfg.Points["C01"] = 17
	cfg.Version = "test-v2"
	r, err := EvaluatePhaseOne("e", 34, []Finding{f}, nil, []PhaseOneBinding{b}, cfg)
	if err != nil || r.Score != 17 || r.ScoreMeaning != "policy_evidence_points_not_probability" {
		t.Fatal(err, r)
	}
	b.Verified = false
	r, err = EvaluatePhaseOne("e", 34, []Finding{f}, nil, []PhaseOneBinding{b}, cfg)
	if err != nil || r.Score != 0 {
		t.Fatal("unbound I scored", err, r)
	}
}
func TestPhaseOneDoesNotJoinDifferentIOC(t *testing.T) {
	s := Scope{AssetID: "a", EndpointID: "tcp://203.0.113.1:80", DeviceID: "n"}
	b := PhaseOneBinding{Scope: s, IOCType: "domain", IOCValue: "a.test", SourceID: "wire", Field: "http.host", Verified: true}
	f := Finding{FactID: "F_HTTP_ENDPOINT_REPEAT", IOCType: "domain", IOCValue: "b.test", Scope: s, SnapshotVersion: 1, Status: Observed, Eligibility: "eligible", SourceIDs: []string{"wire"}}
	r, err := EvaluatePhaseOne("e", 1, []Finding{f}, nil, []PhaseOneBinding{b}, DefaultPhaseOneConfig())
	if err != nil || r.Score != 0 {
		t.Fatal("cross IOC join", err, r)
	}
}
func TestPhaseOneTemporalFamilyNonAdditive(t *testing.T) {
	s := Scope{AssetID: "a", EndpointID: "tcp://203.0.113.1:443", DeviceID: "n"}
	b := PhaseOneBinding{Scope: s, IOCType: "ip", IOCValue: "203.0.113.1", SourceID: "wire", Field: "ipv4.dst_ip", Verified: true}
	fs := []Finding{}
	for _, id := range []FactID{"F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW"} {
		fs = append(fs, Finding{FactID: id, IOCType: b.IOCType, IOCValue: b.IOCValue, Scope: s, SnapshotVersion: 1, Status: Observed, Eligibility: "eligible", SourceIDs: []string{"wire"}})
	}
	r, err := EvaluatePhaseOne("e", 1, fs, nil, []PhaseOneBinding{b}, DefaultPhaseOneConfig())
	if err != nil || r.Score != 15 {
		t.Fatal(err, r)
	}
	duplicates := 0
	for _, u := range r.Units {
		if u.DuplicateOf != "" {
			duplicates++
		}
	}
	if duplicates != 1 {
		t.Fatal(r)
	}
}

func TestPhaseOneHistorySourcesAcrossEndpointPortsNotAdditive(t *testing.T) {
	bindings := []PhaseOneBinding{}
	facts := []Finding{}
	for _, endpoint := range []string{"tcp://203.0.113.1:80", "tcp://203.0.113.1:443"} {
		s := Scope{AssetID: "a", DeviceID: "n", EndpointID: endpoint}
		bindings = append(bindings, PhaseOneBinding{Scope: s, IOCType: "ip", IOCValue: "203.0.113.1", SourceID: endpoint, Field: "ipv4.dst_ip", Verified: true})
		facts = append(facts, Finding{FactID: "F_HIST_ASSET_IOC_RECURRENCE", IOCType: "ip", IOCValue: "203.0.113.1", Scope: s, SnapshotVersion: 1, Status: Observed, Eligibility: "eligible", SourceIDs: []string{"same-history-event"}})
	}
	r, err := EvaluatePhaseOne("e", 1, facts, nil, bindings, DefaultPhaseOneConfig())
	if err != nil || r.Score != 10 {
		t.Fatal("same historical events counted per port", err, r)
	}
}
