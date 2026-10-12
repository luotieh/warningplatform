package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
)

func TestReportPracticalUsesBoundPartialFieldsAndKeepsCache(t *testing.T) {
	at := time.Date(2026, 10, 12, 1, 1, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "tcp://203.0.113.1:8088"}
	p := evidence.Provenance{Verified: true, Complete: false, Version: "saved-1", SourceIDs: []string{"a", "b"}}
	body := uint64(32)
	i := evidence.Input{Scope: scope, Window: &evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)}, Network: &evidence.NetworkData{Provenance: p, Connections: []evidence.Connection{{SourceID: "a", Time: at, AssetID: "asset", Destination: "203.0.113.1", Port: 8088, ProtocolParsed: true, AppProtocol: "http", TCPState: "SYN_SENT"}, {SourceID: "unbound", Time: at, AssetID: "asset", Destination: "fake", Port: 1}}}, HTTP: &evidence.HTTPData{Provenance: p, Records: []evidence.HTTPRecord{{SourceID: "a", Time: at, URL: "http://203.0.113.1:8088/login", Fields: map[string]string{"password": "do-not-store-secret"}, BodyLength: &body}, {SourceID: "b", Time: at.Add(time.Second), URL: "bad", BodyLength: &body}}}}
	out := SnapshotEvidenceInput{Request: evidence.Request{Hits: []evidence.Hit{{ID: "a", OccurredAt: at, Scope: scope}, {ID: "b", OccurredAt: at.Add(time.Second), Scope: scope}}, Inputs: []evidence.Input{i}}}
	collectReportPracticalEvidence(&out)
	foundNetwork, foundHTTP, foundSize := false, false, false
	for _, e := range out.Manifest.ReportPractical {
		if strings.Contains(e.Result, "do-not-store-secret") || strings.Contains(e.Result, "fake") {
			t.Fatal("unbound record or secret leaked")
		}
		if e.Family == "report_practical:network_fields" {
			foundNetwork = true
			if !strings.Contains(e.Result, "http:8088") || len(e.SourceIDs) != 1 {
				t.Fatal(e)
			}
		}
		if e.Family == "report_practical:http_structure" {
			foundHTTP = true
			if !strings.Contains(e.Result, "password") {
				t.Fatal(e)
			}
		}
		if e.Family == "report_practical:http_size" {
			foundSize = true
			if len(e.SourceIDs) != 1 || e.SourceIDs[0] != "a" {
				t.Fatal("size includes unavailable records", e)
			}
		}
	}
	if !foundNetwork || !foundHTTP || !foundSize {
		t.Fatalf("usable fields skipped: %+v", out.Manifest)
	}
	if len(out.Manifest.ReportPracticalChecks) < 3 {
		t.Fatal("execution accounting missing")
	}
	raw, err := json.Marshal(out.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var restored SnapshotEvidenceManifest
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.ReportPractical) != len(out.Manifest.ReportPractical) || len(restored.ReportPracticalChecks) != len(out.Manifest.ReportPracticalChecks) || restored.ReportPractical[0].Result != out.Manifest.ReportPractical[0].Result {
		t.Fatal("cached manifest discarded practical observations")
	}
}

func TestObservedGroupBatchesRetainAllMembersWithoutRoles(t *testing.T) {
	start := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	out := SnapshotEvidenceInput{}
	for n := 0; n < 11; n++ {
		scope := evidence.Scope{AssetID: fmt.Sprintf("asset-%d", n), EndpointID: "tcp://203.0.113.1:443", DeviceID: "device"}
		id := fmt.Sprintf("hit-%d", n)
		out.Request.Hits = append(out.Request.Hits, evidence.Hit{ID: id, OccurredAt: start, Scope: scope})
		out.Manifest.ReportObservations = append(out.Manifest.ReportObservations, ReportMaterialObservation{HitID: id, Time: start, Scope: scope})
	}
	r := evidence.SemanticRequest{EventID: "event", SnapshotVersion: 1, InputMode: evidence.SemanticRaw, Slots: []evidence.SlotKey{{ID: "SC02", Target: "botnet.group_alternative"}}}
	factory := func(s *evidence.SemanticSubject, kind, text, path string, p evidence.Provenance, complete bool) evidence.SemanticMaterial {
		return evidence.SemanticMaterial{ID: s.ID + ":" + kind, Kind: kind, Text: text, FieldPath: path, Provenance: p, Scope: s.Scope, Window: s.Window, SnapshotVersion: 1}
	}
	addReportObservedGroupSubjects(&r, out, factory)
	config := evidence.DefaultSemanticConfig()
	config.ReportPractical = true
	engine, _ := evidence.NewSemanticEngine(config)
	plan, err := engine.Plan(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tasks) != 3 {
		t.Fatalf("members discarded: %+v", plan)
	}
	seen := map[string]bool{}
	for _, task := range plan.Tasks {
		if len(task.Materials) < 2 || len(task.Materials) > 5 {
			t.Fatal("invalid batch")
		}
		for _, m := range task.Materials {
			if m.Role != "" || seen[m.AssetID] {
				t.Fatal("invented role or duplicate")
			}
			seen[m.AssetID] = true
		}
	}
	if len(seen) != 11 {
		t.Fatal("missing members")
	}
}

func TestPracticalHistorySeparatesSameIOCTransportDatesAndSources(t *testing.T) {
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	h := &evidence.HistoryData{Provenance: evidence.Provenance{Verified: true, Version: "platform", SourceIDs: []string{"t", "d", "other"}}, AsOf: at, LookbackStart: at.AddDate(0, 0, -30), IOC: "target", Events: []evidence.HistoryEvent{
		{ID: "t", AssetID: "asset", IOC: "target", ObservationKind: "transport_contact", Time: at.AddDate(0, 0, -1)},
		{ID: "d", AssetID: "asset", IOC: "target", ObservationKind: "dns_record", Time: at.AddDate(0, 0, -2)},
		{ID: "other", AssetID: "asset", IOC: "other", ObservationKind: "transport_contact", Time: at.AddDate(0, 0, -3)},
	}}
	out := SnapshotEvidenceInput{Request: evidence.Request{EventID: "current", Inputs: []evidence.Input{{Scope: evidence.Scope{AssetID: "asset"}, PlatformHistory: h}}}}
	collectReportPracticalEvidence(&out)
	for _, e := range out.Manifest.ReportPractical {
		if e.Family != "report_practical:history_association_transport" {
			continue
		}
		if len(e.SourceIDs) != 1 || e.SourceIDs[0] != "t" || e.SavedDNSRecords != 0 || strings.Contains(e.Result, "2026-10-10") || strings.Contains(e.Result, "2026-10-09") {
			t.Fatal("other IOC/DNS dates promoted to transport recurrence", e)
		}
		if err := validateReportBoundaries("历史通信记录于10月11日出现", []string{"transport"}, map[string]ReportEvidence{"transport": e}); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("real same-IOC transport suppressed by incomplete history")
}
