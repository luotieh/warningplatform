package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
)

func TestReportScheduleDefaultBoundariesAndConsecutiveDays(t *testing.T) {
	policy := reportSchedulePolicy(SnapshotEvidenceManifest{}, "asset")
	rows := []ReportMaterialObservation{}
	for n, stamp := range []string{"2026-10-01T07:59:59+08:00", "2026-10-01T08:00:00+08:00", "2026-10-01T19:59:59+08:00", "2026-10-01T20:00:00+08:00", "2026-10-02T21:00:00+08:00", "2026-10-04T21:00:00+08:00"} {
		at, _ := time.Parse(time.RFC3339, stamp)
		rows = append(rows, ReportMaterialObservation{HitID: string(rune('a' + n)), Time: at})
	}
	rows = append(rows, rows[0], ReportMaterialObservation{HitID: "missing-time"})
	stats := measureReportSchedule(rows, policy)
	if len(stats.Rows) != 6 || stats.Outside != 4 || len(stats.Days) != 3 || stats.Consecutive != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	text := scheduleText(policy, stats)
	if !strings.Contains(text, "2026-10-01=4条") || !strings.Contains(text, "2026-10-04=1条") {
		t.Fatal(text)
	}
	allDay := ReportSchedulePolicy{StartMinute: 0, EndMinute: 1440, Source: "资产专用全天运行配置"}
	manifest := SnapshotEvidenceManifest{ReportSchedules: map[string]ReportSchedulePolicy{"asset": allDay}}
	if measureReportSchedule(rows, reportSchedulePolicy(manifest, "asset")).Outside != 0 {
		t.Fatal("override was ignored")
	}
}

func TestReportDefaultSchedulePlansWithoutInventingAssetRole(t *testing.T) {
	start := time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "tcp://203.0.113.1:443"}
	manifest := SnapshotEvidenceManifest{AdapterVersion: reportSnapshotAdapterVersion, ReportObservations: []ReportMaterialObservation{{HitID: "hit", Time: start, Scope: scope}}}
	subject := evidence.SemanticSubject{ID: "scope:asset", PropositionID: "scope:asset", Scope: scope, Window: evidence.AnalysisWindow{Start: start, End: start.Add(time.Second)}}
	factory := func(s *evidence.SemanticSubject, kind, text, path string, p evidence.Provenance, complete bool) evidence.SemanticMaterial {
		return evidence.SemanticMaterial{ID: s.ID + ":" + kind, Kind: kind, Text: text, FieldPath: path, Provenance: p, Window: s.Window, Scope: s.Scope, SnapshotVersion: 1}
	}
	addReportScheduleMaterials(&subject, manifest, factory)
	if len(subject.Materials) != 2 {
		t.Fatalf("schedule materials missing: %+v", subject)
	}
	for _, m := range subject.Materials {
		if m.Kind == "asset_role" {
			t.Fatal("default invented an asset role")
		}
	}
	request := evidence.SemanticRequest{EventID: "event", SnapshotVersion: 1, InputMode: evidence.SemanticRaw, Subjects: []evidence.SemanticSubject{subject}, Slots: []evidence.SlotKey{{ID: "SC01", Target: "c2.role_schedule_conflict"}}}
	config := evidence.DefaultSemanticConfig()
	config.ReportSchedule = true
	engine, err := evidence.NewSemanticEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tasks) != 1 || plan.Tasks[0].MaxStrength != "weak" {
		t.Fatalf("default not executable: %+v", plan)
	}
	config.ReportSchedule = false
	engine, _ = evidence.NewSemanticEngine(config)
	plan, err = engine.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tasks) != 0 {
		t.Fatal("non-report behavior changed")
	}
	entries := reportScheduleEvidence(manifest)
	if len(entries) != 1 || len(entries[0].SourceIDs) != 1 || entries[0].SourceIDs[0] != "hit" {
		t.Fatalf("deterministic evidence missing: %+v", entries)
	}
}
