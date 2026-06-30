package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestSeverityToLevel(t *testing.T) {
	cases := map[string]int{"critical": 1, "high": 2, "medium": 3, "middle": 3, "low": 4, "unknown": 4, "": 4}
	for sev, want := range cases {
		if got := severityToLevel(sev); got != want {
			t.Fatalf("severityToLevel(%q)=%d want %d", sev, got, want)
		}
	}
}

func TestBuildTransferIncidentReq(t *testing.T) {
	event := domain.Event{
		EventID:  "evt-9",
		Title:    "可疑横向移动",
		Message:  "命中规则：SMB 暴力破解",
		Severity: "high",
		Category: "lateral_movement",
		Context:  `{"victim_target":"DB-01","cve_id":"CVE-2024-1","cvss_score":7.5,"ai_confidence":0.92}`,
		Observables: []domain.IOC{
			{Type: "ip", Value: "10.0.0.5", Role: "source"},
			{Type: "ip", Value: "10.0.0.9", Role: "destination"},
		},
	}
	summaries := []domain.Summary{{EventSummary: "研判：确为攻击"}}

	req := buildTransferIncidentReq(event, summaries)

	if req.IncidentNo != "evt-9" {
		t.Fatalf("IncidentNo=%q", req.IncidentNo)
	}
	if req.Name != "可疑横向移动" {
		t.Fatalf("Name=%q", req.Name)
	}
	if req.Level != 2 {
		t.Fatalf("Level=%d want 2", req.Level)
	}
	if req.AiOpinion != "研判：确为攻击" {
		t.Fatalf("AiOpinion=%q", req.AiOpinion)
	}
	if req.AiConfidence != 0.92 {
		t.Fatalf("AiConfidence=%v", req.AiConfidence)
	}
	if req.SourceSystem == "" {
		t.Fatal("SourceSystem empty")
	}
	if req.AssetInfo == nil || req.AssetInfo.SiteIP != "10.0.0.9" {
		t.Fatalf("AssetInfo.SiteIP mismatch: %+v", req.AssetInfo)
	}
	if req.AssetInfo.AssetName != "DB-01" {
		t.Fatalf("AssetInfo.AssetName=%q", req.AssetInfo.AssetName)
	}
	if req.MetadataInfo == nil || req.MetadataInfo.CveId != "CVE-2024-1" || req.MetadataInfo.CvssScore != 7.5 {
		t.Fatalf("MetadataInfo mismatch: %+v", req.MetadataInfo)
	}
	if req.MetadataInfo.IncidentType != "lateral_movement" {
		t.Fatalf("IncidentType=%q", req.MetadataInfo.IncidentType)
	}
}

func TestBuildTransferIncidentReqNameFallback(t *testing.T) {
	req := buildTransferIncidentReq(domain.Event{EventID: "evt-x"}, nil)
	if req.Name != "流量分析事件 evt-x" {
		t.Fatalf("fallback Name=%q", req.Name)
	}
}
