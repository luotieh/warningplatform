package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/store"
)

func TestAggregatedEvidenceContextIncludesIOCEnrichment(t *testing.T) {
	ctx := context.Background()
	svc := Services{Store: store.NewMemoryStore()}
	hit := testHit("ioc-context", time.Now().UTC().Add(-time.Minute))
	hit["ioc_type"] = "ip"
	hit["ioc_value"] = "203.0.113.10"
	hit["ioc_description"] = "WHOIS 显示近期注册的可疑地址"
	hit["ioc_evidence"] = map[string]any{
		"source":      "ThreatBook",
		"cross_check": "WHOIS 与 ThreatBook 交叉验证",
		"confidence":  "high",
		"narrative":   "多来源均标记为恶意基础设施",
	}
	hit["recommended_action"] = "block_and_report"
	r, err := svc.ProcessLyEvent(ctx, hit)
	if err != nil {
		t.Fatal(err)
	}
	id := asString(r["deepsoc_event_id"])
	if err := svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	event := mustEvent(t, svc, id)
	raw, err := svc.EvidenceContext(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(raw)) > 6000 {
		t.Fatalf("model context exceeds limit: %d", len([]rune(raw)))
	}
	modelContext := decodeEventContext(raw)
	ioc, _ := modelContext["ioc"].(map[string]any)
	if ioc["ioc_description"] != "WHOIS 显示近期注册的可疑地址" {
		t.Fatalf("IOC description missing: %v", ioc)
	}
	evidence, _ := modelContext["ioc_evidence"].(map[string]any)
	if evidence["cross_check"] != "WHOIS 与 ThreatBook 交叉验证" || evidence["source"] != "ThreatBook" {
		t.Fatalf("IOC cross-check missing: %v", evidence)
	}
	if modelContext["recommended_action"] != "block_and_report" {
		t.Fatalf("IOC action missing: %v", modelContext["recommended_action"])
	}
	event.Context = raw
	prompt := autoAnalysisPrompt(event, "")
	for _, want := range []string{"WHOIS 显示近期注册的可疑地址", "WHOIS 与 ThreatBook 交叉验证", "block_and_report"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("model prompt missing %q", want)
		}
	}
}
