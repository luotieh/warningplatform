package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestScanConvergedClosesAndSchedulesFinal(t *testing.T) {
	st := store.NewMemoryStore()
	now := time.Now().UTC()
	lastSeen := now.Add(-ConvergenceIdleWindow - time.Minute).Format(time.RFC3339)
	ctxMap := map[string]any{
		"occurrence_count": 3,
		"last_seen_at":     lastSeen,
		"quant_stats": map[string]any{
			"occurrence_count": 3,
			"window_start":     now.Add(-20 * time.Minute).Format(time.RFC3339),
			"window_end":       now.Add(-11 * time.Minute).Format(time.RFC3339),
			"by_rule":          map[string]any{"SEC-CC-001": 3},
			"by_direction":     map[string]any{"inbound": 3},
			"by_ioc":           []any{},
			"source_ips":       map[string]any{"1.2.3.4": 3},
			"dest_ips":         map[string]any{"10.0.0.8": 3},
		},
	}
	ctxJSON, _ := json.Marshal(ctxMap)
	_, err := st.CreateEvent(domain.Event{
		EventID:         "evt-converge-1",
		EventName:       "CC攻击",
		Severity:        "high",
		EventStatus:     "pending",
		Context:         string(ctxJSON),
		AnalysisVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := Services{Store: st}

	n, err := svc.ScanConverged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("scheduled = %d, want 1", n)
	}
	ev, ok := st.GetEvent("evt-converge-1")
	if !ok {
		t.Fatal("event missing")
	}
	if !ev.AggregationClosed {
		t.Fatal("event should be marked aggregation_closed")
	}
	// 未收敛事件不受影响。
	_, err = st.CreateEvent(domain.Event{
		EventID:     "evt-active-1",
		EventName:   "进行中",
		Severity:    "medium",
		EventStatus: "pending",
		Context:     `{"last_seen_at":"` + now.Format(time.RFC3339) + `"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, _ = svc.ScanConverged(context.Background())
	if n != 0 {
		t.Fatalf("second scan scheduled = %d, want 0", n)
	}
}

func TestGenerateAssetMonthlySummaries(t *testing.T) {
	st := store.NewMemoryStore()
	_, err := st.CreateAsset(domain.Asset{ID: "asset-1", Name: "支付网关", AssetType: "ip", Address: "10.0.0.8", Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	period := time.Now().UTC().Format("2006-01")
	within := time.Now().UTC().Format(time.RFC3339)
	ctxMap := map[string]any{
		"dst_ip":           "10.0.0.8",
		"event_type":       "cc_attack",
		"last_time":        within,
		"occurrence_count": 5,
		"quant_stats": map[string]any{
			"occurrence_count": 5,
			"total_wire_bytes": 5000,
			"window_start":     within,
			"window_end":       within,
			"by_rule":          map[string]any{"SEC-CC-001": 5},
			"by_direction":     map[string]any{"inbound": 5},
			"by_ioc":           []any{},
			"source_ips":       map[string]any{"1.2.3.4": 5},
			"dest_ips":         map[string]any{"10.0.0.8": 5},
		},
	}
	ctxJSON, _ := json.Marshal(ctxMap)
	_, err = st.CreateEvent(domain.Event{
		EventID:           "evt-m-1",
		EventName:         "CC攻击",
		Severity:          "high",
		EventStatus:       "closed",
		Context:           string(ctxJSON),
		AggregationClosed: true,
		AnalysisVersion:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 不同目标 IP 的事件不应计入。
	_, err = st.CreateEvent(domain.Event{
		EventID:           "evt-m-2",
		EventName:         "其它",
		Severity:          "low",
		EventStatus:       "closed",
		Context:           `{"dst_ip":"10.0.0.9","last_time":"` + within + `"}`,
		AggregationClosed: true,
		AnalysisVersion:   2,
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := Services{Store: st}
	summaries, err := svc.GenerateAssetMonthlySummaries(context.Background(), period)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}
	sm := summaries[0]
	if sm.EventCount != 1 {
		t.Fatalf("event_count = %d, want 1", sm.EventCount)
	}
	if sm.Stats.TotalOccurrences != 5 || sm.Stats.TotalWireBytes != 5000 {
		t.Fatalf("stats mismatch: occ=%d wire=%d", sm.Stats.TotalOccurrences, sm.Stats.TotalWireBytes)
	}
	if sm.Stats.BySeverity["high"] != 1 {
		t.Fatalf("severity distribution mismatch: %+v", sm.Stats.BySeverity)
	}
	if len(sm.Stats.TopRules) != 1 || sm.Stats.TopRules[0].Value != "SEC-CC-001" {
		t.Fatalf("top rules mismatch: %+v", sm.Stats.TopRules)
	}
	if sm.Narrative == "" {
		t.Fatal("narrative should have LLM fallback text")
	}
	// 幂等重跑：同一资产+月份应覆盖更新而不是新增。
	summaries2, err := svc.GenerateAssetMonthlySummaries(context.Background(), period)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries2) != 1 {
		t.Fatalf("second run summaries = %d, want 1 (upsert)", len(summaries2))
	}
}
