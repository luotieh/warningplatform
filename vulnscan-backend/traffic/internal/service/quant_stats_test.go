package service

import (
	"testing"
	"time"
)

func TestInitAndUpdateQuantStats(t *testing.T) {
	ctx := map[string]any{}
	hit1 := map[string]any{
		"occurrence_time": "2026-08-01 10:00:00",
		"src_ip":          "1.2.3.4",
		"dst_ip":          "10.0.0.8",
		"rule_id":         "SEC-CC-001",
		"direction":       "inbound",
		"ioc_value":       "1.2.3.4",
		"ioc_type":        "ip",
		"wire_bytes":      1024,
		"packets":         5,
	}
	initQuantStats(ctx, hit1)

	qs := quantStatsFromContext(ctx)
	if qs == nil {
		t.Fatal("quant_stats missing after init")
	}
	if qs.OccurrenceCount != 1 {
		t.Fatalf("occurrence_count = %d, want 1", qs.OccurrenceCount)
	}
	if qs.TotalWireBytes != 1024 || qs.TotalPackets != 5 {
		t.Fatalf("volume mismatch: wire=%d packets=%d", qs.TotalWireBytes, qs.TotalPackets)
	}

	hit2 := map[string]any{
		"occurrence_time": "2026-08-01 10:05:30",
		"src_ip":          "1.2.3.4",
		"dst_ip":          "10.0.0.8",
		"rule_id":         "SEC-CC-001",
		"direction":       "inbound",
		"ioc_value":       "1.2.3.4",
		"ioc_type":        "ip",
		"wire_bytes":      512,
		"packets":         3,
	}
	updateQuantStats(ctx, hit2)
	qs = quantStatsFromContext(ctx)
	if qs.OccurrenceCount != 2 {
		t.Fatalf("occurrence_count = %d, want 2", qs.OccurrenceCount)
	}
	if qs.WindowStart != "2026-08-01 10:00:00" || qs.WindowEnd != "2026-08-01 10:05:30" {
		t.Fatalf("window = %s ~ %s", qs.WindowStart, qs.WindowEnd)
	}
	if qs.TotalWireBytes != 1536 || qs.TotalPackets != 8 {
		t.Fatalf("volume mismatch after merge: wire=%d packets=%d", qs.TotalWireBytes, qs.TotalPackets)
	}
	if qs.ByRule["SEC-CC-001"] != 2 {
		t.Fatalf("by_rule = %d, want 2", qs.ByRule["SEC-CC-001"])
	}
	if qs.ByDirection["inbound"] != 2 {
		t.Fatalf("by_direction = %d, want 2", qs.ByDirection["inbound"])
	}
	if len(qs.ByIOC) != 1 || qs.ByIOC[0].Count != 2 {
		t.Fatalf("by_ioc mismatch: %+v", qs.ByIOC)
	}
	if qs.UniqueSrcIPs != 1 || qs.UniqueDstIPs != 1 {
		t.Fatalf("unique ips = %d/%d, want 1/1", qs.UniqueSrcIPs, qs.UniqueDstIPs)
	}
}

func TestFreezeQuantStatsComputesRateAndPeak(t *testing.T) {
	base := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	ctx := map[string]any{
		quantStatsKey: map[string]any{
			"window_start":     base.Format(time.RFC3339),
			"window_end":       base.Add(10 * time.Minute).Format(time.RFC3339),
			"occurrence_count": 10,
			"by_rule":          map[string]any{},
			"by_direction":     map[string]any{},
			"by_ioc":           []any{},
			"source_ips":       map[string]any{"1.2.3.4": 10},
			"dest_ips":         map[string]any{"10.0.0.8": 10},
		},
	}
	occ := make([]any, 0, 10)
	for i := 0; i < 10; i++ {
		occ = append(occ, map[string]any{"time": base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)})
	}
	ctx["occurrences"] = occ

	freezeQuantStats(ctx)
	qs := quantStatsFromContext(ctx)
	if qs.DurationSec != 600 {
		t.Fatalf("duration = %d, want 600", qs.DurationSec)
	}
	if qs.RatePerMin < 0.99 || qs.RatePerMin > 1.01 {
		t.Fatalf("rate = %.2f, want ~1.0/min", qs.RatePerMin)
	}
	// 10 分钟内每分钟 1 次：5 分钟窗口最大包含 5~6 次。
	if qs.PeakWindow.Count < 5 || qs.PeakWindow.Count > 6 {
		t.Fatalf("peak count = %d, want 5~6", qs.PeakWindow.Count)
	}
	if qs.PeakWindow.StartTime == "" || qs.PeakWindow.EndTime == "" {
		t.Fatalf("peak window bounds empty: %+v", qs.PeakWindow)
	}
}
