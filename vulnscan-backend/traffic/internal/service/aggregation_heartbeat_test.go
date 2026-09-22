package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/store"
)

func TestAggregationHeartbeatPersistedFromFullScan(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	id := ""
	for i := 0; i < 12; i++ {
		r, err := svc.ProcessLyEvent(ctx, testHit(fmt.Sprint(i), base.Add(time.Duration(i*30)*time.Second)))
		if err != nil {
			t.Fatal(err)
		}
		id = asString(r["deepsoc_event_id"])
	}
	if err := svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	c := decodeEventContext(mustEvent(t, svc, id).Context)
	if got, ok := c["heartbeat_detected"].(bool); !ok || !got {
		t.Fatalf("heartbeat_detected = %v (ok=%v), want true", c["heartbeat_detected"], ok)
	}
	if got := toInt(c["heartbeat_period_sec"]); got != 30 {
		t.Fatalf("heartbeat_period_sec = %d, want 30", got)
	}
	// UI 预览只有最近 10 条，12 条全量判定结论必须来自快照而非预览。
	if occs, _ := c["occurrences"].([]any); len(occs) > 10 {
		t.Fatalf("expected bounded UI preview, got %d", len(occs))
	}
}

func TestAggregationHeartbeatExcludedByLargePacket(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	id := ""
	for i := 0; i < 12; i++ {
		m := testHit(fmt.Sprint(i), base.Add(time.Duration(i*30)*time.Second))
		if i == 5 {
			m["packets"] = 9
		}
		r, err := svc.ProcessLyEvent(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		id = asString(r["deepsoc_event_id"])
	}
	if err := svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	c := decodeEventContext(mustEvent(t, svc, id).Context)
	detected, ok := c["heartbeat_detected"].(bool)
	if !ok {
		t.Fatal("heartbeat_detected missing after rebuild; 否定结论也必须持久化，避免展示层回退到预览窗口重判")
	}
	if detected {
		t.Fatal("large-packet observation must exclude heartbeat")
	}
}
