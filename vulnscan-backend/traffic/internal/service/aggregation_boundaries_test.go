package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestAggregationLargeDistributionKeepsCompleteSnapshotAndBoundedModelInput(t *testing.T) {
	ctx := context.Background()
	svc := Services{Store: store.NewMemoryStore()}
	at := time.Now().UTC().Add(-time.Hour)
	id := ""
	for i := 0; i < 80; i++ {
		m := testHit(fmt.Sprint(i), at.Add(time.Duration(i)*time.Second))
		m["rule_id"] = fmt.Sprintf("rule-%03d", i)
		m["ioc_value"] = fmt.Sprintf("domain-%03d.example.test", i)
		m["ioc_type"] = "domain"
		m["exchange"] = map[string]any{"response": strings.Repeat("HTTP response evidence ", 1000)}
		r, err := svc.ProcessLyEvent(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		id = asString(r["deepsoc_event_id"])
	}
	if err := svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.EvidenceSnapshot(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := snap.Context["quant_stats"].(map[string]any)
	if len(q["by_ioc"].([]any)) != 80 || len(q["by_rule"].(map[string]any)) != 80 {
		t.Fatal("full statistical distribution lost")
	}
	ev := mustEvent(t, svc, id)
	if len(ev.Context) > 60000 {
		t.Fatalf("event projection exceeds TEXT budget: %d", len(ev.Context))
	}
	raw, err := svc.EvidenceContext(ctx, ev)
	if err != nil || len([]rune(raw)) > 6000 {
		t.Fatalf("model budget failed: %d %v", len([]rune(raw)), err)
	}
	c := decodeEventContext(raw)
	if len(c["evidence_index"].([]any)) == 0 {
		t.Fatal("statistics squeezed out all raw evidence")
	}
	manifest := c["input_manifest"].(map[string]any)
	if toInt(manifest["scanned_hits"]) != 80 || manifest["distribution_compression"] == nil {
		t.Fatal("missing compression provenance")
	}
}

func TestAggregationOrderAndThirtyMinuteBoundary(t *testing.T) {
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	offsets := []time.Duration{0, 20 * time.Minute, 40 * time.Minute, 70 * time.Minute, 100*time.Minute - time.Microsecond, 130 * time.Minute}
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5}, {5, 4, 3, 2, 1, 0}, {2, 0, 5, 1, 4, 3}} {
		svc := Services{Store: store.NewMemoryStore()}
		for _, i := range order {
			ingestTestHit(t, svc, fmt.Sprint(i), base.Add(offsets[i]))
		}
		if err := svc.DrainAggregation(context.Background(), 100); err != nil {
			t.Fatal(err)
		}
		records, err := svc.Store.AggregateRecords(context.Background(), "segment", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		counts := []int{}
		for _, r := range records {
			var seg EventSegment
			_ = json.Unmarshal(r.Value, &seg)
			if seg.CanonicalID == seg.EventID {
				counts = append(counts, int(seg.Count))
			}
		}
		sort.Ints(counts)
		if fmt.Sprint(counts) != "[1 2 3]" {
			t.Fatalf("order %v -> %v", order, counts)
		}
	}
}

func TestAggregationPacketIdentityDeviceScopeAndDirection(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	m := testHit("same-id", at)
	m["volume_mode"] = "packet"
	m["packets"] = 1
	r, err := svc.ProcessLyEvent(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	id := asString(r["deepsoc_event_id"])
	m["event_id"] = "second-rule"
	m["rule_id"] = "rule-b"
	if _, err = svc.ProcessLyEvent(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err = svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.EvidenceSnapshot(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := snap.Context["quant_stats"].(map[string]any)
	if snap.Count != 2 || toInt(q["total_packets"]) != 1 || toInt(q["total_payload_bytes"]) != 150 {
		t.Fatalf("same packet multi-rule: %v", q)
	}
	if stats := fromMap(q); stats == nil || stats.OccurrenceCount != 2 {
		t.Fatal("legacy stats reader incompatible")
	}
	m["device_id"] = "node-b"
	if _, err = svc.ProcessLyEvent(ctx, m); err != nil {
		t.Fatal(err)
	}
	m["src_ip"], m["dst_ip"] = m["dst_ip"], m["src_ip"]
	m["event_id"] = "reverse"
	reverse, err := svc.ProcessLyEvent(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	// 方向无关聚合：请求/应答（端点互换）同键合并为同一事件。
	if asString(reverse["deepsoc_event_id"]) != id {
		t.Fatalf("reverse direction not merged: %v", reverse)
	}
	if err = svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	snap, err = svc.EvidenceSnapshot(ctx, id, 0)
	if err != nil || snap.Count != 4 {
		t.Fatalf("device scoped identity: %d %v", snap.Count, err)
	}
	if _, err = svc.Occurrences(ctx, id, "", asString(reverse["hit_id"]), 1); err != nil {
		t.Fatal("reverse hit must be queryable within the merged event")
	}
}

func TestAggregationSnapshotReportInvalidation(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	id := ingestTestHit(t, svc, "first", at)
	if err := svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	raw, err := svc.EvidenceContext(ctx, mustEvent(t, svc, id))
	if err != nil {
		t.Fatal(err)
	}
	ingestTestHit(t, svc, "arrived-during-model", at.Add(time.Second))
	if err = svc.MarkReportSnapshot(ctx, id, raw); err != nil {
		t.Fatal(err)
	}
	c := decodeEventContext(mustEvent(t, svc, id).Context)
	if c["report_stale"] != true || toInt(c["report_data_version"]) != 1 || toInt(c["occurrence_count"]) != 1 || toInt(c["data_version"]) != 2 {
		t.Fatalf("mixed published versions: %v", c)
	}
	if err = svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	old, err := svc.EvidenceSnapshot(ctx, id, 1)
	if err != nil || old.Count != 1 {
		t.Fatal("old report membership changed")
	}
	filtered, err := svc.OccurrencesAt(ctx, id, "", "", 100, 0, at.Add(time.Second).UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), at.Add(2*time.Second).Format(time.RFC3339Nano))
	if err != nil || len(filtered.Items) != 1 {
		t.Fatalf("time-filtered evidence: %v %v", filtered, err)
	}
}

func TestAggregationMicrosecondAndInvalidTimes(t *testing.T) {
	at := time.Date(2026, 9, 14, 16, 0, 0, 123457000, time.UTC)
	m := testHit("numeric-only", at)
	delete(m, "raw_packet")
	h, _, reason := normalizeHit(m, time.Now().UTC())
	if reason != "" || !h.OccurredAt.Equal(at) {
		t.Fatalf("microsecond changed: %v %s", h.OccurredAt, reason)
	}
	for _, value := range []any{nil, "bad", time.Now().Add(time.Hour).Format(time.RFC3339Nano)} {
		m["event_time"] = value
		if _, _, reason := normalizeHit(m, time.Now().UTC()); reason != "missing_or_invalid_occurrence_time" {
			t.Fatalf("invalid time accepted: %v", value)
		}
	}
}

func TestAggregationRepairRollbackPreventsReactivation(t *testing.T) {
	ctx := context.Background()
	svc := Services{Store: store.NewMemoryStore()}
	at := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	h, m, _ := normalizeHit(testHit("historic", at), time.Now().UTC())
	m["occurrences"] = []any{hitOccurrence(h)}
	m["occurrence_count"] = 1
	raw, _ := json.Marshal(m)
	_, err := svc.Store.CreateEvent(domain.Event{EventID: "legacy", Context: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	before := mustEvent(t, svc, "legacy")
	plan, err := svc.AuditAggregation(ctx)
	if err != nil || len(plan.Entries[0].Recoverable) != 1 {
		t.Fatalf("audit: %v %+v", err, plan)
	}
	if err = svc.ApplyAggregationRepair(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err = svc.RollbackAggregationRepair(ctx, plan.BatchID); err != nil {
		t.Fatal(err)
	}
	if err = svc.ApplyAggregationRepair(ctx, plan); err == nil {
		t.Fatal("rolled-back batch accepted")
	}
	if err = svc.RebuildAggregation(ctx, "legacy"); err != nil {
		t.Fatal(err)
	}
	if err = svc.convergeAggregation(ctx, "legacy", time.Now()); err != nil {
		t.Fatal(err)
	}
	after := mustEvent(t, svc, "legacy")
	if before.Context != after.Context || before.ReviewStatus != after.ReviewStatus || before.AggregationClosed != after.AggregationClosed || after.LastSeenAt != nil {
		t.Fatal("rollback did not restore lifecycle")
	}
	if _, err = svc.EvidenceSnapshot(ctx, "legacy", 0); err == nil || err.Error() != "legacy_event" {
		t.Fatalf("rolled-back snapshot revived: %v", err)
	}
	if tasks, err := svc.Store.AggregateRecords(ctx, "analysis_outbox", "pending", 0); err != nil || len(tasks) != 0 {
		t.Fatalf("repair scheduled model: %v %v", tasks, err)
	}
}

func TestAggregationCumulativeBaselineAndReset(t *testing.T) {
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	v := newVolumeAccumulator(at)
	for i, n := range []int{150, 100, 150, 20} {
		m := testHit(fmt.Sprint(i), at.Add(time.Duration(i)*time.Second))
		m["volume_mode"] = "cumulative"
		m["session_id"] = "flow"
		m["counter_epoch"] = "first"
		if i == 3 {
			m["counter_epoch"] = "reset"
		}
		m["counter_zero_baseline"] = true
		m["counter_started_at"] = at.Format(time.RFC3339Nano)
		m["bytes"] = n
		v.add(m)
	}
	q := map[string]any{}
	v.publish(q)
	if toInt(q["total_payload_bytes"]) != 170 {
		t.Fatalf("counter high water/reset: %v", q)
	}
	m := testHit("cross-event", at)
	m["volume_mode"] = "cumulative"
	m["session_id"] = "flow"
	m["counter_epoch"] = "first"
	m["counter_zero_baseline"] = true
	m["counter_started_at"] = at.Add(-time.Minute).Format(time.RFC3339Nano)
	v = newVolumeAccumulator(at)
	v.add(m)
	q = map[string]any{}
	v.publish(q)
	if q["volume_quality"] != "unverified" || q["total_payload_bytes"] != nil {
		t.Fatalf("cross-event flow counted: %v", q)
	}
}
