package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestRepairPartialDryRunApplyRollback(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	ctx := context.Background()
	raw := `{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","event_type":"scan","occurrence_count":184913,"quant_stats":{"occurrence_count":184713},"last_time":"2026-09-10T20:50:10Z","occurrences":[{"time":"2026-09-10T20:50:10Z"}]}`
	_, e := st.CreateEvent(domain.Event{EventID: "legacy", Context: raw})
	if e != nil {
		t.Fatal(e)
	}
	st.UpdateEvent("legacy", map[string]any{"archive_date": "2026-09-14"})
	before, _ := st.GetEvent("legacy")
	plan, e := svc.AuditAggregation(ctx)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := st.GetEvent("legacy")
	if digest(before) != digest(after) {
		t.Fatal("audit wrote database")
	}
	if plan.Entries[0].Quality != "partial" || len(plan.Entries[0].Recoverable) != 0 {
		t.Fatal("invented missing hits")
	}
	b, _ := json.Marshal(plan)
	var reloaded RepairPlan
	if e = json.Unmarshal(b, &reloaded); e != nil {
		t.Fatal(e)
	}
	if e = svc.ApplyAggregationRepair(ctx, reloaded); e != nil {
		t.Fatal(e)
	}
	if e = svc.ApplyAggregationRepair(ctx, reloaded); e != nil {
		t.Fatal(e)
	}
	applied, _ := st.GetEvent("legacy")
	if toInt(decodeEventContext(applied.Context)["occurrence_count"]) != 184913 {
		t.Fatal("changed unverified total")
	}
	if applied.ArchiveDate.Format("2006-01-02") != "2026-09-11" {
		t.Fatal("wrong Beijing archive date")
	}
	if e = svc.RollbackAggregationRepair(ctx, plan.BatchID); e != nil {
		t.Fatal(e)
	}
	restored, _ := st.GetEvent("legacy")
	if restored.Context != before.Context || !restored.ArchiveDate.Equal(*before.ArchiveDate) {
		t.Fatal("rollback did not restore original")
	}
}

func TestRepairRejectsConcurrentEdits(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	_, _ = st.CreateEvent(domain.Event{EventID: "legacy", Context: `{"occurrence_count":4,"occurrences":[]}`})
	plan, e := svc.AuditAggregation(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	st.UpdateEvent("legacy", map[string]any{"review_status": "approved"})
	if e = svc.ApplyAggregationRepair(context.Background(), plan); e == nil {
		t.Fatal("overwrote post-preview review")
	}
}

func TestRepairReconstructsVerifiedGroup(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	ctx := context.Background()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	for i, id := range []string{"legacy-a", "legacy-b"} {
		m := testHit(id, base.Add(time.Duration(i)*time.Minute))
		hit, n, reason := normalizeHit(m, time.Now().UTC())
		if reason != "" {
			t.Fatal(reason)
		}
		o := hitOccurrence(hit)
		delete(o, "hit_id")
		delete(o, "evidence_id")
		n["occurrences"] = []any{o, o}
		n["occurrence_count"] = 2
		raw, _ := json.Marshal(n)
		_, e := st.CreateEvent(domain.Event{EventID: id, Context: string(raw), AnalysisVersion: 2})
		if e != nil {
			t.Fatal(e)
		}
	}
	plan, e := svc.AuditAggregation(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Entries) != 2 || plan.Entries[0].Quality != "verified" {
		t.Fatalf("not recoverable: %+v", plan.Entries)
	}
	if e = svc.ApplyAggregationRepair(ctx, plan); e != nil {
		t.Fatal(e)
	}
	if e = svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	page, e := st.ListEventsPage(store.EventQuery{Scope: "all"})
	if e != nil || page.Total != 1 {
		t.Fatalf("%v %d", e, page.Total)
	}
	snap, e := svc.EvidenceSnapshot(ctx, page.Items[0].EventID, 0)
	if e != nil || snap.Count != 2 {
		t.Fatalf("wrong recovered count %v %d", e, snap.Count)
	}
	if e = svc.RollbackAggregationRepair(ctx, plan.BatchID); e == nil {
		t.Fatal("rollback overwrote later snapshot publication")
	}
}

func TestVerifiedCumulativeCountersDoNotSumSnapshots(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	ctx := context.Background()
	id := ""
	for i, n := range []int{100, 150, 150} {
		m := testHit(string(rune('a'+i)), at.Add(time.Duration(i)*time.Second))
		m["volume_mode"] = "cumulative"
		m["session_id"] = "session"
		m["counter_epoch"] = "epoch"
		m["counter_zero_baseline"] = true
		m["counter_started_at"] = at.Format(time.RFC3339Nano)
		m["bytes"] = n
		m["wire_bytes"] = n
		m["packets"] = n / 50
		r, e := svc.ProcessLyEvent(ctx, m)
		if e != nil {
			t.Fatal(e)
		}
		id = asString(r["deepsoc_event_id"])
	}
	if e := svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(ctx, id, 0)
	if e != nil {
		t.Fatal(e)
	}
	q := snap.Context["quant_stats"].(map[string]any)
	if toInt(q["total_payload_bytes"]) != 150 || q["volume_quality"] != "verified" {
		t.Fatalf("%v", q)
	}
}
