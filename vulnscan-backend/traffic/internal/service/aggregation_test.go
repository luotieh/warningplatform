package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func testHit(id string, at time.Time) map[string]any {
	return map[string]any{"event_id": id, "device_id": "node-a", "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "src_port": 1234, "dst_port": 53, "event_type": "scan", "protocol": "udp", "rule_id": "rule-a", "event_time": at.UnixMicro(), "raw_packet": map[string]any{"capture_time": at.Format(time.RFC3339Nano), "packet_sequence": at.UnixMicro(), "payload_hex": "00010203"}, "bytes": 150, "packets": 3, "wire_bytes": 200}
}
func ingestTestHit(t *testing.T, s Services, id string, at time.Time) string {
	t.Helper()
	r, e := s.ProcessLyEvent(context.Background(), testHit(id, at))
	if e != nil {
		t.Fatal(e)
	}
	event := asString(r["deepsoc_event_id"])
	if event == "" {
		t.Fatalf("not accepted: %v", r)
	}
	return event
}

func TestAggregationConcurrentRetryAndEvidenceConflict(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	m := testHit("same", time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond))
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := svc.ProcessLyEvent(ctx, m); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	events := svc.Store.ListEvents()
	if len(events) != 1 {
		t.Fatal(len(events))
	}
	if e := svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(ctx, events[0].EventID, 0)
	if e != nil || snap.Count != 1 {
		t.Fatalf("%v count=%d", e, snap.Count)
	}
	m["dst_ip"] = "192.0.2.9"
	r, e := svc.ProcessLyEvent(ctx, m)
	if e != nil || r["ingest_status"] != "identity_conflict" {
		t.Fatalf("%v %v", r, e)
	}
	if len(svc.Store.ListEvents()) != 1 {
		t.Fatal("conflict created event")
	}
}

// 方向无关聚合：同一次通联的请求/应答（端点对互换、同事件类型）必须合并为
// 一条事件，occurrences 按命中时间排序（请求在前、应答在后）。
func TestAggregationRequestResponseMerge(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	request := testHit("req-1", base)
	event := ingestTestHit(t, svc, "req-1", base)

	response := testHit("resp-1", base.Add(time.Second))
	response["src_ip"], response["dst_ip"] = request["dst_ip"], request["src_ip"]
	response["src_port"], response["dst_port"] = request["dst_port"], request["src_port"]
	r, err := svc.ProcessLyEvent(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	if got := asString(r["deepsoc_event_id"]); got != event {
		t.Fatalf("response hit split into separate event: %q != %q", got, event)
	}
	if r["aggregated"] != true {
		t.Fatalf("response hit not aggregated: %v", r)
	}
	if len(svc.Store.ListEvents()) != 1 {
		t.Fatal("request/response must stay one event")
	}
	if err = svc.DrainAggregation(ctx, 20); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.EvidenceSnapshot(ctx, event, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Count != 2 {
		t.Fatalf("count=%d, want 2", snap.Count)
	}
	occs, _ := snap.Context["occurrences"].([]any)
	if len(occs) != 2 {
		t.Fatalf("occurrences=%d, want 2", len(occs))
	}
	first, _ := occs[0].(map[string]any)
	second, _ := occs[1].(map[string]any)
	if asString(first["time"]) != base.Format(time.RFC3339Nano) {
		t.Fatalf("first occurrence is not the request: %v", first["time"])
	}
	if asString(second["time"]) != base.Add(time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("second occurrence is not the response: %v", second["time"])
	}
}

// 乱序摄入：应答先到、请求后到。合并后事件朝向必须校正为时间最早的请求方向，
// occurrences 仍为请求在前、应答在后。
func TestAggregationResponseFirstOrientation(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	response := testHit("resp-1", base.Add(time.Second))
	response["src_ip"], response["dst_ip"] = "192.0.2.2", "192.0.2.1"
	response["src_port"], response["dst_port"] = 53, 1234
	r0, err := svc.ProcessLyEvent(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	event := asString(r0["deepsoc_event_id"])
	if event == "" {
		t.Fatalf("not accepted: %v", r0)
	}

	ev, _ := svc.Store.GetEvent(event)
	ctxMap := decodeEventContext(ev.Context)
	if asString(ctxMap["src_ip"]) != "192.0.2.2" {
		t.Fatalf("setup: response-oriented event expected, got src=%v", ctxMap["src_ip"])
	}

	r, err := svc.ProcessLyEvent(ctx, testHit("req-1", base))
	if err != nil {
		t.Fatal(err)
	}
	if got := asString(r["deepsoc_event_id"]); got != event {
		t.Fatalf("earlier request hit split into separate event: %q != %q", got, event)
	}
	ev, _ = svc.Store.GetEvent(event)
	ctxMap = decodeEventContext(ev.Context)
	if asString(ctxMap["src_ip"]) != "192.0.2.1" || asString(ctxMap["dst_ip"]) != "192.0.2.2" {
		t.Fatalf("orientation not corrected to request direction: %v -> %v", ctxMap["src_ip"], ctxMap["dst_ip"])
	}
	if err = svc.DrainAggregation(ctx, 20); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.EvidenceSnapshot(ctx, event, 0)
	if err != nil {
		t.Fatal(err)
	}
	occs, _ := snap.Context["occurrences"].([]any)
	if len(occs) != 2 {
		t.Fatalf("occurrences=%d, want 2", len(occs))
	}
	first, _ := occs[0].(map[string]any)
	if asString(first["time"]) != base.Format(time.RFC3339Nano) {
		t.Fatalf("occurrences not chronologically ordered: %v", first["time"])
	}
}
func TestAggregationLateBridgePreservesSnapshots(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	first := ingestTestHit(t, svc, "a", base)
	second := ingestTestHit(t, svc, "b", base.Add(40*time.Minute))
	if first == second {
		t.Fatal("merged separated segments")
	}
	firstSeg, _, _ := readSegment(ctx, svc.Store, first)
	secondSeg, _, _ := readSegment(ctx, svc.Store, second)
	// Windows can return identical wall-clock creation times; the contract then
	// chooses the lexicographically smaller event ID, not call order.
	if firstSeg.Created.Equal(secondSeg.Created) && second < first {
		first, second = second, first
	}
	if e := svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	old, e := svc.EvidenceSnapshot(ctx, second, 0)
	if e != nil {
		t.Fatal(e)
	}
	svc.Store.UpdateEvent(second, map[string]any{"review_status": "approved", "circular_code": "keep-this"})
	bridge := ingestTestHit(t, svc, "bridge", base.Add(20*time.Minute))
	if bridge != first {
		t.Fatal("canonical not earliest")
	}
	if e := svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(ctx, first, 0)
	if e != nil || snap.Count != 3 {
		t.Fatalf("%v %d", e, snap.Count)
	}
	oldAgain, e := svc.EvidenceSnapshot(ctx, second, old.Version)
	if e != nil || oldAgain.Count != 1 {
		t.Fatal("historical snapshot changed")
	}
	alias, _ := svc.Store.GetEvent(second)
	if alias.CircularCode != "keep-this" {
		t.Fatal("lost review")
	}
	page, e := svc.Store.ListEventsPage(store.EventQuery{Scope: "all"})
	if e != nil || page.Total != 1 {
		t.Fatalf("aliases visible: %v %d", e, page.Total)
	}
}

func TestAggregationFullPeakAndStablePagination(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	id := ""
	for i := 0; i < 676; i++ {
		id = ingestTestHit(t, svc, fmt.Sprint(i), at)
	}
	if e := svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(ctx, id, 0)
	if e != nil {
		t.Fatal(e)
	}
	qs := snap.Context["quant_stats"].(map[string]any)
	peak := qs["peak_window"].(map[string]any)
	if toInt(peak["count"]) != 676 || qs["rate_per_min"] != nil || qs["total_payload_bytes"] != nil {
		t.Fatalf("wrong full stats: %v", qs)
	}
	first, e := svc.Occurrences(ctx, id, "", "", 100)
	if e != nil {
		t.Fatal(e)
	}
	version := first.SnapshotVersion
	seen := map[string]bool{}
	cursor := first.NextCursor
	for _, o := range first.Items {
		seen[asString(o["hit_id"])] = true
	}
	ingestTestHit(t, svc, "late-new", at.Add(-time.Second))
	if e := svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	for cursor != "" {
		p, e := svc.Occurrences(ctx, id, cursor, "", 100)
		if e != nil {
			t.Fatal(e)
		}
		if p.SnapshotVersion != version {
			t.Fatal("page version drift")
		}
		for _, o := range p.Items {
			hid := asString(o["hit_id"])
			if seen[hid] {
				t.Fatal("duplicate page")
			}
			seen[hid] = true
		}
		cursor = p.NextCursor
	}
	if len(seen) != 676 {
		t.Fatal(len(seen))
	}
	raw, e := svc.EvidenceContext(ctx, mustEvent(t, svc, id))
	if e != nil {
		t.Fatal(e)
	}
	c := decodeEventContext(raw)
	if toInt(c["input_manifest"].(map[string]any)["scanned_hits"]) != 677 {
		t.Fatal("not full scan")
	}
}

func mustEvent(t *testing.T, s Services, id string) domain.Event {
	t.Helper()
	e, ok := s.Store.GetEvent(id)
	if !ok {
		t.Fatal("missing event")
	}
	return e
}

func TestAggregationRevisionDoesNotAddHit(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	m := testHit("revision", time.Now().UTC().Add(-time.Hour))
	m["context_revision"] = 1
	r, e := svc.ProcessLyEvent(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	id := asString(r["deepsoc_event_id"])
	if e = svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	old, e := svc.EvidenceSnapshot(ctx, id, 0)
	if e != nil {
		t.Fatal(e)
	}
	m["context_revision"] = 2
	m["exchange"] = map[string]any{"response": "new evidence"}
	r, e = svc.ProcessLyEvent(ctx, m)
	if e != nil || r["ingest_status"] != "evidence_updated" {
		t.Fatalf("%v %v", r, e)
	}
	if e = svc.DrainAggregation(ctx, 20); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(ctx, id, 0)
	if e != nil || snap.Count != 1 {
		t.Fatalf("%v %d", e, snap.Count)
	}
	page, e := svc.Occurrences(ctx, id, "", "", 100)
	if e != nil || page.Items[0]["exchange"] == nil {
		t.Fatalf("revision lost: %v %v", page, e)
	}
	oldPage, e := svc.OccurrencesAt(ctx, id, "", asString(r["hit_id"]), 1, old.Version)
	if e != nil || len(oldPage.Items) != 1 || oldPage.Items[0]["exchange"] != nil {
		t.Fatalf("old report resolved newer evidence: %v %v", oldPage, e)
	}
	raw, e := svc.EvidenceContext(ctx, mustEvent(t, svc, id))
	if e != nil {
		t.Fatal(e)
	}
	modelInput := decodeEventContext(raw)
	evidence := modelInput["evidence_index"].([]any)
	if len(evidence) != 1 || evidence[0].(map[string]any)["exchange"] == nil {
		t.Fatal("model lost response enrichment")
	}
	oldSnap, e := svc.EvidenceSnapshot(ctx, id, old.Version)
	if e != nil || oldSnap.RevisionWatermark != 0 {
		t.Fatal("old evidence changed")
	}
	r, e = svc.ProcessLyEvent(ctx, m)
	if e != nil || r["duplicate"] != true {
		t.Fatalf("revision retry %v %v", r, e)
	}
	m["exchange"] = map[string]any{"response": "conflicting same revision"}
	r, e = svc.ProcessLyEvent(ctx, m)
	if e != nil || r["ingest_status"] != "evidence_revision_conflict" {
		t.Fatalf("revision conflict lost: %v %v", r, e)
	}
}

func TestAggregationInvalidIdentityQuarantined(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	m := testHit("a", time.Now().UTC())
	delete(m, "device_id")
	r, e := svc.ProcessLyEvent(context.Background(), m)
	if e != nil || r["ingest_status"] != "pending_verification" || len(svc.Store.ListEvents()) != 0 {
		t.Fatalf("%v %v", r, e)
	}
}

func TestAggregationPeakHalfOpenBoundary(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	base := time.Now().UTC().Add(-time.Hour)
	id := ingestTestHit(t, svc, "a", base)
	ingestTestHit(t, svc, "b", base.Add(5*time.Minute))
	if e := svc.DrainAggregation(context.Background(), 20); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(context.Background(), id, 0)
	if e != nil {
		t.Fatal(e)
	}
	if toInt(snap.Context["quant_stats"].(map[string]any)["peak_window"].(map[string]any)["count"]) != 1 {
		t.Fatal("300 second boundary included")
	}
}
