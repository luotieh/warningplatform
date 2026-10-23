package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestEventListPacketPayloadSortUsesMeasuredFrames(t *testing.T) {
	s, st := newTestEventService(t, "")
	ctx := context.Background()
	frame := "00112233445566778899aabb08004500002b0000000040060000c0000201cb007102afc800500000007b000000005010200000000000616263"
	for i, n := range []int{0, 3} {
		id := fmt.Sprintf("measured-%d", n)
		rawFrame := frame
		if n == 0 {
			rawFrame = strings.Replace(frame, "4500002b", "45000028", 1)
			rawFrame = strings.TrimSuffix(rawFrame, "616263")
		}
		_, err := st.CreateEvent(domain.Event{EventID: id, Context: `{"src_ip":"192.0.2.1","dst_ip":"203.0.113.2","quant_stats":{"volume_quality":"verified","total_payload_bytes":999999}}`})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"device_id": id, "src_ip": "192.0.2.1", "dst_ip": "203.0.113.2", "src_port": 45000, "dst_port": 80, "protocol": "tcp", "raw_packet": map[string]any{"packet_hex": rawFrame, "capture_time": "2026-10-23T01:00:00Z", "packet_sequence": i + 1}})
		hit, err := st.InsertHit(ctx, store.Hit{ID: id, DedupKey: id, EventID: id, OccurredAt: time.Date(2026, 10, 23, 1, 0, i, 0, time.UTC), Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range []struct {
			kind, key string
			value     any
		}{{"segment", id, map[string]any{"event_id": id, "stats_version": 1}}, {"snapshot", id + ":1", trafficservice.EvidenceSnapshot{EventID: id, Version: 1, Sources: []string{id}, Watermark: hit.Sequence, Count: 1}}} {
			b, _ := json.Marshal(r.value)
			if err := st.PutAggregateRecord(ctx, store.AggregateRecord{Kind: r.kind, Key: r.key, Value: b}); err != nil {
				t.Fatal(err)
			}
		}
	}
	st.CreateEvent(domain.Event{EventID: "legacy-unknown", Context: `{"quant_stats":{"volume_quality":"verified","total_payload_bytes":999999999}}`})
	for _, order := range []string{"asc", "desc"} {
		rows, total, err := s.ListPage(ctx, store.EventQuery{Scope: "all", Sort: "payload", Order: order, PageSize: 20})
		if err != nil {
			t.Fatal(err)
		}
		first := "measured-3"
		if order == "asc" {
			first = "measured-0"
		}
		if total != 3 || rows[0]["id"] != first || rows[2]["id"] != "legacy-unknown" {
			t.Fatalf("wrong measured sorting %s: %+v", order, rows)
		}
		value := rows[0]["hit_packet_payload"].(trafficservice.HitPacketPayload)
		if value.Quality != "verified" {
			t.Fatalf("not measured %+v", value)
		}
	}
}
