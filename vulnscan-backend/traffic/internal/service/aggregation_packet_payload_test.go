package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/store"
)

func packetPayloadFixture(t *testing.T, body string, seq int) map[string]any {
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	rp := exchangeTestPacket(t, []byte(body), 123, 0, at, false)
	rp["packet_sequence"] = seq
	m := testHit("packet-a", at)
	m["src_ip"], m["dst_ip"], m["src_port"], m["dst_port"], m["protocol"] = "192.0.2.1", "203.0.113.2", 45000, 80, "tcp"
	m["raw_packet"] = rp
	m["device_id"] = "test-node"
	// These are deliberately unrelated cumulative counters, never packet bytes.
	m["bytes"], m["wire_bytes"], m["packets"] = 999999, 9999999, 5000
	raw, _ := json.Marshal(m)
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	return decoded
}
func TestHitPacketPayloadDeduplicatesRulesAndCountsRetransmissions(t *testing.T) {
	m := packetPayloadFixture(t, "abc", 1)
	a := newPacketPayloadAccumulator()
	a.add(m)
	m["event_id"] = "packet-other-rule"
	m["rule_id"] = "another"
	a.add(m)
	nestedMap(m, "raw_packet")["packet_sequence"] = float64(2)
	a.add(m)
	r := a.finish(3)
	if r.Quality != "verified" || r.PayloadBytes != 6 || r.UniquePackets != 2 || r.DuplicateRecords != 1 {
		t.Fatalf("wrong packet volume: %+v", r)
	}
}
func TestHitPacketPayloadRejectsUnsafeFrames(t *testing.T) {
	for _, name := range []string{"missing_identity", "truncated", "bad_hex", "tuple_conflict", "declared_truncated"} {
		t.Run(name, func(t *testing.T) {
			m := packetPayloadFixture(t, "abc", 1)
			rp := nestedMap(m, "raw_packet")
			switch name {
			case "missing_identity":
				delete(rp, "packet_sequence")
			case "truncated":
				b, _ := hex.DecodeString(asString(rp["packet_hex"]))
				rp["packet_hex"] = hex.EncodeToString(b[:len(b)-8])
			case "bad_hex":
				rp["packet_hex"] = "zz"
			case "tuple_conflict":
				m["src_port"] = 45001
			case "declared_truncated":
				rp["capture_truncated"] = true
			}
			a := newPacketPayloadAccumulator()
			a.add(m)
			r := a.finish(1)
			if r.Quality != "unavailable" || r.PayloadBytes != 0 || r.RejectedRecords != 1 {
				t.Fatalf("unsafe frame accepted: %+v", r)
			}
		})
	}
}
func TestHitPacketPayloadPartialZeroAndConflicts(t *testing.T) {
	m := packetPayloadFixture(t, "", 1)
	a := newPacketPayloadAccumulator()
	a.add(m)
	if r := a.finish(1); r.Quality != "verified" || r.PayloadBytes != 0 || r.UniquePackets != 1 {
		t.Fatalf("zero payload lost %+v", r)
	}
	if r := a.finish(2); r.Quality != "partial" || r.Reasons["snapshot_record_count_mismatch"] == 0 {
		t.Fatalf("missing row not partial %+v", r)
	}
	m = packetPayloadFixture(t, "abc", 2)
	a = newPacketPayloadAccumulator()
	a.add(m)
	rp := nestedMap(m, "raw_packet")
	frame, _ := hex.DecodeString(asString(rp["packet_hex"]))
	frame[len(frame)-1] ^= 1
	rp["packet_hex"] = hex.EncodeToString(frame)
	a.add(m)
	if r := a.finish(2); r.Quality != "unavailable" || r.PayloadBytes != 0 || r.Reasons["packet_identity_conflict"] != 1 {
		t.Fatalf("conflict counted %+v", r)
	}
}
func TestHitPacketPayloadOldSnapshotCacheAndNoReportChanges(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	m := packetPayloadFixture(t, "hello", 1)
	out, err := svc.ProcessLyEvent(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	id := asString(out["deepsoc_event_id"])
	if err = svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	before, _ := svc.Store.GetEvent(id)
	for i := 0; i < 2; i++ {
		r, err := svc.HitPacketPayload(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Quality != "verified" || r.PayloadBytes != 5 {
			t.Fatalf("wrong saved result %+v", r)
		}
	}
	after, _ := svc.Store.GetEvent(id)
	if before.Context != after.Context || before.AnalysisVersion != after.AnalysisVersion || len(svc.Store.ListSummaries(id)) != 0 {
		t.Fatal("reading packet bytes changed event or report")
	}
	cached, err := svc.Store.AggregateRecords(ctx, "hit_packet_payload", id, 0)
	if err != nil || len(cached) != 1 {
		t.Fatal("derived cache missing")
	}
}
