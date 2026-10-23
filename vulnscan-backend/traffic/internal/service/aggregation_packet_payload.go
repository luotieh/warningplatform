package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const hitPacketPayloadVersion = "captured-hit-payload-1"

// Captured transport payload, including retransmissions, limited to saved hit
// frames. Never a complete session volume or unique application-byte estimate.
type HitPacketPayload struct {
	SnapshotVersion   int64            `json:"snapshot_version"`
	Watermark         int64            `json:"watermark"`
	RevisionWatermark int64            `json:"revision_watermark"`
	Version           string           `json:"version"`
	Quality           string           `json:"quality"`
	PayloadBytes      int64            `json:"payload_bytes"`
	UniquePackets     int64            `json:"unique_packets"`
	ReadRecords       int64            `json:"read_records"`
	RejectedRecords   int64            `json:"rejected_records"`
	DuplicateRecords  int64            `json:"duplicate_records"`
	ExpectedRecords   int64            `json:"expected_records"`
	Reasons           map[string]int64 `json:"reasons"`
}
type capturedPacket struct {
	hash     string
	bytes    int64
	conflict bool
}
type packetPayloadAccumulator struct {
	result HitPacketPayload
	seen   map[string]capturedPacket
}

func newPacketPayloadAccumulator() *packetPayloadAccumulator {
	return &packetPayloadAccumulator{result: HitPacketPayload{Version: hitPacketPayloadVersion, Reasons: map[string]int64{}}, seen: map[string]capturedPacket{}}
}
func (a *packetPayloadAccumulator) reject(reason string) {
	a.result.RejectedRecords++
	a.result.Reasons[reason]++
}
func (a *packetPayloadAccumulator) add(m map[string]any) {
	a.result.ReadRecords++
	key, hash, n, reason := capturedPacketMeasurement(m)
	if reason != "" {
		a.reject(reason)
		return
	}
	if old, ok := a.seen[key]; ok {
		if old.conflict {
			a.reject("packet_identity_conflict")
			return
		}
		if old.hash != hash {
			a.result.PayloadBytes -= old.bytes
			a.result.UniquePackets--
			old.conflict = true
			a.seen[key] = old
			a.reject("packet_identity_conflict")
			return
		}
		a.result.DuplicateRecords++
		return
	}
	a.seen[key] = capturedPacket{hash: hash, bytes: n}
	a.result.UniquePackets++
	a.result.PayloadBytes += n
}
func (a *packetPayloadAccumulator) finish(expected int64) HitPacketPayload {
	r := a.result
	r.ExpectedRecords = expected
	if expected != r.ReadRecords {
		r.Reasons["snapshot_record_count_mismatch"]++
	}
	switch {
	case r.UniquePackets == 0:
		r.Quality = "unavailable"
	case r.RejectedRecords > 0 || expected != r.ReadRecords:
		r.Quality = "partial"
	default:
		r.Quality = "verified"
	}
	return r
}
func capturedPacketMeasurement(m map[string]any) (string, string, int64, string) {
	rp := nestedMap(m, "raw_packet")
	at := domain.ParseEventTime(rp["capture_time"])
	seq, err := strictPacketSequence(rp["packet_sequence"])
	if err != nil || at.IsZero() || asString(m["device_id"]) == "" {
		return "", "", 0, "missing_packet_identity"
	}
	raw := asString(rp["packet_hex"])
	if len(raw) == 0 || len(raw) > 2*maxEvidenceMessageBytes {
		return "", "", 0, "frame_missing_or_oversized"
	}
	frame, err := hex.DecodeString(raw)
	if err != nil {
		return "", "", 0, "invalid_packet_hex"
	}
	if asBool(rp["capture_truncated"]) {
		return "", "", 0, "truncated_frame"
	}
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	network := p.NetworkLayer()
	if network == nil {
		return "", "", 0, "unsupported_network_frame"
	}
	var src, dst net.IP
	switch ip := network.(type) {
	case *layers.IPv4:
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			return "", "", 0, "fragmented_frame"
		}
		if int(ip.Length) != len(ip.Contents)+len(ip.Payload) {
			return "", "", 0, "truncated_frame"
		}
		src, dst = ip.SrcIP, ip.DstIP
	case *layers.IPv6:
		if ip.Length == 0 || int(ip.Length) != len(ip.Payload) {
			return "", "", 0, "truncated_or_jumbo_frame"
		}
		src, dst = ip.SrcIP, ip.DstIP
	default:
		return "", "", 0, "unsupported_network_frame"
	}
	transport := p.TransportLayer()
	if p.Layer(layers.LayerTypeIPv6Fragment) != nil {
		return "", "", 0, "fragmented_frame"
	}
	if p.Metadata().Truncated {
		return "", "", 0, "truncated_frame"
	}
	if !src.Equal(net.ParseIP(asString(m["src_ip"]))) || !dst.Equal(net.ParseIP(asString(m["dst_ip"]))) {
		return "", "", 0, "packet_tuple_conflict"
	}
	var sp, dp uint16
	var body []byte
	proto := ""
	switch t := transport.(type) {
	case *layers.TCP:
		sp, dp = uint16(t.SrcPort), uint16(t.DstPort)
		body = t.Payload
		proto = "tcp"
		if t.DataOffset < 5 {
			return "", "", 0, "invalid_transport_header"
		}
	case *layers.UDP:
		sp, dp = uint16(t.SrcPort), uint16(t.DstPort)
		body = t.Payload
		proto = "udp"
		if t.Length < 8 || int(t.Length) != 8+len(body) {
			return "", "", 0, "invalid_udp_length"
		}
	default:
		return "", "", 0, "unsupported_transport_frame"
	}
	srcPort, sok := packetMeasurementUint(m["src_port"])
	dstPort, dok := packetMeasurementUint(m["dst_port"])
	if !sok || !dok || srcPort != uint64(sp) || dstPort != uint64(dp) || proto != strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"]))) {
		return "", "", 0, "packet_tuple_conflict"
	}
	// Exclude rule/IOC/event IDs: one physical frame may trigger many findings.
	key := digest([]any{m["device_id"], m["capture_session_id"], rp["session_start_time"], at, seq})
	return key, digest(frame), int64(len(body)), ""
}
func strictPacketSequence(v any) (uint64, error) {
	n, ok := packetMeasurementUint(v)
	if !ok {
		return 0, fmt.Errorf("invalid sequence")
	}
	return n, nil
}

// Read an immutable published snapshot. A separate versioned derived cache also
// supports old snapshots without rewriting their evidence or event reports.
func (s Services) HitPacketPayload(ctx context.Context, id string) (HitPacketPayload, error) {
	snap, err := s.EvidenceSnapshot(ctx, id, 0)
	if err != nil {
		return HitPacketPayload{}, err
	}
	key := digest([]any{hitPacketPayloadVersion, id, snap.Version, snap.Watermark, snap.RevisionWatermark, snap.Count, snap.Sources})
	r, exists, err := s.Store.AggregateRecord(ctx, "hit_packet_payload", key)
	if err != nil {
		return HitPacketPayload{}, err
	}
	var cached HitPacketPayload
	if exists && json.Unmarshal(r.Value, &cached) == nil && cached.Version == hitPacketPayloadVersion && cached.ExpectedRecords == snap.Count {
		return cached, nil
	}
	a := newPacketPayloadAccumulator()
	q := store.HitQuery{Sources: snap.Sources, Watermark: snap.Watermark, Limit: 500}
	for {
		if err := ctx.Err(); err != nil {
			return HitPacketPayload{}, err
		}
		hits, err := snapshotHitPage(ctx, s.Store, q, snap.RevisionWatermark)
		if err != nil {
			return HitPacketPayload{}, err
		}
		if len(hits) == 0 {
			break
		}
		for _, h := range hits {
			var m map[string]any
			if json.Unmarshal(h.Raw, &m) != nil {
				a.result.ReadRecords++
				a.reject("invalid_raw_json")
				continue
			}
			a.add(m)
		}
		tail := hits[len(hits)-1]
		q.AfterTime, q.AfterID = tail.OccurredAt, tail.ID
	}
	result := a.finish(snap.Count)
	result.SnapshotVersion, result.Watermark, result.RevisionWatermark = snap.Version, snap.Watermark, snap.RevisionWatermark
	if err := putRecord(ctx, s.Store, "hit_packet_payload", key, id, result); err != nil {
		return result, err
	}
	return result, nil
}

func packetMeasurementUint(v any) (uint64, bool) {
	if n, ok := v.(float64); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 9007199254740991 || math.Trunc(n) != n {
			return 0, false
		}
		return uint64(n), true
	}
	return strictUint(v)
}
