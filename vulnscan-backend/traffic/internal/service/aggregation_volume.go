package service

import (
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

type volumeCounter struct{ Payload, Wire, Packets int64 }
type volumeAccumulator struct {
	counters map[string]volumeCounter
	known    bool
	reason   string
	first    time.Time
}

func newVolumeAccumulator(first time.Time) *volumeAccumulator {
	return &volumeAccumulator{counters: map[string]volumeCounter{}, known: true, first: first}
}
func (v *volumeAccumulator) add(m map[string]any) {
	mode := asString(m["volume_mode"])
	rp := nestedMap(m, "raw_packet")
	device := asString(m["device_id"])
	key := ""
	switch mode {
	case "packet":
		if rp["packet_sequence"] == nil || rp["capture_time"] == nil {
			v.known = false
			v.reason = "缺少可核验的物理报文身份"
			return
		}
		key = digest([]any{device, m["capture_session_id"], rp["capture_time"], rp["packet_sequence"], m["src_ip"], m["src_port"], m["dst_ip"], m["dst_port"]})
	case "cumulative":
		session := asString(m["session_id"])
		epoch := asString(m["counter_epoch"])
		start := domain.ParseEventTime(m["counter_started_at"])
		if session == "" || epoch == "" || !asBool(m["counter_zero_baseline"]) || start.IsZero() || start.Before(v.first) {
			v.known = false
			v.reason = "流累计值缺少会话/计数周期/零基线，或跨越事件起点"
			return
		}
		key = digest([]any{device, session, epoch, m["src_ip"], m["src_port"], m["dst_ip"], m["dst_port"], m["direction"]})
	default:
		v.known = false
		v.reason = "上游流累计观测值缺少可核验的计量契约；不累加为实际流量"
		return
	}
	for _, k := range []string{"bytes", "wire_bytes", "packets"} {
		if _, ok := m[k]; !ok || toInt(m[k]) < 0 {
			v.known = false
			v.reason = "计量字段缺失或非法"
			return
		}
	}
	next := volumeCounter{int64(toInt(m["bytes"])), int64(toInt(m["wire_bytes"])), int64(toInt(m["packets"]))}
	old, ok := v.counters[key]
	if mode == "packet" && ok && old != next {
		v.known = false
		v.reason = "同一报文计量冲突"
		return
	}
	if next.Payload < old.Payload {
		next.Payload = old.Payload
	}
	if next.Wire < old.Wire {
		next.Wire = old.Wire
	}
	if next.Packets < old.Packets {
		next.Packets = old.Packets
	}
	v.counters[key] = next
}
func (v *volumeAccumulator) publish(qs map[string]any) {
	if !v.known {
		qs["volume_quality"] = "unverified"
		qs["volume_reason"] = v.reason
		return
	}
	total := volumeCounter{}
	for _, c := range v.counters {
		total.Payload += c.Payload
		total.Wire += c.Wire
		total.Packets += c.Packets
	}
	qs["total_payload_bytes"] = total.Payload
	qs["total_wire_bytes"] = total.Wire
	qs["total_packets"] = total.Packets
	qs["volume_quality"] = "verified"
	delete(qs, "volume_reason")
}
