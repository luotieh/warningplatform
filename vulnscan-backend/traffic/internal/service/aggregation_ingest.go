package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"net/netip"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const AggregationVersion = 2

type EventSegment struct {
	Disabled          bool      `json:"disabled,omitempty"`
	EventID           string    `json:"event_id"`
	AggregateKey      string    `json:"aggregate_key"`
	CanonicalID       string    `json:"canonical_id"`
	Sources           []string  `json:"source_events"`
	First             time.Time `json:"first_time"`
	Last              time.Time `json:"last_time"`
	Created           time.Time `json:"created_at"`
	Version           int64     `json:"data_version"`
	Published         int64     `json:"stats_version"`
	Watermark         int64     `json:"watermark"`
	RevisionWatermark int64     `json:"revision_watermark"`
	Count             int64     `json:"hit_count"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func putRecord(ctx context.Context, st store.Store, kind, key, group string, value any) error {
	if kind == "outbox" {
		if m, ok := value.(map[string]any); ok && m["last_attempt"] == nil {
			r, exists, err := st.AggregateRecord(ctx, kind, key)
			if err != nil {
				return err
			}
			if exists {
				var previous map[string]any
				_ = json.Unmarshal(r.Value, &previous)
				m["last_attempt"] = previous["last_attempt"]
			}
		}
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return st.PutAggregateRecord(ctx, store.AggregateRecord{Kind: kind, Key: key, Group: group, Value: b})
}
func readSegment(ctx context.Context, st store.Store, id string) (seg EventSegment, ok bool, err error) {
	r, ok, err := st.AggregateRecord(ctx, "segment", id)
	if err == nil && ok {
		err = json.Unmarshal(r.Value, &seg)
	}
	return seg, ok, err
}

// Numeric fields are normalized through JSON before hashing. Transport-only
// metadata is excluded from the immutable identity, while evidence is retained.
func normalizeHit(ly map[string]any, now time.Time) (store.Hit, map[string]any, string) {
	raw, _ := json.Marshal(ly)
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"src_ip", "dst_ip"} {
		v := strings.TrimSpace(asString(m[k]))
		if ip, err := netip.ParseAddr(v); err == nil {
			m[k] = ip.Unmap().String()
		}
	}
	m["event_type"] = strings.ToLower(strings.TrimSpace(firstNonEmpty(asString(m["event_type"]), asString(m["type"]), asString(m["threat_type"]))))
	rp := nestedMap(m, "raw_packet")
	var at time.Time
	timeSource := ""
	for _, field := range []struct {
		k string
		v any
	}{{"raw_packet.capture_time", rp["capture_time"]}, {"capture_time", m["capture_time"]}, {"packet_time_usec", m["packet_time_usec"]}, {"event_time", m["event_time"]}, {"occurrence_time", m["occurrence_time"]}, {"time", m["time"]}} {
		if t := domain.ParseEventTime(field.v); !t.IsZero() {
			at = t.UTC().Truncate(time.Microsecond)
			timeSource = field.k
			break
		}
	}
	h := store.Hit{ReceivedAt: now, OccurredAt: at}
	if at.IsZero() || at.Year() < 2000 || at.After(now.Add(5*time.Minute)) {
		h.Raw = raw
		return h, m, "missing_or_invalid_occurrence_time"
	}
	if asString(m["src_ip"]) == "" || asString(m["dst_ip"]) == "" || asString(m["event_type"]) == "" {
		h.Raw = raw
		return h, m, "missing_aggregation_identity"
	}
	device := asString(m["device_id"])
	source := firstNonEmpty(asString(m["system_ref"]), asString(m["source"]), "ta_node")
	if device == "" {
		h.Raw = raw
		return h, m, "missing_device_identity"
	}
	m["occurrence_time"] = at.Format(time.RFC3339Nano)
	m["time_source"] = timeSource
	rule := []any{m["rule_id"], m["ioc_type"], m["ioc_value"], m["threat_index"]}
	sourceID := asString(m["event_id"])
	if sourceID != "" {
		// ta_node's documented event_id is a per-packet/per-rule identifier.
		h.DedupKey = digest([]any{"source-hit-v2", source, device, sourceID})
	} else if rp["packet_sequence"] != nil && rp["capture_time"] != nil && (asString(m["rule_id"]) != "" || asString(m["ioc_value"]) != "") {
		h.DedupKey = digest([]any{"packet-hit-v2", source, device, m["capture_session_id"], rp["session_start_time"], at, rp["packet_sequence"], m["src_ip"], m["src_port"], m["dst_ip"], m["dst_port"], firstNonEmpty(asString(m["protocol"]), asString(m["proto"])), rule})
	} else {
		h.Raw = raw
		return h, m, "insufficient_hit_identity"
	}
	h.ID = "hit-" + h.DedupKey
	h.AggregateKey = Fingerprint(m)
	h.Identity = digest([]any{h.AggregateKey, at, m["src_port"], m["dst_port"], firstNonEmpty(asString(m["protocol"]), asString(m["proto"])), rule, rp["packet_sequence"], rp["capture_time"], rp["payload_hex"], rp["payload_text"]})
	h.Raw, _ = json.Marshal(m)
	return h, m, ""
}

func (s Services) ingestHit(ctx context.Context, ly map[string]any) (map[string]any, error) {
	if s.DeepSOC.Enabled() {
		return nil, errors.New("全量命中接入要求本地事件存储；远端 DeepSOC 转发模式尚未支持此事务协议")
	}
	now := time.Now().UTC()
	hit, m, reason := normalizeHit(ly, now)
	if reason != "" {
		key := digest(ly)
		err := s.Store.AggregationTransaction(ctx, "receipt-"+key, func(tx store.Store) error {
			return putRecord(ctx, tx, "receipt", key, "pending", map[string]any{"status": "pending_verification", "reason": reason, "received_at": now, "raw": ly})
		})
		return map[string]any{"success": err == nil, "ingest_status": "pending_verification", "reason": reason}, err
	}
	var result map[string]any
	err := s.Store.AggregationTransaction(ctx, "hit-"+hit.DedupKey, func(tx store.Store) error {
		old, found, err := tx.FindHit(ctx, hit.DedupKey)
		if err != nil {
			return err
		}
		if found {
			if old.Identity != hit.Identity {
				key := digest([]string{hit.DedupKey, hit.Identity})
				if err = putRecord(ctx, tx, "receipt", key, "conflict", map[string]any{"status": "identity_conflict", "original_hit_id": old.ID, "received_at": now, "raw": m}); err != nil {
					return err
				}
				result = map[string]any{"success": true, "ingest_status": "identity_conflict", "hit_id": old.ID}
				return nil
			}
			if err = tx.LockAggregationKey(ctx, "group-"+old.AggregateKey); err != nil {
				return err
			}
			id := old.EventID
			if seg, ok, e := readSegment(ctx, tx, id); e != nil {
				return e
			} else if ok {
				id = seg.CanonicalID
			}
			if revised, e := s.acceptHitRevision(ctx, tx, old, hit, m, id); e != nil {
				return e
			} else if revised != "" {
				result = map[string]any{"success": true, "duplicate": false, "ingest_status": revised, "hit_id": old.ID, "deepsoc_event_id": id}
				return nil
			}
			result = map[string]any{"success": true, "duplicate": true, "ingest_status": "duplicate", "hit_id": old.ID, "deepsoc_event_id": id}
			return nil
		}
		if err = tx.LockAggregationKey(ctx, "group-"+hit.AggregateKey); err != nil {
			return err
		}
		records, err := tx.AggregateRecords(ctx, "segment", hit.AggregateKey, 0)
		if err != nil {
			return err
		}
		related := []EventSegment{}
		for _, r := range records {
			var seg EventSegment
			if err = json.Unmarshal(r.Value, &seg); err != nil {
				return err
			}
			if !seg.Disabled && seg.CanonicalID == seg.EventID && hit.OccurredAt.After(seg.First.Add(-domain.ConvergenceIdleWindow)) && hit.OccurredAt.Before(seg.Last.Add(domain.ConvergenceIdleWindow)) {
				related = append(related, seg)
			}
		}
		sort.Slice(related, func(i, j int) bool {
			if related[i].Created.Equal(related[j].Created) {
				return related[i].EventID < related[j].EventID
			}
			return related[i].Created.Before(related[j].Created)
		})
		fresh := len(related) == 0
		seg := EventSegment{}
		if fresh {
			ev := LyEventToDeepSOC(m)
			ev.EventID = "ly-" + uuid.NewString()
			ev.Context = `{"aggregation_version":2,"statistics_quality":"rebuilding","occurrence_count":null,"quant_stats":{},"occurrences":[]}`
			if _, err = tx.CreateEvent(ev); err != nil {
				return err
			}
			seg = EventSegment{EventID: ev.EventID, CanonicalID: ev.EventID, AggregateKey: hit.AggregateKey, Sources: []string{ev.EventID}, First: hit.OccurredAt, Last: hit.OccurredAt, Created: now}
		} else {
			seg = related[0]
		}
		before := seg
		hit.EventID = seg.EventID
		hit, err = tx.InsertHit(ctx, hit)
		if err != nil {
			return err
		}
		for i, other := range related {
			if i == 0 {
				continue
			}
			seg.Sources = append(seg.Sources, other.Sources...)
			if other.RevisionWatermark > seg.RevisionWatermark {
				seg.RevisionWatermark = other.RevisionWatermark
			}
			seg.Count += other.Count
			if other.First.Before(seg.First) {
				seg.First = other.First
			}
			if other.Last.After(seg.Last) {
				seg.Last = other.Last
			}
		}
		if hit.OccurredAt.Before(seg.First) {
			seg.First = hit.OccurredAt
		}
		if hit.OccurredAt.After(seg.Last) {
			seg.Last = hit.OccurredAt
		}
		seg.Count++
		seg.Version++
		seg.Watermark = hit.Sequence
		if err = putRecord(ctx, tx, "segment", seg.EventID, seg.AggregateKey, seg); err != nil {
			return err
		}
		// Update every original segment's alias, including earlier merged descendants.
		if len(related) > 1 {
			for _, id := range seg.Sources {
				if id == seg.EventID {
					continue
				}
				alias, ok, e := readSegment(ctx, tx, id)
				if e != nil {
					return e
				}
				if ok {
					alias.CanonicalID = seg.EventID
					if e = putRecord(ctx, tx, "segment", id, seg.AggregateKey, alias); e != nil {
						return e
					}
				}
				ev, ok := tx.GetEvent(id)
				if !ok {
					return errors.New("merged event missing")
				}
				c := decodeEventContext(ev.Context)
				c["canonical_event_id"] = seg.EventID
				c["report_stale"] = true
				b, _ := json.Marshal(c)
				if _, ok = tx.UpdateEvent(id, map[string]any{"context": string(b), "aggregation_closed": true}); !ok {
					return errors.New("save event alias failed")
				}
			}
		}
		ev, ok := tx.GetEvent(seg.EventID)
		if !ok {
			return errors.New("event missing")
		}
		c := decodeEventContext(ev.Context)
		c["aggregation_version"] = 2
		c["data_version"] = seg.Version
		c["stats_version"] = seg.Published
		c["statistics_quality"] = "rebuilding"
		c["report_stale"] = true
		c["canonical_event_id"] = seg.EventID
		c["aggregation_key"] = seg.AggregateKey
		if fresh {
			base := decodeEventContext(LyEventToDeepSOC(m).Context)
			for k, v := range base {
				if k != "occurrence_count" && k != "quant_stats" && k != "occurrences" {
					if k == "app" || k == "session_summary" || k == "ioc" || k == "ioc_evidence" || k == "recommended_action" {
						v = boundedEvidenceValue(v, 0)
					}
					if k == "evidence_files" {
						if files, ok := v.([]any); ok && len(files) > 20 {
							v = files[:20]
							c["evidence_files_preview"] = true
						}
					}
					c[k] = v
				}
			}
		}
		if len(related) > 1 {
			c["merged_event_ids"] = seg.Sources
			c["merge_review_required"] = true
		}
		b, _ := json.Marshal(c)
		patch := map[string]any{"context": string(b), "last_seen_at": seg.Last.Format(time.RFC3339Nano), "aggregation_closed": !now.Before(seg.Last.Add(domain.ConvergenceIdleWindow)), "archive_date": nil}
		if seg.Last.In(domain.Beijing).Format("2006-01-02") < now.In(domain.Beijing).Format("2006-01-02") && !now.Before(seg.Last.Add(domain.ConvergenceIdleWindow)) {
			patch["archive_date"] = seg.Last.In(domain.Beijing).Format("2006-01-02")
		}
		if len(related) > 1 {
			patch["review_status"] = "pending"
		}
		if _, ok = tx.UpdateEvent(seg.EventID, patch); !ok {
			return errors.New("save aggregation event failed")
		}
		if len(related) > 1 {
			if err = putRecord(ctx, tx, "revision", fmt.Sprintf("%s-%d", seg.EventID, seg.Version), seg.EventID, map[string]any{"action": "bridge_merge", "before": before, "related": related, "after": seg, "hit_id": hit.ID}); err != nil {
				return err
			}
		}
		if err = putRecord(ctx, tx, "outbox", seg.EventID, "pending", map[string]any{"event_id": seg.EventID, "aggregate_key": seg.AggregateKey, "data_version": seg.Version}); err != nil {
			return err
		}
		result = map[string]any{"success": true, "duplicate": false, "aggregated": !fresh, "ingest_status": "accepted", "hit_id": hit.ID, "deepsoc_event_id": seg.EventID, "data_version": seg.Version, "occurrence_count": seg.Count}
		return nil
	})
	return result, err
}
