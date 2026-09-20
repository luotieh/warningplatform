package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type EvidenceSnapshot struct {
	EventID           string           `json:"event_id"`
	Version           int64            `json:"snapshot_version"`
	Sources           []string         `json:"source_events"`
	Watermark         int64            `json:"watermark"`
	RevisionWatermark int64            `json:"revision_watermark"`
	Count             int64            `json:"count"`
	Context           map[string]any   `json:"context"`
	Evidence          []map[string]any `json:"evidence"`
	Manifest          map[string]any   `json:"input_manifest"`
}

func snapshotKey(id string, version int64) string { return fmt.Sprintf("%s:%d", id, version) }

func (s Services) EvidenceSnapshot(ctx context.Context, id string, version int64) (EvidenceSnapshot, error) {
	seg, ok, err := readSegment(ctx, s.Store, id)
	if err != nil {
		return EvidenceSnapshot{}, err
	}
	if !ok || seg.Disabled {
		return EvidenceSnapshot{}, errors.New("legacy_event")
	}
	if version == 0 {
		version = seg.Published
	}
	if version == 0 {
		return EvidenceSnapshot{}, errors.New("统计更新中，请稍后重试")
	}
	r, ok, err := s.Store.AggregateRecord(ctx, "snapshot", snapshotKey(id, version))
	if err != nil {
		return EvidenceSnapshot{}, err
	}
	if !ok {
		return EvidenceSnapshot{}, errors.New("快照不存在")
	}
	var snap EvidenceSnapshot
	err = json.Unmarshal(r.Value, &snap)
	return snap, err
}

func hitOccurrence(h store.Hit) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(h.Raw, &m)
	out := map[string]any{"hit_id": h.ID, "evidence_id": h.ID, "time": h.OccurredAt.Format(time.RFC3339Nano), "received_at": h.ReceivedAt.Format(time.RFC3339Nano), "origin_event_id": h.EventID}
	for _, k := range []string{"device_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "proto", "direction", "rule_id", "ioc_type", "ioc_value", "app", "evidence_file", "evidence_files", "packets", "bytes", "wire_bytes", "session_summary", "time_source", "session_id", "transaction_id", "exchange", "context_revision", "context_final"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	for k, v := range nestedMap(m, "raw_packet") {
		out[k] = v
	}
	// The stable IDs and normalized time cannot be supplied/overridden by a probe.
	out["hit_id"] = h.ID
	out["evidence_id"] = h.ID
	out["time"] = h.OccurredAt.Format(time.RFC3339Nano)
	return out
}

func previewOccurrence(o map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"hit_id", "evidence_id", "time", "capture_time", "packet_sequence", "device_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "direction", "rule_id", "ioc_type", "ioc_value", "payload_hex", "payload_text", "captured_length", "wire_length", "capture_truncated", "context_revision", "context_final"} {
		if v, ok := o[k]; ok {
			out[k] = v
		}
	}
	for _, k := range []string{"payload_hex", "payload_text"} {
		if v, ok := out[k].(string); ok && len([]rune(v)) > 512 {
			out[k] = string([]rune(v)[:512])
			out[k+"_preview_truncated"] = true
		}
	}
	for _, k := range []string{"exchange", "app", "session_summary", "request", "response"} {
		if v, ok := o[k]; ok {
			out[k] = boundedEvidenceValue(v, 0)
		}
	}
	return out
}

// Rebuild scans a committed membership watermark, not the bounded UI preview.
// Only timestamp runs in the live five-minute window and bounded evidence
// samples are retained. Raw packet bodies are read in pages.
func (s Services) buildSnapshot(ctx context.Context, seg EventSegment) (EvidenceSnapshot, error) {
	ev, ok := s.Store.GetEvent(seg.EventID)
	if !ok {
		return EvidenceSnapshot{}, errors.New("event missing")
	}
	snap := EvidenceSnapshot{EventID: seg.EventID, Version: seg.Version, Sources: seg.Sources, Watermark: seg.Watermark, RevisionWatermark: seg.RevisionWatermark, Context: decodeEventContext(ev.Context), Evidence: []map[string]any{}}
	type run struct {
		at time.Time
		n  int64
	}
	window := []run{}
	var windowCount, peak int64
	var peakStart, first, last time.Time
	byRule := map[string]int64{}
	byIOC := map[string]*domain.IocHitStat{}
	byDirection := map[string]int64{}
	preview := []map[string]any{}
	selected := map[string]map[string]any{}
	selectedKeys := []string{}
	var observationBytes, observationWire, observationPackets int64
	q := store.HitQuery{Sources: seg.Sources, Watermark: seg.Watermark, Limit: 500}
	volume := newVolumeAccumulator(seg.First)
	for {
		page, err := s.Store.HitPage(ctx, q)
		if err != nil {
			return snap, err
		}
		if len(page) == 0 {
			break
		}
		for _, h := range page {
			if seg.RevisionWatermark > 0 {
				raw, e := s.Store.HitRevision(ctx, h.ID, seg.RevisionWatermark)
				if e != nil {
					return snap, e
				}
				if raw != nil {
					h.Raw = raw
				}
			}
			if err := ctx.Err(); err != nil {
				return snap, err
			}
			m := map[string]any{}
			if err = json.Unmarshal(h.Raw, &m); err != nil {
				return snap, err
			}
			o := hitOccurrence(h)
			volume.add(m)
			snap.Count++
			if first.IsZero() {
				first = h.OccurredAt
			}
			last = h.OccurredAt
			for len(window) > 0 && !h.OccurredAt.Before(window[0].at.Add(5*time.Minute)) {
				windowCount -= window[0].n
				window = window[1:]
			}
			if len(window) > 0 && window[len(window)-1].at.Equal(h.OccurredAt) {
				window[len(window)-1].n++
			} else {
				window = append(window, run{h.OccurredAt, 1})
			}
			windowCount++
			if windowCount > peak {
				peak = windowCount
				peakStart = window[0].at
			}
			byRule[firstNonEmpty(asString(m["rule_id"]), "unknown")]++
			if value := asString(m["ioc_value"]); value != "" {
				kind := asString(m["ioc_type"])
				key := digest([]string{kind, value})
				if byIOC[key] == nil {
					byIOC[key] = &domain.IocHitStat{IOCValue: value, IOCType: kind, FirstSeen: h.OccurredAt.Format(time.RFC3339Nano)}
				}
				byIOC[key].Count++
				byIOC[key].LastSeen = h.OccurredAt.Format(time.RFC3339Nano)
			}
			byDirection[firstNonEmpty(asString(m["direction"]), "unknown")]++
			observationBytes += int64(toInt(m["bytes"]))
			observationWire += int64(toInt(m["wire_bytes"]))
			observationPackets += int64(toInt(m["packets"]))
			p := previewOccurrence(o)
			ui := map[string]any{}
			for _, key := range []string{"hit_id", "evidence_id", "time", "device_id", "rule_id", "ioc_value", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_sequence", "captured_length", "wire_length", "capture_truncated"} {
				if v, ok := p[key]; ok {
					ui[key] = v
				}
			}
			preview = append(preview, ui)
			if len(preview) > 10 {
				preview = preview[1:]
			}
			// Deterministic content/identity sampling scans every hit. Payload duplicates
			// affect model compression only; they remain independent database records.
			signature := digest([]any{m["rule_id"], m["ioc_value"], o["payload_hex"], o["payload_text"], m["app"], m["exchange"], o["request"], o["response"]})
			if old, ok := selected[signature]; ok {
				old["represented_hits"] = toInt(old["represented_hits"]) + 1
			} else {
				p["represented_hits"] = 1
				p["selection_reason"] = "全量扫描后的内容分组代表证据"
				selected[signature] = p
				selectedKeys = append(selectedKeys, signature)
				p["selection_score"] = evidenceScore(m, o)
				sort.Slice(selectedKeys, func(i, j int) bool {
					a, b := toInt(selected[selectedKeys[i]]["selection_score"]), toInt(selected[selectedKeys[j]]["selection_score"])
					if a == b {
						return selectedKeys[i] < selectedKeys[j]
					}
					return a > b
				})
				if len(selectedKeys) > 48 {
					delete(selected, selectedKeys[len(selectedKeys)-1])
					selectedKeys = selectedKeys[:48]
				}
			}
		}
		tail := page[len(page)-1]
		q.AfterTime = tail.OccurredAt
		q.AfterID = tail.ID
	}
	if snap.Count != seg.Count {
		return snap, fmt.Errorf("membership count mismatch: expected %d got %d", seg.Count, snap.Count)
	}
	for _, k := range selectedKeys {
		snap.Evidence = append(snap.Evidence, selected[k])
	}
	duration := last.Sub(first).Seconds()
	var rate any
	if duration > 0 {
		rate = float64(snap.Count) * 60 / duration
	}
	qs := map[string]any{"occurrence_count": snap.Count, "window_start": first.Format(time.RFC3339Nano), "window_end": last.Format(time.RFC3339Nano), "duration_sec": duration, "rate_per_min": rate, "peak_window": map[string]any{"count": peak, "start_time": peakStart.Format(time.RFC3339Nano), "end_time": peakStart.Add(5 * time.Minute).Format(time.RFC3339Nano), "interval": "[start,end)"}, "by_rule": byRule, "by_ioc": byIOC, "by_direction": byDirection, "source_ips": map[string]int64{asString(snap.Context["src_ip"]): snap.Count}, "dest_ips": map[string]int64{asString(snap.Context["dst_ip"]): snap.Count}, "total_payload_bytes": nil, "total_wire_bytes": nil, "total_packets": nil, "volume_quality": "unverified", "volume_reason": "上游为流累计观测值，尚无可验证的会话基线；不能累加为实际流量", "reported_observation_bytes": observationBytes, "reported_observation_wire_bytes": observationWire, "reported_observation_packets": observationPackets}
	snap.Context["quant_stats"] = qs
	volume.publish(qs)
	iocs := []domain.IocHitStat{}
	for _, stat := range byIOC {
		iocs = append(iocs, *stat)
	}
	sort.Slice(iocs, func(i, j int) bool {
		if iocs[i].Count != iocs[j].Count {
			return iocs[i].Count > iocs[j].Count
		}
		if iocs[i].IOCValue != iocs[j].IOCValue {
			return iocs[i].IOCValue < iocs[j].IOCValue
		}
		return iocs[i].IOCType < iocs[j].IOCType
	})
	qs["by_ioc"] = iocs
	qs["event_id"] = seg.EventID
	qs["duration_sec"] = int64(duration)
	qs["duration_seconds_precise"] = duration
	qs["unique_src_ips"] = 1
	qs["unique_dst_ips"] = 1
	if duration == 0 {
		qs["rate_reason"] = "首末发生时间相同，平均频率不可计算"
	}
	snap.Context["occurrence_count"] = snap.Count
	snap.Context["first_time"] = first.Format(time.RFC3339Nano)
	snap.Context["last_time"] = last.Format(time.RFC3339Nano)
	snap.Context["last_seen_at"] = last.Format(time.RFC3339Nano)
	snap.Context["stats_version"] = snap.Version
	snap.Context["data_version"] = snap.Version
	snap.Context["statistics_quality"] = "verified"
	snap.Context["occurrences"] = preview
	snap.Context["occurrences_preview"] = true
	snap.Context["occurrences_total"] = snap.Count
	snap.Context["occurrences_has_more"] = snap.Count > int64(len(preview))
	snap.Manifest = map[string]any{"snapshot_version": snap.Version, "stats_version": snap.Version, "scanned_hits": snap.Count, "available_hits": snap.Count, "evidence_selected": len(snap.Evidence), "statistics_quality": "verified", "volume_quality": "unverified", "selection": "bounded deterministic content representatives; raw records retained", "model_omitted_hits": snap.Count - int64(len(snap.Evidence))}
	snap.Manifest["volume_quality"] = qs["volume_quality"]
	return snap, nil
}

func (s Services) RebuildAggregation(ctx context.Context, id string) error {
	seg, ok, err := readSegment(ctx, s.Store, id)
	if err != nil || !ok {
		return err
	}
	if seg.Disabled || seg.CanonicalID != id {
		return s.Store.AggregationTransaction(ctx, "group-"+seg.AggregateKey, func(tx store.Store) error {
			return putRecord(ctx, tx, "outbox", id, "done", map[string]any{"canonical_id": seg.CanonicalID})
		})
	}
	if seg.Published == seg.Version {
		return nil
	}
	snap, err := s.buildSnapshot(ctx, seg)
	if err != nil {
		return err
	}
	return s.Store.AggregationTransaction(ctx, "group-"+seg.AggregateKey, func(tx store.Store) error {
		current, ok, err := readSegment(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok || current.Disabled || current.CanonicalID != id || current.Published >= snap.Version {
			return nil
		}
		if err = putRecord(ctx, tx, "snapshot", snapshotKey(id, snap.Version), id, snap); err != nil {
			return err
		}
		ev, ok := tx.GetEvent(id)
		if !ok {
			return errors.New("event disappeared")
		}
		c := decodeEventContext(ev.Context)
		// Copy only aggregate-owned fields; reports and review changes may have been
		// written while the snapshot was scanning.
		for _, k := range []string{"quant_stats", "occurrence_count", "first_time", "last_time", "last_seen_at", "occurrences", "occurrences_preview", "occurrences_total", "occurrences_has_more"} {
			c[k] = snap.Context[k]
		}
		// events.context remains a small compatibility projection. Full IOC/rule
		// distributions live in the immutable LONGTEXT snapshot and stats endpoint.
		statsProjection, omittedDistributions := modelStatistics(snap.Context["quant_stats"])
		c["quant_stats"] = statsProjection
		c["quant_stats_distribution_projection"] = omittedDistributions
		c["stats_version"] = snap.Version
		c["data_version"] = current.Version
		c["statistics_quality"] = "verified"
		if current.Version > snap.Version {
			c["statistics_quality"] = "rebuilding"
		}
		c["input_manifest"] = snap.Manifest
		b, _ := json.Marshal(c)
		patch := map[string]any{"context": string(b), "last_seen_at": current.Last.Format(time.RFC3339Nano)}
		if _, ok = tx.UpdateEvent(id, patch); !ok {
			return errors.New("publish stats failed")
		}
		current.Published = snap.Version
		if ev.AnalysisVersion == 0 && !asBool(c["suppress_auto_analysis"]) {
			if _, exists, e := tx.AggregateRecord(ctx, "analysis_outbox", id); e != nil {
				return e
			} else if !exists {
				kind := "initial"
				if ev.AggregationClosed {
					kind = "final"
				}
				if e = putRecord(ctx, tx, "analysis_outbox", id, "pending", map[string]any{"kind": kind, "version": snap.Version}); e != nil {
					return e
				}
			}
		}
		if err = putRecord(ctx, tx, "segment", id, current.AggregateKey, current); err != nil {
			return err
		}
		group := "pending"
		if current.Version == snap.Version {
			group = "done"
		}
		return putRecord(ctx, tx, "outbox", id, group, map[string]any{"event_id": id, "data_version": current.Version, "last_attempt": time.Now().UnixMilli()})
	})
}

func (s Services) DrainAggregation(ctx context.Context, limit int) error {
	records, err := s.Store.AggregateRecords(ctx, "outbox", "pending", limit)
	if err != nil {
		return err
	}
	var failures []error
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err = s.RebuildAggregation(ctx, r.Key); err != nil {
			failures = append(failures, err)
			seg, ok, readErr := readSegment(ctx, s.Store, r.Key)
			if readErr != nil {
				failures = append(failures, readErr)
				continue
			}
			if ok {
				err := s.Store.AggregationTransaction(ctx, "group-"+seg.AggregateKey, func(tx store.Store) error {
					latest, exists, e := tx.AggregateRecord(ctx, "outbox", r.Key)
					if e != nil || !exists {
						return e
					}
					var task map[string]any
					if e = json.Unmarshal(latest.Value, &task); e != nil {
						return e
					}
					task["last_attempt"] = time.Now().UnixMilli()
					return putRecord(ctx, tx, "outbox", r.Key, latest.Group, task)
				})
				if err != nil {
					failures = append(failures, err)
				}
			}
		}
	}
	return errors.Join(failures...)
}

type OccurrencePage struct {
	TotalScope      string           `json:"total_scope,omitempty"`
	Items           []map[string]any `json:"items"`
	Total           int64            `json:"total"`
	SnapshotVersion int64            `json:"snapshot_version"`
	NextCursor      string           `json:"next_cursor"`
	Quality         string           `json:"statistics_quality"`
	DeclaredCount   any              `json:"declared_count,omitempty"`
}
type hitCursor struct {
	Event   string    `json:"event"`
	Version int64     `json:"version"`
	At      time.Time `json:"at"`
	ID      string    `json:"id"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
}

func (s Services) Occurrences(ctx context.Context, id, cursor, hitID string, limit int) (OccurrencePage, error) {
	return s.OccurrencesAt(ctx, id, cursor, hitID, limit, 0)
}

func (s Services) OccurrencesAt(ctx context.Context, id, cursor, hitID string, limit int, version int64, timeRange ...string) (OccurrencePage, error) {
	out := OccurrencePage{Items: []map[string]any{}}
	if limit < 1 || limit > 200 {
		limit = 100
	}
	cur := hitCursor{Event: id, Version: version}
	if len(timeRange) == 2 {
		cur.From, cur.To = domain.ParseEventTime(timeRange[0]), domain.ParseEventTime(timeRange[1])
		if (timeRange[0] != "" && cur.From.IsZero()) || (timeRange[1] != "" && cur.To.IsZero()) || (!cur.From.IsZero() && !cur.To.IsZero() && !cur.From.Before(cur.To)) {
			return out, errors.New("invalid occurrence time range")
		}
	}
	if cursor != "" {
		requested := cur
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(b, &cur) != nil || cur.Event != id || cur.Version < 1 {
			return out, errors.New("invalid occurrence cursor")
		}
		if (version > 0 && cur.Version != version) || (!requested.From.IsZero() && !requested.From.Equal(cur.From)) || (!requested.To.IsZero() && !requested.To.Equal(cur.To)) {
			return out, errors.New("cursor snapshot/filter mismatch")
		}
	}
	snap, err := s.EvidenceSnapshot(ctx, id, cur.Version)
	if err != nil {
		if err.Error() != "legacy_event" {
			return out, err
		}
		ev, ok := s.Store.GetEvent(id)
		if !ok {
			return out, errors.New("事件不存在")
		}
		c := decodeEventContext(ev.Context)
		oc, _ := c["occurrences"].([]any)
		out.Total = int64(len(oc))
		out.Quality = "unverified"
		out.DeclaredCount = c["occurrence_count"]
		// Legacy indexes are explicitly unverified; never resolve them as new hit IDs.
		if hitID != "" {
			return out, errors.New("历史证据引用无法核验")
		}
		for i, o := range oc {
			if m, ok := o.(map[string]any); ok {
				at := domain.ParseEventTime(m["time"])
				if (!cur.From.IsZero() && at.Before(cur.From)) || (!cur.To.IsZero() && !at.Before(cur.To)) {
					continue
				}
				m["legacy_index"] = i + 1
				out.Items = append(out.Items, m)
			}
		}
		return out, nil
	}
	hits, err := s.Store.HitPage(ctx, store.HitQuery{Sources: snap.Sources, Watermark: snap.Watermark, AfterTime: cur.At, AfterID: cur.ID, From: cur.From, To: cur.To, ID: hitID, Limit: limit + 1})
	if err != nil {
		return out, err
	}
	out.Total = snap.Count
	out.TotalScope = "snapshot"
	out.SnapshotVersion = snap.Version
	out.Quality = "verified"
	more := len(hits) > limit
	if more {
		hits = hits[:limit]
	}
	for _, h := range hits {
		if snap.RevisionWatermark > 0 {
			raw, e := s.Store.HitRevision(ctx, h.ID, snap.RevisionWatermark)
			if e != nil {
				return out, e
			}
			if raw != nil {
				h.Raw = raw
			}
		}
		out.Items = append(out.Items, hitOccurrence(h))
	}
	if hitID != "" && len(hits) == 0 {
		return out, errors.New("该证据不属于此事件快照")
	}
	if more {
		tail := hits[len(hits)-1]
		cur.Version, cur.At, cur.ID = snap.Version, tail.OccurredAt, tail.ID
		b, _ := json.Marshal(cur)
		out.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	}
	return out, nil
}

// EvidenceContext is shared by the pipeline and engineer chat. It deliberately
// excludes the UI preview: a preview is never described as all source records.
func (s Services) EvidenceContext(ctx context.Context, event domain.Event) (string, error) {
	snap, err := s.EvidenceSnapshot(ctx, event.EventID, 0)
	if err != nil {
		if err.Error() != "legacy_event" {
			return "", err
		}
		c := decodeEventContext(event.Context)
		oc, _ := c["occurrences"].([]any)
		c["statistics_quality"] = "unverified"
		c["evidence_note"] = "历史统计未核验；仅扫描已保存明细，不代表全量原始命中"
		c["input_manifest"] = map[string]any{"available_hits": len(oc), "declared_hits": c["occurrence_count"], "statistics_quality": "unverified"}
		b, _ := json.Marshal(c)
		return string(b), nil
	}
	c := map[string]any{"event_id": event.EventID, "snapshot_version": snap.Version, "quant_stats": snap.Context["quant_stats"], "occurrence_count": snap.Count, "input_manifest": snap.Manifest, "evidence_index": snap.Evidence, "statistics_quality": "verified"}
	stats, omitted := modelStatistics(snap.Context["quant_stats"])
	c["quant_stats"] = stats
	snap.Manifest["distribution_compression"] = omitted
	// Preserve valid JSON and whole evidence records when fitting the context.
	// Never truncate a serialized JSON string in the middle of an identity.
	for {
		ids := []string{}
		for _, e := range snap.Evidence {
			ids = append(ids, asString(e["hit_id"]))
		}
		snap.Manifest["selected_hit_ids"] = ids
		snap.Manifest["evidence_selected"] = len(ids)
		snap.Manifest["model_omitted_hits"] = snap.Count - int64(len(ids))
		c["evidence_index"] = snap.Evidence
		b, err := json.Marshal(c)
		if err != nil {
			return "", err
		}
		if len([]rune(string(b))) <= 6000 {
			return string(b), nil
		}
		if len(snap.Evidence) == 0 {
			return "", errors.New("统计摘要超过模型输入预算，请检查异常长的统计字段")
		}
		if len(snap.Evidence) == 1 {
			e := snap.Evidence[0]
			if e["summary_budget_limited"] == true {
				return "", errors.New("证据摘要超过模型输入预算")
			}
			compact := map[string]any{"summary_budget_limited": true}
			for _, k := range []string{"hit_id", "evidence_id", "time", "rule_id", "ioc_value", "payload_hex", "payload_text", "response", "exchange"} {
				if v, ok := e[k]; ok {
					compact[k] = boundedEvidenceValue(v, 0)
				}
			}
			snap.Evidence[0] = compact
			continue
		}
		snap.Evidence = snap.Evidence[:len(snap.Evidence)-1]
	}
}

func (s Services) AggregationStatus(ctx context.Context, id string) map[string]any {
	seg, ok, err := readSegment(ctx, s.Store, id)
	if err != nil || !ok {
		return map[string]any{"statistics_quality": "unverified"}
	}
	return map[string]any{"data_version": seg.Version, "stats_version": seg.Published, "canonical_event_id": seg.CanonicalID}
}

// Strip internal file locations before passing occurrence samples to a model.
func (s Services) MarkReportSnapshot(ctx context.Context, id, raw string) error {
	c := decodeEventContext(raw)
	version := int64(toInt(c["snapshot_version"]))
	if version == 0 {
		return nil
	}
	seg, ok, err := readSegment(ctx, s.Store, id)
	if err != nil || !ok {
		return err
	}
	return s.Store.AggregationTransaction(ctx, "group-"+seg.AggregateKey, func(tx store.Store) error {
		latest, ok, e := readSegment(ctx, tx, id)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("report event missing")
		}
		ev, ok := tx.GetEvent(id)
		if !ok {
			return errors.New("report event missing")
		}
		ec := decodeEventContext(ev.Context)
		ec["report_data_version"] = version
		ec["report_stale"] = latest.Version != version || latest.CanonicalID != id
		b, _ := json.Marshal(ec)
		if _, ok = tx.UpdateEvent(id, map[string]any{"context": string(b)}); !ok {
			return errors.New("save report version failed")
		}
		return putRecord(ctx, tx, "report_manifest", snapshotKey(id, version), id, c["input_manifest"])
	})
}
