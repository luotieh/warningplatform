package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Repair manifests contain the exact original state. They are local operational
// artifacts, not model inputs; operators must protect them like database backups.
type RepairEntry struct {
	EventID     string       `json:"event_id"`
	Before      domain.Event `json:"before"`
	BeforeHash  string       `json:"before_hash"`
	Quality     string       `json:"quality"`
	Reasons     []string     `json:"reasons"`
	Declared    int          `json:"declared_hits"`
	Available   int          `json:"available_hits"`
	Unique      int          `json:"unique_hits"`
	ArchiveDate string       `json:"corrected_archive_date,omitempty"`
	Recoverable []store.Hit  `json:"recoverable_hits,omitempty"`
}
type RepairPlan struct {
	Schema   int           `json:"schema"`
	BatchID  string        `json:"batch_id"`
	Created  time.Time     `json:"created_at"`
	Entries  []RepairEntry `json:"entries"`
	Checksum string        `json:"checksum"`
}

func repairChecksum(plan RepairPlan) string { plan.Checksum = ""; return digest(plan) }

// A maintenance batch includes the selected event's entire directional group;
// it must not split related legacy rows merely to satisfy an arbitrary row limit.
func (s Services) AuditAggregationGroup(ctx context.Context, eventID string) (RepairPlan, error) {
	plan, err := s.AuditAggregation(ctx)
	if err != nil || eventID == "" {
		return plan, err
	}
	ev, ok := s.Store.GetEvent(eventID)
	if !ok {
		return plan, errors.New("audit event not found")
	}
	fp := Fingerprint(decodeEventContext(ev.Context))
	entries := []RepairEntry{}
	for _, entry := range plan.Entries {
		if Fingerprint(decodeEventContext(entry.Before.Context)) == fp {
			entries = append(entries, entry)
		}
	}
	plan.Entries = entries
	plan.Checksum = repairChecksum(plan)
	return plan, nil
}

func (s Services) AuditAggregation(ctx context.Context) (RepairPlan, error) {
	plan := RepairPlan{Schema: 1, Created: time.Now().UTC(), Entries: []RepairEntry{}}
	plan.BatchID = "repair-" + plan.Created.Format("20060102T150405.000000000")
	// Read only: no migrations, metadata updates or model calls.
	for _, ev := range s.Store.ListEvents() {
		if err := ctx.Err(); err != nil {
			return plan, err
		}
		c := decodeEventContext(ev.Context)
		if toInt(c["aggregation_version"]) == 2 {
			continue
		}
		entry := RepairEntry{EventID: ev.EventID, Before: ev, BeforeHash: digest(ev), Quality: "unverified", Reasons: []string{}}
		oc, _ := c["occurrences"].([]any)
		entry.Available = len(oc)
		entry.Declared = toInt(c["occurrence_count"])
		if entry.Declared > len(oc) {
			entry.Quality = "partial"
			entry.Reasons = append(entry.Reasons, "原始明细缺失，不能从样本恢复真实总数")
		}
		all := entry.Declared == len(oc) && len(oc) > 0
		seen := map[string]bool{}
		for _, v := range oc {
			o, ok := v.(map[string]any)
			if !ok {
				all = false
				continue
			}
			// Do not infer each packet's rule/IOC from the first hit of an aggregate.
			if asString(o["rule_id"]) == "" && asString(o["ioc_value"]) == "" {
				all = false
				continue
			}
			m := map[string]any{}
			for k, v := range o {
				m[k] = v
			}
			for _, k := range []string{"device_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "event_type"} {
				if m[k] == nil {
					m[k] = c[k]
				}
			}
			delete(m, "event_id")
			m["raw_packet"] = o
			m["occurrence_time"] = o["time"]
			hit, _, reason := normalizeHit(m, plan.Created)
			if reason != "" {
				all = false
				continue
			}
			if !seen[hit.DedupKey] {
				seen[hit.DedupKey] = true
				entry.Recoverable = append(entry.Recoverable, hit)
			}
		}
		entry.Unique = len(seen)
		if all {
			entry.Quality = "verified"
			entry.Reasons = append(entry.Reasons, "全部保存明细具备可核验身份，可重新计算去重与时间段")
		} else {
			entry.Recoverable = nil
			entry.Reasons = append(entry.Reasons, "仅标记完整性；不推断丢失记录或各包检测身份")
		}
		if qs, ok := c["quant_stats"].(map[string]any); ok && toInt(qs["occurrence_count"]) != entry.Declared {
			entry.Reasons = append(entry.Reasons, "列表次数与量化统计不一致")
		}
		last := domain.ParseEventTime(c["last_time"])
		if ev.ArchiveDate != nil && !last.IsZero() {
			entry.ArchiveDate = last.In(domain.Beijing).Format("2006-01-02")
		}
		plan.Entries = append(plan.Entries, entry)
	}
	plan.Checksum = repairChecksum(plan)
	return plan, nil
}

type repairApplied struct {
	Before      []domain.Event    `json:"before"`
	AfterHashes map[string]string `json:"after_hashes"`
	Segments    []EventSegment    `json:"segments"`
	Batch       string            `json:"batch"`
	RolledBack  bool              `json:"rolled_back"`
}

func (s Services) ApplyAggregationRepair(ctx context.Context, plan RepairPlan) error {
	if plan.Schema != 1 || plan.Checksum == "" || plan.Checksum != repairChecksum(plan) {
		return errors.New("repair manifest checksum mismatch")
	}
	return s.Store.AggregationTransaction(ctx, "repair-batch", func(tx store.Store) error {
		if existing, ok, err := tx.AggregateRecord(ctx, "repair_batch", plan.BatchID); err != nil {
			return err
		} else if ok {
			if existing.Group == "rolled_back" {
				return errors.New("该批次已回退，请重新审计，不可重复应用旧清单")
			}
			return nil
		}
		applied := repairApplied{Batch: plan.BatchID, AfterHashes: map[string]string{}}
		groups := map[string][]store.Hit{}
		owners := map[string][]RepairEntry{}
		for _, entry := range plan.Entries {
			current, ok := tx.GetEvent(entry.EventID)
			if !ok || digest(current) != entry.BeforeHash {
				return fmt.Errorf("事件 %s 在预览后发生变化，请重新生成计划", entry.EventID)
			}
			applied.Before = append(applied.Before, current)
			if len(entry.Recoverable) > 0 {
				fp := entry.Recoverable[0].AggregateKey
				for _, h := range entry.Recoverable {
					if h.AggregateKey != fp {
						return errors.New("mixed aggregation identities in historical event")
					}
				}
				groups[fp] = append(groups[fp], entry.Recoverable...)
				owners[fp] = append(owners[fp], entry)
			} else {
				c := decodeEventContext(current.Context)
				c["statistics_quality"] = entry.Quality
				c["historical_declared_count"] = entry.Declared
				c["occurrences_available"] = entry.Available
				c["quality_reasons"] = entry.Reasons
				b, _ := json.Marshal(c)
				patch := map[string]any{"context": string(b)}
				if entry.ArchiveDate != "" {
					patch["archive_date"] = entry.ArchiveDate
				}
				if _, ok = tx.UpdateEvent(entry.EventID, patch); !ok {
					return errors.New("save historical quality failed")
				}
			}
		}
		keys := []string{}
		for key := range groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, fp := range keys {
			if err := tx.LockAggregationKey(ctx, "group-"+fp); err != nil {
				return err
			}
			existing, err := tx.AggregateRecords(ctx, "segment", fp, 0)
			if err != nil {
				return err
			}
			if len(existing) > 0 {
				return fmt.Errorf("聚合键 %s 已有新链路数据；为避免覆盖，需重新核验后合并", fp)
			}
			hits := groups[fp]
			sort.Slice(hits, func(i, j int) bool {
				if hits[i].OccurredAt.Equal(hits[j].OccurredAt) {
					return hits[i].ID < hits[j].ID
				}
				return hits[i].OccurredAt.Before(hits[j].OccurredAt)
			})
			unique := []store.Hit{}
			seen := map[string]bool{}
			for _, h := range hits {
				if !seen[h.DedupKey] {
					unique = append(unique, h)
					seen[h.DedupKey] = true
				}
			}
			entries := owners[fp]
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].Before.CreatedAt.Equal(entries[j].Before.CreatedAt) {
					return entries[i].EventID < entries[j].EventID
				}
				return entries[i].Before.CreatedAt.Before(entries[j].Before.CreatedAt)
			})
			canonical := entries[0].EventID
			segments := [][]store.Hit{}
			for _, h := range unique {
				if len(segments) == 0 || h.OccurredAt.Sub(segments[len(segments)-1][len(segments[len(segments)-1])-1].OccurredAt) >= domain.ConvergenceIdleWindow {
					segments = append(segments, []store.Hit{})
				}
				segments[len(segments)-1] = append(segments[len(segments)-1], h)
			}
			rebuiltIDs := []string{}
			for n, hits := range segments {
				id := canonical
				if n > 0 {
					id = "ly-repair-" + digest([]any{plan.BatchID, fp, n})[:32]
					m := map[string]any{}
					_ = json.Unmarshal(hits[0].Raw, &m)
					ev := LyEventToDeepSOC(m)
					ev.EventID = id
					if _, err = tx.CreateEvent(ev); err != nil {
						return err
					}
				}
				rebuiltIDs = append(rebuiltIDs, id)
				seg := EventSegment{EventID: id, CanonicalID: id, AggregateKey: fp, Sources: []string{id}, First: hits[0].OccurredAt, Last: hits[len(hits)-1].OccurredAt, Created: entries[0].Before.CreatedAt, Version: 1, Count: int64(len(hits))}
				for _, h := range hits {
					if _, ok, e := tx.FindHit(ctx, h.DedupKey); e != nil {
						return e
					} else if ok {
						return errors.New("historical hit already exists; refusing ambiguous ownership")
					}
					h.EventID = id
					stored, e := tx.InsertHit(ctx, h)
					if e != nil {
						return e
					}
					if stored.Sequence > seg.Watermark {
						seg.Watermark = stored.Sequence
					}
				}
				if err = putRecord(ctx, tx, "segment", id, fp, seg); err != nil {
					return err
				}
				applied.Segments = append(applied.Segments, seg)
				ev, _ := tx.GetEvent(id)
				c := decodeEventContext(ev.Context)
				c["aggregation_version"] = 2
				c["suppress_auto_analysis"] = true
				c["data_version"] = 1
				c["stats_version"] = 0
				c["statistics_quality"] = "rebuilding"
				c["report_stale"] = true
				c["canonical_event_id"] = id
				c["aggregation_key"] = fp
				c["historical_declared_count"] = c["occurrence_count"]
				c["occurrence_count"] = nil
				c["quant_stats"] = map[string]any{}
				c["occurrences"] = []any{}
				// 旧快照的全量心跳结论一并作废，等待重建重新计算。
				delete(c, "heartbeat_detected")
				delete(c, "heartbeat_period_sec")
				b, _ := json.Marshal(c)
				if _, ok := tx.UpdateEvent(id, map[string]any{"context": string(b), "last_seen_at": seg.Last.Format(time.RFC3339Nano), "aggregation_closed": true, "archive_date": seg.Last.In(domain.Beijing).Format("2006-01-02"), "review_status": "pending"}); !ok {
					return errors.New("save historical rebuilt event failed")
				}
				if err = putRecord(ctx, tx, "outbox", id, "pending", map[string]any{"event_id": id, "repair_batch": plan.BatchID}); err != nil {
					return err
				}
			}
			for _, entry := range entries {
				ev, _ := tx.GetEvent(entry.EventID)
				c := decodeEventContext(ev.Context)
				c["historical_rebuilt_events"] = rebuiltIDs
				c["merge_review_required"] = true
				if entry.EventID != canonical {
					c["canonical_event_id"] = canonical
					c["report_stale"] = true
				}
				b, _ := json.Marshal(c)
				if _, ok := tx.UpdateEvent(entry.EventID, map[string]any{"context": string(b)}); !ok {
					return errors.New("save historical link failed")
				}
			}
		}
		for _, ev := range applied.Before {
			after, _ := tx.GetEvent(ev.EventID)
			applied.AfterHashes[ev.EventID] = digest(after)
		}
		for _, seg := range applied.Segments {
			after, _ := tx.GetEvent(seg.EventID)
			applied.AfterHashes[seg.EventID] = digest(after)
		}
		return putRecord(ctx, tx, "repair_batch", plan.BatchID, "applied", applied)
	})
}

func (s Services) RollbackAggregationRepair(ctx context.Context, batch string) error {
	return s.Store.AggregationTransaction(ctx, "repair-batch", func(tx store.Store) error {
		r, ok, err := tx.AggregateRecord(ctx, "repair_batch", batch)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("repair batch missing")
		}
		var applied repairApplied
		if err = json.Unmarshal(r.Value, &applied); err != nil {
			return err
		}
		if applied.RolledBack {
			return nil
		}
		// Do not restore over subsequent ingestion, analysis, review or publication.
		for id, hash := range applied.AfterHashes {
			ev, ok := tx.GetEvent(id)
			if !ok || digest(ev) != hash {
				return fmt.Errorf("事件 %s 已发生后续修改；拒绝覆盖，请执行补偿重建", id)
			}
		}
		originals := map[string]bool{}
		roots := map[string]string{}
		for _, before := range applied.Before {
			originals[before.EventID] = true
			fp := Fingerprint(decodeEventContext(before.Context))
			if roots[fp] == "" {
				roots[fp] = before.EventID
			}
		}
		for _, seg := range applied.Segments {
			if err = tx.LockAggregationKey(ctx, "group-"+seg.AggregateKey); err != nil {
				return err
			}
			current, ok, e := readSegment(ctx, tx, seg.EventID)
			if e != nil {
				return e
			}
			if !ok || current.Version != seg.Version {
				return errors.New("rebuilt segment changed")
			}
			current.Disabled = true
			if err = putRecord(ctx, tx, "segment", seg.EventID, seg.AggregateKey, current); err != nil {
				return err
			}
			if err = putRecord(ctx, tx, "outbox", seg.EventID, "done", map[string]any{"rolled_back": batch}); err != nil {
				return err
			}
			if !originals[seg.EventID] {
				ev, _ := tx.GetEvent(seg.EventID)
				c := decodeEventContext(ev.Context)
				c["canonical_event_id"] = roots[seg.AggregateKey]
				c["repair_rolled_back"] = batch
				b, _ := json.Marshal(c)
				if _, ok = tx.UpdateEvent(seg.EventID, map[string]any{"context": string(b)}); !ok {
					return errors.New("preserve rolled-back event failed")
				}
			}
		}
		for _, before := range applied.Before {
			var archive any
			var lastSeen any
			if before.LastSeenAt != nil {
				lastSeen = before.LastSeenAt.Format(time.RFC3339Nano)
			}
			if before.ArchiveDate != nil {
				archive = before.ArchiveDate.Format("2006-01-02")
			}
			if _, ok := tx.UpdateEvent(before.EventID, map[string]any{"context": before.Context, "archive_date": archive, "aggregation_closed": before.AggregationClosed, "last_seen_at": lastSeen, "review_status": before.ReviewStatus}); !ok {
				return errors.New("restore historical event failed")
			}
		}
		applied.RolledBack = true
		return putRecord(ctx, tx, "repair_batch", batch, "rolled_back", applied)
	})
}
