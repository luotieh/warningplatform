package service

import (
	"context"
	"encoding/json"
	"sync"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

// Freeze candidate membership/revision watermarks before feature computation.
// This is a logical snapshot, not a claim of a cross-table SQL transaction.
func (s Services) freezePipelineHistory(ctx context.Context, history *ReportHistory) {
	defer pipelineMeasure(ctx, "freeze_history")()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	history.FrozenSnapshots = map[string]EvidenceSnapshot{}
	history.SnapshotIssues = map[string]string{}
	ids := []string{}
	seen := map[string]bool{}
	for _, row := range history.Rows {
		if seen[row.EventID] {
			continue
		}
		seen[row.EventID] = true
		if len(ids) >= contextPipelineLimits(ctx).HistorySnapshots {
			history.SnapshotIssues[row.EventID] = "snapshot_freeze_budget_exceeded"
			continue
		}
		ids = append(ids, row.EventID)
	}
	type result struct {
		snapshot EvidenceSnapshot
		issue    string
		lookedUp bool
	}
	results := make([]result, len(ids))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for n := 0; n < min(max(contextPipelineLimits(ctx).HistoryFreezeWorkers, 1), len(ids)); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					results[i].issue = "snapshot_freeze_timeout"
					continue
				}
				snap, err := s.EvidenceSnapshot(ctx, ids[i], 0)
				results[i].lookedUp = true
				if err != nil {
					results[i].issue = "historical_snapshot_unavailable"
					continue
				}
				snap.Context, snap.Manifest = nil, nil
				results[i].snapshot = snap
			}
		}()
	}
	for i := range ids {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	// Workers own separate slots; only the parent mutates maps and metrics.
	for i, r := range results {
		if r.lookedUp {
			if m := pipelineMetrics(ctx); m != nil {
				m.HistoricalSnapshotLookups++
			}
		}
		if r.issue != "" {
			history.SnapshotIssues[ids[i]] = r.issue
		} else {
			history.FrozenSnapshots[ids[i]] = r.snapshot
		}
	}
}

func (s Services) pipelineTimeline(ctx context.Context, snap EvidenceSnapshot, current PhaseOneMaterials, history ReportHistory, assets []domain.Asset, persist bool) (PhaseOneMaterials, error) {
	defer pipelineMeasure(ctx, "timeline")()
	ctx, cancel := context.WithTimeout(ctx, contextPipelineLimits(ctx).HistoryTimeout)
	defer cancel()
	key := digest([]any{contextPipelineLimits(ctx), EvidencePipelineVersion, reportSnapshotAdapterVersion, snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, current, history, assets})
	if history.FrozenSnapshots != nil && len(history.SnapshotIssues) == 0 {
		if record, ok, err := s.Store.AggregateRecord(ctx, "evidence_timeline", key); err == nil && ok && len(record.Value) <= 8<<20 {
			var cached struct {
				Key       string            `json:"key"`
				Materials PhaseOneMaterials `json:"materials"`
			}
			if json.Unmarshal(record.Value, &cached) == nil && cached.Key == key && cached.Materials.Expanded && cached.Materials.Complete {
				for i := range cached.Materials.Records {
					if h := cached.Materials.Records[i].HTTP; h != nil {
						h.RawRequest, h.ParsedBody = cached.Materials.Records[i].RawRequest, cached.Materials.Records[i].ParsedBody
					}
				}
				if m := pipelineMetrics(ctx); m != nil {
					m.CacheHits["timeline"]++
				}
				return cached.Materials, nil
			}
		}
	}
	out, err := s.phaseOneTimeline(ctx, snap, current, history, assets)
	out.Expanded = true
	if err == nil && persist && out.Complete && len(history.SnapshotIssues) == 0 {
		value := struct {
			Key       string            `json:"key"`
			Materials PhaseOneMaterials `json:"materials"`
		}{key, out}
		if raw, e := json.Marshal(value); e == nil && len(raw) <= 8<<20 {
			_ = putRecord(ctx, s.Store, "evidence_timeline", key, snap.EventID, value)
		}
	}
	return out, err
}
