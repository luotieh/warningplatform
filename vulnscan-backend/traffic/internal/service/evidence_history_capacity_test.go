package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/store"
)

type delayedHistoryStore struct {
	store.Store
	active atomic.Int32
	peak   atomic.Int32
}

func (s *delayedHistoryStore) AggregateRecord(ctx context.Context, kind, key string) (store.AggregateRecord, bool, error) {
	if kind == "snapshot" {
		n := s.active.Add(1)
		defer s.active.Add(-1)
		for p := s.peak.Load(); n > p; p = s.peak.Load() {
			if s.peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-ctx.Done():
			return store.AggregateRecord{}, false, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	return s.Store.AggregateRecord(ctx, kind, key)
}

func TestEvidencePipelineHistoryFreezeWorkersAndBudget(t *testing.T) {
	s := phaseOneFixture(t)
	rows := []ReportHistoryRow{}
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("freeze-capacity-%d", i)
		phaseOneInstallSnapshot(t, s, id, 1, []map[string]any{phaseOneWire(t, at, uint32(100+i*500), phaseOneHTTP("cmd=id"), false, false)})
		rows = append(rows, ReportHistoryRow{EventID: id})
	}
	delayed := &delayedHistoryStore{Store: s.Store}
	s.Store = delayed
	samples := []map[string]any{}
	for _, count := range []int{1, 25, 100} {
		var serial string
		for _, workers := range []int{1, 4} {
			limits := s.pipelineLimits()
			limits.HistoryFreezeWorkers = workers
			ctx := context.WithValue(context.Background(), pipelineLimitsKey{}, limits)
			h := ReportHistory{Rows: rows[:count]}
			start := time.Now()
			s.freezePipelineHistory(ctx, &h)
			elapsed := time.Since(start).Microseconds()
			if len(h.FrozenSnapshots) != count || len(h.SnapshotIssues) != 0 {
				t.Fatal("freeze failed", h.SnapshotIssues)
			}
			if workers == 1 {
				serial = digest(h.FrozenSnapshots)
			} else if serial != digest(h.FrozenSnapshots) {
				t.Fatal("worker count changed frozen identities")
			}
			samples = append(samples, map[string]any{"snapshots": count, "workers": workers, "elapsed_us": elapsed, "snapshot_digest": digest(h.FrozenSnapshots)})
		}
	}
	if delayed.peak.Load() > 4 || delayed.peak.Load() < 2 {
		t.Fatal("unbounded or inactive parallel reads", delayed.peak.Load())
	}
	limits := s.pipelineLimits()
	limits.HistorySnapshots = 2
	h := ReportHistory{Rows: append(rows[:3], rows[0])}
	s.freezePipelineHistory(context.WithValue(context.Background(), pipelineLimitsKey{}, limits), &h)
	if len(h.FrozenSnapshots) != 2 || h.SnapshotIssues[rows[2].EventID] != "snapshot_freeze_budget_exceeded" {
		t.Fatal("budget lost scope diagnostics", h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h = ReportHistory{Rows: rows[:2]}
	s.freezePipelineHistory(ctx, &h)
	if len(h.FrozenSnapshots) != 0 || len(h.SnapshotIssues) != 2 {
		t.Fatal("cancelled freeze silently complete")
	}
	if dir := os.Getenv("EVIDENCE_V21_OUTPUT"); dir != "" {
		raw, _ := json.MarshalIndent(map[string]any{"controlled_snapshot_lookup_delay_ms": 1, "peak_workers": delayed.peak.Load(), "samples": samples}, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "history-freeze-performance.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
