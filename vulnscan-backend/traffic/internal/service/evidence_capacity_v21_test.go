package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"vulnscan-backend/evidence"
)

// This harness also runs against the frozen, unmodified local v2.0 baseline.
// Synthetic ledger capacity only; it does not manufacture algorithm findings.
func TestEvidenceV21Capacity(t *testing.T) {
	path := os.Getenv("EVIDENCE_CAPACITY_OUTPUT")
	if path == "" {
		t.Skip("optional capacity measurement")
	}
	output := []map[string]any{}
	percentile := func(values []int64, p int) int64 {
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		return values[(p*len(values)+99)/100-1]
	}
	for _, n := range []int{1000, 10000} {
		s := phaseOneFixture(t)
		sources := []string{}
		for i := 0; i < 500; i++ {
			sources = append(sources, fmt.Sprintf("controlled-source-%05d", i))
		}
		items := []evidence.UnifiedEvidence{}
		for i := 0; i < n; i++ {
			items = append(items, evidence.UnifiedEvidence{ID: fmt.Sprintf("N%08d", i), Kind: "fact", RuleID: "capacity-only", Status: "missing", TerminalStatus: "missing", SourceIDs: sources, Dependencies: []evidence.Dependency{{Kind: "controlled-source-set", Version: "1", SourceIDs: sources}}, Version: "fixture-only"})
		}
		key := fmt.Sprintf("capacity-%d", n)
		audit := pipelineAudit("capacity", SnapshotFactEvaluation{}, ReportSemanticEvaluation{})
		audit.Key = key
		journal := pipelineJournal{Audit: audit, Evidence: ReportEvidenceBundle{Normalized: evidence.NormalizedEvidence{Items: items}}}
		begin := time.Now()
		if err := s.persistPipelineJournal(context.Background(), key, "capacity", journal); err != nil {
			t.Fatal(err)
		}
		writeUS := time.Since(begin).Microseconds()
		doc := ReportDocument{EventID: "capacity", Evidence: ReportEvidenceBundle{Pipeline: &audit}}
		latency := []int64{}
		var allocated uint64
		var heap uint64
		for i := 0; i < 15; i++ {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			p, err := s.ReportEvidenceDetails(context.Background(), doc, 99, 100)
			elapsed := time.Since(start).Microseconds()
			runtime.ReadMemStats(&after)
			if err != nil || len(p.Items) != 100 || p.Total != n || p.Items[0].ID != "N00000099" || len(p.Items[0].SourceIDs) != 500 {
				t.Fatal("page/source mismatch", err)
			}
			latency = append(latency, elapsed)
			allocated += after.TotalAlloc - before.TotalAlloc
			heap = max(heap, after.HeapAlloc)
		}
		concurrent := []int64{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 5; i++ {
					start := time.Now()
					p, err := s.ReportEvidenceDetails(context.Background(), doc, n-50, 100)
					elapsed := time.Since(start).Microseconds()
					if err != nil || len(p.Items) != 50 {
						t.Error("concurrent page", err)
					}
					mu.Lock()
					concurrent = append(concurrent, elapsed)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		empty, err := s.ReportEvidenceDetails(context.Background(), doc, n+500, 100)
		if err != nil || len(empty.Items) != 0 || empty.Total != n {
			t.Fatal("empty page", err)
		}
		output = append(output, map[string]any{"items": n, "sources_per_instance": 500, "single_samples": 15, "single_p50_us": percentile(latency, 50), "single_p95_us": percentile(latency, 95), "concurrent_workers": 4, "concurrent_samples": 20, "concurrent_p50_us": percentile(concurrent, 50), "concurrent_p95_us": percentile(concurrent, 95), "mean_allocated_bytes": allocated / 15, "max_sampled_heap_bytes": heap, "persist_us": writeUS})
	}
	raw, _ := json.MarshalIndent(map[string]any{"workload": "controlled synthetic ledger, no database/model capacity claim", "samples": output}, "", "  ")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
