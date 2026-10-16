package service

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"
	"vulnscan-backend/evidence"
)

// This harness also compiles unchanged against the M0 commit. It measures a
// controlled local workload, not database/network/model inference performance.
func TestEvidencePipelinePerformanceSamples(t *testing.T) {
	path := os.Getenv("EVIDENCE_PIPELINE_PERF_OUTPUT")
	if path == "" {
		t.Skip("optional performance export")
	}
	type sample struct {
		Mode           string `json:"mode"`
		ElapsedUS      int64  `json:"elapsed_us"`
		AllocatedBytes uint64 `json:"allocated_bytes"`
		HeapAfter      uint64 `json:"heap_after_bytes"`
		HitPages       int    `json:"hit_pages"`
		ModelCalls     int    `json:"model_calls"`
		PromptBytes    int    `json:"prompt_bytes"`
		ResponseBytes  int    `json:"response_bytes"`
		Evidence       any    `json:"pipeline,omitempty"`
	}
	rows := []sample{}
	for _, mode := range []string{"cold", "warm"} {
		var run func() sample
		setup := func() {
			s := phaseOneFixture(t)
			at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
			messages := []map[string]any{}
			for i := 0; i < 24; i++ {
				messages = append(messages, phaseOneWire(t, at.Add(time.Duration(i)*time.Minute), uint32(100+i*500), phaseOneHTTP("cmd=636174202f6574632f706173737764"), false, false))
			}
			snap := phaseOneInstallSnapshot(t, s, "perf-controlled-http", 1, messages)
			counter := &evidenceReadCounter{Store: s.Store}
			s.Store = counter
			calls, promptBytes, responseBytes := 0, 0, 0
			s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
				calls++
				promptBytes += len(c.System) + len(c.Prompt)
				reply := acceptedSemanticResponse(t, c)
				responseBytes += len(reply)
				return reply, nil
			})
			event := mustEvent(t, s, snap.EventID)
			run = func() sample {
				pages0, calls0, prompt0, response0 := counter.hitPages, calls, promptBytes, responseBytes
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				p, err := s.prepareReportInputMode(context.Background(), event, true)
				elapsed := time.Since(start).Microseconds()
				runtime.ReadMemStats(&after)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(p.Evidence)
				var output map[string]json.RawMessage
				_ = json.Unmarshal(raw, &output)
				var pipeline any
				if value := output["pipeline"]; len(value) > 0 {
					_ = json.Unmarshal(value, &pipeline)
				}
				return sample{mode, elapsed, after.TotalAlloc - before.TotalAlloc, after.HeapAlloc, counter.hitPages - pages0, calls - calls0, promptBytes - prompt0, responseBytes - response0, pipeline}
			}
		}
		if mode == "warm" {
			setup()
			_ = run()
		}
		for i := 0; i < 15; i++ {
			if mode == "cold" {
				setup()
			}
			rows = append(rows, run())
		}
	}
	summaries := map[string]any{}
	for _, mode := range []string{"cold", "warm"} {
		times := []int64{}
		var allocated, maxHeap uint64
		pages, calls := 0, 0
		for _, r := range rows {
			if r.Mode == mode {
				times = append(times, r.ElapsedUS)
				allocated += r.AllocatedBytes
				maxHeap = max(maxHeap, r.HeapAfter)
				pages += r.HitPages
				calls += r.ModelCalls
			}
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		summaries[mode] = map[string]any{"samples": len(times), "p50_us": times[len(times)/2], "p95_us": times[(95*len(times)+99)/100-1], "mean_allocated_bytes": allocated / uint64(len(times)), "max_sampled_heap_bytes": maxHeap, "hit_pages": pages, "model_calls": calls}
	}
	value := map[string]any{"workload": "24 controlled HTTP requests, 15 cold + 15 warm runs, deterministic semantic model stub", "go": runtime.Version(), "token_counts_known": false, "summaries": summaries, "samples": rows}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestEvidencePipelineModelChangePerformance(t *testing.T) {
	path := os.Getenv("EVIDENCE_PIPELINE_MODEL_CHANGE_OUTPUT")
	if path == "" {
		t.Skip("optional model change cache export")
	}
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 24; i++ {
		messages = append(messages, phaseOneWire(t, at.Add(time.Duration(i)*time.Minute), uint32(100+i*500), phaseOneHTTP("cmd=636174202f6574632f706173737764"), false, false))
	}
	snap := phaseOneInstallSnapshot(t, s, "perf-model-change", 1, messages)
	counter := &evidenceReadCounter{Store: s.Store}
	s.Store = counter
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, c), nil
	})
	opts := DefaultReportSemanticOptions()
	opts.ModelVersion = "perf-model-a"
	s.ReportSemantics = &opts
	p1 := phaseOneRun(t, s, snap, true)
	before := counter.hitPages
	opts.ModelVersion = "perf-model-b"
	start := time.Now()
	p2 := phaseOneRun(t, s, snap, true)
	value := map[string]any{"workload": "24 controlled HTTP requests; only model version changes; deterministic model stub", "first_read_pages": before, "model_change_read_pages": counter.hitPages - before, "elapsed_us": time.Since(start).Microseconds(), "first_score": p1.Evidence.PhaseOne.Result.Score, "second_score": p2.Evidence.PhaseOne.Result.Score}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
