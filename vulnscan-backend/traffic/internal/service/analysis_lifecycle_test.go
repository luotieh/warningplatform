package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestPeriodicQueueAndConvergencePriority(t *testing.T) {
	s := Services{Store: store.NewMemoryStore()}
	now := time.Now().UTC()
	id := ingestTestHit(t, s, "periodic-a", now.Add(-45*time.Minute))
	if id != ingestTestHit(t, s, "periodic-b", now.Add(-20*time.Minute)) {
		t.Fatal("split active event")
	}
	if err := s.DrainAggregation(context.Background(), 20); err != nil {
		t.Fatal(err)
	}
	s.Store.UpdateEvent(id, map[string]any{"analysis_version": 1, "last_analysis_at": now.Add(-31 * time.Minute).Format(time.RFC3339Nano)})
	putRecord(context.Background(), s.Store, "analysis_outbox", id, "done", map[string]any{"kind": "initial", "version": 2})
	n, err := s.ScanPeriodicAnalysis(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("periodic %d %v", n, err)
	}
	n, err = s.ScanPeriodicAnalysis(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("duplicate periodic %d %v", n, err)
	}
	if err = s.convergeAggregation(context.Background(), id, now.Add(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	r, _, _ := s.Store.AggregateRecord(context.Background(), "analysis_outbox", id)
	var task map[string]any
	json.Unmarshal(r.Value, &task)
	if task["kind"] != "final" {
		t.Fatalf("final did not supersede periodic: %v", task)
	}
}

func TestAnalysisFailureHintPersistedAndCleared(t *testing.T) {
	s := Services{Store: store.NewMemoryStore()}
	s.Store.CreateEvent(domain.Event{EventID: "hint", Context: `{}`})
	raw := "status=403; weekly usage limit; URL=https://private.example/api; secret-key"
	if err := s.setAnalysisJob("hint", "failed", "initial", raw); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Store.GetEvent("hint")
	c := decodeEventContext(e.Context)
	if c["analysis_failure_reason"] != "模型额度不足，恢复额度后重试" || c["analysis_failed_at"] == nil || strings.Contains(asString(c["analysis_failure_reason"]), "secret") {
		t.Fatalf("unsafe or missing cause: %v", c)
	}
	at := c["analysis_failed_at"]
	s.setAnalysisJob("hint", "failed", "initial", raw)
	e, _ = s.Store.GetEvent("hint")
	if decodeEventContext(e.Context)["analysis_failed_at"] != at {
		t.Fatal("retry polling changed failure time")
	}
	if err := s.publishAnalysisState("hint", "initial", 1, nil); err != nil {
		t.Fatal(err)
	}
	e, _ = s.Store.GetEvent("hint")
	c = decodeEventContext(e.Context)
	if c["analysis_failure_reason"] != nil || c["analysis_failed_at"] != nil {
		t.Fatal("stale failure after success")
	}
}

func TestPeriodicVersionDoesNotBlockFinal(t *testing.T) {
	s := Services{Store: store.NewMemoryStore()}
	e := domain.Event{EventID: "periodic-v2", AnalysisVersion: 2, AggregationClosed: true, Context: `{"report_kind":"periodic","report_published":true,"data_version":3,"report_data_version":2,"ai_probability":55}`}
	s.Store.CreateEvent(e)
	if s.finalReportCurrent(e) {
		t.Fatal("periodic mistaken for final")
	}
	// No model is configured: a genuine final attempt must fail, not silently skip.
	if err := s.RunFinalAnalysis(context.Background(), e.EventID); err == nil {
		t.Fatal("final was skipped")
	}
	e, _ = s.Store.GetEvent(e.EventID)
	if domain.AnalysisState(e, time.Now()) != "completed" || toInt(decodeEventContext(e.Context)["ai_probability"]) != 55 || e.AnalysisVersion != 2 {
		t.Fatalf("old report damaged: %+v", e)
	}
}

func TestPublicationPreservesLatestStatsAndClearsNullProbability(t *testing.T) {
	s := Services{Store: store.NewMemoryStore()}
	s.Store.CreateEvent(domain.Event{EventID: "publish", Context: `{"data_version":8,"stats_version":8,"occurrence_count":8,"report_data_version":7,"report_stale":true,"ai_probability":55}`})
	if err := s.publishAnalysisState("publish", "periodic", 3, nil); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Store.GetEvent("publish")
	c := decodeEventContext(e.Context)
	if c["ai_probability"] != nil || toInt(c["data_version"]) != 8 || c["report_stale"] != true || e.AnalysisVersion != 3 || domain.AnalysisState(e, time.Now()) != "completed" {
		t.Fatalf("inconsistent publication: %+v", e)
	}
}
