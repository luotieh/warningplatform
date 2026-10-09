package service

import (
	"context"
	"encoding/json"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type EvidenceReadMetric struct {
	Calls     int     `json:"calls"`
	Failures  int     `json:"failures"`
	ElapsedMS float64 `json:"elapsed_ms"`
}
type EvidenceValidation struct {
	EventID        string                        `json:"event_id"`
	ElapsedMS      float64                       `json:"elapsed_ms"`
	Reads          map[string]EvidenceReadMetric `json:"reads"`
	Evaluation     SnapshotFactEvaluation        `json:"evaluation"`
	StatusCounts   map[string]int                `json:"status_counts"`
	MissingReasons map[string]int                `json:"missing_reasons"`
}

type evidenceMeasuredStore struct {
	store.Store
	reads map[string]EvidenceReadMetric
}

func (s *evidenceMeasuredStore) record(k string, started time.Time, err error) {
	m := s.reads[k]
	m.Calls++
	if err != nil {
		m.Failures++
	}
	m.ElapsedMS += float64(time.Since(started).Microseconds()) / 1000
	s.reads[k] = m
}
func (s *evidenceMeasuredStore) AggregateRecord(c context.Context, k, id string) (r store.AggregateRecord, ok bool, err error) {
	start := time.Now()
	defer func() { s.record("record:"+k, start, err) }()
	return s.Store.AggregateRecord(c, k, id)
}
func (s *evidenceMeasuredStore) HitPage(c context.Context, q store.HitQuery) (r []store.Hit, err error) {
	start := time.Now()
	defer func() { s.record("hit_page", start, err) }()
	return s.Store.HitPage(c, q)
}
func (s *evidenceMeasuredStore) HitRevisions(c context.Context, ids []string, w int64) (r map[string]json.RawMessage, err error) {
	start := time.Now()
	defer func() { s.record("revision_batch", start, err) }()
	return s.Store.HitRevisions(c, ids, w)
}
func (s *evidenceMeasuredStore) ListAssets() []domain.Asset {
	start := time.Now()
	defer func() { s.record("asset_registry", start, nil) }()
	return s.Store.ListAssets()
}

func (s *evidenceMeasuredStore) ListAssetsContext(ctx context.Context) (assets []domain.Asset, err error) {
	start := time.Now()
	defer func() { s.record("asset_registry", start, err) }()
	return s.Store.ListAssetsContext(ctx)
}
func (s *evidenceMeasuredStore) GetEvent(id string) (event domain.Event, ok bool) {
	start := time.Now()
	defer func() { s.record("event", start, nil) }()
	return s.Store.GetEvent(id)
}

// ValidateReportEvidence runs the SAME preparation as automatic initial/final
// reports, forcing a fresh deterministic evaluation. It makes no writes, no
// model calls and does not change report/event lifecycle or production caches.
// Metrics count store operations, not driver round trips hidden inside a method.
func (s Services) ValidateReportEvidence(ctx context.Context, eventID string) (EvidenceValidation, error) {
	start := time.Now()
	counted := &evidenceMeasuredStore{Store: s.Store, reads: map[string]EvidenceReadMetric{}}
	s.Store = counted
	out := EvidenceValidation{EventID: eventID, Reads: counted.reads, StatusCounts: map[string]int{}, MissingReasons: map[string]int{}}
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return out, &SnapshotInputError{Code: "validation_event_not_found", Stage: "load_event", EventID: eventID}
	}
	p, err := s.prepareReportInputMode(ctx, event, false)
	out.Evaluation = p.Evaluation
	out.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000
	// Full findings include source references; validation exports only the
	// manifest. Operators can retrieve complete persisted evidence separately.
	out.Evaluation.Result = nil
	for _, row := range p.Evaluation.Manifest.FactCoverage {
		out.StatusCounts[row.Status]++
		if row.Status == "missing" {
			out.MissingReasons[string(row.Reason)]++
		}
	}
	return out, err
}
