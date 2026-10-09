package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"vulnscan-backend/evidence"
)

type SnapshotEvidenceDiagnostics struct {
	EventID         string                   `json:"event_id"`
	SnapshotVersion int64                    `json:"snapshot_version"`
	At              time.Time                `json:"at"`
	Status          string                   `json:"status"`
	Reason          string                   `json:"reason,omitempty"`
	ResultKey       string                   `json:"result_key,omitempty"`
	ResultPersisted bool                     `json:"result_persisted"`
	Manifest        SnapshotEvidenceManifest `json:"manifest"`
}

// Read-only debugging: never executes an algorithm or reads the hit table.
func (s Services) EvidenceInputDiagnostics(ctx context.Context, eventID string, version int64) (SnapshotEvidenceDiagnostics, error) {
	if eventID == "" || version < 0 {
		return SnapshotEvidenceDiagnostics{}, errors.New("invalid event/snapshot version")
	}
	if version == 0 {
		snap, err := s.EvidenceSnapshot(ctx, eventID, 0)
		if err != nil {
			return SnapshotEvidenceDiagnostics{}, err
		}
		version = snap.Version
	}
	record, ok, err := s.Store.AggregateRecord(ctx, "evidence_diagnostics", snapshotKey(eventID, version))
	if err != nil {
		return SnapshotEvidenceDiagnostics{}, errors.New("evidence diagnostics read failed")
	}
	if !ok {
		return SnapshotEvidenceDiagnostics{EventID: eventID, SnapshotVersion: version, Status: "not_evaluated"}, nil
	}
	var diagnostic SnapshotEvidenceDiagnostics
	if err := json.Unmarshal(record.Value, &diagnostic); err != nil || diagnostic.EventID != eventID || diagnostic.SnapshotVersion != version {
		return diagnostic, errors.New("invalid stored evidence diagnostics")
	}
	return diagnostic, nil
}

// Diagnostics never contain raw payloads, credentials, SQL or driver messages.
// Full causes remain available through errors.Unwrap for callers and tests.
type SnapshotInputError struct {
	Code            string
	Stage           string
	EventID         string
	SnapshotVersion int64
	HitID           string
	Cause           error
}

func (e *SnapshotInputError) Error() string {
	return fmt.Sprintf("evidence input %s: stage=%s event=%s snapshot=%d hit=%s", e.Code, e.Stage, e.EventID, e.SnapshotVersion, e.HitID)
}
func (e *SnapshotInputError) Unwrap() error { return e.Cause }

type SnapshotInputIssue struct {
	Code      string         `json:"code"`
	Stage     string         `json:"stage"`
	Field     string         `json:"field,omitempty"`
	HitID     string         `json:"hit_id,omitempty"`
	Scope     evidence.Scope `json:"scope"`
	Retryable bool           `json:"retryable"`
	CauseType string         `json:"cause_type,omitempty"`
	CauseCode string         `json:"cause_code,omitempty"`
}

func snapshotIssueCause(issue SnapshotInputIssue, err error) SnapshotInputIssue {
	var databaseError *mysql.MySQLError
	if errors.As(err, &databaseError) {
		issue.CauseCode = fmt.Sprintf("mysql_%d", databaseError.Number)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		issue.CauseCode = "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		issue.CauseCode = "cancelled"
	}
	cause := err
	for i := 0; i < 16 && errors.Unwrap(cause) != nil; i++ {
		cause = errors.Unwrap(cause)
	}
	if cause != nil {
		issue.CauseType = fmt.Sprintf("%T", cause)
	}
	return issue
}

func (m *SnapshotEvidenceManifest) addIssue(issue SnapshotInputIssue) {
	m.IssueCount++
	if len(m.Issues) < 128 {
		m.Issues = append(m.Issues, issue)
	} else {
		m.OmittedIssues++
	}
}

type SnapshotFactCoverage struct {
	FactID    evidence.FactID     `json:"fact_id"`
	Scope     evidence.Scope      `json:"scope"`
	Requested bool                `json:"requested"`
	Status    string              `json:"status"`
	Reason    evidence.ReasonCode `json:"reason_code"`
	Inputs    []string            `json:"inputs"`
}

// Catalog is a coverage/explanation contract, never a replacement eligibility
// checker. Actual rule execution remains the single authority for readiness.
func snapshotFactCoverage(req evidence.Request, result evidence.Result) []SnapshotFactCoverage {
	selected := map[evidence.FactID]bool{}
	ids := req.Facts
	if ids == nil {
		ids = []evidence.FactID{evidence.BeaconPeriodic, evidence.MultiDayPersist}
	}
	for _, id := range ids {
		selected[id] = true
	}
	rows := []SnapshotFactCoverage{}
	for _, f := range result.Findings {
		rows = append(rows, SnapshotFactCoverage{FactID: f.FactID, Scope: f.Scope, Requested: true, Status: string(f.Status), Reason: f.ReasonCode, Inputs: evidence.FactInputs(f.FactID)})
	}
	// Retain all 59 even for explicit subsets. Not requested is never negative.
	for _, id := range evidence.SupportedFacts() {
		if !selected[id] {
			rows = append(rows, SnapshotFactCoverage{FactID: id, Status: "not_requested", Reason: evidence.NotRequested, Inputs: evidence.FactInputs(id)})
		}
	}
	return rows
}

func snapshotUnavailableCoverage(facts []evidence.FactID, reason evidence.ReasonCode) []SnapshotFactCoverage {
	if facts == nil {
		facts = []evidence.FactID{evidence.BeaconPeriodic, evidence.MultiDayPersist}
	}
	selected := map[evidence.FactID]bool{}
	for _, id := range facts {
		selected[id] = true
	}
	rows := []SnapshotFactCoverage{}
	for _, id := range evidence.SupportedFacts() {
		row := SnapshotFactCoverage{FactID: id, Requested: selected[id], Status: "not_requested", Reason: evidence.NotRequested, Inputs: evidence.FactInputs(id)}
		if selected[id] {
			row.Status = "unavailable"
			row.Reason = reason
		}
		rows = append(rows, row)
	}
	return rows
}
