package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Reject any attempt to expand historical events into snapshots or packets.
type summaryOnlyReader struct {
	store.EvidenceReader
	current string
}

func (r *summaryOnlyReader) EvidenceEvent(ctx context.Context, id string) (domain.Event, bool, error) {
	if id != r.current {
		return domain.Event{}, false, fmt.Errorf("unexpected_historical_event_read")
	}
	return r.EvidenceReader.EvidenceEvent(ctx, id)
}
func (r *summaryOnlyReader) AggregateRecord(ctx context.Context, kind, key string) (store.AggregateRecord, bool, error) {
	if (kind == "segment" && key != r.current) || (kind == "snapshot" && !strings.HasPrefix(key, r.current+":")) {
		return store.AggregateRecord{}, false, fmt.Errorf("unexpected_historical_snapshot_read")
	}
	return r.EvidenceReader.AggregateRecord(ctx, kind, key)
}
func (r *summaryOnlyReader) SnapshotPage(ctx context.Context, q store.HitQuery, rw, pb, rb int64) ([]store.Hit, error) {
	for _, id := range q.Sources {
		if id != r.current {
			return nil, fmt.Errorf("unexpected_historical_packet_read")
		}
	}
	return r.EvidenceReader.SnapshotPage(ctx, q, rw, pb, rb)
}
func TestProviderHistorySummariesNeverLoadPacketsOrBackfillJitter(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{providerTemporalMessage(t, at, 10)})
	for day := 1; day <= 20; day++ {
		m := providerTemporalMessage(t, at.AddDate(0, 0, -day), uint32(day*100))
		m["ioc_description"] = strings.Repeat("irrelevant", 20000)
		m["app"].(map[string]any)["body"] = strings.Repeat("irrelevant", 20000)
		nestedMap(m, "raw_packet")["capture_truncated"] = true
		phaseOneInstallSnapshot(t, s, fmt.Sprintf("history-%d", day), 1, []map[string]any{m})
	}
	r := &summaryOnlyReader{EvidenceReader: s.Store.(store.EvidenceReader), current: "current"}
	o := providerTestOptions(t)
	o.MaxBytes = 64 << 10
	o.MaxHits = 1
	c, err := CollectEvidenceFromPlatform(context.Background(), r, "current", o)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.HistoryCandidates) != 20 || len(c.HistorySnapshots) != 0 {
		t.Fatal("history not summary-only")
	}
	for _, e := range c.HistoryCandidates {
		if strings.Contains(e.Context, "irrelevant") {
			t.Fatal("unneeded app body supplied")
		}
	}
	b, _, err := PreprocessCollectedEvidence(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Inputs.Manifest.PhaseOne.Contacts) != 1 || len(b.History.Rows) != 20 {
		t.Fatal("history polluted current contacts or summaries lost")
	}
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[evidence.FactID]bool{}
	for _, f := range result.Evaluation.Result.Findings {
		switch f.FactID {
		case "F_BEACON_JITTER":
			if f.ReasonCode != evidence.InsufficientSamples || f.Measurements.SampleCount != 1 {
				t.Fatal("history backfilled jitter", f)
			}
			seen[f.FactID] = true
		case "F_FIXED_DAILY_WINDOW":
			if f.ObservationKind != "event_occurrence" || f.Measurements.SampleCount != 21 || f.Status != evidence.Observed {
				t.Fatal("event schedule failed", f)
			}
			seen[f.FactID] = true
		case evidence.MultiDayPersist:
			if f.Status != evidence.Observed || f.Measurements.DaysActive == nil || *f.Measurements.DaysActive != 21 {
				t.Fatal("event day count failed", f)
			}
			seen[f.FactID] = true
		}
	}
	if len(seen) != 3 {
		t.Fatal("missing temporal rule", seen)
	}
	c.HistorySnapshots["legacy"] = CollectedSnapshotReference{EventID: "legacy", Loaded: true, Hits: []CollectedHit{{Raw: []byte("invalid packet JSON")}}}
	c.Seal()
	replayed, _, err := PreprocessCollectedEvidence(context.Background(), c)
	if err != nil || digest(replayed.Inputs.Manifest.PhaseOne.Contacts) != digest(b.Inputs.Manifest.PhaseOne.Contacts) {
		t.Fatal("legacy packet payload consumed", err)
	}
}
