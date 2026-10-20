package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type temporalArchiveReader struct {
	store.EvidenceReader
	archive *coverageArchiveStore
}

func (r temporalArchiveReader) SnapshotPage(ctx context.Context, q store.HitQuery, rw, pb, rb int64) ([]store.Hit, error) {
	return r.archive.SnapshotPage(ctx, q, rw, pb, rb)
}

// Optional replay of two already archived real events. The reader contains only
// these archived events, never live data; missing archive history is disclosed.
func TestProviderTemporalFrozenArchive(t *testing.T) {
	dir := os.Getenv("PROVIDER_TEMPORAL_ARCHIVE")
	if dir == "" {
		t.Skip("optional local frozen archive")
	}
	ctx := context.Background()
	memory := store.NewMemoryStore()
	archive := &coverageArchiveStore{Store: memory, revisions: map[string]int64{}}
	ids := []string{"ly-fd1496c4-14e6-40ae-bb29-57d162a9d94f", "ly-14725b4b-84f0-4233-b6f3-98d6444ce2e6"}
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	var inv struct {
		Assets []domain.Asset `json:"assets"`
	}
	coverageReadJSON(t, filepath.Join(dir, "coverage180-inventory.json"), &inv)
	for _, asset := range inv.Assets {
		if _, err := memory.CreateAsset(asset); err != nil {
			t.Fatal(err)
		}
	}
	var contexts []struct {
		EventID string          `json:"event_id"`
		Context json.RawMessage `json:"context"`
		Created time.Time       `json:"created_at"`
		Last    *time.Time      `json:"last_seen_at"`
	}
	if err := json.Unmarshal(coverageUnpack(t, filepath.Join(dir, "coverage180-contexts.json")), &contexts); err != nil {
		t.Fatal(err)
	}
	for _, event := range contexts {
		if selected[event.EventID] {
			if _, err := memory.CreateEvent(domain.Event{EventID: event.EventID, Context: string(event.Context), CreatedAt: event.Created, LastSeenAt: event.Last}); err != nil {
				t.Fatal(err)
			}
		}
	}
	var saved struct {
		Snapshots []struct {
			Key   string           `json:"key"`
			Value EvidenceSnapshot `json:"value"`
		} `json:"snapshots"`
		Segments []struct {
			Key   string       `json:"key"`
			Value EventSegment `json:"value"`
		} `json:"segments"`
	}
	coverageReadJSON(t, filepath.Join(dir, "coverage180-snapshots.json"), &saved)
	for _, row := range saved.Snapshots {
		if selected[row.Value.EventID] {
			if err := putRecord(ctx, memory, "snapshot", row.Key, row.Value.EventID, row.Value); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, row := range saved.Segments {
		if selected[row.Key] {
			if err := putRecord(ctx, memory, "segment", row.Key, row.Key, row.Value); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, id := range ids {
		path := filepath.Join(dir, "coverage180-raw-"+id+".json")
		var header struct {
			Revision int64 `json:"revision_watermark"`
			Count    int   `json:"count"`
		}
		coverageReadJSON(t, path, &header)
		var hits []store.Hit
		if err := json.Unmarshal(coverageUnpack(t, path), &hits); err != nil {
			t.Fatal(err)
		}
		if len(hits) != header.Count {
			t.Fatal("archive count mismatch")
		}
		for _, hit := range hits {
			archive.revisions[hit.ID] = header.Revision
		}
		archive.hits = append(archive.hits, hits...)
	}
	sort.Slice(archive.hits, func(i, j int) bool {
		a, b := archive.hits[i], archive.hits[j]
		if a.OccurredAt.Equal(b.OccurredAt) {
			return a.ID < b.ID
		}
		return a.OccurredAt.Before(b.OccurredAt)
	})
	reader := temporalArchiveReader{EvidenceReader: memory, archive: archive}
	rows := []map[string]any{}
	for _, id := range ids {
		bundle, audit, err := PrepareEvidenceFromPlatform(ctx, reader, id, providerTestOptions(t))
		if err != nil {
			t.Fatal(id, err)
		}
		result, err := ExecutePreparedEvidence(ctx, bundle, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
		if err != nil {
			t.Fatal(id, err)
		}
		facts := []evidence.Finding{}
		for _, fact := range result.Evaluation.Result.Findings {
			if fact.FactID == "F_BEACON_JITTER" || fact.FactID == "F_FIXED_DAILY_WINDOW" || fact.FactID == evidence.MultiDayPersist {
				facts = append(facts, fact)
			}
		}
		row := map[string]any{"event_id": id, "loaded_hits": bundle.Inputs.Manifest.LoadedHits, "contacts": len(bundle.Inputs.Manifest.PhaseOne.Contacts), "observations": len(bundle.Inputs.Observations), "wire_decodes": bundle.Inputs.Manifest.WireFrameDecodeCount, "history_rows": len(bundle.History.Rows), "findings": facts, "valid": audit.Valid, "archive_scope": "two archived events only; no claim of complete platform history"}
		row["temporal_window_coverage"] = bundle.Inputs.Manifest.PhaseOne.TemporalWindowCoverage
		reasons := map[string]int{}
		for _, values := range bundle.Inputs.Manifest.PhaseOne.ScopeIncomplete {
			for _, reason := range values {
				reasons[reason]++
			}
		}
		row["scope_incomplete_reasons"] = reasons
		rows = append(rows, row)
		t.Logf("%s: hits=%d contacts=%d observations=%d", id, bundle.Inputs.Manifest.LoadedHits, len(bundle.Inputs.Manifest.PhaseOne.Contacts), len(bundle.Inputs.Observations))
	}
	if path := os.Getenv("PROVIDER_TEMPORAL_ARCHIVE_OUTPUT"); path != "" {
		raw, _ := json.MarshalIndent(map[string]any{"read_only": true, "model_called": false, "events": rows}, "", "  ")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
