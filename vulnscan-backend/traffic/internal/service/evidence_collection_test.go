package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Simulates a platform connection that is closed immediately after collection.
// Raw fields include an integer above float64's exact range and formatted JSON.
type collectionTestReader struct {
	store.EvidenceReader
	closed   bool
	calls    int
	returned map[string][]byte
}

func (r *collectionTestReader) check() error {
	r.calls++
	if r.closed {
		return errors.New("platform disconnected after collection")
	}
	return nil
}
func (r *collectionTestReader) EvidenceEvent(ctx context.Context, id string) (domain.Event, bool, error) {
	if err := r.check(); err != nil {
		return domain.Event{}, false, err
	}
	return r.EvidenceReader.EvidenceEvent(ctx, id)
}
func (r *collectionTestReader) EvidenceAssets(ctx context.Context, n int) ([]domain.Asset, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return r.EvidenceReader.EvidenceAssets(ctx, n)
}
func (r *collectionTestReader) AggregateRecord(ctx context.Context, kind, key string) (store.AggregateRecord, bool, error) {
	if err := r.check(); err != nil {
		return store.AggregateRecord{}, false, err
	}
	return r.EvidenceReader.AggregateRecord(ctx, kind, key)
}
func (r *collectionTestReader) HistoryCandidates(ctx context.Context, q store.HistoryQuery) ([]domain.Event, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return r.EvidenceReader.HistoryCandidates(ctx, q)
}
func (r *collectionTestReader) SnapshotPage(ctx context.Context, q store.HitQuery, rw, pb, rb int64) ([]store.Hit, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	hits, err := r.EvidenceReader.SnapshotPage(ctx, q, rw, pb, rb)
	for i := range hits {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(hits[i].Raw, &fields); err != nil {
			return nil, err
		}
		fields["raw_packet"] = json.RawMessage(`{"packet_hex":"abcdef","tcp_seq":18446744073709551615,"capture_truncated":true}`)
		fields["exchange"] = json.RawMessage(`{"request":{"reassembled_text":"GET /a?x=1&y=2 HTTP/1.1\r\n"}}`)
		hits[i].Raw, _ = json.MarshalIndent(fields, "", "  ")
		r.returned[hits[i].ID] = append([]byte(nil), hits[i].Raw...)
	}
	return hits, err
}

func TestEvidenceCollectionOfflineReplayAndRawPreservation(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	providerTestEvent(t, s, "peer", "peer-asset", "192.0.2.11", "peer-sensor", at)
	prior := at.Add(-24 * time.Hour)
	current, _ := s.GetEvent("current")
	contextFields := decodeEventContext(current.Context)
	contextFields["first_time"], contextFields["last_time"] = prior.Format(time.RFC3339), prior.Format(time.RFC3339)
	raw, _ := json.Marshal(contextFields)
	if _, err := s.CreateEvent(domain.Event{EventID: "history", Context: string(raw), CreatedAt: prior, LastSeenAt: &prior}); err != nil {
		t.Fatal(err)
	}
	reader := &collectionTestReader{EvidenceReader: s, returned: map[string][]byte{}}
	options := providerTestOptions(t)
	collection, err := CollectEvidenceFromPlatform(ctx, reader, "current", options)
	if err != nil {
		t.Fatal(err)
	}
	if err = collection.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(collection.Peers) != 1 || len(collection.HistoryCandidates) != 1 || len(collection.HistorySnapshots) != 0 {
		t.Fatal("cross-event collection missing")
	}
	for _, hit := range append(append([]CollectedHit(nil), collection.Hits...), collection.Peers[0].Hits...) {
		if !bytes.Equal(hit.Raw, reader.returned[hit.ID]) {
			t.Fatalf("raw source bytes changed: %s", hit.ID)
		}
		if !bytes.Contains(hit.Raw, []byte("18446744073709551615")) {
			t.Fatal("integer precision lost")
		}
	}
	before := digest(collection)
	reader.closed = true
	calls := reader.calls
	bundle, audit, err := PreprocessCollectedEvidence(ctx, collection)
	if err != nil || !audit.Valid {
		t.Fatal("offline preprocessing failed", err)
	}
	if calls != reader.calls || digest(collection) != before {
		t.Fatal("preprocessor read platform or mutated collection")
	}
	if len(bundle.Inputs.Request.Groups) != 1 || len(bundle.History.Rows) != 1 {
		t.Fatal("offline peer/history assembly lost")
	}
	encoded, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}
	var replay EvidenceCollection
	if err = json.Unmarshal(encoded, &replay); err != nil {
		t.Fatal(err)
	}
	replayed, _, err := PreprocessCollectedEvidence(ctx, replay)
	if err != nil || replayed.InputDigest != bundle.InputDigest {
		t.Fatal("serialized collection replay differs", err)
	}
	// Caller changes to the result/options must not affect the frozen source.
	bundle.Assets[0].Address = "changed"
	options.Contracts[0].ID = "changed"
	if digest(collection) != before {
		t.Fatal("source aliases result or caller options")
	}
	reader.closed = false
	facade, _, err := PrepareEvidenceFromPlatform(ctx, reader, "current", providerTestOptions(t))
	if err != nil || facade.InputDigest != replayed.InputDigest {
		t.Fatal("facade differs from explicit layers", err)
	}
}

func TestEvidenceCollectionDefersContextValidationToPreprocessing(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	source := json.RawMessage(`{"unexpected":"source-registry"}`)
	extra := json.RawMessage(`{"event_id":"current","snapshot_version":1,"version":"extra"}`)
	for _, record := range []store.AggregateRecord{{Kind: "evidence_sources", Key: "active", Value: source}, {Kind: "evidence_inputs", Key: snapshotKey("current", 1), Value: extra}} {
		if err := s.PutAggregateRecord(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	collection, err := CollectEvidenceFromPlatform(ctx, s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal("collection applied preprocessing validation", err)
	}
	if collection.SourceRegistry == nil || collection.Supplemental == nil || !bytes.Equal(collection.SourceRegistry.Value, source) || !bytes.Equal(collection.Supplemental.Value, extra) {
		t.Fatal("context records dropped or aliased")
	}
	before := digest(collection)
	_, audit, err := PreprocessCollectedEvidence(ctx, collection)
	if err == nil || audit.Queries[len(audit.Queries)-1].Status != "failed" || audit.Valid {
		t.Fatal("untrusted context accepted")
	}
	if digest(collection) != before {
		t.Fatal("failed preprocessing mutated collection")
	}
}

func TestEvidenceCollectionRejectsChangesAndCancelledReplay(t *testing.T) {
	s := store.NewMemoryStore()
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC))
	collection, err := CollectEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = PreprocessCollectedEvidence(ctx, collection); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	collection.Snapshot.Version++
	if _, _, err = PreprocessCollectedEvidence(context.Background(), collection); err == nil || !strings.Contains(err.Error(), "collection_digest") {
		t.Fatal("modified source accepted", err)
	}
}
