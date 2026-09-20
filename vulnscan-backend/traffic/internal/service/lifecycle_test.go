package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func seedLifecycle(t *testing.T, st store.Store, id string, last time.Time, closed bool) map[string]any {
	t.Helper()
	ly := map[string]any{"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "event_type": "scan", "time": last.Format(time.RFC3339Nano), "bytes": 10}
	e := LyEventToDeepSOC(ly)
	e.EventID, e.AggregationClosed, e.AnalysisVersion = id, closed, 2
	if _, err := st.CreateEvent(e); err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(ly)
	st.ReserveFingerprint(fp)
	st.BindEventMap(fp, "source", id)
	return ly
}

func TestAttackLifecycleBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		gap   time.Duration
		merge bool
	}{
		{"below-window", 30*time.Minute - time.Microsecond, true},
		{"exact-window", 30 * time.Minute, false},
		{"after-window", 31 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := Services{Store: store.NewMemoryStore()}
			base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
			a := ingestTestHit(t, svc, "a", base)
			b := ingestTestHit(t, svc, "b", base.Add(tc.gap))
			if (a == b) != tc.merge {
				t.Fatalf("event-time boundary: %s %s", a, b)
			}
			if err := svc.DrainAggregation(context.Background(), 20); err != nil {
				t.Fatal(err)
			}
			snap, err := svc.EvidenceSnapshot(context.Background(), a, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(1)
			if tc.merge {
				want = 2
			}
			if snap.Count != want {
				t.Fatalf("count=%d", snap.Count)
			}
		})
	}
}

func TestArchivedLifecycleAndHistoricalAnalysis(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	last := time.Now().UTC().Add(-48 * time.Hour)
	ly := seedLifecycle(t, st, "archived", last, true)
	st.UpdateEvent("archived", map[string]any{"archive_date": "2026-09-12"})
	before, _ := st.GetEvent("archived")
	ly["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	ly["device_id"], ly["event_id"] = "test-node", "new-hit"
	res, err := svc.ProcessLyEvent(context.Background(), ly)
	if err != nil {
		t.Fatal(err)
	}
	latest := asString(res["deepsoc_event_id"])
	ly["analysis_only"], ly["event_id"] = true, "archived"
	res, err = svc.ProcessLyEvent(context.Background(), ly)
	if err != nil || res["deepsoc_event_id"] != "archived" {
		t.Fatalf("analysis targeted latest lifecycle: %v %v", res, err)
	}
	after, _ := st.GetEvent("archived")
	if after.Context != before.Context || after.ArchiveDate == nil || !after.ArchiveDate.Equal(*before.ArchiveDate) {
		t.Fatal("archived data changed")
	}
	if err := svc.DrainAggregation(context.Background(), 20); err != nil {
		t.Fatal(err)
	}
	fresh, _ := st.GetEvent(latest)
	if toInt(decodeEventContext(fresh.Context)["occurrence_count"]) != 1 {
		t.Fatal("analysis counted as a hit")
	}
	ly["event_id"] = "missing"
	if _, err = svc.ProcessLyEvent(context.Background(), ly); err == nil {
		t.Fatal("missing analysis target created an event")
	}
	if len(st.ListEvents()) != 2 {
		t.Fatal("unexpected extra events")
	}
}

func TestConcurrentIngestionAndScanner(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	seedLifecycle(t, st, "old-concurrent", time.Now().UTC().Add(-time.Hour), false)
	const hits = 24
	var wg sync.WaitGroup
	results := make(chan string, hits)
	for i := 0; i < hits; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ly := map[string]any{"event_id": fmt.Sprint(i), "device_id": "test-node", "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "event_type": "scan", "time": time.Now().UTC().Format(time.RFC3339Nano)}
			res, err := svc.ProcessLyEvent(context.Background(), ly)
			if err != nil {
				t.Error(err)
				return
			}
			results <- asString(res["deepsoc_event_id"])
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := svc.ScanConverged(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	close(results)
	id := ""
	for got := range results {
		if id != "" && id != got {
			t.Fatal("concurrent hits split into multiple new lifecycles")
		}
		id = got
	}
	if len(st.ListEvents()) != 2 {
		t.Fatalf("events=%d", len(st.ListEvents()))
	}
	if err := svc.DrainAggregation(context.Background(), 20); err != nil {
		t.Fatal(err)
	}
	fresh, _ := st.GetEvent(id)
	old, _ := st.GetEvent("old-concurrent")
	if toInt(decodeEventContext(fresh.Context)["occurrence_count"]) != hits || !old.AggregationClosed || fresh.AggregationClosed {
		t.Fatal("lost hits or invalid lifecycle state")
	}
}

func TestOutOfOrderHitKeepsLatestActivity(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	last := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	id := ingestTestHit(t, svc, "first", last)
	other := ingestTestHit(t, svc, "older", last.Add(-time.Minute))
	if id != other {
		t.Fatal("late hit split")
	}
	if err := svc.DrainAggregation(context.Background(), 20); err != nil {
		t.Fatal(err)
	}
	e, _ := svc.Store.GetEvent(id)
	if !domain.LastActivity(e).Equal(last) {
		t.Fatal("last activity moved backwards")
	}
}

type failCreateStore struct {
	store.Store
	fail bool
}

func (s *failCreateStore) CreateEvent(e domain.Event) (domain.Event, error) {
	if s.fail {
		s.fail = false
		return domain.Event{}, errors.New("test create failure")
	}
	return s.Store.CreateEvent(e)
}
func (s *failCreateStore) AggregationTransaction(ctx context.Context, key string, fn func(store.Store) error) error {
	return s.Store.AggregationTransaction(ctx, key, func(tx store.Store) error {
		wrapper := &failCreateStore{Store: tx, fail: s.fail}
		err := fn(wrapper)
		s.fail = wrapper.fail
		return err
	})
}
func TestFailedCreationDoesNotPoisonFingerprint(t *testing.T) {
	st := &failCreateStore{Store: store.NewMemoryStore(), fail: true}
	svc := Services{Store: st}
	ly := testHit("failure", time.Now().UTC().Add(-time.Minute))
	if _, err := svc.ProcessLyEvent(context.Background(), ly); err == nil {
		t.Fatal("expected create failure")
	}
	res, err := svc.ProcessLyEvent(context.Background(), ly)
	if err != nil || asString(res["deepsoc_event_id"]) == "" || len(st.ListEvents()) != 1 {
		t.Fatalf("retry failed: %v %v", res, err)
	}
}
