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
		name   string
		idle   time.Duration
		closed bool
		merge  bool
	}{
		{"within-29-minutes", 29 * time.Minute, false, true},
		{"exactly-30-minutes", 30 * time.Minute, false, false},
		{"scheduler-delayed", 31 * time.Minute, false, false},
		{"already-closed", time.Minute, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := store.NewMemoryStore()
			svc := Services{Store: st}
			last := time.Now().UTC().Add(-tc.idle)
			ly := seedLifecycle(t, st, "old-"+tc.name, last, tc.closed)
			before, _ := st.GetEvent("old-" + tc.name)
			ly["time"] = last.Add(tc.idle).Format(time.RFC3339Nano)
			ly["bytes"] = 20
			res, err := svc.ProcessLyEvent(context.Background(), ly)
			if err != nil {
				t.Fatal(err)
			}
			id := asString(res["deepsoc_event_id"])
			old, _ := st.GetEvent(before.EventID)
			if tc.merge {
				if id != old.EventID || toInt(decodeEventContext(old.Context)["occurrence_count"]) != 2 {
					t.Fatalf("not merged: %v", res)
				}
			} else {
				if id == old.EventID || !old.AggregationClosed {
					t.Fatalf("reused old lifecycle: %v", res)
				}
				oldCtx := decodeEventContext(old.Context)
				if toInt(oldCtx["occurrence_count"]) != 1 || quantStatsFromContext(oldCtx).TotalPayloadBytes != 10 {
					t.Fatal("old statistics contaminated")
				}
				if !tc.closed && !domain.ParseEventTime(oldCtx["converged_at"]).Equal(last) {
					t.Fatalf("convergence time is not last activity: %v", oldCtx["converged_at"])
				}
				fresh, _ := st.GetEvent(id)
				if toInt(decodeEventContext(fresh.Context)["occurrence_count"]) != 1 || fresh.AggregationClosed {
					t.Fatal("new lifecycle not initialized")
				}
				mapping, _ := st.GetEventMap(Fingerprint(ly))
				if mapping.DeepSOCEventID != id {
					t.Fatal("fingerprint not rebound")
				}
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
			ly := map[string]any{"id": fmt.Sprint(i), "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "event_type": "scan", "time": time.Now().UTC().Format(time.RFC3339Nano)}
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
	fresh, _ := st.GetEvent(id)
	old, _ := st.GetEvent("old-concurrent")
	if toInt(decodeEventContext(fresh.Context)["occurrence_count"]) != hits || !old.AggregationClosed || fresh.AggregationClosed {
		t.Fatal("lost hits or invalid lifecycle state")
	}
}

func TestOutOfOrderHitKeepsLatestActivity(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	last := time.Now().UTC().Add(-time.Minute)
	ly := seedLifecycle(t, st, "unordered", last, false)
	ly["time"] = last.Add(-time.Minute).In(domain.Beijing).Format("2006-01-02 15:04:05")
	if _, err := svc.ProcessLyEvent(context.Background(), ly); err != nil {
		t.Fatal(err)
	}
	e, _ := st.GetEvent("unordered")
	if !domain.LastActivity(e).Equal(last) {
		t.Fatalf("last activity moved: %v", domain.LastActivity(e))
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
func TestFailedCreationDoesNotPoisonFingerprint(t *testing.T) {
	st := &failCreateStore{Store: store.NewMemoryStore(), fail: true}
	svc := Services{Store: st}
	ly := map[string]any{"src_ip": "192.0.2.3", "dst_ip": "192.0.2.4", "event_type": "scan"}
	if _, err := svc.ProcessLyEvent(context.Background(), ly); err == nil {
		t.Fatal("expected create failure")
	}
	res, err := svc.ProcessLyEvent(context.Background(), ly)
	if err != nil || asString(res["deepsoc_event_id"]) == "" || len(st.ListEvents()) != 1 {
		t.Fatalf("retry failed: %v %v", res, err)
	}
}
