package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type hookedHitStore struct {
	store.Store
	hook func(context.Context, store.HitQuery) error
}

func (s *hookedHitStore) HitPage(ctx context.Context, q store.HitQuery) ([]store.Hit, error) {
	if s.hook != nil {
		if err := s.hook(ctx, q); err != nil {
			return nil, err
		}
	}
	return s.Store.HitPage(ctx, q)
}

func TestSnapshotPublicationPreservesNewHits(t *testing.T) {
	st := &hookedHitStore{Store: store.NewMemoryStore()}
	svc := Services{Store: st}
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := now.Add(-31 * time.Minute)
	id := ingestTestHit(t, svc, "first", first)
	// Both gaps are below 30 min; new hit arrives during the older scan.
	ingestTestHit(t, svc, "second", now.Add(-20*time.Minute))
	st.hook = func(ctx context.Context, q store.HitQuery) error {
		st.hook = nil
		if got := ingestTestHit(t, svc, "third", now.Add(-time.Minute)); got != id {
			t.Fatal("split within quiet window")
		}
		return nil
	}
	if err := svc.RebuildAggregation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	ev := mustEvent(t, svc, id)
	c := decodeEventContext(ev.Context)
	if toInt(c["occurrence_count"]) != 3 || !domain.LastActivity(ev).Equal(now.Add(-time.Minute)) || domain.IsConverged(ev, now) {
		t.Fatal("old snapshot overwrote live membership", c)
	}
	if toInt(c["stats_version"]) != 2 || toInt(c["data_version"]) != 3 {
		t.Fatal("lost snapshot watermarks")
	}
	snap, err := svc.EvidenceSnapshot(context.Background(), id, 2)
	if err != nil || snap.Count != 2 {
		t.Fatal("immutable snapshot changed", err)
	}
	if err = svc.RebuildAggregation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if toInt(decodeEventContext(mustEvent(t, svc, id).Context)["stats_version"]) != 3 {
		t.Fatal("statistics did not catch up")
	}
}

func TestRebuildTimeoutDoesNotBlockOtherEvents(t *testing.T) {
	st := &hookedHitStore{Store: store.NewMemoryStore()}
	svc := Services{Store: st}
	at := time.Now().UTC().Add(-time.Minute)
	slow := ingestTestHit(t, svc, "slow", at)
	ingestTestHit(t, svc, "slow-second", at.Add(time.Second))
	m := testHit("fast", at)
	m["src_ip"] = "192.0.2.9"
	r, err := svc.ProcessLyEvent(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	fast := asString(r["deepsoc_event_id"])
	// Simulate an old stale list projection and a database query that times out.
	ev := mustEvent(t, svc, slow)
	c := decodeEventContext(ev.Context)
	c["occurrence_count"] = 1
	delete(c, "hit_count_current")
	b, _ := json.Marshal(c)
	st.UpdateEvent(slow, map[string]any{"context": string(b)})
	st.hook = func(ctx context.Context, q store.HitQuery) error {
		if len(q.Sources) > 0 && q.Sources[0] == slow {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	err = svc.drainAggregation(context.Background(), 20, 10*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("missing timeout", err)
	}
	seg, _, _ := readSegment(context.Background(), st, fast)
	if seg.Published != seg.Version {
		t.Fatal("other event blocked")
	}
	c = decodeEventContext(mustEvent(t, svc, slow).Context)
	if toInt(c["occurrence_count"]) != 2 {
		t.Fatal("stale count was not repaired")
	}
	task, ok, err := st.AggregateRecord(context.Background(), "outbox", slow)
	if err != nil || !ok {
		t.Fatal(err)
	}
	var retry map[string]any
	_ = json.Unmarshal(task.Value, &retry)
	if asString(retry["last_error"]) == "" || toInt(retry["failed_attempts"]) != 1 {
		t.Fatal("failure not recorded", retry)
	}
	eligible, err := st.AggregateRecords(context.Background(), "outbox", "pending", 20)
	if err != nil || len(eligible) != 0 {
		t.Fatal("failed task not delayed", err)
	}
	// Once the dependency recovers and the retry is due, catch up successfully.
	st.hook = func(ctx context.Context, q store.HitQuery) error {
		if len(q.Sources) > 0 && q.Sources[0] == slow {
			select {
			case <-time.After(15 * time.Millisecond):
				st.hook = nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	retry["retry_not_before"] = time.Now().Add(-time.Second).UnixMilli()
	if err = putRecord(context.Background(), st, "outbox", slow, "pending", retry); err != nil {
		t.Fatal(err)
	}
	if err = svc.drainAggregation(context.Background(), 20, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	seg, _, _ = readSegment(context.Background(), st, slow)
	if seg.Published != seg.Version {
		t.Fatal("recovered event did not catch up")
	}
}
