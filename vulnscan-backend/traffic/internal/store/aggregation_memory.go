package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

func (s *MemoryStore) LockAggregationKey(ctx context.Context, _ string) error { return ctx.Err() }

func (s *MemoryStore) InsertHitRevision(ctx context.Context, id string, revision int64, raw json.RawMessage) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("hit_revision/%s:%d", id, revision)
	if _, ok := s.aggregateRecords[key]; ok {
		return 0, errors.New("duplicate source revision")
	}
	s.hitSeq++
	value, _ := json.Marshal(map[string]any{"sequence": s.hitSeq, "revision": revision, "raw": raw})
	s.aggregateRecords[key] = AggregateRecord{Kind: "hit_revision", Key: key, Group: id, Value: value}
	return s.hitSeq, ctx.Err()
}
func (s *MemoryStore) HitRevision(ctx context.Context, id string, watermark int64) (json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best int64 = -1
	var raw json.RawMessage
	for _, r := range s.aggregateRecords {
		if r.Kind != "hit_revision" || r.Group != id {
			continue
		}
		var v struct {
			Sequence int64
			Revision int64
			Raw      json.RawMessage
		}
		_ = json.Unmarshal(r.Value, &v)
		if v.Sequence <= watermark && v.Revision > best {
			best = v.Revision
			raw = v.Raw
		}
	}
	return raw, ctx.Err()
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		b, _ := json.Marshal(v)
		var copy V
		_ = json.Unmarshal(b, &copy)
		out[k] = copy
	}
	return out
}
func (s *MemoryStore) AggregationTransaction(ctx context.Context, _ string, fn func(Store) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx := NewMemoryStore()
	tx.events = cloneMap(s.events)
	tx.eventSeq = s.eventSeq
	tx.eventMaps = cloneMap(s.eventMaps)
	tx.aggregateRecords = cloneMap(s.aggregateRecords)
	tx.aggregateHits = cloneMap(s.aggregateHits)
	tx.hitSeq = s.hitSeq
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.events = tx.events
	s.eventSeq = tx.eventSeq
	s.eventMaps = tx.eventMaps
	s.aggregateRecords = tx.aggregateRecords
	s.aggregateHits = tx.aggregateHits
	s.hitSeq = tx.hitSeq
	return nil
}
func (s *MemoryStore) AggregateRecord(ctx context.Context, kind, key string) (AggregateRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.aggregateRecords[kind+"/"+key]
	r.Value = append([]byte(nil), r.Value...)
	return r, ok, ctx.Err()
}
func (s *MemoryStore) PutAggregateRecord(ctx context.Context, r AggregateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	key := r.Kind + "/" + r.Key
	if _, ok := s.aggregateRecords[key]; ok && (r.Kind == "snapshot" || r.Kind == "revision") {
		return errors.New("immutable aggregation record already exists")
	}
	r.Value = append([]byte(nil), r.Value...)
	s.aggregateRecords[key] = r
	return nil
}
func (s *MemoryStore) AggregateRecords(ctx context.Context, kind, group string, limit int) ([]AggregateRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []AggregateRecord{}
	for _, r := range s.aggregateRecords {
		if r.Kind == kind && (group == "" || r.Group == group) {
			r.Value = append([]byte(nil), r.Value...)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if kind == "outbox" || kind == "analysis_outbox" {
			var a, b struct {
				LastAttempt int64 `json:"last_attempt"`
			}
			_ = json.Unmarshal(out[i].Value, &a)
			_ = json.Unmarshal(out[j].Value, &b)
			if a.LastAttempt != b.LastAttempt {
				return a.LastAttempt < b.LastAttempt
			}
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, ctx.Err()
}
func (s *MemoryStore) FindHit(ctx context.Context, key string) (Hit, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.aggregateHits[key]
	h.Raw = append([]byte(nil), h.Raw...)
	return h, ok, ctx.Err()
}
func (s *MemoryStore) InsertHit(ctx context.Context, h Hit) (Hit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return h, err
	}
	if _, ok := s.aggregateHits[h.DedupKey]; ok {
		return h, errors.New("duplicate hit")
	}
	s.hitSeq++
	h.Sequence = s.hitSeq
	h.Raw = append([]byte(nil), h.Raw...)
	s.aggregateHits[h.DedupKey] = h
	return h, nil
}
func (s *MemoryStore) HitPage(ctx context.Context, q HitQuery) ([]Hit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := map[string]bool{}
	for _, id := range q.Sources {
		ids[id] = true
	}
	out := []Hit{}
	for _, h := range s.aggregateHits {
		if (!q.From.IsZero() && h.OccurredAt.Before(q.From)) || (!q.To.IsZero() && !h.OccurredAt.Before(q.To)) {
			continue
		}
		if !ids[h.EventID] || h.Sequence > q.Watermark || (q.ID != "" && h.ID != q.ID) {
			continue
		}
		if !q.AfterTime.IsZero() && (h.OccurredAt.Before(q.AfterTime) || (h.OccurredAt.Equal(q.AfterTime) && h.ID <= q.AfterID)) {
			continue
		}
		h.Raw = append([]byte(nil), h.Raw...)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	if q.Limit < 1 || q.Limit > 500 {
		q.Limit = 200
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, ctx.Err()
}
