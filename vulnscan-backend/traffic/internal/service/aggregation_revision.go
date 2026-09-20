package service

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"vulnscan-backend/traffic/internal/store"
)

func (s Services) acceptHitRevision(ctx context.Context, tx store.Store, old, incoming store.Hit, m map[string]any, id string) (string, error) {
	revision := int64(toInt(m["context_revision"]))
	if revision == 0 {
		return "", nil
	}
	base := map[string]any{}
	_ = json.Unmarshal(old.Raw, &base)
	latest, err := tx.HitRevision(ctx, old.ID, math.MaxInt64)
	if err != nil {
		return "", err
	}
	if latest != nil {
		_ = json.Unmarshal(latest, &base)
	}
	previous := int64(toInt(base["context_revision"]))
	if revision == previous {
		enrichment := func(x map[string]any) string {
			rp := nestedMap(x, "raw_packet")
			return digest([]any{x["exchange"], x["session_summary"], x["context_final"], rp["request"], rp["response"]})
		}
		if enrichment(base) != enrichment(m) {
			key := digest([]any{old.ID, revision, enrichment(m)})
			err := putRecord(ctx, tx, "receipt", key, "conflict", map[string]any{"status": "evidence_revision_conflict", "hit_id": old.ID, "raw": m})
			return "evidence_revision_conflict", err
		}
	}
	if revision <= previous {
		return "", nil
	}
	seg, ok, err := readSegment(ctx, tx, id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("revision segment missing")
	}
	if err = tx.LockAggregationKey(ctx, "group-"+seg.AggregateKey); err != nil {
		return "", err
	}
	seg, ok, err = readSegment(ctx, tx, id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("revision segment missing")
	}
	if seg.CanonicalID != id {
		seg, ok, err = readSegment(ctx, tx, seg.CanonicalID)
		if err != nil || !ok {
			return "", errors.New("canonical revision segment missing")
		}
		id = seg.EventID
	}
	if seg.Disabled {
		key := digest([]any{old.ID, revision, "disabled"})
		err := putRecord(ctx, tx, "receipt", key, "pending", map[string]any{"status": "pending_verification", "reason": "historical_repair_rolled_back", "hit_id": old.ID, "raw": m})
		return "pending_verification", err
	}
	sequence, err := tx.InsertHitRevision(ctx, old.ID, revision, incoming.Raw)
	if err != nil {
		return "", err
	}
	seg.Version++
	seg.RevisionWatermark = sequence
	if err = putRecord(ctx, tx, "segment", id, seg.AggregateKey, seg); err != nil {
		return "", err
	}
	ev, ok := tx.GetEvent(id)
	if !ok {
		return "", errors.New("revision event missing")
	}
	c := decodeEventContext(ev.Context)
	c["data_version"] = seg.Version
	c["report_stale"] = true
	c["statistics_quality"] = "rebuilding"
	b, _ := json.Marshal(c)
	if _, ok = tx.UpdateEvent(id, map[string]any{"context": string(b)}); !ok {
		return "", errors.New("save revision failed")
	}
	if err = putRecord(ctx, tx, "outbox", id, "pending", map[string]any{"event_id": id, "data_version": seg.Version}); err != nil {
		return "", err
	}
	return "evidence_updated", nil
}
