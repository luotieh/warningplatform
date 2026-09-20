package service

import (
	"context"
	"encoding/json"
	"vulnscan-backend/traffic/internal/store"
)

func (s Services) HitEvidenceFiles(ctx context.Context, id, hitID string) ([]any, error) {
	snap, err := s.EvidenceSnapshot(ctx, id, 0)
	if err != nil {
		return nil, err
	}
	q := store.HitQuery{Sources: snap.Sources, Watermark: snap.Watermark, ID: hitID, Limit: 500}
	files := []any{}
	seen := map[string]bool{}
	index := 0
	for {
		page, err := s.Store.HitPage(ctx, q)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for _, h := range page {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if snap.RevisionWatermark > 0 {
				raw, err := s.Store.HitRevision(ctx, h.ID, snap.RevisionWatermark)
				if err != nil {
					return nil, err
				}
				if raw != nil {
					h.Raw = raw
				}
			}
			m := map[string]any{}
			if err = json.Unmarshal(h.Raw, &m); err != nil {
				return nil, err
			}
			for _, file := range normalizeEvidenceFiles(m, index, h.OccurredAt.Format("2006-01-02T15:04:05.999999Z07:00")) {
				entry, _ := file.(map[string]any)
				key := asString(entry["device_id"]) + ":" + evidenceDedupKey(entry)
				if !seen[key] {
					files = append(files, file)
					seen[key] = true
				}
			}
			index++
		}
		if hitID != "" {
			break
		}
		tail := page[len(page)-1]
		q.AfterTime = tail.OccurredAt
		q.AfterID = tail.ID
	}
	return files, nil
}
