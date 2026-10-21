package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SnapshotPageReader bounds base+effective revision bytes BEFORE reading JSON;
// Implementations preserve immutable membership and never skip an oversized row.
type SnapshotPageReader interface {
	SnapshotPage(context.Context, HitQuery, int64, int64, int64) ([]Hit, error)
}

func (s *MySQLStore) SnapshotPage(ctx context.Context, q HitQuery, rw, pageBytes, rowBytes int64) ([]Hit, error) {
	if len(q.Sources) == 0 {
		return []Hit{}, nil
	}
	if pageBytes < 1 || rowBytes < 1 {
		return nil, fmt.Errorf("invalid_snapshot_page_budget")
	}
	if q.Limit < 1 || q.Limit > 500 {
		q.Limit = 200
	}
	where := "h.origin_event_id IN (" + strings.TrimRight(strings.Repeat("?,", len(q.Sources)), ",") + ") AND h.sequence<=?"
	args := []any{rw}
	for _, id := range q.Sources {
		args = append(args, id)
	}
	args = append(args, q.Watermark)
	if !q.From.IsZero() {
		where += " AND h.occurred_at>=?"
		args = append(args, mysqlHitWindowBound(q.From))
	}
	if !q.To.IsZero() {
		where += " AND h.occurred_at<?"
		args = append(args, mysqlHitWindowBound(q.To))
	}
	if !q.AfterTime.IsZero() {
		where += " AND (h.occurred_at>? OR (h.occurred_at=? AND h.hit_id>?))"
		args = append(args, q.AfterTime, q.AfterTime, q.AfterID)
	}
	if q.ID != "" {
		where += " AND h.hit_id=?"
		args = append(args, q.ID)
	}
	args = append(args, q.Limit)
	query := `SELECT h.hit_id,OCTET_LENGTH(h.raw_json),COALESCE((SELECT OCTET_LENGTH(r.raw_json) FROM traffic_hit_revisions r WHERE r.hit_id=h.hit_id AND r.sequence<=? ORDER BY r.source_revision DESC LIMIT 1),0) FROM traffic_event_hits h WHERE ` + where + ` ORDER BY h.occurred_at,h.hit_id LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	var total int64
	for rows.Next() {
		var id string
		var base, rev int64
		if err = rows.Scan(&id, &base, &rev); err != nil {
			rows.Close()
			return nil, err
		}
		cost := base + rev
		if cost > rowBytes || cost > pageBytes {
			if len(ids) == 0 {
				rows.Close()
				return nil, fmt.Errorf("snapshot_row_budget_exceeded:%s", id)
			}
			break
		}
		if total+cost > pageBytes {
			break
		}
		total += cost
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []Hit{}, nil
	}
	q.Limit = len(ids)
	page, err := s.HitPage(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(page) != len(ids) {
		return nil, fmt.Errorf("snapshot_page_membership_changed")
	}
	var revisions map[string]json.RawMessage
	if rw > 0 {
		revisions, err = s.HitRevisions(ctx, ids, rw)
		if err != nil {
			return nil, err
		}
	}
	total = 0
	for i := range page {
		if page[i].ID != ids[i] {
			return nil, fmt.Errorf("snapshot_page_membership_changed")
		}
		cost := int64(len(page[i].Raw))
		if raw, ok := revisions[page[i].ID]; ok {
			cost += int64(len(raw))
			page[i].Raw = raw
		}
		total += cost
		if cost > rowBytes || total > pageBytes {
			return nil, fmt.Errorf("snapshot_page_byte_binding_changed")
		}
	}
	return page, nil
}
