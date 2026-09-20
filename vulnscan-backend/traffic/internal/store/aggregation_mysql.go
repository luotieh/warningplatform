package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

func (s *MySQLStore) LockAggregationKey(ctx context.Context, key string) error {
	if _, ok := s.db.(*sql.Tx); !ok {
		return errors.New("aggregation lock requires transaction")
	}
	if _, err := s.db.ExecContext(ctx, "INSERT INTO traffic_aggregation_locks(lock_key) VALUES (?) ON DUPLICATE KEY UPDATE lock_key=VALUES(lock_key)", key); err != nil {
		return err
	}
	var locked string
	return s.db.QueryRowContext(ctx, "SELECT lock_key FROM traffic_aggregation_locks WHERE lock_key=? FOR UPDATE", key).Scan(&locked)
}

func (s *MySQLStore) AggregationTransaction(ctx context.Context, key string, fn func(Store) error) error {
	db, ok := s.db.(*sql.DB)
	if !ok {
		return errors.New("nested aggregation transaction")
	}
	for attempt := 0; attempt < 3; attempt++ {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO traffic_aggregation_locks(lock_key) VALUES (?) ON DUPLICATE KEY UPDATE lock_key=VALUES(lock_key)", key)
		if err == nil {
			var locked string
			err = tx.QueryRowContext(ctx, "SELECT lock_key FROM traffic_aggregation_locks WHERE lock_key=? FOR UPDATE", key).Scan(&locked)
		}
		if err == nil {
			err = fn(&MySQLStore{db: tx})
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		var me *mysql.MySQLError
		if !errors.As(err, &me) || (me.Number != 1213 && me.Number != 1205) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 20 * time.Millisecond):
		}
	}
	return errors.New("aggregation transaction retry limit")
}

func (s *MySQLStore) AggregateRecord(ctx context.Context, kind, key string) (AggregateRecord, bool, error) {
	r := AggregateRecord{Kind: kind, Key: key}
	query := "SELECT group_key,value_json FROM traffic_aggregation_records WHERE kind=? AND record_key=?"
	if _, ok := s.db.(*sql.Tx); ok {
		query += " FOR UPDATE"
	}
	err := s.db.QueryRowContext(ctx, query, kind, key).Scan(&r.Group, &r.Value)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}
func (s *MySQLStore) PutAggregateRecord(ctx context.Context, r AggregateRecord) error {
	// Snapshots and revision journals are immutable, even on worker retries.
	query := "INSERT INTO traffic_aggregation_records(kind,record_key,group_key,value_json) VALUES (?,?,?,?)"
	if r.Kind != "snapshot" && r.Kind != "revision" {
		query += " ON DUPLICATE KEY UPDATE group_key=VALUES(group_key),value_json=VALUES(value_json)"
	}
	_, err := s.db.ExecContext(ctx, query, r.Kind, r.Key, r.Group, string(r.Value))
	return err
}
func (s *MySQLStore) AggregateRecords(ctx context.Context, kind, group string, limit int) ([]AggregateRecord, error) {
	q := "SELECT record_key,group_key,value_json FROM traffic_aggregation_records WHERE kind=?"
	args := []any{kind}
	if group != "" {
		q += " AND group_key=?"
		args = append(args, group)
	}
	if kind == "outbox" || kind == "analysis_outbox" {
		q += " ORDER BY COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(value_json, '$.last_attempt')) AS UNSIGNED),0), record_key"
	} else {
		q += " ORDER BY record_key"
	}
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AggregateRecord{}
	for rows.Next() {
		r := AggregateRecord{Kind: kind}
		if err = rows.Scan(&r.Key, &r.Group, &r.Value); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const hitColumns = "sequence,hit_id,dedup_key,identity_digest,aggregate_key,origin_event_id,occurred_at,received_at,raw_json"

func (s *MySQLStore) InsertHitRevision(ctx context.Context, id string, revision int64, raw json.RawMessage) (int64, error) {
	r, err := s.db.ExecContext(ctx, "INSERT INTO traffic_hit_revisions(hit_id,source_revision,raw_json) VALUES (?,?,?)", id, revision, string(raw))
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}
func (s *MySQLStore) HitRevision(ctx context.Context, id string, watermark int64) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.db.QueryRowContext(ctx, "SELECT raw_json FROM traffic_hit_revisions WHERE hit_id=? AND sequence<=? ORDER BY source_revision DESC LIMIT 1", id, watermark).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func scanHit(row interface{ Scan(...any) error }) (h Hit, err error) {
	err = row.Scan(&h.Sequence, &h.ID, &h.DedupKey, &h.Identity, &h.AggregateKey, &h.EventID, &h.OccurredAt, &h.ReceivedAt, &h.Raw)
	return
}
func (s *MySQLStore) FindHit(ctx context.Context, key string) (Hit, bool, error) {
	h, err := scanHit(s.db.QueryRowContext(ctx, "SELECT "+hitColumns+" FROM traffic_event_hits WHERE dedup_key=?", key))
	if errors.Is(err, sql.ErrNoRows) {
		return h, false, nil
	}
	return h, err == nil, err
}
func (s *MySQLStore) InsertHit(ctx context.Context, h Hit) (Hit, error) {
	r, err := s.db.ExecContext(ctx, `INSERT INTO traffic_event_hits(hit_id,dedup_key,identity_digest,aggregate_key,origin_event_id,occurred_at,received_at,raw_json) VALUES (?,?,?,?,?,?,?,?)`, h.ID, h.DedupKey, h.Identity, h.AggregateKey, h.EventID, h.OccurredAt, h.ReceivedAt, string(h.Raw))
	if err != nil {
		return h, err
	}
	h.Sequence, err = r.LastInsertId()
	return h, err
}
func (s *MySQLStore) HitPage(ctx context.Context, q HitQuery) ([]Hit, error) {
	if len(q.Sources) == 0 {
		return []Hit{}, nil
	}
	if q.Limit < 1 || q.Limit > 500 {
		q.Limit = 200
	}
	query := "SELECT " + hitColumns + " FROM traffic_event_hits WHERE origin_event_id IN (" + strings.TrimRight(strings.Repeat("?,", len(q.Sources)), ",") + ") AND sequence<=?"
	args := []any{}
	for _, id := range q.Sources {
		args = append(args, id)
	}
	args = append(args, q.Watermark)
	if !q.From.IsZero() {
		query += " AND occurred_at>=?"
		args = append(args, q.From)
	}
	if !q.To.IsZero() {
		query += " AND occurred_at<?"
		args = append(args, q.To)
	}
	if !q.AfterTime.IsZero() {
		query += " AND (occurred_at>? OR (occurred_at=? AND hit_id>?))"
		args = append(args, q.AfterTime, q.AfterTime, q.AfterID)
	}
	if q.ID != "" {
		query += " AND hit_id=?"
		args = append(args, q.ID)
	}
	query += " ORDER BY occurred_at,hit_id LIMIT ?"
	args = append(args, q.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query hits: %w", err)
	}
	defer rows.Close()
	out := []Hit{}
	for rows.Next() {
		h, err := scanHit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
