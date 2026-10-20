package store

// This read surface deliberately excludes every Store mutation. It is used by
// the independent provider, never by ingestion or report refresh.
import (
	"context"
	"database/sql"
	"fmt"
	"vulnscan-backend/traffic/internal/domain"
)

type EvidenceReader interface {
	EvidenceEvent(context.Context, string) (domain.Event, bool, error)
	EvidenceAssets(context.Context, int) ([]domain.Asset, error)
	AggregateRecord(context.Context, string, string) (AggregateRecord, bool, error)
	HistoryCandidates(context.Context, HistoryQuery) ([]domain.Event, error)
	SnapshotPageReader
}

// NewEvidenceReadTransaction takes a repeatable, read-only database view. The
// caller must Rollback; no migration, seed, application initialization or commit.
func NewEvidenceReadTransaction(ctx context.Context, db *sql.DB) (EvidenceReader, func() error, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, nil, err
	}
	return &MySQLStore{db: txDB{tx}}, tx.Rollback, nil
}

// Hide *sql.Tx from legacy GetEvent's FOR UPDATE behavior. Only the narrow
// EvidenceReader escapes this package.
type txDB struct{ *sql.Tx }

func (s *MySQLStore) EvidenceEvent(ctx context.Context, id string) (domain.Event, bool, error) {
	e, err := scanEvent(s.db.QueryRowContext(ctx, "SELECT "+eventSelectCols+" FROM events WHERE event_id=?", id))
	if err == sql.ErrNoRows {
		return e, false, nil
	}
	return e, err == nil, err
}
func (s *MemoryStore) EvidenceEvent(ctx context.Context, id string) (domain.Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Event{}, false, err
	}
	e, ok := s.GetEvent(id)
	return e, ok, ctx.Err()
}
func (s *MySQLStore) EvidenceAssets(ctx context.Context, limit int) ([]domain.Asset, error) {
	if limit < 1 || limit > 4096 {
		return nil, fmt.Errorf("asset_budget_invalid")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,asset_type,address,unit,owner,status,remark,created_at,updated_at FROM traffic_assets ORDER BY id LIMIT ?`, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Asset{}
	for rows.Next() {
		a, e := scanAsset(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("asset_registry_budget_exceeded")
	}
	return out, nil
}
func (s *MemoryStore) EvidenceAssets(ctx context.Context, limit int) ([]domain.Asset, error) {
	if limit < 1 || limit > 4096 {
		return nil, fmt.Errorf("asset_budget_invalid")
	}
	a, err := s.ListAssetsContext(ctx)
	if len(a) > limit {
		return nil, fmt.Errorf("asset_registry_budget_exceeded")
	}
	return a, err
}

var _ EvidenceReader = (*MemoryStore)(nil)
var _ EvidenceReader = (*MySQLStore)(nil)

func (s *MemoryStore) SnapshotPage(ctx context.Context, q HitQuery, rw, pageBytes, rowBytes int64) ([]Hit, error) {
	if pageBytes < 1 || rowBytes < 1 {
		return nil, fmt.Errorf("invalid_snapshot_page_budget")
	}
	rows, err := s.HitPage(ctx, q)
	if err != nil {
		return nil, err
	}
	out := []Hit{}
	var total int64
	for _, h := range rows {
		rev, e := s.HitRevision(ctx, h.ID, rw)
		if e != nil {
			return nil, e
		}
		cost := int64(len(h.Raw) + len(rev))
		if cost > rowBytes || cost > pageBytes {
			if len(out) == 0 {
				return nil, fmt.Errorf("snapshot_row_budget_exceeded")
			}
			break
		}
		if total+cost > pageBytes {
			break
		}
		if len(rev) > 0 {
			h.Raw = rev
		}
		total += cost
		out = append(out, h)
	}
	return out, ctx.Err()
}
