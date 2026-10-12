package store

import (
	"context"
	"sort"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

// Bounded lookup; the periodic scheduler never scans archived events.
func (s *MySQLStore) ListPeriodicAnalysisDue(ctx context.Context, now time.Time) ([]domain.Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+eventSelectCols+` FROM events
WHERE aggregation_closed=0 AND archive_date IS NULL AND analysis_version>0
AND last_seen_at>? AND last_analysis_at<=? ORDER BY last_analysis_at,id LIMIT 500`, now.Add(-domain.ConvergenceIdleWindow), now.Add(-30*time.Minute))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *MemoryStore) ListPeriodicAnalysisDue(ctx context.Context, now time.Time) ([]domain.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []domain.Event{}
	for _, e := range s.events {
		if !e.AggregationClosed && e.ArchiveDate == nil && e.AnalysisVersion > 0 && e.LastAnalysisAt != nil && !e.LastAnalysisAt.After(now.Add(-30*time.Minute)) && domain.LastActivity(e).After(now.Add(-domain.ConvergenceIdleWindow)) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAnalysisAt.Before(*out[j].LastAnalysisAt) })
	if len(out) > 500 {
		out = out[:500]
	}
	return out, nil
}
