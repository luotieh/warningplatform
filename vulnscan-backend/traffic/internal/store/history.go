package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

// This bounded candidate query is shared by all report scopes. It does not
// fetch packets, messages or report bodies and does not use model similarity.
type HistoryQuery struct {
	Start, End time.Time
	ExcludeIDs []string
	Addresses  []string
	IOCs       []domain.IOC
	Limit      int
}

func historyQueryValid(q HistoryQuery) error {
	for _, ioc := range q.IOCs {
		if len(ioc.Value) > 2048 || len(ioc.Type) > 32 || ioc.Value == "" || ioc.Type == "" {
			return fmt.Errorf("history_query_invalid")
		}
	}
	if q.Start.IsZero() || !q.Start.Before(q.End) || q.Limit < 1 || q.Limit > 201 || len(q.Addresses) > 32 || len(q.IOCs) > 32 || len(q.ExcludeIDs) > 256 || len(q.Addresses)+len(q.IOCs) == 0 {
		return fmt.Errorf("history_query_invalid")
	}
	return nil
}
func historyCandidateTime(e domain.Event) time.Time {
	if e.LastSeenAt != nil {
		return *e.LastSeenAt
	}
	return e.CreatedAt
}
func historyCandidateMatches(e domain.Event, q HistoryQuery) bool {
	t := historyCandidateTime(e)
	if t.Before(q.Start) || !t.Before(q.End) {
		return false
	}
	for _, id := range q.ExcludeIDs {
		if e.EventID == id {
			return false
		}
	}
	var c map[string]any
	_ = json.Unmarshal([]byte(e.Context), &c)
	if canonical, ok := c["canonical_event_id"].(string); ok && canonical != "" && canonical != e.EventID {
		return false
	}
	for _, address := range q.Addresses {
		if c["src_ip"] == address || c["dst_ip"] == address {
			return true
		}
	}
	for _, ioc := range q.IOCs {
		for _, o := range e.Observables {
			if o.Value == ioc.Value && o.Type == ioc.Type {
				return true
			}
		}
		for _, key := range []string{"ioc", "ioc_evidence"} {
			if m, ok := c[key].(map[string]any); ok && m["ioc_value"] == ioc.Value && m["ioc_type"] == ioc.Type {
				return true
			}
		}
	}
	return false
}
func (s *MemoryStore) HistoryCandidates(ctx context.Context, q HistoryQuery) ([]domain.Event, error) {
	if err := historyQueryValid(q); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []domain.Event{}
	for _, e := range s.events {
		if historyCandidateMatches(e, q) {
			rows = append(rows, e)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := historyCandidateTime(rows[i]), historyCandidateTime(rows[j])
		if a.Equal(b) {
			return rows[i].EventID < rows[j].EventID
		}
		return a.After(b)
	})
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
	}
	for index := range rows {
		var c map[string]any
		_ = json.Unmarshal([]byte(rows[index].Context), &c)
		minimal := map[string]any{}
		for _, key := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "device_id", "app", "detection_method", "first_time", "last_time", "occurrence_time", "canonical_event_id"} {
			minimal[key] = c[key]
		}
		for _, key := range []string{"ioc", "ioc_evidence"} {
			if ioc, ok := c[key].(map[string]any); ok {
				minimal[key] = map[string]any{"ioc_type": ioc["ioc_type"], "ioc_value": ioc["ioc_value"]}
			}
		}
		b, _ := json.Marshal(minimal)
		rows[index].Context = string(b)
	}
	return rows, ctx.Err()
}

func historySQL(q HistoryQuery) (string, []any, error) {
	if err := historyQueryValid(q); err != nil {
		return "", nil, err
	}
	where := []string{"((last_seen_at>=? AND last_seen_at<?) OR (last_seen_at IS NULL AND created_at>=? AND created_at<?))", "(CASE WHEN JSON_VALID(context) THEN COALESCE(JSON_UNQUOTE(JSON_EXTRACT(context,'$.canonical_event_id')),event_id) ELSE event_id END)=event_id"}
	args := []any{q.Start, q.End, q.Start, q.End}
	for _, id := range q.ExcludeIDs {
		where = append(where, "event_id<>?")
		args = append(args, id)
	}
	match := []string{}
	field := func(path string) string {
		return "CASE WHEN JSON_VALID(context) THEN JSON_UNQUOTE(JSON_EXTRACT(context,'" + path + "')) ELSE NULL END"
	}
	for _, address := range q.Addresses {
		match = append(match, "("+field("$.src_ip")+"=? OR "+field("$.dst_ip")+"=?)")
		args = append(args, address, address)
	}
	for _, ioc := range q.IOCs {
		raw, _ := json.Marshal(map[string]string{"type": ioc.Type, "value": ioc.Value})
		match = append(match, "((CASE WHEN JSON_VALID(observables) THEN JSON_CONTAINS(observables,?) ELSE 0 END) OR ("+field("$.ioc.ioc_value")+"=? AND "+field("$.ioc.ioc_type")+"=?) OR ("+field("$.ioc_evidence.ioc_value")+"=? AND "+field("$.ioc_evidence.ioc_type")+"=?))")
		args = append(args, string(raw), ioc.Value, ioc.Type, ioc.Value, ioc.Type)
	}
	where = append(where, "("+strings.Join(match, " OR ")+")")
	args = append(args, q.Limit)
	projected := []string{}
	for _, key := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "device_id", "app", "detection_method", "first_time", "last_time", "occurrence_time", "canonical_event_id"} {
		if key == "app" {
			projected = append(projected, "'app',CASE WHEN JSON_VALID(context) THEN JSON_EXTRACT(context,'$.app') ELSE NULL END")
			continue
		}
		projected = append(projected, "'"+key+"',"+field("$."+key))
	}
	for _, key := range []string{"ioc", "ioc_evidence"} {
		projected = append(projected, "'"+key+"',JSON_OBJECT('ioc_type',"+field("$."+key+".ioc_type")+",'ioc_value',"+field("$."+key+".ioc_value")+")")
	}
	cols := strings.Replace(eventSelectCols, ", context,", ", JSON_OBJECT("+strings.Join(projected, ",")+") AS context,", 1)
	return "SELECT " + cols + " FROM events WHERE " + strings.Join(where, " AND ") + " ORDER BY COALESCE(last_seen_at,created_at) DESC,event_id ASC LIMIT ?", args, nil
}
func (s *MySQLStore) HistoryCandidates(ctx context.Context, q HistoryQuery) ([]domain.Event, error) {
	query, args, err := historySQL(q)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
