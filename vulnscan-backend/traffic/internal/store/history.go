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
	// RequireAssetIOC requires both identities; candidate events are still
	// checked against their saved contact records during preprocessing.
	RequireAssetIOC bool
	// SummaryOnly omits messages, review prose and unrelated application data.
	SummaryOnly bool
	// ExactRelations opt in to AND-bound transport/application history. Legacy
	// callers retain the broad context search; phase-one never uses that OR path.
	ExactRelations []HistoryRelation
	DeviceID       string
	BeforeTime     time.Time
	AfterID        string
}
type HistoryRelation struct {
	Address string
	IOC     domain.IOC
}

func historyQueryValid(q HistoryQuery) error {
	if q.RequireAssetIOC && (len(q.Addresses) == 0 || len(q.IOCs) == 0 || len(q.ExactRelations) != 0) {
		return fmt.Errorf("history_query_invalid")
	}
	if len(q.ExactRelations) > 32 || len(q.ExactRelations) > 0 && q.DeviceID == "" {
		return fmt.Errorf("history_query_invalid")
	}
	for _, r := range q.ExactRelations {
		if r.Address == "" || (r.IOC.Type != "ip" && r.IOC.Type != "domain" && r.IOC.Type != "url") || r.IOC.Value == "" || len(r.IOC.Value) > 2048 {
			return fmt.Errorf("history_query_invalid")
		}
	}
	for _, ioc := range q.IOCs {
		if len(ioc.Value) > 2048 || len(ioc.Type) > 32 || ioc.Value == "" || ioc.Type == "" {
			return fmt.Errorf("history_query_invalid")
		}
	}
	if q.Start.IsZero() || !q.Start.Before(q.End) || q.Limit < 1 || q.Limit > 201 || len(q.Addresses) > 32 || len(q.IOCs) > 32 || len(q.ExcludeIDs) > 256 || len(q.Addresses)+len(q.IOCs)+len(q.ExactRelations) == 0 {
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
	if !q.BeforeTime.IsZero() && (t.After(q.BeforeTime) || t.Equal(q.BeforeTime) && e.EventID <= q.AfterID) {
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
	if len(q.ExactRelations) > 0 {
		if c["device_id"] != q.DeviceID {
			return false
		}
		for _, r := range q.ExactRelations {
			if ExactHistoryRelation(c, r) {
				return true
			}
		}
		return false
	}
	assetMatch := false
	for _, address := range q.Addresses {
		if c["src_ip"] == address || c["dst_ip"] == address {
			assetMatch = true
		}
	}
	iocMatch := false
	for _, ioc := range q.IOCs {
		for _, o := range e.Observables {
			if o.Value == ioc.Value && o.Type == ioc.Type {
				iocMatch = true
			}
		}
		for _, key := range []string{"ioc", "ioc_evidence"} {
			if m, ok := c[key].(map[string]any); ok && m["ioc_value"] == ioc.Value && m["ioc_type"] == ioc.Type {
				iocMatch = true
			}
		}
	}
	if q.RequireAssetIOC {
		return assetMatch && iocMatch
	}
	return assetMatch || iocMatch
}

// Requires both the declared IOC identity and the actual relevant field. DNS
// answer membership cannot establish an IP transport contact.
func ExactHistoryRelation(c map[string]any, r HistoryRelation) bool {
	i, _ := c["ioc"].(map[string]any)
	if i["ioc_type"] != r.IOC.Type || i["ioc_value"] != r.IOC.Value {
		return false
	}
	src, dst := c["src_ip"], c["dst_ip"]
	if src != r.Address && dst != r.Address {
		return false
	}
	if r.IOC.Type == "ip" {
		return src == r.Address && dst == r.IOC.Value || dst == r.Address && src == r.IOC.Value
	}
	a, _ := c["app"].(map[string]any)
	if r.IOC.Type == "url" {
		return a["http_url"] == r.IOC.Value
	}
	for _, key := range []string{"http_host", "tls_sni", "dns_query"} {
		v, _ := a[key].(string)
		if strings.EqualFold(strings.TrimSuffix(v, "."), strings.TrimSuffix(r.IOC.Value, ".")) {
			return true
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
		if q.SummaryOnly {
			app, _ := c["app"].(map[string]any)
			minimal["app"] = map[string]any{}
			for _, key := range []string{"http_url", "http_host", "tls_sni", "dns_query"} {
				minimal["app"].(map[string]any)[key] = app[key]
			}
			rows[index].Message, rows[index].ReviewComment = "", ""
		}
		for _, key := range []string{"ioc", "ioc_evidence"} {
			if ioc, ok := c[key].(map[string]any); ok {
				minimal[key] = map[string]any{"ioc_type": ioc["ioc_type"], "ioc_value": ioc["ioc_value"]}
			}
		}
		b, _ := json.Marshal(minimal)
		rows[index].Context = string(b)
		if q.SummaryOnly {
			rows[index] = minimalHistoryEvent(rows[index])
		}
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
	if !q.BeforeTime.IsZero() {
		where = append(where, "(COALESCE(last_seen_at,created_at)<? OR (COALESCE(last_seen_at,created_at)=? AND event_id>?))")
		args = append(args, q.BeforeTime, q.BeforeTime, q.AfterID)
	}
	if len(q.ExactRelations) > 0 {
		where = append(where, field("$.device_id")+"=?")
		args = append(args, q.DeviceID)
		for _, r := range q.ExactRelations {
			clause := "(" + field("$.ioc.ioc_type") + "=? AND " + field("$.ioc.ioc_value") + "=? AND "
			args = append(args, r.IOC.Type, r.IOC.Value)
			if r.IOC.Type == "ip" {
				clause += "((" + field("$.src_ip") + "=? AND " + field("$.dst_ip") + "=?) OR (" + field("$.dst_ip") + "=? AND " + field("$.src_ip") + "=?)))"
				args = append(args, r.Address, r.IOC.Value, r.Address, r.IOC.Value)
			} else {
				clause += "(" + field("$.src_ip") + "=? OR " + field("$.dst_ip") + "=?) AND ("
				args = append(args, r.Address, r.Address)
				keys := []string{"http_host", "tls_sni", "dns_query"}
				if r.IOC.Type == "url" {
					keys = []string{"http_url"}
				}
				parts := []string{}
				for _, k := range keys {
					if r.IOC.Type == "url" {
						parts = append(parts, field("$.app."+k)+"=?")
					} else {
						parts = append(parts, "LOWER(TRIM(TRAILING '.' FROM "+field("$.app."+k)+"))=LOWER(TRIM(TRAILING '.' FROM ?))")
					}
					args = append(args, r.IOC.Value)
				}
				clause += strings.Join(parts, " OR ") + "))"
			}
			match = append(match, clause)
		}
	}
	if len(q.ExactRelations) == 0 {
		for _, address := range q.Addresses {
			match = append(match, "("+field("$.src_ip")+"=? OR "+field("$.dst_ip")+"=?)")
			args = append(args, address, address)
		}
		for _, ioc := range q.IOCs {
			raw, _ := json.Marshal(map[string]string{"type": ioc.Type, "value": ioc.Value})
			match = append(match, "((CASE WHEN JSON_VALID(observables) THEN JSON_CONTAINS(observables,?) ELSE 0 END) OR ("+field("$.ioc.ioc_value")+"=? AND "+field("$.ioc.ioc_type")+"=?) OR ("+field("$.ioc_evidence.ioc_value")+"=? AND "+field("$.ioc_evidence.ioc_type")+"=?))")
			args = append(args, string(raw), ioc.Value, ioc.Type, ioc.Value, ioc.Type)
		}
	}
	if q.RequireAssetIOC {
		where = append(where, "("+strings.Join(match[:len(q.Addresses)], " OR ")+")", "("+strings.Join(match[len(q.Addresses):], " OR ")+")")
	} else {
		where = append(where, "("+strings.Join(match, " OR ")+")")
	}
	args = append(args, q.Limit)
	projected := []string{}
	for _, key := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "device_id", "app", "detection_method", "first_time", "last_time", "occurrence_time", "canonical_event_id"} {
		if key == "app" {
			if q.SummaryOnly {
				parts := []string{}
				for _, k := range []string{"http_url", "http_host", "tls_sni", "dns_query"} {
					parts = append(parts, "'"+k+"',"+field("$.app."+k))
				}
				projected = append(projected, "'app',JSON_OBJECT("+strings.Join(parts, ",")+")")
			} else {
				projected = append(projected, "'app',CASE WHEN JSON_VALID(context) THEN JSON_EXTRACT(context,'$.app') ELSE NULL END")
			}
			continue
		}
		projected = append(projected, "'"+key+"',"+field("$."+key))
	}
	for _, key := range []string{"ioc", "ioc_evidence"} {
		projected = append(projected, "'"+key+"',JSON_OBJECT('ioc_type',"+field("$."+key+".ioc_type")+",'ioc_value',"+field("$."+key+".ioc_value")+")")
	}
	cols := strings.Replace(eventSelectCols, ", context,", ", JSON_OBJECT("+strings.Join(projected, ",")+") AS context,", 1)
	if q.SummaryOnly {
		// Predicates may inspect the full observables column, but consumers only
		// need explicit IOC/application relations in context. Do not return the
		// entire unbounded column or report/review prose merely to filter rows.
		for _, name := range []string{"event_name", "title", "message", "source", "severity", "event_status", "review_status", "review_comment", "reviewed_by", "circular_code"} {
			cols = strings.Replace(cols, ", "+name+",", ", '' AS "+name+",", 1)
		}
		for _, name := range []string{"current_round", "analysis_version", "aggregation_closed"} {
			cols = strings.Replace(cols, ", "+name+",", ", 0 AS "+name+",", 1)
		}
		for _, name := range []string{"reviewed_at", "last_analysis_at"} {
			cols = strings.Replace(cols, ", "+name+",", ", NULL AS "+name+",", 1)
		}
		cols = strings.Replace(cols, "id, event_id", "0 AS id, event_id", 1)
		cols = strings.Replace(cols, ", observables,", ", '[]' AS observables,", 1)
		cols = strings.Replace(cols, ", archive_date", ", NULL AS archive_date", 1)
	}
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

// The same retained fields are used by MemoryStore and MySQL summary reads.
// Legacy full history callers keep their existing projection. UpdatedAt is
// retained as source metadata; CreatedAt/LastSeenAt are the paging identity.
func minimalHistoryEvent(e domain.Event) domain.Event {
	return domain.Event{EventID: e.EventID, Category: e.Category, Context: e.Context, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, LastSeenAt: e.LastSeenAt}
}

// HistorySummaryBytes counts the entire retained record, not just Context.
// This is canonical application JSON size, not database protocol wire bytes.
func HistorySummaryBytes(e domain.Event) int {
	b, _ := json.Marshal(e)
	return len(b)
}
