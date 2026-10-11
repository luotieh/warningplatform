package store

import (
	"context"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

func TestHistorySQLIsParameterizedBoundedAndIncludesArchived(t *testing.T) {
	end := time.Now().UTC()
	q := HistoryQuery{Start: end.AddDate(0, 0, -30), End: end, Addresses: []string{"192.0.2.1"}, IOCs: []domain.IOC{{Type: "ip", Value: "192.0.2.2' OR 1=1"}}, ExcludeIDs: []string{"current"}, Limit: 201}
	query, args, err := historySQL(q)
	if err != nil || !strings.Contains(query, "LIMIT ?") || strings.Contains(query, "LIKE") || strings.Contains(query, "archive_date IS NULL") || strings.Contains(query, "OR 1=1") || args[len(args)-1] != 201 {
		t.Fatalf("unsafe/unbounded query: %s %v", query, err)
	}
	if !strings.Contains(query, "JSON_OBJECT(") || strings.Contains(query, ", context,") {
		t.Fatal("history query retrieves full event payload context")
	}
	q.Limit = 202
	if _, _, err = historySQL(q); err == nil {
		t.Fatal("unbounded query accepted")
	}
}
func TestMemoryHistoryBoundaryAndAliases(t *testing.T) {
	st := NewMemoryStore()
	end := time.Now().UTC()
	at := end.Add(-time.Hour)
	for _, e := range []domain.Event{{EventID: "old", CreatedAt: at, Context: `{"src_ip":"192.0.2.1"}`}, {EventID: "alias", CreatedAt: at, Context: `{"src_ip":"192.0.2.1","canonical_event_id":"old"}`}, {EventID: "boundary", CreatedAt: end, Context: `{"src_ip":"192.0.2.1"}`}} {
		if _, err := st.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	q := HistoryQuery{Start: end.Add(-24 * time.Hour), End: end, Addresses: []string{"192.0.2.1"}, Limit: 201}
	rows, err := st.HistoryCandidates(context.Background(), q)
	if err != nil || len(rows) != 1 || rows[0].EventID != "old" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.HistoryCandidates(ctx, q); err == nil {
		t.Fatal("cancellation ignored")
	}
}
