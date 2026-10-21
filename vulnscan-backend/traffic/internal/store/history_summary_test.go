package store

import (
	"context"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

func TestHistoryRequiresBothAssetAndIOC(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	end := time.Now().UTC()
	ioc := domain.IOC{Type: "ip", Value: "203.0.113.1"}
	for _, e := range []domain.Event{
		{EventID: "both", Context: `{"src_ip":"192.0.2.1","ioc":{"ioc_type":"ip","ioc_value":"203.0.113.1"}}`},
		{EventID: "asset-only", Context: `{"src_ip":"192.0.2.1","ioc":{"ioc_type":"ip","ioc_value":"203.0.113.2"}}`},
		{EventID: "ioc-only", Context: `{"src_ip":"192.0.2.2","ioc":{"ioc_type":"ip","ioc_value":"203.0.113.1"}}`},
	} {
		e.CreatedAt = end.Add(-time.Hour)
		if _, err := s.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	q := HistoryQuery{Start: end.Add(-24 * time.Hour), End: end, Addresses: []string{"192.0.2.1"}, IOCs: []domain.IOC{ioc}, Limit: 10, RequireAssetIOC: true}
	rows, err := s.HistoryCandidates(ctx, q)
	if err != nil || len(rows) != 1 || rows[0].EventID != "both" {
		t.Fatal(rows, err)
	}
	query, args, err := historySQL(q)
	if err != nil || len(args) == 0 || !strings.Contains(query, "AND (((CASE WHEN JSON_VALID(observables)") {
		t.Fatal("SQL did not AND-bind IOC group", query, err)
	}
	q.RequireAssetIOC = false
	rows, err = s.HistoryCandidates(ctx, q)
	if err != nil || len(rows) != 3 {
		t.Fatal("legacy context query changed", rows, err)
	}
	q.RequireAssetIOC = true
	q.IOCs = nil
	if _, _, err = historySQL(q); err == nil {
		t.Fatal("one-sided query accepted")
	}
}

func TestHistorySummaryOmitsUnneededPayload(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now().UTC()
	e := domain.Event{EventID: "event", CreatedAt: now.Add(-time.Hour), Message: "unneeded-message", ReviewComment: "unneeded-review", Context: `{"src_ip":"192.0.2.1","ioc":{"ioc_type":"domain","ioc_value":"example.test"},"app":{"http_host":"example.test","body":"unneeded-body"},"raw_packet":{"packet_hex":"unneeded-packet"}}`}
	if _, err := s.CreateEvent(e); err != nil {
		t.Fatal(err)
	}
	q := HistoryQuery{Start: now.Add(-24 * time.Hour), End: now, Addresses: []string{"192.0.2.1"}, IOCs: []domain.IOC{{Type: "domain", Value: "example.test"}}, RequireAssetIOC: true, SummaryOnly: true, Limit: 10}
	rows, err := s.HistoryCandidates(context.Background(), q)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if rows[0].Message != "" || rows[0].ReviewComment != "" || strings.Contains(rows[0].Context, "unneeded") || !strings.Contains(rows[0].Context, "example.test") {
		t.Fatal("projection lost binding or kept payload", rows)
	}
	query, _, err := historySQL(q)
	if err != nil || !strings.Contains(query, "'' AS message") || !strings.Contains(query, "'' AS review_comment") || strings.Contains(query, "JSON_EXTRACT(context,'$.app')") || !strings.Contains(query, "$.app.http_host") {
		t.Fatal("SQL summary does not match memory projection", query, err)
	}
}
