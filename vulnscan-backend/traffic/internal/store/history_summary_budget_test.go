package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

func TestHistorySummaryFiltersBeforeProjectionAndPreservesExactRelations(t *testing.T) {
	st := NewMemoryStore()
	end := time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC)
	at := end.Add(-time.Hour)
	for _, e := range []domain.Event{
		{EventID: "observable-only", Context: `{"src_ip":"192.0.2.1"}`, Observables: []domain.IOC{{Type: "domain", Value: "only-observable.test"}}},
		{EventID: "ip", Context: `{"device_id":"sensor","src_ip":"192.0.2.1","dst_ip":"203.0.113.1","ioc":{"ioc_type":"ip","ioc_value":"203.0.113.1"}}`},
		{EventID: "domain", Context: `{"device_id":"sensor","src_ip":"192.0.2.1","dst_ip":"203.0.113.1","ioc":{"ioc_type":"domain","ioc_value":"Example.test."},"app":{"http_host":"example.test","body":"discard"}}`},
		{EventID: "url", Context: `{"device_id":"sensor","src_ip":"192.0.2.1","dst_ip":"203.0.113.1","ioc":{"ioc_type":"url","ioc_value":"https://example.test/path"},"app":{"http_url":"https://example.test/path","body":"discard"}}`},
	} {
		e.CreatedAt, e.LastSeenAt, e.UpdatedAt = at, &at, at
		e.Title, e.Message, e.Category = strings.Repeat("unused", 10000), "discard", "network"
		if _, err := st.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	q := HistoryQuery{Start: end.Add(-24 * time.Hour), End: end, IOCs: []domain.IOC{{Type: "domain", Value: "only-observable.test"}}, SummaryOnly: true, Limit: 10}
	rows, err := st.HistoryCandidates(context.Background(), q)
	if err != nil || len(rows) != 1 || rows[0].EventID != "observable-only" {
		t.Fatal("predicate was applied after observables projection", rows, err)
	}
	if len(rows[0].Observables) != 0 || rows[0].Title != "" || rows[0].Message != "" {
		t.Fatal("unneeded fields retained", rows[0])
	}
	q.SummaryOnly = false
	legacy, err := st.HistoryCandidates(context.Background(), q)
	if err != nil || len(legacy) != 1 || len(legacy[0].Observables) != 1 || legacy[0].Title == "" {
		t.Fatal("legacy contract changed", legacy, err)
	}
	q.SummaryOnly = true
	q.IOCs = nil
	q.DeviceID = "sensor"
	for _, rel := range []HistoryRelation{{Address: "192.0.2.1", IOC: domain.IOC{Type: "ip", Value: "203.0.113.1"}}, {Address: "192.0.2.1", IOC: domain.IOC{Type: "domain", Value: "Example.test."}}, {Address: "192.0.2.1", IOC: domain.IOC{Type: "url", Value: "https://example.test/path"}}} {
		q.ExactRelations = []HistoryRelation{rel}
		rows, err = st.HistoryCandidates(context.Background(), q)
		if err != nil || len(rows) != 1 || rows[0].EventID != rel.IOC.Type {
			t.Fatal("lost exact relation", rel, rows, err)
		}
		var c map[string]any
		if err = json.Unmarshal([]byte(rows[0].Context), &c); err != nil || !ExactHistoryRelation(c, rel) {
			t.Fatal("projection removed consumer binding", c, err)
		}
		if rows[0].Category != "network" || rows[0].LastSeenAt == nil || !rows[0].LastSeenAt.Equal(at) || strings.Contains(rows[0].Context, "discard") {
			t.Fatal("incorrect minimal retained summary", rows[0])
		}
	}
}

func TestHistorySummaryMySQLProjectionScannerAndSingleRead(t *testing.T) {
	at := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	ctx := `{"src_ip":"192.0.2.1","ioc":{"ioc_type":"domain","ioc_value":"example.test"},"app":{"http_host":"example.test"}}`
	want := minimalHistoryEvent(domain.Event{EventID: "source", Category: "network", Context: ctx, CreatedAt: at, UpdatedAt: at, LastSeenAt: &at})
	// Exercise the actual SQL builder/QueryContext/scanner path using the
	// projected values a database returns. SQL execution against MySQL itself
	// is deliberately outside this local test's claim.
	f := &queryFixture{rows: [][]driver.Value{{int64(0), want.EventID, "", "", "", ctx, "", "", want.Category, "", int64(0), []byte("[]"), at, at, "", "", "", nil, "", int64(0), false, nil, at, nil}}}
	db := sql.OpenDB(f)
	defer db.Close()
	st := &MySQLStore{db: db}
	q := HistoryQuery{Start: at.Add(-time.Hour), End: at.Add(time.Hour), IOCs: []domain.IOC{{Type: "domain", Value: "example.test"}}, SummaryOnly: true, Limit: 10}
	got, err := st.HistoryCandidates(context.Background(), q)
	if err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	gb, _ := json.Marshal(got[0])
	wb, _ := json.Marshal(want)
	if !reflect.DeepEqual(gb, wb) {
		t.Fatalf("memory/SQL retained contracts differ: %s != %s", gb, wb)
	}
	if len(f.queries) != 1 {
		t.Fatal("summary introduced extra SQL calls", len(f.queries))
	}
	selectPart, wherePart, ok := strings.Cut(f.queries[0], " FROM events WHERE ")
	if !ok || !strings.Contains(wherePart, "JSON_CONTAINS(observables,?)") {
		t.Fatal("IOC filter lost original observables", f.queries[0])
	}
	for _, field := range []string{"event_name", "title", "message", "source", "severity", "event_status", "review_status", "review_comment", "reviewed_by", "circular_code"} {
		if !strings.Contains(selectPart, "'' AS "+field) {
			t.Fatal("unbounded field not projected", field, selectPart)
		}
	}
	if !strings.Contains(selectPart, "'[]' AS observables") || strings.Contains(selectPart, "JSON_EXTRACT(context,'$.app')") || !strings.Contains(selectPart, "$.app.http_host") {
		t.Fatal("summary SQL returned unbounded material or lost application relation", selectPart)
	}
	if HistorySummaryBytes(got[0]) != len(gb) {
		t.Fatal("cost did not count whole retained JSON")
	}
}
