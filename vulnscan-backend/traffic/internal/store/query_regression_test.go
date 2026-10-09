package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

func TestQueryWindowsUseBeijingAndDefaultIncludesArchive(t *testing.T) {
	now := time.Date(2026, 10, 7, 16, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		scope string
		day   int
	}{{"today", 8}, {"3", 6}, {"7", 2}} {
		q, err := (EventQuery{Scope: tc.scope}).Normalize(now)
		want := time.Date(2026, 10, tc.day, 0, 0, 0, 0, domain.Beijing)
		if err != nil || !q.StartTime.Equal(want) || !q.EndTime.Equal(now) {
			t.Fatalf("%s: %+v %v", tc.scope, q, err)
		}
	}
	st := NewMemoryStore()
	archive := now.AddDate(0, 0, -1)
	st.CreateEvent(domain.Event{EventID: "archived", CreatedAt: now, ArchiveDate: &archive})
	page, err := st.ListEventsPage(EventQuery{})
	if err != nil || page.Total != 1 {
		t.Fatalf("default hides archive: %+v %v", page, err)
	}
}

func TestQueryTimeMatchesDisplayForLegacyNumericAndOffsets(t *testing.T) {
	start := time.Date(2026, 10, 8, 0, 0, 0, 0, domain.Beijing)
	end := start.AddDate(0, 0, 1)
	st := NewMemoryStore()
	values := []any{"2026-10-08T00:05:00+08:00", "2026-10-07T16:05:00Z", "2026-10-08 00:05:00", start.Add(5 * time.Minute).Unix(), start.Add(5 * time.Minute).UnixMilli(), start.Add(5 * time.Minute).UnixMicro()}
	for i, v := range values {
		ctx, _ := json.Marshal(map[string]any{"first_time": v})
		st.CreateEvent(domain.Event{EventID: fmt.Sprintf("in-%d", i), Context: string(ctx), CreatedAt: start.AddDate(0, 0, -3), ArchiveDate: &start})
	}
	st.CreateEvent(domain.Event{EventID: "before", Context: `{"first_time":"2026-10-07T23:30:00+08:00"}`, CreatedAt: start})
	st.CreateEvent(domain.Event{EventID: "end", Context: `{"first_time":"2026-10-09T00:00:00+08:00"}`, CreatedAt: start})
	st.CreateEvent(domain.Event{EventID: "legacy", Context: `{"first_time":"bad","occurrence_time":"2026-10-08T01:00:00+08:00"}`, CreatedAt: start.AddDate(0, 0, -3), ArchiveDate: &start})
	q := EventQuery{Scope: "today", StartTime: &start, EndTime: &end, Page: 2, PageSize: 3}
	page, err := st.ListEventsPage(q)
	if err != nil || page.Total != 7 || len(page.Items) != 3 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	all, err := st.ListEventsMatching(q)
	if err != nil || len(all) != 7 {
		t.Fatalf("matching=%v err=%v", all, err)
	}
	for _, e := range all {
		if !matchesEventTime(e, q) {
			t.Fatalf("display time outside window: %s", e.EventID)
		}
	}
}

func TestArchivedLegacyAssetReportQueryIncludesAllMatches(t *testing.T) {
	st := NewMemoryStore()
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, domain.Beijing)
	to := from.AddDate(0, 1, 0)
	for i := 0; i < 1001; i++ {
		st.CreateEvent(domain.Event{EventID: fmt.Sprintf("legacy-%d", i), CreatedAt: from.AddDate(0, -1, 0), ArchiveDate: &from,
			Context: `{"dst_ip":"192.0.2.1","victim_target":"10.0.0.8","last_time":"2026-10-08T00:05:00+08:00"}`})
	}
	events := st.ListEventsByTargetIP("10.0.0.8", from, to)
	if len(events) != 1001 {
		t.Fatalf("archived legacy events=%d want1001", len(events))
	}
}
