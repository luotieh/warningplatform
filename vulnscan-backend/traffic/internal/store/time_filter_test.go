package store

import (
	"sort"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

// 事件列表按时间筛选：[StartTime, EndTime) 半开区间；
// 聚合 v2 事件以 context.first_time 为准，其余以 created_at 为准。
func TestListEventsPageTimeRangeFilter(t *testing.T) {
	st := NewMemoryStore()
	at := func(day, hour int) time.Time {
		return time.Date(2026, 9, day, hour, 0, 0, 0, time.UTC)
	}
	ctxJSON := func(version int, firstTime string) string {
		return `{"aggregation_version":` + string(rune('0'+version)) + `,"first_time":"` + firstTime + `"}`
	}
	events := []domain.Event{
		{EventID: "evt-in", EventName: "区间内", CreatedAt: at(19, 12)},
		{EventID: "evt-at-start", EventName: "起始边界含", CreatedAt: at(19, 0)},
		{EventID: "evt-at-end", EventName: "结束边界不含", CreatedAt: at(20, 0)},
		{EventID: "evt-before", EventName: "早于下界", CreatedAt: at(18, 12)},
		{EventID: "evt-after", EventName: "晚于上界", CreatedAt: at(20, 12)},
		// 聚合 v2：first_time 优先于 created_at。
		{EventID: "evt-v2-first-in", EventName: "v2首命中在区间内", CreatedAt: at(17, 0),
			Context: ctxJSON(2, "2026-09-19T08:00:00Z")},
		{EventID: "evt-v2-first-out", EventName: "v2首命中在区间外", CreatedAt: at(19, 8),
			Context: ctxJSON(2, "2026-09-18T08:00:00Z")},
		// 非 v2：忽略 first_time，用 created_at。
		{EventID: "evt-v1-first-ignored", EventName: "v1忽略first_time", CreatedAt: at(19, 8),
			Context: ctxJSON(1, "2026-09-17T08:00:00Z")},
		// v2 但 first_time 无法解析：回退 created_at。
		{EventID: "evt-v2-first-invalid", EventName: "v2首命中无效回退", CreatedAt: at(19, 8),
			Context: ctxJSON(2, "not-a-time")},
	}
	for _, e := range events {
		if _, err := st.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}

	start, end := at(19, 0), at(20, 0)
	page, err := st.ListEventsPage(EventQuery{
		Scope: "all", Page: 1, PageSize: 100,
		StartTime: &start, EndTime: &end,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(page.Items))
	for _, e := range page.Items {
		got = append(got, e.EventID)
	}
	sort.Strings(got)
	want := []string{"evt-at-start", "evt-in", "evt-v1-first-ignored", "evt-v2-first-in", "evt-v2-first-invalid"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if page.Total != len(want) {
		t.Fatalf("total=%d want %d", page.Total, len(want))
	}
}
