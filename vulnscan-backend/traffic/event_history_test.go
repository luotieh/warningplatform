package traffic

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestIOCHistoryQueryParameters(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/events/list?scope=all&ioc_value=example.com&ioc_type=domain&victim=10.0.0.1&page=2&page_size=20", nil)
	q, err := eventQueryFromRequest(c)
	if err != nil || q.Scope != "all" || q.IOCValue != "example.com" || q.IOCType != "domain" || q.Victim != "10.0.0.1" || q.Page != 2 {
		t.Fatalf("query=%+v err=%v", q, err)
	}
}

func TestIOCHistoryFiltersBeforePagination(t *testing.T) {
	svc, st := newTestEventService(t, "")
	for _, event := range []domain.Event{
		{EventID: "history-1", Context: `{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4","ioc":{"ioc_value":"1.2.3.4","ioc_type":"ip"}}`},
		{EventID: "history-2", Context: `{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4","ioc":{"ioc_value":"1.2.3.4","ioc_type":"ip"}}`},
		{EventID: "history-other-victim", Context: `{"src_ip":"10.0.0.2","dst_ip":"1.2.3.4","ioc":{"ioc_value":"1.2.3.4","ioc_type":"ip"}}`},
		{EventID: "history-prefix", Context: `{"src_ip":"10.0.0.1","dst_ip":"1.2.3.40","ioc":{"ioc_value":"1.2.3.40","ioc_type":"ip"}}`},
		{EventID: "history-no-ioc", Context: `{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4"}`},
	} {
		if _, err := st.CreateEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := st.UpdateEvent("history-1", map[string]any{"archive_date": "2026-09-01"}); !ok {
		t.Fatal("archive failed")
	}
	q := store.EventQuery{Scope: "all", IOCValue: "1.2.3.4", IOCType: "ip", Victim: "10.0.0.1", Page: 2, PageSize: 1}
	rows, total, err := svc.ListPage(context.Background(), q)
	if err != nil || total != 2 || len(rows) != 1 {
		t.Fatalf("same victim total=%d rows=%v err=%v", total, rows, err)
	}
	if rows[0]["victimDevice"] != "10.0.0.1" {
		t.Fatalf("wrong attribution: %v", rows[0])
	}
	q.Victim, q.PageSize, q.Page = "", 20, 1
	rows, total, err = svc.ListPage(context.Background(), q)
	if err != nil || total != 3 || len(rows) != 3 {
		t.Fatalf("all IOC total=%d rows=%d err=%v", total, len(rows), err)
	}
	foundArchived := false
	for _, row := range rows {
		if row["event_id"] == "history-1" {
			foundArchived = true
		}
	}
	if !foundArchived {
		t.Fatal("history must include archived events")
	}
	q.IOCType = "domain"
	_, total, err = svc.ListPage(context.Background(), q)
	if err != nil || total != 0 {
		t.Fatalf("type must match: total=%d err=%v", total, err)
	}
}

func TestIOCHistoryExactCaseInsensitiveMatch(t *testing.T) {
	row := map[string]any{"ioc": map[string]any{"ioc_value": "Example.COM", "ioc_type": "domain"}, "victimDevice": "10.0.0.1"}
	if !matchesIOCHistory(row, store.EventQuery{IOCValue: " example.com ", IOCType: "DOMAIN", Victim: "10.0.0.1"}) {
		t.Fatal("case and whitespace")
	}
	if matchesIOCHistory(row, store.EventQuery{IOCValue: "example.co"}) {
		t.Fatal("IOC must match exactly")
	}
	if matchesIOCHistory(row, store.EventQuery{IOCValue: "example.com", Victim: "10.0.0.2"}) {
		t.Fatal("victim must match exactly")
	}
}
