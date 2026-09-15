package traffic

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestArchiveListRangesAndPagination(t *testing.T) {
	st := store.NewMemoryStore()
	for i, date := range []string{"2026-09-01", "2026-09-12", "2026-09-14", ""} {
		e := domain.Event{EventID: date, CreatedAt: time.Date(2026, 8, i+1, 12, 0, 0, 0, time.UTC)}
		if date != "" {
			d, _ := time.Parse("2006-01-02", date)
			e.ArchiveDate = &d
		}
		if _, err := st.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{events: NewEventService(trafficservice.Services{Store: st})}
	router := gin.New()
	router.GET("/events", h.ListEvents)
	for _, tc := range []struct {
		query         string
		status, total int
	}{
		{"scope=archive", 200, 3},
		{"scope=today", 200, 1},
		{"scope=all", 200, 4},
		{"scope=archive&archive_from=2026-09-12&archive_to=2026-09-14", 200, 2},
		{"scope=archive&archive_from=2026-09-14&archive_to=2026-09-14", 200, 1},
		{"scope=archive&date=2026-09-12", 200, 1},
		{"scope=archive&archive_from=2026-09-15", 200, 0},
		{"scope=archive&archive_to=2026-09-01", 200, 1},
		{"scope=archive&archive_from=2026-02-30", 400, 0},
		{"scope=archive&archive_from=2026-09-14&archive_to=2026-09-12", 400, 0},
		{"scope=archive&date=2026-09-12&archive_from=2026-09-01", 400, 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/events?"+tc.query, nil))
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if tc.status == 200 {
				var response struct {
					Data struct {
						Total int `json:"total"`
					} `json:"data"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.Data.Total != tc.total {
					t.Fatalf("total=%d want=%d", response.Data.Total, tc.total)
				}
			}
		})
	}
	// 默认排序发生在分页前，范围依据归档日而非创建时间。
	page, err := st.ListEventsPage(store.EventQuery{Scope: "archive", Page: 2, PageSize: 1})
	if err != nil || page.Total != 3 || len(page.Items) != 1 || page.Items[0].EventID != "2026-09-12" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	first, _ := st.ListEventsPage(store.EventQuery{Scope: "archive", PageSize: 1})
	if first.Items[0].EventID != "2026-09-14" {
		t.Fatalf("unexpected order: %+v", first)
	}
}
