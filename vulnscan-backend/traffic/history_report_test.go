package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
)

func TestHistoryReportAllMatchingEventsAndIndependentModelInput(t *testing.T) {
	svc, st := newTestEventService(t, "")
	// More than one UI page. Include archived history and an unrelated victim.
	for i := 0; i < 25; i++ {
		_, err := st.CreateEvent(domain.Event{EventID: fmt.Sprintf("history-%02d", i), Message: "RAW_SECRET_PACKET", Context: fmt.Sprintf(`{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4","protocol":"tcp","occurrence_count":2,"first_time":"2026-10-%02dT01:00:00Z","last_time":"2026-10-%02dT02:00:00Z","ioc":{"ioc_value":"1.2.3.4","ioc_type":"ip"}}`, 1+i%2, 1+i%2)})
		if err != nil {
			t.Fatal(err)
		}
	}
	st.UpdateEvent("history-00", map[string]any{"archive_date": "2026-10-01"})
	st.CreateEvent(domain.Event{EventID: "other", Context: `{"src_ip":"10.0.0.2","dst_ip":"1.2.3.4","ioc":{"ioc_value":"1.2.3.4","ioc_type":"ip"}}`})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), "RAW_SECRET_PACKET") || strings.Contains(string(raw), "history-00") {
			t.Error("individual event material leaked into model prompt")
		}
		if !strings.Contains(string(raw), `\"event_count\":25`) {
			t.Errorf("missing full history: %s", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"finish_reason":"stop","message":{"content":"## 总体判断\n历史活动总结"}}]}`)
	}))
	defer server.Close()
	svc.core.LLM = &client.LLMClient{BaseURL: server.URL, HTTP: server.Client(), Model: "test"}
	result, err := svc.GenerateHistoryReport(context.Background(), HistoryReportScope{IOCValue: "1.2.3.4", IOCType: "ip", Victim: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := result["snapshot"].(HistoryReportSnapshot)
	if snapshot.EventCount != 25 || snapshot.KnownHits != 50 || snapshot.MissingHitCounts != 0 || len(snapshot.EventIDs) != 25 {
		t.Fatalf("wrong totals: %+v", snapshot)
	}
	if len(snapshot.Daily) != 2 || snapshot.Daily[0].EventStarts != 13 || snapshot.Daily[1].EventStarts != 12 {
		t.Fatalf("wrong daily starts: %+v", snapshot.Daily)
	}
	if snapshot.Protocols["tcp"] != 25 {
		t.Fatal("missing protocol distribution")
	}
	for _, e := range st.ListEvents() {
		if e.AnalysisVersion != 0 || len(st.ListSummaries(e.EventID)) != 0 || len(st.ListMessages(e.EventID)) != 0 {
			t.Fatal("individual event modified")
		}
	}
}

func TestHistorySnapshotBeijingAndMissingCounts(t *testing.T) {
	snapshot := buildHistoryReportSnapshot(HistoryReportScope{}, []domain.Event{{EventID: "one", CreatedAt: time.Date(2026, 10, 1, 18, 0, 0, 0, time.UTC), Context: `{"first_time":"2026-10-01T18:00:00Z","last_time":"2026-10-03T18:00:00Z"}`}})
	if snapshot.MissingHitCounts != 1 || snapshot.KnownHits != 0 || len(snapshot.Daily) != 1 || snapshot.Daily[0].Date != "2026-10-02" {
		t.Fatalf("wrong date or missing count: %+v", snapshot)
	}
}

func TestHistoryReportRejectsUnusableModelOutput(t *testing.T) {
	for _, tc := range []struct{ name, reply, reason string }{
		{"empty", "", "stop"}, {"truncated", "unfinished", "length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st := newTestEventService(t, "")
			_, err := st.CreateEvent(domain.Event{EventID: "event", Context: `{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4","ioc":{"ioc_type":"ip","ioc_value":"1.2.3.4"}}`})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": tc.reason, "message": map[string]any{"content": tc.reply}}}})
			}))
			defer server.Close()
			svc.core.LLM = &client.LLMClient{BaseURL: server.URL, HTTP: server.Client(), Model: "test"}
			if _, err := svc.GenerateHistoryReport(context.Background(), HistoryReportScope{IOCValue: "1.2.3.4"}); err == nil {
				t.Fatal("unusable model output accepted")
			}
		})
	}
}

func TestHistoryReportManualRequestPersistsCompletedResult(t *testing.T) {
	svc, st := newTestEventService(t, "")
	st.CreateEvent(domain.Event{EventID: "event", Context: `{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4","ioc":{"ioc_type":"ip","ioc_value":"1.2.3.4"}}`})
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"finish_reason":"stop","message":{"content":"综合报告"}}]}`)
	}))
	defer server.Close()
	svc.core.LLM = &client.LLMClient{BaseURL: server.URL, HTTP: server.Client(), Model: "test"}
	h := &Handler{events: svc}
	router := gin.New()
	router.POST("/history", h.GenerateHistoryReport)
	if calls != 0 {
		t.Fatal("report generated without manual request")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/history", strings.NewReader(`{"ioc_value":"1.2.3.4"}`)))
	var response struct {
		Data map[string]any `json:"data"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || calls != 1 {
		t.Fatalf("manual generation failed: %s", w.Body.String())
	}
	id, _ := response.Data["report_id"].(string)
	record, found, err := st.AggregateRecord(context.Background(), "history_report", id)
	if err != nil || !found || !strings.Contains(string(record.Value), "综合报告") {
		t.Fatal("completed result not persisted")
	}
	router.GET("/reports", h.ListHistoryReports)
	router.GET("/reports/:reportID", h.GetHistoryReport)
	svc.core.LLM = nil
	for _, path := range []string{"/reports?ioc_value=1.2.3.4", "/reports/" + id} {
		read := httptest.NewRecorder()
		router.ServeHTTP(read, httptest.NewRequest("GET", path, nil))
		if read.Code != 200 || !strings.Contains(read.Body.String(), id) || calls != 1 {
			t.Fatalf("saved report unavailable without model: %s", read.Body.String())
		}
	}
	filtered := httptest.NewRecorder()
	router.ServeHTTP(filtered, httptest.NewRequest("GET", "/reports?ioc_value=1.2.3.4&victim=other", nil))
	if filtered.Code != 200 || strings.Contains(filtered.Body.String(), id) {
		t.Fatalf("archive leaked a different scope: %s", filtered.Body.String())
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/history", strings.NewReader(`{"ioc_value":"1.2.3.4"}`)))
	if w.Code != 422 || !strings.Contains(w.Body.String(), "模型") {
		t.Fatal("generation failures must be returned directly")
	}
}
