package traffic

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestGinReportEndpointsRejectInvalidVersionAndUnboundLegacy(t *testing.T) {
	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(domain.Event{EventID: "legacy-event"}); err != nil {
		t.Fatal(err)
	}
	summary, err := st.AddSummary(domain.Summary{EventID: "legacy-event", EventSummary: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{events: NewEventService(service.Services{Store: st})}
	router := gin.New()
	router.GET("/report/:eventID", h.EventReportDocument)
	router.GET("/export/:eventID", h.ExportEventReport)
	for _, path := range []string{"/report/legacy-event?summary_id=-1", "/export/legacy-event?summary_id=abc", "/report/legacy-event?summary_id=" + fmt.Sprint(summary.ID), "/export/legacy-event?summary_id=" + fmt.Sprint(summary.ID)} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 || !(strings.Contains(w.Body.String(), "正整数") || strings.Contains(w.Body.String(), "legacy_report_without_evidence_document")) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
