package traffic

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"vulnscan-backend/traffic/internal/domain"
)

func TestHistoryFeaturesUsesObservedDaysAndMarksPartialCoverage(t *testing.T) {
	svc, st := newTestEventService(t, "")
	ev, err := st.CreateEvent(domain.Event{EventID: "cross-day", Context: `{"src_ip":"10.0.0.1","first_time":"2026-10-01T18:00:00Z","last_time":"2026-10-04T18:00:00Z","occurrence_count":500,"heartbeat_detected":true,"heartbeat_period_sec":60,"quant_stats":{"volume_quality":"unverified","total_payload_bytes":999},"ioc":{"threat_type":"c2"},"occurrences":[{"time":"2026-10-01T18:00:00Z","dst_ip":"8.8.8.8","dst_port":53,"protocol":"dns"},{"time":"2026-10-01T19:00:00Z","protocol":"dns"},{"time":"2026-10-04T18:00:00Z","protocol":"tcp"},{"time":"invalid"}]}`})
	if err != nil {
		t.Fatal(err)
	}
	f, err := svc.historyFeatures(context.Background(), []domain.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Daily) != 2 || f.Daily[0].Date != "2026-10-02" || f.Daily[1].Date != "2026-10-05" || f.Daily[0].ObservedHits != 2 || f.Daily[0].ActiveEvents != 1 {
		t.Fatalf("wrong observed days: %+v", f.Daily)
	}
	if f.Coverage["legacy_partial"] != 1 || f.Coverage["invalid_time_records"] != 1 {
		t.Fatalf("missing coverage boundaries: %+v", f.Coverage)
	}
	if f.Protocols["dns"] != 2 || f.Daily[1].Protocols["tcp"] != 1 || f.HeartbeatEvents != 1 || f.Intelligence[`threat_type="c2"`] != 1 || f.VerifiedPayloadBytes != 0 || f.VerifiedVolumeEvents != 0 {
		t.Fatalf("wrong features: %+v", f)
	}
}

func TestHistoryReportArchiveCanReopenWithoutModel(t *testing.T) {
	svc, _ := newTestEventService(t, "")
	h := &Handler{events: svc}
	router := gin.New()
	router.GET("/reports", h.ListHistoryReports)
	router.GET("/reports/:reportID", h.GetHistoryReport)
	for _, path := range []string{"/reports", "/reports/not-an-id", "/reports/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 && w.Code != 404 {
			t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/reports?ioc_value=test", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "[]") {
		t.Fatalf("empty archive: %s", w.Body.String())
	}
}
