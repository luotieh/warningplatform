package traffic

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestEvidenceDiagnosticsHandlerReadsPersistedFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewMemoryStore()
	_, _ = st.CreateEvent(domain.Event{EventID: "event", Severity: "high"})
	diagnostic := trafficservice.SnapshotEvidenceDiagnostics{EventID: "event", SnapshotVersion: 7, Status: "unavailable", Reason: "snapshot_read_failed"}
	value, _ := json.Marshal(diagnostic)
	if err := st.PutAggregateRecord(context.Background(), store.AggregateRecord{Kind: "evidence_diagnostics", Key: "event:7", Group: "event", Value: value}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{events: NewEventService(trafficservice.Services{Store: st})}
	router := gin.New()
	router.GET("/events/detail/:eventID/evidence-diagnostics", h.EventEvidenceDiagnostics)
	for _, tc := range []struct {
		query string
		code  int
		want  string
	}{{"7", 200, "snapshot_read_failed"}, {"-1", 400, "snapshot_version"}, {"bad", 400, "snapshot_version"}} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest("GET", "/events/detail/event/evidence-diagnostics?snapshot_version="+tc.query, nil))
		if response.Code != tc.code || !strings.Contains(response.Body.String(), tc.want) {
			t.Fatalf("unexpected diagnostic response: %d %s", response.Code, response.Body.String())
		}
	}
}
