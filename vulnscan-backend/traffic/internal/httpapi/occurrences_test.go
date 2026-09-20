package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestOccurrencesAuthenticationAndSnapshotMembership(t *testing.T) {
	st := store.NewMemoryStore()
	svc := service.Services{Store: st}
	srv := New(config.Config{}, svc, nil)
	user, err := st.CreateUser(domain.User{UserID: "reader", Username: "reader", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.tokens["valid-test-token"] = user.UserID
	ids, hits := []string{}, []string{}
	for i := 0; i < 2; i++ {
		m := map[string]any{"event_id": fmt.Sprint(i), "device_id": "node", "src_ip": "192.0.2.1", "dst_ip": fmt.Sprintf("192.0.2.%d", i+2), "event_type": "scan", "rule_id": "r", "event_time": time.Now().Add(-time.Hour).Format(time.RFC3339Nano)}
		r, err := svc.ProcessLyEvent(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		id := r["deepsoc_event_id"].(string)
		if err = svc.RebuildAggregation(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		hits = append(hits, r["hit_id"].(string))
	}
	for _, tc := range []struct {
		token, path string
		status      int
	}{
		{"", "/api/events/detail/" + ids[0] + "/occurrences", 401},
		{"expired", "/api/events/detail/" + ids[0] + "/occurrences/" + hits[0], 401},
		{"valid-test-token", "/api/events/detail/" + ids[0] + "/occurrences?limit=1", 200},
		{"valid-test-token", "/api/events/detail/" + ids[0] + "/occurrences/" + hits[0] + "?snapshot_version=1", 200},
		{"valid-test-token", "/api/events/detail/" + ids[0] + "/occurrences/" + hits[1], 400},
		{"valid-test-token", "/api/events/detail/" + ids[0] + "/occurrences?cursor=invalid", 400},
		{"valid-test-token", "/api/events/detail/" + ids[0] + "/occurrences?snapshot_version=999", 400},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s got %d want %d: %s", tc.path, w.Code, tc.status, w.Body.String())
		}
	}
}
