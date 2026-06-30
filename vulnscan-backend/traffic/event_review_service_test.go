package traffic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func newTestEventService(t *testing.T, circularURL string) (*EventService, store.Store) {
	t.Helper()
	st := store.NewMemoryStore()
	svc := trafficservice.Services{
		Store:    st,
		Circular: client.CircularClient{HTTP: http.DefaultClient},
	}
	return NewEventService(svc), st
}

func TestReviewApprovePushesAndStoresCode(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"circular_code":"XF-1"},"msg":""}`))
	}))
	defer srv.Close()

	es, st := newTestEventService(t, srv.URL)
	_, _ = st.CreateEvent(domain.Event{EventID: "evt-1", EventStatus: "round_finished", Severity: "high", Title: "x"})

	res, err := es.Review(context.Background(), "evt-1", "approve", "ok", "alice", "Bearer tok", srv.URL)
	if err != nil {
		t.Fatalf("review approve: %v", err)
	}
	if res["circular_code"] != "XF-1" || res["review_status"] != "approved" {
		t.Fatalf("unexpected result: %+v", res)
	}
	got, _ := st.GetEvent("evt-1")
	if got.CircularCode != "XF-1" || got.ReviewStatus != "approved" {
		t.Fatalf("event not updated: %+v", got)
	}
	if got.ReviewedBy != "alice" {
		t.Fatalf("reviewed_by not stored: got %q, want %q", got.ReviewedBy, "alice")
	}

	// 幂等：再次 approve 不应再次调用 circular
	_, err = es.Review(context.Background(), "evt-1", "approve", "", "", "Bearer tok", srv.URL)
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 circular call, got %d", calls)
	}
}

func TestReviewRejectDoesNotPush(t *testing.T) {
	es, st := newTestEventService(t, "")
	_, _ = st.CreateEvent(domain.Event{EventID: "evt-2", EventStatus: "round_finished", Severity: "low"})
	res, err := es.Review(context.Background(), "evt-2", "reject", "误报", "", "", "")
	if err != nil {
		t.Fatalf("review reject: %v", err)
	}
	if res["review_status"] != "rejected" {
		t.Fatalf("unexpected: %+v", res)
	}
	got, _ := st.GetEvent("evt-2")
	if got.ReviewStatus != "rejected" || got.ReviewComment != "误报" {
		t.Fatalf("event not updated: %+v", got)
	}
}

func TestReviewRejectsNonFinished(t *testing.T) {
	es, st := newTestEventService(t, "")
	_, _ = st.CreateEvent(domain.Event{EventID: "evt-3", EventStatus: "processing"})
	_, err := es.Review(context.Background(), "evt-3", "approve", "", "", "Bearer tok", "http://x")
	if err == nil {
		t.Fatal("expected guard error for non round_finished event")
	}
}
