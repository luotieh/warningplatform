package store

import (
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

func TestMemoryStoreUpdateEventReviewFields(t *testing.T) {
	s := NewMemoryStore()
	created, err := s.CreateEvent(domain.Event{EventID: "evt-review-1", EventStatus: "round_finished"})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	updated, ok := s.UpdateEvent(created.EventID, map[string]any{
		"review_status":  "approved",
		"review_comment": "ok",
		"reviewed_by":    "alice",
		"reviewed_at":    ts,
		"circular_code":  "XF-2026-0001",
	})
	if !ok {
		t.Fatal("update returned not ok")
	}
	if updated.ReviewStatus != "approved" || updated.ReviewComment != "ok" ||
		updated.ReviewedBy != "alice" || updated.CircularCode != "XF-2026-0001" {
		t.Fatalf("review fields not patched: %+v", updated)
	}
	if updated.ReviewedAt == nil {
		t.Fatal("reviewed_at not set")
	}
}
