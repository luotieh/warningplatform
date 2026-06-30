package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestLyCompatibleEventIncludesReviewFields(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{
		EventID:      "evt-1",
		EventStatus:  "round_finished",
		ReviewStatus: "approved",
		CircularCode: "XF-1",
	})
	if row["review_status"] != "approved" {
		t.Fatalf("review_status=%v", row["review_status"])
	}
	if row["circular_code"] != "XF-1" {
		t.Fatalf("circular_code=%v", row["circular_code"])
	}
}

func TestLyCompatibleEventDefaultReviewStatus(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{EventID: "evt-2", EventStatus: "processing"})
	if row["review_status"] != "" {
		t.Fatalf("expected empty review_status, got %v", row["review_status"])
	}
}
