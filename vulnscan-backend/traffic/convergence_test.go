package traffic

import (
	"encoding/json"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

func TestConvergencePresentationUsesLastAttackInBeijing(t *testing.T) {
	e := domain.Event{EventID: "historical", AggregationClosed: true, UpdatedAt: time.Now(), Context: `{"first_time":"2026-09-14T15:50:00Z","last_time":"2026-09-14T16:05:00Z","occurrence_count":2}`}
	got := lyCompatibleEvent(e)
	if got["converged_at"] != "2026-09-15T00:05:00+08:00" || got["first_time"] != "2026-09-14T23:50:00+08:00" {
		t.Fatalf("wrong Beijing times: %v", got)
	}
	if got["duration"] != int64(900) || got["is_active"] != false || got["is_final"] != true {
		t.Fatal("quiet period included in attack duration or closed state wrong")
	}
}

func TestActivePresentationDoesNotExposeConvergenceTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	raw, _ := json.Marshal(map[string]any{"first_time": now.Add(-10 * time.Minute).Format(time.RFC3339), "last_time": now.Add(-time.Minute).Format(time.RFC3339), "occurrence_count": 1})
	got := lyCompatibleEvent(domain.Event{Context: string(raw)})
	if got["is_final"] != false || got["converged_at"] != nil || got["is_active"] != true {
		t.Fatal("active event shown as converged")
	}
	if d := got["duration"].(int64); d < 600 || d > 602 {
		t.Fatalf("ongoing duration=%d", d)
	}
}
