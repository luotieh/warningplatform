package service

import (
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// 已收敛事件再次收到命中：收敛标记重开 + 归档日清空（拉回今日视图）。
func TestMergeOccurrenceReopensConvergedEvent(t *testing.T) {
	st := store.NewMemoryStore()
	last := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	d := time.Now().UTC().AddDate(0, 0, -1)
	created, _ := st.CreateEvent(domain.Event{
		EventID:           "evt-reopen",
		EventName:         "已收敛事件",
		AggregationClosed: true,
		ArchiveDate:       &d,
		LastSeenAt:        timePtr(last),
		Context:           `{"occurrence_count":1,"first_time":"2026-08-11T00:00:00Z","last_time":"2026-08-11T01:00:00Z","occurrences":[],"last_seen_at":"` + last + `"}`,
	})
	svc := Services{Store: st}
	svc.mergeOccurrence(created.EventID, map[string]any{
		"occurrence_time": time.Now().UTC().Format(time.RFC3339),
		"device_id":       "node-x",
		"evidence_files":  []any{},
	})
	got, _ := st.GetEvent("evt-reopen")
	if got.AggregationClosed {
		t.Fatal("aggregation_closed should be reopened to false")
	}
	if got.ArchiveDate != nil {
		t.Fatalf("archive_date should be cleared, got %v", got.ArchiveDate)
	}
}

func timePtr(v string) *time.Time {
	t, _ := time.Parse(time.RFC3339, v)
	return &t
}
