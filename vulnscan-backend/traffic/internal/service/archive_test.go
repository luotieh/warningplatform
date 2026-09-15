package service

import (
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// 收敛后的历史事件不可重开，次数、证据和归档日期保持不变。
func TestMergeOccurrencePreservesConvergedEvent(t *testing.T) {
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
	if !got.AggregationClosed {
		t.Fatal("aggregation_closed must remain true")
	}
	if got.ArchiveDate == nil || !got.ArchiveDate.Equal(d) || got.Context != created.Context {
		t.Fatal("historical event was modified")
	}
}

func timePtr(v string) *time.Time {
	t, _ := time.Parse(time.RFC3339, v)
	return &t
}
