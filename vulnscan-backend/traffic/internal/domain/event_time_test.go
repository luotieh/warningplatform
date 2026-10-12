package domain

import (
	"testing"
	"time"
)

func TestEventTimeFormatsAndQuietBoundary(t *testing.T) {
	want := time.Date(2026, 9, 14, 16, 30, 0, 0, time.UTC)
	for _, v := range []any{"2026-09-15 00:30:00", "2026-09-15T00:30:00", "2026-09-15T00:30:00+08:00", "2026-09-14T16:30:00Z", want.Unix(), want.UnixMilli(), want.UnixMicro()} {
		if got := ParseEventTime(v); !got.Equal(want) {
			t.Errorf("%v = %v want %v", v, got, want)
		}
	}
	e := Event{Context: `{"last_time":"2026-09-15 00:30:00"}`, UpdatedAt: want.Add(24 * time.Hour)}
	if IsConverged(e, want.Add(30*time.Minute-time.Nanosecond)) || !IsConverged(e, want.Add(30*time.Minute)) {
		t.Fatal("incorrect quiet boundary")
	}
	if !LastActivity(e).Equal(want) {
		t.Fatal("analysis timestamp changed activity")
	}
}

func TestStaleSnapshotDoesNotPrematurelyConverge(t *testing.T) {
	now := time.Now().UTC()
	latest := now.Add(-5 * time.Minute)
	e := Event{Context: `{"last_time":"2026-01-01T00:00:00Z"}`, LastSeenAt: &latest}
	if !LastActivity(e).Equal(latest) || IsConverged(e, now) {
		t.Fatal("old statistics overrode latest activity")
	}
	if IsConverged(e, latest.Add(ConvergenceIdleWindow-time.Nanosecond)) || !IsConverged(e, latest.Add(ConvergenceIdleWindow)) {
		t.Fatal("incorrect 30-minute boundary")
	}
}
