package domain

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Beijing is the business timezone, independent of host timezone/tzdata.
var Beijing = time.FixedZone("Asia/Shanghai", 8*60*60)

const ConvergenceIdleWindow = 30 * time.Minute

// ParseEventTime interprets timestamps without an offset as Beijing time.
// Numeric packet timestamps support Unix seconds, milliseconds and microseconds.
func ParseEventTime(value any) time.Time {
	if value == nil {
		return time.Time{}
	}
	v := strings.TrimSpace(fmt.Sprint(value))
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		if n >= 1e14 {
			n /= 1e6
		} else if n >= 1e11 {
			n /= 1e3
		}
		return time.Unix(int64(n), int64((n-float64(int64(n)))*1e9)).UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t.UTC()
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, Beijing); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// LastActivity uses attack time; analysis/review updates never extend the window.
func LastActivity(e Event) time.Time {
	ctx := map[string]any{}
	_ = json.Unmarshal([]byte(e.Context), &ctx)
	for _, key := range []string{"last_time", "occurrence_time"} {
		if t := ParseEventTime(ctx[key]); !t.IsZero() {
			return t
		}
	}
	if e.LastSeenAt != nil {
		return e.LastSeenAt.UTC()
	}
	if t := ParseEventTime(ctx["last_seen_at"]); !t.IsZero() {
		return t
	}
	return e.CreatedAt
}

func IsConverged(e Event, now time.Time) bool {
	last := LastActivity(e)
	return e.AggregationClosed || e.ArchiveDate != nil || (!last.IsZero() && !now.Before(last.Add(ConvergenceIdleWindow)))
}
