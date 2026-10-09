package store

import (
	"fmt"
	"strings"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

// Normalize applies Beijing calendar windows; archiving never hides time-window results.
func (q EventQuery) Normalize(now time.Time) (EventQuery, error) {
	q.Scope = strings.ToLower(strings.TrimSpace(q.Scope))
	if q.Scope == "" {
		q.Scope = "all"
	}
	switch q.Scope {
	case "all", "archive", "active":
	case "today", "3", "7":
		if q.StartTime == nil && q.EndTime == nil {
			days := 1
			if q.Scope == "3" {
				days = 3
			}
			if q.Scope == "7" {
				days = 7
			}
			local := now.In(domain.Beijing)
			start := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, domain.Beijing).AddDate(0, 0, -(days - 1)).UTC()
			end := now.UTC()
			q.StartTime, q.EndTime = &start, &end
		}
	default:
		return q, fmt.Errorf("无效的事件查询范围: %s", q.Scope)
	}
	if q.StartTime != nil && q.EndTime != nil && !q.StartTime.Before(*q.EndTime) {
		return q, fmt.Errorf("开始时间必须早于结束时间")
	}
	if _, _, err := q.ArchiveRange(); err != nil {
		return q, err
	}
	return q, nil
}

func matchesEventTime(e domain.Event, q EventQuery) bool {
	t := domain.EventStartTime(e)
	return (q.StartTime == nil || !t.Before(*q.StartTime)) && (q.EndTime == nil || t.Before(*q.EndTime))
}
