package service

import (
	"encoding/json"
	"hash/fnv"
	"sync"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

// Services is copied by value. Shared bounded locks coordinate ingestion and
// the scheduler in this backend process, without accumulating per-event locks.
var fingerprintLocks [256]sync.Mutex
var eventLocks [256]sync.Mutex

func lifecycleLock(locks *[256]sync.Mutex, key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &locks[h.Sum32()%256]
}

func activityTime(ly map[string]any) time.Time {
	for _, key := range []string{"occurrence_time", "time", "packet_time_usec"} {
		if t := domain.ParseEventTime(ly[key]); !t.IsZero() {
			return t
		}
	}
	return time.Now().UTC()
}

// Caller holds the event lock. The business end time is the last attack,
// whereas convergence is detected only after the following 30 quiet minutes.
func (s Services) closeEvent(ev domain.Event) bool {
	if ev.AggregationClosed {
		return true
	}
	ctx := decodeEventContext(ev.Context)
	freezeQuantStats(ctx)
	last := domain.LastActivity(ev)
	ctx["converged_at"] = last.UTC().Format(time.RFC3339Nano)
	ctx["last_seen_at"] = last.UTC().Format(time.RFC3339Nano)
	raw, _ := json.Marshal(ctx)
	_, ok := s.Store.UpdateEvent(ev.EventID, map[string]any{
		"context": string(raw), "aggregation_closed": true,
		"last_seen_at": last.UTC().Format(time.RFC3339Nano),
	})
	if ok && ev.AnalysisVersion < 2 {
		s.RunFinalAnalysisAsync(ev.EventID)
	}
	return ok
}
