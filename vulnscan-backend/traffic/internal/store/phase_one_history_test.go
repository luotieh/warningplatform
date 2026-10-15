package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

func TestPhaseOneHistoryExactRelationPagination(t *testing.T) {
	st := NewMemoryStore()
	end := time.Date(2026, 10, 13, 4, 34, 18, 0, time.UTC)
	at := end.Add(-time.Hour)
	for i := 0; i < 260; i++ {
		c := map[string]any{"src_ip": "192.0.2.1", "dst_ip": "203.0.113.1", "device_id": "node", "ioc": map[string]any{"ioc_type": "ip", "ioc_value": "203.0.113.1"}}
		if i < 230 {
			c["dst_ip"] = "203.0.113.99"
		}
		if i == 230 {
			c["device_id"] = "other"
		}
		if i == 231 {
			c["dst_ip"] = "8.8.8.8"
			c["app"] = map[string]any{"dns_answers": []string{"203.0.113.1"}}
		}
		b, _ := json.Marshal(c)
		_, err := st.CreateEvent(domain.Event{EventID: fmt.Sprintf("e%03d", i), CreatedAt: at, LastSeenAt: &at, Context: string(b)})
		if err != nil {
			t.Fatal(err)
		}
	}
	q := HistoryQuery{Start: end.Add(-24 * time.Hour), End: end, DeviceID: "node", ExactRelations: []HistoryRelation{{Address: "192.0.2.1", IOC: domain.IOC{Type: "ip", Value: "203.0.113.1"}}}, Limit: 10}
	rows, err := st.HistoryCandidates(context.Background(), q)
	if err != nil || len(rows) != 10 {
		t.Fatal(err, len(rows))
	}
	q.BeforeTime = at
	q.AfterID = rows[9].EventID
	next, err := st.HistoryCandidates(context.Background(), q)
	if err != nil || len(next) != 10 || next[0].EventID <= rows[9].EventID {
		t.Fatal("keyset", err, next)
	}
	sql, args, err := historySQL(q)
	if err != nil || !strings.Contains(sql, "event_id>?") || strings.Contains(sql, "203.0.113.1") || strings.Contains(sql, "JSON_CONTAINS(observables") {
		t.Fatal("exact SQL leaked broad OR", err, sql)
	}
	if args[len(args)-1] != 10 {
		t.Fatal(args)
	}
}
