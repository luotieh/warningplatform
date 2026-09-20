package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"vulnscan-backend/traffic/internal/store"
)

func TestAggregationMySQLTwoHundredThousandHits(t *testing.T) {
	if os.Getenv("TRAFFIC_AGGREGATION_SCALE") != "1" {
		t.Skip("opt-in 200k hit integration fixture")
	}
	cfg, err := mysql.ParseDSN(os.Getenv("TRAFFIC_AGGREGATION_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.DBName, "_test") || !strings.HasPrefix(cfg.Addr, "127.0.0.1:") {
		t.Fatal("local *_test database required")
	}
	cfg.ParseTime = true
	cfg.MultiStatements = true
	cfg.Loc = time.UTC
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err = db.Exec(store.MySQLSchema); err != nil {
		t.Fatal(err)
	}
	st := store.NewMySQLStore(db)
	svc := Services{Store: st}
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	tag := fmt.Sprint(time.Now().UnixNano())
	m := testHit("scale-"+tag, base)
	m["event_type"] = "scale-" + tag
	ev := LyEventToDeepSOC(m)
	ev.EventID = "scale-" + tag
	if _, err = st.CreateEvent(ev); err != nil {
		t.Fatal(err)
	}
	const count = 200000
	fp := Fingerprint(m)
	started := time.Now()
	for offset := 0; offset < count; offset += 500 {
		values := make([]string, 0, 500)
		args := make([]any, 0, 4500)
		for i := offset; i < offset+500; i++ {
			at := base.Add(time.Duration(i) * time.Millisecond)
			sample := testHit(fmt.Sprintf("%s-%d", tag, i), at)
			sample["event_type"] = m["event_type"]
			h, _, reason := normalizeHit(sample, time.Now().UTC())
			if reason != "" {
				t.Fatal(reason)
			}
			values = append(values, "(?,?,?,?,?,?,?,?)")
			args = append(args, h.ID, h.DedupKey, h.Identity, fp, ev.EventID, h.OccurredAt, h.ReceivedAt, string(h.Raw))
		}
		_, err = db.ExecContext(ctx, "INSERT INTO traffic_event_hits(hit_id,dedup_key,identity_digest,aggregate_key,origin_event_id,occurred_at,received_at,raw_json) VALUES "+strings.Join(values, ","), args...)
		if err != nil {
			t.Fatal(err)
		}
	}
	var watermark int64
	if err = db.QueryRow("SELECT MAX(sequence) FROM traffic_event_hits WHERE origin_event_id=?", ev.EventID).Scan(&watermark); err != nil {
		t.Fatal(err)
	}
	seg := EventSegment{EventID: ev.EventID, CanonicalID: ev.EventID, Sources: []string{ev.EventID}, AggregateKey: fp, First: base, Last: base.Add((count - 1) * time.Millisecond), Version: 1, Watermark: watermark, Count: count, Created: base}
	if err = putRecord(ctx, st, "segment", seg.EventID, fp, seg); err != nil {
		t.Fatal(err)
	}
	ingestElapsed := time.Since(started)
	started = time.Now()
	if err = svc.RebuildAggregation(ctx, seg.EventID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := svc.EvidenceSnapshot(ctx, seg.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	stats := snapshot.Context["quant_stats"].(map[string]any)
	peak := stats["peak_window"].(map[string]any)
	if snapshot.Count != count || toInt(peak["count"]) != count {
		t.Fatalf("full stats wrong: %d %v", snapshot.Count, peak)
	}
	page, err := svc.Occurrences(ctx, seg.EventID, "", "", 200)
	if err != nil || len(page.Items) != 200 || page.NextCursor == "" {
		t.Fatalf("paging: %v %d", err, len(page.Items))
	}
	projection, _ := json.Marshal(snapshot.Context)
	if len(projection) > 60000 {
		t.Fatalf("unbounded event projection: %d", len(projection))
	}
	t.Logf("200k hits: fixture=%s snapshot=%s projection=%d bytes", ingestElapsed, time.Since(started), len(projection))
}
