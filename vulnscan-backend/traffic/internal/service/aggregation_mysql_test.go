package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"vulnscan-backend/traffic/internal/store"
)

func TestAggregationMySQLTransactions(t *testing.T) {
	dsn := os.Getenv("TRAFFIC_AGGREGATION_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated TRAFFIC_AGGREGATION_TEST_DSN not configured")
	}
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasSuffix(cfg.DBName, "_test") || (!strings.HasPrefix(cfg.Addr, "127.0.0.1:") && !strings.HasPrefix(cfg.Addr, "localhost:")) {
		t.Fatal("integration tests require a local *_test database")
	}
	cfg.MultiStatements = true
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	db, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(16)
	if _, e = db.Exec(store.MySQLSchema); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	st := store.NewMySQLStore(db)
	svc := Services{Store: st}
	batch := fmt.Sprint(time.Now().UnixNano())
	m := testHit("sql-"+batch, time.Now().UTC().Add(-48*time.Hour))
	m["device_id"] = batch
	m["event_type"] = "sql-" + batch
	// Execute the same hit concurrently in two independent OS processes.
	// Their connection pools and process-local locks cannot coordinate dedup.
	raw, _ := json.Marshal(m)
	children := []*exec.Cmd{}
	for i := 0; i < 2; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAggregationMySQLChildProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), "TRAFFIC_AGGREGATION_CHILD_HIT="+string(raw))
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		children = append(children, cmd)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := svc.ProcessLyEvent(ctx, m); errs <- e }()
	}
	wg.Wait()
	for _, cmd := range children {
		if e := cmd.Wait(); e != nil {
			t.Fatal(e)
		}
	}
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	h, _, reason := normalizeHit(m, time.Now().UTC())
	if reason != "" {
		t.Fatal(reason)
	}
	stored, ok, e := st.FindHit(ctx, h.DedupKey)
	if e != nil || !ok {
		t.Fatal(e)
	}
	if e = svc.RebuildAggregation(ctx, stored.EventID); e != nil {
		t.Fatal(e)
	}
	snap, e := svc.EvidenceSnapshot(ctx, stored.EventID, 0)
	if e != nil || snap.Count != 1 {
		t.Fatalf("%v count=%d", e, snap.Count)
	}
	// Roll back an inserted hit and verify it cannot be acknowledged/retrieved.
	fake := h
	fake.ID = "hit-" + digest(batch)
	fake.DedupKey = digest(batch)
	fake.EventID = stored.EventID
	sentinel := fmt.Errorf("fault injection")
	e = st.AggregationTransaction(ctx, "rollback-"+batch, func(tx store.Store) error {
		if _, e := tx.InsertHit(ctx, fake); e != nil {
			return e
		}
		return sentinel
	})
	if e != sentinel {
		t.Fatal(e)
	}
	if _, ok, e = st.FindHit(ctx, fake.DedupKey); e != nil || ok {
		t.Fatal("rollback left a hit")
	}
	// A fresh repository instance (new process semantics) sees durable dedup.
	otherDB, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	defer otherDB.Close()
	other := Services{Store: store.NewMySQLStore(otherDB)}
	res, e := other.ProcessLyEvent(ctx, m)
	if e != nil || res["duplicate"] != true {
		t.Fatalf("restart dedup: %v %v", res, e)
	}
}

func TestAggregationMySQLChildProcess(t *testing.T) {
	raw := os.Getenv("TRAFFIC_AGGREGATION_CHILD_HIT")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	cfg, err := mysql.ParseDSN(os.Getenv("TRAFFIC_AGGREGATION_TEST_DSN"))
	if err != nil || !strings.HasSuffix(cfg.DBName, "_test") || !strings.HasPrefix(cfg.Addr, "127.0.0.1:") {
		t.Fatal("local *_test database required")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var m map[string]any
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	svc := Services{Store: store.NewMySQLStore(db)}
	for i := 0; i < 10; i++ {
		if _, err = svc.ProcessLyEvent(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
}
