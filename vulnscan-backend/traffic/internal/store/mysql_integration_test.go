package store

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"vulnscan-backend/traffic/internal/domain"
)

func TestMySQLConvergencePatchAndBeijingArchive(t *testing.T) {
	st, _ := newMySQLTestStore(t)
	last := time.Date(2026, 9, 14, 16, 5, 0, 0, time.UTC)
	_, err := st.CreateEvent(domain.Event{EventID: "quiet", LastSeenAt: &last})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ListEventsConvergedDue(last)) != 1 {
		t.Fatal("exact boundary excluded")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, ok := st.UpdateEvent("quiet", map[string]any{"event_status": "round_finished", "analysis_version": 2}); !ok {
				t.Error("analysis update failed")
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, ok := st.UpdateEvent("quiet", map[string]any{"aggregation_closed": true, "context": `{"occurrence_count":9}`, "last_seen_at": last.Format(time.RFC3339)}); !ok {
				t.Error("convergence update failed")
			}
		}
	}()
	wg.Wait()
	e, _ := st.GetEvent("quiet")
	if !e.AggregationClosed || e.Context != `{"occurrence_count":9}` || e.AnalysisVersion != 2 || !e.LastSeenAt.Equal(last) {
		t.Fatalf("concurrent patch lost fields: %+v", e)
	}
	if n, err := st.ArchiveConvergedEvents(last.Add(24*time.Hour), 10); err != nil || n != 1 {
		t.Fatalf("archive=%d %v", n, err)
	}
	e, _ = st.GetEvent("quiet")
	if e.ArchiveDate == nil || e.ArchiveDate.Format("2006-01-02") != "2026-09-15" {
		t.Fatalf("archive date is not Beijing day: %v", e.ArchiveDate)
	}
}

// newMySQLTestStore connects to the MySQL instance pointed at by
// TRAFFIC_TEST_MYSQL_DSN, drops all store tables and re-creates them from
// MySQLSchema. Tests are skipped when the env var is empty.
func newMySQLTestStore(t *testing.T) (*MySQLStore, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("TRAFFIC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TRAFFIC_TEST_MYSQL_DSN not set; skipping MySQL integration test")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MultiStatements = true
	cfg.ParseTime = true
	cfg.Loc = time.UTC

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	_, err = db.ExecContext(ctx, `
SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS messages, tasks, actions, commands, executions, summaries,
events, users, event_maps, sync_cursors, pushed_events, traffic_assets,
audit_logs, prompts, settings, app_states;
SET FOREIGN_KEY_CHECKS=1;`)
	if err != nil {
		t.Fatalf("drop tables: %v", err)
	}
	if _, err := db.ExecContext(ctx, MySQLSchema); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	return NewMySQLStore(db), db
}

func TestMySQLEventCRUD(t *testing.T) {
	st, _ := newMySQLTestStore(t)

	obs := []domain.IOC{
		{Type: "ip", Value: "1.2.3.4", Role: "src"},
		{Type: "domain", Value: "evil.example.com"},
	}
	createdAt := time.Date(2026, 7, 3, 8, 9, 10, 123456000, time.UTC)
	created, err := st.CreateEvent(domain.Event{
		EventID:     "evt-it-1",
		EventName:   "港口扫描",
		Message:     "suspicious scan",
		Severity:    "high",
		Observables: obs,
		CreatedAt:   createdAt,
	})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	if created.ID <= 0 {
		t.Fatalf("expected auto id, got %d", created.ID)
	}

	got, ok := st.GetEvent("evt-it-1")
	if !ok {
		t.Fatal("get event failed")
	}
	if got.ID != created.ID || got.Message != "suspicious scan" || got.Severity != "high" {
		t.Fatalf("event fields mismatch: %+v", got)
	}
	if len(got.Observables) != 2 || got.Observables[0].Value != "1.2.3.4" || got.Observables[1].Type != "domain" {
		t.Fatalf("observables did not round-trip: %+v", got.Observables)
	}
	// UTC 回环：DATETIME(6) 微秒精度，写入值按微秒对齐应精确相等
	if !got.CreatedAt.Equal(createdAt) {
		t.Fatalf("created_at round-trip mismatch: want %v got %v", createdAt, got.CreatedAt)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Fatalf("created_at not UTC: %v", got.CreatedAt.Location())
	}

	ts := time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	updated, ok := st.UpdateEvent("evt-it-1", map[string]any{
		"event_status":   "round_finished",
		"review_status":  "approved",
		"review_comment": "ok",
		"reviewed_by":    "alice",
		"reviewed_at":    ts,
		"circular_code":  "XF-2026-0001",
	})
	if !ok {
		t.Fatal("update event returned not ok")
	}
	if updated.EventStatus != "round_finished" || updated.ReviewStatus != "approved" ||
		updated.ReviewedBy != "alice" || updated.CircularCode != "XF-2026-0001" {
		t.Fatalf("patched fields missing: %+v", updated)
	}
	if updated.ReviewedAt == nil || !updated.ReviewedAt.Equal(time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("reviewed_at mismatch: %v", updated.ReviewedAt)
	}
	// UPDATE 会把 observables JSON 原样写回，验证 JSON 列经 UPDATE 后仍完整
	if len(updated.Observables) != 2 || updated.Observables[0].Value != "1.2.3.4" {
		t.Fatalf("observables lost after update: %+v", updated.Observables)
	}

	list := st.ListEvents()
	if len(list) != 1 || list[0].EventID != "evt-it-1" {
		t.Fatalf("list events mismatch: %+v", list)
	}

	if _, ok := st.UpdateEvent("evt-missing", map[string]any{"severity": "low"}); ok {
		t.Fatal("update of missing event should return not ok")
	}
}

func TestMySQLAssetUniqueAddress(t *testing.T) {
	st, _ := newMySQLTestStore(t)

	a, err := st.CreateAsset(domain.Asset{Name: "web-1", AssetType: "ip", Address: "10.0.0.9", Status: 1})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if a.ID == "" {
		t.Fatal("asset id not generated")
	}
	if _, err := st.CreateAsset(domain.Asset{Name: "web-dup", AssetType: "ip", Address: "10.0.0.9"}); err == nil {
		t.Fatal("expected duplicate address error")
	}
	if got := st.ListAssets(); len(got) != 1 {
		t.Fatalf("list assets want 1 got %d", len(got))
	}
}

func TestMySQLMessagesTasksCascade(t *testing.T) {
	st, db := newMySQLTestStore(t)

	if _, err := st.CreateEvent(domain.Event{EventID: "evt-cas-1", Message: "m"}); err != nil {
		t.Fatalf("create event: %v", err)
	}

	msg, err := st.AddMessage(domain.Message{EventID: "evt-cas-1", MessageFrom: "user", MessageContent: "hello"})
	if err != nil {
		t.Fatalf("add message: %v", err)
	}
	if msg.ID <= 0 || msg.MessageID == "" {
		t.Fatalf("message ids not assigned: %+v", msg)
	}
	// 外键：不存在的事件应报错
	if _, err := st.AddMessage(domain.Message{EventID: "evt-nope", MessageContent: "x"}); err == nil {
		t.Fatal("expected FK error for missing event")
	}

	task, err := st.AddTask(domain.Task{EventID: "evt-cas-1", TaskName: "调查", AssignedTo: "_operator"})
	if err != nil {
		t.Fatalf("add task: %v", err)
	}
	if task.TaskAssignee != "_operator" {
		t.Fatalf("task_assignee not backfilled: %+v", task)
	}

	msgs := st.ListMessages("evt-cas-1")
	if len(msgs) != 1 || msgs[0].MessageContent != "hello" {
		t.Fatalf("list messages mismatch: %+v", msgs)
	}
	tasks := st.ListTasks("evt-cas-1")
	if len(tasks) != 1 || tasks[0].TaskName != "调查" {
		t.Fatalf("list tasks mismatch: %+v", tasks)
	}

	// UpdateTask 使用重复占位符（同一值同时更新 assigned_to/task_assignee）
	up, ok := st.UpdateTask(task.TaskID, map[string]any{"task_status": "done"})
	if !ok || up.TaskStatus != "done" {
		t.Fatalf("update task failed: %+v ok=%v", up, ok)
	}
	if up.AssignedTo != "_operator" || up.TaskAssignee != "_operator" {
		t.Fatalf("empty patch must keep assignees: %+v", up)
	}
	up2, ok := st.UpdateTask(task.TaskID, map[string]any{"assigned_to": "_executor"})
	if !ok || up2.AssignedTo != "_executor" || up2.TaskAssignee != "_executor" {
		t.Fatalf("assigned_to patch must update both columns: %+v", up2)
	}

	// ON DELETE CASCADE：删除事件后 messages/tasks 应随之删除
	if _, err := db.ExecContext(context.Background(), `DELETE FROM events WHERE event_id=?`, "evt-cas-1"); err != nil {
		t.Fatalf("delete event: %v", err)
	}
	if got := st.ListMessages("evt-cas-1"); len(got) != 0 {
		t.Fatalf("messages not cascaded: %+v", got)
	}
	if got := st.ListTasks("evt-cas-1"); len(got) != 0 {
		t.Fatalf("tasks not cascaded: %+v", got)
	}
}

func TestMySQLSyncCursorUpsert(t *testing.T) {
	st, db := newMySQLTestStore(t)

	st.SaveCursor(domain.SyncCursor{Name: "ly", LastTS: "2026-01-01T00:00:00Z"})
	st.SaveCursor(domain.SyncCursor{Name: "ly", LastTS: "2026-02-02T00:00:00Z"})

	c := st.GetCursor("ly")
	if c.LastTS != "2026-02-02T00:00:00Z" {
		t.Fatalf("cursor not upserted: %+v", c)
	}
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sync_cursors WHERE name=?`, "ly").Scan(&n); err != nil {
		t.Fatalf("count cursors: %v", err)
	}
	if n != 1 {
		t.Fatalf("upsert must keep single row, got %d", n)
	}
	if got := st.GetCursor("missing"); got.Name != "missing" || got.LastTS != "" {
		t.Fatalf("missing cursor should return zero value with name: %+v", got)
	}
}

func TestMySQLTimeUTCRoundTrip(t *testing.T) {
	st, _ := newMySQLTestStore(t)

	at := time.Date(2026, 7, 3, 12, 34, 56, 789012000, time.UTC)
	if _, err := st.CreateEvent(domain.Event{EventID: "evt-utc-1", Message: "t", CreatedAt: at}); err != nil {
		t.Fatalf("create event: %v", err)
	}
	got, ok := st.GetEvent("evt-utc-1")
	if !ok {
		t.Fatal("get event failed")
	}
	if !got.CreatedAt.Equal(at) {
		t.Fatalf("created_at UTC round-trip mismatch: want %v got %v", at, got.CreatedAt)
	}
	if got.UpdatedAt.IsZero() || got.UpdatedAt.Location() != time.UTC {
		t.Fatalf("updated_at not UTC: %v", got.UpdatedAt)
	}

	st.SaveCursor(domain.SyncCursor{Name: "utc", LastTS: "x", UpdatedAt: at})
	c := st.GetCursor("utc")
	if !c.UpdatedAt.Equal(at) {
		t.Fatalf("cursor updated_at round-trip mismatch: want %v got %v", at, c.UpdatedAt)
	}
}
