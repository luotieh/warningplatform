package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// TestInitMySQLEndToEnd 走一遍完整自动初始化：目标库事先不存在 →
// InitMySQL 自动建库 + 建表（store + ly_server 兼容表）+ 种子；随后
// 二次调用验证幂等（零 DDL 报错、种子不重复、既有数据存活）。
// TRAFFIC_TEST_MYSQL_DSN 为空时跳过；DSN 账号需具备 CREATE DATABASE 权限。
func TestInitMySQLEndToEnd(t *testing.T) {
	dsn := os.Getenv("TRAFFIC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TRAFFIC_TEST_MYSQL_DSN not set; skipping MySQL init e2e test")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.DBName += "_init_e2e"
	dbName := cfg.DBName

	// 确保目标库不存在，逼出自动建库路径；结束后清理。
	srvCfg := cfg.Clone()
	srvCfg.DBName = ""
	srv, err := sql.Open("mysql", srvCfg.FormatDSN())
	if err != nil {
		t.Fatalf("open server-level conn: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	dropStmt := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", strings.ReplaceAll(dbName, "`", "``"))
	if _, err := srv.Exec(dropStmt); err != nil {
		t.Fatalf("pre-drop database: %v", err)
	}
	t.Cleanup(func() { _, _ = srv.Exec(dropStmt) })

	ctx := context.Background()

	// 第一遍：建库 + 建表 + 种子。
	db, err := InitMySQL(ctx, cfg.FormatDSN(), true, 30)
	if err != nil {
		t.Fatalf("first InitMySQL: %v", err)
	}

	var tables int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?`, dbName).Scan(&tables); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if tables != 38 {
		t.Fatalf("expected 38 tables (16 store + 22 ly_server), got %d", tables)
	}

	assertCount := func(label, query string, want int) {
		t.Helper()
		var got int
		if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got != want {
			t.Fatalf("%s: want %d, got %d", label, want, got)
		}
	}
	assertCount("store admin seed", `SELECT COUNT(*) FROM users WHERE username='admin'`, 1)
	assertCount("ly admin seed", `SELECT COUNT(*) FROM t_user WHERE username='admin'`, 1)
	assertCount("ly event levels seed", `SELECT COUNT(*) FROM t_event_level`, 3)
	assertCount("ly default mogroup", `SELECT COUNT(*) FROM t_mogroup WHERE name='default'`, 1)

	// 埋一行业务数据，验证二次初始化不会破坏既有数据。
	if _, err := db.ExecContext(ctx, `
INSERT INTO events (event_id, event_name, title, message, context, source, severity, category,
                    event_status, current_round, observables, review_comment, created_at, updated_at)
VALUES ('e2e-marker', 'marker', 'marker', '', '{}', 'e2e', 'low', 'test', 'pending', 1, '[]', '', NOW(6), NOW(6))`); err != nil {
		t.Fatalf("insert marker event: %v", err)
	}
	_ = db.Close()

	// 第二遍：幂等。
	db2, err := InitMySQL(ctx, cfg.FormatDSN(), true, 30)
	if err != nil {
		t.Fatalf("second InitMySQL (idempotency): %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	db = db2

	assertCount("tables after rerun",
		fmt.Sprintf(`SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = '%s'`,
			strings.ReplaceAll(dbName, "'", "''")), 38)
	assertCount("admin seed not duplicated", `SELECT COUNT(*) FROM users WHERE username='admin'`, 1)
	assertCount("ly levels not duplicated", `SELECT COUNT(*) FROM t_event_level`, 3)
	assertCount("marker event survived", `SELECT COUNT(*) FROM events WHERE event_id='e2e-marker'`, 1)

	// 顺手验证 UTC 时间回环（DSN 未显式 loc 时驱动默认 UTC）。
	var createdAt time.Time
	if err := db.QueryRowContext(ctx,
		`SELECT created_at FROM events WHERE event_id='e2e-marker'`).Scan(&createdAt); err != nil {
		t.Fatalf("scan created_at: %v", err)
	}
	if d := time.Since(createdAt); d < 0 || d > 10*time.Minute {
		t.Fatalf("created_at looks wrong (timezone mismatch?): %s (delta %s)", createdAt, d)
	}

	// t_agent(ip) 唯一键存在，且同 IP upsert 刷新而非累积（对齐节点保存语义）。
	assertCount("t_agent unique key present", `
SELECT COUNT(*) FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 't_agent' AND INDEX_NAME = 'uq_t_agent_ip'`, 1)
	agentUpsert := `
INSERT INTO t_agent (name, ip, port, status, version, meta, updated_at)
VALUES (?,?,?,?,?,?,NOW(6))
ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), name=VALUES(name), port=VALUES(port),
status=VALUES(status), version=VALUES(version), meta=VALUES(meta), updated_at=NOW(6)`
	res1, err := db.ExecContext(ctx, agentUpsert, "node-a", "10.0.0.9", 8080, "running", "v1", "{}")
	if err != nil {
		t.Fatalf("first agent upsert: %v", err)
	}
	id1, _ := res1.LastInsertId()
	res2, err := db.ExecContext(ctx, agentUpsert, "node-a-renamed", "10.0.0.9", 9090, "running", "v2", "{}")
	if err != nil {
		t.Fatalf("second agent upsert: %v", err)
	}
	id2, _ := res2.LastInsertId()
	if id1 != id2 {
		t.Fatalf("agent upsert id changed: %d -> %d", id1, id2)
	}
	assertCount("same-ip agent rows", `SELECT COUNT(*) FROM t_agent WHERE ip='10.0.0.9'`, 1)
	assertCount("agent row refreshed", `SELECT COUNT(*) FROM t_agent WHERE ip='10.0.0.9' AND name='node-a-renamed' AND port=9090`, 1)
}

// TestInitMySQLBackfillsTAgentUniqueKey 模拟旧版建表 DDL 留下的存量库：
// 缺 uq_t_agent_ip 时再次 InitMySQL 自动补键；存量已有重复 ip 时告警放行
// （初始化不失败，键保持缺失待人工去重）。
func TestInitMySQLBackfillsTAgentUniqueKey(t *testing.T) {
	dsn := os.Getenv("TRAFFIC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TRAFFIC_TEST_MYSQL_DSN not set; skipping MySQL init e2e test")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.DBName += "_keyfix_e2e"
	dbName := cfg.DBName

	srvCfg := cfg.Clone()
	srvCfg.DBName = ""
	srv, err := sql.Open("mysql", srvCfg.FormatDSN())
	if err != nil {
		t.Fatalf("open server-level conn: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	dropStmt := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", strings.ReplaceAll(dbName, "`", "``"))
	if _, err := srv.Exec(dropStmt); err != nil {
		t.Fatalf("pre-drop database: %v", err)
	}
	t.Cleanup(func() { _, _ = srv.Exec(dropStmt) })

	ctx := context.Background()
	db, err := InitMySQL(ctx, cfg.FormatDSN(), true, 30)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keyCount := func() int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 't_agent' AND INDEX_NAME = 'uq_t_agent_ip'`).Scan(&n); err != nil {
			t.Fatalf("count key: %v", err)
		}
		return n
	}

	// 场景一：键被去掉（等价旧版 DDL 建的表）→ 再次 InitMySQL 自动补回。
	if _, err := db.ExecContext(ctx, "ALTER TABLE t_agent DROP KEY uq_t_agent_ip"); err != nil {
		t.Fatalf("drop key: %v", err)
	}
	if _, err := InitMySQL(ctx, cfg.FormatDSN(), true, 30); err != nil {
		t.Fatalf("re-init after key drop: %v", err)
	}
	if keyCount() != 1 {
		t.Fatalf("unique key not backfilled")
	}

	// 场景二：键缺失且存量有重复 ip → 初始化告警放行，键保持缺失。
	if _, err := db.ExecContext(ctx, "ALTER TABLE t_agent DROP KEY uq_t_agent_ip"); err != nil {
		t.Fatalf("drop key again: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.ExecContext(ctx, `
INSERT INTO t_agent (name, ip, port, status, version, meta, updated_at)
VALUES ('dup', '10.9.9.9', 1, 'running', 'v1', '{}', NOW(6))`); err != nil {
			t.Fatalf("insert dup row %d: %v", i, err)
		}
	}
	if _, err := InitMySQL(ctx, cfg.FormatDSN(), true, 30); err != nil {
		t.Fatalf("init with duplicate ip rows should not fail: %v", err)
	}
	if keyCount() != 0 {
		t.Fatalf("unique key should stay absent while duplicates exist")
	}
}
