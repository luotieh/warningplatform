package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

const (
	dbInitDefaultWaitSeconds = 30
	dbInitBackoffStart       = 500 * time.Millisecond
	dbInitBackoffMax         = 5 * time.Second
)

// InitMySQL opens the shared MySQL 8.0 connection pool for the traffic
// module, waiting for the server to come up, creating the database when
// missing and — when autoMigrate is true — applying the full schema
// (MySQLSchema + LyServerMySQLSchema) and the idempotent base seeds.
//
// The DSN must be a go-sql-driver DSN including a database name, e.g.
// "user:pass@tcp(127.0.0.1:3306)/traffic?parseTime=true". parseTime is
// forced on when absent. waitSeconds bounds the total time spent waiting
// for the server (<=0 means 30).
func InitMySQL(ctx context.Context, dsn string, autoMigrate bool, waitSeconds int) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("traffic: mysql DSN is empty (set DATABASE_URL, e.g. user:pass@tcp(host:3306)/traffic?parseTime=true)")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("traffic: parse mysql DSN: %w", err)
	}
	if strings.TrimSpace(cfg.DBName) == "" {
		return nil, errors.New("traffic: mysql DSN must include a database name (e.g. user:pass@tcp(host:3306)/traffic)")
	}
	if !cfg.ParseTime {
		log.Printf("traffic: mysql DSN does not set parseTime=true, forcing it on (required to scan DATETIME columns)")
		cfg.ParseTime = true
	}
	cfg.Loc = time.UTC
	// Re-materialize the DSN so every derived connection uses the normalized form.
	cfg, err = mysql.ParseDSN(cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("traffic: normalize mysql DSN: %w", err)
	}

	if waitSeconds <= 0 {
		waitSeconds = dbInitDefaultWaitSeconds
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(waitSeconds)*time.Second)
	defer cancel()

	log.Printf("traffic: waiting for mysql at %s (database %q, timeout %ds)", cfg.Addr, cfg.DBName, waitSeconds)

	var (
		db      *sql.DB
		lastErr error
	)
	backoff := dbInitBackoffStart
	for {
		// Best-effort database creation: even when it fails (e.g. the account
		// has no server-level privileges) the target database may already have
		// been provisioned by a DBA, so we still try to connect to it.
		ensureErr := ensureMySQLDatabase(waitCtx, cfg)
		pool, connErr := openMySQLPool(waitCtx, cfg)
		if connErr == nil {
			db = pool
			break
		}
		lastErr = connErr
		if ensureErr != nil {
			lastErr = fmt.Errorf("%w (ensure database: %v)", connErr, ensureErr)
		}
		log.Printf("traffic: mysql not ready yet, retrying in %s: %v", backoff, lastErr)
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("traffic: mysql at %s (database %q) not ready within %ds: %w", cfg.Addr, cfg.DBName, waitSeconds, lastErr)
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > dbInitBackoffMax {
			backoff = dbInitBackoffMax
		}
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if autoMigrate {
		if err := migrateMySQLSchema(ctx, cfg); err != nil {
			_ = db.Close()
			return nil, err
		}
		if err := ensureLySchemaUpgrades(ctx, db); err != nil {
			_ = db.Close()
			return nil, err
		}
		if err := ensureTrafficSchemaUpgrades(ctx, db); err != nil {
			_ = db.Close()
			return nil, err
		}
		if err := seedMySQLBaseData(ctx, db); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	log.Printf("traffic: mysql store ready (database %q)", cfg.DBName)
	return db, nil
}

// ensureMySQLDatabase connects without a default schema and creates the
// target database when it does not exist yet. Missing CREATE privileges
// (MySQL errors 1044/1142) are logged and tolerated: the database may have
// been pre-created by a DBA.
func ensureMySQLDatabase(ctx context.Context, cfg *mysql.Config) error {
	srvCfg := cfg.Clone()
	srvCfg.DBName = ""
	srv, err := sql.Open("mysql", srvCfg.FormatDSN())
	if err != nil {
		return fmt.Errorf("open server-level mysql connection: %w", err)
	}
	defer srv.Close()
	if err := srv.PingContext(ctx); err != nil {
		return fmt.Errorf("ping mysql server: %w", err)
	}

	log.Printf("traffic: ensuring database %q exists", cfg.DBName)
	stmt := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		strings.ReplaceAll(cfg.DBName, "`", "``"),
	)
	if _, err := srv.ExecContext(ctx, stmt); err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && (me.Number == 1044 || me.Number == 1142) {
			log.Printf("traffic: no privilege to create database %q (mysql error %d), assuming it is pre-created: %v", cfg.DBName, me.Number, err)
			return nil
		}
		return fmt.Errorf("create database %q: %w", cfg.DBName, err)
	}
	return nil
}

// openMySQLPool opens the runtime connection pool against the target
// database and verifies connectivity.
func openMySQLPool(ctx context.Context, cfg *mysql.Config) (*sql.DB, error) {
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open mysql pool: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database %q: %w", cfg.DBName, err)
	}
	return db, nil
}

// migrateMySQLSchema applies the store schema and the ly_server
// compatibility schema on a dedicated short-lived connection with
// multiStatements enabled, so the runtime pool never allows multi-statement
// execution.
func migrateMySQLSchema(ctx context.Context, cfg *mysql.Config) error {
	log.Printf("traffic: migrating schema (store tables + ly_server compatibility tables)")
	migCfg := cfg.Clone()
	migCfg.MultiStatements = true
	mig, err := sql.Open("mysql", migCfg.FormatDSN())
	if err != nil {
		return fmt.Errorf("traffic: open migration connection: %w", err)
	}
	defer mig.Close()
	if _, err := mig.ExecContext(ctx, MySQLSchema); err != nil {
		return fmt.Errorf("traffic: apply store schema: %w", err)
	}
	if _, err := mig.ExecContext(ctx, LyServerMySQLSchema); err != nil {
		return fmt.Errorf("traffic: apply ly_server compatibility schema: %w", err)
	}
	return nil
}

// ensureTrafficSchemaUpgrades applies idempotent column additions for tables
// created by older revisions of MySQLSchema (CREATE TABLE IF NOT EXISTS never
// alters an existing table). New columns introduced by the quantitative
// analysis design: events(analysis_version/aggregation_closed/last_analysis_at)
// and summaries(version/kind).
func ensureTrafficSchemaUpgrades(ctx context.Context, db *sql.DB) error {
	type colDef struct {
		table  string
		column string
		ddl    string
	}
	defs := []colDef{
		{"events", "analysis_version", "ALTER TABLE events ADD COLUMN analysis_version INTEGER NOT NULL DEFAULT 0"},
		{"events", "aggregation_closed", "ALTER TABLE events ADD COLUMN aggregation_closed TINYINT(1) NOT NULL DEFAULT 0"},
		{"events", "last_analysis_at", "ALTER TABLE events ADD COLUMN last_analysis_at DATETIME(6) NULL"},
		{"events", "last_seen_at", "ALTER TABLE events ADD COLUMN last_seen_at DATETIME(6) NULL"},
		{"events", "archive_date", "ALTER TABLE events ADD COLUMN archive_date DATE NULL COMMENT '逻辑归档日（Asia/Shanghai 自然日，NULL=未归档/今日视图）'"},
		{"summaries", "version", "ALTER TABLE summaries ADD COLUMN version INTEGER NOT NULL DEFAULT 1"},
		{"summaries", "kind", "ALTER TABLE summaries ADD COLUMN kind VARCHAR(32) NOT NULL DEFAULT 'initial'"},
	}
	for _, d := range defs {
		var n int
		if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
			d.table, d.column).Scan(&n); err != nil {
			return fmt.Errorf("traffic: check column %s.%s: %w", d.table, d.column, err)
		}
		if n > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, d.ddl); err != nil {
			var me *mysql.MySQLError
			if errors.As(err, &me) && me.Number == 1060 { // 列已存在（并发初始化）
				continue
			}
			return fmt.Errorf("traffic: %s: %w", d.ddl, err)
		}
		log.Printf("traffic: added missing column %s.%s", d.table, d.column)
	}
	// 归档日索引（旧库补建；重复键名 1061 容忍）。
	var idxCount int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'events' AND INDEX_NAME = 'idx_events_archive_date'`).Scan(&idxCount); err != nil {
		return fmt.Errorf("traffic: check events archive_date index: %w", err)
	}
	if idxCount == 0 {
		if _, err := db.ExecContext(ctx,
			"ALTER TABLE events ADD KEY idx_events_archive_date (archive_date, created_at DESC)"); err != nil {
			var me *mysql.MySQLError
			if !(errors.As(err, &me) && me.Number == 1061) {
				return fmt.Errorf("traffic: add events archive_date index: %w", err)
			}
		}
		log.Printf("traffic: added missing index events.idx_events_archive_date")
	}
	// 存量事件回填 last_seen_at（升级前该字段只存在 context JSON 中）。
	if _, err := db.ExecContext(ctx, `
UPDATE events
SET last_seen_at = STR_TO_DATE(JSON_UNQUOTE(JSON_EXTRACT(context, '$.last_seen_at')), '%Y-%m-%dT%H:%i:%s.%fZ')
WHERE last_seen_at IS NULL AND JSON_EXTRACT(context, '$.last_seen_at') IS NOT NULL`); err != nil {
		return fmt.Errorf("traffic: backfill events.last_seen_at: %w", err)
	}
	return nil
}

// ensureLySchemaUpgrades applies idempotent fixups for tables created by
// older revisions of the DDL — CREATE TABLE IF NOT EXISTS never alters an
// existing table. Currently: t_agent(ip) 唯一键（对齐原始 ly_server dump 的
// UNIQUE KEY ip，早期建表 DDL 遗漏）。存量数据已有重复 ip 时仅告警放行，
// 人工去重后重启即可获得约束。
func ensureLySchemaUpgrades(ctx context.Context, db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 't_agent' AND INDEX_NAME = 'uq_t_agent_ip'`).Scan(&n); err != nil {
		return fmt.Errorf("traffic: check t_agent(ip) unique key: %w", err)
	}
	if n > 0 {
		return nil
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE t_agent ADD UNIQUE KEY uq_t_agent_ip (ip)"); err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) {
			switch me.Number {
			case 1062: // 存量重复 ip，无法加键：告警放行，不阻塞启动
				log.Printf("traffic: cannot add unique key t_agent(ip) because duplicate ip rows exist; please dedupe manually (keep the newest row per ip) and restart: %v", err)
				return nil
			case 1061: // 键已存在（并发初始化等）：视为成功
				return nil
			}
		}
		return fmt.Errorf("traffic: add unique key t_agent(ip): %w", err)
	}
	log.Printf("traffic: added missing unique key uq_t_agent_ip on t_agent(ip)")
	return nil
}

// seedMySQLBaseData seeds the default admin account and the ly_server
// reference data through the runtime pool. Every statement is idempotent.
func seedMySQLBaseData(ctx context.Context, db *sql.DB) error {
	log.Printf("traffic: seeding default admin user and ly_server reference data")
	if _, err := db.ExecContext(ctx, `
INSERT IGNORE INTO users (user_id, username, nickname, email, phone, password_hash, role, is_active)
VALUES ('admin', 'admin', '管理员', 'admin@example.local', '', 'admin', 'admin', 1)`); err != nil {
		return fmt.Errorf("traffic: seed admin user: %w", err)
	}
	if err := SeedLyServerReferenceData(ctx, db); err != nil {
		return fmt.Errorf("traffic: %w", err)
	}
	return nil
}
