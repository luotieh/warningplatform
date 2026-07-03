package store

import (
	"context"
	"database/sql"
	"fmt"
)

// LyServerMySQLSchema mirrors the original ly_server t_* data model closely
// enough for the Go-native /d/* replacement, expressed as MySQL 8.0 DDL.
// It keeps the original table names (t_user, t_mo, t_event_data, ...) so the
// final deployment remains MySQL + RabbitMQ + Go only.
//
// Unique keys are part of the DML contract with the lyserver handlers
// (upserts rely on them): t_agent(ip), t_mo(moip,moport,protocol),
// t_device(devid), t_config(key), t_blacklist(value), t_whitelist(value),
// t_user_session(token), t_user(username), t_mogroup(name),
// t_internal_ip_list(cidr).
// t_agent(ip) 对齐原始 ly_server MariaDB dump 的 UNIQUE KEY ip；早期版本建表
// 遗漏该键，dbinit 的 ensureLySchemaUpgrades 会对存量库幂等补齐。
const LyServerMySQLSchema = `
CREATE TABLE IF NOT EXISTS t_agent (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL DEFAULT '',
    ip VARCHAR(64) NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'running',
    version VARCHAR(64) NOT NULL DEFAULT '',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_t_agent_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_device (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL DEFAULT '',
    devid VARCHAR(128) UNIQUE NOT NULL,
    ip VARCHAR(64) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'online',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_user (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL DEFAULT '',
    role VARCHAR(64) NOT NULL DEFAULT 'admin',
    nickname VARCHAR(128) NOT NULL DEFAULT '',
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_user_session (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    token VARCHAR(255) UNIQUE NOT NULL,
    remote_addr VARCHAR(128) NOT NULL DEFAULT '',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_config (
    ` + "`key`" + ` VARCHAR(128) PRIMARY KEY,
    value JSON NOT NULL,
    description TEXT NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_mogroup (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_mo (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    moip VARCHAR(64) NOT NULL,
    moport VARCHAR(32) NOT NULL DEFAULT '0',
    protocol VARCHAR(32) NOT NULL DEFAULT '',
    pip VARCHAR(64) NOT NULL DEFAULT '',
    pport VARCHAR(32) NOT NULL DEFAULT '',
    modesc TEXT NOT NULL,
    tag VARCHAR(128) NOT NULL DEFAULT '',
    mogroupid BIGINT NOT NULL DEFAULT 1,
    filter TEXT NOT NULL,
    devid VARCHAR(128) NOT NULL DEFAULT '',
    direction VARCHAR(32) NOT NULL DEFAULT 'ALL',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE(moip, moport, protocol),
    KEY idx_t_mo_moip (moip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_blacklist (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    value VARCHAR(256) UNIQUE NOT NULL,
    value_type VARCHAR(32) NOT NULL DEFAULT 'ip',
    description TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_whitelist (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    value VARCHAR(256) UNIQUE NOT NULL,
    value_type VARCHAR(32) NOT NULL DEFAULT 'ip',
    description TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_internal_ip_list (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    cidr VARCHAR(64) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_internal_srv_list (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(64) NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    protocol VARCHAR(32) NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE(ip, port, protocol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_type (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_level (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) UNIQUE NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'medium'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_status (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) UNIQUE NOT NULL,
    description TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_action (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_data (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(128) UNIQUE NOT NULL,
    event_type VARCHAR(128) NOT NULL DEFAULT '',
    detail_type VARCHAR(128) NOT NULL DEFAULT '',
    event_level VARCHAR(64) NOT NULL DEFAULT '中',
    rule_desc TEXT NOT NULL,
    threat_source VARCHAR(128) NOT NULL DEFAULT '',
    victim_target VARCHAR(128) NOT NULL DEFAULT '',
    method VARCHAR(128) NOT NULL DEFAULT '',
    occurrence_time DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    duration INTEGER NOT NULL DEFAULT 0,
    processing_status VARCHAR(64) NOT NULL DEFAULT 'pending',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    raw JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_t_event_data_time (occurrence_time DESC),
    KEY idx_t_event_data_src_dst (threat_source, victim_target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_data_aggre (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    aggre_key VARCHAR(256) UNIQUE NOT NULL,
    event_type VARCHAR(128) NOT NULL DEFAULT '',
    event_count INTEGER NOT NULL DEFAULT 0,
    threat_source VARCHAR(128) NOT NULL DEFAULT '',
    victim_target VARCHAR(128) NOT NULL DEFAULT '',
    first_time DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_time DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    severity VARCHAR(32) NOT NULL DEFAULT 'medium',
    raw JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_t_event_data_aggre_time (last_time DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_event_ignore (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    rule_key VARCHAR(256) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_asset_ip (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(64) UNIQUE NOT NULL,
    asset_name VARCHAR(256) NOT NULL DEFAULT '',
    owner VARCHAR(128) NOT NULL DEFAULT '',
    business VARCHAR(128) NOT NULL DEFAULT '',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_t_asset_ip_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_asset_srv (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(64) NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    protocol VARCHAR(32) NOT NULL DEFAULT '',
    service_name VARCHAR(128) NOT NULL DEFAULT '',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE(ip, port, protocol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_asset_host (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(256) UNIQUE NOT NULL,
    ip VARCHAR(64) NOT NULL DEFAULT '',
    os VARCHAR(128) NOT NULL DEFAULT '',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS t_asset_url (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    host VARCHAR(256) NOT NULL DEFAULT '',
    title VARCHAR(256) NOT NULL DEFAULT '',
    meta JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

// lyServerSeedStatements is the ly_server reference/config vocabulary seed,
// split into single statements so it can run on a connection pool that does
// not enable multiStatements.
var lyServerSeedStatements = []string{
	`INSERT INTO t_user (username, password, role, nickname, enabled)
VALUES ('admin', 'admin', 'admin', '管理员', true)
ON DUPLICATE KEY UPDATE role=VALUES(role), enabled=true, updated_at=NOW(6)`,

	// Inserting an explicit id into the AUTO_INCREMENT column is valid MySQL;
	// the mo handlers default mogroupid to 1, so the row must exist with id=1.
	`INSERT INTO t_mogroup (id, name, description)
VALUES (1, 'default', '默认资产组')
ON DUPLICATE KEY UPDATE description=VALUES(description), updated_at=NOW(6)`,

	`INSERT IGNORE INTO t_internal_ip_list (cidr, description)
VALUES ('172.16.0.0/12', '默认内网地址段')`,

	`INSERT INTO t_event_type (name, description)
VALUES ('Network Threat', '网络威胁')
ON DUPLICATE KEY UPDATE description=VALUES(description)`,

	`INSERT INTO t_event_level (name, severity)
VALUES ('高', 'high'), ('中', 'medium'), ('低', 'low')
ON DUPLICATE KEY UPDATE severity=VALUES(severity)`,

	`INSERT INTO t_event_status (name, description)
VALUES ('pending', '待处理'), ('processing', '处理中'), ('closed', '已关闭')
ON DUPLICATE KEY UPDATE description=VALUES(description)`,

	`INSERT INTO t_event_action (name, description)
VALUES ('investigate', '调查'), ('block', '封禁'), ('ignore', '忽略')
ON DUPLICATE KEY UPDATE description=VALUES(description)`,
}

// SeedLyServerReferenceData seeds only the reference/config vocabulary the
// ly_server-compatible schema needs to function (bootstrap admin, default
// asset group, internal network segment, and the event taxonomies). It
// intentionally does NOT seed any fabricated security data (agents, probes,
// threat events, assets) so the UI only ever shows real, runtime-ingested
// data. All statements are idempotent.
//
// Note: the bootstrap admin row is created with a placeholder password.
// Rotating it / enforcing first-login password change is a separate security
// task.
func SeedLyServerReferenceData(ctx context.Context, db *sql.DB) error {
	for _, stmt := range lyServerSeedStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("seed ly_server reference data (%.40s...): %w", stmt, err)
		}
	}
	return nil
}
