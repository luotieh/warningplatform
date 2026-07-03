package store

const MySQLSchema = `
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) UNIQUE NOT NULL,
    username VARCHAR(64) UNIQUE NOT NULL,
    nickname VARCHAR(128) NOT NULL DEFAULT '',
    email VARCHAR(255) NOT NULL DEFAULT '',
    phone VARCHAR(64) NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    last_login_at DATETIME(6) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(128) UNIQUE NOT NULL,
    event_name VARCHAR(256) NOT NULL DEFAULT '',
    title VARCHAR(256) NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    context TEXT NOT NULL,
    source VARCHAR(64) NOT NULL DEFAULT '',
    severity VARCHAR(32) NOT NULL DEFAULT 'medium',
    category VARCHAR(128) NOT NULL DEFAULT '',
    event_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    current_round INTEGER NOT NULL DEFAULT 1,
    observables JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    review_status VARCHAR(32) NOT NULL DEFAULT '',
    review_comment TEXT NOT NULL,
    reviewed_by VARCHAR(128) NOT NULL DEFAULT '',
    reviewed_at DATETIME(6) NULL,
    circular_code VARCHAR(70) NOT NULL DEFAULT '',
    KEY idx_events_created_at (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(128) UNIQUE NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(128) NOT NULL DEFAULT '',
    user_nickname VARCHAR(128) NOT NULL DEFAULT '',
    message_from VARCHAR(64) NOT NULL DEFAULT '',
    message_type VARCHAR(64) NOT NULL DEFAULT '',
    message_category VARCHAR(32) NOT NULL DEFAULT 'agent',
    sender_type VARCHAR(32) NOT NULL DEFAULT 'agent',
    chat_session_id VARCHAR(128) NOT NULL DEFAULT '',
    message_content TEXT NOT NULL,
    round_id INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_messages_event_id (event_id, id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tasks (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(128) UNIQUE NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    task_name VARCHAR(256) NOT NULL DEFAULT '',
    task_type VARCHAR(64) NOT NULL DEFAULT '',
    task_description TEXT NOT NULL,
    task_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    task_priority VARCHAR(32) NOT NULL DEFAULT '',
    assigned_to VARCHAR(128) NOT NULL DEFAULT '',
    task_assignee VARCHAR(128) NOT NULL DEFAULT '',
    round_id INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_tasks_event_id (event_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS actions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    action_id VARCHAR(128) UNIQUE NOT NULL,
    task_id VARCHAR(128) NOT NULL DEFAULT '',
    event_id VARCHAR(128) NOT NULL,
    round_id INTEGER NOT NULL DEFAULT 1,
    action_name VARCHAR(256) NOT NULL DEFAULT '',
    action_type VARCHAR(64) NOT NULL DEFAULT '',
    action_assignee VARCHAR(128) NOT NULL DEFAULT '',
    action_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    action_result TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_actions_event_id (event_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS commands (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    command_id VARCHAR(128) UNIQUE NOT NULL,
    action_id VARCHAR(128) NOT NULL DEFAULT '',
    task_id VARCHAR(128) NOT NULL DEFAULT '',
    event_id VARCHAR(128) NOT NULL,
    round_id INTEGER NOT NULL DEFAULT 1,
    command_name VARCHAR(256) NOT NULL DEFAULT '',
    command_type VARCHAR(64) NOT NULL DEFAULT '',
    command_assignee VARCHAR(128) NOT NULL DEFAULT '',
    command_entity TEXT NOT NULL,
    command_params TEXT NOT NULL,
    command_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    command_result TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_commands_event_id (event_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS executions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    execution_id VARCHAR(128) UNIQUE NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    task_id VARCHAR(128) NOT NULL DEFAULT '',
    action_id VARCHAR(128) NOT NULL DEFAULT '',
    round_id INTEGER NOT NULL DEFAULT 1,
    command_id VARCHAR(128) NOT NULL DEFAULT '',
    execution_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    execution_result TEXT NOT NULL,
    execution_summary TEXT NOT NULL,
    ai_summary TEXT NOT NULL,
    command_name VARCHAR(256) NOT NULL DEFAULT '',
    command_type VARCHAR(64) NOT NULL DEFAULT '',
    command_entity VARCHAR(256) NOT NULL DEFAULT '',
    command_params TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_executions_event_id (event_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS summaries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(128) NOT NULL,
    round_id INTEGER NOT NULL DEFAULT 1,
    event_summary TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_summaries_event_id (event_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS event_maps (
    fingerprint VARCHAR(128) PRIMARY KEY,
    ly_event_id VARCHAR(128) NOT NULL DEFAULT '',
    deepsoc_event_id VARCHAR(128) NOT NULL DEFAULT '',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sync_cursors (
    name VARCHAR(64) PRIMARY KEY,
    last_ts VARCHAR(128) NOT NULL DEFAULT '',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS pushed_events (
    ly_event_id VARCHAR(128) PRIMARY KEY,
    idempotency_key VARCHAR(128) UNIQUE NOT NULL,
    deepsoc_event_id VARCHAR(128) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_pushed_events_idempotency_key (idempotency_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS traffic_assets (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(256) NOT NULL DEFAULT '',
    asset_type VARCHAR(32) NOT NULL DEFAULT 'ip',
    address VARCHAR(256) UNIQUE NOT NULL,
    unit VARCHAR(128) NOT NULL DEFAULT '',
    owner VARCHAR(128) NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 1,
    remark TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor VARCHAR(128) NOT NULL DEFAULT 'unknown',
    action VARCHAR(64) NOT NULL DEFAULT '',
    target VARCHAR(256) NOT NULL DEFAULT '',
    meta TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_audit_logs_created_at (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS prompts (
    role VARCHAR(64) PRIMARY KEY,
    content TEXT NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
    ` + "`key`" + ` VARCHAR(128) PRIMARY KEY,
    value JSON NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS app_states (
    ` + "`key`" + ` VARCHAR(128) PRIMARY KEY,
    value JSON NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
