package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/mq"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

const demoEventID = "demo-event-001"

// Options mirrors the original DeepSOC startup flags:
//
//	-init            => reset/create tables + default prompts + admin user
//	-init-with-demo  => init + demo data
//	-load_demo       => demo data only, requiring an existing schema
//
// It also initializes RabbitMQ topology when MQ_BACKEND=rabbitmq.
type Options struct {
	Init          bool
	InitWithDemo  bool
	LoadDemo      bool
	Reset         bool
	InitMQ        bool
	PublishDemoMQ bool
}

func Run(ctx context.Context, cfg config.Config, opts Options) error {
	if opts.InitWithDemo {
		opts.Init = true
		opts.Reset = true
		opts.LoadDemo = true
		opts.InitMQ = true
		opts.PublishDemoMQ = true
	}
	if cfg.StoreBackend == "" {
		cfg.StoreBackend = "mysql"
	}
	if cfg.StoreBackend != "mysql" {
		return fmt.Errorf("bootstrap currently requires STORE_BACKEND=mysql, got %q", cfg.StoreBackend)
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("DATABASE_URL is empty")
	}

	if opts.Reset {
		// Drop everything first on a plain (non-migrating) connection, so the
		// subsequent InitMySQL run re-creates the schema from scratch.
		resetDB, err := store.InitMySQL(ctx, cfg.DatabaseURL, false, 30)
		if err != nil {
			return err
		}
		log.Println("bootstrap: resetting database schema")
		err = ResetSchema(ctx, resetDB)
		_ = resetDB.Close()
		if err != nil {
			return err
		}
	}

	// InitMySQL waits for the server, creates the database when missing,
	// applies the full schema (store + ly_server compatibility tables) and
	// seeds the base data (admin user + ly_server reference data).
	log.Println("bootstrap: initializing mysql database (schema + base seed)")
	db, err := store.InitMySQL(ctx, cfg.DatabaseURL, true, 30)
	if err != nil {
		return err
	}
	defer db.Close()

	if opts.Init || opts.Reset {
		log.Println("bootstrap: seeding default prompts and admin user")
		if err := SeedBase(ctx, db); err != nil {
			return err
		}
	}
	if opts.LoadDemo {
		log.Println("bootstrap: loading demo data")
		if err := SeedDemo(ctx, db); err != nil {
			return err
		}
	}
	if opts.InitMQ && strings.EqualFold(cfg.MQBackend, "rabbitmq") {
		log.Println("bootstrap: initializing rabbitmq exchange/queue/bindings")
		if err := InitRabbitMQ(ctx, cfg); err != nil {
			return err
		}
	}
	if opts.PublishDemoMQ && strings.EqualFold(cfg.MQBackend, "rabbitmq") {
		log.Println("bootstrap: publishing demo event message to rabbitmq")
		if err := PublishDemoEvent(ctx, cfg); err != nil {
			return err
		}
	}
	return nil
}

// resetTables lists every table owned by the traffic module: the store
// tables (store.MySQLSchema) plus the ly_server compatibility tables
// (store.LyServerMySQLSchema). Order does not matter because foreign key
// checks are disabled while dropping.
var resetTables = []string{
	// store tables
	"audit_logs",
	"pushed_events",
	"sync_cursors",
	"event_maps",
	"summaries",
	"executions",
	"commands",
	"actions",
	"tasks",
	"messages",
	"events",
	"users",
	"prompts",
	"settings",
	"app_states",
	"traffic_assets",
	// ly_server compatibility tables
	"t_agent",
	"t_device",
	"t_user",
	"t_user_session",
	"t_config",
	"t_mogroup",
	"t_mo",
	"t_blacklist",
	"t_whitelist",
	"t_internal_ip_list",
	"t_internal_srv_list",
	"t_event_type",
	"t_event_level",
	"t_event_status",
	"t_event_action",
	"t_event_data",
	"t_event_data_aggre",
	"t_event_ignore",
	"t_asset_ip",
	"t_asset_srv",
	"t_asset_host",
	"t_asset_url",
}

// ResetSchema drops all traffic-module tables. MySQL has no cascading drop,
// so foreign key checks are toggled off on a single dedicated connection
// while the tables are dropped one by one.
func ResetSchema(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		return fmt.Errorf("disable foreign key checks: %w", err)
	}
	for _, table := range resetTables {
		if _, err := conn.ExecContext(ctx, "DROP TABLE IF EXISTS `"+table+"`"); err != nil {
			_, _ = conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
			return fmt.Errorf("drop table %s: %w", table, err)
		}
	}
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1"); err != nil {
		return fmt.Errorf("re-enable foreign key checks: %w", err)
	}
	return nil
}

func SeedBase(ctx context.Context, db *sql.DB) error {
	// prompts.role is the primary key, so the upsert below is keyed on it.
	for role, content := range service.DefaultPrompts {
		if _, err := db.ExecContext(ctx, `
INSERT INTO prompts (role, content, updated_at)
VALUES (?, ?, NOW(6))
ON DUPLICATE KEY UPDATE content=VALUES(content), updated_at=NOW(6)`, role, content); err != nil {
			return err
		}
	}

	_, err := db.ExecContext(ctx, `
INSERT INTO users (user_id, username, nickname, email, phone, password_hash, role, is_active, created_at, updated_at)
VALUES ('admin', 'admin', '管理员', 'admin@deepsoc.local', '18999990000', 'admin123', 'admin', true, NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE
  nickname=VALUES(nickname),
  email=VALUES(email),
  phone=VALUES(phone),
  password_hash=VALUES(password_hash),
  role=VALUES(role),
  is_active=true,
  updated_at=NOW(6)`)
	return err
}

func SeedDemo(ctx context.Context, db *sql.DB) error {
	observables, _ := json.Marshal([]map[string]string{
		{"type": "ip", "value": "66.240.205.34", "role": "source"},
		{"type": "ip", "value": "172.16.10.10", "role": "destination"},
	})
	contextData, _ := json.Marshal(map[string]any{
		"system_ref":       "demo",
		"ly_id":            "demo-ly-001",
		"event_type":       "Network Threat",
		"detail_type":      "SSH Brute Force",
		"detection_method": "rule",
		"occurrence_time":  time.Now().UTC().Format(time.RFC3339),
	})
	// review_comment is TEXT NOT NULL without a default in MySQL, so it must
	// be provided explicitly.
	_, err := db.ExecContext(ctx, `
INSERT INTO events (event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, review_comment, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,'',NOW(6),NOW(6))
ON DUPLICATE KEY UPDATE
  event_name=VALUES(event_name),
  title=VALUES(title),
  message=VALUES(message),
  context=VALUES(context),
  source=VALUES(source),
  severity=VALUES(severity),
  category=VALUES(category),
  event_status=VALUES(event_status),
  current_round=VALUES(current_round),
  observables=VALUES(observables),
  updated_at=NOW(6)`, demoEventID, "演示事件：公网 SSH 暴力破解", "演示事件：公网 SSH 暴力破解",
		"检测到 66.240.205.34 对 172.16.10.10 发起多次 SSH 登录尝试，疑似暴力破解。", string(contextData), "demo", "high", "Network Threat", "pending", 1, string(observables))
	if err != nil {
		return err
	}

	messages := []struct {
		ID      string
		From    string
		Type    string
		Content string
	}{
		{"demo-message-001", "system", "system_notification", `{"response_text":"系统创建了演示安全事件。"}`},
		{"demo-message-002", "_captain", "task_assignment", `{"response_text":"请先查询攻击源IP威胁情报和目标资产信息。"}`},
		{"demo-message-003", "queue-worker", "queue_notification", `{"response_text":"演示数据已初始化，等待异步任务处理。"}`},
	}
	for _, m := range messages {
		if _, err := db.ExecContext(ctx, `
INSERT INTO messages (message_id, event_id, user_id, user_nickname, message_from, message_type, message_content, round_id, created_at)
VALUES (?,?,'','',?,?,?,1,NOW(6))
ON DUPLICATE KEY UPDATE message_content=VALUES(message_content)`, m.ID, demoEventID, m.From, m.Type, m.Content); err != nil {
			return err
		}
	}

	tasks := []struct {
		ID, Name, Desc, Priority, Assigned string
	}{
		{"demo-task-001", "查询攻击源IP威胁情报", "查询 66.240.205.34 的威胁情报、地理位置和历史攻击记录。", "high", "_analyst"},
		{"demo-task-002", "查询目标资产信息", "查询 172.16.10.10 的资产负责人、业务归属和暴露面。", "medium", "_analyst"},
	}
	for _, t := range tasks {
		if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (task_id, event_id, task_name, task_description, task_status, task_priority, assigned_to, round_id, created_at, updated_at)
VALUES (?,?,?,?,'pending',?,?,1,NOW(6),NOW(6))
ON DUPLICATE KEY UPDATE task_name=VALUES(task_name), task_description=VALUES(task_description), updated_at=NOW(6)`, t.ID, demoEventID, t.Name, t.Desc, t.Priority, t.Assigned); err != nil {
			return err
		}
	}

	// execution_summary and ai_summary are TEXT NOT NULL without defaults in
	// MySQL, so they must be provided explicitly.
	_, err = db.ExecContext(ctx, `
INSERT INTO executions (execution_id, event_id, command_id, execution_status, execution_result, execution_summary, ai_summary, command_name, command_type, command_entity, command_params, created_at, updated_at)
VALUES ('demo-execution-001', ?, 'demo-command-001', 'pending', '', '', '', '威胁情报查询', 'playbook', '66.240.205.34', '{"ip":"66.240.205.34"}', NOW(6), NOW(6))
ON DUPLICATE KEY UPDATE updated_at=NOW(6)`, demoEventID)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO summaries (event_id, round_id, event_summary, created_at, updated_at)
VALUES (?, 1, '演示事件已初始化：发现公网IP对内部资产进行SSH暴力破解尝试，建议先完成情报和资产核查。', NOW(6), NOW(6))`, demoEventID)
	return err
}

func InitRabbitMQ(ctx context.Context, cfg config.Config) error {
	if strings.TrimSpace(cfg.RabbitMQURL) == "" {
		return fmt.Errorf("RABBITMQ_URL is empty")
	}
	conn, err := amqp.Dial(cfg.RabbitMQURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	exchange := firstNonEmpty(cfg.RabbitMQExchange, "traffic.events")
	queue := firstNonEmpty(cfg.RabbitMQEventQueue, "traffic.events.default")
	if err := ch.ExchangeDeclare(exchange, "topic", true, false, false, false, nil); err != nil {
		return err
	}
	if _, err := ch.QueueDeclare(queue, true, false, false, false, nil); err != nil {
		return err
	}
	for _, key := range []string{"event.*", "sync.*", "evidence.*", "task.*", "llm.*", "report.*"} {
		if err := ch.QueueBind(queue, key, exchange, false, nil); err != nil {
			return err
		}
	}
	return nil
}

func PublishDemoEvent(ctx context.Context, cfg config.Config) error {
	q, err := mq.NewRabbitMQ(ctx, mq.RabbitConfig{
		URL:      cfg.RabbitMQURL,
		Exchange: cfg.RabbitMQExchange,
		Queue:    cfg.RabbitMQEventQueue,
	})
	if err != nil {
		return err
	}
	defer q.Close()
	return q.Publish(ctx, "event.created", mq.EventMessage{
		Type:      "event.created",
		EventID:   demoEventID,
		Source:    "bootstrap-demo",
		Payload:   map[string]any{"message": "demo event initialized"},
		CreatedAt: time.Now().UTC(),
	})
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
