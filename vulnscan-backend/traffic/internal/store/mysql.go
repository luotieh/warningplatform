package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

type MySQLStore struct {
	db sqlRunner
}

type sqlRunner interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var _ Store = (*MySQLStore)(nil)

// NewMySQLStore wraps an already-opened *sql.DB. Connection setup,
// migration and seeding are the caller's responsibility.
func NewMySQLStore(db *sql.DB) *MySQLStore {
	return &MySQLStore{db: db}
}

func (s *MySQLStore) CreateUser(u domain.User) (domain.User, error) {
	if u.UserID == "" {
		u.UserID = newID("u")
	}
	if u.Role == "" {
		u.Role = "user"
	}
	if u.Password == "" {
		u.Password = "ChangeMe123!"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	u.UpdatedAt = time.Now().UTC()
	u.IsActive = true
	u.LastLoginAt = nil
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO users (user_id, username, nickname, email, phone, password_hash, role, is_active, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?)`,
		u.UserID, u.Username, u.Nickname, u.Email, u.Phone, u.Password, u.Role, true, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return domain.User{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		u.ID = id
	}
	return u, nil
}

func (s *MySQLStore) GetUserByUsername(username string) (domain.User, bool) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, user_id, username, nickname, email, phone, password_hash, role, last_login_at, is_active, created_at, updated_at
FROM users WHERE username=?`, username)
	u, err := scanUser(row)
	return u, err == nil
}

func (s *MySQLStore) GetUser(userID string) (domain.User, bool) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, user_id, username, nickname, email, phone, password_hash, role, last_login_at, is_active, created_at, updated_at
FROM users WHERE user_id=?`, userID)
	u, err := scanUser(row)
	return u, err == nil
}

func (s *MySQLStore) ListUsers() []domain.User {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, user_id, username, nickname, email, phone, password_hash, role, last_login_at, is_active, created_at, updated_at
FROM users ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []domain.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err == nil {
			out = append(out, u)
		}
	}
	return out
}

func (s *MySQLStore) UpdateUser(userID string, patch map[string]any) (domain.User, bool) {
	u, ok := s.GetUser(userID)
	if !ok {
		return domain.User{}, false
	}
	if v, ok := stringPatch(patch, "nickname"); ok {
		u.Nickname = v
	}
	if v, ok := stringPatch(patch, "email"); ok {
		u.Email = v
	}
	if v, ok := stringPatch(patch, "phone"); ok {
		u.Phone = v
	}
	if v, ok := stringPatch(patch, "role"); ok {
		u.Role = v
	}
	if v, ok := boolPatch(patch, "is_active"); ok {
		u.IsActive = v
	}
	if v, ok := stringPatch(patch, "password"); ok {
		u.Password = v
	}
	if t, ok := timePatch(patch, "last_login_at"); ok {
		u.LastLoginAt = t
	}
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(context.Background(), `
UPDATE users
SET nickname=?, email=?, phone=?, password_hash=?, role=?, last_login_at=?, is_active=?, updated_at=?
WHERE user_id=?`,
		u.Nickname, u.Email, u.Phone, u.Password, u.Role, u.LastLoginAt, u.IsActive, u.UpdatedAt, userID)
	if err != nil {
		return domain.User{}, false
	}
	return s.GetUser(userID)
}

func (s *MySQLStore) DeleteUser(userID string) bool {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM users WHERE user_id=?`, userID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *MySQLStore) CreateEvent(e domain.Event) (domain.Event, error) {
	if e.EventID == "" {
		e.EventID = newID("evt")
	}
	if e.Severity == "" {
		e.Severity = "medium"
	}
	if e.Source == "" {
		e.Source = "manual"
	}
	if e.EventStatus == "" {
		e.EventStatus = "pending"
	}
	if e.CurrentRound == 0 {
		e.CurrentRound = 1
	}
	now := time.Now().UTC()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	// Review fields start at their zero values on insert; mirror that in the
	// returned struct so it matches the row actually stored.
	e.ReviewStatus = ""
	e.ReviewComment = ""
	e.ReviewedBy = ""
	e.ReviewedAt = nil
	e.CircularCode = ""
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO events (event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, circular_code, analysis_version, aggregation_closed, last_seen_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.EventID, e.EventName, e.Title, e.Message, e.Context, e.Source, e.Severity, e.Category, e.EventStatus, e.CurrentRound, string(toJSON(e.Observables)), e.CreatedAt, e.UpdatedAt, e.ReviewStatus, e.ReviewComment, e.ReviewedBy, e.CircularCode, e.AnalysisVersion, e.AggregationClosed, e.LastSeenAt)
	if err != nil {
		return domain.Event{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		e.ID = id
	}
	return e, nil
}

func (s *MySQLStore) GetEvent(eventID string) (domain.Event, bool) {
	query := `
SELECT id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code, analysis_version, aggregation_closed, last_analysis_at, last_seen_at, archive_date
FROM events WHERE event_id=?`
	if _, ok := s.db.(*sql.Tx); ok {
		query += " FOR UPDATE"
	}
	row := s.db.QueryRowContext(context.Background(), query, eventID)
	e, err := scanEvent(row)
	return e, err == nil
}

func (s *MySQLStore) ListEvents() []domain.Event {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code, analysis_version, aggregation_closed, last_analysis_at, last_seen_at, archive_date
FROM events ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []domain.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

const eventSelectCols = `id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code, analysis_version, aggregation_closed, last_analysis_at, last_seen_at, archive_date`

// ListEventsPage 服务端分页/过滤查询：today=未归档、archive=归档日期范围（可选）、all=全量。
func (s *MySQLStore) ListEventsPage(q EventQuery) (EventPage, error) {
	from, to, err := q.ArchiveRange()
	if err != nil {
		return EventPage{}, err
	}
	where := []string{"(CASE WHEN JSON_VALID(context) THEN COALESCE(JSON_UNQUOTE(JSON_EXTRACT(context, '$.canonical_event_id')), event_id) ELSE event_id END) = event_id"}
	args := []any{}
	switch strings.ToLower(strings.TrimSpace(q.Scope)) {
	case "", "today":
		where = append(where, "archive_date IS NULL")
	case "archive":
		where = append(where, "archive_date IS NOT NULL")
		if from != "" {
			where = append(where, "archive_date >= ?")
			args = append(args, from)
		}
		if to != "" {
			where = append(where, "archive_date <= ?")
			args = append(args, to)
		}
	case "all":
	default:
		where = append(where, "archive_date IS NULL")
	}
	if v := strings.TrimSpace(q.Level); v != "" {
		where = append(where, "severity = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(q.Keyword); v != "" {
		kw := "%" + escapeLike(v) + "%"
		where = append(where, "(event_name LIKE ? OR title LIKE ? OR message LIKE ? OR context LIKE ?)")
		args = append(args, kw, kw, kw, kw)
	}
	if v := strings.TrimSpace(q.Asset); v != "" {
		asset := "%" + escapeLike(v) + "%"
		where = append(where, "(context LIKE ? OR observables LIKE ?)")
		args = append(args, asset, asset)
	}
	if q.StartTime != nil {
		where = append(where, eventFilterTimeSQL()+" >= ?")
		args = append(args, *q.StartTime)
	}
	if q.EndTime != nil {
		where = append(where, eventFilterTimeSQL()+" < ?")
		args = append(args, *q.EndTime)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM events"+whereSQL, args...).Scan(&total); err != nil {
		return EventPage{}, err
	}
	page, pageSize := normalizePage(q.Page, q.PageSize)
	orderBy := eventOrderBy(q)
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+eventSelectCols+" FROM events"+whereSQL+
			" ORDER BY "+orderBy+" LIMIT ? OFFSET ?",
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	out := make([]domain.Event, 0, pageSize)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return EventPage{Items: out, Total: total}, nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	return page, pageSize
}

// eventOrderBy 把 EventQuery.Sort/Order 翻译为 SQL 排序子句。
// payload 与 frequency 取自 context JSON（quant_stats.total_payload_bytes / occurrence_count），
// 缺失（旧事件）或 context 非合法 JSON（手工创建）时按 0 处理；同值以时间倒序兜底。
func eventOrderBy(q EventQuery) string {
	dir := strings.ToLower(strings.TrimSpace(q.Order))
	if dir != "asc" && dir != "desc" {
		dir = "desc"
	}
	dir = strings.ToUpper(dir)
	jsonNum := func(path string) string {
		return "CASE WHEN JSON_VALID(context) THEN " +
			"CAST(JSON_UNQUOTE(JSON_EXTRACT(context, '" + path + "')) AS UNSIGNED) ELSE 0 END"
	}
	switch strings.ToLower(strings.TrimSpace(q.Sort)) {
	case "payload":
		return "CASE WHEN JSON_VALID(context) THEN CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(context,'$.quant_stats.volume_quality'))='unverified' THEN 1 ELSE 0 END ELSE 0 END ASC, " + jsonNum("$.quant_stats.total_payload_bytes") + " " + dir +
			", created_at DESC, id DESC"
	case "frequency":
		return jsonNum("$.occurrence_count") + " " + dir +
			", created_at DESC, id DESC"
	default:
		return "created_at " + dir + ", id DESC"
	}
}

func eventFilterTimeSQL() string {
	return "CASE WHEN JSON_VALID(context) AND JSON_UNQUOTE(JSON_EXTRACT(context,'$.aggregation_version'))='2' THEN COALESCE(STR_TO_DATE(REPLACE(SUBSTRING(JSON_UNQUOTE(JSON_EXTRACT(context,'$.first_time')),1,19),'T',' '),'%Y-%m-%d %H:%i:%s'),created_at) ELSE created_at END"
}

// ArchiveConvergedEvents 把已收敛且最后活跃早于阈值的未归档事件标记归档日
// （archive_date = last_seen_at 所在自然日）。返回本次处理条数。
func (s *MySQLStore) ArchiveConvergedEvents(threshold time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 500
	}
	res, err := s.db.ExecContext(context.Background(), `
UPDATE events
SET archive_date = DATE(DATE_ADD(last_seen_at, INTERVAL 8 HOUR)), updated_at = NOW(6)
WHERE aggregation_closed = 1
  AND last_seen_at IS NOT NULL
  AND last_seen_at < ?
  AND archive_date IS NULL
ORDER BY last_seen_at ASC
LIMIT ?`, threshold, batchSize)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *MySQLStore) SaveArchiveJob(job domain.ArchiveJob) (domain.ArchiveJob, error) {
	now := time.Now().UTC()
	if job.JobID == "" {
		job.JobID = newID("arc")
	}
	if job.Status == "" {
		job.Status = "running"
	}
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO archive_jobs (job_id, period, status, total, processed, error, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
  status=VALUES(status), total=VALUES(total), processed=VALUES(processed),
  error=VALUES(error), updated_at=VALUES(updated_at)`,
		job.JobID, job.Period, job.Status, job.Total, job.Processed, job.Error, now, now)
	if err != nil {
		return domain.ArchiveJob{}, err
	}
	saved, ok := s.GetArchiveJob(job.JobID)
	if !ok {
		return domain.ArchiveJob{}, errors.New("archive job not found after save")
	}
	return saved, nil
}

func (s *MySQLStore) GetArchiveJob(jobID string) (domain.ArchiveJob, bool) {
	var j domain.ArchiveJob
	err := s.db.QueryRowContext(context.Background(), `
SELECT id, job_id, period, status, total, processed, error, created_at, updated_at
FROM archive_jobs WHERE job_id=?`, jobID).
		Scan(&j.ID, &j.JobID, &j.Period, &j.Status, &j.Total, &j.Processed, &j.Error, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return domain.ArchiveJob{}, false
	}
	return j, true
}

// ListEventsConvergedDue 返回已到期收敛但未标记的事件（MySQL 条件查询，替代全表扫描）。
func (s *MySQLStore) ListEventsConvergedDue(threshold time.Time) []domain.Event {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code, analysis_version, aggregation_closed, last_analysis_at, last_seen_at, archive_date
FROM events
WHERE aggregation_closed = 0 AND (last_seen_at IS NOT NULL AND last_seen_at <= ?)
ORDER BY last_seen_at ASC
LIMIT 500`, threshold)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

// ListEventsByTargetIP 按目标 IP（context.dst_ip / victim_target）与 last_seen_at
// 时间窗口查询事件（月度总结用）。
func (s *MySQLStore) ListEventsByTargetIP(ip string, from time.Time, to time.Time) []domain.Event {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, event_id, event_name, title, message, context, source, severity, category, event_status, current_round, observables, created_at, updated_at, review_status, review_comment, reviewed_by, reviewed_at, circular_code, analysis_version, aggregation_closed, last_analysis_at, last_seen_at, archive_date
FROM events
WHERE (JSON_UNQUOTE(JSON_EXTRACT(context, '$.dst_ip')) = ?
       OR JSON_UNQUOTE(JSON_EXTRACT(context, '$.victim_target')) = ?)
  AND last_seen_at IS NOT NULL AND last_seen_at >= ? AND last_seen_at < ?
ORDER BY last_seen_at DESC
LIMIT 1000`, ip, ip, from, to)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *MySQLStore) UpdateEvent(eventID string, patch map[string]any) (domain.Event, bool) {
	// Write only supplied columns: background analysis must never restore stale
	// aggregation/context/last_seen values read before a concurrent attack.
	columns := []string{}
	args := []any{}
	add := func(key string, value any) { columns = append(columns, key+"=?"); args = append(args, value) }
	for _, key := range []string{"event_name", "message", "context", "severity", "event_status", "review_status", "review_comment", "reviewed_by", "circular_code"} {
		if v, ok := stringPatch(patch, key); ok {
			add(key, v)
		}
	}
	for _, key := range []string{"reviewed_at", "last_analysis_at", "last_seen_at"} {
		if v, ok := patch[key]; ok && v == nil {
			add(key, nil)
		} else if v, ok := stringPatch(patch, key); ok {
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				add(key, t.UTC())
			}
		}
	}
	if v, ok := intPatch(patch, "analysis_version"); ok {
		add("analysis_version", v)
	}
	if v, ok := boolPatch(patch, "aggregation_closed"); ok {
		add("aggregation_closed", v)
	}
	if v, ok := patch["archive_date"]; ok {
		if v == nil {
			add("archive_date", nil)
		} else if t, ok := v.(time.Time); ok {
			add("archive_date", t)
		} else if str, ok := v.(string); ok {
			if t, err := time.Parse("2006-01-02", str); err == nil {
				add("archive_date", t)
			}
		}
	}
	add("updated_at", time.Now().UTC())
	args = append(args, eventID)
	_, err := s.db.ExecContext(context.Background(), "UPDATE events SET "+strings.Join(columns, ",")+" WHERE event_id=?", args...)
	if err != nil {
		return domain.Event{}, false
	}
	return s.GetEvent(eventID)
}

func (s *MySQLStore) AddMessage(m domain.Message) (domain.Message, error) {
	m = domain.NormalizeMessage(m)
	if m.MessageID == "" {
		m.MessageID = newID("msg")
	}
	if m.RoundID == 0 {
		m.RoundID = 1
	}
	if m.MessageCategory == "" {
		m.MessageCategory = "agent"
	}
	if m.SenderType == "" {
		m.SenderType = "agent"
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO messages (message_id, event_id, user_id, user_nickname, message_from, message_type, message_category, sender_type, chat_session_id, message_content, round_id, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		m.MessageID, m.EventID, m.UserID, m.UserNickname, m.MessageFrom, m.MessageType, m.MessageCategory, m.SenderType, m.ChatSessionID, m.MessageContent, m.RoundID, m.CreatedAt)
	if err != nil {
		return domain.Message{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		m.ID = id
	}
	return m, nil
}

func (s *MySQLStore) ListMessages(eventID string) []domain.Message {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, message_id, event_id, user_id, user_nickname, message_from, message_type, message_category, sender_type, chat_session_id, message_content, round_id, created_at
FROM messages WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []domain.Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err == nil && !domain.IsInternalMessage(m) {
			out = append(out, domain.NormalizeMessage(m))
		}
	}
	return out
}

func (s *MySQLStore) AddTask(t domain.Task) (domain.Task, error) {
	if t.TaskID == "" {
		t.TaskID = newID("task")
	}
	if t.TaskStatus == "" {
		t.TaskStatus = "pending"
	}
	if t.RoundID == 0 {
		t.RoundID = 1
	}
	if t.TaskAssignee == "" {
		t.TaskAssignee = t.AssignedTo
	}
	if t.AssignedTo == "" {
		t.AssignedTo = t.TaskAssignee
	}
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO tasks (task_id, event_id, task_name, task_type, task_description, task_status, task_priority, assigned_to, task_assignee, round_id, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.TaskID, t.EventID, t.TaskName, t.TaskType, t.TaskDescription, t.TaskStatus, t.TaskPriority, t.AssignedTo, t.TaskAssignee, t.RoundID, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return domain.Task{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		t.ID = id
	}
	return t, nil
}

func (s *MySQLStore) UpdateTask(taskID string, patch map[string]any) (domain.Task, bool) {
	status, _ := stringPatch(patch, "task_status")
	assigned, _ := stringPatch(patch, "assigned_to")
	// The same value patches both assigned_to and task_assignee, so the
	// placeholder is passed twice (MySQL consumes ? positionally).
	_, err := s.db.ExecContext(context.Background(), `
UPDATE tasks SET
task_status=COALESCE(NULLIF(?,''), task_status),
assigned_to=COALESCE(NULLIF(?,''), assigned_to),
task_assignee=COALESCE(NULLIF(?,''), task_assignee),
updated_at=NOW(6)
WHERE task_id=?`,
		status, assigned, assigned, taskID)
	if err != nil {
		return domain.Task{}, false
	}
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, task_id, event_id, task_name, task_type, task_description, task_status, task_priority, assigned_to, task_assignee, round_id, created_at, updated_at
FROM tasks WHERE task_id=?`, taskID)
	t, err := scanTask(row)
	return t, err == nil
}

func (s *MySQLStore) ListTasks(eventID string) []domain.Task {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, task_id, event_id, task_name, task_type, task_description, task_status, task_priority, assigned_to, task_assignee, round_id, created_at, updated_at
FROM tasks WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []domain.Task{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err == nil {
			out = append(out, t)
		}
	}
	return out
}

func (s *MySQLStore) AddAction(a domain.Action) (domain.Action, error) {
	if a.ActionID == "" {
		a.ActionID = newID("act")
	}
	if a.ActionStatus == "" {
		a.ActionStatus = "pending"
	}
	if a.RoundID == 0 {
		a.RoundID = 1
	}
	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO actions (action_id, task_id, event_id, round_id, action_name, action_type, action_assignee, action_status, action_result, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		a.ActionID, a.TaskID, a.EventID, a.RoundID, a.ActionName, a.ActionType, a.ActionAssignee, a.ActionStatus, a.ActionResult, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return domain.Action{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		a.ID = id
	}
	return a, nil
}

func (s *MySQLStore) UpdateAction(actionID string, patch map[string]any) (domain.Action, bool) {
	status, _ := stringPatch(patch, "action_status")
	result, _ := stringPatch(patch, "action_result")
	_, err := s.db.ExecContext(context.Background(), `
UPDATE actions SET
action_status=COALESCE(NULLIF(?,''), action_status),
action_result=COALESCE(NULLIF(?,''), action_result),
updated_at=NOW(6)
WHERE action_id=?`,
		status, result, actionID)
	if err != nil {
		return domain.Action{}, false
	}
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, action_id, task_id, event_id, round_id, action_name, action_type, action_assignee, action_status, action_result, created_at, updated_at
FROM actions WHERE action_id=?`, actionID)
	a, err := scanAction(row)
	return a, err == nil
}

func (s *MySQLStore) ListActions(eventID string) []domain.Action {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, action_id, task_id, event_id, round_id, action_name, action_type, action_assignee, action_status, action_result, created_at, updated_at
FROM actions WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.Action{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (s *MySQLStore) AddCommand(c domain.Command) (domain.Command, error) {
	if c.CommandID == "" {
		c.CommandID = newID("cmd")
	}
	if c.CommandStatus == "" {
		c.CommandStatus = "pending"
	}
	if c.RoundID == 0 {
		c.RoundID = 1
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO commands (command_id, action_id, task_id, event_id, round_id, command_name, command_type, command_assignee, command_entity, command_params, command_status, command_result, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.CommandID, c.ActionID, c.TaskID, c.EventID, c.RoundID, c.CommandName, c.CommandType, c.CommandAssignee, c.CommandEntity, c.CommandParams, c.CommandStatus, c.CommandResult, c.CreatedAt, c.UpdatedAt)
	if err != nil {
		return domain.Command{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		c.ID = id
	}
	return c, nil
}

func (s *MySQLStore) UpdateCommand(commandID string, patch map[string]any) (domain.Command, bool) {
	status, _ := stringPatch(patch, "command_status")
	result, _ := stringPatch(patch, "command_result")
	_, err := s.db.ExecContext(context.Background(), `
UPDATE commands SET
command_status=COALESCE(NULLIF(?,''), command_status),
command_result=COALESCE(NULLIF(?,''), command_result),
updated_at=NOW(6)
WHERE command_id=?`,
		status, result, commandID)
	if err != nil {
		return domain.Command{}, false
	}
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, command_id, action_id, task_id, event_id, round_id, command_name, command_type, command_assignee, command_entity, command_params, command_status, command_result, created_at, updated_at
FROM commands WHERE command_id=?`, commandID)
	c, err := scanCommand(row)
	return c, err == nil
}

func (s *MySQLStore) ListCommands(eventID string) []domain.Command {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, command_id, action_id, task_id, event_id, round_id, command_name, command_type, command_assignee, command_entity, command_params, command_status, command_result, created_at, updated_at
FROM commands WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.Command{}
	for rows.Next() {
		c, err := scanCommand(rows)
		if err == nil {
			out = append(out, c)
		}
	}
	return out
}

func (s *MySQLStore) AddExecution(e domain.Execution) (domain.Execution, error) {
	if e.ExecutionID == "" {
		e.ExecutionID = newID("exec")
	}
	if e.ExecutionStatus == "" {
		e.ExecutionStatus = "pending"
	}
	if e.RoundID == 0 {
		e.RoundID = 1
	}
	now := time.Now().UTC()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO executions (execution_id, event_id, task_id, action_id, round_id, command_id, execution_status, execution_result, execution_summary, ai_summary, command_name, command_type, command_entity, command_params, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ExecutionID, e.EventID, e.TaskID, e.ActionID, e.RoundID, e.CommandID, e.ExecutionStatus, e.ExecutionResult, e.ExecutionSummary, e.AISummary, e.CommandName, e.CommandType, e.CommandEntity, e.CommandParams, e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return domain.Execution{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		e.ID = id
	}
	return e, nil
}

func (s *MySQLStore) ListExecutions(eventID string) []domain.Execution {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, execution_id, event_id, task_id, action_id, round_id, command_id, execution_status, execution_result, execution_summary, ai_summary, command_name, command_type, command_entity, command_params, created_at, updated_at
FROM executions WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []domain.Execution{}
	for rows.Next() {
		e, err := scanExecution(rows)
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *MySQLStore) AddSummary(sm domain.Summary) (domain.Summary, error) {
	if sm.RoundID == 0 {
		sm.RoundID = 1
	}
	if sm.Version == 0 {
		sm.Version = 1
	}
	if sm.Kind == "" {
		sm.Kind = "initial"
	}
	now := time.Now().UTC()
	if sm.CreatedAt.IsZero() {
		sm.CreatedAt = now
	}
	sm.UpdatedAt = now
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO summaries (event_id, round_id, event_summary, version, kind, created_at, updated_at)
VALUES (?,?,?,?,?,?,?)`,
		sm.EventID, sm.RoundID, sm.EventSummary, sm.Version, sm.Kind, sm.CreatedAt, sm.UpdatedAt)
	if err != nil {
		return domain.Summary{}, err
	}
	if id, err := res.LastInsertId(); err == nil {
		sm.ID = id
	}
	return sm, nil
}

func (s *MySQLStore) ListSummaries(eventID string) []domain.Summary {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, event_id, round_id, event_summary, version, kind, created_at, updated_at
FROM summaries WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []domain.Summary{}
	for rows.Next() {
		var sm domain.Summary
		if err := rows.Scan(&sm.ID, &sm.EventID, &sm.RoundID, &sm.EventSummary, &sm.Version, &sm.Kind, &sm.CreatedAt, &sm.UpdatedAt); err == nil {
			out = append(out, sm)
		}
	}
	return out
}

func (s *MySQLStore) ReserveFingerprint(fp string) bool {
	res, err := s.db.ExecContext(context.Background(), `
INSERT IGNORE INTO event_maps (fingerprint) VALUES (?)`, fp)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *MySQLStore) BindEventMap(fp, lyID, deepSOCID string) {
	_, _ = s.db.ExecContext(context.Background(), `
UPDATE event_maps SET ly_event_id=?, deepsoc_event_id=? WHERE fingerprint=?`,
		lyID, deepSOCID, fp)
}

func (s *MySQLStore) GetEventMap(fp string) (domain.EventMap, bool) {
	var row domain.EventMap
	err := s.db.QueryRowContext(context.Background(), `
SELECT fingerprint, ly_event_id, deepsoc_event_id, created_at FROM event_maps WHERE fingerprint=?`, fp).
		Scan(&row.Fingerprint, &row.LyEventID, &row.DeepSOCEventID, &row.CreatedAt)
	return row, err == nil
}

func (s *MySQLStore) GetCursor(name string) domain.SyncCursor {
	var c domain.SyncCursor
	err := s.db.QueryRowContext(context.Background(), `
SELECT name, last_ts, updated_at FROM sync_cursors WHERE name=?`, name).
		Scan(&c.Name, &c.LastTS, &c.UpdatedAt)
	if err != nil {
		return domain.SyncCursor{Name: name}
	}
	return c
}

func (s *MySQLStore) SaveCursor(c domain.SyncCursor) {
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now().UTC()
	}
	_, _ = s.db.ExecContext(context.Background(), `
INSERT INTO sync_cursors (name, last_ts, updated_at)
VALUES (?,?,?)
ON DUPLICATE KEY UPDATE last_ts=VALUES(last_ts), updated_at=VALUES(updated_at)`,
		c.Name, c.LastTS, c.UpdatedAt)
}

func (s *MySQLStore) AlreadyPushed(id string) bool {
	var n int
	err := s.db.QueryRowContext(context.Background(), `SELECT 1 FROM pushed_events WHERE ly_event_id=?`, id).Scan(&n)
	return err == nil
}

func (s *MySQLStore) SavePushedEvent(pe domain.PushedEvent) {
	now := time.Now().UTC()
	if pe.CreatedAt.IsZero() {
		pe.CreatedAt = now
	}
	pe.UpdatedAt = now
	_, _ = s.db.ExecContext(context.Background(), `
INSERT INTO pushed_events (ly_event_id, idempotency_key, deepsoc_event_id, status, attempts, last_error, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
idempotency_key=VALUES(idempotency_key),
deepsoc_event_id=VALUES(deepsoc_event_id),
status=VALUES(status),
attempts=VALUES(attempts),
last_error=VALUES(last_error),
updated_at=VALUES(updated_at)`,
		pe.LyEventID, pe.IdempotencyKey, pe.DeepSOCEventID, pe.Status, pe.Attempts, pe.LastError, pe.CreatedAt, pe.UpdatedAt)
}

func (s *MySQLStore) AddAuditLog(a domain.AuditLog) domain.AuditLog {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(context.Background(), `
INSERT INTO audit_logs (actor, action, target, meta, created_at)
VALUES (?,?,?,?,?)`, a.Actor, a.Action, a.Target, a.Meta, a.CreatedAt)
	if err == nil {
		if id, err := res.LastInsertId(); err == nil {
			a.ID = id
		}
	}
	return a
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (domain.User, error) {
	var u domain.User
	var last sql.NullTime
	err := row.Scan(&u.ID, &u.UserID, &u.Username, &u.Nickname, &u.Email, &u.Phone, &u.Password, &u.Role, &last, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
	if last.Valid {
		u.LastLoginAt = &last.Time
	}
	return u, err
}

func scanEvent(row scanner) (domain.Event, error) {
	var e domain.Event
	var obs []byte
	err := row.Scan(&e.ID, &e.EventID, &e.EventName, &e.Title, &e.Message, &e.Context, &e.Source, &e.Severity, &e.Category, &e.EventStatus, &e.CurrentRound, &obs, &e.CreatedAt, &e.UpdatedAt, &e.ReviewStatus, &e.ReviewComment, &e.ReviewedBy, &e.ReviewedAt, &e.CircularCode, &e.AnalysisVersion, &e.AggregationClosed, &e.LastAnalysisAt, &e.LastSeenAt, &e.ArchiveDate)
	if len(obs) > 0 {
		_ = json.Unmarshal(obs, &e.Observables)
	}
	return e, err
}

func scanTask(row scanner) (domain.Task, error) {
	var t domain.Task
	err := row.Scan(&t.ID, &t.TaskID, &t.EventID, &t.TaskName, &t.TaskType, &t.TaskDescription, &t.TaskStatus, &t.TaskPriority, &t.AssignedTo, &t.TaskAssignee, &t.RoundID, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func scanAction(row scanner) (domain.Action, error) {
	var a domain.Action
	err := row.Scan(&a.ID, &a.ActionID, &a.TaskID, &a.EventID, &a.RoundID, &a.ActionName, &a.ActionType, &a.ActionAssignee, &a.ActionStatus, &a.ActionResult, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func scanCommand(row scanner) (domain.Command, error) {
	var c domain.Command
	err := row.Scan(&c.ID, &c.CommandID, &c.ActionID, &c.TaskID, &c.EventID, &c.RoundID, &c.CommandName, &c.CommandType, &c.CommandAssignee, &c.CommandEntity, &c.CommandParams, &c.CommandStatus, &c.CommandResult, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func scanExecution(row scanner) (domain.Execution, error) {
	var e domain.Execution
	err := row.Scan(&e.ID, &e.ExecutionID, &e.EventID, &e.TaskID, &e.ActionID, &e.RoundID, &e.CommandID, &e.ExecutionStatus, &e.ExecutionResult, &e.ExecutionSummary, &e.AISummary, &e.CommandName, &e.CommandType, &e.CommandEntity, &e.CommandParams, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

func scanMessage(row scanner) (domain.Message, error) {
	var m domain.Message
	err := row.Scan(&m.ID, &m.MessageID, &m.EventID, &m.UserID, &m.UserNickname, &m.MessageFrom, &m.MessageType, &m.MessageCategory, &m.SenderType, &m.ChatSessionID, &m.MessageContent, &m.RoundID, &m.CreatedAt)
	return domain.NormalizeMessage(m), err
}

func (s *MySQLStore) CreateAsset(a domain.Asset) (domain.Asset, error) {
	if a.ID == "" {
		a.ID = newID("asset")
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO traffic_assets (id, name, asset_type, address, unit, owner, status, remark, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.AssetType, a.Address, a.Unit, a.Owner, a.Status, a.Remark, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return domain.Asset{}, err
	}
	return a, nil
}

func scanAsset(row scanner) (domain.Asset, error) {
	var a domain.Asset
	err := row.Scan(&a.ID, &a.Name, &a.AssetType, &a.Address, &a.Unit, &a.Owner, &a.Status, &a.Remark, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func (s *MySQLStore) GetAsset(id string) (domain.Asset, bool) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT id, name, asset_type, address, unit, owner, status, remark, created_at, updated_at
FROM traffic_assets WHERE id=?`, id)
	a, err := scanAsset(row)
	return a, err == nil
}

func (s *MySQLStore) ListAssets() []domain.Asset {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, name, asset_type, address, unit, owner, status, remark, created_at, updated_at
FROM traffic_assets ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.Asset{}
	for rows.Next() {
		if a, err := scanAsset(rows); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (s *MySQLStore) UpdateAsset(id string, patch map[string]any) (domain.Asset, bool) {
	a, ok := s.GetAsset(id)
	if !ok {
		return domain.Asset{}, false
	}
	if v, ok := stringPatch(patch, "name"); ok {
		a.Name = v
	}
	if v, ok := stringPatch(patch, "asset_type"); ok {
		a.AssetType = v
	}
	if v, ok := stringPatch(patch, "address"); ok {
		a.Address = v
	}
	if v, ok := stringPatch(patch, "unit"); ok {
		a.Unit = v
	}
	if v, ok := stringPatch(patch, "owner"); ok {
		a.Owner = v
	}
	if v, ok := stringPatch(patch, "remark"); ok {
		a.Remark = v
	}
	if v, ok := intPatch(patch, "status"); ok {
		a.Status = v
	}
	a.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(context.Background(), `
UPDATE traffic_assets SET name=?, asset_type=?, address=?, unit=?, owner=?, status=?, remark=?, updated_at=?
WHERE id=?`,
		a.Name, a.AssetType, a.Address, a.Unit, a.Owner, a.Status, a.Remark, a.UpdatedAt, id)
	if err != nil {
		return domain.Asset{}, false
	}
	return a, true
}

func (s *MySQLStore) DeleteAsset(id string) bool {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM traffic_assets WHERE id=?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *MySQLStore) SaveAssetReportSummary(sm domain.AssetReportSummary) (domain.AssetReportSummary, error) {
	if sm.ID == "" {
		sm.ID = newID("ars")
	}
	now := time.Now().UTC()
	if sm.CreatedAt.IsZero() {
		sm.CreatedAt = now
	}
	sm.UpdatedAt = now
	if sm.Status == "" {
		sm.Status = "pending"
	}
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO asset_report_summaries (summary_id, asset_id, asset_ip, period, window_from, window_to, event_count, stats, narrative, status, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
asset_ip=VALUES(asset_ip),
window_from=VALUES(window_from),
window_to=VALUES(window_to),
event_count=VALUES(event_count),
stats=VALUES(stats),
narrative=VALUES(narrative),
status=VALUES(status),
updated_at=VALUES(updated_at)`,
		sm.ID, sm.AssetID, sm.AssetIP, sm.Period, sm.WindowFrom, sm.WindowTo, sm.EventCount, string(toJSON(sm.Stats)), sm.Narrative, sm.Status, sm.CreatedAt, sm.UpdatedAt)
	if err != nil {
		return domain.AssetReportSummary{}, err
	}
	saved, ok := s.GetAssetReportSummary(sm.AssetID, sm.Period)
	if !ok {
		return domain.AssetReportSummary{}, fmt.Errorf("保存后回读资产月度总结失败")
	}
	return saved, nil
}

func (s *MySQLStore) GetAssetReportSummary(assetID string, period string) (domain.AssetReportSummary, bool) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT summary_id, asset_id, asset_ip, period, window_from, window_to, event_count, stats, narrative, status, created_at, updated_at
FROM asset_report_summaries WHERE asset_id=? AND period=?`, assetID, period)
	sm, err := scanAssetReportSummary(row)
	return sm, err == nil
}

func (s *MySQLStore) ListAssetReportSummaries(assetID string) []domain.AssetReportSummary {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT summary_id, asset_id, asset_ip, period, window_from, window_to, event_count, stats, narrative, status, created_at, updated_at
FROM asset_report_summaries WHERE asset_id=? ORDER BY period DESC`, assetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []domain.AssetReportSummary{}
	for rows.Next() {
		sm, err := scanAssetReportSummary(rows)
		if err == nil {
			out = append(out, sm)
		}
	}
	return out
}

func scanAssetReportSummary(row scanner) (domain.AssetReportSummary, error) {
	var sm domain.AssetReportSummary
	var stats []byte
	err := row.Scan(&sm.ID, &sm.AssetID, &sm.AssetIP, &sm.Period, &sm.WindowFrom, &sm.WindowTo, &sm.EventCount, &stats, &sm.Narrative, &sm.Status, &sm.CreatedAt, &sm.UpdatedAt)
	if len(stats) > 0 {
		_ = json.Unmarshal(stats, &sm.Stats)
	}
	return sm, err
}

func (s *MySQLStore) CreateAssetReportJob(job domain.AssetReportJob) (domain.AssetReportJob, error) {
	if job.ID == "" {
		job.ID = newID("arj")
	}
	if job.Status == "" {
		job.Status = "queued"
	}
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO asset_report_jobs (job_id, period, status, total_assets, completed_assets, error, created_at, updated_at, started_at, finished_at)
VALUES (?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.Period, job.Status, job.TotalAssets, job.CompletedAssets, job.Error, job.CreatedAt, job.UpdatedAt, job.StartedAt, job.FinishedAt)
	if err != nil {
		return domain.AssetReportJob{}, err
	}
	saved, ok := s.GetAssetReportJob(job.ID)
	if !ok {
		return domain.AssetReportJob{}, fmt.Errorf("创建后回读任务失败")
	}
	return saved, nil
}

func (s *MySQLStore) UpdateAssetReportJob(jobID string, patch map[string]any) (domain.AssetReportJob, bool) {
	job, ok := s.GetAssetReportJob(jobID)
	if !ok {
		return domain.AssetReportJob{}, false
	}
	if v, ok := stringPatch(patch, "status"); ok {
		job.Status = v
	}
	if v, ok := intPatch(patch, "total_assets"); ok {
		job.TotalAssets = v
	}
	if v, ok := intPatch(patch, "completed_assets"); ok {
		job.CompletedAssets = v
	}
	if v, ok := stringPatch(patch, "error"); ok {
		job.Error = v
	}
	if v, ok := stringPatch(patch, "started_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			job.StartedAt = &tu
		}
	}
	if v, ok := stringPatch(patch, "finished_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			job.FinishedAt = &tu
		}
	}
	job.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(context.Background(), `
UPDATE asset_report_jobs
SET status=?, total_assets=?, completed_assets=?, error=?, updated_at=?, started_at=?, finished_at=?
WHERE job_id=?`,
		job.Status, job.TotalAssets, job.CompletedAssets, job.Error, job.UpdatedAt, job.StartedAt, job.FinishedAt, jobID)
	if err != nil {
		return domain.AssetReportJob{}, false
	}
	return s.GetAssetReportJob(jobID)
}

func (s *MySQLStore) GetAssetReportJob(jobID string) (domain.AssetReportJob, bool) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT job_id, period, status, total_assets, completed_assets, error, created_at, updated_at, started_at, finished_at
FROM asset_report_jobs WHERE job_id=?`, jobID)
	job, err := scanAssetReportJob(row)
	return job, err == nil
}

func scanAssetReportJob(row scanner) (domain.AssetReportJob, error) {
	var j domain.AssetReportJob
	err := row.Scan(&j.ID, &j.Period, &j.Status, &j.TotalAssets, &j.CompletedAssets, &j.Error, &j.CreatedAt, &j.UpdatedAt, &j.StartedAt, &j.FinishedAt)
	return j, err
}
