package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

type MemoryStore struct {
	mu               sync.RWMutex
	aggregateRecords map[string]AggregateRecord
	aggregateHits    map[string]Hit
	hitSeq           int64

	usersByID       map[string]domain.User
	usersByUsername map[string]string
	userSeq         int64

	events        map[string]domain.Event
	eventSeq      int64
	archiveJobs   map[string]domain.ArchiveJob
	archiveJobSeq int64

	messagesByEvent map[string][]domain.Message
	messageSeq      int64

	tasksByEvent      map[string][]domain.Task
	actionsByEvent    map[string][]domain.Action
	commandsByEvent   map[string][]domain.Command
	execByEvent       map[string][]domain.Execution
	summariesByEvent  map[string][]domain.Summary
	taskSeq           int64
	actionSeq         int64
	commandSeq        int64
	execSeq           int64
	summarySeq        int64
	assetReportSeq    int64
	eventMaps         map[string]domain.EventMap
	cursors           map[string]domain.SyncCursor
	pushed            map[string]domain.PushedEvent
	audits            []domain.AuditLog
	auditSeq          int64
	assets            map[string]domain.Asset
	assetReports      map[string]domain.AssetReportSummary
	assetReportJobs   map[string]domain.AssetReportJob
	assetReportJobSeq int64
}

func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		aggregateRecords: map[string]AggregateRecord{},
		aggregateHits:    map[string]Hit{},
		usersByID:        map[string]domain.User{},
		usersByUsername:  map[string]string{},
		events:           map[string]domain.Event{},
		archiveJobs:      map[string]domain.ArchiveJob{},
		messagesByEvent:  map[string][]domain.Message{},
		tasksByEvent:     map[string][]domain.Task{},
		actionsByEvent:   map[string][]domain.Action{},
		commandsByEvent:  map[string][]domain.Command{},
		execByEvent:      map[string][]domain.Execution{},
		summariesByEvent: map[string][]domain.Summary{},
		eventMaps:        map[string]domain.EventMap{},
		cursors:          map[string]domain.SyncCursor{},
		pushed:           map[string]domain.PushedEvent{},
		assets:           map[string]domain.Asset{},
		assetReports:     map[string]domain.AssetReportSummary{},
		assetReportJobs:  map[string]domain.AssetReportJob{},
	}
	now := time.Now().UTC()
	admin := domain.User{
		ID:        1,
		UserID:    "admin",
		Username:  "admin",
		Nickname:  "管理员",
		Email:     "admin@example.local",
		Role:      "admin",
		IsActive:  true,
		Password:  "admin",
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.userSeq = 1
	s.usersByID[admin.UserID] = admin
	s.usersByUsername[admin.Username] = admin.UserID
	return s
}

func (s *MemoryStore) CreateUser(u domain.User) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByUsername[u.Username]; ok {
		return domain.User{}, errors.New("username already exists")
	}
	now := time.Now().UTC()
	s.userSeq++
	if u.UserID == "" {
		u.UserID = newID("u")
	}
	u.ID = s.userSeq
	u.IsActive = true
	if u.Role == "" {
		u.Role = "user"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	s.usersByID[u.UserID] = u
	s.usersByUsername[u.Username] = u.UserID
	return u, nil
}

func (s *MemoryStore) GetUserByUsername(username string) (domain.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usersByUsername[username]
	if !ok {
		return domain.User{}, false
	}
	u, ok := s.usersByID[id]
	return u, ok
}

func (s *MemoryStore) GetUser(userID string) (domain.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usersByID[userID]
	return u, ok
}

func (s *MemoryStore) ListUsers() []domain.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.User, 0, len(s.usersByID))
	for _, u := range s.usersByID {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *MemoryStore) UpdateUser(userID string, patch map[string]any) (domain.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[userID]
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
	s.usersByID[userID] = u
	return u, true
}

func (s *MemoryStore) DeleteUser(userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[userID]
	if !ok {
		return false
	}
	delete(s.usersByUsername, u.Username)
	delete(s.usersByID, userID)
	return true
}

func (s *MemoryStore) CreateEvent(e domain.Event) (domain.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.EventID == "" {
		e.EventID = newID("evt")
	}
	if _, exists := s.events[e.EventID]; exists {
		return domain.Event{}, errors.New("event already exists")
	}
	now := time.Now().UTC()
	s.eventSeq++
	e.ID = s.eventSeq
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
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	s.events[e.EventID] = e
	return e, nil
}

func (s *MemoryStore) GetEvent(eventID string) (domain.Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.events[eventID]
	return e, ok
}

func (s *MemoryStore) ListEvents() []domain.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Event, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *MemoryStore) UpdateEvent(eventID string, patch map[string]any) (domain.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.events[eventID]
	if !ok {
		return domain.Event{}, false
	}
	if v, ok := stringPatch(patch, "event_name"); ok {
		e.EventName = v
	}
	if v, ok := stringPatch(patch, "message"); ok {
		e.Message = v
	}
	if v, ok := stringPatch(patch, "context"); ok {
		e.Context = v
	}
	if v, ok := stringPatch(patch, "severity"); ok {
		e.Severity = v
	}
	if v, ok := stringPatch(patch, "event_status"); ok {
		e.EventStatus = v
	}
	if v, ok := stringPatch(patch, "review_status"); ok {
		e.ReviewStatus = v
	}
	if v, ok := stringPatch(patch, "review_comment"); ok {
		e.ReviewComment = v
	}
	if v, ok := stringPatch(patch, "reviewed_by"); ok {
		e.ReviewedBy = v
	}
	if v, ok := stringPatch(patch, "circular_code"); ok {
		e.CircularCode = v
	}
	if v, ok := stringPatch(patch, "reviewed_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			e.ReviewedAt = &tu
		}
	}
	if v, ok := intPatch(patch, "analysis_version"); ok {
		e.AnalysisVersion = v
	}
	if v, ok := boolPatch(patch, "aggregation_closed"); ok {
		e.AggregationClosed = v
	}
	if v, ok := stringPatch(patch, "last_analysis_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			e.LastAnalysisAt = &tu
		}
	}
	if v, ok := patch["last_seen_at"]; ok && v == nil {
		e.LastSeenAt = nil
	} else if v, ok := stringPatch(patch, "last_seen_at"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tu := t.UTC()
			e.LastSeenAt = &tu
		}
	}
	if v, ok := patch["archive_date"]; ok {
		if v == nil {
			e.ArchiveDate = nil
		} else if t, ok := v.(time.Time); ok {
			tt := t
			e.ArchiveDate = &tt
		} else if s, ok := v.(string); ok && s != "" {
			if t, err := time.Parse("2006-01-02", s); err == nil {
				e.ArchiveDate = &t
			}
		}
	}
	e.UpdatedAt = time.Now().UTC()
	s.events[eventID] = e
	return e, true
}

func (s *MemoryStore) ListEventsPage(q EventQuery) (EventPage, error) {
	from, to, err := q.ArchiveRange()
	if err != nil {
		return EventPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []domain.Event{}
	for _, e := range s.events {
		var aggregation map[string]any
		_ = json.Unmarshal([]byte(e.Context), &aggregation)
		if canonical, _ := aggregation["canonical_event_id"].(string); canonical != "" && canonical != e.EventID {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(q.Scope)) {
		case "", "today":
			if e.ArchiveDate != nil {
				continue
			}
		case "archive":
			if e.ArchiveDate == nil {
				continue
			}
			date := e.ArchiveDate.Format("2006-01-02")
			if (from != "" && date < from) || (to != "" && date > to) {
				continue
			}
		case "all":
		default:
			if e.ArchiveDate != nil {
				continue
			}
		}
		if q.Level != "" && e.Severity != q.Level {
			continue
		}
		if q.Keyword != "" {
			kw := strings.ToLower(q.Keyword)
			hay := strings.ToLower(e.EventName + " " + e.Title + " " + e.Message + " " + e.Context)
			if !strings.Contains(hay, kw) {
				continue
			}
		}
		if q.Asset != "" {
			asset := strings.ToLower(q.Asset)
			if !strings.Contains(strings.ToLower(e.Context+string(toJSON(e.Observables))), asset) {
				continue
			}
		}
		filterTime := e.CreatedAt
		if aggregation["aggregation_version"] == float64(2) {
			if t := domain.ParseEventTime(aggregation["first_time"]); !t.IsZero() {
				filterTime = t
			}
		}
		if q.StartTime != nil && filterTime.Before(*q.StartTime) {
			continue
		}
		if q.EndTime != nil && !filterTime.Before(*q.EndTime) {
			continue
		}
		out = append(out, e)
	}
	sortEvents(out, q)
	total := len(out)
	page, pageSize := normalizePage(q.Page, q.PageSize)
	start := (page - 1) * pageSize
	if start > len(out) {
		start = len(out)
	}
	end := start + pageSize
	if end > len(out) {
		end = len(out)
	}
	return EventPage{Items: out[start:end], Total: total}, nil
}

// sortEvents 按 EventQuery.Sort/Order 排序（与 MySQL eventOrderBy 口径一致）：
// time=created_at、payload=context.quant_stats.total_payload_bytes、
// frequency=context.occurrence_count；同值以 created_at DESC, id DESC 兜底。
func sortEvents(out []domain.Event, q EventQuery) {
	dir := strings.ToLower(strings.TrimSpace(q.Order))
	if dir != "asc" && dir != "desc" {
		dir = "desc"
	}
	lessTime := func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	}
	ctxNum := func(e domain.Event, path string) int64 {
		m := map[string]any{}
		if e.Context != "" {
			_ = json.Unmarshal([]byte(e.Context), &m)
		}
		var cur any = m
		for _, key := range strings.Split(path, ".") {
			mm, ok := cur.(map[string]any)
			if !ok {
				return 0
			}
			cur, ok = mm[key]
			if !ok {
				return 0
			}
		}
		switch v := cur.(type) {
		case float64:
			return int64(v)
		case int64:
			return v
		case int:
			return int64(v)
		case string:
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(q.Sort)) {
	case "payload":
		sort.SliceStable(out, func(i, j int) bool {
			unknown := func(e domain.Event) bool {
				var c map[string]any
				_ = json.Unmarshal([]byte(e.Context), &c)
				q, _ := c["quant_stats"].(map[string]any)
				return q["volume_quality"] == "unverified"
			}
			if a, b := unknown(out[i]), unknown(out[j]); a != b {
				return !a
			}
			a, b := ctxNum(out[i], "quant_stats.total_payload_bytes"), ctxNum(out[j], "quant_stats.total_payload_bytes")
			if a == b {
				return lessTime(i, j)
			}
			if dir == "asc" {
				return a < b
			}
			return a > b
		})
	case "frequency":
		sort.SliceStable(out, func(i, j int) bool {
			a, b := ctxNum(out[i], "occurrence_count"), ctxNum(out[j], "occurrence_count")
			if a == b {
				return lessTime(i, j)
			}
			if dir == "asc" {
				return a < b
			}
			return a > b
		})
	case "probability":
		// 研判概率（context.ai_probability，LLM 输出提取，可为小数）：
		// 有概率的事件排前（未研判沉底，与升降序无关），同值以时间倒序兜底。
		ctxProb := func(e domain.Event) (float64, bool) {
			m := map[string]any{}
			if e.Context != "" {
				_ = json.Unmarshal([]byte(e.Context), &m)
			}
			v, ok := m["ai_probability"]
			if !ok {
				return 0, false
			}
			switch n := v.(type) {
			case float64:
				return n, true
			case string:
				f, err := strconv.ParseFloat(n, 64)
				return f, err == nil
			}
			return 0, false
		}
		sort.SliceStable(out, func(i, j int) bool {
			ai, aok := ctxProb(out[i])
			bi, bok := ctxProb(out[j])
			if aok != bok {
				return aok
			}
			if ai == bi {
				return lessTime(i, j)
			}
			if dir == "asc" {
				return ai < bi
			}
			return ai > bi
		})
	default:
		if dir == "asc" {
			sort.SliceStable(out, func(i, j int) bool {
				if out[i].CreatedAt.Equal(out[j].CreatedAt) {
					return out[i].ID > out[j].ID
				}
				return out[i].CreatedAt.Before(out[j].CreatedAt)
			})
		} else {
			sort.SliceStable(out, lessTime)
		}
	}
}

func (s *MemoryStore) ArchiveConvergedEvents(threshold time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 500
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	ids := []string{}
	for id, e := range s.events {
		if !e.AggregationClosed || e.ArchiveDate != nil {
			continue
		}
		last := eventLastSeenFromEvent(e)
		if last.IsZero() || !last.Before(threshold) {
			continue
		}
		ids = append(ids, id)
		if len(ids) >= batchSize {
			break
		}
	}
	for _, id := range ids {
		e := s.events[id]
		last := eventLastSeenFromEvent(e).In(domain.Beijing)
		d := time.Date(last.Year(), last.Month(), last.Day(), 0, 0, 0, 0, last.Location())
		e.ArchiveDate = &d
		e.UpdatedAt = time.Now().UTC()
		s.events[id] = e
		count++
	}
	return count, nil
}

func (s *MemoryStore) SaveArchiveJob(job domain.ArchiveJob) (domain.ArchiveJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.JobID == "" {
		s.archiveJobSeq++
		job.JobID = fmt.Sprintf("arc-%d", s.archiveJobSeq)
	}
	if job.Status == "" {
		job.Status = "running"
	}
	now := time.Now().UTC()
	if existing, ok := s.archiveJobs[job.JobID]; ok {
		job.ID = existing.ID
		job.CreatedAt = existing.CreatedAt
	} else {
		s.archiveJobSeq++
		job.ID = s.archiveJobSeq
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	s.archiveJobs[job.JobID] = job
	return job, nil
}

func (s *MemoryStore) GetArchiveJob(jobID string) (domain.ArchiveJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.archiveJobs[jobID]
	return job, ok
}

func (s *MemoryStore) ListEventsConvergedDue(threshold time.Time) []domain.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []domain.Event{}
	for _, e := range s.events {
		if e.AggregationClosed {
			continue
		}
		last := eventLastSeenFromEvent(e)
		if !last.IsZero() && !last.After(threshold) {
			out = append(out, e)
		}
	}
	return out
}

func (s *MemoryStore) ListEventsByTargetIP(ip string, from time.Time, to time.Time) []domain.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []domain.Event{}
	for _, e := range s.events {
		last := eventLastSeenFromEvent(e)
		if last.Before(from) || !last.Before(to) {
			continue
		}
		ctxMap := map[string]any{}
		if e.Context != "" {
			_ = json.Unmarshal([]byte(e.Context), &ctxMap)
		}
		dst := ""
		if v, ok := ctxMap["dst_ip"].(string); ok {
			dst = v
		}
		if dst == "" {
			if v, ok := ctxMap["victim_target"].(string); ok {
				dst = v
			}
		}
		if dst == ip {
			out = append(out, e)
		}
	}
	return out
}

// eventLastSeenFromEvent 取事件最近命中时刻：优先列值，其次 context.last_seen_at，
// 最后退回 UpdatedAt（兼容升级前旧数据与测试用例）。
func eventLastSeenFromEvent(e domain.Event) time.Time {
	return domain.LastActivity(e)
}

func (s *MemoryStore) AddMessage(m domain.Message) (domain.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[m.EventID]; !ok {
		return domain.Message{}, errors.New("event not found")
	}
	s.messageSeq++
	m.ID = s.messageSeq
	if m.MessageID == "" {
		m.MessageID = newID("msg")
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if m.RoundID == 0 {
		m.RoundID = 1
	}
	m = domain.NormalizeMessage(m)
	s.messagesByEvent[m.EventID] = append(s.messagesByEvent[m.EventID], m)
	return m, nil
}

func (s *MemoryStore) ListMessages(eventID string) []domain.Message {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]domain.Message(nil), s.messagesByEvent[eventID]...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	filtered := out[:0]
	for _, m := range out {
		m = domain.NormalizeMessage(m)
		if !domain.IsInternalMessage(m) {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func (s *MemoryStore) ListTasks(eventID string) []domain.Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]domain.Task(nil), s.tasksByEvent[eventID]...)
}

func (s *MemoryStore) AddTask(t domain.Task) (domain.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[t.EventID]; !ok {
		return domain.Task{}, errors.New("event not found")
	}
	now := time.Now().UTC()
	s.taskSeq++
	t.ID = s.taskSeq
	if t.TaskID == "" {
		t.TaskID = newID("task")
	}
	if t.TaskStatus == "" {
		t.TaskStatus = "pending"
	}
	if t.RoundID == 0 {
		t.RoundID = 1
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	s.tasksByEvent[t.EventID] = append(s.tasksByEvent[t.EventID], t)
	return t, nil
}

func (s *MemoryStore) UpdateTask(taskID string, patch map[string]any) (domain.Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for eventID, rows := range s.tasksByEvent {
		for i := range rows {
			if rows[i].TaskID != taskID {
				continue
			}
			if v, ok := stringPatch(patch, "task_status"); ok {
				rows[i].TaskStatus = v
			}
			if v, ok := stringPatch(patch, "assigned_to"); ok {
				rows[i].AssignedTo = v
			}
			rows[i].UpdatedAt = time.Now().UTC()
			s.tasksByEvent[eventID] = rows
			return rows[i], true
		}
	}
	return domain.Task{}, false
}

func (s *MemoryStore) AddAction(a domain.Action) (domain.Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[a.EventID]; !ok {
		return domain.Action{}, errors.New("event not found")
	}
	now := time.Now().UTC()
	s.actionSeq++
	a.ID = s.actionSeq
	if a.ActionID == "" {
		a.ActionID = newID("act")
	}
	if a.ActionStatus == "" {
		a.ActionStatus = "pending"
	}
	if a.RoundID == 0 {
		a.RoundID = 1
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	s.actionsByEvent[a.EventID] = append(s.actionsByEvent[a.EventID], a)
	return a, nil
}

func (s *MemoryStore) UpdateAction(actionID string, patch map[string]any) (domain.Action, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for eventID, rows := range s.actionsByEvent {
		for i := range rows {
			if rows[i].ActionID != actionID {
				continue
			}
			if v, ok := stringPatch(patch, "action_status"); ok {
				rows[i].ActionStatus = v
			}
			if v, ok := stringPatch(patch, "action_result"); ok {
				rows[i].ActionResult = v
			}
			rows[i].UpdatedAt = time.Now().UTC()
			s.actionsByEvent[eventID] = rows
			return rows[i], true
		}
	}
	return domain.Action{}, false
}

func (s *MemoryStore) ListActions(eventID string) []domain.Action {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]domain.Action(nil), s.actionsByEvent[eventID]...)
}

func (s *MemoryStore) AddCommand(c domain.Command) (domain.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[c.EventID]; !ok {
		return domain.Command{}, errors.New("event not found")
	}
	now := time.Now().UTC()
	s.commandSeq++
	c.ID = s.commandSeq
	if c.CommandID == "" {
		c.CommandID = newID("cmd")
	}
	if c.CommandStatus == "" {
		c.CommandStatus = "pending"
	}
	if c.RoundID == 0 {
		c.RoundID = 1
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	s.commandsByEvent[c.EventID] = append(s.commandsByEvent[c.EventID], c)
	return c, nil
}

func (s *MemoryStore) UpdateCommand(commandID string, patch map[string]any) (domain.Command, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for eventID, rows := range s.commandsByEvent {
		for i := range rows {
			if rows[i].CommandID != commandID {
				continue
			}
			if v, ok := stringPatch(patch, "command_status"); ok {
				rows[i].CommandStatus = v
			}
			if v, ok := stringPatch(patch, "command_result"); ok {
				rows[i].CommandResult = v
			}
			rows[i].UpdatedAt = time.Now().UTC()
			s.commandsByEvent[eventID] = rows
			return rows[i], true
		}
	}
	return domain.Command{}, false
}

func (s *MemoryStore) ListCommands(eventID string) []domain.Command {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]domain.Command(nil), s.commandsByEvent[eventID]...)
}

func (s *MemoryStore) AddExecution(e domain.Execution) (domain.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[e.EventID]; !ok {
		return domain.Execution{}, errors.New("event not found")
	}
	now := time.Now().UTC()
	s.execSeq++
	e.ID = s.execSeq
	if e.ExecutionID == "" {
		e.ExecutionID = newID("exec")
	}
	if e.ExecutionStatus == "" {
		e.ExecutionStatus = "pending"
	}
	if e.RoundID == 0 {
		e.RoundID = 1
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	s.execByEvent[e.EventID] = append(s.execByEvent[e.EventID], e)
	return e, nil
}

func (s *MemoryStore) ListExecutions(eventID string) []domain.Execution {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]domain.Execution(nil), s.execByEvent[eventID]...)
}

func (s *MemoryStore) AddSummary(sm domain.Summary) (domain.Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[sm.EventID]; !ok {
		return domain.Summary{}, errors.New("event not found")
	}
	now := time.Now().UTC()
	s.summarySeq++
	sm.ID = s.summarySeq
	if sm.RoundID == 0 {
		sm.RoundID = 1
	}
	if sm.Version == 0 {
		sm.Version = 1
	}
	if sm.Kind == "" {
		sm.Kind = "initial"
	}
	if sm.CreatedAt.IsZero() {
		sm.CreatedAt = now
	}
	sm.UpdatedAt = now
	s.summariesByEvent[sm.EventID] = append(s.summariesByEvent[sm.EventID], sm)
	return sm, nil
}

func (s *MemoryStore) ListSummaries(eventID string) []domain.Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]domain.Summary(nil), s.summariesByEvent[eventID]...)
}

func (s *MemoryStore) ReserveFingerprint(fp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.eventMaps[fp]; exists {
		return false
	}
	s.eventMaps[fp] = domain.EventMap{Fingerprint: fp, CreatedAt: time.Now().UTC()}
	return true
}

func (s *MemoryStore) BindEventMap(fp, lyID, deepSOCID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.eventMaps[fp]
	row.Fingerprint = fp
	row.LyEventID = lyID
	row.DeepSOCEventID = deepSOCID
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	s.eventMaps[fp] = row
}

func (s *MemoryStore) GetEventMap(fp string) (domain.EventMap, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	row, ok := s.eventMaps[fp]
	return row, ok
}

func (s *MemoryStore) GetCursor(name string) domain.SyncCursor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cursors[name]; ok {
		return c
	}
	return domain.SyncCursor{Name: name}
}

func (s *MemoryStore) SaveCursor(c domain.SyncCursor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.UpdatedAt = time.Now().UTC()
	s.cursors[c.Name] = c
}

func (s *MemoryStore) AlreadyPushed(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.pushed[id]
	return ok
}

func (s *MemoryStore) SavePushedEvent(pe domain.PushedEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if pe.CreatedAt.IsZero() {
		pe.CreatedAt = now
	}
	pe.UpdatedAt = now
	s.pushed[pe.LyEventID] = pe
}

func (s *MemoryStore) AddAuditLog(a domain.AuditLog) domain.AuditLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSeq++
	a.ID = s.auditSeq
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	s.audits = append(s.audits, a)
	return a
}

func (s *MemoryStore) CreateAsset(a domain.Asset) (domain.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		a.ID = newID("asset")
	}
	for _, ex := range s.assets {
		if ex.Address == a.Address {
			return domain.Asset{}, errors.New("asset address already exists")
		}
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	s.assets[a.ID] = a
	return a, nil
}

func (s *MemoryStore) GetAsset(id string) (domain.Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	return a, ok
}

func (s *MemoryStore) ListAssets() []domain.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *MemoryStore) UpdateAsset(id string, patch map[string]any) (domain.Asset, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
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
	s.assets[id] = a
	return a, true
}

func (s *MemoryStore) DeleteAsset(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.assets[id]; !ok {
		return false
	}
	delete(s.assets, id)
	return true
}

func (s *MemoryStore) SaveAssetReportSummary(sm domain.AssetReportSummary) (domain.AssetReportSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sm.ID == "" {
		s.assetReportSeq++
		sm.ID = fmt.Sprintf("ars-%d", s.assetReportSeq)
	}
	now := time.Now().UTC()
	if sm.CreatedAt.IsZero() {
		sm.CreatedAt = now
	}
	sm.UpdatedAt = now
	if sm.Status == "" {
		sm.Status = "pending"
	}
	key := sm.AssetID + "|" + sm.Period
	s.assetReports[key] = sm
	return sm, nil
}

func (s *MemoryStore) GetAssetReportSummary(assetID string, period string) (domain.AssetReportSummary, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sm, ok := s.assetReports[assetID+"|"+period]
	return sm, ok
}

func (s *MemoryStore) ListAssetReportSummaries(assetID string) []domain.AssetReportSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []domain.AssetReportSummary{}
	for _, sm := range s.assetReports {
		if sm.AssetID == assetID {
			out = append(out, sm)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Period > out[j].Period })
	return out
}

func (s *MemoryStore) CreateAssetReportJob(job domain.AssetReportJob) (domain.AssetReportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assetReportJobSeq++
	if job.ID == "" {
		job.ID = fmt.Sprintf("arj-%d", s.assetReportJobSeq)
	}
	if job.Status == "" {
		job.Status = "queued"
	}
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	s.assetReportJobs[job.ID] = job
	return job, nil
}

func (s *MemoryStore) UpdateAssetReportJob(jobID string, patch map[string]any) (domain.AssetReportJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.assetReportJobs[jobID]
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
	s.assetReportJobs[jobID] = job
	return job, true
}

func (s *MemoryStore) GetAssetReportJob(jobID string) (domain.AssetReportJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.assetReportJobs[jobID]
	return job, ok
}
