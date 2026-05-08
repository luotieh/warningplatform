package sitemonitor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"vulnscan-backend/boot"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type NatsServiceImpl struct {
	nats     *boot.NatsClient
	db       *db.DB
	objStore *objStoreWrapper
}

func NewNatsServiceImpl(natsClient *boot.NatsClient, database *db.DB) *NatsServiceImpl {
	var obj *objStoreWrapper
	if natsClient != nil && natsClient.ObjStore != nil {
		obj = &objStoreWrapper{store: natsClient.ObjStore}
	}
	return &NatsServiceImpl{nats: natsClient, db: database, objStore: obj}
}

func (s *NatsServiceImpl) PublishTask(ctx context.Context, msg model.MonitorTaskMessage) error {
	if s.nats == nil || s.nats.JS == nil {
		return fmt.Errorf("NATS JetStream未初始化")
	}
	data, _ := json.Marshal(msg)
	subject := fmt.Sprintf("monitor.task.%s", msg.Dimension)
	_, err := s.nats.JS.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("发布任务失败: %w", err)
	}
	slog.Info("[NATS] 任务已发布", "subject", subject, "eid", msg.ExecutionID)
	return nil
}

func (s *NatsServiceImpl) BroadcastSchedulerSync(action string, taskID string) {
	if s.nats == nil || s.nats.Conn == nil || !s.nats.IsConnected() {
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"action":  action,
		"task_id": taskID,
	})
	if err := s.nats.Conn.Publish("monitor.scheduler.sync", payload); err != nil {
		slog.Warn("[NATS] 调度器同步广播失败", "action", action, "task_id", taskID, "error", err)
	}
}

func (s *NatsServiceImpl) StartSchedulerSyncSubscriber(_ context.Context, scheduler interface {
	SyncTaskFromDB(string)
	RemoveTask(string)
}) error {
	if s.nats == nil || s.nats.Conn == nil {
		return nil
	}
	_, err := s.nats.Conn.Subscribe("monitor.scheduler.sync", func(msg *nats.Msg) {
		var ev struct {
			Action string `json:"action"`
			TaskID string `json:"task_id"`
		}
		if err := json.Unmarshal(msg.Data, &ev); err != nil {
			return
		}
		switch ev.Action {
		case "upsert":
			scheduler.SyncTaskFromDB(ev.TaskID)
			slog.Debug("[Scheduler] sync: upsert from peer", "task_id", ev.TaskID)
		case "delete":
			scheduler.RemoveTask(ev.TaskID)
			slog.Debug("[Scheduler] sync: delete from peer", "task_id", ev.TaskID)
		}
	})
	if err != nil {
		return fmt.Errorf("调度器同步订阅失败: %w", err)
	}
	slog.Info("[NATS] 调度器同步订阅已启动")
	return nil
}

func (s *NatsServiceImpl) SendAgentCommand(ctx context.Context, agentUUID string, command string) (map[string]any, error) {
	if s.nats == nil || s.nats.Conn == nil || !s.nats.IsConnected() {
		return nil, fmt.Errorf("NATS 未连接")
	}
	subject := fmt.Sprintf("monitor.agent.command.%s", agentUUID)
	payload, _ := json.Marshal(map[string]string{"command": command})

	msg, err := s.nats.Conn.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return nil, fmt.Errorf("指令发送失败（Agent可能离线）: %w", err)
	}

	var resp map[string]any
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, fmt.Errorf("Agent响应解析失败: %w", err)
	}
	slog.Info("[NATS] Agent指令已执行", "uuid", agentUUID, "command", command, "resp", resp)
	return resp, nil
}

func (s *NatsServiceImpl) GetActiveBaseline(ctx context.Context, url string) (*model.MonitorBaseline, error) {
	session, err := s.db.GetDBSession()
	if err != nil {
		return nil, fmt.Errorf("获取数据库会话失败: %w", err)
	}
	uh := urlHash(url)
	var baseline model.MonitorBaseline
	err = session.WithContext(ctx).
		Where("url_hash = ? AND is_active = ?", uh, true).
		Order("version DESC").
		First(&baseline).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &baseline, nil
}

func (s *NatsServiceImpl) SaveBaselineFromAgent(ctx context.Context, outerTx *gorm.DB, executionID, url, agentID string, bu *model.MonitorBaselineUpdate) error {
	uh := urlHash(url)

	doSave := func(tx *gorm.DB) error {
		var exists int64
		if err := tx.Model(&model.MonitorBaseline{}).Where("execution_id = ?", executionID).Count(&exists).Error; err != nil {
			return fmt.Errorf("幂等检查失败: %w", err)
		}
		if exists > 0 {
			slog.Info("[Baseline] 幂等跳过（已存在）", "eid", executionID, "url", url)
			return nil
		}

		var maxVersion int
		if err := tx.Raw("SELECT COALESCE(MAX(version), 0) FROM monitor_baselines WHERE url_hash = ? FOR UPDATE", uh).
			Scan(&maxVersion).Error; err != nil {
			return fmt.Errorf("版本号查询失败: %w", err)
		}
		nextVersion := maxVersion + 1

		if err := tx.Model(&model.MonitorBaseline{}).
			Where("url_hash = ? AND is_active = ?", uh, true).
			Update("is_active", false).Error; err != nil {
			return fmt.Errorf("旧基线退活失败: %w", err)
		}

		exemptJSON, _ := json.Marshal(bu.ExemptSelectors)
		extResJSON, _ := json.Marshal(bu.ExternalResources)

		baseline := model.MonitorBaseline{
			URL:                   url,
			URLHash:               uh,
			Version:               nextVersion,
			IsActive:              true,
			ExecutionID:           executionID,
			ContentHash:           bu.ContentHash,
			Simhash:               bu.Simhash,
			DomStructureHash:      bu.DomStructureHash,
			VisualHash:            bu.VisualHash,
			Title:                 bu.Title,
			StatusCode:            bu.StatusCode,
			VisibleTextLength:     bu.VisibleTextLength,
			ExemptSelectorsJSON:   string(exemptJSON),
			ExternalResourcesJSON: string(extResJSON),
			ObjKeyHTML:            bu.ObjKeyHTML,
			ObjKeyText:            bu.ObjKeyText,
			ObjKeyScreenshot:      bu.ObjKeyScreenshot,
			AgentID:               agentID,
			ConfirmedBy:           bu.ConfirmedBy,
		}
		baseline.ID = qulid.GenerateID()

		if err := tx.Create(&baseline).Error; err != nil {
			return fmt.Errorf("创建基线失败: %w", err)
		}
		slog.Info("[Baseline] 基线已保存",
			"url", url, "version", nextVersion, "agent", agentID, "eid", executionID, "action", bu.Action)
		return nil
	}

	if outerTx != nil {
		return doSave(outerTx)
	}
	session, err := s.db.GetDBSession()
	if err != nil {
		return fmt.Errorf("获取数据库会话失败: %w", err)
	}
	return session.WithContext(ctx).Transaction(doSave)
}

func (s *NatsServiceImpl) GetLastSimhash(ctx context.Context, taskID string) string {
	session, err := s.db.GetDBSession()
	if err != nil {
		return ""
	}
	var result model.MonitorResultSensitiveWord
	err = session.WithContext(ctx).
		Where("task_id = ?", taskID).
		Order("created_at DESC").
		First(&result).Error
	if err != nil {
		return ""
	}
	var prep map[string]any
	if err := json.Unmarshal([]byte(result.PreprocessingJSON), &prep); err != nil {
		return ""
	}
	if sh, ok := prep["simhash"]; ok {
		if s, ok := sh.(string); ok {
			return s
		}
	}
	return ""
}

func (s *NatsServiceImpl) ObjGetGzip(ctx context.Context, key string) ([]byte, error) {
	if s.objStore == nil {
		return nil, fmt.Errorf("Object Store 未初始化")
	}
	return s.objStore.GetGzip(ctx, key)
}

func (s *NatsServiceImpl) ObjGetRaw(ctx context.Context, key string) ([]byte, error) {
	if s.objStore == nil {
		return nil, fmt.Errorf("Object Store 未初始化")
	}
	return s.objStore.GetRaw(ctx, key)
}

func (s *NatsServiceImpl) ObjDeleteSilent(ctx context.Context, key string) {
	if s.objStore != nil {
		s.objStore.DeleteSilent(ctx, key)
	}
}

func (s *NatsServiceImpl) Close() {
	if s.nats != nil {
		s.nats.Close()
	}
}

func urlHash(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return fmt.Sprintf("%x", h[:8])
}

func jsonBool(raw string, key string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}
