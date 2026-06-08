package sitemonitor

import (
	"context"
	"fmt"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

// ══ Agent ══

func (s *serviceMonitor) ListAgents(ctx context.Context, scopes ...func(*gorm.DB) *gorm.DB) ([]model.MonitorAgent, error) {
	var agents []model.MonitorAgent
	if err := s.session().WithContext(ctx).Scopes(scopes...).Order("updated_at DESC").Find(&agents).Error; err != nil {
		return nil, err
	}
	return agents, nil
}

func (s *serviceMonitor) SyncAgentRules(ctx context.Context, agentUUID string) (map[string]any, error) {
	if s.nats == nil {
		return nil, fmt.Errorf("NATS 未连接")
	}
	return s.nats.SendAgentCommand(ctx, agentUUID, "sync_rules")
}

func (s *serviceMonitor) ShutdownAgent(ctx context.Context, agentUUID string) (map[string]any, error) {
	if s.nats == nil {
		return nil, fmt.Errorf("NATS 未连接")
	}
	return s.nats.SendAgentCommand(ctx, agentUUID, "shutdown")
}

const embeddedMonitorAgentUUID = "embedded-default"

func (s *serviceMonitor) DeleteAgent(ctx context.Context, agentUUID string) error {
	agentUUID = strings.TrimSpace(agentUUID)
	if agentUUID == "" {
		return fmt.Errorf("Agent UUID 为空")
	}
	if agentUUID == embeddedMonitorAgentUUID {
		return fmt.Errorf("内置监测执行引擎不可删除")
	}
	var ag model.MonitorAgent
	if err := s.session().WithContext(ctx).Where("uuid = ?", agentUUID).First(&ag).Error; err != nil {
		return fmt.Errorf("监测节点不存在")
	}
	if ag.RunningTasks > 0 {
		return fmt.Errorf("节点仍有运行中任务，请稍后再试")
	}
	res := s.session().WithContext(ctx).Where("uuid = ?", agentUUID).Delete(&model.MonitorAgent{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("监测节点不存在")
	}
	return nil
}

// ══ 告警配置 ══

func (s *serviceMonitor) GetAlertConfig(ctx context.Context) (*model.MonitorAlertConfig, error) {
	var cfg model.MonitorAlertConfig
	if err := s.session().WithContext(ctx).First(&cfg).Error; err != nil {
		return &model.MonitorAlertConfig{AlertEnabled: true, SilenceDurationMinutes: 60, MaxAlertsPerHour: 100, MaxTamperScreenshots: 10}, nil
	}
	return &cfg, nil
}

func (s *serviceMonitor) UpdateAlertConfig(ctx context.Context, cfg *model.MonitorAlertConfig) error {
	var existing model.MonitorAlertConfig
	if s.session().WithContext(ctx).First(&existing).Error != nil {
		if cfg.ID == "" {
			cfg.ID = ulid.GenerateID()
		}
		return s.session().WithContext(ctx).Create(cfg).Error
	}
	return s.session().WithContext(ctx).Model(&existing).Updates(cfg).Error
}
