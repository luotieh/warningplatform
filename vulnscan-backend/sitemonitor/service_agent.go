package sitemonitor

import (
	"context"
	"fmt"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
)

// ══ Agent ══

func (s *serviceMonitor) ListAgents(ctx context.Context) ([]model.MonitorAgent, error) {
	var agents []model.MonitorAgent
	if err := s.session().WithContext(ctx).Order("updated_at DESC").Find(&agents).Error; err != nil {
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

// ══ 告警配置 ══

func (s *serviceMonitor) GetAlertConfig(ctx context.Context) (*model.MonitorAlertConfig, error) {
	var cfg model.MonitorAlertConfig
	if err := s.session().WithContext(ctx).First(&cfg).Error; err != nil {
		return &model.MonitorAlertConfig{AlertEnabled: true, SilenceDurationMinutes: 60, MaxAlertsPerHour: 100}, nil
	}
	return &cfg, nil
}

func (s *serviceMonitor) UpdateAlertConfig(ctx context.Context, cfg *model.MonitorAlertConfig) error {
	var existing model.MonitorAlertConfig
	if s.session().WithContext(ctx).First(&existing).Error != nil {
		if cfg.ID == "" {
			cfg.ID = qulid.GenerateID()
		}
		return s.session().WithContext(ctx).Create(cfg).Error
	}
	return s.session().WithContext(ctx).Model(&existing).Updates(cfg).Error
}
