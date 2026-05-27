package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"
)

// ══ 规则数据 ══

func (s *serviceMonitor) GetRuleData(ctx context.Context, moduleKey string) (*model.MonitorRuleData, error) {
	var rd model.MonitorRuleData
	if err := s.session().WithContext(ctx).Where("module_key = ?", moduleKey).First(&rd).Error; err != nil {
		return nil, err
	}
	decoded, err := model.MonitorDecodeRuleData(rd.Data)
	if err != nil {
		return nil, err
	}
	rd.Data = decoded
	return &rd, nil
}

func (s *serviceMonitor) PutRuleData(ctx context.Context, moduleKey string, data string) error {
	encoded, err := model.MonitorEncodeRuleData(data)
	if err != nil {
		return err
	}
	result := s.session().WithContext(ctx).Model(&model.MonitorRuleData{}).
		Where("module_key = ?", moduleKey).
		Update("data", encoded)
	if result.RowsAffected == 0 {
		return s.session().WithContext(ctx).Create(&model.MonitorRuleData{
			ModuleKey: moduleKey,
			Data:      encoded,
		}).Error
	}
	return result.Error
}

func (s *serviceMonitor) ListRuleDataSummary(ctx context.Context) ([]contract.RuleDataSummary, error) {
	var allData []model.MonitorRuleData
	s.session().WithContext(ctx).Find(&allData)
	dataMap := map[string]model.MonitorRuleData{}
	for _, d := range allData {
		dataMap[d.ModuleKey] = d
	}
	summaries := make([]contract.RuleDataSummary, 0, len(model.MonitorRuleDataModuleKeys))
	for _, key := range model.MonitorRuleDataModuleKeys {
		def := model.MonitorModuleRegistry[key]
		item := contract.RuleDataSummary{
			ModuleKey:   key,
			Name:        def.Name,
			Description: def.Description,
			Type:        def.Type,
			Group:       def.Group,
			Icon:        def.Icon,
		}
		if d, ok := dataMap[key]; ok {
			item.HasData = d.Data != ""
			item.UpdatedAt = d.UpdatedAt.Format("2006-01-02 15:04:05")
			item.RuleCount = countRuleEntries(d)
		}
		summaries = append(summaries, item)
	}
	return summaries, nil
}

func countRuleEntries(rd model.MonitorRuleData) int {
	decoded, err := model.MonitorDecodeRuleData(rd.Data)
	if err != nil || decoded == "" {
		return 0
	}
	var raw map[string]any
	if json.Unmarshal([]byte(decoded), &raw) != nil {
		return 0
	}
	total := 0
	for _, v := range raw {
		if arr, ok := v.([]any); ok {
			total += len(arr)
		}
	}
	return total
}

func (s *serviceMonitor) SyncAllRuleData(ctx context.Context) error {
	if s.nats == nil {
		return fmt.Errorf("NATS 未连接")
	}
	var allData []model.MonitorRuleData
	s.session().WithContext(ctx).Find(&allData)
	for _, d := range allData {
		def, ok := model.MonitorModuleRegistry[d.ModuleKey]
		if !ok {
			continue
		}
		decoded, err := model.MonitorDecodeRuleData(d.Data)
		if err != nil {
			slog.Error("[RuleData] decode failed", "key", d.ModuleKey, "error", err)
			continue
		}
		if err := s.nats.SyncRuleDataToKV(ctx, def.KVKey, []byte(decoded)); err != nil {
			slog.Error("[RuleData] KV sync failed", "key", d.ModuleKey, "error", err)
		}
	}
	return nil
}
