package sitemonitor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

// ══ 任务 ══

func (s *serviceMonitor) CreateTask(ctx context.Context, task *model.MonitorTask) error {
	if task.ID == "" {
		task.ID = qulid.GenerateID()
	}
	return s.session().WithContext(ctx).Create(task).Error
}

func (s *serviceMonitor) UpdateTask(ctx context.Context, id string, req contract.TaskUpdateReq) error {
	updates := map[string]any{}
	if req.TaskName != "" {
		updates["task_name"] = req.TaskName
	}
	if req.Notes != "" {
		updates["notes"] = req.Notes
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.TargetHomepage != "" {
		updates["target_homepage"] = req.TargetHomepage
	}
	if req.TargetDomain != "" {
		updates["target_domain"] = req.TargetDomain
	}
	if req.TargetSubdomains != "" {
		updates["target_subdomains"] = req.TargetSubdomains
	}
	if req.TargetIps != "" {
		updates["target_ips"] = req.TargetIps
	}
	if req.ScheduleEnabled != nil {
		updates["schedule_enabled"] = *req.ScheduleEnabled
	}
	// PLACEHOLDER_TASK_CONTINUE
	if req.ScheduleCron != "" {
		updates["schedule_cron"] = req.ScheduleCron
	}
	if req.ConfigAvailability != nil {
		updates["config_availability"] = model.JSONMap(req.ConfigAvailability)
	}
	if req.ConfigDomainHijack != nil {
		updates["config_domain_hijack"] = model.JSONMap(req.ConfigDomainHijack)
	}
	if req.ConfigTamper != nil {
		updates["config_tamper"] = model.JSONMap(req.ConfigTamper)
	}
	if req.ConfigSensitiveFile != nil {
		updates["config_sensitive_file"] = model.JSONMap(req.ConfigSensitiveFile)
	}
	if req.ConfigSensitiveWord != nil {
		updates["config_sensitive_word"] = model.JSONMap(req.ConfigSensitiveWord)
	}
	if req.ConfigBlacklink != nil {
		updates["config_blacklink"] = model.JSONMap(req.ConfigBlacklink)
	}
	if len(updates) == 0 {
		return nil
	}
	return s.session().WithContext(ctx).Model(&model.MonitorTask{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceMonitor) DeleteTask(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tx.Where("task_id = ?", id).Delete(&model.MonitorExecution{})
		return tx.Where("id = ?", id).Delete(&model.MonitorTask{}).Error
	})
}

func (s *serviceMonitor) GetTask(ctx context.Context, id string) (*model.MonitorTask, error) {
	var task model.MonitorTask
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&task).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *serviceMonitor) ListTasks(ctx context.Context, req contract.TaskListReq) (int64, []model.MonitorTask, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorTask{})
	if req.Name != "" {
		query = query.Where("task_name LIKE ?", "%"+req.Name+"%")
	}
	if req.Enabled == "true" {
		query = query.Where("enabled = ?", true)
	} else if req.Enabled == "false" {
		query = query.Where("enabled = ?", false)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	var list []model.MonitorTask
	if err := paginateQuery(query, req.Index, req.Size).Order("created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

func (s *serviceMonitor) RunTask(ctx context.Context, id string, dimensions []string) ([]string, error) {
	var task model.MonitorTask
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&task).Error; err != nil {
		return nil, fmt.Errorf("任务不存在")
	}
	if len(dimensions) == 0 {
		for _, dim := range model.MonitorAllDimensions {
			cfg := task.GetDimensionConfig(dim)
			if cfg != nil {
				if enabled, _ := cfg["enabled"].(bool); enabled {
					dimensions = append(dimensions, dim)
				}
			}
		}
	}
	if len(dimensions) == 0 {
		dimensions = append(dimensions, model.MonitorAllDimensions...)
		for _, dim := range dimensions {
			cfg := task.GetDimensionConfig(dim)
			if cfg == nil {
				cfg = model.JSONMap{"enabled": true}
			} else {
				cfg["enabled"] = true
			}
			task.SetDimensionConfig(dim, cfg)
		}
		s.session().WithContext(ctx).Save(&task)
	}
	var execIDs []string
	var errs []string
	for _, dim := range dimensions {
		execID, err := s.runTaskDimension(ctx, &task, dim)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", dim, err.Error()))
			continue
		}
		execIDs = append(execIDs, execID)
	}
	if len(execIDs) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("所有维度执行失败: %s", strings.Join(errs, "; "))
	}
	return execIDs, nil
}

func (s *serviceMonitor) runTaskDimension(ctx context.Context, task *model.MonitorTask, dimension string) (string, error) {
	cfg := task.GetDimensionConfig(dimension)
	if cfg == nil {
		return "", fmt.Errorf("维度 %s 未配置", dimension)
	}
	enabled, _ := cfg["enabled"].(bool)
	if !enabled {
		return "", fmt.Errorf("维度 %s 未启用", dimension)
	}

	if dimension == "sensitive_file" {
		flIDs := extractStringSlice(cfg, "file_library_ids")
		if len(flIDs) == 0 {
			slog.Warn("sensitive_file 维度未配置 file_library_ids，将使用默认检测", "task_id", task.ID)
		}
	}
	if dimension == "sensitive_word" {
		wlIDs := extractStringSlice(cfg, "word_library_ids")
		if len(wlIDs) == 0 {
			slog.Warn("sensitive_word 维度未配置 word_library_ids，将使用默认检测", "task_id", task.ID)
		}
	}

	execID := qulid.GenerateID()
	exec := model.MonitorExecution{
		TaskID:    task.ID,
		Dimension: dimension,
		URL:       task.TargetHomepage,
		Status:    "pending",
	}
	exec.ID = execID

	if txErr := s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var activeCount int64
		tx.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND status IN ?", task.ID, dimension, []string{"pending", "running"}).
			Count(&activeCount)
		if activeCount > 0 {
			return fmt.Errorf("维度 %s 已有执行中的记录", dimension)
		}
		return tx.Create(&exec).Error
	}); txErr != nil {
		return "", txErr
	}

	if col := model.MonitorLastRunColumn(dimension); col != "" {
		s.session().WithContext(ctx).Model(task).Update(col, time.Now())
	}
	return execID, nil
}

func (s *serviceMonitor) buildAgentConfig(ctx context.Context, task *model.MonitorTask, dimension string, cfg map[string]any) (map[string]any, error) {
	agentCfg := make(map[string]any)
	session := s.session().WithContext(ctx)

	switch dimension {
	case "availability":
		agentCfg["timeout"] = toInt(cfg["timeout_seconds"])
		agentCfg["method"] = "GET"
		agentCfg["follow_redirects"] = true
		if codes, _ := cfg["exclude_status_codes"].(string); codes != "" {
			var intCodes []int
			for _, c := range strings.Split(codes, ";") {
				if n := toInt(strings.TrimSpace(c)); n > 0 {
					intCodes = append(intCodes, n)
				}
			}
			agentCfg["exclude_codes"] = intCodes
		}
		if task.TargetIps != "" {
			agentCfg["expected_ips"] = strings.Split(task.TargetIps, ",")
		}
	case "domain_hijack":
		if task.TargetIps != "" {
			ips := strings.Split(task.TargetIps, ",")
			agentCfg["expected_ip"] = strings.TrimSpace(ips[0])
		}
	case "tamper":
		if v, ok := cfg["search_engine_ua"]; ok {
			agentCfg["use_search_ua"] = v
		}
		agentCfg["update_baseline"] = false
	case "sensitive_word":
		wlIDs := extractStringSlice(cfg, "word_library_ids")
		agentCfg["word_library_ids"] = wlIDs
		var categories []model.MonitorWordCategory
		if err := session.Where("library_id IN ?", wlIDs).Find(&categories).Error; err == nil {
			names := make([]string, 0, len(categories))
			for _, c := range categories {
				names = append(names, c.Name)
			}
			if len(names) > 0 {
				agentCfg["word_categories"] = names
			}
		}
		if s.nats != nil {
			if lastSH := s.nats.GetLastSimhash(ctx, task.ID); lastSH != "" {
				agentCfg["last_content_simhash"] = lastSH
			}
		}
	case "sensitive_file":
		flIDs := extractStringSlice(cfg, "file_library_ids")
		agentCfg["file_library_ids"] = flIDs
		var libs []model.MonitorFileLibrary
		if err := session.Where("id IN ?", flIDs).Find(&libs).Error; err == nil {
			groups := make([]string, 0, len(libs))
			for _, l := range libs {
				groups = append(groups, l.Name)
			}
			if len(groups) > 0 {
				agentCfg["file_groups"] = groups
			}
		}
	case "blacklink":
		agentCfg["scan_js_files"] = true
		agentCfg["static_compare"] = true
		agentCfg["max_js_files"] = 30
	}

	return agentCfg, nil
}

func (s *serviceMonitor) injectBaseline(ctx context.Context, msg *model.MonitorTaskMessage, targetURL string) {
	bl, err := s.nats.GetActiveBaseline(ctx, targetURL)
	if err != nil || bl == nil {
		return
	}
	msg.Baseline = &model.MonitorBaselineMetadata{
		Version:           bl.Version,
		Simhash:           bl.Simhash,
		ContentHash:       bl.ContentHash,
		DomStructureHash:  bl.DomStructureHash,
		VisualHash:        bl.VisualHash,
		Title:             bl.Title,
		StatusCode:        bl.StatusCode,
		VisibleTextLength: bl.VisibleTextLength,
		ObjKeyHTML:        bl.ObjKeyHTML,
		ObjKeyText:        bl.ObjKeyText,
		ObjKeyScreenshot:  bl.ObjKeyScreenshot,
	}
}

func extractStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []any:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return arr
	}
	return nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	}
	return 0
}

func (s *serviceMonitor) BatchToggleEnabled(ctx context.Context, ids []string) error {
	return s.session().WithContext(ctx).Exec(
		"UPDATE monitor_tasks SET enabled = NOT enabled WHERE id IN ?", ids,
	).Error
}

func (s *serviceMonitor) BatchUpdateConfigs(ctx context.Context, req contract.BatchUpdateConfigsReq) error {
	updates := map[string]any{}
	if req.ConfigAvailability != nil {
		updates["config_availability"] = model.JSONMap(req.ConfigAvailability)
	}
	if req.ConfigDomainHijack != nil {
		updates["config_domain_hijack"] = model.JSONMap(req.ConfigDomainHijack)
	}
	if req.ConfigTamper != nil {
		updates["config_tamper"] = model.JSONMap(req.ConfigTamper)
	}
	if req.ConfigSensitiveFile != nil {
		updates["config_sensitive_file"] = model.JSONMap(req.ConfigSensitiveFile)
	}
	if req.ConfigSensitiveWord != nil {
		updates["config_sensitive_word"] = model.JSONMap(req.ConfigSensitiveWord)
	}
	if req.ConfigBlacklink != nil {
		updates["config_blacklink"] = model.JSONMap(req.ConfigBlacklink)
	}
	if len(updates) == 0 {
		return nil
	}
	return s.session().WithContext(ctx).Model(&model.MonitorTask{}).Where("id IN ?", req.Ids).Updates(updates).Error
}

func (s *serviceMonitor) UpdateTaskFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	return s.session().WithContext(ctx).Model(&model.MonitorTask{}).Where("id = ?", id).Updates(fields).Error
}

func (s *serviceMonitor) BatchUpdateTaskFields(ctx context.Context, ids []string, fields map[string]any) error {
	if len(fields) == 0 || len(ids) == 0 {
		return nil
	}
	return s.session().WithContext(ctx).Model(&model.MonitorTask{}).Where("id IN ?", ids).Updates(fields).Error
}

func (s *serviceMonitor) BatchSyncNames(ctx context.Context, ids []string) (int, error) {
	var tasks []model.MonitorTask
	if err := s.session().WithContext(ctx).Where("id IN ?", ids).Find(&tasks).Error; err != nil {
		return 0, err
	}
	synced := 0
	for _, task := range tasks {
		title := fetchPageTitle(task.TargetHomepage)
		if title == "" {
			continue
		}
		if err := s.session().WithContext(ctx).Model(&task).Update("task_name", title).Error; err != nil {
			slog.Warn("[SyncNames] 更新失败", "id", task.ID, "error", err)
			continue
		}
		synced++
	}
	return synced, nil
}

func (s *serviceMonitor) BatchDeleteTasks(ctx context.Context, ids []string) error {
	return s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tx.Where("task_id IN ?", ids).Delete(&model.MonitorExecution{})
		return tx.Where("id IN ?", ids).Delete(&model.MonitorTask{}).Error
	})
}
