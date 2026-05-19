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

func (s *serviceMonitor) CreatePathTask(ctx context.Context, pt *model.MonitorPathTask) error {
	if pt.TargetID == "" {
		return fmt.Errorf("target_id 不能为空")
	}
	if strings.TrimSpace(pt.Name) == "" {
		return fmt.Errorf("name 不能为空")
	}
	var target model.MonitorTarget
	if err := s.session().WithContext(ctx).First(&target, "id = ?", pt.TargetID).Error; err != nil {
		return fmt.Errorf("监测目标不存在")
	}
	if pt.Path == "" && pt.URLOverride == "" {
		pt.Path = "/"
	}
	if _, err := ResolvePathTaskURL(&target, pt); err != nil {
		return err
	}
	if pt.ID == "" {
		pt.ID = qulid.GenerateID()
	}
	seedPathTaskDefaults(pt)
	return s.session().WithContext(ctx).Create(pt).Error
}

func seedPathTaskDefaults(pt *model.MonitorPathTask) {
	for _, dim := range model.MonitorPathDimensions {
		if pt.GetDimensionConfig(dim) != nil {
			continue
		}
		if seed, ok := model.MonitorDefaultConfigSeeds[dim]; ok {
			cp := model.JSONMap{}
			for k, v := range seed {
				cp[k] = v
			}
			pt.SetDimensionConfig(dim, cp)
		}
	}
	if pathTaskHasScheduledDimensions(pt) {
		pt.ScheduleEnabled = true
	}
}

func (s *serviceMonitor) UpdatePathTask(ctx context.Context, id string, req contract.PathTaskUpdateReq) error {
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Notes != "" {
		updates["notes"] = req.Notes
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.Path != "" {
		updates["path"] = req.Path
	}
	if req.URLOverride != "" {
		updates["url_override"] = req.URLOverride
	}
	if req.ScheduleEnabled != nil {
		updates["schedule_enabled"] = *req.ScheduleEnabled
	}
	if req.ScheduleCron != "" {
		updates["schedule_cron"] = req.ScheduleCron
	}
	if req.ConfigAvailability != nil {
		updates["config_availability"] = model.JSONMap(req.ConfigAvailability)
	}
	if req.ConfigTamper != nil {
		updates["config_tamper"] = model.JSONMap(req.ConfigTamper)
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
	if err := s.session().WithContext(ctx).Model(&model.MonitorPathTask{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	return s.syncPathTaskScheduleFromDimensions(ctx, id)
}

// syncPathTaskScheduleFromDimensions 有已启用且带周期的维度时自动打开 schedule_enabled。
func (s *serviceMonitor) syncPathTaskScheduleFromDimensions(ctx context.Context, id string) error {
	var pt model.MonitorPathTask
	if err := s.session().WithContext(ctx).First(&pt, "id = ?", id).Error; err != nil {
		return err
	}
	should := pt.Enabled && pathTaskHasScheduledDimensions(&pt)
	if should == pt.ScheduleEnabled {
		return nil
	}
	return s.session().WithContext(ctx).Model(&pt).Update("schedule_enabled", should).Error
}

func (s *serviceMonitor) DeletePathTask(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tx.Where("path_task_id = ?", id).Delete(&model.MonitorExecution{})
		return tx.Where("id = ?", id).Delete(&model.MonitorPathTask{}).Error
	})
}

func (s *serviceMonitor) GetPathTask(ctx context.Context, id string) (*model.MonitorPathTask, error) {
	var pt model.MonitorPathTask
	if err := s.session().WithContext(ctx).First(&pt, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &pt, nil
}

func (s *serviceMonitor) ListPathTasks(ctx context.Context, req contract.PathTaskListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorPathTask, error) {
	q := s.session().WithContext(ctx).Model(&model.MonitorPathTask{}).Scopes(scopes...)
	if req.TargetID != "" {
		q = q.Where("target_id = ?", req.TargetID)
	}
	if req.Name != "" {
		q = q.Where("name LIKE ?", "%"+req.Name+"%")
	}
	if req.Enabled == "true" {
		q = q.Where("enabled = ?", true)
	} else if req.Enabled == "false" {
		q = q.Where("enabled = ?", false)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	var list []model.MonitorPathTask
	if err := paginateQuery(q, req.Index, req.Size).Order("created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

// RunPathTask 手动执行路径任务（兼容旧 RunTask 入口）。
func (s *serviceMonitor) RunPathTask(ctx context.Context, id string, dimensions []string) (*contract.RunTaskOutcome, error) {
	var pt model.MonitorPathTask
	if err := s.session().WithContext(ctx).First(&pt, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("路径任务不存在")
	}
	var target model.MonitorTarget
	if err := s.session().WithContext(ctx).First(&target, "id = ?", pt.TargetID).Error; err != nil {
		return nil, fmt.Errorf("监测目标不存在")
	}
	if len(dimensions) == 0 {
		for _, dim := range model.MonitorPathDimensions {
			cfg, err := pathConfigForRun(&pt, dim)
			if err != nil {
				continue
			}
			if configEnabled(cfg) {
				dimensions = append(dimensions, dim)
			}
		}
	}
	outcome := &contract.RunTaskOutcome{ExecutionIDs: []string{}, Skipped: []contract.RunTaskSkip{}}
	for _, dim := range dimensions {
		execID, err := s.runPathTaskDimension(ctx, &target, &pt, dim)
		if err != nil {
			outcome.Skipped = append(outcome.Skipped, contract.RunTaskSkip{Dimension: dim, Reason: err.Error()})
			continue
		}
		outcome.ExecutionIDs = append(outcome.ExecutionIDs, execID)
	}
	if len(outcome.ExecutionIDs) == 0 && len(outcome.Skipped) > 0 {
		return outcome, fmt.Errorf("所有维度执行失败: %s", formatRunTaskSkips(outcome.Skipped))
	}
	return outcome, nil
}

func (s *serviceMonitor) runPathTaskDimension(ctx context.Context, target *model.MonitorTarget, pt *model.MonitorPathTask, dimension string) (string, error) {
	cfg, err := pathConfigForRun(pt, dimension)
	if err != nil {
		return "", err
	}
	if !configEnabled(cfg) {
		return "", fmt.Errorf("维度 %s 未启用", dimension)
	}
	ep, err := ResolvePathTaskURL(target, pt)
	if err != nil {
		return "", err
	}
	execID := qulid.GenerateID()
	exec := model.MonitorExecution{
		TargetID:   target.ID,
		PathTaskID: pt.ID,
		Dimension:  dimension,
		URL:        ep.DisplayURL,
		Status:     "pending",
	}
	exec.ID = execID
	session := s.session().WithContext(ctx)
	if _, err := ExpireStaleExecutionsForScope(session, target.ID, pt.ID, dimension); err != nil {
		slog.Warn("expire stale execution", "path_task_id", pt.ID, "dimension", dimension, "error", err)
	}
	if txErr := session.Transaction(func(tx *gorm.DB) error {
		var active int64
		tx.Model(&model.MonitorExecution{}).
			Where("path_task_id = ? AND dimension = ? AND status IN ?", pt.ID, dimension, []string{"pending", "running"}).
			Count(&active)
		if active > 0 {
			return fmt.Errorf("维度 %s 已有执行中的记录", dimension)
		}
		return tx.Create(&exec).Error
	}); txErr != nil {
		return "", txErr
	}
	if col := model.MonitorPathLastRunColumn(dimension); col != "" {
		session.Model(pt).Update(col, time.Now())
	}
	return execID, nil
}

func (s *serviceMonitor) BatchDeletePathTasks(ctx context.Context, ids []string) error {
	return s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tx.Where("path_task_id IN ?", ids).Delete(&model.MonitorExecution{})
		return tx.Where("id IN ?", ids).Delete(&model.MonitorPathTask{}).Error
	})
}
