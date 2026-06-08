package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/monitorcrawl"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

func (s *serviceMonitor) CreateTarget(ctx context.Context, t *model.MonitorTarget) error {
	if err := validateTarget(t); err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = ulid.GenerateID()
	}
	if t.DefaultScheme == "" {
		t.DefaultScheme = "https"
	}
	return s.session().WithContext(ctx).Create(t).Error
}

func validateTarget(t *model.MonitorTarget) error {
	tt := strings.ToLower(strings.TrimSpace(t.TargetType))
	if tt != model.MonitorTargetTypeDomain && tt != model.MonitorTargetTypeIP {
		return fmt.Errorf("target_type 必须为 domain 或 ip")
	}
	if strings.TrimSpace(t.TargetValue) == "" {
		return fmt.Errorf("target_value 不能为空")
	}
	if tt == model.MonitorTargetTypeIP && strings.TrimSpace(t.VirtualHost) == "" {
		return fmt.Errorf("IP 目标必须填写 virtual_host（虚拟主机 Host 头）")
	}
	return nil
}

func (s *serviceMonitor) UpdateTarget(ctx context.Context, id string, req contract.TargetUpdateReq) error {
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
	if req.TargetType != "" {
		updates["target_type"] = req.TargetType
	}
	if req.TargetValue != "" {
		updates["target_value"] = req.TargetValue
	}
	if req.DefaultScheme != "" {
		updates["default_scheme"] = req.DefaultScheme
	}
	if req.VirtualHost != "" {
		updates["virtual_host"] = req.VirtualHost
	}
	if req.ExpectedIPs != "" {
		updates["expected_ips"] = req.ExpectedIPs
	}
	if req.ScheduleEnabled != nil {
		updates["schedule_enabled"] = *req.ScheduleEnabled
	}
	if req.ScheduleCron != "" {
		updates["schedule_cron"] = req.ScheduleCron
	}
	if req.ConfigDomainHijack != nil {
		updates["config_domain_hijack"] = model.JSONMap(req.ConfigDomainHijack)
	}
	if req.ConfigSensitiveFile != nil {
		updates["config_sensitive_file"] = model.JSONMap(req.ConfigSensitiveFile)
	}
	if len(updates) == 0 {
		return nil
	}
	if err := s.session().WithContext(ctx).Model(&model.MonitorTarget{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	return s.syncTargetScheduleFromDimensions(ctx, id)
}

func (s *serviceMonitor) syncTargetScheduleFromDimensions(ctx context.Context, id string) error {
	var t model.MonitorTarget
	if err := s.session().WithContext(ctx).First(&t, "id = ?", id).Error; err != nil {
		return err
	}
	should := t.Enabled && targetHasScheduledDimensions(&t)
	if should == t.ScheduleEnabled {
		return nil
	}
	return s.session().WithContext(ctx).Model(&t).Update("schedule_enabled", should).Error
}

func (s *serviceMonitor) DeleteTarget(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var pathIDs []string
		tx.Model(&model.MonitorPathTask{}).Where("target_id = ?", id).Pluck("id", &pathIDs)
		if len(pathIDs) > 0 {
			tx.Where("path_task_id IN ? OR target_id = ?", pathIDs, id).Delete(&model.MonitorExecution{})
			tx.Where("id IN ?", pathIDs).Delete(&model.MonitorPathTask{})
		} else {
			tx.Where("target_id = ?", id).Delete(&model.MonitorExecution{})
		}
		tx.Where("target_id = ?", id).Delete(&model.MonitorCrawlJob{})
		return tx.Where("id = ?", id).Delete(&model.MonitorTarget{}).Error
	})
}

func (s *serviceMonitor) GetTarget(ctx context.Context, id string) (*model.MonitorTarget, error) {
	var t model.MonitorTarget
	if err := s.session().WithContext(ctx).First(&t, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *serviceMonitor) ListTargets(ctx context.Context, req contract.TargetListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorTarget, error) {
	q := s.session().WithContext(ctx).Model(&model.MonitorTarget{}).Scopes(scopes...)
	if req.Name != "" {
		q = q.Where("name LIKE ?", "%"+req.Name+"%")
	}
	if req.TargetType != "" {
		q = q.Where("target_type = ?", req.TargetType)
	}
	if req.TargetValue != "" {
		q = q.Where("target_value LIKE ?", "%"+req.TargetValue+"%")
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
	var list []model.MonitorTarget
	if err := paginateQuery(q, req.Index, req.Size).Order("created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

func (s *serviceMonitor) RunTarget(ctx context.Context, targetID string, dimensions []string) (*contract.RunTaskOutcome, error) {
	var target model.MonitorTarget
	if err := s.session().WithContext(ctx).First(&target, "id = ?", targetID).Error; err != nil {
		return nil, fmt.Errorf("监测目标不存在")
	}
	if len(dimensions) == 0 {
		for _, dim := range model.MonitorTargetDimensions {
			cfg, err := targetConfigForRun(&target, dim)
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
		execID, err := s.runTargetDimension(ctx, &target, dim)
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

func (s *serviceMonitor) runTargetDimension(ctx context.Context, target *model.MonitorTarget, dimension string) (string, error) {
	cfg, err := targetConfigForRun(target, dimension)
	if err != nil {
		return "", err
	}
	if !configEnabled(cfg) {
		return "", fmt.Errorf("维度 %s 未启用", dimension)
	}
	ep, err := ResolveTargetRootURL(target)
	if err != nil {
		return "", err
	}
	execID := ulid.GenerateID()
	exec := model.MonitorExecution{
		TargetID:  target.ID,
		Dimension: dimension,
		URL:       ep.DisplayURL,
		Status:    "pending",
	}
	exec.ID = execID
	session := s.session().WithContext(ctx)
	if _, err := ExpireStaleExecutionsForScope(session, target.ID, "", dimension); err != nil {
		slog.Warn("expire stale execution", "target_id", target.ID, "dimension", dimension, "error", err)
	}
	if txErr := session.Transaction(func(tx *gorm.DB) error {
		var active int64
		tx.Model(&model.MonitorExecution{}).
			Where("target_id = ? AND path_task_id = '' AND dimension = ? AND status IN ?", target.ID, dimension, []string{"pending", "running"}).
			Count(&active)
		if active > 0 {
			return fmt.Errorf("维度 %s 已有执行中的记录", dimension)
		}
		return tx.Create(&exec).Error
	}); txErr != nil {
		return "", txErr
	}
	if col := model.MonitorTargetLastRunColumn(dimension); col != "" {
		session.Model(target).Update(col, time.Now())
	}
	return execID, nil
}

func (s *serviceMonitor) StartCrawl(ctx context.Context, targetID string, req contract.CrawlStartReq) (*model.MonitorCrawlJob, error) {
	var target model.MonitorTarget
	if err := s.session().WithContext(ctx).First(&target, "id = ?", targetID).Error; err != nil {
		return nil, fmt.Errorf("监测目标不存在")
	}

	var ep *ResolvedEndpoint
	if customURL := strings.TrimSpace(req.StartURL); customURL != "" {
		ep = &ResolvedEndpoint{
			RequestURL:  customURL,
			RequestHost: target.TargetValue,
			DisplayURL:  customURL,
		}
	} else {
		var err error
		ep, err = ResolveTargetRootURL(&target)
		if err != nil {
			return nil, err
		}
	}
	job := &model.MonitorCrawlJob{
		ID:          ulid.GenerateID(),
		TargetID:    targetID,
		Status:      model.MonitorCrawlStatusPending,
		UseHeadless: req.UseHeadless,
		MaxDepth:    req.MaxDepth,
		MaxPages:    req.MaxPages,
		SameHost:    req.SameHost,
	}
	if job.MaxDepth <= 0 {
		job.MaxDepth = 2
	}
	if job.MaxPages <= 0 {
		job.MaxPages = 50
	}
	if err := s.session().WithContext(ctx).Create(job).Error; err != nil {
		return nil, err
	}
	go s.runCrawlJob(job.ID, ep, req)
	return job, nil
}

func (s *serviceMonitor) runCrawlJob(jobID string, ep *ResolvedEndpoint, req contract.CrawlStartReq) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if req.CreatorID != "" {
		ctx = WithCreatorID(ctx, req.CreatorID)
	}

	session := s.session().WithContext(ctx)
	now := time.Now()
	session.Model(&model.MonitorCrawlJob{}).Where("id = ?", jobID).Updates(map[string]any{
		"status": model.MonitorCrawlStatusRunning, "started_at": now,
	})

	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Crawl] panic recovered", "job", jobID, "panic", r)
			s.session().Model(&model.MonitorCrawlJob{}).Where("id = ?", jobID).Updates(map[string]any{
				"status":      model.MonitorCrawlStatusFailed,
				"error":       fmt.Sprintf("internal panic: %v", r),
				"finished_at": time.Now(),
			})
		}
	}()

	var uploader monitorcrawl.ScreenshotUploader
	if s.crawlUploader != nil {
		uploader = func(jpegData []byte, name string) (string, error) {
			return s.crawlUploader(ctx, jpegData, name)
		}
	}

	ssWidth, ssHeight, ssQuality := req.ScreenshotWidth, req.ScreenshotHeight, req.ScreenshotQuality
	if ssWidth == 0 || ssHeight == 0 || ssQuality == 0 {
		if cfg, err := s.GetDefaultConfig(ctx, "screenshot"); err == nil && cfg.ConfigJSON != nil {
			if ssWidth == 0 {
				if v, ok := cfg.ConfigJSON["width"].(float64); ok {
					ssWidth = int(v)
				}
			}
			if ssHeight == 0 {
				if v, ok := cfg.ConfigJSON["height"].(float64); ok {
					ssHeight = int(v)
				}
			}
			if ssQuality == 0 {
				if v, ok := cfg.ConfigJSON["quality"].(float64); ok {
					ssQuality = int(v)
				}
			}
		}
	}

	lastUpdate := time.Now()
	crawlRes := monitorcrawl.Crawl(ctx, monitorcrawl.Options{
		StartURL:    ep.RequestURL,
		RequestHost: ep.RequestHost,
		UseHeadless: req.UseHeadless,
		MaxDepth:    req.MaxDepth,
		MaxPages:    req.MaxPages,
		SameHost:    true,
		Screenshot: monitorcrawl.ScreenshotConfig{
			Width:   ssWidth,
			Height:  ssHeight,
			Quality: ssQuality,
		},
		Uploader: uploader,
		OnPage: func(partial *monitorcrawl.Result) {
			if time.Since(lastUpdate) < 2*time.Second {
				return
			}
			lastUpdate = time.Now()
			raw, _ := json.Marshal(partial)
			s.session().Model(&model.MonitorCrawlJob{}).Where("id = ?", jobID).
				Update("result_json", string(raw))
		},
	})

	fin := time.Now()
	raw, _ := json.Marshal(crawlRes)

	status := model.MonitorCrawlStatusSuccess
	errMsg := ""
	if ctx.Err() != nil {
		status = model.MonitorCrawlStatusFailed
		errMsg = "crawl timed out (5min limit)"
		slog.Warn("[Crawl] timed out", "job", jobID)
	} else if crawlRes == nil || len(crawlRes.Pages) == 0 {
		status = model.MonitorCrawlStatusFailed
		errMsg = "no pages discovered"
	}

	s.session().Model(&model.MonitorCrawlJob{}).Where("id = ?", jobID).Updates(map[string]any{
		"status":      status,
		"result_json": string(raw),
		"error":       errMsg,
		"finished_at": fin,
	})
}

func (s *serviceMonitor) GetCrawlJob(ctx context.Context, id string) (*model.MonitorCrawlJob, error) {
	var job model.MonitorCrawlJob
	if err := s.session().WithContext(ctx).First(&job, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *serviceMonitor) ApplyCrawlPaths(ctx context.Context, jobID string, req contract.CrawlApplyReq) (int, error) {
	job, err := s.GetCrawlJob(ctx, jobID)
	if err != nil {
		return 0, err
	}
	var crawlRes monitorcrawl.Result
	if err := json.Unmarshal([]byte(job.ResultJSON), &crawlRes); err != nil {
		return 0, fmt.Errorf("爬虫结果无效")
	}
	selectedSet := make(map[string]bool, len(req.SelectedURLs))
	for _, u := range req.SelectedURLs {
		selectedSet[u] = true
	}
	filterBySelection := len(selectedSet) > 0

	created := 0
	for _, p := range crawlRes.Pages {
		if filterBySelection && !selectedSet[p.URL] {
			continue
		}
		if req.SkipExisting {
			var cnt int64
			s.session().WithContext(ctx).Model(&model.MonitorPathTask{}).
				Where("target_id = ? AND (url_override = ? OR path = ?)", job.TargetID, p.URL, pathFromURL(p.URL)).
				Count(&cnt)
			if cnt > 0 {
				continue
			}
		}
		name := p.Title
		if name == "" {
			name = p.URL
		}
		pt := &model.MonitorPathTask{
			TargetID:    job.TargetID,
			Name:        name,
			URLOverride: p.URL,
			Enabled:     true,
		}
		pt.ID = ulid.GenerateID()
		seedPathTaskDefaults(pt)
		if err := s.session().WithContext(ctx).Create(pt).Error; err != nil {
			continue
		}
		created++
	}
	return created, nil
}

func pathFromURL(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if j := strings.Index(raw, "/"); j >= 0 {
		return raw[j:]
	}
	return "/"
}
