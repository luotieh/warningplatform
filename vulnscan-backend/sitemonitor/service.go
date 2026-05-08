package sitemonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/model"
	mc "vulnscan-backend/sitemonitor/sitemonitor-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"github.com/xuri/excelize/v2"
	"golang.org/x/net/html"
	"gorm.io/gorm"
)

type serviceMonitor struct {
	db   *db.DB
	nats *NatsServiceImpl
}

func NewServiceMonitor(database *db.DB) *serviceMonitor {
	return &serviceMonitor{db: database}
}

func (s *serviceMonitor) GetDB() *db.DB { return s.db }

func (s *serviceMonitor) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func paginateQuery(query *gorm.DB, index, size int) *gorm.DB {
	if size <= 0 {
		size = 20
	}
	offset := 0
	if index > 0 && size > 0 {
		offset = (index - 1) * size
	}
	return query.Offset(offset).Limit(size)
}

// ══ KV 同步辅助（3次指数退避） ══

func (s *serviceMonitor) retryKVSync(ctx context.Context, fn func() error, label string) {
	if s.nats == nil {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(200<<uint(attempt-1)) * time.Millisecond)
		}
		if err := fn(); err != nil {
			slog.Warn("[Monitor] KV同步失败", "label", label, "attempt", attempt+1, "error", err)
			continue
		}
		return
	}
	slog.Error("[Monitor] KV同步最终失败", "label", label)
}

// ══ 词库 ══

func (s *serviceMonitor) CreateWordLibrary(ctx context.Context, lib *model.MonitorWordLibrary) error {
	if lib.ID == "" {
		lib.ID = qulid.GenerateID()
	}
	if err := s.session().WithContext(ctx).Create(lib).Error; err != nil {
		return fmt.Errorf("创建词库失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, lib.ID) }, "word-lib-create:"+lib.ID)
	return nil
}

func (s *serviceMonitor) UpdateWordLibrary(ctx context.Context, id string, req mc.WordLibraryUpdateReq) error {
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if len(updates) == 0 {
		return nil
	}
	if err := s.session().WithContext(ctx).Model(&model.MonitorWordLibrary{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新词库失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, id) }, "word-lib-update:"+id)
	return nil
}

func (s *serviceMonitor) DeleteWordLibrary(ctx context.Context, id string) error {
	err := s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var cats []model.MonitorWordCategory
		if err := tx.Where("library_id = ?", id).Find(&cats).Error; err != nil {
			return err
		}
		catIDs := make([]string, 0, len(cats))
		for _, c := range cats {
			catIDs = append(catIDs, c.ID)
		}
		if len(catIDs) > 0 {
			if err := tx.Where("category_id IN ?", catIDs).Delete(&model.MonitorWordEntry{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("library_id = ?", id).Delete(&model.MonitorWordCategory{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.MonitorWordLibrary{}).Error
	})
	if err != nil {
		return fmt.Errorf("删除词库失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.DeleteWordLibraryFromKV(ctx, id) }, "word-lib-delete:"+id)
	return nil
}

func (s *serviceMonitor) GetWordLibrary(ctx context.Context, id string) (*mc.WordLibraryDetail, error) {
	var lib model.MonitorWordLibrary
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&lib).Error; err != nil {
		return nil, fmt.Errorf("词库不存在")
	}
	var cats []model.MonitorWordCategory
	s.session().WithContext(ctx).Where("library_id = ?", id).Find(&cats)

	detail := &mc.WordLibraryDetail{
		MonitorWordLibrary: lib,
		Categories:         make([]mc.WordCategoryWithEntries, 0, len(cats)),
	}
	var totalWords int64
	for _, cat := range cats {
		var entries []model.MonitorWordEntry
		s.session().WithContext(ctx).Where("category_id = ?", cat.ID).Find(&entries)
		totalWords += int64(len(entries))
		detail.Categories = append(detail.Categories, mc.WordCategoryWithEntries{
			MonitorWordCategory: cat,
			Entries:             entries,
			EntryCount:          int64(len(entries)),
		})
	}
	detail.TotalWords = totalWords
	return detail, nil
}

func (s *serviceMonitor) ListWordLibraries(ctx context.Context, req mc.WordLibraryListReq) (int64, []model.MonitorWordLibrary, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorWordLibrary{})
	if req.Name != "" {
		query = query.Where("name LIKE ?", "%"+req.Name+"%")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	var list []model.MonitorWordLibrary
	if err := paginateQuery(query, req.Index, req.Size).Order("created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

// ══ 词库分类 ══

func (s *serviceMonitor) CreateWordCategory(ctx context.Context, cat *model.MonitorWordCategory) error {
	if cat.ID == "" {
		cat.ID = qulid.GenerateID()
	}
	if err := s.session().WithContext(ctx).Create(cat).Error; err != nil {
		return fmt.Errorf("创建分类失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, cat.LibraryID) }, "word-cat-create")
	return nil
}

func (s *serviceMonitor) UpdateWordCategory(ctx context.Context, id string, req mc.WordCategoryUpdateReq) error {
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if err := s.session().WithContext(ctx).Model(&model.MonitorWordCategory{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新分类失败: %w", err)
	}
	var cat model.MonitorWordCategory
	if s.session().WithContext(ctx).Where("id = ?", id).First(&cat).Error == nil {
		s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, cat.LibraryID) }, "word-cat-update")
	}
	return nil
}

func (s *serviceMonitor) DeleteWordCategory(ctx context.Context, id string) error {
	var cat model.MonitorWordCategory
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&cat).Error; err != nil {
		return fmt.Errorf("分类不存在")
	}
	err := s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("category_id = ?", id).Delete(&model.MonitorWordEntry{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.MonitorWordCategory{}).Error
	})
	if err != nil {
		return fmt.Errorf("删除分类失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, cat.LibraryID) }, "word-cat-delete")
	return nil
}

func (s *serviceMonitor) ListWordCategories(ctx context.Context, libraryID string) ([]model.MonitorWordCategory, error) {
	var cats []model.MonitorWordCategory
	if err := s.session().WithContext(ctx).Where("library_id = ?", libraryID).Order("created_at ASC").Find(&cats).Error; err != nil {
		return nil, err
	}
	return cats, nil
}

// ══ 词条 ══

func (s *serviceMonitor) BatchCreateWordEntries(ctx context.Context, entries []model.MonitorWordEntry) error {
	if err := s.session().WithContext(ctx).CreateInBatches(entries, 100).Error; err != nil {
		return fmt.Errorf("批量创建词条失败: %w", err)
	}
	synced := map[string]bool{}
	for _, e := range entries {
		if synced[e.CategoryID] {
			continue
		}
		synced[e.CategoryID] = true
		var cat model.MonitorWordCategory
		if s.session().WithContext(ctx).Where("id = ?", e.CategoryID).First(&cat).Error == nil {
			if !synced[cat.LibraryID] {
				synced[cat.LibraryID] = true
				s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, cat.LibraryID) }, "word-entry-create")
			}
		}
	}
	return nil
}

func (s *serviceMonitor) DeleteWordEntries(ctx context.Context, ids []int64) error {
	var entries []model.MonitorWordEntry
	s.session().WithContext(ctx).Where("id IN ?", ids).Find(&entries)
	affectedLibs := map[string]bool{}
	for _, e := range entries {
		var cat model.MonitorWordCategory
		if s.session().WithContext(ctx).Where("id = ?", e.CategoryID).First(&cat).Error == nil {
			affectedLibs[cat.LibraryID] = true
		}
	}
	if err := s.session().WithContext(ctx).Where("id IN ?", ids).Delete(&model.MonitorWordEntry{}).Error; err != nil {
		return fmt.Errorf("删除词条失败: %w", err)
	}
	for libID := range affectedLibs {
		lid := libID
		s.retryKVSync(ctx, func() error { return s.nats.SyncWordLibraryToKV(ctx, lid) }, "word-entry-delete")
	}
	return nil
}

func (s *serviceMonitor) ListWordEntries(ctx context.Context, req mc.WordEntryListReq) (int64, []model.MonitorWordEntry, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorWordEntry{}).Where("category_id = ?", req.CategoryID)
	if req.Word != "" {
		query = query.Where("word LIKE ?", "%"+req.Word+"%")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	size := req.Size
	if size <= 0 {
		size = 50
	}
	var list []model.MonitorWordEntry
	if err := paginateQuery(query, req.Index, size).Order("id ASC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

// ══ 文件库 ══

func (s *serviceMonitor) CreateFileLibrary(ctx context.Context, lib *model.MonitorFileLibrary) error {
	if lib.ID == "" {
		lib.ID = qulid.GenerateID()
	}
	if err := s.session().WithContext(ctx).Create(lib).Error; err != nil {
		return fmt.Errorf("创建文件库失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.SyncFileLibraryToKV(ctx, lib.ID) }, "file-lib-create:"+lib.ID)
	return nil
}

func (s *serviceMonitor) UpdateFileLibrary(ctx context.Context, id string, req mc.FileLibraryUpdateReq) error {
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if len(updates) == 0 {
		return nil
	}
	if err := s.session().WithContext(ctx).Model(&model.MonitorFileLibrary{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新文件库失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.SyncFileLibraryToKV(ctx, id) }, "file-lib-update:"+id)
	return nil
}

func (s *serviceMonitor) DeleteFileLibrary(ctx context.Context, id string) error {
	err := s.session().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("library_id = ?", id).Delete(&model.MonitorFileEntry{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.MonitorFileLibrary{}).Error
	})
	if err != nil {
		return fmt.Errorf("删除文件库失败: %w", err)
	}
	s.retryKVSync(ctx, func() error { return s.nats.DeleteFileLibraryFromKV(ctx, id) }, "file-lib-delete:"+id)
	return nil
}

func (s *serviceMonitor) GetFileLibrary(ctx context.Context, id string) (*mc.FileLibraryDetail, error) {
	var lib model.MonitorFileLibrary
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&lib).Error; err != nil {
		return nil, fmt.Errorf("文件库不存在")
	}
	var totalFiles int64
	s.session().WithContext(ctx).Model(&model.MonitorFileEntry{}).Where("library_id = ?", id).Count(&totalFiles)
	return &mc.FileLibraryDetail{MonitorFileLibrary: lib, TotalFiles: totalFiles}, nil
}

func (s *serviceMonitor) ListFileLibraries(ctx context.Context, req mc.FileLibraryListReq) (int64, []model.MonitorFileLibrary, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorFileLibrary{})
	if req.Name != "" {
		query = query.Where("name LIKE ?", "%"+req.Name+"%")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	var list []model.MonitorFileLibrary
	if err := paginateQuery(query, req.Index, req.Size).Order("created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

// ══ 文件条目 ══

func (s *serviceMonitor) BatchCreateFileEntries(ctx context.Context, entries []model.MonitorFileEntry) error {
	for i, e := range entries {
		if e.Risk != "" && !model.MonitorValidSeverities[e.Risk] {
			return fmt.Errorf("第%d条 risk 值无效: %s", i+1, e.Risk)
		}
		if e.Risk == "" {
			entries[i].Risk = "high"
		}
	}
	if err := s.session().WithContext(ctx).CreateInBatches(entries, 100).Error; err != nil {
		return fmt.Errorf("批量创建文件条目失败: %w", err)
	}
	synced := map[string]bool{}
	for _, e := range entries {
		if !synced[e.LibraryID] {
			synced[e.LibraryID] = true
			lid := e.LibraryID
			s.retryKVSync(ctx, func() error { return s.nats.SyncFileLibraryToKV(ctx, lid) }, "file-entry-create")
		}
	}
	return nil
}

func (s *serviceMonitor) DeleteFileEntries(ctx context.Context, ids []int64) error {
	var entries []model.MonitorFileEntry
	s.session().WithContext(ctx).Where("id IN ?", ids).Find(&entries)
	affectedLibs := map[string]bool{}
	for _, e := range entries {
		affectedLibs[e.LibraryID] = true
	}
	if err := s.session().WithContext(ctx).Where("id IN ?", ids).Delete(&model.MonitorFileEntry{}).Error; err != nil {
		return fmt.Errorf("删除文件条目失败: %w", err)
	}
	for libID := range affectedLibs {
		lid := libID
		s.retryKVSync(ctx, func() error { return s.nats.SyncFileLibraryToKV(ctx, lid) }, "file-entry-delete")
	}
	return nil
}

func (s *serviceMonitor) CountFileEntryByPath(ctx context.Context, libraryID, path string, count *int64) {
	s.session().WithContext(ctx).Model(&model.MonitorFileEntry{}).
		Where("library_id = ? AND path = ?", libraryID, path).Count(count)
}

func (s *serviceMonitor) ListFileEntries(ctx context.Context, req mc.FileEntryListReq) (int64, []model.MonitorFileEntry, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorFileEntry{}).Where("library_id = ?", req.LibraryID)
	if req.Path != "" {
		query = query.Where("path LIKE ?", "%"+req.Path+"%")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	size := req.Size
	if size <= 0 {
		size = 50
	}
	var list []model.MonitorFileEntry
	if err := paginateQuery(query, req.Index, size).Order("id ASC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

// ══ 默认配置 ══

func (s *serviceMonitor) ListDefaultConfigs(ctx context.Context) ([]model.MonitorDefaultConfig, error) {
	var configs []model.MonitorDefaultConfig
	if err := s.session().WithContext(ctx).Find(&configs).Error; err != nil {
		return nil, err
	}
	return configs, nil
}

func (s *serviceMonitor) GetDefaultConfig(ctx context.Context, dimension string) (*model.MonitorDefaultConfig, error) {
	var cfg model.MonitorDefaultConfig
	if err := s.session().WithContext(ctx).Where("dimension = ?", dimension).First(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *serviceMonitor) UpdateDefaultConfig(ctx context.Context, dimension string, configJSON map[string]any) error {
	return s.session().WithContext(ctx).Model(&model.MonitorDefaultConfig{}).
		Where("dimension = ?", dimension).
		Update("config_json", configJSON).Error
}

// ══ 任务 ══

func (s *serviceMonitor) CreateTask(ctx context.Context, task *model.MonitorTask) error {
	if task.ID == "" {
		task.ID = qulid.GenerateID()
	}
	return s.session().WithContext(ctx).Create(task).Error
}

func (s *serviceMonitor) UpdateTask(ctx context.Context, id string, req mc.TaskUpdateReq) error {
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

func (s *serviceMonitor) ListTasks(ctx context.Context, req mc.TaskListReq) (int64, []model.MonitorTask, error) {
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

func (s *serviceMonitor) BatchUpdateConfigs(ctx context.Context, req mc.BatchUpdateConfigsReq) error {
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

// ══ 执行记录 ══

func (s *serviceMonitor) ListExecutions(ctx context.Context, req mc.ExecutionListReq) (int64, []model.MonitorExecution, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorExecution{})
	if req.TaskID != "" {
		query = query.Where("task_id = ?", req.TaskID)
	}
	if req.Dimension != "" {
		query = query.Where("dimension = ?", req.Dimension)
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.HasIssue == "true" {
		query = query.Where("has_issue = ?", true)
	} else if req.HasIssue == "false" {
		query = query.Where("has_issue = ?", false)
	}
	if req.Disposition != "" {
		query = query.Where("disposition = ?", req.Disposition)
	}
	if req.TimeStart != "" {
		query = query.Where("created_at >= ?", req.TimeStart)
	}
	if req.TimeEnd != "" {
		query = query.Where("created_at <= ?", req.TimeEnd)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	var list []model.MonitorExecution
	if err := paginateQuery(query, req.Index, req.Size).Order("created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

func (s *serviceMonitor) GetExecutionDetail(ctx context.Context, id string) (*mc.ExecutionDetail, error) {
	var exec model.MonitorExecution
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&exec).Error; err != nil {
		return nil, err
	}
	detail := &mc.ExecutionDetail{MonitorExecution: exec}
	if exec.Dimension == "sensitive_word" {
		var wr model.MonitorResultSensitiveWord
		if s.session().WithContext(ctx).Where("execution_id = ?", id).First(&wr).Error == nil {
			detail.WordResult = &wr
			var matches []model.MonitorResultSensitiveWordMatch
			s.session().WithContext(ctx).Where("result_id = ?", wr.ID).Find(&matches)
			detail.WordMatches = matches
		}
	}
	if exec.Dimension == "sensitive_file" {
		var fr model.MonitorResultSensitiveFile
		if s.session().WithContext(ctx).Where("execution_id = ?", id).First(&fr).Error == nil {
			detail.FileResult = &fr
			var findings []model.MonitorResultSensitiveFileFinding
			s.session().WithContext(ctx).Where("result_id = ?", fr.ID).Find(&findings)
			detail.FileFindings = findings
		}
	}
	if exec.Dimension == "availability" {
		var baseline model.MonitorPerfBaseline
		if s.session().WithContext(ctx).Where("task_id = ?", exec.TaskID).First(&baseline).Error == nil {
			detail.PerfBaseline = &baseline
		}
	}
	return detail, nil
}

func (s *serviceMonitor) GetEvidenceAsset(ctx context.Context, executionID, assetType string) ([]byte, string, error) {
	if s.nats == nil {
		return nil, "", fmt.Errorf("NATS 未连接")
	}
	var exec model.MonitorExecution
	if err := s.session().WithContext(ctx).Where("id = ?", executionID).First(&exec).Error; err != nil {
		return nil, "", fmt.Errorf("执行记录不存在")
	}

	objKey := fmt.Sprintf("evidence/%s/%s", executionID, assetType)
	contentType := "application/octet-stream"

	switch assetType {
	case "html", "text":
		data, err := s.nats.ObjGetGzip(ctx, objKey)
		if err != nil {
			return nil, "", err
		}
		if assetType == "html" {
			contentType = "text/html; charset=utf-8"
		} else {
			contentType = "text/plain; charset=utf-8"
		}
		return data, contentType, nil
	case "screenshot":
		data, err := s.nats.ObjGetRaw(ctx, objKey)
		if err != nil {
			return nil, "", err
		}
		contentType = "image/png"
		return data, contentType, nil
	default:
		data, err := s.nats.ObjGetRaw(ctx, objKey)
		if err != nil {
			return nil, "", err
		}
		return data, contentType, nil
	}
}

func (s *serviceMonitor) DeleteExecution(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Where("id = ?", id).Delete(&model.MonitorExecution{}).Error
}

func (s *serviceMonitor) BatchDeleteExecutions(ctx context.Context, ids []string) error {
	return s.session().WithContext(ctx).Where("id IN ?", ids).Delete(&model.MonitorExecution{}).Error
}

func (s *serviceMonitor) UpdateDisposition(ctx context.Context, id, disposition, remark, username string) error {
	now := time.Now()
	return s.session().WithContext(ctx).Model(&model.MonitorExecution{}).Where("id = ?", id).Updates(map[string]any{
		"disposition":        disposition,
		"disposition_remark": remark,
		"disposed_by":        username,
		"disposed_at":        &now,
	}).Error
}

func (s *serviceMonitor) BatchUpdateDisposition(ctx context.Context, ids []string, disposition, remark, username string) error {
	now := time.Now()
	return s.session().WithContext(ctx).Model(&model.MonitorExecution{}).Where("id IN ?", ids).Updates(map[string]any{
		"disposition":        disposition,
		"disposition_remark": remark,
		"disposed_by":        username,
		"disposed_at":        &now,
	}).Error
}

func (s *serviceMonitor) GetDashboardStats(ctx context.Context) (*mc.DashboardStats, error) {
	db := s.session().WithContext(ctx)
	stats := &mc.DashboardStats{}
	db.Model(&model.MonitorTask{}).Count(&stats.TotalTasks)
	db.Model(&model.MonitorTask{}).Where("enabled = ?", true).Count(&stats.EnabledTasks)
	db.Model(&model.MonitorExecution{}).Count(&stats.TotalExecutions)
	db.Model(&model.MonitorExecution{}).Where("has_issue = ?", true).Count(&stats.IssueExecutions)
	db.Model(&model.MonitorAgent{}).Where("status = ?", "online").Count(&stats.OnlineAgents)
	db.Model(&model.MonitorAgent{}).Count(&stats.TotalAgents)
	return stats, nil
}

func (s *serviceMonitor) GetTaskExecutionStats(ctx context.Context) (map[string]map[string]*mc.TaskDimStat, error) {
	type row struct {
		TaskID     string
		Dimension  string
		Total      int64
		IssueCount int64
		PendingCnt int64
		ValidCnt   int64
	}
	var rows []row
	err := s.session().WithContext(ctx).Raw(`
		SELECT task_id, dimension,
			COUNT(*) as total,
			SUM(CASE WHEN has_issue = 1 THEN 1 ELSE 0 END) as issue_count,
			SUM(CASE WHEN has_issue = 1 AND disposition = 'pending' THEN 1 ELSE 0 END) as pending_cnt,
			SUM(CASE WHEN has_issue = 1 AND disposition = 'valid' THEN 1 ELSE 0 END) as valid_cnt
		FROM monitor_executions GROUP BY task_id, dimension
	`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := map[string]map[string]*mc.TaskDimStat{}
	for _, r := range rows {
		if result[r.TaskID] == nil {
			result[r.TaskID] = map[string]*mc.TaskDimStat{}
		}
		result[r.TaskID][r.Dimension] = &mc.TaskDimStat{
			Total:        r.Total,
			IssueCount:   r.IssueCount,
			PendingCount: r.PendingCnt,
			ValidCount:   r.ValidCnt,
		}
	}
	return result, nil
}

func (s *serviceMonitor) GetTaskTrend(ctx context.Context, taskID string, hours int) (*mc.TaskTrendResp, error) {
	db := s.session().WithContext(ctx)

	var task model.MonitorTask
	if err := db.Where("id = ?", taskID).First(&task).Error; err != nil {
		return nil, err
	}

	resp := &mc.TaskTrendResp{
		TaskID:   task.ID,
		TaskName: task.TaskName,
		URL:      task.TargetHomepage,
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	var execs []model.MonitorExecution
	db.Where("task_id = ? AND dimension = ? AND status = ? AND created_at >= ?",
		taskID, "availability", "success", since).
		Order("created_at ASC").Find(&execs)

	var totalMS, maxMS, minMS float64
	minMS = 1e9
	for _, e := range execs {
		pt := mc.TaskTrendPoint{
			Time:     e.CreatedAt.Format("2006-01-02 15:04"),
			HasIssue: e.HasIssue,
		}
		var rj map[string]any
		if e.ResultJSON != "" {
			if err := json.Unmarshal([]byte(e.ResultJSON), &rj); err == nil {
				pt.Available, _ = rj["available"].(bool)
				if sc, ok := rj["status_code"].(float64); ok {
					pt.StatusCode = int(sc)
				}
				if tm, ok := rj["timing"].(map[string]any); ok {
					pt.TotalMS, _ = tm["total_ms"].(float64)
					pt.DNSMS, _ = tm["dns_ms"].(float64)
					pt.TCPMS, _ = tm["tcp_connect_ms"].(float64)
					pt.TLSMS, _ = tm["tls_handshake_ms"].(float64)
					pt.TTFBMS, _ = tm["ttfb_ms"].(float64)
				}
			}
		}
		resp.Points = append(resp.Points, pt)

		totalMS += pt.TotalMS
		if pt.TotalMS > maxMS {
			maxMS = pt.TotalMS
		}
		if pt.TotalMS > 0 && pt.TotalMS < minMS {
			minMS = pt.TotalMS
		}
		if pt.Available {
			resp.Summary.AvailableCount++
		} else {
			resp.Summary.UnavailableCount++
		}
		if pt.HasIssue {
			resp.Summary.IssueCount++
		}
	}
	resp.Summary.TotalChecks = int64(len(execs))
	if resp.Summary.TotalChecks > 0 {
		resp.Summary.AvgResponseMS = totalMS / float64(resp.Summary.TotalChecks)
		resp.Summary.MaxResponseMS = maxMS
		if minMS < 1e9 {
			resp.Summary.MinResponseMS = minMS
		}
		resp.Summary.AvailabilityPct = float64(resp.Summary.AvailableCount) / float64(resp.Summary.TotalChecks) * 100
	}

	for _, dim := range model.MonitorAllDimensions {
		brief := mc.TaskDimBrief{Dimension: dim}
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ?", taskID, dim).
			Count(&brief.Total)
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND status = ?", taskID, dim, "success").
			Count(&brief.SuccessCount)
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND status = ?", taskID, dim, "failed").
			Count(&brief.FailedCount)
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND has_issue = ?", taskID, dim, true).
			Count(&brief.IssueCount)
		var last model.MonitorExecution
		if db.Where("task_id = ? AND dimension = ?", taskID, dim).
			Order("created_at DESC").First(&last).Error == nil {
			brief.LastStatus = last.Status
			brief.LastTime = last.CreatedAt.Format("2006-01-02 15:04:05")
		}
		resp.Dimensions = append(resp.Dimensions, brief)
	}

	return resp, nil
}

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

// ══ 导入 ══

func (s *serviceMonitor) GenerateImportTemplate(_ context.Context) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	sheet := "监测任务导入"
	f.SetSheetName("Sheet1", sheet)

	headers := []string{
		"系统名称", "首页URL（必填）", "目标域名", "目标IP（多个用逗号分隔）",
		"可用性监测", "域名劫持监测", "篡改监测", "敏感词检测", "敏感文件检测", "黑链检测",
	}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, h)
	}

	dvRange := excelize.NewDataValidation(true)
	dvRange.Sqref = "E2:J1000"
	dvRange.SetDropList([]string{"开启", "关闭"})
	f.AddDataValidation(sheet, dvRange)

	colWidths := map[string]float64{
		"A": 20, "B": 40, "C": 25, "D": 30,
		"E": 12, "F": 12, "G": 12, "H": 12, "I": 12, "J": 12,
	}
	for col, width := range colWidths {
		f.SetColWidth(sheet, col, col, width)
	}

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, fmt.Errorf("生成模板失败: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *serviceMonitor) ImportTasks(ctx context.Context, fileData []byte) (*mc.ImportResult, error) {
	f, err := excelize.OpenReader(bytes.NewReader(fileData))
	if err != nil {
		return nil, fmt.Errorf("Excel解析失败: %w", err)
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("Excel无Sheet页")
	}

	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, fmt.Errorf("读取行数据失败: %w", err)
	}

	result := &mc.ImportResult{
		ID:        qulid.GenerateID(),
		Total:     len(rows) - 1,
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	defaults, _ := s.loadDefaultConfigs(ctx)

	for i, row := range rows {
		if i == 0 {
			continue
		}
		rowResult := mc.ImportRowResult{Row: i + 1}
		if len(row) < 2 || strings.TrimSpace(row[1]) == "" {
			rowResult.Error = "首页URL为空"
			result.Failed++
			result.Results = append(result.Results, rowResult)
			continue
		}

		targetURL := strings.TrimSpace(row[1])
		rowResult.URL = targetURL

		task := model.MonitorTask{
			TargetHomepage: targetURL,
		}
		task.ID = qulid.GenerateID()
		if len(row) > 0 {
			task.TaskName = strings.TrimSpace(row[0])
		}
		if task.TaskName == "" {
			task.TaskName = targetURL
		}
		rowResult.Name = task.TaskName
		if len(row) > 2 {
			task.TargetDomain = strings.TrimSpace(row[2])
		}
		if len(row) > 3 {
			task.TargetIps = strings.TrimSpace(row[3])
		}
		task.Enabled = true

		dimCols := []struct {
			idx int
			dim string
		}{
			{4, "availability"}, {5, "domain_hijack"}, {6, "tamper"},
			{7, "sensitive_word"}, {8, "sensitive_file"}, {9, "blacklink"},
		}
		for _, dc := range dimCols {
			enabled := true
			if len(row) > dc.idx {
				enabled = strings.TrimSpace(row[dc.idx]) != "关闭"
			}
			cfg := map[string]any{"enabled": enabled}
			if defCfg, ok := defaults[dc.dim]; ok {
				for k, v := range defCfg {
					if k != "enabled" {
						cfg[k] = v
					}
				}
			}
			task.SetDimensionConfig(dc.dim, cfg)
		}

		if err := s.session().WithContext(ctx).Create(&task).Error; err != nil {
			rowResult.Error = err.Error()
			result.Failed++
		} else {
			rowResult.Success = true
			rowResult.TaskID = task.ID
			result.Success++
		}
		result.Results = append(result.Results, rowResult)
	}

	return result, nil
}

func (s *serviceMonitor) loadDefaultConfigs(ctx context.Context) (map[string]map[string]any, error) {
	var configs []model.MonitorDefaultConfig
	if err := s.session().WithContext(ctx).Find(&configs).Error; err != nil {
		return nil, err
	}
	result := make(map[string]map[string]any)
	for _, c := range configs {
		result[c.Dimension] = c.ConfigJSON
	}
	return result, nil
}

func (s *serviceMonitor) GetImportResult(_ context.Context, _ string) (*mc.ImportResult, error) {
	return nil, fmt.Errorf("导入结果缓存未实现（需Redis）")
}

func (s *serviceMonitor) ExportImportResult(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("导出导入结果未实现（需Redis）")
}

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

func (s *serviceMonitor) ListRuleDataSummary(ctx context.Context) ([]mc.RuleDataSummary, error) {
	var allData []model.MonitorRuleData
	s.session().WithContext(ctx).Find(&allData)
	dataMap := map[string]model.MonitorRuleData{}
	for _, d := range allData {
		dataMap[d.ModuleKey] = d
	}
	summaries := make([]mc.RuleDataSummary, 0, len(model.MonitorRuleDataModuleKeys))
	for _, key := range model.MonitorRuleDataModuleKeys {
		def := model.MonitorModuleRegistry[key]
		s := mc.RuleDataSummary{
			ModuleKey:   key,
			Name:        def.Name,
			Description: def.Description,
			Type:        def.Type,
		}
		if d, ok := dataMap[key]; ok {
			s.HasData = d.Data != ""
			s.UpdatedAt = d.UpdatedAt.Format("2006-01-02 15:04:05")
		}
		summaries = append(summaries, s)
	}
	return summaries, nil
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

func (s *serviceMonitor) FetchTaskMeta(_ context.Context, url string) (string, string, error) {
	title := fetchPageTitle(url)
	return title, url, nil
}

func fetchPageTitle(targetURL string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return ""
	}
	return extractTitle(doc)
}

func extractTitle(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "title" {
		if n.FirstChild != nil {
			return strings.TrimSpace(n.FirstChild.Data)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if t := extractTitle(c); t != "" {
			return t
		}
	}
	return ""
}

// HandleAgentResult 处理 Agent 上报的检测结果（HTTP API 入口）
func (s *serviceMonitor) HandleAgentResult(ctx context.Context, ar *model.MonitorAgentResult) {
	session := s.session()
	if session == nil {
		slog.Error("[AgentAPI] DB session error")
		return
	}

	startedAt := parseTime(ar.StartedAt)
	finishedAt := parseTime(ar.FinishedAt)

	exec := model.MonitorExecution{}
	if err := session.Where("id = ?", ar.ExecutionID).First(&exec).Error; err != nil {
		slog.Error("[AgentAPI] execution not found", "eid", ar.ExecutionID)
		return
	}

	if exec.Status == "success" || exec.Status == "failed" {
		canOverride := exec.Status == "failed" && exec.ReapedAt != nil && ar.Status == "success"
		if !canOverride {
			slog.Debug("[AgentAPI] execution already terminal", "eid", ar.ExecutionID, "status", exec.Status)
			return
		}
	}

	txErr := session.Transaction(func(tx *gorm.DB) error {
		exec.AgentID = ar.AgentID
		exec.Status = ar.Status
		exec.Error = ar.Error
		exec.StartedAt = startedAt
		exec.FinishedAt = finishedAt
		exec.ResultJSON = ar.Result
		exec.ReapedAt = nil

		if ar.Status == "failed" {
			return tx.Save(&exec).Error
		}

		saveFn := s.buildResultSaver(tx)
		saveFn(&exec, ar)

		if exec.HasIssue {
			exec.Disposition = model.MonitorDispositionPending
		} else {
			exec.Disposition = model.MonitorDispositionValid
		}

		return tx.Save(&exec).Error
	})

	if txErr != nil {
		slog.Error("[AgentAPI] save result failed", "error", txErr, "eid", ar.ExecutionID)
	} else {
		slog.Info("[AgentAPI] result processed", "eid", ar.ExecutionID, "dim", ar.Dimension, "status", ar.Status)
	}
}

func (s *serviceMonitor) buildResultSaver(tx *gorm.DB) func(*model.MonitorExecution, *model.MonitorAgentResult) {
	nats := s.nats
	return func(exec *model.MonitorExecution, ar *model.MonitorAgentResult) {
		switch ar.Dimension {
		case "sensitive_word":
			var r model.MonitorSensitiveWordResult
			if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
				exec.Error = fmt.Sprintf("结果解析失败: %v", err)
				exec.HasIssue = true
			} else {
				exec.HasIssue = r.HasHit
				if r.Error != "" {
					exec.Error = r.Error
				}
				if nats != nil {
					_ = nats.saveSensitiveWordResult(tx, ar.ExecutionID, ar.TaskID, &r)
				}
			}
		case "sensitive_file":
			var r model.MonitorSensitiveFileResult
			if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
				exec.Error = fmt.Sprintf("结果解析失败: %v", err)
				exec.HasIssue = true
			} else {
				exec.HasIssue = r.HasHit
				if r.Error != "" {
					exec.Error = r.Error
				}
				if nats != nil {
					_ = nats.saveSensitiveFileResult(tx, ar.ExecutionID, ar.TaskID, &r)
				}
			}
		case "tamper":
			var tr model.MonitorTamperResult
			if err := json.Unmarshal([]byte(ar.Result), &tr); err != nil {
				exec.HasIssue = jsonBool(ar.Result, "tampered")
			} else {
				exec.HasIssue = tr.Tampered
				if tr.BaselineUpdate != nil && nats != nil {
					_ = nats.saveBaselineFromResult(tx, ar.ExecutionID, ar.URL, ar.AgentID, tr.BaselineUpdate)
				}
			}
		case "blacklink":
			exec.HasIssue = jsonBool(ar.Result, "has_black")
		case "availability":
			exec.HasIssue = !jsonBool(ar.Result, "available")
		case "domain_hijack":
			exec.HasIssue = jsonBool(ar.Result, "hijacked")
		}
	}
}
