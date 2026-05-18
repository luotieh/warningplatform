package sitemonitor

import (
	"context"
	"fmt"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

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

func (s *serviceMonitor) UpdateWordLibrary(ctx context.Context, id string, req contract.WordLibraryUpdateReq) error {
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

func (s *serviceMonitor) GetWordLibrary(ctx context.Context, id string) (*contract.WordLibraryDetail, error) {
	var lib model.MonitorWordLibrary
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&lib).Error; err != nil {
		return nil, fmt.Errorf("词库不存在")
	}
	var cats []model.MonitorWordCategory
	s.session().WithContext(ctx).Where("library_id = ?", id).Find(&cats)

	detail := &contract.WordLibraryDetail{
		MonitorWordLibrary: lib,
		Categories:         make([]contract.WordCategoryWithEntries, 0, len(cats)),
	}
	var totalWords int64
	for _, cat := range cats {
		var entries []model.MonitorWordEntry
		s.session().WithContext(ctx).Where("category_id = ?", cat.ID).Find(&entries)
		totalWords += int64(len(entries))
		detail.Categories = append(detail.Categories, contract.WordCategoryWithEntries{
			MonitorWordCategory: cat,
			Entries:             entries,
			EntryCount:          int64(len(entries)),
		})
	}
	detail.TotalWords = totalWords
	return detail, nil
}

func (s *serviceMonitor) ListWordLibraries(ctx context.Context, req contract.WordLibraryListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorWordLibrary, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorWordLibrary{}).Scopes(scopes...)
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

func (s *serviceMonitor) UpdateWordCategory(ctx context.Context, id string, req contract.WordCategoryUpdateReq) error {
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

func (s *serviceMonitor) ListWordEntries(ctx context.Context, req contract.WordEntryListReq) (int64, []model.MonitorWordEntry, error) {
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

func (s *serviceMonitor) UpdateFileLibrary(ctx context.Context, id string, req contract.FileLibraryUpdateReq) error {
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

func (s *serviceMonitor) GetFileLibrary(ctx context.Context, id string) (*contract.FileLibraryDetail, error) {
	var lib model.MonitorFileLibrary
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&lib).Error; err != nil {
		return nil, fmt.Errorf("文件库不存在")
	}
	var totalFiles int64
	s.session().WithContext(ctx).Model(&model.MonitorFileEntry{}).Where("library_id = ?", id).Count(&totalFiles)
	return &contract.FileLibraryDetail{MonitorFileLibrary: lib, TotalFiles: totalFiles}, nil
}

func (s *serviceMonitor) ListFileLibraries(ctx context.Context, req contract.FileLibraryListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorFileLibrary, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorFileLibrary{}).Scopes(scopes...)
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

func (s *serviceMonitor) ListFileEntries(ctx context.Context, req contract.FileEntryListReq) (int64, []model.MonitorFileEntry, error) {
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
