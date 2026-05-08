package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"vulnscan-backend/model"
)

func (s *NatsServiceImpl) SyncWordLibraryToKV(ctx context.Context, libraryID string) error {
	if s.nats == nil || s.nats.KV == nil {
		return fmt.Errorf("NATS KV未初始化")
	}
	session, err := s.db.GetDBSession()
	if err != nil {
		return fmt.Errorf("获取数据库会话失败: %w", err)
	}

	var lib model.MonitorWordLibrary
	if err := session.WithContext(ctx).Where("id = ?", libraryID).First(&lib).Error; err != nil {
		return fmt.Errorf("词库不存在: %w", err)
	}

	kvCats := make(map[string]map[string][]string)
	totalWords := 0

	var categories []model.MonitorWordCategory
	if err := session.WithContext(ctx).Where("library_id = ?", libraryID).Order("created_at ASC").Find(&categories).Error; err != nil {
		return fmt.Errorf("查询词库分类失败: %w", err)
	}
	for _, cat := range categories {
		var entries []model.MonitorWordEntry
		if err := session.WithContext(ctx).Where("category_id = ?", cat.ID).Find(&entries).Error; err != nil {
			return fmt.Errorf("查询词条失败(category=%s): %w", cat.ID, err)
		}
		if len(entries) == 0 {
			continue
		}
		sevMap, ok := kvCats[cat.Name]
		if !ok {
			sevMap = make(map[string][]string)
			kvCats[cat.Name] = sevMap
		}
		for _, e := range entries {
			sev := e.Severity
			if sev == "" {
				sev = "medium"
			}
			sevMap[sev] = append(sevMap[sev], e.Word)
			totalWords++
		}
	}

	payload := map[string]any{
		"id":         libraryID,
		"name":       lib.Name,
		"categories": kvCats,
	}
	data, _ := json.Marshal(payload)
	key := fmt.Sprintf("lib/word/%s", libraryID)
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(200<<uint(attempt-1)) * time.Millisecond)
		}
		if _, err = s.nats.KV.Put(ctx, key, data); err == nil {
			slog.Info("[NATS KV] 词库同步成功", "key", key, "words", totalWords)
			return nil
		}
	}
	return fmt.Errorf("写入KV失败（已重试3次）: %w", err)
}

func (s *NatsServiceImpl) DeleteWordLibraryFromKV(ctx context.Context, libraryID string) error {
	if s.nats == nil || s.nats.KV == nil {
		return nil
	}
	return s.nats.KV.Delete(ctx, fmt.Sprintf("lib/word/%s", libraryID))
}

func (s *NatsServiceImpl) SyncFileLibraryToKV(ctx context.Context, libraryID string) error {
	if s.nats == nil || s.nats.KV == nil {
		return fmt.Errorf("NATS KV未初始化")
	}
	session, err := s.db.GetDBSession()
	if err != nil {
		return fmt.Errorf("获取数据库会话失败: %w", err)
	}

	var lib model.MonitorFileLibrary
	if err := session.WithContext(ctx).Where("id = ?", libraryID).First(&lib).Error; err != nil {
		return fmt.Errorf("文件库不存在: %w", err)
	}

	var entries []model.MonitorFileEntry
	if err := session.WithContext(ctx).Where("library_id = ?", libraryID).Find(&entries).Error; err != nil {
		return fmt.Errorf("查询文件条目失败: %w", err)
	}

	type fileItem struct {
		Path string `json:"path"`
		Mark string `json:"mark"`
		Risk string `json:"risk"`
	}
	items := make([]fileItem, 0, len(entries))
	for _, e := range entries {
		risk := e.Risk
		if risk == "" {
			risk = "high"
		}
		items = append(items, fileItem{Path: e.Path, Mark: e.Mark, Risk: risk})
	}

	payload := map[string]any{
		"id":      libraryID,
		"name":    lib.Name,
		"entries": items,
	}
	data, _ := json.Marshal(payload)
	key := fmt.Sprintf("lib/file/%s", libraryID)
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(200<<uint(attempt-1)) * time.Millisecond)
		}
		if _, err = s.nats.KV.Put(ctx, key, data); err == nil {
			slog.Info("[NATS KV] 文件库同步成功", "key", key, "paths", len(items))
			return nil
		}
	}
	return fmt.Errorf("写入KV失败（已重试3次）: %w", err)
}

func (s *NatsServiceImpl) DeleteFileLibraryFromKV(ctx context.Context, libraryID string) error {
	if s.nats == nil || s.nats.KV == nil {
		return nil
	}
	return s.nats.KV.Delete(ctx, fmt.Sprintf("lib/file/%s", libraryID))
}

func (s *NatsServiceImpl) SyncRuleDataToKV(ctx context.Context, kvKey string, data []byte) error {
	if s.nats == nil || s.nats.KV == nil {
		return fmt.Errorf("NATS KV未初始化")
	}
	_, err := s.nats.KV.Put(ctx, kvKey, data)
	if err != nil {
		return fmt.Errorf("写入KV失败: %w", err)
	}
	slog.Info("[NATS KV] 规则数据同步成功", "key", kvKey, "size", len(data))
	return nil
}

func (s *NatsServiceImpl) ListKVKeysByPrefix(ctx context.Context, prefix string) ([]string, error) {
	if s.nats == nil || s.nats.KV == nil {
		return nil, fmt.Errorf("NATS KV未初始化")
	}
	lister, err := s.nats.KV.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("列举KV keys失败: %w", err)
	}
	var keys []string
	for key := range lister.Keys() {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (s *NatsServiceImpl) DeleteKVKey(ctx context.Context, key string) error {
	if s.nats == nil || s.nats.KV == nil {
		return nil
	}
	return s.nats.KV.Delete(ctx, key)
}
