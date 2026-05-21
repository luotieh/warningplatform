package nuclei

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

type PocStore struct {
	db       *gorm.DB
	mu       sync.RWMutex
	entries  []*PocEntry
	lastLoad time.Time
	cacheTTL time.Duration
	version  int64
}

func NewPocStore(db *gorm.DB) *PocStore {
	return &PocStore{
		db:       db,
		cacheTTL: 5 * time.Minute,
	}
}

func NewPocStoreNoDB() *PocStore {
	return &PocStore{
		cacheTTL: 24 * time.Hour,
	}
}

// Invalidate 清空 PoC 内存缓存，下次 LoadAll 从数据库重新加载。
func (s *PocStore) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
	s.lastLoad = time.Time{}
	s.version++
}

func (s *PocStore) LoadAll() []*PocEntry {
	s.mu.RLock()
	if time.Since(s.lastLoad) < s.cacheTTL && len(s.entries) > 0 {
		entries := s.entries
		s.mu.RUnlock()
		return entries
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.lastLoad) < s.cacheTTL && len(s.entries) > 0 {
		return s.entries
	}

	if s.db == nil {
		return s.entries
	}

	var records []model.PocTemplate
	if err := s.db.Where("enabled = ?", true).Find(&records).Error; err != nil {
		slog.Warn("[PocStore] 加载PoC模板失败", "error", err)
		return s.entries
	}

	var entries []*PocEntry
	for _, rec := range records {
		tmpl, err := ParseTemplate([]byte(rec.Content))
		if err != nil {
			slog.Debug("[PocStore] 解析PoC失败", "poc_id", rec.PocID, "error", err)
			continue
		}
		entries = append(entries, &PocEntry{
			ID:         tmpl.ID,
			Name:       tmpl.Info.Name,
			Severity:   tmpl.Info.Severity,
			Tags:       tmpl.Info.Tags,
			RawContent: rec.Content,
		})
	}

	s.entries = entries
	s.lastLoad = time.Now()

	slog.Info("[PocStore] PoC 模板加载完成", "count", len(entries))
	return entries
}

// InvalidateCache 清空内存缓存，便于主控同步或外部写入 DB 后重新加载。
func (s *PocStore) InvalidateCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
	s.lastLoad = time.Time{}
	s.version++
}

func (s *PocStore) LoadByIDs(ids []string) []*PocEntry {
	all := s.LoadAll()
	if len(ids) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			want[strings.ToLower(id)] = struct{}{}
		}
	}
	var filtered []*PocEntry
	seen := make(map[string]struct{})
	for _, entry := range all {
		key := strings.ToLower(entry.ID)
		if _, ok := want[key]; ok {
			if _, dup := seen[key]; !dup {
				filtered = append(filtered, entry)
				seen[key] = struct{}{}
			}
		}
	}
	if len(filtered) > 0 || s.db == nil {
		return filtered
	}
	var records []model.PocTemplate
	if err := s.db.Where("enabled = ?", true).Find(&records).Error; err != nil {
		return filtered
	}
	for _, rec := range records {
		if _, ok := want[strings.ToLower(rec.PocID)]; !ok {
			continue
		}
		tmpl, err := ParseTemplate([]byte(rec.Content))
		if err != nil {
			continue
		}
		key := strings.ToLower(tmpl.ID)
		if _, dup := seen[key]; dup {
			continue
		}
		filtered = append(filtered, &PocEntry{
			ID:         tmpl.ID,
			Name:       tmpl.Info.Name,
			Severity:   tmpl.Info.Severity,
			Tags:       tmpl.Info.Tags,
			RawContent: rec.Content,
		})
		seen[key] = struct{}{}
	}
	return filtered
}

func (s *PocStore) LoadBySeverity(severities []string) []*PocEntry {
	all := s.LoadAll()
	if len(severities) == 0 {
		return all
	}

	set := make(map[string]struct{})
	for _, sev := range severities {
		set[strings.ToLower(sev)] = struct{}{}
	}

	var filtered []*PocEntry
	for _, entry := range all {
		if _, ok := set[strings.ToLower(entry.Severity)]; ok {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (s *PocStore) LoadByTags(tags []string) []*PocEntry {
	all := s.LoadAll()
	if len(tags) == 0 {
		return all
	}

	tagSet := make(map[string]struct{})
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = struct{}{}
	}

	var filtered []*PocEntry
	for _, entry := range all {
		entryTags := strings.Split(entry.Tags, ",")
		for _, tt := range entryTags {
			if _, ok := tagSet[strings.ToLower(strings.TrimSpace(tt))]; ok {
				filtered = append(filtered, entry)
				break
			}
		}
	}
	return filtered
}

func (s *PocStore) LoadByProducts(products []string) []*PocEntry {
	all := s.LoadAll()
	if len(products) == 0 {
		return all
	}

	productSet := make(map[string]struct{})
	for _, p := range products {
		productSet[strings.ToLower(p)] = struct{}{}
	}

	matched := make(map[int]struct{})
	var filtered []*PocEntry

	for i, entry := range all {
		entryTags := strings.Split(entry.Tags, ",")
		for _, tag := range entryTags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			for product := range productSet {
				if tag == product || strings.Contains(tag, product) || strings.Contains(product, tag) {
					if _, ok := matched[i]; !ok {
						matched[i] = struct{}{}
						filtered = append(filtered, entry)
					}
					break
				}
			}
			if _, ok := matched[i]; ok {
				break
			}
		}

		if _, ok := matched[i]; !ok {
			entryName := strings.ToLower(entry.Name)
			entryID := strings.ToLower(entry.ID)
			for product := range productSet {
				if strings.Contains(entryID, product) || strings.Contains(entryName, product) {
					matched[i] = struct{}{}
					filtered = append(filtered, entry)
					break
				}
			}
		}
	}

	slog.Info("[PocStore] 按产品筛选PoC", "products", len(products), "matched", len(filtered), "total", len(all))
	return filtered
}

func (s *PocStore) ImportFromDir(dir string) (imported int, skipped int, errors int) {
	if s.db == nil {
		return 0, 0, 0
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return 0, 0, 0
	}

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			errors++
			return nil
		}

		tmpl, parseErr := ParseTemplate(data)
		if parseErr != nil {
			errors++
			return nil
		}

		var existing model.PocTemplate
		result := s.db.Where("poc_id = ?", tmpl.ID).First(&existing)

		if result.Error == gorm.ErrRecordNotFound {
			record := model.PocTemplate{
				ID:          qulid.GenerateID(),
				PocID:       tmpl.ID,
				Name:        tmpl.Info.Name,
				Author:      tmpl.Info.Author,
				Severity:    tmpl.Info.Severity,
				Description: tmpl.Info.Description,
				Reference:   tmpl.Info.Reference,
				Tags:        parseTags(tmpl.Info.Tags),
				Content:     string(data),
				Format:      "yaml",
				Enabled:     true,
				Builtin:     true,
				Source:      "file_import",
				SourceURL:   path,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			if err := s.db.Create(&record).Error; err != nil {
				errors++
			} else {
				imported++
			}
		} else if result.Error == nil {
			s.db.Model(&existing).Updates(map[string]interface{}{
				"content":    string(data),
				"name":       tmpl.Info.Name,
				"severity":   tmpl.Info.Severity,
				"updated_at": time.Now(),
			})
			skipped++
		} else {
			errors++
		}

		return nil
	})

	s.InvalidateCache()

	slog.Info("[PocStore] 文件导入完成",
		"dir", dir,
		"imported", imported,
		"skipped", skipped,
		"errors", errors,
	)
	return
}

func (s *PocStore) ImportFromYAML(yamlContent string) (*model.PocTemplate, error) {
	tmpl, err := ParseTemplate([]byte(yamlContent))
	if err != nil {
		return nil, err
	}

	var existing model.PocTemplate
	result := s.db.Where("poc_id = ?", tmpl.ID).First(&existing)

	if result.Error == gorm.ErrRecordNotFound {
		record := &model.PocTemplate{
			ID:          qulid.GenerateID(),
			PocID:       tmpl.ID,
			Name:        tmpl.Info.Name,
			Author:      tmpl.Info.Author,
			Severity:    tmpl.Info.Severity,
			Description: tmpl.Info.Description,
			Reference:   tmpl.Info.Reference,
			Tags:        parseTags(tmpl.Info.Tags),
			Content:     yamlContent,
			Format:      "yaml",
			Enabled:     true,
			Source:      "manual",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := s.db.Create(record).Error; err != nil {
			return nil, err
		}

		s.InvalidateCache()
		return record, nil
	}

	s.db.Model(&existing).Updates(map[string]interface{}{
		"content":    yamlContent,
		"name":       tmpl.Info.Name,
		"severity":   tmpl.Info.Severity,
		"updated_at": time.Now(),
	})

	s.InvalidateCache()
	return &existing, nil
}

func (s *PocStore) CacheVersion() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *PocStore) Count() int64 {
	if s.db == nil {
		return int64(len(s.entries))
	}
	var count int64
	s.db.Model(&model.PocTemplate{}).Where("enabled = ?", true).Count(&count)
	return count
}

func (s *PocStore) ExportToYAML(pocID string) (string, error) {
	var record model.PocTemplate
	if err := s.db.Where("poc_id = ? OR id = ?", pocID, pocID).First(&record).Error; err != nil {
		return "", err
	}
	return record.Content, nil
}

func parseTags(tagStr string) model.StringArray {
	if tagStr == "" {
		return nil
	}
	parts := strings.Split(tagStr, ",")
	var tags model.StringArray
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			tags = append(tags, p)
		}
	}
	return tags
}

func marshalYAML(tmpl *NucleiTemplate) (string, error) {
	data, err := yaml.Marshal(tmpl)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
