package nuclei

import (
	"fmt"
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

// ProductLinker resolves a product name+vendor into a ProductID.
type ProductLinker interface {
	MatchOrCreate(name, vendor string) string
}

type PocStore struct {
	db               *gorm.DB
	mu               sync.RWMutex
	entries          []*PocEntry
	lastLoad         time.Time
	cacheTTL         time.Duration
	version          int64
	integrityChecker *TemplateIntegrityChecker
	productLinker    ProductLinker
}

func NewPocStore(db *gorm.DB) *PocStore {
	return &PocStore{
		db:               db,
		cacheTTL:         5 * time.Minute,
		integrityChecker: NewTemplateIntegrityChecker(true),
	}
}

// SetProductLinker enables automatic product-to-ProductID resolution on import.
func (s *PocStore) SetProductLinker(linker ProductLinker) {
	s.productLinker = linker
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
			ID:            tmpl.ID,
			Name:          tmpl.Info.Name,
			Severity:      tmpl.Info.Severity,
			Tags:          tmpl.Info.Tags,
			Product:       rec.Product,
			Vendor:        rec.Vendor,
			AffectedRange: rec.AffectedRange,
			RawContent:    rec.Content,
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
			ID:            tmpl.ID,
			Name:          tmpl.Info.Name,
			Severity:      tmpl.Info.Severity,
			Tags:          tmpl.Info.Tags,
			Product:       rec.Product,
			Vendor:        rec.Vendor,
			AffectedRange: rec.AffectedRange,
			RawContent:    rec.Content,
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

// LoadByProductsWithDecisions performs structured product+version matching and returns decisions.
func (s *PocStore) LoadByProductsWithDecisions(products []string) ([]*PocEntry, []MatchDecision) {
	all := s.LoadAll()
	if len(products) == 0 {
		return all, nil
	}

	detected := ParseDetectedProducts(products)

	nameSet := make(map[string]struct{})
	for _, dp := range detected {
		nameSet[strings.ToLower(dp.Name)] = struct{}{}
	}
	detectedByName := make(map[string]DetectedProduct)
	for _, dp := range detected {
		key := strings.ToLower(dp.Name)
		if existing, ok := detectedByName[key]; !ok || (dp.Version != "" && existing.Version == "") {
			detectedByName[key] = dp
		}
	}

	matched := make(map[int]struct{})
	var filtered []*PocEntry
	var decisions []MatchDecision

	for i, entry := range all {
		// Phase 1: Structured product+version match
		if entry.Product != "" {
			entryProduct := strings.ToLower(entry.Product)
			for _, dp := range detected {
				dpName := strings.ToLower(dp.Name)
				if entryProduct != dpName && !strings.Contains(dpName, entryProduct) && !strings.Contains(entryProduct, dpName) {
					continue
				}
				if entry.AffectedRange != "" && dp.Version != "" {
					if MatchVersionRange(dp.Version, entry.AffectedRange) {
						matched[i] = struct{}{}
						filtered = append(filtered, entry)
						decisions = append(decisions, MatchDecision{
							PocID: entry.ID, PocName: entry.Name, Matched: true,
							MatchMethod: "product+version", MatchProduct: dp.Name,
							MatchVersion: dp.Version,
							Reason:       "产品 " + dp.Name + ":" + dp.Version + " 在影响范围 " + entry.AffectedRange + " 内",
						})
						break
					}
				} else {
					matched[i] = struct{}{}
					filtered = append(filtered, entry)
					method := "product"
					reason := "产品名称匹配: " + dp.Name
					if entry.AffectedRange != "" {
						reason += " (目标未识别版本，无法验证范围 " + entry.AffectedRange + ")"
					}
					decisions = append(decisions, MatchDecision{
						PocID: entry.ID, PocName: entry.Name, Matched: true,
						MatchMethod: method, MatchProduct: dp.Name,
						Reason: reason,
					})
					break
				}
			}
			if _, ok := matched[i]; ok {
				continue
			}
			if entry.AffectedRange != "" {
				decisions = append(decisions, MatchDecision{
					PocID: entry.ID, PocName: entry.Name, Matched: false,
					MatchMethod: "product+version",
					Reason:      "产品 " + entry.Product + " 不在检测列表中或版本不在影响范围",
				})
			}
		}

		if _, ok := matched[i]; ok {
			continue
		}

		// Phase 2: Tag-based matching (fallback)
		entryTags := strings.Split(entry.Tags, ",")
		for _, tag := range entryTags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			for product := range nameSet {
				if tag == product || strings.Contains(tag, product) || strings.Contains(product, tag) {
					if _, ok := matched[i]; !ok {
						matched[i] = struct{}{}
						filtered = append(filtered, entry)
						decisions = append(decisions, MatchDecision{
							PocID: entry.ID, PocName: entry.Name, Matched: true,
							MatchMethod: "tag", MatchProduct: product,
							Reason: "标签 \"" + tag + "\" 匹配产品 " + product,
						})
					}
					break
				}
			}
			if _, ok := matched[i]; ok {
				break
			}
		}

		if _, ok := matched[i]; !ok {
			// Phase 3: Name/ID heuristic (weakest)
			entryName := strings.ToLower(entry.Name)
			entryID := strings.ToLower(entry.ID)
			for product := range nameSet {
				if strings.Contains(entryID, product) || strings.Contains(entryName, product) {
					matched[i] = struct{}{}
					filtered = append(filtered, entry)
					decisions = append(decisions, MatchDecision{
						PocID: entry.ID, PocName: entry.Name, Matched: true,
						MatchMethod: "heuristic", MatchProduct: product,
						Reason: "PoC ID/名称包含产品关键词 " + product,
					})
					break
				}
			}
		}
	}

	// Phase 4: Tech stack exclusion — remove PoC targeting undetected tech stacks
	exclusionSet := BuildTechExclusionSet(products)
	if exclusionSet != nil {
		var kept []*PocEntry
		for _, entry := range filtered {
			if ShouldExcludeByTechStack(entry, exclusionSet) {
				decisions = append(decisions, MatchDecision{
					PocID: entry.ID, PocName: entry.Name, Matched: false,
					MatchMethod: "tech_exclusion",
					Reason:      "目标技术栈不匹配，已排除",
				})
				continue
			}
			kept = append(kept, entry)
		}
		if excluded := len(filtered) - len(kept); excluded > 0 {
			slog.Info("[PocStore] 技术栈排除",
				"excluded", excluded, "before", len(filtered), "after", len(kept))
		}
		filtered = kept
	}

	slog.Info("[PocStore] 按产品筛选PoC",
		"products", len(products), "matched", len(filtered), "total", len(all),
		"structured_fields", countStructuredEntries(all))
	return filtered, decisions
}

func countStructuredEntries(entries []*PocEntry) int {
	n := 0
	for _, e := range entries {
		if e.Product != "" {
			n++
		}
	}
	return n
}

// LoadByProducts is the backward-compatible wrapper that discards decisions.
func (s *PocStore) LoadByProducts(products []string) []*PocEntry {
	entries, _ := s.LoadByProductsWithDecisions(products)
	return entries
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

		if s.integrityChecker != nil {
			if checkErr := s.integrityChecker.CheckContent(data); checkErr != nil {
				slog.Warn("[PocStore] 模板安全检查失败，跳过", "path", path, "error", checkErr)
				errors++
				return nil
			}
		}

		tmpl, parseErr := ParseTemplate(data)
		if parseErr != nil {
			errors++
			return nil
		}

		dirProdName := tmpl.ExtractProduct()
		dirVendorName := tmpl.ExtractVendor()
		dirProductID := s.resolveProductID(dirProdName, dirVendorName)

		var existing model.PocTemplate
		result := s.db.Where("poc_id = ?", tmpl.ID).First(&existing)

		if result.Error == gorm.ErrRecordNotFound {
			record := model.PocTemplate{
				ID:            qulid.GenerateID(),
				PocID:         tmpl.ID,
				Name:          tmpl.Info.Name,
				Author:        tmpl.Info.Author,
				Severity:      tmpl.Info.Severity,
				Description:   tmpl.Info.Description,
				Reference:     tmpl.Info.Reference,
				Tags:          parseTags(tmpl.Info.Tags),
				Product:       dirProdName,
				Vendor:        dirVendorName,
				AffectedRange: tmpl.ExtractAffectedRange(),
				CPE:           tmpl.ExtractCPE(),
				ProductID:     dirProductID,
				Content:       string(data),
				Format:        "yaml",
				Enabled:       true,
				Builtin:       true,
				Source:        "file_import",
				SourceURL:     path,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}

			if err := s.db.Create(&record).Error; err != nil {
				errors++
			} else {
				imported++
			}
		} else if result.Error == nil {
			dirUpdates := map[string]interface{}{
				"content":        string(data),
				"name":           tmpl.Info.Name,
				"severity":       tmpl.Info.Severity,
				"product":        dirProdName,
				"vendor":         dirVendorName,
				"affected_range": tmpl.ExtractAffectedRange(),
				"cpe":            tmpl.ExtractCPE(),
				"updated_at":     time.Now(),
			}
			if dirProductID != "" {
				dirUpdates["product_id"] = dirProductID
			}
			s.db.Model(&existing).Updates(dirUpdates)
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
	if s.integrityChecker != nil {
		if err := s.integrityChecker.CheckContent([]byte(yamlContent)); err != nil {
			return nil, fmt.Errorf("模板安全检查失败: %w", err)
		}
	}

	tmpl, err := ParseTemplate([]byte(yamlContent))
	if err != nil {
		return nil, err
	}

	var existing model.PocTemplate
	result := s.db.Where("poc_id = ?", tmpl.ID).First(&existing)

	prodName := tmpl.ExtractProduct()
	vendorName := tmpl.ExtractVendor()
	productID := s.resolveProductID(prodName, vendorName)

	if result.Error == gorm.ErrRecordNotFound {
		record := &model.PocTemplate{
			ID:            qulid.GenerateID(),
			PocID:         tmpl.ID,
			Name:          tmpl.Info.Name,
			Author:        tmpl.Info.Author,
			Severity:      tmpl.Info.Severity,
			Description:   tmpl.Info.Description,
			Reference:     tmpl.Info.Reference,
			Tags:          parseTags(tmpl.Info.Tags),
			Product:       prodName,
			Vendor:        vendorName,
			AffectedRange: tmpl.ExtractAffectedRange(),
			CPE:           tmpl.ExtractCPE(),
			ProductID:     productID,
			Content:       yamlContent,
			Format:        "yaml",
			Enabled:       true,
			Source:        "manual",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := s.db.Create(record).Error; err != nil {
			return nil, err
		}

		s.InvalidateCache()
		return record, nil
	}

	updates := map[string]interface{}{
		"content":        yamlContent,
		"name":           tmpl.Info.Name,
		"severity":       tmpl.Info.Severity,
		"product":        prodName,
		"vendor":         vendorName,
		"affected_range": tmpl.ExtractAffectedRange(),
		"cpe":            tmpl.ExtractCPE(),
		"updated_at":     time.Now(),
	}
	if productID != "" {
		updates["product_id"] = productID
	}
	s.db.Model(&existing).Updates(updates)

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

func (s *PocStore) resolveProductID(product, vendor string) string {
	if s.productLinker == nil || strings.TrimSpace(product) == "" {
		return ""
	}
	return s.productLinker.MatchOrCreate(product, vendor)
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
