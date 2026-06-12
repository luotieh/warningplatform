package poc

import (
	"os"
	"sync"
	"time"

	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type PocQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Severity string `form:"severity"`
	Category string `form:"category"`
	Tag      string `form:"tag"`
	Enabled  *bool  `form:"enabled"`
}

type ImportJobStatus string

const (
	ImportJobPending   ImportJobStatus = "pending"
	ImportJobRunning   ImportJobStatus = "running"
	ImportJobCompleted ImportJobStatus = "completed"
	ImportJobFailed    ImportJobStatus = "failed"
)

type ImportJob struct {
	ID        string          `json:"id"`
	Status    ImportJobStatus `json:"status"`
	Imported  int             `json:"imported"`
	Skipped   int             `json:"skipped"`
	Errors    int             `json:"errors"`
	Total     int             `json:"total"`
	Error     string          `json:"error,omitempty"`
	CreatedAt string          `json:"created_at"`
}

type ServicePoc struct {
	db    *db.DB
	store *nuclei.PocStore

	importMu   sync.RWMutex
	importJobs map[string]*ImportJob
}

func NewServicePoc(database *db.DB, store *nuclei.PocStore) *ServicePoc {
	return &ServicePoc{
		db:         database,
		store:      store,
		importJobs: make(map[string]*ImportJob),
	}
}

func (s *ServicePoc) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// Session 返回 GORM 会话（供 Handler 等创建 NucleiModule 等使用）。
func (s *ServicePoc) Session() *gorm.DB {
	return s.session()
}

func (s *ServicePoc) List(q PocQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.PocTemplate, int64, error) {
	tx := s.session().Model(&model.PocTemplate{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR poc_id LIKE ? OR cve LIKE ?", like, like, like)
	}
	if q.Severity != "" {
		tx = tx.Where("severity = ?", q.Severity)
	}
	if q.Category != "" {
		tx = tx.Where("category = ?", q.Category)
	}
	if q.Tag != "" {
		tx = tx.Where("tags LIKE ?", "%"+q.Tag+"%")
	}
	if q.Enabled != nil {
		tx = tx.Where("enabled = ?", *q.Enabled)
	}

	var count int64
	tx.Count(&count)

	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	offset := (q.Page - 1) * q.PageSize

	var items []model.PocTemplate
	err := tx.Order("created_at DESC").Offset(offset).Limit(q.PageSize).Find(&items).Error
	return items, count, err
}

func (s *ServicePoc) GetByID(id string) (*model.PocTemplate, error) {
	var item model.PocTemplate
	err := s.session().Where("id = ?", id).First(&item).Error
	return &item, err
}

func (s *ServicePoc) InvalidateCache() {
	if s.store != nil {
		s.store.Invalidate()
	}
}

func (s *ServicePoc) Create(item *model.PocTemplate) error {
	if item.ID == "" {
		item.ID = ulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *ServicePoc) Update(id string, updates map[string]any) error {
	err := s.session().Model(&model.PocTemplate{}).Where("id = ?", id).Updates(updates).Error
	if err == nil {
		s.store.InvalidateCache()
	}
	return err
}

func (s *ServicePoc) Delete(id string) error {
	err := s.session().Where("id = ?", id).Delete(&model.PocTemplate{}).Error
	if err == nil {
		s.store.InvalidateCache()
	}
	return err
}

func (s *ServicePoc) Toggle(id string, enabled bool) error {
	err := s.session().Model(&model.PocTemplate{}).Where("id = ?", id).Update("enabled", enabled).Error
	if err == nil {
		s.store.InvalidateCache()
	}
	return err
}

func (s *ServicePoc) ImportYAML(yaml string) (*model.PocTemplate, error) {
	return s.store.ImportFromYAML(yaml)
}

func (s *ServicePoc) ImportDir(dir string) (imported, skipped, errors int) {
	return s.store.ImportFromDir(dir)
}

func (s *ServicePoc) StartAsyncImportDir(dir string, cleanupDir bool) *ImportJob {
	job := &ImportJob{
		ID:        ulid.GenerateID(),
		Status:    ImportJobPending,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	s.importMu.Lock()
	s.importJobs[job.ID] = job
	s.importMu.Unlock()

	go func() {
		if cleanupDir {
			defer func() {
				_ = removeAllSafe(dir)
			}()
		}
		s.importMu.Lock()
		job.Status = ImportJobRunning
		s.importMu.Unlock()

		imported, skipped, errors := s.store.ImportFromDir(dir)
		s.InvalidateCache()

		s.importMu.Lock()
		job.Imported = imported
		job.Skipped = skipped
		job.Errors = errors
		job.Total = imported + skipped + errors
		job.Status = ImportJobCompleted
		s.importMu.Unlock()
	}()

	return job
}

func (s *ServicePoc) GetImportJob(jobID string) (*ImportJob, bool) {
	s.importMu.RLock()
	defer s.importMu.RUnlock()
	job, ok := s.importJobs[jobID]
	if !ok {
		return nil, false
	}
	snapshot := *job
	return &snapshot, true
}

func removeAllSafe(dir string) error {
	if dir == "" || dir == "/" || dir == "." {
		return nil
	}
	return os.RemoveAll(dir)
}

type PocTagGroup struct {
	Tag   string `json:"tag"`
	Count int64  `json:"count"`
}

type PocStats struct {
	Total      int64            `json:"total"`
	Enabled    int64            `json:"enabled"`
	BySeverity map[string]int64 `json:"by_severity"`
	TopTags    []PocTagGroup    `json:"top_tags"`
	ByCategory map[string]int64 `json:"by_category"`
}

func (s *ServicePoc) Stats(scopes ...func(*gorm.DB) *gorm.DB) (*PocStats, error) {
	base := s.session().Model(&model.PocTemplate{}).Scopes(scopes...)

	stats := &PocStats{
		BySeverity: make(map[string]int64),
		ByCategory: make(map[string]int64),
	}

	base.Count(&stats.Total)
	base.Where("enabled = ?", true).Count(&stats.Enabled)

	type sevRow struct {
		Severity string `gorm:"column:severity"`
		Count    int64  `gorm:"column:cnt"`
	}
	var sevRows []sevRow
	s.session().Model(&model.PocTemplate{}).Scopes(scopes...).
		Select("severity, COUNT(*) as cnt").
		Group("severity").
		Find(&sevRows)
	for _, r := range sevRows {
		if r.Severity != "" {
			stats.BySeverity[r.Severity] = r.Count
		}
	}

	type catRow struct {
		Category string `gorm:"column:category"`
		Count    int64  `gorm:"column:cnt"`
	}
	var catRows []catRow
	s.session().Model(&model.PocTemplate{}).Scopes(scopes...).
		Select("category, COUNT(*) as cnt").
		Where("category != ''").
		Group("category").
		Order("cnt DESC").
		Find(&catRows)
	for _, r := range catRows {
		stats.ByCategory[r.Category] = r.Count
	}

	var allItems []model.PocTemplate
	s.session().Model(&model.PocTemplate{}).Scopes(scopes...).
		Select("tags").
		Find(&allItems)
	tagCount := make(map[string]int64)
	for _, item := range allItems {
		for _, t := range item.Tags {
			if t != "" {
				tagCount[t]++
			}
		}
	}

	type kv struct {
		k string
		v int64
	}
	var sorted []kv
	for k, v := range tagCount {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	limit := 50
	if len(sorted) < limit {
		limit = len(sorted)
	}
	for _, s := range sorted[:limit] {
		stats.TopTags = append(stats.TopTags, PocTagGroup{Tag: s.k, Count: s.v})
	}

	return stats, nil
}
