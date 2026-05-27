package datalib

import (
	"bufio"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type DataLibQuery struct {
	Page         int    `form:"page"`
	PageSize     int    `form:"page_size"`
	Keyword      string `form:"keyword"`
	Type         string `form:"type"`
	ExcludeTypes string `form:"exclude_types"`
	Category     string `form:"category"`
	Status       string `form:"status"`
}

type EntryQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Type     string `form:"type"`
	Enabled  *bool  `form:"enabled"`
}

type ServiceDataLib struct {
	db *db.DB
}

func NewServiceDataLib(database *db.DB) *ServiceDataLib {
	return &ServiceDataLib{db: database}
}

func (s *ServiceDataLib) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

// ── Library CRUD ──

func (s *ServiceDataLib) List(q DataLibQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.DataLibrary, int64, error) {
	tx := s.session().Model(&model.DataLibrary{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR description LIKE ?", like, like)
	}
	if q.Type != "" {
		tx = tx.Where("type = ?", q.Type)
	}
	if q.ExcludeTypes != "" {
		excluded := strings.Split(q.ExcludeTypes, ",")
		tx = tx.Where("type NOT IN ?", excluded)
	}
	if q.Category != "" {
		tx = tx.Where("category = ?", q.Category)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}

	var items []model.DataLibrary
	err := tx.Order("created_at DESC").Offset((q.Page - 1) * q.PageSize).Limit(q.PageSize).Find(&items).Error
	return items, count, err
}

func (s *ServiceDataLib) GetByID(id string) (*model.DataLibrary, error) {
	var item model.DataLibrary
	err := s.session().Where("id = ?", id).First(&item).Error
	return &item, err
}

func (s *ServiceDataLib) Create(item *model.DataLibrary) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *ServiceDataLib) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.DataLibrary{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceDataLib) Delete(id string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("library_id = ?", id).Delete(&model.DataLibraryEntry{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.DataLibrary{}).Error
	})
}

// ── Entry CRUD ──

func (s *ServiceDataLib) ListEntries(libID string, q EntryQuery) ([]model.DataLibraryEntry, int64, error) {
	tx := s.session().Model(&model.DataLibraryEntry{}).Where("library_id = ?", libID)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR value LIKE ?", like, like)
	}
	if q.Type != "" {
		tx = tx.Where("type = ?", q.Type)
	}
	if q.Enabled != nil {
		tx = tx.Where("enabled = ?", *q.Enabled)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	page := q.Page
	if page <= 0 {
		page = 1
	}

	var items []model.DataLibraryEntry
	err := tx.Order("priority DESC, created_at DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error
	return items, count, err
}

func (s *ServiceDataLib) GetEntryByID(entryID string) (*model.DataLibraryEntry, error) {
	var item model.DataLibraryEntry
	err := s.session().Where("id = ?", entryID).First(&item).Error
	return &item, err
}

func (s *ServiceDataLib) AddEntry(libID string, entry *model.DataLibraryEntry) error {
	entry.ID = qulid.GenerateID()
	entry.LibraryID = libID
	err := s.session().Create(entry).Error
	if err == nil {
		s.updateEntryCount(libID)
	}
	return err
}

func (s *ServiceDataLib) UpdateEntry(entryID string, updates map[string]any) error {
	return s.session().Model(&model.DataLibraryEntry{}).Where("id = ?", entryID).Updates(updates).Error
}

func (s *ServiceDataLib) DeleteEntry(entryID string) error {
	var entry model.DataLibraryEntry
	if err := s.session().Where("id = ?", entryID).First(&entry).Error; err != nil {
		return err
	}
	err := s.session().Where("id = ?", entryID).Delete(&model.DataLibraryEntry{}).Error
	if err == nil {
		s.updateEntryCount(entry.LibraryID)
	}
	return err
}

func (s *ServiceDataLib) BatchAddEntries(libID string, entries []model.DataLibraryEntry) (int, error) {
	for i := range entries {
		entries[i].ID = qulid.GenerateID()
		entries[i].LibraryID = libID
	}
	result := s.session().CreateInBatches(entries, 100)
	if result.Error == nil {
		s.updateEntryCount(libID)
	}
	return int(result.RowsAffected), result.Error
}

// ── Bulk Operations ──

func (s *ServiceDataLib) ImportText(libID string, text string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	var entries []model.DataLibraryEntry
	seen := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		entries = append(entries, model.DataLibraryEntry{
			ID:        qulid.GenerateID(),
			LibraryID: libID,
			Value:     line,
			Enabled:   true,
		})
	}

	if len(entries) == 0 {
		return 0, nil
	}

	result := s.session().CreateInBatches(entries, 200)
	if result.Error == nil {
		s.updateEntryCount(libID)
	}
	return int(result.RowsAffected), result.Error
}

func (s *ServiceDataLib) ExportText(libID string) (string, error) {
	var entries []model.DataLibraryEntry
	if err := s.session().Where("library_id = ? AND enabled = ?", libID, true).Order("priority DESC").Find(&entries).Error; err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.Value)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func (s *ServiceDataLib) ClearEntries(libID string) error {
	err := s.session().Where("library_id = ?", libID).Delete(&model.DataLibraryEntry{}).Error
	if err == nil {
		s.session().Model(&model.DataLibrary{}).Where("id = ?", libID).Update("entry_count", 0)
	}
	return err
}

// ── Helpers ──

func (s *ServiceDataLib) GetCategories(libType string) ([]string, error) {
	var categories []string
	q := s.session().Model(&model.DataLibrary{})
	if libType != "" {
		q = q.Where("type = ?", libType)
	}
	err := q.Where("category != ''").Select("DISTINCT category").Order("category ASC").Pluck("category", &categories).Error
	return categories, err
}

func (s *ServiceDataLib) updateEntryCount(libID string) {
	var count int64
	s.session().Model(&model.DataLibraryEntry{}).Where("library_id = ?", libID).Count(&count)
	s.session().Model(&model.DataLibrary{}).Where("id = ?", libID).Update("entry_count", count)
}

func (s *ServiceDataLib) ReloadPayloads(loader interface{}) error {
	type Reloader interface {
		Reload() error
	}
	if r, ok := loader.(Reloader); ok {
		return r.Reload()
	}
	return nil
}
