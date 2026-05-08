package dict

import (
	"bufio"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type DictQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Type     string `form:"type"`
	Status   string `form:"status"`
}

type ServiceDict struct {
	db *db.DB
}

func NewServiceDict(database *db.DB) *ServiceDict {
	return &ServiceDict{db: database}
}

func (s *ServiceDict) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceDict) List(q DictQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Dictionary, int64, error) {
	tx := s.session().Model(&model.Dictionary{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR description LIKE ?", like, like)
	}
	if q.Type != "" {
		tx = tx.Where("type = ?", q.Type)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
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

	var items []model.Dictionary
	err := tx.Order("created_at DESC").Offset(offset).Limit(q.PageSize).Find(&items).Error
	return items, count, err
}

func (s *ServiceDict) GetByID(id string) (*model.Dictionary, error) {
	var item model.Dictionary
	err := s.session().Where("id = ?", id).First(&item).Error
	return &item, err
}

func (s *ServiceDict) Create(item *model.Dictionary) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *ServiceDict) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.Dictionary{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceDict) Delete(id string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("dictionary_id = ?", id).Delete(&model.DictionaryEntry{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.Dictionary{}).Error
	})
}

func (s *ServiceDict) ListEntries(dictID string, page, pageSize int) ([]model.DictionaryEntry, int64, error) {
	tx := s.session().Model(&model.DictionaryEntry{}).Where("dictionary_id = ?", dictID)

	var count int64
	tx.Count(&count)

	if pageSize <= 0 {
		pageSize = 50
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var items []model.DictionaryEntry
	err := tx.Order("priority DESC").Offset(offset).Limit(pageSize).Find(&items).Error
	return items, count, err
}

func (s *ServiceDict) AddEntry(dictID string, entry *model.DictionaryEntry) error {
	entry.ID = qulid.GenerateID()
	entry.DictionaryID = dictID
	err := s.session().Create(entry).Error
	if err == nil {
		s.updateEntryCount(dictID)
	}
	return err
}

func (s *ServiceDict) DeleteEntry(entryID string) error {
	var entry model.DictionaryEntry
	if err := s.session().Where("id = ?", entryID).First(&entry).Error; err != nil {
		return err
	}
	err := s.session().Where("id = ?", entryID).Delete(&model.DictionaryEntry{}).Error
	if err == nil {
		s.updateEntryCount(entry.DictionaryID)
	}
	return err
}

func (s *ServiceDict) ImportText(dictID string, text string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	var entries []model.DictionaryEntry
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
		entries = append(entries, model.DictionaryEntry{
			ID:           qulid.GenerateID(),
			DictionaryID: dictID,
			Value:        line,
		})
	}

	if len(entries) == 0 {
		return 0, nil
	}

	result := s.session().CreateInBatches(entries, 200)
	if result.Error == nil {
		s.updateEntryCount(dictID)
	}
	return int(result.RowsAffected), result.Error
}

func (s *ServiceDict) ExportText(dictID string) (string, error) {
	var entries []model.DictionaryEntry
	if err := s.session().Where("dictionary_id = ?", dictID).Order("priority DESC").Find(&entries).Error; err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.Value)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func (s *ServiceDict) ClearEntries(dictID string) error {
	err := s.session().Where("dictionary_id = ?", dictID).Delete(&model.DictionaryEntry{}).Error
	if err == nil {
		s.session().Model(&model.Dictionary{}).Where("id = ?", dictID).Update("entry_count", 0)
	}
	return err
}

func (s *ServiceDict) updateEntryCount(dictID string) {
	var count int64
	s.session().Model(&model.DictionaryEntry{}).Where("dictionary_id = ?", dictID).Count(&count)
	s.session().Model(&model.Dictionary{}).Where("id = ?", dictID).Update("entry_count", count)
}
