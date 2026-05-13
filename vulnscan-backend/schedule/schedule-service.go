package schedule

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type ServiceSchedule struct {
	db *db.DB
}

func NewServiceSchedule(database *db.DB) *ServiceSchedule {
	return &ServiceSchedule{db: database}
}

func (s *ServiceSchedule) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceSchedule) List(query scheduleQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ScanSchedule, int64, error) {
	var items []model.ScanSchedule
	var count int64

	tx := s.session().Model(&model.ScanSchedule{}).Scopes(scopes...)
	if query.Keyword != "" {
		tx = tx.Where("name LIKE ?", "%"+query.Keyword+"%")
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page := query.Page
	if page <= 0 {
		page = 1
	}
	size := query.PageSize
	if size <= 0 {
		size = 20
	}

	if err := tx.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, count, nil
}

func (s *ServiceSchedule) GetByID(id string) (*model.ScanSchedule, error) {
	var item model.ScanSchedule
	if err := s.session().Where("id = ?", id).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceSchedule) Create(item *model.ScanSchedule) error {
	item.ID = qulid.GenerateID()
	item.Status = model.ScheduleStatusIdle

	next := calcNextRun(*item)
	item.NextRunAt = next

	return s.session().Create(item).Error
}

func (s *ServiceSchedule) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceSchedule) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.ScanSchedule{}).Error
}

func (s *ServiceSchedule) Toggle(id string, enabled bool) error {
	updates := map[string]any{"enabled": enabled}
	if enabled {
		var item model.ScanSchedule
		if err := s.session().Where("id = ?", id).First(&item).Error; err == nil {
			item.Enabled = true
			next := calcNextRun(item)
			updates["next_run_at"] = next
		}
	}
	return s.session().Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(updates).Error
}
