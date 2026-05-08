package organize

import (
	"fmt"

	"vulnscan-backend/model"
	oc "vulnscan-backend/organize/organize-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceOrganize struct {
	db *db.DB
}

func NewServiceOrganize(database *db.DB) *serviceOrganize {
	return &serviceOrganize{db: database}
}

func (s *serviceOrganize) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceOrganize) List(req oc.OrganizeListReq) ([]model.Organize, int64, error) {
	var items []model.Organize
	var count int64

	q := s.session().Model(&model.Organize{}).Where("deleted_at IS NULL")
	if req.Name != "" {
		q = q.Where("name LIKE ?", "%"+req.Name+"%")
	}

	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page, size := req.Page, req.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceOrganize) GetByID(id string) (*model.Organize, error) {
	var item model.Organize
	if err := s.session().Where("id = ? AND deleted_at IS NULL", id).First(&item).Error; err != nil {
		return nil, fmt.Errorf("组织不存在")
	}
	return &item, nil
}

func (s *serviceOrganize) Create(item *model.Organize) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Omit("deleted_at").Create(item).Error
}

func (s *serviceOrganize) Update(id string, updates map[string]interface{}) error {
	return s.session().Model(&model.Organize{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error
}

func (s *serviceOrganize) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.Organize{}).Error
}

func (s *serviceOrganize) Tree() ([]model.Organize, error) {
	var items []model.Organize
	err := s.session().Where("deleted_at IS NULL").Order("created_at").Find(&items).Error
	return items, err
}

var _ oc.ServiceOrganize = (*serviceOrganize)(nil)
