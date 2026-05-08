package organize

import (
	"fmt"

	"vulnscan-backend/model"
	oc "vulnscan-backend/organize/organize-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceConstruction struct {
	db *db.DB
}

func NewServiceConstruction(database *db.DB) *serviceConstruction {
	return &serviceConstruction{db: database}
}

func (s *serviceConstruction) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceConstruction) List(req oc.ConstructionListReq) ([]model.ConstructionOrg, int64, error) {
	var items []model.ConstructionOrg
	var count int64

	q := s.session().Model(&model.ConstructionOrg{})
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

func (s *serviceConstruction) GetByID(id string) (*model.ConstructionOrg, error) {
	var item model.ConstructionOrg
	if err := s.session().Where("id = ?", id).First(&item).Error; err != nil {
		return nil, fmt.Errorf("记录不存在")
	}
	return &item, nil
}

func (s *serviceConstruction) Create(item *model.ConstructionOrg) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *serviceConstruction) Update(id string, updates map[string]interface{}) error {
	return s.session().Model(&model.ConstructionOrg{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceConstruction) Delete(id string) error {
	var item model.ConstructionOrg
	if err := s.session().Where("id = ?", id).First(&item).Error; err != nil {
		return fmt.Errorf("记录不存在")
	}
	if item.Used > 0 {
		return fmt.Errorf("该单位有关联资产，不允许删除")
	}
	return s.session().Where("id = ?", id).Delete(&model.ConstructionOrg{}).Error
}

var _ oc.ServiceConstruction = (*serviceConstruction)(nil)
