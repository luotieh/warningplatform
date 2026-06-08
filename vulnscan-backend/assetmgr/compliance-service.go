package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceComplianceItem struct {
	db *db.DB
}

func NewServiceComplianceItem(database *db.DB) *serviceComplianceItem {
	return &serviceComplianceItem{db: database}
}

func (s *serviceComplianceItem) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceComplianceItem) List(req ac.ComplianceItemReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.AssetCompliance, int64, error) {
	var items []model.AssetCompliance
	var count int64

	q := s.session().Model(&model.AssetCompliance{}).Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if req.ItemType != "" {
		q = q.Where("item_type = ?", req.ItemType)
	}
	if req.Status != "" {
		q = q.Where("status = ?", req.Status)
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
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceComplianceItem) Create(item *model.AssetCompliance) error {
	return s.session().Create(item).Error
}

func (s *serviceComplianceItem) Update(id int64, data map[string]interface{}) error {
	return s.session().Model(&model.AssetCompliance{}).Where("id = ?", id).Updates(data).Error
}

func (s *serviceComplianceItem) Delete(id int64) error {
	return s.session().Where("id = ?", id).Delete(&model.AssetCompliance{}).Error
}

var _ ac.ServiceComplianceItem = (*serviceComplianceItem)(nil)

// ── 合规模板 ──

type serviceComplianceTemplate struct {
	db *db.DB
}

func NewServiceComplianceTemplate(database *db.DB) *serviceComplianceTemplate {
	return &serviceComplianceTemplate{db: database}
}

func (s *serviceComplianceTemplate) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceComplianceTemplate) List(req ac.TemplateListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ComplianceTemplate, int64, error) {
	var items []model.ComplianceTemplate
	var count int64

	q := s.session().Model(&model.ComplianceTemplate{}).Scopes(scopes...)
	if req.Standard != "" {
		q = q.Where("standard = ?", req.Standard)
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
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceComplianceTemplate) GetByID(id int64) (*model.ComplianceTemplate, error) {
	var item model.ComplianceTemplate
	if err := s.session().Where("id = ?", id).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceComplianceTemplate) Create(item *model.ComplianceTemplate) error {
	return s.session().Create(item).Error
}

func (s *serviceComplianceTemplate) Update(id int64, data map[string]interface{}) error {
	return s.session().Model(&model.ComplianceTemplate{}).Where("id = ?", id).Updates(data).Error
}

func (s *serviceComplianceTemplate) Delete(id int64) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		tx.Where("template_id = ?", id).Delete(&model.ComplianceTemplateItem{})
		return tx.Where("id = ?", id).Delete(&model.ComplianceTemplate{}).Error
	})
}

func (s *serviceComplianceTemplate) ListItems(templateID int64) ([]model.ComplianceTemplateItem, error) {
	var items []model.ComplianceTemplateItem
	err := s.session().Where("template_id = ?", templateID).Order("sort_order, id").Find(&items).Error
	return items, err
}

func (s *serviceComplianceTemplate) CreateItem(item *model.ComplianceTemplateItem) error {
	return s.session().Create(item).Error
}

var _ ac.ServiceComplianceTemplate = (*serviceComplianceTemplate)(nil)

// ── 合规检查结果 ──

type serviceCheckResult struct {
	db *db.DB
}

func NewServiceCheckResult(database *db.DB) *serviceCheckResult {
	return &serviceCheckResult{db: database}
}

func (s *serviceCheckResult) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceCheckResult) List(req ac.CheckResultListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ComplianceCheckResult, int64, error) {
	var items []model.ComplianceCheckResult
	var count int64

	q := s.session().Model(&model.ComplianceCheckResult{}).Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if req.TemplateID > 0 {
		q = q.Where("template_id = ?", req.TemplateID)
	}
	if req.Status != "" {
		q = q.Where("status = ?", req.Status)
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
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceCheckResult) Upsert(item *model.ComplianceCheckResult) error {
	var existing model.ComplianceCheckResult
	err := s.session().Where("asset_id = ? AND template_id = ? AND item_id = ?",
		item.AssetID, item.TemplateID, item.ItemID).First(&existing).Error
	if err == nil {
		return s.session().Model(&existing).Updates(map[string]interface{}{
			"status":     item.Status,
			"evidence":   item.Evidence,
			"remark":     item.Remark,
			"checked_by": item.CheckedBy,
		}).Error
	}
	return s.session().Create(item).Error
}

var _ ac.ServiceCheckResult = (*serviceCheckResult)(nil)
