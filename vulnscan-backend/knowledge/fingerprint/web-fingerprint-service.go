package fingerprint

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type WebFingerprintQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Category string `form:"category"`
	Status   string `form:"status"`
}

type WebFingerprintCreateReq struct {
	Product     string `json:"product" binding:"required"`
	Category    string `json:"category" binding:"required"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	HeaderRules string `json:"header_rules"`
	BodyRules   string `json:"body_rules"`
	FaviconHash string `json:"favicon_hash"`
	MetaRules   string `json:"meta_rules"`
	VersionExpr string `json:"version_expr"`
}

type WebFingerprintUpdateReq struct {
	Product     *string `json:"product"`
	Category    *string `json:"category"`
	Version     *string `json:"version"`
	Description *string `json:"description"`
	Priority    *int    `json:"priority"`
	Status      *string `json:"status"`
	HeaderRules *string `json:"header_rules"`
	BodyRules   *string `json:"body_rules"`
	FaviconHash *string `json:"favicon_hash"`
	MetaRules   *string `json:"meta_rules"`
	VersionExpr *string `json:"version_expr"`
}

// ProductLinker resolves a product name into a ProductID.
type ProductLinker interface {
	MatchOrCreate(name, vendor string) string
}

type ServiceWebFingerprint struct {
	db            *db.DB
	productLinker ProductLinker
}

func NewServiceWebFingerprint(database *db.DB) *ServiceWebFingerprint {
	return &ServiceWebFingerprint{db: database}
}

// SetProductLinker enables automatic product-to-ProductID resolution on create/update.
func (s *ServiceWebFingerprint) SetProductLinker(linker ProductLinker) {
	s.productLinker = linker
}

func (s *ServiceWebFingerprint) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceWebFingerprint) List(q WebFingerprintQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.WebFingerprint, int64, error) {
	tx := s.session().Model(&model.WebFingerprint{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("product LIKE ? OR description LIKE ?", like, like)
	}
	if q.Category != "" {
		tx = tx.Where("category = ?", q.Category)
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

	var items []model.WebFingerprint
	if err := tx.Offset(offset).Limit(q.PageSize).Order("priority DESC, created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *ServiceWebFingerprint) GetByID(id string) (*model.WebFingerprint, error) {
	var item model.WebFingerprint
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceWebFingerprint) Create(req WebFingerprintCreateReq, createdBy string) (*model.WebFingerprint, error) {
	item := model.WebFingerprint{
		Product:     req.Product,
		Category:    req.Category,
		Version:     req.Version,
		Description: req.Description,
		Priority:    req.Priority,
		Status:      "active",
		Source:      "custom",
		HeaderRules: req.HeaderRules,
		BodyRules:   req.BodyRules,
		FaviconHash: req.FaviconHash,
		MetaRules:   req.MetaRules,
		VersionExpr: req.VersionExpr,
	}
	item.ID = qulid.GenerateID()
	item.CreatedBy = createdBy

	if item.Priority == 0 {
		item.Priority = 50
	}

	if s.productLinker != nil && req.Product != "" {
		item.ProductID = s.productLinker.MatchOrCreate(req.Product, "")
	}

	if err := s.session().Create(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceWebFingerprint) Update(id string, req WebFingerprintUpdateReq) error {
	updates := make(map[string]interface{})
	if req.Product != nil {
		updates["product"] = *req.Product
	}
	if req.Category != nil {
		updates["category"] = *req.Category
	}
	if req.Version != nil {
		updates["version"] = *req.Version
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Priority != nil {
		updates["priority"] = *req.Priority
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.HeaderRules != nil {
		updates["header_rules"] = *req.HeaderRules
	}
	if req.BodyRules != nil {
		updates["body_rules"] = *req.BodyRules
	}
	if req.FaviconHash != nil {
		updates["favicon_hash"] = *req.FaviconHash
	}
	if req.MetaRules != nil {
		updates["meta_rules"] = *req.MetaRules
	}
	if req.VersionExpr != nil {
		updates["version_expr"] = *req.VersionExpr
	}

	if s.productLinker != nil {
		if req.Product != nil && *req.Product != "" {
			if pid := s.productLinker.MatchOrCreate(*req.Product, ""); pid != "" {
				updates["product_id"] = pid
			}
		}
	}

	if len(updates) == 0 {
		return nil
	}
	return s.session().Model(&model.WebFingerprint{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceWebFingerprint) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.WebFingerprint{}).Error
}
