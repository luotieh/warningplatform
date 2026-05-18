package organizeContract

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type OrganizeListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Name     string `form:"name"`
}

type EnsureOrganizeReq struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	ParentID                string `json:"parent_id"`
	UnifiedSocialCreditCode string `json:"unified_social_credit_code"`
}

type ServiceOrganize interface {
	List(req OrganizeListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Organize, int64, error)
	GetByID(id string) (*model.Organize, error)
	Create(item *model.Organize) error
	Update(id string, updates map[string]interface{}) error
	Delete(id string) error
	Tree() ([]model.Organize, error)
	SyncFromIAM(nodes []*OrganizeNode) (int, error)
	Ensure(req EnsureOrganizeReq) (*model.Organize, error)
}

type OrganizeNode struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	ParentID string          `json:"parent_id"`
	Sort     int             `json:"sort"`
	Status   string          `json:"status"`
	Children []*OrganizeNode `json:"children,omitempty"`
}

type ConstructionListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Name     string `form:"name"`
}

type ServiceConstruction interface {
	List(req ConstructionListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ConstructionOrg, int64, error)
	GetByID(id string) (*model.ConstructionOrg, error)
	Create(item *model.ConstructionOrg) error
	Update(id string, updates map[string]interface{}) error
	Delete(id string) error
}
