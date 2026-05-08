package organizeContract

import "vulnscan-backend/model"

type OrganizeListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Name     string `form:"name"`
}

type ServiceOrganize interface {
	List(req OrganizeListReq) ([]model.Organize, int64, error)
	GetByID(id string) (*model.Organize, error)
	Create(item *model.Organize) error
	Update(id string, updates map[string]interface{}) error
	Delete(id string) error
	Tree() ([]model.Organize, error)
}

type ConstructionListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Name     string `form:"name"`
}

type ServiceConstruction interface {
	List(req ConstructionListReq) ([]model.ConstructionOrg, int64, error)
	GetByID(id string) (*model.ConstructionOrg, error)
	Create(item *model.ConstructionOrg) error
	Update(id string, updates map[string]interface{}) error
	Delete(id string) error
}
