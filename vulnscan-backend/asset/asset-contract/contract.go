package assetContract

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type AssetQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Type     string `form:"type"`
	GroupID  string `form:"group_id"`
	Status   *int   `form:"status"`

	OrganizeID              string `form:"organize_id"`
	DataNumber              string `form:"data_number"`
	SystemType              string `form:"system_type"`
	SecurityProtectionLevel string `form:"security_protection_level"`
	LifecycleState          string `form:"lifecycle_state"`
	DataSource              string `form:"data_source"`
}

type CreateAssetReq struct {
	Name    string   `json:"name" binding:"required"`
	Type    string   `json:"type" binding:"required"`
	Address string   `json:"address" binding:"required"`
	GroupID string   `json:"group_id"`
	Port    int      `json:"port"`
	Tags    []string `json:"tags"`

	Domain                  string `json:"domain"`
	IPv4                    string `json:"ipv4"`
	URL                     string `json:"url"`
	Protocol                string `json:"protocol"`
	Service                 string `json:"service"`
	Version                 string `json:"version"`
	OS                      string `json:"os"`
	DataNumber              string `json:"data_number"`
	SystemName              string `json:"system_name"`
	SystemType              string `json:"system_type"`
	IsOnline                bool   `json:"is_online"`
	IsKey                   bool   `json:"is_key"`
	SecurityProtectionLevel string `json:"security_protection_level"`
	FilingCertNumber        string `json:"filing_cert_number"`
	IcpFilingNumber         string `json:"icp_filing_number"`
	ConstructionOrgID       string `json:"construction_org_id"`
	OperationOrgID          string `json:"operation_org_id"`
	DataSource              string `json:"data_source"`
	ResponsibleUserID       string `json:"responsible_user_id"`
	ResponsibleUserName     string `json:"responsible_user_name"`
	Remark                  string `json:"remark"`
}

type BatchUpdateReq struct {
	IDs     []string       `json:"ids" binding:"required,min=1"`
	Updates map[string]any `json:"updates" binding:"required,min=1"`
}

type ServiceAsset interface {
	List(query AssetQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Asset, int64, error)
	GetByID(id string) (*model.Asset, error)
	Create(item *model.Asset) error
	Update(id string, updates map[string]any) error
	Delete(id string) error
	BatchImport(items []*model.Asset) (int, error)
	BatchUpdate(ids []string, updates map[string]any) (int64, error)
	ListByIDs(ids []string) ([]model.Asset, error)
}
