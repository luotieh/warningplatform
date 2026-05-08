package inputContract

import (
	"context"
	"vulnscan-backend/model"

	"github.com/gin-gonic/gin"
	"mime/multipart"
)

type ListQuery struct {
	Page     int    `form:"page"`
	Size     int    `form:"page_size"`
	Title    string `form:"title"`
	Code     string `form:"code"`
	Status   string `form:"status"`
	Source   string `form:"source"`
	Organize string `form:"organize"`
}

type ListResp struct {
	model.Circular
	OrganizeStatusList []model.CircularOrganizeStatus `json:"organize_status_list" gorm:"-"`
}

type InputAddReq struct {
	Title              string             `json:"title" binding:"required"`
	CustomCode         string             `json:"custom_code"`
	Organize           string             `json:"organize"`
	DisposalOrganize   string             `json:"disposal_organize"`
	ProcessingDeadline string             `json:"processing_deadline"`
	CircularTemplate   string             `json:"circular_template" binding:"required"`
	CircularData       model.JSONMapSlice `json:"circular_data"`
	DisposalTemplate   string             `json:"disposal_template"`
	DisposalData       model.JSONMapSlice `json:"disposal_data"`
	IncidentNo         string             `json:"incident_no"`
	Name               string             `json:"name"`
	Level              int                `json:"level"`
	AiOpinion          string             `json:"ai_opinion"`
	AiConfidence       float64            `json:"ai_confidence"`
	AssetInfo          *TransferAssetInfo `json:"asset_info"`
	MetadataInfo       *TransferMetaInfo  `json:"metadata_info"`
}

type TransferAssetInfo struct {
	AssetName  string `json:"asset_name"`
	SystemName string `json:"system_name"`
	DomainIP   string `json:"domain_ip"`
	Unit       string `json:"unit"`
}

type TransferMetaInfo struct {
	IncidentType string `json:"incident_type"`
	IncidentURL  string `json:"incident_url"`
	Description  string `json:"incident_description"`
}

type InputEditReq struct {
	Title              *string             `json:"title"`
	CustomCode         *string             `json:"custom_code"`
	Organize           *string             `json:"organize"`
	ProcessingDeadline *string             `json:"processing_deadline"`
	CircularData       *model.JSONMapSlice `json:"circular_data"`
}

type InputDetailResp struct {
	model.Circular
	OrganizeStatusList []model.CircularOrganizeStatus `json:"organize_status_list"`
	Distributions      []model.CircularDistribution   `json:"distributions"`
	Disposals          []model.CircularDisposal       `json:"disposals"`
	Reviews            []model.CircularReview         `json:"reviews"`
}

type ServiceInput interface {
	Add(ctx context.Context, req InputAddReq, createdBy string) error
	List(ctx context.Context, req ListQuery) (int64, []ListResp, error)
	Detail(ctx context.Context, id string) (*InputDetailResp, error)
	Delete(ctx context.Context, id string) error
	Edit(ctx context.Context, id string, req InputEditReq, updatedBy string) error
	Export(ctx context.Context, codes []string) error
	Import(ctx context.Context, file *multipart.FileHeader, createdBy string) (int, error)
	CommonTemplateDownload(c *gin.Context)
	Submit(ctx context.Context, id string, userId string) error
	ThirdPartyImport(ctx context.Context, req InputAddReq, createdBy string) error
}
