package templateContract

import (
	"context"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type TemplateListQuery struct {
	Page    int                        `form:"page"`
	Size    int                        `form:"page_size"`
	TmpType model.CircularTemplateType `form:"tmp_type"`
	Code    string                     `form:"code"`
}

type TemplateEditReq struct {
	TemplateName        *string                     `json:"template_name"`
	TemplateDescription *string                     `json:"template_description"`
	TemplateData        *string                     `json:"template_data"`
	Type                *model.CircularTemplateType `json:"type"`
	DefaultFlag         *bool                       `json:"default_flag"`
}

type ServiceTemplate interface {
	Add(ctx context.Context, tmp model.CircularTemplate, tx ...*gorm.DB) error
	List(ctx context.Context, req TemplateListQuery) (int64, []model.CircularTemplate, error)
	Edit(ctx context.Context, templateId string, req TemplateEditReq, updatedBy string, tx ...*gorm.DB) error
	Delete(ctx context.Context, templateId string, tx ...*gorm.DB) error
}
