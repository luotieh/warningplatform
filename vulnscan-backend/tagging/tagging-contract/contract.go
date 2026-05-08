package taggingContract

import "vulnscan-backend/model"

type TagListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Name     string `form:"name"`
	Category string `form:"category"`
}

type AssetTagReq struct {
	AssetID string  `json:"asset_id" binding:"required"`
	TagIDs  []int64 `json:"tag_ids" binding:"required"`
}

type ChangeLogListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	AssetID    string `form:"asset_id"`
	ChangeType string `form:"change_type"`
}

type ServiceTag interface {
	List(req TagListReq) ([]model.Tag, int64, error)
	GetByID(id int64) (*model.Tag, error)
	Create(tag *model.Tag) error
	Update(id int64, data map[string]interface{}) error
	Delete(id int64) error
	GetAssetTags(assetID string) ([]model.Tag, error)
	SetAssetTags(assetID string, tagIDs []int64, source string) error
}

type ServiceChangeLog interface {
	List(req ChangeLogListReq) ([]model.AssetChangeLog, int64, error)
	GetByAssetID(assetID string) ([]model.AssetChangeLog, error)
	Record(log *model.AssetChangeLog) error
}
