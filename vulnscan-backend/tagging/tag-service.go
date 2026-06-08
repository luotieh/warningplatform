package tagging

import (
	"vulnscan-backend/model"
	tc "vulnscan-backend/tagging/tagging-contract"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceTag struct {
	db *db.DB
}

func NewServiceTag(database *db.DB) *serviceTag {
	return &serviceTag{db: database}
}

func (s *serviceTag) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceTag) List(req tc.TagListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Tag, int64, error) {
	var list []model.Tag
	var count int64

	q := s.session().Model(&model.Tag{}).Scopes(scopes...)
	if req.Name != "" {
		q = q.Where("name LIKE ?", "%"+req.Name+"%")
	}
	if req.Category != "" {
		q = q.Where("category = ?", req.Category)
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
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&list).Error
	return list, count, err
}

func (s *serviceTag) GetByID(id int64) (*model.Tag, error) {
	var tag model.Tag
	if err := s.session().Where("id = ?", id).First(&tag).Error; err != nil {
		return nil, err
	}
	return &tag, nil
}

func (s *serviceTag) Create(tag *model.Tag) error {
	return s.session().Create(tag).Error
}

func (s *serviceTag) Update(id int64, data map[string]interface{}) error {
	return s.session().Model(&model.Tag{}).Where("id = ?", id).Updates(data).Error
}

func (s *serviceTag) Delete(id int64) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tag_id = ?", id).Delete(&model.AssetTag{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&model.Tag{}).Error
	})
}

func (s *serviceTag) GetAssetTags(assetID string) ([]model.Tag, error) {
	var tags []model.Tag
	err := s.session().Raw(`
		SELECT t.* FROM vs_tag t
		INNER JOIN vs_asset_tag at ON at.tag_id = t.id
		WHERE at.asset_id = ?
		ORDER BY t.id
	`, assetID).Scan(&tags).Error
	return tags, err
}

func (s *serviceTag) SetAssetTags(assetID string, tagIDs []int64, source string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("asset_id = ? AND source = ?", assetID, source).Delete(&model.AssetTag{}).Error; err != nil {
			return err
		}
		for _, tid := range tagIDs {
			at := model.AssetTag{AssetID: assetID, TagID: tid, Source: source}
			if err := tx.Create(&at).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

var _ tc.ServiceTag = (*serviceTag)(nil)
