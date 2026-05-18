package organize

import (
	"fmt"
	"strings"

	"vulnscan-backend/model"
	oc "vulnscan-backend/organize/organize-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceOrganize struct {
	db *db.DB
}

func NewServiceOrganize(database *db.DB) *serviceOrganize {
	return &serviceOrganize{db: database}
}

func (s *serviceOrganize) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceOrganize) List(req oc.OrganizeListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Organize, int64, error) {
	var items []model.Organize
	var count int64

	q := s.session().Model(&model.Organize{}).Scopes(scopes...).Where("deleted_at IS NULL")
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

func (s *serviceOrganize) GetByID(id string) (*model.Organize, error) {
	var item model.Organize
	if err := s.session().Where("id = ? AND deleted_at IS NULL", id).First(&item).Error; err != nil {
		return nil, fmt.Errorf("组织不存在")
	}
	return &item, nil
}

func (s *serviceOrganize) Create(item *model.Organize) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	db := s.session().Omit("deleted_at")
	if strings.TrimSpace(item.UnifiedSocialCreditCode) == "" {
		db = db.Omit("unified_social_credit_code")
	} else {
		item.UnifiedSocialCreditCode = strings.TrimSpace(item.UnifiedSocialCreditCode)
	}
	return db.Create(item).Error
}

func (s *serviceOrganize) Update(id string, updates map[string]interface{}) error {
	NormalizeOrganizeUpdates(updates)
	if credit, ok := updates["unified_social_credit_code"].(string); ok {
		conflict, err := s.findByUnifiedSocialCreditCode(credit)
		if err != nil {
			return err
		}
		if conflict != nil && conflict.ID != id {
			return fmt.Errorf("统一社会信用代码「%s」已被单位「%s」使用", credit, conflict.Name)
		}
	}
	if len(updates) == 0 {
		return nil
	}
	return s.session().Model(&model.Organize{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error
}

func (s *serviceOrganize) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.Organize{}).Error
}

func (s *serviceOrganize) Tree() ([]model.Organize, error) {
	var items []model.Organize
	err := s.session().Where("deleted_at IS NULL").Order("created_at").Find(&items).Error
	if err != nil {
		return nil, err
	}
	_ = s.enrichAssetCounts(items)
	return items, nil
}

// enrichAssetCounts 按 organize_id 统计资产数量，填充 asset_count 列。
func (s *serviceOrganize) enrichAssetCounts(items []model.Organize) error {
	if len(items) == 0 {
		return nil
	}
	type countRow struct {
		OrganizeID string
		Count      int64
	}
	var rows []countRow
	err := s.session().Model(&model.Asset{}).
		Select("organize_id, COUNT(*) as count").
		Where("organize_id <> ''").
		Group("organize_id").
		Scan(&rows).Error
	if err != nil {
		return err
	}
	countMap := make(map[string]int64, len(rows))
	for _, row := range rows {
		countMap[row.OrganizeID] = row.Count
	}
	for i := range items {
		items[i].AssetCount = countMap[items[i].ID]
	}
	return nil
}

func (s *serviceOrganize) SyncFromIAM(nodes []*oc.OrganizeNode) (int, error) {
	flat := flattenOrganizeNodes(nodes)
	if len(flat) == 0 {
		return 0, nil
	}

	tx := s.session().Begin()
	count := 0
	for _, n := range flat {
		var existing model.Organize
		err := tx.Where("id = ?", n.ID).First(&existing).Error
		if err == nil {
			tx.Model(&existing).Updates(map[string]interface{}{
				"name":       n.Name,
				"parent_id":  n.ParentID,
				"deleted_at": nil,
			})
		} else {
			tx.Select("ID", "Name", "ParentID").Create(&model.Organize{
				ID:       n.ID,
				Name:     n.Name,
				ParentID: n.ParentID,
			})
			count++
		}
	}
	if err := tx.Commit().Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (s *serviceOrganize) Ensure(req oc.EnsureOrganizeReq) (*model.Organize, error) {
	if req.UnifiedSocialCreditCode != "" {
		conflict, err := s.findByUnifiedSocialCreditCode(req.UnifiedSocialCreditCode)
		if err != nil {
			return nil, err
		}
		if conflict != nil && conflict.ID != req.ID {
			if err := s.applyEnsureUpdates(conflict, req, false); err != nil {
				return nil, err
			}
			return conflict, nil
		}
	}

	var existing model.Organize
	err := s.session().Where("id = ? AND deleted_at IS NULL", req.ID).First(&existing).Error
	if err == nil {
		if err := s.applyEnsureUpdates(&existing, req, true); err != nil {
			return nil, err
		}
		return &existing, nil
	}

	newOrg := model.Organize{
		ID:       req.ID,
		Name:     req.Name,
		ParentID: req.ParentID,
	}
	db := s.session().Omit("deleted_at")
	if credit := strings.TrimSpace(req.UnifiedSocialCreditCode); credit != "" {
		newOrg.UnifiedSocialCreditCode = credit
	} else {
		db = db.Omit("unified_social_credit_code")
	}
	if err := db.Create(&newOrg).Error; err != nil {
		return nil, fmt.Errorf("创建组织失败: %w", err)
	}
	return &newOrg, nil
}

func (s *serviceOrganize) findByUnifiedSocialCreditCode(code string) (*model.Organize, error) {
	if code == "" {
		return nil, nil
	}

	var item model.Organize
	err := s.session().Where("unified_social_credit_code = ? AND deleted_at IS NULL", code).First(&item).Error
	if err == nil {
		return &item, nil
	}
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return nil, err
}

func (s *serviceOrganize) applyEnsureUpdates(item *model.Organize, req oc.EnsureOrganizeReq, allowCreditCodeUpdate bool) error {
	if item == nil {
		return nil
	}

	needUpdate := false
	updates := map[string]interface{}{}
	if req.Name != "" && item.Name != req.Name {
		updates["name"] = req.Name
		needUpdate = true
	}
	if req.ParentID != "" && item.ParentID != req.ParentID {
		updates["parent_id"] = req.ParentID
		needUpdate = true
	}
	if allowCreditCodeUpdate && req.UnifiedSocialCreditCode != "" && item.UnifiedSocialCreditCode != req.UnifiedSocialCreditCode {
		updates["unified_social_credit_code"] = req.UnifiedSocialCreditCode
		needUpdate = true
	}
	if needUpdate {
		if err := s.session().Model(item).Updates(updates).Error; err != nil {
			return fmt.Errorf("更新组织失败: %w", err)
		}
	}

	item.Name = firstNonEmptyStr(req.Name, item.Name)
	item.ParentID = firstNonEmptyStr(req.ParentID, item.ParentID)
	if allowCreditCodeUpdate {
		item.UnifiedSocialCreditCode = firstNonEmptyStr(req.UnifiedSocialCreditCode, item.UnifiedSocialCreditCode)
	}
	return nil
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func flattenOrganizeNodes(nodes []*oc.OrganizeNode) []oc.OrganizeNode {
	var result []oc.OrganizeNode
	var walk func([]*oc.OrganizeNode)
	walk = func(list []*oc.OrganizeNode) {
		for _, n := range list {
			result = append(result, *n)
			if len(n.Children) > 0 {
				walk(n.Children)
			}
		}
	}
	walk(nodes)
	return result
}

var _ oc.ServiceOrganize = (*serviceOrganize)(nil)
