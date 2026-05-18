package asset

import (
	"fmt"
	"time"

	assetContract "vulnscan-backend/asset/asset-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceAsset struct {
	db *db.DB
}

func NewServiceAsset(database *db.DB) *serviceAsset {
	return &serviceAsset{db: database}
}

func (s *serviceAsset) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// buildAssetListQuery 与资产列表 List 使用相同的过滤条件（不含分页），供统计接口等复用。
func buildAssetListQuery(sess *gorm.DB, query assetContract.AssetQuery, scopes ...func(*gorm.DB) *gorm.DB) *gorm.DB {
	tx := sess.Model(&model.Asset{}).Scopes(scopes...)

	if query.Keyword != "" {
		tx = tx.Where("name LIKE ? OR address LIKE ?", "%"+query.Keyword+"%", "%"+query.Keyword+"%")
	}
	if query.Type != "" {
		tx = tx.Where("type = ?", query.Type)
	}
	if query.GroupID != "" {
		tx = tx.Where("group_id = ?", query.GroupID)
	}
	if query.Status != nil {
		tx = tx.Where("status = ?", *query.Status)
	}
	if query.OrganizeID != "" {
		tx = tx.Where("organize_id = ?", query.OrganizeID)
	}
	if query.DataNumber != "" {
		tx = tx.Where("data_number LIKE ?", "%"+query.DataNumber+"%")
	}
	if query.SystemType != "" {
		tx = tx.Where("system_type = ?", query.SystemType)
	}
	if query.SecurityProtectionLevel != "" {
		tx = tx.Where("security_protection_level = ?", query.SecurityProtectionLevel)
	}
	if query.DataSource != "" {
		tx = tx.Where("data_source = ?", query.DataSource)
	}
	if query.AssetFamily != "" {
		tx = applyAssetFamilyFilter(tx, query.AssetFamily)
	}
	return tx
}

func (s *serviceAsset) List(query assetContract.AssetQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Asset, int64, error) {
	var items []model.Asset
	var count int64

	tx := buildAssetListQuery(s.session(), query, scopes...)

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 100 {
		query.PageSize = 20
	}

	offset := (query.Page - 1) * query.PageSize
	if err := tx.Offset(offset).Limit(query.PageSize).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}

	normalizeAssetFamilies(items)
	return items, count, nil
}

func (s *serviceAsset) GetByID(id string) (*model.Asset, error) {
	var item model.Asset
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	normalizeAssetFamily(&item)
	return &item, nil
}

func (s *serviceAsset) Create(item *model.Asset) error {
	if err := s.session().Create(item).Error; err != nil {
		return err
	}
	s.ensureVerifyTasks([]model.Asset{*item}, item.CreatedBy, string(model.DataSourceManual))
	return nil
}

func (s *serviceAsset) Update(id string, updates map[string]any) error {
	return s.UpdateWithOperator(id, updates, "")
}

func (s *serviceAsset) UpdateWithOperator(id string, updates map[string]any, operator string) error {
	var old model.Asset
	if err := s.session().First(&old, "id = ?", id).Error; err != nil {
		return s.session().Model(&model.Asset{}).Where("id = ?", id).Updates(updates).Error
	}

	if err := s.session().Model(&model.Asset{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}

	s.recordChangeLogs(&old, updates, operator)
	return nil
}

func (s *serviceAsset) recordChangeLogs(old *model.Asset, updates map[string]any, operator string) {
	fieldMap := map[string]func() string{
		"name":                      func() string { return old.Name },
		"type":                      func() string { return old.Type },
		"address":                   func() string { return old.Address },
		"group_id":                  func() string { return old.GroupID },
		"organize_id":               func() string { return old.OrganizeID },
		"status":                    func() string { return fmt.Sprintf("%d", old.Status) },
		"domain":                    func() string { return old.Domain },
		"ipv4":                      func() string { return old.IPv4 },
		"ipv6":                      func() string { return old.IPv6 },
		"port":                      func() string { return fmt.Sprintf("%d", old.Port) },
		"protocol":                  func() string { return old.Protocol },
		"service":                   func() string { return old.Service },
		"version":                   func() string { return old.Version },
		"os":                        func() string { return old.OS },
		"system_type":               func() string { return old.SystemType },
		"asset_family":              func() string { return old.AssetFamily },
		"asset_subtype":             func() string { return old.AssetSubtype },
		"security_protection_level": func() string { return old.SecurityProtectionLevel },
		"data_source":               func() string { return string(old.DataSource) },
		"responsible_user_name":     func() string { return old.ResponsibleUserName },
		"remark":                    func() string { return old.Remark },
	}

	now := time.Now()
	var logs []model.AssetChangeLog
	for field, newVal := range updates {
		getOld, ok := fieldMap[field]
		if !ok {
			continue
		}
		oldStr := getOld()
		newStr := fmt.Sprintf("%v", newVal)
		if oldStr == newStr {
			continue
		}
		logs = append(logs, model.AssetChangeLog{
			AssetID:    old.ID,
			ChangeType: "update",
			Field:      field,
			OldValue:   oldStr,
			NewValue:   newStr,
			Source:     "user",
			Operator:   operator,
			CreatedAt:  now,
		})
	}
	if len(logs) > 0 {
		s.session().CreateInBatches(logs, 50)
	}
}

func (s *serviceAsset) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.Asset{}).Error
}

func (s *serviceAsset) BatchImport(items []*model.Asset) (int, error) {
	result := s.session().CreateInBatches(items, 100)
	if result.Error == nil && result.RowsAffected > 0 {
		assets := make([]model.Asset, 0, len(items))
		operator := ""
		for _, item := range items {
			if item == nil {
				continue
			}
			if operator == "" {
				operator = item.CreatedBy
			}
			assets = append(assets, *item)
		}
		s.ensureVerifyTasks(assets, operator, string(model.DataSourceImport))
	}
	return int(result.RowsAffected), result.Error
}

func (s *serviceAsset) ensureVerifyTasks(assets []model.Asset, operator, sourceType string) {
	if len(assets) == 0 {
		return
	}
	now := time.Now()
	batchID := qulid.GenerateID()
	sess := s.session()
	exists := make(map[string]bool)
	var existing []model.AssetVerifyTask
	if err := sess.Where("asset_id IN ? AND status <> ?", assetIDsFromAssets(assets), model.AssetVerifyTaskArchived).
		Find(&existing).Error; err == nil {
		for _, task := range existing {
			exists[task.AssetID] = true
		}
	}

	var tasks []model.AssetVerifyTask
	var logs []model.AssetVerifyOplog

	for _, asset := range assets {
		if exists[asset.ID] {
			continue
		}
		targetOrganizeID := asset.OrganizeID
		status := model.AssetVerifyTaskPendingDispatch
		if targetOrganizeID != "" {
			status = model.AssetVerifyTaskPendingReceive
		}
		task := model.AssetVerifyTask{
			ID:                qulid.GenerateID(),
			AssetID:           asset.ID,
			BatchID:           batchID,
			SourceType:        sourceType,
			Status:            status,
			OwnerOrganizeID:   asset.OrganizeID,
			CurrentOrganizeID: targetOrganizeID,
			TargetOrganizeID:  targetOrganizeID,
			ConstructionOrgID: asset.ConstructionOrgID,
			OperationOrgID:    asset.OperationOrgID,
			CreatedBy:         operator,
			UpdatedBy:         operator,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		tasks = append(tasks, task)
		logs = append(logs, model.AssetVerifyOplog{
			TaskID:           task.ID,
			AssetID:          task.AssetID,
			Action:           model.AssetVerifyActionCreate,
			ToStatus:         string(task.Status),
			TargetOrganizeID: task.TargetOrganizeID,
			Operator:         operator,
			Remark:           "asset auto verify task",
			CreatedAt:        now,
		})
	}

	if len(tasks) == 0 {
		return
	}
	if err := sess.CreateInBatches(tasks, 100).Error; err != nil {
		return
	}
	if len(logs) > 0 {
		_ = sess.CreateInBatches(logs, 100).Error
	}
}

func assetIDsFromAssets(assets []model.Asset) []string {
	ids := make([]string, 0, len(assets))
	for _, asset := range assets {
		ids = append(ids, asset.ID)
	}
	return ids
}

func (s *serviceAsset) BatchUpdate(ids []string, updates map[string]any) (int64, error) {
	result := s.session().Model(&model.Asset{}).Where("id IN ?", ids).Updates(updates)
	return result.RowsAffected, result.Error
}

func (s *serviceAsset) ListByIDs(ids []string) ([]model.Asset, error) {
	var items []model.Asset
	if err := s.session().Where("id IN ?", ids).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
