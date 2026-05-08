package template

import (
	"context"
	"crypto/md5"
	"fmt"
	"vulnscan-backend/model"

	templateContract "vulnscan-backend/circular/template/template-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceTemplate struct {
	db *db.DB
}

func NewServiceTemplate(database *db.DB) *serviceTemplate {
	return &serviceTemplate{db: database}
}

func (s *serviceTemplate) session(tx ...*gorm.DB) *gorm.DB {
	if len(tx) > 0 && tx[0] != nil {
		return tx[0]
	}
	session, _ := s.db.GetDBSession()
	return session
}

func (s *serviceTemplate) Add(ctx context.Context, tmp model.CircularTemplate, tx ...*gorm.DB) error {
	if tmp.Id == "" {
		tmp.Id = qulid.GenerateID()
	}

	sess := s.session(tx...)
	return sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		if tmp.DefaultFlag {
			session.Model(&model.CircularTemplate{}).
				Where("type = ? AND default_flag = ?", tmp.Type, true).
				Updates(map[string]interface{}{"default_flag": false})
		}

		history := model.CircularTemplateHistory{
			TemplateId:   tmp.Id,
			TemplateName: tmp.TemplateName,
			Type:         tmp.Type,
			TemplateData: tmp.TemplateData,
		}
		history.Id = qulid.GenerateID()
		if err := session.Create(&history).Error; err != nil {
			return err
		}

		tmp.TemplateHistoryLastId = history.Id
		return session.Create(&tmp).Error
	})
}

func (s *serviceTemplate) List(ctx context.Context, req templateContract.TemplateListQuery) (int64, []model.CircularTemplate, error) {
	var items []model.CircularTemplate

	sess := s.session()
	tx := sess.WithContext(ctx).Model(&model.CircularTemplate{})

	if req.Code != "" {
		tx = tx.Where("id = ?", req.Code)
	}
	if req.TmpType != "" {
		tx = tx.Where("type = ?", req.TmpType)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, nil, err
	}

	page, size := normalizePage(req.Page, req.Size)
	offset := (page - 1) * size

	if err := tx.Offset(offset).Limit(size).
		Order("default_flag DESC").Order("created_at DESC").
		Find(&items).Error; err != nil {
		return 0, nil, err
	}

	return count, items, nil
}

func (s *serviceTemplate) Edit(ctx context.Context, templateId string, req templateContract.TemplateEditReq, updatedBy string, tx ...*gorm.DB) error {
	if templateId == "" {
		return fmt.Errorf("模板ID不允许为空")
	}

	sess := s.session(tx...)

	var oldTemplate model.CircularTemplate
	if err := sess.WithContext(ctx).Where("id = ?", templateId).First(&oldTemplate).Error; err != nil {
		return fmt.Errorf("模板不存在")
	}

	updates := make(map[string]any)

	return sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		if req.TemplateData != nil {
			md5Old := fmt.Sprintf("%x", md5.Sum([]byte(oldTemplate.TemplateData)))
			md5New := fmt.Sprintf("%x", md5.Sum([]byte(*req.TemplateData)))
			if md5Old != md5New {
				history := &model.CircularTemplateHistory{
					TemplateId:   templateId,
					TemplateData: *req.TemplateData,
					TemplateName: oldTemplate.TemplateName,
					Type:         oldTemplate.Type,
				}
				if req.TemplateName != nil && *req.TemplateName != "" {
					history.TemplateName = *req.TemplateName
				}
				history.Id = qulid.GenerateID()
				updates["template_history_last_id"] = history.Id
				if err := session.Create(history).Error; err != nil {
					return err
				}
			}
		}

		if req.DefaultFlag != nil && *req.DefaultFlag != oldTemplate.DefaultFlag {
			if !oldTemplate.DefaultFlag {
				session.Model(&model.CircularTemplate{}).
					Where("type = ? AND default_flag = ?", oldTemplate.Type, true).
					Updates(map[string]interface{}{"default_flag": false})
			}
			updates["default_flag"] = *req.DefaultFlag
		}
		if req.TemplateName != nil {
			updates["template_name"] = *req.TemplateName
		}
		if req.TemplateDescription != nil {
			updates["template_description"] = *req.TemplateDescription
		}
		if req.Type != nil {
			updates["type"] = *req.Type
		}

		if len(updates) > 0 {
			updates["updated_by"] = updatedBy
			return session.Model(&model.CircularTemplate{}).Where("id = ?", templateId).Updates(updates).Error
		}
		return nil
	})
}

func (s *serviceTemplate) Delete(ctx context.Context, templateId string, tx ...*gorm.DB) error {
	if templateId == "" {
		return fmt.Errorf("模板ID不可为空")
	}
	sess := s.session(tx...)
	return sess.WithContext(ctx).Where("id = ?", templateId).Delete(&model.CircularTemplate{}).Error
}

func normalizePage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}
	return page, size
}
