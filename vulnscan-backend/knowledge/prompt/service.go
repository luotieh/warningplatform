package prompt

import (
	"context"
	"fmt"
	"time"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type service struct {
	db *db.DB
}

func NewService(database *db.DB) Service {
	return &service{db: database}
}

func (s *service) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *service) Create(ctx context.Context, req CreateReq) error {
	tpl := model.PromptTemplate{
		Name:         req.Name,
		Scene:        req.Scene,
		Description:  req.Description,
		SystemPrompt: req.SystemPrompt,
		UserPrompt:   req.UserPrompt,
		OutputFormat: req.OutputFormat,
		Variables:    req.Variables,
		ModelName:    req.ModelName,
		Temperature:  req.Temperature,
		MaxTokens:    req.MaxTokens,
		Enabled:      true,
		Version:      1,
	}
	if tpl.Temperature == 0 {
		tpl.Temperature = 0.3
	}
	if tpl.MaxTokens == 0 {
		tpl.MaxTokens = 2000
	}
	return s.session().WithContext(ctx).Create(&tpl).Error
}

func (s *service) Update(ctx context.Context, id string, req UpdateReq) error {
	var existing model.PromptTemplate
	if err := s.session().WithContext(ctx).First(&existing, "id = ?", id).Error; err != nil {
		return err
	}

	updates := make(map[string]interface{})
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Scene != "" {
		updates["scene"] = req.Scene
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.SystemPrompt != "" {
		updates["system_prompt"] = req.SystemPrompt
	}
	if req.UserPrompt != "" {
		updates["user_prompt"] = req.UserPrompt
	}
	if req.OutputFormat != "" {
		updates["output_format"] = req.OutputFormat
	}
	if req.Variables != "" {
		updates["variables"] = req.Variables
	}
	if req.ModelName != "" {
		updates["model_name"] = req.ModelName
	}
	if req.Temperature > 0 {
		updates["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		updates["max_tokens"] = req.MaxTokens
	}

	if len(updates) == 0 {
		return nil
	}
	updates["version"] = gorm.Expr("version + 1")
	updates["updated_at"] = time.Now()
	return s.session().WithContext(ctx).Model(&model.PromptTemplate{}).
		Where("id = ?", id).Updates(updates).Error
}

func (s *service) Delete(ctx context.Context, id string) error {
	var tpl model.PromptTemplate
	if err := s.session().WithContext(ctx).First(&tpl, "id = ?", id).Error; err != nil {
		return err
	}
	if tpl.IsBuiltin {
		return fmt.Errorf("内置模板不允许删除")
	}
	return s.session().WithContext(ctx).Where("id = ?", id).Delete(&model.PromptTemplate{}).Error
}

func (s *service) GetDetail(ctx context.Context, id string) (*DetailResp, error) {
	var tpl model.PromptTemplate
	if err := s.session().WithContext(ctx).First(&tpl, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return toDetailResp(&tpl), nil
}

func (s *service) List(ctx context.Context, req ListReq) ([]ListItem, int64, error) {
	var items []model.PromptTemplate
	var count int64

	tx := s.session().WithContext(ctx).Model(&model.PromptTemplate{})
	if req.Scene != "" {
		tx = tx.Where("scene = ?", req.Scene)
	}
	if req.Keyword != "" {
		tx = tx.Where("name LIKE ? OR description LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if err := tx.Scopes(db.Paginate(req.Index, req.Size)).
		Order("is_builtin DESC, created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}

	result := make([]ListItem, len(items))
	for i, t := range items {
		result[i] = ListItem{
			ID:          t.Id,
			Name:        t.Name,
			Scene:       t.Scene,
			Description: t.Description,
			ModelName:   t.ModelName,
			Enabled:     t.Enabled,
			IsBuiltin:   t.IsBuiltin,
			Version:     t.Version,
			CreatedAt:   t.CreatedAt,
			UpdatedAt:   t.UpdatedAt,
		}
	}
	return result, count, nil
}

func (s *service) GetByScene(ctx context.Context, scene string) (*DetailResp, error) {
	var tpl model.PromptTemplate
	if err := s.session().WithContext(ctx).
		Where("scene = ? AND enabled = ?", scene, true).
		Order("is_builtin DESC, version DESC").
		First(&tpl).Error; err != nil {
		return nil, err
	}
	return toDetailResp(&tpl), nil
}

func (s *service) Toggle(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Model(&model.PromptTemplate{}).
		Where("id = ?", id).
		UpdateColumn("enabled", gorm.Expr("NOT enabled")).Error
}

func toDetailResp(t *model.PromptTemplate) *DetailResp {
	return &DetailResp{
		ID:           t.Id,
		Name:         t.Name,
		Scene:        t.Scene,
		Description:  t.Description,
		SystemPrompt: t.SystemPrompt,
		UserPrompt:   t.UserPrompt,
		OutputFormat: t.OutputFormat,
		Variables:    t.Variables,
		ModelName:    t.ModelName,
		Temperature:  t.Temperature,
		MaxTokens:    t.MaxTokens,
		Enabled:      t.Enabled,
		IsBuiltin:    t.IsBuiltin,
		Version:      t.Version,
		CreatedAt:    t.CreatedAt,
		UpdatedAt:    t.UpdatedAt,
	}
}
