package knowledge

import (
	"context"
	"fmt"
	"time"
	"vulnscan-backend/model"

	knowledgeContract "vulnscan-backend/incident/knowledge/knowledge-contract"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceKnowledge struct {
	db *db.DB
}

func NewServiceKnowledge(database *db.DB) *serviceKnowledge {
	return &serviceKnowledge{db: database}
}

func (s *serviceKnowledge) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceKnowledge) CreateArticle(ctx context.Context, req knowledgeContract.KBCreateReq) error {
	article := model.KnowledgeArticle{
		Title:        req.Title,
		Content:      req.Content,
		Category:     req.Category,
		Tags:         req.Tags,
		IncidentId:   req.IncidentId,
		Level:        req.Level,
		Summary:      req.Summary,
		Solution:     req.Solution,
		IncidentType: req.IncidentType,
		AuthorId:     req.AuthorId,
		AuthorName:   req.AuthorName,
		Source:       "manual",
	}
	return s.session().WithContext(ctx).Create(&article).Error
}

func (s *serviceKnowledge) UpdateArticle(ctx context.Context, id string, req knowledgeContract.KBUpdateReq) error {
	updates := make(map[string]interface{})
	if req.Title != "" {
		updates["title"] = req.Title
	}
	if req.Content != "" {
		updates["content"] = req.Content
	}
	if req.Category != "" {
		updates["category"] = req.Category
	}
	if req.Tags != "" {
		updates["tags"] = req.Tags
	}
	if req.Summary != "" {
		updates["summary"] = req.Summary
	}
	if req.Solution != "" {
		updates["solution"] = req.Solution
	}
	if len(updates) == 0 {
		return nil
	}
	updates["updated_at"] = time.Now()
	return s.session().WithContext(ctx).Model(&model.KnowledgeArticle{}).
		Where("id = ?", id).Updates(updates).Error
}

func (s *serviceKnowledge) DeleteArticle(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Where("id = ?", id).Delete(&model.KnowledgeArticle{}).Error
}

func (s *serviceKnowledge) GetArticleDetail(ctx context.Context, id string) (*knowledgeContract.KBDetailResp, error) {
	var article model.KnowledgeArticle
	if err := s.session().WithContext(ctx).First(&article, "id = ?", id).Error; err != nil {
		return nil, err
	}

	// Increment view count
	s.session().WithContext(ctx).Model(&model.KnowledgeArticle{}).
		Where("id = ?", id).UpdateColumn("view_count", gorm.Expr("view_count + 1"))

	resp := &knowledgeContract.KBDetailResp{
		ID:           article.Id,
		Title:        article.Title,
		Content:      article.Content,
		Category:     article.Category,
		Tags:         article.Tags,
		IncidentId:   article.IncidentId,
		Level:        article.Level,
		Summary:      article.Summary,
		Solution:     article.Solution,
		IncidentType: article.IncidentType,
		ViewCount:    article.ViewCount + 1,
		LikeCount:    article.LikeCount,
		AuthorId:     article.AuthorId,
		AuthorName:   article.AuthorName,
		Source:       article.Source,
		CreatedAt:    article.CreatedAt,
		UpdatedAt:    article.UpdatedAt,
	}
	return resp, nil
}

func (s *serviceKnowledge) ListArticles(ctx context.Context, req knowledgeContract.KBListReq) ([]knowledgeContract.KBListItem, int64, error) {
	var items []model.KnowledgeArticle
	var count int64

	tx := s.session().WithContext(ctx).Model(&model.KnowledgeArticle{})

	if req.Category != "" {
		tx = tx.Where("category = ?", req.Category)
	}
	if req.IncidentType != "" {
		tx = tx.Where("incident_type = ?", req.IncidentType)
	}
	if req.Keyword != "" {
		tx = tx.Where("title LIKE ?", "%"+req.Keyword+"%")
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if err := tx.Scopes(db.Paginate(req.Page, req.PageSize)).
		Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}

	result := make([]knowledgeContract.KBListItem, len(items))
	for i, a := range items {
		result[i] = knowledgeContract.KBListItem{
			ID:           a.Id,
			Title:        a.Title,
			Category:     a.Category,
			Tags:         a.Tags,
			Level:        a.Level,
			Summary:      a.Summary,
			IncidentType: a.IncidentType,
			ViewCount:    a.ViewCount,
			LikeCount:    a.LikeCount,
			AuthorName:   a.AuthorName,
			Source:       a.Source,
			CreatedAt:    a.CreatedAt,
		}
	}
	return result, count, nil
}

func (s *serviceKnowledge) RecommendSimilar(ctx context.Context, incidentId string) ([]knowledgeContract.KBListItem, error) {
	var incident model.SecurityIncident
	if err := s.session().WithContext(ctx).
		Preload("EventMetadata").
		First(&incident, "id = ?", incidentId).Error; err != nil {
		return nil, fmt.Errorf("事件不存在: %w", err)
	}

	var incidentType string
	if incident.EventMetadata != nil {
		incidentType = incident.EventMetadata.IncidentType
	}
	category := incident.AiCategory
	level := incident.Level

	tx := s.session().WithContext(ctx).Model(&model.KnowledgeArticle{}).
		Where("(incident_type = ? AND incident_type != '') OR (category = ? AND category != '') OR level = ?",
			incidentType, category, level).
		Order("view_count DESC").
		Limit(5)

	var articles []model.KnowledgeArticle
	if err := tx.Find(&articles).Error; err != nil {
		return nil, err
	}

	result := make([]knowledgeContract.KBListItem, len(articles))
	for i, a := range articles {
		result[i] = knowledgeContract.KBListItem{
			ID:           a.Id,
			Title:        a.Title,
			Category:     a.Category,
			Tags:         a.Tags,
			Level:        a.Level,
			Summary:      a.Summary,
			IncidentType: a.IncidentType,
			ViewCount:    a.ViewCount,
			LikeCount:    a.LikeCount,
			AuthorName:   a.AuthorName,
			Source:       a.Source,
			CreatedAt:    a.CreatedAt,
		}
	}
	return result, nil
}

func (s *serviceKnowledge) ArchiveFromIncident(ctx context.Context, incidentId string) error {
	var incident model.SecurityIncident
	if err := s.session().WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", incidentId).Error; err != nil {
		return fmt.Errorf("事件不存在: %w", err)
	}

	if incident.Status != model.IncidentStatusClosed {
		return fmt.Errorf("只有已关闭的事件才能归档为知识库文章")
	}

	var incidentType string
	var description string
	if incident.EventMetadata != nil {
		incidentType = incident.EventMetadata.IncidentType
		description = incident.EventMetadata.IncidentDescription
	}

	var assetName string
	if incident.AssetDetail != nil {
		assetName = incident.AssetDetail.AssetName
	}

	summary := fmt.Sprintf("事件[%s]关联资产[%s]，等级: %s",
		incident.Name, assetName, model.IncidentLevelText[incident.Level])

	article := model.KnowledgeArticle{
		Title:        fmt.Sprintf("[自动归档] %s", incident.Name),
		Content:      description,
		Category:     incident.AiCategory,
		IncidentId:   incident.Id,
		Level:        incident.Level,
		Summary:      summary,
		Solution:     incident.RemediationPlan,
		IncidentType: incidentType,
		Source:       "auto_archive",
		AuthorId:     "system",
		AuthorName:   "系统自动归档",
	}
	if article.Category == "" {
		article.Category = "案例"
	}

	return s.session().WithContext(ctx).Create(&article).Error
}
