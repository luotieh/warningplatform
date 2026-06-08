package comment

import (
	"context"
	"fmt"
	"vulnscan-backend/model"

	commentContract "vulnscan-backend/incident/comment/comment-contract"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceComment struct {
	db *db.DB
}

func NewServiceComment(database *db.DB) *serviceComment {
	return &serviceComment{db: database}
}

func (s *serviceComment) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceComment) CreateComment(ctx context.Context, req commentContract.CommentCreateReq) (*commentContract.CommentItem, error) {
	comment := model.BuildIncidentComment(
		req.IncidentId,
		req.ParentId,
		req.Content,
		req.AuthorId,
		req.AuthorName,
		req.Mentions,
	)

	if err := s.session().WithContext(ctx).Create(&comment).Error; err != nil {
		return nil, err
	}

	item := &commentContract.CommentItem{
		ID:         comment.Id,
		IncidentId: comment.IncidentId,
		ParentId:   comment.ParentId,
		Content:    comment.Content,
		AuthorId:   comment.AuthorId,
		AuthorName: comment.AuthorName,
		Mentions:   comment.Mentions,
		CreatedAt:  comment.CreatedAt,
	}
	return item, nil
}

func (s *serviceComment) ListComments(ctx context.Context, incidentId string) ([]commentContract.CommentItem, error) {
	var comments []model.IncidentComment
	if err := s.session().WithContext(ctx).
		Where("incident_id = ?", incidentId).
		Order("created_at ASC").
		Find(&comments).Error; err != nil {
		return nil, err
	}

	// Build tree structure: separate top-level comments and replies
	topLevel := make([]commentContract.CommentItem, 0)
	repliesMap := make(map[string][]commentContract.CommentItem)

	for _, c := range comments {
		item := commentContract.CommentItem{
			ID:         c.Id,
			IncidentId: c.IncidentId,
			ParentId:   c.ParentId,
			Content:    c.Content,
			AuthorId:   c.AuthorId,
			AuthorName: c.AuthorName,
			Mentions:   c.Mentions,
			CreatedAt:  c.CreatedAt,
		}

		if c.ParentId == "" {
			topLevel = append(topLevel, item)
		} else {
			repliesMap[c.ParentId] = append(repliesMap[c.ParentId], item)
		}
	}

	// Attach replies to their parent comments
	for i := range topLevel {
		if replies, ok := repliesMap[topLevel[i].ID]; ok {
			topLevel[i].Replies = replies
		}
	}

	return topLevel, nil
}

func (s *serviceComment) DeleteComment(ctx context.Context, id string, operatorId string) error {
	var comment model.IncidentComment
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&comment).Error; err != nil {
		return fmt.Errorf("评论不存在")
	}

	// Soft delete
	return s.session().WithContext(ctx).Where("id = ?", id).Delete(&model.IncidentComment{}).Error
}
