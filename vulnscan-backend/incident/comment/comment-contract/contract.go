package commentContract

import (
	"context"
	"time"
)

type ServiceComment interface {
	CreateComment(ctx context.Context, req CommentCreateReq) (*CommentItem, error)
	ListComments(ctx context.Context, incidentId string) ([]CommentItem, error)
	DeleteComment(ctx context.Context, id string, operatorId string) error
}

type CommentCreateReq struct {
	IncidentId string `json:"incident_id" binding:"required"`
	ParentId   string `json:"parent_id"`
	Content    string `json:"content" binding:"required"`
	AuthorId   string `json:"author_id"`
	AuthorName string `json:"author_name"`
	Mentions   string `json:"mentions"`
}

type CommentItem struct {
	ID         string        `json:"id"`
	IncidentId string        `json:"incident_id"`
	ParentId   string        `json:"parent_id"`
	Content    string        `json:"content"`
	AuthorId   string        `json:"author_id"`
	AuthorName string        `json:"author_name"`
	Mentions   string        `json:"mentions"`
	CreatedAt  time.Time     `json:"created_at"`
	Replies    []CommentItem `json:"replies,omitempty"`
}
