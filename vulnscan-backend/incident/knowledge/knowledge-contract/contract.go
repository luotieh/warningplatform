package knowledgeContract

import (
	"context"
	"time"
)

type ServiceKnowledge interface {
	CreateArticle(ctx context.Context, req KBCreateReq) error
	UpdateArticle(ctx context.Context, id string, req KBUpdateReq) error
	DeleteArticle(ctx context.Context, id string) error
	GetArticleDetail(ctx context.Context, id string) (*KBDetailResp, error)
	ListArticles(ctx context.Context, req KBListReq) ([]KBListItem, int64, error)
	RecommendSimilar(ctx context.Context, incidentId string) ([]KBListItem, error)
	ArchiveFromIncident(ctx context.Context, incidentId string) error
}

type KBCreateReq struct {
	Title        string `json:"title" binding:"required"`
	Content      string `json:"content"`
	Category     string `json:"category" binding:"required"`
	Tags         string `json:"tags"`
	IncidentId   string `json:"incident_id"`
	Level        int    `json:"level"`
	Summary      string `json:"summary"`
	Solution     string `json:"solution"`
	IncidentType string `json:"incident_type"`
	AuthorId     string `json:"author_id"`
	AuthorName   string `json:"author_name"`
}

type KBUpdateReq struct {
	Title    string `json:"title"`
	Content  string `json:"content"`
	Category string `json:"category"`
	Tags     string `json:"tags"`
	Summary  string `json:"summary"`
	Solution string `json:"solution"`
}

type KBListReq struct {
	Category     string `form:"category"`
	Keyword      string `form:"keyword"`
	IncidentType string `form:"incident_type"`
	Index        int    `form:"index"`
	Size         int    `form:"size" binding:"lte=100"`
}

type KBListItem struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Category     string    `json:"category"`
	Tags         string    `json:"tags"`
	Level        int       `json:"level"`
	Summary      string    `json:"summary"`
	IncidentType string    `json:"incident_type"`
	ViewCount    int       `json:"view_count"`
	LikeCount    int       `json:"like_count"`
	AuthorName   string    `json:"author_name"`
	Source       string    `json:"source"`
	CreatedAt    time.Time `json:"created_at"`
}

type KBDetailResp struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
	Category     string    `json:"category"`
	Tags         string    `json:"tags"`
	IncidentId   string    `json:"incident_id"`
	Level        int       `json:"level"`
	Summary      string    `json:"summary"`
	Solution     string    `json:"solution"`
	IncidentType string    `json:"incident_type"`
	ViewCount    int       `json:"view_count"`
	LikeCount    int       `json:"like_count"`
	AuthorId     string    `json:"author_id"`
	AuthorName   string    `json:"author_name"`
	Source       string    `json:"source"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
