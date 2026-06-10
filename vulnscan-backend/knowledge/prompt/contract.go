package prompt

import (
	"context"
	"time"
)

type Service interface {
	Create(ctx context.Context, req CreateReq) error
	Update(ctx context.Context, id string, req UpdateReq) error
	Delete(ctx context.Context, id string) error
	GetDetail(ctx context.Context, id string) (*DetailResp, error)
	List(ctx context.Context, req ListReq) ([]ListItem, int64, error)
	GetByScene(ctx context.Context, scene string) (*DetailResp, error)
	Toggle(ctx context.Context, id string) error
}

type CreateReq struct {
	Name         string  `json:"name" binding:"required"`
	Scene        string  `json:"scene" binding:"required"`
	Description  string  `json:"description"`
	SystemPrompt string  `json:"system_prompt" binding:"required"`
	UserPrompt   string  `json:"user_prompt" binding:"required"`
	OutputFormat string  `json:"output_format"`
	Variables    string  `json:"variables"`
	ModelName    string  `json:"model_name"`
	Temperature  float64 `json:"temperature"`
	MaxTokens    int     `json:"max_tokens"`
}

type UpdateReq struct {
	Name         string  `json:"name"`
	Scene        string  `json:"scene"`
	Description  string  `json:"description"`
	SystemPrompt string  `json:"system_prompt"`
	UserPrompt   string  `json:"user_prompt"`
	OutputFormat string  `json:"output_format"`
	Variables    string  `json:"variables"`
	ModelName    string  `json:"model_name"`
	Temperature  float64 `json:"temperature"`
	MaxTokens    int     `json:"max_tokens"`
}

type ListReq struct {
	Scene    string `form:"scene"`
	Keyword  string `form:"keyword"`
	Page     int    `form:"page"`
	PageSize int    `form:"page_size" binding:"lte=100"`
}

type ListItem struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Scene       string    `json:"scene"`
	Description string    `json:"description"`
	ModelName   string    `json:"model_name"`
	Enabled     bool      `json:"enabled"`
	IsBuiltin   bool      `json:"is_builtin"`
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DetailResp struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Scene        string    `json:"scene"`
	Description  string    `json:"description"`
	SystemPrompt string    `json:"system_prompt"`
	UserPrompt   string    `json:"user_prompt"`
	OutputFormat string    `json:"output_format"`
	Variables    string    `json:"variables"`
	ModelName    string    `json:"model_name"`
	Temperature  float64   `json:"temperature"`
	MaxTokens    int       `json:"max_tokens"`
	Enabled      bool      `json:"enabled"`
	IsBuiltin    bool      `json:"is_builtin"`
	Version      int       `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
