package dispatchContract

import (
	"context"
	"vulnscan-backend/model"
)

type OrderQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Status   string `form:"status"`
	Type     string `form:"type"`
	Priority int    `form:"priority"`
}

type CreateOrderReq struct {
	Title           string        `json:"title" binding:"required"`
	Description     string        `json:"description"`
	Type            string        `json:"type" binding:"required"`
	Priority        int           `json:"priority"`
	SourceType      string        `json:"source_type"`
	SourceID        string        `json:"source_id"`
	SourceTitle     string        `json:"source_title"`
	AssigneeType    string        `json:"assignee_type"`
	AssigneeID      string        `json:"assignee_id"`
	AssigneeName    string        `json:"assignee_name"`
	AssigneeContact string        `json:"assignee_contact"`
	Deadline        string        `json:"deadline"`
	Attachments     model.JSONMap `json:"attachments"`
}

type AssignReq struct {
	AssigneeType    string `json:"assignee_type" binding:"required"`
	AssigneeID      string `json:"assignee_id"`
	AssigneeName    string `json:"assignee_name" binding:"required"`
	AssigneeContact string `json:"assignee_contact"`
	Deadline        string `json:"deadline"`
}

type SubmitResultReq struct {
	Result      string        `json:"result" binding:"required"`
	ResultData  model.JSONMap `json:"result_data"`
	Attachments model.JSONMap `json:"attachments"`
}

type ReviewReq struct {
	Approved bool   `json:"approved"`
	Comment  string `json:"comment"`
}

type ContactQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Company  string `form:"company"`
}

type CreateContactReq struct {
	Name    string            `json:"name" binding:"required"`
	Company string            `json:"company"`
	Role    string            `json:"role"`
	Email   string            `json:"email"`
	Phone   string            `json:"phone"`
	Tags    model.StringArray `json:"tags"`
	Note    string            `json:"note"`
}

type UpdateContactReq struct {
	Name    string            `json:"name"`
	Company string            `json:"company"`
	Role    string            `json:"role"`
	Email   string            `json:"email"`
	Phone   string            `json:"phone"`
	Tags    model.StringArray `json:"tags"`
	Note    string            `json:"note"`
}

type StatsOverview struct {
	Total             int64          `json:"total"`
	ByStatus          map[string]int `json:"by_status"`
	ByType            map[string]int `json:"by_type"`
	ByPriority        map[string]int `json:"by_priority"`
	Overdue           int            `json:"overdue"`
	AvgDaysToComplete float64        `json:"avg_days_to_complete"`
}

type ServiceOrder interface {
	List(ctx context.Context, query OrderQuery, organizeID string) ([]model.DispatchOrder, int64, error)
	GetByID(ctx context.Context, id string) (*model.DispatchOrder, error)
	Create(ctx context.Context, req CreateOrderReq, userID, organizeID string) (*model.DispatchOrder, error)
	Cancel(ctx context.Context, id, userID string) error
	Assign(ctx context.Context, id string, req AssignReq, userID string) error
	Accept(ctx context.Context, id, userID string) error
	Reject(ctx context.Context, id, userID, reason string) error
	SubmitResult(ctx context.Context, id string, req SubmitResultReq, userID string) error
	Review(ctx context.Context, id string, req ReviewReq, userID string) error
	GetOplogs(ctx context.Context, orderID string) ([]model.DispatchOplog, error)
	Stats(ctx context.Context, organizeID string) (*StatsOverview, error)
}

type ServiceContact interface {
	List(ctx context.Context, query ContactQuery, organizeID string) ([]model.DispatchContact, int64, error)
	GetByID(ctx context.Context, id string) (*model.DispatchContact, error)
	Create(ctx context.Context, req CreateContactReq, userID, organizeID string) (*model.DispatchContact, error)
	Update(ctx context.Context, id string, req UpdateContactReq) error
	Delete(ctx context.Context, id string) error
}
