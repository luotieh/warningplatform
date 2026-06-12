package model

import "time"

// ─── 派发单 ───

type DispatchOrder struct {
	ID          string `gorm:"primarykey;type:varchar(36)" json:"id"`
	Code        string `gorm:"type:varchar(50);uniqueIndex;not null" json:"code"`
	Title       string `gorm:"type:varchar(500);not null" json:"title"`
	Description string `gorm:"type:text" json:"description"`
	Type        string `gorm:"type:varchar(30);index" json:"type"`
	Priority    int    `gorm:"default:3" json:"priority"`
	Status      string `gorm:"type:varchar(30);index;default:'draft'" json:"status"`

	SourceType  string `gorm:"type:varchar(30);index" json:"source_type"`
	SourceID    string `gorm:"type:varchar(36);index" json:"source_id"`
	SourceTitle string `gorm:"type:varchar(500)" json:"source_title"`

	AssigneeType    string `gorm:"type:varchar(20)" json:"assignee_type"`
	AssigneeID      string `gorm:"type:varchar(36);index" json:"assignee_id"`
	AssigneeName    string `gorm:"type:varchar(100)" json:"assignee_name"`
	AssigneeContact string `gorm:"type:varchar(200)" json:"assignee_contact"`

	Deadline    *time.Time `json:"deadline"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	SubmittedAt *time.Time `json:"submitted_at"`
	CompletedAt *time.Time `json:"completed_at"`

	Result      string  `gorm:"type:text" json:"result"`
	ResultData  JSONMap `gorm:"type:text" json:"result_data"`
	Attachments JSONMap `gorm:"type:text" json:"attachments"`

	ReviewerID    string     `gorm:"type:varchar(36)" json:"reviewer_id"`
	ReviewComment string     `gorm:"type:text" json:"review_comment"`
	ReviewedAt    *time.Time `json:"reviewed_at"`

	RejectReason string `gorm:"type:text" json:"reject_reason"`

	CreatedBy  string    `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string    `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (DispatchOrder) TableName() string { return "vs_dispatch_order" }

// ─── 派发单状态 ───

const (
	DispatchStatusDraft      = "draft"
	DispatchStatusPending    = "pending"
	DispatchStatusRejected   = "rejected"
	DispatchStatusInProgress = "in_progress"
	DispatchStatusSubmitted  = "submitted"
	DispatchStatusReviewing  = "reviewing"
	DispatchStatusCompleted  = "completed"
	DispatchStatusCancelled  = "cancelled"
	DispatchStatusOverdue    = "overdue"
)

// ─── 派发单类型 ───

const (
	DispatchTypeVulnRetest  = "vuln_retest"
	DispatchTypeSecurityFix = "security_fix"
	DispatchTypePentest     = "pentest"
	DispatchTypeAudit       = "audit"
	DispatchTypeCustom      = "custom"
)

// ─── 来源类型 ───

const (
	DispatchSourceVuln     = "vuln"
	DispatchSourceFinding  = "finding"
	DispatchSourceIncident = "incident"
	DispatchSourceTask     = "task"
	DispatchSourceManual   = "manual"
)

// ─── 外部联系人 ───

type DispatchContact struct {
	ID         string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name       string      `gorm:"type:varchar(100);not null" json:"name"`
	Company    string      `gorm:"type:varchar(200)" json:"company"`
	Role       string      `gorm:"type:varchar(100)" json:"role"`
	Email      string      `gorm:"type:varchar(200)" json:"email"`
	Phone      string      `gorm:"type:varchar(50)" json:"phone"`
	Tags       StringArray `gorm:"type:text" json:"tags"`
	Note       string      `gorm:"type:text" json:"note"`
	CreatedBy  string      `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string      `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

func (DispatchContact) TableName() string { return "vs_dispatch_contact" }

// ─── 操作日志 ───

type DispatchOplog struct {
	ID        int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	OrderID   string    `gorm:"type:varchar(36);index;not null" json:"order_id"`
	Action    string    `gorm:"type:varchar(30);not null" json:"action"`
	Operator  string    `gorm:"type:varchar(64)" json:"operator"`
	Content   string    `gorm:"type:text" json:"content"`
	Data      JSONMap   `gorm:"type:text" json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

func (DispatchOplog) TableName() string { return "vs_dispatch_oplog" }
