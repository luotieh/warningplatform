package model

import (
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type DynamicFormTemplate struct {
	ID               string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name             string    `gorm:"type:varchar(200);not null;index" json:"name"`
	Code             string    `gorm:"type:varchar(100);not null;uniqueIndex" json:"code"`
	Business         string    `gorm:"type:varchar(50);not null;index" json:"business"`
	ObjectType       string    `gorm:"type:varchar(100);index" json:"object_type"`
	Description      string    `gorm:"type:varchar(500)" json:"description"`
	Schema           JSONMap   `gorm:"type:text" json:"schema"`
	Options          JSONMap   `gorm:"type:text" json:"options"`
	Version          int       `gorm:"default:1" json:"version"`
	CurrentVersionID string    `gorm:"type:varchar(36);index" json:"current_version_id"`
	DraftVersionID   string    `gorm:"type:varchar(36);index" json:"draft_version_id"`
	Enabled          bool      `gorm:"default:true;index" json:"enabled"`
	IsDefault        bool      `gorm:"default:false;index" json:"is_default"`
	CreatedBy        string    `gorm:"type:varchar(64)" json:"created_by"`
	UpdatedBy        string    `gorm:"type:varchar(64)" json:"updated_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (DynamicFormTemplate) TableName() string { return "vs_dynamic_form_template" }

func (m *DynamicFormTemplate) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = qulid.GenerateID()
	}
	if m.Version == 0 {
		m.Version = 1
	}
	return nil
}

type DynamicFormTemplateVersion struct {
	ID          string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	TemplateID  string     `gorm:"type:varchar(36);not null;index:idx_form_template_version,unique" json:"template_id"`
	Version     int        `gorm:"not null;index:idx_form_template_version,unique" json:"version"`
	Status      string     `gorm:"type:varchar(20);not null;index" json:"status"`
	Schema      JSONMap    `gorm:"type:text" json:"schema"`
	Options     JSONMap    `gorm:"type:text" json:"options"`
	ChangeLog   string     `gorm:"type:varchar(500)" json:"change_log"`
	CreatedBy   string     `gorm:"type:varchar(64)" json:"created_by"`
	UpdatedBy   string     `gorm:"type:varchar(64)" json:"updated_by"`
	PublishedBy string     `gorm:"type:varchar(64)" json:"published_by"`
	PublishedAt *time.Time `json:"published_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (DynamicFormTemplateVersion) TableName() string { return "vs_dynamic_form_template_version" }

func (m *DynamicFormTemplateVersion) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = qulid.GenerateID()
	}
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Status == "" {
		m.Status = "draft"
	}
	return nil
}

type DynamicFormSubmission struct {
	ID                string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	TemplateID        string    `gorm:"type:varchar(36);not null;index" json:"template_id"`
	TemplateVersionID string    `gorm:"type:varchar(36);index" json:"template_version_id"`
	Business          string    `gorm:"type:varchar(50);not null;index" json:"business"`
	ObjectID          string    `gorm:"type:varchar(64);not null;index" json:"object_id"`
	ObjectType        string    `gorm:"type:varchar(100);index" json:"object_type"`
	FormData          JSONMap   `gorm:"type:text" json:"form_data"`
	Version           int       `gorm:"default:1" json:"version"`
	CreatedBy         string    `gorm:"type:varchar(64)" json:"created_by"`
	UpdatedBy         string    `gorm:"type:varchar(64)" json:"updated_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (DynamicFormSubmission) TableName() string { return "vs_dynamic_form_submission" }

func (m *DynamicFormSubmission) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = qulid.GenerateID()
	}
	if m.Version == 0 {
		m.Version = 1
	}
	return nil
}
