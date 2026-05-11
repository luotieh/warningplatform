package model

import (
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type SystemDict struct {
	ID          string    `gorm:"primarykey;type:varchar(64)" json:"id"`
	Name        string    `gorm:"type:varchar(200);not null" json:"name"`
	Category    string    `gorm:"type:varchar(100);index" json:"category"`
	Description string    `gorm:"type:varchar(500)" json:"description"`
	ItemCount   int64     `gorm:"default:0" json:"item_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (SystemDict) TableName() string { return "vs_system_dict" }

func (m *SystemDict) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = qulid.GenerateID()
	}
	return nil
}

type SystemDictItem struct {
	ID        string         `gorm:"primarykey;type:varchar(64)" json:"id"`
	DictID    string         `gorm:"type:varchar(64);not null;index" json:"dict_id"`
	Label     string         `gorm:"type:varchar(200);not null" json:"label"`
	Value     string         `gorm:"type:varchar(200);not null;index" json:"value"`
	Sort      int            `gorm:"default:0" json:"sort"`
	Enabled   bool           `gorm:"default:true" json:"enabled"`
	Remark    string         `gorm:"type:varchar(500)" json:"remark"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (SystemDictItem) TableName() string { return "vs_system_dict_item" }

func (m *SystemDictItem) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = qulid.GenerateID()
	}
	return nil
}
