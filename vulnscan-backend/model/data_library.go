package model

import "time"

const (
	DataLibTypeSubdomain = "subdomain"
	DataLibTypeDirpath   = "dirpath"
	DataLibTypeUsername  = "username"
	DataLibTypePassword  = "password"
	DataLibTypeUserAgent = "useragent"
	DataLibTypePayload   = "payload"
	DataLibTypePattern   = "pattern"
	DataLibTypeConfig    = "config"
	DataLibTypeCustom    = "custom"

	DataLibStatusActive   = "active"
	DataLibStatusDisabled = "disabled"
)

type DataLibrary struct {
	BaseModel
	Name        string `gorm:"type:varchar(128);not null;uniqueIndex" json:"name"`
	Type        string `gorm:"type:varchar(32);not null;index" json:"type"`
	Category    string `gorm:"type:varchar(64);index" json:"category"`
	Description string `gorm:"type:text" json:"description"`
	EntryCount  int    `gorm:"default:0" json:"entry_count"`
	Source      string `gorm:"type:varchar(64)" json:"source"`
	Status      string `gorm:"type:varchar(16);default:'active'" json:"status"`
}

func (DataLibrary) TableName() string { return "vs_data_library" }

type DataLibraryEntry struct {
	ID        string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	LibraryID string    `gorm:"type:varchar(36);not null;index:idx_datalib_entry" json:"library_id"`
	Name      string    `gorm:"type:varchar(200)" json:"name"`
	Value     string    `gorm:"type:text;not null" json:"value"`
	Type      string    `gorm:"type:varchar(50)" json:"type"`
	Tags      string    `gorm:"type:varchar(500)" json:"tags"`
	Metadata  JSONMap   `gorm:"type:text" json:"metadata"`
	Priority  int       `gorm:"default:0" json:"priority"`
	Enabled   bool      `gorm:"default:true;index" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (DataLibraryEntry) TableName() string { return "vs_data_library_entry" }
