package model

const (
	DictTypeSubdomain = "subdomain"
	DictTypeDirpath   = "dirpath"
	DictTypeUsername  = "username"
	DictTypePassword  = "password"
	DictTypeUserAgent = "useragent"
	DictTypeCustom    = "custom"

	DictStatusActive   = "active"
	DictStatusDisabled = "disabled"
)

// Dictionary 字典集
type Dictionary struct {
	BaseModel
	Name        string `gorm:"type:varchar(128);not null;uniqueIndex" json:"name"`
	Type        string `gorm:"type:varchar(32);not null;index" json:"type"`
	Description string `gorm:"type:text" json:"description"`
	EntryCount  int    `gorm:"default:0" json:"entry_count"`
	Source      string `gorm:"type:varchar(64)" json:"source"`
	Status      string `gorm:"type:varchar(16);default:'active'" json:"status"`
}

func (Dictionary) TableName() string { return "vs_dictionary" }

// DictionaryEntry 字典条目
type DictionaryEntry struct {
	ID           string `gorm:"primarykey;type:varchar(36)" json:"id"`
	DictionaryID string `gorm:"type:varchar(36);not null;index:idx_dict_entry" json:"dictionary_id"`
	Value        string `gorm:"type:varchar(512);not null;index:idx_dict_entry" json:"value"`
	Tags         string `gorm:"type:varchar(256)" json:"tags"`
	Priority     int    `gorm:"default:0" json:"priority"`
}

func (DictionaryEntry) TableName() string { return "vs_dictionary_entry" }
