package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type JSONMap map[string]interface{}

func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return "null", nil
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("cannot scan %T into JSONMap", value)
	}
	return json.Unmarshal(bytes, j)
}

type JSONArray []interface{}

func (j JSONArray) Value() (driver.Value, error) {
	if j == nil {
		return "null", nil
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func (j *JSONArray) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("cannot scan %T into JSONArray", value)
	}
	return json.Unmarshal(bytes, j)
}

type StringArray []string

func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}

func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
	return json.Unmarshal(bytes, s)
}

type BaseModel struct {
	ID         string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	CreatedBy  string    `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string    `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (m *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = qulid.GenerateID()
	}
	return nil
}

// ─── 通报/事件模块共用嵌入基础模型 ───

type FullModel struct {
	Id        string    `json:"id" gorm:"primaryKey;type:varchar(80)"`
	CreatedAt time.Time `json:"created_at" gorm:"type:timestamp"`
	CreatedBy string    `json:"created_by" gorm:"type:varchar(70)"`
	UpdatedAt time.Time `json:"updated_at" gorm:"type:timestamp"`
	UpdatedBy string    `json:"updated_by" gorm:"type:varchar(70)"`
}

func (m *FullModel) BeforeCreate(tx *gorm.DB) error {
	if m.Id == "" {
		m.Id = qulid.GenerateID()
	}
	return nil
}

type ReadOnlyModel struct {
	Id        string    `json:"id" gorm:"primaryKey;type:varchar(80)"`
	CreatedAt time.Time `json:"created_at" gorm:"type:timestamp"`
}

type AutoIncModel struct {
	Id        int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time `json:"created_at" gorm:"type:timestamp"`
	UpdatedAt time.Time `json:"updated_at" gorm:"type:timestamp"`
}

// ─── 扩展 JSON 类型 ───

type JSONMapSlice []map[string]any

func (j JSONMapSlice) Value() (driver.Value, error) {
	if j == nil {
		return "[]", nil
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func (j *JSONMapSlice) Scan(v any) error {
	if v == nil {
		return nil
	}
	switch data := v.(type) {
	case []byte:
		return json.Unmarshal(data, j)
	case string:
		return json.Unmarshal([]byte(data), j)
	default:
		return errors.New("unsupported type for JSONMapSlice")
	}
}
