package setting

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"code.yt-security.com/public/sdk/middleware"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Handler struct {
	db    *gorm.DB
	cache sync.Map
}

func NewHandler(db *gorm.DB) *Handler {
	h := &Handler{db: db}
	h.warmCache()
	return h
}

func (h *Handler) warmCache() {
	var items []model.SystemSetting
	if err := h.db.Find(&items).Error; err != nil {
		slog.Error("加载系统设置缓存失败", "error", err)
		return
	}
	for _, item := range items {
		h.cache.Store(item.Key, item.Value)
	}
	slog.Info("[+] 系统设置缓存已加载", "count", len(items))
}

func (h *Handler) Get(key, fallback string) string {
	if v, ok := h.cache.Load(key); ok {
		return v.(string)
	}
	return fallback
}

func (h *Handler) GetInt(key string, fallback int) int {
	s := h.Get(key, "")
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

func (h *Handler) GetBool(key string, fallback bool) bool {
	s := h.Get(key, "")
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return fallback
	}
	return v
}

func (h *Handler) GetJSON(key string, target interface{}) error {
	s := h.Get(key, "")
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), target)
}

func (h *Handler) ListAll(c *gin.Context) {
	group := c.Query("group")
	var items []model.SystemSetting
	tx := h.db.Model(&model.SystemSetting{})
	if group != "" {
		tx = tx.Where("`group` = ?", group)
	}
	tx.Order("`group`, `key`").Find(&items)

	for i := range items {
		if items[i].IsSecret && items[i].Value != "" {
			items[i].Value = "******"
		}
	}
	web.RespContent(c, web.Success, items)
}

func (h *Handler) GetByKey(c *gin.Context) {
	key := c.Param("key")
	var item model.SystemSetting
	if err := h.db.Where("`key` = ?", key).First(&item).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	if item.IsSecret && item.Value != "" {
		item.Value = "******"
	}
	web.RespContent(c, web.Success, item)
}

type batchUpdateReq struct {
	Items []struct {
		Key   string `json:"key" binding:"required"`
		Value string `json:"value"`
	} `json:"items" binding:"required"`
}

func (h *Handler) BatchUpdate(c *gin.Context) {
	var req batchUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	user, _ := middleware.GetCurrentUser(c)
	updatedBy := ""
	if user != nil {
		updatedBy = user.UserID
	}

	now := time.Now()
	err := h.db.Transaction(func(tx *gorm.DB) error {
		for _, item := range req.Items {
			result := tx.Model(&model.SystemSetting{}).
				Where("`key` = ?", item.Key).
				Updates(map[string]any{
					"value":      item.Value,
					"updated_at": now,
					"updated_by": updatedBy,
				})
			if result.RowsAffected == 0 {
				return tx.Create(&model.SystemSetting{
					Key:       item.Key,
					Value:     item.Value,
					UpdatedAt: now,
					UpdatedBy: updatedBy,
				}).Error
			}
			if result.Error != nil {
				return result.Error
			}
		}
		return nil
	})
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	for _, item := range req.Items {
		h.cache.Store(item.Key, item.Value)
	}
	web.Resp(c, web.Success)
}

func (h *Handler) ResetGroup(c *gin.Context) {
	group := c.Param("group")
	defaults := defaultSettings()

	user, _ := middleware.GetCurrentUser(c)
	updatedBy := ""
	if user != nil {
		updatedBy = user.UserID
	}

	now := time.Now()
	err := h.db.Transaction(func(tx *gorm.DB) error {
		for _, d := range defaults {
			if d.Group != group {
				continue
			}
			tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at", "updated_by"}),
			}).Create(&model.SystemSetting{
				Key:       d.Key,
				Value:     d.Value,
				Group:     d.Group,
				Label:     d.Label,
				ValueType: d.ValueType,
				UpdatedAt: now,
				UpdatedBy: updatedBy,
			})
			h.cache.Store(d.Key, d.Value)
		}
		return nil
	})
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) SeedDefaults() {
	defaults := defaultSettings()
	now := time.Now()
	for _, d := range defaults {
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.SystemSetting{
			Key:         d.Key,
			Value:       d.Value,
			Group:       d.Group,
			Label:       d.Label,
			Description: d.Description,
			ValueType:   d.ValueType,
			IsSecret:    d.IsSecret,
			UpdatedAt:   now,
		})
		if _, loaded := h.cache.Load(d.Key); !loaded {
			h.cache.Store(d.Key, d.Value)
		}
	}
}

type SettingRoutes struct {
	handler *Handler
}

func NewSettingRoutes(handler *Handler) *SettingRoutes {
	return &SettingRoutes{handler: handler}
}

func (m *SettingRoutes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/setting"), []authorize.Route{
		{
			Name: "系统设置", Enabled: true,
			Children: []authorize.Route{
				{Name: "查询设置", Path: "list", Method: "GET", Handler: m.handler.ListAll, Enabled: true},
				{Name: "获取设置项", Path: ":key", Method: "GET", Handler: m.handler.GetByKey, Enabled: true},
				{Name: "批量保存", Path: "batch", Method: "PUT", Handler: m.handler.BatchUpdate, Enabled: true},
				{Name: "重置分组", Path: "reset/:group", Method: "POST", Handler: m.handler.ResetGroup, Enabled: true},
			},
		},
	})
}
