package setting

import (
	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/access/middleware"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *ServiceSetting
}

func NewHandler(svc *ServiceSetting) *Handler {
	return &Handler{svc: svc}
}

// Get delegates to the service cache.
func (h *Handler) Get(key, fallback string) string {
	return h.svc.Get(key, fallback)
}

// GetInt delegates to the service cache.
func (h *Handler) GetInt(key string, fallback int) int {
	return h.svc.GetInt(key, fallback)
}

// GetBool delegates to the service cache.
func (h *Handler) GetBool(key string, fallback bool) bool {
	return h.svc.GetBool(key, fallback)
}

// GetJSON delegates to the service cache.
func (h *Handler) GetJSON(key string, target interface{}) error {
	return h.svc.GetJSON(key, target)
}

// SeedDefaults delegates to the service.
func (h *Handler) SeedDefaults() {
	h.svc.SeedDefaults()
}

func (h *Handler) ListAll(c *gin.Context) {
	group := c.Query("group")
	items, err := h.svc.ListAll(group)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	for i := range items {
		if items[i].IsSecret && items[i].Value != "" {
			items[i].Value = "******"
		}
	}
	web.Succeed(c).Data(items).Send()
}

func (h *Handler) GetByKey(c *gin.Context) {
	key := c.Param("key")
	item, err := h.svc.GetByKey(key)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	if item.IsSecret && item.Value != "" {
		item.Value = "******"
	}
	web.Succeed(c).Data(item).Send()
}

type batchUpdateReq struct {
	Items []struct {
		Key   string `json:"key" binding:"required"`
		Value string `json:"value"`
	} `json:"items" binding:"required"`
}

func (h *Handler) BatchUpdate(c *gin.Context) {
	req, ok := web.BindJSON[batchUpdateReq](c)
	if !ok {
		return
	}

	user, _ := middleware.GetCurrentUser(c)
	updatedBy := ""
	if user != nil {
		updatedBy = user.UserID
	}

	svcItems := make([]struct {
		Key   string
		Value string
	}, len(req.Items))
	for i, item := range req.Items {
		svcItems[i] = struct {
			Key   string
			Value string
		}{Key: item.Key, Value: item.Value}
	}

	if err := h.svc.BatchUpdate(svcItems, updatedBy); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) ResetGroup(c *gin.Context) {
	group := c.Param("group")

	user, _ := middleware.GetCurrentUser(c)
	updatedBy := ""
	if user != nil {
		updatedBy = user.UserID
	}

	if err := h.svc.ResetGroup(group, updatedBy); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
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
