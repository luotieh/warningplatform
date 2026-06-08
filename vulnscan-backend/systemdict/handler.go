package systemdict

import (
	"time"

	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *ServiceSystemDict
}

func NewHandler(svc *ServiceSystemDict) *Handler {
	return &Handler{svc: svc}
}

type dictListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Category string `form:"category"`
}

type dictCreateReq struct {
	ID          string          `json:"id"`
	Name        string          `json:"name" binding:"required"`
	Category    string          `json:"category"`
	Description string          `json:"description"`
	Items       []dictItemInput `json:"items"`
}

type dictUpdateReq struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type dictItemInput struct {
	ID      string `json:"id"`
	Label   string `json:"label" binding:"required"`
	Value   string `json:"value" binding:"required"`
	Sort    int    `json:"sort"`
	Enabled *bool  `json:"enabled"`
	Remark  string `json:"remark"`
}

type itemDeleteReq struct {
	IDs []string `json:"ids" binding:"required"`
}

type dictURI struct {
	ID string `uri:"id" binding:"required"`
}

type dictItemURI struct {
	DictID string `uri:"dictId" binding:"required"`
}

type dictItemQuery struct {
	DictID  string `form:"dict_id"`
	Enabled string `form:"enabled"`
}

func (h *Handler) List(c *gin.Context) {
	req, ok := web.BindQuery[dictListReq](c)
	if !ok {
		return
	}

	items, count, err := h.svc.List(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(count, items).Send()
}

func (h *Handler) Get(c *gin.Context) {
	uri, ok := web.BindUri[dictURI](c)
	if !ok {
		return
	}
	item, children, err := h.svc.GetByID(uri.ID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"dict": item, "items": children}).Send()
}

func (h *Handler) Create(c *gin.Context) {
	req, ok := web.BindJSON[dictCreateReq](c)
	if !ok {
		return
	}
	id, err := h.svc.Create(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"id": id}).Send()
}

func (h *Handler) Update(c *gin.Context) {
	uri, ok := web.BindUri[dictURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[dictUpdateReq](c)
	if !ok {
		return
	}
	updates := map[string]any{"updated_at": time.Now()}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Category != "" {
		updates["category"] = req.Category
	}
	updates["description"] = req.Description
	if err := h.svc.Update(uri.ID, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) Delete(c *gin.Context) {
	uri, ok := web.BindUri[dictURI](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(uri.ID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) Items(c *gin.Context) {
	query, ok := web.BindQuery[dictItemQuery](c)
	if !ok {
		return
	}
	items, err := h.svc.ListItems(query.DictID, query.Enabled != "false")
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(items).Send()
}

func (h *Handler) ItemsByDict(c *gin.Context) {
	uri, ok := web.BindUri[dictItemURI](c)
	if !ok {
		return
	}
	query, ok := web.BindQuery[dictItemQuery](c)
	if !ok {
		return
	}
	items, err := h.svc.ListItems(uri.DictID, query.Enabled != "false")
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(items).Send()
}

func (h *Handler) AddItems(c *gin.Context) {
	uri, ok := web.BindUri[dictItemURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[[]dictItemInput](c)
	if !ok {
		return
	}
	if err := h.svc.AddItems(uri.DictID, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) UpdateItem(c *gin.Context) {
	uri, ok := web.BindUri[dictItemURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[dictItemInput](c)
	if !ok || req.ID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	if err := h.svc.UpdateItem(uri.DictID, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) DeleteItems(c *gin.Context) {
	uri, ok := web.BindUri[dictItemURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[itemDeleteReq](c)
	if !ok {
		return
	}
	if err := h.svc.DeleteItems(uri.DictID, req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) SeedDefaults() {
	h.svc.SeedDefaults()
}

type Routes struct {
	handler *Handler
}

func NewRoutes(handler *Handler) *Routes {
	return &Routes{handler: handler}
}

func (m *Routes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/system/dict"), []authorize.Route{
		{
			Name: "系统字典", Enabled: true,
			Children: []authorize.Route{
				{Name: "字典列表", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "字典创建", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "字典详情", Path: "detail/:id", Method: "GET", Handler: m.handler.Get, Enabled: true},
				{Name: "字典更新", Path: "detail/:id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "字典删除", Path: "detail/:id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "字典项全部", Path: "item/all/:dictId", Method: "GET", Handler: m.handler.ItemsByDict, Enabled: true},
				{Name: "字典项查询", Path: "item", Method: "GET", Handler: m.handler.Items, Enabled: true},
				{Name: "字典项添加", Path: "item/:dictId", Method: "POST", Handler: m.handler.AddItems, Enabled: true},
				{Name: "字典项更新", Path: "item/:dictId", Method: "PUT", Handler: m.handler.UpdateItem, Enabled: true},
				{Name: "字典项删除", Path: "item/:dictId", Method: "DELETE", Handler: m.handler.DeleteItems, Enabled: true},
			},
		},
	})
}
