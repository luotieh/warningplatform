package systemdict

import (
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(database *db.DB) *Handler {
	session, _ := database.GetDBSession()
	return &Handler{db: session}
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
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 100 {
		req.PageSize = 20
	}

	tx := h.db.Model(&model.SystemDict{})
	if req.Keyword != "" {
		tx = tx.Where("id LIKE ? OR name LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}
	if req.Category != "" {
		tx = tx.Where("category = ?", req.Category)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	var items []model.SystemDict
	if err := tx.Order("category ASC, id ASC").
		Offset((req.Page - 1) * req.PageSize).
		Limit(req.PageSize).
		Find(&items).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *Handler) Get(c *gin.Context) {
	uri, ok := web.BindUri[dictURI](c)
	if !ok {
		return
	}
	var item model.SystemDict
	if err := h.db.First(&item, "id = ?", uri.ID).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	var children []model.SystemDictItem
	if err := h.db.Where("dict_id = ?", uri.ID).Order("sort ASC, created_at ASC").Find(&children).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"dict": item, "items": children})
}

func (h *Handler) Create(c *gin.Context) {
	req, ok := web.BindJSON[dictCreateReq](c)
	if !ok {
		return
	}
	if req.ID == "" {
		req.ID = qulid.GenerateID()
	}

	now := time.Now()
	err := h.db.Transaction(func(tx *gorm.DB) error {
		dict := model.SystemDict{
			ID:          req.ID,
			Name:        req.Name,
			Category:    req.Category,
			Description: req.Description,
			ItemCount:   int64(len(req.Items)),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := tx.Create(&dict).Error; err != nil {
			return err
		}
		return h.createItems(tx, req.ID, req.Items)
	})
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"id": req.ID})
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
	if err := h.db.Model(&model.SystemDict{}).Where("id = ?", uri.ID).Updates(updates).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) Delete(c *gin.Context) {
	uri, ok := web.BindUri[dictURI](c)
	if !ok {
		return
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("dict_id = ?", uri.ID).Delete(&model.SystemDictItem{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.SystemDict{}, "id = ?", uri.ID).Error
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) Items(c *gin.Context) {
	query, ok := web.BindQuery[dictItemQuery](c)
	if !ok {
		return
	}
	h.listItems(c, query.DictID, query.Enabled != "false")
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
	h.listItems(c, uri.DictID, query.Enabled != "false")
}

func (h *Handler) listItems(c *gin.Context, dictID string, enabledOnly bool) {
	tx := h.db.Model(&model.SystemDictItem{})
	if dictID != "" {
		tx = tx.Where("dict_id = ?", dictID)
	}
	if enabledOnly {
		tx = tx.Where("enabled = ?", true)
	}
	var items []model.SystemDictItem
	if err := tx.Order("sort ASC, created_at ASC").Find(&items).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, items)
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
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := h.createItems(tx, uri.DictID, req); err != nil {
			return err
		}
		return h.refreshItemCount(tx, uri.DictID)
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) UpdateItem(c *gin.Context) {
	uri, ok := web.BindUri[dictItemURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[dictItemInput](c)
	if !ok || req.ID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	updates := map[string]any{
		"label":      req.Label,
		"value":      req.Value,
		"sort":       req.Sort,
		"remark":     req.Remark,
		"updated_at": time.Now(),
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if err := h.db.Model(&model.SystemDictItem{}).
		Where("dict_id = ? AND id = ?", uri.DictID, req.ID).
		Updates(updates).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
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
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("dict_id = ? AND id IN ?", uri.DictID, req.IDs).Delete(&model.SystemDictItem{}).Error; err != nil {
			return err
		}
		return h.refreshItemCount(tx, uri.DictID)
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) createItems(tx *gorm.DB, dictID string, inputs []dictItemInput) error {
	if len(inputs) == 0 {
		return nil
	}
	now := time.Now()
	items := make([]model.SystemDictItem, 0, len(inputs))
	for i, input := range inputs {
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		sort := input.Sort
		if sort == 0 {
			sort = i + 1
		}
		items = append(items, model.SystemDictItem{
			ID:        firstNonEmpty(input.ID, qulid.GenerateID()),
			DictID:    dictID,
			Label:     input.Label,
			Value:     input.Value,
			Sort:      sort,
			Enabled:   enabled,
			Remark:    input.Remark,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return tx.Create(&items).Error
}

func (h *Handler) refreshItemCount(tx *gorm.DB, dictID string) error {
	var count int64
	if err := tx.Model(&model.SystemDictItem{}).Where("dict_id = ?", dictID).Count(&count).Error; err != nil {
		return err
	}
	return tx.Model(&model.SystemDict{}).Where("id = ?", dictID).Updates(map[string]any{
		"item_count": count,
		"updated_at": time.Now(),
	}).Error
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (h *Handler) SeedDefaults() {
	defaults := defaultDicts()
	for _, d := range defaults {
		itemCount := int64(len(d.Items))
		dict := model.SystemDict{
			ID:          d.ID,
			Name:        d.Name,
			Category:    d.Category,
			Description: d.Description,
			ItemCount:   itemCount,
		}
		if err := h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&dict).Error; err != nil {
			slog.Warn("初始化系统字典失败", "dict", d.ID, "error", err)
			continue
		}
		for i, item := range d.Items {
			enabled := true
			h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.SystemDictItem{
				ID:      d.ID + "_" + item.Value,
				DictID:  d.ID,
				Label:   item.Label,
				Value:   item.Value,
				Sort:    i + 1,
				Enabled: enabled,
			})
		}
		_ = h.refreshItemCount(h.db, d.ID)
	}
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
