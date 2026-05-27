package exclusion

import (
	exclusionContract "vulnscan-backend/exclusion/exclusion-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"vulnscan-backend/pkg/definition"
)

type HandlerExclusion struct {
	svc exclusionContract.ServiceExclusion
}

func NewHandlerExclusion(svc exclusionContract.ServiceExclusion) *HandlerExclusion {
	return &HandlerExclusion{svc: svc}
}

func (h *HandlerExclusion) List(c *gin.Context) {
	query, ok := web.BindQuery[exclusionContract.ExclusionQuery](c)
	if !ok {
		return
	}

	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerExclusion) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

type createExclusionReq struct {
	Name        string `json:"name" binding:"required"`
	RuleType    string `json:"rule_type" binding:"required"`
	MatchValue  string `json:"match_value" binding:"required"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
}

func (h *HandlerExclusion) Create(c *gin.Context) {
	req, ok := web.BindJSON[createExclusionReq](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	item := model.ScanExclusion{
		Name:        req.Name,
		RuleType:    req.RuleType,
		MatchValue:  req.MatchValue,
		Description: req.Description,
		Scope:       req.Scope,
		Enabled:     true,
		CreatedBy:   user.UserID,
		OrganizeID:  user.OrganizeID,
	}
	if item.Scope == "" {
		item.Scope = model.ExclusionScopeGlobal
	}

	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

type updateExclusionReq struct {
	Name        *string `json:"name"`
	RuleType    *string `json:"rule_type"`
	MatchValue  *string `json:"match_value"`
	Description *string `json:"description"`
	Scope       *string `json:"scope"`
	Enabled     *bool   `json:"enabled"`
}

func (h *HandlerExclusion) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[updateExclusionReq](c)
	if !ok {
		return
	}

	updates := make(map[string]any)
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.RuleType != nil {
		updates["rule_type"] = *req.RuleType
	}
	if req.MatchValue != nil {
		updates["match_value"] = *req.MatchValue
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Scope != nil {
		updates["scope"] = *req.Scope
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if len(updates) == 0 {
		web.OK(c).Send()
		return
	}
	if err := h.svc.Update(uri.Id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerExclusion) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerExclusion) Toggle(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Toggle(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
