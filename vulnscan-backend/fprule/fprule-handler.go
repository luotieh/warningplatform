package fprule

import (
	fpruleContract "vulnscan-backend/fprule/fprule-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerFPRule struct {
	svc fpruleContract.ServiceFPRule
}

func NewHandlerFPRule(svc fpruleContract.ServiceFPRule) *HandlerFPRule {
	return &HandlerFPRule{svc: svc}
}

func (h *HandlerFPRule) List(c *gin.Context) {
	query, ok := web.BindQuery[fpruleContract.FPRuleQuery](c)
	if !ok {
		return
	}

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerFPRule) GetByID(c *gin.Context) {
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

type createFPRuleReq struct {
	Name       string `json:"name"`
	MatchType  string `json:"match_type" binding:"required"`
	MatchField string `json:"match_field"`
	MatchValue string `json:"match_value" binding:"required"`
	Reason     string `json:"reason"`
	Scope      string `json:"scope"`
}

func (h *HandlerFPRule) Create(c *gin.Context) {
	req, ok := web.BindJSON[createFPRuleReq](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	item := model.FPRule{
		Name:       req.Name,
		MatchType:  req.MatchType,
		MatchField: req.MatchField,
		MatchValue: req.MatchValue,
		Reason:     req.Reason,
		Scope:      req.Scope,
		Enabled:    true,
		CreatedBy:  user.UserID,
		OrganizeID: user.OrganizeID,
	}
	if item.Scope == "" {
		item.Scope = "global"
	}

	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

type updateFPRuleReq struct {
	Name       *string `json:"name"`
	MatchType  *string `json:"match_type"`
	MatchField *string `json:"match_field"`
	MatchValue *string `json:"match_value"`
	Reason     *string `json:"reason"`
	Enabled    *bool   `json:"enabled"`
}

func (h *HandlerFPRule) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[updateFPRuleReq](c)
	if !ok {
		return
	}

	updates := make(map[string]any)
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.MatchType != nil {
		updates["match_type"] = *req.MatchType
	}
	if req.MatchField != nil {
		updates["match_field"] = *req.MatchField
	}
	if req.MatchValue != nil {
		updates["match_value"] = *req.MatchValue
	}
	if req.Reason != nil {
		updates["reason"] = *req.Reason
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

func (h *HandlerFPRule) Delete(c *gin.Context) {
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

func (h *HandlerFPRule) Toggle(c *gin.Context) {
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

func (h *HandlerFPRule) Mark(c *gin.Context) {
	req, ok := web.BindJSON[fpruleContract.MarkFPReq](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	rule, err := h.svc.MarkFromFinding(req.FindingID, req.MatchType, req.Reason, user.UserID, user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(rule).Send()
}
