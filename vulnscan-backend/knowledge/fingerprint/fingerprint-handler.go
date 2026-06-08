package fingerprint

import (
	"vulnscan-backend/model"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"vulnscan-backend/pkg/definition"
)

type HandlerFingerprint struct {
	svc *ServiceFingerprint
}

func NewHandlerFingerprint(svc *ServiceFingerprint) *HandlerFingerprint {
	return &HandlerFingerprint{svc: svc}
}

func (h *HandlerFingerprint) List(c *gin.Context) {
	query, ok := web.BindQuery[FingerprintQuery](c)
	if !ok {
		return
	}

	scope := iamsdk.DataFilterScopeStatic(c, definition.VulnscanFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(count, items).Send()
}

func (h *HandlerFingerprint) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *HandlerFingerprint) Create(c *gin.Context) {
	req, ok := web.BindJSON[model.ServiceFingerprint](c)
	if !ok {
		return
	}
	if err := h.svc.Create(&req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(req).Send()
}

func (h *HandlerFingerprint) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.Update(uri.Id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerFingerprint) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}
