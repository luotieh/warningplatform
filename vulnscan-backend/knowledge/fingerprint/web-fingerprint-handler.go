package fingerprint

import (
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerWebFingerprint struct {
	svc *ServiceWebFingerprint
}

func NewHandlerWebFingerprint(svc *ServiceWebFingerprint) *HandlerWebFingerprint {
	return &HandlerWebFingerprint{svc: svc}
}

func (h *HandlerWebFingerprint) List(c *gin.Context) {
	query, ok := web.BindQuery[WebFingerprintQuery](c)
	if !ok {
		return
	}

	items, count, err := h.svc.List(query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerWebFingerprint) GetByID(c *gin.Context) {
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

func (h *HandlerWebFingerprint) Create(c *gin.Context) {
	req, ok := web.BindJSON[WebFingerprintCreateReq](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	item, err := h.svc.Create(req, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerWebFingerprint) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[WebFingerprintUpdateReq](c)
	if !ok {
		return
	}

	if err := h.svc.Update(uri.Id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerWebFingerprint) Delete(c *gin.Context) {
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
