package vuln

import (
	vulnContract "vulnscan-backend/vuln/vuln-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerVuln struct {
	svc vulnContract.ServiceVuln
}

func NewHandlerVuln(svc vulnContract.ServiceVuln) *HandlerVuln {
	return &HandlerVuln{svc: svc}
}

func (h *HandlerVuln) List(c *gin.Context) {
	query, ok := web.BindQuery[vulnContract.VulnQuery](c)
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

func (h *HandlerVuln) GetByID(c *gin.Context) {
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

func (h *HandlerVuln) Delete(c *gin.Context) {
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

type markIgnoredReq struct {
	Reason string `json:"reason"`
}

func (h *HandlerVuln) MarkFixed(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.MarkFixed(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerVuln) MarkIgnored(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[markIgnoredReq](c)
	if !ok {
		return
	}
	if err := h.svc.MarkIgnored(uri.Id, req.Reason); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerVuln) Reopen(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Reopen(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerVuln) StatusHistory(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	items, err := h.svc.GetStatusHistory(uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerVuln) Stats(c *gin.Context) {
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	stats, err := h.svc.Stats(scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(stats).Send()
}
