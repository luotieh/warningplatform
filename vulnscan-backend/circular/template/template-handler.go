package template

import (
	"vulnscan-backend/model"

	templateContract "vulnscan-backend/circular/template/template-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerTemplate struct {
	svc templateContract.ServiceTemplate
}

func NewHandlerTemplate(svc templateContract.ServiceTemplate) *HandlerTemplate {
	return &HandlerTemplate{svc: svc}
}

func (h *HandlerTemplate) Add(c *gin.Context) {
	tmp, ok := web.BindJSON[model.CircularTemplate](c)
	if !ok {
		return
	}

	if err := h.svc.Add(c.Request.Context(), tmp); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerTemplate) List(c *gin.Context) {
	req, ok := web.BindQuery[templateContract.TemplateListQuery](c)
	if !ok {
		return
	}

	total, items, err := h.svc.List(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, items).Send()
}

func (h *HandlerTemplate) Edit(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[templateContract.TemplateEditReq](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Edit(c.Request.Context(), uri.Id, req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerTemplate) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}

	if err := h.svc.Delete(c.Request.Context(), uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
