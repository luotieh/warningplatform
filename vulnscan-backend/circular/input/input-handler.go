package input

import (
	inputContract "vulnscan-backend/circular/input/input-contract"
	"vulnscan-backend/circular/scope"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerInput struct {
	svc inputContract.ServiceInput
}

func NewHandlerInput(svc inputContract.ServiceInput) *HandlerInput {
	return &HandlerInput{svc: svc}
}

func (h *HandlerInput) Add(c *gin.Context) {
	req, ok := web.BindJSON[inputContract.InputAddReq](c)
	if !ok {
		return
	}
	id, err := h.svc.Add(c.Request.Context(), req, scope.ActorFromContext(c))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"id": id}).Send()
}

func (h *HandlerInput) List(c *gin.Context) {
	req, ok := web.BindQuery[inputContract.ListQuery](c)
	if !ok {
		return
	}
	total, items, err := h.svc.List(c, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(total, items).Send()
}

func (h *HandlerInput) Detail(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.Detail(c.Request.Context(), uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *HandlerInput) Edit(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[inputContract.InputEditReq](c)
	if !ok {
		return
	}
	if err := h.svc.Edit(c.Request.Context(), uri.Id, req, scope.ActorFromContext(c)); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerInput) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerInput) Submit(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Submit(c.Request.Context(), uri.Id, scope.ActorFromContext(c)); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerInput) Export(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		Codes []string `json:"codes" binding:"required"`
	}](c)
	if !ok {
		return
	}
	if err := h.svc.Export(c.Request.Context(), req.Codes); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerInput) Import(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		web.Fail(c).Msg("请上传文件").Send()
		return
	}
	count, err := h.svc.Import(c.Request.Context(), file, scope.ActorFromContext(c))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(map[string]any{"count": count}).Send()
}

func (h *HandlerInput) CommonTemplateDownload(c *gin.Context) {
	h.svc.CommonTemplateDownload(c)
}

func (h *HandlerInput) ThirdPartyImport(c *gin.Context) {
	req, ok := web.BindJSON[inputContract.InputAddReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.ThirdPartyImport(c.Request.Context(), req, scope.ActorFromContext(c), user.OrganizeID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}
