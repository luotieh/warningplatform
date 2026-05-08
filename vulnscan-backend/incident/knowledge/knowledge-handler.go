package knowledge

import (
	knowledgeContract "vulnscan-backend/incident/knowledge/knowledge-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerKnowledge struct {
	svc knowledgeContract.ServiceKnowledge
}

func NewHandlerKnowledge(svc knowledgeContract.ServiceKnowledge) *HandlerKnowledge {
	return &HandlerKnowledge{svc: svc}
}

func (h *HandlerKnowledge) Create(c *gin.Context) {
	req, ok := web.BindJSON[knowledgeContract.KBCreateReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	req.AuthorId = user.UserID
	req.AuthorName = user.Account
	if err := h.svc.CreateArticle(c.Request.Context(), req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerKnowledge) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[knowledgeContract.KBUpdateReq](c)
	if !ok {
		return
	}
	if err := h.svc.UpdateArticle(c.Request.Context(), uri.Id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerKnowledge) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.DeleteArticle(c.Request.Context(), uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerKnowledge) Detail(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetArticleDetail(c.Request.Context(), uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerKnowledge) List(c *gin.Context) {
	req, ok := web.BindQuery[knowledgeContract.KBListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListArticles(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerKnowledge) Recommend(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		IncidentId string `form:"incident_id" binding:"required"`
	}](c)
	if !ok {
		return
	}
	items, err := h.svc.RecommendSimilar(c.Request.Context(), query.IncidentId)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerKnowledge) Archive(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		IncidentId string `json:"incident_id" binding:"required"`
	}](c)
	if !ok {
		return
	}
	if err := h.svc.ArchiveFromIncident(c.Request.Context(), req.IncidentId); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
