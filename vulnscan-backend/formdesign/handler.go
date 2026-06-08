package formdesign

import (
	"vulnscan-backend/model"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

const (
	formVersionDraft     = "draft"
	formVersionPublished = "published"
	formVersionArchived  = "archived"
)

type Handler struct {
	svc *ServiceFormDesign
}

func NewHandler(svc *ServiceFormDesign) *Handler {
	return &Handler{svc: svc}
}

type templateListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	Keyword    string `form:"keyword"`
	Business   string `form:"business"`
	ObjectType string `form:"object_type"`
	Enabled    string `form:"enabled"`
}

type templateSaveReq struct {
	Name        string        `json:"name" binding:"required"`
	Code        string        `json:"code"`
	Business    string        `json:"business" binding:"required"`
	ObjectType  string        `json:"object_type"`
	Description string        `json:"description"`
	Schema      model.JSONMap `json:"schema"`
	Options     model.JSONMap `json:"options"`
	Version     int           `json:"version"`
	Enabled     *bool         `json:"enabled"`
	IsDefault   bool          `json:"is_default"`
}

type versionSaveReq struct {
	Schema    model.JSONMap `json:"schema"`
	Options   model.JSONMap `json:"options"`
	ChangeLog string        `json:"change_log"`
}

type templateURI struct {
	ID string `uri:"id" binding:"required"`
}

type versionURI struct {
	ID        string `uri:"id" binding:"required"`
	VersionID string `uri:"versionId" binding:"required"`
}

type submissionListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	TemplateID string `form:"template_id"`
	Business   string `form:"business"`
	ObjectID   string `form:"object_id"`
	ObjectType string `form:"object_type"`
}

type submissionSaveReq struct {
	TemplateID        string        `json:"template_id" binding:"required"`
	TemplateVersionID string        `json:"template_version_id"`
	Business          string        `json:"business" binding:"required"`
	ObjectID          string        `json:"object_id" binding:"required"`
	ObjectType        string        `json:"object_type"`
	FormData          model.JSONMap `json:"form_data"`
	Version           int           `json:"version"`
}

type submissionURI struct {
	ID string `uri:"id" binding:"required"`
}

func (h *Handler) ListTemplates(c *gin.Context) {
	req, ok := web.BindQuery[templateListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListTemplates(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(count, items).Send()
}

func (h *Handler) GetTemplate(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	item, err := h.svc.GetTemplateWithEditableVersion(uri.ID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *Handler) CreateTemplate(c *gin.Context) {
	req, ok := web.BindJSON[templateSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	created, err := h.svc.CreateTemplate(req, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(created).Send()
}

func (h *Handler) UpdateTemplate(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[templateSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.UpdateTemplate(uri.ID, req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) DeleteTemplate(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	if err := h.svc.DeleteTemplate(uri.ID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *Handler) ListVersions(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	items, err := h.svc.ListVersions(uri.ID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(items).Send()
}

func (h *Handler) GetVersion(c *gin.Context) {
	uri, ok := web.BindUri[versionURI](c)
	if !ok {
		return
	}
	item, err := h.svc.GetVersion(uri.ID, uri.VersionID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *Handler) SaveDraft(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[versionSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	draftID, err := h.svc.SaveDraft(uri.ID, req, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"id": draftID}).Send()
}

func (h *Handler) CreateDraft(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	draft, err := h.svc.CreateDraft(uri.ID, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(draft).Send()
}

func (h *Handler) PublishDraft(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[versionSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	published, err := h.svc.PublishDraft(uri.ID, req, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(published).Send()
}

func (h *Handler) ListSubmissions(c *gin.Context) {
	req, ok := web.BindQuery[submissionListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListSubmissions(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(count, items).Send()
}

func (h *Handler) GetSubmission(c *gin.Context) {
	uri, ok := web.BindUri[submissionURI](c)
	if !ok {
		return
	}
	item, version, err := h.svc.GetSubmission(uri.ID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"submission": item, "version": version}).Send()
}

func (h *Handler) SaveSubmission(c *gin.Context) {
	req, ok := web.BindJSON[submissionSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	result, err := h.svc.SaveSubmission(req, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"id": result.ID, "template_version_id": result.TemplateVersionID}).Send()
}

func (h *Handler) DeleteSubmission(c *gin.Context) {
	uri, ok := web.BindUri[submissionURI](c)
	if !ok {
		return
	}
	if err := h.svc.DeleteSubmission(uri.ID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}
