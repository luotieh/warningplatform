package task

import (
	"vulnscan-backend/model"
	taskContract "vulnscan-backend/task/task-contract"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerTask struct {
	svc taskContract.ServiceTask
}

func NewHandlerTask(svc taskContract.ServiceTask) *HandlerTask {
	return &HandlerTask{svc: svc}
}

func (h *HandlerTask) List(c *gin.Context) {
	query, ok := web.BindQuery[taskContract.TaskQuery](c)
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

func (h *HandlerTask) GetByID(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	item, err := h.svc.GetByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	web.OK(c).Data(item).Send()
}

func (h *HandlerTask) Create(c *gin.Context) {
	var req taskContract.CreateTaskReq
	if !web.ValidationJson(c, &req) {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	item := model.ScanTask{
		ID:         qulid.GenerateID(),
		Name:       req.Name,
		TemplateID: req.TemplateID,
		Type:       req.Type,
		Targets:    req.Targets,
		Config:     req.Config,
		Parameters: req.Parameters,
		Priority:   req.Priority,
		CreatedBy:  user.UserID,
		OrganizeID: user.OrganizeID,
	}

	if item.Priority <= 0 {
		item.Priority = 5
	}

	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(item).Send()
}

func (h *HandlerTask) Cancel(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	if err := h.svc.Cancel(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Send()
}

func (h *HandlerTask) Pause(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Pause(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerTask) Resume(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Resume(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerTask) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	if err := h.svc.Delete(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Send()
}

func (h *HandlerTask) ListFindings(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	query, ok := web.BindQuery[taskContract.FindingQuery](c)
	if !ok {
		return
	}
	query.TaskID = taskID

	items, count, err := h.svc.ListFindings(query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).List(count, items).Send()
}

func (h *HandlerTask) FindingSummary(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	summary, err := h.svc.FindingSummary(taskID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(summary).Send()
}

func (h *HandlerTask) ListAssets(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	assets, err := h.svc.ListAssets(taskID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(assets).Send()
}

func (h *HandlerTask) ListLogs(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	logs, err := h.svc.ListLogs(taskID, 200)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(logs).Send()
}
