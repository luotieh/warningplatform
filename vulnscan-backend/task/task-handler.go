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
	var query taskContract.TaskQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerTask) GetByID(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	item, err := h.svc.GetByID(id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	web.RespContent(c, web.Success, item)
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
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, item)
}

func (h *HandlerTask) Cancel(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.svc.Cancel(id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *HandlerTask) Pause(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Pause(id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerTask) Resume(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Resume(id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerTask) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.svc.Delete(id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *HandlerTask) ListFindings(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	var query taskContract.FindingQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	query.TaskID = taskID

	items, count, err := h.svc.ListFindings(query)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerTask) FindingSummary(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	summary, err := h.svc.FindingSummary(taskID)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, summary)
}

func (h *HandlerTask) ListAssets(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	assets, err := h.svc.ListAssets(taskID)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, assets)
}

func (h *HandlerTask) ListLogs(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	logs, err := h.svc.ListLogs(taskID, 200)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, logs)
}
