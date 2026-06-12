package sitemonitor

import (
	"net/http"

	"vulnscan-backend/pkg/definition"
	"vulnscan-backend/sitemonitor/contract"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

// ══ 执行记录 ══

func (h *HandlerMonitor) ListExecutions(c *gin.Context) {
	req, ok := web.BindQuery[contract.ExecutionListReq](c)
	if !ok {
		return
	}
	scope := definition.SafeDataFilterScope(c, monitorExecutionFieldMapping)
	total, list, err := h.svc.ListExecutions(c.Request.Context(), req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(total, list).Send()
}

func (h *HandlerMonitor) GetExecutionDetail(c *gin.Context) {
	id := c.Param("id")
	detail, err := h.svc.GetExecutionDetail(c.Request.Context(), id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(detail).Send()
}

func (h *HandlerMonitor) DeleteExecution(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteExecution(c.Request.Context(), id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) BatchDeleteExecutions(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchDeleteExecutions(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) UpdateDisposition(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Disposition string `json:"disposition" binding:"required"`
		Remark      string `json:"remark"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.UpdateDisposition(c.Request.Context(), id, req.Disposition, req.Remark, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) BatchUpdateDisposition(c *gin.Context) {
	var req struct {
		IDs         []string `json:"ids" binding:"required"`
		Disposition string   `json:"disposition" binding:"required"`
		Remark      string   `json:"remark"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.BatchUpdateDisposition(c.Request.Context(), req.IDs, req.Disposition, req.Remark, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) GetEvidenceAsset(c *gin.Context) {
	id := c.Param("id")
	assetType := c.Param("type")
	data, contentType, err := h.svc.GetEvidenceAsset(c.Request.Context(), id, assetType)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	c.Data(http.StatusOK, contentType, data)
}
