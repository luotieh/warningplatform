package sitemonitor

import (
	"io"
	"net/http"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

// ══ 导入 ══

func (h *HandlerMonitor) DownloadImportTemplate(c *gin.Context) {
	data, err := h.svc.GenerateImportTemplate(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Header("Content-Disposition", "attachment; filename=import_template.xlsx")
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", data)
}

func (h *HandlerMonitor) ImportTasks(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	defer file.Close()
	fileData, err := io.ReadAll(file)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	result, err := h.svc.ImportTasks(c.Request.Context(), fileData)
	if err != nil {
		web.Fail(c).Err(err).Msg(err.Error()).Send()
		return
	}
	web.Succeed(c).Data(gin.H{
		"id":     result.ID,
		"status": result.Status,
		"total":  result.Total,
	}).Send()
}

func (h *HandlerMonitor) GetImportResult(c *gin.Context) {
	importID := c.Param("importId")
	result, err := h.svc.GetImportResult(c.Request.Context(), importID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(result).Send()
}

func (h *HandlerMonitor) ExportImportResult(c *gin.Context) {
	importID := c.Param("importId")
	data, err := h.svc.ExportImportResult(c.Request.Context(), importID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Header("Content-Disposition", "attachment; filename=import_result.xlsx")
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", data)
}
