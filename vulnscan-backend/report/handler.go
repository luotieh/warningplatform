package report

import (
	"fmt"
	"time"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc       *ServiceReport
	generator *Generator
}

type previewReq struct {
	Title  string `json:"title"`
	Type   string `json:"type"`
	TaskID string `json:"task_id"`
}

func NewHandler(svc *ServiceReport) *Handler {
	return &Handler{
		svc:       svc,
		generator: NewGenerator(),
	}
}

func (h *Handler) Generate(c *gin.Context) {
	var req struct {
		Title  string `json:"title" binding:"required"`
		Type   string `json:"type"`
		Format string `json:"format"`
		TaskID string `json:"task_id"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if req.Format == "" {
		req.Format = FormatJSON
	}
	if req.Type == "" {
		req.Type = TypeTechnical
	}

	data := h.svc.BuildReportData(req.Title, req.Type, req.TaskID)

	content, err := h.generator.Generate(data, req.Format)
	if err != nil {
		web.Fail(c).Msg("报告生成失败").Err(err).Send()
		return
	}

	contentType := "application/json"
	ext := "json"
	switch req.Format {
	case FormatMarkdown:
		contentType = "text/markdown; charset=utf-8"
		ext = "md"
	case FormatCSV:
		contentType = "text/csv; charset=utf-8"
		ext = "csv"
	case FormatSARIF:
		contentType = "application/json"
		ext = "sarif.json"
	}

	filename := fmt.Sprintf("%s_%s.%s", req.Title, time.Now().Format("20060102_150405"), ext)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Data(200, contentType, content)
}

func (h *Handler) Preview(c *gin.Context) {
	req, _ := web.BindJSON[previewReq](c)
	if req.Title == "" {
		req.Title = "安全评估报告"
	}
	if req.Type == "" {
		req.Type = TypeTechnical
	}

	data := h.svc.BuildReportData(req.Title, req.Type, req.TaskID)
	web.OK(c).Data(data).Send()
}

func (h *Handler) Compare(c *gin.Context) {
	baseID := c.Query("base")
	compareID := c.Query("compare")
	if baseID == "" || compareID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	result, err := h.svc.CompareTasks(baseID, compareID)
	if err != nil {
		web.Fail(c).Msg("对比失败").Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *Handler) AvailableTasks(c *gin.Context) {
	tasks := h.svc.AvailableTasks()
	web.OK(c).Data(tasks).Send()
}

func (h *Handler) TaskReport(c *gin.Context) {
	taskID := c.Param("task_id")
	format := c.DefaultQuery("format", "json")

	task, err := h.svc.GetTask(taskID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	title := fmt.Sprintf("扫描报告 - %s", task.Name)
	data := h.svc.BuildReportData(title, TypeTechnical, taskID)

	if format == "json" {
		web.OK(c).Data(data).Send()
		return
	}

	content, err := h.generator.Generate(data, format)
	if err != nil {
		web.Fail(c).Msg("报告生成失败").Err(err).Send()
		return
	}

	contentType := "application/octet-stream"
	ext := format
	switch format {
	case FormatMarkdown:
		contentType = "text/markdown; charset=utf-8"
		ext = "md"
	case FormatCSV:
		contentType = "text/csv; charset=utf-8"
		ext = "csv"
	case FormatSARIF:
		contentType = "application/json"
		ext = "sarif.json"
	}

	filename := fmt.Sprintf("report_%s.%s", taskID, ext)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Data(200, contentType, content)
}
