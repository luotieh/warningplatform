package report

import (
	"fmt"
	"time"

	"code.yt-security.com/public/core/web"
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

type taskReportURI struct {
	TaskID string `uri:"task_id" binding:"required"`
}

func NewHandler(svc *ServiceReport) *Handler {
	return &Handler{
		svc:       svc,
		generator: NewGenerator(),
	}
}

func (h *Handler) Generate(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		Title  string `json:"title" binding:"required"`
		Type   string `json:"type"`
		Format string `json:"format"`
		TaskID string `json:"task_id"`
	}](c)
	if !ok {
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
		web.Fail(c).Msg("生成报告失败").Err(err).Send()
		return
	}

	contentType := "application/json"
	ext := "json"
	switch req.Format {
	case FormatWord:
		contentType = "application/msword; charset=utf-8"
		ext = "doc"
	case FormatPDF:
		contentType = "application/pdf"
		ext = "pdf"
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
		req.Title = "扫描报告预览"
	}
	if req.Type == "" {
		req.Type = TypeTechnical
	}

	data := h.svc.BuildReportData(req.Title, req.Type, req.TaskID)
	web.Succeed(c).Data(data).Send()
}

func (h *Handler) Compare(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		Base    string `form:"base" binding:"required"`
		Compare string `form:"compare" binding:"required"`
	}](c)
	if !ok {
		return
	}

	result, err := h.svc.CompareTasks(query.Base, query.Compare)
	if err != nil {
		web.Fail(c).Msg("对比任务失败").Err(err).Send()
		return
	}
	web.Succeed(c).Data(result).Send()
}

func (h *Handler) AvailableTasks(c *gin.Context) {
	tasks := h.svc.AvailableTasks()
	web.Succeed(c).Data(tasks).Send()
}

func (h *Handler) TaskReport(c *gin.Context) {
	uri, ok := web.BindUri[taskReportURI](c)
	if !ok {
		return
	}
	format := c.DefaultQuery("format", FormatJSON)

	task, err := h.svc.GetTask(uri.TaskID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	title := fmt.Sprintf("扫描任务报告 - %s", task.Name)
	data := h.svc.BuildReportData(title, TypeTechnical, uri.TaskID)
	if format == FormatJSON {
		web.Succeed(c).Data(data).Send()
		return
	}

	content, err := h.generator.Generate(data, format)
	if err != nil {
		web.Fail(c).Msg("生成报告失败").Err(err).Send()
		return
	}

	contentType := "application/octet-stream"
	ext := format
	switch format {
	case FormatWord:
		contentType = "application/msword; charset=utf-8"
		ext = "doc"
	case FormatPDF:
		contentType = "application/pdf"
		ext = "pdf"
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

	filename := fmt.Sprintf("report_%s.%s", uri.TaskID, ext)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Data(200, contentType, content)
}
