package report

import (
	"fmt"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct {
	db        *gorm.DB
	generator *Generator
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		db:        db,
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

	data := h.buildReportData(req.Title, req.Type, req.TaskID)

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
	var req struct {
		Title  string `json:"title"`
		Type   string `json:"type"`
		TaskID string `json:"task_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Title = "安全评估报告"
		req.Type = TypeTechnical
	}

	data := h.buildReportData(req.Title, req.Type, req.TaskID)
	web.RespContent(c, web.Success, data)
}

func (h *Handler) Compare(c *gin.Context) {
	baseID := c.Query("base")
	compareID := c.Query("compare")
	if baseID == "" || compareID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	result, err := CompareTasks(h.db, baseID, compareID)
	if err != nil {
		web.Fail(c).Msg("对比失败").Err(err).Send()
		return
	}
	web.RespContent(c, web.Success, result)
}

func (h *Handler) AvailableTasks(c *gin.Context) {
	var tasks []model.ScanTask
	h.db.Where("status = ?", "completed").
		Order("finished_at DESC").
		Limit(50).
		Select("id, name, target, status, finished_at").
		Find(&tasks)
	web.RespContent(c, web.Success, tasks)
}

func (h *Handler) TaskReport(c *gin.Context) {
	taskID := c.Param("task_id")
	format := c.DefaultQuery("format", "json")

	var task model.ScanTask
	if h.db.First(&task, "id = ?", taskID).Error != nil {
		web.Resp(c, web.NotFound)
		return
	}

	title := fmt.Sprintf("扫描报告 - %s", task.Name)
	data := h.buildReportData(title, TypeTechnical, taskID)

	if format == "json" {
		web.RespContent(c, web.Success, data)
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

func (h *Handler) buildReportData(title, reportType, taskID string) *ReportData {
	data := &ReportData{
		Title:       title,
		GeneratedAt: time.Now(),
		GeneratedBy: "system",
	}

	vulnQuery := h.db.Model(&model.Vulnerability{})
	if taskID != "" {
		vulnQuery = vulnQuery.Where("task_id = ?", taskID)
	}

	var vulns []model.Vulnerability
	vulnQuery.Order("severity DESC").Limit(500).Find(&vulns)

	for _, v := range vulns {
		cveID := ""
		if len(v.CVEIDs) > 0 {
			cveID = v.CVEIDs[0]
		}
		data.Vulnerabilities = append(data.Vulnerabilities, VulnItem{
			ID:          v.ID,
			Title:       v.Title,
			Severity:    v.Severity,
			CVEID:       cveID,
			Asset:       v.Target,
			Status:      v.Status,
			Description: v.Description,
			Evidence:    v.Evidence,
			Remediation: v.Solution,
		})
	}

	var critCount, highCount, medCount, lowCount, infoCount int
	for _, v := range data.Vulnerabilities {
		switch v.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	var assetCount int64
	h.db.Model(&model.Asset{}).Count(&assetCount)

	data.Summary = ReportSummary{
		TotalAssets:   int(assetCount),
		TotalVulns:    len(data.Vulnerabilities),
		CriticalCount: critCount,
		HighCount:     highCount,
		MediumCount:   medCount,
		LowCount:      lowCount,
		InfoCount:     infoCount,
	}

	if reportType == TypeASM {
		data.Title = title + " (攻击面)"
	}

	return data
}
