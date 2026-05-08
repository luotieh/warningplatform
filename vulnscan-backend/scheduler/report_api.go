package scheduler

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/definition"
	"vulnscan-backend/report"
	"vulnscan-backend/scan/engine"
)

type ReportAPI struct {
	db  *gorm.DB
	gen *report.Generator
}

func NewReportAPI(db *gorm.DB) *ReportAPI {
	return &ReportAPI{db: db, gen: report.NewGenerator()}
}

func (a *ReportAPI) RegisterRoutes(g *gin.RouterGroup) {
	rg := g.Group("/report")
	{
		rg.POST("/generate", a.Generate)
		rg.GET("/task/:id", a.GenerateForTask)
		rg.GET("/compare", a.Compare)
		rg.GET("/attack-path/:id", a.AttackPath)
		rg.GET("/delta/:current/:base", a.DeltaScan)
		rg.GET("/timeline", a.Timeline)
	}
}

func (a *ReportAPI) Compare(c *gin.Context) {
	baseID := c.Query("base")
	compareID := c.Query("compare")
	if baseID == "" || compareID == "" {
		web.Resp(c, definition.ScanReportBadParams)
		return
	}

	result, err := report.CompareTasks(a.db, baseID, compareID)
	if err != nil {
		web.Resp(c, definition.ScanReportFailed)
		return
	}
	web.RespContent(c, web.Success, result)
}

type ReportRequest struct {
	Title    string   `json:"title"`
	TaskIDs  []string `json:"task_ids"`
	Format   string   `json:"format"`
	Severity []string `json:"severity"`
}

func (a *ReportAPI) Generate(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, definition.ScanReportBadParams)
		return
	}

	format := req.Format
	if format == "" {
		format = report.FormatJSON
	}

	data := a.buildReportData(req.Title, req.TaskIDs, req.Severity)

	output, err := a.gen.Generate(data, format)
	if err != nil {
		web.Resp(c, definition.ScanReportFailed.SetMessage("生成报告失败: "+err.Error()))
		return
	}

	a.serveReport(c, output, format, req.Title)
}

func (a *ReportAPI) GenerateForTask(c *gin.Context) {
	taskID := c.Param("id")
	format := c.DefaultQuery("format", report.FormatJSON)

	var task model.ScanTask
	if err := a.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		web.Resp(c, definition.ScanTaskNotFound)
		return
	}

	data := a.buildReportData(
		fmt.Sprintf("扫描报告 - %s", task.Name),
		[]string{taskID},
		nil,
	)

	if task.StartedAt != nil {
		end := task.FinishedAt
		if end == nil {
			now := time.Now()
			end = &now
		}
		dur := end.Sub(*task.StartedAt)
		if dur < time.Minute {
			data.Summary.ScanDuration = fmt.Sprintf("%d秒", int(dur.Seconds()))
		} else {
			data.Summary.ScanDuration = fmt.Sprintf("%d分%d秒", int(dur.Minutes()), int(dur.Seconds())%60)
		}
	}

	output, err := a.gen.Generate(data, format)
	if err != nil {
		web.Resp(c, definition.ScanReportFailed)
		return
	}

	a.serveReport(c, output, format, task.Name)
}

func (a *ReportAPI) buildReportData(title string, taskIDs, severityFilter []string) *report.ReportData {
	if title == "" {
		title = "安全检测报告"
	}

	data := &report.ReportData{
		Title:       title,
		GeneratedAt: time.Now(),
	}

	// 1) 查询 ScanFinding（扫描发现）
	fQuery := a.db.Model(&model.ScanFinding{})
	if len(taskIDs) > 0 {
		fQuery = fQuery.Where("task_id IN ?", taskIDs)
	}
	if len(severityFilter) > 0 {
		fQuery = fQuery.Where("severity IN ?", severityFilter)
	}

	const maxItems = 10000
	var findings []model.ScanFinding
	fQuery.Order("severity ASC, created_at DESC").Limit(maxItems).Find(&findings)

	// 2) 同时查询 Vulnerability（已确认漏洞），合并去重
	vQuery := a.db.Model(&model.Vulnerability{})
	if len(taskIDs) > 0 {
		vQuery = vQuery.Where("task_id IN ?", taskIDs)
	}
	if len(severityFilter) > 0 {
		vQuery = vQuery.Where("severity IN ?", severityFilter)
	}

	var vulns []model.Vulnerability
	vQuery.Order("severity ASC, created_at DESC").Limit(maxItems).Find(&vulns)

	seenIDs := make(map[string]bool)

	// 漏洞类 finding
	vulnCategories := map[string]bool{"vuln": true}
	for _, f := range findings {
		if seenIDs[f.ID] {
			continue
		}
		seenIDs[f.ID] = true

		item := report.VulnItem{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			Asset:       f.Target,
			Description: f.Description,
			Evidence:    f.Evidence,
		}
		if f.Port > 0 {
			item.Asset = fmt.Sprintf("%s:%d", f.Target, f.Port)
		}

		if vulnCategories[f.Category] {
			item.Status = "detected"
			if f.VerificationLevel == "exploit" {
				item.Status = "confirmed"
			}
		} else {
			item.Status = "info"
		}

		data.Vulnerabilities = append(data.Vulnerabilities, item)
	}

	// 已确认的漏洞记录
	for _, v := range vulns {
		if seenIDs[v.ID] {
			continue
		}
		seenIDs[v.ID] = true

		cveID := ""
		if len(v.CVEIDs) > 0 {
			cveID = strings.Join(v.CVEIDs, ",")
		}
		data.Vulnerabilities = append(data.Vulnerabilities, report.VulnItem{
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

	// 3) 构建资产清单
	type assetAgg struct {
		host  string
		ip    string
		ports map[int]bool
		svcs  map[string]bool
		techs map[string]bool
		vulnN int
	}
	assetMap := make(map[string]*assetAgg)

	for _, f := range findings {
		host := f.Target
		ag, ok := assetMap[host]
		if !ok {
			ag = &assetAgg{
				host:  host,
				ports: make(map[int]bool),
				svcs:  make(map[string]bool),
				techs: make(map[string]bool),
			}
			assetMap[host] = ag
		}
		if f.Port > 0 {
			ag.ports[f.Port] = true
		}
		if f.Category == "vuln" {
			ag.vulnN++
		}
		if f.Type == "service" && f.Data != nil {
			if svc, ok := f.Data["service"].(string); ok && svc != "" {
				ag.svcs[svc] = true
			}
		}
		if (f.Type == "tech" || f.Type == "tech_stack") && f.Data != nil {
			if name, ok := f.Data["name"].(string); ok && name != "" {
				ag.techs[name] = true
			}
		}
	}

	for _, ag := range assetMap {
		ports := make([]int, 0, len(ag.ports))
		for p := range ag.ports {
			ports = append(ports, p)
		}
		svcs := make([]string, 0, len(ag.svcs))
		for s := range ag.svcs {
			svcs = append(svcs, s)
		}
		techs := make([]string, 0, len(ag.techs))
		for t := range ag.techs {
			techs = append(techs, t)
		}
		data.Assets = append(data.Assets, report.AssetItem{
			Host:         ag.host,
			IP:           ag.ip,
			OpenPorts:    ports,
			Services:     svcs,
			Fingerprints: techs,
			VulnCount:    ag.vulnN,
		})
	}

	// 4) 统计摘要
	data.Summary = report.ReportSummary{
		TotalVulns:  len(data.Vulnerabilities),
		TotalAssets: len(assetMap),
	}
	for _, item := range data.Vulnerabilities {
		switch item.Severity {
		case model.SeverityCritical:
			data.Summary.CriticalCount++
		case model.SeverityHigh:
			data.Summary.HighCount++
		case model.SeverityMedium:
			data.Summary.MediumCount++
		case model.SeverityLow:
			data.Summary.LowCount++
		case model.SeverityInfo:
			data.Summary.InfoCount++
		}
	}

	data.Summary.RiskScore = computeRiskScore(data.Summary)

	return data
}

func computeRiskScore(s report.ReportSummary) float64 {
	score := float64(s.CriticalCount)*10 + float64(s.HighCount)*5 +
		float64(s.MediumCount)*2 + float64(s.LowCount)*0.5
	score = math.Min(score, 100)
	return score
}

func (a *ReportAPI) AttackPath(c *gin.Context) {
	taskID := c.Param("id")

	var task model.ScanTask
	if err := a.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		web.Resp(c, definition.ScanTaskNotFound)
		return
	}

	var findings []model.ScanFinding
	a.db.Where("task_id = ?", taskID).Find(&findings)

	engineTargets := make([]*engine.Target, 0, len(task.Targets))
	for _, raw := range task.Targets {
		engineTargets = append(engineTargets, &engine.Target{Host: raw})
	}

	engineFindings := make([]*engine.Finding, 0, len(findings))
	for _, f := range findings {
		engineFindings = append(engineFindings, &engine.Finding{
			ModuleID: f.ModuleID,
			Target: &engine.Target{
				Host: f.Target,
				Port: f.Port,
			},
			Type:       f.Type,
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: f.Confidence,
		})
	}

	analyzer := engine.NewAttackPathAnalyzer()
	paths := analyzer.Analyze(engineTargets, engineFindings)

	web.OK(c).Data(gin.H{
		"task_id":      taskID,
		"attack_paths": paths,
		"total_hosts":  len(paths),
	}).Send()
}

func (a *ReportAPI) DeltaScan(c *gin.Context) {
	currentID := c.Param("current")
	baseID := c.Param("base")

	delta := NewDeltaScanEngine(a.db)
	result, err := delta.Compare(currentID, baseID)
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}

	web.OK(c).Data(result).Send()
}

func (a *ReportAPI) Timeline(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		web.Fail(c).Msg("target required").Send()
		return
	}

	delta := NewDeltaScanEngine(a.db)
	entries, err := delta.Timeline(target, 50)
	if err != nil {
		web.Fail(c).Msg("获取时间线失败").Err(err).Send()
		return
	}

	web.OK(c).Data(entries).Send()
}

func (a *ReportAPI) serveReport(c *gin.Context, data []byte, format, name string) {
	safeName := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '"' || r == '\'' || r < 32 {
			return '_'
		}
		return r
	}, name)
	if safeName == "" {
		safeName = "report"
	}

	switch format {
	case report.FormatMarkdown:
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.md"`, safeName))
		c.Data(http.StatusOK, "text/markdown; charset=utf-8", data)
	case report.FormatCSV:
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, safeName))
		c.Data(http.StatusOK, "text/csv; charset=utf-8", data)
	case report.FormatSARIF:
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.sarif.json"`, safeName))
		c.Data(http.StatusOK, "application/json; charset=utf-8", data)
	default:
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, safeName))
		c.Data(http.StatusOK, "application/json; charset=utf-8", data)
	}
}
